#!/usr/bin/env python3
import glob
import ipaddress
import json
import os
import random
import signal
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Set, Tuple

import grpc
import uvicorn
from fastapi import FastAPI, HTTPException, Response, status
from fastapi.responses import FileResponse
from google.protobuf.json_format import MessageToDict
from pydantic import BaseModel, Field

from apipb.api import attribute_pb2 as attr_pb2
from apipb.api import gobgp_pb2 as pb
from apipb.api import gobgp_pb2_grpc as pb_grpc
from apipb.api import common_pb2 as common_pb2
from apipb.api import nlri_pb2 as nlri_pb2

POD_IP = os.environ["POD_IP"]
LOCAL_ASN = int(os.environ["ASN"])
ROUTER_ID = os.environ["ROUTER_ID"]
KUBE_NAMESPACE = os.environ["POD_NAMESPACE"]
NEIGHBORS_JSON_RAW = os.environ["NEIGHBORS_JSON"]

GOBGP_CONFIG_PATH = "/etc/gobgp/gobgp.conf"
PCAP_DIR = "/tmp/pcaps"
GOBGP_API_ADDR = os.getenv("GOBGP_API_ADDR", "127.0.0.1:50051")

neighbor_state_by_service_name: Dict[str, Dict[str, Any]] = {}
gobgp_daemon_process: Optional[subprocess.Popen] = None
tcpdump_process: Optional[subprocess.Popen] = None
current_pcap_filepath: Optional[str] = None
neighbor_state_lock = threading.Lock()

noise_thread: Optional[threading.Thread] = None
noise_stop_event = threading.Event()
noise_pause_event = threading.Event()
noise_pause_started_at: Optional[float] = None
noise_runtime_config: Dict[str, Any] = {}
noise_active_prefixes: Dict[ipaddress.IPv4Network, Tuple[float, int]] = {}
noise_lock = threading.Lock()


def community_to_u32(community: str) -> int:
    left, right = community.split(":")
    return (int(left) << 16) | int(right)


def ipv4_family() -> common_pb2.Family:
    return common_pb2.Family(afi=common_pb2.Family.AFI_IP, safi=common_pb2.Family.SAFI_UNICAST)


def nlri_from_prefix(prefix: str) -> nlri_pb2.NLRI:
    network = ipaddress.ip_network(prefix, strict=False)
    return nlri_pb2.NLRI(
        prefix=nlri_pb2.IPAddressPrefix(
            prefix_len=network.prefixlen, prefix=str(network.network_address)
        )
    )


def is_owned_path(path: pb.Path) -> bool:
    for attr in path.pattrs:
        if attr.HasField("next_hop") and attr.next_hop.next_hop == POD_IP:
            return True
    return False


class GoBGPRpc:
    RETRYABLE = {grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.UNKNOWN, grpc.StatusCode.DEADLINE_EXCEEDED}

    def __init__(self, target: Optional[str] = None, timeout: float = 5.0, retries: int = 3, backoff: float = 0.25):
        self.target = target or GOBGP_API_ADDR
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.channel = grpc.insecure_channel(
            self.target,
            options=[
                ("grpc.max_receive_message_length", 64 * 1024 * 1024),
                ("grpc.max_send_message_length", 64 * 1024 * 1024),
                ("grpc.keepalive_time_ms", 30_000),
                ("grpc.keepalive_timeout_ms", 10_000),
                ("grpc.http2.max_pings_without_data", 0),
                ("grpc.keepalive_permit_without_calls", 1),
            ],
        )
        if hasattr(pb_grpc, "GoBgpServiceStub"):
            self.stub = pb_grpc.GoBgpServiceStub(self.channel)
        elif hasattr(pb_grpc, "GobgpApiStub"):
            self.stub = pb_grpc.GobgpApiStub(self.channel)
        else:
            raise RuntimeError("No matching GoBGP gRPC stub found")

    def close(self) -> None:
        try:
            self.channel.close()
        except Exception:
            pass

    def _unary(self, method, request):
        last_exc: Optional[grpc.RpcError] = None
        for attempt in range(self.retries):
            try:
                return method(request, timeout=self.timeout, wait_for_ready=True)
            except grpc.RpcError as exc:
                if exc.code() in self.RETRYABLE and attempt < self.retries - 1:
                    time.sleep(self.backoff * (2 ** attempt))
                    continue
                last_exc = exc
                break
        raise last_exc  # type: ignore

    def _stream_to_list(self, method, request):
        last_exc: Optional[grpc.RpcError] = None
        for attempt in range(self.retries):
            try:
                return list(method(request, timeout=self.timeout, wait_for_ready=True))
            except grpc.RpcError as exc:
                if exc.code() in self.RETRYABLE and attempt < self.retries - 1:
                    time.sleep(self.backoff * (2 ** attempt))
                    continue
                last_exc = exc
                break
        raise last_exc  # type: ignore

    @staticmethod
    def extract_next_hop(path: pb.Path) -> Optional[str]:
        for attr in path.pattrs:
            if attr.HasField("next_hop"):
                return attr.next_hop.next_hop
        return None

    def list_neighbors(self):
        try:
            responses = self._stream_to_list(self.stub.ListPeer, pb.ListPeerRequest())
            return [MessageToDict(resp.peer) for resp in responses]
        except grpc.RpcError as exc:
            return {"error": f"{exc.code().name}: {exc.details()}"}

    def list_rib_ipv4(self):
        try:
            request = pb.ListPathRequest(table_type=pb.TABLE_TYPE_GLOBAL, family=ipv4_family())
            responses = self._stream_to_list(self.stub.ListPath, request)
            return [MessageToDict(r) for r in responses]
        except grpc.RpcError as exc:
            return {"error": f"{exc.code().name}: {exc.details()}"}

    def rib_summary_ipv4(self):
        try:
            request = pb.GetTableRequest(table_type=pb.TABLE_TYPE_GLOBAL, family=ipv4_family())
            resp = self._unary(self.stub.GetTable, request)
            return {"num_destinations": resp.num_destination, "num_paths": resp.num_path}
        except grpc.RpcError as exc:
            return {"error": f"{exc.code().name}: {exc.details()}"}

    def add_route_ipv4(
        self,
        prefix: str,
        next_hop: str,
        as_path: Optional[List[int]] = None,
        community: Optional[str] = None,
        identifier: Optional[int] = None,
    ):
        try:
            pattrs: List[attr_pb2.Attribute] = [
                attr_pb2.Attribute(origin=attr_pb2.OriginAttribute(origin=0)),
                attr_pb2.Attribute(next_hop=attr_pb2.NextHopAttribute(next_hop=next_hop)),
            ]
            if as_path:
                seg = attr_pb2.AsSegment(type=attr_pb2.AsSegment.TYPE_AS_SEQUENCE, numbers=[int(a) for a in as_path])
                pattrs.append(attr_pb2.Attribute(as_path=attr_pb2.AsPathAttribute(segments=[seg])))
            if community:
                pattrs.append(attr_pb2.Attribute(communities=attr_pb2.CommunitiesAttribute(communities=[community_to_u32(community)])))
            path = pb.Path(nlri=nlri_from_prefix(prefix), pattrs=pattrs, family=ipv4_family())
            if identifier is not None:
                path.identifier = int(identifier)
            req = pb.AddPathRequest(table_type=pb.TABLE_TYPE_GLOBAL, path=path)
            resp = self._unary(self.stub.AddPath, req)
            return {"uuid": list(resp.uuid)}
        except grpc.RpcError as exc:
            return {"error": f"{exc.code().name}: {exc.details()}"}

    def _paths_for_prefix(self, prefix: str) -> List[Tuple[str, pb.Path]]:
        request = pb.ListPathRequest(
            table_type=pb.TABLE_TYPE_GLOBAL,
            family=ipv4_family(),
            prefixes=[pb.TableLookupPrefix(prefix=prefix, type=pb.TableLookupPrefix.TYPE_EXACT)],
        )
        responses = self._stream_to_list(self.stub.ListPath, request)
        out: List[Tuple[str, pb.Path]] = []
        for resp in responses:
            dest = resp.destination
            for p in dest.paths:
                out.append((dest.prefix, p))
        return out

    def del_route_ipv4(self, prefix: str, identifier: Optional[int] = None):
        try:
            paths = self._paths_for_prefix(prefix)
            if not paths:
                return {
                    "prefix": prefix,
                    "mode": "none",
                    "identifier": int(identifier) if identifier is not None else None,
                    "removed_owned": 0,
                    "not_removed_foreign": 0,
                    "remaining_for_prefix": 0,
                }

            targets: List[pb.Path] = []
            if identifier is not None:
                ident = int(identifier)
                for _, p in paths:
                    if getattr(p, "identifier", 0) == ident or getattr(p, "local_identifier", 0) == ident:
                        targets.append(p)
                mode = "identifier"
            else:
                targets = [p for _, p in paths]
                mode = "all-for-prefix"

            removed_owned = 0
            not_removed_foreign = 0

            for p in targets:
                if not is_owned_path(p):
                    not_removed_foreign += 1
                    continue
                nh = self.extract_next_hop(p)
                if not nh:
                    continue
                del_path = pb.Path(
                    nlri=nlri_from_prefix(prefix),
                    pattrs=[attr_pb2.Attribute(next_hop=attr_pb2.NextHopAttribute(next_hop=nh))],
                    family=ipv4_family(),
                )
                if identifier is not None:
                    del_path.identifier = int(identifier)
                self._unary(
                    self.stub.DeletePath,
                    pb.DeletePathRequest(table_type=pb.TABLE_TYPE_GLOBAL, family=ipv4_family(), path=del_path),
                )
                removed_owned += 1

            remaining_for_prefix = 0
            for _, p in self._paths_for_prefix(prefix):
                remaining_for_prefix += 1

            return {
                "prefix": prefix,
                "mode": mode,
                "identifier": int(identifier) if identifier is not None else None,
                "removed_owned": removed_owned,
                "not_removed_foreign": not_removed_foreign,
                "remaining_for_prefix": remaining_for_prefix,
            }
        except grpc.RpcError as exc:
            return {"error": f"{exc.code().name}: {exc.details()}"}

    def del_all_routes_ipv4(self):
        try:
            request = pb.ListPathRequest(table_type=pb.TABLE_TYPE_GLOBAL, family=ipv4_family())
            responses = self._stream_to_list(self.stub.ListPath, request)

            removed_owned = 0
            skipped_foreign = 0
            targets: List[Tuple[str, Optional[str], pb.Path]] = []
            for resp in responses:
                dest = resp.destination
                for p in dest.paths:
                    nh = self.extract_next_hop(p)
                    targets.append((dest.prefix, nh, p))

            for prefix, nh, p in targets:
                if not is_owned_path(p):
                    skipped_foreign += 1
                    continue
                if not nh:
                    continue
                del_path = pb.Path(
                    nlri=nlri_from_prefix(prefix),
                    pattrs=[attr_pb2.Attribute(next_hop=attr_pb2.NextHopAttribute(next_hop=nh))],
                    family=ipv4_family(),
                )
                self._unary(
                    self.stub.DeletePath,
                    pb.DeletePathRequest(table_type=pb.TABLE_TYPE_GLOBAL, family=ipv4_family(), path=del_path),
                )
                removed_owned += 1

            remaining_paths = 0
            for _ in self._stream_to_list(self.stub.ListPath, pb.ListPathRequest(table_type=pb.TABLE_TYPE_GLOBAL, family=ipv4_family())):
                remaining_paths += 1

            return {"removed_owned": removed_owned, "skipped_foreign": skipped_foreign, "remaining_paths": remaining_paths}
        except grpc.RpcError as exc:
            return {"error": f"{exc.code().name}: {exc.details()}"}


gobgp = GoBGPRpc()


def parse_neighbors_definition(raw_json: str) -> Dict[str, Dict[str, Any]]:
    parsed = json.loads(raw_json)
    neighbors: Dict[str, Dict[str, Any]] = {}
    for neighbor in parsed:
        name = neighbor["name"]
        peer_as = int(neighbor["peerAs"])
        tags = [int(tag) for tag in neighbor.get("communitiesAddTags", [])]
        lp = neighbor.get("localPref")
        neighbors[name] = {
            "peerAs": peer_as,
            "tags": tags,
            "localPref": int(lp) if lp is not None else None,
            "ip": None,
        }
    return neighbors


NEIGHBOR_DEFINITION_TEMPLATE = parse_neighbors_definition(NEIGHBORS_JSON_RAW)


def resolve_neighbor_ip(service_name: str) -> Optional[str]:
    fqdn = f"{service_name}.{KUBE_NAMESPACE}.svc"
    try:
        return subprocess.check_output(["getent", "hosts", fqdn], text=True).split()[0]
    except subprocess.CalledProcessError:
        return None


def write_gobgp_config_file() -> None:
    GOBGP_OPERA_ENABLED = os.getenv("GOBGP_OPERA_ENABLED", "true").lower() == "true"

    with neighbor_state_lock:
        snapshot = {name: data.copy() for name, data in neighbor_state_by_service_name.items()}

    lines: List[str] = []
    lines += [
        "[global.config]",
        f"  as = {LOCAL_ASN}",
        f'  router-id = "{ROUTER_ID}"',
        "",
    ]

    import_policy_names = []

    for name, data in snapshot.items():
        ip_addr = data.get("ip")
        if not ip_addr:
            continue

        lp = data.get("localPref")
        tags = data.get("tags", []) if GOBGP_OPERA_ENABLED else []

        if not lp and not tags:
            continue

        ns_name = f"from-nh-{ip_addr.replace('.', '-')}"
        pol_name = f"policy-{ip_addr.replace('.', '-')}"
        import_policy_names.append(f'"{pol_name}"')

        lines += [
            "[[defined-sets.neighbor-sets]]",
            f'  neighbor-set-name = "{ns_name}"',
            f'  neighbor-info-list = ["{ip_addr}"]',
            "",
            "[[policy-definitions]]",
            f'  name = "{pol_name}"',
            "  [[policy-definitions.statements]]",
            f'    name = "set-attrs-{ip_addr}"',
            "    [policy-definitions.statements.conditions.match-neighbor-set]",
            f'      neighbor-set = "{ns_name}"',
            '      match-set-options = "any"',
            "    [policy-definitions.statements.actions]",
            '      route-disposition = "accept-route"',
        ]

        if lp:
            lines += [
                "    [policy-definitions.statements.actions.bgp-actions]",
                f"      set-local-pref = {int(lp)}",
            ]

        if tags:
            communities_literal = ", ".join([f'"{LOCAL_ASN}:{tag}"' for tag in sorted(tags)])
            lines += [
                "    [policy-definitions.statements.actions.bgp-actions.set-community]",
                '      options = "add"',
                "      [policy-definitions.statements.actions.bgp-actions.set-community.set-community-method]",
                f"        communities-list = [{communities_literal}]",
            ]

        lines.append("")

    if import_policy_names:
        lines += [
            "[global.apply-policy.config]",
            f"  import-policy-list = [{', '.join(import_policy_names)}]",
            '  default-import-policy = "accept-route"',
            "",
        ]
    else:
        lines += [
            "[global.apply-policy.config]",
            '  default-import-policy = "accept-route"',
            "",
        ]

    for name, data in snapshot.items():
        ip_addr = data.get("ip")
        if not ip_addr:
            continue
        peer_as = data["peerAs"]
        passive_mode = "true" if peer_as > LOCAL_ASN else "false"

        lines += [
            "[[neighbors]]",
            "  [neighbors.config]",
            f'    neighbor-address = "{ip_addr}"',
            f"    peer-as = {peer_as}",
            "  [neighbors.transport.config]",
            f"    passive-mode = {passive_mode}",
            "  [neighbors.add-paths.config]",
            "    receive = true",
            f"    send-max = 1",
            "  [[neighbors.afi-safis]]",
            "    [neighbors.afi-safis.config]",
            '      afi-safi-name = "ipv4-unicast"',
            "",
        ]

    os.makedirs(os.path.dirname(GOBGP_CONFIG_PATH), exist_ok=True)
    with open(GOBGP_CONFIG_PATH, "w") as f:
        f.write("\n".join(lines))



def restart_gobgp_daemon() -> None:
    global gobgp_daemon_process
    if gobgp_daemon_process and gobgp_daemon_process.poll() is None:
        gobgp_daemon_process.send_signal(signal.SIGTERM)
        try:
            gobgp_daemon_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            gobgp_daemon_process.kill()
            gobgp_daemon_process.wait()
    gobgp_daemon_process = subprocess.Popen(["gobgpd", "--api-hosts", GOBGP_API_ADDR, "-f", GOBGP_CONFIG_PATH])


def neighbor_resolution_loop() -> None:
    with neighbor_state_lock:
        neighbor_state_by_service_name.update(NEIGHBOR_DEFINITION_TEMPLATE)
    first_render = True
    while True:
        changed = False
        for name in list(neighbor_state_by_service_name.keys()):
            resolved_ip = resolve_neighbor_ip(name)
            with neighbor_state_lock:
                prev_ip = neighbor_state_by_service_name[name].get("ip")
                if resolved_ip != prev_ip:
                    neighbor_state_by_service_name[name]["ip"] = resolved_ip
                    changed = True
        if changed or first_render:
            if any(n.get("ip") for n in neighbor_state_by_service_name.values()):
                write_gobgp_config_file()
                restart_gobgp_daemon()
                first_render = False
        time.sleep(2)


def start_bgp_tcpdump() -> Tuple[subprocess.Popen, str]:
    os.makedirs(PCAP_DIR, exist_ok=True)
    pcap_file = os.path.join(PCAP_DIR, f"bgp-{int(time.time())}.pcap")
    proc = subprocess.Popen(["tcpdump", "-i", "any", "port", "179", "-w", pcap_file], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return proc, pcap_file


def stop_bgp_tcpdump():
    global tcpdump_process, current_pcap_filepath
    if tcpdump_process and tcpdump_process.poll() is None:
        tcpdump_process.terminate()
        tcpdump_process.wait()
        fname = os.path.basename(current_pcap_filepath) if current_pcap_filepath else None
        tcpdump_process = None
        current_pcap_filepath = None
        return fname
    return None


def realistic_prefix_length() -> int:
    r = random.random()
    if r < 0.6:
        return 24
    if r < 0.8:
        return random.choice([22, 23])
    if r < 0.95:
        return random.choice([20, 21])
    return random.randint(16, 19)


def random_non_overlapping_subnet(start: int, end: int, active: dict) -> Tuple[Optional[str], Optional[ipaddress.IPv4Network]]:
    for _ in range(1000):
        plen = realistic_prefix_length()
        size = 1 << (32 - plen)
        base = random.randint(start // size, (end // size) - 1) * size
        prefix = ipaddress.ip_network((base, plen))
        if not any(prefix.overlaps(a) for a in active.keys()):
            return str(prefix), prefix
    return None, None


def noise_worker():
    global noise_runtime_config, noise_active_prefixes
    block_index = int(noise_runtime_config.get("PREFIX_BLOCK", 0))
    blocks = int(noise_runtime_config.get("NUMBER_OF_BLOCKS", 1))
    rate = float(noise_runtime_config.get("rate", 1))
    lifetime = float(noise_runtime_config.get("lifetime", 60))
    jitter = float(noise_runtime_config.get("jitter", 0.5))
    max_active = int(noise_runtime_config.get("max_active", 250))
    total_space = 1 << 32
    block_size = total_space // blocks
    start = block_index * block_size
    end = total_space if block_index == blocks - 1 else start + block_size
    with noise_lock:
        noise_active_prefixes.clear()
    while not noise_stop_event.is_set():
        if noise_pause_event.is_set():
            noise_stop_event.wait(0.5)
            continue

        now = time.time()
        with noise_lock:
            expired = [p for p, (exp, _) in noise_active_prefixes.items() if exp <= now]
        for prefix in expired:
            _, ident = noise_active_prefixes.get(prefix, (0.0, 0))
            gobgp.del_route_ipv4(str(prefix), identifier=ident if ident else None)
            with noise_lock:
                noise_active_prefixes.pop(prefix, None)
        with noise_lock:
            if len(noise_active_prefixes) < max_active:
                prefix_str, prefix_obj = random_non_overlapping_subnet(start, end, noise_active_prefixes)
                if prefix_str:
                    ident = random.randint(1, 2**31 - 1)
                    res = gobgp.add_route_ipv4(prefix_str, POD_IP, identifier=ident)
                    if isinstance(res, dict) and "error" not in res:
                        delta = lifetime * (1 + random.uniform(-jitter, jitter))
                        noise_active_prefixes[prefix_obj] = (now + delta, ident)
        noise_stop_event.wait(max(1.0 / rate, 0.01))


class RibAddRequest(BaseModel):
    prefix: str = Field(..., json_schema_extra="203.0.113.0/24", description="CIDR prefix to add")
    next_hop: str = Field(..., json_schema_extra="10.0.0.10", description="IPv4 next hop address")
    as_path: Optional[List[int]] = Field(None, json_schema_extra=[65010, 65020], description="Ordered list of AS numbers")
    community: Optional[str] = Field(None, json_schema_extra="65000:100", description="Single community value in NNNN:NNNN format")
    identifier: Optional[int] = Field(None, json_schema_extra=123456, description="Path identifier used to correlate add and delete")


class RibAddResponse(BaseModel):
    uuid: List[int] = Field(..., json_schema_extra=[1, 2, 3, 4], description="Opaque identifier returned by GoBGP as byte values")


class RibDelRequest(BaseModel):
    prefix: str = Field(..., json_schema_extra="203.0.113.0/24", description="CIDR prefix to delete")
    identifier: Optional[int] = Field(None, json_schema_extra=123456, description="Path identifier to delete a specific injected path")

class RibPathLengthResponse(BaseModel):
    min: int = Field(..., json_schema_extra=1, description="Minimum AS path length in the table")
    avg: float = Field(..., json_schema_extra=3.5, description="Average AS path length in the table")
    max: int = Field(..., json_schema_extra=10, description="Maximum AS path length in the table")


class NoiseConfig(BaseModel):
    PREFIX_BLOCK: int = Field(0, ge=0, json_schema_extra=0, description="Block index inside the full IPv4 space")
    NUMBER_OF_BLOCKS: int = Field(1, ge=1, json_schema_extra=4, description="Total number of blocks used to shard the IPv4 space")
    rate: float = Field(1.0, ge=0.01, json_schema_extra=20, description="Announcements per second")
    lifetime: float = Field(60.0, ge=1.0, json_schema_extra=60, description="Lifetime in seconds for each announced prefix")
    jitter: float = Field(0.5, ge=0.0, le=1.0, json_schema_extra=0.5, description="Relative lifetime variance from zero to one")
    max_active: int = Field(250, ge=1, json_schema_extra=1000, description="Maximum number of active prefixes at any time")


class PcapStartResponse(BaseModel):
    filename: str = Field(..., json_schema_extra="bgp-1726312345.pcap", description="File name of the created capture")


class PcapStopResponse(BaseModel):
    filename: str = Field(..., json_schema_extra="bgp-1726312345.pcap", description="File name of the stopped capture")


class PcapsListResponse(BaseModel):
    files: List[str] = Field(..., json_schema_extra=["bgp-1726312345.pcap"], description="List of available capture files")


class NoiseStartResponse(BaseModel):
    config: NoiseConfig


class NoiseStopResponse(BaseModel):
    cleaned_count: int = Field(..., json_schema_extra=987, description="Number of prefixes removed on stop")


class NoisePauseResponse(BaseModel):
    paused: bool = Field(..., description="True if paused after the call; False if running")


class NoiseStatus(BaseModel):
    running: bool = Field(..., json_schema_extra=True, description="Indicates whether noise generation thread is alive")
    paused: bool = Field(..., json_schema_extra=False, description="Indicates whether noise generation is paused")
    config: Optional[NoiseConfig] = None
    active_count: int = Field(..., json_schema_extra=123, description="Number of active prefixes currently held")

class NoiseDrainRequest(BaseModel):
    count: Optional[int] = Field(None, ge=1, description="Number of prefixes to withdraw")
    percent: Optional[float] = Field(None, ge=0.01, le=100.0, description="Percentage of active prefixes to withdraw")

class NoiseDrainResponse(BaseModel):
    requested: int = Field(..., description="Number of withdrawals requested")
    removed: int = Field(..., description="Number of prefixes actually withdrawn")
    remaining: int = Field(..., description="Number of active prefixes remaining after withdrawal")

class RibDelResult(BaseModel):
    prefix: str = Field(..., description="Prefix that was targeted")
    mode: str = Field(..., description="Deletion mode used")
    identifier: Optional[int] = Field(None, description="Identifier used for selection if present")
    removed_owned: int = Field(..., json_schema_extra=3, description="Count of locally injected paths that were removed")
    not_removed_foreign: int = Field(..., json_schema_extra=2, description="Count of paths not removed because they were learned from peers or CLI")
    remaining_for_prefix: int = Field(..., json_schema_extra=2, description="Total remaining paths for this prefix after deletion")


class RibDelAllResult(BaseModel):
    removed_owned: int = Field(..., json_schema_extra=1200, description="Total removed paths that were locally injected")
    skipped_foreign: int = Field(..., json_schema_extra=340, description="Total paths skipped because they were learned from peers or CLI")
    remaining_paths: int = Field(..., json_schema_extra=340, description="Total remaining paths after deletion of owned paths")


class RibSummaryResponse(BaseModel):
    num_destinations: int = Field(..., json_schema_extra=128, description="Number of destination prefixes in the IPv4 table")
    num_paths: int = Field(..., json_schema_extra=256, description="Number of paths in the IPv4 table")


@asynccontextmanager
async def app_lifespan(app: FastAPI):
    t = threading.Thread(target=neighbor_resolution_loop, daemon=True)
    t.start()
    yield
    shutdown()


tags_metadata = [
    {"name": "RIB", "description": "Routing Information Base operations"},
    {"name": "Noise", "description": "Route noise generation"},
    {"name": "PCAP", "description": "Packet capture management"},
    {"name": "BGP", "description": "Operational BGP views"},
    {"name": "System", "description": "Service utilities and configuration"},
]

app = FastAPI(
    title="GoBGP Lab API",
    description="API for interacting with the GoBGP Lab",
    version="2.1.0",
    swagger_ui_parameters={
        "tryItOutEnabled": True,
        "defaultModelsExpandDepth": 1,
        "displayRequestDuration": True,
    },
    openapi_tags=tags_metadata,
    lifespan=app_lifespan,
)


@app.get("/ip", tags=["System"], summary="Get pod IP", description="Returns the IPv4 address of this pod")
def get_pod_ip():
    return {"pod_ip": POD_IP}


@app.get("/config", tags=["System"], summary="Get current config", description="Returns the current GoBGP configuration file")
def get_config():
    try:
        with open(GOBGP_CONFIG_PATH, "r") as f:
            return {"config": f.read()}
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no config yet")


@app.post(
    "/pcap/start",
    tags=["PCAP"],
    response_model=PcapStartResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start BGP capture",
    description="Starts a capture of BGP traffic and returns the file name",
)
def start_pcap_capture(response: Response):
    global tcpdump_process, current_pcap_filepath
    if tcpdump_process and tcpdump_process.poll() is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="capture already running")
    tcpdump_process, current_pcap_filepath = start_bgp_tcpdump()
    filename = os.path.basename(current_pcap_filepath)
    response.headers["Location"] = f"/pcaps/{filename}"
    return PcapStartResponse(filename=filename)


@app.post(
    "/pcap/stop",
    tags=["PCAP"],
    response_model=PcapStopResponse,
    status_code=status.HTTP_200_OK,
    summary="Stop capture",
    description="Stops the running capture and returns the file name",
)
def stop_pcap_capture():
    fname = stop_bgp_tcpdump()
    if not fname:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="no capture running")
    return PcapStopResponse(filename=fname)


@app.get("/pcaps", tags=["PCAP"], response_model=PcapsListResponse, summary="List captures", description="Lists available capture files")
def list_pcaps_files():
    files = sorted(glob.glob(os.path.join(PCAP_DIR, "*.pcap")))
    return PcapsListResponse(files=[os.path.basename(f) for f in files])


@app.get("/pcaps/{filename}", tags=["PCAP"], summary="Download capture", description="Downloads a capture file by name")
def download_pcap_file(filename: str):
    file_path = os.path.join(PCAP_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="file not found")
    return FileResponse(path=file_path, filename=filename, media_type="application/vnd.tcpdump.pcap")


@app.get("/neighbors", tags=["BGP"], summary="List BGP neighbors", description="Returns the neighbor view from GoBGP")
def get_neighbors():
    res = gobgp.list_neighbors()
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res["error"])
    return res


@app.get("/rib", tags=["RIB"], summary="List RIB paths", description="Returns all paths from the IPv4 global table")
def list_rib():
    res = gobgp.list_rib_ipv4()
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res["error"])
    return res


@app.get("/rib/summary", tags=["RIB"], response_model=RibSummaryResponse, summary="RIB summary", description="Returns counters for destinations and paths in the IPv4 table")
def get_rib_summary():
    res = gobgp.rib_summary_ipv4()
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res["error"])
    return RibSummaryResponse(**res)


@app.post(
    "/rib/add",
    tags=["RIB"],
    response_model=RibAddResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Add route",
    description="Adds a route to the IPv4 table",
)
def add_rib_entry(body: RibAddRequest):
    try:
        ipaddress.ip_network(body.prefix, strict=False)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid prefix")
    res = gobgp.add_route_ipv4(body.prefix, body.next_hop, body.as_path, body.community, body.identifier)
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res["error"])
    return RibAddResponse(**res)


@app.post(
    "/rib/del",
    tags=["RIB"],
    response_model=RibDelResult,
    status_code=status.HTTP_200_OK,
    summary="Delete prefix",
    description="Deletes owned paths for the given prefix",
)
def delete_rib_prefix(body: RibDelRequest):
    try:
        ipaddress.ip_network(body.prefix, strict=False)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid prefix")
    res = gobgp.del_route_ipv4(body.prefix, body.identifier)
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res["error"])
    if res.get("removed_owned", 0) == 0 and res.get("not_removed_foreign", 0) == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={"prefix": body.prefix, "note": "no matching paths"})
    return RibDelResult(**res)

@app.get(
    "/rib/pathlengths",
    tags=["RIB"],
    response_model=RibPathLengthResponse,
    summary="RIB path length stats",
    description="Returns min/avg/max AS path length across all IPv4 RIB entries"
)
def get_rib_pathlengths():
    res = gobgp.list_rib_ipv4()
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res["error"])

    lengths = []
    for entry in res:
        dest = entry.get("destination", {})
        for path in dest.get("paths", []):
            for pattr in path.get("pattrs", []):
                if "asPath" in pattr:
                    for seg in pattr["asPath"].get("segments", []):
                        nums = seg.get("numbers", [])
                        if nums:
                            lengths.append(len(nums))

    if not lengths:
        return RibPathLengthResponse(min=0, avg=0.0, max=0)

    return RibPathLengthResponse(
        min=min(lengths),
        avg=sum(lengths) / len(lengths),
        max=max(lengths),
    )

@app.delete("/rib", tags=["RIB"], response_model=RibDelAllResult, status_code=status.HTTP_200_OK, summary="Delete all owned", description="Deletes all locally injected paths and reports remaining foreign paths")
def delete_all_rib():
    res = gobgp.del_all_routes_ipv4()
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res["error"])
    return RibDelAllResult(**res)


@app.post(
    "/noise/start",
    tags=["Noise"],
    response_model=NoiseStartResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start noise",
    description="Starts route noise generation with the given parameters",
)
def start_noise(cfg: NoiseConfig):
    global noise_thread, noise_runtime_config, noise_stop_event, noise_pause_event, noise_pause_started_at
    if noise_thread and noise_thread.is_alive():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"error": "noise already running", "config": noise_runtime_config})
    noise_runtime_config = cfg.model_dump()
    noise_stop_event.clear()
    noise_pause_event.clear()
    noise_pause_started_at = None
    t = threading.Thread(target=noise_worker, daemon=True)
    t.start()
    globals()["noise_thread"] = t
    return NoiseStartResponse(config=cfg)


@app.post("/noise/stop", tags=["Noise"], response_model=NoiseStopResponse, status_code=status.HTTP_200_OK, summary="Stop noise", description="Stops noise generation and cleans up active prefixes")
def stop_noise():
    global noise_thread, noise_stop_event, noise_active_prefixes
    if not noise_thread or not noise_thread.is_alive():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="noise not running")
    noise_stop_event.set()
    noise_thread.join(timeout=2)
    cleaned_count = 0
    with noise_lock:
        for prefix, (_, ident) in list(noise_active_prefixes.items()):
            gobgp.del_route_ipv4(str(prefix), identifier=ident if ident else None)
            cleaned_count += 1
        noise_active_prefixes.clear()
    return NoiseStopResponse(cleaned_count=cleaned_count)


@app.post("/noise/pause", tags=["Noise"], response_model=NoisePauseResponse, status_code=status.HTTP_200_OK, summary="Pause noise", description="Pauses noise generation without withdrawing existing prefixes")
def pause_noise():
    global noise_thread, noise_pause_event, noise_pause_started_at
    if not noise_thread or not noise_thread.is_alive():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="noise not running")
    if not noise_pause_event.is_set():
        noise_pause_started_at = time.time()
        noise_pause_event.set()
    return NoisePauseResponse(paused=True)


@app.post("/noise/resume", tags=["Noise"], response_model=NoisePauseResponse, status_code=status.HTTP_200_OK, summary="Resume noise", description="Resumes noise generation and shifts expirations by pause duration")
def resume_noise():
    global noise_thread, noise_pause_event, noise_pause_started_at, noise_active_prefixes
    if not noise_thread or not noise_thread.is_alive():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="noise not running")
    if noise_pause_event.is_set():
        paused_duration = max(0.0, time.time() - (noise_pause_started_at or time.time()))
        with noise_lock:
            for pfx, (exp, ident) in list(noise_active_prefixes.items()):
                noise_active_prefixes[pfx] = (exp + paused_duration, ident)
        noise_pause_event.clear()
        noise_pause_started_at = None
    return NoisePauseResponse(paused=False)


@app.get("/noise/status", tags=["Noise"], response_model=NoiseStatus, status_code=status.HTTP_200_OK, summary="Noise status", description="Returns whether noise is running/paused and the count of active prefixes")
def get_noise_status():
    running = noise_thread is not None and noise_thread.is_alive()
    paused = noise_pause_event.is_set()
    with noise_lock:
        active_count = len(noise_active_prefixes)
    return NoiseStatus(running=running, paused=paused, config=noise_runtime_config if running else None, active_count=active_count)


def shutdown(*_):
    global gobgp_daemon_process
    stop_bgp_tcpdump()
    if gobgp_daemon_process and gobgp_daemon_process.poll() is None:
        try:
            gobgp_daemon_process.send_signal(signal.SIGTERM)
            gobgp_daemon_process.wait(timeout=10)
        except Exception:
            pass
    noise_stop_event.set()
    with noise_lock:
        for prefix, (_, ident) in list(noise_active_prefixes.items()):
            gobgp.del_route_ipv4(str(prefix), identifier=ident if ident else None)
        noise_active_prefixes.clear()
    gobgp.close()
    raise SystemExit(0)

@app.post(
    "/noise/drain",
    tags=["Noise"],
    response_model=NoiseDrainResponse,
    status_code=status.HTTP_200_OK,
    summary="Partial noise drain",
    description="Withdraws a specified number or percentage of currently active noise prefixes",
)
def drain_noise(body: NoiseDrainRequest):
    with noise_lock:
        active = list(noise_active_prefixes.items())

    if not active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no active noise prefixes")

    if body.count is not None:
        target_count = min(body.count, len(active))
    elif body.percent is not None:
        target_count = max(1, int(len(active) * (body.percent / 100.0)))
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="must specify either count or percent")

    to_remove = random.sample(active, target_count)

    removed = 0
    for prefix, (_, ident) in to_remove:
        res = gobgp.del_route_ipv4(str(prefix), identifier=ident if ident else None)
        if not (isinstance(res, dict) and "error" in res):
            removed += 1
            with noise_lock:
                noise_active_prefixes.pop(prefix, None)

    with noise_lock:
        remaining = len(noise_active_prefixes)

    return NoiseDrainResponse(requested=target_count, removed=removed, remaining=remaining)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    uvicorn.run(app, host="0.0.0.0", port=8080)
