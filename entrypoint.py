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
from fastapi import Body, FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from google.protobuf.json_format import MessageToDict

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

neighbor_state_by_name: Dict[str, Dict[str, Any]] = {}
gobgpd_process: Optional[subprocess.Popen] = None
tcpdump_process: Optional[subprocess.Popen] = None
current_pcap_file: Optional[str] = None
neighbor_state_lock = threading.Lock()

noise_thread: Optional[threading.Thread] = None
noise_stop_event = threading.Event()
noise_config: Dict[str, Any] = {}
noise_active_prefixes: Dict[ipaddress.IPv4Network, Tuple[float, int]] = {}
noise_lock = threading.Lock()


def _community_to_u32(comm: str) -> int:
    left, right = comm.split(":")
    return (int(left) << 16) | int(right)


def _ipv4_family() -> common_pb2.Family:
    return common_pb2.Family(afi=common_pb2.Family.AFI_IP, safi=common_pb2.Family.SAFI_UNICAST)


def _nlri_prefix(prefix: str) -> nlri_pb2.NLRI:
    net = ipaddress.ip_network(prefix, strict=False)
    return nlri_pb2.NLRI(prefix=nlri_pb2.IPAddressPrefix(prefix_len=net.prefixlen, prefix=str(net.network_address)))


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

    def close(self):
        try:
            self.channel.close()
        except Exception:
            pass

    def _unary(self, method, request):
        last_exc: Optional[grpc.RpcError] = None
        for attempt in range(self.retries):
            try:
                return method(request, timeout=self.timeout, wait_for_ready=True)
            except grpc.RpcError as e:
                if e.code() in self.RETRYABLE and attempt < self.retries - 1:
                    time.sleep(self.backoff * (2**attempt))
                    continue
                last_exc = e
                break
        raise last_exc  # type: ignore

    def _stream_list(self, method, request):
        last_exc: Optional[grpc.RpcError] = None
        for attempt in range(self.retries):
            try:
                return list(method(request, timeout=self.timeout, wait_for_ready=True))
            except grpc.RpcError as e:
                if e.code() in self.RETRYABLE and attempt < self.retries - 1:
                    time.sleep(self.backoff * (2**attempt))
                    continue
                last_exc = e
                break
        raise last_exc  # type: ignore

    def neighbors(self):
        try:
            resps = self._stream_list(self.stub.ListPeer, pb.ListPeerRequest())
            return [MessageToDict(resp.peer) for resp in resps]
        except grpc.RpcError as e:
            return {"error": f"{e.code().name}: {e.details()}"}

    def list_rib_ipv4(self):
        try:
            req = pb.ListPathRequest(table_type=pb.TABLE_TYPE_GLOBAL, family=_ipv4_family())
            resps = self._stream_list(self.stub.ListPath, req)
            return [MessageToDict(r) for r in resps]
        except grpc.RpcError as e:
            return {"error": f"{e.code().name}: {e.details()}"}

    def rib_summary_ipv4(self):
        try:
            req = pb.GetTableRequest(table_type=pb.TABLE_TYPE_GLOBAL, family=_ipv4_family())
            resp = self._unary(self.stub.GetTable, req)
            return {"num_destinations": resp.num_destination, "num_paths": resp.num_path}
        except grpc.RpcError as e:
            return {"error": f"{e.code().name}: {e.details()}"}

    def add_route_ipv4(
        self,
        prefix: str,
        nexthop: str,
        aspath: Optional[List[int]] = None,
        community: Optional[str] = None,
        identifier: Optional[int] = None,
    ):
        try:
            pattrs: List[attr_pb2.Attribute] = [
                attr_pb2.Attribute(origin=attr_pb2.OriginAttribute(origin=0)),
                attr_pb2.Attribute(next_hop=attr_pb2.NextHopAttribute(next_hop=nexthop)),
            ]
            if aspath:
                seg = attr_pb2.AsSegment(type=attr_pb2.AsSegment.TYPE_AS_SEQUENCE, numbers=[int(a) for a in aspath])
                pattrs.append(attr_pb2.Attribute(as_path=attr_pb2.AsPathAttribute(segments=[seg])))
            if community:
                pattrs.append(
                    attr_pb2.Attribute(
                        communities=attr_pb2.CommunitiesAttribute(communities=[_community_to_u32(community)])
                    )
                )
            path = pb.Path(nlri=_nlri_prefix(prefix), pattrs=pattrs, family=_ipv4_family())
            if identifier is not None:
                path.identifier = int(identifier)
            req = pb.AddPathRequest(table_type=pb.TABLE_TYPE_GLOBAL, path=path)
            resp = self._unary(self.stub.AddPath, req)
            return {"uuid": list(resp.uuid)}
        except grpc.RpcError as e:
            return {"error": f"{e.code().name}: {e.details()}"}

    def _paths_for_prefix(self, prefix: str) -> List[Tuple[str, pb.Path]]:
        req = pb.ListPathRequest(
            table_type=pb.TABLE_TYPE_GLOBAL,
            family=_ipv4_family(),
            prefixes=[pb.TableLookupPrefix(prefix=prefix, type=pb.TableLookupPrefix.TYPE_EXACT)],
        )
        resps = self._stream_list(self.stub.ListPath, req)
        out: List[Tuple[str, pb.Path]] = []
        for resp in resps:
            dest = resp.destination
            for p in dest.paths:
                out.append((dest.prefix, p))
        return out

    @staticmethod
    def _extract_next_hop(p: pb.Path) -> Optional[str]:
        for a in p.pattrs:
            if a.HasField("next_hop"):
                return a.next_hop.next_hop
        return None

    def del_route_ipv4(self, prefix: str, identifier: Optional[int] = None):
        try:
            paths = self._paths_for_prefix(prefix)
            if not paths:
                return {"deleted": 0, "prefix": prefix, "note": "no matching paths"}
            targets: List[pb.Path] = []
            if identifier is not None:
                ident = int(identifier)
                for _, p in paths:
                    if getattr(p, "identifier", 0) == ident or getattr(p, "local_identifier", 0) == ident:
                        targets.append(p)
                if not targets:
                    return {"deleted": 0, "prefix": prefix, "identifier": ident, "note": "identifier not found"}
            else:
                targets = [p for _, p in paths]
            deleted = 0
            for p in targets:
                nh = self._extract_next_hop(p)
                if not nh:
                    continue
                del_path = pb.Path(
                    nlri=_nlri_prefix(prefix),
                    pattrs=[attr_pb2.Attribute(next_hop=attr_pb2.NextHopAttribute(next_hop=nh))],
                    family=_ipv4_family(),
                )
                if identifier is not None:
                    del_path.identifier = int(identifier)
                self._unary(
                    self.stub.DeletePath,
                    pb.DeletePathRequest(table_type=pb.TABLE_TYPE_GLOBAL, family=_ipv4_family(), path=del_path),
                )
                deleted += 1
            remaining = []
            for _, p in self._paths_for_prefix(prefix):
                if identifier is None or getattr(p, "identifier", 0) == int(identifier) or getattr(
                    p, "local_identifier", 0
                ) == int(identifier):
                    remaining.append(p)
            return {
                "deleted": deleted,
                "remaining": len(remaining),
                "prefix": prefix,
                "mode": "identifier" if identifier is not None else "all-for-prefix",
                "identifier": int(identifier) if identifier is not None else None,
            }
        except grpc.RpcError as e:
            return {"error": f"{e.code().name}: {e.details()}"}

    def del_all_routes_ipv4(self):
        try:
            req = pb.ListPathRequest(table_type=pb.TABLE_TYPE_GLOBAL, family=_ipv4_family())
            resps = self._stream_list(self.stub.ListPath, req)
            targets: List[Tuple[str, Optional[str]]] = []
            scanned = 0
            for resp in resps:
                dest = resp.destination
                for p in dest.paths:
                    scanned += 1
                    nh = self._extract_next_hop(p)
                    targets.append((dest.prefix, nh))
            deleted = 0
            for prefix, nh in targets:
                if not nh:
                    continue
                del_path = pb.Path(
                    nlri=_nlri_prefix(prefix),
                    pattrs=[attr_pb2.Attribute(next_hop=attr_pb2.NextHopAttribute(next_hop=nh))],
                    family=_ipv4_family(),
                )
                self._unary(
                    self.stub.DeletePath,
                    pb.DeletePathRequest(table_type=pb.TABLE_TYPE_GLOBAL, family=_ipv4_family(), path=del_path),
                )
                deleted += 1
            remaining_total = 0
            for _ in self._stream_list(self.stub.ListPath, pb.ListPathRequest(table_type=pb.TABLE_TYPE_GLOBAL, family=_ipv4_family())):
                remaining_total += 1
            return {"deleted": deleted, "scanned_paths": scanned, "remaining_paths": remaining_total}
        except grpc.RpcError as e:
            return {"error": f"{e.code().name}: {e.details()}"}


gobgp = GoBGPRpc()


def parse_neighbors_json(raw_json: str) -> Dict[str, Dict[str, Any]]:
    parsed = json.loads(raw_json)
    neighbors: Dict[str, Dict[str, Any]] = {}
    for neighbor in parsed:
        neighbor_name = neighbor["name"]
        peer_asn = int(neighbor["peerAs"])
        community_tags = [int(tag) for tag in neighbor.get("communitiesAddTags", [])]
        neighbors[neighbor_name] = {"peerAs": peer_asn, "tags": community_tags, "ip": None}
    return neighbors


NEIGHBOR_TEMPLATE = parse_neighbors_json(NEIGHBORS_JSON_RAW)


def resolve_neighbor_ip_address(neighbor_name: str) -> Optional[str]:
    service_fqdn = f"{neighbor_name}.{KUBE_NAMESPACE}.svc"
    try:
        ip_address = subprocess.check_output(["getent", "hosts", service_fqdn], text=True).split()[0]
        return ip_address
    except subprocess.CalledProcessError:
        return None


def write_gobgp_config_file() -> None:
    with neighbor_state_lock:
        neighbors_snapshot = {name: data.copy() for name, data in neighbor_state_by_name.items()}
    tags_by_peer_asn: Dict[int, Set[int]] = {}
    for neighbor_data in neighbors_snapshot.values():
        tags_by_peer_asn.setdefault(neighbor_data["peerAs"], set()).update(neighbor_data.get("tags", []))
    peer_asns_with_tags = sorted(asn for asn, tags in tags_by_peer_asn.items() if tags)
    import_policy_names = ", ".join([f'"{f"tag-from-as{peer_asn}"}"' for peer_asn in peer_asns_with_tags])
    config_lines: List[str] = []
    config_lines += [
        "[global.config]",
        f"  as = {LOCAL_ASN}",
        f'  router-id = "{ROUTER_ID}"',
        "",
        "[global.apply-policy.config]",
        f"  import-policy-list = [{import_policy_names}]",
        '  default-import-policy = "accept-route"',
        "",
    ]
    for peer_asn in peer_asns_with_tags:
        config_lines += [
            "[[defined-sets.bgp-defined-sets.as-path-sets]]",
            f'  as-path-set-name = "from-as{peer_asn}"',
            f'  as-path-list = ["^{peer_asn}$", "^{peer_asn}_"]',
            "",
        ]
        tag_set = tags_by_peer_asn[peer_asn]
        config_lines += [
            "[[policy-definitions]]",
            f'  name = "tag-from-as{peer_asn}"',
            "  [[policy-definitions.statements]]",
            f'    name = "tag-{LOCAL_ASN}-from-as{peer_asn}"',
            "    [policy-definitions.statements.conditions.bgp-conditions.match-as-path-set]",
            f'      as-path-set = "from-as{peer_asn}"',
            '      match-set-options = "any"',
            "    [policy-definitions.statements.actions]",
            '      route-disposition = "accept-route"',
        ]
        communities_literal = ", ".join([f'"{LOCAL_ASN}:{tag}"' for tag in sorted(tag_set)])
        config_lines += [
            "    [policy-definitions.statements.actions.bgp-actions.set-community]",
            '      options = "add"',
            "      [policy-definitions.statements.actions.bgp-actions.set-community.set-community-method]",
            f"        communities-list = [{communities_literal}]",
            "",
        ]
    for neighbor_name, neighbor_data in neighbors_snapshot.items():
        ip_address = neighbor_data.get("ip")
        if not ip_address:
            continue
        peer_asn = neighbor_data["peerAs"]
        is_passive_mode = "true" if peer_asn > LOCAL_ASN else "false"
        config_lines += [
            "[[neighbors]]",
            "  [neighbors.config]",
            f'    neighbor-address = "{ip_address}"',
            f"    peer-as = {peer_asn}",
            "  [neighbors.transport.config]",
            f"    passive-mode = {is_passive_mode}",
            "  [neighbors.add-paths.config]",
            "    receive = true",
            "    send-max = 3",
            "  [[neighbors.afi-safis]]",
            "    [neighbors.afi-safis.config]",
            '      afi-safi-name = "ipv4-unicast"',
            "",
        ]
    os.makedirs(os.path.dirname(GOBGP_CONFIG_PATH), exist_ok=True)
    with open(GOBGP_CONFIG_PATH, "w") as f:
        f.write("\n".join(config_lines))


def restart_gobgpd() -> None:
    global gobgpd_process
    if gobgpd_process and gobgpd_process.poll() is None:
        gobgpd_process.send_signal(signal.SIGTERM)
        try:
            gobgpd_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            gobgpd_process.kill()
            gobgpd_process.wait()
    gobgpd_process = subprocess.Popen(["gobgpd", "--api-hosts", GOBGP_API_ADDR, "-f", GOBGP_CONFIG_PATH])


def neighbor_resolution_polling_loop() -> None:
    with neighbor_state_lock:
        neighbor_state_by_name.update(NEIGHBOR_TEMPLATE)
    is_first_render = True
    while True:
        has_changes = False
        for neighbor_name in list(neighbor_state_by_name.keys()):
            resolved_ip = resolve_neighbor_ip_address(neighbor_name)
            with neighbor_state_lock:
                prev_ip = neighbor_state_by_name[neighbor_name].get("ip")
                if resolved_ip != prev_ip:
                    neighbor_state_by_name[neighbor_name]["ip"] = resolved_ip
                    has_changes = True
        if has_changes or is_first_render:
            if any(n.get("ip") for n in neighbor_state_by_name.values()):
                write_gobgp_config_file()
                restart_gobgpd()
                is_first_render = False
        time.sleep(2)


def start_tcpdump() -> Tuple[subprocess.Popen, str]:
    os.makedirs(PCAP_DIR, exist_ok=True)
    pcap_file = os.path.join(PCAP_DIR, f"bgp-{int(time.time())}.pcap")
    proc = subprocess.Popen(["tcpdump", "-i", "any", "port", "179", "-w", pcap_file], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    return proc, pcap_file


def stop_tcpdump():
    global tcpdump_process, current_pcap_file
    if tcpdump_process and tcpdump_process.poll() is None:
        tcpdump_process.terminate()
        tcpdump_process.wait()
        fname = os.path.basename(current_pcap_file) if current_pcap_file else None
        tcpdump_process = None
        current_pcap_file = None
        return fname
    return None


def realistic_prefixlen() -> int:
    r = random.random()
    if r < 0.6:
        return 24
    if r < 0.8:
        return random.choice([22, 23])
    if r < 0.95:
        return random.choice([20, 21])
    return random.randint(16, 19)


def _rand_subnet(start: int, end: int, active: dict) -> Tuple[Optional[str], Optional[ipaddress.IPv4Network]]:
    for _ in range(1000):
        plen = realistic_prefixlen()
        size = 1 << (32 - plen)
        base = random.randint(start // size, (end // size) - 1) * size
        prefix = ipaddress.ip_network((base, plen))
        if not any(prefix.overlaps(a) for a in active.keys()):
            return str(prefix), prefix
    return None, None


def noise_worker():
    global noise_config, noise_active_prefixes
    PREFIX_BLOCK = int(noise_config.get("PREFIX_BLOCK", 0))
    NUMBER_OF_BLOCKS = int(noise_config.get("NUMBER_OF_BLOCKS", 1))
    rate = float(noise_config.get("rate", 1))
    lifetime = float(noise_config.get("lifetime", 60))
    jitter = float(noise_config.get("jitter", 0.5))
    max_active = int(noise_config.get("max_active", 250))
    total_space = 1 << 32
    block_size = total_space // NUMBER_OF_BLOCKS
    start = PREFIX_BLOCK * block_size
    end = total_space if PREFIX_BLOCK == NUMBER_OF_BLOCKS - 1 else start + block_size
    with noise_lock:
        noise_active_prefixes.clear()
    while not noise_stop_event.is_set():
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
                prefix_str, prefix_obj = _rand_subnet(start, end, noise_active_prefixes)
                if prefix_str:
                    ident = random.randint(1, 2**31 - 1)
                    res = gobgp.add_route_ipv4(prefix_str, POD_IP, identifier=ident)
                    if isinstance(res, dict) and "error" not in res:
                        delta = lifetime * (1 + random.uniform(-jitter, jitter))
                        noise_active_prefixes[prefix_obj] = (now + delta, ident)
        noise_stop_event.wait(1.0 / rate)


@asynccontextmanager
async def lifespan(app: FastAPI):
    t = threading.Thread(target=neighbor_resolution_polling_loop, daemon=True)
    t.start()
    yield
    _shutdown()


app = FastAPI(lifespan=lifespan)


@app.get("/ip")
def http_ip():
    return {"pod_ip": POD_IP}


@app.get("/config")
def http_config():
    try:
        with open(GOBGP_CONFIG_PATH, "r") as f:
            return {"config": f.read()}
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no config yet")


@app.post("/pcap/start")
def http_start_pcap():
    global tcpdump_process, current_pcap_file
    if tcpdump_process and tcpdump_process.poll() is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="capture already running")
    tcpdump_process, current_pcap_file = start_tcpdump()
    return {"started": os.path.basename(current_pcap_file)}


@app.post("/pcap/stop")
def http_stop_pcap():
    fname = stop_tcpdump()
    if not fname:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="no capture running")
    return {"stopped": fname}


@app.get("/pcaps")
def list_pcaps():
    files = sorted(glob.glob(os.path.join(PCAP_DIR, "*.pcap")))
    return {"files": [os.path.basename(f) for f in files]}


@app.get("/pcaps/{filename}")
def download_pcap(filename: str):
    file_path = os.path.join(PCAP_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="file not found")
    return FileResponse(path=file_path, filename=filename, media_type="application/vnd.tcpdump.pcap")


@app.get("/neighbors")
def http_neighbors():
    res = gobgp.neighbors()
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res["error"])
    return res


@app.get("/rib")
def http_rib():
    res = gobgp.list_rib_ipv4()
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res["error"])
    return res


@app.get("/rib/summary")
def http_rib_summary():
    res = gobgp.rib_summary_ipv4()
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res["error"])
    return res


@app.post("/rib/add")
def http_rib_add(
    prefix: str = Body(..., embed=True),
    nexthop: str = Body(..., embed=True),
    aspath: Optional[List[int]] = Body(None, embed=True),
    community: Optional[str] = Body(None, embed=True),
    identifier: Optional[int] = Body(None, embed=True),
):
    try:
        ipaddress.ip_network(prefix, strict=False)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid prefix")
    res = gobgp.add_route_ipv4(prefix, nexthop, aspath, community, identifier)
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res["error"])
    return res


@app.post("/rib/del")
def http_rib_del(
    prefix: str = Body(..., embed=True),
    identifier: Optional[int] = Body(None, embed=True),
):
    try:
        ipaddress.ip_network(prefix, strict=False)
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid prefix")
    res = gobgp.del_route_ipv4(prefix, identifier)
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res["error"])
    if res.get("deleted", 0) == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=res)
    if res.get("remaining", 0) > 0:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res)
    return res


@app.delete("/rib")
def http_rib_del_all():
    res = gobgp.del_all_routes_ipv4()
    if isinstance(res, dict) and "error" in res:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res["error"])
    if res.get("remaining_paths", 0) > 0:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=res)
    return res


@app.post("/noise/start")
def http_noise_start(cfg: Dict[str, Any] = Body(...)):
    global noise_thread, noise_config, noise_stop_event
    if noise_thread and noise_thread.is_alive():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"error": "noise already running", "config": noise_config})
    noise_config = cfg
    noise_stop_event.clear()
    noise_thread = threading.Thread(target=noise_worker, daemon=True)
    noise_thread.start()
    return {"started": True, "config": noise_config}


@app.post("/noise/stop")
def http_noise_stop():
    global noise_thread, noise_stop_event, noise_active_prefixes
    if not noise_thread or not noise_thread.is_alive():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="noise not running")
    noise_stop_event.set()
    noise_thread.join(timeout=2)
    with noise_lock:
        for prefix, (_, ident) in list(noise_active_prefixes.items()):
            gobgp.del_route_ipv4(str(prefix), identifier=ident if ident else None)
        noise_active_prefixes.clear()
    return {"stopped": True, "cleaned": True}


@app.get("/noise/status")
def http_noise_status():
    running = noise_thread is not None and noise_thread.is_alive()
    return {
        "running": running,
        "config": noise_config if running else None,
        "active_prefixes": [{"prefix": str(p), "identifier": ident, "expires_in": max(0, int(exp - time.time()))} for p, (exp, ident) in noise_active_prefixes.items()],
    }


def _shutdown(*_):
    global gobgpd_process
    stop_tcpdump()
    if gobgpd_process and gobgpd_process.poll() is None:
        try:
            gobgpd_process.send_signal(signal.SIGTERM)
            gobgpd_process.wait(timeout=10)
        except Exception:
            pass
    noise_stop_event.set()
    with noise_lock:
        for prefix, (_, ident) in list(noise_active_prefixes.items()):
            gobgp.del_route_ipv4(str(prefix), identifier=ident if ident else None)
        noise_active_prefixes.clear()
    gobgp.close()
    raise SystemExit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    uvicorn.run(app, host="0.0.0.0", port=8080)
