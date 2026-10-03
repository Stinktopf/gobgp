"""Router controller of the emulation lab.

Runs next to gobgpd in every router pod: it configures and runs gobgpd,
injects route noise on origin routers, applies the failures and policy
changes of scenarios, and exposes the counters the lab samples.
"""

import gzip
import io
import ipaddress
import itertools
import json
import math
import os
import random
import signal
import socket
import subprocess
import threading
import time
import urllib.request
from collections import deque
from contextlib import asynccontextmanager
from typing import Literal

import grpc
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from google.protobuf.json_format import MessageToDict
from pydantic import BaseModel, Field

from api import attribute_pb2, common_pb2, gobgp_pb2, gobgp_pb2_grpc, nlri_pb2

POD_IP = os.environ["POD_IP"]
ROUTER_NAME = os.environ["ROUTER_NAME"]
ASN = int(os.environ["ASN"])
ROUTER_ID = os.environ["ROUTER_ID"]
NAMESPACE = os.environ["POD_NAMESPACE"]
NEIGHBORS = json.loads(os.environ["NEIGHBORS_JSON"])
# Set by the chart from the experiment; a missing one fails at the start.
SEED = os.environ["LAB_SEED"]
TIMERS = {k: int(os.environ[k.upper()]) for k in ("hold_time", "keepalive", "connect_retry")}
GRACEFUL = os.environ["GRACEFUL_RESTART"] == "true"

# Gao-Rexford: a neighbor's relation to this router gives the Local
# Preference of its routes, unless the topology sets one, and a community
# that says where a route was learned. Routes of peers and providers are
# not exported to peers and providers.
PREFERENCE = {"customer": 200, "peer": 150, "provider": 100}
LEARNED = {"customer": "64999:1", "peer": "64999:2", "provider": "64999:3"}

GOBGP_API = "127.0.0.1:50051"
GOBGP_METRICS = "http://127.0.0.1:6060/metrics"  # gobgpd's default
GOBGP_CONFIG = "/etc/gobgp/gobgp.conf"
IPV4 = common_pb2.Family(afi=common_pb2.Family.AFI_IP, safi=common_pb2.Family.SAFI_UNICAST)
GLOBAL = gobgp_pb2.TABLE_TYPE_GLOBAL

stub = gobgp_pb2_grpc.GoBgpServiceStub(grpc.insecure_channel(GOBGP_API))


# gobgpd


def resolve_neighbors() -> dict[str, str]:
    """Waits until every neighbor service resolves and returns name -> IP."""
    addresses: dict[str, str] = {}
    while len(addresses) < len(NEIGHBORS):
        for n in NEIGHBORS:
            if n["name"] not in addresses:
                try:
                    addresses[n["name"]] = socket.gethostbyname(f"{n['name']}.{NAMESPACE}.svc")
                except OSError:
                    pass
        time.sleep(1)
    return addresses


class Daemon:
    """gobgpd, its configuration and the policies scenarios change at runtime.

    A crash ends the pod, since measurements assume one lifetime of the
    daemon; scenarios stop and start it on purpose.
    """

    def __init__(self) -> None:
        self.process: subprocess.Popen | None = None
        self.addresses: dict[str, str] = {}
        self.preferences = {n["name"]: n.get("localPref") for n in NEIGHBORS}
        self.relations = {n["name"]: n.get("relation") for n in NEIGHBORS}
        self.prepend = 0
        self.denied: set[str] = set()  # neighbors no routes are exported to
        self.revision = 0  # of the configuration, to know when gobgpd took it
        self.started = 0.0  # when gobgpd last started, by the wall clock
        self.lock = threading.Lock()

    def boot(self) -> None:
        self.addresses = resolve_neighbors()
        self.start()
        threading.Thread(target=self._watch, daemon=True).start()

    def _watch(self) -> None:
        while True:
            process = self.process
            if process and process.poll() is not None and process is self.process:
                os._exit(1)
            time.sleep(0.5)

    def start(self, graceful: bool = False) -> None:
        """Starts gobgpd; graceful flags the restart to the peers, which then
        keep its routes until it sent them all again."""
        with self.lock:
            if self.process and self.process.poll() is None:
                return
            self._write()
            flags = ["-r"] if graceful else []
            self.process = subprocess.Popen(["gobgpd", "--api-hosts", GOBGP_API, "-f", GOBGP_CONFIG, *flags])
            self.started = time.time()

    def running(self) -> bool:
        process = self.process
        return process is not None and process.poll() is None

    def stop(self, kill: bool = False) -> None:
        """Stops gobgpd. It closes its sessions with a notification; killed, it
        just ends, as a crash does, which peers may take as a graceful restart."""
        with self.lock:
            process, self.process = self.process, None
            if process:
                process.kill() if kill else process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def reload(self, export: bool = False) -> None:
        """Applies changed policies. gobgpd reloads its configuration on SIGHUP
        and then asks its peers for their routes again (soft reset in). A
        changed export policy also needs a soft reset out, once gobgpd took
        the new configuration."""
        with self.lock:
            self.revision += 1
            self._write()
            if not self.process:
                return
            self.process.send_signal(signal.SIGHUP)
        if export:
            self._await_revision()
            stub.ResetPeer(gobgp_pb2.ResetPeerRequest(address="all", soft=True, direction=gobgp_pb2.ResetPeerRequest.DIRECTION_OUT), timeout=10)

    def _await_revision(self, timeout: float = 10) -> None:
        """Waits until the export policies of gobgpd begin with this revision."""
        request = gobgp_pb2.ListPolicyAssignmentRequest(name="global", direction=gobgp_pb2.POLICY_DIRECTION_EXPORT)
        deadline = time.monotonic() + timeout
        while True:
            for r in stub.ListPolicyAssignment(request, timeout=5):
                if any(p.name == f"rev-{self.revision}" for p in r.assignment.policies):
                    return
            if time.monotonic() > deadline:
                raise HTTPException(503, "gobgpd did not take the new policies")
            time.sleep(0.05)

    def _write(self) -> None:
        os.makedirs(os.path.dirname(GOBGP_CONFIG), exist_ok=True)
        with open(GOBGP_CONFIG, "w") as f:
            f.write(self.render())

    def render(self) -> str:
        lines = ["[global.config]", f"  as = {ASN}", f'  router-id = "{ROUTER_ID}"', ""]
        for name in self.addresses:
            lines += ["[[defined-sets.neighbor-sets]]", f'  neighbor-set-name = "{name}"', f'  neighbor-info-list = ["{self.addresses[name]}"]', ""]
        # Matches nothing; once gobgpd lists it, it runs this configuration.
        lines += ["[[defined-sets.neighbor-sets]]", f'  neighbor-set-name = "rev-{self.revision}"', '  neighbor-info-list = ["192.0.2.1/32"]', ""]
        lines += self._policy(f"rev-{self.revision}", f"rev-{self.revision}", "reject-route")
        imports, exports = [], [f'"rev-{self.revision}"']

        for name in self.addresses:
            relation, pref = self.relations.get(name), self.preferences.get(name)
            pref = pref or PREFERENCE.get(relation)
            if not pref and not relation:
                continue
            imports.append(f'"in-{name}"')
            actions = [f"      set-local-pref = {int(pref)}"] if pref else []
            if relation:
                actions += ["    [policy-definitions.statements.actions.bgp-actions.set-community]",
                            '      options = "replace"',
                            "      [policy-definitions.statements.actions.bgp-actions.set-community.set-community-method]",
                            f'        communities-list = ["{LEARNED[relation]}"]']
            lines += self._policy(f"in-{name}", name, "accept-route", actions)

        for name in sorted(self.denied):
            exports.append(f'"deny-{name}"')
            lines += self._policy(f"deny-{name}", name, "reject-route")

        up = [n for n, r in self.relations.items() if r in ("peer", "provider") and n in self.addresses]
        if up:
            exports.append('"valley-free"')
            lines += [
                "[[defined-sets.neighbor-sets]]",
                '  neighbor-set-name = "peers-and-providers"',
                f"  neighbor-info-list = {json.dumps([self.addresses[n] for n in up])}",
                "[[defined-sets.bgp-defined-sets.community-sets]]",
                '  community-set-name = "learned-up"',
                f'  community-list = ["{LEARNED["peer"]}", "{LEARNED["provider"]}"]',
                "[[policy-definitions]]",
                '  name = "valley-free"',
                "  [[policy-definitions.statements]]",
                "    [policy-definitions.statements.conditions.match-neighbor-set]",
                '      neighbor-set = "peers-and-providers"',
                "    [policy-definitions.statements.conditions.bgp-conditions.match-community-set]",
                '      community-set = "learned-up"',
                "    [policy-definitions.statements.actions]",
                '      route-disposition = "reject-route"',
                "",
            ]

        if self.prepend:
            exports.append('"prepend"')
            lines += [
                "[[policy-definitions]]",
                '  name = "prepend"',
                "  [[policy-definitions.statements]]",
                "    [policy-definitions.statements.actions]",
                '      route-disposition = "accept-route"',
                "    [policy-definitions.statements.actions.bgp-actions.set-as-path-prepend]",
                f'      as = "{ASN}"',
                f"      repeat-n = {self.prepend}",
                "",
            ]
        lines += [
            "[global.apply-policy.config]",
            f"  import-policy-list = [{', '.join(imports)}]",
            '  default-import-policy = "accept-route"',
            f"  export-policy-list = [{', '.join(exports)}]",
            '  default-export-policy = "accept-route"',
            "",
        ]
        for n in NEIGHBORS:
            # The router with the higher ASN opens the session.
            passive = "true" if int(n["peerAs"]) > ASN else "false"
            lines += [
                "[[neighbors]]",
                "  [neighbors.config]",
                f'    neighbor-address = "{self.addresses[n["name"]]}"',
                f"    peer-as = {int(n['peerAs'])}",
                "  [neighbors.timers.config]",
                f"    hold-time = {TIMERS['hold_time']}",
                f"    keepalive-interval = {TIMERS['keepalive']}",
                f"    connect-retry = {TIMERS['connect_retry']}",
                f"    idle-hold-time-after-reset = {TIMERS['connect_retry']}",
                "  [neighbors.transport.config]",
                f"    passive-mode = {passive}",
            ]
            if GRACEFUL:
                lines += ["  [neighbors.graceful-restart.config]", "    enabled = true",
                          f"    restart-time = {max(30, TIMERS['hold_time'])}"]
            lines += [
                "  [[neighbors.afi-safis]]",
                "    [neighbors.afi-safis.config]",
                '      afi-safi-name = "ipv4-unicast"',
            ]
            if GRACEFUL:
                lines += ["    [neighbors.afi-safis.mp-graceful-restart.config]", "      enabled = true"]
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _policy(name: str, neighbors: str, disposition: str, actions: list[str] | None = None) -> list[str]:
        """A policy of one statement for the routes of or to a neighbor set."""
        lines = [
            "[[policy-definitions]]",
            f'  name = "{name}"',
            "  [[policy-definitions.statements]]",
            "    [policy-definitions.statements.conditions.match-neighbor-set]",
            f'      neighbor-set = "{neighbors}"',
            "    [policy-definitions.statements.actions]",
            f'      route-disposition = "{disposition}"',
        ]
        if actions:
            lines.append("    [policy-definitions.statements.actions.bgp-actions]")
            lines += actions
        return lines + [""]


daemon = Daemon()


def peers() -> list:
    return [r.peer for r in stub.ListPeer(gobgp_pb2.ListPeerRequest(), timeout=5)]


# Samples


def memory() -> dict:
    """From the Prometheus metrics of gobgpd: the paths OBGP suppresses, the
    routes received from all peers (the Adj-RIB-In), the resident memory,
    the heap in use, its objects and the CPU seconds so far. A daemon
    without the suppressed count gives None."""
    with urllib.request.urlopen(GOBGP_METRICS, timeout=1) as response:
        text = response.read().decode()
    out = {"suppressed": None, "adj_in": 0, "rss_mb": None, "heap_mb": None, "heap_objects": None, "cpu_s": None}
    for line in text.splitlines():
        name, _, value = line.rpartition(" ")
        if name.startswith("bgp_obgp_suppressed_paths{"):
            out["suppressed"] = (out["suppressed"] or 0) + int(float(value))
        elif name.startswith("bgp_routes_received{"):
            out["adj_in"] += int(float(value))
        elif name == "process_resident_memory_bytes":
            out["rss_mb"] = round(float(value) / 2**20, 1)
        elif name == "go_memstats_heap_inuse_bytes":
            out["heap_mb"] = round(float(value) / 2**20, 2)
        elif name == "go_memstats_heap_objects":
            out["heap_objects"] = int(float(value))
        elif name == "process_cpu_seconds_total":
            out["cpu_s"] = round(float(value), 2)
    return out


def lengths(cache: dict, key: tuple) -> None:
    """The shortest, mean and longest AS path of the table, into the cache.
    It reads every path, which takes minutes on full tables."""
    started, found = time.monotonic(), []
    try:
        for r in stub.ListPath(gobgp_pb2.ListPathRequest(table_type=GLOBAL, family=IPV4), timeout=600):
            for path in r.destination.paths:
                length = sum(len(s.numbers) for a in path.pattrs if a.HasField("as_path") for s in a.as_path.segments)
                if length:
                    found.append(length)
    except grpc.RpcError:  # busy or restarted: the last values stand
        cache["lengths_running"] = False
        return
    cache.update(key=key, lengths_took=time.monotonic() - started, lengths_running=False, lengths={
        "path_len_min": min(found, default=0),
        "path_len_avg": round(sum(found) / len(found), 4) if found else 0.0,
        "path_len_max": max(found, default=0),
    })


def sample(cache: dict) -> dict:
    """The counters of gobgpd. Path lengths are recomputed apart when the
    table changed, at most once a second or, on large tables, every five
    times the time they took: they read every path. Once the table holds
    still, they are exact again. The memory is read when the table changed
    or once a second."""
    table = stub.GetTable(gobgp_pb2.GetTableRequest(table_type=GLOBAL, family=IPV4), timeout=5)
    by_peer = {}
    for p in peers():
        name = next((n for n, ip in daemon.addresses.items() if ip == p.conf.neighbor_address), p.conf.neighbor_address)
        by_peer[name] = (p.state.messages.received.update, p.state.messages.sent.update)
    rx, tx = sum(v[0] for v in by_peer.values()), sum(v[1] for v in by_peer.values())
    key = (table.num_destination, table.num_path, rx)
    every = max(1.0, 5 * cache.get("lengths_took", 0))
    if cache.get("key") != key and not cache.get("lengths_running") and time.monotonic() - cache.get("lengths_at", -every) >= every:
        cache.update(lengths_running=True, lengths_at=time.monotonic())
        cache.setdefault("lengths", dict.fromkeys(["path_len_min", "path_len_avg", "path_len_max"], 0))
        threading.Thread(target=lengths, args=(cache, key), daemon=True).start()
    if cache.get("memory_key") != key or time.monotonic() - cache.get("memory_at", 0) >= 1:
        try:
            cache["memory"] = memory()
        except OSError:  # busy: the last values stand, memory changes slowly
            cache.setdefault("memory", dict.fromkeys(["suppressed", "adj_in", "rss_mb", "heap_mb", "heap_objects", "cpu_s"]))
        cache.update(memory_key=key, memory_at=time.monotonic())
    return {
        "destinations": table.num_destination,
        "paths": table.num_path,
        **cache["lengths"],
        **cache["memory"],
        "updates_rx": rx,
        "updates_tx": tx,
        # Updates received per neighbor, for the replay: "a=3 b=0"
        "peers_rx": " ".join(f"{n}={v[0]}" for n, v in sorted(by_peer.items())),
    }


class Recorder:
    """Samples gobgpd at t0 + k * interval, for the lab to fetch in batches.

    All routers get the same t0 and the pods share the clock of the host,
    so the samples of all routers fall on the same times. A stopped
    daemon is not sampled; a daemon that just started is given a few
    seconds before failed samples count.
    """

    GRACE = 5.0
    LIMIT = 500_000

    def __init__(self) -> None:
        self.samples: deque = deque(maxlen=self.LIMIT)
        self.seq = 0
        self.failures = 0
        self.stopped = threading.Event()
        self.lock = threading.Lock()

    def start(self, t0: float, interval: float) -> None:
        self.stop()
        with self.lock:
            self.samples.clear()
            self.failures = 0
        self.stopped = threading.Event()
        threading.Thread(target=self._run, args=(t0, interval, self.stopped), daemon=True).start()

    def stop(self) -> None:
        self.stopped.set()

    def _run(self, t0: float, interval: float, stopped: threading.Event) -> None:
        cache: dict = {}
        k = max(0, math.ceil((time.time() - t0) / interval))
        while not stopped.wait(max(0.0, t0 + k * interval - time.time())):
            if daemon.running():
                # The time of the reading, on the grid of the interval: a
                # busy router may start it later than planned.
                began = max(k, round((time.time() - t0) / interval))
                try:
                    row = sample(cache)
                except grpc.RpcError:
                    if daemon.running() and time.time() - daemon.started > self.GRACE:
                        self.failures += 1
                else:
                    with self.lock:
                        self.seq += 1
                        self.samples.append({"seq": self.seq, "t": round(began * interval, 3), **row})
                k = began
            # A slow sample skips the times it missed.
            k = max(k + 1, math.floor((time.time() - t0) / interval) + 1)

    def after(self, seq: int) -> dict:
        with self.lock:
            first = self.samples[0]["seq"] if self.samples else 0
            rows = list(itertools.islice(self.samples, max(0, seq - first + 1), None))
            return {"samples": rows, "failures": self.failures}


recorder = Recorder()


# Route noise


def prefix_nlri(prefix: ipaddress.IPv4Network) -> nlri_pb2.NLRI:
    return nlri_pb2.NLRI(
        prefix=nlri_pb2.IPAddressPrefix(prefix_len=prefix.prefixlen, prefix=str(prefix.network_address))
    )


def announce(prefix: ipaddress.IPv4Network) -> bytes:
    path = gobgp_pb2.Path(
        nlri=prefix_nlri(prefix),
        family=IPV4,
        pattrs=[
            attribute_pb2.Attribute(origin=attribute_pb2.OriginAttribute(origin=0)),
            attribute_pb2.Attribute(next_hop=attribute_pb2.NextHopAttribute(next_hop=POD_IP)),
        ],
    )
    return stub.AddPath(gobgp_pb2.AddPathRequest(table_type=GLOBAL, path=path), timeout=5).uuid


def withdraw(uuid: bytes) -> None:
    stub.DeletePath(gobgp_pb2.DeletePathRequest(table_type=GLOBAL, family=IPV4, uuid=uuid), timeout=5)


class NoiseConfig(BaseModel):
    """All given by the runner; the defaults of a scenario are in lab/scenario.py."""

    block: int = Field(ge=0, description="Index of the IPv4 block to draw prefixes from")
    blocks: int = Field(ge=1, description="Number of equal blocks the IPv4 space is split into")
    rate: float = Field(gt=0, description="Announcements per second")
    lifetime: float = Field(gt=0, description="Mean prefix lifetime in seconds")
    jitter: float = Field(ge=0, le=1, description="Relative lifetime variation")
    max_active: int = Field(ge=1, description="Maximum number of active prefixes")


class Noise:
    """Announces random prefixes at a fixed rate and withdraws them after their lifetime.

    Prefixes are mostly /24, then /22–23, /20–21 and /16–19; they never
    overlap, and all randomness derives from the lab seed and the router name.
    """

    def __init__(self) -> None:
        self.rng = random.Random(f"{SEED}/{ROUTER_NAME}")
        self.lock = threading.Lock()
        self.active: dict[ipaddress.IPv4Network, tuple[float, bytes]] = {}
        self.config: NoiseConfig | None = None
        self.paused_at: float | None = None

    def start(self, config: NoiseConfig) -> None:
        """Starts announcing, or continues a paused noise with a new configuration."""
        with self.lock:
            running = self.config is not None
            self.config = config
        if running:
            self.resume()
        else:
            threading.Thread(target=self._run, daemon=True).start()

    def pause(self) -> None:
        with self.lock:
            self.paused_at = self.paused_at or time.time()

    def resume(self) -> None:
        with self.lock:
            if self.paused_at is not None:
                shift = time.time() - self.paused_at
                self.active = {p: (expiry + shift, uuid) for p, (expiry, uuid) in self.active.items()}
                self.paused_at = None

    def drain(self, percent: float) -> int:
        """Withdraws the given share of active prefixes and returns how many remain."""
        with self.lock:
            count = max(1, int(len(self.active) * percent / 100)) if self.active else 0
            victims = self.rng.sample(sorted(self.active), count)
            for prefix in victims:
                uuid = self.active.pop(prefix)[1]
                if daemon.running():  # a stopped daemon has no routes to withdraw
                    withdraw(uuid)
            return len(self.active)

    def load(self, prefixes: list[ipaddress.IPv4Network], rate: float) -> None:
        """Announces given prefixes at a rate, which stay until withdrawn, as
        real prefixes do. While gobgpd is stopped they wait."""
        for prefix in prefixes:
            while True:
                with self.lock:
                    if prefix in self.active:
                        break
                    if daemon.running():
                        try:
                            self.active[prefix] = (math.inf, announce(prefix))
                            break
                        except grpc.RpcError as e:
                            print(f"load: {e.code()}", flush=True)
                time.sleep(1 / rate)
            time.sleep(1 / rate)

    def withdraw(self, prefixes: list[ipaddress.IPv4Network]) -> int:
        """Withdraws given prefixes, those announced, and returns how many remain."""
        with self.lock:
            for prefix in prefixes:
                if (entry := self.active.pop(prefix, None)) and daemon.running():
                    withdraw(entry[1])
            return len(self.active)

    def restore(self) -> None:
        """Announces the active prefixes again, to a daemon that started anew."""
        with self.lock:
            self.active = {p: (expiry, announce(p)) for p, (expiry, _) in self.active.items()}

    def status(self) -> dict:
        with self.lock:
            return {
                "running": self.config is not None,
                "paused": self.paused_at is not None,
                "active": len(self.active),
                "prefixes": sorted(map(str, self.active)),
                "originated": sorted(originated),
                "config": self.config.model_dump() if self.config else None,
            }

    def _run(self) -> None:
        # While gobgpd is stopped the noise holds, as a router that is down
        # announces nothing; a failed call is tried again with the next tick.
        while True:
            config = self.config
            size = (1 << 32) // config.blocks
            start = config.block * size
            with self.lock:
                if self.paused_at is None and daemon.running():
                    try:
                        now = time.time()
                        for prefix in [p for p, (expiry, _) in self.active.items() if expiry <= now]:
                            withdraw(self.active[prefix][1])
                            del self.active[prefix]
                        if len(self.active) < config.max_active and (prefix := self._draw(start, start + size)):
                            lifetime = config.lifetime * (1 + self.rng.uniform(-config.jitter, config.jitter))
                            self.active[prefix] = (now + lifetime, announce(prefix))
                    except grpc.RpcError as e:
                        print(f"noise: {e.code()}", flush=True)
            time.sleep(1 / config.rate)

    def _draw(self, start: int, end: int) -> ipaddress.IPv4Network | None:
        for _ in range(1000):
            length = self._length()
            size = 1 << (32 - length)
            prefix = ipaddress.ip_network((self.rng.randrange(start // size, end // size) * size, length))
            if not any(prefix.overlaps(p) for p in self.active):
                return prefix
        return None

    def _length(self) -> int:
        r = self.rng.random()
        if r < 0.6:
            return 24
        if r < 0.8:
            return self.rng.choice([22, 23])
        if r < 0.95:
            return self.rng.choice([20, 21])
        return self.rng.randint(16, 19)


noise = Noise()
originated: dict[str, bytes] = {}  # copies of other routers' prefixes, prefix -> uuid


# Failures: iptables drops the packets of failed links, tc netem degrades them.

failures = {"cut": set(), "oneway": set()}  # peer names
degraded: dict[str, dict] = {}              # peer name -> netem parameters


def run(*args: str) -> None:
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise HTTPException(500, f"{' '.join(args)}: {result.stderr.strip()}")


def drop(peer: str, both: bool, add: bool) -> None:
    ip = daemon.addresses[peer]
    rules = [["INPUT", "-s", ip]] + ([["OUTPUT", "-d", ip]] if both else [])
    for chain, direction, address in rules:
        if add:
            run("iptables", "-I", chain, direction, address, "-j", "DROP")
        else:
            while subprocess.run(["iptables", "-D", chain, direction, address, "-j", "DROP"], capture_output=True).returncode == 0:
                pass


def apply_degradation() -> None:
    """Rebuilds the egress queueing: one netem band per degraded peer."""
    subprocess.run(["tc", "qdisc", "del", "dev", "eth0", "root"], capture_output=True)
    if not degraded:
        return
    run("tc", "qdisc", "add", "dev", "eth0", "root", "handle", "1:", "prio", "bands", "16",
        "priomap", *["0"] * 16)
    for band, (peer, d) in enumerate(sorted(degraded.items()), start=2):
        netem = ["delay", f"{d['delay_ms']}ms", f"{d['jitter_ms']}ms", "loss", f"{d['loss_pct']}%"]
        run("tc", "qdisc", "add", "dev", "eth0", "parent", f"1:{band}", "handle", f"{band}0:", "netem", *netem)
        run("tc", "filter", "add", "dev", "eth0", "parent", "1:", "protocol", "ip", "prio", "1", "u32",
            "match", "ip", "dst", f"{daemon.addresses[peer]}/32", "flowid", f"1:{band}")


# API


@asynccontextmanager
async def lifespan(_: FastAPI):
    threading.Thread(target=daemon.boot, daemon=True).start()
    yield
    daemon.stop()


app = FastAPI(title=f"Router controller ({ROUTER_NAME})", lifespan=lifespan)


@app.get("/ready", summary="200 once all BGP sessions are established")
def ready(response: Response):
    try:
        established = sum(
            p.state.session_state == gobgp_pb2.PeerState.SESSION_STATE_ESTABLISHED for p in peers()
        )
    except grpc.RpcError:
        established = 0
    if established < len(NEIGHBORS):
        response.status_code = 503
    return {"established": established, "neighbors": len(NEIGHBORS)}


@app.get("/sessions", summary="Whether the session to each neighbor is established")
def sessions():
    names = {ip: name for name, ip in daemon.addresses.items()}
    try:
        return {names.get(p.conf.neighbor_address, p.conf.neighbor_address): p.state.session_state == gobgp_pb2.PeerState.SESSION_STATE_ESTABLISHED
                for p in peers()}
    except grpc.RpcError:
        return {}


class Recording(BaseModel):
    t0: float = Field(description="Wall-clock time of the first sample, in seconds since the epoch")
    interval: float = Field(ge=0.01, description="Seconds between samples")


@app.get("/time", summary="Wall clock of the pod, to align the samples of all routers")
def clock():
    return {"now": time.time()}


@app.post("/samples/start", summary="Start sampling at t0 + k * interval")
def samples_start(recording: Recording):
    recorder.start(recording.t0, recording.interval)
    return {"now": time.time()}


@app.post("/samples/stop")
def samples_stop():
    recorder.stop()
    return {"stopped": True}


@app.get("/samples", summary="Samples after a sequence number")
def samples(after: int = 0):
    return recorder.after(after)


@app.get("/noise")
def noise_status():
    return noise.status()


@app.post("/noise/start")
def noise_start(config: NoiseConfig):
    noise.start(config)
    return noise.status()


@app.post("/noise/pause")
def noise_pause():
    noise.pause()
    return noise.status()


class LoadRequest(BaseModel):
    prefixes: list[ipaddress.IPv4Network] = Field(max_length=10_000)
    rate: float = Field(gt=0, le=10_000, description="Announcements per second")


@app.post("/noise/load", summary="Announce given prefixes at a rate, until they are withdrawn")
def noise_load(request: LoadRequest):
    threading.Thread(target=noise.load, args=(request.prefixes, request.rate), daemon=True).start()
    return {"loading": len(request.prefixes)}


class PrefixesRequest(BaseModel):
    prefixes: list[ipaddress.IPv4Network] = Field(max_length=10_000)


@app.post("/noise/withdraw", summary="Withdraw given prefixes")
def noise_withdraw(request: PrefixesRequest):
    return {"remaining": noise.withdraw(request.prefixes)}


class DrainRequest(BaseModel):
    percent: float = Field(gt=0, le=100)


@app.post("/noise/drain")
def noise_drain(request: DrainRequest):
    return {"remaining": noise.drain(request.percent)}


# Failures and policy changes of scenarios


def neighbor(name: str) -> str:
    if name not in daemon.addresses:
        raise HTTPException(404, f"{name} is not a neighbor")
    return daemon.addresses[name]


class DownRequest(BaseModel):
    mode: Literal["session", "cut", "oneway"] = "session"


@app.post("/peers/{name}/down", summary="Fail the link to a neighbor")
def peer_down(name: str, request: DownRequest):
    ip = neighbor(name)
    if request.mode == "session":
        stub.DisablePeer(gobgp_pb2.DisablePeerRequest(address=ip, communication="lab: link down"), timeout=5)
    else:
        drop(name, both=request.mode == "cut", add=True)
        failures[request.mode].add(name)
    return {"down": name, "mode": request.mode}


@app.post("/peers/{name}/up", summary="Restore the link to a neighbor")
def peer_up(name: str):
    ip = neighbor(name)
    try:
        stub.EnablePeer(gobgp_pb2.EnablePeerRequest(address=ip), timeout=5)
    except grpc.RpcError:
        pass  # the session was not disabled
    for mode in failures:
        if name in failures[mode]:
            drop(name, both=mode == "cut", add=False)
            failures[mode].discard(name)
    if degraded.pop(name, None):
        apply_degradation()
    return {"up": name}


class DegradeRequest(BaseModel):
    delay_ms: float = Field(0, ge=0)
    jitter_ms: float = Field(0, ge=0)
    loss_pct: float = Field(0, ge=0, le=100)


@app.post("/peers/{name}/degrade", summary="Delay or drop packets to a neighbor")
def peer_degrade(name: str, request: DegradeRequest):
    neighbor(name)
    degraded[name] = request.model_dump()
    apply_degradation()
    return {"degraded": name, **degraded[name]}


@app.post("/daemon/stop")
def daemon_stop():
    daemon.stop()
    return {"running": False}


def restore() -> None:
    """After gobgpd started anew: its own prefixes and copies are announced
    again, as a router announces its configured prefixes after a restart."""
    deadline = time.time() + 15
    while True:  # until the new daemon takes paths
        try:
            noise.restore()
            for prefix in list(originated):
                originated[prefix] = announce(ipaddress.ip_network(prefix))
            return
        except grpc.RpcError:
            if time.time() > deadline:
                raise HTTPException(503, "gobgpd did not take the prefixes again")
            time.sleep(0.2)


@app.post("/daemon/start")
def daemon_start():
    if not daemon.running():
        daemon.start()
        restore()
    return {"running": True}


class RestartRequest(BaseModel):
    graceful: bool = False


@app.post("/daemon/restart")
def daemon_restart(request: RestartRequest | None = None):
    graceful = bool(request and request.graceful)
    if graceful and not GRACEFUL:
        raise HTTPException(400, "graceful restart is not enabled for this experiment")
    daemon.stop(kill=graceful)
    daemon.start(graceful=graceful)
    restore()
    return {"running": True, "graceful": graceful}


class PreferenceRequest(BaseModel):
    neighbor: str
    value: int = Field(ge=0)


@app.post("/policy/preference", summary="Set the Local Preference for routes from a neighbor")
def policy_preference(request: PreferenceRequest):
    neighbor(request.neighbor)
    daemon.preferences[request.neighbor] = request.value or None
    daemon.reload()
    return {"neighbor": request.neighbor, "value": request.value}


class PrependRequest(BaseModel):
    times: int = Field(ge=0, le=16)


@app.post("/policy/prepend", summary="Prepend the own ASN to every announced path")
def policy_prepend(request: PrependRequest):
    daemon.prepend = request.times
    daemon.reload(export=True)
    return {"times": request.times}


class ExportRequest(BaseModel):
    neighbor: str
    allow: bool


@app.post("/policy/export", summary="Stop or resume announcing routes to a neighbor")
def policy_export(request: ExportRequest):
    neighbor(request.neighbor)
    if request.allow:
        daemon.denied.discard(request.neighbor)
    else:
        daemon.denied.add(request.neighbor)
    daemon.reload(export=True)
    return {"neighbor": request.neighbor, "allow": request.allow}


class SoftResetRequest(BaseModel):
    direction: Literal["in", "out", "both"]


@app.post("/bgp/soft-reset", summary="Ask all neighbors for their routes again, or send them ours")
def soft_reset(request: SoftResetRequest):
    direction = {"in": gobgp_pb2.ResetPeerRequest.DIRECTION_IN, "out": gobgp_pb2.ResetPeerRequest.DIRECTION_OUT,
                 "both": gobgp_pb2.ResetPeerRequest.DIRECTION_BOTH}[request.direction]
    stub.ResetPeer(gobgp_pb2.ResetPeerRequest(address="all", soft=True, direction=direction), timeout=10)
    return {"direction": request.direction}


@app.get("/routes", summary="The best route to every prefix: the neighbor it comes from and its AS path")
def routes():
    names = {ip: name for name, ip in daemon.addresses.items()}
    out = {}
    for r in stub.ListPath(gobgp_pb2.ListPathRequest(table_type=GLOBAL, family=IPV4), timeout=5):
        paths = r.destination.paths
        # The best path comes first; daemons before 2026-10 do not mark it.
        path = next((p for p in paths if p.best), paths[0] if paths else None)
        if path is not None and not path.is_withdraw:
            as_path = [n for a in path.pattrs if a.HasField("as_path") for seg in a.as_path.segments for n in seg.numbers]
            out[r.destination.prefix] = {"from": names.get(path.neighbor_ip), "as_path": as_path}
    return out


class OriginateRequest(BaseModel):
    prefixes: list[str]
    more_specific: bool = False


# Full tables


class Rib:
    """A table of the Internet this router injects, as if learned from beyond
    the topology: every route with its origin and AS path, next hop itself."""

    def __init__(self) -> None:
        self.loaded = self.total = 0
        self.done, self.error = True, None

    def load(self, data: bytes) -> None:
        lines = gzip.open(io.BytesIO(data), "rt").read().splitlines()
        self.loaded, self.total, self.done, self.error = 0, len(lines), False, None
        threading.Thread(target=self._stream, args=(lines,), daemon=True).start()

    def _stream(self, lines: list[str]) -> None:
        def batches():
            for start in range(0, len(lines), 1000):
                paths = []
                for line in lines[start:start + 1000]:
                    prefix, origin, *path = line.split()
                    paths.append(gobgp_pb2.Path(nlri=prefix_nlri(ipaddress.IPv4Network(prefix)), family=IPV4, pattrs=[
                        attribute_pb2.Attribute(origin=attribute_pb2.OriginAttribute(origin=int(origin))),
                        attribute_pb2.Attribute(as_path=attribute_pb2.AsPathAttribute(segments=[
                            attribute_pb2.AsSegment(type=attribute_pb2.AsSegment.TYPE_AS_SEQUENCE, numbers=[int(a) for a in path])])),
                        attribute_pb2.Attribute(next_hop=attribute_pb2.NextHopAttribute(next_hop=POD_IP)),
                    ]))
                yield gobgp_pb2.AddPathStreamRequest(table_type=GLOBAL, paths=paths)
                self.loaded += len(paths)
        try:
            stub.AddPathStream(batches(), timeout=3600)
        except (grpc.RpcError, ValueError) as e:
            self.error = str(e)[:300]
        self.done = True


rib = Rib()


@app.post("/rib/load", summary="Inject a table, gzip of lines 'prefix origin AS…'")
async def rib_load(request: Request):
    if not rib.done:
        raise HTTPException(409, "a table is still loading")
    try:
        rib.load(await request.body())
    except (OSError, EOFError) as e:
        raise HTTPException(400, f"not a table: {e}") from None
    return {"total": rib.total}


@app.get("/rib", summary="How far the table is injected")
def rib_status():
    return {"loaded": rib.loaded, "total": rib.total, "done": rib.done, "error": rib.error}


@app.post("/rib/clear", summary="Withdraw every route this router injected or announced")
def rib_clear():
    stub.DeletePath(gobgp_pb2.DeletePathRequest(table_type=GLOBAL, family=IPV4), timeout=600)
    rib.loaded = rib.total = 0
    return {"cleared": True}


@app.post("/originate", summary="Announce copies of other routers' prefixes")
def originate(request: OriginateRequest):
    for text in request.prefixes:
        prefix = ipaddress.ip_network(text)
        if request.more_specific and prefix.prefixlen < 32:
            prefix = next(prefix.subnets())
        if str(prefix) not in originated:
            originated[str(prefix)] = announce(prefix)
    return {"originated": sorted(originated)}


@app.post("/originate/clear", summary="Withdraw all copies")
def originate_clear():
    if daemon.running():
        for uuid in originated.values():
            withdraw(uuid)
    originated.clear()
    return {"originated": []}


# For looking into a router by hand, e.g. through kubectl port-forward.

@app.get("/stats", summary="The counters of gobgpd now")
def stats():
    return sample({})


@app.get("/neighbors", summary="Neighbor view of gobgpd")
def neighbors():
    return [MessageToDict(p) for p in peers()]


@app.get("/config", summary="Rendered gobgpd configuration")
def config():
    try:
        with open(GOBGP_CONFIG) as f:
            return Response(f.read(), media_type="text/plain")
    except FileNotFoundError:
        raise HTTPException(404, "gobgpd not configured yet")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")
