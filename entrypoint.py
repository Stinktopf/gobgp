#!/usr/bin/env python3
import glob
import json
import os
import signal
import subprocess
import threading
import time
import gzip
import shutil
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, Body, UploadFile, File
from fastapi.responses import FileResponse
import uvicorn
import requests
import random
import ipaddress

POD_IP = os.environ["POD_IP"]
LOCAL_ASN = int(os.environ["ASN"])
ROUTER_ID = os.environ["ROUTER_ID"]
KUBE_NAMESPACE = os.environ["POD_NAMESPACE"]
NEIGHBORS_JSON_RAW = os.environ["NEIGHBORS_JSON"]

GOBGP_CONFIG_PATH = "/etc/gobgp/gobgp.conf"
PCAP_DIR = "/tmp/pcaps"
MRT_DIR = "/tmp/mrt"

neighbor_state_by_name: Dict[str, Dict[str, Any]] = {}
gobgpd_process: Optional[subprocess.Popen] = None
tcpdump_process: Optional[subprocess.Popen] = None
current_pcap_file: Optional[str] = None
neighbor_state_lock = threading.Lock()

noise_thread: Optional[threading.Thread] = None
noise_stop_event = threading.Event()
noise_config: Dict[str, Any] = {}
noise_active_prefixes: Dict[str, float] = {}
noise_lock = threading.Lock()


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
        ip_address = subprocess.check_output(
            ["getent", "hosts", service_fqdn], text=True
        ).split()[0]
        return ip_address
    except subprocess.CalledProcessError:
        return None


def write_gobgp_config_file() -> None:
    with neighbor_state_lock:
        neighbors_snapshot = {
            name: data.copy() for name, data in neighbor_state_by_name.items()
        }

    tags_by_peer_asn: Dict[int, Set[int]] = {}
    for neighbor_data in neighbors_snapshot.values():
        tags_by_peer_asn.setdefault(neighbor_data["peerAs"], set()).update(
            neighbor_data.get("tags", [])
        )

    peer_asns_with_tags = sorted(asn for asn, tags in tags_by_peer_asn.items() if tags)
    import_policy_names = ", ".join(
        [f'"tag-from-as{peer_asn}"' for peer_asn in peer_asns_with_tags]
    )

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
        communities_literal = ", ".join(
            [f'"{LOCAL_ASN}:{tag}"' for tag in sorted(tag_set)]
        )
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
    with open(GOBGP_CONFIG_PATH, "w") as config_file:
        config_file.write("\n".join(config_lines))
    print(f"[Config] written to {GOBGP_CONFIG_PATH}", flush=True)


def restart_gobgpd() -> None:
    global gobgpd_process
    if gobgpd_process and gobgpd_process.poll() is None:
        print("[Gobgpd] stopping old process", flush=True)
        gobgpd_process.send_signal(signal.SIGTERM)
        try:
            gobgpd_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            print("[Gobgpd] SIGKILL old process", flush=True)
            gobgpd_process.kill()
            gobgpd_process.wait()
    print(f"[Gobgpd] starting with {GOBGP_CONFIG_PATH}", flush=True)
    gobgpd_process = subprocess.Popen(["gobgpd", "-f", GOBGP_CONFIG_PATH])


def neighbor_resolution_polling_loop() -> None:
    with neighbor_state_lock:
        neighbor_state_by_name.update(NEIGHBOR_TEMPLATE)

    is_first_render = True
    while True:
        has_changes = False

        for neighbor_name in list(neighbor_state_by_name.keys()):
            resolved_ip = resolve_neighbor_ip_address(neighbor_name)
            with neighbor_state_lock:
                previous_ip = neighbor_state_by_name[neighbor_name].get("ip")
                if resolved_ip != previous_ip:
                    neighbor_state_by_name[neighbor_name]["ip"] = resolved_ip
                    print(
                        f"[State] {neighbor_name} IP changed: {previous_ip} -> {resolved_ip}",
                        flush=True,
                    )
                    has_changes = True

        if has_changes or is_first_render:
            if any(neighbor.get("ip") for neighbor in neighbor_state_by_name.values()):
                write_gobgp_config_file()
                restart_gobgpd()
                is_first_render = False
            else:
                print("[Config] skip render (no neighbor IPs yet)", flush=True)

        time.sleep(2)


def start_tcpdump() -> (subprocess.Popen, str):
    os.makedirs(PCAP_DIR, exist_ok=True)
    pcap_file = os.path.join(PCAP_DIR, f"bgp-{int(time.time())}.pcap")
    print(f"[tcpdump] start capture to {pcap_file}", flush=True)
    proc = subprocess.Popen(
        ["tcpdump", "-i", "any", "port", "179", "-w", pcap_file],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )
    return proc, pcap_file


def stop_tcpdump():
    global tcpdump_process, current_pcap_file
    if tcpdump_process and tcpdump_process.poll() is None:
        tcpdump_process.terminate()
        tcpdump_process.wait()
        print(f"[tcpdump] stopped, file: {current_pcap_file}", flush=True)
        fname = os.path.basename(current_pcap_file) if current_pcap_file else None
        tcpdump_process = None
        current_pcap_file = None
        return fname
    return None


def run_gobgp(args: List[str], json_out: bool = False):
    try:
        cmd = ["gobgp"] + args
        if json_out:
            cmd.append("-j")
        res = subprocess.run(cmd, text=True, capture_output=True, check=True)
        return json.loads(res.stdout) if json_out else res.stdout.strip()
    except subprocess.CalledProcessError as e:
        return {"error": e.stderr.strip() or str(e)}


def realistic_prefixlen() -> int:
    r = random.random()
    if r < 0.6:
        return 24
    elif r < 0.8:
        return random.choice([22, 23])
    elif r < 0.95:
        return random.choice([20, 21])
    else:
        return random.randint(16, 19)


def _rand_subnet(start: int, end: int, active: dict) -> str:
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
        expired = []
        with noise_lock:
            expired = [p for p, exp in noise_active_prefixes.items() if exp <= now]
        for prefix in expired:
            run_gobgp(["global", "rib", "del", str(prefix)])
            with noise_lock:
                noise_active_prefixes.pop(prefix, None)

        with noise_lock:
            if len(noise_active_prefixes) < max_active:
                prefix_str, prefix_obj = _rand_subnet(start, end, noise_active_prefixes)
                if prefix_str:
                    res = run_gobgp([
                        "global", "rib", "add",
                        prefix_str,
                        "nexthop", POD_IP,
                        "origin", "igp"
                    ])
                    if not isinstance(res, dict) or "error" not in res:
                        delta = lifetime * (1 + random.uniform(-jitter, jitter))
                        noise_active_prefixes[prefix_obj] = now + delta

        noise_stop_event.wait(1.0 / rate)


@asynccontextmanager
async def lifespan(app: FastAPI):
    neighbor_polling_thread = threading.Thread(
        target=neighbor_resolution_polling_loop, daemon=True
    )
    neighbor_polling_thread.start()
    yield
    _shutdown()


app = FastAPI(lifespan=lifespan)


@app.get("/ip")
def http_ip():
    return {"pod_ip": POD_IP}


@app.get("/config")
def http_config():
    try:
        with open(GOBGP_CONFIG_PATH, "r") as config_file:
            return {"config": config_file.read()}
    except FileNotFoundError:
        return {"error": "no config yet"}


@app.post("/pcap/start")
def http_start_pcap():
    global tcpdump_process, current_pcap_file
    if tcpdump_process and tcpdump_process.poll() is None:
        return {"error": "capture already running"}
    tcpdump_process, current_pcap_file = start_tcpdump()
    return {"started": os.path.basename(current_pcap_file)}


@app.post("/pcap/stop")
def http_stop_pcap():
    fname = stop_tcpdump()
    if not fname:
        return {"error": "no capture running"}
    return {"stopped": fname}


@app.get("/pcaps")
def list_pcaps():
    files = sorted(glob.glob(os.path.join(PCAP_DIR, "*.pcap")))
    return {"files": [os.path.basename(f) for f in files]}


@app.get("/pcaps/{filename}")
def download_pcap(filename: str):
    file_path = os.path.join(PCAP_DIR, filename)
    if not os.path.exists(file_path):
        return {"error": "file not found"}
    return FileResponse(
        path=file_path, filename=filename, media_type="application/vnd.tcpdump.pcap"
    )


@app.get("/neighbors")
def http_neighbors():
    return run_gobgp(["neighbor"], json_out=True)


@app.get("/rib")
def http_rib():
    return run_gobgp(["global", "rib"], json_out=True)


@app.get("/rib/summary")
def http_rib_summary():
    return run_gobgp(["global", "rib", "summary"], json_out=True)


@app.get("/rib/count")
def http_rib_count():
    routes = run_gobgp(["global", "rib"], json_out=True)
    if isinstance(routes, dict) and "error" in routes:
        return routes
    return {"count": len(routes)}


@app.post("/rib/add")
def http_rib_add(
    prefix: str = Body(..., embed=True),
    nexthop: str = Body(..., embed=True),
    aspath: Optional[List[int]] = Body(None, embed=True),
    community: Optional[str] = Body(None, embed=True),
    identifier: Optional[int] = Body(None, embed=True),
):
    cmd = ["global", "rib", "add", prefix, "nexthop", nexthop]
    if aspath:
        cmd += ["aspath"] + [str(a) for a in aspath]
    if community:
        cmd += ["community", community]
    if identifier:
        cmd += ["identifier", str(identifier)]
    return run_gobgp(cmd)


@app.post("/rib/del")
def http_rib_del(prefix: str = Body(..., embed=True)):
    return run_gobgp(["global", "rib", "del", prefix])


@app.delete("/rib")
def http_rib_del_all():
    return run_gobgp(["global", "rib", "del", "all"])


@app.post("/mrt/upload")
def http_mrt_upload(
    file: UploadFile = File(...),
    inject: bool = Body(False, embed=True),
    count: Optional[int] = Body(None, embed=True),
):
    os.makedirs(MRT_DIR, exist_ok=True)
    file_path = os.path.join(MRT_DIR, file.filename)
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    if file_path.endswith(".gz"):
        unzipped_path = file_path[:-3]
        with gzip.open(file_path, "rb") as f_in:
            with open(unzipped_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(file_path)
        file_path = unzipped_path

    result = None
    if inject:
        args = ["mrt", "inject", "global", file_path]
        if count is not None:
            args.append(str(count))
        result = run_gobgp(args)

    return {"uploaded": os.path.basename(file_path), "injected": inject, "count": count, "inject_result": result}


@app.post("/mrt/inject")
def http_mrt_inject(
    filename: str = Body(..., embed=True),
    count: Optional[int] = Body(None, embed=True),
):
    file_path = os.path.join(MRT_DIR, filename)
    if not os.path.exists(file_path):
        return {"error": "file not found", "path": file_path}
    args = ["mrt", "inject", "global", file_path]
    if count is not None:
        args.append(str(count))
    result = run_gobgp(args)
    return {"injected": filename, "count": count, "result": result}


@app.get("/mrt")
def http_mrt_list():
    os.makedirs(MRT_DIR, exist_ok=True)
    files = sorted(glob.glob(os.path.join(MRT_DIR, "*")))
    return {"files": [os.path.basename(f) for f in files]}


@app.delete("/mrt/{filename}")
def http_mrt_delete(filename: str):
    file_path = os.path.join(MRT_DIR, filename)
    if not os.path.exists(file_path):
        return {"error": "file not found"}
    os.remove(file_path)
    return {"deleted": filename}


@app.delete("/mrt")
def http_mrt_delete_all():
    os.makedirs(MRT_DIR, exist_ok=True)
    removed = []
    for f in glob.glob(os.path.join(MRT_DIR, "*")):
        os.remove(f)
        removed.append(os.path.basename(f))
    return {"deleted": removed}


@app.post("/mrt/download")
def http_mrt_download(
    url: str = Body(..., embed=True),
    inject: bool = Body(False, embed=True),
    count: Optional[int] = Body(None, embed=True),
):
    os.makedirs(MRT_DIR, exist_ok=True)
    filename = url.split("/")[-1]
    file_path = os.path.join(MRT_DIR, filename)
    try:
        with requests.get(url, stream=True, timeout=60) as r:
            r.raise_for_status()
            with open(file_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
    except Exception as e:
        return {"error": str(e)}

    result = None
    if inject:
        args = ["mrt", "inject", "global", file_path]
        if count is not None:
            args.append(str(count))
        result = run_gobgp(args)

    return {"downloaded": filename, "path": file_path, "injected": inject, "count": count, "inject_result": result}


@app.post("/noise/start")
def http_noise_start(cfg: Dict[str, Any] = Body(...)):
    global noise_thread, noise_config, noise_stop_event
    if noise_thread and noise_thread.is_alive():
        return {"error": "noise already running", "config": noise_config}
    noise_config = cfg
    noise_stop_event.clear()
    noise_thread = threading.Thread(target=noise_worker, daemon=True)
    noise_thread.start()
    return {"started": True, "config": noise_config}


@app.post("/noise/stop")
def http_noise_stop():
    global noise_thread, noise_stop_event, noise_active_prefixes
    if not noise_thread or not noise_thread.is_alive():
        return {"error": "noise not running"}
    noise_stop_event.set()
    noise_thread.join(timeout=2)

    with noise_lock:
        for prefix in list(noise_active_prefixes.keys()):
            run_gobgp(["global", "rib", "del", str(prefix)])
        noise_active_prefixes.clear()
    return {"stopped": True, "cleaned": True}


@app.get("/noise/status")
def http_noise_status():
    running = noise_thread is not None and noise_thread.is_alive()
    return {
        "running": running,
        "config": noise_config if running else None,
        "active_prefixes": [str(p) for p in noise_active_prefixes.keys()],
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
        for prefix in list(noise_active_prefixes.keys()):
            run_gobgp(["global", "rib", "del", str(prefix)])
        noise_active_prefixes.clear()
    raise SystemExit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    uvicorn.run(app, host="0.0.0.0", port=8080)
