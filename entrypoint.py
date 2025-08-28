#!/usr/bin/env python3
import json
import os
import signal
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI
import uvicorn

POD_IP = os.environ["POD_IP"]
LOCAL_ASN = int(os.environ["ASN"])
ROUTER_ID = os.environ["ROUTER_ID"]
KUBE_NAMESPACE = os.environ["POD_NAMESPACE"]
NEIGHBORS_JSON_RAW = os.environ["NEIGHBORS_JSON"]

GOBGP_CONFIG_PATH = "/etc/gobgp/gobgp.conf"

neighbor_state_by_name: Dict[str, Dict[str, Any]] = {}
active_neighbors: Dict[str, Dict[str, Any]] = {}
gobgpd_process: Optional[subprocess.Popen] = None
neighbor_state_lock = threading.Lock()


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


def write_initial_policies() -> None:
    tags_by_peer_asn: Dict[int, Set[int]] = {}
    for neighbor_data in NEIGHBOR_TEMPLATE.values():
        tags_by_peer_asn.setdefault(neighbor_data["peerAs"], set()).update(neighbor_data.get("tags", []))

    peer_asns_with_tags = sorted(asn for asn, tags in tags_by_peer_asn.items() if tags)
    import_policy_names = ", ".join([f'"tag-from-as{peer_asn}"' for peer_asn in peer_asns_with_tags])

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
        tag_set = tags_by_peer_asn[peer_asn]
        config_lines += [
            "[[defined-sets.bgp-defined-sets.as-path-sets]]",
            f'  as-path-set-name = "from-as{peer_asn}"',
            f'  as-path-list = ["^{peer_asn}$", "^{peer_asn}_"]',
            "",
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

    os.makedirs(os.path.dirname(GOBGP_CONFIG_PATH), exist_ok=True)
    with open(GOBGP_CONFIG_PATH, "w") as config_file:
        config_file.write("\n".join(config_lines))
    print(f"[CONFIG] initial policies written to {GOBGP_CONFIG_PATH}", flush=True)


def start_gobgpd() -> None:
    global gobgpd_process
    print(f"[GOBGP] starting with {GOBGP_CONFIG_PATH}", flush=True)
    gobgpd_process = subprocess.Popen(["gobgpd", "-f", GOBGP_CONFIG_PATH])


def apply_neighbor_diff():
    global active_neighbors
    desired = {name: data for name, data in neighbor_state_by_name.items() if data.get("ip")}

    for name, data in desired.items():
        new_ip = data["ip"]
        old_ip = None
        for ip, d in active_neighbors.items():
            if d["peerAs"] == data["peerAs"] and ip != new_ip:
                old_ip = ip
                break
        if old_ip:
            print(f"[NEIGHBOR] DEL {old_ip} replaced by {new_ip} (ASN {data['peerAs']})", flush=True)
            subprocess.run(["gobgp", "neighbor", "del", old_ip], check=True)
            active_neighbors.pop(old_ip, None)

    for name, data in desired.items():
        ip = data["ip"]
        if ip and ip not in active_neighbors:
            print(f"[NEIGHBOR] ADD {ip} (ASN {data['peerAs']})", flush=True)
            subprocess.run(["gobgp", "neighbor", "add", ip, "as", str(data["peerAs"])], check=True)
            active_neighbors[ip] = data

    for ip in list(active_neighbors.keys()):
        if all(d["ip"] != ip for d in desired.values()):
            print(f"[NEIGHBOR] DEL {ip} (ASN {data['peerAs']})", flush=True)
            subprocess.run(["gobgp", "neighbor", "del", ip], check=True)
            active_neighbors.pop(ip, None)



def neighbor_resolution_polling_loop() -> None:
    with neighbor_state_lock:
        neighbor_state_by_name.update(NEIGHBOR_TEMPLATE)

    is_first_run = True
    while True:
        has_changes = False

        for neighbor_name in list(neighbor_state_by_name.keys()):
            resolved_ip = resolve_neighbor_ip_address(neighbor_name)
            with neighbor_state_lock:
                previous_ip = neighbor_state_by_name[neighbor_name].get("ip")
                if resolved_ip != previous_ip:
                    neighbor_state_by_name[neighbor_name]["ip"] = resolved_ip
                    print(f"[IP] {neighbor_name} Changed: {previous_ip} -> {resolved_ip}", flush=True)
                    has_changes = True

        if has_changes or is_first_run:
            apply_neighbor_diff()
            is_first_run = False

        time.sleep(2)


@asynccontextmanager
async def lifespan(app: FastAPI):
    neighbor_polling_thread = threading.Thread(target=neighbor_resolution_polling_loop, daemon=True)
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


def _shutdown(*_):
    global gobgpd_process
    if gobgpd_process and gobgpd_process.poll() is None:
        try:
            gobgpd_process.send_signal(signal.SIGTERM)
            gobgpd_process.wait(timeout=10)
        except Exception:
            pass
    raise SystemExit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    write_initial_policies()
    start_gobgpd()

    uvicorn.run(app, host="0.0.0.0", port=8080)
