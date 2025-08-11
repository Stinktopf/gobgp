#!/usr/bin/env python3
import os
import signal
import subprocess
import threading
import time
import json
from typing import Dict, Optional, List

from fastapi import FastAPI
import uvicorn

app = FastAPI()

POD_IP        = os.environ["POD_IP"]
ASN           = int(os.environ["ASN"])
ROUTER_ID     = os.environ["ROUTER_ID"]
POD_NAMESPACE = os.environ["POD_NAMESPACE"]
NEIGHBORS_JSON_STR = os.environ["NEIGHBORS_JSON"]

CONFIG_PATH = "/etc/gobgp/gobgp.conf"

neighbor_state: Dict[str, dict] = {}
gobgpd_proc: Optional[subprocess.Popen] = None
state_lock = threading.Lock()


def parse_neighbors_json(s: str) -> Dict[str, dict]:
    data = json.loads(s)
    out: Dict[str, dict] = {}
    for item in data:
        name = item["name"]
        peer_as = int(item["peerAs"])
        tags = [int(t) for t in item.get("communitiesAddTags", [])]
        out[name] = {"peerAs": peer_as, "tags": tags, "ip": None}
    return out


NEIGHBOR_SEED = parse_neighbors_json(NEIGHBORS_JSON_STR)


def resolve_neighbor(name: str) -> Optional[str]:
    fqdn = f"{name}.{POD_NAMESPACE}.svc"
    try:
        ip = subprocess.check_output(["getent", "hosts", fqdn], text=True).split()[0]
        print(f"[Resolve] {fqdn} -> {ip}", flush=True)
        return ip
    except subprocess.CalledProcessError:
        print(f"[Resolve] {fqdn} -> no IP found", flush=True)
        return None


def generate_config() -> None:
    with state_lock:
        snapshot = {k: v.copy() for k, v in neighbor_state.items()}

    peer_as_list = sorted({v["peerAs"] for v in snapshot.values()})

    import_policies = ", ".join([f'"tag-from-as{p_as}"' for p_as in peer_as_list])

    lines: List[str] = []
    lines += [
        "[global.config]",
        f"  as = {ASN}",
        f'  router-id = "{ROUTER_ID}"',
        "",
        "[global.apply-policy.config]",
        f"  import-policy-list = [{import_policies}]",
        '  default-import-policy = "accept-route"',
        "",
    ]

    for p_as in peer_as_list:
        lines += [
            "[[defined-sets.bgp-defined-sets.as-path-sets]]",
            f'  as-path-set-name = "from-as{p_as}"',
            f'  as-path-list = ["^{p_as}$", "^{p_as}_"]',
            ""
        ]

    tags_by_as: Dict[int, List[int]] = {}
    for v in snapshot.values():
        tags_by_as.setdefault(v["peerAs"], set()).update(v.get("tags", []))

    for p_as in peer_as_list:
        lines += [
            "[[policy-definitions]]",
            f'  name = "tag-from-as{p_as}"',
            "  [[policy-definitions.statements]]",
            f'    name = "tag-{ASN}-from-as{p_as}"',
            "    [policy-definitions.statements.conditions.bgp-conditions.match-as-path-set]",
            f'      as-path-set = "from-as{p_as}"',
            '      match-set-options = "any"',
            "    [policy-definitions.statements.actions]",
            '      route-disposition = "accept-route"',
        ]
        tag_set = tags_by_as.get(p_as, set())
        if tag_set:
            comms_str = ", ".join([f'"{ASN}:{t}"' for t in sorted(tag_set)])
            lines += [
                "    [policy-definitions.statements.actions.bgp-actions.set-community]",
                '      options = "add"',
                "      [policy-definitions.statements.actions.bgp-actions.set-community.set-community-method]",
                f"        communities-list = [{comms_str}]",
            ]
        lines.append("")

    for name, v in snapshot.items():
        ip = v.get("ip")
        if not ip:
            continue
        peer_as = v["peerAs"]
        lines += [
            "[[neighbors]]",
            "  [neighbors.config]",
            f'    neighbor-address = "{ip}"',
            f"    peer-as = {peer_as}",
            "  [neighbors.add-paths.config]",
            "    receive = true",
            "    send-max = 3",
            "  [[neighbors.afi-safis]]",
            "    [neighbors.afi-safis.config]",
            '      afi-safi-name = "ipv4-unicast"',
            ""
        ]

    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        f.write("\n".join(lines))
    print(f"[Config] written to {CONFIG_PATH}", flush=True)


def restart_gobgpd() -> None:
    global gobgpd_proc
    if gobgpd_proc and gobgpd_proc.poll() is None:
        print("[Gobgpd] stopping old process", flush=True)
        gobgpd_proc.send_signal(signal.SIGTERM)
        try:
            gobgpd_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            print("[Gobgpd] SIGKILL old process", flush=True)
            gobgpd_proc.kill()
            gobgpd_proc.wait()
    print(f"[Gobgpd] starting with {CONFIG_PATH}", flush=True)
    gobgpd_proc = subprocess.Popen(["gobgpd", "-f", CONFIG_PATH])


def poll_neighbors_loop() -> None:
    with state_lock:
        neighbor_state.update(NEIGHBOR_SEED)

    first_render = True
    while True:
        changed = False
        for name in list(neighbor_state.keys()):
            ip = resolve_neighbor(name)
            with state_lock:
                old_ip = neighbor_state[name].get("ip")
                if ip != old_ip:
                    neighbor_state[name]["ip"] = ip
                    print(f"[State] {name} IP changed: {old_ip} -> {ip}", flush=True)
                    changed = True

        if changed or first_render:
            if any(v.get("ip") for v in neighbor_state.values()):
                generate_config()
                restart_gobgpd()
                first_render = False
            else:
                print("[Config] skip render (no neighbor IPs yet)", flush=True)

        time.sleep(2)


@app.on_event("startup")
def on_startup():
    t = threading.Thread(target=poll_neighbors_loop, daemon=True)
    t.start()


@app.get("/ip")
def http_ip():
    return {"pod_ip": POD_IP}


@app.get("/config")
def http_config():
    try:
        with open(CONFIG_PATH, "r") as f:
            return {"config": f.read()}
    except FileNotFoundError:
        return {"error": "no config yet"}


def _shutdown(*_):
    global gobgpd_proc
    if gobgpd_proc and gobgpd_proc.poll() is None:
        try:
            gobgpd_proc.send_signal(signal.SIGTERM)
            gobgpd_proc.wait(timeout=10)
        except Exception:
            pass
    raise SystemExit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    uvicorn.run(app, host="0.0.0.0", port=8080)
