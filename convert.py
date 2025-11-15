#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.9"
# dependencies = ["pyyaml", "unidecode"]
# ///
import json
import yaml
import sys
import re
from unidecode import unidecode

def normalize(name: str) -> str:
    n = unidecode(name)
    n = n.lower()
    n = re.sub(r"[^a-z0-9]+", "-", n)
    return n.strip("-")

def capacity_from_utilization(util_percent: float) -> int:
    if util_percent < 10.0:
        return 1_000
    elif util_percent < 33.0:
        return 10_000
    elif util_percent <= 66.0:
        return 100_000
    else:
        return 400_000

def latency_from_distance(dist_km: float) -> float:
    return max(1.0, round(dist_km * 0.005, 3))

def encode_bitfield(cap: int, lat: float) -> int:
    cap_exp = min(cap.bit_length(), 255)
    lat_val = min(int(lat), 255)
    return ((cap_exp & 0xFF) << 8) | (lat_val & 0xFF)

def add_neighbor(routers, a, b, comm):
    if not any(nb["name"] == b for nb in routers[a]["neighbors"]):
        routers[a]["neighbors"].append({
            "name": b,
            "peerAs": routers[b]["asn"],
            "communitiesAddTags": [comm]
        })

def convert(json_file: str, yaml_file: str):
    with open(json_file, "r") as f:
        data = json.load(f)

    nodes = {n["id"]: normalize(n["name"]) for n in data.get("nodes", [])}
    links = data.get("links", [])
    routers = {}

    for link in links:
        src = link["source"]
        dst = link["target"]
        dist_km = link.get("dist", 100)

        util_fwd = link.get("ecmp_fwd", {}).get("deg", 0)
        util_bwd = link.get("ecmp_bwd", {}).get("deg", 0)

        rname = nodes.get(src, f"router-{src}")
        nbname = nodes.get(dst, f"router-{dst}")

        if rname not in routers:
            routers[rname] = {
                "asn": 65000 + int(src),
                "routerId": f"10.0.0.{int(src)+1}",
                "neighbors": []
            }
        if nbname not in routers:
            routers[nbname] = {
                "asn": 65000 + int(dst),
                "routerId": f"10.0.0.{int(dst)+1}",
                "neighbors": []
            }

        lat = latency_from_distance(dist_km)

        cap_fwd = capacity_from_utilization(util_fwd)
        comm_fwd = encode_bitfield(cap_fwd, lat)
        add_neighbor(routers, rname, nbname, comm_fwd)

        cap_bwd = capacity_from_utilization(util_bwd)
        comm_bwd = encode_bitfield(cap_bwd, lat)
        add_neighbor(routers, nbname, rname, comm_bwd)

    values_yaml = {
        "image": {
            "repository": "gobgp",
            "tag": "dev",
            "pullPolicy": "IfNotPresent"
        },
        "routers": routers
    }

    with open(yaml_file, "w") as f:
        yaml.dump(values_yaml, f, sort_keys=False)

def main():
    if len(sys.argv) != 3:
        print("Usage: convert <input.json> <output.yaml>")
        sys.exit(1)
    convert(sys.argv[1], sys.argv[2])
    print(f"Conversion completed → {sys.argv[2]}")

if __name__ == "__main__":
    main()
