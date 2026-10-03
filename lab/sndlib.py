"""Imports networks of SNDlib (sndlib.put.poznan.pl) as topologies.

Every node becomes a router in its own AS, every link a BGP session.
Longitudes and latitudes become map locations; other coordinates only
place the routers in the graph view. The router with the most links is
the origin; change it in the editor.
"""

import math
import os
import re
import urllib.request
import zipfile
from pathlib import Path

from . import topology

ARCHIVE_URL = "https://sndlib.put.poznan.pl/download/sndlib-networks-native.zip"
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "obgp-lab" / "sndlib-networks-native.zip"
WIDTH = 900  # of the graph view, in pixels


def archive() -> zipfile.ZipFile:
    """The SNDlib network archive, downloaded once."""
    if not CACHE.exists():
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(ARCHIVE_URL, timeout=60) as response:
            part = CACHE.with_suffix(".part")
            part.write_bytes(response.read())
            part.replace(CACHE)
    return zipfile.ZipFile(CACHE)


def networks() -> dict[str, str]:
    """Maps network names to their native file content."""
    with archive() as z:
        return {Path(n).stem: z.read(n).decode() for n in z.namelist() if n.endswith(".txt")}


def parse(text: str) -> tuple[dict[str, tuple[float, float]], list[tuple[str, str]]]:
    """Returns the nodes with their coordinates and the undirected links."""
    if "NODES (" not in text or "LINKS (" not in text:
        raise ValueError("not an SNDlib network in native format: no NODES or LINKS section")
    section = lambda name: text.split(f"{name} (", 1)[1].split("\n)", 1)[0]
    nodes = {n: (float(x), float(y)) for n, x, y in re.findall(r"^\s*(\S+)\s*\(\s*([-\d.eE]+)\s+([-\d.eE]+)\s*\)", section("NODES"), re.M)}
    links = {tuple(sorted((a, b))) for a, b in re.findall(r"^\s*\S+\s*\(\s*(\S+)\s+(\S+)\s*\)", section("LINKS"), re.M) if a != b}
    return nodes, sorted(links)


def is_geographic(nodes: dict[str, tuple[float, float]]) -> bool:
    """Whether the coordinates are longitudes and latitudes, not units of a drawing.

    Drawings place nodes on whole units, real locations are fractional.
    """
    values = [v for xy in nodes.values() for v in xy]
    return (all(-180 <= x <= 180 and -90 <= y <= 90 for x, y in nodes.values())
            and not all(v.is_integer() for v in values) and len({*nodes.values()}) > 1)


def slug(node: str, taken: set[str] = frozenset()) -> str:
    """A name of lowercase letters, digits and dashes, unique among taken."""
    base = re.sub(r"[^a-z0-9]+", "-", node.lower()).strip("-")[:55] or "router"
    name, i = base, 2
    while name in taken:
        name, i = f"{base}-{i}", i + 1
    return name


def convert(network: str, text: str) -> dict:
    """The topology of an SNDlib network, as lab.topology works with it."""
    nodes, links = parse(text)
    if not nodes:
        raise ValueError("the network has no nodes")
    if unknown := {n for link in links for n in link} - nodes.keys():
        raise ValueError(f"links to unknown nodes: {', '.join(sorted(unknown))}")
    names: dict[str, str] = {}
    for node in nodes:
        names[node] = slug(node, set(names.values()))
    geographic = is_geographic(nodes)
    # Longitudes shrink towards the poles.
    shrink = math.cos(math.radians(sum(y for _, y in nodes.values()) / len(nodes))) if geographic else 1
    xs, ys = [x * shrink for x, _ in nodes.values()], [y for _, y in nodes.values()]
    scale = WIDTH / max(max(xs) - min(xs), max(ys) - min(ys), 1e-9)
    routers = {}
    for i, (node, (x, y)) in enumerate(nodes.items()):
        r = routers[names[node]] = {"asn": 65000 + i, "routerId": f"10.0.{(i + 1) // 256}.{(i + 1) % 256}", "neighbors": []}
        if geographic:
            r["location"] = {"lat": round(y, 4), "lon": round(x, 4)}
        # Latitudes grow northwards, screen coordinates downwards.
        r["position"] = {"x": (x * shrink - min(xs)) * scale, "y": ((max(ys) - y) if geographic else (y - min(ys))) * scale}
    for a, b in links:
        ra, rb = routers[names[a]], routers[names[b]]
        ra["neighbors"].append({"name": names[b], "peerAs": rb["asn"]})
        rb["neighbors"].append({"name": names[a], "peerAs": ra["asn"]})
    origin = max(routers, key=lambda r: (len(routers[r]["neighbors"]), r))
    return {"source": f"sndlib/{network}", "roles": {"origins": [origin]}, "routers": routers}


def summary() -> list[dict]:
    """Name, size and map support of every SNDlib network."""
    out, imported = [], topology.sources()
    for name, text in sorted(networks().items()):
        t = convert(name, text)
        out.append({"name": name, "routers": len(t["routers"]), "links": sum(len(r["neighbors"]) for r in t["routers"].values()) // 2,
                    "map": all("location" in r for r in t["routers"].values()), "imported": imported.get(f"sndlib/{name}", [])})
    return out


def import_network(network: str, name: str | None = None, text: str | None = None) -> str:
    """Imports a network of SNDlib, or a file in its native format, and returns the topology name."""
    from_archive = text is None
    if from_archive:
        texts = networks()
        if network not in texts:
            raise ValueError(f"no SNDlib network {network}")
        text = texts[network]
    name = name or network
    if topology.path(name).exists():
        raise FileExistsError(f"A topology named {name} exists already.")
    t = convert(network, text)
    topology.save(name, t["routers"], t["roles"], t["source"] if from_archive else None)
    return name
