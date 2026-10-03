"""Topology files in gobgp-lab/topologies/: reading, validating, writing.

A topology lists its routers; each router lists its neighbors, with an
optional Local Preference for routes learned from that neighbor, and
optionally what the neighbor is to it: customer, peer or provider. These
relations make the routers follow Gao-Rexford. Routers marked with
obgp: true run OBGP in hybrid variants. Roles
name groups of routers that scenarios refer to, e.g. origins. Routers may
carry a map location (lat, lon) or an editor position (x, y). The source
names where an imported topology comes from, e.g. sndlib/germany50.
Helm only sees the routers.
"""

import copy
import ipaddress
from pathlib import Path

from .config import NAME, ROOT, file_of, load_yaml, names_in

DIRECTORY = ROOT / "gobgp-lab" / "topologies"


def path(name: str) -> Path:
    return file_of(DIRECTORY, name)


def names() -> list[str]:
    return names_in(DIRECTORY)


_parsed: dict[Path, tuple[tuple[int, int], dict]] = {}


def load(name: str, shared: bool = False) -> dict:
    """Returns {"source": str | None, "roles": {...}, "routers": {...}}, a
    copy of its own. Parsed once until the file changes: parts of the
    Internet take a while to parse, and pages read every topology. Copying
    a large one takes long too, so callers that only read take the parsed
    one itself with shared, and must not change it."""
    file = path(name)
    stat = file.stat()
    stamp = (stat.st_mtime_ns, stat.st_size)
    if (kept := _parsed.get(file)) is None or kept[0] != stamp:
        kept = _parsed[file] = (stamp, parse(file.read_text()))
    return kept[1] if shared else copy.deepcopy(kept[1])


def parse(text: str) -> dict:
    data = load_yaml(text)
    return {"source": data.get("source"), "roles": data.get("roles") or {}, "routers": data["routers"] or {}}


def validate(routers: dict, roles: dict | None = None) -> list[str]:
    """Returns the problems of a topology, empty if it is valid."""
    problems = []
    for role, members in (roles or {}).items():
        if unknown := [m for m in members if m not in routers]:
            problems.append(f"role {role}: unknown routers {', '.join(unknown)}")
    asns, ids = {}, {}
    for name, r in routers.items():
        if not NAME.fullmatch(name):
            problems.append(f"{name}: names use lowercase letters, digits and dashes")
        try:
            asn = int(r["asn"])
            if not 1 <= asn < 2**32 - 1:
                raise ValueError
            if asn in asns:
                problems.append(f"{name}: ASN {asn} is used by {asns[asn]}")
            asns[asn] = name
        except (KeyError, TypeError, ValueError):
            problems.append(f"{name}: invalid ASN")
        try:
            rid = str(ipaddress.IPv4Address(r["routerId"]))
            if rid in ids:
                problems.append(f"{name}: router ID {rid} is used by {ids[rid]}")
            ids[rid] = name
        except (KeyError, ValueError):
            problems.append(f"{name}: invalid router ID")
        if r.get("obgp") not in (None, True, False):
            problems.append(f"{name}: obgp must be true or false")
    for name, r in routers.items():
        for n in r.get("neighbors", []):
            peer = routers.get(n.get("name"))
            if peer is None:
                problems.append(f"{name}: unknown neighbor {n.get('name')}")
                continue
            if str(n.get("peerAs")) != str(peer.get("asn")):
                problems.append(f"{name}: peerAs of {n['name']} is not its ASN")
            if not any(m.get("name") == name for m in peer.get("neighbors", [])):
                problems.append(f"{name}: {n['name']} does not list {name} as neighbor")
            lp = n.get("localPref")
            if lp is not None and (not isinstance(lp, int) or lp < 1):
                problems.append(f"{name}: Local Preference for {n['name']} must be a positive integer")
            relation = n.get("relation")
            if relation not in (None, *RELATIONS):
                problems.append(f"{name}: relation of {n['name']} must be one of {', '.join(RELATIONS)}")
                continue
            back = next((m.get("relation") for m in peer.get("neighbors", []) if m.get("name") == name), None)
            if back != RELATIONS.get(relation):
                problems.append(f"{name}: {n['name']} is its {relation or 'neighbor'}, but {name} is not its {RELATIONS.get(relation) or 'neighbor'}")
    if cycle := provider_cycle(routers):
        problems.append(f"providers form a cycle: {' → '.join(cycle)}")
    return problems


# What a neighbor is to a router, and what the router then is to it.
RELATIONS = {"customer": "provider", "peer": "peer", "provider": "customer"}


def provider_cycle(routers: dict) -> list[str] | None:
    """A chain of routers, each the provider of the next, that returns to its
    start; None if the providers form a hierarchy, as Gao-Rexford needs."""
    customers = {r: [n["name"] for n in cfg.get("neighbors", []) if n.get("relation") == "customer"] for r, cfg in routers.items()}
    state: dict[str, int] = {}  # 1 on the path, 2 done

    def visit(r: str, path: list[str]) -> list[str] | None:
        state[r] = 1
        for c in customers.get(r, []):
            if state.get(c) == 1:
                return path[path.index(c):] + [c] if c in path else [r, c]
            if c not in state and (found := visit(c, path + [c])):
                return found
        state[r] = 2
        return None

    for r in routers:
        if r not in state and (found := visit(r, [r])):
            return found
    return None


def dump(routers: dict, roles: dict | None = None, source: str | None = None) -> str:
    lines = []
    if source:
        lines.append(f"source: {source}")
    if roles:
        lines.append("roles:")
        lines += [f"  {role}: [{', '.join(members)}]" for role, members in roles.items()]
    lines.append("routers:")
    for name, r in routers.items():
        lines += [f"  {name}:", f"    asn: {int(r['asn'])}", f"    routerId: {r['routerId']}"]
        if r.get("obgp"):
            lines.append("    obgp: true")
        if "location" in r:
            lines.append(f"    location: {{lat: {r['location']['lat']}, lon: {r['location']['lon']}}}")
        if "position" in r:
            lines.append(f"    position: {{x: {round(r['position']['x'])}, y: {round(r['position']['y'])}}}")
        lines.append("    neighbors:")
        for n in r.get("neighbors", []):
            lines += [f"      - name: {n['name']}", f"        peerAs: {int(n['peerAs'])}"]
            if n.get("localPref") is not None:
                lines.append(f"        localPref: {int(n['localPref'])}")
            if n.get("relation"):
                lines.append(f"        relation: {n['relation']}")
    return "\n".join(lines) + "\n"


def save(name: str, routers: dict, roles: dict | None = None, source: str | None = None) -> None:
    if problems := validate(routers, roles):
        raise ValueError("; ".join(problems))
    path(name).write_text(dump(routers, roles, source))


def sources() -> dict[str, list[str]]:
    """Maps each source to the topologies that come from it."""
    out: dict[str, list[str]] = {}
    for name in names():
        if source := load(name)["source"]:
            out.setdefault(source, []).append(name)
    return out

