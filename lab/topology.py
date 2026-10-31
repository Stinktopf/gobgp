"""Topology files in gobgp-lab/topologies/: reading, validating, writing.

A topology lists its routers; each router lists its neighbors, with an
optional Local Preference for routes learned from that neighbor, and
optionally what the neighbor is to it: customer, peer, provider, or
sibling, an AS of the same organization. These relations make the routers
follow Gao-Rexford, siblings pass each other every route. A customer with
partialTransit: true gets only the routes of the provider's customers. Routers with the same ASN
form one AS and speak iBGP with each other: in a full mesh, or through
route reflectors that mark their clients with rrClient: true. A route
server marks its neighbors with rsClient: true: it passes their routes on
without its own AS and with their next hop, as gobgpd's. Inside an AS,
igp lists the links between its routers with a cost: no IGP runs, the lab
and the simulator forward over the cheapest links. A neighbor may get a
MED (med), a path filter (denyVia: no routes through that AS are sent
to it) and a community its routes get (tag, e.g. 0:65003 asks not to pass
them to AS 65003), and a router with leak: true exports every route to every
neighbor, ignoring valley-free: a route leak. Routers with the same
confederation are members of a confederation (RFC 5065): their asn is the
member AS, neighbors outside see the confederation as peerAs. Routers marked with
obgp: true run OBGP in hybrid variants. Roles
name groups of routers that scenarios refer to, e.g. origins. Routers may
carry a map location (lat, lon) or an editor position (x, y). The source
names where an imported topology comes from, e.g. sndlib/germany50.
Helm only sees the routers.
"""

import copy
import ipaddress
from pathlib import Path

from .config import (
    NAME,
    ROOT,
    _scalar,
    community_ok,
    file_of,
    load_yaml,
    names_kept,
    parsed_once,
)

DIRECTORY = ROOT / "gobgp-lab" / "topologies"


def path(name: str) -> Path:
    return file_of(DIRECTORY, name)


_parsed: dict[Path, tuple[tuple[int, int], dict]] = {}


def names() -> list[str]:
    """The topologies there are."""
    return names_kept(_parsed, DIRECTORY)


def load(name: str, shared: bool = False) -> dict:
    """Returns {"source": str | None, "roles": {...}, "routers": {...}}, a
    copy of its own. Parsed once until the file changes: parts of the
    Internet take a while to parse, and pages read every topology. Copying
    a large one takes long too, so callers that only read take the parsed
    one itself with shared, and must not change it."""
    parsed = parsed_once(_parsed, path(name), lambda file: parse(file.read_text()))
    return parsed if shared else copy.deepcopy(parsed)


def parse(text: str) -> dict:
    data = load_yaml(text)
    return {"source": data.get("source"), "roles": data.get("roles") or {}, "routers": data["routers"] or {}}


def validate(routers: dict, roles: dict | None = None) -> list[str]:
    """Returns the problems of a topology, empty if it is valid."""
    problems = []
    for role, members in (roles or {}).items():
        if not NAME.fullmatch(role) or role in routers:
            problems.append(f"role {role}: names use lowercase letters, digits and dashes, not the name of a router")
        if unknown := [m for m in members if m not in routers]:
            problems.append(f"role {role}: unknown routers {', '.join(unknown)}")
    ids = {}
    for name, r in routers.items():
        if not NAME.fullmatch(name):
            problems.append(f"{name}: names use lowercase letters, digits and dashes")
        try:
            asn = int(r["asn"])
            if not 1 <= asn < 2**32 - 1:
                raise ValueError
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
        if r.get("leak") not in (None, True, False):
            problems.append(f"{name}: leak must be true or false")
        if (c := r.get("confederation")) is not None and (not isinstance(c, int) or isinstance(c, bool) or not 1 <= c < 2**32 - 1):
            problems.append(f"{name}: invalid confederation")
        for link in r.get("igp", []):
            other, cost = routers.get(link.get("name")), link.get("cost")
            if other is None or link.get("name") == name:
                problems.append(f"{name}: unknown IGP link to {link.get('name')}")
            elif str(other.get("asn")) != str(r.get("asn")):
                problems.append(f"{name}: IGP link to {link['name']} leaves the AS")
            elif not isinstance(cost, int) or isinstance(cost, bool) or cost < 1:
                problems.append(f"{name}: IGP cost to {link['name']} must be a positive integer")
            elif not any(m.get("name") == name and m.get("cost") == cost for m in other.get("igp", [])):
                problems.append(f"{name}: {link['name']} does not list the IGP link with cost {cost}")
    for name, r in routers.items():
        for n in r.get("neighbors", []):
            peer = routers.get(n.get("name"))
            if peer is None:
                problems.append(f"{name}: unknown neighbor {n.get('name')}")
                continue
            if str(n.get("peerAs")) != str(seen_as(r, peer)):
                problems.append(f"{name}: peerAs of {n['name']} is not its ASN" +
                                (", outside its confederation that is the confederation" if peer.get("confederation") else ""))
            if not any(m.get("name") == name for m in peer.get("neighbors", [])):
                problems.append(f"{name}: {n['name']} does not list {name} as neighbor")
            internal = str(peer.get("asn")) == str(r.get("asn"))
            member = not internal and r.get("confederation") is not None and r.get("confederation") == peer.get("confederation")
            med = n.get("med")
            if med is not None and (not isinstance(med, int) or isinstance(med, bool) or med < 0 or internal):
                problems.append(f"{name}: MED towards {n['name']} must be a number from 0, to another AS")
            via = n.get("denyVia")
            if via is not None and (not isinstance(via, int) or isinstance(via, bool) or not 1 <= via < 2**32 - 1 or internal):
                problems.append(f"{name}: denyVia towards {n['name']} must be an ASN, to another AS")
            if n.get("tag") is not None and (not community_ok(n["tag"]) or internal):
                problems.append(f"{name}: the tag of {n['name']} must be a community like 0:65003 or no-export, from another AS")
            if n.get("rrClient") not in (None, True, False):
                problems.append(f"{name}: rrClient of {n['name']} must be true or false")
            elif n.get("rrClient") and not internal:
                problems.append(f"{name}: {n['name']} is in another AS and cannot be a route reflector client")
            elif n.get("rrClient") and any(m.get("name") == name and m.get("rrClient") for m in peer.get("neighbors", [])):
                problems.append(f"{name}: {n['name']} and {name} cannot both be clients of each other")
            if n.get("rsClient") not in (None, True, False):
                problems.append(f"{name}: rsClient of {n['name']} must be true or false")
            elif n.get("rsClient") and (internal or member):
                problems.append(f"{name}: {n['name']} is in its own AS or confederation and cannot be a route server client")
            if internal and (n.get("relation") or n.get("localPref") is not None):
                problems.append(f"{name}: {n['name']} is in the same AS, relation and Local Preference are for other ASes")
                continue
            if member and n.get("relation"):
                problems.append(f"{name}: {n['name']} is in the same confederation, relations are for other ASes")
                continue
            lp = n.get("localPref")
            if lp is not None and (not isinstance(lp, int) or lp < 1):
                problems.append(f"{name}: Local Preference for {n['name']} must be a positive integer")
            relation = n.get("relation")
            if n.get("partialTransit") not in (None, True, False) or n.get("partialTransit") and relation != "customer":
                problems.append(f"{name}: partial transit is for a customer, true or false, not for {n['name']}")
            if relation not in (None, *RELATIONS):
                problems.append(f"{name}: relation of {n['name']} must be one of {', '.join(RELATIONS)}")
                continue
            back = next((m.get("relation") for m in peer.get("neighbors", []) if m.get("name") == name), None)
            if back != RELATIONS.get(relation):
                problems.append(f"{name}: {n['name']} is its {relation or 'neighbor'}, but {name} is not its {RELATIONS.get(relation) or 'neighbor'}")
    if cycle := provider_cycle(routers):
        problems.append(f"providers form a cycle: {' → '.join(cycle)}")
    for asn, members in ases(routers).items():
        for a in members:
            if missing := sorted(set(members) - ibgp_reach(routers, a)):
                problems.append(f"AS {asn}: iBGP does not carry routes of {a} to {', '.join(missing)}. "
                                "Mesh them, or add a route reflector")
                break
    return problems


def ases(routers: dict) -> dict[int, list[str]]:
    """The ASes of more than one router, by ASN."""
    out: dict[int, list[str]] = {}
    for name, r in routers.items():
        try:
            out.setdefault(int(r["asn"]), []).append(name)
        except (KeyError, TypeError, ValueError):
            continue
    return {asn: members for asn, members in out.items() if len(members) > 1}


def ibgp_reach(routers: dict, start: str) -> set[str]:
    """The routers of its AS that a route of start reaches over iBGP: a
    route learned over iBGP goes on only through a route reflector, from a
    client to all, from others to its clients (RFC 4456)."""
    asn = str(routers[start].get("asn"))
    clients = {name: {n["name"] for n in r.get("neighbors", []) if n.get("rrClient")} for name, r in routers.items()}
    internal = {name: [n["name"] for n in r.get("neighbors", []) if str(routers.get(n["name"], {}).get("asn")) == asn]
                for name, r in routers.items() if str(r.get("asn")) == asn}
    reached, queue = {start}, [(start, None)]
    while queue:
        at, came = queue.pop()
        for nxt in internal.get(at, []):
            passes = came is None or came in clients[at] or nxt in clients[at]
            if passes and nxt not in reached:
                reached.add(nxt)
                queue.append((nxt, at))
    return reached


def seen_as(router: dict, peer: dict):
    """The AS a router sees its peer in: the confederation from outside it, else the peer's own."""
    if peer.get("confederation") is not None and peer.get("confederation") != router.get("confederation"):
        return peer["confederation"]
    return peer.get("asn")


# What a neighbor is to a router, and what the router then is to it.
RELATIONS = {"customer": "provider", "peer": "peer", "provider": "customer", "sibling": "sibling"}


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


def one_as(t: dict, externals: int = 4, reflectors: int = 2, asn: int = 65000) -> dict:
    """A network as the inside of one AS: its routers speak iBGP through the
    reflectors, the routers of most links, which mesh among themselves. The
    next routers by links each get a neighbor in an AS of its own, ext-1 on,
    the origin of the prefixes. These neighbors form a ring, so that routes
    enter the AS at several borders. The links of the network become its IGP, of
    cost 1, over which the lab and the simulator forward inside the AS."""
    routers = t["routers"]
    if len(routers) < 2:
        raise ValueError("one AS needs at least two routers")
    by_links = sorted(routers, key=lambda r: (-len(routers[r].get("neighbors", [])), r))
    rrs = by_links[:max(1, min(reflectors, len(routers) - 1))]
    borders = [r for r in by_links if r not in rrs][:externals] or rrs[:1]
    out = {}
    for name, r in routers.items():
        router = {k: v for k, v in r.items() if k != "neighbors"} | {"asn": asn, "neighbors": []}
        if name in rrs:
            router["neighbors"] = [{"name": o, "peerAs": asn} for o in rrs if o != name]
            router["neighbors"] += [{"name": c, "peerAs": asn, "rrClient": True} for c in routers if c not in rrs]
        else:
            router["neighbors"] = [{"name": rr, "peerAs": asn} for rr in rrs]
        # The links of the network become the IGP of the AS, all of cost 1.
        router["igp"] = [{"name": n["name"], "cost": 1} for n in r.get("neighbors", []) if n["name"] in routers]
        out[name] = router
    placed = [r["position"] for r in routers.values() if "position" in r]
    for i, border in enumerate(borders, 1):
        ext = f"ext-{i}"
        out[ext] = {"asn": asn + i, "routerId": f"10.255.0.{i}", "neighbors": [{"name": border, "peerAs": asn}]}
        if "position" in routers[border]:
            out[ext]["position"] = outside(routers[border]["position"], placed)
        out[border]["neighbors"].append({"name": ext, "peerAs": asn + i})
    # The neighbors outside form a ring, so that routes enter the AS at several borders.
    names = [f"ext-{i}" for i in range(1, len(borders) + 1)]
    for a, b in zip(names, names[1:] + names[:1]) if len(names) > 2 else zip(names[:1], names[1:]):
        out[a]["neighbors"].append({"name": b, "peerAs": out[b]["asn"]})
        out[b]["neighbors"].append({"name": a, "peerAs": out[a]["asn"]})
    return {"source": t.get("source"), "roles": {"origins": ["ext-1"], "externals": [f"ext-{i}" for i in range(1, len(borders) + 1)]},
            "routers": out}


def outside(at: dict, placed: list[dict], margin: float = 70) -> dict:
    """A position beyond the box of all placed routers, in the direction of
    at from their centre: for a neighbor drawn outside the frame of an AS."""
    xs, ys = [p["x"] for p in placed], [p["y"] for p in placed]
    cx, cy = sum(xs) / len(xs), sum(ys) / len(ys)
    dx, dy = at["x"] - cx, at["y"] - cy
    if abs(dx) < 1e-9 and abs(dy) < 1e-9:
        dx, dy = 0.0, -1.0
    steps = [((max(xs) if dx > 0 else min(xs)) + (margin if dx > 0 else -margin) - cx) / dx if dx else float("inf"),
             ((max(ys) if dy > 0 else min(ys)) + (margin if dy > 0 else -margin) - cy) / dy if dy else float("inf")]
    t = min(steps)
    return {"x": cx + t * dx, "y": cy + t * dy}


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
        if r.get("leak"):
            lines.append("    leak: true")
        if r.get("confederation") is not None:
            lines.append(f"    confederation: {int(r['confederation'])}")
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
            if n.get("rrClient"):
                lines.append("        rrClient: true")
            if n.get("rsClient"):
                lines.append("        rsClient: true")
            if n.get("med") is not None:
                lines.append(f"        med: {int(n['med'])}")
            if n.get("denyVia") is not None:
                lines.append(f"        denyVia: {int(n['denyVia'])}")
            if n.get("tag") is not None:
                lines.append(f"        tag: {_scalar(n['tag'])}")
            if n.get("partialTransit"):
                lines.append("        partialTransit: true")
        if r.get("igp"):
            lines.append("    igp:")
            lines += [f"      - {{name: {link['name']}, cost: {int(link['cost'])}}}" for link in r["igp"]]
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

