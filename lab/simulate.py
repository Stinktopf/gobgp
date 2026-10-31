"""The simulator and the lab, each in the terms of the other.

The simulator (internal/pkg/obgpsim, cmd/obgp-sim) plays one prefix with
the decision code of gobgpd. A topology and scenario of the lab become an
instance of it, and an instance becomes a topology and scenario, so that
both judge the same network alike. What one side cannot express is named,
never approximated: a conversion either is exact or says why it is not.

The same on both sides:
  routers and ASes          a router per entry, routers of one ASN one AS
  iBGP                      a full mesh, or route reflectors whose clients
                            are all others of the AS, meshed among themselves
  IGP                       the igp costs of the topology, no IGP runs
  relations, Local Pref.    Gao-Rexford with 200, 150 and 100, siblings,
                            partialTransit, localPref
  MED, leaks                med per neighbor, leak per router
  tagging                   tag per neighbor
  announce                  one origin, its prefixes stay: the simulator
                            plays one of them, prefixes do not interact.
                            For a comparison, one instance per origin and
                            per life of a prefix, held or removed
  withdraw                  all prefixes
  down, up                  a link a-b, closed with a notification
  set_preference, prepend, set_export, set_import
  expect                    prefixes, via, avoid and forwarding
  until_stable, wait        the simulator plays until the network is quiet

The order of messages is not the lab's to choose: where a result depends
on it, compare how often it occurs, over seeds of the simulator and runs
of the lab, never one run with one seed.
"""

import json
import os
import shutil
import subprocess
import threading
import tempfile
from pathlib import Path

from . import scenario as scenarios
from . import topology as topologies
from .config import ROOT

QUIET = 1 << 30  # an event of the simulator once the network is quiet
GO_IMAGE = "golang:1.24"  # as the Dockerfile builds gobgpd


class Unsupported(ValueError):
    """What the other side cannot express, one reason per item."""

    def __init__(self, reasons: list[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = reasons


# Lab to simulator

def to_instance(topology: dict, scenario) -> dict:
    """The instance of the simulator for a topology and scenario of the
    lab, as plain data. Unsupported names everything that does not map."""
    return _instance(topology, scenario)


def to_instances(topology: dict, scenario) -> list[tuple[str, dict]]:
    """The instances of the simulator that together play a topology and
    scenario of the lab for its pure modes, each with a label: one per
    origin, as prefixes do not interact, and one per life a prefix can
    have, held or removed once the network is quiet, by expiry or a
    partial withdraw. Marks of hybrids do not matter in pure modes.
    Unsupported names what does not map."""
    sc = scenario if isinstance(scenario, scenarios.Scenario) else scenarios.parse(scenario)
    origins = [o for o in topology.get("roles", {}).get("origins", []) if o in topology["routers"]]
    lives, problems = _lives(sc.steps)
    if not origins:
        problems.append("no origin")
    out = []
    for origin in origins:
        for life in lives:
            try:
                inst = _instance(topology, sc, origin, life)
            except Unsupported as e:
                problems += [r for r in e.reasons if r not in problems]
                continue
            out.append((" · ".join(x for x in (origin if len(origins) > 1 else "", life if len(lives) > 1 else "") if x), inst))
    if problems:
        raise Unsupported(problems)
    return out


def _lives(steps: list) -> tuple[list[str], list[str]]:
    """The lives of a prefix of the first announcement: held, or removed by
    expiry or a partial withdraw. An expiry is played once the network is
    quiet, which is exact only where no other step follows that it could
    fall before or after; times are upper bounds, until_stable at its timeout."""
    first = next((i for i, s in enumerate(steps) if s.kind == "announce"), None)
    if first is None:
        return ["held"], []
    a, after = steps[first].args, steps[first + 1:]
    partial = any(s.kind == "withdraw" and s.args.percent < 100 for s in after)
    bound = {"wait": lambda s: s.args, "until_stable": lambda s: s.args.timeout, "announce": lambda s: s.args.for_}
    end = a.for_ + sum(bound[s.kind](s) if s.kind in bound else 0 for s in after)
    expiring = a.lifetime < 3600 and a.lifetime * (1 - a.jitter) < end
    problems = []
    if expiring and (others := sorted({s.kind for s in after if s.kind not in ("wait", "until_stable", "withdraw")})):
        problems.append(f"prefixes expire after {a.lifetime * (1 - a.jitter):g} s or later while {', '.join(others)} follow, "
                        "the simulator cannot place the expiry among them")
    held = not expiring or a.for_ + a.lifetime * (1 + a.jitter) >= end
    return [life for life, ok in (("held", held), ("removed", expiring or partial)) if ok], problems


def _instance(topology: dict, scenario, origin: str | None = None, life: str | None = None) -> dict:
    """An instance for one origin and one life of its prefix, or with
    neither, the strict translation: one origin, prefixes held."""
    routers = topology["routers"]
    names = list(routers)
    index = {name: i for i, name in enumerate(names)}
    problems = []
    asns = []
    for name in names:
        if int(routers[name]["asn"]) not in asns:
            asns.append(int(routers[name]["asn"]))
    as_of = [asns.index(int(routers[n]["asn"])) for n in names]
    # The lab's numbers: OBGP orders paths by AS number, iBGP breaks ties by router ID.
    inst = {"routers": len(names), "asns": asns, "router_ids": [str(routers[n]["routerId"]) for n in names],
            "links": [], "costs": [], "seed": 1}
    if len(asns) < len(names):
        inst["as"] = as_of
    sessions, customers, peers, siblings = [], [], [], []
    for name in names:
        r = routers[name]
        if r.get("obgp") and life is None:
            problems.append(f"{name}: hybrids, the simulator runs one mode on all routers")
        for n in r.get("neighbors", []):
            other = n["name"]
            if as_of[index[other]] == as_of[index[name]]:
                continue
            if index[name] < index[other]:
                inst["links"].append([index[name], index[other]])
                inst["costs"].append(1)
            relation = n.get("relation")
            if relation == "customer":
                customers.append([index[name], index[other]])
            elif relation == "peer" and index[name] < index[other]:
                peers.append([index[name], index[other]])
            elif relation == "sibling" and index[name] < index[other]:
                siblings.append([index[name], index[other]])
            if n.get("localPref") is not None:
                sessions.append({"from": index[other], "to": index[name], "local_pref": int(n["localPref"])})
            if n.get("tag") is not None:
                sessions.append({"from": index[other], "to": index[name], "tag": n["tag"]})
            if n.get("partialTransit"):
                sessions.append({"from": index[name], "to": index[other], "partial_transit": True})
            if n.get("med") is not None:
                sessions.append({"from": index[name], "to": index[other], "med": int(n["med"])})
            if n.get("denyVia") is not None:
                sessions.append({"from": index[name], "to": index[other], "deny_via": int(n["denyVia"])})
    for a, b, cost in _igp(routers):
        inst["links"].append([index[a], index[b]])
        inst["costs"].append(cost)
    if customers:
        inst["customers"] = customers
    if peers:
        inst["peers"] = peers
    if siblings:
        inst["siblings"] = siblings
    if sessions:
        inst["sessions"] = _merged(sessions)
    if leakers := [index[n] for n in names if routers[n].get("leak")]:
        inst["leakers"] = leakers
    # A route server serves all its neighbors, as the simulator plays it.
    servers = [n for n in names if any(m.get("rsClient") for m in routers[n].get("neighbors", []))]
    for n in servers:
        if not all(m.get("rsClient") for m in routers[n].get("neighbors", [])):
            problems.append(f"{n}: a route server with neighbors that are not its clients")
    if servers:
        inst["route_servers"] = [index[n] for n in servers]
    confeds: dict[int, list[int]] = {}
    for n in names:
        if (c := routers[n].get("confederation")) is not None and as_of[index[n]] not in confeds.setdefault(int(c), []):
            confeds[int(c)].append(as_of[index[n]])
    if confeds:
        inst["confeds"] = [{"members": sorted(m), "id": c} for c, m in confeds.items()]
    ibgp, why = _ibgp(routers, names, as_of)
    problems += why
    if ibgp:
        inst["ibgp"] = ibgp
    origins = [o for o in topology.get("roles", {}).get("origins", []) if o in routers]
    if origin is not None:
        inst["origin"] = index[origin]
    elif len(origins) != 1:
        problems.append(f"{len(origins)} origins, the simulator plays one")
    else:
        inst["origin"] = index[origins[0]]
    events, why = _events(scenario, topology, index, origin or (origins[0] if len(origins) == 1 else None), life)
    problems += why
    if events and "kind" not in events[0]:
        inst.update(events.pop(0))
    if events:
        inst["events"] = events
    if problems:
        raise Unsupported(problems)
    return inst


def _igp(routers: dict) -> list[tuple[str, str, int]]:
    from .forwarding import links
    return links(routers)


def _merged(sessions: list[dict]) -> list[dict]:
    """One policy per directed session."""
    out: dict[tuple[int, int], dict] = {}
    for s in sessions:
        out.setdefault((s["from"], s["to"]), {"from": s["from"], "to": s["to"]}).update(s)
    return list(out.values())


def _ibgp(routers: dict, names: list[str], as_of: list[int]) -> tuple[list[dict], list[str]]:
    """The iBGP of every AS of several routers as the simulator knows it: a
    full mesh, or reflectors whose clients are all other routers of the AS,
    meshed among themselves. Anything else is named."""
    out, problems = [], []
    for as_index in sorted(set(as_of)):
        members = [n for i, n in enumerate(names) if as_of[i] == as_index]
        if len(members) < 2:
            continue
        sessions = {frozenset((n, m["name"])) for n in members for m in routers[n].get("neighbors", []) if m["name"] in members}
        reflectors = [n for n in members if any(m.get("rrClient") for m in routers[n].get("neighbors", []))]
        if reflectors:
            clients = [n for n in members if n not in reflectors]
            wanted = {frozenset((a, b)) for a in reflectors for b in members if a != b}
            marked = all(any(m["name"] == c and m.get("rrClient") for m in routers[r].get("neighbors", [])) for r in reflectors for c in clients)
            if sessions != wanted or not marked:
                problems.append(f"AS {routers[members[0]]['asn']}: iBGP other than reflectors with all others as clients")
            out.append({"as": as_index, "reflectors": [names.index(r) for r in reflectors]})
        elif sessions != {frozenset((a, b)) for a in members for b in members if a != b}:
            problems.append(f"AS {routers[members[0]]['asn']}: iBGP neither a full mesh nor through reflectors")
    return out, problems


def _routers(target: str, topology: dict, index: dict) -> list[int] | None:
    """The routers a step names, as Network.routers_of resolves them, without
    random choices: all, a role or a router."""
    if target == "all" and target not in index:
        return sorted(index.values())
    if target in topology.get("roles", {}):
        return sorted(index[r] for r in topology["roles"][target] if r in index)
    if target in index:
        return [index[target]]
    return None


def _events(scenario, topology: dict, index: dict, own: str | None = None, life: str | None = None) -> tuple[list[dict], list[str]]:
    """The events of a scenario for the prefix of the origin own. With a
    life, prefixes may expire or be withdrawn in part: a removed prefix goes
    once the network is quiet after the first announcement, or at the
    partial withdraw; a held one stays. A check of all prefixes holds no
    claim on one that is gone, as the lab checks the prefixes still announced."""
    events, problems = [], []
    started = False
    present = True  # whether the prefix is announced
    origin: dict[str, list] = {}  # the AS_SET, poisoned ASes and communities of the announcement
    steps = scenario.steps if isinstance(scenario, scenarios.Scenario) else scenarios.parse(scenario).steps
    for position, step in enumerate(steps):
        kind, a = step.kind, step.args
        where = f"step {position + 1} ({kind})"
        if kind in ("until_stable", "wait", "soft_reset"):
            continue  # the simulator plays until quiet, and policies apply at once
        if kind == "announce":
            if a.router != "origins":
                problems.append(f"{where}: announce from the origins only")
            elif a.lifetime < 3600 and life is None:
                problems.append(f"{where}: prefixes that expire after {a.lifetime:g} s, the simulator holds its prefix")
            elif started and _origin(a) != origin:
                problems.append(f"{where}: another AS_SET, poison or communities than the first announcement")
            elif started:
                events.append({"after": QUIET, "kind": "announce"})
                present = True
            elif life == "removed" and a.lifetime < 3600 and not any(s.kind == "withdraw" and s.args.percent < 100 for s in steps):
                events.append({"after": QUIET, "kind": "withdraw"})  # it expires
                present = False
            origin = _origin(a)
            started = True
            continue
        if not started:
            problems.append(f"{where}: before the origin announces")
            continue
        if kind == "withdraw":
            origins = topology.get("roles", {}).get("origins", [])
            mine = a.router == "origins" or a.router == own
            if a.router not in ("origins", *origins) or (a.percent != 100 and life is None):
                problems.append(f"{where}: withdraw all prefixes of the origins only")
            elif mine and present and (a.percent == 100 or life == "removed"):
                events.append({"after": QUIET, "kind": "withdraw"})
                present = False
        elif kind in ("down", "up"):
            if not a.link or a.link == "random" or getattr(a, "mode", "session") != "session" or "-" not in a.link:
                problems.append(f"{where}: links a-b closed with a notification only")
                continue
            ends = _link(a.link, index)
            if ends is None:
                problems.append(f"{where}: unknown link {a.link}")
                continue
            events.append({"after": QUIET, "kind": kind, "from": ends[0], "to": ends[1]})
        elif kind in ("set_preference", "set_export", "set_import"):
            if a.router not in index or a.neighbor not in index:
                problems.append(f"{where}: a named router and neighbor only")
                continue
            r, n = index[a.router], index[a.neighbor]
            if kind == "set_preference":
                events.append({"after": QUIET, "kind": "local-pref", "from": n, "to": r, "value": a.value})
            elif kind == "set_export":
                events.append({"after": QUIET, "kind": "deny-export", "from": r, "to": n, "value": int(not a.allow)})
            else:
                events.append({"after": QUIET, "kind": "deny-import", "from": n, "to": r, "value": int(not a.allow)})
        elif kind == "igp":
            ends = _link(a.link, index)
            if ends is None:
                problems.append(f"{where}: unknown link {a.link}")
                continue
            events.append({"after": QUIET, "kind": "igp", "from": ends[0], "to": ends[1], "value": a.cost})
        elif kind == "prepend" and a.neighbor != "all":
            if a.router not in index or a.neighbor not in index:
                problems.append(f"{where}: a named router and neighbor only")
                continue
            events.append({"after": QUIET, "kind": "prepend", "from": index[a.router], "to": index[a.neighbor], "value": a.times})
        elif kind == "prepend":
            routers = _routers(a.router, topology, index)
            if routers is None:
                problems.append(f"{where}: named routers only")
                continue
            events += [{"after": QUIET, "kind": "prepend-all", "from": r, "value": a.times} for r in routers]
        elif kind == "expect":
            routers = _routers(a.router, topology, index)
            if routers is None or (a.via and a.via not in index) or (a.avoid and a.avoid not in index):
                problems.append(f"{where}: named routers only")
                continue
            e = {"after": QUIET, "kind": "expect", "routers": routers, "prefixes": a.prefixes if present or a.prefixes != "all" else "any"}
            if a.via:
                e["via"] = index[a.via]
            if a.avoid:
                e["avoid"] = index[a.avoid]
            if a.forwarding:
                e["forwarding"] = True
            if a.consistent:
                e["consistent"] = True
            if a.may_fail:
                e["may_fail"] = a.may_fail  # the lab's, which the simulator passes over
            events.append(e)
        else:
            problems.append(f"{where}: no counterpart in the simulator")
    if not started:
        problems.append("the origin never announces")
    if origin:
        events.insert(0, origin)  # taken out by to_instance
    return events, problems


def _origin(a) -> dict[str, list]:
    """What the announcement adds to the route, in the simulator's terms."""
    return {k: list(v) for k, v in (("origin_set", a.as_set), ("origin_poison", a.poison), ("origin_communities", a.communities)) if v}


def _link(link: str, index: dict) -> tuple[int, int] | None:
    for i in range(1, len(link)):
        if link[i] == "-" and link[:i] in index and link[i + 1:] in index:
            return index[link[:i]], index[link[i + 1:]]
    return None


# Simulator to lab

def router_name(i: int) -> str:
    return f"r{i}"


def from_instance(inst: dict, name: str = "sim") -> tuple[dict, dict]:
    """The topology and scenario of the lab for an instance of the
    simulator: routers r0, r1 and so on. Unsupported for what the lab
    cannot play."""
    problems = []
    n = inst["routers"]
    as_of = inst.get("as") or list(range(n))
    asns, ids = inst.get("asns") or [], inst.get("router_ids") or []
    asn = lambda a: asns[a] if a < len(asns) else 65001 + a
    routers = {router_name(i): {"asn": asn(as_of[i]), "routerId": ids[i] if i < len(ids) else f"10.0.{(i + 1) >> 8}.{(i + 1) & 255}",
                                "neighbors": []} for i in range(n)}
    confed_of = {}
    for c in inst.get("confeds", []):
        for member in c["members"]:
            confed_of[member] = c["id"]
    for i in range(n):
        if as_of[i] in confed_of:
            routers[router_name(i)]["confederation"] = confed_of[as_of[i]]
    seen = lambda x, y: confed_of[as_of[y]] if as_of[y] in confed_of and confed_of.get(as_of[x]) != confed_of[as_of[y]] else asn(as_of[y])
    relation = {}
    for p, c in inst.get("customers", []):
        relation[(p, c)], relation[(c, p)] = "customer", "provider"
    for a, b in inst.get("peers", []):
        relation[(a, b)], relation[(b, a)] = "peer", "peer"
    for a, b in inst.get("siblings", []):
        relation[(a, b)], relation[(b, a)] = "sibling", "sibling"
    policy = {(s["from"], s["to"]): s for s in inst.get("sessions", [])}
    costs = inst.get("costs") or []
    for k, (a, b) in enumerate(inst["links"]):
        if as_of[a] == as_of[b]:
            cost = costs[k] if k < len(costs) and costs[k] else 1
            routers[router_name(a)].setdefault("igp", []).append({"name": router_name(b), "cost": cost})
            routers[router_name(b)].setdefault("igp", []).append({"name": router_name(a), "cost": cost})
            continue
        for x, y in ((a, b), (b, a)):
            entry = {"name": router_name(y), "peerAs": seen(x, y)}
            if (x, y) in relation:
                entry["relation"] = relation[(x, y)]
            if (s := policy.get((y, x))) and s.get("local_pref"):
                entry["localPref"] = s["local_pref"]
            if (s := policy.get((y, x))) and s.get("tag"):
                entry["tag"] = s["tag"]
            if (s := policy.get((x, y))) and s.get("partial_transit"):
                entry["partialTransit"] = True
            if (s := policy.get((x, y))) and s.get("med") is not None:
                entry["med"] = s["med"]
            if (s := policy.get((x, y))) and s.get("deny_via"):
                entry["denyVia"] = s["deny_via"]
            routers[router_name(x)]["neighbors"].append(entry)
    for s in inst.get("sessions", []):
        for key in ("deny_export", "prepend", "deny_import"):
            if s.get(key):
                problems.append(f"session {s['from']}-{s['to']}: {key} from the start, the lab sets it with a step")
    reflectors = {c["as"]: c.get("reflectors", []) for c in inst.get("ibgp", [])}
    for as_index in sorted(set(as_of)):
        members = [i for i in range(n) if as_of[i] == as_index]
        rr = reflectors.get(as_index, [])
        for a in members:
            for b in members:
                if a == b or (rr and a not in rr and b not in rr):
                    continue
                entry = {"name": router_name(b), "peerAs": asn(as_index)}
                if a in rr and b not in rr:
                    entry["rrClient"] = True
                routers[router_name(a)]["neighbors"].append(entry)
    for i in inst.get("leakers", []):
        routers[router_name(i)]["leak"] = True
    for r in inst.get("route_servers", []):  # it serves all its neighbors
        for m in routers[router_name(r)]["neighbors"]:
            if m["peerAs"] != routers[router_name(r)]["asn"]:
                m["rsClient"] = True
    origin = router_name(inst.get("origin", 0))
    topology = {"source": None, "roles": {"origins": [origin]}, "routers": routers}
    announce = {"rate": 1, "for": 1, "lifetime": 86400, "jitter": 0, "max_active": 1}
    for key, arg in (("origin_set", "as_set"), ("origin_poison", "poison"), ("origin_communities", "communities")):
        if inst.get(key):
            announce[arg] = list(inst[key])
    steps = [{"kind": "announce", "args": announce}, {"kind": "until_stable", "args": {"timeout": 120}}]
    for e in sorted(inst.get("events", []), key=lambda e: e["after"]):
        if e["after"] != QUIET:
            problems.append(f"{e['kind']} after {e['after']} messages, the lab acts once quiet")
            continue
        steps += _step(e, problems, announce)
    if problems:
        raise Unsupported(problems)
    return topology, {"name": name, "steps": steps}


def _step(e: dict, problems: list[str], announce: dict) -> list[dict]:
    r = router_name
    stable = [{"kind": "until_stable", "args": {"timeout": 120}}]
    match e["kind"]:
        case "withdraw":
            return [{"kind": "withdraw", "args": {"percent": 100}}, *stable]
        case "announce":
            return [{"kind": "announce", "args": announce}, *stable]
        case "down" | "up":
            return [{"kind": e["kind"], "args": {"link": f"{r(e.get('from', 0))}-{r(e.get('to', 0))}"}}, *stable]
        case "deny-export":
            return [{"kind": "set_export", "args": {"router": r(e.get("from", 0)), "neighbor": r(e.get("to", 0)),
                                                    "allow": not e.get("value")}}, *stable]
        case "deny-import":
            return [{"kind": "set_import", "args": {"router": r(e.get("to", 0)), "neighbor": r(e.get("from", 0)),
                                                    "allow": not e.get("value")}}, *stable]
        case "local-pref":
            return [{"kind": "set_preference", "args": {"router": r(e.get("to", 0)), "neighbor": r(e.get("from", 0)),
                                                        "value": e.get("value", 0)}}, *stable]
        case "igp":
            return [{"kind": "igp", "args": {"link": f"{r(e.get('from', 0))}-{r(e.get('to', 0))}", "cost": e.get("value", 0)}}]
        case "prepend-all":
            return [{"kind": "prepend", "args": {"router": r(e.get("from", 0)), "times": e.get("value", 0)}}, *stable]
        case "prepend":
            return [{"kind": "prepend", "args": {"router": r(e.get("from", 0)), "neighbor": r(e.get("to", 0)), "times": e.get("value", 0)}}, *stable]
        case "expect":
            out = []
            for router in e.get("routers", []):  # the lab's expect names one router or a role
                args = {"router": r(router), "prefixes": e.get("prefixes") or "all"}
                if e.get("via") is not None:
                    args["via"] = r(e["via"])
                if e.get("avoid") is not None:
                    args["avoid"] = r(e["avoid"])
                if e.get("forwarding"):
                    args["forwarding"] = True
                if e.get("consistent"):
                    args["consistent"] = True
                if e.get("may_fail"):
                    args["may_fail"] = e["may_fail"]
                out.append({"kind": "expect", "args": args})
            return out
    problems.append(f"{e['kind']}: no step in the lab")
    return []


# Running the simulator

def _go(arguments: list[str]) -> list[str]:
    """A go command: with go if it is installed, else in the Go image under
    Docker, its module cache under ~/obgp-lab/cache/go."""
    if shutil.which("go"):
        return ["go", *arguments]
    cache = Path.home() / "obgp-lab" / "cache" / "go"
    cache.mkdir(parents=True, exist_ok=True)
    _record_image()
    return ["docker", "run", "--rm", "-i", "-v", f"{ROOT}:/src", "-v", f"{cache}:/go", "-w", "/src",
            "-e", "GOFLAGS=-buildvcs=false", "-e", "CGO_ENABLED=0", "-u", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp", GO_IMAGE, "go", *arguments]


def _record_image() -> None:
    """Pulls the Go image if it is missing and records that in
    ~/obgp-lab/installed.txt, so that uninstall removes what it pulled and
    nothing that was there before."""
    present = subprocess.run(["docker", "image", "inspect", GO_IMAGE], capture_output=True, timeout=120).returncode == 0
    if not present:
        subprocess.run(["docker", "pull", "-q", GO_IMAGE], check=True, capture_output=True, timeout=1800)
        from .uninstall import record
        record(Path.home() / "obgp-lab", f"docker-image {GO_IMAGE}")


SOURCES = ("cmd/obgp-sim", "internal/pkg/obgpsim", "internal/pkg/table", "pkg/packet/bgp")


def binary() -> Path:
    """cmd/obgp-sim, built once into the cache and again when its code
    changed, with go if it is installed, else in the Go image. The binary
    then runs natively, so that nice and a stop reach the simulator itself."""
    cache = Path.home() / "obgp-lab" / "cache" / "go"
    out = cache / "obgp-sim"
    newest = max((f.stat().st_mtime for d in SOURCES for f in (ROOT / d).rglob("*.go")), default=0)
    if not out.exists() or out.stat().st_mtime < newest:
        cache.mkdir(parents=True, exist_ok=True)
        target = str(out) if shutil.which("go") else "/go/obgp-sim"
        done = subprocess.run(_go(["build", "-o", target, "./cmd/obgp-sim"]), cwd=ROOT, capture_output=True, text=True,
                              timeout=1800, env={**os.environ, "CGO_ENABLED": "0"})
        if done.returncode:
            raise RuntimeError(f"building the simulator failed: {done.stderr.strip()[-500:]}")
    return out


def _simulator(arguments: list[str], stdin: str | None = None, timeout: float = 3600, guest: bool = False, started=None,
               progress=None) -> str:
    """Runs cmd/obgp-sim. As a guest it runs at the lowest priority, in a
    process group of its own whose id started receives, to stop it.
    progress receives how far it is, (done, total), as it reports it."""
    args = [str(binary()), *arguments]
    if guest:
        args = ["nice", "-n", "19", *args]
    proc = subprocess.Popen(args, cwd=ROOT, stdin=subprocess.PIPE if stdin is not None else None, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, start_new_session=guest)
    if started:
        started(proc.pid)
    # stdout and stderr in threads of their own: stderr carries the progress as it comes.
    out, err = [], []

    def drain_err() -> None:
        for line in proc.stderr:
            parts = line.split()
            if progress and len(parts) == 3 and parts[0] == "progress" and parts[1].isdigit() and parts[2].isdigit():
                progress(int(parts[1]), int(parts[2]))
            else:
                err.append(line)
    readers = [threading.Thread(target=lambda: out.append(proc.stdout.read()), daemon=True), threading.Thread(target=drain_err, daemon=True)]
    for r in readers:
        r.start()
    if stdin is not None:
        proc.stdin.write(stdin)
        proc.stdin.close()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, 9) if guest else proc.kill()
        proc.wait()
        raise RuntimeError(f"the simulator took longer than {timeout / 3600:g} h") from None
    for r in readers:
        r.join(5)
    out, err = "".join(out), "".join(err)
    if proc.returncode:
        raise RuntimeError(f"the simulator failed: {err.strip()[-500:]}" if proc.returncode > 0 else "the simulator was stopped")
    return out


def run(inst: dict, seeds: int = 100, per_neighbor: bool = False) -> dict:
    """Plays an instance in every mode over seeds orders of messages: how
    often each converged, failed each expect, and showed each deviation.
    With per_neighbor the OBGP modes keep a table per neighbor."""
    return json.loads(_simulator(["-instance", "-", "-seeds", str(seeds), *(["-per-neighbor"] if per_neighbor else [])], json.dumps(inst)))


PREDICTION_SEEDS = 20  # orders of messages per prediction: enough to see a mode that rests only sometimes


def sim_mode(variant) -> str | None:
    """The simulator's mode of a variant, None for a mixed one: the simulator runs one mode on all routers."""
    from . import modes

    if modes.get(variant.mode).inner is not None:
        return None
    return per_neighbor(variant.mode) if variant.per_neighbor else variant.mode


def predictions(experiment, seeds: int = PREDICTION_SEEDS, workers: int = 8) -> dict:
    """What the simulator expects of every topology and scenario of an
    experiment, per mode of its variants: in how many orders of messages
    the routes came to rest, over every part (origin and life of a prefix).
    Where the simulator cannot play it, why not. Asked once as a result
    begins, so that its runs are judged against the simulator."""
    from concurrent.futures import ThreadPoolExecutor

    wanted = {m for v in experiment.variants if (m := sim_mode(v))}
    jobs = []
    for t, case in experiment.combinations():
        try:
            parts = to_instances(topologies.load(t), experiment.scenario_of(case))
        except Unsupported as e:
            jobs.append((f"{t}|{case}", None, e.reasons, False))
            continue
        for _, inst in parts:
            jobs.append((f"{t}|{case}", inst, None, False))
            if any(m.endswith("-pn") for m in wanted):
                jobs.append((f"{t}|{case}", inst, None, True))

    def play(job):
        key, inst, reasons, pn = job
        if inst is None:
            return key, {"unsupported": reasons}
        try:
            out = run(inst, seeds, per_neighbor=pn)
        except (RuntimeError, ValueError, OSError) as e:
            return key, {"unsupported": [str(e)[-200:]]}
        # The run with tables per neighbor adds only the -pn modes: BGP and the paper's OBGP are the same in both.
        named = {(per_neighbor(m) if pn else m): o for m, o in out.items() if not pn or per_neighbor(m) != m}
        return key, {m: o for m, o in named.items() if m in wanted}

    result: dict = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for key, found in pool.map(play, jobs):
            entry = result.setdefault(key, {})
            if "unsupported" in found:
                entry["unsupported"] = found["unsupported"]
                continue
            for mode, o in found.items():
                kept = entry.setdefault(mode, {"converged": 0, "runs": 0})
                kept["converged"] += o["converged"]
                kept["runs"] += o["runs"]
    return result


FUZZ_TARGETS = ("FuzzInModel", "FuzzIBGP", "FuzzSoft")


def fuzz(target: str, hours: float, parallel: int) -> int:
    """Fuzzes one target of the simulator for hours on parallel cores, as a
    guest: few cores, a low priority. A failing network lands in
    internal/pkg/obgpsim/testdata, where the tests replay it from then on.
    Returns the exit code of go test."""
    if target not in FUZZ_TARGETS:
        raise ValueError(f"unknown target {target}, known: {', '.join(FUZZ_TARGETS)}")
    args = _go(["test", "-tags", "obgpsim", "-run", "^$", "-fuzz", f"^{target}$", "-fuzztime", f"{int(hours * 3600)}s",
                "-parallel", str(parallel), "./internal/pkg/obgpsim/"])
    return subprocess.run(["nice", "-n", "19", *args], cwd=ROOT).returncode


SEARCH_HOURS = 6  # the longest a search may take, five routers in every family included


def per_neighbor(mode: str) -> str:
    """A mode with tables per neighbor, named as the lab's variants are. BGP
    and the paper's OBGP have none."""
    return mode if mode in ("bgp", "obgp-paper") or mode.endswith("-pn") else f"{mode}-pn"


def search(routers: int = 4, seeds: int = 3, family: str = "", transient: bool = False, started=None,
           tables: bool = False, progress=None) -> list[dict]:
    """The smallest example of every deviation the simulator finds on all
    topologies up to routers, one per number of routers, as cmd/obgp-sim
    writes them, each with how often it showed. With transient also the way to rest: loops, routers
    blocked waiting for a route refresh and routers without a route for a while.
    With tables the OBGP modes keep a table per neighbor, their names end in -pn."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "examples.json"
        _simulator(["-routers", str(routers), "-seeds", str(seeds), "-out", str(out), *(["-family", family] if family else []),
                    *(["-transient"] if transient else []), *(["-per-neighbor"] if tables else []), *(["-progress"] if progress else [])],
                   timeout=SEARCH_HOURS * 3600, guest=True, started=started, progress=progress)
        found = json.loads(out.read_text())
    if tables:
        for e in found:
            e["finding"]["mode"] = per_neighbor(e["finding"]["mode"])
            e["results"] = {per_neighbor(m): {**r, "mode": per_neighbor(m)} for m, r in (e.get("results") or {}).items()}
    return found


def trace(inst: dict, mode: str) -> dict:
    """Plays an instance once in one mode, with the seed it carries, and
    returns every step with the tables of each router. A mode ending in -pn
    keeps a table per neighbor."""
    tables = mode.endswith("-pn")
    played = json.loads(_simulator(["-instance", "-", "-trace", mode.removesuffix("-pn"), "-json", *(["-per-neighbor"] if tables else [])],
                                   json.dumps(inst), timeout=600, guest=True))
    played["mode"] = mode
    return played


def expectation(example: dict) -> dict | None:
    """The expect step of the lab that tells the deviation of an example as
    the lab can see it, or None: the simulator then plays the same step."""
    finding, inst = example["finding"], example["instance"]
    routers = finding.get("routers") or []
    # The modes the simulator saw failing on this network may fail the check: the lab
    # then tells a predicted failure from one that was not. Tables per neighbor end in -pn.
    failing = sorted({f["mode"] for f in example.get("findings") or [finding] if f["kind"] == finding["kind"]})
    check = {"after": QUIET, "kind": "expect", "routers": routers, "may_fail": failing}
    match finding["kind"]:
        case "unreachable":
            return check
        case "loop" | "black-hole":
            return {**check, "forwarding": True}
        case "leaked":
            return {**check, "avoid": inst["leakers"][0]}
        case "inconsistent-export":
            return {**check, "consistent": True}
    return None  # no-convergence shows as oscillates


def export(examples: list[dict], prefix: str = "sim", overwrite: bool = False, name: str | None = None) -> tuple[list[str], dict[str, list[str]]]:
    """Writes one example per family and deviation that the lab can play as
    a topology and scenario of the same name, the deviation as an expect
    step, of OBGP with refresh pruning where it shows there. Returns the names and, for
    the others, why not. A name given names the first example."""
    written, skipped, seen, given = [], {}, set(), name
    order = ["obgp-rp", "obgp-sp", "obgp-hp", "obgp-np", "obgp-paper", "bgp"]
    # Per deviation the simulator keeps the smallest network of each size: the smallest of all goes.
    rank = lambda e: (order.index(e["finding"]["mode"]) if e["finding"]["mode"] in order else len(order),
                      e["instance"].get("routers", 0), len(e["instance"].get("links", [])))
    for example in sorted(examples, key=rank):
        inst, finding = example["instance"], example["finding"]
        family = inst.get("family", "network")
        if (family, finding["kind"]) in seen:
            continue
        seen.add((family, finding["kind"]))
        name = (given if not written and not skipped else None) or f"{prefix}-{family}-{finding['mode']}-{finding['kind']}"
        inst = {**inst, "events": [*inst.get("events", []), *filter(None, [expectation(example)])]}
        try:
            t, s = from_instance(inst, name)
        except Unsupported as e:
            skipped[name] = e.reasons
            continue
        if not overwrite and (topologies.path(name).exists() or scenarios.path(name).exists()):
            skipped[name] = ["exists already"]
            continue
        topologies.save(name, t["routers"], t["roles"], "obgp-sim")
        s["description"] = (f"The simulator's smallest {finding['kind']} of {finding['mode']} in {inst.get('family')}, "
                             f"seed {inst.get('seed')}: {finding.get('detail', '')}")
        scenarios.path(name).write_text(scenarios.to_yaml(scenarios.parse(s)))
        written.append(name)
    return written, skipped


def predict(topology_name: str, scenario_name: str, seeds: int = 100) -> dict:
    """What the simulator expects of a topology and scenario of the lab, for
    every mode of the lab it can play. allowed says per expect whether the
    scenario allows the mode to fail it."""
    inst = to_instance(topologies.load(topology_name), scenarios.load(scenario_name))
    out = run(inst, seeds)
    may_fail = [e.get("may_fail", []) for e in inst.get("events", []) if e["kind"] == "expect"]
    for mode, o in out.items():
        o["allowed"] = [mode in names for names in may_fail]
    return out


def compare(dataset, seeds: int = 100) -> tuple[list[dict], dict[str, list[str]]]:
    """The runs of a result beside the simulator's orders of messages, per
    topology, scenario and variant of a pure mode: how often the routes came
    to rest and how often each check failed. A deviation is what the
    simulator rules out: it always converges or always passes a check and
    the lab did not, or never and the lab did. Shares in between depend on
    the order of messages and are not deviations. Topologies and scenarios
    are the lab's files as they are now. Returns the rows and, for what
    cannot be compared, why not."""
    from . import analysis, modes

    metrics = analysis.run_summary(dataset)
    e = dataset.experiment
    rows, skipped = [], {}
    for t, case in e.combinations():
        try:
            parts = to_instances(topologies.load(t), e.scenario_of(case))
        except Unsupported as x:
            skipped[f"{t} · {case}"] = x.reasons
            continue
        played = None
        for v in e.variants:
            if modes.get(v.mode).inner is not None:
                skipped[v.name] = ["mixed mode, the simulator runs one mode on all routers"]
                continue
            keys = [k for k in dataset.keys() if (k.topology, k.scenario, k.variant) == (t, case, v.name) and dataset.is_done(k)]
            runs = [(k, r) for k in keys if (r := dataset.run(k))["status"] != "error"]
            if not runs:
                continue
            played = played or [(label, run(inst, seeds)) for label, inst in parts]
            sims = [(label, out[v.mode]) for label, out in played if v.mode in out]
            if not sims:
                skipped[v.name] = [f"the simulator does not play {v.mode}"]
                continue
            n = len(runs)
            rested = sum(r["status"] != "timeout" and metrics.get(str(k), {}).get("oscillates") != 1 for k, r in runs)
            checks = [[ev for ev in r["events"] if ev["name"] == "expect"] for _, r in runs]
            count = min((len(c) for c in checks), default=0)
            lab_failed = [sum(not c[i]["passed"] for c in checks) for i in range(count)]
            sim_failed = [max(o["failed"][i] for _, o in sims if i < len(o["failed"])) for i in range(count)]
            always = lambda i, sims=sims: any(i < len(o["failed"]) and o["failed"][i] == o["runs"] for _, o in sims)
            converged = min(o["converged"] for _, o in sims)
            deviations = []
            if all(o["converged"] == o["runs"] for _, o in sims) and rested < n:
                deviations.append(f"did not come to rest in {n - rested} of {n} runs, the simulator always converges")
            if converged == 0 and rested:
                deviations.append(f"came to rest in {rested} of {n} runs, the simulator never converges")
            for i in range(count):
                if not any(i < len(o["failed"]) and o["failed"][i] for _, o in sims) and lab_failed[i]:
                    deviations.append(f"check {i + 1} failed in {lab_failed[i]} of {n} runs, the simulator never fails it")
                if always(i) and lab_failed[i] < n:
                    deviations.append(f"check {i + 1} passed in {n - lab_failed[i]} of {n} runs, the simulator always fails it")
            rows.append({"topology": t, "scenario": case, "variant": v.name, "runs": n, "rested": rested, "seeds": seeds,
                         "converged": converged, "instances": [label for label, _ in parts],
                         "lab_failed": lab_failed, "sim_failed": sim_failed, "deviations": deviations})
    return rows, skipped
