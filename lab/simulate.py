"""The simulator and the lab, each in the terms of the other.

The simulator (internal/pkg/obgpsim, cmd/obgp-sim) plays one prefix with
the decision code of gobgpd. A topology and scenario of the lab become an
instance of it, and an instance becomes a topology and scenario, so that
both judge the same network alike. What one side cannot express is named,
never approximated: a conversion either is exact or says why it is not.

The same on both sides:
  routers and ASes          a router per entry, routers of one ASN one AS
  iBGP                      a full mesh, or route reflectors whose clients
                            are all others of the AS, meshed among themselves,
                            and confederations
  IGP                       the igp costs of the topology, no IGP runs
  relations, Local Pref.    Gao-Rexford with 200, 150 and 100, siblings,
                            partialTransit, localPref
  MED, leaks                med per neighbor, leak per router
  tagging                   tag per neighbor
  announce                  the simulator plays one prefix, prefixes do not
                            interact: one instance per origin and per life
                            of a prefix, held, removed by a partial
                            withdraw, or expired after any step it can
                            follow. A lifetime runs only while an
                            announcement at the origin lasts. Later
                            announcements with the AS_SET, poison and
                            communities of the first
  withdraw                  the prefix of the origin, a share where its life
                            is removed, and the copies of routers it names
  originate                 copies at more routers, a life of its own,
                            not a more specific prefix
  down, up, restart         every eBGP link the step takes down, of routers,
                            regions and cuts too, a silent failure once the
                            hold timer ends it; up brings back what is down.
                            A restart starts with a fresh table, its
                            sessions down at once. The links of one step
                            change in any order, as sessions come back
  graceful restart          a graceful restart and a silent failure keep
                            the routes stale until the End-of-RIB after the
                            session is back, or until the restart time ends
                            where the steps' times tell it
  degrade                   nothing: the simulator plays every delay, TCP
                            keeps the order, while the sessions hold
  MRAI                      an update waiting on a session to another AS
                            gives way to a newer one or a withdrawal of its
                            path ID: the coalescing, not the timer
  set_preference, set_export, set_import, prepend, igp, expect
                            the targets the runner chooses, random ones too,
                            with the seed and position of the run
  parallel, repeat          at the same moment: the first that sends at the
                            moment of the step, the others at any point
                            among its messages, in any order where each
                            adds one event. Repetitions unrolled. Steps at
                            any point are drawn one after another: the
                            simulator plays more orders than the lab can,
                            never fewer
  until_stable              the next step comes once the network is quiet,
                            or where it never is after a share of the
                            messages, as the runner after the timeout.
                            Any other step comes at any point among the
                            messages, one before the announcement before it
  wait, soft_reset          nothing: the simulator plays every order, and
                            policies apply at once

The order of messages is not the lab's to choose: where a result depends
on it, compare how often it occurs, over seeds of the simulator and runs
of the lab, never one run with one seed.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from . import scenario as scenarios
from . import topology as topologies
from .config import ROOT

QUIET = 1 << 30  # an event of the simulator once the network is quiet
BEFORE = -1  # an event of the simulator before the origin announces
DEFAULT_SEED = 42  # an experiment's, unless it sets one: random choices of a scenario played on its own
GO_IMAGE = "golang:1.24"  # as the Dockerfile builds gobgpd


class Unsupported(ValueError):
    """What the other side cannot express, one reason per item."""

    def __init__(self, reasons: list[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = reasons


# Lab to simulator

def to_instances(topology: dict, scenario, seed: int = DEFAULT_SEED, index: int = 1, bgp=None) -> list[tuple[str, dict]]:
    """The instances of the simulator that together play a topology and
    scenario of the lab for its pure modes, each with a label: one per
    origin, as prefixes do not interact, and one per life a prefix can
    have. Random choices as run index of an experiment with seed makes them.
    bgp, the experiment's settings of the sessions, adds the MRAI and
    graceful restart, see with_bgp. The mode of each router of a mixed
    variant comes in with_modes. Unsupported names what does not map."""
    sc = scenario if isinstance(scenario, scenarios.Scenario) else scenarios.parse(scenario)
    origins = [o for o in topology.get("roles", {}).get("origins", []) if o in topology["routers"]]
    problems = [] if origins else ["no origin"]
    out = []
    for origin in origins:
        lives, why = _lives(sc, topology, origin, seed, index)
        problems += [r for r in why if r not in problems]
        for life in lives:
            try:
                inst = to_instance(topology, sc, origin, life, seed, index, bgp)
            except Unsupported as e:
                problems += [r for r in e.reasons if r not in problems]
                continue
            out.append((", ".join(x for x in (origin if len(origins) > 1 else "", life.label if len(lives) > 1 else "") if x), inst))
    if problems:
        raise Unsupported(problems)
    return out


def expect_keys(scenario) -> list[str]:
    """The keys of the expect steps of a scenario in the order the simulator
    counts its checks: the order of the steps, parallel ones by their place,
    repetitions unrolled. A check of the lab is matched by its key, see
    analysis.expect_keys, not by its place in time: the checks of a parallel
    step end in any order."""
    sc = scenario if isinstance(scenario, scenarios.Scenario) else scenarios.parse(scenario)
    return [key for key, _, _, step in _timed(sc.steps)[1] if step.kind == "expect"]


def draws(scenario) -> bool:
    """Whether a scenario chooses targets at random, so that its runs differ and each needs a prediction of its own."""
    sc = scenario if isinstance(scenario, scenarios.Scenario) else scenarios.parse(scenario)
    return any(isinstance(s.args, scenarios.Model) and "random" in s.args.model_dump().values() for s in scenarios.each_step(sc.steps))


class Life:
    """What becomes of the prefix an instance plays: held, removed by a
    partial withdraw, or expired after the step at path, and whether an
    originate step copies it."""

    def __init__(self, label: str, expires: str | None = None, partial: bool = False, copied: bool = False) -> None:
        self.label, self.expires, self.partial, self.copied = label, expires, partial, copied


def _timed(steps: list) -> tuple[float, list]:
    """The acting steps in the order the runner plays them, repetitions
    unrolled, each with its key (see _key) and the earliest and latest
    second it starts: until_stable takes from nothing to its timeout, other
    steps but waits and announcements no time. And the earliest end."""
    out, seen = [], {}

    def one(step, path: tuple, lo: float, hi: float) -> tuple[float, float]:
        if step.kind == "wait":
            return lo + step.args, hi + step.args
        if step.kind == "until_stable":
            return lo, hi + step.args.timeout
        if step.kind == "parallel":
            ends = [one(c, path + (j,), lo, hi) for j, c in enumerate(step.args)]
            return max(e[0] for e in ends), max(e[1] for e in ends)
        if step.kind == "repeat":
            for _ in range(step.args.times):
                start = (lo, hi)
                lo, hi = walk(step.args.steps, path + ("repeat",), lo, hi)
                lo, hi = max(lo, start[0] + step.args.every), max(hi, start[1] + step.args.every)
            return lo, hi
        out.append((_key(path, seen), lo, hi, step))
        return (lo + step.args.for_, hi + step.args.for_) if step.kind == "announce" else (lo, hi)

    def walk(items: list, position: tuple, lo: float, hi: float) -> tuple[float, float]:
        for i, step in enumerate(items):
            lo, hi = one(step, position + (i,), lo, hi)
        return lo, hi

    end, _ = walk(steps, (), 0.0, 0.0)
    return end, out


def _key(path: tuple, seen: dict) -> str:
    """A step's position as the runner names it, with its repetition: 2.repeat.0#1 the second time."""
    name = ".".join(map(str, path))
    seen[name] = seen.get(name, -1) + 1
    return f"{name}#{seen[name]}"


def _lives(sc, topology: dict, origin: str, seed: int, index: int) -> tuple[list[Life], list[str]]:
    """The lives of a prefix of the first announcement of the origin: held
    while the run lasts, removed by a partial withdraw, or expired, after
    any step it may expire after while an announcement at the origin lasts.
    Each also copied by an originate step, where one may copy it."""
    _, timed = _timed(sc.steps)
    first = next((k for k, (_, _, _, s) in enumerate(timed) if s.kind == "announce"), None)
    if first is None:
        return [Life("held")], []
    step = timed[first][3]
    a = step.args
    lives = []
    expiring = a.lifetime < 3600
    network = scenarios.Network(topology["routers"], topology.get("roles", {}))
    rng = lambda key: scenarios.rng(seed, index, tuple(p if p == "repeat" else int(p) for p in key.partition("#")[0].split(".")))
    # Lifetimes run only while an announcement of the origin lasts: the runner pauses the announcer after for,
    # which stops them, until a later announcement at the origin resumes it. Each window: start, latest end, length.
    windows = [(lo, hi + s.args.for_, s.args.for_) for k, (key, lo, hi, s) in enumerate(timed[first:])
               if s.kind == "announce" and (k == 0 or origin in network.routers_of(s.args.router, rng(key)))]
    shortest, longest = a.lifetime * (1 - a.jitter), a.lifetime * (1 + a.jitter)
    lengths = [w[2] for w in windows]
    # A prefix announced in the first window lives there from nothing to all of it, in later ones all of each.
    # It expires in window i where its lifetime can end after the time before i and within the time up to its end.
    ends = [w for i, w in enumerate(windows) if shortest < sum(lengths[:i + 1]) and longest > sum(lengths[1:i])]
    if not expiring or longest > sum(lengths[1:]):
        lives.append(Life("held"))
    if any(s.kind == "withdraw" and s.args.percent < 100 for _, _, _, s in timed[first + 1:]):
        lives.append(Life("removed", partial=True))
    elif expiring:
        after = timed[first:]
        for k, (key, lo, _, _) in enumerate(after):
            following = after[k + 1][2] if k + 1 < len(after) else float("inf")
            if any(lo < end and following > start for start, end, _ in ends):
                lives.append(Life("expires", expires=key))
        if len([x for x in lives if x.expires]) > 1:
            for x in lives:
                if x.expires:
                    name, _, repetition = x.expires.partition("#")
                    x.label = f"expires after step {scenarios._number(name.replace('.repeat', ''))}" + (f", repetition {int(repetition) + 1}" if ".repeat" in name else "")
    out = []
    copies = False
    for key, _, _, s in timed:
        if s.kind == "originate":
            copies |= origin in network.routers_of(s.args.like, rng(key))
    for life in lives:
        out.append(life)
        if copies:
            out.append(Life(f"{life.label}, copied", life.expires, life.partial, True))
    return out, []


def to_instance(topology: dict, scenario, origin: str | None = None, life: Life | None = None, seed: int = DEFAULT_SEED,
                run_index: int = 1, bgp=None) -> dict:
    """The instance of the simulator, as plain data, for one origin and one
    life of its prefix, or with neither, the strict translation of a
    topology and scenario of the lab: one origin, prefixes held.
    Unsupported names everything that does not map."""
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
    events, why = _events(scenario, topology, index, origin or (origins[0] if len(origins) == 1 else None), life, seed, run_index, bgp)
    problems += why
    if events and "kind" not in events[0]:
        inst.update(events.pop(0))
    if events:
        inst["events"] = events
    if problems:
        raise Unsupported(problems)
    return with_bgp(inst, bgp) if bgp is not None else inst


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


DELAY_MS = 1000  # degraded links up to this delay keep their sessions under every hold time the lab allows


def _events(scenario, topology: dict, index: dict, own: str | None = None, life: Life | None = None, seed: int = DEFAULT_SEED,
            run_index: int = 1, bgp=None) -> tuple[list[dict], list[str]]:
    """The events of a scenario for the prefix of the origin own, in the
    order the runner plays the steps, with the targets it chooses: the same
    function and random source. A step right after until_stable comes once
    the network is quiet or after a share of the messages, any other at any
    point among the messages, a step
    before the announcement before the origin announces. With a life, the
    prefix may expire after a step or go with a partial withdraw, and be
    copied by an originate step. A check of all prefixes holds no claim on
    one that is gone, as the lab checks the prefixes still announced. With
    graceful restart in bgp, the stale routes of a restart and a silent
    failure, see _Play.stale."""
    sc = scenario if isinstance(scenario, scenarios.Scenario) else scenarios.parse(scenario)
    return _Play(topology, index, own, life, seed, run_index, bgp).play(sc.steps)


class _Play:
    """One walk over the steps, as Run.steps in lab/runner.py walks them."""

    def __init__(self, topology: dict, index: dict, own: str | None, life: Life | None, seed: int, run_index: int, bgp=None) -> None:
        self.routers, self.index, self.own, self.life = topology["routers"], index, own, life
        self.network = scenarios.Network(topology["routers"], topology.get("roles", {}))
        self.origins = tuple(topology.get("roles", {}).get("origins", []))
        self.seed, self.run_index = seed, run_index
        self.events, self.problems = [], []
        self.started, self.present, self.quiet = False, True, False
        self.origin: dict[str, list] = {}  # the AS_SET, poisoned ASes and communities of the announcement
        self.down: set[tuple[str, str]] = set()  # links down, by name
        self.copiers: set[str] = set()  # routers announcing copies of the prefix
        self.seen: dict[str, int] = {}  # how often each step played, for repetitions
        self.graceful = bool(bgp and bgp.graceful_restart)
        self.bgp = bgp
        self.times: dict[str, tuple[float, float]] = {}  # the earliest and latest start of each step, by its key
        self.expiring: dict[tuple[str, str], tuple[float, float]] = {}  # silent failures with stale routes: when they may expire

    def play(self, steps: list) -> tuple[list[dict], list[str]]:
        self.times = {key: (lo, hi) for key, lo, hi, _ in _timed(steps)[1]}
        self.walk(steps, ())
        for x, y in self.expiring:  # the run may end before or after they expire
            self.problems.append(f"the stale routes of the silent failure of {x}-{y} expire after the last step, before or after the final check")
        if not self.started:
            self.problems.append("the origin never announces")
        if self.origin:
            self.events.insert(0, self.origin)  # taken out by to_instance
        return self.events, self.problems

    def walk(self, steps: list, position: tuple) -> None:
        for i, step in enumerate(steps):
            self.step(step, position + (i,))

    def add(self, kind: str, anywhere: bool = False, **fields) -> None:
        """An event at the moment of the step: before the announcement, once quiet, or at any point."""
        e = {"after": BEFORE if not self.started else QUIET, "kind": kind, **fields}
        if self.started and (not self.quiet or anywhere):
            e["any"] = True
        elif self.started:
            e["bounded"] = True  # until_stable waits at most its timeout, then the runner goes on
        self.events.append(e)

    def step(self, step, position: tuple) -> None:
        kind, a = step.kind, step.args
        where = f"step {scenarios._number('.'.join(str(p) for p in position if p != 'repeat'))} ({kind})"
        rng = scenarios.rng(self.seed, self.run_index, position)
        if kind == "until_stable":
            self.quiet = True
            return
        if kind == "wait":  # the simulator plays every order
            self.quiet = False
            return
        if kind == "parallel":  # at the same moment: after the first that sends, the others at any point among its messages
            spans = []
            for j, child in enumerate(a):
                first = len(self.events)
                self.step(child, position + (j,))
                spans.append((first, len(self.events)))
            # Where every step that acts adds one event, any of them comes first, with the moment of the step.
            acting = [(x, y) for x, y in spans if y > x and self.events[x]["kind"] != "expect" and self.events[x]["after"] != BEFORE]
            if len(acting) > 1 and all(y - x == 1 for x, y in acting) and acting[-1][1] - acting[0][0] == len(acting):
                for x, _ in acting:
                    self.events[x]["group"] = acting[0][0] + 1
            return
        if kind == "repeat":  # the position leaves out the repetition, as the runner's
            for _ in range(a.times):
                self.walk(a.steps, position + ("repeat",))
                self.quiet = False
            return
        self.key = _key(position, self.seen)  # as _timed and the lab name it, see expect_keys
        self.expire(where)
        try:
            self.act(kind, a, rng, where)
        except (ValueError, KeyError, IndexError) as e:
            self.problems.append(f"{where}: {e}")
        if self.life and self.life.expires == self.key and self.present:
            self.quiet = False
            self.add("withdraw")  # it expires at some point after this step
            self.present = False
        # A check, a cost of the IGP or a slower link sends no message: a quiet network stays quiet.
        self.quiet = self.quiet and kind in ("expect", "igp", "degrade")

    def expire(self, where: str) -> None:
        """Stale routes of a silent failure expire before this step where its
        earliest start comes after their latest expiry. Where the step may
        start before or after, the order is not the lab's to know."""
        lo, hi = self.times.get(self.key, (0.0, 0.0))
        for link, (first, last) in list(self.expiring.items()):
            if lo >= last:
                self.add("expire", anywhere=True, **{"from": self.index[link[0]], "to": self.index[link[1]]})
                del self.expiring[link]
            elif hi > first:
                self.problems.append(f"{where}: the stale routes of the silent failure of {link[0]}-{link[1]} may expire before or after it")
                del self.expiring[link]

    def stale(self, links: list) -> None:
        """With graceful restart, a silent failure keeps the routes stale on
        the ends that find it by their hold timer, until the link is back or
        the restart time ends: max(30 s, hold time), as the lab configures
        it, after the failure is found within the hold time."""
        lo, hi = self.times.get(self.key, (0.0, 0.0))
        restart = max(30, self.bgp.hold_time)
        for link in links:
            self.expiring[link] = (lo + restart, hi + self.bgp.hold_time + restart)

    def link(self, a: str, b: str, where: str) -> list[int] | None:
        if str(self.routers[a]["asn"]) == str(self.routers[b]["asn"]):
            self.problems.append(f"{where}: an iBGP session {a}-{b}, the simulator takes eBGP links down only")
            return None
        return [self.index[a], self.index[b]]

    def back(self, x: str, y: str, where: str) -> None:
        """A link with stale routes comes back: before they expire where its
        session is surely up again, connect retry after its latest start,
        before their earliest expiry. Otherwise the order is not known."""
        _, hi = self.times.get(self.key, (0.0, 0.0))
        first, _ = self.expiring.pop((x, y))
        if hi + self.bgp.connect_retry > first:
            self.problems.append(f"{where}: the session {x}-{y} may come back before or after its stale routes expire")

    def links_of(self, router: str) -> list[tuple[str, str]]:
        return [tuple(sorted((router, n["name"]))) for n in self.routers[router].get("neighbors", [])]

    def act(self, kind: str, a, rng, where: str) -> None:
        if kind == "announce":
            if a.router != "origins":
                self.problems.append(f"{where}: announce from the origins only")
            elif not self.started and a.lifetime < 3600 and self.life is None:
                self.problems.append(f"{where}: prefixes that expire after {a.lifetime:g} s, played as lives of their own")
            elif self.started and _origin(a) != self.origin:
                self.problems.append(f"{where}: another AS_SET, poison or communities than the first announcement")
            elif self.started:
                self.add("announce")
                self.present = True
            self.origin = _origin(a)
            self.started = True
            return
        if kind in ("down", "up", "restart"):
            routers, links = self.network.targets(kind, a, rng)
            if kind == "restart" and a.graceful and not self.graceful:
                self.problems.append(f"{where}: a graceful restart without graceful restart in the experiment")
                return
            if kind == "up" and not routers and not links:
                links = sorted(self.down)  # everything
            links = sorted(set(links) | {link for r in routers for link in self.links_of(r)})
            links = [link for link in links if (link in self.down) == (kind == "up")]  # only what changes
            silent = kind == "down" and a.mode != "session" and self.graceful  # found by the hold timer: stale routes
            # The links of one step change in an order the lab does not control, sessions come back in any order.
            group = {"group": len(self.events) + 1} if len(links) > 1 else {}
            if kind == "restart":  # a fresh table, all sessions down at once, gracefully its peers keep its routes
                if all(self.link(x, y, where) is not None for x, y in links):
                    for r in routers:
                        self.add("restart", **{"from": self.index[r], "value": int(a.graceful)})
            for x, y in links:
                if kind == "up" and (x, y) in self.expiring:
                    self.back(x, y, where)
                if kind == "restart":
                    continue
                if (ends := self.link(x, y, where)) is not None:  # all at the moment of the step
                    value = {"value": {"cut": 1, "oneway": 2}[a.mode]} if silent else {}  # oneway: y drops the packets of x
                    self.add(kind, **{"from": ends[0], "to": ends[1]}, **value, **group)
                (self.down.add if kind == "down" else self.down.discard)((x, y))
            if silent:
                self.stale(links)
            if kind == "restart":  # back at any point after
                self.quiet = False
                group = {"group": len(self.events) + 1} if len(links) > 1 else {}
                for x, y in links:
                    if (ends := self.link(x, y, where)) is not None:
                        self.add("up", **{"from": ends[0], "to": ends[1]}, **group)
            return
        if kind == "soft_reset":  # policies apply at once in the simulator
            return
        if kind == "degrade":  # TCP delivers late, in order: an order the simulator plays, while the sessions hold
            if a.loss_pct >= 100 or a.delay_ms + a.jitter_ms >= DELAY_MS:
                self.problems.append(f"{where}: loss of 100 % or delays from {DELAY_MS} ms, sessions may fall")
            return
        if kind in ("announce_real", "announce_rib", "withdraw_rib", "replay"):  # prefixes of the Internet, from many origins
            self.problems.append(f"{where}: no counterpart in the simulator")
            return
        if not self.started:
            if kind not in ("set_preference", "set_export", "set_import", "prepend", "igp"):
                self.problems.append(f"{where}: before the origin announces")
                return
        if kind == "withdraw":
            routers, _ = self.network.targets(kind, a, rng)
            if self.own in routers and self.present and (a.percent == 100 or (self.life and self.life.partial)):
                self.add("withdraw")
                self.present = False
            elif self.own in routers and a.percent < 100 and not self.life:
                self.problems.append(f"{where}: a share of the prefixes, played as a life of its own")
            for r in sorted(self.copiers & set(routers)):  # the lab withdraws every copy
                self.add("originate", **{"from": self.index[r], "value": 0})
            self.copiers -= set(routers)
        elif kind == "originate":
            routers, _ = self.network.targets(kind, a, rng)
            if a.more_specific:
                self.problems.append(f"{where}: a more specific prefix, the simulator plays one")
            elif self.life is None and self.own in self.network.routers_of(a.like, rng):
                self.problems.append(f"{where}: copies of some prefixes, played as a life of their own")
            elif self.life and self.life.copied and self.own in self.network.routers_of(a.like, rng):
                for r in routers:
                    self.add("originate", **{"from": self.index[r], "value": 1})
                self.copiers |= set(routers)
        elif kind in ("set_preference", "set_export", "set_import"):
            [r], [(_, n)] = self.network.targets(kind, a, rng)
            r, n = self.index[r], self.index[n]
            if kind == "set_preference":
                self.add("local-pref", **{"from": n, "to": r, "value": a.value})
            elif kind == "set_export":
                self.add("deny-export", **{"from": r, "to": n, "value": int(not a.allow)})
            else:
                self.add("deny-import", **{"from": n, "to": r, "value": int(not a.allow)})
        elif kind == "igp":
            _, [(x, y)] = self.network.targets(kind, a, rng)
            self.add("igp", **{"from": self.index[x], "to": self.index[y], "value": a.cost})
        elif kind == "prepend":
            routers, links = self.network.targets(kind, a, rng)
            if links:
                [(r, n)] = links
                self.add("prepend", **{"from": self.index[r], "to": self.index[n], "value": a.times})
            else:
                for r in routers:
                    self.add("prepend-all", **{"from": self.index[r], "value": a.times})
        elif kind == "expect":
            routers, _ = self.network.targets(kind, a, rng)
            # A check of the prefixes of some origins claims nothing of another's.
            claims = self.present and (not a.of or self.own in self.network.routers_of(a.of, rng))
            e = {"routers": sorted(self.index[r] for r in routers), "prefixes": a.prefixes if claims or a.prefixes != "all" else "any"}
            if a.via:
                e["via"] = self.index[a.via]
            if a.avoid:
                e["avoid"] = self.index[a.avoid]
            if a.forwarding:
                e["forwarding"] = True
            if a.consistent:
                e["consistent"] = True
            if a.may_fail:
                e["may_fail"] = a.may_fail  # the lab's, which the simulator passes over
            e["step"] = self.key  # the lab's check it stands for, which the simulator carries
            self.add("expect", **e)
        else:
            self.problems.append(f"{where}: no counterpart in the simulator")


def _origin(a) -> dict[str, list]:
    """What the announcement adds to the route, in the simulator's terms."""
    return {k: list(v) for k, v in (("origin_set", a.as_set), ("origin_poison", a.poison), ("origin_communities", a.communities)) if v}


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
    before, steps = [], [{"kind": "announce", "args": announce}, {"kind": "until_stable", "args": {"timeout": 120}}]
    for e in sorted(inst.get("events", []), key=lambda e: e["after"]):
        if e["after"] == BEFORE:  # a step before the announcement
            before += [s for s in _step(e, problems, announce) if s["kind"] != "until_stable"]
            continue
        if e["after"] != QUIET:
            problems.append(f"{e['kind']} after {e['after']} messages, the lab acts once quiet or at any point")
            continue
        if e.get("any") and steps[-1]["kind"] == "until_stable":
            steps.pop()  # without waiting for rest: at any point, as to_instance reads it back
        steps += _step(e, problems, announce)
    steps = before + steps
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
    changed, with go if it is installed, else in the Go image, one package
    at a time at the lowest priority. The binary
    then runs natively, so that nice and a stop reach the simulator itself."""
    cache = Path.home() / "obgp-lab" / "cache" / "go"
    out = cache / "obgp-sim"
    newest = max((f.stat().st_mtime for d in SOURCES for f in (ROOT / d).rglob("*.go")), default=0)
    if not out.exists() or out.stat().st_mtime < newest:
        cache.mkdir(parents=True, exist_ok=True)
        target = str(out) if shutil.which("go") else "/go/obgp-sim"
        # One job at the lowest priority: a case may need it while an experiment runs.
        done = subprocess.run(["nice", "-n", "19", *_go(["build", "-p", "1", "-o", target, "./cmd/obgp-sim"])], cwd=ROOT,
                              capture_output=True, text=True, timeout=1800, env={**os.environ, "CGO_ENABLED": "0"})
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
            elif parts and parts[0] == "slow":  # a network that took long: into the log of the search
                sys.stderr.write(f"the simulator {line}")
                sys.stderr.flush()
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


def run(inst: dict, seeds: int = 100, per_neighbor: bool = False, guest: bool = False, timeout: float = 3600,
        both: bool = False, modes: list[str] | None = None) -> dict:
    """Plays an instance in every mode over seeds orders of messages: how
    often each converged, failed each expect, and showed each deviation,
    on the way to rest as well.
    With per_neighbor the OBGP modes keep a table per neighbor, under their
    own names. With both they play with one table and, named -pn, with a
    table per neighbor, in one pass. With modes only those, the instance's
    mixed ones among them, and BGP."""
    # The way to rest always: transient loops, holes and blocking are what the lab measures on the way.
    flags = ["-both-tables"] if both else ["-per-neighbor"] if per_neighbor else []
    flags += ["-modes", ",".join(modes)] if modes else []
    return json.loads(_simulator(["-instance", "-", "-seeds", str(seeds), "-transient", *flags],
                                 json.dumps(inst), timeout=timeout, guest=guest))


PREDICTION_SEEDS = 20  # orders of messages per prediction: enough to see a mode that rests only sometimes


def sim_mode(variant) -> str:
    """The simulator's mode of a variant. A mixed one is named by its mode,
    -pn with tables per neighbor, a random one also by its share in percent,
    e.g. random-rp-pn-50: the instance gives the mode of each router, see
    router_modes."""
    from . import modes

    mode = modes.get(variant.mode)
    if mode.inner is not None:
        name = variant.mode + ("-pn" if variant.per_neighbor else "")
        return name + (f"-{variant.share * 100:g}" if mode.pick == "random" else "")
    if variant.per_neighbor:
        return "bgp-pn" if variant.mode == "bgp" else per_neighbor(variant.mode)
    return variant.mode


def mixed(variant) -> bool:
    """Whether a variant runs a mode per router: hybrids and random ones."""
    from . import modes

    return modes.get(variant.mode).inner is not None


def drawn(variant) -> bool:
    """Whether a variant draws its routers anew for every run."""
    from . import modes

    return modes.get(variant.mode).pick == "random"


def router_modes(variant, topology: dict, seed: int) -> list[str]:
    """The simulator's mode of every router of a mixed variant, in the order
    of the topology, as the runner deploys them in the run of this seed
    (experiment seed * 1000 + run index, see Run.execute and
    Cluster.deploy): the pure mode modes.assign gives each router, with
    tables per neighbor -pn on the OBGP routers but the paper's, and
    bgp-pn on all where all run BGP (NS-BGP)."""
    try:
        assigned = variant.modes_of(topology["routers"], seed)
    except ValueError as e:
        raise Unsupported([str(e)]) from None
    ns_bgp = set(assigned.values()) == {"bgp"}
    if not variant.per_neighbor:
        return [assigned[r] for r in topology["routers"]]
    return ["bgp-pn" if ns_bgp else per_neighbor(assigned[r]) for r in topology["routers"]]


def with_modes(inst: dict, variants: list, topology: dict, seed: int) -> dict:
    """The instance with the mode of each router of the mixed variants, by
    their simulator's mode, for the run with this seed."""
    return {**inst, "mixed": {sim_mode(v): router_modes(v, topology, seed) for v in variants}}


def with_bgp(inst: dict, bgp) -> dict:
    """The instance with the settings of an experiment's sessions that the
    simulator models: an MRAI as coalescing of the updates that wait on a
    session to another AS, without its timer, and graceful restart: stale
    routes after a graceful restart or a silent failure."""
    return {**inst, **({"mrai": True} if bgp.mrai > 0 else {}), **({"graceful_restart": True} if bgp.graceful_restart else {})}


def stored(predictions: dict, key, mode: str | None) -> tuple[str, dict]:
    """The entry of the predictions for a run's mode and its name: per run
    where the run has its own for the mode, as where the scenario or the
    variant draws, else per topology and scenario. Without the mode in
    either, the one of the run first."""
    run, cell = f"{key.topology}|{key.scenario}#{key.index}", f"{key.topology}|{key.scenario}"
    for name in (run, cell):
        if mode in predictions.get(name, {}):
            return name, predictions[name]
    for name in (run, cell):
        if name in predictions:
            return name, predictions[name]
    return cell, {}


def predictions(experiment, seeds: int = PREDICTION_SEEDS, workers: int = 8, guest: bool = False,
                only: dict[str, set[str]] | None = None, timeout: float = 3600) -> dict:
    """What the simulator expects of every topology and scenario of an
    experiment, per mode of its variants: in how many orders of messages
    the routes came to rest, over every part (origin and life of a prefix).
    Where the simulator cannot play it, why not. Asked once as a result
    begins, so that its runs are judged against the simulator. With only,
    just those keys and modes, see more_orders."""
    from concurrent.futures import ThreadPoolExecutor

    wanted = {sim_mode(v) for v in experiment.variants if not mixed(v)}
    jobs = []
    for t, case in experiment.combinations():
        sc = experiment.scenario_of(case)
        topology = topologies.load(t)
        # Random targets differ by run: then each run has a prediction of its own.
        runs = [(f"{t}|{case}#{i}", i) for i in range(1, experiment.runs + 1)]
        for key, index in (runs if draws(sc) else [(f"{t}|{case}", 1)]):
            if only is not None and (key not in only or not wanted & only[key]):
                continue
            try:
                parts = to_instances(topology, sc, experiment.seed, index, experiment.bgp)
            except Unsupported as e:
                jobs.append((key, None, e.reasons, False, None))
                continue
            modes = wanted if only is None else wanted & only[key]
            for _, inst in parts:  # both tables in one pass where a -pn mode is wanted, BGP once
                jobs.append((key, inst, None, any(m.endswith("-pn") and m != "bgp-pn" for m in modes), None))
        # Mixed variants with the routers of each run where they are drawn, one pass for all of a key.
        by_key: dict[tuple[str, int], list] = {}
        for v in experiment.variants:
            if mixed(v):
                for key, index in (runs if draws(sc) or drawn(v) else [(f"{t}|{case}", 1)]):
                    if only is None or sim_mode(v) in only.get(key, ()):
                        by_key.setdefault((key, index), []).append(v)
        for (key, index), variants in by_key.items():
            names = [sim_mode(v) for v in variants]
            try:
                parts = to_instances(topology, sc, experiment.seed, index if draws(sc) else 1, experiment.bgp)
            except Unsupported as e:
                jobs.append((key, None, e.reasons, False, names))
                continue
            try:
                parts = [(label, with_modes(inst, variants, topology, experiment.seed * 1000 + index)) for label, inst in parts]
            except Unsupported as e:
                jobs.append((key, None, e.reasons, False, names))
                continue
            for _, inst in parts:
                jobs.append((key, inst, None, False, names))

    def play(job):
        key, inst, reasons, pn, names = job
        if inst is None:  # the reasons of a mixed mode are its own: the pure modes may play
            return key, {m: {"unsupported": reasons} for m in names} if names else {"unsupported": reasons}
        try:
            out = run(inst, seeds, guest=guest, timeout=timeout, both=pn, modes=names)
        except (RuntimeError, ValueError, OSError) as e:
            return key, {m: {"unsupported": [str(e)[-200:]]} for m in names} if names else {"unsupported": [str(e)[-200:]]}
        if names:
            return key, {m: o for m, o in out.items() if m in names}
        return key, {m: o for m, o in out.items() if m in wanted and (only is None or m in only[key])}

    result: dict = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for key, found in pool.map(play, jobs):
            entry = result.setdefault(key, {})
            if "unsupported" in found:
                entry["unsupported"] = found["unsupported"]
                continue
            for mode, o in found.items():
                if "unsupported" in o or "unsupported" in entry.get(mode, {}):  # a part of a mixed mode it cannot play
                    entry[mode] = {"unsupported": o.get("unsupported") or entry[mode]["unsupported"]}
                    continue
                kept = entry.setdefault(mode, {"converged": 0, "settled": 0, "runs": 0})
                kept["converged"] += o["converged"]
                kept["settled"] += o.get("settled", o["converged"])
                kept["runs"] += o["runs"]
                # Per check of the scenario, in how many orders it failed: a failed check of the lab is then judged too.
                for i, n in enumerate(o.get("failed") or []):
                    failed = kept.setdefault("failed", [])
                    failed.extend([0] * (i + 1 - len(failed)))
                    failed[i] += n
                if o.get("endless"):  # orders without rest proven to go on forever
                    kept["endless"] = kept.get("endless", 0) + o["endless"]
                if "findings" in o:  # looked at the way, also where it found nothing
                    kept.setdefault("findings", {})
                for finding, n in (o.get("findings") or {}).items():  # in how many orders, e.g. transient-loop
                    kept["findings"][finding] = kept["findings"].get(finding, 0) + n
    return result


def predict_again(dataset) -> dict:
    """Asks the simulator again for a result that does not run, e.g. after the
    translation was corrected, and keeps its answer: the runs are judged
    against it from then on, after more orders where they differ. Few cores
    at the lowest priority, as a result may run beside it."""
    if dataset.status.get("state") == "running":
        raise ValueError(f"{dataset.name} runs: it keeps the predictions it began with")
    found = predictions(dataset.experiment, workers=2, guest=True)
    dataset.update(predictions=found)
    more_orders(dataset)
    return dataset.meta["predictions"]


MORE_ORDERS = 1000  # orders of messages where a run and the prediction differ: a miss of 20 orders is rare after them
MORE_ORDERS_S = 600  # the longest one part of a key may take, as a large topology plays slowly
MORE_ORDERS_KEYS = 20  # the most keys played again after a result, so that the queue goes on


def differs(dataset) -> dict[str, set[str]]:
    """The predictions a finished run contradicts, per key the modes: the
    run did not come to rest where the simulator always did, came to rest
    where it never did, failed a check the simulator never failed, or
    looped, lost packets or blocked on the way where the simulator never
    did. Played in more orders before the run counts as unforeseen, as 20
    orders can miss what shows only in few."""
    from . import analysis, problems

    out: dict[str, set[str]] = {}
    metrics = analysis.run_summary(dataset)
    # Checks and the way to rest the simulator did not predict, as the verdict finds them.
    unforeseen = {(p["topology"], p["variant"], p["scenario"], p["run"]) for p in problems.of(dataset, metrics)
                  if p.get("predicted") is False and (p["kind"] == "check" or p.get("cause") in problems.ON_THE_WAY)}
    for key in dataset.keys():
        if not dataset.is_done(key) or (run := dataset.run(key))["status"] == "error":
            continue
        p = problems.prediction(dataset, key)
        if p is None or p.get("more"):
            continue
        rested = analysis.rested(run, metrics.get(str(key)))
        always = p["converged"] == p["runs"] and p.get("settled", p["converged"]) == p["runs"]  # at the end and at every step
        # With an MRAI a run at rest where the simulator never rests is no problem: the simulator coalesces without the timer.
        if rested is False and always or rested is True and p["converged"] == 0 and not dataset.experiment.bgp.mrai \
                or (key.topology, key.variant, key.scenario, key.index) in unforeseen:
            variant = next(v for v in dataset.experiment.variants if v.name == key.variant)
            name, _ = stored(dataset.meta["predictions"], key, sim_mode(variant))
            out.setdefault(name, set()).add(sim_mode(variant))
    return out


def more_orders(dataset, seeds: int = MORE_ORDERS) -> dict[str, set[str]]:
    """Plays the predictions the runs contradict in seeds orders of messages,
    the 20 of the prediction among them, and keeps the answer in their place.
    Returns what it played again."""
    again = dict(list(differs(dataset).items())[:MORE_ORDERS_KEYS])
    if not again:
        return again
    found = predictions(dataset.experiment, seeds, workers=2, guest=True, only=again, timeout=MORE_ORDERS_S)
    kept = dataset.meta["predictions"]
    for key, modes in found.items():
        if "unsupported" in modes:  # a part timed out: the prediction of 20 orders over every part stays
            continue
        for mode, o in modes.items():
            if "unsupported" not in o:
                kept[key][mode] = {**o, "more": True}
    dataset.update(predictions=kept)
    return again


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
    """An OBGP mode of the simulator's -per-neighbor run, named as the lab's
    variants are. BGP and the paper's OBGP have none there, bgp-pn is
    NS-BGP in every run."""
    return mode if mode in ("bgp", "obgp-paper") or mode.endswith("-pn") else f"{mode}-pn"


def search_workers() -> int:
    """The processes a search runs in: every CPU the lab may use, its share
    of the host beside what the host keeps (cluster.free), but two: for the
    process that gathers what they find and for the web server. The search
    runs alone in the lab's queue, at the lowest priority. 0 where that
    cannot be told: the simulator then takes its own default."""
    from . import cluster

    try:
        return max(1, cluster.free()[0] - 2)
    except Exception:
        return 0


def search(routers: int = 4, seeds: int = 20, family: str = "", transient: bool = True, started=None,
           tables: bool | str = False, progress=None) -> list[dict]:
    """The smallest example of every deviation the simulator finds on all
    topologies up to routers, one per number of routers, as cmd/obgp-sim
    writes them, each with how often it showed. With transient also the way to rest: loops, routers
    blocked waiting for a route refresh and routers without a route for a while.
    With tables the OBGP modes keep a table per neighbor, their names end in -pn,
    with tables "both" the OBGP modes play with one table and with them, in one pass."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "examples.json"
        workers = search_workers()
        _simulator(["-routers", str(routers), "-seeds", str(seeds), "-out", str(out), *(["-family", family] if family else []),
                    *(["-workers", str(workers)] if workers else []),
                    *(["-transient"] if transient else []), *(["-both-tables"] if tables == "both" else ["-per-neighbor"] if tables else []), *(["-progress"] if progress else [])],
                   timeout=SEARCH_HOURS * 3600, guest=True, started=started, progress=progress)
        found = json.loads(out.read_text())
    if tables and tables != "both":
        for e in found:
            e["finding"]["mode"] = per_neighbor(e["finding"]["mode"])
            e["results"] = {per_neighbor(m): {**r, "mode": per_neighbor(m)} for m, r in (e.get("results") or {}).items()}
    return found


def trace(inst: dict, mode: str) -> dict:
    """Plays an instance once in one mode, with the seed it carries, and
    returns every step with the tables of each router. A mode ending in -pn
    keeps a table per neighbor, bgp-pn is the simulator's own mode."""
    tables = mode.endswith("-pn") and mode != "bgp-pn"
    played = json.loads(_simulator(["-instance", "-", "-trace", mode if mode == "bgp-pn" else mode.removesuffix("-pn"), "-json",
                                    *(["-per-neighbor"] if tables else [])],
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


def predict(topology_name: str, scenario_name: str, seeds: int = 100, tables: bool = False, guest: bool = False,
            timeout: float = 3600, seed: int = DEFAULT_SEED, index: int = 1) -> dict[str, dict]:
    """What the simulator expects of a topology and scenario of the lab, for
    every mode of the lab it can play, per part as a result's predictions
    play it (origin and life of a prefix, "" for a single part). allowed
    says per expect whether the scenario allows the mode to fail it. With
    tables the OBGP modes keep a table per neighbor and are named -pn.
    timeout holds for all parts together. Random targets as run index of an
    experiment with seed chooses them."""
    deadline = time.monotonic() + timeout
    out = {}
    for part, inst in to_instances(topologies.load(topology_name), scenarios.load(scenario_name), seed, index):
        played = run(inst, seeds, per_neighbor=tables, guest=guest, timeout=max(1.0, deadline - time.monotonic()))
        if tables:  # BGP and the paper's OBGP are the same as without
            played = {per_neighbor(m): o for m, o in played.items() if per_neighbor(m) != m}
        may_fail = [e.get("may_fail", []) for e in inst.get("events", []) if e["kind"] == "expect"]
        for mode, o in played.items():
            o["allowed"] = [mode in names for names in may_fail]
        out[part] = played
    return out


def compare(dataset, seeds: int = 100) -> tuple[list[dict], dict[str, list[str]]]:
    """The runs of a result beside the simulator's orders of messages, per
    topology, scenario and variant, a mixed one with the routers of each
    run where it draws them: how often the routes came
    to rest and how often each check failed. A deviation is what the
    simulator rules out: it always converges or always passes a check and
    the lab did not, or never and the lab did. Shares in between depend on
    the order of messages and are not deviations. Topologies and scenarios
    are the lab's files as they are now. Returns the rows and, for what
    cannot be compared, why not."""
    from . import analysis

    metrics = analysis.run_summary(dataset)
    e = dataset.experiment
    rows, skipped = [], {}
    for t, case in e.combinations():
        sc = e.scenario_of(case)
        topology = topologies.load(t)
        try:  # random targets differ by run: the parts of every run
            parts = [(f"run {i}, {label}" if draws(sc) else label, inst, i) for i in (range(1, e.runs + 1) if draws(sc) else [1])
                     for label, inst in to_instances(topology, sc, e.seed, i, e.bgp)]
        except Unsupported as x:
            skipped[f"{t}, {case}"] = x.reasons
            continue
        played = None
        for v in e.variants:
            mode = sim_mode(v)
            keys = [k for k in dataset.keys() if (k.topology, k.scenario, k.variant) == (t, case, v.name) and dataset.is_done(k)]
            runs = [(k, r) for k in keys if (r := dataset.run(k))["status"] != "error"]
            if not runs:
                continue
            instances = [label for label, _, _ in parts]
            if mixed(v):  # the routers of every run where the variant draws them
                each = [(f"run {i}, {label}", inst, i) for i in range(1, e.runs + 1) for label, inst, _ in parts] \
                    if drawn(v) and not draws(sc) else parts
                try:
                    mine = [(label, with_modes(inst, [v], topology, e.seed * 1000 + i)) for label, inst, i in each]
                except Unsupported as x:
                    skipped[v.name] = x.reasons
                    continue
                sims = [(label, run(inst, seeds, modes=[mode])[mode]) for label, inst in mine]
                instances = [label for label, _ in mine]
            else:
                # Both tables in one pass: a variant with tables per neighbor is its -pn mode.
                played = played or [(label, run(inst, seeds, both=True)) for label, inst, _ in parts]
                sims = [(label, out[mode]) for label, out in played if mode in out]
            if not sims:
                skipped[v.name] = [f"the simulator does not play {mode}"]
                continue
            # Runs without a rest value tell nothing about rest: they count neither way.
            rest = [r["status"] != "timeout" and analysis.rested(r, metrics.get(str(k))) for k, r in runs]
            n, measured, rested = len(runs), sum(x is not None for x in rest), sum(x is True for x in rest)
            # Each check of the lab by the key of its step, in the order the simulator counts them.
            keys = expect_keys(sc)
            checks = [{k: ev for ev, k in analysis.expect_keys(r["events"])} for _, r in runs]
            count = len(keys)
            lab_failed = [sum(keys[i] in c and not c[keys[i]]["passed"] for c in checks) for i in range(count)]
            lab_ran = [sum(keys[i] in c for c in checks) for i in range(count)]
            sim_failed = [max(o["failed"][i] for _, o in sims if i < len(o["failed"])) for i in range(count)]
            always = lambda i, sims=sims: any(i < len(o["failed"]) and o["failed"][i] == o["runs"] for _, o in sims)
            # Rest as the lab's: at every step that waits for it and at the end.
            converged = min(o.get("settled", o["converged"]) for _, o in sims)
            deviations = []
            if all(o.get("settled", o["converged"]) == o["runs"] for _, o in sims) and rested < measured:
                deviations.append(f"did not come to rest in {measured - rested} of {measured} measured runs, the simulator always converges")
            if converged == 0 and rested:
                deviations.append(f"came to rest in {rested} of {measured} measured runs, the simulator never converges")
            for i in range(count):
                if not any(i < len(o["failed"]) and o["failed"][i] for _, o in sims) and lab_failed[i]:
                    deviations.append(f"check {i + 1} failed in {lab_failed[i]} of {lab_ran[i]} runs, the simulator never fails it")
                if always(i) and lab_failed[i] < lab_ran[i]:
                    deviations.append(f"check {i + 1} passed in {lab_ran[i] - lab_failed[i]} of {lab_ran[i]} runs, the simulator always fails it")
            rows.append({"topology": t, "scenario": case, "variant": v.name, "runs": n, "measured": measured, "rested": rested, "seeds": seeds,
                         "converged": converged, "instances": instances,
                         "lab_failed": lab_failed, "sim_failed": sim_failed, "deviations": deviations})
    return rows, skipped


def _without_rest(found: int, of: int) -> str:
    """How often a deviation showed, in the only terms simulator and lab share."""
    return "never" if found == 0 else "always" if found == of else "sometimes"


# Deviations at rest both sides tell alike, beside rest: the simulator's names, see internal/pkg/obgpsim/oracle.go.
# Those on the way do not compare: the lab sees them only beyond two sampling intervals, the simulator every message.
AT_REST = ("unreachable", "loop", "black-hole", "leaked")


def _lab_deviations(final: dict, reference: dict | None) -> dict[str, bool | None]:
    """Which deviations a run at rest showed, by its final check, None where it cannot tell: fewer routes than
    the BGP run of its seed at rest, packets that loop or end without a route, a path that is not valley-free."""
    fewer = None if reference is None else any(h < reference["held"].get(r, 0) for r, h in final["held"].items())
    return {"unreachable": fewer, "loop": bool(final.get("loops")), "black-hole": bool(final.get("holed")),
            "leaked": None if "valleys" not in final else any(final["valleys"].values())}


def agreement(dataset) -> dict:
    """Simulator and lab side by side on rest, per topology, scenario and
    variant: in how many orders the simulator found no rest, in how many
    measured runs the lab did, with the exact 95 % interval of that share.
    Rest is the same on both sides: at every step that waits for it and at
    the end, the simulator's settled and the lab's rested. Of the orders
    without rest, endless repeat an earlier state, a proof that they never
    rest, busy were still busy at the bound or at a step, without a proof.
    Shares of orders and of runs do not compare, their schedulers differ:
    only never, sometimes and always do. A contradiction at an extreme is a
    signal: the lab without rest where the simulator always rested, or at
    rest where it never did (not with an MRAI, the simulator coalesces
    without its timer).
    Per mode the cells are counted by both answers. Cells without a
    prediction are counted as not translated, with why.
    Beside rest, per deviation at rest (AT_REST), the same answers on both
    sides: in how many orders that came to rest the simulator showed it, in
    how many runs at rest the lab did, with the same signal at the extremes.
    A lost route counts against BGP in the same order and in the run of the
    same seed. The simulator looks for leaks only where routers leak by
    their policy: elsewhere it has no answer on them."""
    from . import analysis, problems
    from .results import RunKey

    metrics = analysis.run_summary(dataset)
    e = dataset.experiment
    kept = dataset.meta.get("predictions") or {}
    cells: dict[tuple, dict] = {}
    # The BGP run of the same seed a variant compares with, as problems.broken takes it, where it came to rest.
    references = [v.name for v in e.variants if v.mode == "bgp" and not v.per_neighbor]
    rate = lambda name: e.sampling_of(name).interval
    reference = lambda name: name if name in references else next((b for b in references if rate(b) == rate(name)), references[0] if references else None)

    def usable(key) -> dict | None:
        if not dataset.is_done(key) or (run := dataset.run(key))["status"] == "error":
            return None
        final = analysis.final_of(run)
        return final if final and final.get("stable") is not False and analysis.rested(run, metrics.get(str(key))) else None

    leaky: dict[str, bool] = {}

    def leaks(topology: str) -> bool:
        if topology not in leaky:
            try:
                leaky[topology] = any(r.get("leak") for r in (topologies.load(topology).get("routers") or {}).values())
            except (OSError, ValueError, KeyError):
                leaky[topology] = False
        return leaky[topology]
    for key in dataset.keys():
        if not dataset.is_done(key) or (run := dataset.run(key))["status"] == "error":
            continue
        variant = next(v for v in e.variants if v.name == key.variant)
        c = cells.setdefault((key.topology, key.scenario, key.variant), {
            "topology": key.topology, "scenario": key.scenario, "variant": key.variant, "mode": sim_mode(variant),
            "orders": 0, "orders_without_rest": 0, "endless": 0, "busy": 0, "measured": 0, "runs_without_rest": 0, "why_not": None, "seen": set(),
            "deviations": {d: {"orders": 0, "orders_with": 0, "runs": 0, "runs_with": 0} for d in AT_REST}})
        rested = analysis.rested(run, metrics.get(str(key)))
        if rested is not None:
            c["measured"] += 1
            c["runs_without_rest"] += rested is False
        final = analysis.final_of(run)
        if rested and final and final.get("stable") is not False:
            bgp = reference(key.variant)
            ref = usable(RunKey(key.topology, bgp, key.scenario, key.index)) if bgp and bgp != key.variant else None
            for d, shown in _lab_deviations(final, ref).items():
                if shown is not None and not (d == "unreachable" and key.variant == bgp):
                    c["deviations"][d]["runs"] += 1
                    c["deviations"][d]["runs_with"] += shown
        p = problems.prediction(dataset, key)
        name, found = stored(kept, key, c["mode"])
        if p is None:
            c["why_not"] = "; ".join(found.get("unsupported") or found.get(c["mode"], {}).get("unsupported") or []) or "no prediction"
            continue
        if name not in c["seen"]:  # a prediction per run where targets are drawn, else one per cell
            c["seen"].add(name)
            c["orders"] += p["runs"]
            c["orders_without_rest"] += p["runs"] - p.get("settled", p["converged"])
            c["endless"] += p.get("endless", 0)
            c["busy"] += p["runs"] - p.get("settled", p["converged"]) - p.get("endless", 0)
            if "findings" in p:  # a prediction from before it kept them answers on rest only
                for d in AT_REST:
                    if d == "leaked" and not leaks(key.topology):
                        continue
                    c["deviations"][d]["orders"] += p["converged"]
                    c["deviations"][d]["orders_with"] += min(p["findings"].get(d, 0), p["converged"])
    out, per_mode = [], {}
    for c in cells.values():
        c.pop("seen")
        for d, x in c["deviations"].items():
            x["interval"] = [round(v, 4) for v in analysis.clopper_pearson(x["runs_with"], x["runs"])] if x["runs"] else None
            x["simulator"] = _without_rest(x["orders_with"], x["orders"]) if x["orders"] else None
            x["lab"] = _without_rest(x["runs_with"], x["runs"]) if x["runs"] else None
            x["signal"] = None
            if x["simulator"] and x["lab"]:
                if x["simulator"] == "never" and x["runs_with"]:
                    x["signal"] = f"the lab showed {d} where the simulator never did"
                elif x["simulator"] == "always" and x["runs_with"] < x["runs"]:
                    x["signal"] = f"the lab did not show {d} where the simulator always did"
        translated = c["orders"] > 0
        if translated:
            c["why_not"] = None
        c["interval"] = [round(x, 4) for x in analysis.clopper_pearson(c["runs_without_rest"], c["measured"])] if c["measured"] else None
        c["simulator"] = _without_rest(c["orders_without_rest"], c["orders"]) if translated else None
        c["lab"] = _without_rest(c["runs_without_rest"], c["measured"]) if c["measured"] else None
        c["signal"] = None
        if translated and c["lab"]:
            if c["simulator"] == "never" and c["runs_without_rest"]:
                c["signal"] = "the lab found no rest where the simulator always rested"
            elif c["simulator"] == "always" and c["runs_without_rest"] < c["measured"] and not e.bgp.mrai:
                c["signal"] = "the lab came to rest where the simulator never rested" + (
                    f", {c['busy']} of its orders only still busy at the bound, not shown to go on forever" if c["busy"] else "")
        out.append(c)
        m = per_mode.setdefault(c["variant"], {"mode": c["mode"], "cells": 0, "not_translated": 0, "signals": 0, "answers": {}})
        m["cells"] += 1
        if not translated:
            m["not_translated"] += 1
            continue
        pair = f"simulator {c['simulator']}, lab {c['lab'] or 'not measured'}"
        m["answers"][pair] = m["answers"].get(pair, 0) + 1
        m["signals"] += c["signal"] is not None
        for d, x in c["deviations"].items():
            if x["simulator"] and x["lab"]:
                kept_ = m.setdefault("deviations", {}).setdefault(d, {"cells": 0, "signals": 0, "answers": {}})
                kept_["cells"] += 1
                kept_["signals"] += x["signal"] is not None
                pair = f"simulator {x['simulator']}, lab {x['lab']}"
                kept_["answers"][pair] = kept_["answers"].get(pair, 0) + 1
    return {"cells": out, "per_variant": per_mode}
