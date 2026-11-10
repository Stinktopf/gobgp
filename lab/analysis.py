"""Metrics and time series of the runs of a result.

The events of a run come from its scenario. Metrics are measured from the
reference event: the first event after the announcement, e.g. a
withdrawal or a failure, or the end of the announcement if there is none.
Charts put t = 0 at the event that defines the scenario: the first
announcement for pure announcements, the reference event otherwise.

convergence_s   time until every router holds the expected prefixes; routes
                may still change then, settle_s says when they stand still
settle_s        time until no router changes anything
                (both until the next event, and only if the state holds there
                for the quiet time: stable_s, with an MRAI one and a half
                MRAI, so that a pause between MRAI waves is no rest)
settle_end_s    the same from the last event to the end of the run: for a
                series of steps, e.g. flaps, the time to rest after all of them
hold_churn      updates per router and second in the longest stretch without
                events, a replay being one; zero unless routes keep changing
sample_hz       how often the routers really sampled, the median router;
                sample_hz_min the slowest one. Busy routers sample less often
                than set, and the times above are then only as exact. Per
                run also sample_gap_s, the longest gap between two samples
                of any router, and sample_slowest, the slowest routers
host_cpu_max    the largest share of the CPUs of the host in use during the
                run, in one second; runs before 2026-10-02 did not record it
host_others_spread  on a shared host, how much the share of others changed
                during the run; runs before 2026-10-03 did not record it
host_others_mean    on a shared host, the mean share of its CPUs in use by
                others during the run: the noise of the host, nothing of
                the processes themselves
rest_s          the seconds from the last event to the end of the run, in
                which routes had to come to rest for oscillates
oscillates      1 if routes still change in the last quiet time of a hold
                of at least three quiet times after the last event, 0 if
                they stand still for the last quiet time; none if the
                samples after the last event span less

The final check of every run, at its end, whatever its scenario checks:
unreached       router and prefix pairs without a route, of all announced
                prefixes at every router; BGP of the same seed tells what
                the policies allow, see lab/problems.py
stale_end       router and prefix pairs still held after their withdrawal
loops_end       prefixes whose packets loop between routers at the end
holes_end       prefixes whose packets end at a router without a route
The final check waits for the routes to stand still first, a bounded
time; its stable says whether they did.

Loops on the way, from the next hop of every prefix each router samples
whenever its table changes, on tables up to 256 prefixes:
loops_s         seconds in which packets to some prefix looped
loops_max       the most prefixes looping at once
holes_s         seconds in which packets to some prefix ended at a router without a route
holes_max       the most prefixes ending so at once
hops_sampled    on larger tables the prefixes of the sample all routers follow,
                the same for every run of an experiment; loops and holes count from then

Sessions, from the counters of every router, the origins too:
flaps           how often a session fell from established during the run,
                both ends count it
sessions_down_end  sessions not established at the last sample
flaps_unplanned, down_unplanned  the same for sessions no step touched:
                down, degrade or restart of either end or their link

Blocking, from the prefixes each router counts as blocked: a valid path
set aside and none admitted, so no route, in every pruning mode; under
refresh pruning the router waits for a route refresh:
blocked_s       seconds in which any router had a blocked prefix
blocked_max     the most prefixes blocked at one router at once

The sizes of the tables, each the peak of the mean over the routers. A
path is one AS path to a prefix from one neighbor, a route the path
selected for a prefix, one per prefix:
adj_in_mean     the paths received from all peers (Adj-RIB-In)
rib_mean        the paths the import admits, the Loc-RIB size of the paper;
                rib_max is the largest of any router
suppressed_mean the paths OBGP keeps without admitting them
selected_mean   the routes the decision process selects, one per prefix
                (the Loc-RIB of RFC 4271): the prefixes with a route
known_mean      the prefixes with a path admitted or set aside: known_mean
                above selected_mean are prefixes known without a route
The resources of gobgpd, from its Prometheus metrics, likewise the peak of
the mean over the routers:
rss_mean        the resident memory; the Go runtime returns freed memory
                to the system late
heap_mean       the heap in use, garbage included until the next collection
objects_mean    the heap objects, likewise
cpu_s_mean      CPU seconds per router within the window, of the whole
                daemon, its API and sampling included
For each of these, <metric>_routers holds the smallest and the largest
router, each at its own peak: how the routers differ.
"""

import bisect
import fcntl
import json
import math
import subprocess
import sys
import threading
from collections import Counter, defaultdict
from contextlib import contextmanager
from statistics import mean, median

from .config import write_atomic
from .results import COUNTERS, Dataset, RunKey

VERSION = 40  # of the metrics; a change recomputes the cached summaries
METRICS = ["convergence_s", "settle_s", "settle_end_s", "hold_churn", "oscillates", "rest_s", "unreached", "stale_end", "loops_end", "holes_end", "loops_s", "loops_max", "holes_s", "holes_max", "flaps", "sessions_down_end", "flaps_unplanned", "down_unplanned", "hops_sampled",
           "blocked_s", "blocked_max", "known_mean", "sample_hz", "sample_hz_min", "host_cpu_max", "host_others_spread", "host_others_mean", "adj_in_mean", "rib_mean", "rib_max", "suppressed_mean",
           "selected_mean", "path_len_avg", "rss_mean", "heap_mean", "objects_mean", "cpu_s_mean"]
# The sizes and resources that differ by router, and the field of each in the samples.
ROUTER_FIELDS = {"adj_in_mean": "adj_in", "rib_mean": "paths", "suppressed_mean": "suppressed", "known_mean": "known", "selected_mean": "destinations",
                 "rss_mean": "rss_mb", "heap_mean": "heap_mb", "objects_mean": "heap_objects"}
ROUTER_METRICS = [*ROUTER_FIELDS, "cpu_s_mean"]
SERIES = ["destinations", "known", "blocked", "paths", "suppressed", "adj_in", "rss_mb", "heap_mb", "heap_objects", "cpu", "path_len_avg", "churn",
          "sessions_down", "looping", "holed", "sample_rate", "host_cpu"]
WAY = ("looping", "holed")  # of the whole network, from the sampled next hops, not per router
RATES = {"churn": ("updates_rx", 1), "cpu": ("cpu_s", 100)}  # per second; CPU in percent
PREFIX_EVENTS = ("announce", "announced")
LEAD = 5  # seconds shown before the event
# The latest sample of a router stands for it this long. Routers busy with
# large tables sample every few seconds only; their counters keep counting,
# so a change shows with the next sample.
STALE_S = 10


CHECKS = ("expect", "final")  # events that look at the routes without changing them
# Events of the lab's own bookkeeping, which change no route: the sample of prefixes whose next hops the routers follow.
BOOKKEEPING = ("hops_sample",)


def clopper_pearson(k: int, n: int, level: float = 0.95) -> tuple[float, float]:
    """The exact interval of a share of k in n: the shares under which k or
    more, and k or fewer, come with at least (1 - level) / 2 each."""
    if n <= 0:
        return 0.0, 1.0
    tail = (1 - level) / 2

    def at_most(p: float) -> float:
        return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k + 1))

    def solve(f, rising: bool) -> float:  # f(p) = tail on [0, 1], f monotone
        lo, hi = 0.0, 1.0
        for _ in range(60):
            mid = (lo + hi) / 2
            if (f(mid) < tail) == rising:
                lo = mid
            else:
                hi = mid
        return (lo + hi) / 2

    lower = 0.0 if k == 0 else solve(lambda p: 1 - at_most(p) + math.comb(n, k) * p ** k * (1 - p) ** (n - k), True)
    upper = 1.0 if k == n else solve(at_most, False)
    return lower, upper


def acting(events: list[dict]) -> list[dict]:
    """The events that change something, without the checks and the lab's
    bookkeeping: neither may move the reference, end a window or split a rest."""
    return [e for e in events if e["name"] not in CHECKS + BOOKKEEPING]


def anchors(events: list[dict]) -> tuple[dict, dict, float]:
    """The event the metrics are measured from, the event at t = 0 of the
    charts, and how many seconds the charts show before it."""
    # After the announcement, as the module says: a failure before it, e.g.
    # a link taken down to shape the topology, is no reference.
    announced = next((e["t"] for e in events if e["name"] == "announced"), None)
    after = [e for e in events if e["name"] not in PREFIX_EVENTS and (announced is None or e["t"] >= announced)]
    if after:
        return after[0], after[0], LEAD
    return next((e for e in events if e["name"] == "announced"), events[0]), events[0], 0


def stopped(events: list[dict]) -> list[tuple[float, set[str]]]:
    """From which time which routers are stopped, which do not sample."""
    down, out = set(), [(float("-inf"), set())]
    for e in events:
        if e["name"] == "down" and e.get("mode") == "session":
            down |= set(e["routers"])
        elif e["name"] == "up":
            down -= set(e["routers"])
        else:
            continue
        out.append((e["t"], set(down)))
    return out


def planned_sessions(events: list[dict]) -> set:
    """The sessions steps of a run touched, as pairs of routers, and the
    routers whose every session they touched: down, degrade, restart."""
    touched: set = set()
    for e in events:
        if e["name"] in ("down", "degrade"):
            touched |= {frozenset(link) for link in e.get("links", [])}
        if e["name"] in ("down", "restart"):
            touched |= set(e.get("routers", []))
    return touched


def watched_only(samples: list[dict], run: dict) -> list[dict]:
    """The samples of the watched routers: the origins, sampled too for
    their next hops, take no part in the sizes, rates and times."""
    watched = set(run["watched"])
    return [s for s in samples if s["router"] in watched]


def ticks(samples: list[dict], run: dict) -> dict[float, list[dict]]:
    """The samples of all routers at every time some router answered: of
    each router its latest sample, if not older than STALE_S. Busy routers
    skip ticks of their own, so few times hold an answer of every one. A
    time at which a running router has been silent longer is left out."""
    by_t = defaultdict(list)
    for s in samples:
        by_t[s["t"]].append(s)
    changes, watched = stopped(run["events"]), set(run["watched"])
    latest: dict[str, dict] = {}
    out = {}
    seen = 0  # changes taken into account
    for t, rows in sorted(by_t.items()):
        # A sample from before a router was stopped does not stand for it after.
        while seen < len(changes) and changes[seen][0] <= t:
            for r in changes[seen][1]:
                latest.pop(r, None)
            seen += 1
        for r in rows:
            latest[r["router"]] = r
        off = next(routers for since, routers in reversed(changes) if since <= t)
        running = watched - off
        if all(r in latest and t - latest[r]["t"] <= STALE_S for r in running):
            out[t] = [latest[r] for r in sorted(running | ({r["router"] for r in rows} & watched))]
    return out


def values_of(rows: list[dict], metric: str) -> list[float] | None:
    """The values of a metric in the rows of one time, None unless every
    router has one: runs before 2026-10 did not count the paths set aside,
    the Adj-RIB-In and the memory."""
    v = [r.get(metric) for r in rows]
    return None if any(x is None for x in v) else v


def used(by_t: dict, times: list[float], counter: str) -> dict[str, float]:
    """What a counter grew per router over the times; a restart counts from zero."""
    last, out = {}, defaultdict(float)
    for t in times:
        for r in by_t[t]:
            if r.get(counter) is None:
                continue  # not read then
            if (before := last.get(r["router"])) is not None:
                out[r["router"]] += max(0.0, r[counter] - before)
            last[r["router"]] = r[counter]
    return out


def held_since(times: list[float], condition, seconds: float) -> float | None:
    """The first time from which condition holds until the end, for at least
    `seconds`. Counted in time, not in samples: routers that answer at
    times of their own make many more times than the sampling interval."""
    since = None
    for t in times:
        if condition(t):
            since = t if since is None else since
        else:
            since = None
    return since if since is not None and times[-1] - since >= seconds - 1e-9 else None


def settled_since(times: list[float], state, seconds: float) -> float | None:
    """The time of the last change, if the state holds from there to the end
    for at least `seconds`, as held_since holds a condition: the sample of the
    change counts, as it does for convergence. None if it changes too late."""
    if not times:
        return None
    changes = [t for before, t in zip(times, times[1:]) if state(t) != state(before)]
    since = changes[-1] if changes else times[0]
    return since if times[-1] - since >= seconds - 1e-9 else None


def hop_of(router: str, value: str, addresses: dict[str, str]):
    """The router a sampled next hop leads to: "." the router itself, else the
    router of the next hop's address, else the neighbor the route came from.
    With NS-BGP, "own;neighbor>route;...", a forwarding.Ingress of the router
    and the first AS of each route."""
    from . import forwarding

    def one(v: str) -> tuple[str | None, int | None]:
        if v == ".":
            return router, None
        neighbor, next_hop, first = (v.split("|") + ["", ""])[:3]
        return addresses.get(next_hop) or neighbor or None, int(first) if first else None

    if ";" not in value and value.count("|") < 2:
        return one(value)[0]
    own, *sent = value.split(";")
    return forwarding.Ingress({None: one(own), **{n: one(v) for n, _, v in (s.partition(">") for s in sent)}})


def loops_on_the_way(dataset: Dataset, key: RunKey, run: dict, own: dict, start: float, end: float,
                     timeline: list | None = None, checks: list | None = None) -> tuple[float, int, float, int] | None:
    """How long any prefix looped between start and end, and the most
    prefixes that looped at once, then the same for black holes, packets
    that end at a router without a route, from the next hops every router, the
    origins too, sampled when its routes changed, over the IGP costs the
    run's igp steps set. A stopped router forwards nothing until it is up
    again. On large tables the routers follow a sample of the prefixes from
    the time the lab named it: counted from then. None for runs that did not
    sample them, or whose tables grew too large to follow without a sample."""
    from . import forwarding

    # When each router's next hops were read: the sample's time on the grid and, where the controller tells it, the
    # delay of the read after it. Two routers read in one sample at different moments are then ordered by when.
    hops_at = sorted((r["t"] + (r.get("hops_ms") or 0) / 1000, router, r["hops"]) for router, rows in own.items() for r in rows if r.get("hops"))
    if sampled := next((e["t"] for e in run.get("events", []) if e["name"] == "hops_sample"), None):
        # Before the sample the routers sent "!" or every prefix: each router counts from its first whole table after it.
        firsts = {}
        for t, router, v in hops_at:
            if t >= sampled and router not in firsts and (v == "~" or v.startswith("*")):
                firsts[router] = t
        if set(firsts) != {router for _, router, _ in hops_at}:  # a router without the sample: not followed
            return None
        hops_at = [(t, router, v) for t, router, v in hops_at if t >= firsts[router]]
        start = max(start, max(firsts.values(), default=sampled))
    if not hops_at or any(v == "!" for _, _, v in hops_at):
        return None
    topology = dataset.topology(key.topology)["routers"]
    addresses, costs, off = run.get("addresses") or {}, {}, set()
    # What happens, in time: next hops, IGP costs, routers stopping and coming back.
    happenings = [(t, "hops", (router, value)) for t, router, value in hops_at]
    happenings += [(e["t"], "igp", (frozenset(e["routers"]), e["cost"])) for e in run.get("events", []) if e["name"] == "igp"]
    happenings += [(t, "stopped", routers) for t, routers in stopped(run.get("events", [])) if t != float("-inf")]
    happenings.sort(key=lambda h: h[0])
    current: dict[str, dict[str, str | None]] = {}
    kept: dict[str, dict] = {}  # the routes of a stopped router, for the changes it sends once it is up
    # Routers back up that have not told their routes since: unknown. Packets
    # end there, neither looping nor in a black hole: their old routes are
    # gone with the restart, and an empty table would be no truer.
    unknown: set[str] = set()
    looping: dict[str, bool] = {}
    holing: dict[str, bool] = {}
    routers, total, most, last, touched, everything = topology, 0.0, 0, None, set(), False
    holed, holed_most = 0.0, 0
    for k, (t, what, detail) in enumerate(happenings):
        if what == "hops":
            router, value = detail
            if router in unknown:
                unknown.discard(router)
                everything = True
            before = dict(current.get(router, {}))
            items = value.split()
            if value == "~" or (items and items[0] == "*"):  # the whole table: empty, or every prefix
                current[router] = {}
                items = items[1:] if value != "~" else []
            mine = current.setdefault(router, {})
            for prefix, _, hop in (item.partition("=") for item in items):
                if hop == "-":
                    mine.pop(prefix, None)
                else:
                    mine[prefix] = hop_of(router, hop, addresses)
            touched |= set(before) | set(mine)
        elif what == "igp":
            link, cost = detail
            costs[link] = cost
            routers, everything = forwarding.with_igp(topology, costs), True
        else:
            for r in detail - off:
                kept[r], current[r] = current.get(r, {}), {}
            for r in off - detail:
                current[r] = kept.pop(r, {})
                unknown.add(r)
            unknown -= set(detail)
            off, everything = set(detail), True
        # Every happening at one moment applied, then the prefixes it touched, and those looping, are followed.
        if k + 1 < len(happenings) and happenings[k + 1][0] == t:
            continue
        changed = set(looping) | touched if everything else touched | {p for p, v in looping.items() if v} | {p for p, v in holing.items() if v}
        touched, everything = set(), False
        if last is not None:
            span = max(0.0, min(t, end) - max(last, start))
            total += span if any(looping.values()) else 0.0
            holed += span if any(holing.values()) else 0.0
        for prefix in changed:
            hops = {r: r if r in unknown else current.get(r, {}).get(prefix) for r in routers}
            found = forwarding.check(routers, hops)
            if checks is not None:  # every verdict, for the episodes an agent reads
                checks.append((t, prefix, found))
            looping[prefix] = any("loops" in p for p in found)
            holing[prefix] = any("without a route" in p for p in found)
        if timeline is not None:  # the prefixes looping and holed from t on, for the charts
            timeline.append((t, sum(looping.values()), sum(holing.values())))
        if start <= t <= end:
            most = max(most, sum(looping.values()))
            holed_most = max(holed_most, sum(holing.values()))
        last = t
    if last is not None and last < end:
        total += end - max(last, start) if any(looping.values()) else 0.0
        holed += end - max(last, start) if any(holing.values()) else 0.0
    return round(total, 3), most, round(holed, 3), holed_most


def run_metrics(dataset: Dataset, key: RunKey, run: dict | None = None) -> dict:
    run = run or dataset.run(key)
    sampling = dataset.experiment.sampling_of(key.variant)
    # The samples of a quiet time span one interval less. With an MRAI quiet
    # lasts longer than one MRAI pause, see Experiment.quiet_s.
    quiet = dataset.experiment.quiet_s(key.variant)
    stable = quiet - sampling.interval
    events = acting(run["events"])
    ref, zero, lead = anchors(events)
    every = dataset.samples(key)
    samples = watched_only(every, run)
    by_t = ticks(samples, run)
    own = defaultdict(list)  # the samples of each router, in time
    for row in sorted(samples, key=lambda r: r["t"]):
        own[row["router"]].append(row)
    # The next hops of every router, the origins included, for loops on the way.
    hops = defaultdict(list)
    for row in sorted(every, key=lambda r: r["t"]):
        if row.get("hops"):
            hops[row["router"]].append(row)
    window = [t for t in by_t if t >= zero["t"] - lead]
    out = dict.fromkeys(METRICS)
    # Sessions: the drops of each router over the run, and those down at its last sample.
    flaps, last = {}, {}
    for row in sorted(every, key=lambda r: r["t"]):
        if row.get("flaps") is not None:
            first, _ = flaps.get(row["router"], (row["flaps"], 0))
            flaps[row["router"]] = (first, row["flaps"])
            last[row["router"]] = row.get("sessions_down") or 0
    if flaps:
        # A restarted gobgpd counts from zero again: its run has a planned restart anyway.
        out["flaps"] = int(sum(max(0, b - a) for a, b in flaps.values()))
        out["sessions_down_end"] = int(sum(last.values()))
    # Per session, those no step touched.
    by, down_by, touched = {}, {}, planned_sessions(run.get("events", []))
    unplanned = lambda r, p: frozenset((r, p)) not in touched and r not in touched and p not in touched
    for row in sorted(every, key=lambda r: r["t"]):
        if row.get("flaps_by") is not None:
            for item in row["flaps_by"].split():
                peer, _, n = item.partition("=")
                first, _ = by.get((row["router"], peer), (int(n), 0))
                by[(row["router"], peer)] = (first, int(n))
            down_by[row["router"]] = set((row.get("down_by") or "").split())
    if by:
        out["flaps_unplanned"] = sum(max(0, b - a) for (r, p), (a, b) in by.items() if unplanned(r, p))
        out["down_unplanned"] = sum(1 for r, peers in down_by.items() for p in peers if unplanned(r, p))
    if final := final_of(run):
        out["unreached"] = sum(final["prefixes"] - h for h in final["held"].values())
        out["loops_end"], out["holes_end"] = final["loops"], final["holes"]
        out["stale_end"] = sum((final.get("stale") or {}).values()) if "stale" in final else None
    if not window:
        return out
    # How often the routers really sampled in the window, the median router
    # and the slowest. Below the interval, times are only as exact as that.
    rates, gaps = {}, []
    for router, rows in own.items():
        inside = [r["t"] for r in rows if r["t"] >= window[0]]
        if len(inside) > 1 and inside[-1] > inside[0]:
            rates[router] = (len(inside) - 1) / (inside[-1] - inside[0])
            gaps.append(max(b - a for a, b in zip(inside, inside[1:])))
    if rates:
        out["sample_hz"], out["sample_hz_min"] = round(median(rates.values()), 2), round(min(rates.values()), 2)
        out["sample_gap_s"] = round(max(gaps), 2)
        out["sample_slowest"] = [[r, round(hz, 2)] for r, hz in sorted(rates.items(), key=lambda x: x[1])[:3]]

    # How busy the host was, all of its CPUs: a saturated host measures itself.
    if host := run.get("host"):
        out["host_cpu_max"] = host["cpu_max"]
        # On a shared host, how much the load of others changed while it ran.
        if "others_max" in host:
            out["host_others_spread"] = round(host["others_max"] - host["others_min"], 3)
            out["host_others_mean"] = host["others_mean"]

    # Convergence and settling are measured until the next event.
    until = min((e["t"] for e in events if e["t"] > ref["t"]), default=float("inf"))
    after = [t for t in window if ref["t"] <= t < until]
    lengths = [r["path_len_avg"] for t in window for r in by_t[t] if r["destinations"]]
    counters = by_t[window[0]][0].get("updates_rx") is not None
    # The Loc-RIB size of Table II, the admitted paths: the largest mean over
    # routers, and the largest table of any router.
    out["rib_mean"] = max(mean(r["paths"] for r in by_t[t]) for t in window)
    out["rib_max"] = max(r["paths"] for t in window for r in by_t[t])
    out["selected_mean"] = max(mean(r["destinations"] for r in by_t[t]) for t in window)
    out["path_len_avg"] = mean(lengths) if lengths else None
    for metric, field in (("adj_in_mean", "adj_in"), ("suppressed_mean", "suppressed"), ("known_mean", "known"), ("rss_mean", "rss_mb"),
                          ("heap_mean", "heap_mb"), ("objects_mean", "heap_objects")):
        # Times at which a router could not read its metrics are left out;
        # runs that never had them give none.
        if values := [v for t in window if (v := values_of(by_t[t], field)) is not None]:
            out[metric] = max(mean(v) for v in values)
    # Blocking: prefixes with a valid path set aside and none admitted, so
    # without a route. The most at one router, and how long any was blocked.
    if any(values_of(by_t[t], "blocked") is not None for t in window):
        out["blocked_max"] = max((r.get("blocked") or 0) for t in window for r in by_t[t])
        out["blocked_s"] = round(sum(b - a for a, b in zip(window, window[1:]) if any(r.get("blocked") for r in by_t[a])), 3)
    # Loops on the way, from the next hops the routers sampled on every change of their table.
    if (found := loops_on_the_way(dataset, key, run, hops, window[0], window[-1])) is not None:
        out["loops_s"], out["loops_max"], out["holes_s"], out["holes_max"] = found
        out["hops_sampled"] = next((e["prefixes"] for e in run["events"] if e["name"] == "hops_sample"), None)
    if any(values_of(by_t[t], "cpu_s") is not None for t in window):
        cpu = used(by_t, window, "cpu_s")
        out["cpu_s_mean"] = mean(cpu.values())
        out["cpu_s_mean_routers"] = [min(cpu.values()), max(cpu.values())]
    # How the routers differ: each router at its own peak, the smallest and the largest.
    for metric, field in ROUTER_FIELDS.items():
        peaks = {}
        for t in window:
            for r in by_t[t]:
                if (v := r.get(field)) is not None:
                    peaks[r["router"]] = max(v, peaks.get(r["router"], v))
        if peaks:
            out[f"{metric}_routers"] = [min(peaks.values()), max(peaks.values())]

    if ref.get("expected") is not None:
        since = held_since(after, lambda t: all(r["destinations"] == ref["expected"] for r in by_t[t]), stable)
        out["convergence_s"] = None if since is None else round(since - ref["t"], 3)

    # Settled: no router changes its table, or receives updates, from one sample to the next.
    fields = COUNTERS if counters else COUNTERS[:2]
    state = lambda t: {r["router"]: tuple(r[f] for f in fields) for r in by_t[t]}
    since = settled_since(after, state, stable)
    out["settle_s"] = None if since is None else round(since - ref["t"], 3)

    # Oscillating: routes still change in the last quiet time after the last
    # event. At rest it needs the quiet time only, as the final check waits
    # for it. Still changing it needs a hold of three quiet times, so that a
    # path exploration that is slow but ends is no oscillation.
    tail = [t for t in window if t >= max(e["t"] for e in events)]
    if len(tail) > 1:
        end = [t for t in tail if t >= tail[-1] - quiet]
        changing = len({tuple(sorted(state(t).items())) for t in end}) > 1
        if tail[-1] - tail[0] >= (3 * quiet if changing else quiet):
            out["oscillates"] = int(changing)
            # How long the routes had to come to rest.
            out["rest_s"] = round(tail[-1] - tail[0], 1)
        # Settling after the last event, as settle_s after the reference: for steps in a series, e.g. flaps, the end of all.
        if out["oscillates"] == 0 and (since := settled_since(tail, state, stable)) is not None:
            out["settle_end_s"] = round(since - max(e["t"] for e in events), 3)

    if counters:
        # The longest pause between events after the announcement, without
        # the seconds it takes to become stable. A replay is no pause: it
        # changes prefixes all along.
        announced = next((e["t"] for e in events if e["name"] == "announced"), None)
        if announced is not None:
            settle = quiet
            busy = [(e["t"], next((f["t"] for f in events if f["name"] == "replayed" and f["t"] >= e["t"]), window[-1]))
                    for e in events if e["name"] == "replay"]
            bounds = sorted({e["t"] for e in events if e["t"] >= announced} | {window[-1]})
            spans = [(a + settle, b) for a, b in zip(bounds, bounds[1:])
                     if b - a > settle + 1 and not any(x <= a < y for x, y in busy)]
            if spans:
                a, b = max(spans, key=lambda s: s[1] - s[0])
                # Per router from its own first and last sample in the
                # hold, over their own times.
                rates = []
                for rows in own.values():
                    inside = [r for r in rows if a <= r["t"] <= b and r.get("updates_rx") is not None]
                    if len(inside) > 1 and inside[-1]["t"] > inside[0]["t"]:
                        rates.append(max(0.0, inside[-1]["updates_rx"] - inside[0]["updates_rx"]) / (inside[-1]["t"] - inside[0]["t"]))
                if rates:
                    out["hold_churn"] = mean(rates)
    return out


def summary(dataset: Dataset) -> list[dict]:
    """Outcomes and metrics per topology, scenario and variant.

    Metrics are aggregated as median, minimum and maximum over the runs
    that did not end in an error, and cached in the folder of the result, with the
    metrics of every run: a new run only adds its own.
    """
    return _summarize(dataset)[0]


def _stamped(dataset: Dataset) -> tuple[dict, list]:
    """The modification time of every finished run, as os.stat's st_mtime
    which the cache holds, and the stamp of the result: the version of the
    metrics, how many runs are done and when the last changed."""
    mtimes = {k: ns // 10**9 + (ns % 10**9) * 1e-9 for k, ns in dataset.done_stamps().items()}
    return mtimes, [VERSION, len(mtimes), max(mtimes.values(), default=0)]


def _cached(dataset: Dataset) -> tuple[dict, dict]:
    """The cache of a result as written, and the runs in it still of this
    version of the metrics. Both empty when there is none or it is damaged."""
    try:
        cached = json.loads((dataset.path / "analysis.json").read_text())
    except (OSError, ValueError):
        return {}, {}
    return cached, cached.get("runs", {}) if cached.get("stamp", [None])[0] == VERSION else {}


def summary_if_known(dataset: Dataset) -> list[dict] | None:
    """The summary as far as it is known already, None while it is still to
    be made, e.g. right after a new version of the metrics: for lists that
    must not wait for the analysis of every result."""
    _, stamp = _stamped(dataset)
    if (kept := getattr(dataset, "_summary", None)) and kept[0] == stamp:
        return kept[1][0]
    cached, _ = _cached(dataset)
    return cached["groups"] if cached.get("stamp") == stamp else None


def run_summary(dataset: Dataset) -> dict[str, dict]:
    """The metrics of every finished run that did not end in an error, by its key."""
    return _summarize(dataset)[1]


def _measure(path: str, key: RunKey) -> tuple[RunKey, dict | None]:
    """The metrics of one run, in a process of its own (see _in_parallel).
    None for a run that ended in an error or could not be measured: this
    process then treats it one by one, as before."""
    from pathlib import Path

    dataset = Dataset(Path(path))
    try:
        run = dataset.run(key)
        return key, (None if run["status"] == "error" else run_metrics(dataset, key, run))
    except Exception:  # noqa: BLE001  told where it is measured again, in the summary's own process
        return key, None


def _bins(path: str, key: RunKey) -> RunKey:
    """The time series of one run, cached beside it, in a process of its own."""
    from pathlib import Path

    dataset = Dataset(Path(path))
    try:
        run_bins(dataset, key, dataset.run(key))
    except Exception:  # noqa: BLE001  the charts then make it when they are opened
        pass
    return key


PARALLEL_FROM = 8  # runs: fewer are measured at once in this process, starting processes costs more


def workers() -> int:
    """Processes for measuring runs, at low priority so the web server stays
    responsive: an eighth of the cores of a host that is often shared, at most
    16, and one per 2 GiB of free memory, as a run of a large topology reads
    many samples."""
    import os

    try:  # what the kernel can give without swapping, the page cache included
        free = next(int(line.split()[1]) * 1024 for line in open("/proc/meminfo") if line.startswith("MemAvailable:"))
    except (OSError, StopIteration, ValueError):
        free = 2**31
    return max(1, min(16, (os.cpu_count() or 2) // 8, int(free // 2**31)))


def _in_parallel(work, path: str, keys: list, done=None) -> list:
    """work(path, key) for every key in processes of their own, as each ends,
    so that a result's runs are measured on several cores, not one. The
    processes start fresh (forkserver), as the web server runs threads."""
    import multiprocessing
    import os
    from concurrent.futures import ProcessPoolExecutor, as_completed

    out = []
    with ProcessPoolExecutor(min(workers(), len(keys)), mp_context=multiprocessing.get_context("forkserver"), initializer=os.nice, initargs=(19,)) as pool:
        for future in as_completed([pool.submit(work, path, k) for k in keys]):
            out.append(future.result())
            if done:
                done()
    return out


def measure_series(dataset: Dataset) -> None:
    """The time series of every finished run of a result made, several runs at once."""
    keys = [k for k in dataset.keys() if dataset.is_done(k)]
    if len(keys) >= PARALLEL_FROM and workers() > 1:
        _in_parallel(_bins, str(dataset.path), keys)
    else:
        for k in keys:
            run_bins(dataset, k, dataset.run(k))


# How far the analysis of a result is, by its folder: runs measured of those to measure.
PROGRESS: dict[str, list[int]] = {}
REPORT = False  # set in a process that analyses for the web server: it tells how far it is on stdout
_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


@contextmanager
def _lock(dataset: Dataset):
    """One analysis of a result at a time, also across processes: a second
    waits and then reads the first's cache."""
    with _LOCKS_GUARD:
        local = _LOCKS.setdefault(str(dataset.path), threading.Lock())
    with local:
        from .config import SETTINGS

        try:
            (folder := SETTINGS / "analysing").mkdir(parents=True, exist_ok=True)
            held = open(folder / f"{dataset.path.parent.name}-{dataset.path.name}.lock", "a")
        except OSError:
            held = None  # alone then, as before
        try:
            if held:
                fcntl.flock(held, fcntl.LOCK_EX)
            yield
        finally:
            if held:
                held.close()


def _tick(path: str) -> None:
    """One more run measured of a result."""
    if (counted := PROGRESS.get(path)) is not None:
        counted[0] += 1
        if REPORT:
            print("progress", *counted, flush=True)


def to_measure(dataset: Dataset) -> int:
    """How many finished runs still lack their metrics, 0 when the summary is known."""
    if summary_if_known(dataset) is not None:
        return 0
    mtimes, _ = _stamped(dataset)
    _, known = _cached(dataset)
    return sum(1 for k in mtimes if (known.get(str(k)) or {}).get("mtime") != mtimes[k])


def known_metrics(dataset: Dataset) -> dict[str, dict]:
    """The metrics of the runs measured already, from the cache, never
    measured here: for what must not wait, as the dock. The rest is measured
    in the background."""
    _, runs = _cached(dataset)
    if to_measure(dataset):
        analyse_in_background(dataset)
    return {k: e["metrics"] for k, e in runs.items()}


_FAILED: dict[str, list] = {}  # by folder, the result as it was when its process failed


def analyse_in_background(dataset: Dataset) -> bool:
    """Measures a result in a process of its own at the lowest priority,
    unless one does already, so that the web server keeps its CPU and
    memory for requests. False when that process failed for the result as
    it is now: a page then measures it itself and shows why."""
    path = str(dataset.path)
    if path in PROGRESS:
        return True
    if _FAILED.get(path) == (stamp := _stamped(dataset)[1]):
        return False
    PROGRESS[path] = [0, to_measure(dataset)]

    def work():
        try:
            proc = subprocess.Popen([sys.executable, "-m", "lab.cli", "analyse", dataset.name], stdout=subprocess.PIPE, text=True)
        except OSError:  # no process allowed: in a thread of this one, as before
            try:
                summary(dataset)
            except (OSError, ValueError, KeyError):
                pass  # the page then shows the error as it would have
            PROGRESS.pop(path, None)
            return
        try:
            for line in proc.stdout:
                parts = line.split()
                if len(parts) == 3 and parts[0] == "progress" and parts[1].isdigit() and parts[2].isdigit():
                    PROGRESS[path] = [int(parts[1]), int(parts[2])]
            if proc.wait():
                _FAILED[path] = stamp
        finally:
            PROGRESS.pop(path, None)

    threading.Thread(target=work, daemon=True).start()
    return True


def _summarize(dataset: Dataset) -> tuple[list[dict], dict[str, dict]]:
    with _lock(dataset):
        return _summarize_locked(dataset)


def _summarize_locked(dataset: Dataset) -> tuple[list[dict], dict[str, dict]]:
    mtimes, stamp = _stamped(dataset)
    done = list(mtimes)
    # A page asks several times: kept on the dataset until a run changes.
    if (kept := getattr(dataset, "_summary", None)) and kept[0] == stamp:
        return kept[1]
    out = _summarize_files(dataset, done, mtimes, stamp)
    dataset._summary = (stamp, out)
    return out


def _summarize_files(dataset: Dataset, done: list, mtimes: dict, stamp: list) -> tuple[list[dict], dict[str, dict]]:
    cache = dataset.path / "analysis.json"
    cached, known = _cached(dataset)  # none yet, or damaged: made again
    if cached.get("stamp") == stamp:
        return cached["groups"], {k: e["metrics"] for k, e in cached["runs"].items()}
    per_run = {}
    # Runs whose metrics are missing, measured on several cores at once when they are many.
    missing = [k for k in done if (known.get(str(k)) or {}).get("mtime") != mtimes[k]]
    if len(missing) >= PARALLEL_FROM and workers() > 1:
        try:
            for key, metrics in _in_parallel(_measure, str(dataset.path), missing, lambda: _tick(str(dataset.path))):
                if metrics is not None:
                    known[str(key)] = {"mtime": mtimes[key], "metrics": metrics}
        except (OSError, ValueError, KeyError, RuntimeError):
            pass  # e.g. no processes allowed: measured one by one below

    def metrics_of(key: RunKey, run: dict) -> dict:
        entry = known.get(str(key))
        if not entry or entry["mtime"] != mtimes[key]:
            entry = {"mtime": mtimes[key], "metrics": run_metrics(dataset, key, run)}
            _tick(str(dataset.path))
        per_run[str(key)] = entry
        return entry["metrics"]

    runs = defaultdict(list)
    for key in done:
        runs[key.topology, key.variant, key.scenario].append(key)
    groups = []
    e = dataset.experiment
    for t, s in e.combinations():
        for v in e.variants:
            keys = runs[t, v.name, s]
            read = {k: dataset.run(k) for k in keys}
            ran = {k: r for k, r in read.items() if r["status"] != "error"}
            values = [metrics_of(k, r) for k, r in ran.items()]
            groups.append({
                "topology": t, "scenario": s, "variant": v.name, "runs": len(keys),
                "statuses": dict(Counter(r["status"] for r in read.values())),
                # Whether the runs know the expected prefixes, which convergence needs.
                "measurable": any(anchors(acting(r["events"]))[0].get("expected") is not None for r in ran.values()),
                "metrics": {m: _with_routers(_aggregate([x[m] for x in values]), [x.get(f"{m}_routers") for x in values]) for m in METRICS},
                "checks": _checks(ran.values()),
            })
    try:
        write_atomic(cache, json.dumps({"stamp": stamp, "groups": groups, "runs": per_run}))
    except OSError:
        pass  # e.g. a public result on a read-only checkout: not cached
    return groups, {k: e["metrics"] for k, e in per_run.items()}


def run_bins(dataset: Dataset, key: RunKey, run: dict) -> dict:
    """One run in one-second bins: per bin and metric the mean, smallest and
    largest router of every sample, and the events relative to t = 0.
    Cached in the folder of the run, since it reads every sample."""
    path = dataset.path / key.path / "series.json"
    stamp = [VERSION, (dataset.path / key.path / "run.json").stat().st_mtime]
    try:
        if (cached := json.loads(path.read_text())).get("stamp") == stamp:
            return cached
    except (OSError, ValueError):
        pass
    _, zero, lead = anchors(acting(run["events"]))
    bins = defaultdict(lambda: defaultdict(list))
    samples = watched_only(dataset.samples(key), run)
    spans = {m: _spans(samples, counter, factor) for m, (counter, factor) in RATES.items()}
    for t, rows in ticks(samples, run).items():
        b = math.floor(t - zero["t"])  # bin b holds [b, b + 1)
        if b < -lead:
            continue
        values = {m: v for m in SERIES if m not in RATES and m not in WAY and (v := values_of(rows, m)) is not None}
        for m in RATES:
            rates = [x for r in rows if (x := _rate_at(spans[m].get(r["router"]), t)) is not None]
            if len(rates) == len(rows):
                values[m] = rates
        for m, v in values.items():
            bins[b][m].append((mean(v), min(v), max(v)))
    # How often each watched router sampled in every second, 0 for one that
    # did not, and how busy the host was: the quality of the measurement.
    counts = defaultdict(lambda: defaultdict(int))
    for row in samples:
        counts[math.floor(row["t"] - zero["t"])][row["router"]] += 1
    watched = run.get("watched") or sorted({row["router"] for row in samples})
    end = max((row["t"] for row in samples), default=0) - zero["t"]
    for b, per_router in counts.items():
        if -lead <= b and b + 1 <= end:  # whole seconds only, the last one is cut off
            v = [per_router.get(r, 0) for r in watched]
            bins[b]["sample_rate"].append((mean(v), min(v), max(v)))
    # Loops and black holes on the way: per second the most prefixes at once, held from one change to the next.
    hops = defaultdict(list)
    for row in sorted(dataset.samples(key), key=lambda r: r["t"]):
        if row.get("hops"):
            hops[row["router"]].append(row)
    timeline: list = []
    try:
        followed = hops and loops_on_the_way(dataset, key, run, hops, zero["t"] - lead, end + zero["t"], timeline) is not None
    except Exception:  # noqa: BLE001  the charts of loops are extra: a run they fail on keeps its other series
        followed, timeline = False, []
    if followed and timeline:
        k, now = 0, (0, 0)
        for b in range(max(-lead, math.floor(timeline[0][0] - zero["t"])), math.floor(end)):  # whole seconds, as sample_rate
            most = now
            while k < len(timeline) and timeline[k][0] - zero["t"] < b + 1:
                now = timeline[k][1:]
                most = tuple(map(max, most, now))
                k += 1
            for m, v in zip(WAY, most):
                bins[b][m].append((v, v, v))
    for t, share in (run.get("host") or {}).get("series", []):
        if (b := math.floor(t - zero["t"])) >= -lead:
            bins[b]["host_cpu"].append((100 * share,) * 3)
    out = {"stamp": stamp, "events": [{"name": e["name"], "t": round(e["t"] - zero["t"], 1)} for e in run["events"]],
           "bins": {str(b): dict(ms) for b, ms in bins.items()}}
    try:
        write_atomic(path, json.dumps(out))
    except OSError:
        pass  # e.g. a public result on a read-only checkout: not cached
    return out


def _spans(samples: list[dict], counter: str, factor: float) -> dict[str, tuple[list, list, list]]:
    """Per router the spans between its own consecutive samples, as their
    starts, ends and the rate of the counter in them. A router that answers
    seldom spreads what its counter grew over the whole span, instead of
    the moment its sample came. A restarted router counts from zero again."""
    out: dict[str, tuple[list, list, list]] = {}
    last: dict[str, dict] = {}
    for row in sorted(samples, key=lambda r: r["t"]):
        r = row["router"]
        if row.get(counter) is None:
            continue
        if (before := last.get(r)) is not None and row["t"] > before["t"]:
            starts, ends, rates = out.setdefault(r, ([], [], []))
            starts.append(before["t"])
            ends.append(row["t"])
            rates.append(factor * max(0.0, row[counter] - before[counter]) / (row["t"] - before["t"]))
        last[r] = row
    return out


def _rate_at(spans: tuple[list, list, list] | None, t: float) -> float | None:
    """The rate of the span that holds t, (start, end]."""
    if not spans:
        return None
    starts, ends, rates = spans
    i = bisect.bisect_left(ends, t)
    return rates[i] if i < len(ends) and starts[i] < t else None


def series(dataset: Dataset, topology: str, variant: str, scenario: str) -> dict:
    """Time series over all runs of a group, in one-second bins.

    For every metric and time: `median` is the median over the runs of
    each run's mean over its routers, as the summary takes it, with the
    exact interval of that median (`ci_low`, `ci_high`, `ci_level`, from
    three runs on); `min`/`max` span all routers of all runs, how the
    routers differ. `events` are the events of the first run.
    """
    per_bin = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))  # bin -> metric -> run -> [(mean, min, max)]
    events = None
    for index in range(1, dataset.experiment.runs + 1):
        key = RunKey(topology, variant, scenario, index)
        if not dataset.is_done(key) or (run := dataset.run(key))["status"] == "error":
            continue
        cached = run_bins(dataset, key, run)
        if events is None:
            events = cached["events"]
        for b, metrics in cached["bins"].items():
            for m, values in metrics.items():
                per_bin[int(b)][m][index].extend(tuple(v) for v in values)
    bins = sorted(per_bin)

    def at(b: int, m: str) -> dict:
        runs = per_bin[b][m]
        if not runs:
            return {}
        means = [mean(x[0] for x in values) for values in runs.values()]  # one value per run
        ci = median_ci(means) or {}
        return {"median": median(means), "ci_low": ci.get("low"), "ci_high": ci.get("high"), "ci_level": ci.get("level"),
                "min": min(x[1] for values in runs.values() for x in values), "max": max(x[2] for values in runs.values() for x in values)}

    out = {m: {k: [] for k in ("median", "ci_low", "ci_high", "ci_level", "min", "max")} for m in SERIES}
    for b in bins:
        for m in SERIES:
            point = at(b, m)
            for k, values in out[m].items():
                values.append(None if point.get(k) is None else round(point[k], 4) if k == "ci_level" else _round(point[k]))
    return {"t": bins, "events": events or [], "metrics": out}


def final_of(run: dict) -> dict | None:
    """The final check of a run that looked at the routes, None if it did not."""
    return next((e for e in run.get("events", []) if e["name"] == "final" and "held" in e), None)


def rested(run: dict, m: dict | None) -> bool | None:
    """Whether the routes of a finished run came to rest: False where a step or
    the final check waited for rest in vain or routes still changed at the end,
    None where the run has no rest value (not measured), True otherwise."""
    final = final_of(run)
    if (m or {}).get("oscillates") == 1 or any(not s.get("stable", True) for s in run.get("measurements", [])) \
            or (final and final.get("stable") is False):
        return False
    if not m or m.get("oscillates") is None or m.get("settle_s") is None:
        return None
    return True


def check_ok(event: dict) -> bool:
    """Whether an expect step passed, or failed in a mode its scenario allows to fail it."""
    return event["passed"] or event.get("allowed", False)


def _checks(runs) -> dict | None:
    """Of the runs with expect steps, how many passed all of them, failures
    their scenario allows counted as passed."""
    checked = [[check_ok(e) for e in r["events"] if e["name"] == "expect"] for r in runs]
    checked = [c for c in checked if c]
    return {"passed": sum(all(c) for c in checked), "runs": len(checked)} if checked else None


def size_series(topologies: list[str]) -> bool:
    """Whether topologies are one network in several sizes: their names differ
    in one number only, like core-32 and core-64, not unrelated networks."""
    parts = [t.split("-") for t in topologies]
    if len(parts) < 2 or len({len(p) for p in parts}) != 1:
        return False
    differ = [i for i in range(len(parts[0])) if len({p[i] for p in parts}) > 1]
    return len(differ) == 1 and all(p[differ[0]].isdigit() for p in parts)


def curve(dataset: Dataset, topology: str, scenario_name: str, metric: str) -> dict:
    """A metric over the values of the sweep a case belongs to, or else over
    the size of the topologies: per variant the median of the runs at every point and the
    exact interval of that median, as in the summary."""
    from . import scenario

    e = dataset.experiment
    if sweep := e.sweep_of(scenario_name):
        points = [(v, topology, scenario.case_name(sweep.scenario, sweep.param, v)) for v in sweep.values]
        label = sweep.param
    else:
        points = sorted((len(dataset.topology(t)["routers"]), t, scenario_name) for t in e.topologies)
        label = "routers"
    groups = {(g["topology"], g["scenario"], g["variant"]): g for g in summary(dataset)}
    series = {}
    for v in e.variants:
        cells = [(groups.get((t, s, v.name)) or {}).get("metrics", {}).get(metric) or {} for _, t, s in points]
        series[v.name] = {k: [c.get(k) for c in cells] for k in ("median", "ci_low", "ci_high", "ci_level", "n", "router_min", "router_max")}
    return {"x": [x for x, _, _ in points], "label": label, "variants": [v.name for v in e.variants], "series": series}


def failed_checks(dataset: Dataset, topology: str | None = None) -> list[dict]:
    """Every expect step that failed, with the run, its step and its problems."""
    out = []
    for key in sorted(dataset.keys(), key=lambda k: (k.topology, k.scenario, k.variant, k.index)):
        if (topology and key.topology != topology) or not dataset.is_done(key):
            continue
        for e in dataset.run(key).get("events", []):  # a run that ended in an error has none
            if e["name"] == "expect" and not check_ok(e):
                out.append({"topology": key.topology, "scenario": key.scenario, "variant": key.variant, "run": key.index,
                            "step": e.get("step"), "t": e.get("t"), "routers": e.get("routers", []), "problems": e.get("problems", [])})
    return out


def _aggregate(values: list) -> dict | None:
    values = [v for v in values if v is not None]
    if not values:
        return None
    out = {"median": _round(median(values)), "min": _round(min(values)), "max": _round(max(values)), "n": len(values)}
    if ci := median_ci(values):
        out |= {"ci_low": _round(ci["low"]), "ci_high": _round(ci["high"]), "ci_level": round(ci["level"], 4)}
    return out


def _with_routers(cell: dict | None, spreads: list) -> dict | None:
    """A cell with the smallest and the largest router of all its runs, where routers differ."""
    spreads = [x for x in spreads if x]
    if cell is None or not spreads:
        return cell
    return {**cell, "router_min": _round(min(x[0] for x in spreads)), "router_max": _round(max(x[1] for x in spreads))}


def median_ci(values: list[float], level: float = 0.95) -> dict | None:
    """The exact, distribution-free confidence interval of the median from
    order statistics: [x(k), x(n+1-k)] covers it with 1 - 2 P(B <= k-1),
    B ~ Binomial(n, 1/2). The narrowest that reaches the level, or else the
    widest, [min, max], with the level it reaches: 75 % for three runs,
    93.8 % for five, 96.9 % for six. With few runs it is the range of the
    runs, at a lower level. None below three: two runs reach 50 %."""
    x, n = sorted(values), len(values)
    if n < 3:
        return None
    cdf = lambda c: sum(math.comb(n, i) for i in range(c + 1)) / 2 ** n
    k = max([j for j in range(1, n // 2 + 1) if 1 - 2 * cdf(j - 1) >= level], default=1)
    return {"low": x[k - 1], "high": x[n - k], "level": 1 - 2 * cdf(k - 1)}


def hodges_lehmann(differences: list[float], level: float = 0.95) -> dict | None:
    """The Hodges-Lehmann estimate of the shift of paired differences, the
    median of their Walsh averages, with the exact confidence interval that
    belongs to the Wilcoxon signed-rank test: [W(k), W(M+1-k)] of the M sorted
    averages covers the shift with 1 - 2 P(T <= k-1), T the signed-rank
    statistic. As for the median: the narrowest at the level, or else the
    widest with the level it reaches. None for fewer than two pairs."""
    n = len(differences)
    if n < 2:
        return None
    walsh = sorted((differences[i] + differences[j]) / 2 for i in range(n) for j in range(i, n))
    counts = [1] + [0] * (n * (n + 1) // 2)  # ways for each rank sum, rank by rank
    for r in range(1, n + 1):
        for total in range(len(counts) - 1, r - 1, -1):
            counts[total] += counts[total - r]
    cdf = lambda c: sum(counts[: c + 1]) / 2 ** n
    m = len(walsh)
    k = max([j for j in range(1, m // 2 + 1) if 1 - 2 * cdf(j - 1) >= level], default=1)
    return {"estimate": median(walsh), "low": walsh[k - 1], "high": walsh[m - k], "level": 1 - 2 * cdf(k - 1)}


def _round(x: float) -> float:
    return round(x, 3)


FRAMES = 1200


def replay(dataset: Dataset, key: RunKey) -> dict:
    """One run, frame by frame, for the replay on the topology.

    For every sample time: updates per second, paths and prefixes of each
    router, and updates per second on each link, from the counters per
    neighbor where the run has them. A stopped router has empty tables.
    t = 0 is the start of the run.
    """
    run = dataset.run(key)
    by_t = ticks(watched_only(dataset.samples(key), run), run)
    times = list(by_t)
    # Long runs of many routers at most FRAMES frames, evenly: a frame holds
    # every link, thousands in the core. Rates then span the longer step.
    if len(times) > FRAMES:
        times = times[::-(-len(times) // FRAMES)]
    frames = {r: {"churn": [], "paths": [], "suppressed": [], "adj_in": [], "destinations": []} for r in run["watched"]}
    links: dict[tuple, list] = defaultdict(lambda: [0.0] * len(times))
    # A router may answer seldom: its rates come from its own samples and
    # hold until its next one.
    before: dict[str, dict] = {}
    rate: dict[str, float] = {}
    link_rate: dict[tuple, dict[str, float]] = defaultdict(dict)
    for i, t in enumerate(times):
        rows = {row["router"]: row for row in by_t[t]}
        for r, frame in frames.items():
            row, last = rows.get(r), before.get(r)
            frame["paths"].append(int(row["paths"]) if row else 0)
            frame["suppressed"].append(int(row.get("suppressed") or 0) if row else 0)
            frame["adj_in"].append(int(row.get("adj_in") or 0) if row else 0)
            frame["destinations"].append(int(row["destinations"]) if row else 0)
            fresh = row and last and row is not last and row["t"] > last["t"] and row.get("updates_rx") is not None
            if fresh:
                dt = row["t"] - last["t"]
                rate[r] = round(max(0.0, row["updates_rx"] - last["updates_rx"]) / dt, 1)
                if row.get("peers_rx") and last.get("peers_rx"):
                    now, then = _peers(row["peers_rx"]), _peers(last["peers_rx"])
                    link_rate[r] = {peer: round(max(0, count - then.get(peer, count)) / dt, 1) for peer, count in now.items()}
            elif not row:
                rate.pop(r, None)
                link_rate.pop(r, None)
            frame["churn"].append(rate.get(r, 0.0))
            for peer, value in link_rate.get(r, {}).items():
                links[tuple(sorted((r, peer)))][i] += value
            if row:
                before[r] = row
    events = sorted(run["events"], key=lambda e: e["t"])  # older runs kept the order in which they ended
    # The end of every until_stable, stable or not: where the variants
    # align in the replay by steps.
    settled = [{"name": "settled", "t": m["t"], "stable": m["stable"], **({"step": m["step"]} if "step" in m else {})}
               for m in run.get("measurements", [])]
    return {
        "t": [round(t, 3) for t in times],
        # Runs of the former scripts have no update counters, so no activity,
        # and runs before 2026-10 did not count the paths set aside and the
        # Adj-RIB-In.
        "counters": any(row.get("updates_rx") is not None for rows in by_t.values() for row in rows),
        "sizes": any(row.get("suppressed") is not None for rows in by_t.values() for row in rows),
        "routers": frames,
        "links": {f"{a}|{b}": v for (a, b), v in links.items()},
        "events": sorted([{**e, "links": e.get("links", [])} for e in events] + settled, key=lambda e: e["t"]),
        "expected": [_expected(events, t) for t in times],
        "status": run["status"],
    }


def _peers(text: str) -> dict[str, int]:
    return {k: int(v) for k, v in (item.split("=", 1) for item in text.split())}


def _expected(events: list[dict], t: float):
    """The prefixes every router should hold at t, from the latest event that says so."""
    known = [e["expected"] for e in events if e["t"] <= t and e.get("expected") is not None]
    return known[-1] if known else None


def wilcoxon_p(differences: list[float]) -> float | None:
    """The exact two-sided p of the Wilcoxon signed-rank test, for paired
    differences; zero ones are left out, ties share their ranks. None for
    fewer than two. Counted over all signs by dynamic programming on doubled
    ranks, which are whole numbers also for ties. With n pairs the smallest
    p is 2 / 2**n: five pairs can never fall below 0.0625, so they cannot
    tell a difference at 5 %."""
    d = [x for x in differences if x != 0]
    n = len(d)
    if n < 2:
        return None
    order = sorted(range(n), key=lambda i: abs(d[i]))
    doubled = [0] * n  # twice the rank, the mean rank of a tie doubled is whole
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(d[order[j + 1]]) == abs(d[order[i]]):
            j += 1
        for k in range(i, j + 1):
            doubled[order[k]] = i + j + 2
        i = j + 1
    w = sum(r for r, x in zip(doubled, d) if x > 0)
    total = sum(doubled)
    counts = [1] + [0] * total  # ways to reach each doubled rank sum
    for r in doubled:
        for t in range(total, r - 1, -1):
            counts[t] += counts[t - r]
    extreme = abs(2 * w - total)  # distance from the centre, doubled again
    return sum(c for t, c in enumerate(counts) if abs(2 * t - total) >= extreme) / 2 ** n


def paired(dataset: Dataset, topology: str, scenario: str, metric: str, variant: str, baseline: str) -> dict | None:
    """A variant against a baseline in the runs paired by their seed: the
    median of the relative differences of the pairs, the p of the Wilcoxon
    signed-rank test, and the Hodges-Lehmann shift with its exact interval."""
    runs = run_summary(dataset)
    pairs = []
    for i in range(1, dataset.experiment.runs + 1):
        a = (runs.get(str(RunKey(topology, variant, scenario, i))) or {}).get(metric)
        b = (runs.get(str(RunKey(topology, baseline, scenario, i))) or {}).get(metric)
        if a is not None and b is not None:
            pairs.append((a, b))
    if not pairs:
        return None
    relative = [100 * (a - b) / b for a, b in pairs if b]
    differences = [a - b for a, b in pairs]
    out = {"n": len(pairs), "change": median(relative) if relative else None, "p": wilcoxon_p(differences)}
    if shift := hodges_lehmann(differences):
        out |= {"shift": shift["estimate"], "shift_low": shift["low"], "shift_high": shift["high"], "shift_level": shift["level"]}
    return out


def holm(ps: list[float]) -> list[float]:
    """Holm's step-down adjustment of p values, in their order: the smallest
    times their number, the next times one less, never below the one before."""
    order = sorted(range(len(ps)), key=lambda i: ps[i])
    out, running = [0.0] * len(ps), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(ps) - rank) * ps[i]))
        out[i] = running
    return out


def primary(dataset: Dataset) -> dict | None:
    """The comparison the experiment is about, every compared variant in
    every cell, its p values Holm-corrected per variant across its cells.
    None without one."""
    e = dataset.experiment
    if not (p := e.primary):
        return None
    variants = p.compared([v.name for v in e.variants])
    cells = []
    for variant in variants:
        for topology in e.topologies:
            for case in e.cases_of(topology):
                pr = paired(dataset, topology, case, p.metric, variant, p.baseline)
                cells.append({"variant": variant, "topology": topology, "scenario": case, **(pr or {"n": 0, "p": None})})
    tested = [c for c in cells if c["p"] is not None]
    # One family per variant: each gets the same test against the baseline, none is preferred.
    for variant in variants:
        mine = [c for c in tested if c["variant"] == variant]
        for c, adjusted in zip(mine, holm([c["p"] for c in mine])):
            c["holm"] = adjusted
    each = {v: {"tested": sum(c["variant"] == v for c in tested), "significant": sum(c["variant"] == v and c["holm"] < 0.05 for c in tested)}
            for v in variants}
    return {"metric": p.metric, "variants": variants, "baseline": p.baseline, "cells": cells, "each": each,
            "tested": len(tested), "significant": sum(c["holm"] < 0.05 for c in tested)}


BUSY_HOST = 0.9  # a larger share of the CPUs in use, and a run may measure the host
SHIFTING_HOST = 0.2  # the load of others on a shared host changed by more during a run


def integrity(dataset: Dataset) -> dict:
    """What limits the measurements of a result: routers that sampled far
    less often than set, so that times are only as exact as their samples;
    a host that was nearly saturated, or whose load by others changed much;
    runs of different images of a variant. Oscillating names the groups
    whose routes did not come to rest, which loads the host most."""
    hz = lambda variant: 1 / dataset.experiment.sampling_of(variant).interval
    set_hz = max((hz(v.name) for v in dataset.experiment.variants), default=hz(None))
    out = {"set": set_hz, "low": None, "high": None, "slow": [], "busy": [], "shifting": [], "images": {}, "noise": None,
           "skipped": dataset.status.get("skipped") or {}, "limit": dataset.status.get("limit")}
    try:
        groups = summary(dataset)
    except (OSError, ValueError, KeyError):
        return out
    medians = [m["min"] for g in groups if (m := g["metrics"].get("sample_hz"))]
    slowest = [(g, m) for g in groups if (m := g["metrics"].get("sample_hz_min"))]
    where = lambda g: {"topology": g["topology"], "scenario": g["scenario"], "variant": g["variant"],
                       "oscillating": bool((o := g["metrics"].get("oscillates")) and o["max"])}
    out.update(low=min((m["min"] for _, m in slowest), default=None), high=max(medians, default=None),
               slow=sorted(({**where(g), "hz": m["min"]} for g, m in slowest if m["min"] < hz(g["variant"]) / 2), key=lambda x: x["hz"]),
               busy=sorted(({**where(g), "cpu": m["max"]} for g in groups if (m := g["metrics"].get("host_cpu_max")) and m["max"] > BUSY_HOST),
                           key=lambda x: -x["cpu"]),
               shifting=sorted(({**where(g), "spread": m["max"]} for g in groups
                                if (m := g["metrics"].get("host_others_spread")) and m["max"] > SHIFTING_HOST),
                               key=lambda x: -x["spread"]))
    # The noise of a shared host: what others used, as a share of its CPUs.
    if noise := [m for g in groups if (m := g["metrics"].get("host_others_mean"))]:
        out["noise"] = {"median": median(m["median"] for m in noise), "max": max(m["max"] for m in noise)}
    images = defaultdict(set)
    for key in dataset.keys():
        if dataset.is_done(key) and (image := dataset.run(key).get("image")):
            images[key.variant].add(image)
    out["images"] = {v: sorted(tags) for v, tags in images.items() if len(tags) > 1}
    return out


def episodes(dataset: Dataset, key: RunKey, run: dict) -> list[dict] | None:
    """Every loop and black hole on the way of a run: the prefix, what the
    forwarding check found, from when until when, by the same analysis as
    the metrics. None where the run did not follow its next hops."""
    from collections import defaultdict as _dd

    own = _dd(list)
    for row in dataset.samples(key):
        own[row["router"]].append(row)
    checks: list = []
    if loops_on_the_way(dataset, key, run, own, float("-inf"), float("inf"), checks=checks) is None:
        return None
    out, open_ = [], {}
    for t, prefix, found in checks:
        now = set(found)
        for problem in [p for (pre, p) in open_ if pre == prefix and p not in now]:
            out.append({"prefix": prefix, "problem": problem, "from_s": open_.pop((prefix, problem)), "to_s": t})
        for problem in now:
            open_.setdefault((prefix, problem), t)
    out += [{"prefix": pre, "problem": p, "from_s": t0, "to_s": None} for (pre, p), t0 in open_.items()]
    return sorted(out, key=lambda e: (e["from_s"], e["prefix"]))
