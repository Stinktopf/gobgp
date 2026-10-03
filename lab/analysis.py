"""Metrics and time series of the runs of a result.

The events of a run come from its scenario. Metrics are measured from the
reference event: the first event after the announcement, e.g. a
withdrawal or a failure, or the end of the announcement if there is none.
Charts put t = 0 at the event that defines the scenario: the first
announcement for pure announcements, the reference event otherwise.

convergence_s   time until every router holds the expected prefixes
settle_s        time until no router changes anything
                (both until the next event, and only if the state holds there)
hold_churn      updates per router and second in the longest stretch without
                events, a replay being one; zero unless routes keep changing
sample_hz       how often the routers really sampled, the median router;
                sample_hz_min the slowest one. Busy routers sample less often
                than set, and the times above are then only as exact
host_cpu_max    the largest share of the CPUs of the host in use during the
                run, in one second; runs before 2026-10-02 did not record it
host_others_spread  on a shared host, how much the share of others changed
                during the run; runs before 2026-10-03 did not record it
rest_s          the seconds from the last event to the end of the run, in
                which routes had to come to rest for oscillates
oscillates      1 if routes still change at the end of a hold after the
                last event, else 0; none if the run ends once quiet

The sizes of the tables, each the peak of the mean over the routers:
adj_in_mean     the paths received from all peers (Adj-RIB-In)
rib_mean        the paths the import admits, the Loc-RIB size of the paper;
                rib_max is the largest of any router
suppressed_mean the paths OBGP keeps without admitting them
selected_mean   the routes the decision process selects, one per prefix
                (the Loc-RIB of RFC 4271)
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
import json
import math
from collections import Counter, defaultdict
from statistics import mean, median

from .results import COUNTERS, Dataset, RunKey, write_atomic

VERSION = 24  # of the metrics; a change recomputes the cached summaries
METRICS = ["convergence_s", "settle_s", "hold_churn", "oscillates", "rest_s", "sample_hz", "sample_hz_min", "host_cpu_max", "host_others_spread", "adj_in_mean", "rib_mean", "rib_max", "suppressed_mean",
           "selected_mean", "path_len_avg", "rss_mean", "heap_mean", "objects_mean", "cpu_s_mean"]
# The sizes and resources that differ by router, and the field of each in the samples.
ROUTER_FIELDS = {"adj_in_mean": "adj_in", "rib_mean": "paths", "suppressed_mean": "suppressed", "selected_mean": "destinations",
                 "rss_mean": "rss_mb", "heap_mean": "heap_mb", "objects_mean": "heap_objects"}
ROUTER_METRICS = [*ROUTER_FIELDS, "cpu_s_mean"]
SERIES = ["destinations", "paths", "suppressed", "adj_in", "rss_mb", "heap_mb", "heap_objects", "cpu", "path_len_avg", "churn"]
RATES = {"churn": ("updates_rx", 1), "cpu": ("cpu_s", 100)}  # per second; CPU in percent
PREFIX_EVENTS = ("announce", "announced")
LEAD = 5  # seconds shown before the event
# The latest sample of a router stands for it this long. Routers busy with
# large tables sample every few seconds only; their counters keep counting,
# so a change shows with the next sample.
STALE_S = 10


CHECKS = ("expect",)  # events that look at the routes without changing them


def acting(events: list[dict]) -> list[dict]:
    """The events that change something, without the checks: a check must
    not move the reference, end a window or split a rest."""
    return [e for e in events if e["name"] not in CHECKS]


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
            out[t] = [latest[r] for r in sorted(running | {r["router"] for r in rows})]
    return out


def values_of(rows: list[dict], metric: str) -> list[float] | None:
    """The values of a metric in the rows of one time, None unless every
    router has one: runs before 2026-10 did not count the suppressed paths,
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


def run_metrics(dataset: Dataset, key: RunKey, run: dict | None = None) -> dict:
    run = run or dataset.run(key)
    sampling = dataset.experiment.sampling
    # As long as stable_count samples span at the sampling interval.
    stable = sampling.stable_s - sampling.interval
    events = acting(run["events"])
    ref, zero, lead = anchors(events)
    samples = dataset.samples(key)
    by_t = ticks(samples, run)
    own = defaultdict(list)  # the samples of each router, in time
    for row in sorted(samples, key=lambda r: r["t"]):
        own[row["router"]].append(row)
    window = [t for t in by_t if t >= zero["t"] - lead]
    out = dict.fromkeys(METRICS)
    if not window:
        return out
    # How often the routers really sampled in the window, the median router
    # and the slowest. Below the interval, times are only as exact as that.
    rates = []
    for rows in own.values():
        inside = [r["t"] for r in rows if r["t"] >= window[0]]
        if len(inside) > 1 and inside[-1] > inside[0]:
            rates.append((len(inside) - 1) / (inside[-1] - inside[0]))
    if rates:
        out["sample_hz"], out["sample_hz_min"] = round(median(rates), 2), round(min(rates), 2)

    # How busy the host was, all of its CPUs: a saturated host measures itself.
    if host := run.get("host"):
        out["host_cpu_max"] = host["cpu_max"]
        # On a shared host, how much the load of others changed while it ran.
        if "others_max" in host:
            out["host_others_spread"] = round(host["others_max"] - host["others_min"], 3)

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
    for metric, field in (("adj_in_mean", "adj_in"), ("suppressed_mean", "suppressed"), ("rss_mean", "rss_mb"),
                          ("heap_mean", "heap_mb"), ("objects_mean", "heap_objects")):
        # Times at which a router could not read its metrics are left out;
        # runs that never had them give none.
        if values := [v for t in window if (v := values_of(by_t[t], field)) is not None]:
            out[metric] = max(mean(v) for v in values)
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

    # Oscillating: in a hold of some length after the last event, routes
    # still change at its end. A run that ends once quiet holds too briefly.
    tail = [t for t in window if t >= max(e["t"] for e in events)]
    if len(tail) > 1 and tail[-1] - tail[0] >= 3 * sampling.stable_s:
        end = [t for t in tail if t >= tail[-1] - sampling.stable_s]
        out["oscillates"] = int(len({tuple(sorted(state(t).items())) for t in end}) > 1)
        # How long the routes had to come to rest: path exploration that
        # takes longer than this counts as oscillation too.
        out["rest_s"] = round(tail[-1] - tail[0], 1)

    if counters:
        # The longest pause between events after the announcement, without
        # the seconds it takes to become stable. A replay is no pause: it
        # changes prefixes all along.
        announced = next((e["t"] for e in events if e["name"] == "announced"), None)
        if announced is not None:
            settle = sampling.stable_s
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
    that did not fail, and cached in the folder of the result, with the
    metrics of every run: a new run only adds its own.
    """
    return _summarize(dataset)[0]


def run_summary(dataset: Dataset) -> dict[str, dict]:
    """The metrics of every finished run that did not fail, by its key."""
    return _summarize(dataset)[1]


def _summarize(dataset: Dataset) -> tuple[list[dict], dict[str, dict]]:
    done = [k for k in dataset.keys() if dataset.is_done(k)]
    mtimes = {k: (dataset.path / k.path / "run.json").stat().st_mtime for k in done}
    stamp = [VERSION, len(done), max(mtimes.values(), default=0)]
    cache = dataset.path / "analysis.json"
    try:
        cached = json.loads(cache.read_text())
        if cached.get("stamp") == stamp:
            return cached["groups"], {k: e["metrics"] for k, e in cached["runs"].items()}
        known = cached.get("runs", {}) if cached.get("stamp", [None])[0] == VERSION else {}
    except (OSError, ValueError):
        known = {}  # none yet, or damaged: made again
    per_run = {}

    def metrics_of(key: RunKey, run: dict) -> dict:
        entry = known.get(str(key))
        if not entry or entry["mtime"] != mtimes[key]:
            entry = {"mtime": mtimes[key], "metrics": run_metrics(dataset, key, run)}
        per_run[str(key)] = entry
        return entry["metrics"]

    runs = defaultdict(list)
    for key in done:
        runs[key.topology, key.variant, key.scenario].append(key)
    groups = []
    e = dataset.experiment
    for t in e.topologies:
        for s in e.cases():
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
    samples = dataset.samples(key)
    spans = {m: _spans(samples, counter, factor) for m, (counter, factor) in RATES.items()}
    for t, rows in ticks(samples, run).items():
        b = math.floor(t - zero["t"])  # bin b holds [b, b + 1)
        if b < -lead:
            continue
        values = {m: v for m in SERIES if m not in RATES and (v := values_of(rows, m)) is not None}
        for m in RATES:
            rates = [x for r in rows if (x := _rate_at(spans[m].get(r["router"]), t)) is not None]
            if len(rates) == len(rows):
                values[m] = rates
        for m, v in values.items():
            bins[b][m].append((mean(v), min(v), max(v)))
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


def _checks(runs) -> dict | None:
    """Of the runs with expect steps, how many passed all of them."""
    checked = [[e["passed"] for e in r["events"] if e["name"] == "expect"] for r in runs]
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
        for e in dataset.run(key)["events"]:
            if e["name"] == "expect" and not e["passed"]:
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
    by_t = ticks(dataset.samples(key), run)
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
        # and runs before 2026-10 did not count the suppressed paths and the
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
    fewer than two. With n pairs the smallest p is 2 / 2**n: five pairs can
    never fall below 0.0625, so they cannot tell a difference at 5 %."""
    d = [x for x in differences if x != 0]
    n = len(d)
    if n < 2 or n > 20:
        return None
    order = sorted(range(n), key=lambda i: abs(d[i]))
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(d[order[j + 1]]) == abs(d[order[i]]):
            j += 1
        for k in range(i, j + 1):
            ranks[order[k]] = (i + j) / 2 + 1
        i = j + 1
    w = sum(r for r, x in zip(ranks, d) if x > 0)
    centre = n * (n + 1) / 4
    extreme = abs(w - centre)
    count = 0
    for mask in range(2 ** n):
        total = sum(ranks[i] for i in range(n) if mask >> i & 1)
        if abs(total - centre) >= extreme - 1e-9:
            count += 1
    return count / 2 ** n


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
