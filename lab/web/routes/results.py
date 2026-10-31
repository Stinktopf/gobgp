"""Results: the list, each result with its tabs, and comparisons."""

import csv
import io
import re
from collections import defaultdict
from statistics import median
from urllib.parse import urlencode

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ... import (
    analysis,
    config,
)
from ...problems import PROPERTIES
from ...problems import grouped as problem_groups
from ...problems import of as problems_of
from ...results import Dataset, RunKey, folder_size, storage
from ..common import (
    METRICS,
    back,
    download,
    find,
    gone,
    jobs,
    metrics_of,
    problems,
    still,
    with_error,
)
from ..context import allowed_failures, came_to_rest, render
from .experiments import start, wake

router = APIRouter()


# From what ran to the numbers, over time, a single run, and how it was set up.
TABS = {"runs": "Runs", "table": "Table", "charts": "Charts", "replay": "Replay", "quality": "Quality", "details": "Details"}


OLD_TABS = {"overview": "table"}  # links from before


SERIES_CACHE: dict = {}  # (result, topology, scenario, done runs) -> series of every variant


def result_context(dataset: Dataset, tab: str, topology: str = "", scenario: str = "") -> dict:
    experiment = dataset.experiment
    status = dataset.status
    topologies = experiment.topologies
    topology = topology if topology in topologies else topologies[0]
    scenarios = experiment.cases_of(topology)  # those that run on it
    context = {
        "result": dataset,
        "experiment": experiment,
        "status": status,
        "queued": dataset.name in jobs.queue(),
        # The experiment file it was made from, if it is still there.
        "source": experiment.name if config.path_ok(experiment.name) and config.path(experiment.name).exists() else None,
        "topology": topology,
        "scenario": scenario if scenario in scenarios else "",
        "integrity": analysis.integrity(dataset),
        "failed": failed_by_topology(dataset),
        "problems": problems_of(dataset),
    }
    if tab == "table":
        context["running"] = status.get("current") if status.get("state") == "running" else None
        groups = {(g["scenario"], g["variant"]): g for g in analysis.summary(dataset) if g["topology"] == topology}
        context["table"] = [
            {"scenario": s, "cells": [groups.get((s, v.name)) for v in experiment.variants]}
            for s in scenarios
        ]
        context["paired"] = lambda s, variant, metric, baseline: analysis.paired(dataset, topology, s, metric, variant, baseline)
        context["failed_checks"] = lambda: analysis.failed_checks(dataset, topology)  # read only for the checks
        context["primary"] = analysis.primary(dataset) if experiment.primary else None
    if tab in ("charts", "quality"):
        # The chosen scenario, by default the first that has runs.
        done = {k.scenario for k in dataset.keys() if k.topology == topology and dataset.is_done(k)}
        context["scenario"] = scenario if scenario in scenarios else next((s for s in scenarios if s in done), scenarios[0])
    if tab == "runs":
        context["problem_groups"] = problem_groups(context["problems"])
        log = dataset.path / "lab.log"
        lines = log.read_text().splitlines()[-300:] if log.exists() else []
        # "2026-09-30 11:04:08,590 INFO message" as (time, level, message)
        context["log"] = [(m[2], m[3], m[4]) if (m := re.match(r"(\S+) (\S+?)(?:,\d+)? (\w+) (.*)", line)) else ("", "", line)
                          for line in lines]
        # topology -> variant -> scenario -> the state of every run
        metrics = analysis.run_summary(dataset) if any(dataset.is_done(k) for k in dataset.keys()) else {}

        # A run that failed a check or broke a property is failed alike, one whose every failure was foretold allowed.
        broke = defaultdict(list)
        for p in context["problems"]:
            if p["kind"] in ("check", "property"):
                broke[RunKey(p["topology"], p["variant"], p["scenario"], p["run"])].append(p)

        def cell(key: RunKey) -> dict:
            if dataset.is_done(key):
                run = dataset.run(key)
                facts = run_facts(dataset, key, run, metrics.get(str(key), {}))
                found = broke.get(key, [])
                facts["facts"] = [f"{PROPERTIES[p['cause']]}: {p['message']}" for p in found if p["kind"] == "property"] + facts["facts"]
                if run["status"] == "error":
                    state = "error"
                elif run["status"] == "failed" or any(not p.get("predicted") for p in found):
                    state = "failed"
                elif found or facts["allowed"]:
                    state = "allowed"
                else:
                    state = "completed"
                return {"state": state, **facts}
            running = str(key) == status.get("current") and status.get("state") == "running"
            return {"state": "running" if running else "pending"}
        context["grid"] = {t: {v.name: {s: [cell(RunKey(t, v.name, s, i)) for i in range(1, experiment.runs + 1)]
                                        for s in experiment.cases_of(t)} for v in experiment.variants} for t in experiment.topologies}
    if tab == "quality":  # the chosen topology and scenario, as the charts above the table
        context["sampling_rows"] = [r for r in sampling_table(dataset) if (r["topology"], r["scenario"]) == (topology, context["scenario"])]
    if tab == "replay":
        context["scenario"] = scenario if scenario in scenarios else scenarios[0]
        context["runs"] = list(range(1, experiment.runs + 1))
    return context


# Settings of an experiment as people read them.
SETTING_NAMES = {"hold_time": "hold time, s", "keepalive": "keepalive, s", "connect_retry": "connect retry, s", "mrai": "MRAI, s",
                 "graceful_restart": "graceful restart", "interval": "interval, s", "stable_s": "stable after, s",
                 "cpus": "CPUs", "memory_mb": "memory, MiB", "router_limit_mb": "memory per router, MiB"}


def comparison(first: Dataset, second: Dataset, topology: str, metric: str) -> dict:
    """What two results share, how their setup differs, and one metric of both."""
    ea, eb = first.experiment, second.experiment
    topologies = [t for t in ea.topologies if t in eb.topologies]
    scenarios = [s for s in ea.cases() if s in eb.cases()]  # with the values of their sweeps
    shared = [v.name for v in ea.variants if v.name in {w.name for w in eb.variants}]
    topology = topology if topology in topologies else (topologies or [""])[0]
    differences = []

    def differ(label: str, x, y) -> None:
        if isinstance(x, dict) and isinstance(y, dict):  # setting by setting
            for k in dict.fromkeys([*x, *y]):
                differ(f"{label} {SETTING_NAMES.get(k, k.replace('_', ' '))}", x.get(k, "–"), y.get(k, "–"))
        elif x != y:
            differences.append((label, str(x), str(y)))

    va, vb = {v.name: v for v in ea.variants}, {v.name: v for v in eb.variants}
    for v in shared:
        differ(f"{v}: code", first.commits.get(v, "")[:8], second.commits.get(v, "")[:8])
        differ(f"{v}: mode", va[v].summary(), vb[v].summary())
    only = lambda xs, ys: ", ".join(x for x in xs if x not in ys) or "–"
    differ("Variants only in one", only(va, vb), only(vb, va))
    differ("Topologies only in one", only(ea.topologies, eb.topologies), only(eb.topologies, ea.topologies))
    differ("Scenarios only in one", only(ea.cases(), eb.cases()), only(eb.cases(), ea.cases()))
    differ("BGP", ea.bgp.model_dump(), eb.bgp.model_dump())
    differ("Sampling", ea.sampling.model_dump(), eb.sampling.model_dump())
    differ("Runs per combination", ea.runs, eb.runs)
    differ("Seed", ea.seed, eb.seed)
    # The cluster as set, overlaid with what a result recorded of it: older ones record nothing, newer ones CPUs and memory.
    differ("Cluster", {**ea.cluster.model_dump(), **(first.meta.get("cluster") or {})}, {**eb.cluster.model_dump(), **(second.meta.get("cluster") or {})})
    changed = [t for t in topologies if first.topology(t) != second.topology(t)]
    changed += [s for s in scenarios if first.scenario(s) != second.scenario(s)]
    differ("Changed since", "–", ", ".join(changed) or "–")
    groups = [{(g["scenario"], g["variant"]): g for g in analysis.summary(d) if g["topology"] == topology} for d in (first, second)]
    rows = [{"scenario": s, "cells": [[(groups[i].get((s, v)) or {}).get("metrics", {}).get(metric) for i in (0, 1)] for v in shared]}
            for s in scenarios]
    return {"first": first, "second": second, "topologies": topologies, "topology": topology, "variants": shared,
            "rows": rows, "differences": differences, "metric": metric, "digits": ea.digits()}


def run_facts(dataset: Dataset, key: RunKey, run: dict, m: dict) -> dict:
    """Whether a run's routes came to rest, and how exactly it was measured:
    the rate the routers sampled at against the rate set, and how busy the
    host was. None where the run does not tell, e.g. one that ended in an error."""
    if run.get("status") == "error":
        return {"settled": None, "allowed": False, "facts": [run["message"]] if run.get("message") else []}
    if not m:
        return {"settled": None, "allowed": False, "facts": []}
    settled = came_to_rest(m)
    set_hz = 1 / dataset.experiment.sampling_of(key.variant).interval
    # Short lines of label and value, the title already names the state.
    facts = [f"Rest: after {m['settle_s']:g} s"] if settled else []
    if m.get("sample_hz") is not None:
        slowest = (m.get("sample_slowest") or [[None]])[0][0]
        facts.append(f"Sampling: {m['sample_hz']:g} of {set_hz:g} Hz, slowest {m['sample_hz_min']:g}"
                     + (f" ({slowest})" if slowest else "") + f", exact to {2 / m['sample_hz_min']:.2g} s")
    if host := run.get("host"):
        facts.append(f"Host CPU: {100 * host['cpu_mean']:.0f} % mean, {100 * host['cpu_max']:.0f} % peak"
                     + (f", others {100 * host['others_mean']:.0f} %" if "others_mean" in host else ""))
    # Checks the scenario allows this mode to fail, with what went wrong.
    allowed = allowed_failures(run)
    for e in allowed:
        found = problems(e.get("problems", []))
        facts.append(f"Allowed failure at step {e.get('step')}: " + (found[0] if found else "a check")
                     + (f" and {len(found) - 1} more" if len(found) > 1 else ""))
    return {"settled": settled, "allowed": bool(allowed), "facts": facts}


def sampling_table(dataset: Dataset) -> list[dict]:
    """Per topology, scenario and variant, and in it per run: the rate set,
    the rate the median router and the slowest router sampled at, the
    longest gap between two samples of a router, the resolution (two
    intervals of the slowest router), and the load of the host, on average,
    at its peak, how long at its limit, and by others. A group at the limit
    comes first."""
    metrics = analysis.run_summary(dataset)
    done = dataset.statuses()  # one look into the folder, not one per run
    groups = defaultdict(list)
    for k in dataset.keys():
        if k in done and str(k) in metrics:
            groups[k.topology, k.scenario, k.variant].append(k)
    rows = []
    for t, sc in dataset.experiment.combinations():
        for v in dataset.experiment.variants:
            keys = sorted(groups[t, sc, v.name], key=lambda k: k.index)
            if not keys:
                continue
            set_hz = 1 / dataset.experiment.sampling_of(v.name).interval
            runs = []
            for k in keys:
                m, h = metrics[str(k)], dataset.run(k).get("host") or {}
                slowest = (m.get("sample_slowest") or [[None, m.get("sample_hz_min")]])[0]
                runs.append({"index": k.index, "hz": m.get("sample_hz"), "slowest": slowest[1], "slowest_router": slowest[0],
                             "gap": m.get("sample_gap_s"), "cpu_mean": h.get("cpu_mean"), "cpu_max": h.get("cpu_max"),
                             "saturated": h.get("saturated_s"), "others": h.get("others_mean"), "oscillates": m.get("oscillates") == 1,
                             "settle": None if m.get("oscillates") == 1 else m.get("settle_s")})
            pick = lambda f, field, runs=runs: (f(vs) if (vs := [r[field] for r in runs if r[field] is not None]) else None)
            row = {"topology": t, "scenario": sc, "variant": v.name, "set_hz": set_hz, "runs": runs,
                   "hz": pick(median, "hz"), "slowest": pick(min, "slowest"), "gap": pick(max, "gap"),
                   "cpu_mean": pick(median, "cpu_mean"), "cpu_max": pick(max, "cpu_max"), "saturated": pick(max, "saturated"),
                   "others": pick(median, "others"), "oscillates": any(r["oscillates"] for r in runs),
                   "rested": sum(r["settle"] is not None for r in runs)}
            for r in [row, *runs]:
                r["resolution"] = 2 / r["slowest"] if r["slowest"] else None
                # What is at the limit, each on its own: sampling or the host.
                r["slow"] = r["slowest"] is not None and r["slowest"] < set_hz / 2
                r["busy"] = r["cpu_max"] is not None and r["cpu_max"] > analysis.BUSY_HOST
                r["limit"] = r["slow"] or r["busy"]
                r["below"] = r["hz"] is not None and r["hz"] < 0.95 * set_hz  # worth naming the rate set
            rows.append(row)
    return sorted(rows, key=lambda r: not r["limit"])


def failed_by_topology(dataset: Dataset) -> dict[str, int]:
    """The runs that failed a check, per topology, from the cached summary."""
    out = defaultdict(int)
    try:
        for g in analysis.summary(dataset):
            if n := g["statuses"].get("failed", 0):
                out[g["topology"]] += n
    except (OSError, ValueError, KeyError):
        return {}
    return dict(out)


def failed_run_count(dataset: Dataset) -> int:
    """How many runs of a finished result failed a check, from its cached summary."""
    if dataset.status.get("state") != "finished":
        return 0
    try:
        return sum(g["statuses"].get("failed", 0) for g in analysis.summary(dataset))
    except (OSError, ValueError, KeyError):
        return 0


def series_of(dataset: Dataset, topology: str, scenario: str) -> dict:
    """The time series of every variant of a scenario. Reading every sample
    takes seconds for large results, so they are kept until another run of
    the scenario is done."""
    done = tuple(sorted((str(k), (dataset.path / k.path / "run.json").stat().st_mtime)
                        for k in dataset.keys() if k.topology == topology and k.scenario == scenario and dataset.is_done(k)))
    key = (str(dataset.path), topology, scenario, done)
    if (series := SERIES_CACHE.get(key)) is None:
        series = {v.name: analysis.series(dataset, topology, v.name, scenario) for v in dataset.experiment.variants}
        SERIES_CACHE[key] = series
        while len(SERIES_CACHE) > 32:
            SERIES_CACHE.pop(next(iter(SERIES_CACHE)))
    return series


@router.get("/results", response_class=HTMLResponse)
def results(request: Request, show: str = "all", error: str = ""):
    every, older = Dataset.all(), Dataset.older()
    sizes = {d.name: folder_size(d.path) for d in every + older}
    used = {public: sum(sizes[d.name] for d in every + older if d.public == public) for public in (True, False)}
    pick = lambda datasets: [d for d in datasets if show == "all" or d.public == (show == "public")]
    failed = {d.name: failed_run_count(d) for d in every}
    return render(request, "results.html", nav="results", results=pick(every), older=pick(older), show=show, failed=failed,
                  sizes=sizes, storage=storage(used), error=error)





@router.get("/results/compare", response_class=HTMLResponse)
def results_compare(request: Request, a: str, b: str, topology: str = "", metric: str = ""):
    """Two results side by side: what differs in their setup, and every
    metric of the scenarios and variants they share, the first one at first."""
    first, second = find(a), find(b)
    metrics = {k: m for k, m in METRICS.items() if k != "checks"}
    return render(request, "compare.html", nav="results", metrics=metrics,
                  **comparison(first, second, topology, metric if metric in metrics else next(iter(metrics))))


@router.get("/results/{name}", response_class=HTMLResponse)
def result(request: Request, name: str, tab: str = "runs", metric: str = "",
           topology: str = "", scenario: str = "", error: str = ""):
    tab = OLD_TABS.get(tab, tab)
    tab = tab if tab in TABS else "runs"
    dataset = find(name)
    metrics = metrics_of(dataset)
    metric = metric if metric in metrics else next(iter(metrics))
    return render(request, "result.html", nav="results", tab=tab, metric=metric, tabs=TABS, metrics=metrics,
                  error=error, **result_context(dataset, tab, topology, scenario))


@router.get("/results/{name}/partials/header", response_class=HTMLResponse)
def result_header(request: Request, name: str):
    if not (dataset := Dataset.find(name)):
        return gone()
    return still(dataset, render(request, "partials/result-header.html", **result_context(dataset, "")))


@router.get("/results/{name}/partials/{tab}", response_class=HTMLResponse)
def result_partial(request: Request, name: str, tab: str, metric: str = "",
                   topology: str = "", scenario: str = ""):
    tab = OLD_TABS.get(tab, tab)
    if tab not in TABS:
        raise HTTPException(404)
    if not (dataset := Dataset.find(name)):
        return gone()
    metrics = metrics_of(dataset)
    metric = metric if metric in metrics else next(iter(metrics))
    return still(dataset, render(request, f"partials/tab-{tab}.html", tab=tab, metric=metric, metrics=metrics,
                                 **result_context(dataset, tab, topology, scenario)))


@router.get("/results/{name}/replay")
def result_replay(name: str, topology: str, scenario: str, variant: str, run: int = 1):
    dataset = find(name)
    key = RunKey(topology, variant, scenario, run)
    e = dataset.experiment
    if (topology, scenario) not in e.combinations() or variant not in [v.name for v in e.variants]:
        raise HTTPException(404)
    if not dataset.is_done(key) or dataset.run(key)["status"] == "error":
        return JSONResponse({"missing": True})
    t = dataset.topology(topology)
    # The modes of a mixed run mark its OBGP routers; other runs mark none.
    topology = {"routers": t["routers"], "roles": t["roles"], "modes": dataset.run(key).get("modes")}
    return JSONResponse({**analysis.replay(dataset, key), "topology": topology})


@router.get("/results/{name}/summary.csv")
def result_summary_csv(name: str):
    """Every metric of every topology, scenario and variant: median, range and runs."""
    dataset = find(name)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["topology", "scenario", "variant", "runs", "checks_passed", "checks_runs",
                     *[f"{m}_{k}" for m in analysis.METRICS for k in ("median", "min", "max", "n", "ci_low", "ci_high", "ci_level", "router_min", "router_max")]])
    for g in analysis.summary(dataset):
        checks = g.get("checks") or {}
        row = [g["topology"], g["scenario"], g["variant"], g["runs"], checks.get("passed", ""), checks.get("runs", "")]
        for m in analysis.METRICS:
            v = g["metrics"].get(m) or {}
            row += [v.get(k, "") for k in ("median", "min", "max", "n", "ci_low", "ci_high", "ci_level", "router_min", "router_max")]
        writer.writerow(row)
    return download(out.getvalue(), f"{name}-summary.csv", "text/csv")


@router.get("/results/{name}/series.csv")
def result_series_csv(name: str, topology: str, scenario: str):
    """The time series of one scenario, one row per second, variant and metric."""
    dataset = find(name)
    e = dataset.experiment
    if (topology, scenario) not in e.combinations():
        raise HTTPException(404)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["t_s", "variant", "metric", "median", "ci_low", "ci_high", "ci_level", "router_min", "router_max"])
    for v, s in series_of(dataset, topology, scenario).items():
        for m in analysis.SERIES:
            for i, t in enumerate(s["t"]):
                values = [s["metrics"][m][k][i] for k in ("median", "ci_low", "ci_high", "ci_level", "min", "max")]
                if values[0] is not None:
                    writer.writerow([t, v, m, *values])
    return download(out.getvalue(), f"{name}-{topology}-{scenario}-series.csv", "text/csv")


@router.get("/results/{name}/curve")
def result_curve(name: str, topology: str, scenario: str, metric: str):
    dataset = find(name)
    e = dataset.experiment
    if (topology, scenario) not in e.combinations() or metric not in METRICS or metric == "checks" \
            or not (e.sweep_of(scenario) or analysis.size_series(e.topologies)):
        raise HTTPException(404)
    return JSONResponse(analysis.curve(dataset, topology, scenario, metric))


@router.get("/results/{name}/progress")
def result_progress(name: str):
    """How many runs are done, for pages that tell when new ones are."""
    s = find(name).status
    return JSONResponse({"done": s.get("done", 0), "state": s.get("state")})


@router.get("/results/{name}/series")
def result_series(name: str, topology: str, scenario: str):
    """Time series of every variant for the charts, on a common time axis."""
    dataset = find(name)
    experiment = dataset.experiment
    if (topology, scenario) not in experiment.combinations():
        raise HTTPException(404)
    variants = [v.name for v in experiment.variants]
    per_variant = series_of(dataset, topology, scenario)
    t = sorted({x for s in per_variant.values() for x in s["t"]})
    metrics = {m: {} for m in analysis.SERIES}
    for v, s in per_variant.items():
        index = {x: i for i, x in enumerate(s["t"])}
        for m in analysis.SERIES:
            metrics[m][v] = {k: [s["metrics"][m][k][index[x]] if x in index else None for x in t] for k in ("median", "ci_low", "ci_high", "ci_level", "min", "max")}
    # Events per variant: until_stable lets the variants take different times.
    events = {v: s["events"] for v, s in per_variant.items()}
    return JSONResponse({"t": t, "variants": variants, "metrics": metrics, "events": events})


@router.post("/results/{name}/stop")
def stop(request: Request, name: str):
    jobs.stop(find(name).name)
    return RedirectResponse(back(request, f"/results/{name}"), 303)


@router.post("/results/{name}/resume")
def resume(name: str, start_cluster: bool = Form(False)):
    jobs.enqueue(find(name).name)
    problem = wake(start_cluster)
    return RedirectResponse(f"/results/{name}" + (f"?{urlencode({'error': problem})}" if problem else ""), 303)


# Picked results: their names in the query, as the confirmation posts nothing else.
@router.post("/results/delete")
def results_delete(request: Request):
    problems = []
    for name in request.query_params.getlist("names"):
        try:
            find(name).delete()
        except (ValueError, OSError, HTTPException) as error:
            problems.append(f"{name}: {getattr(error, 'detail', error)}")
    return RedirectResponse("/results" + (f"?{urlencode({'error': 'Not deleted: ' + ' '.join(problems)})}" if problems else ""), 303)


@router.post("/results/run-again")
def results_run_again(request: Request):
    problems, started = [], set()
    for name in request.query_params.getlist("names"):
        dataset = Dataset.find(name)
        experiment = dataset.experiment.name if dataset else None
        if experiment in started:  # once for every experiment
            continue
        try:
            if not experiment or not config.path_ok(experiment) or not config.path(experiment).exists():
                raise ValueError("its experiment file is gone")
            start(experiment)
            started.add(experiment)
        except ValueError as error:
            problems.append(f"{name}: {error}")
    return RedirectResponse("/results" + (f"?{urlencode({'error': 'Not started: ' + ' '.join(problems)})}" if problems else ""), 303)


@router.post("/results/{name}/delete")
def result_delete(request: Request, name: str):
    dataset = find(name)
    try:
        dataset.delete()
    except (ValueError, OSError) as error:
        return RedirectResponse(with_error(back(request, f"/results/{name}"), str(error)), 303)
    return RedirectResponse("/results", 303)


@router.post("/results/{name}/visibility")
def visibility(request: Request, name: str, public: bool = Form()):
    dataset = find(name)
    page = back(request, f"/results/{name}?tab=details")
    try:
        dataset.publish(public)
    except (ValueError, FileExistsError) as error:
        text = str(error) if isinstance(error, ValueError) else f"{name} exists in results/{'public' if public else 'private'} already."
        return RedirectResponse(with_error(page, text), 303)
    return RedirectResponse(page, 303)
