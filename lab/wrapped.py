"""An overview of what the lab has measured, plainly: did the routes come to
rest, did the runs run right, how fast they converged per scenario, and
what OBGP costs against BGP.

Only results of the current lab count, those that record an image per run,
with update counters and the real sampling rate; older ones measured less
and otherwise. Experiments that check the lab, not OBGP, are left out.
Every mode stands for itself, compared with BGP of the same results:
pooling OBGP with OBGP without pruning, or partial deployments, would
blur what each does.
"""

from collections import defaultdict
from statistics import median

from . import analysis, cluster, modes, scenario
from .results import Dataset, RunKey

ORDER = ["bgp", "obgp", "obgp-np", "hybrid", "hybrid-np", "random", "random-np"]
# Experiments of the lab itself check the measurements, not OBGP.
LAB = "lab-"

_kept: tuple | None = None


def current(dataset: Dataset) -> bool:
    """Whether the current lab made a result: its runs record their image."""
    key = next((k for k in dataset.keys() if dataset.is_done(k)), None)
    return key is not None and "image" in dataset.run(key)


def overview() -> dict:
    """The overview, kept until a result changes."""
    global _kept
    datasets = [d for d in Dataset.all() if not d.experiment.name.startswith(LAB) and current(d)]
    stamp = (analysis.VERSION, tuple((d.name, *(_mtime(d.path / f) for f in ("status.json", "analysis.json"))) for d in datasets))
    if _kept and _kept[0] == stamp:
        return _kept[1]
    out = _overview(datasets)
    _kept = (stamp, out)
    return out


def _mtime(path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _overview(datasets: list[Dataset]) -> dict:
    runs = []
    groups = []
    for d in datasets:
        variants = {v.name: v.mode for v in d.experiment.variants}
        metrics = analysis.run_summary(d)
        for key in d.keys():
            if not d.is_done(key):
                continue
            run = d.run(key)
            expected = [e["expected"] for e in run["events"] if e.get("expected") is not None]
            runs.append({"mode": variants[key.variant], "status": run["status"], "metrics": metrics.get(str(key), {}),
                         "seconds": run.get("duration_s") or 0, "empty": bool(expected) and expected[-1] == 0,
                         "routers": len(run.get("watched") or []), "topology": key.topology, "scenario": key.scenario,
                         "result": d.name, "key": key})
        groups += [(d, g, variants[g["variant"]]) for g in analysis.summary(d) if g["runs"]]
    present = [m for m in ORDER if any(r["mode"] == m for r in runs)]
    return {
        "results": [d.name for d in datasets],
        "since": min((d.meta["created"][:10] for d in datasets), default=None),
        "until": max((d.meta["created"][:10] for d in datasets), default=None),
        "daemons": len({_daemon(c) for d in datasets for c in d.commits.values()}),
        "runs": len(runs),
        "hours": sum(r["seconds"] for r in runs) / 3600,
        "routers": sum(r["routers"] for r in runs),
        "topologies": len({r["topology"] for r in runs}),
        "scenarios": len({r["scenario"] for r in runs}),
        "labels": {m: modes.get(m).label for m in present},
        "rest": _rest(runs, present),
        "oscillation": _oscillation(runs, present),
        "checks": _checks(groups),
        "cost": _cost(groups),
        "outcomes": _outcomes(runs, groups, present),
        "convergence": _convergence(groups, present),
        "resources": _resources(groups, present),
    }


_daemons: dict[str, str] = {}


def _daemon(commit: str) -> str:
    """The version of the daemon at a commit: the tree of its sources, so
    that commits that changed only the lab count as one."""
    if commit not in _daemons:
        try:
            _daemons[commit] = cluster.git("ls-tree", commit, "--", *cluster.DAEMON_SOURCES)
        except Exception:  # e.g. a commit not in this clone
            _daemons[commit] = commit
    return _daemons[commit]


def _rest(runs: list[dict], present: list[str]) -> list[dict]:
    """Per mode: of the runs that end with prefixes and rest long enough to
    tell, how many still changed at the end, and how long they rested."""
    out = []
    for m in present:
        held = [r for r in runs if r["mode"] == m and not r["empty"] and r["metrics"].get("oscillates") is not None]
        if held:
            rests = [r["metrics"]["rest_s"] for r in held if r["metrics"].get("rest_s")]
            out.append({"mode": m, "runs": len(held), "oscillated": sum(r["metrics"]["oscillates"] for r in held),
                        "rest_s": median(rests) if rests else None})
    return out


def _outcomes(runs: list[dict], groups: list, present: list[str]) -> list[dict]:
    """Per mode: how the runs ended, and how many passed every check."""
    out = []
    for m in present:
        mine = [r for r in runs if r["mode"] == m]
        checks = [g["checks"] for _, g, mode in groups if mode == m and g.get("checks")]
        out.append({"mode": m, "runs": len(mine), "statuses": [r["status"] for r in mine],
                    **{s: sum(r["status"] == s for r in mine) for s in ("completed", "timeout", "failed", "error")},
                    "checked": sum(c["runs"] for c in checks), "passed": sum(c["passed"] for c in checks)})
    return out


def _convergence(groups: list, present: list[str]) -> dict:
    """Per result, topology and scenario where convergence is measured: the
    median of each mode over its runs that converged, and how many did."""
    rows = defaultdict(dict)
    for d, g, mode in groups:
        if not g.get("measurable"):
            continue
        c = g["metrics"].get("convergence_s")
        rows[(d.name, g["topology"], g["scenario"])][mode] = {
            "median": c["median"] if c else None, "n": c["n"] if c else 0, "runs": g["runs"],
            "resolution": 2 * d.experiment.sampling.interval}
    columns = [m for m in present if any(m in cells for cells in rows.values())]
    return {"columns": columns, "rows": [{"result": r, "topology": t, "scenario": s, "cells": cells}
                                          for (r, t, s), cells in sorted(rows.items(), key=lambda x: (x[0][1], x[0][2], x[0][0]))]}


def _resources(groups: list, present: list[str]) -> list[dict]:
    """Per mode against BGP of the same result, topology and scenario: the
    median change of memory, heap and CPU time over the scenarios."""
    base = {(d.name, g["topology"], g["scenario"]): g["metrics"] for d, g, mode in groups if mode == "bgp"}
    out = []
    for m in present:
        if m == "bgp":
            continue
        row = {"mode": m}
        for metric, what in (("rss_mean", "memory"), ("heap_mean", "heap"), ("cpu_s_mean", "cpu")):
            changes = []
            for d, g, mode in groups:
                b = base.get((d.name, g["topology"], g["scenario"]), {}).get(metric)
                v = g["metrics"].get(metric)
                if mode == m and v and b and b["median"]:
                    changes.append(100 * (v["median"] - b["median"]) / b["median"])
            row[what] = {"median": median(changes), "low": min(changes), "high": max(changes), "n": len(changes)} if changes else None
        if any(row[w] for w in ("memory", "heap", "cpu")):
            out.append(row)
    return out


def replay(result: str, key: RunKey) -> str:
    return (f"/results/{result}?tab=replay&topology={key.topology}&scenario={key.scenario}"
            f"&variant={key.variant}&run={key.index}")


def _oscillation(runs: list[dict], present: list[str]) -> dict:
    """How often OBGP as designed and BGP oscillated, the other modes apart,
    and a run of BGP that did, with its OBGP twin, to watch."""
    rest = {r["mode"]: r for r in _rest(runs, present)}
    held = [r for r in runs if not r["empty"] and r["metrics"].get("oscillates") is not None]
    out = {"obgp": rest.get("obgp", {}).get("oscillated", 0), "obgp_runs": rest.get("obgp", {}).get("runs", 0),
           "bgp": rest.get("bgp", {}).get("oscillated", 0), "bgp_runs": rest.get("bgp", {}).get("runs", 0),
           "others": [{**r, "label": modes.get(m).label} for m, r in rest.items() if m not in ("obgp", "bgp")],
           "rest_s": median([r["rest_s"] for m, r in rest.items() if m in ("obgp", "bgp") and r["rest_s"]] or [0]) or None}
    if flapping := [r for r in held if r["mode"] == "bgp" and r["metrics"]["oscillates"]]:
        r = max(flapping, key=lambda r: r["routers"])
        twin = next((o for o in held if o["mode"] == "obgp" and o["result"] == r["result"] and o["topology"] == r["topology"]
                     and o["scenario"] == r["scenario"] and o["key"].index == r["key"].index), None)
        out["example"] = {"bgp": replay(r["result"], r["key"]), "obgp": twin and replay(twin["result"], twin["key"])}
    return out


def _checks(groups: list) -> dict:
    """Runs that passed every check, of all modes, and of the others how
    many ran scenarios that leave the model on purpose."""
    with_checks = [(d, g) for d, g, _ in groups if g.get("checks")]
    outside = sum(g["checks"]["runs"] - g["checks"]["passed"] for d, g in with_checks
                  if any(step.kind == "set_export" for step in scenario.each_step(d.scenario(g["scenario"]).steps)))
    return {"passed": sum(g["checks"]["passed"] for _, g in with_checks),
            "runs": sum(g["checks"]["runs"] for _, g in with_checks), "outside": outside}


def _cost(groups: list) -> list[dict]:
    """Memory, heap and CPU of OBGP as designed against BGP: the median
    change over the scenarios, its range, and whether within 5 %."""
    row = next((r for r in _resources(groups, ["obgp"]) if r["mode"] == "obgp"), None)
    if not row:
        return []
    return [{"what": what, **row[key], "same": abs(row[key]["median"]) < 5}
            for key, what in (("memory", "Memory"), ("heap", "Heap"), ("cpu", "CPU time")) if row[key]]
