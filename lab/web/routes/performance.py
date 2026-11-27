"""The Benchmark area: benchmarks of commits and results with CPU profiles,
read from the results, as the Simulation area reads its searches. The list,
as the other areas have one, and a page per result: the verdict per mode as a
forest plot, the pair of variants compared, their profiles and call tree."""

import math
import re
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ... import analysis, marks
from ...problems import twins_of
from ...results import Dataset
from ..context import render
from .results import known_verdict, measuring, performance

router = APIRouter()

VERDICT_ORDER = ("behaves differently", "slower", "faster, worse elsewhere", "lab drifts", "too few runs",
                 "faster, a guard unmeasured", "slower, within the margin", "no change shown", "faster")


def kind_of(dataset: Dataset) -> str | None:
    """A benchmark, a result with complete profiles, or neither: one whose profiles stop before rest has nothing to show here."""
    e = dataset.experiment
    if e.benchmark:
        return "benchmark"
    if e.sampling.profile_s <= 0:
        return None
    done = [k for k in dataset.keys() if dataset.is_done(k)][:6]
    return "profiled" if any(analysis.profiled_fully(dataset.run(k)) for k in done) else None


def verdicts(dataset: Dataset) -> dict | None:
    """Per mode the verdict of its candidates, the gravest where a mode has several
    cells or candidates; None while the result waits for its metrics."""
    if dataset.status.get("state") != "finished" or not dataset.experiment.speed or analysis.summary_if_known(dataset) is None:
        return None  # a verdict once every run is in, not "too few runs" before the first
    out: dict[str, str] = {}
    for c in (analysis.speed(dataset) or {}).get("cells", []):
        mode = c["baseline"]
        now = out.get(mode)
        out[mode] = c["verdict"] if now is None or VERDICT_ORDER.index(c["verdict"]) < VERDICT_ORDER.index(now) else now
    return out


def forest(cells: list[dict]) -> dict:
    """The rows of the forest plot: shift and interval in percent of the
    baseline's median, the margin and the A/A shift, and the axis that holds them."""
    rows = []
    for c in cells:
        if not c.get("baseline_median") or c.get("shift") is None:
            rows.append({**c, "drawn": False})
            continue
        pct = 100 / c["baseline_median"]
        aa = c.get("aa") or {}
        rows.append({**c, "drawn": True, "s": c["shift"] * pct, "lo": c["low"] * pct, "hi": c["high"] * pct,
                     "m": c["margin"] * pct, "aa_s": aa["shift"] * pct if aa else None})
    drawn = [r for r in rows if r["drawn"]]
    reach = 1.3 * max([abs(x) for r in drawn for x in (r["lo"], r["hi"], r["m"])] + [0.5])
    step = next(s for s in (0.25, 0.5, 1, 2, 5, 10, 20, 50, 100, 1000) if reach / s <= 4)
    edge = step * -(-reach // step)
    return {"rows": rows, "edge": edge, "ticks": [k * step for k in range(-int(edge / step), int(edge / step) + 1)]}


def bottleneck(dataset: Dataset, topology: str, scenario: str, variants: list[str], run: int = 1) -> dict | None:
    """The cores the profiled router used over a run of each variant, the
    limit of its threads, and when the announcement began and ended and the
    routes came to rest: the curves of analysis.cores, side by side."""
    e = dataset.experiment
    found = {v: c for v in variants if (c := analysis.cores(dataset, topology, scenario, v, run))}
    if not found:
        return None
    lines = {v: c["line"] for v, c in found.items()}
    events: dict = {}
    for c in found.values():
        for name, t in c["events"].items():
            events.setdefault(name, t)
    router = list(found.values())[-1]["router"]
    limit = e.bgp.procs or None
    t_max = max(t for pts in lines.values() for t, _ in pts) or 1.0
    top = max([c for pts in lines.values() for _, c in pts] + [limit or 0, 0.5])
    return {"router": router, "lines": lines, "events": {k: x for k, x in events.items() if x is not None},
            "limit": limit, "t_max": t_max, "top": top * 1.1}


FLAME_MIN = 0.008  # a node below this share of the root is left out: too narrow to read
FLAME_DEPTH = 16  # rows below the root, deeper calls stay inside their parent's box


def short_name(fn: str) -> str:
    """A function as people say it: without its module path, package and receiver."""
    import re

    base = fn.rsplit("/", 1)[-1]
    base = base.split(".", 1)[1] if "." in base else base
    return re.sub(r"^\(\*?[\w\[\], ]+\)\.", "", base)


def flame(mine: dict, base: dict | None, focus: list[str], aa: dict | None = None) -> dict | None:
    """The boxes of an icicle of the candidate's call tree, per run, from the
    node focus names down: left and width as shares of that node, the depth,
    and the change against the same path in the baseline's tree. A change
    counts only beyond what the baseline's A/A twin shows on that path, and
    beyond a hundredth of the whole: below, it is timing, not the commit."""
    if not mine.get("tree"):
        return None
    n, m = mine["tree_runs"], (base or {}).get("tree_runs") or 1

    def at(tree: dict | None, path: list[str]) -> dict | None:
        for fn in path:
            tree = (tree or {}).get("c", {}).get(fn)
        return tree
    top, other = at(mine["tree"], focus), at((base or {}).get("tree"), focus) if base else None
    twin_aa = at((aa or {}).get("tree"), focus) if aa and aa.get("tree") else None
    k = (aa or {}).get("tree_runs") or 1
    if top is None:
        return None
    total = top["s"] or 1.0
    boxes, deepest = [], 0

    def walk(node: dict, theirs: dict | None, path: list[str], left: float, depth: int, same: dict | None = None, branch: int = 0) -> None:
        nonlocal deepest
        x = left
        for i, (fn, child) in enumerate(sorted(node["c"].items(), key=lambda kv: -kv[1]["s"])):
            width = child["s"] / total
            if width < FLAME_MIN:
                continue
            strand = i if depth == 1 else branch  # each main branch below the root its own hue, which its calls keep
            twin = (theirs or {}).get("c", {}).get(fn) if theirs is not None else None
            again = (same or {}).get("c", {}).get(fn) if same is not None else None
            s, before = child["s"] / n, (twin["s"] / m if twin else 0.0)
            noise = abs(again["s"] / k - before) if again is not None else 0.0
            shown = base and before and abs(s - before) > max(noise, 0.01 * total / n)
            change = (s - before) / before if shown else (0.0 if base and before else None)
            new = bool(base) and not before and s > 0.01 * total / n
            boxes.append({"name": fn, "short": short_name(fn), "left": x, "width": width, "depth": depth, "s": s, "branch": strand,
                          "before": before if base else None, "change": change, "new": new, "path": [*path, fn]})
            deepest = max(deepest, depth)
            if depth < FLAME_DEPTH:
                walk(child, twin, [*path, fn], x, depth + 1, again, strand)
            x += width
    walk(top, other, list(focus), 0.0, 1, twin_aa)
    # The root as a bar of its own across: what every width below is a share of.
    root = {"name": focus[-1] if focus else "", "short": short_name(focus[-1]) if focus else "whole tree", "left": 0.0, "width": 1.0,
            "depth": 0, "s": total / n, "before": None, "change": None, "new": False, "path": list(focus), "root": True}
    return {"boxes": [root, *boxes], "depth": deepest + 1, "focus": focus, "total": total / n}


@router.get("/performance")
def old_address(request: Request):
    """The area's former address."""
    return RedirectResponse(f"/benchmark?{request.url.query}" if request.url.query else "/benchmark", status_code=301)


def answer(cells: list[dict], benchmark) -> str:
    """The page's answer in one sentence: the verdicts and in how many modes."""
    if not cells:
        return ""
    counts: dict[str, int] = {}
    for c in cells:
        counts[c["verdict"]] = counts.get(c["verdict"], 0) + 1
    parts = [f"{v} in {n} mode{'s' if n != 1 else ''}" for v, n in sorted(counts.items(), key=lambda x: VERDICT_ORDER.index(x[0]))]
    text = ", ".join(parts)  # the title above names the commits
    return text[:1].upper() + text[1:] + "."


def chosen(dataset: Dataset, topology: str, scenario: str, mode: str = "", reference: str = "", compare: str = "") -> dict:
    """The topology and scenario shown, the speed rule's cells there, and the
    pair everything below the overview is about: a reference and a variant
    compared with it, any two of the result. By default the baseline commit
    and the candidate of the first mode of a benchmark, else bgp, or the
    first variant, and the variant with the most CPU. mode, of former links,
    names the mode whose baseline and candidate to take."""
    e = dataset.experiment
    topology = topology if topology in e.topologies else e.topologies[0]
    scenarios = e.cases_of(topology)
    scenario = scenario if scenario in scenarios else scenarios[0]
    speed = analysis.speed(dataset) if e.speed else None
    cells = [c for c in (speed or {}).get("cells", []) if (c["topology"], c["scenario"]) == (topology, scenario)]
    names = [v.name for v in e.variants if not v.records]
    if mode and not (reference or compare):
        cell = next((c for c in cells if c["baseline"] == mode), None)
        reference, compare = (cell["baseline"], cell["variant"]) if cell else ("", mode)
    if reference not in names:
        reference = cells[0]["baseline"] if cells else "bgp" if "bgp" in names else names[0]
    if compare not in names or compare == reference:
        cell = next((c for c in cells if c["baseline"] == reference), None)
        if cell:
            compare = cell["variant"]
        else:
            groups = {g["variant"]: g for g in analysis.summary(dataset) if (g["topology"], g["scenario"]) == (topology, scenario)}
            cpu = lambda v: (((groups.get(v) or {}).get("metrics") or {}).get("prof_s") or {}).get("median") or 0.0
            others = [v for v in names if v != reference]
            compare = max(others, key=cpu) if others else reference
    twin = twins_of(e).get(compare)
    aa = twin[1] if twin and twin[0] == reference else None  # the noise band only against its own baseline
    return {"topology": topology, "scenario": scenario, "speed": speed, "cells": cells, "names": names,
            "reference": reference, "compare": compare, "aa": aa, "variant": compare}


MACRO = [  # the parts of lab/profile.py in five shares of the whole, each in a hue of its own
    ("routing", "Routing work", ("policy", "export", "decision", "tables", "obgp", "rib")),
    ("io", "Sending and receiving", ("send", "receive")),
    ("gc", "Garbage collector", ("gc",)),
    ("api", "API, read by the lab", ("api",)),
    ("other", "Other", ("other",)),
]
MACRO_METRICS = [("cpu_s_mean", "CPU"), ("settle_s", "Settle"), ("rss_mean", "Memory"), ("updates_prefix_max", "Updates")]


def pct(pr: dict | None) -> float | None:
    """A paired change in % of the baseline: the Hodges-Lehmann shift, as the verdict, else the median of the ratios."""
    pr = pr or {}
    return pr.get("shift_pct", pr.get("change"))


def short_ref(ref: str) -> str:
    """A commit as its first eight hex digits, any other ref as it is."""
    return ref[:8] if re.fullmatch(r"[0-9a-f]{9,40}", ref) else ref


def overview(dataset: Dataset, topology: str, scenario: str, cells: list[dict]) -> dict:
    """Over the whole workload, every mode at once: the shares of the CPU of
    the profiled routers in five parts, its seconds, and for a benchmark the
    change of the candidate against the baseline in the macro metrics."""
    e = dataset.experiment
    groups = {g["variant"]: g for g in analysis.summary(dataset) if (g["topology"], g["scenario"]) == (topology, scenario)}

    def bar(v: str) -> dict | None:
        m = (groups.get(v) or {}).get("metrics") or {}
        whole = (m.get("prof_s") or {}).get("median")
        if not whole:
            return None
        shares = [{"key": k, "label": label, "s": sum((m.get(f"prof_{b}_s") or {}).get("median") or 0.0 for b in parts)}
                  for k, label, parts in MACRO]
        return {"variant": v, "seconds": whole, "shares": [{**x, "pct": 100 * x["s"] / whole} for x in shares]}

    rule = e.speed

    def change(metric: str, c: dict, margin: float) -> dict:
        """The candidate's paired change in % of the baseline, beyond only past
        the margin and what the A/A twin changes by itself."""
        pr = analysis.paired(dataset, topology, scenario, metric, c["variant"], c["baseline"])
        aa = (c.get("aa") or {}).get("variant")
        noise = abs(pct(analysis.paired(dataset, topology, scenario, metric, aa, c["baseline"]) if aa else None) or 0.0)
        beyond = bool(pr and pr.get("shift_low") is not None and (pr["shift_low"] > 0 or pr["shift_high"] < 0)
                      and pct(pr) is not None and abs(pct(pr)) > max(noise, margin))
        return {"change": pct(pr), "beyond": beyond, "n": (pr or {}).get("n")}

    # A benchmark: per mode the baseline commit and its candidate, one above the other, the candidate
    # with its change of the profiled CPU, judged by the margin of the rule's CPU. Else every variant once.
    pairs = []
    for c in cells:
        base, cand = bar(c["baseline"]), bar(c["variant"])
        if cand:
            cand |= change("prof_s", c, rule.margin_pct if rule else 0.0)
        pairs.append((c["baseline"], [base, cand]))
    if not cells:
        pairs = [(v.name, [bar(v.name)]) for v in e.variants if not v.records]
    modes = [{"mode": mode, "bars": [b for b in bs if b]} for mode, bs in pairs if any(bs)]
    bars = [b for x in modes for b in x["bars"]]
    changes = []
    for c in cells:
        # The guards' margin for the other metrics.
        changes.append({"mode": c["baseline"], "variant": c["variant"], "cells": [
            {"metric": metric, "label": label, **change(metric, c, (rule.margin_pct if metric == rule.metric else rule.guard_pct) if rule else 0.0)}
            for metric, label in MACRO_METRICS]})
    return {"bars": bars, "modes": modes, "pair": bool(cells), "longest": max([b["seconds"] for b in bars] + [1.0]), "changes": changes}


RADAR = [("cpu_s_mean", "CPU"), ("cpu_cores_max", "Peak cores"), ("settle_s", "Settle"), ("rss_mean", "Memory"),
         ("prof_gc_s", "GC"), ("updates_prefix_max", "Updates")]
RADAR_SPANS = (0.25, 0.5, 1.0, 2.0)  # log2 of the ratio at the rim, the smallest that holds every shape of a result


def radar_radius(ratio: float, span: float) -> float:
    """Where a ratio to the reference lies between the centre (0) and the rim (1), the reference at 0.5."""
    return min(1.0, max(0.0, 0.5 + math.log2(max(ratio, 1e-9)) / (2 * span)))


def ring_label(ratio: float) -> str:
    if 0.75 < ratio < 1.5:
        return f"{100 * (ratio - 1):+.0f} %".replace("-", "−")
    return f"{ratio:g}×".replace("0.5×", "½×").replace("0.25×", "¼×")


def radar(dataset: Dataset, topology: str, scenario: str, reference: str, compare: str, aa: str | None) -> dict | None:
    """The compared variant as a shape on six axes, each the ratio of a
    metric to the reference on one logarithmic scale, paired by seed, with
    what the A/A twin of the reference changes by itself as a band."""
    if compare == reference:
        return None
    n = len(RADAR)
    angle = lambda i: math.pi * (2 * i / n - 0.5)
    at = lambda i, r: (round(50 + 40 * r * math.cos(angle(i)), 2), round(50 + 40 * r * math.sin(angle(i)), 2))
    axes = []
    for metric, label in RADAR:
        pr = analysis.paired(dataset, topology, scenario, metric, compare, reference) or {}
        change = pct(pr)
        noise = abs(pct(analysis.paired(dataset, topology, scenario, metric, aa, reference) if aa else None) or 0.0)
        ratio = 1 + change / 100 if change is not None and change > -100 else None
        axes.append({"label": label, "change": change, "noise": noise, "n": pr.get("n"), "ratio": ratio,
                     "low": pr.get("shift_low"), "high": pr.get("shift_high")})
    if sum(a["ratio"] is not None for a in axes) < 3:
        return None
    # The smallest span that holds the shape and its band, the rest marked at the rim.
    widest = max([abs(math.log2(a["ratio"])) for a in axes if a["ratio"]] + [math.log2(1 + a["noise"] / 100) for a in axes])
    span = next((x for x in RADAR_SPANS if widest <= x), RADAR_SPANS[-1])
    for i, a in enumerate(axes):
        a["point"] = at(i, radar_radius(a["ratio"], span)) if a["ratio"] else None
        a["clipped"] = bool(a["ratio"]) and abs(math.log2(a["ratio"])) > span
    band = None
    if aa:
        band = {"outer": [at(i, radar_radius(1 + a["noise"] / 100, span)) for i, a in enumerate(axes)],
                "inner": [at(i, radar_radius(max(0.01, 1 - a["noise"] / 100), span)) for i, a in enumerate(axes)]}
    return {"axes": axes, "points": [a["point"] for a in axes if a["point"]], "band": band,
            "rings": [{"ratio": x, "r": round(40 * radar_radius(x, span), 2), "label": ring_label(x)} for x in (2 ** (-span / 2), 1.0, 2 ** (span / 2))],
            "spokes": [{"label": label, "end": at(i, 1.0), "text": at(i, 1.2)} for i, (_, label) in enumerate(RADAR)]}


def listed() -> list[dict]:
    """The benchmarks and profiled results, starred first, each part in its order, as in the list of results."""
    items = []
    for d in Dataset.all():
        if (kind := kind_of(d)) is None:
            continue
        b = d.experiment.benchmark
        found = verdicts(d) if kind == "benchmark" else None
        # Per verdict the modes that got it, the most serious first, as the page orders them.
        counts = {}
        for mode, v in sorted((found or {}).items()):
            counts.setdefault(v, []).append(mode)
        items.append({"dataset": d, "kind": kind, "verdicts": found,
                      "verdict_counts": sorted(counts.items(), key=lambda x: VERDICT_ORDER.index(x[0])),
                      "title": f"{', '.join(b.candidates)} against {b.baseline}" if b else d.experiment.name})
    starred = marks.starred("result")
    return sorted(items, key=lambda i: i["dataset"].name not in starred)


@router.get("/benchmark", response_class=HTMLResponse)
def area(request: Request, show: str = "all", result: str = ""):
    """The list, as the other areas have it: search, a choice of the kind, stars. Each one opens a page of its own."""
    if result:  # the address of one before it had a page of its own
        query = "&".join(f"{k}={quote(v)}" for k, v in request.query_params.items() if k != "result")
        return RedirectResponse(f"/benchmark/{quote(result)}" + (f"?{query}" if query else ""), status_code=301)
    show = show if show in ("all", "benchmark", "profiled") else "all"
    items = [i for i in listed() if show in ("all", i["kind"])]
    shown = [i["dataset"] for i in items]
    # Their state as in the list of results: the same word for the same result.
    return render(request, "benchmarks.html", nav="benchmark", items=items, show=show, starred=marks.starred("result"),
                  verdicts={d.name: known_verdict(d) for d in shown},
                  analysing={d.name for d in shown if str(d.path) in analysis.PROGRESS})


@router.get("/benchmark/{name}", response_class=HTMLResponse)
def page(request: Request, name: str, mode: str = "", reference: str = "", compare: str = "", topology: str = "",
         scenario: str = "", focus: str = ""):
    """Quick: the answer, the shares of the CPU, the verdict and the pair. Its profiles load after, see details."""
    d = Dataset.find(name)
    if d is None or (kind := kind_of(d)) is None:
        raise HTTPException(404, f"No benchmark or profiled result {name}.")
    b = d.experiment.benchmark
    shown = {"dataset": d, "kind": kind, "title": f"{', '.join(b.candidates)} against {b.baseline}" if b else d.experiment.name}
    ctx = {"nav": "benchmark", "shown": shown, "focus": focus, "starred": marks.starred("result")}
    if measuring(d):
        return render(request, "benchmark.html", **ctx, analysing=analysis.PROGRESS.get(str(d.path)))
    c = chosen(d, topology, scenario, mode, reference, compare)
    ctx |= c | {"plot": forest(c["cells"]), "answer": answer(c["cells"], b),
                 "overview": overview(d, c["topology"], c["scenario"], c["cells"]), "macro": MACRO,
                 "radar": radar(d, c["topology"], c["scenario"], c["reference"], c["compare"], c["aa"]), "macro_metrics": MACRO_METRICS,
                 "refs": {v.name: short_ref(v.ref) for v in d.experiment.variants}}
    # Something to compare yet: shares of the CPU, a verdict drawn or a pair with runs of both.
    ctx["ready"] = bool(ctx["overview"]["bars"] or any(r["drawn"] for r in ctx["plot"]["rows"]) or ctx["radar"])
    return render(request, "benchmark.html", **ctx)


@router.get("/benchmark/{result}/details", response_class=HTMLResponse)
def details(request: Request, result: str, mode: str = "", reference: str = "", compare: str = "", topology: str = "",
            scenario: str = "", focus: str = ""):
    """The profiles of the chosen mode, read once each: cores used, where the CPU goes, the long runners and the call tree."""
    d = Dataset.find(result)
    if d is None or kind_of(d) is None:
        raise HTTPException(404, f"No benchmark or profiled result {result}.")
    c = chosen(d, topology, scenario, mode, reference, compare)
    perf = performance(d, c["topology"], c["scenario"], c["compare"], c["reference"])
    twin = analysis.profile_cell(d, c["topology"], c["scenario"], c["aa"]) if c["aa"] else None
    mine, base = perf["mine"], perf["base"]
    whole = mine.get("seconds") or 0.0
    # Long runners by their own time, the change of that own time, shown only beyond the A/A twin and a hundredth of the whole.
    for h in perf["hotspots"]:
        h["short_name"] = short_name(h["name"])
        if base and base.get("flat") is not None:
            h["change"] = h["flat"] - base["flat"].get(h["name"], 0.0)
            noise = abs(twin["flat"].get(h["name"], 0.0) - base["flat"].get(h["name"], 0.0)) if twin and twin.get("flat") else 0.0
            h["shown"] = abs(h["change"]) > max(noise, 0.01 * whole)
    return render(request, "partials/benchmark-details.html", result=d, experiment=d.experiment, perf=perf, **c,
                  busy=bottleneck(d, c["topology"], c["scenario"], [x for x in (perf["against"], perf["variant"]) if x]),
                  flame=flame(mine, base, [f for f in focus.split(";") if f], twin), focus=focus,
                  groups={g["variant"]: g for g in analysis.summary(d) if (g["topology"], g["scenario"]) == (c["topology"], c["scenario"])})
