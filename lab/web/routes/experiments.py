"""Experiments: the list, the builder and starting them."""

import re
from html import escape
from urllib.parse import urlencode

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import ValidationError

from ... import (
    cluster,
    config,
    estimate,
    scenario,
    topology,
    wrapped,
)
from ...config import Experiment, Variant
from ...modes import MODES
from ...results import Dataset
from .. import groups
from ..common import duration, jobs
from ..context import (
    check_rename,
    experiments,
    own_group,
    readable_topologies,
    render,
    step_kinds,
    thumb_stamps,
    topology_summary,
)

router = APIRouter()




def start(name: str) -> str:
    """Queues a new result of an experiment, as its file is now, and returns its name; ValueError if it cannot."""
    try:
        e = Experiment.load(config.path(name))
    except FileNotFoundError as error:
        raise ValueError(str(error)) from None
    if problem := cluster.too_large(e):
        raise ValueError(f"Not started: {problem}.")
    result = Dataset.new_name(e)
    Dataset.create(e, result)
    jobs.enqueue(result)
    return result


def read_experiment(name: str) -> tuple[Experiment | None, str]:
    """An experiment file, also when its topologies or scenarios are missing: (experiment, problem)."""
    try:
        return Experiment.load(config.path(name)), ""  # checked, and kept so
    except (ValueError, OSError):
        pass
    try:
        data = config.load_yaml(config.path(name).read_text())
        e = Experiment.model_validate(data)
    except (ValueError, OSError, ValidationError):
        return None, f"No experiment {name}."
    try:
        e.check_files()
    except ValueError as error:
        return e, str(error)
    return e, ""


# Run all queues the checks of the lab first, smoke and calibration before the others.
ALL_FIRST = ["lab-smoke", "lab-calibration"]


RUN_ALL = {"all": "Everything", "experiments": "Experiments only", "lab": "Lab checks only"}


def run_all(listed: list[dict], which: str = "all") -> tuple[list[dict], list[tuple[str, str]]]:
    """The experiments Run all queues, in order, and what it leaves out, with why:
    whole experiments, and topologies larger than this host."""
    chosen, left = [], []
    for x in listed:
        lab = x["name"].startswith(wrapped.LAB)
        if (which == "lab" and not lab) or (which == "experiments" and lab):
            continue
        if "error" in x:
            left.append((x["name"], "does not load"))
        else:
            skips = cluster.oversized(x["experiment"])
            whole = len(skips) == len(x["experiment"].topologies)
            if not whole:
                chosen.append(x)
            for t, why in skips.items():
                left.append((x["name"] if whole and len(skips) == 1 else f"{x['name']} / {t}",
                             f"needs {', '.join(why)} (host: up to {cluster.limit(x['experiment']).removeprefix('at most ')})"))
    first = {n: i for i, n in enumerate(ALL_FIRST)}
    return sorted(chosen, key=lambda x: (not x["name"].startswith(wrapped.LAB), first.get(x["name"], len(first)), x["name"])), left


def git_refs() -> list[str]:
    try:
        out = cluster.git("for-each-ref", "--format=%(refname:short)", "refs/heads", "refs/tags")
    except Exception:
        return []
    return ["HEAD", *out.split()]


def builder_context() -> dict:
    loaded = readable_topologies()[0]
    scenarios = []
    for n in scenario.names():
        try:
            sc = scenario.load(n)
        except (ValueError, OSError):
            continue
        scenarios.append({"name": n, "duration_s": sc.duration(), "description": sc.description, "kinds": step_kinds(sc.steps), "params": sc.params})
    return {
        "topologies": [{"name": n, **topology_summary(t)} for n, t in loaded.items()],
        "thumbs": thumb_stamps(loaded),
        "scenarios": scenarios,
        "refs": git_refs(),
        "modes": list(MODES.values()),
        "intervals": [1.0, 0.5, 0.2, 0.1, 0.05],
        # The numbers a sweep can set, by kind of step.
        # The parameters each scenario offers for sweeps, with the values it gives them.
        "params": {x["name"]: x["params"] for x in scenarios if x["params"]},
    }


def builder_values(e: Experiment | None, original: str = "") -> dict:
    """The fields of the experiment builder; original is the file it edits."""
    e = e or Experiment(name="", variants=[Variant(name="bgp", mode="bgp"), Variant(name="obgp-rp", mode="obgp-rp")],
                        topologies=["bad-gadget"], scenarios=["full-drain-60"])
    return {
        "original": original,
        "name": e.name, "description": e.description, "runs": e.runs, "seed": e.seed,
        "variants": [v.model_dump() for v in e.variants],
        "topologies": e.topologies, "scenarios": e.scenarios, "paired": e.paired,
        "cpus": e.cluster.cpus, "memory_mb": e.cluster.memory_mb, "router_limit_mb": e.cluster.router_limit_mb,
        "hold_time": e.bgp.hold_time, "keepalive": e.bgp.keepalive, "connect_retry": e.bgp.connect_retry, "mrai": e.bgp.mrai, "refresh": e.bgp.refresh,
        "graceful_restart": e.bgp.graceful_restart,
        "interval": e.sampling.interval, "stable_s": e.sampling.stable_s, "error": "",
        "sweeps": [{"scenario": w.scenario, "param": w.param, "values": ", ".join(f"{v:g}" for v in w.values)} for w in e.sweeps],
    }


def _variants(form) -> list[dict]:
    rows = sorted({int(k[1:].split("_")[0]) for k in form.keys() if re.fullmatch(r"v\d+_name", k)})
    return [{"name": str(form.get(f"v{i}_name", "")).strip(), "ref": str(form.get(f"v{i}_ref", "")).strip() or "HEAD",
             "mode": (mode := str(form.get(f"v{i}_mode", ""))),
             "share": float(form.get(f"v{i}_share") or 0) / 100 if MODES.get(mode) and MODES[mode].pick == "random" else None,
             "interval": float(form.get(f"v{i}_interval") or 0) or None,
             "refresh_delay": float(form.get(f"v{i}_refresh_delay") or 0) or None}
            for i in rows if str(form.get(f"v{i}_name", "")).strip()]


def _sweeps(form) -> list[dict]:
    """The sweeps of the builder form, a row each, those without a scenario left out."""
    rows = sorted({int(k[1:].split("_")[0]) for k in form.keys() if re.fullmatch(r"s\d+_scenario", k)})
    out = []
    for i in rows:
        if not (name := str(form.get(f"s{i}_scenario", ""))):
            continue
        raw = str(form.get(f"s{i}_values", "")).replace(" ", "")
        try:  # by commas, or by semicolons for decimal commas: 0,5; 1
            values = [float(v.replace(",", ".")) for v in (raw.split(";") if ";" in raw else raw.split(",")) if v]
        except ValueError:
            raise ValueError(f"Sweep of {name}: values are numbers, separated by commas.") from None
        out.append({"scenario": name, "param": str(form.get(f"s{i}_param", "")), "values": values})
    return out


def parse_builder(form) -> Experiment:
    """The experiment of the builder form; ValueError with a readable message if it is invalid."""
    name = str(form.get("name", "")).strip()
    number = lambda key, kind=int: kind(str(form.get(key) or 0).replace(",", "."))
    try:
        e = Experiment(
            name=name, description=str(form.get("description", "")).strip(), runs=number("runs"), seed=number("seed"),
            variants=_variants(form), topologies=form.getlist("topologies"), scenarios=form.getlist("scenarios"),
            paired=form.get("paired") == "on",
            cluster={"cpus": number("cpus"), "memory_mb": number("memory_mb"),
                     **({"router_limit_mb": number("router_limit_mb")} if form.get("router_limit_mb") else {})},
            bgp={"hold_time": number("hold_time"), "keepalive": number("keepalive"), "connect_retry": number("connect_retry"), "mrai": number("mrai", float), **({"refresh": number("refresh", float)} if form.get("refresh") else {}),
                 "graceful_restart": form.get("graceful_restart") == "on"},
            sampling={"interval": number("interval", float), "stable_s": number("stable_s", float)},
            sweeps=_sweeps(form),
        )
        e.check_files()
    except ValidationError as error:
        first = error.errors()[0]
        field = ".".join(str(x) for x in first["loc"]) or "experiment"
        if first["loc"][:1] == ("sweeps",) and len(first["loc"]) > 1:
            name = _sweeps(form)[first["loc"][1]]["scenario"]
            if first["type"] == "too_short":
                raise ValueError(f"Give the sweep of {name} at least two values.") from None
            raise ValueError(f"Sweep of {name}: {first['msg'].removeprefix('Value error, ')}.") from None
        if first["type"] == "too_short":
            raise ValueError(f"Pick at least one of the {field}.") from None
        raise ValueError(f"{field}: {first['msg'].removeprefix('Value error, ')}") from None
    return e


def host_notes(e: Experiment) -> str:
    """For the builder, as on a result: the topologies this host leaves out, and why."""
    skips = cluster.oversized(e)
    if not skips:
        return '<ul id="host-notes" hx-swap-oob="true" class="hidden"></ul>'
    limit = cluster.limit(e).removeprefix("at most ").replace(", ", " and ")
    lines = [f"{t} needs {' and '.join(why)}." for t, why in skips.items()]
    whole = len(skips) == len(e.topologies)
    lines.append(f"This host runs at most {limit}, " + ("so the experiment cannot start here." if whole else "so the experiment runs without them."))
    items = "".join(f"<li>{escape(line)}</li>" for line in lines)
    return ('<ul id="host-notes" hx-swap-oob="true" class="mb-6 space-y-1 rounded-lg bg-amber-50 px-4 py-2.5 text-sm text-amber-900 '
            f'dark:bg-amber-950/40 dark:text-amber-200" aria-label="Limits of this host">{items}</ul>')


def mixed_notes(e: Experiment) -> list[str]:
    """For the builder: how many routers of each topology run OBGP in each mixed variant."""
    notes = []
    for v in e.variants:
        mode = MODES[v.mode]
        if mode.inner is None:
            continue
        parts = []
        for t in e.topologies:
            routers = topology.load(t, shared=True)["routers"]
            chosen = sum(m != "bgp" for m in v.modes_of(routers, seed=e.seed * 1000 + 1).values())
            parts.append(f"{chosen} of {len(routers)} on {t}")
        drawn = ", drawn anew for every run" if mode.pick == "random" else ", as the topology marks them"
        notes.append(f"{v.name}: {MODES[mode.inner].label} on {'; '.join(parts)}{drawn}")
    return notes


@router.get("/experiments", response_class=HTMLResponse)
def experiments_page(request: Request, error: str = ""):
    listed = experiments()
    choices = {which: run_all(listed, which) for which in RUN_ALL}
    for x in listed:
        x["own"] = groups.of_experiment(x["name"])
    return render(request, "experiments.html", cluster_state=jobs.cluster_control.snapshot(), nav="experiments", experiments=listed, error=error,
                  groups=groups.arrange("experiments", listed, config.names()),
                  run_all=[{"which": w, "label": RUN_ALL[w], "count": len(c), "s": sum(x["estimate_s"] or 0 for x in c)} for w, (c, _) in choices.items()],
                  all_left=choices["all"][1], left_counts=(sum(" / " not in n for n, _ in choices["all"][1]), sum(" / " in n for n, _ in choices["all"][1])), max_routers=cluster.max_routers(), limits=cluster.limits())


@router.post("/experiments/run-all")
def experiments_run_all(which: str = Form("all")):
    problems = []
    for x in run_all(experiments(), which if which in RUN_ALL else "all")[0]:
        try:
            result = Dataset.new_name(x["experiment"])
            Dataset.create(x["experiment"], result)
            jobs.enqueue(result)
        except ValueError as error:
            problems.append(f"{x['name']}: {error}")
    return RedirectResponse("/experiments" + (f"?{urlencode({'error': ' '.join(problems)})}" if problems else ""), 303)


@router.post("/experiments/{name}/start")
def experiment_start(name: str, stay: bool = False):
    """Queues an experiment. From the list of experiments the list stays."""
    try:
        result = start(name)
    except ValueError as error:
        return RedirectResponse(f"/experiments?{urlencode({'error': str(error)})}", 303)
    return RedirectResponse("/experiments" if stay else f"/results/{result}", 303)


@router.get("/experiments/new", response_class=HTMLResponse)
def experiment_new(request: Request, like: str = ""):
    base, _ = read_experiment(like) if like else (None, "")
    values = builder_values(base.model_copy(update={"name": f"{base.name}-copy"}) if base else None)
    return render(request, "experiment.html", nav="experiments", values=values, new=True, **builder_context())


@router.get("/experiments/{name}", response_class=HTMLResponse)
def experiment_page(request: Request, name: str):
    e, error = read_experiment(name)
    if not e:
        raise HTTPException(404, error)
    values = {**builder_values(e, original=name), "error": error}
    made = [d for d in Dataset.all() if d.experiment.name == name]  # newest first
    return render(request, "experiment.html", nav="experiments", values=values, new=False, made=made,
                  **builder_context())


@router.post("/experiments/estimate", response_class=HTMLResponse)
async def experiment_estimate(request: Request):
    try:
        e = parse_builder(await request.form())
    except ValueError as error:
        return HTMLResponse(f'<span class="error">{escape(str(error))}</span>')
    how = (f"{len(e.combinations())} × {len(e.variants)} × {e.runs}: topologies with the scenario of their name, variants, runs" if e.paired
           else f"{len(e.topologies)} × {len(e.cases())} × {len(e.variants)} × {e.runs}: topologies, scenarios with the values of their sweeps, variants, runs"
           if e.sweeps else f"{len(e.topologies)} × {len(e.scenarios)} × {len(e.variants)} × {e.runs}: topologies, scenarios, variants, runs")
    notes = "".join(f"<li>{escape(n)}</li>" for n in mixed_notes(e))
    return HTMLResponse(f'<span data-tip="{how}">{e.runs_total()} runs · ≈ {duration(estimate.experiment_s(e))}</span>'
                        f'<ul id="variant-notes" hx-swap-oob="true" class="muted space-y-0.5 px-5 pb-3 text-xs">{notes}</ul>'
                        + host_notes(e))


@router.post("/experiments/save")
async def experiment_save(request: Request):
    form = await request.form()
    original, mode = str(form.get("original", "")), form.get("mode") or None
    try:
        e = parse_builder(form)
        check_rename("experiment", e.name, original, mode, config.path)
        e.check_files()
        cluster.check_modes(e)
        config.save(e)
    except ValueError as error:
        return JSONResponse({"problems": str(error).split("; ")}, status_code=422)
    if original and original != e.name:
        groups.follow("experiments", original, e.name, mode == "rename", own_group("experiments", e.name), groups.of_experiment(original))
    if original and original != e.name and mode == "rename":
        config.path(original).unlink(missing_ok=True)
    if form.get("action") != "start":
        return JSONResponse({"saved": e.name})
    result = Dataset.new_name(e)
    Dataset.create(e, result)
    jobs.enqueue(result)
    return JSONResponse({"saved": e.name, "result": result})


@router.post("/experiments/{name}/delete")
def experiment_delete(name: str):
    try:
        config.path(name).unlink(missing_ok=True)
    except ValueError:
        raise HTTPException(404, f"No experiment {name}.") from None
    groups.forget("experiments", name)
    return RedirectResponse("/experiments", 303)
