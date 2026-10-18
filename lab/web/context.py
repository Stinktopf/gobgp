"""What every page shows, the overview of the lab in the dock and a notice of updates, and the files of the
lab as several pages list them."""

import platform
from collections import defaultdict
from datetime import datetime, timedelta

import yaml
from fastapi import Request
from fastapi.responses import HTMLResponse

from .. import (
    cluster,
    config,
    estimate,
    scenario,
    topology,
)
from .. import host as hostload
from ..config import ROOT, Experiment
from ..results import Dataset
from . import groups
from .common import jobs, load_problem, templates

UPDATES: dict = {}  # the last check of GitHub for new commits of the branch


EXPERIMENTS = ROOT / "experiments"


def readable_topologies() -> tuple[dict[str, dict], dict[str, str]]:
    """The topologies that load, and the problems of those that do not."""
    loaded, broken = {}, {}
    for name in topology.names():
        try:
            loaded[name] = topology.load(name, shared=True)
        except (ValueError, OSError, KeyError, yaml.YAMLError) as error:
            broken[name] = str(error).splitlines()[0]
    return loaded, broken


def topology_summary(t: dict) -> dict:
    routers = t["routers"]
    return {
        "routers": len(routers),
        "links": sum(len(r.get("neighbors", [])) for r in routers.values()) // 2,
        "preferences": sum(1 for r in routers.values() for n in r.get("neighbors", []) if n.get("localPref", 100) != 100),
    }


def thumb_stamps(loaded: dict[str, dict]) -> dict[str, str]:
    """A version of each topology, by its file: the browser keeps a drawing until it changes."""
    out = {}
    for name in loaded:
        try:
            stat = topology.path(name).stat()
            out[name] = f"{stat.st_mtime_ns:x}-{stat.st_size:x}"
        except OSError:
            pass
    return out


def thumbnails(loaded: dict[str, dict]) -> dict[str, dict]:
    """What the small drawings of the topologies need, and no more: each
    session once, by name, and positions to the pixel. Parts of the Internet
    hold thousands of sessions."""
    def router(n: str, r: dict) -> dict:
        out = {"neighbors": [{"name": m["name"]} for m in r.get("neighbors", []) if n < m["name"]]}
        if p := r.get("position"):
            out["position"] = {"x": round(p["x"]), "y": round(p["y"])}
        if loc := r.get("location"):
            out["location"] = loc
        return out
    return {name: {"roles": {"origins": t["roles"].get("origins", [])}, "routers": {n: router(n, r) for n, r in t["routers"].items()}}
            for name, t in loaded.items()}


def users(kind: str) -> dict[str, list[str]]:
    """The experiments that use each topology or scenario (kind: "topologies" or "scenarios")."""
    used = defaultdict(list)
    for x in experiments():
        if e := x.get("experiment"):
            for n in getattr(e, kind):
                used[n].append(e.name)
    return used


def step_kinds(steps) -> list[str]:
    """The building blocks a scenario uses, in order, without the flow."""
    def walk(items):
        for step in items:
            yield step.kind
            if step.kind == "parallel":
                yield from walk(step.args)
            elif step.kind == "repeat":
                yield from walk(step.args.steps)
    return list(dict.fromkeys(k for k in walk(steps) if k not in ("wait", "until_stable", "parallel", "repeat")))


def experiments() -> list[dict]:
    """The experiment files; one that does not load is listed with its problem."""
    out, past = [], estimate.history()
    for path in sorted(EXPERIMENTS.glob("*.yaml")):
        try:
            e = Experiment.load(path)
        except (ValueError, OSError) as error:
            out.append({"name": path.stem, "error": load_problem(error)})
            continue
        out.append({"name": path.stem, "experiment": e, "runs": e.runs_total(), "estimate_s": estimate.experiment_s(e, past),
                    "too_large": cluster.too_large(e), "skips": cluster.oversized(e), "limit": cluster.limit(e)})
    return out


def overview() -> dict:
    """The running result and the waiting ones, each with how long it takes and when it ends."""
    active = jobs.active()
    names = [n for n in jobs.queue() if not active or n != active.name]
    paused = jobs.paused()
    pause_reason = jobs.pause_reason() if paused else ""
    gpu_wait = jobs.gpu_wait_s() if names else 0
    docker_down = bool(names) and not hostload.docker_running()
    if not active and not names:
        return {"active": None, "queue": [], "paused": paused, "pause_reason": pause_reason, "gpu_wait_s": 0, "docker_down": False}
    past = estimate.history()
    clock = datetime.now()
    left = estimate.remaining_s(active, past) if active else None
    ends = clock + timedelta(seconds=left or 0)
    queue = []
    for name in names:
        dataset = Dataset.find(name)
        takes = waiting_s(dataset, past) if dataset else None
        if takes is not None:
            ends += timedelta(seconds=estimate.STARTUP_S + takes)
        # Its sub-jobs come when it is opened, from /partials/dock/parts.
        queue.append({"name": name, "takes_s": takes, "ends": ends if takes is not None else None})
    # The whole of it: the running result and every waiting one that can be estimated.
    return {"active": active, "active_parts": parts(active, running=True) if active else [], "left_s": left, "active_ends": clock + timedelta(seconds=left) if left is not None else None,
            "queue": queue, "paused": paused, "pause_reason": pause_reason, "gpu_wait_s": gpu_wait, "gpu_busy": hostload.gpu_in_use(hostload.now()) is not False,
            "docker_down": docker_down, "all_ends": ends if queue and ends > clock and not paused and not gpu_wait and not docker_down else None, "all_s": (ends - clock).total_seconds()}


WAITING_S: dict = {}  # result -> (what it was estimated from, seconds)


def waiting_s(dataset: Dataset, past: dict) -> float | None:
    """How long a waiting result takes, estimated again only when it or the history changes."""
    try:  # the runner writes its status after every run
        stamp = ((dataset.path / "status.json").stat().st_mtime_ns, len(past))
    except OSError:
        stamp = (0, len(past))
    if (kept := WAITING_S.get(dataset.path)) is None or kept[0] != stamp:
        kept = WAITING_S[dataset.path] = (stamp, estimate.remaining_s(dataset, past))
    return kept[1]


def parts(dataset: Dataset, running: bool = False) -> list[dict]:
    """The sub-jobs of a result: its runs by topology and scenario, each
    running, pending or as it ended (completed, timeout, failed, error).
    The running one first, then those to come, the finished ones last, so
    that a long list shows what matters at its top."""
    try:
        keys = dataset.keys()
    except (ValueError, OSError):
        return []
    current = dataset.status.get("current") if running else None
    done = dataset.statuses()
    out: dict[tuple, dict] = {}
    for key in keys:
        part = out.setdefault((key.topology, key.scenario), {"topology": key.topology, "scenario": key.scenario, "runs": []})
        state = "running" if str(key) == current else done.get(key, "pending")
        part["runs"].append({"variant": key.variant, "index": key.index, "state": state})
    for part in out.values():
        part["done"] = sum(r["state"] not in ("running", "pending") for r in part["runs"])
    order = lambda p: 0 if any(r["state"] == "running" for r in p["runs"]) else 2 if p["done"] == len(p["runs"]) else 1
    return sorted(out.values(), key=order)


def render(request: Request, template: str, **context) -> HTMLResponse:
    return templates.TemplateResponse(request, template, {"host": platform.node(), "machine": hostload.now(), "cluster_off": cluster.manually_stopped(), "update_ready": UPDATES.get("behind", 0) > 0,
                                                          **overview(), **context})


def check_rename(kind: str, name: str, original: str, mode, path, used_in: str = "") -> None:
    """Checks saving under a new name: mode rename moves the original, copy keeps it."""
    if not config.path_ok(name):
        raise ValueError("Names use lowercase letters, digits and dashes.")
    if name == original:
        return
    if path(name).exists():
        raise ValueError(f"A {kind} named {name} exists already.")
    if original and mode == "rename" and used_in and (used := users(used_in)[original]):
        raise ValueError(f"{original} is used by {', '.join(used)}, so save a copy instead.")


def own_group(kind: str, name: str) -> str | None:
    """The group an experiment, scenario or topology has by itself, None if there is no such item."""
    if not config.path_ok(name):
        return None
    match kind:
        case "experiments":
            return groups.of_experiment(name) if config.path(name).exists() else None
        case "scenarios":
            return groups.of_scenario(users("scenarios")[name]) if scenario.path(name).exists() else None
        case "topologies":
            return groups.of_topology(topology.load(name, shared=True)["source"]) if topology.path(name).exists() else None
    return None
