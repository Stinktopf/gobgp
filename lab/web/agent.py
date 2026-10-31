"""What an agent may ask and do, as plain data: the API and MCP both use it.
Answers are short on purpose, an agent asks for more where it needs it.

An agent reads everything, and with a token of scope control changes
experiments and scenarios, runs the queue and updates the lab. It never
deletes results, never changes settings, and never touches the paper's
runs. With a token that asks first, each change waits for a person."""

import functools
import hashlib
import inspect
import re
import threading

from pydantic import ValidationError

from .. import analysis, cluster, config, estimate, host, scenario, simulation, topology, update
from ..config import Experiment
from ..modes import MODES
from ..problems import grouped
from ..problems import of as problems_of
from ..results import Dataset
from . import approvals, groups, tokens
from .common import METRICS, duration, jobs, load_problem
from .context import experiments as experiment_files
from .context import overview, users
from .routes.experiments import start as queue_new

LOG_LINES = 2000  # the most a log answer holds
PAPER = "ifip-networking-2026"  # the paper's runs: the experiment, its scenarios and topologies stay as they are


class NotFound(LookupError):
    pass


def _result(name: str) -> Dataset:
    if not (dataset := Dataset.find(name)):
        raise NotFound(f"No result {name}.")
    return dataset


def _progress(dataset: Dataset) -> dict:
    s = dataset.status
    return {"state": s.get("state"), "done": s.get("done"), "total": s.get("total"), "errors": s.get("errors", 0)}


def status() -> dict:
    """The queue, the running result with its run, attempt and phase, the cluster and the host."""
    active = jobs.active()
    running = None
    if active:
        s = active.status
        running = {"result": active.name, **_progress(active), "run": s.get("current"), "phase": s.get("phase"),
                   "attempt": s.get("attempt"), "failure": s.get("failure")}
    c = jobs.cluster_control.snapshot() if jobs.cluster_control else {}
    h = host.now()
    return {"running": running, "queue": jobs.queue(), "paused": jobs.paused(),
            "pause_reason": jobs.pause_reason() if jobs.paused() else "",
            "cluster": {k: c.get(k) for k in ("status", "cpus", "memory_mb", "error", "manual_off")},
            "host": {k: h.get(k) for k in ("busy", "lab", "others", "memory_mb", "lab_mb", "total_mb", "threads")}}


def experiments() -> list[dict]:
    """The experiment files: what each runs and how many runs."""
    out = []
    for f in experiment_files():
        if "error" in f:
            out.append({"name": f["name"], "error": f["error"]})
            continue
        e = f["experiment"]
        out.append({"name": f["name"], "description": e.description, "runs": f["runs"], "estimate_s": f["estimate_s"],
                    "topologies": e.topologies, "scenarios": e.cases(), "variants": [v.name for v in e.variants],
                    "too_large": f["too_large"] or None})
    return out


def results() -> list[dict]:
    """Every result, the newest first, with its progress."""
    return [{"name": d.name, "experiment": d.experiment.name, "public": d.public, "created": d.meta.get("created"), **_progress(d)}
            for d in Dataset.all()]


def result(name: str) -> dict:
    """A result: its setup, progress and the number of problems of each kind. What the metrics mean: metrics."""
    d = _result(name)
    e = d.experiment
    found = problems_of(d)
    return {"name": d.name, "experiment": e.name, "description": e.description, **_progress(d),
            "topologies": e.topologies, "scenarios": e.cases(), "runs_per_combination": e.runs,
            "variants": [{"name": v.name, "mode": v.summary(), "commit": d.commits.get(v.name, "")[:12]} for v in e.variants],
            "bgp": e.bgp.model_dump(), "sampling": e.sampling.model_dump(), "cluster": {**e.cluster.model_dump(), **(d.meta.get("cluster") or {})},
            "problems": {kind: sum(p["kind"] == kind for p in found) for kind in ("error", "check", "property", "retried")}}


def metrics() -> dict:
    """What each metric of summary and runs means, with its unit."""
    return {k: {"label": m[0], "unit": m[1], "meaning": m[2]} for k, m in METRICS.items()}


def version() -> dict:
    """The commit the lab runs, and what GitHub has beyond it."""
    s = update.status(fetch=True)
    return {k: s.get(k) for k in ("branch", "commit", "date", "behind", "ahead", "new", "dirty", "problem", "resettable")}


def summary(name: str, topology: str = "", scenario: str = "", variant: str = "", metrics: list[str] | None = None) -> list[dict]:
    """The median, its interval and the range over the runs, per topology, scenario and variant, filtered."""
    rows = []
    for g in analysis.summary(_result(name)):
        if (topology and g["topology"] != topology) or (scenario and g["scenario"] != scenario) or (variant and g["variant"] != variant):
            continue
        chosen = {k: v for k, v in g["metrics"].items() if not metrics or k in metrics}
        rows.append({"topology": g["topology"], "scenario": g["scenario"], "variant": g["variant"], "statuses": g["statuses"], "metrics": chosen})
    return rows


def runs(name: str, topology: str = "", scenario: str = "", variant: str = "", metrics: list[str] | None = None) -> list[dict]:
    """The metrics of every finished run, filtered, for analyses of one's own."""
    d = _result(name)
    out = []
    for key, m in analysis.run_summary(d).items():
        t, v, s, i = _key(key)
        if (topology and t != topology) or (scenario and s != scenario) or (variant and v != variant):
            continue
        out.append({"topology": t, "variant": v, "scenario": s, "run": int(i), "metrics": {k: x for k, x in m.items() if not metrics or k in metrics}})
    return out


def _key(key: str) -> tuple[str, str, str, str]:
    """topology/variant/scenario#run, as str(RunKey) writes it."""
    t, v, rest = key.split("/", 2)
    s, _, i = rest.rpartition("#")
    return t, v, s, i


def paired(name: str, topology: str, scenario: str, metric: str, variant: str, baseline: str) -> dict | None:
    """A variant against a baseline in the runs paired by seed: median relative difference, Wilcoxon p, Hodges-Lehmann shift and interval."""
    return analysis.paired(_result(name), topology, scenario, metric, variant, baseline)


def primary(name: str) -> dict | None:
    """The comparison the experiment is about, in every cell, with p values Holm-corrected across the cells. Other tests are exploratory."""
    return analysis.primary(_result(name))


def problems(name: str) -> list[dict]:
    """Runs that ended in an error, failed a check or completed only after a failed attempt, grouped by cause."""
    return grouped(problems_of(_result(name)))


def log(name: str, tail: int = 200, grep: str = "") -> list[str]:
    """The last lines of a result's log, optionally only those that match a regular expression."""
    path = _result(name).path / "lab.log"
    lines = path.read_text().splitlines() if path.exists() else []
    if grep:
        try:
            pattern = re.compile(grep)
        except re.error as e:
            raise ValueError(f"grep: {e}") from None
        lines = [line for line in lines if pattern.search(line)]
    return lines[-max(1, min(tail, LOG_LINES)):]


def topologies() -> list[dict]:
    """The topologies: routers, links and where they come from."""
    out = []
    for name in topology.names():
        t = topology.load(name, shared=True)
        links = sum(len(r.get("neighbors", [])) for r in t["routers"].values()) // 2
        out.append({"name": name, "source": t.get("source"), "routers": len(t["routers"]), "links": links})
    return out


def topology_of(name: str) -> dict:
    """One topology: its routers with ASN and roles, the names scenarios target."""
    try:
        t = topology.load(name, shared=True)
    except (ValueError, OSError):
        raise NotFound(f"No topology {name}.") from None
    return {"name": name, "source": t.get("source"), "roles": t.get("roles") or {},
            "routers": {r: {"asn": x.get("asn"), "neighbors": [n["name"] for n in x.get("neighbors", [])]} for r, x in t["routers"].items()}}


def scenarios() -> list[dict]:
    """The scenarios: what they do and how long they take."""
    out = []
    for name in scenario.names():
        try:
            sc = scenario.load(name)
        except (ValueError, OSError) as e:
            out.append({"name": name, "error": load_problem(e)})
            continue
        out.append({"name": name, "description": sc.description, "params": sc.params or {}})
    return out


def scenario_of(name: str) -> dict:
    """One scenario as its file, to read or to change and save."""
    try:
        return {"name": name, "yaml": scenario.path(name).read_text(), "used_by": users("scenarios")[name]}
    except (ValueError, OSError):
        raise NotFound(f"No scenario {name}.") from None


def experiment_of(name: str) -> dict:
    """One experiment as its file, to read or to change and save."""
    try:
        return {"name": name, "yaml": config.path(name).read_text(), "protected": name == PAPER}
    except (ValueError, OSError):
        raise NotFound(f"No experiment {name}.") from None


def simulation_searches() -> list[dict]:
    """The searches of the simulator, the newest first: parameters, state, how many findings (found) and how many
    problems they make, as the web interface groups them."""
    return simulation.searches()


def simulation_search(search_id: str) -> dict:
    """One search and its findings by kind of deviation, each with the id simulation_case takes, how often it
    showed (count of of networks), the routers it hit, and whether its family is inside the proof's model. The
    problems group them as the web interface does: a kind in the same modes, what the proofs say, and the finding
    ids of its networks, the smallest first."""
    entry = simulation.search(search_id)
    grouped = [{"kind": p["kind"], "modes": p["modes"], "proof": p["proof"], "families": p["families"],
                "networks": [c["id"] for c in p["examples"]]} for p in simulation.problems(entry)]
    found = [{"id": e["id"], "kind": e["finding"]["kind"], "mode": e["finding"]["mode"], "family": e["instance"].get("family"),
              "routers": e["instance"].get("routers"), "links": len(e["instance"].get("links", [])), "hit": e["finding"].get("routers"),
              "detail": e["finding"].get("detail"), "count": e.get("count"), "of": e.get("of"), "in_model": e.get("in_model")}
             for e in entry.pop("findings")]
    return {**entry, "findings": found, "problems": grouped}


def simulation_case(search_id: str, finding: int, mode: str = "", start: int = 0, limit: int = 40) -> dict:
    """One finding played in a mode, its own mode by default: the network, a summary (messages, whether it came to
    rest, the first step with a forwarding loop, the routers at the end), and steps start to start + limit, each a
    message or an event with, after it, what every router forwards on, admits, sets aside and announces."""
    example = simulation.finding(search_id, finding)
    played = simulation.trace(search_id, finding, mode or example["finding"]["mode"], not jobs.active())
    steps = played["steps"]
    first_loop = next((k for k, st in enumerate(steps) if st.get("loop")), None)
    return {"instance": example["instance"], "finding": example["finding"], "mode": played["mode"],
            "summary": {"steps": len(steps), "converged": played["result"]["converged"], "first_loop": first_loop,
                        "end": steps[-1]["routers"] if steps else []},
            "start": start, "steps": steps[max(0, start):max(0, start) + max(1, min(limit, 200))]}


def vocabulary() -> dict:
    """What files may name: the modes of variants and the steps of scenarios with their fields."""
    steps = {kind: [f.alias or n for n, f in model.model_fields.items()] for kind, model in scenario.ARGS.items()}
    return {"modes": {m.name: m.description for m in MODES.values()},
            "steps": {**steps, "wait": ["seconds"], "parallel": ["steps"]}}


# Changes: only with a token of scope control. Each one runs at once, or
# with a token that asks first, waits for a person, see approvals.

ACTIONS: dict = {}


def controlled(describe, always_ask: str = "", ask=None, details=None, bind=None):
    """Marks a change; describe tells it in a few words, from its arguments. It waits for a person
    with a token that asks first, always when always_ask gives the reason, and when ask gives one,
    e.g. a full queue. details tell its extent to the person, bind fingerprints the file it acts on."""
    def wrap(fn):
        @functools.wraps(fn)
        def action(*args, **kwargs):
            token = tokens.caller.get()
            bound = inspect.signature(fn).bind(*args, **kwargs)
            bound.apply_defaults()
            values = dict(bound.arguments)
            why = (ask(**values) if ask and token else "") or always_ask
            if token and (token.get("approval") or always_ask or why):
                text = describe(**values)
                entry = approvals.propose(token, fn.__name__, values, text, details(**values) if details else "", why,
                                          bind(**values) if bind else None)
                tokens.record(f"asks to {text}" + (f": {why}" if why else ""))
                return {"waiting": entry["id"], "action": text, "why": why or "its token asks first",
                        "for": "a person to approve it in the settings"}
            return fn(*args, **kwargs)
        action.run, action.bind = fn, bind
        ACTIONS[fn.__name__] = action
        return action
    return wrap


def _fingerprint(file) -> str | None:
    try:
        return hashlib.sha256(file.read_bytes()).hexdigest()
    except (OSError, ValueError):
        return None


def _experiment_s(name: str) -> float:
    try:
        return estimate.experiment_s(Experiment.load(config.path(name)), estimate.history())
    except (OSError, ValueError):
        return 0.0


def _over_budget(experiment: str) -> str:
    """Why queueing it needs a person: more estimated hours than agents may queue."""
    hours = tokens.limits()["queue_h"]
    queued = overview().get("all_s") or 0
    if queued + _experiment_s(experiment) > hours * 3600:
        return f"the queue would run longer than the {hours:g} h agents may fill"
    return ""


def _resume_over_budget(name: str) -> str:
    """Why resuming needs a person: what is left of the result would overrun what agents may queue."""
    try:
        left = estimate.remaining_s(_result(name)) or 0.0
    except (NotFound, OSError, ValueError):
        return ""
    hours = tokens.limits()["queue_h"]
    if (overview().get("all_s") or 0) + left > hours * 3600:
        return f"the queue would run longer than the {hours:g} h agents may fill"
    return ""


def _extent(experiment: str) -> str:
    try:
        e = Experiment.load(config.path(experiment))
    except (OSError, ValueError):
        return ""
    return f"{e.runs_total()} runs, about {duration(_experiment_s(experiment))}"


def _incoming(branch: str = "") -> str:
    new = update.status(fetch=True).get("new") or []
    return "; ".join(new[:5]) + (f" and {len(new) - 5} more" if len(new) > 5 else "") if new else "no new commits"


def action(action_id: str) -> dict:
    """An action that waited for approval: waiting, done, failed or rejected, and what came of it."""
    if not (entry := approvals.get(action_id)):
        raise NotFound(f"No action {action_id}.")
    return {k: entry.get(k) for k in ("id", "text", "state", "outcome", "created", "decided")}


def decide(action_id: str, approve: bool) -> dict:
    """A person approves or rejects an action that waits; it runs as the agent that asked."""
    entry = approvals.get(action_id)
    if not entry or entry["state"] != "waiting":
        raise NotFound(f"No action {action_id} waits.")
    tokens.caller.set(next((t for t in tokens.load() if t["id"] == entry["token"]), {"name": entry["by"]}))
    bind = ACTIONS[entry["call"]].bind
    if approve and bind and entry.get("fingerprint") != bind(**entry["args"]):
        approvals.settle(action_id, "failed", "the file changed since the agent asked")
        return {"state": "failed", "outcome": "The file changed since the agent asked. Let it ask again."}
    if not approve:
        approvals.settle(action_id, "rejected", "")
        tokens.record(f"was refused: {entry['text']}")
        return {"state": "rejected"}
    try:
        outcome = ACTIONS[entry["call"]].run(**entry["args"])
    except (ValueError, LookupError) as e:
        approvals.settle(action_id, "failed", str(e))
        return {"state": "failed", "outcome": str(e)}
    approvals.settle(action_id, "done", ", ".join(f"{k}: {v}" for k, v in outcome.items() if not isinstance(v, (list, dict))))
    return {"state": "done", **outcome}


@controlled(lambda experiment: f"queue {experiment}", ask=_over_budget, details=_extent,
            bind=lambda experiment: _fingerprint(config.path(experiment)))
def start(experiment: str) -> dict:
    """Queues a new result of an experiment, as its file is now."""
    token = tokens.caller.get()
    result = queue_new(experiment, by=token["name"] if token else None)
    tokens.record(f"queued {result}")
    return {"result": result, "queue": jobs.queue()}


@controlled(lambda name: f"stop {name}")
def stop(name: str) -> dict:
    """Stops a running or waiting result. It can be resumed later."""
    jobs.stop(_result(name).name)
    tokens.record(f"stopped {name}")
    return {"queue": jobs.queue()}


@controlled(lambda name: f"resume {name}", ask=_resume_over_budget)
def resume(name: str) -> dict:
    """Queues a stopped result again, to run what is left."""
    jobs.enqueue(_result(name).name)
    tokens.record(f"resumed {name}")
    return {"queue": jobs.queue()}


@controlled(lambda branch: f"update the lab{' to ' + branch if branch else ''}", always_ask="an update changes the lab's code",
            details=_incoming, bind=lambda branch: approvals.head())
def update_lab(branch: str = "") -> dict:
    """Takes the new commits from GitHub, or moves to a branch there, also after its
    history was rewritten, and starts the web server again. Only while no result runs."""
    if active := jobs.active():
        raise ValueError(f"{active.name} runs. Stop it or wait, then update.")
    s = update.status(fetch=True)
    try:
        with cluster.claim("__maintenance__"):
            commit = update.switch(branch or s["branch"]) if branch or s["resettable"] else update.update()
    except (update.UpdateError, cluster.Busy) as e:
        raise ValueError(str(e)) from None
    tokens.record(f"updated the lab to {commit}")
    threading.Timer(1.0, update.restart).start()  # after this answer is sent
    return {"commit": commit, "restarting": True}


@controlled(lambda: "pause the queue")
def pause() -> dict:
    """Pauses the queue after the running run."""
    jobs.pause()
    tokens.record("paused the queue")
    return {"paused": True}


@controlled(lambda: "resume the queue")
def unpause() -> dict:
    """Resumes the queue."""
    if cluster.manually_stopped():
        raise ValueError("The cluster is switched off. Start it in the settings first.")
    jobs.resume_queue()
    tokens.record("resumed the queue")
    return {"paused": False}


def _mapping(text: str) -> dict:
    data = config.load_yaml(text)
    if not isinstance(data, dict):
        raise ValueError("The file must be a mapping of fields, as experiment_of and scenario_of show.")
    return data


def _not_paper(kind: str, name: str) -> None:
    paper = Experiment.load(config.path(PAPER))
    if (kind == "experiment" and name == PAPER) or (kind == "scenario" and name in paper.scenarios):
        raise ValueError(f"{name} belongs to the paper's runs, which stay as they are.")


@controlled(lambda: "queue a search of the simulator")
def start_simulation() -> dict:
    """Queues a search of the simulator that checks everything: every connected network up to five routers, every
    family of policies, three orders of messages each, the way to rest, one table and tables per neighbor (modes named
    -pn). It waits in the lab's queue as a result does and runs when nothing runs before it; status shows it."""
    token = tokens.caller.get()
    search_id = simulation.start(by=token["name"] if token else None)
    tokens.record(f"started the simulator search {search_id}")
    return {"search": search_id}


@controlled(lambda search_id: f"stop the simulator search {search_id}")
def stop_simulation(search_id: str) -> dict:
    """Stops a search of the simulator that runs."""
    stopped = simulation.stop(search_id)
    tokens.record(f"stopped the simulator search {search_id}")
    return stopped


@controlled(lambda search_id, finding: f"make finding {finding} of the simulator search {search_id} an experiment")
def simulation_to_lab(search_id: str, finding: int) -> dict:
    """Makes a finding of a search an experiment of the lab, as Play in the lab does: its network a topology, its order of
    events a scenario with the simulator's prediction as checks, every mode a variant, 6 runs. The same finding gives the
    same experiment, kept as it is when it exists. start_experiment then runs it. The lab cannot replay the simulator's
    order of messages: a deviation it saw in few orders may not show in the runs."""
    name = simulation.to_lab(search_id, finding)
    tokens.record(f"made finding {finding} of the simulator search {search_id} the experiment {name}")
    return {"experiment": name, "runs": Experiment.load(config.path(name)).runs_total()}


@controlled(lambda name, yaml: f"save the experiment {name}")
def save_experiment(name: str, yaml: str) -> dict:
    """Creates or replaces an experiment from its file, checked as the editor checks it.
    vocabulary names the modes, experiment_of shows an example."""
    _not_paper("experiment", name)
    try:
        e = Experiment.model_validate({**_mapping(yaml), "name": name})
        cluster.check_modes(e)
        config.save(e)
    except ValidationError as error:
        raise ValueError(load_problem(error)) from None
    tokens.record(f"saved the experiment {name}")
    return {"saved": name, "runs": e.runs_total()}


@controlled(lambda name: f"delete the experiment {name}", bind=lambda name: _fingerprint(config.path(name)))
def delete_experiment(name: str) -> dict:
    """Deletes an experiment file. Its results stay."""
    _not_paper("experiment", name)
    if not config.path(name).exists():
        raise NotFound(f"No experiment {name}.")
    config.path(name).unlink()
    groups.forget("experiments", name)
    tokens.record(f"deleted the experiment {name}")
    return {"deleted": name}


@controlled(lambda name, yaml: f"save the scenario {name}")
def save_scenario(name: str, yaml: str) -> dict:
    """Creates or replaces a scenario from its file, checked as the editor checks it.
    vocabulary names the steps, scenario_of shows an example."""
    _not_paper("scenario", name)
    try:
        sc = scenario.parse({**_mapping(yaml), "name": name})
    except ValidationError as error:
        raise ValueError(load_problem(error)) from None
    scenario.path(name).write_text(scenario.to_yaml(sc))
    tokens.record(f"saved the scenario {name}")
    return {"saved": name}


@controlled(lambda name: f"delete the scenario {name}", bind=lambda name: _fingerprint(scenario.path(name)))
def delete_scenario(name: str) -> dict:
    """Deletes a scenario that no experiment uses."""
    _not_paper("scenario", name)
    if not scenario.path(name).exists():
        raise NotFound(f"No scenario {name}.")
    if used := users("scenarios")[name]:
        raise ValueError(f"{name} is used by {', '.join(used)}.")
    scenario.path(name).unlink()
    groups.forget("scenarios", name)
    tokens.record(f"deleted the scenario {name}")
    return {"deleted": name}
