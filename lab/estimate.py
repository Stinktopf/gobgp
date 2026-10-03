"""How long results still take, from the durations of earlier runs.

A pending run takes the median of what the most alike finished runs took:
of the same topology, variant and scenario in this result, else in earlier
ones; else of the same topology and scenario with another variant; else the
scenario as long as it took elsewhere plus what deploying this topology
takes; else the planned duration of the scenario, scaled by how much longer
the finished runs of this result took than planned. Deploying takes some
seconds per router, so a topology without runs is guessed by its size.
"""

from collections import defaultdict
from datetime import datetime
from statistics import median

from . import scenario
from .results import Dataset, RunKey

STARTUP_S = 30  # starting the cluster and checking the images, once per result
# Deploying and cleaning up a topology without runs to go by: measured
# 24 to 42 s for 30 routers, about 165 s for 100.
DEPLOY_BASE_S, DEPLOY_PER_ROUTER_S = 10, 1.5

_took: dict[str, tuple[str, dict[RunKey, tuple[float, float | None]]]] = {}


def _runs(dataset: Dataset) -> dict[RunKey, tuple[float, float | None]]:
    """Per finished run the seconds it took and those of its scenario."""
    stamp = f'{dataset.status.get("state")} {dataset.status.get("done")}'  # changes when a run ends
    if (hit := _took.get(str(dataset.path))) and hit[0] == stamp:
        return hit[1]
    out: dict[RunKey, tuple[float, float | None]] = {}
    try:
        for key in dataset.keys():
            if dataset.is_done(key) and "took_s" in (run := dataset.run(key)):
                out[key] = (run["took_s"], run.get("duration_s"))
    except (ValueError, OSError):  # an unreadable result
        pass
    _took[str(dataset.path)] = (stamp, out)
    return out


def took(dataset: Dataset) -> dict[RunKey, float]:
    """Seconds each finished run of a result took."""
    return {k: t for k, (t, _) in _runs(dataset).items()}


class Past(dict):
    """What finished runs took, by topology, variant and scenario, and
    besides by topology and scenario, the scenario alone, and what
    deploying each topology took."""

    def __init__(self) -> None:
        super().__init__()
        self.by_ts, self.scenario_s, self.deploy_s = defaultdict(list), defaultdict(list), defaultdict(list)

    def add(self, key: RunKey, seconds: float, scenario_s: float | None) -> None:
        self.setdefault(kind(key), []).append(seconds)
        self.by_ts[key.topology, key.scenario].append(seconds)
        if scenario_s is not None:
            self.scenario_s[key.scenario].append(scenario_s)
            self.deploy_s[key.topology].append(seconds - scenario_s)


def history(exclude: Dataset | None = None) -> Past:
    """Durations of all finished runs, but those of exclude."""
    past = Past()
    for dataset in Dataset.all():
        if exclude is None or dataset.path != exclude.path:
            for key, (seconds, scenario_s) in _runs(dataset).items():
                past.add(key, seconds, scenario_s)
    return past


def kind(key: RunKey) -> tuple[str, str, str]:
    return key.topology, key.variant, key.scenario


def run_s(dataset: Dataset, key: RunKey, mine: dict[RunKey, float], past: dict, planned: dict | None = None) -> float:
    """Seconds a pending run of a result takes; mine are its finished runs."""
    planned = planned or _planned(dataset)
    return guess(key, mine, past, planned, lambda t: _size(dataset, t))


def guess(key: RunKey, mine: dict[RunKey, float], past: dict, planned: dict[str, float], size) -> float:
    """Seconds a run takes, from the most alike finished runs (see above);
    size gives the routers of a topology."""
    same = [s for k, s in mine.items() if kind(k) == kind(key)] or past.get(kind(key))
    if same:
        return median(same)
    alike = [s for k, s in mine.items() if (k.topology, k.scenario) == (key.topology, key.scenario)]
    if alike := alike or getattr(past, "by_ts", {}).get((key.topology, key.scenario)):
        return median(alike)
    deploy_guess = lambda t: DEPLOY_BASE_S + DEPLOY_PER_ROUTER_S * size(t)
    deploy = getattr(past, "deploy_s", {}).get(key.topology)
    deploy_s = median(deploy) if deploy else deploy_guess(key.topology)
    if elsewhere := getattr(past, "scenario_s", {}).get(key.scenario):
        return deploy_s + median(elsewhere)
    # Scaled by how the finished runs of this result compare to their plan.
    ratios = [s / (deploy_guess(k.topology) + planned[k.scenario]) for k, s in mine.items() if k.scenario in planned]
    return (deploy_s + planned[key.scenario]) * (median(ratios) if ratios else 1.0)


def _planned(dataset: Dataset) -> dict[str, float]:
    """The planned duration of each scenario, as the result has it."""
    return {s: dataset.scenario(s).duration() for s in dataset.experiment.cases()}


_sizes: dict[tuple[str, str], int] = {}


def _size(dataset: Dataset, topology: str) -> int:
    if (str(dataset.path), topology) not in _sizes:
        try:
            _sizes[str(dataset.path), topology] = len(dataset.topology(topology)["routers"])
        except (ValueError, OSError, KeyError):
            _sizes[str(dataset.path), topology] = 20
    return _sizes[str(dataset.path), topology]


def remaining_s(dataset: Dataset, past: dict | None = None) -> float | None:
    """Seconds until a result is finished; None if it cannot be read."""
    try:
        keys = dataset.keys()
        planned = _planned(dataset)  # the scenarios as the result has them
    except (ValueError, OSError):
        return None
    past = history() if past is None else past
    mine = took(dataset)
    status = dataset.status
    done = dataset.statuses()
    total = 0.0
    for key in keys:
        if key in mine or key in done:
            continue
        guess = run_s(dataset, key, mine, past, planned)
        if str(key) == status.get("current") and status.get("run_started"):
            elapsed = (datetime.now().astimezone() - datetime.fromisoformat(status["run_started"])).total_seconds()
            guess = max(5.0, guess - elapsed)
        total += guess
    return total


def experiment_s(experiment, past: dict | None = None) -> float:
    """Seconds a new result of an experiment takes."""
    from . import topology

    past = history() if past is None else past
    planned = {}
    for s in experiment.cases():
        try:
            planned[s] = experiment.scenario_of(s).duration()
        except (ValueError, OSError):
            pass

    def size(name: str) -> int:
        try:
            return len(topology.load(name, shared=True)["routers"])
        except (ValueError, OSError, KeyError):
            return 20

    total = STARTUP_S
    for t in experiment.topologies:
        for s in planned:
            for v in experiment.variants:
                total += experiment.runs * guess(RunKey(t, v.name, s, 1), {}, past, planned, size)
    return total
