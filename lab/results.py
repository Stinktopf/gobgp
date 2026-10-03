"""Results of experiments, called datasets in the code.

results/private/<result>/ holds every result; representative ones are
moved to results/public/, which is tracked in git. A result contains

    dataset.json                                   experiment, commits, host
    status.json                                    progress while it runs
    lab.log, worker.log                            what the runner logged
    analysis.json                                  cached metrics
    topologies/, scenarios/                        copies of the files it uses
    <topology>/<variant>/<scenario>/<run>/run.json         outcome and events
    <topology>/<variant>/<scenario>/<run>/samples.csv.gz   sampled counters
"""

import csv
import gzip
import json
import os
import random
import shutil
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from . import cluster, config, scenario, topology
from .config import ROOT, Experiment, load_yaml

RESULTS = ROOT / "results"
PUBLIC = RESULTS / "public"
PRIVATE = RESULTS / "private"


def queue_file() -> Path:
    """The queue of the web interface: names of results, the running one first."""
    return PRIVATE / "queue.json"


def pause_file() -> Path:
    """There while the queue is paused: nothing new starts."""
    return PRIVATE / "queue.paused"


def queued() -> list[str]:
    try:
        names = json.loads(queue_file().read_text())
    except (OSError, ValueError):
        return []
    return [n for n in names if isinstance(n, str)] if isinstance(names, list) else []
SAMPLE_FIELDS = [
    "t", "router", "destinations", "paths", "path_len_min", "path_len_avg", "path_len_max",
    "updates_rx", "updates_tx", "peers_rx", "suppressed", "adj_in", "rss_mb", "heap_mb", "heap_objects", "cpu_s",
]
TEXT_FIELDS = ("router", "peers_rx")
COUNTERS = ("destinations", "paths", "updates_rx")  # what changes while routes change


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


_STATUSES: dict[Path, tuple[int, str]] = {}  # run.json -> (its stamp, how the run ended)


@dataclass(frozen=True)
class RunKey:
    topology: str
    variant: str
    scenario: str
    index: int

    @property
    def path(self) -> Path:
        return Path(self.topology, self.variant, self.scenario, str(self.index))

    def __str__(self) -> str:
        return f"{self.topology}/{self.variant}/{self.scenario}#{self.index}"


def folder_size(path) -> int:
    """Bytes of the files below path."""
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.stat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def storage(used: dict[bool, int]) -> dict:
    """Bytes of the public (True) and private (False) results, and the space left on their disk."""
    PRIVATE.mkdir(parents=True, exist_ok=True)
    disk = shutil.disk_usage(PRIVATE)
    return {"public": used[True], "private": used[False], "free": disk.free, "total": disk.total}


def copy_files(path: Path, experiment: Experiment) -> None:
    """Copies of the topologies and scenarios, which keep a result reproducible."""
    for directory, names, source in (("topologies", experiment.topologies, topology.path),
                                     ("scenarios", experiment.scenarios, scenario.path)):
        (path / directory).mkdir(exist_ok=True)
        for n in names:
            shutil.copyfile(source(n), path / directory / f"{n}.yaml")


class Dataset:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.meta = json.loads((path / "dataset.json").read_text())

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def public(self) -> bool:
        return self.path.parent == PUBLIC

    @property
    def status(self) -> dict:
        try:
            return json.loads((self.path / "status.json").read_text())
        except FileNotFoundError:
            return {"state": "finished"}

    @property
    def experiment(self) -> Experiment:
        return Experiment.model_validate(self.meta["experiment"])

    @property
    def commits(self) -> dict[str, str]:
        """The commit each variant was resolved to when the dataset was created."""
        return self.meta["commits"]

    def topology(self, name: str) -> dict:
        return topology.parse((self.path / "topologies" / f"{name}.yaml").read_text())

    def scenario(self, name: str) -> "scenario.Scenario":
        """A scenario as the result has it, with the value of its sweep if it is a case of one."""
        base, param, value = scenario.split_case(name)
        sc = scenario.parse(load_yaml((self.path / "scenarios" / f"{base}.yaml").read_text()))
        return scenario.with_param(sc, param, value, name) if param else sc

    @staticmethod
    def new_name(experiment: Experiment) -> str:
        """The name of a new result: the experiment and the minute, with -2, -3, … if taken."""
        base = f"{experiment.name}-{datetime.now():%Y%m%d-%H%M}"
        name, n = base, 1
        while Dataset.find(name) or (PRIVATE / name).exists() or (PUBLIC / name).exists():
            n += 1
            name = f"{base}-{n}"
        return name

    @classmethod
    def create(cls, experiment: Experiment, name: str) -> "Dataset":
        if not config.path_ok(name):
            raise ValueError("Names use lowercase letters, digits and dashes.")
        experiment.check_files()
        cluster.check_modes(experiment)
        path = PRIVATE / name
        path.mkdir(parents=True)
        copy_files(path, experiment)
        meta = {
            "experiment": experiment.model_dump(mode="json"),
            "commits": {v.name: cluster.resolve(v.ref) for v in experiment.variants},
            "created": now(),
            "lab": {"commit": cluster.resolve("HEAD"), "dirty": bool(cluster.git("status", "--porcelain"))},
            "host": cluster.host(),
        }
        write_atomic(path / "dataset.json", json.dumps(meta, indent=2))
        dataset = cls(path)
        dataset.write_status({"state": "stopped"})  # until it is queued or runs
        return dataset

    @classmethod
    def _each(cls):
        """Every dataset folder, with whether this version of the lab reads it."""
        for base in (PUBLIC, PRIVATE):
            for p in sorted(base.glob("*/dataset.json")):
                dataset = cls(p.parent)
                try:
                    _ = dataset.experiment, dataset.meta["created"]  # reading them validates them
                    yield dataset, True
                except (OSError, ValueError, KeyError, TypeError):  # older or damaged
                    yield dataset, False

    @classmethod
    def all(cls) -> list["Dataset"]:
        """All datasets in the current format, newest first."""
        return sorted((d for d, readable in cls._each() if readable), key=lambda d: d.meta["created"], reverse=True)

    @classmethod
    def older(cls) -> list["Dataset"]:
        """Datasets written by an older version of the lab, or damaged, which can only be deleted."""
        return [d for d, readable in cls._each() if not readable]

    @classmethod
    def find(cls, name: str) -> "Dataset | None":
        for base in (PRIVATE, PUBLIC):
            if (base / name / "dataset.json").exists():
                return cls(base / name)
        return None

    def busy(self) -> str | None:
        """Why the dataset cannot be moved or deleted now, if it cannot."""
        if cluster.holder() == self.name:
            return "It is running. Stop it first."
        if self.name in queued():
            return "It is queued. Stop it first."
        return None

    def delete(self) -> None:
        """Deletes a private dataset that does not run; a public one is made private first."""
        if self.public:
            raise ValueError("It is public. Make it private first.")
        if problem := self.busy():
            raise ValueError(problem)
        shutil.rmtree(self.path)

    def publish(self, public: bool) -> None:
        """Moves the dataset between results/private and results/public, unless it runs."""
        if problem := self.busy():
            raise ValueError(problem)
        target = (PUBLIC if public else PRIVATE) / self.name
        if target != self.path:
            if target.exists():
                raise FileExistsError(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(self.path, target)
            self.path = target

    def update(self, **fields) -> None:
        self.meta.update(fields)
        write_atomic(self.path / "dataset.json", json.dumps(self.meta, indent=2))

    def keys(self) -> list[RunKey]:
        """All runs, with the variants interleaved so that drift over time
        affects them equally, in an order of their own in every round, drawn
        from the seed, so that none always runs first."""
        e = self.experiment
        out = []
        for t in e.topologies:
            for s in e.cases():
                for i in range(1, e.runs + 1):
                    names = [v.name for v in e.variants]
                    random.Random(f"{e.seed}/{t}/{s}/{i}").shuffle(names)
                    out += [RunKey(t, n, s, i) for n in names]
        return out

    def is_done(self, key: RunKey) -> bool:
        return (self.path / key.path / "run.json").exists()

    def statuses(self) -> dict[RunKey, str]:
        """How every finished run ended, at once: one look into the folder,
        each status read once until its run changes. For pages that ask often."""
        out = {}
        for file in self.path.glob("*/*/*/*/run.json"):
            topology, variant, scenario, index = file.parent.relative_to(self.path).parts
            try:
                stamp = file.stat().st_mtime_ns
                if (kept := _STATUSES.get(file)) is None or kept[0] != stamp:
                    kept = _STATUSES[file] = (stamp, json.loads(file.read_text()).get("status", "completed"))
                out[RunKey(topology, variant, scenario, int(index))] = kept[1]
            except (OSError, ValueError):
                continue  # being written, or not a run
        return out

    def run(self, key: RunKey) -> dict:
        return json.loads((self.path / key.path / "run.json").read_text())

    def samples(self, key: RunKey) -> list[dict]:
        """The samples of a run, with numbers parsed and missing counters as None."""
        with gzip.open(self.path / key.path / "samples.csv.gz", "rt", newline="") as f:
            return [
                {k: v if k in TEXT_FIELDS else (float(v) if v else None) for k, v in row.items()}
                for row in csv.DictReader(f)
            ]

    def write_run(self, key: RunKey, run: dict, samples: list[dict]) -> None:
        directory = self.path / key.path
        directory.mkdir(parents=True, exist_ok=True)
        with gzip.open(directory / "samples.csv.gz", "wt", newline="") as f:
            writer = csv.DictWriter(f, SAMPLE_FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(samples)
        # run.json marks the run as done, so it is written last.
        write_atomic(directory / "run.json", json.dumps(run, indent=2))

    def write_status(self, status: dict) -> None:
        write_atomic(self.path / "status.json", json.dumps(status, indent=2))


def write_atomic(path: Path, text: str) -> None:
    """Replaces a file atomically, also when several threads write it."""
    with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=f".{path.name}.", delete=False) as tmp:
        try:
            tmp.write(text)
        except BaseException:
            tmp.close()
            os.unlink(tmp.name)
            raise
    try:
        os.replace(tmp.name, path)
    except BaseException:
        os.unlink(tmp.name)
        raise
