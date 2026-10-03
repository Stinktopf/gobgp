"""Experiment configuration, loaded from experiments/*.yaml.

An experiment runs every scenario on every topology, for every variant of
the daemon, a number of times. Topologies and scenarios are referenced by
name; a result keeps copies of them, so later edits do not change it.
"""

import math
import os
import re
from pathlib import Path
from typing import ClassVar

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

ROOT = Path(__file__).resolve().parent.parent
DIRECTORY = ROOT / "experiments"
SETTINGS = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "obgp-lab"
# Names of topologies, scenarios and experiments; routers are Kubernetes services.
NAME = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")


def load_yaml(text: str):
    """YAML with the C parser of libyaml where it is installed, which is many times faster."""
    return yaml.load(text, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))


# What the host keeps for Docker, Kubernetes and the system besides the lab,
# at least 4 threads and 4 GB, and how many routers a thread keeps sampling:
# beyond about four, routers sample too seldom to measure (50 routers on 12
# threads did on 2026-10-02).
HOST_DEFAULTS = {"keep_cpus": 4, "keep_mb": 4096, "routers_per_cpu": 4}
HOST_KEEP_AT_LEAST = {"keep_cpus": 4, "keep_mb": 4096}
_host: tuple | None = None


def host_settings() -> dict:
    """The settings of the host, from host.yaml in the settings: the share of
    a shared host the lab may take (cpus, memory_mb, all if missing), what it
    keeps free, and the routers per thread. Read once until the file changes."""
    global _host
    file = SETTINGS / "host.yaml"
    try:
        stamp = file.stat().st_mtime_ns
    except OSError:
        stamp = None
    if _host and _host[0] == (file, stamp):
        return dict(_host[1])
    try:
        data = load_yaml(file.read_text()) or {}
    except OSError:
        data = {}
    out = {**HOST_DEFAULTS, **{k: int(v) for k, v in data.items() if k in ("cpus", "memory_mb", *HOST_DEFAULTS)}}
    out.update({k: max(out[k], least) for k, least in HOST_KEEP_AT_LEAST.items()})  # also for an older file
    _host = ((file, stamp), out)
    return dict(out)


def save_host(values: dict) -> None:
    """Saves the settings of the host, without those at their default."""
    data = {k: int(v) for k, v in values.items() if v is not None and HOST_DEFAULTS.get(k) != int(v)}
    SETTINGS.mkdir(parents=True, exist_ok=True)
    (SETTINGS / "host.yaml").write_text(yaml.safe_dump(data, sort_keys=False) if data else "")


def host_limit() -> dict:
    """How much of a shared host the lab may take, e.g. {cpus: 128, memory_mb: 524288}; empty for all of it."""
    return {k: v for k, v in host_settings().items() if k in ("cpus", "memory_mb")}


_checked: dict[str, tuple] = {}


def _inputs_stamp() -> tuple:
    """Changes whenever a topology or a scenario changes."""
    from . import scenario, topology

    return tuple((p.name, p.stat().st_mtime_ns) for d in (topology.DIRECTORY, scenario.DIRECTORY)
                 for p in sorted(Path(d).glob("*.yaml")))


def file_of(directory: Path, name: str) -> Path:
    """The YAML file of a name in a directory; ValueError for an invalid name."""
    if not NAME.fullmatch(name):
        raise ValueError(f"invalid name {name!r}")
    return directory / f"{name}.yaml"


def names_in(directory: Path) -> list[str]:
    return sorted(p.stem for p in directory.glob("*.yaml"))


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Cluster(Model):
    """Resources of the minikube cluster that runs all routers."""

    cpus: int = 20
    memory_mb: int = 14000
    # Beyond this a single router is ended, not the node: a leak or a table
    # far larger than planned costs one run, not the cluster. Full tables
    # need far more.
    router_limit_mb: int = Field(512, ge=128)

    # Measured on 2026-10-01: an idle router pod takes 70 to 78 MB, mostly its
    # controller, and every received path some 2 to 2.6 KB more (167,000
    # paths of real prefixes on 30 routers). A router reserves ROUTER_MB,
    # Kubernetes itself SYSTEM_MB, a path PATH_KB. The node reports the
    # memory of the host, not of the profile, so the lab checks this itself.
    ROUTER_MB: ClassVar[int] = 96
    SYSTEM_MB: ClassVar[int] = 1536
    PATH_KB: ClassVar[float] = 3.0

    def routers(self) -> int:
        """How many routers fit."""
        return max(0, (self.memory_mb - self.SYSTEM_MB) // self.ROUTER_MB)


class Variant(Model):
    """A daemon under test: a git ref of this repository and the mode of its
    routers, see lab/modes.py. Random modes give the share of the routers
    that run OBGP."""

    name: str
    ref: str = "HEAD"
    mode: str
    share: float | None = Field(None, gt=0, le=1)

    @model_validator(mode="before")
    @classmethod
    def legacy(cls, data):
        """Variants before modes had obgp: true or false."""
        if isinstance(data, dict) and "obgp" in data and "mode" not in data:
            data = {k: v for k, v in data.items() if k != "obgp"} | {"mode": "obgp" if data["obgp"] else "bgp"}
        return data

    @model_validator(mode="after")
    def check_mode(self):
        from . import modes

        random_ = modes.get(self.mode).pick == "random"
        if random_ and self.share is None:
            raise ValueError(f"{self.mode} needs a share of the routers")
        if not random_ and self.share is not None:
            raise ValueError(f"only random modes take a share, not {self.mode}")
        return self

    @property
    def obgp(self) -> bool:
        """Whether any router runs OBGP."""
        from . import modes

        return modes.get(self.mode).obgp

    @property
    def mixed(self) -> bool:
        from . import modes

        return modes.get(self.mode).inner is not None

    def label(self) -> str:
        from . import modes

        return modes.get(self.mode).label

    def summary(self) -> str:
        """The mode in words, e.g. "OBGP on 50 % of the routers"."""
        from . import modes

        mode = modes.get(self.mode)
        if mode.pick == "random":
            return f"{modes.get(mode.inner).label} on {self.share * 100:g} % of the routers"
        return mode.label

    def modes_of(self, routers: dict, seed: int = 0) -> dict[str, str]:
        """The pure mode of every router of a topology in the run with this seed."""
        from . import modes

        try:
            return modes.assign(self.mode, routers, self.share, seed)
        except ValueError as problem:
            raise ValueError(f"variant {self.name}: {problem}") from None


class Bgp(Model):
    """BGP timers of every session, in seconds, and graceful restart."""

    hold_time: int = Field(90, ge=3)
    keepalive: int = Field(30, ge=1)
    connect_retry: int = Field(5, ge=1, description="Retry interval of a session that is down")
    graceful_restart: bool = Field(False, description="Peers keep the routes of a router that restarts gracefully")


class Sampling(Model):
    interval: float = Field(0.1, ge=0.01, description="Seconds between two samples of every router")
    stable_s: float = Field(3.0, gt=0, description="Seconds a state must hold to count as stable")

    def digits(self) -> int:
        """Decimals that times measured at this interval can show."""
        return max(0, -math.floor(math.log10(self.interval) + 1e-9))

    def stable_count(self) -> int:
        """The number of consecutive samples that make a state stable."""
        return max(1, round(self.stable_s / self.interval))


class Sweep(Model):
    """One parameter of one scenario set to each value in turn, the others
    at the values the scenario gives them: one factor at a time."""

    scenario: str
    param: str
    values: list[float] = Field(min_length=2)

    @model_validator(mode="after")
    def check(self):
        if len(set(self.values)) != len(self.values):
            raise ValueError("every value only once")
        return self


class Experiment(Model):
    name: str
    description: str = ""
    cluster: Cluster = Cluster()
    runs: int = Field(6, ge=1)  # five pairs can never reach p < 0.05
    seed: int = 42
    variants: list[Variant] = Field(min_length=1)
    topologies: list[str] = Field(min_length=1)
    scenarios: list[str] = Field(min_length=1)
    bgp: Bgp = Bgp()
    sampling: Sampling = Sampling()
    sweeps: list[Sweep] = []

    def cases(self) -> list[str]:
        """The scenarios as they run: one without sweeps once, one with sweeps
        once for every value of each, the other parameters as it gives them."""
        from . import scenario

        out = []
        for s in self.scenarios:
            mine = [w for w in self.sweeps if w.scenario == s]
            out += [scenario.case_name(s, w.param, v) for w in mine for v in w.values] if mine else [s]
        return out

    def sweep_of(self, case: str) -> Sweep | None:
        """The sweep a case belongs to, if any."""
        from . import scenario

        base, param, _ = scenario.split_case(case)
        return next((w for w in self.sweeps if w.scenario == base and w.param == param), None)

    def scenario_of(self, case: str):
        """The scenario of a case, from the files of the lab, with the value of its sweep."""
        from . import scenario

        base, param, value = scenario.split_case(case)
        sc = scenario.load(base)
        return scenario.with_param(sc, param, value, case) if param else sc

    @model_validator(mode="after")
    def check_names(self):
        for kind, names in [("variant", [v.name for v in self.variants]), ("topology", self.topologies), ("scenario", self.scenarios)]:
            if len(set(names)) != len(names):
                raise ValueError(f"duplicate {kind} names: {names}")
        swept = [(w.scenario, w.param) for w in self.sweeps]
        if len(set(swept)) != len(swept):
            raise ValueError("every parameter of a scenario only in one sweep")
        return self

    def check_files(self) -> None:
        """Checks that the referenced topologies and scenarios exist."""
        from . import scenario, topology

        if missing := set(self.topologies) - set(topology.names()):
            raise ValueError(f"unknown topologies: {sorted(missing)}")
        if missing := set(self.scenarios) - set(scenario.names()):
            raise ValueError(f"unknown scenarios: {sorted(missing)}")
        for w in self.sweeps:
            if w.scenario not in self.scenarios:
                raise ValueError(f"a sweep sets {w.scenario}, which the experiment does not run")
            if w.param not in scenario.load(w.scenario).params:
                raise ValueError(f"{w.scenario} does not offer {w.param} for sweeps. Mark it in the scenario editor")
            for v in w.values:  # every value must make valid steps
                try:
                    self.scenario_of(scenario.case_name(w.scenario, w.param, v))
                except ValueError as error:
                    raise ValueError(f"{w.param} = {v:g} in {w.scenario}: {str(error).splitlines()[-1].strip()}") from None
        for t in self.topologies:
            data = topology.load(t, shared=True)
            for v in self.variants:
                try:
                    v.modes_of(data["routers"])
                except ValueError:
                    raise ValueError(f"{v.name} runs {v.label()} on the routers a topology marks, but {t} marks none. "
                                     "Mark them in its editor, under OBGP in hybrids.") from None
        self.check_targets()
        self.check_capacity()

    def check_capacity(self) -> None:
        """Checks that every topology fits into the cluster, which would
        otherwise run out of memory."""
        from . import topology

        for t in self.topologies:
            n = len(topology.load(t, shared=True)["routers"])
            if n > self.cluster.routers():
                need = Cluster.SYSTEM_MB + n * Cluster.ROUTER_MB
                raise ValueError(f"{t} has {n} routers, which need about {need:,} MB. The cluster of the experiment has "
                                 f"{self.cluster.memory_mb:,} MB, enough for {self.cluster.routers()}. "
                                 "Give it more memory, or import fewer routers.")

    def check_targets(self) -> None:
        """Checks that every step finds its routers and links on every topology, in every run,
        so that a result does not fail hours after its start."""
        from . import scenario, topology

        problems = []
        for s in self.scenarios:
            graceful = any(step.kind == "restart" and step.args.graceful for step in scenario.each_step(scenario.load(s).steps))
            if graceful and not self.bgp.graceful_restart:
                problems.append(f"{s} restarts gracefully, which needs graceful restart in the BGP settings")
        real = [s for s in self.scenarios if any(step.kind in ("announce_real", "replay", "announce_rib") for step in scenario.each_step(scenario.load(s).steps))]
        for t in self.topologies:
            data = topology.load(t, shared=True)
            if real and not (data["source"] or "").startswith("caida/"):
                problems.append(f"{real[0]} announces real prefixes, which needs a topology imported from CAIDA, not {t}")
            network = scenario.Network(data["routers"], data["roles"])
            for s in self.scenarios:
                steps = scenario.load(s).steps
                for index in range(1, self.runs + 1):
                    for step, target in scenario.preview_targets(steps, network, self.seed, index).items():
                        if "error" in target:
                            number = ".".join(str(int(p) + 1) for p in step.split("."))  # as the editor counts
                            problems.append(f"{s} on {t}, step {number}: {target['error']}")
                    if problems:
                        break
        if problems:
            raise ValueError("; ".join(dict.fromkeys(problems)))

    def runs_total(self) -> int:
        return len(self.variants) * len(self.topologies) * len(self.cases()) * self.runs

    @classmethod
    def load(cls, path: Path) -> "Experiment":
        """The experiment of a file, checked against its topologies and
        scenarios. Checking resolves every step of every run, so a checked
        experiment is kept until the file, a topology or a scenario changes."""
        key = (str(Path(path).resolve()), Path(path).stat().st_mtime_ns, _inputs_stamp())
        if (hit := _checked.get(key[0])) and hit[0] == key:
            return hit[1]
        experiment = cls.model_validate(load_yaml(Path(path).read_text()))
        experiment.check_files()
        _checked[key[0]] = (key, experiment)
        return experiment

    def to_yaml(self) -> str:
        """The experiment file, compact and without default values."""
        flow = lambda d: "{" + ", ".join(f"{k}: {_scalar(v)}" for k, v in d.items()) + "}"
        lines = [f"name: {self.name}"]
        if self.description:
            lines.append(f"description: {_scalar(self.description)}")
        lines.append(f"runs: {self.runs}")
        if self.seed != type(self).model_fields["seed"].default:
            lines.append(f"seed: {self.seed}")
        for key in ("cluster", "bgp", "sampling"):
            if values := getattr(self, key).model_dump(exclude_defaults=True):
                lines.append(f"{key}: {flow(values)}")
        lines.append("variants:")
        lines += [f"  - {flow(v.model_dump(exclude_defaults=True))}" for v in self.variants]
        lines.append(f"topologies: [{', '.join(self.topologies)}]")
        lines.append("scenarios:")
        lines += [f"  - {s}" for s in self.scenarios]
        if self.sweeps:
            lines.append("sweeps:")
            lines += [f"  - {{scenario: {w.scenario}, param: {w.param}, values: [{', '.join(f'{v:g}' for v in w.values)}]}}" for w in self.sweeps]
        return "\n".join(lines) + "\n"


def _scalar(value) -> str:
    if isinstance(value, dict):
        return "{" + ", ".join(f"{k}: {_scalar(v)}" for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(_scalar(v) for v in value) + "]"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return yaml.safe_dump(value, default_style=None, width=1000).removesuffix("\n...\n").strip()
    return str(value)


def path_ok(name: str) -> bool:
    return bool(NAME.fullmatch(name))


def path(name: str) -> Path:
    return file_of(DIRECTORY, name)


def names() -> list[str]:
    return names_in(DIRECTORY)


def save(experiment: Experiment) -> None:
    experiment.check_files()
    path(experiment.name).write_text(experiment.to_yaml())
