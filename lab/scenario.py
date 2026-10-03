"""Scenarios: repeatable sequences of steps, stored in scenarios/*.yaml.

A step is a mapping with a single key, its kind:

    announce      origins announce prefixes at a rate for a while, then pause
    announce_real routers announce prefixes their AS announces on the Internet,
                  on topologies imported from CAIDA
    replay        such prefixes then appear and vanish as they did on the
                  Internet in a window of time, faster
    withdraw      withdraw a share of the prefixes, or all of them
    originate     routers announce copies of the origins' prefixes (hijack, anycast)
    down / up     take links or routers down and bring them back
    degrade       add delay, jitter or loss to links
    restart       restart routers, gracefully if the experiment enables it
    set_preference, prepend
                  change the policy of a router at runtime
    set_export    stop or resume announcing to one neighbor, outside the model
                  of OBGP, for experiments at its boundary
    soft_reset    send or ask for all routes again (route refresh)
    expect        check the routes of routers, e.g. that they avoid a router
    wait          wait a number of seconds
    until_stable  wait until no router changes anything, at most until a timeout;
                  after a silent failure (cut, oneway) at least one hold time,
                  since BGP detects it only then
    parallel      run steps at the same time
    repeat        run steps a number of times at a fixed period

Targets name routers, roles of the topology (e.g. origins), links as
"a-b", regions around a router, or random choices. Random choices depend
only on the seed of the run and the position of the step, so they are the
same for every variant and every repetition of a run.
"""

import copy
import math
import random
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .config import ROOT, _scalar, file_of, load_yaml, names_in

DIRECTORY = ROOT / "scenarios"


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# Targets


class Targets(Model):
    """Exactly one way of choosing what a step acts on."""

    router: str | None = Field(None, description="A router, a role such as origins, or random")
    link: str | None = Field(None, description="A link a-b, or random")
    region: dict | None = Field(None, description="{around: router, radius_km: n}: routers in the region")
    cut: dict | None = Field(None, description="{around: router, radius_km: n}: links leaving the region")
    count: int = Field(1, ge=1, description="Number of random choices")

    @model_validator(mode="after")
    def one_target(self):
        given = [k for k in ("router", "link", "region", "cut") if getattr(self, k) is not None]
        if len(given) > 1:
            raise ValueError(f"choose one of router, link, region and cut, not {given}")
        return self


class Announce(Model):
    rate: float = Field(gt=0, description="Announcements per second, split across the routers")
    for_: float = Field(alias="for", gt=0, description="Seconds to announce before pausing")
    router: str = "origins"
    lifetime: float = Field(60, gt=0)
    jitter: float = Field(0.5, ge=0, le=1)
    max_active: int = Field(90, ge=1, description="Active prefixes per router")


class AnnounceReal(Model):
    router: str = Field("all", description="Routers that announce prefixes of their AS")
    per_router: int = Field(20, ge=1, le=1000, description="Prefixes per router at most, drawn by the seed")
    rate: float = Field(50, gt=0, description="Announcements per second, split across the routers")


class Replay(Model):
    start: str = Field(description="Start of the window on the Internet, UTC, e.g. 2026-09-01 12:00")
    minutes: int = Field(30, ge=5, le=120, description="Length of the window")
    speed: float = Field(10, ge=1, le=1000, description="How much faster than on the Internet")
    collector: str = Field("rrc00", pattern=r"^rrc\d\d$", description="The RIS collector whose updates tell what happened")
    per_router: int = Field(20, ge=1, le=1000, description="Prefixes per router at most, those that changed first")


class AnnounceRib(Model):
    at: str = Field(description="Time of the table on the Internet, UTC, e.g. 2026-09-01 08:00; RIS keeps one every eight hours")
    collector: str = Field("rrc00", pattern=r"^rrc\d\d$", description="The RIS collector whose peers' tables are injected")
    router: str = Field("all", description="Routers that inject the table of their AS, where it peers with the collector")
    at_most: int | None = Field(None, ge=1, description="At most this many of them inject, in the order of the topology; all if not given")
    prefixes: int | None = Field(None, ge=1, description="Prefixes at most, the same for every router, drawn by the seed; all if not given")
    timeout: float = Field(3600, gt=0, description="Seconds until every router injected its table")


class WithdrawRib(Model):
    router: str = Field("all", description="Routers that withdraw the table they injected")


class Withdraw(Model):
    percent: float = Field(100, gt=0, le=100)
    router: str = "origins"


class Originate(Model):
    router: str = Field(description="Routers that announce the copies")
    like: str = Field("origins", description="Routers whose prefixes are copied")
    count: int = Field(5, ge=1)
    more_specific: bool = Field(False, description="Announce a more specific prefix instead")


class Down(Targets):
    mode: Literal["session", "cut", "oneway"] = Field(
        "session", description="session: closed with a notification; cut: silently dropped; oneway: one direction dropped"
    )


class Up(Targets):
    """Brings back the chosen targets, or everything that is down or degraded."""


class Degrade(Targets):
    delay_ms: float = Field(0, ge=0)
    jitter_ms: float = Field(0, ge=0)
    loss_pct: float = Field(0, ge=0, le=100)


class Restart(Model):
    router: str
    graceful: bool = Field(False, description="Without closing the sessions: peers keep the routes until it is back. Needs graceful_restart in the experiment")


class SetPreference(Model):
    router: str
    neighbor: str = Field("random", description="A neighbor of the router, or random")
    value: int = Field(ge=0, description="0 removes the preference")


class Prepend(Model):
    router: str
    times: int = Field(ge=0, le=16, description="0 removes the prepending")


class SetExport(Model):
    """Outside the model: OBGP assumes that export filters depend only on the
    Gao-Rexford class of a neighbor. For experiments at that boundary."""

    router: str
    neighbor: str = Field("random", description="A neighbor of the router, or random")
    allow: bool = Field(False, description="false stops announcing routes to the neighbor, true announces them again")


class SoftReset(Model):
    router: str
    direction: Literal["in", "out", "both"] = Field("both", description="in asks the neighbors for their routes, out sends them all routes again")


class Expect(Model):
    """Checks the best routes of routers to the announced prefixes, at the moment of the step."""

    router: str
    prefixes: Literal["all", "none", "any"] = Field("all", description="Whether the routers hold every announced prefix, none, or any number")
    via: str | None = Field(None, description="The best route to every prefix comes from this neighbor")
    avoid: str | None = Field(None, description="No best route passes this router")


class UntilStable(Model):
    timeout: float = Field(gt=0)


class Repeat(Model):
    times: int = Field(ge=1)
    every: float = Field(gt=0, description="Seconds from the start of one repetition to the next")
    steps: list["Step"] = Field(min_length=1)


ARGS = {
    "announce": Announce, "announce_real": AnnounceReal, "replay": Replay, "announce_rib": AnnounceRib,
    "withdraw_rib": WithdrawRib, "withdraw": Withdraw, "originate": Originate, "down": Down, "up": Up,
    "degrade": Degrade, "restart": Restart, "set_preference": SetPreference, "prepend": Prepend,
    "set_export": SetExport, "soft_reset": SoftReset, "expect": Expect, "until_stable": UntilStable, "repeat": Repeat,
}
KINDS = [*ARGS, "wait", "parallel"]


class Step(Model):
    kind: str
    args: (Announce | AnnounceReal | Replay | AnnounceRib | WithdrawRib | Withdraw | Originate | Down | Up | Degrade | Restart | SetPreference | Prepend | SetExport | SoftReset
           | Expect | UntilStable | Repeat | float | list["Step"] | None) = None

    @model_validator(mode="before")
    @classmethod
    def parse(cls, value):
        if isinstance(value, dict) and set(value) - {"kind", "args"}:
            if len(value) != 1:
                raise ValueError(f"a step has exactly one kind, got {sorted(value)}")
            (kind, args), = value.items()
            if kind not in KINDS:
                raise ValueError(f"unknown step {kind!r}; steps are {', '.join(KINDS)}")
            if kind == "wait":
                args = float(args)
            elif kind == "parallel":
                if not args:
                    raise ValueError("a parallel group needs steps")
                args = [Step.model_validate(s) for s in args]
            else:
                args = ARGS[kind].model_validate(args or {})
            return {"kind": kind, "args": args}
        return value

    def dump(self) -> dict:
        if self.kind == "wait":
            return {"wait": self.args}
        if self.kind == "parallel":
            return {"parallel": [s.dump() for s in self.args]}
        data = self.args.model_dump(by_alias=True, exclude_defaults=True)
        if self.kind == "repeat":
            data = {"times": self.args.times, "every": self.args.every, **data, "steps": [s.dump() for s in self.args.steps]}
        return {self.kind: data}


Repeat.model_rebuild()


PARAM = re.compile(r"[a-z][a-z0-9_]*")


def _is_ref(value) -> bool:
    return isinstance(value, str) and value.startswith("$")


def _resolve(steps: list, params: dict, refs: dict, used: set, prefix: str = "") -> list:
    """The steps with every $name replaced by the value of its parameter;
    refs records where each stood, by path (0, 11.0) and argument."""
    out = []
    for i, step in enumerate(steps):
        if not (isinstance(step, dict) and len(step) == 1):
            out.append(step)  # the validation of the step says what is wrong
            continue
        (kind, args), = step.items()
        path = f"{prefix}{i}"
        if kind == "parallel" and isinstance(args, list):
            args = _resolve(args, params, refs, used, path + ".")
        elif kind == "repeat" and isinstance(args, dict):
            args = {**args, "steps": _resolve(args.get("steps") or [], params, refs, used, path + ".")}
        items = {"seconds": args} if kind == "wait" else args if isinstance(args, dict) else {}
        for arg, value in list(items.items()):
            if _is_ref(value):
                name = value[1:]
                if name not in params:
                    raise ValueError(f"step {_number(path)} uses ${name}, which is no parameter of the scenario")
                refs.setdefault(path, {})[arg] = name
                used.add(name)
                items[arg] = params[name]
        out.append({kind: items["seconds"] if kind == "wait" else items if isinstance(args, dict) else args})
    return out


def _number(path: str) -> str:
    """A path as the editor counts steps, from 1."""
    return ".".join(str(int(p) + 1) for p in path.split("."))


def _overlay(steps: list[dict], refs: dict, prefix: str = "") -> list[dict]:
    """Dumped steps with the $name of each parameter back where it stood."""
    out = []
    for i, step in enumerate(steps):
        (kind, args), = step.items()
        path = f"{prefix}{i}"
        if kind == "parallel":
            args = _overlay(args, refs, path + ".")
        elif kind == "repeat":
            args = {**args, "steps": _overlay(args["steps"], refs, path + ".")}
        if path in refs:
            args = f"${refs[path]['seconds']}" if kind == "wait" else {**args, **{a: f"${p}" for a, p in refs[path].items()}}
        out.append({kind: args})
    return out


class Scenario(Model):
    """Steps to play. Numbers of steps may name a parameter, $name, whose
    value params holds: the value it runs with, unless a sweep sets others."""

    name: str
    description: str = ""
    params: dict[str, float] = {}
    steps: list[Step] = Field(min_length=1)
    refs: dict[str, dict[str, str]] = Field(default_factory=dict, exclude=True)  # path -> argument -> parameter

    @model_validator(mode="before")
    @classmethod
    def resolve(cls, data):
        if not isinstance(data, dict) or not isinstance(data.get("steps"), list):
            return data
        params = data.get("params") or {}
        for name, value in params.items():
            if not PARAM.fullmatch(str(name)):
                raise ValueError(f"parameter {name!r}: lowercase letters, digits and _, from a letter")
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValueError(f"parameter {name} needs a number")
        refs, used = {}, set()
        steps = _resolve(copy.deepcopy(data["steps"]), params, refs, used)
        if unused := sorted(set(params) - used):
            raise ValueError(f"no step uses the parameter {', '.join(unused)}")
        return {**data, "params": params, "steps": steps, "refs": refs}

    def dump(self) -> dict:
        steps = _overlay([s.dump() for s in self.steps], self.refs)
        return {"name": self.name, "description": self.description, **({"params": self.params} if self.params else {}), "steps": steps}

    def duration(self) -> float:
        """Expected duration in seconds, taking until_stable as its timeout's third."""
        return max((r["end"] for r in timeline(self.steps)), default=0.0)


def to_yaml(s: Scenario) -> str:
    """Writes a scenario with one step per line, nested steps indented."""
    def value(x) -> str:
        if isinstance(x, dict):
            return "{" + ", ".join(f"{k}: {value(v)}" for k, v in x.items()) + "}"
        if isinstance(x, float) and x.is_integer():
            return str(int(x))
        return _scalar(x)

    def steps(items: list[dict], indent: str) -> list[str]:
        lines = []
        for step in items:
            (kind, args), = step.items()
            if kind == "wait":
                lines.append(f"{indent}- wait: {value(args)}")
            elif kind == "parallel":
                lines.append(f"{indent}- parallel:")
                lines += steps(args, indent + "    ")
            elif kind == "repeat":
                lines += [f"{indent}- repeat:", f"{indent}    times: {value(args['times'])}", f"{indent}    every: {value(args['every'])}", f"{indent}    steps:"]
                lines += steps(args["steps"], indent + "      ")
            else:
                lines.append(f"{indent}- {kind}: {value(args)}")
        return lines

    data = s.dump()  # with the $name of each parameter where it stands
    head = [f"name: {s.name}"] + ([f"description: {_scalar(s.description)}"] if s.description else [])
    head += [f"params: {value(s.params)}"] if s.params else []
    return "\n".join(head + ["steps:"] + steps(data["steps"], "  ")) + "\n"


def path(name: str) -> Path:
    return file_of(DIRECTORY, name)


def names() -> list[str]:
    return names_in(DIRECTORY)


def load(name: str) -> Scenario:
    return parse(load_yaml(path(name).read_text()))


# Sweeps: a scenario once for every value of one of its parameters, named
# like fill-30@rate=5.

CASE = "@"


def case_name(base: str, param: str, value: float) -> str:
    return f"{base}{CASE}{param}={value:g}"


def split_case(name: str) -> tuple[str, str | None, float | None]:
    """The scenario of a case, and the parameter and value of its sweep, if any."""
    base, _, rest = name.partition(CASE)
    if not rest:
        return name, None, None
    param, _, value = rest.partition("=")
    return base, param, float(value)


def with_param(sc: Scenario, param: str, value: float, name: str) -> Scenario:
    """The scenario with a parameter set to a value, under the name of its case."""
    data = sc.dump()
    return parse({**data, "name": name, "params": {**data.get("params", {}), param: value}})


def parse(data: dict) -> Scenario:
    return Scenario.model_validate(data)


# Resolving targets on a topology


def rng(seed: int, index: int, position: tuple) -> random.Random:
    """The random source of a step: the same for every variant and repetition of a run."""
    return random.Random(f"{seed}/{index}/{'.'.join(map(str, position))}")


def distance_km(a: dict, b: dict) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (a["lat"], a["lon"], b["lat"], b["lon"]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(h))


class Network:
    """The routers, links and roles of a topology, for resolving targets."""

    def __init__(self, routers: dict, roles: dict) -> None:
        self.routers = routers
        self.roles = roles
        self.links = sorted({tuple(sorted((a, n["name"]))) for a, r in routers.items() for n in r.get("neighbors", [])})

    def routers_of(self, name: str, random_: random.Random, count: int = 1, exclude: tuple = ()) -> list[str]:
        if name == "all" and name not in self.routers:
            return sorted(self.routers)
        if name == "random":
            pool = sorted(set(self.routers) - set(exclude))
            return sorted(random_.sample(pool, min(count, len(pool))))
        if name in self.roles:
            return list(self.roles[name])
        if name in self.routers:
            return [name]
        raise ValueError(f"unknown router or role {name!r}")

    def links_of(self, name: str, random_: random.Random, count: int = 1, exclude: tuple = ()) -> list[tuple[str, str]]:
        if name == "random":
            pool = [link for link in self.links if not set(link) & set(exclude)]
            return sorted(random_.sample(pool, min(count, len(pool))))
        # Router names may contain dashes themselves.
        for i in [i for i, c in enumerate(name) if c == "-"]:
            link = tuple(sorted((name[:i], name[i + 1:])))
            if link in self.links:
                return [link]
        raise ValueError(f"unknown link {name!r}")

    def region(self, around: str, radius_km: float) -> list[str]:
        center = self.routers[around].get("location")
        if not center:
            raise ValueError("regions need locations for the routers")
        return sorted(r for r, cfg in self.routers.items() if cfg.get("location") and distance_km(center, cfg["location"]) <= radius_km)

    def targets(self, kind: str, args, random_: random.Random) -> tuple[list[str], list[tuple[str, str]]]:
        """The routers and links a step acts on, as the runner and the preview resolve them.

        A Local Preference or an export filter is set at the first router,
        for routes from or to the other end of its link. Raises ValueError or KeyError for targets the
        topology does not have.
        """
        origins = tuple(self.roles.get("origins", []))
        if kind in ("announce", "announce_real", "announce_rib", "withdraw_rib", "withdraw", "prepend"):
            return self.routers_of(args.router, random_), []
        if kind == "replay":
            return sorted(self.routers), []
        if kind in ("originate", "restart"):
            return self.routers_of(args.router, random_, exclude=origins), []
        if kind in ("set_preference", "set_export"):
            router = self.routers_of(args.router, random_, exclude=origins)[0]
            neighbors = sorted(n["name"] for n in self.routers[router].get("neighbors", []))
            neighbor = random_.choice(neighbors) if args.neighbor == "random" else args.neighbor
            if neighbor not in neighbors:
                raise ValueError(f"{neighbor} is not a neighbor of {router}")
            return [router], [(router, neighbor)]
        if kind == "soft_reset":
            return self.routers_of(args.router, random_), []
        if kind == "expect":
            routers = self.routers_of(args.router, random_, exclude=origins)
            for r in routers:
                if args.via and args.via not in {n["name"] for n in self.routers[r].get("neighbors", [])}:
                    raise ValueError(f"{args.via} is not a neighbor of {r}")
            if args.avoid and args.avoid not in self.routers:
                raise ValueError(f"unknown router {args.avoid!r}")
            return routers, []
        if kind in ("down", "up", "degrade"):
            return self.resolve(args, random_)
        return [], []

    def resolve(self, t: Targets, random_: random.Random) -> tuple[list[str], list[tuple[str, str]]]:
        """Returns the routers and links a step acts on. Random choices never hit the origins."""
        origins = tuple(self.roles.get("origins", []))
        if t.router is not None:
            return self.routers_of(t.router, random_, t.count, origins), []
        if t.link is not None:
            return [], self.links_of(t.link, random_, t.count, origins)
        if t.region is not None:
            return self.region(t.region["around"], t.region["radius_km"]), []
        if t.cut is not None:
            inside = set(self.region(t.cut["around"], t.cut["radius_km"]))
            return [], [link for link in self.links if len(inside & set(link)) == 1]
        return [], []


# Previews for the editor


def timeline(steps: list[Step]) -> list[dict]:
    """When each step runs, by its position: [{path, kind, start, end, estimate}].

    until_stable is shown with a third of its timeout, the rest as estimate;
    repeated steps are shown for their first repetition.
    """
    rows = []

    def one(step: Step, t: float, path: tuple) -> float:
        row = {"path": list(path), "kind": step.kind, "start": t}
        rows.append(row)
        if step.kind == "wait":
            t += step.args
        elif step.kind == "announce":
            t += step.args.for_
        elif step.kind == "replay":
            t += step.args.minutes * 60 / step.args.speed
        elif step.kind == "announce_rib":
            row["estimate"] = t + step.args.timeout
            t += step.args.timeout / 6
        elif step.kind == "until_stable":
            row["estimate"] = t + step.args.timeout
            t += step.args.timeout / 3
        elif step.kind == "parallel":
            t = max([one(c, t, path + (j,)) for j, c in enumerate(step.args)] or [t])
        elif step.kind == "repeat":
            once = walk(step.args.steps, t, path) - t
            t += step.args.times * max(step.args.every, once)
        row["end"] = t
        return t

    def walk(items: list[Step], t: float, prefix: tuple) -> float:
        for i, step in enumerate(items):
            t = one(step, t, prefix + (i,))
        return t

    walk(steps, 0.0, ())
    return rows


def each_step(steps: list[Step]):
    """Every step, also those in parallel and repeat groups."""
    for step in steps:
        yield step
        if step.kind == "parallel":
            yield from each_step(step.args)
        elif step.kind == "repeat":
            yield from each_step(step.args.steps)


def preview_targets(steps: list[Step], network: Network, seed: int, index: int = 1) -> dict[str, dict]:
    """What each step acts on in a run, resolved as the runner does: {path: {routers, links}}."""
    out = {}

    def walk(items: list[Step], prefix: tuple, rng_prefix: tuple) -> None:
        for i, step in enumerate(items):
            path, position = prefix + (i,), rng_prefix + (i,)
            a = step.args
            try:
                routers, links = network.targets(step.kind, a, rng(seed, index, position))
                links = [tuple(sorted(link)) for link in links]
            except (ValueError, KeyError, IndexError) as e:
                out[".".join(map(str, path))] = {"error": str(e)}
                continue
            if routers or links:
                out[".".join(map(str, path))] = {"routers": routers, "links": [list(link) for link in links]}
            if step.kind == "parallel":
                walk(a, path, position)
            elif step.kind == "repeat":
                walk(a.steps, path, position + ("repeat",))

    walk(steps, (), ())
    return out
