"""Modes of the daemon: how a router selects and exports paths.

A pure mode is a set of environment variables of gobgpd that every router
gets. A mixed mode runs a pure mode on some routers and BGP on the others,
for partial deployment: hybrids on the routers the topology marks with
obgp: true, random ones on a share of the routers, drawn anew for every
run. A new mode of the daemon is one entry here. since is the first
commit whose daemon knows a mode; an older one would ignore its variables
and run another mode.
"""

import random
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Mode:
    name: str
    label: str
    description: str
    env: dict[str, str] = field(default_factory=dict)
    since: str | None = None
    obgp: bool = False
    # Mixed modes: the pure mode of the chosen routers, and how they are chosen.
    inner: str | None = None
    pick: str | None = None  # "topology" or "random"

    @property
    def pure(self) -> list[str]:
        """The pure modes the routers of this mode run."""
        return [self.name] if self.inner is None else ["bgp", self.inner]


MODES = {
    m.name: m
    for m in [
        Mode("bgp", "BGP", "GoBGP's standard path selection", {"GOBGP_OPERA_ENABLED": "false"}),
        Mode("obgp", "OBGP", "The original design, with superset pruning",
             {"GOBGP_OPERA_ENABLED": "true", "GOBGP_OPERA_PRUNING": "true"}, obgp=True),
        Mode("obgp-np", "OBGP without pruning", "OBGP without superset pruning, a derivative of the original design",
             {"GOBGP_OPERA_ENABLED": "true", "GOBGP_OPERA_PRUNING": "false"}, since="684dd3d5", obgp=True),
        Mode("hybrid", "Hybrid", "OBGP on the routers the topology marks, BGP on the others",
             obgp=True, inner="obgp", pick="topology"),
        Mode("hybrid-np", "Hybrid without pruning", "OBGP without pruning on the routers the topology marks, BGP on the others",
             obgp=True, inner="obgp-np", pick="topology"),
        Mode("random", "Random", "OBGP on a share of the routers, drawn for every run, BGP on the others",
             obgp=True, inner="obgp", pick="random"),
        Mode("random-np", "Random without pruning", "OBGP without pruning on a share of the routers, drawn for every run, BGP on the others",
             obgp=True, inner="obgp-np", pick="random"),
    ]
}


def get(name: str) -> Mode:
    try:
        return MODES[name]
    except KeyError:
        raise ValueError(f"unknown mode {name!r}, known: {', '.join(MODES)}") from None


def assign(name: str, routers: dict, share: float | None = None, seed: int = 0) -> dict[str, str]:
    """The pure mode of every router of a topology. Random modes draw with
    the seed of the run, so all variants of a run get the same routers."""
    mode = get(name)
    if mode.pick is None:
        return dict.fromkeys(routers, name)
    if mode.pick == "topology":
        chosen = {r for r, cfg in routers.items() if cfg.get("obgp")}
        if not chosen:
            raise ValueError("the topology marks no router to run OBGP in hybrids")
    else:
        names = sorted(routers)
        chosen = set(random.Random(f"{seed}/modes").sample(names, round((share or 0) * len(names))))
    return {r: mode.inner if r in chosen else "bgp" for r in routers}
