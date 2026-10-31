"""Modes of the daemon: how a router selects and exports paths.

A pure mode is a set of environment variables of gobgpd that every router
gets. A mixed mode runs a pure mode on some routers and BGP on the others,
for partial deployment: hybrids on the routers the topology marks with
obgp: true, random ones on a share of the routers, drawn anew for every
run. A new mode of the daemon is one entry here. requires names capability
variables a daemon must read, VARIABLE=value also a value it must know; an
older daemon would silently ignore them and run another mode.
"""

import random
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Mode:
    name: str
    label: str
    description: str
    env: dict[str, str] = field(default_factory=dict)
    requires: tuple[str, ...] = ()
    obgp: bool = False
    # Mixed modes: the pure mode of the chosen routers, and how they are chosen.
    inner: str | None = None
    pick: str | None = None  # "topology" or "random"

    @property
    def pure(self) -> list[str]:
        """The pure modes the routers of this mode run."""
        return [self.name] if self.inner is None else ["bgp", self.inner]


# obgp-rp, obgp-sp, obgp-hp and obgp-np share native iBGP, AS_SET ordered
# canonically, confederation hops counted and a transparent route server, and
# differ only in pruning: refresh, soft, hard or none. obgp-paper is the
# paper's code: hard pruning, iBGP filtered, AS_SET as received, confederation
# hops ignored, a route server admitting.
# Each runs pure, in hybrids and on random routers. A daemon before
# native iBGP reads none of this right but the paper's, which it runs whatever
# the variables say. A fix of the built modes needs no new requirement: an
# older daemon runs them as they were built at its commit, which a variant's
# ref names.
BUILT = {"GOBGP_OPERA_ENABLED": "true", "GOBGP_OPERA_IBGP": "native", "GOBGP_OPERA_AS_SET": "canonical",
         "GOBGP_OPERA_CONFED": "count", "GOBGP_OPERA_RS": "transparent"}
NATIVE = ("GOBGP_OPERA_IBGP=filter",)  # daemons that know filter default to native iBGP
VARIANTS = {
    "-rp": (" with refresh pruning", "refresh pruning, native iBGP, AS_SET ordered canonically, confederation hops counted", {**BUILT, "GOBGP_OPERA_PRUNING": "refresh"},
            (*NATIVE, "GOBGP_OPERA_REFRESH_S")),
    "-sp": (" with soft pruning", "soft pruning, native iBGP, AS_SET ordered canonically, confederation hops counted", {**BUILT, "GOBGP_OPERA_PRUNING": "soft"}, NATIVE),
    "-hp": (" with hard pruning", "hard pruning, native iBGP, AS_SET ordered canonically, confederation hops counted",
            {**BUILT, "GOBGP_OPERA_PRUNING": "hard"}, NATIVE),
    "-np": (" without pruning", "no pruning, native iBGP, AS_SET ordered canonically, confederation hops counted", {**BUILT, "GOBGP_OPERA_PRUNING": "false"}, NATIVE),
    "-paper": (" as in the paper", "hard pruning, iBGP filtered, AS_SET as received, confederation hops ignored, the paper's code",
               {"GOBGP_OPERA_ENABLED": "true", "GOBGP_OPERA_PRUNING": "hard", "GOBGP_OPERA_IBGP": "filter",
                "GOBGP_OPERA_AS_SET": "received", "GOBGP_OPERA_CONFED": "ignore", "GOBGP_OPERA_RS": "admit"}, ()),
}

MODES = {
    m.name: m
    for m in [
        Mode("bgp", "BGP", "GoBGP's standard path selection", {"GOBGP_OPERA_ENABLED": "false"}),
        *[m for suffix, (label, what, env, requires) in VARIANTS.items() for m in (
            Mode(f"obgp{suffix}", f"OBGP{label}", f"OBGP, {what}", env, requires=requires, obgp=True),
            Mode(f"hybrid{suffix}", f"Hybrid{label}", f"OBGP{label} on the routers the topology marks, BGP on the others",
                 obgp=True, inner=f"obgp{suffix}", pick="topology"),
            Mode(f"random{suffix}", f"Random{label}", f"OBGP{label} on a share of the routers, drawn for every run, BGP on the others",
                 obgp=True, inner=f"obgp{suffix}", pick="random"),
        )],
    ]
}

# Names in older results: until 2026-10-18 "obgp" was soft pruning and
# "-hard" hard pruning, before that "-soft" soft pruning.
RENAMED = {f"{kind}{old}": f"{kind}{new}" for kind in ("obgp", "hybrid", "random")
           for old, new in (("", "-sp"), ("-soft", "-sp"), ("-hard", "-hp"))} | {"obgp-ibgp": "obgp-sp"}


def may_fail(allowed: list[str], name: str, per_neighbor: bool = False) -> bool:
    """Whether a check that names the pure modes allowed to fail it may fail
    in this mode: in a pure mode listed, or a mixed mode of one. With a table
    per neighbor the mode must be listed with -pn: tables per neighbor
    are there to keep what one table loses."""
    pure = get(name).inner or name
    # Only OBGP with one of the pruning modes keeps tables per neighbor; BGP and the paper's OBGP keep one table.
    suffix = "-pn" if per_neighbor and pure not in ("bgp", "obgp-paper") else ""
    return f"{name}{suffix}" in allowed or (get(name).inner is not None and f"{get(name).inner}{suffix}" in allowed)


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
