"""Groups of the three main views: experiments, scenarios and topologies.

An item's own group follows from what it is: an experiment from its name, a
topology from its source, a scenario from the experiments that play it.
In the web interface an item can move to another group, and a group can be
renamed, which also takes the items that would come into it later, e.g. a
new import from SNDlib. Both are kept in the settings of this installation,
so that they change no file of the repository, whose local changes would
block updates. Names of groups compare without case, so that a group of
the same name is the same group, and a group without items is no group.
"""

import json
import re

from .. import config

KINDS = ("experiments", "scenarios", "topologies")
OTHER = "Other"
ORDER = {
    "experiments": ["Paper", "Behaviour", "Semantics", "Internet", "Lab"],
    "scenarios": ["Paper", "Behaviour", "Semantics", "Internet", "Lab", "Unused"],
    "topologies": ["Hand-made", "SNDlib", "CAIDA", "Simulator", "Generated"],
}
PREFIX = {"ifip": "Paper", "behaviour": "Behaviour", "semantics": "Semantics", "internet": "Internet", "lab": "Lab"}
SOURCE = {"sndlib": "SNDlib", "caida": "CAIDA", "obgp-sim": "Simulator", "generated": "Generated"}
NAME = re.compile(r"[^\s].{0,38}[^\s]|[^\s]")


def of_experiment(name: str) -> str:
    return PREFIX.get(name.split("-")[0], OTHER)


def of_topology(source: str | None) -> str:
    return SOURCE.get(source.split("/")[0], OTHER) if source else "Hand-made"


def of_scenario(experiments: list[str]) -> str:
    """The first group, in the order of the view, of the experiments that play it."""
    groups = {of_experiment(e) for e in experiments}
    return next((g for g in ORDER["experiments"] if g in groups), OTHER if groups else "Unused")


def file():
    return config.SETTINGS / "groups.json"


def _load() -> dict:
    """{"items": {kind: {item: group}}, "renamed": {kind: {own group: name}}}"""
    try:
        data = json.loads(file().read_text())
    except (OSError, ValueError):
        data = {}
    return {part: {k: dict(v) for k, v in (data.get(part) or {}).items() if k in KINDS and isinstance(v, dict)}
            for part in ("items", "renamed")}


def _save(data: dict) -> None:
    config.SETTINGS.mkdir(parents=True, exist_ok=True)
    data = {part: {k: v for k, v in kinds.items() if v} for part, kinds in data.items()}
    file().write_text(json.dumps({part: kinds for part, kinds in data.items() if kinds}, indent=2, sort_keys=True) + "\n")


def _name(group: str) -> str:
    group = " ".join(str(group).split())
    if not NAME.fullmatch(group):
        raise ValueError("A group needs a name of 1 to 40 characters.")
    return group


def _known(data: dict, kind: str) -> list[str]:
    """Every name a group of the kind can have now: the own ones, renamed or not, and those items moved to."""
    renamed = data["renamed"].get(kind, {})
    return [renamed.get(g, g) for g in [*ORDER[kind], OTHER]] + list(data["items"].get(kind, {}).values())


def _same(data: dict, kind: str, group: str) -> str:
    """The name of the group as it exists, whatever its case."""
    return next((g for g in _known(data, kind) if g.lower() == group.lower()), group)


def _check(kind: str) -> None:
    if kind not in KINDS:
        raise ValueError(f"no kind {kind}")


def placed(kind: str, name: str, own: str) -> str:
    """The group an item is in now."""
    data = _load()
    return data["items"].get(kind, {}).get(name) or data["renamed"].get(kind, {}).get(own, own)


def move(kind: str, name: str, group: str, own: str) -> str:
    """Moves an item to a group, back to its own one if that is the group.
    Returns the group's name as kept; ValueError if it is no name."""
    _check(kind)
    data = _load()
    group = _same(data, kind, _name(group))
    items = data["items"].setdefault(kind, {})
    if group == data["renamed"].get(kind, {}).get(own, own):
        items.pop(name, None)
    else:
        items[name] = group
    _save(data)
    return group


def rename(kind: str, old: str, new: str) -> str:
    """Renames a group, into another one if that exists: its items go along,
    and so do the items whose own group it is, also those that come later."""
    _check(kind)
    data = _load()
    new = _same(data, kind, _name(new))
    items, renamed = data["items"].setdefault(kind, {}), data["renamed"].setdefault(kind, {})
    for name, group in items.items():
        if group.lower() == old.lower():
            items[name] = new
    for own in {*ORDER[kind], OTHER, *renamed}:
        if renamed.get(own, own).lower() == old.lower():
            renamed[own] = new
    data["renamed"][kind] = {own: g for own, g in renamed.items() if own != g}
    _save(data)
    return new


def follow(kind: str, original: str, name: str, rename: bool, own: str, own_original: str) -> None:
    """An item saved under a new name stays in the group of the original:
    renamed, or as its copy."""
    _check(kind)
    group = placed(kind, original, own_original)
    if rename:
        forget(kind, original)
    if NAME.fullmatch(group):
        move(kind, name, group, own)


def forget(kind: str, name: str) -> None:
    """A deleted item leaves its group."""
    _check(kind)
    data = _load()
    if data["items"].get(kind, {}).pop(name, None) is not None:
        _save(data)


def arrange(kind: str, items: list[dict], names: list[str] | None = None) -> list[dict]:
    """The items in their groups, in the order of the view: the known
    groups first, renamed ones where they were, others by name, Other
    last, and in each group by name. Each item gets
    its group. With the names of every item there is, the groups forget
    those that are gone, e.g. deleted outside the web interface."""
    data = _load()
    there, renamed = data["items"].get(kind, {}), data["renamed"].get(kind, {})
    if names is not None and (gone := set(there) - set(names)):
        for name in gone:
            there.pop(name)
        _save(data)
    groups: dict[str, list[dict]] = {}
    for item in items:
        own = item.get("own") or OTHER
        item["group"] = there.get(item["name"]) or renamed.get(own, own)
        groups.setdefault(item["group"], []).append(item)
    place = {renamed.get(g, g): i for i, g in enumerate(ORDER[kind])}
    other = renamed.get(OTHER, OTHER)
    rank = lambda g: (0, place[g], "") if g in place else (2, 0, "") if g == other else (1, 0, g.lower())
    return [{"name": g, "items": sorted(groups[g], key=lambda item: item["name"])} for g in sorted(groups, key=rank)]
