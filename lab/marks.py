"""Stars and notes on objects of the lab: results, searches of the simulator
and their cases, and notes on any other page by its path. A star puts an object first in its list, a note says why or
what is still to do. Neither changes a measurement or a verdict.

Both are kept in the settings of this installation, for everyone of the lab,
so that they change no file of the repository. A note names no author, of a
person or an agent alike. An object deleted takes its marks along, a search
those of its cases as well. Marks stay out of downloads unless asked for.
"""

import contextlib
import fcntl
import json
import secrets
import threading
from datetime import UTC, datetime

from . import config
from .config import write_atomic

KINDS = ("result", "search", "case", "page")  # page: any other page of the lab, by its path
TEXT_MAX = 2000  # characters of a note
COLORS = ("yellow", "pink", "blue", "violet", "orange")  # of a slip, to tell notes apart; done ones are green
NOTES_MAX = 100  # notes of one object

_lock = threading.Lock()


def file():
    return config.SETTINGS / "marks.json"


@contextlib.contextmanager
def _locked():
    """One writer at a time, of the web, MCP and the command line alike."""
    file().parent.mkdir(parents=True, exist_ok=True)
    with _lock, open(file().with_suffix(".lock"), "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def _load() -> dict:
    """{kind: {name: {"star": bool, "notes": [note]}}}"""
    try:
        data = json.loads(file().read_text())
    except (OSError, ValueError):
        data = {}
    return {k: {n: m for n, m in (data.get(k) or {}).items() if isinstance(m, dict)} for k in KINDS}


def _save(data: dict) -> None:
    kept = {k: {n: m for n, m in names.items() if m.get("star") or m.get("notes")} for k, names in data.items()}
    write_atomic(file(), json.dumps({k: v for k, v in kept.items() if v}, indent=2, sort_keys=True) + "\n")


def _check(kind: str) -> None:
    if kind not in KINDS:
        raise ValueError(f"Marks are on {', '.join(KINDS)}.")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def resolve(kind: str, name: str) -> str:
    """The name an object is marked under, once it is known to exist: a finding of a case names its case."""
    from . import simulation
    from .results import Dataset

    _check(kind)
    if kind == "page":
        path = name.split("?")[0].split("#")[0]
        if not path.startswith("/") or path.startswith("//") or len(path) > 200:
            raise LookupError(f"No page {name}, name it by its path.")
        return path
    if kind == "result":
        if Dataset.find(name) is None:
            raise LookupError(f"No result {name}.")
        return name
    if kind == "search":
        simulation.search(name)  # LookupError when there is none
        return name
    search, _, case = name.partition("/")
    if not case.isdigit() or (found := simulation.case_of(simulation.search(search), int(case))) is None:
        raise LookupError(f"No case {name}, name it search/case.")
    return f"{search}/{found['case']['id']}"


def of(kind: str, name: str) -> dict:
    """The star and the notes of one object, the open notes first, each in the order written."""
    _check(kind)
    m = _load()[kind].get(name, {})
    notes = sorted(m.get("notes", []), key=lambda n: (n.get("done", False), n["created"]))
    return {"star": bool(m.get("star")), "notes": notes}


def starred(kind: str) -> set[str]:
    _check(kind)
    return {n for n, m in _load()[kind].items() if m.get("star")}


def counts(kind: str) -> dict[str, int]:
    """The open notes per object of a kind, for its list."""
    _check(kind)
    return {n: c for n, m in _load()[kind].items() if (c := sum(not x.get("done") for x in m.get("notes", [])))}


def everything() -> dict:
    """Every starred object and every object with notes, by kind."""
    return {k: {n: of(k, n) for n in names} for k, names in _load().items() if names}


def star(kind: str, name: str, on: bool) -> bool:
    _check(kind)
    with _locked():
        data = _load()
        data[kind].setdefault(name, {})["star"] = bool(on)
        _save(data)
    return bool(on)


def _text(text: str) -> str:
    text = (text or "").strip()
    if not text:
        raise ValueError("A note needs a text.")
    if len(text) > TEXT_MAX:
        raise ValueError(f"A note holds at most {TEXT_MAX:,} characters.")
    return text


def _color(color: str | None) -> str:
    if color not in (None, "", *COLORS):
        raise ValueError(f"Colours are {', '.join(COLORS)}.")
    return color or COLORS[0]


def add(kind: str, name: str, text: str, color: str | None = None) -> dict:
    """A new note on an object, open, yellow unless a colour is given."""
    _check(kind)
    note = {"id": secrets.token_hex(4), "text": _text(text), "created": _now(), "done": False, "color": _color(color)}
    with _locked():
        data = _load()
        notes = data[kind].setdefault(name, {}).setdefault("notes", [])
        if len(notes) >= NOTES_MAX:
            raise ValueError(f"An object holds at most {NOTES_MAX} notes.")
        notes.append(note)
        _save(data)
    return {**note, "kind": kind, "name": name}


def _find(data: dict, note_id: str) -> tuple[str, str, dict]:
    for kind, names in data.items():
        for name, m in names.items():
            for note in m.get("notes", []):
                if note["id"] == note_id:
                    return kind, name, note
    raise LookupError(f"No note {note_id}.")


def edit(note_id: str, text: str | None = None, done: bool | None = None, color: str | None = None) -> dict:
    """Changes the text of a note, whether it is done, or its colour."""
    with _locked():
        data = _load()
        kind, name, note = _find(data, note_id)
        if text is not None:
            note["text"], note["edited"] = _text(text), _now()
        if done is not None:
            note["done"] = bool(done)
        if color:
            note["color"] = _color(color)
        _save(data)
    return {**note, "kind": kind, "name": name}


def delete(note_id: str) -> dict:
    with _locked():
        data = _load()
        kind, name, note = _find(data, note_id)
        data[kind][name]["notes"].remove(note)
        _save(data)
    return {"deleted": note_id, "kind": kind, "name": name}


def bulk(action: str, notes: list[str], objects: list[tuple[str, str]]) -> int:
    """One action on many at once, in one write: done or open again for notes, delete for notes and the stars of
    objects, unstar for objects. Tells on how many it acted."""
    if action not in ("done", "open", "delete", "unstar"):
        raise ValueError("Actions are done, open, delete and unstar.")
    chosen, acted = set(notes), 0
    with _locked():
        data = _load()
        for kind, names in data.items():
            for name, m in names.items():
                if (kind, name) in objects and action in ("delete", "unstar") and m.get("star"):
                    m["star"], acted = False, acted + 1
                for note in m.get("notes", []):
                    if note["id"] in chosen and action in ("done", "open"):
                        note["done"], acted = action == "done", acted + 1
                if action == "delete":
                    kept = [x for x in m.get("notes", []) if x["id"] not in chosen]
                    acted += len(m.get("notes", [])) - len(kept)
                    m["notes"] = kept
        _save(data)
    return acted


def clear_done() -> int:
    """Deletes every done note of the lab, and tells how many."""
    with _locked():
        data = _load()
        gone = 0
        for names in data.values():
            for m in names.values():
                before = len(m.get("notes", []))
                m["notes"] = [n for n in m.get("notes", []) if not n.get("done")]
                gone += before - len(m["notes"])
        _save(data)
    return gone


def forget(kind: str, name: str) -> None:
    """An object is gone, and its marks with it: a search takes those of its cases."""
    _check(kind)
    with _locked():
        data = _load()
        data[kind].pop(name, None)
        if kind == "search":
            data["case"] = {n: m for n, m in data["case"].items() if n.split("/")[0] != name}
        _save(data)


def rename(kind: str, old: str, new: str) -> None:
    """An object renamed keeps its marks."""
    _check(kind)
    with _locked():
        data = _load()
        if old in data[kind]:
            data[kind][new] = data[kind].pop(old)
            _save(data)


def migrate() -> None:
    """Takes the stars of cases from where the simulation kept them before, once."""
    old = config.SETTINGS / "simulation" / "stars.json"
    try:
        stars = json.loads(old.read_text())
    except (OSError, ValueError):
        return
    with _locked():
        data = _load()
        for search, cases in (stars.items() if isinstance(stars, dict) else []):
            for case in cases if isinstance(cases, list) else []:
                data["case"].setdefault(f"{search}/{case}", {})["star"] = True
        _save(data)
    old.unlink(missing_ok=True)
