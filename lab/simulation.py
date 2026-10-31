"""Searches of the simulator, kept for the Simulation area: started from the
web interface, an agent or the command line, run in the background one at a
time and at the lowest priority, each with its parameters, state and
findings, and the replays of its findings kept beside it."""

import contextlib
import fcntl
import json
import os
import shutil
import signal
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import config, simulate
from .results import queue_file, queued, write_atomic

FAMILIES = ("withdraw", "link-down", "gao-rexford", "partial-transit", "siblings", "aggregation", "communities", "tagging",
            "poison", "export-filter", "as-path-filter", "prepend", "import-filter", "local-pref", "ibgp-mesh", "ibgp-rr",
            "med-rr", "confed", "route-server", "route-leak")
MODES = ("bgp", "obgp-rp", "obgp-sp", "obgp-hp", "obgp-np", "obgp-paper", "obgp-rp-pn", "obgp-sp-pn", "obgp-hp-pn", "obgp-np-pn")
ROUTERS = (2, 3, 4, 5)  # every connected topology up to this many routers
SEEDS = range(1, 11)    # orders of messages per network

_lock = threading.Lock()


def folder() -> Path:
    return config.SETTINGS / "simulation" / "searches"


def _path(search_id: str) -> Path:
    if not (search_id.isascii() and search_id.isdigit()):
        raise LookupError(f"No search {search_id}.")
    return folder() / f"{search_id}.json"


def _read(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _put(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(path)


def _write(entry: dict) -> None:
    _put(_path(entry["id"]), entry)


@contextlib.contextmanager
def _exclusive():
    """One search starts at a time, across the web server and the command line."""
    folder().mkdir(parents=True, exist_ok=True)
    with _lock, open(folder() / ".lock", "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


_entry_lock = threading.Lock()


def _change(search_id: str, how) -> dict:
    """Changes an entry, read and written under a lock across processes:
    how gets the entry as it is and returns the changes, or None for none."""
    folder().mkdir(parents=True, exist_ok=True)
    with _entry_lock, open(folder() / ".entries.lock", "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        entry = _read(_path(search_id)) or {}
        if (changes := how(entry)) is None:
            return entry
        entry = {**entry, **changes}
        _write(entry)
    return entry


def _update(search_id: str, **changes) -> dict:
    """Changes an entry. A stop between the worker's read and write of its progress is kept."""
    stale = lambda entry: "progress" in changes and "state" not in changes and entry.get("state") != "running"
    return _change(search_id, lambda entry: None if stale(entry) else changes)


def requeue(search_id: str) -> dict:
    """A running search a pause stops: queued again, its worker ended on purpose."""
    return _update(search_id, state="queued", group=None, progress=None)


DEATHS = 2  # a worker that dies this often fails its search, else the queue would start it again and again


def died(search_id: str, why: str, state: str = "running", pid: int | None = None) -> dict:
    """A worker of a search ended without finishing it. Queued again while
    it is in the lab's queue, until the worker died DEATHS times. Counted
    once, under the lock, only while the entry still is in state and, with
    pid, was not taken up by that process: a worker that began and died is
    counted where its search is found running, not again when it ended."""
    waiting = queue_name(search_id) in queued()

    def how(entry: dict) -> dict | None:
        if entry.get("state") != state or (pid is not None and entry.get("pid") == pid):
            return None
        deaths = entry.get("deaths", 0) + 1
        again = waiting and deaths < DEATHS
        return {"deaths": deaths, "died": why, "group": None, "progress": None,
                **({"state": "queued"} if again else {"state": "failed", "error": f"{why}, {deaths} times" if deaths > 1 else why})}
    return _change(search_id, how)


def _born(pid: int | None) -> int | None:
    """When a process started, in clock ticks since boot, so that a reused
    process id is not taken for the process that ran a search."""
    try:
        return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])
    except (OSError, ValueError, IndexError, TypeError):
        return None


def _same(pid: int | None, born: int | None) -> bool:
    return bool(pid) and born is not None and _born(pid) == born


def _alive(entry: dict) -> dict:
    """A search runs while the process that runs it does. Once that process
    ended, a simulator it left behind is stopped, if it is still the same
    process, and the search is queued again if it still is in the lab's
    queue, as a result whose worker vanished, else it failed. See died."""
    if entry.get("state") == "running" and not _same(entry.get("pid"), entry.get("born")):
        _kill(entry.get("group"), entry.get("group_born"))
        entry = died(entry["id"], "the process that ran it stopped")
    return entry


def _kill(group: int | None, born: int | None) -> None:
    if _same(group, born):
        try:
            os.killpg(group, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass


def check(routers: int, seeds: int, family: str) -> None:
    if routers not in ROUTERS:
        raise ValueError(f"Routers are {', '.join(map(str, ROUTERS))}.")
    if seeds not in SEEDS:
        raise ValueError(f"Message orders are 1 to {SEEDS[-1]}.")
    if family and family not in FAMILIES:
        raise ValueError(f"Unknown family {family}.")


def running() -> dict | None:
    """The search that runs now, in this process or another."""
    return next((s for s in searches() if s["state"] == "running"), None)


# A search checks everything by default: every family, the way to rest,
# one table and tables per neighbor, on every network up to five routers,
# the most a search finishes in hours. Six routers would take days.
DEFAULT = {"routers": 5, "seeds": 3, "family": "", "transient": True, "tables": "both"}


def queue_name(search_id: str) -> str:
    """The name of a search in the lab's queue, beside the results."""
    return f"sim:{search_id}"


def _new(routers: int, seeds: int, family: str, transient: bool, by: str | None, tables: bool | str = False, state: str = "running") -> dict:
    check(routers, seeds, family)
    if state == "running" and running():
        raise ValueError("A search runs already. Wait until it is done, or stop it.")
    now = datetime.now(timezone.utc)
    return {"id": now.strftime("%Y%m%d%H%M%S%f"), "started": now.isoformat(timespec="seconds"), "by": by,
            "routers": routers, "seeds": seeds, "family": family, "transient": transient, "tables": tables, "state": state,
            **({"pid": os.getpid(), "born": _born(os.getpid())} if state == "running" else {})}


def _finish(entry: dict) -> dict:
    """Runs the search of an entry: one pass per table mode, its progress
    in the entry. With tables "both" the second pass keeps a table per
    neighbor; BGP and the paper's OBGP, the same in both, come from the first."""
    passes = [False, True] if entry.get("tables") == "both" else [bool(entry.get("tables"))]
    last = [0.0]

    def told(k: int):
        def progress(done: int, total: int) -> None:
            share = (k + done / max(1, total)) / len(passes)
            if share - last[0] >= 0.005 or done == total:  # every half percent
                last[0] = share
                _update(entry["id"], progress=round(share, 4), progress_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        return progress
    try:
        found = []
        for k, tables in enumerate(passes):
            more = simulate.search(entry["routers"], entry["seeds"], entry["family"], entry.get("transient", False),
                                   started=lambda pid: _update(entry["id"], group=pid, group_born=_born(pid)), tables=tables, progress=told(k))
            found += [e for e in more if not (k and e["finding"]["mode"] in ("bgp", "obgp-paper"))]
        findings = [{**e, "id": i} for i, e in enumerate(found)]
        changes = {"state": "done", "findings": findings, "problems": len(problems({"findings": findings})), "grouping": GROUPING, "progress": 1.0}
    except Exception as e:  # the simulator failed, timed out or was stopped: the search tells why
        changes = {"state": "failed", "error": str(e)[-300:]}
    changes = {**changes, "finished": datetime.now(timezone.utc).isoformat(timespec="seconds"), "group": None}
    # A person stopped it, whatever the simulator still answered: checked under the lock.
    return _change(entry["id"], lambda now: {**changes, "state": "stopped"} if now.get("state") == "stopped" else changes)


def run(routers: int, seeds: int = 3, family: str = "", transient: bool = False, by: str | None = None, tables: bool | str = False) -> dict:
    """Runs a search now, in this process, and keeps it: the command line."""
    with _exclusive():
        entry = _new(routers, seeds, family, transient, by, tables)
        _write(entry)
    return _finish(entry)


def start(by: str | None = None) -> str:
    """Queues a search in the lab's queue, beside the results: it runs when
    nothing runs before it, in a worker of its own, as a result does, and
    goes on after a restart of the web server."""
    with _exclusive():
        entry = _new(DEFAULT["routers"], DEFAULT["seeds"], DEFAULT["family"], DEFAULT["transient"], by, DEFAULT["tables"], state="queued")
        _write(entry)
        names = queued()
        queue_file().parent.mkdir(parents=True, exist_ok=True)
        write_atomic(queue_file(), json.dumps(names + [queue_name(entry["id"])]))
    return entry["id"]


def execute(search_id: str) -> dict:
    """Runs a queued search in this process: the worker the queue starts."""
    with _exclusive():
        entry = search(search_id)
        if entry["state"] not in ("queued", "running"):
            raise ValueError(f"Search {search_id} is {entry['state']}.")
        entry = _update(search_id, state="running", pid=os.getpid(), born=_born(os.getpid()), progress=0.0,
                        began=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    return _finish(entry)


def _dequeue(search_id: str) -> None:
    with _exclusive():
        write_atomic(queue_file(), json.dumps([n for n in queued() if n != queue_name(search_id)]))


def stop(search_id: str) -> dict:
    """Stops a search, running or queued: it leaves the queue."""
    entry = search(search_id)
    if entry["state"] not in ("running", "queued"):
        raise ValueError(f"Search {search_id} does not run.")
    _dequeue(search_id)
    _update(search_id, state="stopped")
    _kill(entry.get("group"), entry.get("group_born"))
    return {"search": search_id, "state": "stopped"}


def delete(search_id: str) -> dict:
    entry = search(search_id)
    if entry["state"] in ("running", "queued"):
        raise ValueError(f"Search {search_id} {'runs' if entry['state'] == 'running' else 'waits in the queue'}. Stop it first.")
    _path(search_id).unlink(missing_ok=True)
    shutil.rmtree(folder() / search_id, ignore_errors=True)
    return {"deleted": search_id}


GROUPING = 2  # how problems are grouped: a search counted under another grouping is counted again
_summaries: dict[Path, tuple[tuple, dict]] = {}  # per file, its summary while the file stays as it is


def _summary(p: Path) -> dict | None:
    """A search without its findings, read again only when its file changed:
    the queue asks every two seconds, a search done holds many findings."""
    try:
        st = p.stat()
    except OSError:
        return None
    stamp = (st.st_ino, st.st_mtime_ns, st.st_size)  # every write renames a new file into place
    if (hit := _summaries.get(p)) and hit[0] == stamp:
        return dict(hit[1])
    if not (entry := _read(p)):
        return None
    # A search done keeps how many problems it found, older ones and those of another grouping count them now.
    kept = entry.get("problems") if entry.get("grouping") == GROUPING else None
    count = kept if kept is not None else len(problems(entry)) if entry.get("state") == "done" else 0
    summary = {**{k: v for k, v in entry.items() if k != "findings"}, "found": len(entry.get("findings") or []), "problems": count}
    _summaries[p] = (stamp, summary)
    return dict(summary)


def searches() -> list[dict]:
    """Every kept search, the newest first, without its findings."""
    out = []
    for p in sorted(folder().glob("*.json"), reverse=True) if folder().exists() else []:
        if summary := _summary(p):
            if summary.get("state") == "running" and _alive(summary) is not summary:  # its process ended: read it again
                summary = _summary(p) or summary
            out.append(summary)
    return out


KINDS = ("unreachable", "black-hole", "loop", "no-convergence", "leaked", "inconsistent-export",
         "transient-loop", "transient-blocked", "transient-hole")


CLAIMED = ("no-convergence", "loop")  # what Theorems 1 and 2 rule out inside their model
COVERED = MODES[1:6]  # the modes the proofs cover: OBGP with one table
_order = lambda seq, x: seq.index(x) if x in seq else len(seq)


def search(search_id: str) -> dict:
    """One search with its findings, by kind of deviation, then by mode as the lab orders them, then by family."""
    entry = _read(_path(search_id))
    if entry is None:
        raise LookupError(f"No search {search_id}.")
    entry = _alive(entry)
    # Each finding keeps the id it got when the search was stored, so that links and kept replays stay valid.
    entry["findings"] = [{**e, "id": e.get("id", i)} for i, e in enumerate(entry.get("findings") or [])]
    rank = lambda e: (_order(KINDS, e["finding"]["kind"]), _order(MODES, e["finding"]["mode"]), e["instance"].get("family", ""),
                      e["instance"].get("routers", 0), len(e["instance"].get("links", [])))
    entry["findings"] = sorted(entry["findings"], key=rank)
    return entry


def cases(entry: dict) -> list[dict]:
    """The findings of a search as cases: one network, with its order of
    messages, and one kind of deviation, with every mode that shows it
    there and the routers each mode affects. The simulator keeps the
    smallest network of each deviation per mode, so the same network comes
    up several times. Every finding of the network tells the modes, a
    search from before it did names those whose kept network it is. A case
    keeps its first finding's id, and the ids of all."""
    stats = {(e["instance"].get("family"), e["finding"]["mode"], e["finding"]["kind"]): (e.get("count"), e.get("of"))
             for e in entry.get("findings") or []}
    out = {}
    for i, e in enumerate(entry.get("findings") or []):
        kind, net = e["finding"]["kind"], {k: v for k, v in e["instance"].items() if k != "family"}
        c = out.setdefault((kind, json.dumps(net, sort_keys=True)), {
            "id": e.get("id", i), "ids": [], "kind": kind, "instance": e["instance"], "families": [],
            "in_model": e.get("in_model", False), "per_mode": {}})
        c["ids"].append(e.get("id", i))
        family = e["instance"].get("family")
        if family not in c["families"]:
            c["families"].append(family)
        shown = [f for f in e.get("findings") or [] if f["kind"] == kind] or [e["finding"]]
        for f in shown:
            count, of = stats.get((family, f["mode"], kind), (None, None))
            c["per_mode"].setdefault(f["mode"], {"routers": f.get("routers") or [], "count": count, "of": of,
                                                 "cause": cause({**e, "finding": f}, f["mode"])})
    for c in out.values():
        c["modes"] = sorted(c["per_mode"], key=lambda m: _order(MODES, m))
        c["cause"] = " and ".join(sorted({c["per_mode"][m]["cause"] for m in c["modes"]} - {""}))
        c["proof"] = proof(c["kind"], c["in_model"], c["modes"])
    return list(out.values())


def cause(e: dict, mode: str) -> str:
    """What stops a route reaching a router that lacks it at rest, from the
    network and the mode's result: an export or import filter on the
    session, a community, a relation between the routers, or no offer at all. Cases of different causes are
    different problems. Empty where the result does not tell it."""
    if e["finding"]["kind"] not in ("unreachable", "black-hole"):
        return ""
    inst, result = e["instance"], (e.get("results") or {}).get(mode) or {}
    best, exported = result.get("best") or [], result.get("exported") or []
    sessions = {(x.get("from", 0), x.get("to", 0)): x for x in inst.get("sessions") or []}
    related = {frozenset(pair) for k in ("customers", "peers", "siblings") for pair in inst.get(k) or []}
    # AS numbers as the simulator gives them: 65001 + the AS index, unless asns names them.
    as_of = lambda r: (inst.get("as") or list(range(inst.get("routers", 0))))[r]
    asn = lambda r: (inst.get("asns") or [])[as_of(r)] if as_of(r) < len(inst.get("asns") or []) else 65001 + as_of(r)
    # A community 0:ASN on a path asks every router not to announce it to that AS.
    tagged = {x.get("tag") for x in inst.get("sessions") or [] if x.get("tag")}
    found = set()
    for h in e["finding"].get("routers") or []:
        for a, b in inst.get("links") or []:
            x = b if a == h else a if b == h else None
            if x is None or x >= len(best) or best[x] is None:
                continue
            # The session from x to h: x's export filter and h's import filter, as the simulator keys them.
            out, offer = sessions.get((x, h), {}), exported[x] if x < len(exported) else None
            if out.get("deny_export") or (out.get("deny_via") and offer and out["deny_via"] in offer):
                found.add("an export filter drops the offer")
            elif out.get("deny_import"):
                found.add("an import filter drops the offer")
            elif f"0:{asn(h)}" in tagged:
                found.add("a community withholds the offer")
            elif frozenset((x, h)) in related or out.get("partial_transit") or x in (inst.get("leakers") or []):
                found.add("a relation stops the offer")
            elif offer is None:
                found.add("no neighbor offers a route")
            else:
                found.add("it does not admit the offer")
    return " and ".join(sorted(found))


def proof(kind: str, in_model: bool, modes: list[str]) -> str:
    """What the published proofs say about a deviation: an OBGP mode with
    one table that shows what they rule out inside their model contradicts
    them, BGP alone does not, and on lost routes and the way to rest they
    make no claim. Tables per neighbor are outside them, see DESIGN.md."""
    if not in_model:
        return "outside its model"
    if kind not in CLAIMED:
        return "no claim"
    if any(m in COVERED for m in modes):
        return "contradicts it"
    return "BGP only" if modes == ["bgp"] else "outside its model"


def problems(entry: dict) -> list[dict]:
    """The cases of a search by problem: one kind of deviation in the same
    modes, of the same cause, with its networks as examples, the smallest
    first. A problem keeps the id of its smallest example."""
    out = {}
    for c in cases(entry):
        p = out.setdefault((c["kind"], tuple(c["modes"]), c["cause"]), {"kind": c["kind"], "modes": c["modes"], "cause": c["cause"], "examples": []})
        p["examples"].append(c)
    for p in out.values():
        p["examples"].sort(key=lambda c: (c["instance"].get("routers", 0), len(c["instance"].get("links", [])), c["id"]))
        p["id"] = p["examples"][0]["id"]
        p["families"] = list(dict.fromkeys(f for c in p["examples"] for f in c["families"]))
        p["in_model"] = any(c["in_model"] for c in p["examples"])
        p["proof"] = proof(p["kind"], p["in_model"], p["modes"])
    rank = lambda p: (_order(KINDS, p["kind"]), -len(p["modes"]), [_order(MODES, m) for m in p["modes"]])
    return sorted(out.values(), key=rank)


def case_of(entry: dict, finding_id: int) -> dict | None:
    """The problem a finding belongs to, with the case of it as case."""
    for p in problems(entry):
        for c in p["examples"]:
            if finding_id in c["ids"]:
                return {**p, "case": c}
    return None


def seen(path: str) -> str:
    """How often the simulator saw the case of a /simulation/<search>/<case> path, per mode, for the result made from
    it: the lab cannot replay the simulator's order of messages, so a deviation of few orders may not show there."""
    try:
        _, _, search_id, case_id = path.split("/")
        found = case_of(search(search_id), int(case_id))
    except (LookupError, ValueError):
        return ""
    if found is None:
        return ""
    counts = [f"{m} {v['count']} of {v['of']}" for m, v in found["case"]["per_mode"].items() if v.get("count") is not None]
    if not counts:
        return ""
    more = f" and {len(counts) - 3} modes more" if len(counts) > 3 else ""
    return f"The simulator saw it in {', '.join(counts[:3])}{more} orders of messages. The lab cannot replay their order."


def modes_label(modes: list[str]) -> str:
    """The modes of a case, short: a whole group of OBGP modes as one. A
    search with tables per neighbor runs the paper's OBGP with one table."""
    for every, name in ((MODES[1:], "every OBGP mode"), (MODES[1:6], "every OBGP mode with one table"),
                        (MODES[5:], "obgp-paper and every -pn mode"), (MODES[6:], "every -pn mode")):
        if set(every) <= set(modes):
            rest = [m for m in modes if m not in every]
            return ", ".join([*rest, name]) if rest != ["bgp"] else f"bgp and {name}"
    return ", ".join(modes)


def finding(search_id: str, finding_id: int) -> dict:
    found = next((e for e in search(search_id)["findings"] if e["id"] == finding_id), None)
    if found is None:
        raise LookupError(f"No finding {finding_id} in search {search_id}.")
    return found


def trace(search_id: str, finding_id: int, mode: str, new: bool = True) -> dict:
    """A finding played in one mode, kept beside its search after the first
    time. Without new, a replay not kept yet is refused: playing it would
    disturb a measurement."""
    if mode not in MODES:
        raise ValueError(f"Modes are {', '.join(MODES)}.")
    inst = finding(search_id, finding_id)["instance"]
    kept = folder() / search_id / f"{finding_id}-{mode}.json"
    # A replay kept before the trace said what goes in and out per neighbor is played again, unless that would disturb a measurement.
    cached = _read(kept)
    if cached is not None and (not new or all("in" in r for st in cached.get("steps", [])[:1] for r in st["routers"])):
        return cached
    if not new:
        raise ValueError("An experiment runs, and playing this would disturb its measurement. Open it when the queue is idle.")
    played = simulate.trace(inst, mode)
    played.pop("instance", None)  # the finding has it
    _put(kept, played)
    return played


def left_s(entry: dict) -> float | None:
    """The seconds a running search likely still takes, from its progress so far."""
    p, began = entry.get("progress"), entry.get("began")
    if entry.get("state") != "running" or not p or not began:
        return None
    elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(began)).total_seconds()
    return elapsed * (1 - p) / p


def lab_name(search_id: str, case_id: int) -> str:
    """The name a case gets in the lab, from the whole search id, short enough for a name."""
    n, digits = int(search_id), ""
    while n:
        n, d = divmod(n, 36)
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"[d] + digits
    return f"sim-{digits}-{case_id}"


def to_lab(search_id: str, case_id: int) -> str:
    """Makes a case an experiment of the lab: its network a topology, its
    order of events a scenario with the deviation as a check the modes
    the simulator saw failing may fail, every mode as a variant. Returns
    the experiment's name, the same for the same case. An experiment made
    before stays as it is, with any change made to it since."""
    example = finding(search_id, case_id)
    name = lab_name(search_id, case_id)
    if config.path(name).exists():
        return name
    # Its topology and scenario may stay from an experiment deleted since: written anew.
    written, skipped = simulate.export([example], name=name, overwrite=True)
    if not written:
        raise ValueError("; ".join(r for reasons in skipped.values() for r in reasons) or "The lab cannot play this case.")
    experiment = config.Experiment.model_validate({
        "name": name, "runs": 6, "topologies": [name], "scenarios": [name],
        "description": f"Case {case_id} of the Simulation search {search_id}, played on real routers: /simulation/{search_id}/{case_id}",
        "variants": [{"name": m, "mode": m.removesuffix("-pn"), **({"per_neighbor": True} if m.endswith("-pn") else {})} for m in MODES]})
    config.save(experiment)
    return name


# Per kind of deviation, the properties of a lab run that show it; a failed check of the case counts as well.
SHOWN_BY = {"unreachable": ("reach",), "black-hole": ("holes", "holes-alone"), "loop": ("loops",),
            "no-convergence": ("rest-end", "rest-step", "rest-final"), "leaked": ("policy", "policy-alone"), "inconsistent-export": (),
            "transient-loop": ("loops-way",), "transient-blocked": ("blocked",), "transient-hole": ("holes-way",)}


def played(search_id: str, case_id: int, kind: str) -> list[dict]:
    """The lab's results of a case played there, newest first: per mode the
    runs done and those that showed the deviation, by a failed check of the
    case or a property of its kind. The lab cannot replay the simulator's
    order of messages: its share is not the simulator's."""
    from . import problems
    from .results import Dataset

    name = lab_name(search_id, case_id)
    out = []
    for d in Dataset.all():
        if d.experiment.name != name:
            continue
        runs: dict[str, int] = {}
        seen: dict[str, set] = {}
        for k in d.keys():
            if d.is_done(k) and (run := d.run(k))["status"] != "error":
                runs[k.variant] = runs.get(k.variant, 0) + 1
                if any(e["name"] == "expect" and not e.get("passed", True) for e in run.get("events", [])):
                    seen.setdefault(k.variant, set()).add(k.index)
        for p in problems.broken(d):
            if p["cause"] in SHOWN_BY.get(kind, ()):
                seen.setdefault(p["variant"], set()).add(p["run"])
        modes = [{"mode": v.name, "runs": runs.get(v.name, 0), "seen": len(seen.get(v.name, ()))} for v in d.experiment.variants]
        out.append({"name": d.name, "state": d.status.get("state", ""), "modes": modes})
    return out


def latest() -> str | None:
    """The newest search that is done, for the area's first view."""
    return next((s["id"] for s in searches() if s["state"] == "done"), None)
