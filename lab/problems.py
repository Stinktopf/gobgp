"""What went wrong in a result, run by run and grouped by cause: runs that
ended in an error, failed a check, broke one of the properties every run
is measured for, or completed only after a failed attempt. For the web
interface and for agents.

The properties hold for every run, whatever its scenario checks: it comes
to rest, forwards without loops at rest, and reaches what BGP reaches with
the same seed, without black holes BGP has not. On the way to rest it loops
and holes no longer than BGP, and no router waits without a route."""

import re

from . import analysis
from .results import Dataset, RunKey

# (cause, pattern of the message, title, what to do), the first that matches
CAUSES = [
    ("memory", r"took more than \d+ Mi?B", "Routers took more than their memory",
     "Raise Per router, MiB in the experiment."),
    ("unreachable", r"Service Unavailable|Connection refused|Read timed out|Max retries",
     "A router did not answer", "Often right after a restart."),
    ("sampling", r"samples failed", "Too many samples failed",
     "The host was too busy, see Quality."),
    ("other", r"", "Other errors", ""),
]
ORDER = ("error", "check", "property", "retried")  # the most serious first
PROPERTIES = {  # cause: title of its group
    "rest-end": "Routes still change at the end",
    "rest-step": "A step found no rest in time",
    "rest-final": "No rest before the final check",
    "loops": "Loops at rest",
    "reach": "Fewer routes than BGP",
    "holes": "Black holes BGP has not",
    "stale": "Withdrawn routes BGP has not",
    "reference": "No BGP run at rest to compare with",
    "holes-alone": "Black holes, no BGP at rest to compare",
    "stale-alone": "Withdrawn routes kept, no BGP at rest to compare",
    "loops-way": "Loops on the way, longer than BGP",
    "holes-way": "Black holes on the way, longer than BGP",
    "blocked": "Routers wait without a route",
    "unchecked": "No final check",
    "rest-unforeseen": "At rest, the simulator never is",
    "sessions": "Sessions fell without a step for it",
    "policy": "Paths against the relations, more than BGP",
    "policy-alone": "Paths against the relations, no BGP at rest to compare",
}
PLANNED = ("down", "restart", "degrade")  # steps that take sessions down, or may


def plain(message: str) -> str:
    """A message without the URL of the request that failed, which says nothing more."""
    return re.sub(r" for url: \S+", "", message or "")


def cause(message: str) -> tuple[str, str, str]:
    """The cause, title and hint of an error message."""
    return next((c, title, hint) for c, pattern, title, hint in CAUSES if re.search(pattern, message or ""))


def of(dataset: Dataset) -> list[dict]:
    """Every problem of a result, one per run, or per failed check."""
    out = []
    for key in sorted(dataset.keys(), key=lambda k: (k.topology, k.scenario, k.variant, k.index)):
        if not dataset.is_done(key):
            continue
        run = dataset.run(key)
        where = {"topology": key.topology, "variant": key.variant, "scenario": key.scenario, "run": key.index,
                 "attempts": run.get("attempts", 1)}
        if run["status"] == "error":
            message = plain(run.get("message", ""))
            out.append({**where, "kind": "error", "cause": cause(message)[0], "message": message,
                        "failures": [plain(f) for f in run.get("failures") or [message]]})
        elif failures := [plain(f) for f in run.get("failures", [])]:
            out.append({**where, "kind": "retried", "cause": cause(failures[-1])[0], "message": failures[-1], "failures": failures})
    out += broken(dataset)
    for c in analysis.failed_checks(dataset):
        out.append({"topology": c["topology"], "variant": c["variant"], "scenario": c["scenario"], "run": c["run"],
                    "kind": "check", "cause": "check", "step": c["step"], "t": c["t"], "problems": c["problems"]})
    return out


def _final(run: dict) -> dict | None:
    return next((e for e in run.get("events", []) if e["name"] == "final" and "held" in e), None)


# What a failed check says, per kind of problem it can foretell.
FORETOLD = {"loops": "forwarding loops", "holes": "without a route", "reach": " misses "}


def _predicted(run: dict, routers: set[str], kind: str) -> bool:
    """Whether a check the scenario allowed this mode to fail foretold this
    very kind of problem: a lost route by a check of the same routers'
    prefixes that found them missing, a loop or black hole by a check of
    forwarding that found one. A check allowed for one kind foretells no other."""
    for e in run.get("events", []):
        if e["name"] != "expect" or not e.get("allowed"):
            continue
        said = " ".join(e.get("problems") or [])
        if FORETOLD[kind] not in said:
            continue
        if kind != "reach" and e.get("forwarding"):
            return True
        if kind == "reach" and e.get("prefixes", "all") == "all" and not (e.get("via") or e.get("avoid")) and routers <= set(e.get("routers", [])):
            return True
    return False


def prediction(dataset: Dataset, key: RunKey) -> dict | None:
    """In how many orders of messages the simulator saw this run's mode come
    to rest on its topology and scenario, None where it did not play it."""
    from .simulate import sim_mode

    variant = next((v for v in dataset.experiment.variants if v.name == key.variant), None)
    found = ((getattr(dataset, "meta", {}).get("predictions") or {}).get(f"{key.topology}|{key.scenario}") or {})
    if variant is None or "unsupported" in found or not (mode := sim_mode(variant)) or not (p := found.get(mode)) or not p.get("runs"):
        return None
    return p


def restless_predicted(dataset: Dataset, key: RunKey) -> bool:
    """Whether the simulator saw this mode not come to rest here in some order of messages: then a run without rest is the hypothesis."""
    p = prediction(dataset, key)
    return p is not None and p["converged"] < p["runs"]


def broken(dataset: Dataset) -> list[dict]:
    """The runs that broke a property. Rest: routes that still changed at the
    end, a final check or an until_stable step that found no rest. At rest:
    loops, and compared with the BGP run of the same seed, which tells what
    the policies allow, fewer routes, black holes and withdrawn routes BGP
    has not. A run that misses prefixes without a BGP run at rest to compare
    with says so, and then any black hole or withdrawn route kept counts,
    for BGP itself too. On the way: loops and black holes longer than in the
    BGP run of the same seed, judged only where that run exists, and routers that wait
    without a route, each beyond two sampling intervals, the resolution,
    and under refresh pruning beyond the wait for a route refresh.
    A final check skipped, e.g. for tables too large, is told as well, and
    sessions that fell or stayed down in a run without a step for it.
    Paths at rest against the relations between the ASes (valley-free)
    count where more than in BGP of the same seed, whose policies may leak
    on purpose, or at all without a BGP run at rest.
    A failure is predicted when a check the scenario allowed
    this mode to fail foretold it, for the same routers."""
    bgp = next((v.name for v in dataset.experiment.variants if v.mode == "bgp" and not v.per_neighbor), None)
    try:
        metrics = analysis.run_summary(dataset)
    except (OSError, ValueError, KeyError, IndexError):  # one run without samples: each run on its own
        metrics = None
    out = []

    def measured(key: RunKey, run: dict) -> dict:
        if metrics is not None:
            return metrics.get(str(key)) or {}
        try:
            return analysis.run_metrics(dataset, key, run)
        except (OSError, ValueError, KeyError, IndexError):
            return {}

    def oscillates(key: RunKey, run: dict) -> bool:
        return measured(key, run).get("oscillates") == 1

    def usable(key: RunKey | None) -> dict | None:
        """The final check of a BGP run that came to rest without an error, or None."""
        if key is None or not dataset.is_done(key):
            return None
        run = dataset.run(key)
        final = _final(run)
        if run["status"] == "error" or not final or final.get("stable") is False or oscillates(key, run):
            return None
        return final

    for key in sorted(dataset.keys(), key=lambda k: (k.topology, k.scenario, k.variant, k.index)):
        if not dataset.is_done(key):
            continue
        run = dataset.run(key)
        if run["status"] == "error":
            continue
        where = {"topology": key.topology, "variant": key.variant, "scenario": key.scenario, "run": key.index, "kind": "property"}
        found = []
        final = _final(run)
        if skipped := next((e.get("skipped") for e in run.get("events", []) if e["name"] == "final" and e.get("skipped")), None):
            found.append(("unchecked", f"the final check was skipped: {skipped}", False))
        # Rest, told apart: still changing at the end, a step that waited in vain, no rest before the final check.
        # The simulator foretells a run without rest where it saw the mode not come to rest in some order of messages.
        m, p = measured(key, run), prediction(dataset, key)
        restless = p is not None and p["converged"] < p["runs"]
        foretold = f", the simulator rests in {p['converged']} of {p['runs']} orders" if restless else ""
        if m.get("oscillates") == 1:
            churn = f", {m['hold_churn']:.0f} updates a second per router" if m.get("hold_churn") is not None else ""
            found.append(("rest-end", f"after {m.get('rest_s') or 0:g} s of rest the routes still change{churn}{foretold}", restless))
        for s in (s for s in run.get("measurements", []) if not s.get("stable", True)):
            found.append(("rest-step", f"step {s.get('step')} waited until {s.get('t', 0):g} s and found no rest{foretold}", restless))
        if final and final.get("stable") is False:
            found.append(("rest-final", f"at {final.get('t', 0):g} s the routes did not stand still yet{foretold}", restless))
        at_rest = final and final.get("stable") is not False
        if p is not None and p["converged"] == 0 and m.get("oscillates") == 0 and at_rest:
            found.append(("rest-unforeseen", f"the routes came to rest, the simulator never does in {p['runs']} orders", False))
        if at_rest and final.get("loops"):
            found.append(("loops", f"packets to {', '.join(final.get('looping', [])) or str(final['loops']) + ' prefixes'} loop",
                          _predicted(run, set(), "loops")))
        theirs = usable(RunKey(key.topology, bgp, key.scenario, key.index)) if bgp and key.variant != bgp else None
        missing = {r: final["prefixes"] - h for r, h in final["held"].items() if h < final["prefixes"]} if at_rest else {}
        if at_rest and theirs:
            fewer = {r: theirs["held"][r] - h for r, h in final["held"].items() if theirs["held"].get(r, 0) > h}
            if fewer:
                found.append(("reach", ", ".join(f"{r} holds {final['held'][r]} of the {theirs['held'][r]} prefixes BGP holds" for r in sorted(fewer)),
                              _predicted(run, set(fewer), "reach")))
            if extra := sorted(set(final.get("holed", [])) - set(theirs.get("holed", []))):
                found.append(("holes", f"packets to {', '.join(extra)} end at a router without a route", _predicted(run, set(), "holes")))
            if "valleys" in final and "valleys" in theirs and (
                    more := {r: n for r, n in final["valleys"].items() if n > theirs["valleys"].get(r, 0)}):
                found.append(("policy", ", ".join(f"{r} routes {n} prefixes against the relations, BGP {theirs['valleys'].get(r, 0)}"
                                                  for r, n in sorted(more.items())), False))
            stale = {r: n for r, n in (final.get("stale") or {}).items() if n > (theirs.get("stale") or {}).get(r, 0)}
            if stale:
                found.append(("stale", ", ".join(f"{r} keeps {n} withdrawn prefixes" for r, n in sorted(stale.items())), False))
        elif at_rest:
            if missing and bgp and key.variant != bgp:
                found.append(("reference", f"{', '.join(sorted(missing))} miss prefixes, and the BGP run of this seed did not come to rest to compare", False))
            if final.get("holed"):
                found.append(("holes-alone", f"packets to {', '.join(final['holed'])} end at a router without a route", _predicted(run, set(), "holes")))
            if key.variant != bgp and (valleys := final.get("valleys")):
                found.append(("policy-alone", ", ".join(f"{r} routes {n} prefixes against the relations"
                                                  for r, n in sorted(valleys.items())), False))
            if stale := {r: n for r, n in (final.get("stale") or {}).items() if n}:
                found.append(("stale-alone", ", ".join(f"{r} keeps {n} withdrawn prefixes" for r, n in sorted(stale.items())), False))
        # On the way to rest, beyond the resolution: two sampling intervals, of BGP's runs as well.
        resolution = 2 * max(dataset.experiment.sampling_of(v).interval for v in {key.variant, bgp} if v)
        ref = measured(RunKey(key.topology, bgp, key.scenario, key.index), dataset.run(RunKey(key.topology, bgp, key.scenario, key.index))) \
            if bgp and key.variant != bgp and dataset.is_done(RunKey(key.topology, bgp, key.scenario, key.index)) else None
        for metric, cause_, what in (("loops_s", "loops-way", "packets looped"), ("holes_s", "holes-way", "packets ended at a router without a route")):
            # BGP loops and holes on the way too: without its run of this seed there is nothing to judge.
            mine, base = m.get(metric), (ref or {}).get(metric)
            if mine is not None and base is not None and mine > base + resolution:
                found.append((cause_, f"{what} for {mine:g} s on the way, BGP of this seed {base:g} s", False))
        if m.get("flaps_unplanned") is not None:  # per session: those no step touched
            if m["flaps_unplanned"]:
                found.append(("sessions", f"sessions no step touched fell {m['flaps_unplanned']} times, counted at both ends", False))
            if m.get("down_unplanned"):
                found.append(("sessions", f"{m['down_unplanned']} sessions no step touched were not up at the end, counted at both ends", False))
        elif not any(e["name"] in PLANNED for e in run.get("events", [])):  # runs from before, without counts per session
            if m.get("flaps"):
                found.append(("sessions", f"sessions fell {m['flaps']} times, counted at both ends", False))
            if m.get("sessions_down_end"):
                found.append(("sessions", f"{m['sessions_down_end']} sessions were not up at the end, counted at both ends", False))
        # Refresh pruning waits for a route refresh by design: blocking counts beyond that wait.
        variant = next((v for v in dataset.experiment.variants if v.name == key.variant), None)
        wait = (variant.refresh_delay or 0) + dataset.experiment.bgp.refresh if variant and variant.mode.startswith("obgp-rp") else 0
        if (m.get("blocked_s") or 0) > wait + resolution:
            beyond = f", beyond the {wait:g} s refresh pruning waits by design" if wait else ""
            found.append(("blocked", f"for {m['blocked_s']:g} s a router had a valid path set aside and no route{beyond}, up to {m.get('blocked_max', 0)} prefixes", False))
        for cause_, message, predicted in found:
            out.append({**where, "cause": cause_, "message": message, "failures": [message], "predicted": predicted})
    return out


def grouped(found: list[dict]) -> list[dict]:
    """The problems by kind and cause, errors first, each with what to do."""
    groups: dict[tuple, dict] = {}
    for p in found:
        if p["kind"] == "check":
            title, hint = "Failed a check", ""
        elif p["kind"] == "property":
            title = PROPERTIES[p["cause"]] + (", as predicted" if p.get("predicted") else "")
            hint = "As the simulator predicts for this mode." if p.get("predicted") else ""
        else:
            _, title, hint = cause(p["message"])
            if p["kind"] == "retried":
                title, hint = f"{title}, then completed", "Counted. Retries can favour runs below a limit."
        groups.setdefault((p["kind"], p["cause"], p.get("predicted", False)), {"kind": p["kind"], "cause": p["cause"], "title": title, "hint": hint, "runs": []})["runs"].append(p)
    for g in groups.values():
        g["rows"] = rows(g["runs"])
    return sorted(groups.values(), key=lambda g: (ORDER.index(g["kind"]), -len(g["runs"])))


def spans(numbers: list[int]) -> str:
    """Run numbers as ranges: 1 to 10, 12, 14 to 15."""
    out, start = [], None
    for k, x in enumerate(numbers):
        if start is None:
            start = x
        if k + 1 == len(numbers) or numbers[k + 1] != x + 1:
            out.append(str(start) if start == x else f"{start} to {x}")
            start = None
    return ", ".join(out)


def rows(found: list[dict]) -> list[dict]:
    """The problems of a group, one row per topology, variant and scenario:
    the runs it hit, and each failed check or message once. The checks of
    one step, e.g. 6.0 and 6.1, read as one."""
    out: dict[tuple, dict] = {}
    for p in found:
        row = out.setdefault((p["topology"], p["variant"], p["scenario"]),
                             {"topology": p["topology"], "variant": p["variant"], "scenario": p["scenario"], "runs": [], "lines": {}})
        if p["run"] not in row["runs"]:
            row["runs"].append(p["run"])
        if p["kind"] == "check":
            line = row["lines"].setdefault(str(p["step"]).split(".")[0], {"step": str(p["step"]).split(".")[0], "t": p["t"], "problems": []})
            line["problems"] += [x for x in p["problems"] if x not in line["problems"]]
        else:
            for k, f in enumerate(p["failures"], 1):
                text = f"Attempt {k}: {f}" if len(p["failures"]) > 1 or p["kind"] == "retried" else f
                row["lines"].setdefault(text, {"message": text})
    for row in out.values():
        row["runs"].sort()
        row["span"] = spans(row["runs"])
        row["lines"] = list(row["lines"].values())
    return list(out.values())
