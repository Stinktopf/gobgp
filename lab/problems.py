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
    ("samples", r"wrote no samples", "Runs without samples",
     "A fault of the lab, not of the host: the run cannot be measured."),
    ("other", r"", "Other errors", ""),
]
ORDER = ("error", "check", "property", "unmeasured", "retried")  # the most serious first
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
    "unmeasured": "Not measured",
    "calibration": "Measured other than the known values",
}
PLANNED = ("down", "restart", "degrade")  # steps that take sessions down, or may


def plain(message: str) -> str:
    """A message without the URL of the request that failed, which says nothing more."""
    return re.sub(r" for url: \S+", "", message or "")


def cause(message: str) -> tuple[str, str, str]:
    """The cause, title and hint of an error message."""
    return next((c, title, hint) for c, pattern, title, hint in CAUSES if re.search(pattern, message or ""))


def of(dataset: Dataset, metrics: dict | None = None) -> list[dict]:
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
    out += broken(dataset, metrics)
    for c in analysis.failed_checks(dataset):
        key = RunKey(c["topology"], c["variant"], c["scenario"], c["run"])
        predicted = check_predicted(dataset, key, c["key"])
        out.append({"topology": c["topology"], "variant": c["variant"], "scenario": c["scenario"], "run": c["run"],
                    "kind": "check", "cause": "check", "step": c["step"], "t": c["t"], "problems": c["problems"],
                    "predicted": predicted, **_unanswered(dataset, key, predicted)})
    out += calibration_failures(dataset)
    return out


def calibration_failures(dataset: Dataset) -> list[dict]:
    """The runs of a calibration result whose measurements deviate from the
    known values, see lab calibrate: a fault of the lab, never predicted."""
    from . import calibration

    if not calibration.applies(dataset):
        return []
    out: dict[str, dict] = {}
    for c in calibration.checks(dataset):
        if c["ok"]:
            continue
        key = c["key"]
        p = out.setdefault(c["run"], {"topology": key.topology, "variant": key.variant, "scenario": key.scenario, "run": key.index,
                                      "kind": "property", "cause": "calibration", "message": "", "failures": [], "predicted": False})
        p["failures"].append(f"{c['what']}: {c['value']}, expected {c['expected']}")
        p["message"] = p["failures"][0]
    return list(out.values())


def fails(p: dict) -> bool:
    """Whether a failed check or broken property fails its run: the simulator
    did not predict it, or gave no answer where it can play the mode and
    scenario, as after an error or a timeout. Where it cannot play them the
    problem is told, not judged."""
    return p["kind"] in ("check", "property") and (p.get("predicted") is False or p.get("predicted") is None and p.get("unanswered", False))


def look(run: dict, found: list[dict], allowed: bool = False, predictable: bool = True) -> str:
    """How a finished run stands, for its dot on the result page and in the
    dock alike: an error, a check or property the simulator did not predict
    or gave no answer for (failed), not measured, one where it cannot play
    the mode or scenario (unjudged), only what it predicted (allowed), else
    completed where the simulator checked it and open where it cannot: no
    false comfort. The status of the run is not asked: the runner marks it
    failed on any failed check, predicted or not. allowed: a check the
    scenario allows this mode to fail, which the simulator failed as well."""
    judged = [p for p in found if p["kind"] in ("check", "property")]
    if run.get("status") == "error":
        return "error"
    if any(fails(p) for p in judged):
        return "failed"
    if any(p["kind"] == "unmeasured" for p in found):
        return "unmeasured"
    if any(p.get("predicted") is None for p in judged):
        return "unjudged"
    if judged or allowed:
        return "allowed"
    return "completed" if predictable else "open"


_EXPECTS: dict = {}  # (result, scenario) -> the keys of its checks, as the simulator counts them


def check_predicted(dataset: Dataset, key: RunKey, step: str | None) -> bool | None:
    """Whether the simulator failed this check, the expect step of key step
    (see analysis.expect_keys), for this mode in some order of messages:
    predicted (True), not predicted (False), or no prediction (None): where
    it cannot play the mode or scenario, the prediction is from before it
    counted checks, or no order reached the check. See _unanswered."""
    from .simulate import expect_keys

    p = prediction(dataset, key)
    if p is None or "failed" not in p or step is None:
        return None
    cache = (str(getattr(dataset, "path", None)), key.scenario)
    if cache not in _EXPECTS or not hasattr(dataset, "path"):  # a result keeps its scenarios
        try:
            _EXPECTS[cache] = expect_keys(dataset.experiment.scenario_of(key.scenario))
        except (ValueError, KeyError, OSError):
            _EXPECTS[cache] = []
    keys = _EXPECTS[cache]
    if step not in keys or keys.index(step) >= len(p["failed"]):
        return None
    return p["failed"][keys.index(step)] > 0


def allowed_predicted(dataset: Dataset, key: RunKey, run: dict) -> bool | None:
    """Whether the simulator failed every check its scenario allows this
    run's mode to fail and that the run failed: then the run failed only as
    predicted. None where it gives no answer for one of them, False where it
    never failed one. True where there is none."""
    said = [check_predicted(dataset, key, k) for e, k in analysis.expect_keys(run.get("events", [])) if e.get("allowed")]
    return False if False in said else None if None in said else True


_CANNOT: dict = {}  # (result, topology, scenario, run) -> why the simulator cannot play it, "" where it can


def cannot_play(dataset: Dataset, key: RunKey) -> str | None:
    """Why the simulator cannot play this run's mode, topology or scenario:
    a step without a counterpart in it, a mixed mode without the routers
    that run OBGP, or a result it was never asked for. None where it can,
    also where it failed or timed out: then it gave no answer."""
    from . import simulate

    variant = next((v for v in dataset.experiment.variants if v.name == key.variant), None)
    if variant is None:
        return "the variant is not in the experiment"
    predictions = getattr(dataset, "meta", {}).get("predictions")
    if not predictions:  # a result from before predictions, or imported: never asked
        return "the simulator was not asked for this result"
    mode = simulate.sim_mode(variant)
    _, found = simulate.stored(predictions, key, mode)
    if mode not in found and "unsupported" not in found and simulate.mixed(variant):  # asked before it played them
        return "the simulator was asked before it played mixed modes"
    if "unsupported" not in found and "unsupported" not in found.get(mode, {}):
        return None
    # Stored alike with an error of the simulator: the translation tells them apart, also for results of before.
    cache = (str(getattr(dataset, "path", None)), key.topology, key.scenario, key.index, mode)
    if cache not in _CANNOT or not hasattr(dataset, "path"):
        e = dataset.experiment
        try:
            sc = e.scenario_of(key.scenario)
            topology = simulate.topologies.load(key.topology)
            simulate.to_instances(topology, sc, e.seed, key.index if simulate.draws(sc) else 1, e.bgp)
            if simulate.mixed(variant):
                simulate.router_modes(variant, topology, e.seed * 1000 + key.index)
            _CANNOT[cache] = ""
        except simulate.Unsupported as x:
            _CANNOT[cache] = "; ".join(x.reasons)
        except (ValueError, KeyError, OSError):  # the topology is gone: as stored
            _CANNOT[cache] = "; ".join(found.get("unsupported") or found.get(mode, {}).get("unsupported") or [])
    return _CANNOT[cache] or None


def _unanswered(dataset: Dataset, key: RunKey, predicted: bool | None) -> dict:
    """For a problem without a prediction: unanswered where the simulator can
    play the mode and scenario but gave no answer, after an error, a
    timeout, or asked before it judged this, else why it cannot play them."""
    if predicted is not None:
        return {}
    why = cannot_play(dataset, key)
    return {"unanswered": why is None, **({"why": why} if why else {})}


# What a failed check says, per kind of problem it can foretell.
FORETOLD = {"loops": "forwarding loops", "holes": "without a route", "reach": " misses "}


def _predicted(dataset: Dataset, key: RunKey, run: dict, routers: set[str], kind: str) -> bool | None:
    """Whether a check the scenario allowed this mode to fail, and the
    simulator failed as well, foretold this very kind of problem: a lost
    route by a check of the same routers' prefixes that found them missing,
    a loop or black hole by a check of forwarding that found one. A check
    allowed for one kind foretells no other. The scenario's allowance alone
    predicts nothing: None where the simulator gives no answer on the check."""
    said_ = False
    for e, step in analysis.expect_keys(run.get("events", [])):
        if not e.get("allowed"):
            continue
        said = " ".join(e.get("problems") or [])
        if FORETOLD[kind] not in said:
            continue
        if kind != "reach" and e.get("forwarding") or kind == "reach" and e.get("prefixes", "all") == "all" \
                and not (e.get("via") or e.get("avoid")) and routers <= set(e.get("routers", [])):
            if (sim := check_predicted(dataset, key, step)) is True:
                return True
            said_ = None if sim is None or said_ is None else said_
    return said_


def prediction(dataset: Dataset, key: RunKey) -> dict | None:
    """In how many orders of messages the simulator saw this run's mode come
    to rest on its topology and scenario, None where it did not play it."""
    from .simulate import sim_mode, stored

    variant = next((v for v in dataset.experiment.variants if v.name == key.variant), None)
    if variant is None:
        return None
    predictions = getattr(dataset, "meta", {}).get("predictions") or {}
    # Per run where the scenario chooses targets or the variant its routers at random, else per topology and scenario.
    mode = sim_mode(variant)
    _, found = stored(predictions, key, mode)
    if "unsupported" in found or not (p := found.get(mode)) or "unsupported" in p or not p.get("runs"):
        return None
    return p


# What the simulator names each problem on the way, see internal/pkg/obgpsim/oracle.go.
ON_THE_WAY = {"loops-way": "transient-loop", "holes-way": "transient-hole", "blocked": "transient-blocked"}


def unforeseen(dataset: Dataset, key: RunKey) -> bool | None:
    """What a problem is without a prediction: not judged (None) for BGP and
    mixed modes, which may come to rest or not, a problem not predicted
    (False) for a pure OBGP mode, which is to come to rest."""
    from . import modes

    variant = next((v for v in dataset.experiment.variants if v.name == key.variant), None)
    mode = modes.get(variant.mode) if variant else None
    return False if mode is not None and mode.obgp and mode.inner is None else None


def way_predicted(dataset: Dataset, key: RunKey, cause: str) -> bool | None:
    """Whether the simulator saw this problem on the way to rest for this mode
    here, in some order of messages. None without a prediction, or with one
    from before it looked at the way: then the proofs, which claim rest and
    not the way to it, tell nothing either. See _unanswered."""
    p = prediction(dataset, key)
    if p is None or "findings" not in p:  # not predictable: the proofs claim rest, not the way to it
        return None
    return p["findings"].get(ON_THE_WAY[cause], 0) > 0


def leak_predicted(dataset: Dataset, key: RunKey) -> bool:
    """Whether the simulator saw this mode use a path against the relations here, in some order of messages
    (leaked). Without that answer a path against the relations stays a problem not predicted, as a lost route."""
    p = prediction(dataset, key)
    return p is not None and (p.get("findings") or {}).get("leaked", 0) > 0


def no_rest_predicted(dataset: Dataset, key: RunKey) -> bool:
    """Whether the simulator saw this mode not come to rest here in some order of messages, at a step or at the end:
    then a run without rest is the hypothesis."""
    p = prediction(dataset, key)
    return p is not None and p.get("settled", p["converged"]) < p["runs"]


def broken(dataset: Dataset, known: dict | None = None) -> list[dict]:
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
    this mode to fail, and the simulator failed too, foretold it, for the same routers."""
    # The reference of each variant: BGP sampled alike, as lab-sampling has BGP at two rates, else the first BGP.
    references = [v.name for v in dataset.experiment.variants if v.mode == "bgp" and not v.per_neighbor]
    rate = lambda name: dataset.experiment.sampling_of(name).interval
    reference = lambda name: name if name in references else next((b for b in references if rate(b) == rate(name)), references[0] if references else None)
    try:  # known: the metrics measured already, for what must not wait, as the dock
        metrics = known if known is not None else analysis.run_summary(dataset)
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

    way_refs: dict = {}

    def bgp_way(topology: str, scenario: str, bgp: str) -> list[dict]:
        """The metrics of every measured BGP run of a cell, for the way to rest."""
        if (topology, scenario, bgp) not in way_refs:
            keys = [k for k in dataset.keys() if (k.topology, k.scenario, k.variant) == (topology, scenario, bgp) and dataset.is_done(k)]
            way_refs[topology, scenario, bgp] = [x for k in keys if (x := measured(k, dataset.run(k)))]
        return way_refs[topology, scenario, bgp]

    def oscillates(key: RunKey, run: dict) -> bool:
        return measured(key, run).get("oscillates") == 1

    def usable(key: RunKey | None) -> dict | None:
        """The final check of a BGP run that came to rest without an error, or None."""
        if key is None or not dataset.is_done(key):
            return None
        run = dataset.run(key)
        final = analysis.final_of(run)
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
        bgp = reference(key.variant)
        found = []
        final = analysis.final_of(run)
        if skipped := next((e.get("skipped") for e in run.get("events", []) if e["name"] == "final" and e.get("skipped")), None):
            found.append(("unchecked", f"the final check was skipped: {skipped}", False))
        # Rest, told apart: still changing at the end, a step that waited in vain, no rest before the final check.
        # The simulator foretells a run without rest where it saw the mode not come to rest in some order of messages.
        m, p = measured(key, run), prediction(dataset, key)
        # At the end, and at every step that waits for rest: a step may wait in vain where the end comes to rest.
        no_rest = unforeseen(dataset, key) if p is None else p["converged"] < p["runs"]
        settled = None if p is None else p.get("settled", p["converged"])
        no_rest_step = unforeseen(dataset, key) if p is None else settled < p["runs"]
        # With an MRAI the timer's rounds decide rest, which the simulator plays as coalescing without time: not predictable.
        if dataset.experiment.bgp.mrai and p is not None:
            no_rest = no_rest or None
            no_rest_step = no_rest_step or None
        endless = f" and repeats without end in {p['endless']}" if p is not None and p.get("endless") else ""
        foretold = f", the simulator rests in {p['converged']} of {p['runs']} orders{endless}" if no_rest else ""
        foretold_step = f", the simulator rests at every step in {settled} of {p['runs']} orders" if no_rest_step else ""
        if m.get("oscillates") == 1:
            churn = f", {m['hold_churn']:.0f} updates a second per router" if m.get("hold_churn") is not None else ""
            found.append(("rest-end", f"{m.get('rest_s') or 0:g} s after the last step the routes still change{churn}{foretold}", no_rest))
        for s in (s for s in run.get("measurements", []) if not s.get("stable", True)):
            found.append(("rest-step", f"step {s.get('step')} waited until {s.get('t', 0):g} s and found no rest{foretold_step}", no_rest_step))
        if final and final.get("stable") is False:
            found.append(("rest-final", f"at {final.get('t', 0):g} s the routes did not stand still yet{foretold}", no_rest))
        at_rest = final and final.get("stable") is not False
        # Without a rest value the run is neither passed nor failed: tell why it was not measured.
        if analysis.rested(run, m) is None:
            quiet = dataset.experiment.quiet_s(key.variant)
            why = ("its metrics could not be computed" if not m
                   else f"its samples after the last step span less than {quiet:g} s at rest, {3 * quiet:g} s still changing" if m.get("oscillates") is None
                   else f"the routes never stayed unchanged for {quiet:g} s")
            found.append(("unmeasured", f"no rest value: {why}", False))
        # The simulator models an MRAI's coalescing, not its timer: the timer may bring routes to rest that it never sees at rest.
        if p is not None and p["converged"] == 0 and m.get("oscillates") == 0 and at_rest and not dataset.experiment.bgp.mrai:
            found.append(("rest-unforeseen", f"the routes came to rest, the simulator never does in {p['runs']} orders{endless}", False))
        if at_rest and final.get("loops"):
            found.append(("loops", f"packets to {', '.join(final.get('looping', [])) or str(final['loops']) + ' prefixes'} loop",
                          _predicted(dataset, key, run, set(), "loops")))
        partner = RunKey(key.topology, bgp, key.scenario, key.index) if bgp and key.variant != bgp else None
        theirs = usable(partner)
        # BGP's run of this seed still to come: compared once it is done, nothing judged alone before.
        waits = partner is not None and not dataset.is_done(partner)
        missing = {r: final["prefixes"] - h for r, h in final["held"].items() if h < final["prefixes"]} if at_rest else {}
        if at_rest and theirs:
            fewer = {r: theirs["held"][r] - h for r, h in final["held"].items() if theirs["held"].get(r, 0) > h}
            if fewer:
                found.append(("reach", ", ".join(f"{r} holds {final['held'][r]} of the {theirs['held'][r]} prefixes BGP holds" for r in sorted(fewer)),
                              _predicted(dataset, key, run, set(fewer), "reach")))
            if extra := sorted(set(final.get("holed", [])) - set(theirs.get("holed", []))):
                found.append(("holes", f"packets to {', '.join(extra)} end at a router without a route", _predicted(dataset, key, run, set(), "holes")))
            if "valleys" in final and "valleys" in theirs and (
                    more := {r: n for r, n in final["valleys"].items() if n > theirs["valleys"].get(r, 0)}):
                found.append(("policy", ", ".join(f"{r} routes {n} prefixes against the relations, BGP {theirs['valleys'].get(r, 0)}"
                                                  for r, n in sorted(more.items())), leak_predicted(dataset, key)))
            stale = {r: n for r, n in (final.get("stale") or {}).items() if n > (theirs.get("stale") or {}).get(r, 0)}
            if stale:
                found.append(("stale", ", ".join(f"{r} keeps {n} withdrawn prefixes" for r, n in sorted(stale.items())), False))
        elif at_rest and not waits:
            if missing and partner:
                found.append(("reference", f"{', '.join(sorted(missing))} miss prefixes, and the BGP run of this seed did not come to rest to compare", False))
            if final.get("holed"):
                found.append(("holes-alone", f"packets to {', '.join(final['holed'])} end at a router without a route", _predicted(dataset, key, run, set(), "holes")))
            if key.variant != bgp and (valleys := final.get("valleys")):
                found.append(("policy-alone", ", ".join(f"{r} routes {n} prefixes against the relations"
                                                  for r, n in sorted(valleys.items())), leak_predicted(dataset, key)))
            if stale := {r: n for r, n in (final.get("stale") or {}).items() if n}:
                found.append(("stale-alone", ", ".join(f"{r} keeps {n} withdrawn prefixes" for r, n in sorted(stale.items())), False))
        # On the way to rest, beyond the resolution: two sampling intervals, of BGP's runs as well.
        resolution = 2 * max(dataset.experiment.sampling_of(v).interval for v in {key.variant, bgp} if v)
        # BGP loops and holes on the way too, by seed more than the resolution: the most of BGP's runs of this cell is
        # the reference, not one seed, so that timing noise is not judged. Without a BGP run there is nothing to judge.
        refs = bgp_way(key.topology, key.scenario, bgp) if bgp and key.variant != bgp else []
        # Only loops and holes that lasted beyond the resolution: the routers read their next hops one after another,
        # a shorter one may be no more than that. Metrics from before they were counted so: all of them.
        loops, holes = ("loops_beyond_s", "holes_beyond_s") if "holes_beyond_s" in m else ("loops_s", "holes_s")
        lost = lambda x: None if x.get(loops) is None or x.get(holes) is None else x[loops] + x[holes]
        most = lambda f: max((v for r in refs if (v := f(r)) is not None), default=None)
        for metric, cause_, what in ((loops, "loops-way", "packets looped"), (holes, "holes-way", "packets ended at a router without a route")):
            mine, base, base_lost = m.get(metric), most(lambda r: r.get(metric)), most(lost)
            # A packet lost on the way either loops or ends without a route: each counts only where both together exceed BGP's too.
            if mine is not None and base is not None and mine > base + resolution and not (
                    lost(m) is not None and base_lost is not None and lost(m) <= base_lost + resolution):
                beyond = ", each time longer than the resolution" if metric.endswith("_beyond_s") else ""
                found.append((cause_, f"{what} for {mine:g} s on the way{beyond}, BGP at most {base:g} s in {len(refs)} runs",
                              way_predicted(dataset, key, cause_)))
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
            found.append(("blocked", f"for {m['blocked_s']:g} s a router had a valid path set aside and no route{beyond}, up to {m.get('blocked_max', 0)} prefixes",
                          way_predicted(dataset, key, "blocked")))
        # A run without rest is one problem, each way it showed told inside it.
        restless_ = [f for f in found if f[0] in ("rest-end", "rest-step", "rest-final")]
        if len(restless_) > 1:
            found = [f for f in found if f not in restless_[1:]]
        # Fewer routes than BGP where the simulator was asked but cannot play the case: told, not judged. OBGP
        # promises rest, not BGP's reach (DESIGN.md, Choice per neighbor), so only a prediction could judge it.
        unplayable = bool(getattr(dataset, "meta", {}).get("predictions")) and cannot_play(dataset, key) is not None
        for cause_, message, predicted in found:
            if predicted is False and unplayable and cause_ == "reach":
                predicted = None
            told = [f[1] for f in restless_] if restless_ and cause_ == restless_[0][0] else [message]
            out.append({**where, "cause": cause_, "message": message, "failures": told, "predicted": predicted,
                        **({"kind": "unmeasured"} if cause_ == "unmeasured" else _unanswered(dataset, key, predicted))})
    return out


def verdict(dataset: Dataset, found: list[dict] | None = None) -> dict:
    """Whether a finished result passed, from itself alone: no run ended in an
    error, every run was measured, no check failed and no property broke
    that the simulator did not predict or gave no answer for, after an error
    or a timeout, and a calibration measured the known values. passed is
    None while the result is not finished, and for a result imported from the
    former scripts. A finished result without a single run does not pass.
    The reasons count runs. told: what the simulator cannot play, a mixed
    mode or a step without a counterpart, told and not judged."""
    if dataset.status.get("state") != "finished":
        return {"passed": None, "reasons": [], "told": []}
    if dataset.meta.get("imported"):  # recorded by the former scripts, without the checks of the lab
        return {"passed": None, "reasons": ["imported from the former scripts, not judged"], "told": []}
    if not any(dataset.is_done(k) for k in dataset.keys()):
        return {"passed": False, "reasons": ["no run ran on this host"], "told": []}
    if found is None:
        found = of(dataset)
    runs = lambda keep: len({(p["topology"], p["variant"], p["scenario"], p["run"]) for p in found if keep(p)})
    judged = lambda kind, p: p["kind"] == kind and p.get("cause") != "calibration"
    counts = [
        (runs(lambda p: p["kind"] == "error"), "ended in an error"),
        (runs(lambda p: p["kind"] == "unmeasured"), "not measured"),
        (runs(lambda p: p.get("cause") == "calibration"), "measured other than the known values, see lab calibrate"),
        (runs(lambda p: judged("check", p) and p.get("predicted") is False), "failed a check the simulator did not predict"),
        (runs(lambda p: judged("check", p) and p.get("predicted") is None and p.get("unanswered", False)),
         "failed a check the simulator gave no answer for"),
        # Without a prediction a property of BGP is told where the simulator cannot play it, see unforeseen.
        (runs(lambda p: judged("property", p) and p.get("predicted") is False), "broke a property the simulator did not predict"),
        (runs(lambda p: judged("property", p) and p.get("predicted") is None and p.get("unanswered", False)),
         "broke a property the simulator gave no answer for"),
    ]
    reasons = [f"{n} run{'s' * (n != 1)} {what}" for n, what in counts if n]
    told = runs(lambda p: p["kind"] in ("check", "property") and p.get("predicted", False) is None and not p.get("unanswered", False))
    return {"passed": not reasons, "reasons": reasons,
            "told": [f"{told} run{'s' * (told != 1)} failed a check or broke a property the simulator cannot play, not predictable"] if told else []}


def grouped(found: list[dict]) -> list[dict]:
    """The problems by kind and cause, errors first, each with what to do."""
    groups: dict[tuple, dict] = {}
    for p in found:
        said, unanswered = p.get("predicted", False), p.get("unanswered", False)
        if p["kind"] in ("check", "property", "unmeasured"):
            what = "Failed a check" if p["kind"] == "check" else PROPERTIES[p["cause"]]
            if p.get("cause") == "calibration":
                title, hint = what, "A fault of the lab, not of the protocol: lab calibrate tells each value."
            elif said is None and unanswered:
                title = what + ", no answer of the simulator"
                hint = "The simulator failed or timed out here, or answered before it judged this: predict again. Fails the result."
            elif said is None:
                title, hint = what + ", not predictable", "The simulator cannot play this mode or scenario, or was not asked: told, not judged."
            else:
                title = what + (", predicted" if said else ", not predicted" if p["kind"] != "unmeasured" else "")
                hint = "As the simulator predicts for this mode." if said else ""
        else:
            _, title, hint = cause(p["message"])
            if p["kind"] == "retried":
                title, hint = f"{title}, then completed", "Counted. Retries can favour runs below a limit."
        groups.setdefault((p["kind"], p["cause"], said, unanswered), {"kind": p["kind"], "cause": p["cause"], "title": title, "hint": hint,
                                                                       "runs": []})["runs"].append(p)
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
                # Attempts only for retries: a run without rest tells each way it showed as a line of its own.
                text = f"Attempt {k}: {f}" if p["kind"] in ("retried", "error") and len(p["failures"]) > 1 else f
                row["lines"].setdefault(text, {"message": text})
    for row in out.values():
        row["runs"].sort()
        row["span"] = spans(row["runs"])
        row["lines"] = list(row["lines"].values())
    return list(out.values())
