from lab import analysis, config, problems, results
from lab.config import Experiment

OOM = "brussels, lyon took more than 512 MB and restarted"


def rested(found):
    """The problems other than runs without a rest value: these fake runs have no samples."""
    return [x for x in found if x["kind"] != "unmeasured"]


def result_with_problems():
    dataset = results.Dataset.create(Experiment.load(config.path("lab-smoke")), "t-problems")
    first, second, third = dataset.keys()[:3]
    dataset.write_run(first, {"status": "error", "message": OOM, "attempts": 3, "failures": [OOM, "x /noise/pause: 503 Server Error: Service Unavailable", OOM]}, [])
    dataset.write_run(second, {"status": "completed", "attempts": 2, "failures": [OOM], "events": []}, [])
    dataset.write_run(third, {"status": "failed", "events": [{"name": "expect", "passed": False, "step": 2, "t": 1.5, "problems": ["r1 misses 1 of 1 prefixes"]}]}, [])
    return dataset, (first, second, third)


def test_problems_say_which_runs_and_why_grouped_by_cause(lab_files):
    dataset, (first, second, third) = result_with_problems()
    groups = problems.grouped(problems.of(dataset))
    assert [(g["kind"], g["cause"], len(g["runs"])) for g in groups] == [("error", "memory", 1), ("check", "check", 1), ("unmeasured", "unmeasured", 2), ("retried", "memory", 1)]
    assert groups[0]["runs"][0]["failures"][1].endswith("Service Unavailable") and "Per router, MiB" in groups[0]["hint"]
    assert groups[2]["title"] == "Not measured" and groups[2]["runs"][0]["message"] == "no rest value: its metrics could not be computed"
    assert groups[3]["title"].endswith("then completed") and groups[3]["runs"][0]["run"] == second.index


def test_the_runs_tab_lists_the_problems_and_the_header_links_to_them(client, lab_files, monkeypatch):
    dataset, _ = result_with_problems()
    # The fake runs have no samples to analyse.
    monkeypatch.setattr(analysis, "run_summary", lambda d: {})
    monkeypatch.setattr(analysis, "summary", lambda d: [])
    monkeypatch.setattr(analysis, "to_measure", lambda d: 0)
    page = client.get(f"/results/{dataset.name}?tab=runs").text
    assert 'id="problems"' in page and "Routers took more than their memory" in page and "Attempt 2: x /noise/pause" in page
    assert "completed only after a failed attempt" in page and "tab=runs#problems" in page
    assert "r1 misses 1 of 1 prefixes" in page
    assert "Did not pass." not in page  # not finished: no verdict yet
    dataset.write_status({**dataset.status, "state": "finished"})
    page = client.get(f"/results/{dataset.name}?tab=runs").text
    assert "Did not pass." in page and "2 runs not measured, without a rest value." in page and "Passed:" not in page


def test_checks_that_fail_alike_in_many_runs_are_one_row():
    found = [{"topology": "t", "variant": "obgp-hp", "scenario": "s", "run": k, "kind": "check", "cause": "check", "step": step, "t": 17.1,
              "problems": [f"{r} misses 20 of 20 prefixes"]} for k in range(1, 11) for step, r in (("6.0", "r"), ("6.1", "q"))]
    group, = problems.grouped(found)
    row, = group["rows"]
    assert row["span"] == "1 to 10" and len(row["lines"]) == 1 and row["lines"][0]["problems"] == ["r misses 20 of 20 prefixes", "q misses 20 of 20 prefixes"]
    assert problems.spans([1, 2, 3, 5, 7, 8]) == "1 to 3, 5, 7 to 8"


def test_a_run_that_reaches_less_than_bgp_or_loops_or_never_rests_broke_a_property(monkeypatch):
    from lab.results import RunKey

    e = Experiment.model_validate({"name": "x", "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "bgp", "mode": "bgp"}, {"name": "obgp-rp", "mode": "obgp-rp"}]})
    final = lambda held, looping=(), holed=(): {"name": "final", "t": 9, "stable": True, "prefixes": 1, "held": held, "stale": {r: 0 for r in held},
                                                "loops": len(looping), "holes": len(holed), "looping": list(looping), "holed": list(holed)}
    p = "10.0.0.0/24"
    runs = {RunKey("t", "bgp", "s", 1): {"status": "completed", "events": [final({"r1": 1, "r3": 1})]},
            RunKey("t", "obgp-rp", "s", 1): {"status": "completed", "events": [
                final({"r1": 1, "r3": 0}, looping=[p]),
                {"name": "expect", "t": 8, "passed": False, "allowed": True, "routers": ["r3"], "prefixes": "all", "problems": ["r3 misses 1 of 1 prefixes"]}]}}
    dataset = type("D", (), {"experiment": e, "keys": lambda self: list(runs), "is_done": lambda self, k: k in runs, "run": lambda self, k: runs[k]})()

    # BGP at rest: the fewer routes of r3 are compared, and the check allowed to fail for r3 foretold them.
    monkeypatch.setattr(analysis, "run_summary", lambda d: {})
    found = {(x["variant"], x["cause"]): x for x in rested(problems.broken(dataset))}
    assert set(found) == {("obgp-rp", "loops"), ("obgp-rp", "reach")}
    assert found["obgp-rp", "reach"]["message"] == "r3 holds 0 of the 1 prefixes BGP holds" and found["obgp-rp", "reach"]["predicted"]
    assert not found["obgp-rp", "loops"]["predicted"]  # no check of forwarding was allowed to fail

    # BGP never at rest: no reference, said as such, never a comparison with a moment of an oscillation.
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(RunKey("t", "bgp", "s", 1)): {"oscillates": 1}})
    found = {(x["variant"], x["cause"]) for x in rested(problems.broken(dataset))}
    assert found == {("bgp", "rest-end"), ("obgp-rp", "loops"), ("obgp-rp", "reference")}
    titles = {g["title"] for g in problems.grouped(rested(problems.broken(dataset)))}
    # Without a prediction BGP's restlessness is told, not judged.
    assert titles == {"Routes still change at the end, no prediction", "Loops at rest", "No BGP run at rest to compare with"}
    told = rested(problems.broken(dataset))
    assert next(x for x in told if x["cause"] == "rest-end")["predicted"] is None
    dataset.status, dataset.meta = {"state": "finished"}, {}
    assert problems.verdict(dataset, told)["reasons"] == ["1 run broke a property the simulator did not predict"]  # OBGP's, not BGP's


def test_black_holes_and_stale_routes_count_without_bgp_and_the_way_to_rest_is_checked(monkeypatch):
    from lab.results import RunKey

    e = Experiment.model_validate({"name": "x", "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "bgp", "mode": "bgp"}, {"name": "obgp-rp", "mode": "obgp-rp"}]})
    resolution = 2 * e.sampling_of("obgp-rp").interval
    final = lambda holed=(), stale=0: {"name": "final", "t": 9, "stable": True, "prefixes": 1, "held": {"r1": 1}, "stale": {"r1": stale},
                                       "loops": 0, "holes": len(holed), "looping": [], "holed": list(holed)}
    bgp, obgp = RunKey("t", "bgp", "s", 1), RunKey("t", "obgp-rp", "s", 1)
    runs = {bgp: {"status": "completed", "events": [final()]},
            obgp: {"status": "completed", "events": [final(holed=["10.0.0.0/24"], stale=2)]}}
    dataset = type("D", (), {"experiment": e, "keys": lambda self: list(runs), "is_done": lambda self, k: k in runs, "run": lambda self, k: runs[k]})()
    # BGP oscillates: OBGP's black hole and withdrawn routes count on their own.
    # On the way OBGP loops longer than BGP beyond the resolution, holes no longer, and waits without a route.
    monkeypatch.setattr(analysis, "run_summary", lambda d: {
        str(bgp): {"oscillates": 1, "loops_s": 1.0, "holes_s": 3.0},
        str(obgp): {"loops_s": 1.0 + resolution + 0.5, "holes_s": 3.0 + resolution, "blocked_s": resolution + 1.5, "blocked_max": 2}})
    found = {(x["variant"], x["cause"]): x["message"] for x in rested(problems.broken(dataset))}
    assert set(found) == {("bgp", "rest-end"), ("obgp-rp", "holes-alone"), ("obgp-rp", "stale-alone"), ("obgp-rp", "loops-way"), ("obgp-rp", "blocked")}
    assert "BGP of this seed 1 s" in found["obgp-rp", "loops-way"] and "up to 2 prefixes" in found["obgp-rp", "blocked"]
    assert "beyond the 1 s refresh pruning waits by design" in found["obgp-rp", "blocked"]
    # Blocking within the wait for a route refresh is the design, not a problem.
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(bgp): {"oscillates": 1}, str(obgp): {"blocked_s": 1.0, "blocked_max": 2}})
    assert ("obgp-rp", "blocked") not in {(x["variant"], x["cause"]) for x in rested(problems.broken(dataset))}
    # Without BGP's measure of this seed, loops on the way are not judged.
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(bgp): {"oscillates": 1}, str(obgp): {"loops_s": 9.0}})
    assert ("obgp-rp", "loops-way") not in {(x["variant"], x["cause"]) for x in rested(problems.broken(dataset))}
    # Holes where BGP loops longer: no packet is lost longer than in BGP, no problem.
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(bgp): {"oscillates": 1, "loops_s": 22.4, "holes_s": 0.0},
                                                            str(obgp): {"loops_s": 12.5, "holes_s": 3.7}})
    assert ("obgp-rp", "holes-way") not in {(x["variant"], x["cause"]) for x in rested(problems.broken(dataset))}
    # A final check skipped for a large table is told.
    runs[obgp] = {"status": "completed", "events": [{"name": "final", "t": 9, "stable": True, "prefixes": 3000, "skipped": "more than 2000 prefixes"}]}
    assert ("obgp-rp", "unchecked") in {(x["variant"], x["cause"]) for x in rested(problems.broken(dataset))}


def test_sessions_that_fall_without_a_step_for_it_are_a_problem(monkeypatch):
    from lab.results import RunKey

    e = Experiment.model_validate({"name": "x", "topologies": ["noble-eu"], "scenarios": ["fill-60"], "variants": [{"name": "bgp", "mode": "bgp"}]})
    key = RunKey("t", "bgp", "s", 1)
    runs = {key: {"status": "completed", "events": []}}
    dataset = type("D", (), {"experiment": e, "keys": lambda self: list(runs), "is_done": lambda self, k: k in runs, "run": lambda self, k: runs[k]})()
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(key): {"flaps": 2, "sessions_down_end": 0}})
    assert [x["message"] for x in rested(problems.broken(dataset))] == ["sessions fell 2 times, counted at both ends"]
    runs[key]["events"] = [{"name": "down", "mode": "cut", "routers": ["r1"], "t": 3.0}]  # a step took them down
    assert rested(problems.broken(dataset)) == []


def test_paths_against_the_relations_count_beyond_what_bgp_leaks(monkeypatch):
    from lab.results import RunKey

    e = Experiment.model_validate({"name": "x", "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "bgp", "mode": "bgp"}, {"name": "obgp-rp", "mode": "obgp-rp"}]})
    final = lambda valleys: {"name": "final", "t": 9, "stable": True, "prefixes": 1, "held": {"r1": 1, "r2": 1}, "stale": {},
                             "loops": 0, "holes": 0, "looping": [], "holed": [], "valleys": valleys}
    runs = {RunKey("t", "bgp", "s", 1): {"status": "completed", "events": [final({"r1": 1})]},
            RunKey("t", "obgp-rp", "s", 1): {"status": "completed", "events": [final({"r1": 1, "r2": 3})]}}
    dataset = type("D", (), {"experiment": e, "keys": lambda self: list(runs), "is_done": lambda self, k: k in runs, "run": lambda self, k: runs[k]})()
    monkeypatch.setattr(analysis, "run_summary", lambda d: {})
    # The leak BGP has too, by the scenario's policies, is no problem: only what OBGP adds.
    assert [(x["cause"], x["message"]) for x in rested(problems.broken(dataset))] == [("policy", "r2 routes 3 prefixes against the relations, BGP 0")]


def test_a_check_foretells_only_its_own_kind_and_the_simulator_foretells_unrest(monkeypatch):
    from lab.results import RunKey

    e = Experiment.model_validate({"name": "x", "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "bgp", "mode": "bgp"}, {"name": "obgp-rp", "mode": "obgp-rp"}]})
    p = "10.0.0.0/24"
    final = lambda held, looping=(): {"name": "final", "t": 9, "stable": True, "prefixes": 1, "held": held, "stale": {},
                                      "loops": len(looping), "holes": 0, "looping": list(looping), "holed": []}
    # A forwarding check allowed to fail that found a missing route foretells no loop.
    allowed = {"name": "expect", "t": 8, "passed": False, "allowed": True, "routers": ["r1"], "forwarding": True, "problems": ["r1 misses 1 of 1 prefixes"]}
    bgp, obgp = RunKey("t", "bgp", "s", 1), RunKey("t", "obgp-rp", "s", 1)
    runs = {bgp: {"status": "completed", "events": [final({"r1": 1})]}, obgp: {"status": "completed", "events": [final({"r1": 1}, [p]), allowed]}}
    meta = {"predictions": {"t|s": {"bgp": {"converged": 4, "runs": 20, "endless": 16}, "obgp-rp": {"converged": 0, "runs": 20}}}}
    dataset = type("D", (), {"experiment": e, "meta": meta, "keys": lambda self: list(runs), "is_done": lambda self, k: k in runs, "run": lambda self, k: runs[k]})()
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(bgp): {"oscillates": 1, "hold_churn": 900.0, "rest_s": 120.0}, str(obgp): {"oscillates": 0}})
    found = {(x["variant"], x["cause"]): x for x in rested(problems.broken(dataset))}
    assert not found["obgp-rp", "loops"]["predicted"]
    # BGP without rest where the simulator rests in 4 of 20 orders: the hypothesis.
    assert found["bgp", "rest-end"]["predicted"] and "rests in 4 of 20 orders and repeats without end in 16" in found["bgp", "rest-end"]["message"]
    # OBGP at rest where the simulator never rests: a deviation between the two.
    assert "never does in 20 orders" in found["obgp-rp", "rest-unforeseen"]["message"]
    # The simulator has no timers: with an MRAI that rest is no deviation.
    dataset.experiment = e.model_copy(update={"bgp": e.bgp.model_copy(update={"mrai": 30})})
    assert ("obgp-rp", "rest-unforeseen") not in {(x["variant"], x["cause"]) for x in rested(problems.broken(dataset))}
    dataset.experiment = e
    assert problems.no_rest_predicted(dataset, bgp) and not problems.no_rest_predicted(dataset, RunKey("t", "other", "s", 1))
    # A scenario with random targets has a prediction per run, which goes first.
    meta["predictions"]["t|s#1"] = {"bgp": {"converged": 20, "runs": 20}}
    assert not problems.no_rest_predicted(dataset, bgp) and problems.no_rest_predicted(dataset, RunKey("t", "bgp", "s", 2))
    del meta["predictions"]["t|s#1"]
    # Without rest at the end, in a step and at the final check: one problem, each told inside it.
    runs[bgp] = {"status": "completed", "events": [{**final({"r1": 1}), "stable": False}], "measurements": [{"step": 3, "t": 5, "stable": False}]}
    no_rest = [x for x in rested(problems.broken(dataset)) if x["variant"] == "bgp"]
    assert [x["cause"] for x in no_rest] == ["rest-end"] and len(no_rest[0]["failures"]) == 3


def test_expect_none_counts_withdrawn_routes_still_held():
    # After a withdrawal nothing is announced: a route still held is the problem, not a pass.
    from lab import scenario
    from lab.runner import check_routes
    e = scenario.Expect(router="all", prefixes="none")
    route = {"from": "r2", "as_path": [65001]}
    assert check_routes(e, set(), {"r1": {"10.0.0.0/24": route}, "r2": {}}, None) == ["r1 holds 1 prefixes"]
    assert check_routes(e, set(), {"r1": {}}, None) == []


def test_a_loss_foretold_by_a_check_of_some_origins_is_predicted():
    run = {"events": [{"name": "expect", "allowed": True, "routers": ["x-c"], "prefixes": "all", "of": "one-table-sources",
                       "problems": ["x-c misses 30 of 30 prefixes"]}]}
    assert problems._predicted(run, {"x-c"}, "reach")


def test_a_loop_on_the_way_the_simulator_saw_is_predicted():
    from lab.results import RunKey

    meta = {"predictions": {"t|s": {"obgp-rp": {"converged": 20, "runs": 20, "findings": {"transient-loop": 20}}}}}
    e = Experiment.model_validate({"name": "x", "topologies": ["bad-gadget"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "obgp-rp", "mode": "obgp-rp"}]})
    dataset = type("D", (), {"experiment": e, "meta": meta})()
    assert problems.way_predicted(dataset, RunKey("t", "obgp-rp", "s", 1), "loops-way")
    assert not problems.way_predicted(dataset, RunKey("t", "obgp-rp", "s", 1), "holes-way")
    # Asked before the simulator looked at the way: nothing foretold.
    meta["predictions"]["t|s"]["obgp-rp"].pop("findings")
    assert not problems.way_predicted(dataset, RunKey("t", "obgp-rp", "s", 1), "loops-way")


def test_a_completed_run_without_a_rest_value_is_not_measured_and_says_why(monkeypatch):
    from lab.results import RunKey

    e = Experiment.model_validate({"name": "x", "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "bgp", "mode": "bgp"}]})
    keys = [RunKey("t", "bgp", "s", i) for i in (1, 2, 3, 4)]
    runs = {k: {"status": "completed", "events": []} for k in keys}
    dataset = type("D", (), {"experiment": e, "keys": lambda self: list(runs), "is_done": lambda self, k: k in runs, "run": lambda self, k: runs[k]})()
    quiet = e.quiet_s("bgp")
    monkeypatch.setattr(analysis, "run_summary", lambda d: {
        str(keys[0]): {"oscillates": 0, "settle_s": 4.0},  # measured, at rest
        str(keys[1]): {"settle_s": 4.0},  # the hold after the last step too short to judge
        str(keys[2]): {"oscillates": 0, "settle_s": None},
        str(keys[3]): {"oscillates": 1, "rest_s": 30.0},  # no rest: a property, not unmeasured
    })
    found = {x["run"]: x for x in problems.broken(dataset)}
    assert set(found) == {2, 3, 4}
    assert found[2]["kind"] == "unmeasured" and found[2]["message"] == f"no rest value: its samples after the last step span less than {quiet:g} s at rest, {3 * quiet:g} s still changing"
    assert found[3]["kind"] == "unmeasured" and found[3]["message"] == f"no rest value: the routes never stayed unchanged for {quiet:g} s"
    assert found[4]["kind"] == "property" and found[4]["message"] == "30 s after the last step the routes still change"


def test_a_finished_result_passes_only_without_errors_unmeasured_runs_and_unforeseen_problems():
    where = {"topology": "t", "variant": "v", "scenario": "s"}
    d = lambda state, meta={}, done=True: type("D", (), {"status": {"state": state}, "meta": meta, "keys": lambda self: [1],
                                                       "is_done": lambda self, k: done})()
    assert problems.verdict(d("running"), []) == {"passed": None, "reasons": []}
    assert problems.verdict(d("finished"), []) == {"passed": True, "reasons": []}
    # A foretold property and a retried run do not fail it.
    ok = [{**where, "run": 1, "kind": "property", "predicted": True}, {**where, "run": 2, "kind": "retried"}]
    assert problems.verdict(d("finished"), ok)["passed"] is True
    found = ok + [{**where, "run": 3, "kind": "error"}, {**where, "run": 4, "kind": "unmeasured"}, {**where, "run": 5, "kind": "unmeasured"},
                  {**where, "run": 6, "kind": "check"}, {**where, "run": 6, "kind": "check"},
                  {**where, "run": 7, "kind": "property", "predicted": False}]
    assert problems.verdict(d("finished"), found) == {"passed": False, "reasons": [
        "1 run ended in an error", "2 runs not measured", "1 run failed a check", "1 run broke a property the simulator did not predict"]}


def test_a_result_without_a_run_fails_and_an_imported_one_is_not_judged():
    d = lambda meta={}, done=True: type("D", (), {"status": {"state": "finished"}, "meta": meta, "keys": lambda self: [1],
                                                 "is_done": lambda self, k: done})()
    assert problems.verdict(d(done=False), []) == {"passed": False, "reasons": ["no run ran on this host"]}
    assert problems.verdict(d({"imported": {"from": "original/"}}), [])["passed"] is None


def test_without_a_prediction_only_bgp_and_mixed_modes_go_unjudged(monkeypatch):
    from lab.results import RunKey

    e = Experiment.model_validate({"name": "x", "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "bgp", "mode": "bgp"}, {"name": "obgp-rp", "mode": "obgp-rp"},
                                                {"name": "random-rp", "mode": "random-rp", "share": 0.5}]})
    final = {"name": "final", "t": 9, "stable": False, "prefixes": 1, "held": {"r1": 1}, "stale": {}, "loops": 0, "holes": 0, "looping": [], "holed": []}
    runs = {RunKey("t", v, "s", 1): {"status": "completed", "events": [final]} for v in ("bgp", "obgp-rp", "random-rp")}
    dataset = type("D", (), {"experiment": e, "meta": {}, "keys": lambda self: list(runs), "is_done": lambda self, k: k in runs, "run": lambda self, k: runs[k],
                             "status": {"state": "finished"}})()
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(k): {"oscillates": 1} for k in runs})
    told = rested(problems.broken(dataset))
    assert {x["variant"]: x["predicted"] for x in told if x["cause"] == "rest-end"} == {"bgp": None, "obgp-rp": False, "random-rp": None}
    # OBGP is to come to rest: without a prediction its restlessness still fails the verdict.
    assert problems.verdict(dataset, told)["reasons"] == ["1 run broke a property the simulator did not predict"]
