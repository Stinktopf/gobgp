from lab import analysis, config, problems, results
from lab.config import Experiment

OOM = "brussels, lyon took more than 512 MB and restarted"


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
    assert [(g["kind"], g["cause"], len(g["runs"])) for g in groups] == [("error", "memory", 1), ("check", "check", 1), ("retried", "memory", 1)]
    assert groups[0]["runs"][0]["failures"][1].endswith("Service Unavailable") and "Per router, MiB" in groups[0]["hint"]
    assert groups[2]["title"].endswith("then completed") and groups[2]["runs"][0]["run"] == second.index


def test_the_runs_tab_lists_the_problems_and_the_header_links_to_them(client, lab_files, monkeypatch):
    dataset, _ = result_with_problems()
    # The fake runs have no samples to analyse.
    monkeypatch.setattr(analysis, "run_summary", lambda d: {})
    monkeypatch.setattr(analysis, "summary", lambda d: [])
    page = client.get(f"/results/{dataset.name}?tab=runs").text
    assert 'id="problems"' in page and "Routers took more than their memory" in page and "Attempt 2: x /noise/pause" in page
    assert "completed only after a failed attempt" in page and "tab=runs#problems" in page
    assert "r1 misses 1 of 1 prefixes" in page


def test_checks_that_fail_alike_in_many_runs_are_one_row():
    from lab import problems

    found = [{"topology": "t", "variant": "obgp-hp", "scenario": "s", "run": k, "kind": "check", "cause": "check", "step": step, "t": 17.1,
              "problems": [f"{r} misses 20 of 20 prefixes"]} for k in range(1, 11) for step, r in (("6.0", "r"), ("6.1", "q"))]
    group, = problems.grouped(found)
    row, = group["rows"]
    assert row["span"] == "1 to 10" and len(row["lines"]) == 1 and row["lines"][0]["problems"] == ["r misses 20 of 20 prefixes", "q misses 20 of 20 prefixes"]
    assert problems.spans([1, 2, 3, 5, 7, 8]) == "1 to 3, 5, 7 to 8"


def test_a_run_that_reaches_less_than_bgp_or_loops_or_never_rests_broke_a_property(monkeypatch):
    from lab import analysis, problems
    from lab.config import Experiment
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
    found = {(x["variant"], x["cause"]): x for x in problems.broken(dataset)}
    assert set(found) == {("obgp-rp", "loops"), ("obgp-rp", "reach")}
    assert found["obgp-rp", "reach"]["message"] == "r3 holds 0 of the 1 prefixes BGP holds" and found["obgp-rp", "reach"]["predicted"]
    assert not found["obgp-rp", "loops"]["predicted"]  # no check of forwarding was allowed to fail

    # BGP never at rest: no reference, said as such, never a comparison with a moment of an oscillation.
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(RunKey("t", "bgp", "s", 1)): {"oscillates": 1}})
    found = {(x["variant"], x["cause"]) for x in problems.broken(dataset)}
    assert found == {("bgp", "rest-end"), ("obgp-rp", "loops"), ("obgp-rp", "reference")}
    titles = {g["title"] for g in problems.grouped(problems.broken(dataset))}
    assert titles == {"Routes still change at the end", "Loops at rest", "No BGP run at rest to compare with"}


def test_black_holes_and_stale_routes_count_without_bgp_and_the_way_to_rest_is_checked(monkeypatch):
    from lab import analysis, problems
    from lab.config import Experiment
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
    found = {(x["variant"], x["cause"]): x["message"] for x in problems.broken(dataset)}
    assert set(found) == {("bgp", "rest-end"), ("obgp-rp", "holes-alone"), ("obgp-rp", "stale-alone"), ("obgp-rp", "loops-way"), ("obgp-rp", "blocked")}
    assert "BGP of this seed 1 s" in found["obgp-rp", "loops-way"] and "up to 2 prefixes" in found["obgp-rp", "blocked"]
    assert "beyond the 1 s refresh pruning waits by design" in found["obgp-rp", "blocked"]
    # Blocking within the wait for a route refresh is the design, not a problem.
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(bgp): {"oscillates": 1}, str(obgp): {"blocked_s": 1.0, "blocked_max": 2}})
    assert ("obgp-rp", "blocked") not in {(x["variant"], x["cause"]) for x in problems.broken(dataset)}
    # Without BGP's measure of this seed, loops on the way are not judged.
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(bgp): {"oscillates": 1}, str(obgp): {"loops_s": 9.0}})
    assert ("obgp-rp", "loops-way") not in {(x["variant"], x["cause"]) for x in problems.broken(dataset)}
    # A final check skipped for a large table is told.
    runs[obgp] = {"status": "completed", "events": [{"name": "final", "t": 9, "stable": True, "prefixes": 3000, "skipped": "more than 2000 prefixes"}]}
    assert ("obgp-rp", "unchecked") in {(x["variant"], x["cause"]) for x in problems.broken(dataset)}


def test_sessions_that_fall_without_a_step_for_it_are_a_problem(monkeypatch):
    from lab import analysis, problems
    from lab.config import Experiment
    from lab.results import RunKey

    e = Experiment.model_validate({"name": "x", "topologies": ["noble-eu"], "scenarios": ["fill-60"], "variants": [{"name": "bgp", "mode": "bgp"}]})
    key = RunKey("t", "bgp", "s", 1)
    runs = {key: {"status": "completed", "events": []}}
    dataset = type("D", (), {"experiment": e, "keys": lambda self: list(runs), "is_done": lambda self, k: k in runs, "run": lambda self, k: runs[k]})()
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(key): {"flaps": 2, "sessions_down_end": 0}})
    assert [x["message"] for x in problems.broken(dataset)] == ["sessions fell 2 times, counted at both ends"]
    runs[key]["events"] = [{"name": "down", "mode": "cut", "routers": ["r1"], "t": 3.0}]  # a step took them down
    assert problems.broken(dataset) == []


def test_paths_against_the_relations_count_beyond_what_bgp_leaks(monkeypatch):
    from lab import analysis, problems
    from lab.config import Experiment
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
    assert [(x["cause"], x["message"]) for x in problems.broken(dataset)] == [("policy", "r2 routes 3 prefixes against the relations, BGP 0")]


def test_a_check_foretells_only_its_own_kind_and_the_simulator_foretells_unrest(monkeypatch):
    from lab import analysis, problems
    from lab.config import Experiment
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
    meta = {"predictions": {"t|s": {"bgp": {"converged": 4, "runs": 20}, "obgp-rp": {"converged": 0, "runs": 20}}}}
    dataset = type("D", (), {"experiment": e, "meta": meta, "keys": lambda self: list(runs), "is_done": lambda self, k: k in runs, "run": lambda self, k: runs[k]})()
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(bgp): {"oscillates": 1, "hold_churn": 900.0, "rest_s": 120.0}, str(obgp): {"oscillates": 0}})
    found = {(x["variant"], x["cause"]): x for x in problems.broken(dataset)}
    assert not found["obgp-rp", "loops"]["predicted"]
    # BGP without rest where the simulator rests in 4 of 20 orders: the hypothesis.
    assert found["bgp", "rest-end"]["predicted"] and "rests in 4 of 20 orders" in found["bgp", "rest-end"]["message"]
    # OBGP at rest where the simulator never rests: a deviation between the two.
    assert "never does in 20 orders" in found["obgp-rp", "rest-unforeseen"]["message"]
    assert problems.restless_predicted(dataset, bgp) and not problems.restless_predicted(dataset, RunKey("t", "other", "s", 1))
