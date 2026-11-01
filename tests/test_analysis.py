"""The metrics of the paper's runs, which Table II reports."""

from statistics import median

import pytest

from lab import analysis
from lab.config import Experiment
from lab.results import Dataset, RunKey

PAPER = Dataset.find("ifip-networking-2026")


def medians(topology, variant, scenario):
    values = [analysis.run_metrics(PAPER, RunKey(topology, variant, scenario, i)) for i in range(1, PAPER.experiment.runs + 1)]
    return {m: median(v[m] for v in values if v[m] is not None) for m in ("convergence_s", "rib_mean", "rib_max")}


@pytest.mark.skipif(PAPER is None, reason="the paper's data is not checked out")
@pytest.mark.parametrize("topology, variant, expected", [
    ("germany50", "bgp", {"convergence_s": 5.0, "rib_mean": 150.327, "rib_max": 290.0}),
    ("germany50", "obgp", {"convergence_s": 4.0, "rib_mean": 78.286, "rib_max": 124.0}),
    ("noble-eu", "bgp", {"convergence_s": 36.0, "rib_mean": 112.962, "rib_max": 175.0}),
    ("noble-eu", "obgp", {"convergence_s": 2.0, "rib_mean": 76.077, "rib_max": 96.0}),
])
def test_full_drain_60_of_the_paper(topology, variant, expected):
    assert medians(topology, variant, "full-drain-60") == pytest.approx(expected, abs=1e-3)


def test_held_since_needs_the_state_until_the_end():
    times = [0, 1, 2, 3, 4, 5]
    assert analysis.held_since(times, lambda t: t >= 2, 3) == 2
    assert analysis.held_since(times, lambda t: t in (1, 2, 3), 3) is None


def test_stopped_routers_do_not_hide_their_outage():
    run = {"watched": ["a", "b"], "events": [{"name": "down", "t": 1.0, "routers": ["b"], "mode": "session", "links": []},
                                             {"name": "up", "t": 3.0, "routers": ["b"], "links": []}]}
    # b is stopped from 1 to 3 and answers again from 4 on
    samples = [{"t": t, "router": r} for t in (0.0, 1.0, 2.0, 3.0, 4.0) for r in ("a", "b") if not (r == "b" and 1 <= t <= 3)]
    assert list(analysis.ticks(samples, run)) == [0.0, 1.0, 2.0, 4.0]  # at 3 b should be back, but did not answer


def test_a_replay_says_whether_updates_were_counted(lab_files):
    d = Dataset.find("ifip-networking-2026")
    replay = analysis.replay(d, RunKey("germany50", "bgp", "fill-30", 1))
    assert replay["counters"] is False  # the former scripts did not count updates


def test_a_long_replay_keeps_at_most_its_frames(lab_files, monkeypatch):
    d = Dataset.find("ifip-networking-2026")
    full = analysis.replay(d, RunKey("germany50", "bgp", "fill-30", 1))
    monkeypatch.setattr(analysis, "FRAMES", 10)
    thin = analysis.replay(d, RunKey("germany50", "bgp", "fill-30", 1))
    assert len(thin["t"]) <= 10 < len(full["t"]) and thin["t"][0] == full["t"][0]
    assert all(len(f["paths"]) == len(thin["t"]) for f in thin["routers"].values())


def test_sizes_need_every_router_to_count_them():
    rows = [{"router": "a", "paths": 3, "suppressed": 2, "rss_mb": 20.5}, {"router": "b", "paths": 1, "suppressed": 0, "rss_mb": 19.0}]
    assert analysis.values_of(rows, "suppressed") == [2, 0] and analysis.values_of(rows, "rss_mb") == [20.5, 19.0]
    # Older runs did not count them.
    assert analysis.values_of([{"router": "a", "paths": 3}], "suppressed") is None
    assert analysis.values_of([{"router": "a", "paths": 3, "rss_mb": None}], "rss_mb") is None


def test_checks_count_the_runs_that_passed_all():
    run = lambda *passed: {"events": [{"name": "announce"}, *({"name": "expect", "passed": p} for p in passed)]}
    assert analysis._checks([run(True, True), run(True, False), run()]) == {"passed": 1, "runs": 2}
    assert analysis._checks([run(), run()]) is None


def test_failed_checks_list_every_failed_expect():
    class Fake:
        keys = lambda self: [RunKey("t", "obgp", "s", 1), RunKey("t", "bgp", "s", 1), RunKey("u", "bgp", "s", 1)]
        is_done = lambda self, key: True
        run = lambda self, key: {"events": [
            {"name": "expect", "passed": True, "step": "1", "t": 1.0},
            {"name": "expect", "passed": key.variant == "obgp", "step": "2", "t": 2.0, "routers": ["fulda"], "problems": ["fulda holds 2 prefixes"]}]}
    assert analysis.failed_checks(Fake(), "t") == [{"topology": "t", "scenario": "s", "variant": "bgp", "run": 1, "step": "2", "t": 2.0,
                                                    "routers": ["fulda"], "problems": ["fulda holds 2 prefixes"]}]
    assert len(analysis.failed_checks(Fake())) == 2


def test_cpu_seconds_add_up_across_a_restart():
    by_t = {0: [{"router": "a", "cpu_s": 1.0}], 1: [{"router": "a", "cpu_s": 1.5}], 2: [{"router": "a", "cpu_s": 0.2}], 3: [{"router": "a", "cpu_s": 0.7}]}
    assert analysis.used(by_t, [0, 1, 2, 3], "cpu_s") == {"a": 1.0}  # 0.5 before the restart, 0.5 after


def test_busy_routers_stand_by_their_latest_sample():
    from lab import analysis

    run = {"events": [], "watched": ["a", "b"]}
    s = lambda t, router: {"t": t, "router": router, "paths": t}
    # a and b answer at different ticks; c, an origin sampled for its next hops, is not watched and takes no part.
    ticks = analysis.ticks([s(0.0, "a"), s(0.0, "b"), s(0.1, "a"), s(0.2, "b"), s(0.3, "c"), s(3.0, "a")], run)
    assert [(t, [r["router"] for r in rows]) for t, rows in ticks.items()] == [
        (0.0, ["a", "b"]), (0.1, ["a", "b"]), (0.2, ["a", "b"]), (0.3, ["a", "b"]), (3.0, ["a", "b"])]
    assert ticks[0.1][1]["t"] == 0.0 and ticks[3.0][1]["t"] == 0.2  # b by its latest sample
    late = analysis.ticks([s(0.0, "a"), s(0.0, "b"), s(analysis.STALE_S + 1, "a")], run)
    assert list(late) == [0.0]  # b silent for longer than STALE_S: left out


def test_a_seldom_answering_router_shows_its_true_rate_in_the_replay(lab_files, monkeypatch):
    from lab import analysis
    from lab.results import Dataset, RunKey

    run = {"events": [], "watched": ["a", "b"], "status": "completed", "measurements": []}
    # b answers every tenth of a second, a every five seconds, and a gets 50 updates in those five.
    samples = [{"t": round(i / 10, 1), "router": "b", "paths": 1, "destinations": 1, "updates_rx": 0} for i in range(100)]
    samples += [{"t": float(t), "router": "a", "paths": 1, "destinations": 1, "updates_rx": n} for t, n in ((0, 0), (5, 50))]
    d = object.__new__(Dataset)
    monkeypatch.setattr(Dataset, "run", lambda self, key: run)
    monkeypatch.setattr(Dataset, "samples", lambda self, key: samples)
    churn = analysis.replay(d, RunKey("t", "v", "s", 1))["routers"]["a"]["churn"]
    assert max(churn) == 10.0  # 50 updates in 5 s, not 50 in a tenth


def test_the_wilcoxon_test_is_exact():
    from lab import analysis

    assert analysis.wilcoxon_p([1, 2, 3, 4, 5]) == 0.0625  # five pairs can never reach 5 %
    assert analysis.wilcoxon_p([-1, 2, 3, 4, 5, 6, 7, 8]) == 0.015625  # as scipy.stats.wilcoxon
    assert analysis.wilcoxon_p([0, 0, 3]) is None  # zero differences are left out
    assert analysis.wilcoxon_p([1, -1]) == 1.0


def test_runs_are_paired_by_their_seed(lab_files):
    from lab import analysis

    d = Dataset.find("ifip-networking-2026")
    p = analysis.paired(d, "bad-gadget", "fill-30", "rib_mean", "obgp", "bgp")
    assert p["n"] == 5 and p["change"] < 0 and p["p"] == 0.0625


def test_a_check_is_no_reference():
    from lab import analysis

    events = [{"name": "announce", "t": 0.0}, {"name": "announced", "t": 10.0, "expected": 20},
              {"name": "expect", "t": 11.0}, {"name": "withdraw", "t": 12.0, "expected": 0}]
    ref, _, _ = analysis.anchors(analysis.acting(events))
    assert ref["name"] == "withdraw"


def test_an_event_before_the_announcement_is_no_reference():
    from lab import analysis

    events = [{"name": "down", "t": 0.0}, {"name": "announce", "t": 1.0}, {"name": "announced", "t": 10.0, "expected": 20},
              {"name": "up", "t": 15.0, "expected": 20}]
    assert analysis.anchors(events)[0]["name"] == "up"


def test_the_median_ci_comes_from_order_statistics():
    six = analysis.median_ci([3, 1, 6, 2, 5, 4])
    assert (six["low"], six["high"]) == (1, 6) and six["level"] == pytest.approx(62 / 64)
    five = analysis.median_ci([1, 2, 3, 4, 5])  # cannot reach 95 %, says so
    assert (five["low"], five["high"]) == (1, 5) and five["level"] == pytest.approx(0.9375)
    ten = analysis.median_ci(list(range(1, 11)))  # x(2), x(9), as in the tables
    assert (ten["low"], ten["high"]) == (2, 9) and ten["level"] == pytest.approx(1 - 2 * 11 / 1024)
    assert analysis.median_ci([1]) is None and analysis.median_ci([1, 2]) is None  # two runs reach 50 %
    three = analysis.median_ci([3, 1, 2])
    assert (three["low"], three["high"]) == (1, 3) and three["level"] == pytest.approx(0.75)


def test_hodges_lehmann_with_the_interval_of_the_wilcoxon_test():
    d = [float(x) for x in range(1, 11)]
    hl = analysis.hodges_lehmann(d)
    walsh = sorted((d[i] + d[j]) / 2 for i in range(10) for j in range(i, 10))
    # For n = 10 the critical value is 8, so the interval runs from the 9th average.
    assert hl["estimate"] == pytest.approx(5.5) and (hl["low"], hl["high"]) == (walsh[8], walsh[-9])
    assert hl["level"] == pytest.approx(1 - 2 * 25 / 1024)
    assert analysis.hodges_lehmann([2.0]) is None


def test_series_give_the_median_over_the_runs_and_its_interval():
    d = Dataset.find("ifip-networking-2026")
    e = d.experiment
    s = analysis.series(d, e.topologies[0], e.variants[0].name, e.scenarios[0])
    paths = s["metrics"]["paths"]
    i = next(j for j, v in enumerate(paths["median"]) if v and paths["ci_level"][j])
    assert paths["ci_low"][i] <= paths["median"][i] <= paths["ci_high"][i]
    assert paths["ci_level"][i] == pytest.approx(0.9375)  # five runs
    assert paths["min"][i] <= paths["ci_low"][i] and paths["ci_high"][i] <= paths["max"][i]  # the routers spread wider


def test_cells_know_their_smallest_and_largest_router():
    d = Dataset.find("ifip-networking-2026")
    cell = next(g for g in analysis.summary(d) if g["metrics"]["rib_mean"])["metrics"]["rib_mean"]
    assert cell["router_min"] <= cell["median"] <= cell["router_max"]
    assert "router_min" not in (next(g for g in analysis.summary(d) if g["metrics"]["settle_s"])["metrics"]["settle_s"] or {})  # one value per network


def test_settling_holds_from_the_last_change_as_convergence_does():
    # The paper's runs: the last change at 8 s, the recording ends at 10 s, 3 samples at 1 Hz hold 2 s.
    states = {5: "a", 6: "b", 7: "c", 8: "d", 9: "d", 10: "d"}
    assert analysis.settled_since(list(states), states.get, 2) == 8
    assert analysis.settled_since(list(states), states.get, 3) is None  # holds 2 s only
    assert analysis.settled_since([5, 6, 7], {5: "a", 6: "a", 7: "a"}.get, 2) == 5  # never changed
    assert analysis.settled_since([], {}.get, 2) is None


def test_a_pause_between_mrai_waves_is_no_rest():
    # Waves 30 s apart, the last at 90 s, sampled once a second until 200 s.
    times = list(range(0, 201))
    state = lambda t: min(t // 30, 3) if t < 120 else 3
    e = Experiment.model_validate({"name": "x", "bgp": {"mrai": 30}, "sampling": {"interval": 1.0}, "topologies": ["noble-eu"],
                                   "scenarios": ["fill-60"], "variants": [{"name": "a", "mode": "obgp-rp"}]})
    assert analysis.settled_since(times[:85], state, e.sampling.stable_s - 1) == 60  # 3 s took the pause for rest
    assert analysis.settled_since(times[:85], state, e.quiet_s() - 1) is None
    assert analysis.settled_since(times, state, e.quiet_s() - 1) == 90


def test_a_run_that_ended_in_an_error_has_no_checks():
    class Fake:
        keys = lambda self: [RunKey("t", "obgp", "s", 1)]
        is_done = lambda self, key: True
        run = lambda self, key: {"status": "error", "message": "routers of t did not become ready"}  # no events
    assert analysis.failed_checks(Fake()) == []


def test_a_check_the_scenario_allows_to_fail_does_not_count_as_failed():
    from lab import modes

    assert modes.may_fail(["obgp-hp"], "obgp-hp") and modes.may_fail(["obgp-hp"], "random-hp")
    assert not modes.may_fail(["obgp-hp"], "obgp-rp") and not modes.may_fail([], "bgp")
    allowed = {"name": "expect", "passed": False, "allowed": True, "problems": ["r2 misses 1 of 1 prefixes"]}
    failed = {"name": "expect", "passed": False, "problems": ["r3 misses 1 of 1 prefixes"]}

    class Fake:
        keys = lambda self: [RunKey("t", "obgp-hard", "s", 1)]
        is_done = lambda self, key: True
        run = lambda self, key: {"status": "completed", "events": [allowed, failed]}
    assert [f["problems"] for f in analysis.failed_checks(Fake())] == [["r3 misses 1 of 1 prefixes"]]
    assert analysis._checks([{"events": [allowed]}, {"events": [allowed, failed]}]) == {"passed": 1, "runs": 2}


def test_holm_scales_the_smallest_p_by_the_number_of_tests_and_never_falls():
    from lab.analysis import holm

    assert holm([0.01, 0.04, 0.03, 0.005]) == [0.03, 0.06, 0.06, 0.02]
    assert holm([0.9]) == [0.9] and holm([0.6, 0.6]) == [1.0, 1.0] and holm([]) == []


def test_a_run_tells_reach_loops_and_blocking_from_its_final_check_and_samples():
    e = Experiment.model_validate({"name": "x", "sampling": {"interval": 1.0}, "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "a", "mode": "obgp-rp"}]})
    run = {"watched": ["r1", "r2"], "events": [{"name": "announce", "t": 0.0}, {"name": "announced", "t": 1.0},
                      {"name": "final", "t": 9.0, "prefixes": 2, "held": {"r1": 2, "r2": 1}, "loops": 1, "holes": 0, "problems": []}]}
    row = lambda t, r, waiting: {"t": t, "router": r, "destinations": 2, "paths": 2, "known": 2, "blocked": waiting, "path_len_avg": 1,
                                 "flaps": 1 + (r == "r1" and t >= 5), "sessions_down": int(r == "r2" and t == 9)}
    samples = [row(t, r, 1 if r == "r2" and 3 <= t < 6 else 0) for t in range(0, 10) for r in ("r1", "r2")]
    dataset = type("D", (), {"experiment": e, "samples": lambda self, k: samples})()
    out = analysis.run_metrics(dataset, RunKey("t", "a", "s", 1), run)
    assert out["unreached"] == 1 and out["loops_end"] == 1 and out["holes_end"] == 0
    assert out["blocked_max"] == 1 and out["blocked_s"] == 3.0 and out["known_mean"] == 2
    assert out["flaps"] == 1 and out["sessions_down_end"] == 1  # r1 lost a session at 5 s, r2 has one down at the end


def test_session_drops_count_only_where_no_step_touched_the_session():
    e = Experiment.model_validate({"name": "x", "sampling": {"interval": 1.0}, "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "a", "mode": "obgp-rp"}]})
    # r1-r2 was cut by a step, r3 restarted: the drop of r1-r4 and r4's session to r5 down at the end remain.
    run = {"watched": ["r1", "r4"], "events": [{"name": "announce", "t": 0.0}, {"name": "down", "mode": "cut", "routers": [], "links": [["r1", "r2"]], "t": 2.0},
                                               {"name": "restart", "routers": ["r3"], "t": 3.0}]}
    row = lambda t, r: {"t": t, "router": r, "destinations": 1, "paths": 1, "path_len_avg": 1,
                        "flaps_by": {"r1": f"r2={int(t >= 2)} r3={int(t >= 3)} r4={int(t >= 4)}", "r4": "r1=0 r5=0"}[r],
                        "down_by": "r5" if r == "r4" and t == 5 else ""}
    samples = [row(t, r) for t in range(0, 6) for r in ("r1", "r4")]
    dataset = type("D", (), {"experiment": e, "samples": lambda self, k: samples})()
    out = analysis.run_metrics(dataset, RunKey("t", "a", "s", 1), run)
    assert out["flaps_unplanned"] == 1 and out["down_unplanned"] == 1


def test_loops_on_the_way_are_timed_from_the_next_hops_sampled_on_change():
    routers = {r: {"asn": n, "neighbors": []} for n, r in enumerate(("o", "a", "b"), 64600)}
    dataset = type("D", (), {"topology": lambda self, name: {"routers": routers}})()
    p = "10.0.0.0/24"
    own = {"o": [{"t": 0.5, "hops": f"{p}=."}],
           "a": [{"t": 1.0, "hops": f"{p}=o|"}, {"t": 4.0, "hops": f"{p}=b|"}, {"t": 7.0, "hops": f"{p}=o|"}],
           "b": [{"t": 1.0, "hops": f"{p}=o|"}, {"t": 4.0, "hops": f"{p}=a|"}, {"t": 6.0, "hops": "~"}]}
    # a and b send to each other from 4 s until b loses its route at 6 s, then a sends to b without a route until 7 s.
    # The origin o delivers its own prefix.
    assert analysis.loops_on_the_way(dataset, RunKey("t", "v", "s", 1), {}, own, 0.0, 10.0) == (2.0, 1, 1.0, 1)
    assert analysis.loops_on_the_way(dataset, RunKey("t", "v", "s", 1), {}, {"a": [{"t": 1.0, "hops": ""}]}, 0.0, 10.0) is None


def test_a_stopped_router_forwards_nothing_until_it_is_up_again():
    routers = {r: {"asn": n, "neighbors": []} for n, r in enumerate(("o", "a", "b"), 64600)}
    dataset = type("D", (), {"topology": lambda self, name: {"routers": routers}})()
    p = "10.0.0.0/24"
    own = {"o": [{"t": 0.5, "hops": f"* {p}=."}], "a": [{"t": 1.0, "hops": f"* {p}=b|"}], "b": [{"t": 1.0, "hops": f"* {p}=a|"}]}
    # a and b loop from 1 s; b stops at 3 s and comes back at 5 s with the routes it had: meanwhile a sends into a hole.
    run = {"events": [{"name": "down", "mode": "session", "routers": ["b"], "t": 3.0}, {"name": "up", "routers": ["b"], "t": 5.0}]}
    assert analysis.loops_on_the_way(dataset, RunKey("t", "v", "s", 1), run, own, 0.0, 10.0) == (7.0, 1, 2.0, 1)


def test_on_large_tables_loops_on_the_way_count_on_the_sample_from_when_it_was_named():
    routers = {r: {"asn": n, "neighbors": []} for n, r in enumerate(("o", "a", "b"), 64600)}
    dataset = type("D", (), {"topology": lambda self, name: {"routers": routers}})()
    p = "10.0.0.0/24"
    # Before the sample at 2 s the tables were too large to follow; then a and b loop from 4 s to 6 s.
    own = {"o": [{"t": 1.0, "hops": "!"}, {"t": 2.5, "hops": f"* {p}=."}],
           "a": [{"t": 1.0, "hops": "!"}, {"t": 2.5, "hops": f"* {p}=o|"}, {"t": 4.0, "hops": f"{p}=b|"}, {"t": 6.0, "hops": f"{p}=o|"}],
           "b": [{"t": 1.0, "hops": "!"}, {"t": 2.5, "hops": f"* {p}=a|"}]}
    run = {"events": [{"name": "hops_sample", "t": 2.0, "prefixes": 256, "of": 3000}]}
    assert analysis.loops_on_the_way(dataset, RunKey("t", "v", "s", 1), run, own, 0.0, 10.0) == (2.0, 1, 0.0, 0)
    assert analysis.loops_on_the_way(dataset, RunKey("t", "v", "s", 1), {"events": []}, own, 0.0, 10.0) is None
