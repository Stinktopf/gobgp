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
                                                    "routers": ["fulda"], "problems": ["fulda holds 2 prefixes"], "key": "2#0"}]
    assert len(analysis.failed_checks(Fake())) == 2


def test_cpu_seconds_add_up_across_a_restart():
    by_t = {0: [{"router": "a", "cpu_s": 1.0}], 1: [{"router": "a", "cpu_s": 1.5}], 2: [{"router": "a", "cpu_s": 0.2}], 3: [{"router": "a", "cpu_s": 0.7}]}
    assert analysis.used(by_t, [0, 1, 2, 3], "cpu_s") == {"a": 1.0}  # 0.5 before the restart, 0.5 after


def test_busy_routers_stand_by_their_latest_sample():
    run = {"events": [], "watched": ["a", "b"]}
    s = lambda t, router: {"t": t, "router": router, "paths": t}
    # a and b answer at different ticks; c, an origin sampled for its next hops, is not watched and takes no part.
    ticks = analysis.ticks([s(0.0, "a"), s(0.0, "b"), s(0.1, "a"), s(0.2, "b"), s(0.3, "c"), s(3.0, "a")], run)
    assert [(t, [r["router"] for r in rows]) for t, rows in ticks.items()] == [
        (0.0, ["a", "b"]), (0.1, ["a", "b"]), (0.2, ["a", "b"]), (0.3, ["a", "b"]), (3.0, ["a", "b"])]
    assert ticks[0.1][1]["t"] == 0.0 and ticks[3.0][1]["t"] == 0.2  # b by its latest sample
    late = analysis.ticks([s(0.0, "a"), s(0.0, "b"), s(analysis.STALE_S + 1, "a")], run)
    assert list(late) == [0.0]  # b silent for longer than STALE_S: left out
    # b samples only every 30 s: its sample stands while its next one shows no change, never across a change.
    quiet = analysis.ticks([s(0.0, "a"), s(0.0, "b"), s(15.0, "a"), s(30.0, "a"), {**s(30.0, "b"), "paths": 0.0}], run)
    assert list(quiet) == [0.0, 15.0, 30.0] and quiet[15.0][1]["t"] == 0.0
    moved = analysis.ticks([s(0.0, "a"), s(0.0, "b"), s(15.0, "a"), s(30.0, "a"), s(30.0, "b")], run)
    assert list(moved) == [0.0, 30.0]  # b changed somewhere in its gap: 15 s is left out


def test_a_seldom_answering_router_shows_its_true_rate_in_the_replay(lab_files, monkeypatch):
    run = {"events": [], "watched": ["a", "b"], "status": "completed", "measurements": []}
    # b answers every tenth of a second, a every five seconds, and a gets 50 updates in those five.
    samples = [{"t": round(i / 10, 1), "router": "b", "paths": 1, "destinations": 1, "updates_rx": 0} for i in range(100)]
    samples += [{"t": float(t), "router": "a", "paths": 1, "destinations": 1, "updates_rx": n} for t, n in ((0, 0), (5, 50))]
    d = object.__new__(Dataset)
    monkeypatch.setattr(Dataset, "run", lambda self, key: run)
    monkeypatch.setattr(Dataset, "samples", lambda self, key: samples)
    churn = analysis.replay(d, RunKey("t", "v", "s", 1))["routers"]["a"]["churn"]
    assert max(churn) == 10.0  # 50 updates in 5 s, not 50 in a tenth


def test_the_replay_gives_the_updates_per_direction_of_a_link(lab_files, monkeypatch):
    run = {"events": [], "watched": ["a", "b"], "status": "completed", "measurements": []}
    # a gets 10 updates a second from b, b gets none from a.
    samples = [{"t": float(t), "router": r, "paths": 1, "destinations": 1, "updates_rx": n, "peers_rx": f"{peer}={n}"}
               for t in range(3) for r, peer, n in (("a", "b", 10 * t), ("b", "a", 0))]
    d = object.__new__(Dataset)
    monkeypatch.setattr(Dataset, "run", lambda self, key: run)
    monkeypatch.setattr(Dataset, "samples", lambda self, key: samples)
    replay = analysis.replay(d, RunKey("t", "v", "s", 1))
    assert replay["directed"] == {"b>a": [0.0, 10.0, 10.0]}  # from b to a, a direction without updates left out
    assert "links" not in replay
    # Many routers: one line per link, both directions added.
    monkeypatch.setattr(analysis, "LANES", 1)
    replay = analysis.replay(d, RunKey("t", "v", "s", 1))
    assert replay["links"] == {"a|b": [0.0, 10.0, 10.0]} and "directed" not in replay


def test_the_wilcoxon_test_is_exact():
    assert analysis.wilcoxon_p([1, 2, 3, 4, 5]) == 0.0625  # five pairs can never reach 5 %
    assert analysis.wilcoxon_p([-1, 2, 3, 4, 5, 6, 7, 8]) == 0.015625  # as scipy.stats.wilcoxon
    assert analysis.wilcoxon_p([0, 0, 3]) is None  # zero differences are left out
    assert analysis.wilcoxon_p([1, -1]) == 1.0


def test_runs_are_paired_by_their_seed(lab_files):
    d = Dataset.find("ifip-networking-2026")
    p = analysis.paired(d, "bad-gadget", "fill-30", "rib_mean", "obgp", "bgp")
    assert p["n"] == 5 and p["change"] < 0 and p["p"] == 0.0625
    assert p["shift_pct"] < 0  # the shift in % of the baseline's median, as the speed rule judges it


def test_a_check_is_no_reference():
    events = [{"name": "announce", "t": 0.0}, {"name": "announced", "t": 10.0, "expected": 20},
              {"name": "expect", "t": 11.0}, {"name": "withdraw", "t": 12.0, "expected": 0}]
    ref, _, _ = analysis.anchors(analysis.acting(events))
    assert ref["name"] == "withdraw"


def test_the_sample_of_next_hops_is_no_reference():
    # Above 256 prefixes the runner names the sample right after the announcement.
    events = [{"name": "announce_rib", "t": 1.0}, {"name": "announced", "t": 50.0, "expected": 900},
              {"name": "hops_sample", "t": 50.4, "prefixes": 256, "of": 900}, {"name": "withdraw", "t": 200.0, "expected": 0}]
    assert analysis.anchors(analysis.acting(events))[0]["name"] == "withdraw"
    assert analysis.anchors(analysis.acting(events[:3]))[0]["name"] == "announced"


def _tail_run(settled_at: float, end: float):
    """A run of two routers, the last event at 10 s, the routes changing once a second until settled_at, sampled until end."""
    e = Experiment.model_validate({"name": "x", "sampling": {"interval": 1.0}, "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "a", "mode": "obgp-rp"}]})
    run = {"watched": ["r1", "r2"], "events": [{"name": "announce", "t": 0.0}, {"name": "announced", "t": 5.0, "expected": 2},
                                               {"name": "withdraw", "t": 10.0, "expected": 2}]}
    row = lambda t, r: {"t": float(t), "router": r, "destinations": 2, "paths": 2 + int(min(t, settled_at)), "path_len_avg": 1,
                        "updates_rx": int(min(t, settled_at))}
    samples = [row(t, r) for t in range(0, int(end) + 1) for r in ("r1", "r2")]
    dataset = type("D", (), {"experiment": e, "samples": lambda self, k: samples})()
    return analysis.run_metrics(dataset, RunKey("t", "a", "s", 1), run), e.quiet_s("a")


def test_a_run_at_rest_needs_only_the_quiet_time_after_the_last_event():
    # Settled at 12 s, sampled until 18 s: 8 s after the last event, less than three quiet times, as the final check ends it.
    out, quiet = _tail_run(12, 18)
    assert 18 - 10 < 3 * quiet and out["oscillates"] == 0 and out["rest_s"] == 8.0 and out["settle_s"] == 2.0


def test_settling_after_the_last_step_counts_from_the_end_of_a_series():
    # A flap at 10 s and one at 20 s, routes changing until 23 s, sampled until 30 s.
    e = Experiment.model_validate({"name": "x", "sampling": {"interval": 1.0}, "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "a", "mode": "obgp-rp"}]})
    run = {"watched": ["r1"], "events": [{"name": "announce", "t": 0.0}, {"name": "announced", "t": 5.0, "expected": 2},
                                         {"name": "down", "t": 10.0}, {"name": "down", "t": 20.0}]}
    changes = lambda t: int(min(t, 12)) + int(max(0, min(t, 23) - 20))
    samples = [{"t": float(t), "router": "r1", "destinations": 2, "paths": 2 + changes(t), "path_len_avg": 1, "updates_rx": changes(t)}
               for t in range(0, 31)]
    dataset = type("D", (), {"experiment": e, "samples": lambda self, k: samples})()
    out = analysis.run_metrics(dataset, RunKey("t", "a", "s", 1), run)
    assert out["settle_s"] == 2.0 and out["settle_end_s"] == 3.0
    out, _ = _tail_run(99, 30)
    assert out["settle_end_s"] is None  # no rest, no time to it


def test_updates_at_rest_count_from_the_time_the_routes_came_to_rest():
    # A withdrawal whose tail lasts longer than the quiet time: no update at rest, as the routes rest from then.
    _, quiet = _tail_run(12, 18)
    out, _ = _tail_run(10 + quiet + 3, 10 + 6 * quiet)
    assert out["settle_s"] == quiet + 3 and out["hold_churn"] == 0
    # Never at rest: one update a second from the quiet time on.
    out, _ = _tail_run(99, 10 + 3 * quiet)
    assert out["hold_churn"] == 1


def test_routes_still_changing_need_three_quiet_times_to_count_as_oscillating():
    out, quiet = _tail_run(99, 18)
    assert out["oscillates"] is None  # a slow exploration may still end
    out, _ = _tail_run(99, 10 + 3 * quiet)
    assert out["oscillates"] == 1


def test_routes_settled_for_the_quiet_time_rest_as_settle_s_says():
    # The last change one quiet time less one interval before the end: settled, so not still changing either.
    out, quiet = _tail_run(38, 40)
    assert quiet == 3 and out["settle_s"] == 28.0 and out["oscillates"] == 0
    out, _ = _tail_run(39, 40)  # one second later it is too short for rest and still changes at the end
    assert out["settle_s"] is None and out["oscillates"] == 1


def test_an_event_before_the_announcement_is_no_reference():
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


def test_loops_and_holes_beyond_the_resolution_leave_out_shorter_ones():
    routers = {r: {"asn": n, "neighbors": []} for n, r in enumerate(("o", "a", "b"), 64600)}
    dataset = type("D", (), {"topology": lambda self, name: {"routers": routers}})()
    p, q = "10.0.0.0/24", "10.0.1.0/24"
    # p: a and b loop from 4 s to 6 s, a sends into a hole until 7 s. q: a reads its route via b 50 ms before b's
    # route is read, as routers read their next hops one after another: a hole of 50 ms.
    own = {"o": [{"t": 0.5, "hops": f"{p}=. {q}=."}],
           "a": [{"t": 1.0, "hops": f"{p}=o|"}, {"t": 2.0, "hops": f"{q}=b|"}, {"t": 4.0, "hops": f"{p}=b|"}, {"t": 7.0, "hops": f"{p}=o|"}],
           "b": [{"t": 1.0, "hops": f"{p}=o|"}, {"t": 2.05, "hops": f"{q}=o|"}, {"t": 4.0, "hops": f"{p}=a|"}, {"t": 6.0, "hops": f"{p}=-"}]}
    checks: list = []
    assert analysis.loops_on_the_way(dataset, RunKey("t", "v", "s", 1), {}, own, 0.0, 10.0, checks=checks) == (2.0, 1, 1.05, 1)
    assert analysis.lasting(checks, 0.0, 10.0, 0.2) == (2.0, 1.0)
    assert analysis.lasting(checks, 0.0, 6.5, 0.2) == (2.0, 0.5)  # counted within the window
    assert analysis.lasting(checks, 0.0, 10.0, 1.5) == (2.0, 0.0)


def test_a_stopped_router_forwards_nothing_until_it_is_up_again():
    routers = {r: {"asn": n, "neighbors": []} for n, r in enumerate(("o", "a", "b"), 64600)}
    dataset = type("D", (), {"topology": lambda self, name: {"routers": routers}})()
    p = "10.0.0.0/24"
    own = {"o": [{"t": 0.5, "hops": f"* {p}=."}], "a": [{"t": 1.0, "hops": f"* {p}=b|"}], "b": [{"t": 1.0, "hops": f"* {p}=a|"}]}
    # a and b loop from 1 s; b stops at 3 s, a sends into a hole. b comes back at 5 s and is unknown until it tells its
    # routes: its old ones went with the restart, so packets end at b, neither looping nor lost.
    run = {"events": [{"name": "down", "mode": "session", "routers": ["b"], "t": 3.0}, {"name": "up", "routers": ["b"], "t": 5.0}]}
    assert analysis.loops_on_the_way(dataset, RunKey("t", "v", "s", 1), run, own, 0.0, 10.0) == (2.0, 1, 2.0, 1)
    # Once b tells its routes at 7 s, they count again: a loop from 7 s on.
    own["b"].append({"t": 7.0, "hops": f"* {p}=a|"})
    assert analysis.loops_on_the_way(dataset, RunKey("t", "v", "s", 1), run, own, 0.0, 10.0) == (5.0, 1, 2.0, 1)


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


def test_next_hops_count_from_when_they_were_read():
    # In the sample at 1 s, b was read at once and a 50 ms later: the loop begins when a was read, not at 1 s.
    routers = {r: {"asn": n, "neighbors": []} for n, r in enumerate(("o", "a", "b"), 64600)}
    dataset = type("D", (), {"topology": lambda self, name: {"routers": routers}})()
    p = "10.0.0.0/24"
    own = {"o": [{"t": 0.5, "hops": f"* {p}=."}],
           "a": [{"t": 1.0, "hops": f"* {p}=b|", "hops_ms": 50.0}],
           "b": [{"t": 1.0, "hops": f"* {p}=a|", "hops_ms": 0.0}, {"t": 1.1, "hops": f"{p}=o|", "hops_ms": 0.0}]}
    loops_s, *_ = analysis.loops_on_the_way(dataset, RunKey("t", "v", "s", 1), {}, own, 0.0, 10.0)
    assert abs(loops_s - 0.05) < 1e-9


def test_a_run_rests_does_not_or_was_not_measured():
    at_rest = {"oscillates": 0, "settle_s": 4.0}
    assert analysis.rested({"events": []}, at_rest) is True
    assert analysis.rested({"events": []}, {"oscillates": 1}) is False
    assert analysis.rested({"events": [], "measurements": [{"step": "2", "stable": False}]}, at_rest) is False
    assert analysis.rested({"events": [{"name": "final", "held": {}, "stable": False}]}, at_rest) is False
    for m in (None, {}, {"settle_s": 4.0}, {"oscillates": 0, "settle_s": None}):
        assert analysis.rested({"events": []}, m) is None


def test_the_wilcoxon_test_is_exact_for_many_pairs_too():
    assert analysis.wilcoxon_p([float(i) for i in range(1, 26)]) == 2 / 2 ** 25
    assert analysis.wilcoxon_p([1, 1, 2, -2, 3]) == 0.375  # ties share their ranks


def test_updates_per_neighbor_count_from_the_last_sample_before_the_announcement():
    # Two prefixes. r1 received 3 updates from r2 before the announcement (End-of-RIB and earlier), then 2 until the
    # withdrawal, and 5 more after it. r2 has no sample before the announcement and is left out.
    e = Experiment.model_validate({"name": "x", "sampling": {"interval": 1.0}, "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "a", "mode": "obgp-rp"}]})
    run = {"watched": ["r1", "r2"], "events": [{"name": "announce", "t": 1.0}, {"name": "announced", "t": 5.0, "expected": 2},
                                               {"name": "withdraw", "t": 10.0, "expected": 0},
                                               {"name": "final", "t": 20.0, "prefixes": 2, "held": {"r1": 0, "r2": 0}, "loops": 0, "holes": 0}]}
    rx = lambda t: 3 if t < 1 else 5 if t <= 10 else 10
    samples = [{"t": float(t), "router": "r1", "destinations": 2, "paths": 2, "path_len_avg": 1, "updates_rx": rx(t), "peers_rx": f"r2={rx(t)}"}
               for t in range(0, 21)]
    samples += [{"t": float(t), "router": "r2", "destinations": 2, "paths": 2, "path_len_avg": 1, "updates_rx": 9, "peers_rx": "r1=9"}
                for t in range(2, 21)]
    dataset = type("D", (), {"experiment": e, "samples": lambda self, k: samples})()
    assert analysis.run_metrics(dataset, RunKey("t", "a", "s", 1), run)["updates_prefix_max"] == 1.0


def test_cpu_spans_use_the_time_gobgpd_was_read_and_count_a_repeated_reading_once():
    # Read at 0, 1, then busy: the samples at 2 to 4 repeat the reading of 1, the one at 5 was read at 5.
    rows = [{"t": 0.0, "cpu_s": 0.0, "metrics_age_s": 0}, {"t": 1.0, "cpu_s": 1.0, "metrics_age_s": 0},
            {"t": 2.0, "cpu_s": 1.0, "metrics_age_s": 1}, {"t": 4.0, "cpu_s": 1.0, "metrics_age_s": 3},
            {"t": 5.0, "cpu_s": 9.0, "metrics_age_s": 0}]
    assert analysis.cpu_spans(rows, 0, 5, 2.0) == [(0.0, 5.0, 1.8), (1.0, 5.0, 2.0)]
    assert analysis.covered([(0, 2), (1, 3), (5, 6)]) == 4


def test_a_router_at_the_limit_of_its_threads_counts_as_saturated_and_what_it_allocated():
    e = Experiment.model_validate({"name": "x", "sampling": {"interval": 1.0}, "bgp": {"procs": 2}, "topologies": ["noble-eu"],
                                   "scenarios": ["fill-60"], "variants": [{"name": "a", "mode": "obgp-rp"}]})
    run = {"watched": ["r1", "r2"], "events": [{"name": "announce", "t": 0.0}, {"name": "announced", "t": 1.0, "expected": 2}]}
    # r1 uses 2 cores from 2 s to 6 s, else 0.5; r2 always 0.5.
    use = lambda t, r: 0.5 * t + (1.5 * (min(t, 6) - 2) if r == "r1" and t > 2 else 0)
    row = lambda t, r: {"t": float(t), "router": r, "destinations": 2, "paths": 2, "path_len_avg": 1, "cpu_s": use(t, r),
                        "alloc_mb": 10.0 * t, "metrics_age_s": 0}
    samples = [row(t, r) for t in range(0, 13) for r in ("r1", "r2")]
    dataset = type("D", (), {"experiment": e, "samples": lambda self, k: samples})()
    out = analysis.run_metrics(dataset, RunKey("t", "a", "s", 1), run)
    assert out["cpu_cores_max"] == 2.0 and out["cpu_cores_max_router"] == "r1" and out["cpu_cores_max_routers"] == [0.5, 2.0]
    assert out["saturated_s"] == 4.0 and out["alloc_mb_mean"] == 120.0


def _pprof(samples: list[tuple[list, int]]) -> bytes:
    """A small CPU profile as Go writes one: samples of stacks, leaf first, with their nanoseconds.
    A frame is a function's name, or its name and source file."""
    import gzip

    def varint(n):
        out = bytearray()
        while True:
            b, n = n & 0x7F, n >> 7
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)

    def field(number, value):
        if isinstance(value, bytes):
            return varint(number << 3 | 2) + varint(len(value)) + value
        return varint(number << 3) + varint(value)
    strings = ["", "samples", "count", "cpu", "nanoseconds"]
    functions, msg = {}, b""
    samples = [([fn if isinstance(fn, tuple) else (fn, "") for fn in stack], ns) for stack, ns in samples]
    for stack, _ in samples:
        for fn in stack:
            if fn not in functions:
                strings += [x for x in fn if x not in strings]
                functions[fn] = len(functions) + 1
    msg += field(1, field(1, 1) + field(2, 2)) + field(1, field(1, 3) + field(2, 4))
    for stack, ns in samples:
        ids = b"".join(varint(functions[fn]) for fn in stack)
        msg += field(2, field(1, ids) + field(2, varint(1) + varint(ns)))
    for fn, i in functions.items():
        msg += field(4, field(1, i) + field(4, field(1, i)))
        msg += field(5, field(1, i) + field(2, strings.index(fn[0])) + field(4, strings.index(fn[1])))
    for s in strings:
        msg += field(6, s.encode())
    return gzip.compress(msg)


def test_profiles_tell_the_cpu_by_part_of_the_router_and_by_function(tmp_path):
    from lab import profile
    gc = ["runtime.scanobject", "runtime.gcBgMarkWorker"]
    policy = ["table.(*CommunityCondition).Evaluate", "github.com/osrg/gobgp/v4/internal/pkg/table.(*RoutingPolicy).ApplyPolicy",
              "github.com/osrg/gobgp/v4/pkg/server.(*BgpServer).filterpath"]
    read = ["proto.Marshal", "github.com/osrg/gobgp/v4/pkg/server.(*server).ListPath"]
    inject = ["github.com/osrg/gobgp/v4/pkg/server.(*BgpServer).propagateUpdate", "github.com/osrg/gobgp/v4/pkg/server.(*BgpServer).handleMGMTOp"]
    (tmp_path / "cpu-a-0.pb.gz").write_bytes(_pprof([(gc, 2 * 10**9), (policy, 10**9)]))
    (tmp_path / "cpu-a-5.pb.gz").write_bytes(_pprof([(read, 10**9), (inject, 5 * 10**8)]))
    c = profile.of_run(tmp_path)
    assert c["seconds"] == 4.5 and c["buckets"]["gc"] == 2 and c["buckets"]["policy"] == 1 and c["buckets"]["api"] == 1
    assert c["buckets"]["rib"] == 0.5  # routes the controller injects take the router's own way, not the API's
    assert c["flat"]["runtime.scanobject"] == 2 and c["cum"]["github.com/osrg/gobgp/v4/pkg/server.(*BgpServer).filterpath"] == 1
    assert profile.of_run(tmp_path / "none") is None


def test_without_paths_read_loops_and_black_holes_on_the_way_stay_unmeasured_not_zero():
    e = Experiment.model_validate({"name": "x", "sampling": {"interval": 1.0, "paths": False}, "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "a", "mode": "obgp-rp"}]})
    run = {"watched": ["r1"], "events": [{"name": "announce", "t": 0.0}, {"name": "announced", "t": 1.0, "expected": 1}]}
    samples = [{"t": float(t), "router": "r1", "destinations": 1, "paths": 1, "path_len_avg": None, "hops": ""} for t in range(10)]
    dataset = type("D", (), {"experiment": e, "samples": lambda self, k: samples})()
    out = analysis.run_metrics(dataset, RunKey("t", "a", "s", 1), run)
    assert out["loops_s"] is None and out["holes_s"] is None and out["settle_s"] is not None


def test_profile_metrics_come_only_from_profiles_that_reached_rest_uncut(tmp_path):
    e = Experiment.model_validate({"name": "x", "sampling": {"interval": 1.0}, "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "a", "mode": "obgp-rp"}]})
    key = RunKey("t", "a", "s", 1)
    (tmp_path / key.path).mkdir(parents=True)
    (tmp_path / key.path / "cpu-r1-0.pb.gz").write_bytes(_pprof([(["runtime.gcBgMarkWorker"], 10**9)]))
    samples = [{"t": float(t), "router": "r1", "destinations": 1, "paths": 1, "path_len_avg": 1} for t in range(10)]
    dataset = type("D", (), {"experiment": e, "path": tmp_path, "samples": lambda self, k: samples})()
    run = lambda complete: {"watched": ["r1"], "events": [{"name": "announce", "t": 0.0}, {"name": "announced", "t": 1.0, "expected": 1}],
                            "profiles": [{"router": "r1", "chunks": [{"t": 0, "seconds": 5}], "complete": complete}]}
    assert analysis.run_metrics(dataset, key, run(True))["prof_gc_s"] == 1.0
    assert analysis.run_metrics(dataset, key, run(False))["prof_gc_s"] is None


def test_a_function_falls_in_the_same_part_in_every_mode(tmp_path):
    # Frames as gobgpd's profiles name them, with their files.
    from lab import profile
    T, S = "github.com/osrg/gobgp/v4/internal/pkg/table.", "github.com/osrg/gobgp/v4/pkg/server."
    table, opera, neighbor = "/src/internal/pkg/table/destination.go", "/src/internal/pkg/table/opera.go", "/src/internal/pkg/table/opera_neighbor.go"
    decided_per_neighbor = [(T + "(*Destination).Calculate", table), (T + "(*operaView).feed", neighbor), (T + "(*Destination).OperaFeedSorted", neighbor)]
    decided_alone = [(T + "(*Destination).Calculate", table), (T + "(*TableManager).Update", "/src/internal/pkg/table/table_manager.go")]
    view = [(T + "(*operaView).export", neighbor), (T + "(*Destination).OperaExports", neighbor)]
    pruned = [(T + "(*Destination).operaPruned", opera), (S + "(*BgpServer).propagateUpdate", "/src/pkg/server/server.go")]
    read = [(T + "isOperaValid", opera), (T + "(*Table).Info", "/src/internal/pkg/table/table.go"), (S + "(*BgpServer).getRibInfo.func1", "/src/pkg/server/server.go")]
    (tmp_path / "cpu-a-0.pb.gz").write_bytes(_pprof([(decided_per_neighbor, 10**9), (decided_alone, 10**9), (view, 10**9), (pruned, 10**9), (read, 10**9)]))
    c = profile.of_run(tmp_path)["buckets"]
    # The decision process wherever it is called, NS-BGP's tables are no OBGP, and what the lab reads is the API's, OBGP code in it too.
    assert (c["decision"], c["tables"], c["obgp"], c["api"]) == (2, 1, 1, 1)


def test_a_commit_is_faster_only_beyond_its_margin_with_its_guards_held_and_the_lab_steady(monkeypatch):
    e = Experiment.model_validate({"name": "x", "runs": 8, "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "base", "mode": "obgp-rp", "ref": "a"}, {"name": "fast", "mode": "obgp-rp", "ref": "b"},
                                                {"name": "small", "mode": "obgp-rp", "ref": "c"}, {"name": "aa", "mode": "obgp-rp", "ref": "a"}],
                                   "speed": {"baseline": "a", "metric": "cpu_s_mean", "margin_pct": 5, "guards": ["rss_mean"]}})
    cpu = {"base": 100.0, "fast": 80.0, "small": 98.0, "aa": 100.0}
    rss = {"base": 50.0, "fast": 50.0, "small": 50.0, "aa": 50.0}
    runs = lambda: {str(RunKey("noble-eu", v, "fill-60", i)): {"cpu_s_mean": cpu[v] + i * 0.1 * (v not in ("base", "aa")) + i, "rss_mean": rss[v] + i}
                    for v in cpu for i in range(1, 9)}  # noqa: E731
    monkeypatch.setattr(analysis, "run_summary", lambda d: runs())
    dataset = type("D", (), {"experiment": e})()
    verdicts = {r["variant"]: r["verdict"] for r in analysis.speed(dataset, found=[])["cells"]}
    # 20 % below: faster. 2 % below a margin of 5 %: no change shown. aa is the baseline's own commit, no candidate.
    assert verdicts == {"fast": "faster", "small": "no change shown"}
    rss["fast"] = 70.0
    assert {r["variant"]: r["verdict"] for r in analysis.speed(dataset, found=[])["cells"]}["fast"] == "faster, worse elsewhere"
    rss["fast"] = 50.0
    cpu["aa"] = 110.0  # the baseline's own commit shifts: the lab is not steady, nothing is claimed
    assert {r["variant"]: r["verdict"] for r in analysis.speed(dataset, found=[])["cells"]}["fast"] == "lab drifts"
    cpu["aa"] = 100.0
    found = [{"variant": "fast", "topology": "noble-eu", "scenario": "fill-60", "cause": "output"}]
    assert {r["variant"]: r["verdict"] for r in analysis.speed(dataset, found=found)["cells"]}["fast"] == "behaves differently"
    # Routes at rest that differ between runs of the baseline itself: judged on the speed, the routes marked as not compared.
    found = [{"variant": "fast", "topology": "noble-eu", "scenario": "fill-60", "cause": "output-unchecked"}]
    fast = next(r for r in analysis.speed(dataset, found=found)["cells"] if r["variant"] == "fast")
    assert (fast["verdict"], fast["routes_compared"]) == ("faster", False)


def test_a_speed_rule_needs_commits_to_compare_an_aa_variant_and_runs_enough_for_every_comparison():
    import pytest
    make = lambda variants, runs=10: Experiment.model_validate({  # noqa: E731
        "name": "x", "runs": runs, "topologies": ["noble-eu"], "scenarios": ["fill-60"], "variants": variants,
        "speed": {"baseline": "a", "margin_pct": 5}})
    v = lambda name, mode, ref: {"name": name, "mode": mode, "ref": ref}  # noqa: E731
    with pytest.raises(ValueError, match="differ in their ref only"):
        make([v("x", "obgp-rp", "a"), v("y", "bgp", "a")])
    with pytest.raises(ValueError, match="A/A variant"):
        make([v("x", "obgp-rp", "a"), v("y", "obgp-rp", "b")])
    # Two modes, a candidate each: 2 comparisons at 2.5 % each need 7 runs.
    two = [v("rp", "obgp-rp", "a"), v("rp-aa", "obgp-rp", "a"), v("rp-new", "obgp-rp", "b"),
           v("bgp", "bgp", "a"), v("bgp-aa", "bgp", "a"), v("bgp-new", "bgp", "b")]
    with pytest.raises(ValueError, match="2 comparisons, which need 7 runs, not 6"):
        make(two, runs=6)
    assert make(two, runs=7).speed.baseline == "a"


def test_the_baseline_commit_is_the_same_in_every_mode_whatever_the_order_of_the_variants():
    from lab import problems
    v = lambda name, mode, ref: {"name": name, "mode": mode, "ref": ref}  # noqa: E731
    e = Experiment.model_validate({"name": "x", "runs": 10, "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [v("bgp", "bgp", "old"), v("bgp-new", "bgp", "cand"), v("bgp-aa", "bgp", "old"),
                                                v("rp-new", "obgp-rp", "cand"), v("rp", "obgp-rp", "old"), v("rp-aa", "obgp-rp", "old")],
                                   "speed": {"baseline": "old", "margin_pct": 5}})
    assert problems.twins_of(e) == {"bgp-new": ("bgp", "bgp-aa"), "bgp-aa": ("bgp", None), "rp-new": ("rp", "rp-aa"), "rp-aa": ("rp", None)}
