"""The metrics of the paper's runs, which Table II reports."""

from statistics import median

import pytest

from lab import analysis
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
    # a and b answer at different ticks; c is not watched.
    ticks = analysis.ticks([s(0.0, "a"), s(0.0, "b"), s(0.1, "a"), s(0.2, "b"), s(0.3, "c"), s(3.0, "a")], run)
    assert [(t, [r["router"] for r in rows]) for t, rows in ticks.items()] == [
        (0.0, ["a", "b"]), (0.1, ["a", "b"]), (0.2, ["a", "b"]), (0.3, ["a", "b", "c"]), (3.0, ["a", "b"])]
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
