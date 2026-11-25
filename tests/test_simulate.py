"""The simulator and the lab in each other's terms: a conversion there and
back keeps the network, and the simulator judges both alike."""

import shutil

import pytest
from pathlib import Path

from lab import scenario as scenarios
from lab import simulate, topology

QUIET = simulate.QUIET

# Counterexamples of the simulator, as its tests have them.
EXPORT_FILTER = {"routers": 3, "links": [[0, 1], [0, 2], [1, 2]], "seed": 1,
                 "events": [{"after": QUIET, "kind": "deny-export", "from": 0, "to": 1, "value": 1},
                            {"after": QUIET, "kind": "expect", "routers": [1]}]}
GAO_REXFORD = {"routers": 4, "links": [[0, 1], [0, 2], [1, 2], [1, 3]], "customers": [[2, 0], [1, 2], [3, 1]],
               "peers": [[0, 1]], "seed": 2, "events": [{"after": QUIET, "kind": "expect", "routers": [3]}]}
RR_LOOP = {"routers": 5, "as": [0, 1, 1, 3, 1], "links": [[0, 3], [0, 4], [1, 2], [1, 4], [2, 3]], "costs": [1, 1, 10, 10, 1],
           "ibgp": [{"as": 1, "reflectors": [2]}], "seed": 2,
           "events": [{"after": QUIET, "kind": "expect", "routers": [1], "forwarding": True},
                      {"after": QUIET, "kind": "expect", "routers": [2], "consistent": True},
                      {"after": QUIET, "kind": "igp", "from": 1, "to": 4, "value": 0}]}
LEAK_MED_PREF = {"routers": 4, "links": [[0, 1], [1, 2], [2, 3], [0, 3]], "customers": [[1, 0], [1, 2]], "peers": [[2, 3], [0, 3]],
                 "leakers": [2], "sessions": [{"from": 1, "to": 2, "med": 5}, {"from": 3, "to": 2, "local_pref": 250}], "seed": 1,
                 "events": [{"after": QUIET, "kind": "local-pref", "from": 1, "to": 0, "value": 300},
                            {"after": QUIET, "kind": "prepend-all", "from": 3, "value": 2},
                            {"after": QUIET, "kind": "deny-import", "from": 1, "to": 2, "value": 1},
                            {"after": QUIET, "kind": "down", "from": 0, "to": 1},
                            {"after": QUIET, "kind": "expect", "routers": [3], "avoid": 2},
                            {"after": QUIET, "kind": "withdraw"},
                            {"after": QUIET, "kind": "expect", "routers": [1], "prefixes": "none"}]}
INSTANCES = [EXPORT_FILTER, GAO_REXFORD, RR_LOOP, LEAK_MED_PREF]


def normal(inst: dict) -> dict:
    """An instance with lists in one order: conversions may order them differently."""
    out = {"origin": 0, **{k: v for k, v in inst.items() if k not in ("seed",)}}
    ases = max(out.get("as") or [out["routers"] - 1]) + 1
    out.setdefault("asns", [65001 + a for a in range(ases)])
    out.setdefault("router_ids", [f"10.0.0.{i + 1}" for i in range(out["routers"])])
    # What counts is the AS number of every router, not how ASes are indexed.
    as_of = out.pop("as", None) or list(range(out["routers"]))
    asns = out.pop("asns")
    out["router_asns"] = [asns[a] for a in as_of]
    out["ibgp"] = sorted(sorted(c.get("reflectors", [])) for c in out.get("ibgp", []))
    # The lab's until_stable waits at most its timeout: once quiet, the same as the simulator's wait for quiet.
    # The step a check stands for is the lab's, which the simulator only carries.
    out["events"] = [{"prefixes": "all", **e} if e["kind"] == "expect" else e for e in
                     ({k: v for k, v in e.items() if k not in ("bounded", "step")} for e in out.get("events", []))]
    for key in ("customers", "peers", "leakers"):
        if key in out:
            out[key] = sorted(map(lambda x: sorted(x) if key == "peers" else x, out[key]))
    pairs = sorted(zip([sorted(link) for link in out["links"]], out.get("costs") or [1] * len(out["links"])))
    out["links"], out["costs"] = [p[0] for p in pairs], [p[1] for p in pairs]
    if "sessions" in out:
        out["sessions"] = sorted(out["sessions"], key=lambda s: (s["from"], s["to"]))
    return out


@pytest.mark.parametrize("inst", INSTANCES)
def test_an_instance_becomes_a_valid_lab_network_and_back(inst):
    t, s = simulate.from_instance(inst)
    assert topology.validate(t["routers"], t["roles"]) == []
    sc = scenarios.parse(s)
    for step in scenarios.each_step(sc.steps):
        if step.kind not in ("until_stable", "wait"):
            scenarios.Network(t["routers"], t["roles"]).targets(step.kind, step.args, scenarios.rng(1, 1, (0,)))  # every target exists
    assert normal(simulate.to_instance(t, sc)) == normal(inst)


@pytest.mark.skipif(not shutil.which("go"), reason="needs go")
def test_the_simulator_judges_the_converted_network_alike():
    for inst in (EXPORT_FILTER, RR_LOOP):
        t, s = simulate.from_instance(inst)
        again = simulate.to_instance(t, scenarios.parse(s))
        counts = lambda out: {m: {k: v for k, v in o.items() if k != "example"} for m, o in out.items()}  # the example lists links in its order
        assert counts(simulate.run(again, seeds=10)) == counts(simulate.run(inst, seeds=10))


def test_the_example_topologies_convert_or_say_why():
    plain = scenarios.parse({"name": "x", "steps": [
        {"kind": "announce", "args": {"rate": 1, "for": 1, "lifetime": 86400, "jitter": 0, "max_active": 1}},
        {"kind": "until_stable", "args": {"timeout": 60}},
        {"kind": "expect", "args": {"router": "all", "forwarding": True}}]})
    converted = 0
    for name in topology.names():
        t = topology.load(name, shared=True)
        try:
            inst = simulate.to_instance(t, plain)
        except simulate.Unsupported as e:
            assert e.reasons and all(isinstance(r, str) and r for r in e.reasons)
            continue
        converted += 1
        back, _ = simulate.from_instance(inst)
        assert normal(simulate.to_instance(back, plain)) == normal(inst), name
    assert converted > 0


def test_what_does_not_map_is_named_not_approximated():
    t, _ = simulate.from_instance(EXPORT_FILTER)
    noisy = scenarios.parse({"name": "x", "steps": [
        {"announce": {"rate": 5, "for": 10}}, {"restart": {"router": "r1", "graceful": True}},
        {"originate": {"router": "r1", "more_specific": True}}, {"announce_real": {}}]})
    with pytest.raises(simulate.Unsupported) as e:
        simulate.to_instance(t, noisy)
    reasons = " ".join(e.value.reasons)
    assert all(x in reasons for x in ("expire after 60 s", "graceful restart", "more specific prefix", "no counterpart"))


@pytest.mark.skipif(not shutil.which("go"), reason="needs go")
def test_exported_counterexamples_show_their_deviation_again(lab_files):
    examples = simulate.search(routers=3, seeds=2)
    written, skipped = simulate.export(examples, overwrite=True)  # the repository has them already
    assert written and all(name.startswith("sim-") for name in written)
    assert all(reasons for reasons in skipped.values())
    for name in written:
        t = topology.load(name)
        assert topology.validate(t["routers"], t["roles"]) == []
        finding = next(e["finding"] for e in examples if name.endswith(f"-{e['finding']['mode']}-{e['finding']['kind']}"))
        out = simulate.run(simulate.to_instance(t, scenarios.load(name)), seeds=10)
        mode = finding["mode"]
        if finding["kind"].startswith("transient-"):  # on the way to rest: no expect at the end shows it, the finding does
            assert out[mode]["findings"].get(finding["kind"], 0) > 0, name
            continue
        if finding["kind"] == "no-convergence":  # no expect either: some orders do not rest
            assert out[mode]["converged"] < out[mode]["runs"], name
            continue
        assert out[mode]["failed"] and out[mode]["failed"][-1] > 0, name  # the lab's expect, played by the simulator
        if mode != "bgp" and finding["kind"] != "leaked":  # leaks are measured in every mode, BGP included
            assert out["bgp"]["failed"][-1] == 0, name  # BGP is the reference: it passes


def test_poison_and_communities_pass_both_ways():
    inst = {**EXPORT_FILTER, "origin_poison": [65002], "origin_communities": ["no-export", "0:65003"]}
    t, s = simulate.from_instance(inst)
    sc = scenarios.parse(s)
    assert sc.steps[0].args.poison == [65002] and sc.steps[0].args.communities == ["no-export", "0:65003"]
    assert normal(simulate.to_instance(t, sc)) == normal(inst)


@pytest.mark.skipif(not shutil.which("go"), reason="needs go")
def test_the_simulator_withholds_by_community_as_the_lab():
    inst = {"routers": 3, "links": [[0, 1], [1, 2]], "origin_communities": ["no-export"], "seed": 1}
    out = simulate.run(inst, seeds=2)
    assert out["bgp"]["converged"] == 2


def test_an_aggregate_passes_both_ways():
    inst = {**EXPORT_FILTER, "origin_set": [64601, 64600]}
    t, s = simulate.from_instance(inst)
    sc = scenarios.parse(s)
    assert sc.steps[0].args.as_set == [64601, 64600]
    assert normal(simulate.to_instance(t, sc)) == normal(inst)


CONFED = {"routers": 4, "links": [[0, 1], [1, 2], [2, 3]], "confeds": [{"members": [1, 2], "id": 65500}], "seed": 1,
          "events": [{"after": QUIET, "kind": "expect", "routers": [3], "avoid": 1}]}


def test_a_confederation_passes_both_ways():
    t, s = simulate.from_instance(CONFED)
    assert topology.validate(t["routers"], t["roles"]) == []
    assert t["routers"]["r1"]["confederation"] == 65500
    assert {n["name"]: n["peerAs"] for n in t["routers"]["r3"]["neighbors"]} == {"r2": 65500}  # outside: the confederation
    assert {n["name"]: n["peerAs"] for n in t["routers"]["r2"]["neighbors"]} == {"r1": 65002, "r3": 65004}
    assert normal(simulate.to_instance(t, scenarios.parse(s))) == normal(CONFED)


def test_a_preference_is_for_routes_from_other_ases_on_both_sides():
    t, _ = simulate.from_instance(RR_LOOP)
    network = scenarios.Network(t["routers"], t["roles"])
    step = scenarios.parse({"name": "x", "steps": [{"kind": "set_preference", "args": {"router": "r1", "neighbor": "r2", "value": 300}}]}).steps[0]
    with pytest.raises(ValueError, match="r2 is in the AS of r1"):
        network.targets("set_preference", step.args, scenarios.rng(1, 1, (0,)))


# Bad Gadget: each router prefers the path through its clockwise neighbor and
# permits no longer one, a path filter at the neighbor.
BAD_GADGET = {"routers": 4, "links": [[0, 1], [0, 2], [0, 3], [1, 2], [2, 3], [3, 1]], "seed": 1,
              "sessions": [{"from": 2, "to": 1, "local_pref": 200, "deny_via": 65004}, {"from": 3, "to": 2, "local_pref": 200, "deny_via": 65002},
                           {"from": 1, "to": 3, "local_pref": 200, "deny_via": 65003}],
              "events": [{"after": QUIET, "kind": "expect", "routers": [r]} for r in (1, 2, 3)]}  # one per router, as the lab's


def test_bad_gadget_with_its_path_filters_passes_both_ways():
    t, s = simulate.from_instance(BAD_GADGET)
    assert topology.validate(t["routers"], t["roles"]) == []
    assert {"name": "r1", "peerAs": 65002, "denyVia": 65004} in t["routers"]["r2"]["neighbors"]
    assert normal(simulate.to_instance(t, scenarios.parse(s))) == normal(BAD_GADGET)


def test_a_tag_passes_both_ways():
    inst = {**EXPORT_FILTER, "sessions": [*EXPORT_FILTER.get("sessions", []), {"from": 0, "to": 2, "tag": "0:65004"}]}
    t, s = simulate.from_instance(inst)
    assert {"name": "r0", "peerAs": 65001, "tag": "0:65004"}.items() <= next(n for n in t["routers"]["r2"]["neighbors"] if n["name"] == "r0").items()
    assert normal(simulate.to_instance(t, scenarios.parse(s))) == normal(inst)


def test_prepending_towards_one_neighbor_passes_both_ways():
    inst = {**EXPORT_FILTER, "events": [{"after": QUIET, "kind": "prepend", "from": 0, "to": 1, "value": 2}]}
    t, s = simulate.from_instance(inst)
    sc = scenarios.parse(s)
    step = next(x for x in sc.steps if x.kind == "prepend")
    assert (step.args.router, step.args.neighbor, step.args.times) == ("r0", "r1", 2)
    assert normal(simulate.to_instance(t, sc))["events"] == normal(inst)["events"]


def test_siblings_pass_both_ways():
    inst = {"routers": 4, "links": [[0, 1], [1, 2], [2, 3]], "siblings": [[1, 2]], "customers": [[3, 2]], "peers": [[0, 1]], "seed": 1}
    t, s = simulate.from_instance(inst)
    assert topology.validate(t["routers"], t["roles"]) == []
    assert {n["name"]: n.get("relation") for n in t["routers"]["r1"]["neighbors"]}["r2"] == "sibling"
    assert normal(simulate.to_instance(t, scenarios.parse(s))) == normal(inst)


def test_partial_transit_passes_both_ways():
    inst = {"routers": 3, "links": [[0, 1], [1, 2]], "peers": [[0, 1]], "customers": [[1, 2]],
            "sessions": [{"from": 1, "to": 2, "partial_transit": True}], "seed": 1}
    t, s = simulate.from_instance(inst)
    assert next(n for n in t["routers"]["r1"]["neighbors"] if n["name"] == "r2")["partialTransit"] is True
    assert normal(simulate.to_instance(t, scenarios.parse(s))) == normal(inst)


def test_several_origins_and_the_lives_of_a_prefix_are_instances_of_their_own():
    t = topology.load("noble-eu")
    # Prefixes live 30 to 90 s, announced over 100 s: some expire, the last ones stay.
    fill = scenarios.parse({"name": "x", "steps": [{"announce": {"rate": 2, "for": 100}}, {"wait": 10}]})
    parts = simulate.to_instances(t, fill)
    origins = t["roles"]["origins"]
    assert [label for label, _ in parts] == [f"{o}, {life}" for o in origins for life in ("held", "expires")]
    held, removed = dict(parts)[f"{origins[0]}, held"], dict(parts)[f"{origins[0]}, expires"]
    assert "events" not in held and removed["events"] == [{"after": QUIET, "any": True, "kind": "withdraw"}]  # at any point
    assert {i["origin"] for _, i in parts} == {list(t["routers"]).index(o) for o in origins}
    with pytest.raises(simulate.Unsupported):
        simulate.to_instance(t, fill)  # strictly, still one origin and held prefixes


def test_a_partial_withdraw_removes_a_prefix_at_its_step_and_checks_spare_it():
    t, _ = simulate.from_instance(EXPORT_FILTER)
    sc = scenarios.parse({"name": "x", "steps": [{"announce": {"rate": 1, "for": 10, "lifetime": 86400}},
                                                 {"withdraw": {"percent": 50}}, {"expect": {"router": "all"}}]})
    parts = dict(simulate.to_instances(t, sc))
    assert [e["kind"] for e in parts["held"]["events"]] == ["expect"] and parts["held"]["events"][0]["prefixes"] == "all"
    assert [e["kind"] for e in parts["removed"]["events"]] == ["withdraw", "expect"]
    assert parts["removed"]["events"][1]["prefixes"] == "any"  # the lab checks the prefixes still announced


def test_a_prefix_expires_only_during_its_announcement_before_later_steps():
    t, _ = simulate.from_instance(EXPORT_FILTER)
    # Prefixes live 30 to 90 s from their announcement in the first 60 s: some expire before the link fails at 60 s.
    sc = scenarios.parse({"name": "x", "steps": [{"announce": {"rate": 1, "for": 60}}, {"down": {"link": "r0-r1"}}]})
    parts = dict(simulate.to_instances(t, sc))
    kinds = {label: [e["kind"] for e in inst.get("events", [])] for label, inst in parts.items()}
    assert kinds == {"held": ["down"], "expires": ["withdraw", "down"]}
    assert all(e.get("any") for inst in parts.values() for e in inst.get("events", []))  # nothing waits for rest


def test_a_prefix_is_held_while_the_announcer_pauses():
    t, _ = simulate.from_instance(EXPORT_FILTER)
    # The runner pauses the announcer after 30 s, which stops the lifetimes of 30 to 90 s: every prefix stays.
    fill = scenarios.parse({"name": "x", "steps": [{"announce": {"rate": 1, "for": 30}}, {"wait": 120}, {"down": {"link": "r0-r1"}}]})
    assert [label for label, _ in simulate.to_instances(t, fill)] == [""]
    assert "withdraw" not in [e["kind"] for _, inst in simulate.to_instances(t, fill) for e in inst.get("events", [])]
    # A later announcement at the origin resumes them: then they may expire during it.
    again = scenarios.parse({"name": "x", "steps": [{"announce": {"rate": 1, "for": 10, "lifetime": 30}}, {"wait": 40},
                                                    {"down": {"link": "r0-r1"}}, {"announce": {"rate": 1, "for": 30}}]})
    kinds = {label: [e["kind"] for e in inst.get("events", [])] for label, inst in simulate.to_instances(t, again)}
    assert kinds == {"held": ["down", "announce"], "expires": ["down", "announce", "withdraw"]}


def test_compare_names_only_what_the_simulator_rules_out(monkeypatch):
    from lab.config import Experiment
    from lab.results import RunKey

    t, _ = simulate.from_instance(EXPORT_FILTER)
    monkeypatch.setattr(simulate.topologies, "load", lambda name: t)
    e = Experiment.model_validate({"name": "x", "topologies": ["t"], "scenarios": ["s"], "runs": 2,
                                   "variants": [{"name": "bgp", "mode": "bgp"}, {"name": "obgp", "mode": "obgp-rp"}]})
    monkeypatch.setattr(type(e), "scenario_of", lambda self, case: scenarios.parse(
        {"name": "s", "steps": [{"announce": {"rate": 1, "for": 1, "lifetime": 86400}}, {"expect": {"router": "all"}}]}))
    runs = {("bgp", 1): False, ("bgp", 2): True, ("obgp", 1): False, ("obgp", 2): False}  # passed?

    class Fake:
        experiment = e
        keys = lambda self: [RunKey("t", v, "s", i) for v, i in runs]
        is_done = lambda self, key: True
        run = lambda self, key: {"status": "completed", "events": [{"name": "expect", "step": "1", "passed": runs[key.variant, key.index]}]}
    monkeypatch.setattr(simulate, "run", lambda inst, seeds, **k: {
        "bgp": {"runs": seeds, "converged": seeds, "failed": [3]}, "obgp-rp": {"runs": seeds, "converged": seeds, "failed": [0]}})
    monkeypatch.setattr("lab.analysis.run_summary", lambda d: {})
    rows, skipped = simulate.compare(Fake(), seeds=10)
    by = {r["variant"]: r for r in rows}
    assert by["bgp"]["lab_failed"] == [1] and by["bgp"]["deviations"] == []  # both happen, with the order of messages
    assert by["obgp"]["deviations"] == ["check 1 failed in 2 of 2 runs, the simulator never fails it"]


PARALLEL = {"name": "s", "steps": [{"announce": {"rate": 1, "for": 1, "lifetime": 86400}}, {"until_stable": {"timeout": 60}},
                                   {"parallel": [{"expect": {"router": "all"}}, {"wait": 1}, {"expect": {"router": "all", "prefixes": "none"}}]},
                                   {"repeat": {"times": 2, "every": 5, "steps": [{"expect": {"router": "all"}}]}}]}


def test_a_check_is_matched_by_its_step_not_by_its_place_in_time(monkeypatch):
    from lab import analysis
    from lab.config import Experiment
    from lab.results import RunKey

    t, _ = simulate.from_instance(EXPORT_FILTER)
    sc = scenarios.parse(PARALLEL)
    assert simulate.expect_keys(sc) == ["2.0#0", "2.2#0", "3.repeat.0#0", "3.repeat.0#1"]
    # The translation names the step of each check as the lab does.
    inst = simulate.to_instance(t, sc)
    assert [e["step"] for e in inst["events"] if e["kind"] == "expect"] == simulate.expect_keys(sc)
    # The lab ends the second check of the parallel step first: it still is the second, by its step.
    events = [{"name": "expect", "step": "2.2", "t": 5.0, "passed": False}, {"name": "expect", "step": "2.0", "t": 5.2, "passed": True},
              {"name": "expect", "step": "3.repeat.0", "t": 6, "passed": True}, {"name": "expect", "step": "3.repeat.0", "t": 11, "passed": False}]
    assert [k for _, k in analysis.expect_keys(events)] == ["2.2#0", "2.0#0", "3.repeat.0#0", "3.repeat.0#1"]
    monkeypatch.setattr(simulate.topologies, "load", lambda name: t)
    e = Experiment.model_validate({"name": "x", "topologies": ["t"], "scenarios": ["s"], "runs": 1, "variants": [{"name": "obgp", "mode": "obgp-rp"}]})
    monkeypatch.setattr(type(e), "scenario_of", lambda self, case: sc)

    class Fake:
        experiment = e
        meta = {"predictions": {"t|s": {"obgp-rp": {"runs": 20, "converged": 20, "settled": 20, "failed": [0, 20, 0, 20]}}}}
        keys = lambda self: [RunKey("t", "obgp", "s", 1)]
        is_done = lambda self, key: True
        run = lambda self, key: {"status": "failed", "events": events}
    monkeypatch.setattr(simulate, "run", lambda inst, seeds, **k: {"obgp-rp": {"runs": seeds, "converged": seeds, "failed": [0, seeds, 0, seeds]}})
    monkeypatch.setattr("lab.analysis.run_summary", lambda d: {})
    [row], _ = simulate.compare(Fake(), seeds=10)
    assert row["lab_failed"] == [0, 1, 0, 1] and row["deviations"] == []
    from lab import problems
    failed = analysis.failed_checks(Fake())
    assert [(c["key"], problems.check_predicted(Fake(), RunKey("t", "obgp", "s", 1), c["key"])) for c in failed] == [
        ("2.2#0", True), ("3.repeat.0#1", True)]


def test_a_route_server_translates_both_ways():
    t = topology.load("ixp")
    inst = simulate.to_instance(t, scenarios.load("ixp"))
    rs = list(t["routers"]).index("rs")
    assert inst["route_servers"] == [rs]
    back, _ = simulate.from_instance(inst)
    assert all(m.get("rsClient") for m in back["routers"][simulate.router_name(rs)]["neighbors"])


def test_a_prediction_of_a_scenario_without_steps_after_the_announcement(monkeypatch):
    monkeypatch.setattr(simulate, "run", lambda inst, seeds, **k: {"bgp": {"runs": seeds, "converged": 0, "failed": [], "findings": {}}})
    out = simulate.predict("sim-local-pref-bgp-no-convergence", "sim-local-pref-bgp-no-convergence", seeds=3)
    assert out[""]["bgp"]["allowed"] == []  # no checks, nothing to allow


def test_a_prediction_with_tables_per_neighbor_names_only_their_modes(monkeypatch):
    played = {m: {"runs": 3, "converged": 3, "failed": [], "findings": {}} for m in ("bgp", "bgp-pn", "obgp-paper", "obgp-rp")}
    monkeypatch.setattr(simulate, "run", lambda inst, seeds, **k: played if k["per_neighbor"] else {})
    out = simulate.predict("sim-local-pref-bgp-no-convergence", "sim-local-pref-bgp-no-convergence", seeds=3, tables=True)
    assert set(out[""]) == {"obgp-rp-pn"}


def test_an_exported_check_lets_the_modes_fail_that_the_simulator_saw_failing():
    unreachable = {"mode": "obgp-rp", "kind": "unreachable", "routers": [3]}
    example = {"instance": {"routers": 4}, "finding": unreachable,
               "findings": [unreachable, {**unreachable, "mode": "obgp-hp"}, {"mode": "bgp", "kind": "transient-loop", "routers": []}]}
    assert simulate.expectation(example)["may_fail"] == ["obgp-hp", "obgp-rp"]


def test_predictions_sum_the_parts_per_mode_and_say_where_the_simulator_cannot_play(monkeypatch):
    from lab.config import Experiment

    e = Experiment.model_validate({"name": "x", "topologies": ["bad-gadget", "noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "bgp", "mode": "bgp"}, {"name": "obgp-rp", "mode": "obgp-rp"},
                                                {"name": "obgp-rp-pn", "mode": "obgp-rp", "per_neighbor": True}, {"name": "hybrid-rp", "mode": "hybrid-rp"}]})

    def parts(topology, scenario, *run):
        if len(topology["routers"]) > 10:
            raise simulate.Unsupported(["too large here"])
        return [("held", {}), ("expired", {})]
    monkeypatch.setattr(simulate, "to_instances", parts)
    calls = []
    # Both tables in one pass: the simulator names the modes with a table per neighbor itself.
    monkeypatch.setattr(simulate, "run", lambda inst, seeds, per_neighbor=False, guest=False, **k: calls.append(k.get("both")) or {
        "bgp": {"converged": 1, "runs": seeds, "findings": {"transient-loop": 3}}, "obgp-rp": {"converged": seeds, "runs": seeds},
        "obgp-paper": {"converged": 0, "runs": seeds}, **({"obgp-rp-pn": {"converged": seeds, "runs": seeds}} if k.get("both") else {})})
    out = simulate.predictions(e, seeds=10, workers=2)
    # The way to rest is summed as well: in how many orders a mode looped on the way.
    # A summary without settled, from before steps were bounded, counts as settled where it converged.
    assert out["bad-gadget|fill-60"] == {"bgp": {"converged": 2, "settled": 2, "runs": 20, "findings": {"transient-loop": 6}},
                                         "obgp-rp": {"converged": 20, "settled": 20, "runs": 20}, "obgp-rp-pn": {"converged": 20, "settled": 20, "runs": 20},
                                         # A hybrid needs the routers its topology marks: the pure modes play without.
                                         "hybrid-rp": {"unsupported": ["variant hybrid-rp: the topology marks no router to run OBGP in hybrids"]}}
    assert out["noble-eu|fill-60"] == {"unsupported": ["too large here"], "hybrid-rp": {"unsupported": ["too large here"]}}
    assert calls == [True, True]  # one pass per part, both tables at once


def test_a_check_of_some_origins_claims_nothing_of_another_origin():
    from lab import scenario as sc_mod
    from lab import simulate as sim

    topology = {"roles": {"origins": ["a", "b"], "lose": ["c"], "src": ["a"]},
                "routers": {"a": {"asn": 1, "neighbors": [{"name": "c"}]}, "b": {"asn": 2, "neighbors": [{"name": "c"}]},
                            "c": {"asn": 3, "neighbors": [{"name": "a"}, {"name": "b"}]}}}
    sc = sc_mod.parse({"name": "t", "steps": [{"announce": {"rate": 1, "for": 1}}, {"until_stable": {"timeout": 10}},
                                              {"expect": {"router": "lose", "of": "src"}}]})
    index = {r: i for i, r in enumerate(topology["routers"])}
    claims = {own: next(e for e in sim._events(sc, topology, index, own)[0] if e["kind"] == "expect")["prefixes"] for own in ("a", "b")}
    assert claims == {"a": "all", "b": "any"}


def _played(name: str, case: str, label: str = "held", index: int = 1) -> tuple[dict, list[dict]]:
    """The topology of a case of the smoke and the events of one part, as a result's predictions play them."""
    from lab.config import DIRECTORY, Experiment, file_of

    e = Experiment.load(file_of(DIRECTORY, name))
    t = topology.load(e.topologies[0])
    return t, dict(simulate.to_instances(t, e.scenario_of(case), e.seed, index))[label].get("events", [])


def test_random_targets_are_the_ones_the_runner_chooses():
    from lab.config import DIRECTORY, Experiment, file_of

    e = Experiment.load(file_of(DIRECTORY, "lab-smoke"))
    t, events = _played("lab-smoke", "smoke-all@rate=1")
    names = list(t["routers"])
    for index in (1, 2):
        chosen = scenarios.preview_targets(e.scenario_of("smoke-all@rate=1").steps, scenarios.Network(t["routers"], t["roles"]), e.seed, index)
        _, events = _played("lab-smoke", "smoke-all@rate=1", index=index)
        [router] = chosen["4"]["routers"]  # set_preference at a random router, for routes from a random neighbor
        [neighbor] = set(chosen["4"]["links"][0]) - {router}
        assert {k: v for k, v in next(x for x in events if x["kind"] == "local-pref").items() if k != "bounded"} | {"after": 0} == {
            "after": 0, "kind": "local-pref", "from": names.index(neighbor), "to": names.index(router), "value": 300}
    assert simulate.draws(e.scenario_of("smoke-all@rate=1")) and not simulate.draws(e.scenario_of("smoke-drain"))


def test_a_step_comes_once_quiet_after_until_stable_and_at_any_point_else():
    t = topology.load("bad-gadget")
    sc = scenarios.parse({"name": "x", "steps": [
        {"down": {"link": "frankfurt-toronto"}}, {"announce": {"rate": 1, "for": 1, "lifetime": 86400}},
        {"until_stable": {"timeout": 9}}, {"expect": {"router": "fulda"}}, {"wait": 0}, {"up": {}},
        {"down": {"link": "fulda-toronto"}}, {"wait": 1}, {"restart": {"router": "fulda"}}]})
    events = simulate.to_instance(t, sc).get("events", [])
    moments = [(e["kind"], "before" if e["after"] < 0 else "any" if e.get("any") else "quiet") for e in events]
    # The link is down before the announcement. The check changes nothing, so the network stays quiet for it; a wait does not.
    assert moments[:3] == [("down", "before"), ("expect", "quiet"), ("up", "any")]
    assert events[1].get("bounded") and not events[2].get("bounded")  # until_stable waits at most its timeout
    fulda = list(t["routers"]).index("fulda")
    restart = [(e["kind"], e["from"], e.get("to"), e.get("value"), e.get("group")) for e in events[4:]]
    # A restart starts with a fresh table and takes all sessions down at once. The link to toronto is down
    # already: the other two come back, in any order, that one stays down.
    toronto = list(t["routers"]).index("toronto")
    assert restart[0] == ("restart", fulda, None, 0, None)
    ups = restart[1:]
    assert [k for k, *_ in ups] == ["up"] * 2 and all(fulda in (a, b) and toronto not in (a, b) for _, a, b, _, _ in ups)
    assert ups[0][4] and ups[0][4] == ups[1][4]


def test_up_restores_what_is_down_and_a_repetition_hits_the_same_link():
    _, events = _played("lab-smoke", "smoke-all@rate=1")
    downs = [(e["from"], e["to"]) for e in events if e["kind"] == "down"]
    ups = [(e["from"], e["to"]) for e in events if e["kind"] == "up"]
    # A restart takes its sessions down itself, they come back right after it.
    after = {events[i + 1]["group"] for i, e in enumerate(events[:-1]) if e["kind"] == "restart"}
    back = [(e["from"], e["to"]) for e in events if e["kind"] == "up" and e.get("group") in after]
    assert len(back) == 3
    assert sorted(downs + back) == sorted(ups)  # everything that went down came back
    *_, first, second = downs  # the two repetitions of the random cut
    assert first == second


def test_a_copy_of_the_prefix_is_a_life_of_its_own_and_goes_with_its_router():
    t, plain = _played("lab-smoke", "smoke-all@rate=1")
    _, copied = _played("lab-smoke", "smoke-all@rate=1", "held, copied")
    assert not any(e["kind"] == "originate" for e in plain)
    originate = [(e["from"], e["value"]) for e in copied if e["kind"] == "originate"]
    copier = list(t["routers"]).index("fulda")
    assert originate == [(copier, 1), (copier, 0)]  # announced, then withdrawn with every prefix


def test_events_before_the_announcement_and_at_any_point_pass_both_ways():
    inst = {"routers": 3, "links": [[0, 1], [1, 2], [0, 2]], "seed": 1, "events": [
        {"after": simulate.BEFORE, "kind": "down", "from": 1, "to": 2},
        {"after": QUIET, "any": True, "kind": "up", "from": 1, "to": 2},
        {"after": QUIET, "kind": "withdraw"}]}
    t, s = simulate.from_instance(inst)
    assert [step["kind"] for step in s["steps"]][:2] == ["down", "announce"]
    assert normal(simulate.to_instance(t, scenarios.parse(s))) == normal(inst)


def test_a_step_in_either_form_has_the_type_of_its_kind():
    for step in ({"restart": {"router": "r1"}}, {"kind": "restart", "args": {"router": "r1"}}):
        assert type(scenarios.Step.model_validate(step).args) is scenarios.Restart
    assert type(scenarios.Step.model_validate({"kind": "up", "args": {"link": "a-b"}}).args) is scenarios.Up


def test_graceful_restart_keeps_stale_routes_on_both_sides(monkeypatch):
    from lab.config import Bgp

    t, _ = simulate.from_instance(EXPORT_FILTER)
    gr = Bgp(graceful_restart=True, hold_time=9, keepalive=3)
    play = lambda steps, bgp=gr: simulate.to_instance(t, scenarios.parse({"name": "x", "steps": steps}), bgp=bgp)
    announce = {"announce": {"rate": 1, "for": 1, "lifetime": 86400}}
    stable = {"until_stable": {"timeout": 10}}
    # A graceful restart: one event, the sessions back at any point after.
    inst = play([announce, stable, {"restart": {"router": "r1", "graceful": True}}])
    assert inst["graceful_restart"] and [(e["kind"], e.get("value")) for e in inst["events"]] == [("restart", 1), ("up", None), ("up", None)]
    assert len({e.get("group") for e in inst["events"][1:]} - {None}) == 1  # the sessions come back in any order
    with pytest.raises(simulate.Unsupported, match="without graceful restart"):
        play([announce, {"restart": {"router": "r1", "graceful": True}}], Bgp())
    # A silent failure keeps the routes stale, a notification does not: without graceful restart nothing changes.
    for mode, value in (("session", None), ("cut", 1), ("oneway", 2)):
        steps = [announce, stable, {"down": {"link": "r0-r1", "mode": mode}}, stable, {"up": {"link": "r0-r1"}}]
        assert [e.get("value") for e in play(steps)["events"] if e["kind"] == "down"] == [value]
        assert [e.get("value") for e in play(steps, None)["events"] if e["kind"] == "down"] == [None]
    # Never back: the stale routes expire before a step that surely starts later, max(30, hold) after the hold time.
    late = [announce, stable, {"down": {"link": "r0-r1", "mode": "cut"}}, {"wait": 60}, {"expect": {"router": "r1"}}]
    assert [e["kind"] for e in play(late)["events"]] == ["down", "expire", "expect"]
    with pytest.raises(simulate.Unsupported, match="may expire before or after"):
        play([*late[:3], {"wait": 35}, {"expect": {"router": "r1"}}])
    with pytest.raises(simulate.Unsupported, match="expire after the last step"):
        play(late[:3])
    # Back soon: the End-of-RIB removes what is not sent again, no expiry.
    soon = play([announce, stable, {"down": {"link": "r0-r1", "mode": "cut"}}, {"wait": 5}, {"up": {"link": "r0-r1"}}])
    assert [e["kind"] for e in soon["events"]] == ["down", "up"]

def test_a_result_that_does_not_run_is_predicted_again(monkeypatch):
    calls = []
    monkeypatch.setattr(simulate, "predictions", lambda e, workers=8, guest=False: calls.append((workers, guest)) or {"t|s": {"bgp": {"converged": 1, "settled": 0, "runs": 1}}})
    monkeypatch.setattr(simulate, "more_orders", lambda d: calls.append("more"))
    kept = {}
    dataset = type("D", (), {"name": "r", "experiment": None, "status": {"state": "finished"}, "update": lambda self, **f: kept.update(f)})()
    dataset.meta = kept
    simulate.predict_again(dataset)
    # Few cores, lowest priority, then more orders where runs differ.
    assert kept == {"predictions": {"t|s": {"bgp": {"converged": 1, "settled": 0, "runs": 1}}}} and calls == [(2, True), "more"]
    dataset.status = {"state": "running"}
    with pytest.raises(ValueError, match="runs"):
        simulate.predict_again(dataset)


def test_a_run_that_contradicts_the_prediction_gets_more_orders_first(monkeypatch):
    from lab import analysis
    from lab.config import Experiment
    from lab.results import RunKey

    e = Experiment.model_validate({"name": "x", "topologies": ["t"], "scenarios": ["s"], "runs": 2,
                                   "variants": [{"name": "bgp", "mode": "bgp"}, {"name": "obgp-rp", "mode": "obgp-rp"}]})
    keys = [RunKey("t", v, "s", i) for v in ("bgp", "obgp-rp") for i in (1, 2)]
    runs = {k: {"status": "completed", "events": []} for k in keys}
    meta = {"predictions": {"t|s": {"bgp": {"converged": 20, "settled": 20, "runs": 20},
                                    "obgp-rp": {"converged": 20, "settled": 20, "runs": 20}}}}
    dataset = type("D", (), {"experiment": e, "meta": meta, "keys": lambda self: keys, "is_done": lambda self, k: True,
                             "run": lambda self, k: runs[k], "update": lambda self, **f: meta.update(f)})()
    # BGP did not rest in run 2 where the simulator always rested, OBGP rested as foretold.
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(k): {"oscillates": int(k.variant == "bgp" and k.index == 2), "settle_s": 1.0}
                                                         for k in keys})
    asked = []

    def predictions(experiment, seeds, workers=8, guest=False, only=None, timeout=3600):
        asked.append((seeds, only))
        return {"t|s": {"bgp": {"converged": 990, "settled": 990, "runs": 1000}}}
    monkeypatch.setattr(simulate, "predictions", predictions)
    assert simulate.more_orders(dataset) == {"t|s": {"bgp"}}
    assert asked == [(simulate.MORE_ORDERS, {"t|s": {"bgp"}})]
    assert meta["predictions"]["t|s"]["bgp"] == {"converged": 990, "settled": 990, "runs": 1000, "more": True}
    assert meta["predictions"]["t|s"]["obgp-rp"]["runs"] == 20
    # Played once: with 1000 orders it does not ask again.
    assert simulate.more_orders(dataset) == {}
    # Where a part timed out, the prediction over every part stays as it was.
    meta["predictions"]["t|s"]["bgp"] = {"converged": 20, "settled": 20, "runs": 20}
    monkeypatch.setattr(simulate, "predictions", lambda *a, **k: {"t|s": {"unsupported": ["timed out"], "bgp": {"converged": 1, "runs": 1000}}})
    simulate.more_orders(dataset)
    assert meta["predictions"]["t|s"]["bgp"] == {"converged": 20, "settled": 20, "runs": 20}


def test_simulator_and_lab_agree_only_in_never_sometimes_and_always(monkeypatch):
    from lab import analysis
    from lab.config import Experiment
    from lab.results import RunKey

    e = Experiment.model_validate({"name": "x", "topologies": ["t"], "scenarios": ["s"], "runs": 3,
                                   "variants": [{"name": "bgp", "mode": "bgp"}, {"name": "obgp-rp", "mode": "obgp-rp"},
                                                {"name": "hybrid-rp", "mode": "hybrid-rp"}]})
    keys = [RunKey("t", v, "s", i) for v in ("bgp", "obgp-rp", "hybrid-rp") for i in (1, 2, 3)]
    meta = {"predictions": {"t|s": {"bgp": {"converged": 8, "settled": 8, "runs": 20, "endless": 12},
                                    "obgp-rp": {"converged": 1000, "settled": 1000, "runs": 1000}}}}
    dataset = type("D", (), {"experiment": e, "meta": meta, "keys": lambda self: keys, "is_done": lambda self, k: True,
                             "run": lambda self, k: {"status": "completed", "events": []}})()
    # BGP without rest in 2 of 3 runs, OBGP in 1 of 3 where the simulator always rested.
    without = {("bgp", 1), ("bgp", 2), ("obgp-rp", 3)}
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(k): {"oscillates": int((k.variant, k.index) in without), "settle_s": 1.0}
                                                         for k in keys})
    found = simulate.agreement(dataset)
    cells = {c["variant"]: c for c in found["cells"]}
    assert cells["bgp"]["simulator"] == "sometimes" and cells["bgp"]["lab"] == "sometimes" and cells["bgp"]["signal"] is None
    assert cells["bgp"]["endless"] == 12 and cells["bgp"]["interval"] == [round(x, 4) for x in analysis.clopper_pearson(2, 3)]
    assert cells["obgp-rp"]["simulator"] == "never" and cells["obgp-rp"]["signal"] == "the lab found no rest where the simulator always rested"
    assert cells["hybrid-rp"]["simulator"] is None and cells["hybrid-rp"]["why_not"] == "no prediction"
    assert found["per_variant"]["bgp"]["answers"] == {"simulator sometimes, lab sometimes": 1}
    assert found["per_variant"]["obgp-rp"]["signals"] == 1 and found["per_variant"]["hybrid-rp"]["not_translated"] == 1


def test_simulator_and_lab_agree_on_deviations_at_rest(monkeypatch):
    from lab import analysis
    from lab.config import Experiment
    from lab.results import RunKey

    e = Experiment.model_validate({"name": "x", "topologies": ["t"], "scenarios": ["s"], "runs": 3,
                                   "variants": [{"name": "bgp", "mode": "bgp"}, {"name": "obgp-hp", "mode": "obgp-hp"}]})
    keys = [RunKey("t", v, "s", i) for v in ("bgp", "obgp-hp") for i in (1, 2, 3)]
    meta = {"predictions": {"t|s": {"bgp": {"converged": 20, "runs": 20, "findings": {}},
                                    "obgp-hp": {"converged": 20, "runs": 20, "findings": {"unreachable": 15, "leaked": 20}}}}}
    final = lambda held, loops=0: {"name": "final", "t": 9, "stable": True, "prefixes": 1, "held": held, "loops": loops,
                                   "holed": [], "valleys": {"r1": 1}}
    runs = {k: {"status": "completed", "events": [final({"r1": 1, "r2": 1})]} for k in keys}
    runs[RunKey("t", "obgp-hp", "s", 3)]["events"] = [final({"r1": 1, "r2": 1}, loops=1)]  # a loop the simulator never saw
    dataset = type("D", (), {"experiment": e, "meta": meta, "keys": lambda self: keys, "is_done": lambda self, k: True,
                             "run": lambda self, k: runs[k]})()
    monkeypatch.setattr(analysis, "run_summary", lambda d: {str(k): {"oscillates": 0, "settle_s": 1.0} for k in keys})
    monkeypatch.setattr(simulate.topologies, "load", lambda name: {"routers": {"r1": {"leak": True}}})
    cells = {c["variant"]: c for c in simulate.agreement(dataset)["cells"]}
    lost = cells["obgp-hp"]["deviations"]["unreachable"]
    # 15 of 20 orders lose the route, no run does: sometimes and never, no signal, as shares do not compare.
    assert (lost["simulator"], lost["orders_with"], lost["lab"], lost["runs"], lost["signal"]) == ("sometimes", 15, "never", 3, None)
    assert cells["obgp-hp"]["deviations"]["loop"]["signal"] == "the lab showed loop where the simulator never did"
    assert cells["obgp-hp"]["deviations"]["leaked"]["simulator"] == "always" and cells["obgp-hp"]["deviations"]["leaked"]["signal"] is None
    assert cells["bgp"]["deviations"]["unreachable"]["lab"] is None  # BGP is the reference, not compared with itself
    # Without leakers the simulator does not look for leaks: no answer, nothing compared.
    monkeypatch.setattr(simulate.topologies, "load", lambda name: {"routers": {"r1": {}}})
    assert simulate.agreement(dataset)["cells"][0]["deviations"]["leaked"]["simulator"] is None
    # Without BGP at rest in the run of the same seed a lost route is not judged.
    runs[RunKey("t", "bgp", "s", 1)]["events"] = [{**final({"r1": 1, "r2": 1}), "stable": False}]
    cells = {c["variant"]: c for c in simulate.agreement(dataset)["cells"]}
    assert cells["obgp-hp"]["deviations"]["unreachable"]["runs"] == 2


def test_the_exact_interval_of_a_share():
    from lab.analysis import clopper_pearson

    lo, hi = clopper_pearson(0, 10)
    assert lo == 0 and abs(hi - 0.3085) < 1e-4
    lo, hi = clopper_pearson(5, 10)
    assert abs(lo - 0.1871) < 1e-4 and abs(hi - 0.8129) < 1e-4
    assert clopper_pearson(10, 10)[1] == 1


def test_a_search_takes_every_cpu_the_lab_may_use(monkeypatch, tmp_path):
    from lab import cluster

    asked = []

    def simulator(args, *a, **k):
        asked.append(args)
        Path(args[args.index("-out") + 1]).write_text("[]")
        return ""
    monkeypatch.setattr(simulate, "_simulator", simulator)
    monkeypatch.setattr(cluster, "free", lambda: (124, 500_000))
    simulate.search(routers=3, seeds=2)
    assert asked[-1][asked[-1].index("-workers") + 1] == "122"  # two for the gathering process and the web server
    monkeypatch.setattr(cluster, "free", lambda: (_ for _ in ()).throw(OSError("no host")))
    simulate.search(routers=3, seeds=2)
    assert "-workers" not in asked[-1]  # the simulator's own default


def test_a_mixed_variant_runs_the_modes_the_runner_deploys():
    from lab import modes
    from lab.config import Experiment

    t = topology.load("adversarial")
    e = Experiment.model_validate({"name": "x", "topologies": ["adversarial"], "scenarios": ["lifecycle"], "seed": 3, "variants": [
        {"name": "h", "mode": "hybrid-sp"}, {"name": "r", "mode": "random-rp", "share": 0.5},
        {"name": "r-pn", "mode": "random-rp", "share": 0.5, "per_neighbor": True}, {"name": "p", "mode": "random-paper", "share": 0.25, "per_neighbor": True},
        {"name": "none", "mode": "random-hp", "share": 0.01, "per_neighbor": True}]})
    h, r, r_pn, p, none = e.variants
    assert [simulate.sim_mode(v) for v in e.variants] == ["hybrid-sp", "random-rp-50", "random-rp-pn-50", "random-paper-pn-25", "random-hp-pn-1"]
    names = list(t["routers"])
    # As the runner: modes.assign with the run's seed, experiment seed * 1000 + run index.
    for index in (1, 2):
        drawn = modes.assign("random-rp", t["routers"], 0.5, 3000 + index)
        assert simulate.router_modes(r, t, 3000 + index) == [drawn[n] for n in names]
        # With tables per neighbor the OBGP routers get them, the BGP routers keep one table, as Cluster.deploy.
        assert simulate.router_modes(r_pn, t, 3000 + index) == [{"obgp-rp": "obgp-rp-pn", "bgp": "bgp"}[drawn[n]] for n in names]
    assert simulate.router_modes(h, t, 1) == ["obgp-sp" if t["routers"][n].get("obgp") else "bgp" for n in names]
    assert "obgp-paper-pn" not in simulate.router_modes(p, t, 3001)  # the paper's OBGP keeps one table
    assert set(simulate.router_modes(none, t, 3001)) == {"bgp-pn"}  # all BGP with tables: NS-BGP


def test_predictions_of_a_random_variant_are_per_run_and_the_pure_modes_per_cell(monkeypatch):
    from lab import problems
    from lab.config import Experiment
    from lab.results import RunKey

    t = topology.load("adversarial")
    monkeypatch.setattr(simulate.topologies, "load", lambda name: t)
    e = Experiment.model_validate({"name": "x", "topologies": ["adversarial"], "scenarios": ["lifecycle"], "runs": 2, "variants": [
        {"name": "bgp", "mode": "bgp"}, {"name": "hybrid-rp", "mode": "hybrid-rp"}, {"name": "random-rp", "mode": "random-rp", "share": 0.5}]})
    monkeypatch.setattr(simulate, "to_instances", lambda topology, sc, seed, index, bgp=None: [("", {"routers": len(t["routers"])})])
    played = []

    def run(inst, seeds, modes=None, **k):
        played.append((modes, inst.get("mixed")))
        return {m: {"converged": seeds, "runs": seeds} for m in (modes or ["bgp", "obgp-rp"])}
    monkeypatch.setattr(simulate, "run", run)
    out = simulate.predictions(e, seeds=4, workers=1)
    assert set(out) == {"adversarial|lifecycle", "adversarial|lifecycle#1", "adversarial|lifecycle#2"}
    assert set(out["adversarial|lifecycle"]) == {"bgp", "hybrid-rp"} and set(out["adversarial|lifecycle#1"]) == {"random-rp-50"}
    mixed = [m for modes, m in played if modes == ["random-rp-50"]]
    assert [m["random-rp-50"] for m in mixed] == [simulate.router_modes(e.variants[2], t, e.seed * 1000 + i) for i in (1, 2)]
    dataset = type("D", (), {"experiment": e, "meta": {"predictions": out}})()
    for v in ("bgp", "hybrid-rp", "random-rp"):
        assert problems.prediction(dataset, RunKey("adversarial", v, "lifecycle", 2)) == {"converged": 4, "settled": 4, "runs": 4}
    # Played again for a run that contradicts it: only that run's key and mode.
    played.clear()
    again = simulate.predictions(e, seeds=4, workers=1, only={"adversarial|lifecycle#2": {"random-rp-50"}})
    assert set(again) == {"adversarial|lifecycle#2"} and [m for m, _ in played] == [["random-rp-50"]]


def test_an_mrai_plays_as_coalescing_of_the_updates_that_wait(monkeypatch):
    from lab.config import Experiment

    t, _ = simulate.from_instance(EXPORT_FILTER)
    monkeypatch.setattr(simulate.topologies, "load", lambda name: t)
    monkeypatch.setattr(Experiment, "scenario_of", lambda self, case: scenarios.parse({"name": case, "steps": [{"announce": {"rate": 1, "for": 1}}]}))
    for mrai in (0, 2):
        played = []
        monkeypatch.setattr(simulate, "run", lambda inst, seeds, **k: played.append(inst) or {"bgp": {"runs": seeds, "converged": seeds}})
        e = Experiment.model_validate({"name": "x", "topologies": ["t"], "scenarios": ["s"], "runs": 1, "bgp": {"mrai": mrai},
                                       "variants": [{"name": "bgp", "mode": "bgp"}]})
        simulate.predictions(e, seeds=2)
        assert [inst.get("mrai", False) for inst in played] == [bool(mrai)]


@pytest.mark.skipif(not shutil.which("go"), reason="needs go")
def test_the_sessions_after_a_restart_come_back_in_any_order(lab_files):
    # adversarial, lifecycle: after r's restart without grace, p2 gets nothing where p1's session comes back
    # first, as in the lab's runs. In a fixed order of the sessions the simulator hardly saw it.
    from lab.config import DIRECTORY, Experiment, file_of

    e = Experiment.load(file_of(DIRECTORY, "semantics-adversarial"))
    [(_, inst)] = simulate.to_instances(topology.load("adversarial"), scenarios.load("lifecycle"), e.seed, 1, e.bgp)
    out = simulate.run(inst, seeds=40, modes=["obgp-rp"])
    assert 0 < out["obgp-rp"]["failed"][-1] < 40
    assert out["bgp"]["failed"][-1] == 0


def test_the_steps_of_a_parallel_come_in_any_order_after_its_moment():
    # The lab starts them at once: one at the moment of the step, the others at any point among its messages.
    from lab import scenario as sc_mod
    from lab import simulate as sim

    topology = {"roles": {"origins": ["a"]},
                "routers": {"a": {"asn": 1, "neighbors": [{"name": "c"}, {"name": "b"}]}, "b": {"asn": 2, "neighbors": [{"name": "a"}, {"name": "c"}]},
                            "c": {"asn": 3, "neighbors": [{"name": "a"}, {"name": "b"}]}}}
    index = {r: i for i, r in enumerate(topology["routers"])}
    steps = lambda *inner: sc_mod.parse({"name": "t", "steps": [{"announce": {"rate": 1, "for": 1}}, {"until_stable": {"timeout": 10}},
                                                               {"parallel": list(inner)}]})
    acts = [e for e in sim._events(steps({"down": {"link": "a-b"}}, {"down": {"link": "b-c"}}), topology, index, "a")[0] if e["kind"] == "down"]
    assert [bool(e.get("bounded")) for e in acts] == [True, False] and acts[1]["any"]
    assert acts[0]["group"] == acts[1]["group"]
    checks = [e for e in sim._events(steps({"expect": {"router": "b"}}, {"expect": {"router": "c"}}), topology, index, "a")[0] if e["kind"] == "expect"]
    assert all(e.get("bounded") and "group" not in e for e in checks)  # checks only: at rest, as before


def test_an_agent_is_told_when_predicting_again_goes_on(monkeypatch):
    import threading

    from lab.web import agent

    release, calls = threading.Event(), []
    monkeypatch.setattr(agent, "_result", lambda name: name)
    monkeypatch.setattr(agent, "verdict", lambda d: {"passed": True})
    monkeypatch.setattr(agent.tokens, "record", lambda text: None)
    monkeypatch.setattr(simulate, "predict_again", lambda d: calls.append(d) or release.wait(5))
    monkeypatch.setattr(agent, "PREDICT_AGAIN_WAIT_S", 0.05)
    assert agent.predict_again("r")["state"] == "predicting"
    assert agent.predict_again("r")["state"] == "predicting" and calls == ["r"]  # the same answer, not a second
    release.set()
    monkeypatch.setattr(agent, "PREDICT_AGAIN_WAIT_S", 5)
    assert agent.predict_again("r") == {"result": "r", "verdict": {"passed": True}}  # the answer under way, or a new one
    for thread in list(agent._predicting.values()):
        thread.join(5)
    assert agent.predict_again("r") == {"result": "r", "verdict": {"passed": True}} and len(calls) >= 2
    monkeypatch.setattr(simulate, "predict_again", lambda d: (_ for _ in ()).throw(ValueError("r runs")))
    with pytest.raises(ValueError, match="r runs"):
        agent.predict_again("r")
