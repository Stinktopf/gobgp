"""The simulator and the lab in each other's terms: a conversion there and
back keeps the network, and the simulator judges both alike."""

import shutil

import pytest

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
    out["events"] = [{"prefixes": "all", **e} if e["kind"] == "expect" else e for e in out.get("events", [])]
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
        {"kind": "announce", "args": {"rate": 5, "for": 10}},
        {"kind": "down", "args": {"link": "r0-r1", "mode": "cut"}},
        {"kind": "restart", "args": {"router": "r1"}}]})
    with pytest.raises(simulate.Unsupported) as e:
        simulate.to_instance(t, noisy)
    reasons = " ".join(e.value.reasons)
    assert "expire after 60 s" in reasons and "closed with a notification only" in reasons and "no counterpart" in reasons


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
    fill = scenarios.parse({"name": "x", "steps": [{"announce": {"rate": 2, "for": 30}}, {"wait": 10}]})
    parts = simulate.to_instances(t, fill)
    origins = t["roles"]["origins"]
    assert [label for label, _ in parts] == [f"{o} · {life}" for o in origins for life in ("held", "removed")]
    held, removed = dict(parts)[f"{origins[0]} · held"], dict(parts)[f"{origins[0]} · removed"]
    assert "events" not in held and removed["events"] == [{"after": QUIET, "kind": "withdraw"}]  # it expires once quiet
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


def test_an_expiry_among_other_steps_is_named_not_placed():
    t, _ = simulate.from_instance(EXPORT_FILTER)
    sc = scenarios.parse({"name": "x", "steps": [{"announce": {"rate": 1, "for": 10}}, {"wait": 40}, {"down": {"link": "r0-r1"}}]})
    with pytest.raises(simulate.Unsupported) as e:
        simulate.to_instances(t, sc)
    assert "cannot place the expiry" in " ".join(e.value.reasons)


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
        run = lambda self, key: {"status": "completed", "events": [{"name": "expect", "passed": runs[key.variant, key.index]}]}
    monkeypatch.setattr(simulate, "run", lambda inst, seeds: {
        "bgp": {"runs": seeds, "converged": seeds, "failed": [3]}, "obgp-rp": {"runs": seeds, "converged": seeds, "failed": [0]}})
    monkeypatch.setattr("lab.analysis.run_summary", lambda d: {})
    rows, skipped = simulate.compare(Fake(), seeds=10)
    by = {r["variant"]: r for r in rows}
    assert by["bgp"]["lab_failed"] == [1] and by["bgp"]["deviations"] == []  # both happen, with the order of messages
    assert by["obgp"]["deviations"] == ["check 1 failed in 2 of 2 runs, the simulator never fails it"]


def test_a_route_server_translates_both_ways():
    t = topology.load("ixp")
    inst = simulate.to_instance(t, scenarios.load("ixp"))
    rs = list(t["routers"]).index("rs")
    assert inst["route_servers"] == [rs]
    back, _ = simulate.from_instance(inst)
    assert all(m.get("rsClient") for m in back["routers"][simulate.router_name(rs)]["neighbors"])


def test_a_prediction_of_a_scenario_without_steps_after_the_announcement(monkeypatch):
    monkeypatch.setattr(simulate, "run", lambda inst, seeds: {"bgp": {"runs": seeds, "converged": 0, "failed": [], "findings": {}}})
    out = simulate.predict("sim-local-pref-bgp-no-convergence", "sim-local-pref-bgp-no-convergence", seeds=3)
    assert out["bgp"]["allowed"] == []  # no checks, nothing to allow
