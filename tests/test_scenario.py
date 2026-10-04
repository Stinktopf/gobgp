import re

import pytest
import yaml

from lab import scenario, topology


def network(name):
    t = topology.load(name)
    return scenario.Network(t["routers"], t["roles"])


@pytest.mark.parametrize("name", scenario.names())
def test_scenarios_parse_and_round_trip(name):
    s = scenario.load(name)
    again = scenario.parse(yaml.safe_load(scenario.to_yaml(s)))
    assert again == s


@pytest.mark.parametrize("name", scenario.names())
def test_timeline_ends_with_the_duration(name):
    s = scenario.load(name)
    rows = scenario.timeline(s.steps)
    assert max(r["end"] for r in rows) == pytest.approx(s.duration())
    assert all(r["start"] <= r["end"] for r in rows)


def test_timeline_paths_of_parallel_steps():
    s = scenario.load("smoke-all")
    paths = [tuple(r["path"]) for r in scenario.timeline(s.steps)]
    assert len(paths) == len(set(paths))


def test_random_choices_depend_on_seed_run_and_position_only():
    s = scenario.load("link-flap")
    net = network("noble-eu")
    a = scenario.preview_targets(s.steps, net, seed=42, index=1)
    assert a == scenario.preview_targets(s.steps, net, seed=42, index=1)
    assert a != scenario.preview_targets(s.steps, net, seed=43, index=1)


def test_random_choices_never_hit_origins():
    net = network("noble-eu")
    origins = set(net.roles["origins"])
    for seed in range(50):
        routers, _ = net.resolve(scenario.Down(router="random", count=5), scenario.rng(seed, 1, (0,)))
        assert not origins & set(routers)


def test_links_with_dashes_in_router_names():
    net = scenario.Network({"a-b": {"neighbors": [{"name": "c"}]}, "c": {"neighbors": [{"name": "a-b"}]}}, {})
    assert net.links_of("a-b-c", None) == [("a-b", "c")]
    with pytest.raises(ValueError):
        net.links_of("a-c", None)


def test_invalid_steps_are_rejected():
    with pytest.raises(ValueError):
        scenario.parse({"name": "x", "steps": [{"down": {"router": "a", "link": "b"}}]})
    with pytest.raises(ValueError):
        scenario.parse({"name": "x", "steps": [{"parallel": []}]})
    with pytest.raises(ValueError):
        scenario.parse({"name": "x", "steps": [{"jump": {}}]})


def test_texts_that_look_like_yaml_survive():
    s = scenario.parse({"name": "x", "description": "Drain: half, then yes",
                        "steps": [{"restart": {"router": "yes"}}, {"prepend": {"router": "on", "times": 2}}]})
    assert scenario.parse(yaml.safe_load(scenario.to_yaml(s))) == s


def test_preview_checks_the_neighbor():
    s = scenario.parse({"name": "x", "steps": [{"set_preference": {"router": "frankfurt", "neighbor": "nowhere", "value": 300}}]})
    assert "error" in scenario.preview_targets(s.steps, network("bad-gadget"), 42)["0"]


def test_a_number_of_a_step_can_be_a_parameter():
    import yaml

    sc = scenario.parse({"name": "t", "params": {"delay": 50, "times": 2},
                         "steps": [{"degrade": {"link": "a-b", "delay_ms": "$delay"}},
                                   {"repeat": {"times": "$times", "every": 5, "steps": [{"wait": "$delay"}]}}]})
    assert sc.steps[0].args.delay_ms == 50 and sc.steps[1].args.times == 2 and sc.steps[1].args.steps[0].args == 50
    assert sc.dump()["steps"][0] == {"degrade": {"link": "a-b", "delay_ms": "$delay"}}
    assert "params: {delay: 50, times: 2}" in scenario.to_yaml(sc) and "wait: $delay" in scenario.to_yaml(sc)
    assert scenario.parse(yaml.safe_load(scenario.to_yaml(sc))).dump() == sc.dump()


@pytest.mark.parametrize("bad, problem", [
    ({"params": {"x": 1}, "steps": [{"wait": 3}]}, "no step uses the parameter x"),
    ({"steps": [{"wait": "$y"}]}, "uses $y, which is no parameter"),
    ({"params": {"X": 1}, "steps": [{"wait": "$X"}]}, "lowercase"),
])
def test_parameters_must_be_defined_used_and_named_plainly(bad, problem):
    with pytest.raises(ValueError, match=re.escape(problem)):
        scenario.parse({"name": "t", **bad})
