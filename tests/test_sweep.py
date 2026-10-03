import pytest
import yaml

from lab import config, scenario
from lab.config import Experiment


def smoke() -> Experiment:
    return Experiment.load(config.path("lab-smoke"))


def test_the_smoke_test_sweeps_the_rate_of_smoke_all():
    e = smoke()
    assert [(w.scenario, w.param, w.values) for w in e.sweeps] == [("smoke-all", "rate", [1, 2])]
    assert e.cases() == ["smoke-drain", "smoke-all@rate=1", "smoke-all@rate=2"]
    assert e.runs_total() == 3 * len(e.variants) * e.runs
    assert e.sweep_of("smoke-all@rate=2") == e.sweeps[0] and e.sweep_of("smoke-drain") is None


def test_sweeps_vary_one_parameter_at_a_time():
    sc = scenario.parse({"name": "t", "params": {"rate": 1, "delay": 50},
                         "steps": [{"announce": {"rate": "$rate", "for": 5}}, {"degrade": {"link": "a-b", "delay_ms": "$delay"}}]})
    e = smoke().model_copy(update={"sweeps": [config.Sweep(scenario="smoke-all", param="rate", values=[1, 2]),
                                              config.Sweep(scenario="smoke-all", param="other", values=[3, 4])]})
    assert e.cases() == ["smoke-drain", "smoke-all@rate=1", "smoke-all@rate=2", "smoke-all@other=3", "smoke-all@other=4"]
    case = scenario.with_param(sc, "delay", 10, "t@delay=10")
    assert case.steps[0].args.rate == 1 and case.steps[1].args.delay_ms == 10  # the other one as the scenario gives it
    with pytest.raises(ValueError, match="only in one sweep"):
        Experiment.model_validate(smoke().model_dump() | {"sweeps": [{"scenario": "smoke-all", "param": "rate", "values": [1, 2]}] * 2})


def test_a_case_runs_its_scenario_with_the_value():
    e = smoke()
    sc = e.scenario_of("smoke-all@rate=2")
    assert sc.name == "smoke-all@rate=2" and sc.params == {"rate": 2}
    assert [s.args.rate for s in scenario.each_step(sc.steps) if s.kind == "announce"] == [2]
    assert scenario.split_case("smoke-all@rate=2") == ("smoke-all", "rate", 2.0)
    assert scenario.split_case("smoke-all") == ("smoke-all", None, None)


def test_a_sweep_needs_a_parameter_its_scenario_offers_and_good_values():
    e = smoke()
    with pytest.raises(ValueError, match="does not offer nothing"):
        e.model_copy(update={"sweeps": [config.Sweep(scenario="smoke-all", param="nothing", values=[1, 2])]}).check_files()
    with pytest.raises(ValueError, match="does not run"):
        e.model_copy(update={"sweeps": [config.Sweep(scenario="calibration", param="rate", values=[1, 2])]}).check_files()
    with pytest.raises(ValueError, match="rate = 0 in smoke-all"):  # an announce rate must be above 0
        e.model_copy(update={"sweeps": [config.Sweep(scenario="smoke-all", param="rate", values=[0, 1])]}).check_files()
    for bad in ({"values": [1, 1]}, {"values": [3]}):
        with pytest.raises(ValueError):
            config.Sweep(scenario="smoke-all", param="rate", **bad)


def test_the_file_keeps_the_sweeps():
    e = smoke()
    assert "sweeps:\n  - {scenario: smoke-all, param: rate, values: [1, 2]}" in e.to_yaml()
    assert Experiment.model_validate(yaml.safe_load(e.to_yaml())).sweeps == e.sweeps


def test_a_result_keeps_its_cases(lab_files):
    from lab import results

    e = smoke()
    name = results.Dataset.new_name(e)
    results.Dataset.create(e, name)
    d = results.Dataset.find(name)
    assert d.experiment.sweeps == e.sweeps
    assert {k.scenario for k in d.keys()} == set(e.cases())
    assert d.scenario("smoke-all@rate=2").dump() == e.scenario_of("smoke-all@rate=2").dump()


FORM = {"name": "t-sweep", "runs": "1", "seed": "1", "v0_name": "bgp", "v0_mode": "bgp", "topologies": "bad-gadget",
        "scenarios": ["smoke-all", "smoke-drain"], "cpus": "4", "memory_mb": "8000", "hold_time": "90", "keepalive": "30",
        "connect_retry": "5", "interval": "0.1", "stable_s": "3", "s0_scenario": "smoke-all", "s0_param": "rate", "s0_values": "0,5; 2"}


def test_the_builder_saves_sweeps_and_offers_the_parameters(client):
    r = client.post("/experiments/save", data=FORM)
    assert r.status_code == 200, r.text
    e = Experiment.load(config.path("t-sweep"))
    assert e.sweeps[0].values == [0.5, 2] and e.cases() == ["smoke-all@rate=0.5", "smoke-all@rate=2", "smoke-drain"]
    page = client.get("/experiments/t-sweep").text
    assert 'name="s0_scenario"' in page and 'data-value="rate"' in page and '"smoke-all": {"rate": 1' in page


def test_the_builder_says_plainly_what_is_wrong_with_a_sweep(client):
    problems = lambda **change: client.post("/experiments/save", data={**FORM, **change}).json()["problems"]
    assert problems(s0_values="") == ["Give the sweep of smoke-all at least two values."]
    assert problems(s0_values="1, 1") == ["Sweep of smoke-all: every value only once."]


def test_the_curve_runs_over_the_values_or_the_routers(monkeypatch):
    from lab import analysis, results

    d = results.Dataset.find("ifip-networking-2026")
    c = analysis.curve(d, d.experiment.topologies[0], d.experiment.scenarios[0], "rib_mean")
    assert c["label"] == "routers" and c["x"] == sorted(c["x"]) and len(c["x"]) == len(d.experiment.topologies)
    monkeypatch.setattr(type(d), "experiment", property(lambda self: smoke()))
    monkeypatch.setattr(analysis, "summary", lambda _: [{"topology": "bad-gadget", "scenario": "smoke-all@rate=2", "variant": "bgp",
                                                         "metrics": {"rib_mean": {"median": 5, "ci_low": 4, "ci_high": 6, "ci_level": 0.97, "n": 6}}}])
    c = analysis.curve(d, "bad-gadget", "smoke-all@rate=1", "rib_mean")
    assert c["x"] == [1, 2] and c["label"] == "rate" and c["series"]["bgp"]["median"] == [None, 5]


def test_the_charts_tab_shows_the_curve_only_for_sweeps_and_sizes(client, monkeypatch):
    from lab import analysis, results
    from lab.web import app as web

    assert analysis.size_series(["core-32", "core-64", "core-128"]) and analysis.size_series(["ba-m2-16-s1", "ba-m2-32-s1"])
    assert not analysis.size_series(["germany50", "bad-gadget", "noble-eu"]) and not analysis.size_series(["core-32"])
    e = results.Dataset.find("ifip-networking-2026").experiment
    assert "data-curve" not in client.get("/results/ifip-networking-2026?tab=charts").text  # three networks, not one in sizes
    url = f"/results/ifip-networking-2026/curve?topology={e.topologies[0]}&scenario={e.scenarios[0]}&metric=rib_mean"
    assert client.get(url).status_code == 404
    monkeypatch.setattr(analysis, "size_series", lambda topologies: True)
    monkeypatch.setitem(web.templates.env.globals, "size_series", lambda topologies: True)
    page = client.get("/results/ifip-networking-2026?tab=charts&metric=rib_mean").text
    assert "data-curve" in page and "By routers" in page and "order statistics" in page
    assert client.get(url).json()["label"] == "routers"


def test_the_curve_starts_with_the_first_metric_not_admitted(client, monkeypatch):
    from lab.web import app as web

    monkeypatch.setitem(web.templates.env.globals, "size_series", lambda topologies: True)
    page = client.get("/results/ifip-networking-2026?tab=charts").text
    assert "metric=convergence_s" in page.split("data-curve")[1].split(">")[0]
