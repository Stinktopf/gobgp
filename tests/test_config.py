import pytest
import yaml

from lab import config
from lab.config import Experiment, Sampling, Variant
from lab.results import RunKey


@pytest.mark.parametrize("name", config.names())
def test_experiments_load_and_round_trip(name):
    e = Experiment.load(config.path(name))
    assert Experiment.model_validate(yaml.safe_load(e.to_yaml())) == e


@pytest.mark.parametrize("interval, digits", [(1.0, 0), (0.5, 1), (0.1, 1), (0.05, 2)])
def test_decimals_follow_the_sampling(interval, digits):
    assert Sampling(interval=interval).digits() == digits


def test_duplicate_names_are_rejected():
    with pytest.raises(ValueError):
        Experiment(name="x", variants=[{"name": "a", "mode": "obgp-rp"}, {"name": "a", "mode": "bgp"}],
                   topologies=["bad-gadget"], scenarios=["smoke-drain"])


def test_steps_are_checked_against_every_topology_before_a_start(lab_files):
    e = Experiment.load(config.path("lab-smoke"))
    with pytest.raises(ValueError, match=r"smoke-all on germany50, step 12\.1: unknown link 'toronto-fulda'"):
        e.model_copy(update={"topologies": ["germany50"]}).check_targets()


def test_variants_before_modes_still_load():
    from lab.config import Variant

    assert Variant.model_validate({"name": "a", "obgp": True}).mode == "obgp-paper"  # the paper's runs
    assert Variant.model_validate({"name": "a", "obgp": False}).mode == "bgp"


def test_mixed_modes_give_every_router_a_pure_mode():
    from lab.config import Variant

    routers = {"a": {"obgp": True}, "b": {}, "c": {"obgp": True}, "d": {}}
    hybrid = Variant(name="h", mode="hybrid-np")
    assert hybrid.modes_of(routers) == {"a": "obgp-np", "b": "bgp", "c": "obgp-np", "d": "bgp"}
    assert hybrid.mixed and hybrid.obgp and hybrid.summary() == "Hybrid without pruning"
    with pytest.raises(ValueError, match="marks no router"):
        hybrid.modes_of({"a": {}, "b": {}})

    half = Variant(name="r", mode="random-rp", share=0.5)
    first, again = half.modes_of(routers, seed=1), half.modes_of(routers, seed=1)
    assert first == again and sorted(first.values()) == ["bgp", "bgp", "obgp-rp", "obgp-rp"]
    assert any(half.modes_of(routers, seed=s) != first for s in range(2, 10))  # every run draws anew
    assert half.summary() == "OBGP with refresh pruning on 50 % of the routers" and Variant(name="o", mode="obgp-rp").modes_of(routers) == dict.fromkeys(routers, "obgp-rp")
    assert not Variant(name="o", mode="obgp-rp").mixed


@pytest.mark.parametrize("variant", [
    {"name": "a", "mode": "ospf"},
    {"name": "a", "mode": "random-rp"},
    {"name": "a", "mode": "random-np", "share": 1.5},
    {"name": "a", "mode": "hybrid-rp", "share": 0.5},
])
def test_invalid_modes_are_rejected(variant):
    from lab.config import Variant

    with pytest.raises(ValueError):
        Variant.model_validate(variant)


def test_mixed_modes_round_trip_and_are_checked_against_topologies(lab_files):
    e = Experiment.load(config.path("lab-smoke"))
    mixed = Experiment.model_validate(e.model_dump() | {"variants": [{"name": "r", "mode": "random-rp", "share": 0.25}, {"name": "h", "mode": "hybrid-rp"}]})
    assert Experiment.model_validate(yaml.safe_load(mixed.to_yaml())) == mixed
    with pytest.raises(ValueError, match="h runs Hybrid with refresh pruning on the routers a topology marks, but bad-gadget marks none"):
        mixed.check_files()  # bad-gadget marks no router
    Experiment.model_validate(mixed.model_dump() | {"topologies": ["adversarial"], "scenarios": ["class-withdraw"], "sweeps": []}).check_files()


# The daemon of the paper's runs knows only GOBGP_OPERA_ENABLED and no MRAI.
OLD = "ifip-networking-2026"


def test_a_daemon_must_know_its_mode():
    from lab import cluster

    e = Experiment.model_validate({"name": "x", "variants": [{"name": "a", "ref": OLD, "mode": "obgp-np"}],
                                   "topologies": ["bad-gadget"], "scenarios": ["smoke-drain"]})
    with pytest.raises(ValueError, match="does not know OBGP without pruning yet"):
        cluster.check_modes(e)
    cluster.check_modes(e.model_copy(update={"variants": [e.variants[0].model_copy(update={"ref": "HEAD"})]}))
    cluster.check_modes(e.model_copy(update={"variants": [e.variants[0].model_copy(update={"mode": "obgp-paper"})]}))
    with pytest.raises(ValueError, match="does not know OBGP without pruning yet"):
        cluster.check_modes(e.model_copy(update={"variants": [e.variants[0].model_copy(update={"mode": "random-np", "share": 0.5})]}))
    # Native iBGP comes first: a daemon that filters iBGP would not run OBGP as built.
    with pytest.raises(ValueError, match="does not know OBGP with refresh pruning yet. It must read GOBGP_OPERA_IBGP=filter"):
        cluster.check_modes(e.model_copy(update={"variants": [e.variants[0].model_copy(update={"mode": "obgp-rp"})]}))


def test_a_refresh_delay_needs_a_daemon_that_reads_it(lab_files):
    from lab import cluster

    e = Experiment.load(config.path("lab-smoke"))
    delayed = e.variants[1].model_copy(update={"refresh_delay": 1.0})
    assert delayed.summary() == "OBGP with refresh pruning, first refresh after 1 s"
    cluster.check_modes(e.model_copy(update={"variants": [delayed]}))
    with pytest.raises(ValueError, match="does not delay route refreshes yet"):
        cluster.check_modes(e.model_copy(update={"variants": [delayed.model_copy(update={"ref": OLD, "mode": "obgp-paper"})]}))


def test_renamed_modes_keep_their_meaning():
    assert Variant(name="a", mode="obgp").mode == "obgp-sp"  # soft pruning until refresh pruning came
    assert Variant(name="a", mode="obgp-hard").mode == "obgp-hp" and Variant(name="a", mode="hybrid").mode == "hybrid-sp"
    assert Variant(name="a", mode="obgp-soft").mode == "obgp-sp"
    assert Variant(name="a", mode="obgp-ibgp").mode == "obgp-sp"


def test_graceful_restarts_need_the_setting(lab_files):
    from lab import scenario

    scenario.path("t-graceful").write_text("name: t-graceful\nsteps:\n  - restart: {router: fulda, graceful: true}\n")
    e = Experiment.model_validate(Experiment.load(config.path("lab-smoke")).model_dump() | {"scenarios": ["t-graceful"]})
    with pytest.raises(ValueError, match="needs graceful restart"):
        e.check_targets()
    Experiment.model_validate(e.model_dump() | {"bgp": {"graceful_restart": True}}).check_targets()


def test_the_cluster_fits_the_largest_experiment_the_host_allows():
    from lab import cluster

    small, large = (Experiment.model_validate({"name": n, "cluster": {"cpus": c, "memory_mb": m}, "variants": [{"name": "b", "mode": "bgp"}],
                                               "topologies": ["bad-gadget"], "scenarios": ["smoke-drain"]}) for n, c, m in (("s", 2, 4096), ("l", 20, 14000)))
    assert cluster.size_for([small, large], {"cpus": 32, "memory_mb": 64000}) == config.Cluster(cpus=20, memory_mb=14000)
    assert cluster.size_for([small, large], {"cpus": 14, "memory_mb": 15000}) == config.Cluster(cpus=10, memory_mb=10904)
    assert cluster.size_for([small], {"cpus": 14, "memory_mb": 15000}) == config.Cluster(cpus=2, memory_mb=4096)


def test_a_checked_experiment_is_checked_again_when_a_topology_changes(lab_files):
    import os

    from lab import config, topology
    from lab.config import Experiment

    path = config.path("lab-smoke")
    assert Experiment.load(path) is Experiment.load(path)  # kept
    t = topology.path(Experiment.load(path).topologies[0])
    t.write_text(t.read_text().replace("routers:", "routers:\n  broken: {asn: x}", 1))
    os.utime(t, ns=(1, 1))
    with pytest.raises(ValueError):
        Experiment.load(path)


def test_the_calibration_knows_its_values(lab_files, monkeypatch):
    from lab import analysis, calibration

    run = {"status": "completed", "events": [{"name": "announced", "t": 10.0, "expected": 20}, {"name": "degrade", "t": 0.0}, {"name": "withdraw", "t": 20.0, "expected": 0}]}
    good = {"selected_mean": 20, "rib_mean": 20, "rib_max": 20, "suppressed_mean": 0, "hold_churn": 0.0,
            "oscillates": 0, "convergence_s": 1.7, "sample_hz_min": 9.8}
    d = type("D", (), {"experiment": type("E", (), {"sampling": type("S", (), {"interval": 0.1})(), "variants": [], "sampling_of": lambda self, v: self.sampling})(),
                       "keys": lambda self: [RunKey("a", "bgp", "calibration", 1)], "is_done": lambda self, k: True, "run": lambda self, k: run})()
    monkeypatch.setattr(analysis, "run_metrics", lambda dataset, key, run: good)
    assert all(c["ok"] for c in calibration.checks(d))
    good["rib_max"] = 21
    good["sample_hz_min"] = 2.0
    assert {c["what"] for c in calibration.checks(d) if not c["ok"]} == {"admitted paths, largest router", "slowest router samples, Hz"}


def test_the_lab_takes_only_its_share_of_a_shared_host(tmp_path, monkeypatch):
    from lab import cluster

    monkeypatch.setattr(config, "SETTINGS", tmp_path)
    monkeypatch.setattr(cluster, "host", lambda: {"cpus": 255, "memory_mb": 1_000_000})
    assert cluster.capacity() == {"cpus": 255, "memory_mb": 1_000_000}
    (tmp_path / "host.yaml").write_text("cpus: 128\nmemory_mb: 524288\n")
    assert cluster.capacity() == {"cpus": 128, "memory_mb": 524288}


def test_a_large_cluster_holds_more_pods_than_kubernetes_does_by_default():
    from lab import cluster

    assert cluster.Cluster(config.Cluster(cpus=4, memory_mb=4000)).max_pods() == cluster.DEFAULT_PODS
    big = config.Cluster(cpus=128, memory_mb=524288)
    assert cluster.Cluster(big).max_pods() >= big.routers() + cluster.SYSTEM_PODS


def test_a_host_runs_as_many_routers_as_its_memory_holds_and_its_cpus_keep_sampling(lab_files, monkeypatch):
    from lab import cluster

    monkeypatch.setattr(cluster, "capacity", lambda: {"cpus": 14, "memory_mb": 16000})
    assert cluster.max_routers() == 10 * 4  # the CPUs limit first, 4 kept free, 4 routers each
    monkeypatch.setattr(cluster, "capacity", lambda: {"cpus": 128, "memory_mb": 16000})
    assert cluster.max_routers() == config.Cluster(memory_mb=16000 - 4096).routers()  # here the memory
    assert cluster.fitted(config.Cluster(cpus=200, memory_mb=4096)).cpus == 124  # what the host has
    smoke = Experiment.load(config.path("lab-smoke"))
    assert cluster.oversized(smoke) == {} and cluster.too_large(smoke) is None
    monkeypatch.setattr(cluster, "capacity", lambda: {"cpus": 5, "memory_mb": 16000})  # 1 thread keeps 4 routers
    assert cluster.oversized(smoke) == {}
    config.save_host({"routers_per_cpu": 3})  # as the settings set it
    assert cluster.oversized(smoke) == {"bad-gadget": ["4 routers"]}
    assert "bad-gadget" in cluster.too_large(smoke)  # none of its topologies fits


def test_full_tables_need_memory_by_the_routers_that_send_them(monkeypatch):
    from lab import cluster, topology

    dfz = Experiment.load(config.path("internet-dfz"))
    need = cluster.memory_need(dfz, topology.load("core-32")["routers"])
    assert 300_000 < need < 400_000  # MB: a million prefixes from up to four routers each
    monkeypatch.setattr(cluster, "capacity", lambda: {"cpus": 14, "memory_mb": 16000})
    assert cluster.oversized(dfz)["core-32"] == ["about 359 GB"] and cluster.too_large(dfz)


def test_the_settings_set_what_the_host_keeps_free_and_the_routers_per_thread(client, monkeypatch):
    from lab import cluster

    monkeypatch.setattr(cluster, "host", lambda: {"cpus": 14, "memory_mb": 16000})
    monkeypatch.setattr(cluster, "capacity", lambda: {"cpus": 14, "memory_mb": 16000, **config.host_limit()})
    assert config.host_settings() == {"keep_cpus": 4, "keep_mb": 4096, "routers_per_cpu": 4}
    r = client.post("/settings/host", data={"cpus": "14", "memory_gb": "", "keep_cpus": "6", "keep_gb": "5", "routers_per_cpu": "2"}, follow_redirects=False)
    assert "Host+saved" in r.headers["location"]
    assert config.host_settings() == {"keep_cpus": 6, "keep_mb": 5120, "routers_per_cpu": 2}  # all threads count as no cap
    assert cluster.limits()["memory_mb"] == 16000 - 5120 and cluster.max_routers() == 8 * 2
    for data, problem in (({"keep_cpus": "20"}, "Keep+fewer+threads"), ({"keep_cpus": "-1"}, "cannot+be+negative"), ({"keep_gb": "-1"}, "cannot+be+negative")):
        assert problem in client.post("/settings/host", data=data, follow_redirects=False).headers["location"]
    page = client.get("/settings").text
    assert 'aria-label="CPU host reserve"' in page and "Up to 16 routers" in page


def test_a_paired_experiment_runs_each_scenario_on_its_topology(lab_files):
    from lab import scenario as scenarios
    from lab import simulate
    from lab import topology as topologies

    for inst, name in ((simulate.from_instance({"routers": 3, "links": [[0, 1], [1, 2]], "events": []}, "sim-a"), "sim-a"),
                       (simulate.from_instance({"routers": 2, "links": [[0, 1]], "events": []}, "sim-b"), "sim-b")):
        t, s = inst
        topologies.save(name, t["routers"], t["roles"])
        scenarios.path(name).write_text(scenarios.to_yaml(scenarios.parse(s)))
    e = Experiment.model_validate({"name": "x", "paired": True, "variants": [{"name": "bgp", "mode": "bgp"}],
                                   "topologies": ["sim-a", "sim-b"], "scenarios": ["sim-a", "sim-b"], "runs": 2})
    assert e.combinations() == [("sim-a", "sim-a"), ("sim-b", "sim-b")] and e.runs_total() == 4
    e.check_files()
    assert Experiment.model_validate(yaml.safe_load(e.to_yaml())).paired
    with pytest.raises(ValueError, match="needs the scenario of its name"):
        e.model_copy(update={"scenarios": ["sim-a"]}).check_files()
    unpaired = e.model_copy(update={"paired": False})
    assert len(unpaired.combinations()) == 4


def test_a_variant_samples_at_its_own_interval():
    e = Experiment.model_validate({"name": "x", "sampling": {"interval": 0.1}, "topologies": ["noble-eu"], "scenarios": ["fill-60"],
                                   "variants": [{"name": "fast", "mode": "obgp-rp"}, {"name": "slow", "mode": "obgp-rp", "interval": 1.0}]})
    assert e.sampling_of("fast").interval == 0.1 and e.sampling_of("slow").interval == 1.0
    assert e.sampling_of("slow").stable_s == e.sampling.stable_s and e.digits() == 1
    assert "interval: 1.0" in e.to_yaml() and e.to_yaml().count("interval") == 1


def test_an_mrai_needs_a_daemon_that_holds_back():
    from lab import cluster

    e = Experiment.model_validate({"name": "x", "bgp": {"mrai": 30}, "variants": [{"name": "a", "ref": OLD, "mode": "obgp-paper"}],
                                   "topologies": ["bad-gadget"], "scenarios": ["smoke-drain"]})
    with pytest.raises(ValueError, match="would ignore the MRAI"):
        cluster.check_modes(e)


def test_a_paired_experiment_runs_each_scenario_on_its_topology_only():
    e = Experiment.load(config.path("lab-features"))
    assert e.cases_of("lab-features") == ["lab-features"] and e.cases_of("ixp") == ["ixp"]
    smoke = Experiment.load(config.path("lab-smoke"))
    assert smoke.cases_of(smoke.topologies[0]) == smoke.cases()  # not paired: every scenario
