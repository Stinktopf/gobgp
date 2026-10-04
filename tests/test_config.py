import pytest
import yaml

from lab import config
from lab.config import Experiment, Sampling


@pytest.mark.parametrize("name", config.names())
def test_experiments_load_and_round_trip(name):
    e = Experiment.load(config.path(name))
    assert Experiment.model_validate(yaml.safe_load(e.to_yaml())) == e


@pytest.mark.parametrize("interval, digits", [(1.0, 0), (0.5, 1), (0.1, 1), (0.05, 2)])
def test_decimals_follow_the_sampling(interval, digits):
    assert Sampling(interval=interval).digits() == digits


def test_duplicate_names_are_rejected():
    with pytest.raises(ValueError):
        Experiment(name="x", variants=[{"name": "a", "mode": "obgp"}, {"name": "a", "mode": "bgp"}],
                   topologies=["bad-gadget"], scenarios=["smoke-drain"])


def test_steps_are_checked_against_every_topology_before_a_start(lab_files):
    e = Experiment.load(config.path("lab-smoke"))
    with pytest.raises(ValueError, match=r"smoke-all on germany50, step 12\.1: unknown link 'toronto-fulda'"):
        e.model_copy(update={"topologies": ["germany50"]}).check_targets()


def test_variants_before_modes_still_load():
    from lab.config import Variant

    assert Variant.model_validate({"name": "a", "obgp": True}).mode == "obgp"
    assert Variant.model_validate({"name": "a", "obgp": False}).mode == "bgp"


def test_mixed_modes_give_every_router_a_pure_mode():
    from lab.config import Variant

    routers = {"a": {"obgp": True}, "b": {}, "c": {"obgp": True}, "d": {}}
    hybrid = Variant(name="h", mode="hybrid-np")
    assert hybrid.modes_of(routers) == {"a": "obgp-np", "b": "bgp", "c": "obgp-np", "d": "bgp"}
    assert hybrid.mixed and hybrid.obgp and hybrid.summary() == "Hybrid without pruning"
    with pytest.raises(ValueError, match="marks no router"):
        hybrid.modes_of({"a": {}, "b": {}})

    half = Variant(name="r", mode="random", share=0.5)
    first, again = half.modes_of(routers, seed=1), half.modes_of(routers, seed=1)
    assert first == again and sorted(first.values()) == ["bgp", "bgp", "obgp", "obgp"]
    assert any(half.modes_of(routers, seed=s) != first for s in range(2, 10))  # every run draws anew
    assert half.summary() == "OBGP on 50 % of the routers" and Variant(name="o", mode="obgp").modes_of(routers) == dict.fromkeys(routers, "obgp")
    assert not Variant(name="o", mode="obgp").mixed


@pytest.mark.parametrize("variant", [
    {"name": "a", "mode": "ospf"},
    {"name": "a", "mode": "random"},
    {"name": "a", "mode": "random-np", "share": 1.5},
    {"name": "a", "mode": "hybrid", "share": 0.5},
])
def test_invalid_modes_are_rejected(variant):
    from lab.config import Variant

    with pytest.raises(ValueError):
        Variant.model_validate(variant)


def test_mixed_modes_round_trip_and_are_checked_against_topologies(lab_files):
    e = Experiment.load(config.path("lab-smoke"))
    mixed = Experiment.model_validate(e.model_dump() | {"variants": [{"name": "r", "mode": "random", "share": 0.25}, {"name": "h", "mode": "hybrid"}]})
    assert Experiment.model_validate(yaml.safe_load(mixed.to_yaml())) == mixed
    with pytest.raises(ValueError, match="h runs Hybrid on the routers a topology marks, but bad-gadget marks none"):
        mixed.check_files()  # bad-gadget marks no router
    Experiment.model_validate(mixed.model_dump() | {"topologies": ["adversarial"], "scenarios": ["class-withdraw"], "sweeps": []}).check_files()


def test_a_daemon_must_know_its_mode():
    from lab import cluster

    e = Experiment.model_validate({"name": "x", "variants": [{"name": "a", "ref": "761af924", "mode": "obgp-np"}],
                                   "topologies": ["bad-gadget"], "scenarios": ["smoke-drain"]})
    with pytest.raises(ValueError, match="does not know OBGP without pruning yet"):
        cluster.check_modes(e)
    cluster.check_modes(e.model_copy(update={"variants": [e.variants[0].model_copy(update={"ref": "HEAD"})]}))
    cluster.check_modes(e.model_copy(update={"variants": [e.variants[0].model_copy(update={"mode": "obgp"})]}))
    with pytest.raises(ValueError, match="does not know OBGP without pruning yet"):
        cluster.check_modes(e.model_copy(update={"variants": [e.variants[0].model_copy(update={"mode": "random-np", "share": 0.5})]}))


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
    d = type("D", (), {"experiment": type("E", (), {"sampling": type("S", (), {"interval": 0.1})()})(),
                       "keys": lambda self: ["a/bgp/calibration#1"], "is_done": lambda self, k: True, "run": lambda self, k: run})()
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
    monkeypatch.setattr(cluster, "capacity", lambda: {**{"cpus": 14, "memory_mb": 16000}, **config.host_limit()})
    assert config.host_settings() == {"keep_cpus": 4, "keep_mb": 4096, "routers_per_cpu": 4}
    r = client.post("/settings/host", data={"cpus": "14", "memory_gb": "", "keep_cpus": "6", "keep_gb": "5", "routers_per_cpu": "2"}, follow_redirects=False)
    assert "Host+saved" in r.headers["location"]
    assert config.host_settings() == {"keep_cpus": 6, "keep_mb": 5120, "routers_per_cpu": 2}  # all threads count as no cap
    assert cluster.limits()["memory_mb"] == 16000 - 5120 and cluster.max_routers() == 8 * 2
    for data, problem in (({"keep_cpus": "20"}, "Keep+fewer+threads"), ({"keep_cpus": "-1"}, "cannot+be+negative"), ({"keep_gb": "-1"}, "cannot+be+negative")):
        assert problem in client.post("/settings/host", data=data, follow_redirects=False).headers["location"]
    page = client.get("/settings").text
    assert 'aria-label="CPU host reserve"' in page and "Up to 16 routers" in page
