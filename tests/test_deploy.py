"""Deploying routers: progress, the watch on the Kubernetes API, batches."""

import json
import threading
import time

import pytest

from lab import cluster, config
from lab.cluster import LabError

TABLE = """\
r1-5d9c7b-abcde   1/1   Running             0          2m
r2-5d9c7b-fghij   0/1   Running             1 (30s ago)   2m
r3-5d9c7b-klmno   0/1   ContainerCreating   0          10s
r4-5d9c7b-pqrst   0/1   Pending             0          1s
"""


def test_pods_are_counted_by_status_and_readiness():
    assert cluster.pod_status(TABLE) == ({"Running": 2, "ContainerCreating": 1, "Pending": 1}, 1)
    assert cluster.pod_status("") == ({}, 0)


def test_the_watch_logs_progress_and_ends_a_deploy_when_the_api_is_silent(caplog):
    now = [0.0]
    answers = [({"Running": 96, "Pending": 160}, 12)]

    def status():
        if answers:
            return answers.pop()
        raise LabError("kubectl get pods: Unable to connect to the server")

    watch = cluster.Watch("core-256", 256, status, silent=180, clock=lambda: now[0])
    with caplog.at_level("INFO", logger="lab"):
        assert watch.step()
    assert "core-256: 256 of 256 pods (160 Pending, 96 Running), 12 ready with all sessions up" in caplog.text
    now[0] = 100
    assert watch.step() and not watch.lost.is_set()  # silent, but not yet for long
    now[0] = 181
    assert not watch.step() and watch.lost.is_set()
    assert watch.why == "the Kubernetes API stopped answering at 96 of 256 pods running, no answer for 181 s"


def test_a_lost_api_ends_a_command():
    lost = threading.Event()
    threading.Timer(0.2, lost.set).start()
    began = time.monotonic()
    with pytest.raises(LabError, match="aborted"):
        cluster.sh("sleep", "30", abort=lost)
    assert time.monotonic() - began < 3


def test_routers_go_in_batches_only_beyond_one_batch():
    names = [f"r{i}" for i in range(70)]
    assert cluster.batches(names[:32]) == [names[:32]]
    assert [len(b) for b in cluster.batches(names)] == [32, 64, 70]
    assert cluster.batches(names)[-1] == names


def topology(n: int) -> dict:
    """A ring: every router has two neighbors."""
    return {"routers": {f"r{i}": {"asn": 65000 + i, "routerId": f"10.0.0.{i}",
                                  "neighbors": [{"name": f"r{(i - 1) % n}", "peerAs": 65000 + (i - 1) % n},
                                                {"name": f"r{(i + 1) % n}", "peerAs": 65000 + (i + 1) % n}]}
                        for i in range(n)}}


class Controllers:
    """The routers' controllers behind the proxy: they record what they are told."""

    def __init__(self, deaf=()):
        self.pods, self.told, self.deaf = {}, {}, set(deaf)

    def post(self, router, path, body=None, timeout=60):
        assert path == "/neighbors/addresses"
        if router in self.deaf:  # its controller does not listen yet
            self.deaf.discard(router)
            raise LabError(f"{router} {path}: connection refused")
        self.told[router] = body["addresses"]
        return {"told": True}


def pod_line(router, ip, ready, phase="Running", pod=None):
    return f"{pod or router + '-5d9c7b-abcde'} {router} {phase} {ip or '<none>'} {str(ready).lower()} <none>"


@pytest.fixture
def deploying(monkeypatch):
    """A cluster whose Helm calls are recorded with the routers they install,
    and whose pods run as soon as they are installed, ready once told."""
    calls, installed, wanted = [], [], [0]
    controllers = Controllers()

    def sh(*args, **kwargs):
        if args[0] == "helm":
            with open(args[args.index("-f") + 1]) as f:
                values = json.load(f)
            assert len(values["routers"]) == wanted[0]
            routers = values.get("deploy") or list(values["routers"])
            installed[:] = list(routers)
            calls.append(("--wait" in args, list(routers), kwargs.get("abort")))
        return ""

    def router_pods(self):
        return cluster.router_pods("\n".join(pod_line(r, f"10.244.0.{i + 10}", r in controllers.told) for i, r in enumerate(installed)))

    monkeypatch.setattr(cluster, "sh", sh)
    monkeypatch.setattr(cluster.Cluster, "undeploy", lambda self: None)
    monkeypatch.setattr(cluster.Cluster, "_status", lambda self: ({"Running": len(installed)}, 0))
    monkeypatch.setattr(cluster.Cluster, "_router_pods", router_pods)
    monkeypatch.setattr(cluster, "TELL_S", 0)
    monkeypatch.setattr(cluster, "neigh_table", lambda: (0, 65536))
    c =cluster.Cluster(config.Cluster(cpus=8, memory_mb=8192))

    def deploy(n):
        wanted[0] = n
        t = topology(n)
        c.deploy("t", t, "tag", {r: "bgp" for r in t["routers"]}, 1, config.Bgp(), controllers)
        return calls, controllers

    return deploy


def test_a_small_topology_goes_in_one_call(deploying):
    calls, _ = deploying(32)
    assert [(wait, len(routers)) for wait, routers, _ in calls] == [(False, 32)]
    assert all(abort is not None for *_, abort in calls)


def test_a_large_topology_goes_in_batches_that_keep_the_routers_before(deploying):
    calls, _ = deploying(100)
    assert [(wait, len(routers)) for wait, routers, _ in calls] == [(False, 32), (False, 64), (False, 96), (False, 100)]
    assert calls[1][1][:32] == calls[0][1]


def test_every_controller_is_told_its_neighbors_pod_addresses(deploying):
    _, controllers = deploying(40)
    assert set(controllers.told) == {f"r{i}" for i in range(40)}
    assert controllers.told["r0"] == {"r39": "10.244.0.49", "r1": "10.244.0.11"}
    assert controllers.pods["r5"] == "r5-5d9c7b-abcde"


def test_the_chart_has_no_services_and_the_routers_ask_no_dns():
    templates = cluster.CHART / "templates"
    assert not (templates / "service.yaml").exists()
    deployment = (templates / "deployment.yaml").read_text()
    assert "kind: Service" not in deployment and "dnsConfig" not in deployment
    assert "emptyDir" in deployment and "/var/lib/lab" in deployment


def test_pods_are_read_by_router_with_address_and_readiness():
    table = "\n".join([pod_line("a", "10.244.0.5", True), pod_line("b", None, False, phase="Pending"),
                       "c-1 c Running 10.244.0.7 false 2026-11-13T10:00:00Z"])
    assert cluster.router_pods(table) == [
        {"pod": "a-5d9c7b-abcde", "router": "a", "phase": "Running", "ip": "10.244.0.5", "ready": True, "gone": False},
        {"pod": "b-5d9c7b-abcde", "router": "b", "phase": "Pending", "ip": "", "ready": False, "gone": False},
        {"pod": "c-1", "router": "c", "phase": "Running", "ip": "10.244.0.7", "ready": False, "gone": True},
    ]


def watch_of(n):
    return cluster.Watch("t", n, lambda: ({}, 0))


def test_addresses_go_out_only_once_every_pod_runs_with_one(monkeypatch):
    t = topology(3)["routers"]
    rounds = iter([
        [pod_line("r0", "10.0.0.10", False), pod_line("r1", None, False, phase="Pending"), pod_line("r2", "10.0.0.12", False)],
        [pod_line("r0", "10.0.0.10", False), pod_line("r1", "10.0.0.11", False), pod_line("r2", "10.0.0.12", False)],
        [pod_line("r0", "10.0.0.10", False), pod_line("r1", "10.0.0.11", False), pod_line("r2", "10.0.0.12", False)],
        [pod_line("r0", "10.0.0.10", True), pod_line("r1", "10.0.0.11", True), pod_line("r2", "10.0.0.12", True)],
    ])
    told_at = []
    controllers = Controllers(deaf={"r2"})
    original = controllers.post
    monkeypatch.setattr(cluster.Cluster, "_router_pods", lambda self: cluster.router_pods("\n".join(next(rounds))))
    c = cluster.Cluster(config.Cluster(cpus=8, memory_mb=8192))

    def post(router, path, body=None, timeout=60):
        told_at.append(router)
        return original(router, path, body, timeout)

    controllers.post = post
    c._tell(t, controllers, watch_of(3), timeout=60, every=0)
    assert sorted(told_at) == ["r0", "r1", "r2", "r2"]  # nothing while r1 was pending, r2 again once it listened
    assert controllers.told["r1"] == {"r0": "10.0.0.10", "r2": "10.0.0.12"}


def test_addresses_go_out_in_waves_not_all_sessions_at_once(monkeypatch):
    t = topology(40)["routers"]
    controllers, seen = Controllers(), []

    def pods(self):
        seen.append(len(controllers.told))
        return cluster.router_pods("\n".join(pod_line(r, f"10.0.0.{i + 10}", len(controllers.told) == 40) for i, r in enumerate(t)))

    monkeypatch.setattr(cluster.Cluster, "_router_pods", pods)
    cluster.Cluster(config.Cluster(cpus=8, memory_mb=8192))._tell(t, controllers, watch_of(40), timeout=60, every=0)
    assert seen == [0, cluster.WAVE, 2 * cluster.WAVE, 40]


def test_probes_come_less_often_among_many_routers_and_gobgpd_takes_its_threads():
    assert cluster.probe_period(cluster.BATCH) == 2 and cluster.probe_period(cluster.BATCH + 1) == 10
    deployment = (cluster.CHART / "templates" / "deployment.yaml").read_text()
    assert "$.Values.probe.periodS" in deployment and "GOBGPD_PROCS" in deployment
    assert config.Bgp().procs == 0  # one thread per CPU, as gobgpd did before


def test_a_lost_api_is_looked_at_before_the_deploy_ends():
    looks, now = [], [0.0]

    def status():
        raise LabError("kubectl get pods: Unable to connect to the server")

    watch = cluster.Watch("t", 10, status, clock=lambda: now[0], diagnose=lambda why="": looks.append((why, watch.lost.is_set())))
    now[0] = cluster.API_SILENT_S + 1
    assert watch.step() is False
    assert looks == [(watch.why, False)] and watch.lost.is_set()


def test_a_pod_replaced_during_the_deploy_fails_it(monkeypatch):
    t = topology(2)["routers"]
    rounds = iter([
        [pod_line("r0", "10.0.0.10", False), pod_line("r1", "10.0.0.11", False)],
        [pod_line("r0", "10.0.0.10", False), pod_line("r1", "10.0.0.21", False, pod="r1-new")],
    ])
    monkeypatch.setattr(cluster.Cluster, "_router_pods", lambda self: cluster.router_pods("\n".join(next(rounds))))
    c = cluster.Cluster(config.Cluster(cpus=8, memory_mb=8192))
    with pytest.raises(LabError, match="pod of r1 was replaced"):
        c._tell(t, Controllers(), watch_of(2), timeout=60, every=0)


def test_a_deploy_that_never_gets_ready_tells_how_far_it_got(monkeypatch):
    t = topology(2)["routers"]
    monkeypatch.setattr(cluster.Cluster, "_router_pods", lambda self: cluster.router_pods(pod_line("r0", "10.0.0.10", False)))
    c = cluster.Cluster(config.Cluster(cpus=8, memory_mb=8192))
    with pytest.raises(LabError, match="1 of 2 pods running, 0 told their neighbors, 0 ready after 0 s"):
        c._tell(t, Controllers(), watch_of(2), timeout=0, every=0)


def test_a_lost_api_ends_the_deploy_with_its_reason(monkeypatch):
    monkeypatch.setattr(cluster, "sh", lambda *a, **kw: "")
    monkeypatch.setattr(cluster.Cluster, "undeploy", lambda self: None)
    monkeypatch.setattr(cluster.Cluster, "_status", lambda self: ({}, 0))

    def lost(self, count, watch):
        watch.why = "the Kubernetes API stopped answering at 32 of 64 pods running, no answer for 181 s"
        watch.lost.set()
        raise LabError(watch.why)

    monkeypatch.setattr(cluster.Cluster, "_wait_running", lost)
    c = cluster.Cluster(config.Cluster(cpus=8, memory_mb=8192))
    t = topology(64)
    with pytest.raises(cluster.HostLimit, match="routers of t did not become ready: the Kubernetes API stopped answering at 32 of 64"):
        c.deploy("t", t, "tag", {r: "bgp" for r in t["routers"]}, 1, config.Bgp(), Controllers())


def test_a_batch_waits_for_its_pods_to_run_and_tells_how_far_they_got(monkeypatch):
    c = cluster.Cluster(config.Cluster(cpus=8, memory_mb=8192))
    seen = iter([({"Pending": 32}, 0), ({"Running": 20, "Pending": 12}, 0), ({"Running": 32}, 0)])
    monkeypatch.setattr(cluster.Cluster, "_status", lambda self: next(seen))
    watch = cluster.Watch("t", 64, lambda: ({}, 0))
    c._wait_running(32, watch, every=0)
    monkeypatch.setattr(cluster.Cluster, "_status", lambda self: ({"Running": 20}, 0))
    with pytest.raises(LabError, match="20 of 32 pods running after 0 s"):
        c._wait_running(32, watch, timeout=0, every=0)


def test_a_full_connection_tracking_ends_the_deploy_as_a_limit_of_the_host():
    now = [0.0]
    watch = cluster.Watch("t", 256, lambda: ({"Running": 190}, 0), conntrack=lambda: (170000, 262144), clock=lambda: now[0])
    watch.running = 190
    assert watch.step() is False and watch.lost.is_set()
    assert "connection tracking held 170000 of 262144 entries at 190 of 256 pods running" in watch.why
    calm = cluster.Watch("t", 256, lambda: ({"Running": 10}, 0), conntrack=lambda: (20000, 262144), clock=lambda: now[0])
    assert calm.step() is True and not calm.lost.is_set()
    assert issubclass(cluster.HostLimit, cluster.LabError)


def test_a_run_is_guarded_quietly_and_its_guard_ends_it(caplog):
    now, ended = [0.0], []
    answers = [({"Running": 10}, 10)]

    def status():
        if answers:
            return answers.pop()
        raise LabError("kubectl get pods: Unable to connect to the server")

    guard = cluster.Watch("t", 10, status, clock=lambda: now[0], quiet=True, on_lost=lambda: ended.append(1))
    with caplog.at_level("INFO", logger="lab"):
        assert guard.step()
    assert caplog.text == "" and not ended
    now[0] = 181
    assert not guard.step() and ended == [1] and "API stopped answering" in guard.why


def test_a_cluster_is_clean_once_its_api_answers_and_no_routers_stay(monkeypatch):
    c = cluster.Cluster(config.Cluster(cpus=8, memory_mb=8192))
    monkeypatch.setattr(cluster.Cluster, "api_answers", lambda self: False)
    assert c.clean() == "the Kubernetes API does not answer"
    monkeypatch.setattr(cluster.Cluster, "api_answers", lambda self: True)
    monkeypatch.setattr(cluster.Cluster, "undeploy", lambda self: None)
    assert c.clean() is None

    def stays(self):
        raise LabError("routers of the previous run did not terminate")

    monkeypatch.setattr(cluster.Cluster, "undeploy", stays)
    assert c.clean() == "routers of another run stay: routers of the previous run did not terminate"


def test_routers_without_their_release_are_deleted_in_the_lab_namespace_only(monkeypatch):
    c = cluster.Cluster(config.Cluster(cpus=8, memory_mb=8192))
    commands, pods = [], [[{"metadata": {}}], [{"metadata": {}}], []]
    monkeypatch.setattr(cluster.subprocess, "run", lambda args, **kw: commands.append(args))
    monkeypatch.setattr(cluster, "sh", lambda *args, **kw: commands.append(list(args)) or "")
    monkeypatch.setattr(cluster.Cluster, "_pods", lambda self: pods.pop(0))
    monkeypatch.setattr(cluster.time, "sleep", lambda s: None)
    c.undeploy()
    assert commands[0][:2] == ["helm", "uninstall"]
    assert commands[1] == ["kubectl", "--context", cluster.PROFILE, "-n", cluster.NAMESPACE, "delete", "deployments", "--all", "--wait=false"]


def test_the_neighbour_table_is_read_from_the_kernel(tmp_path, monkeypatch):
    (tmp_path / "gc_thresh3").write_text("1024\n")
    stat = tmp_path / "arp_cache"
    stat.write_text("entries  allocs\n0000012c 00000000\n0000012c 00000000\n")
    monkeypatch.setattr(cluster, "NEIGH", tmp_path)
    monkeypatch.setattr(cluster, "NEIGH_STAT", stat)
    assert cluster.neigh_table() == (300, 1024)
    monkeypatch.setattr(cluster, "NEIGH_STAT", tmp_path / "missing")
    assert cluster.neigh_table() is None


def test_a_topology_too_large_for_the_neighbour_table_ends_before_any_pod(deploying, monkeypatch):
    monkeypatch.setattr(cluster, "neigh_table", lambda: (100, 1024))
    with pytest.raises(cluster.HostLimit, match=r"t needs about 1,200 entries in the kernel's neighbour table, which holds 1,024 with 100 in use"):
        deploying(400)
    monkeypatch.setattr(cluster, "neigh_table", lambda: (100, 65536))
    calls, _ = deploying(64)
    assert calls
