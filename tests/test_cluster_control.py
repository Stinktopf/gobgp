import threading
import time

import pytest

from lab import cluster, config, lifecycle
from lab.web.cluster_control import ClusterControl, idle_minutes, save_idle
from lab.web.jobs import Jobs


@pytest.fixture
def power(lab_files, monkeypatch):
    jobs = Jobs()
    monkeypatch.setattr(jobs, "active", lambda: None)
    state = {"status": "Running", "starts": 0, "stops": 0}
    def profile(self):
        return {"Status": state["status"], "Config": {"CPUs": 8, "Memory": 8192}}
    def sh(*args, **kwargs):
        assert args[:2] == ("minikube", "stop")
        state.update(status="Stopped", stops=state["stops"] + 1)
        return ""
    def start(self):
        state.update(status="Running", starts=state["starts"] + 1)
        return {"cpus": 8, "memory_mb": 8192}
    monkeypatch.setattr(cluster.Cluster, "_profile", profile)
    monkeypatch.setattr(cluster.Cluster, "start", start)
    monkeypatch.setattr(cluster, "sh", sh)
    monkeypatch.setattr(cluster, "host", lambda: {"cpus": 16, "memory_mb": 32768})
    monkeypatch.setattr(cluster.Cluster, "delete", lambda self: pytest.fail("unexpected cluster deletion"))
    return ClusterControl(jobs), state


def finish(control):
    control.thread.join(timeout=3)
    assert not control.thread.is_alive()
    assert not control.snapshot()["error"]


def test_stop_is_persistent_and_start_reenables_queue(power):
    control, state = power
    control.request("stop")
    finish(control)
    assert state["status"] == "Stopped" and cluster.manually_stopped()
    assert ClusterControl(Jobs()).snapshot()["manual_off"]
    control.request("stop")
    finish(control)
    assert state["stops"] == 1
    control.request("start")
    finish(control)
    assert state["status"] == "Running" and not cluster.manually_stopped()
    assert cluster.holder() is None


def test_active_runner_blocks_stop_apply_and_saving(power):
    control, state = power
    with cluster.claim("active-experiment"):
        for action in ("stop", "idle-stop", "start", "apply", "save"):
            with pytest.raises(cluster.Busy):
                control.request(action, {"keep_cpus": 2})
    assert state["stops"] == 0 and not (config.SETTINGS / "host.yaml").exists()


def test_worker_before_claim_also_blocks_changes(power, monkeypatch):
    control, state = power
    monkeypatch.setattr(control.jobs, "active", lambda: object())
    with pytest.raises(cluster.Busy):
        control.request("stop")
    assert not state["stops"]


def test_idle_shutdown_waits_30_minutes_and_allows_automatic_wake(power):
    control, state = power
    assert idle_minutes() == 30
    control.idle_since = time.monotonic() - 1790
    control.idle()
    assert control.thread is None
    control.idle_since = time.monotonic() - 1801
    control.idle()
    finish(control)
    assert state["status"] == "Stopped" and not cluster.manually_stopped()
    # The queued worker uses this same shared path under its runner claim.
    with cluster.claim("new-job"):
        lifecycle.ensure_cluster(cluster.Cluster(config.Cluster(cpus=8, memory_mb=8192)))
    assert state["status"] == "Running"


def test_idle_never_stops_for_waiting_or_running_work(power, monkeypatch):
    control, state = power
    for busy in ("queued", "running"):
        control.idle_since = time.monotonic() - 4000
        if busy == "queued":
            monkeypatch.setattr(control.jobs, "queue", lambda: ["waiting"])
            control.idle()
        else:
            monkeypatch.setattr(control.jobs, "queue", lambda: [])
            with cluster.claim("running"):
                control.idle()
    assert control.thread is None and state["stops"] == 0


def test_idle_disabled_and_manual_stop_do_not_auto_start(power):
    control, state = power
    save_idle(0)
    control.idle_since = time.monotonic() - 99999
    control.idle()
    assert control.thread is None
    save_idle(1)
    cluster.set_manually_stopped(True)
    control.idle()
    assert control.thread is None and state["starts"] == 0
    for invalid in (-1, 10081):
        with pytest.raises(ValueError):
            save_idle(invalid)
    assert idle_minutes() == 1


def test_failed_start_is_visible_and_does_not_enable_queue(power, monkeypatch):
    control, state = power
    def fail(_):
        raise RuntimeError("Docker unavailable")
    monkeypatch.setattr(lifecycle, "ensure_cluster", fail)
    control.request("start")
    control.thread.join(timeout=3)
    assert "Docker unavailable" in control.snapshot()["error"]
    assert not control.busy and cluster.manually_stopped() and cluster.holder() is None


def test_apply_runs_in_background_and_keeps_http_available(client, monkeypatch):
    control = client.app.state.cluster_control
    entered, release = threading.Event(), threading.Event()
    def prepare(_):
        entered.set()
        assert release.wait(5)
        cluster.set_manually_stopped(False)
        return {"cpus": 8, "memory_mb": 8192}
    monkeypatch.setattr(lifecycle, "ensure_cluster", prepare)
    monkeypatch.setattr(cluster, "host", lambda: {"cpus": 16, "memory_mb": 32768})
    try:
        response = client.post("/settings/host", data={"action": "apply", "keep_cpus": "2", "keep_gb": "4"}, follow_redirects=False)
        assert response.status_code == 303 and entered.wait(2)
        assert config.host_settings()["keep_cpus"] == 2
        page = client.get("/settings").text
        assert "Applying changes…" in page and "The web interface stays online" in page
        assert client.get("/experiments").status_code == 200
        assert client.get("/partials/cluster").status_code == 200
        blocked = client.post("/settings/cluster", data={"action": "stop"}, follow_redirects=False)
        assert "error=" in blocked.headers["location"]
    finally:
        release.set()
        control.thread.join(timeout=3)


def test_web_controls_require_authentication_and_validate_actions(client):
    assert client.post("/settings/cluster", data={"action": "delete"}).status_code == 400
    response = client.post("/settings/cluster/idle", data={"minutes": "15"}, follow_redirects=False)
    assert response.status_code == 303 and idle_minutes() == 15
    client.cookies.clear()
    response = client.post("/settings/cluster", data={"action": "stop"}, follow_redirects=False)
    assert response.headers["location"] == "/login"


def test_idle_button_stops_cluster_and_keeps_automatic_wake(client, power):
    control = client.app.state.cluster_control
    _, state = power
    for _ in range(2):
        response = client.post("/settings/cluster", data={"action": "idle"}, follow_redirects=False)
        assert response.headers["location"] == "/settings#cluster"
        finish(control)
    assert state["status"] == "Stopped" and state["stops"] == 1
    assert not cluster.manually_stopped()
    page = client.get("/partials/cluster").text
    assert "Idle" in page and "New jobs wake the cluster." in page
    with cluster.claim("new-job"):
        lifecycle.ensure_cluster(cluster.Cluster(config.Cluster(cpus=8, memory_mb=8192)))
    assert state["status"] == "Running"


def test_idle_button_rejects_waiting_jobs(client, power):
    control = client.app.state.cluster_control
    _, state = power
    control.jobs._save(["waiting"])
    response = client.post("/settings/cluster", data={"action": "idle"}, follow_redirects=False)
    assert "error=" in response.headers["location"]
    assert state["stops"] == 0


def test_manual_off_keeps_queued_worker_from_spawning(power, monkeypatch):
    control, state = power
    control.jobs._save(["waiting"])
    cluster.set_manually_stopped(True)
    monkeypatch.setattr("lab.web.jobs.subprocess.Popen", lambda *a, **kw: pytest.fail("spawned while switched off"))
    control.jobs._step()
    assert control.jobs.queue() == ["waiting"]


def test_new_queued_job_launches_worker_after_idle_shutdown(power, monkeypatch, tmp_path):
    from types import SimpleNamespace

    control, state = power
    control.idle_since = time.monotonic() - 1801
    control.idle()
    finish(control)
    control.jobs._save(["new-job"])
    dataset = SimpleNamespace(status={"state": "queued"}, path=tmp_path)
    monkeypatch.setattr("lab.web.jobs.Dataset.find", lambda name: dataset)
    launched = []
    monkeypatch.setattr("lab.web.jobs.subprocess.Popen", lambda args, **kwargs: launched.append(args))
    control.jobs._step()
    assert launched[0][-2:] == ["resume", "new-job"]
    assert not cluster.manually_stopped()


def test_job_arriving_at_idle_deadline_prevents_shutdown(power):
    control, state = power
    control.jobs._save(["just-arrived"])
    with pytest.raises(cluster.Busy):
        control.request("idle-stop")
    assert state["status"] == "Running" and control.thread is None


def test_cli_runner_respects_persistent_manual_stop(power, monkeypatch):
    from lab import cli

    control, _ = power
    control.request("stop")
    finish(control)
    monkeypatch.setattr(cli.runner, "run", lambda *a: pytest.fail("ran while switched off"))
    dataset = type("Dataset", (), {"name": "waiting"})()
    assert cli._run(dataset) == cluster.BUSY
    assert cluster.holder() is None


def test_idle_indicator_normalizes_ok_and_shows_remaining_time(power, monkeypatch):
    control, state = power
    state["status"] = "OK"
    monkeypatch.setattr("lab.web.cluster_control.time.monotonic", lambda: 10000)
    control.idle_since = 9280
    shown = control.snapshot()
    assert shown["status"] == "Running"
    assert shown["idle_seconds"] == 720 and shown["stop_in_seconds"] == 1080
    save_idle(0)
    assert control.snapshot()["stop_in_seconds"] is None
    control.jobs._save(["waiting"])
    assert control.snapshot()["idle_seconds"] is None
    control.jobs._save([])
    monkeypatch.setattr(control.jobs, "active", lambda: object())
    assert control.snapshot()["idle_seconds"] is None


def test_stopped_cluster_does_not_show_idle_countdown(power):
    control, state = power
    state["status"] = "Stopped"
    shown = control.snapshot()
    assert shown["idle_seconds"] is None and shown["stop_in_seconds"] is None
