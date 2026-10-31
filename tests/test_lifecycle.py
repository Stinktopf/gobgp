"""Lifecycle boundaries: repeatability, ownership, locks and retained user data."""

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from lab import cluster, config, lifecycle, service, update
from lab.web import auth


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    settings = tmp_path / "config" / "obgp-lab"
    settings.mkdir(parents=True)
    root = tmp_path / "checkout"
    root.mkdir()
    monkeypatch.setattr(config, "ROOT", root)
    monkeypatch.setattr(config, "SETTINGS", settings)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(settings.parent))
    monkeypatch.setenv("MINIKUBE_HOME", str(tmp_path / "minikube"))
    monkeypatch.setattr(cluster, "host", lambda: {"cpus": 16, "memory_mb": 32768})
    from lab import results
    monkeypatch.setattr(results, "PRIVATE", tmp_path / "results" / "private")  # not the queue of a lab that runs meanwhile
    return settings


def test_first_setup_persists_budget_headroom_and_password_only_once(isolated, monkeypatch):
    answers = iter(["12", "24", "3", "5", "n"])
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    monkeypatch.setattr(lifecycle.getpass, "getpass", lambda prompt: "a good long password")
    args = lifecycle.parser().parse_args(["setup"])
    lifecycle.configure(args, True)
    saved = auth.file().read_bytes()
    assert cluster.keep() == (3, 5120)
    assert config.host_limit() == {"cpus": 12, "memory_mb": 24576}
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("prompted again"))
    monkeypatch.setattr(lifecycle.getpass, "getpass", lambda _: pytest.fail("password prompted again"))
    lifecycle.configure(args, True)
    assert auth.file().read_bytes() == saved
    assert cluster.keep() == (3, 5120)
    assert cluster.size_for([], cluster.capacity()).cpus == 9
    assert cluster.capacity() == {"cpus": 12, "memory_mb": 24576}


def test_unattended_laptop_setup_fits_and_never_prompts(isolated, monkeypatch):
    monkeypatch.setattr(cluster, "host", lambda: {"cpus": 4, "memory_mb": 6144})
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("prompt"))
    monkeypatch.setattr(lifecycle.getpass, "getpass", lambda _: pytest.fail("prompt"))
    lifecycle.configure(lifecycle.parser().parse_args(["setup"]), False)
    assert cluster.keep() == (2, 4096)
    assert auth.initial_file().stat().st_mode & 0o777 == 0o600
    initial = auth.initial_file().read_text().strip()
    assert auth.check_password(initial, auth.load())
    assert lifecycle.desired_cluster().resources.cpus == 2


def test_reconfiguration_merges_limits_and_preserves_auth(isolated):
    config.save_host({"cpus": 12, "keep_cpus": 3, "keep_mb": 2048, "routers_per_cpu": 2})
    auth.set_password("existing password")
    saved = auth.file().read_bytes()
    lifecycle.configure(lifecycle.parser().parse_args(["setup", "--memory-gb", "20"]), False)
    assert config.host_settings() == {"cpus": 12, "memory_mb": 20480, "keep_cpus": 3, "keep_mb": 2048, "routers_per_cpu": 2}
    assert auth.file().read_bytes() == saved


def test_active_experiment_blocks_every_lifecycle_mutation(isolated, monkeypatch):
    monkeypatch.setattr(service, "stop", lambda *a: pytest.fail("server stopped"))
    monkeypatch.setattr(update, "update", lambda **kw: pytest.fail("code updated"))
    with cluster.claim("experiment"):
        for action in ("setup", "reconfigure", "start", "stop", "teardown", "update", "uninstall"):
            assert lifecycle.main([action, "--non-interactive"]) == cluster.BUSY
    assert not (isolated / "host.yaml").exists()


@pytest.fixture
def fake_runtime(isolated, monkeypatch, tmp_path):
    from lab import results
    state = {"cluster": False, "web": False, "deletes": 0, "starts": 0}
    private = config.ROOT / "results/private"
    private.mkdir(parents=True)
    (private / "result.json").write_text("result")
    monkeypatch.setattr(results, "PRIVATE", private)
    def profile(self):
        return {"Config": {"CPUs": 12, "Memory": 14000}} if state["cluster"] else None
    def start(self):
        state["cluster"] = True
        state["starts"] += 1
        return {"cpus": 12, "memory_mb": 14000}
    def delete(self):
        state["cluster"] = False
        state["deletes"] += 1
    monkeypatch.setattr(cluster.Cluster, "_profile", profile)
    monkeypatch.setattr(cluster.Cluster, "start", start)
    monkeypatch.setattr(cluster.Cluster, "delete", delete)
    monkeypatch.setattr(cluster, "sh", lambda *a, **kw: "")
    monkeypatch.setattr(lifecycle, "preflight", lambda *a: state.update(preflight=state.get("preflight", 0) + 1))
    monkeypatch.setattr(service, "discover", lambda: None)
    monkeypatch.setattr(service, "unit", dict)
    monkeypatch.setattr(service, "start", lambda *a: state.update(web=True))
    monkeypatch.setattr(service, "stop", lambda *a: state.update(web=False))
    real = subprocess.run
    def run(command, *a, **kw):  # the test's own crontab still works
        return real(command, *a, **kw) if command[0] == os.environ["OBGP_CRONTAB"] else SimpleNamespace(returncode=1)
    monkeypatch.setattr(lifecycle.subprocess, "run", run)
    return state, private


def test_repeated_setup_start_stop_teardown_preserve_data(isolated, fake_runtime):
    state, private = fake_runtime
    for action in ("setup", "setup", "start", "start", "stop", "stop", "start", "teardown", "teardown"):
        assert lifecycle.main([action, "--non-interactive"]) == 0
        assert (private / "result.json").read_text() == "result"
        assert auth.file().exists()
    assert state["deletes"] == 1
    assert not state["web"] and not state["cluster"]
    assert lifecycle.main(["teardown", "--purge"]) == 0
    assert not private.exists() and auth.file().exists()
    assert lifecycle.main(["teardown", "--purge"]) == 0


@pytest.mark.parametrize("running,manual_off", [(True, False), (False, False), (False, True)])
def test_update_restarts_only_web_and_preserves_cluster(fake_runtime, monkeypatch, running, manual_off):
    state, _ = fake_runtime
    state.update(cluster=running, web=True)
    cluster.set_manually_stopped(manual_off)
    calls = []
    monkeypatch.setattr(update, "update", lambda **kw: calls.append(kw))
    monkeypatch.setattr(lifecycle, "ensure_cluster", lambda *a: pytest.fail("update touched cluster"))
    monkeypatch.setattr(service, "start", lambda options, interactive: calls.append(("web", options)))
    lifecycle.options_file().write_text('{"http": false, "host": "0.0.0.0", "port": 8443}')
    for _ in range(2):
        assert lifecycle.main(["update", "--non-interactive"]) == 0
        assert state["cluster"] == running
        assert cluster.manually_stopped() == manual_off
    assert calls == [{"sync": False, "allow_current": True},
                     ("web", {"http": False, "host": "0.0.0.0", "port": 8443})] * 2
    assert state["starts"] == state["deletes"] == 0


def test_only_incompatible_cluster_is_recreated(isolated, monkeypatch):
    c = cluster.Cluster(config.Cluster(cpus=2, memory_mb=4096))
    monkeypatch.setattr(c, "_profile", lambda: {"Config": {"CPUs": 2, "Memory": 4096}})
    deleted = []
    monkeypatch.setattr(c, "delete", lambda: deleted.append(True))
    def fail():
        raise cluster.LabError("network failure")
    monkeypatch.setattr(c, "start", fail)
    with pytest.raises(cluster.LabError):
        lifecycle.ensure_cluster(c)
    assert not deleted
    attempts = iter([cluster.Incompatible("old runtime"), {"cpus": 2}])
    def start():
        result = next(attempts)
        if isinstance(result, Exception):
            raise result
        return result
    monkeypatch.setattr(c, "start", start)
    assert lifecycle.ensure_cluster(c) == {"cpus": 2}
    assert deleted == [True]


def test_cluster_above_saved_budget_is_recreated(isolated, monkeypatch):
    c = cluster.Cluster(config.Cluster(cpus=2, memory_mb=4096))
    monkeypatch.setattr(c, "_profile", lambda: {"Config": {"CPUs": 16, "Memory": 32768}})
    calls = []
    monkeypatch.setattr(c, "delete", lambda: calls.append("delete"))
    monkeypatch.setattr(c, "start", lambda: calls.append("start"))
    lifecycle.ensure_cluster(c)
    assert calls == ["delete", "start"]


def test_other_users_container_is_never_deleted(isolated, monkeypatch):
    c = cluster.Cluster(config.Cluster())
    monkeypatch.setattr(c, "_profile", lambda: None)
    monkeypatch.setattr(lifecycle.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0))
    monkeypatch.setattr(c, "delete", lambda: pytest.fail("foreign container deleted"))
    with pytest.raises(RuntimeError, match="another user"):
        lifecycle.ensure_cluster(c)


def test_profile_errors_fail_closed(isolated, monkeypatch):
    c = cluster.Cluster(config.Cluster())
    for output in ("", '{"invalid": [{"Name": "obgp-lab"}]}'):
        monkeypatch.setattr(cluster.subprocess, "run", lambda *a, output=output, **kw: SimpleNamespace(returncode=1, stdout=output, stderr="failure"))
        with pytest.raises(cluster.LabError):
            c._profile()
    monkeypatch.setattr(cluster.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=1, stdout='{"valid": [], "invalid": []}', stderr=""))
    assert c._profile() is None


def test_stale_pid_never_signals_an_unrelated_process(isolated, monkeypatch):
    monkeypatch.setattr(service, "unit", dict)
    with subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], cwd=config.ROOT) as child:
        try:
            state = service.identity(child.pid)
            service.save({**state, "start": "old-process", "http": True, "port": 8443})
            service.stop()
            assert child.poll() is None
        finally:
            child.terminate()
            child.wait()


def test_legacy_server_is_adopted_and_stopped_without_pidfile(isolated, monkeypatch, tmp_path):
    monkeypatch.setattr(service, "unit", dict)
    entry = tmp_path / "lab"
    entry.write_text("import time; time.sleep(60)")
    with subprocess.Popen([sys.executable, str(entry), "serve", "--http", "--port", "8456"], cwd=config.ROOT) as child:
        try:
            state = service.discover()
            assert state["pid"] == child.pid and state["port"] == 8456 and state["http"]
            service.stop()
            child.wait(timeout=2)
            service.stop()  # already gone
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait()


def test_start_reuses_ready_server(isolated, monkeypatch):
    state = {"pid": os.getpid(), "http": True, "port": 8443, "host": "127.0.0.1"}
    monkeypatch.setattr(service, "discover", lambda: state)
    monkeypatch.setattr(service, "ready", lambda s: True)
    monkeypatch.setattr(service.subprocess, "Popen", lambda *a, **kw: pytest.fail("started duplicate server"))
    assert service.start({}) == state


@pytest.mark.parametrize("status", ["Running", "OK", "Stopped"])
def test_compatible_cluster_reused_without_recreation(isolated, monkeypatch, status):
    c = cluster.Cluster(config.Cluster(cpus=2, memory_mb=4096))
    profile = {"Status": status, "Config": {"CPUs": 4, "Memory": 8192, "Driver": "docker",
                                               "KubernetesConfig": {"ContainerRuntime": "docker"}}}
    monkeypatch.setattr(c, "_profile", lambda: profile)
    calls = []
    monkeypatch.setattr(cluster, "sh", lambda *a, **kw: calls.append(a))
    monkeypatch.setattr(c, "delete", lambda: pytest.fail("compatible cluster deleted"))
    assert lifecycle.ensure_cluster(c) == {"cpus": 4, "memory_mb": 8192}
    assert len(calls) == (status == "Stopped")
    if calls:
        assert "--cpus=4" in calls[0] and "--memory=8192" in calls[0]


def test_changed_command_invalidates_process_identity(isolated):
    state = service.identity(os.getpid())
    assert service.matches(state)
    assert not service.matches({**state, "command": ["unrelated", "program"]})


def test_squashed_daemon_capability_does_not_need_ancestry(monkeypatch):
    calls = []
    def git(*args):
        calls.append(args)
        if args[0] == "rev-parse":
            return "squashed-commit"
        return 'value := os.Getenv("GOBGP_OPERA_PRUNING")\nibgp := os.Getenv("GOBGP_OPERA_IBGP") == "filter"'
    monkeypatch.setattr(cluster, "git", git)
    experiment = config.Experiment.model_validate({"name": "x", "variants": [{"name": "a", "ref": "HEAD", "mode": "obgp-np"}],
                                                   "topologies": ["bad-gadget"], "scenarios": ["smoke-drain"]})
    cluster.check_modes(experiment)
    assert all(call[0] != "merge-base" for call in calls)


def test_real_web_process_start_reuse_stop_and_restart(isolated, monkeypatch, tmp_path):
    """Exercise detached process registration and HTTP readiness over real sockets."""
    helper = tmp_path / "web.py"
    helper.write_text('''
import argparse
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from lab import config, service
config.ROOT = Path.cwd()
p = argparse.ArgumentParser()
p.add_argument('--host')
p.add_argument('--port', type=int)
p.add_argument('--http', action='store_true')
args = p.parse_args()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
with service.register(args):
    HTTPServer((args.host, args.port), Handler).serve_forever()
''')
    original = subprocess.Popen
    children = []
    def launch(command, **kwargs):
        assert command[1:4] == ["-m", "lab.cli", "serve"]
        child = original([command[0], str(helper), *command[4:]],
                         env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}, **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(service, "unit", dict)
    monkeypatch.setattr(service.subprocess, "Popen", launch)
    try:
        first = service.start({})
        assert service.start({})["pid"] == first["pid"]
        assert len(children) == 1
        service.stop()
        service.stop()
        second = service.start({})
        assert second["pid"] != first["pid"]
        service.stop()
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)


def test_saved_web_options_configure_legacy_systemd_service(isolated, monkeypatch):
    from lab import uninstall
    monkeypatch.setattr(Path, "home", lambda: isolated.parent)
    monkeypatch.setattr(uninstall, "SYSTEMD", isolated / "systemd.conf")
    monkeypatch.setattr(service, "unit", lambda: {"MainPID": "0"})
    commands, content = [], []
    def privileged(command, interactive):
        assert not interactive
        commands.append(command)
        if command[:3] == ["install", "-m", "644"]:
            content.append(Path(command[3]).read_text())
            uninstall.SYSTEMD.write_text(content[-1])
    monkeypatch.setattr(service, "privileged", privileged)
    service.configure_unit({"http": True, "port": 8457}, False)
    assert '"--port" "8457" "--http"' in content[0]
    assert '"--host" "127.0.0.1"' in content[0]
    assert "ExecStart=\nExecStart=" in content[0]
    assert commands[-1] == ["systemctl", "daemon-reload"]


def test_interactive_budget_defaults_use_whole_host(isolated, monkeypatch):
    answers = iter(["", "all", "", "", ""])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    auth.set_password("existing password")
    lifecycle.configure(lifecycle.parser().parse_args(["setup"]), True)
    assert config.host_limit() == {}
    assert cluster.keep() == (4, 4096)


def test_explicit_budget_flags_skip_questions(isolated, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("prompted despite explicit flags"))
    auth.set_password("existing password")
    args = lifecycle.parser().parse_args(["setup", "--cpus", "8", "--memory-gb", "16",
                                         "--keep-cpus", "2", "--keep-memory-gb", "3", "--http"])
    lifecycle.configure(args, True)
    assert config.host_limit() == {"cpus": 8, "memory_mb": 16384}
    assert cluster.keep() == (2, 3072)


@pytest.mark.parametrize("answer", ["0", "17", "2.5"])
def test_invalid_interactive_cpu_budget_is_not_saved(isolated, monkeypatch, answer):
    monkeypatch.setattr("builtins.input", lambda _: answer)
    with pytest.raises(ValueError):
        lifecycle.configure(lifecycle.parser().parse_args(["setup"]), True)
    assert not (isolated / "host.yaml").exists()


def test_headroom_suggestions_fit_chosen_budget(isolated, monkeypatch):
    answers, prompts = iter(["4", "4", "", "", "n"]), []
    def answer(prompt):
        prompts.append(prompt)
        return next(answers)
    monkeypatch.setattr("builtins.input", answer)
    auth.set_password("existing password")
    lifecycle.configure(lifecycle.parser().parse_args(["setup"]), True)
    assert prompts[2].endswith("[2]: ") and prompts[3].endswith("[2]: ")
    assert cluster.keep() == (2, 2048)


@pytest.mark.parametrize("answer,http", [("yes", False), ("", True)])
def test_setup_asks_for_https_once_and_persists_choice(isolated, monkeypatch, answer, http):
    auth.set_password("existing password")
    args = lifecycle.parser().parse_args(["setup", "--cpus", "8", "--memory-gb", "16",
                                         "--keep-cpus", "2", "--keep-memory-gb", "3"])
    answers = iter(["invalid", answer])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert lifecycle.configure(args, True)["http"] is http
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("asked about HTTPS again"))
    assert lifecycle.configure(args, True)["http"] is http
    assert lifecycle.load_options()["http"] is http


@pytest.mark.parametrize("flags,http", [(["--https"], False), (["--http"], True),
                                        (["--host", "0.0.0.0"], False)])
def test_explicit_web_options_skip_https_prompt(isolated, monkeypatch, flags, http):
    auth.set_password("existing password")
    config.save_host({"keep_cpus": 4, "keep_mb": 4096})
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("prompted despite web flags"))
    args = lifecycle.parser().parse_args(["setup", *flags])
    assert lifecycle.configure(args, True)["http"] is http


def test_existing_setup_asks_about_https_after_upgrade(isolated, monkeypatch):
    auth.set_password("existing password")
    config.save_host({"cpus": 8, "keep_cpus": 2, "keep_mb": 4096})
    lifecycle.options_file().write_text('{"http": true, "port": 8443}')
    answers = iter(["yes"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    args = lifecycle.parser().parse_args(["setup"])
    assert lifecycle.configure(args, True)["http"] is False
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("prompt repeated"))
    assert lifecycle.configure(args, True)["http"] is False


def test_reconfigure_keeps_defaults_and_can_reset_forgotten_password(isolated, monkeypatch):
    auth.set_password("forgotten old password")
    config.save_host({"cpus": 8, "memory_mb": 16384, "keep_cpus": 2, "keep_mb": 4096})
    lifecycle.options_file().write_text('{"http": false, "port": 8450, "web_access_configured": true}')
    original = config.host_settings()
    answers = iter(["", "", "", "", "", "yes"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    monkeypatch.setattr(lifecycle.getpass, "getpass", lambda _: "replacement password")
    args = lifecycle.parser().parse_args(["reconfigure"])
    assert lifecycle.configure(args, True)["http"] is False
    assert config.host_settings() == original
    assert auth.check_password("replacement password", auth.load())
    assert not auth.check_password("forgotten old password", auth.load())
    saved = auth.file().read_bytes()
    answers = iter(["all", "all", "", "", "n", "n"])
    assert lifecycle.configure(args, True)["http"] is True
    assert config.host_limit() == {}
    assert auth.file().read_bytes() == saved


def test_noninteractive_reconfigure_resets_password_from_file(isolated, monkeypatch):
    auth.set_password("forgotten password")
    password = isolated / "replacement"
    password.write_text("new automated password")
    monkeypatch.setattr("builtins.input", lambda _: pytest.fail("noninteractive prompt"))
    monkeypatch.setattr(lifecycle.getpass, "getpass", lambda _: pytest.fail("password prompt"))
    args = lifecycle.parser().parse_args(["reconfigure", "--non-interactive", "--password-file", str(password)])
    lifecycle.configure(args, False)
    assert auth.check_password("new automated password", auth.load())


@pytest.mark.parametrize("host,expected", [("0.0.0.0", "198.51.100.7"), ("::", "198.51.100.7"),
                                           ("lab.example", "lab.example"), ("2001:db8::1", "[2001:db8::1]")])
def test_web_url_is_a_browser_address(isolated, monkeypatch, capsys, host, expected):
    class Probe:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def connect(self, _): pass
        def getsockname(self): return ("198.51.100.7", 0)
    monkeypatch.setattr(service.socket, "socket", lambda *_: Probe())
    state = {"http": False, "host": host, "port": 8446}
    monkeypatch.setattr(service, "discover", lambda: state)
    monkeypatch.setattr(service, "ready", lambda _: True)
    service.start({})
    assert f"Web interface: https://{expected}:8446" in capsys.readouterr().out


def test_uninstall_uses_teardown_and_preserves_repository_results(isolated, fake_runtime, monkeypatch):
    from lab import uninstall
    state, private = fake_runtime
    monkeypatch.setattr(Path, "home", lambda: isolated.parent.parent / "home")
    base = Path.home() / "obgp-lab"
    env = config.ROOT / ".venv"
    env.mkdir()
    (env / "owned").write_text("environment")
    (config.ROOT / "README.md").write_text("repository")
    uninstall.record(base, f"dir {env}")
    state.update(cluster=True, web=True)
    auth.set_password("existing password")
    assert lifecycle.main(["uninstall", "--non-interactive"]) == 0
    assert not state["cluster"] and not state["web"]
    assert not env.exists() and not isolated.exists() and not base.exists()
    assert (config.ROOT / "README.md").read_text() == "repository"
    assert (private / "result.json").read_text() == "result"
    assert not cluster.manually_stopped() and cluster.holder() is None


@pytest.fixture
def roomy(isolated, monkeypatch):
    """A host with room on disk, nobody else busy and no GPU."""
    monkeypatch.setattr(lifecycle.host, "docker_root", lambda: config.ROOT)
    monkeypatch.setattr(lifecycle.time, "sleep", lambda s: None)
    monkeypatch.setattr(lifecycle.host.shutil, "disk_usage", lambda p: SimpleNamespace(free=100 * 2**30))
    monkeypatch.setattr(service, "discover", lambda: None)
    monkeypatch.setattr(service, "unit", dict)
    monkeypatch.setattr(lifecycle.host.Meter, "read", lambda self: {"busy": 0.1, "lab": 0.0, "others": 0.1})
    monkeypatch.setattr(lifecycle.host, "memory_mb", lambda: (4096.0, 32768.0))
    monkeypatch.setattr(lifecycle.host, "gpus", list)
    monkeypatch.setattr(lifecycle.host, "low_inotify", lambda: None)
    return cluster.Cluster(config.Cluster(cpus=4, memory_mb=8192))


def test_preflight_stops_on_a_full_disk_before_anything_changes(roomy, monkeypatch):
    monkeypatch.setattr(lifecycle.host.shutil, "disk_usage", lambda p: SimpleNamespace(free=5 * 2**30))
    with pytest.raises(RuntimeError, match="Only 5 GiB free for Docker"):
        lifecycle.preflight({}, roomy)


def test_preflight_stops_on_a_fixed_port_held_by_another_process(roomy):
    import socket
    with socket.socket() as other:
        other.bind(("127.0.0.1", 0))
        other.listen()
        port = other.getsockname()[1]
        with pytest.raises(RuntimeError, match=f"Port {port} is in use"):
            lifecycle.preflight({"port": port, "http": True}, roomy)
        lifecycle.preflight({"http": True}, roomy)  # a free port is chosen then


def test_preflight_only_warns_about_load_and_a_busy_gpu(roomy, monkeypatch, capsys):
    monkeypatch.setattr(lifecycle.host.Meter, "read", lambda self: {"busy": 0.9, "lab": 0.0, "others": 0.9})
    monkeypatch.setattr(lifecycle.host, "memory_mb", lambda: (30000.0, 32768.0))
    monkeypatch.setattr(lifecycle.host, "gpus", lambda: [{"name": "g", "util": 80.0, "memory_mb": 1.0, "total_mb": 2.0}])
    monkeypatch.setattr(lifecycle.host, "low_inotify", lambda: "128 instances, 65536 watches")
    lifecycle.preflight({}, roomy)
    out = capsys.readouterr()
    text = out.out + out.err
    assert "Consider --cpus" in text and "smaller --memory-gb" in text and "Others use a GPU" in text and "128 instances" in text
    assert lifecycle.parser().parse_args(["setup", "--no-sudo"]).no_sudo


def test_the_watchdog_line_is_added_once_and_removed_alone(isolated, own_crontab):
    own_crontab.write_text("0 3 * * * backup # someone else's\n")
    assert service.install_watchdog() and service.install_watchdog()
    lines = own_crontab.read_text().splitlines()
    assert lines[0] == "0 3 * * * backup # someone else's" and len(lines) == 3
    assert lines[1].startswith("@reboot ") and lines[2].startswith("*/5 * * * * ") and "lifecycle.sh watch >> " in lines[1]
    service.remove_watchdog()
    assert own_crontab.read_text() == "0 3 * * * backup # someone else's\n"


@pytest.fixture
def watched(isolated, monkeypatch):
    """A lab that was set up, whose web server is not running."""
    started, told = [], []
    monkeypatch.setattr(service, "discover", lambda: None)
    monkeypatch.setattr(service, "servers", list)
    monkeypatch.setattr(service, "start", lambda settings, interactive=False: started.append(settings))
    monkeypatch.setattr("lab.notify.lab_restarted", lambda **kw: told.append(("restarted", kw)))
    monkeypatch.setattr("lab.notify.watchdog_gave_up", lambda reason, error: told.append(("gave up", reason)))
    boot = ["boot-1"]
    monkeypatch.setattr(service, "boot_id", lambda: boot[0])
    lifecycle.options_file().write_text('{"http": true}')
    return started, told, boot


def test_the_watchdog_starts_the_web_server_unless_stopped_on_purpose(watched, monkeypatch):
    started, told, _ = watched
    service.stopped_file().touch()
    assert lifecycle.main(["watch"]) == 0 and started == []
    service.stopped_file().unlink()
    assert lifecycle.main(["watch"]) == 0 and started == [{"http": True}] and told[0][1]["reboot"] is False
    monkeypatch.setattr(service, "discover", lambda: {"pid": 1})
    monkeypatch.setattr(service, "ready", lambda state: True)
    assert lifecycle.main(["watch"]) == 0 and len(started) == 1  # running: nothing to do


def test_the_watchdog_leaves_a_web_server_of_another_checkout_alone(watched, monkeypatch, capsys):
    started, told, _ = watched
    monkeypatch.setattr(service, "servers", lambda: [{"pid": 1, "root": "/elsewhere/gobgp"}])
    assert lifecycle.main(["watch"]) == 0 and started == [] and told == []
    assert "/elsewhere/gobgp" in capsys.readouterr().out
    def foreign():
        raise RuntimeError("The web server belongs to another checkout: /elsewhere/gobgp")
    monkeypatch.setattr(service, "discover", foreign)
    assert lifecycle.main(["watch"]) == 0 and started == [] and told == []
    assert json.loads(service.history_file().read_text())["restarts"] == []


def test_the_watchdog_waits_for_a_busy_web_server(watched, monkeypatch):
    started, told, _ = watched
    answers = iter([False, False, True])
    monkeypatch.setattr(service, "discover", lambda: {"pid": 1})
    monkeypatch.setattr(service, "matches", lambda state: True)
    monkeypatch.setattr(service, "ready", lambda state: next(answers))
    monkeypatch.setattr(service.time, "sleep", lambda s: None)
    assert lifecycle.main(["watch"]) == 0 and started == [] and told == []


def test_a_start_that_reuses_the_server_is_no_restart(watched, monkeypatch):
    _, told, _ = watched
    monkeypatch.setattr(service, "BUSY_WAIT", 0)
    monkeypatch.setattr(service, "discover", lambda: {"pid": 1})
    monkeypatch.setattr(service, "ready", lambda state: False)
    monkeypatch.setattr(service, "start", lambda settings, interactive=False: {"pid": 1})
    assert lifecycle.main(["watch"]) == 0 and told == []
    assert json.loads(service.history_file().read_text())["restarts"] == []


def test_the_watchdog_gives_up_after_three_restarts_in_an_hour(watched):
    started, told, boot = watched
    lifecycle.main(["watch"])  # a crash
    boot[0] = "boot-2"
    lifecycle.main(["watch"])  # a reboot counts as well
    assert told[-1][1]["reboot"] and told[-1][1]["waiting"] == []
    lifecycle.main(["watch"])
    lifecycle.main(["watch"])
    lifecycle.main(["watch"])
    assert len(started) == service.RESTARTS_PER_HOUR and told[-1][0] == "gave up" and "gave up" in told[-1][1]
    assert service.stopped_file().exists()


def test_discord_says_how_to_start_the_lab_again(monkeypatch):
    from lab import notify

    sent = []
    monkeypatch.setattr(notify, "send", lambda embed, mention=False: sent.append(embed["description"]))
    notify.watchdog_gave_up("The web server had ended, the lab started 3 times within the last hour already. The watchdog gave up.", "boom")
    notify.lab_restarted(reboot=True, waiting=["t-a"])
    assert "scripts/start.sh" in sent[0] and "resumes t-a" in sent[1]


def test_stop_keeps_the_web_server_off_until_start(fake_runtime, own_crontab):
    assert lifecycle.main(["start", "--non-interactive"]) == 0
    assert "obgp-lab watchdog" in own_crontab.read_text() and not service.stopped_file().exists()
    assert lifecycle.main(["stop", "--non-interactive"]) == 0
    assert service.stopped_file().exists()
    assert lifecycle.main(["start", "--non-interactive"]) == 0
    assert not service.stopped_file().exists()


def test_logs_that_grow_for_months_keep_one_before(isolated, monkeypatch):
    monkeypatch.setattr(service, "LOG_LIMIT", 10)
    log = config.SETTINGS / "watch.log"
    log.write_text("x" * 5)
    service.rotate(log)
    assert log.read_text() == "x" * 5
    log.write_text("y" * 20)
    service.rotate(log)
    assert not log.exists() and (config.SETTINGS / "watch.log.1").read_text() == "y" * 20


def test_the_cli_runs_as_the_lab_starts_it():
    """python -m lab.cli, as the web server, the watchdog and the queue run it, not the uv entry point."""
    done = subprocess.run([sys.executable, "-m", "lab.cli", "simulate", "--help"], cwd=config.ROOT, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


@pytest.mark.parametrize("http", [True, False])
def test_the_web_server_gives_open_connections_a_limit_on_stop(isolated, monkeypatch, http):
    """Open browser tabs kept uvicorn waiting forever on SIGTERM, so stop.sh gave up."""
    import uvicorn

    from lab import cli
    from lab.web import app

    runs = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: runs.append(kw))
    monkeypatch.setattr(app, "create_app", lambda: None)
    (config.SETTINGS / "tls.crt").parent.mkdir(parents=True, exist_ok=True)
    (config.SETTINGS / "tls.crt").touch()
    cli._serve(SimpleNamespace(http=http, host="127.0.0.1", port=8443))
    assert 0 < runs[0]["timeout_graceful_shutdown"] < 30
