"""Lifecycle boundaries: repeatability, ownership, locks and retained user data."""

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
    monkeypatch.setattr(service, "discover", lambda: None)
    monkeypatch.setattr(service, "unit", lambda: {})
    monkeypatch.setattr(service, "start", lambda *a: state.update(web=True))
    monkeypatch.setattr(service, "stop", lambda *a: state.update(web=False))
    monkeypatch.setattr(lifecycle.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=1))
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
    monkeypatch.setattr(service, "unit", lambda: {})
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
    monkeypatch.setattr(service, "unit", lambda: {})
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
        return 'value := os.Getenv("GOBGP_OPERA_PRUNING")'
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
    monkeypatch.setattr(service, "unit", lambda: {})
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


@pytest.mark.parametrize("host,expected", [("0.0.0.0", "localhost"), ("::", "localhost"),
                                           ("lab.example", "lab.example"), ("2001:db8::1", "[2001:db8::1]")])
def test_web_url_is_a_browser_address(isolated, monkeypatch, capsys, host, expected):
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
