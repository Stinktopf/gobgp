from types import SimpleNamespace

import pytest

from lab import uninstall


@pytest.fixture
def installation(tmp_path):
    root, settings, base = (tmp_path / name for name in ("repo", "settings", "installation"))
    for path in (root, settings, base / "bin"):
        path.mkdir(parents=True)
    return root, settings, base


def no_sudo(command):
    pytest.fail(f"unexpected privileged command: {command}")


def test_cleanup_only_removes_recorded_files_and_keeps_unrelated(installation):
    root, settings, base = installation
    tool = base / "bin/minikube"
    tool.write_text("installed binary")
    unrelated = base / "bin/unrelated"
    unrelated.write_text("keep")
    (settings / "host.yaml").write_text("configuration")
    (settings / "user-notes").write_text("keep")
    uninstall.record(base, f"file {tool}")
    uninstall.record(base, f"file {unrelated}")
    kept = uninstall.cleanup(root, settings, base, no_sudo)
    assert not tool.exists() and not (settings / "host.yaml").exists()
    assert unrelated.read_text() == "keep" and (settings / "user-notes").read_text() == "keep"
    assert kept


def test_modified_tool_and_inventory_are_kept(installation):
    root, settings, base = installation
    tool = base / "bin/uv"
    tool.write_text("original")
    uninstall.record(base, f"file {tool}")
    uninstall.record(base, f"sha256 {uninstall.digest(tool)} {tool}")
    tool.write_text("user replacement")
    kept = uninstall.cleanup(root, settings, base, no_sudo)
    assert kept and tool.read_text() == "user replacement"
    assert (base / "installed.txt").exists()


def test_cleanup_is_repeatable_and_never_removes_preexisting_environment(installation):
    root, settings, base = installation
    (root / ".venv").mkdir()
    for _ in range(2):
        assert uninstall.cleanup(root, settings, base, no_sudo) == []
    assert (root / ".venv").is_dir()


def test_other_checkout_blocks_cleanup(installation, tmp_path):
    root, _, base = installation
    other = tmp_path / "other/.venv"
    other.mkdir(parents=True)
    uninstall.record(base, f"dir {other}")
    with pytest.raises(RuntimeError, match="Another checkout"):
        uninstall.preflight(root, base)


def test_other_docker_containers_keep_host_changes(installation, monkeypatch):
    _, _, base = installation
    monkeypatch.setattr(uninstall.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(uninstall, "output", lambda _: "unrelated-container")
    kept = []
    uninstall.undo_host(["package docker.io 1.0", "inotify-before 128 65536"], base, no_sudo, kept)
    assert kept == ["host changes (other Docker containers exist)"]


def test_changed_packages_and_unrecorded_dependents_are_kept(monkeypatch):
    def run(command, **kwargs):
        return SimpleNamespace(returncode=0, stdout="install ok installed\n2.0\n")
    monkeypatch.setattr(uninstall.subprocess, "run", run)
    kept = []
    uninstall.remove_packages([("curl", "1.0")], no_sudo, kept)
    assert "changed since setup" in kept[0]
    monkeypatch.setattr(uninstall, "output", lambda _: "Remv curl [2.0]\nRemv unrelated [1.0]")
    kept = []
    uninstall.remove_packages([("curl", "2.0")], no_sudo, kept)
    assert "APT would change other packages" in kept[0]


def test_only_recorded_unchanged_packages_are_removed(monkeypatch):
    monkeypatch.setattr(uninstall.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout="install ok installed\n1.0\n"))
    monkeypatch.setattr(uninstall, "output", lambda _: "Purg curl [1.0]")
    commands, kept = [], []
    uninstall.remove_packages([("curl", "1.0")], commands.append, kept)
    assert commands == [["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "purge", "--no-auto-remove", "-y", "curl"]]
    assert not kept


def test_service_configuration_is_restored_only_when_unchanged(installation, monkeypatch):
    _, _, base = installation
    target = base / "service.conf"
    monkeypatch.setattr(uninstall, "SYSTEMD", target)
    target.write_text("original")
    uninstall.before_service_change(base)
    target.write_text("lab configuration")
    uninstall.record(base, f"sha256 {uninstall.digest(target)} {target}")
    commands, kept = [], []
    uninstall.undo_service(uninstall.inventory(base), base, commands.append, kept)
    assert commands[0] == ["cp", "--", str(base / "systemd.before"), str(target)]
    assert (base / "systemd.before").read_text() == "original"
    target.write_text("administrator changed it")
    uninstall.undo_service(uninstall.inventory(base), base, no_sudo, kept)
    assert "changed since setup" in kept[0]


def test_repeat_uninstall_after_environment_removal(tmp_path, monkeypatch):
    from pathlib import Path
    root = tmp_path / "repo"
    (root / "lab").mkdir(parents=True)
    private = root / "results/private"
    private.mkdir(parents=True)
    (private / "result").write_text("result")
    public = root / "results/public"
    public.mkdir()
    (public / "result").write_text("public")
    monkeypatch.setattr(uninstall, "__file__", str(root / "lab/uninstall.py"))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("MINIKUBE_HOME", str(tmp_path / "minikube"))
    monkeypatch.setattr(uninstall.sys, "argv", ["uninstall"])
    assert uninstall.main() == 0
    assert uninstall.main() == 0
    assert (private / "result").read_text() == "result"
    monkeypatch.setattr(uninstall.sys, "argv", ["uninstall", "--purge"])
    assert uninstall.main() == 0
    assert uninstall.main() == 0
    assert not private.exists() and (public / "result").read_text() == "public"


def test_symlink_tool_directory_blocks_cleanup(installation, tmp_path):
    root, _, base = installation
    (base / "bin").rmdir()
    (base / "bin").symlink_to(tmp_path)
    with pytest.raises(RuntimeError, match="symlink"):
        uninstall.preflight(root, base)
