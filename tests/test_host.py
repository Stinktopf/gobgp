import subprocess
from types import SimpleNamespace

from lab import host

ID = "f543ba81d91a6e8824697169a5bac0083e6a1829c96bd742bb33b84c7584834c"


def test_the_lab_is_the_whole_minikube_container_not_its_init(tmp_path, monkeypatch):
    scope = tmp_path / "system.slice" / f"docker-{ID}.scope"
    (scope / "init.scope").mkdir(parents=True)
    for group in (scope, scope / "init.scope"):
        (group / "cpu.stat").write_text("usage_usec 1\n")
    proc = tmp_path / "proc"
    proc.mkdir()
    (proc / "cgroup").write_text(f"0::/system.slice/docker-{ID}.scope/init.scope\n")
    monkeypatch.setattr(host, "CGROUP", tmp_path)
    monkeypatch.setattr(host.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=f"{ID} 4242\n"))
    real = host.Path
    monkeypatch.setattr(host, "Path", lambda p: proc / "cgroup" if p == "/proc/4242/cgroup" else real(p))
    assert host.lab_cgroup() == scope


def test_no_minikube_container_means_no_lab_share(monkeypatch):
    def missing(*a, **k):
        raise subprocess.SubprocessError
    monkeypatch.setattr(host.subprocess, "run", missing)
    assert host.lab_cgroup() is None
