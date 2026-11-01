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


def test_the_processes_of_the_lab_count_as_the_lab_others_not():
    import os
    import sys
    import time

    spin = "import time\nend = time.time() + 1.5\nwhile time.time() < end: pass\n"
    own = subprocess.Popen([sys.executable, "-c", spin], env={**os.environ, host.MARK: "1"})
    other = subprocess.Popen([sys.executable, "-c", spin], env={k: v for k, v in os.environ.items() if k != host.MARK})
    time.sleep(1)
    found = {pid for pid, _ in host.own_processes()}
    own.wait(), other.wait()
    assert own.pid in found and other.pid not in found


def test_without_a_cluster_the_lab_is_its_processes(monkeypatch):
    monkeypatch.setattr(host, "lab_cgroup", lambda: None)
    monkeypatch.setattr(host, "cluster_hidden", lambda: False)
    times = iter([(0, 100), (60, 200)])
    monkeypatch.setattr(host, "cpu_times", lambda: next(times))
    procs = iter([{(1, 1): (5.0, 100.0)}, {(1, 1): (25.0, 300.0), (2, 9): (10.0, 50.0)}])
    monkeypatch.setattr(host, "own_processes", lambda: next(procs))
    meter = host.Meter()
    shares = meter.read()
    assert shares["lab"] == 0.3 and abs(shares["others"] - 0.3) < 1e-9 and meter.lab_mb == 350.0
