import os
import subprocess
from pathlib import Path
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


def test_the_processes_of_the_lab_count_as_the_lab_others_not(monkeypatch):
    import sys
    import time

    spin = "import time\nend = time.time() + 1.5\nwhile time.time() < end: pass\n"
    own = subprocess.Popen([sys.executable, "-c", spin], env={**os.environ, host.MARK: "1"})
    other = subprocess.Popen([sys.executable, "-c", spin], env={k: v for k, v in os.environ.items() if k != host.MARK})
    time.sleep(1)
    monkeypatch.setattr(host, "_scanned", -host.SCAN_S)
    found = {pid for pid, _ in host.own_processes()}
    own.wait(), other.wait()
    assert own.pid in found and other.pid not in found


def test_between_scans_only_the_labs_processes_are_read(monkeypatch):
    monkeypatch.setattr(host, "_scanned", -host.SCAN_S)
    monkeypatch.setattr(host, "_marked", {})
    me = os.getpid()
    with open(f"/proc/{me}/environ", "rb") as f:
        marked = f"{host.MARK}=1".encode() in f.read().split(b"\0")
    host.own_processes()
    listed = []
    monkeypatch.setattr(host.os, "listdir", lambda path: listed.append(path) or [])
    found = host.own_processes()
    assert not listed  # no scan of /proc within SCAN_S
    assert (me in {pid for pid, _ in found}) == marked


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


def fake_sysfs(root, nodes, siblings=2, memory_kb=(16 * 2**20, 16 * 2**20)):
    """A host with these NUMA nodes, each a list of CPUs, hyperthreads paired by their position."""
    every = sorted(c for n in nodes for c in n)
    (root / "cpu").mkdir(parents=True)
    (root / "cpu" / "online").write_text(host.cpu_text(every))
    for i, cpus in enumerate(nodes):
        d = root / "node" / f"node{i}"
        d.mkdir(parents=True)
        (d / "cpulist").write_text(host.cpu_text(cpus))
        (d / "meminfo").write_text(f"Node {i} MemTotal:       {memory_kb[i]} kB\n")
        for k in range(0, len(cpus), siblings):
            pair = cpus[k:k + siblings]
            for c in pair:
                (root / "cpu" / f"cpu{c}" / "topology").mkdir(parents=True)
                (root / "cpu" / f"cpu{c}" / "topology" / "thread_siblings_list").write_text(host.cpu_text(pair))


def test_the_cluster_gets_whole_cores_of_one_node(tmp_path, monkeypatch):
    fake_sysfs(tmp_path, [list(range(0, 8)), list(range(8, 16))])
    monkeypatch.setattr(host, "SYSFS", tmp_path)
    assert host.cpu_list("0-2,5,7-8") == [0, 1, 2, 5, 7, 8] and host.cpu_text([8, 7, 5, 0, 1, 2]) == "0-2,5,7-8"
    # The highest node, whole cores, its memory too.
    assert host.pick_cores(4, 8192) == {"cpus": "12-15", "count": 4, "mems": "1", "node": 1, "memory_local": True}
    # An odd count takes one thread of the last core.
    assert host.pick_cores(3, 8192)["cpus"] == "13-15"
    # A node too small for the memory: its CPUs, the memory of all nodes.
    assert host.pick_cores(4, 64 * 1024)["mems"] == "0-1"
    # More CPUs than a node has: across nodes, always the same ones.
    across = host.pick_cores(12, 8192)
    assert across["count"] == 12 and across["node"] is None and across["cpus"] == "4-15" and host.pick_cores(12, 8192) == across


def test_what_others_run_on_the_clusters_cpus_is_told_apart(monkeypatch):
    # Bound to CPUs 4 and 5, the cluster used 1.5 s of their 2 s busy time: others 0.5 s of 4 s.
    cores = iter([(10.0, 20.0), (12.0, 24.0)])
    lab = iter([0.0, 1.5])
    monkeypatch.setattr(host, "cpu_times_of", lambda c: next(cores))
    monkeypatch.setattr(host, "cpu_times", lambda: (0.0, 1.0))
    monkeypatch.setattr(host, "lab_cgroup", lambda: Path("/"))
    monkeypatch.setattr(host, "lab_cpu_s", lambda group: next(lab))
    monkeypatch.setattr(host, "own_processes", dict)
    monkeypatch.setattr(host, "lab_memory_mb", lambda group: 0.0)
    out = host.Meter([4, 5]).read()
    assert out["cores_busy"] == 0.5 and out["others_cores"] == 0.125
