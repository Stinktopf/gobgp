"""How busy the host is, and how much of that is the lab.

The lab may share its host with others. Its own share is the CPU time of the
minikube container, which holds every pod; the rest of the busy time is
others. Where that container cannot be seen, e.g. under Docker Desktop, only
the whole host is known.
"""

import os
import shutil
import subprocess
import threading
import time
from collections import deque
from pathlib import Path

from .cluster import PROFILE

CGROUP = Path("/sys/fs/cgroup")
GPU_EVERY_S = 10
GPU_BUSY = 20  # percent utilization of a GPU that counts as in use by others, the lab uses none
HISTORY_S = 600  # what the web interface charts, one value a second


def cpu_times() -> tuple[float, float] | None:
    """Busy and total CPU time of the host so far, in seconds of all threads."""
    try:
        with open("/proc/stat") as f:
            values = [float(x) for x in f.readline().split()[1:]]
    except (OSError, ValueError):
        return None
    idle = values[3] + (values[4] if len(values) > 4 else 0)  # idle and iowait
    hz = os.sysconf("SC_CLK_TCK")
    return (sum(values) - idle) / hz, sum(values) / hz


def lab_cgroup() -> Path | None:
    """The cgroup of the minikube container, if this host runs it."""
    try:
        found = subprocess.run(["docker", "inspect", "-f", "{{.Id}} {{.State.Pid}}", PROFILE],
                               capture_output=True, text=True, timeout=5).stdout.split()
        container, pid = found if len(found) == 2 else ("", "")
        line = Path(f"/proc/{pid}/cgroup").read_text().splitlines()[0] if pid and pid != "0" else ""
    except (OSError, subprocess.SubprocessError):
        return None
    parts = line.split("::", 1)[1].strip("/").split("/") if "::" in line else []
    # The container's init process, systemd in minikube, sits in a child
    # such as init.scope; the pods sit beside it. Take the container's own.
    named = [i for i, part in enumerate(parts) if container and container in part]
    path = CGROUP.joinpath(*parts[:named[-1] + 1] if named else parts) if parts else None
    return path if path and (path / "cpu.stat").exists() else None


def lab_cpu_s(group: Path | None) -> float | None:
    """CPU time of the lab so far, in seconds."""
    try:
        stat = (group / "cpu.stat").read_text() if group else ""
    except OSError:
        return None
    usec = next((int(line.split()[1]) for line in stat.splitlines() if line.startswith("usage_usec")), None)
    return usec / 1e6 if usec is not None else None


def lab_memory_mb(group: Path | None) -> float | None:
    try:
        return int((group / "memory.current").read_text()) / 2**20 if group else None
    except (OSError, ValueError):
        return None


def memory_mb() -> tuple[float, float]:
    """Used and total memory of the host."""
    info = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            info[key] = int(value.split()[0]) / 1024
    except (OSError, ValueError):
        return 0.0, 0.0
    total = info.get("MemTotal", 0.0)
    return total - info.get("MemAvailable", total), total


def gpus() -> list[dict]:
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=name,utilization.gpu,memory.used,memory.total",
                              "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    rows = [[x.strip() for x in line.split(",")] for line in out.splitlines() if line.strip()]
    return [{"name": r[0], "util": float(r[1]), "memory_mb": float(r[2]), "total_mb": float(r[3])}
            for r in rows if len(r) == 4 and r[1].replace(".", "").isdigit()]


FREE_GB = 20  # images and results need this much room on disk


def docker_root() -> Path:
    try:
        root = subprocess.run(["docker", "info", "--format", "{{.DockerRootDir}}"], capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        root = ""
    return Path(root or "/var/lib/docker")


def low_disk(results: Path) -> str | None:
    """Why the disk is too full for the lab, or None: the room of Docker,
    which holds images and the cluster, and of the results."""
    for label, path in (("Docker", docker_root()), ("results", results)):
        while not path.exists() and path != path.parent:
            path = path.parent
        try:
            free = shutil.disk_usage(path).free / 2**30
        except OSError:
            continue  # not readable for this user: Docker reports a full disk itself
        if free < FREE_GB:
            return f"Only {free:.0f} GiB free for {label} at {path}. The lab needs {FREE_GB} GiB."
    return None


def low_inotify() -> str | None:
    """The inotify limits of the kernel, when below what many pods need."""
    try:
        instances, watches = (int(Path(f"/proc/sys/fs/inotify/{k}").read_text()) for k in ("max_user_instances", "max_user_watches"))
    except (OSError, ValueError):
        return None
    return f"{instances} instances, {watches} watches" if instances < 1024 or watches < 524288 else None


def gpu_busy(found: list[dict]) -> bool:
    return any(g["util"] >= GPU_BUSY for g in found)


def gpu_in_use(state: dict) -> bool | None:
    """Whether others use a GPU, from a state of Watch: None before the first
    reading, True as well when nvidia-smi exists but tells nothing."""
    if "gpus" not in state:
        return None
    return state.get("gpu_error", False) or gpu_busy(state["gpus"])


class Meter:
    """Shares of all threads of the host, busy in all and busy with the lab,
    over the interval since the last call of read()."""

    def __init__(self) -> None:
        self.group = lab_cgroup()
        self.found = time.monotonic()
        self.before = cpu_times()
        self.lab_before = lab_cpu_s(self.group)

    def read(self) -> dict:
        # The cluster may start or restart while the lab runs.
        if self.group is None or not (self.group / "cpu.stat").exists():
            if time.monotonic() - self.found > 10:
                self.group, self.found = lab_cgroup(), time.monotonic()
                self.lab_before = lab_cpu_s(self.group)
        after, lab_after = cpu_times(), lab_cpu_s(self.group)
        out = {"busy": None, "lab": None, "others": None}
        if self.before and after and after[1] > self.before[1]:
            total = after[1] - self.before[1]
            out["busy"] = (after[0] - self.before[0]) / total
            if self.lab_before is not None and lab_after is not None:
                out["lab"] = min(out["busy"], max(0.0, (lab_after - self.lab_before) / total))
                out["others"] = out["busy"] - out["lab"]
        self.before, self.lab_before = after, lab_after
        return out


class Watch(threading.Thread):
    """The host now, measured every second, for the web interface."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.state: dict = {}
        self.history: deque = deque(maxlen=HISTORY_S)
        self.gpu_at = 0.0

    def run(self) -> None:
        meter = Meter()
        while True:
            time.sleep(1.0)
            shares = meter.read()
            used, total = memory_mb()
            state = {**shares, "threads": os.cpu_count(), "load": os.getloadavg()[0], "memory_mb": used,
                     "total_mb": total, "lab_mb": lab_memory_mb(meter.group), "gpus": self.state.get("gpus", []),
                     "gpu_error": self.state.get("gpu_error", False)}
            if time.monotonic() - self.gpu_at > GPU_EVERY_S:
                state["gpus"], self.gpu_at = gpus(), time.monotonic()
                state["gpu_error"] = not state["gpus"] and shutil.which("nvidia-smi") is not None
            self.state = state
            self.history.append(state)


_watch: Watch | None = None
_lock = threading.Lock()


def _watching() -> Watch:
    global _watch
    with _lock:
        if _watch is None:
            _watch = Watch()
            _watch.start()
    return _watch


def now() -> dict:
    """The latest state of the host; empty until the first second passed."""
    return _watching().state


def series(points: int = 120) -> dict:
    """The last minutes as means over equal spans, for charts: the shares of
    the lab and of others, or where the lab cannot be seen of all, the
    memory in use, and the mean utilization of the GPUs, measured every
    GPU_EVERY_S, as a share."""
    rows = [r for r in list(_watching().history) if r.get("busy") is not None]
    span = max(1, -(-len(rows) // points))
    chunks = [rows[i:i + span] for i in range(0, len(rows), span)]
    mean = lambda chunk, key: sum(r[key] for r in chunk) / len(chunk)
    split = bool(rows) and all(r["lab"] is not None for r in rows)
    return {"seconds": len(rows), "split": split,
            "lab": [mean(c, "lab") for c in chunks] if split else [],
            "others": [mean(c, "others") for c in chunks] if split else [],
            "busy": [mean(c, "busy") for c in chunks],
            "memory_mb": [mean(c, "memory_mb") for c in chunks],
            "lab_mb": [mean(c, "lab_mb") for c in chunks] if rows and all(r.get("lab_mb") is not None for r in rows) else [],
            "gpu": [sum(sum(g["util"] for g in r["gpus"]) / len(r["gpus"]) for r in c) / len(c) / 100 for c in chunks]
            if rows and all(r.get("gpus") for r in rows) else []}


_docker: tuple[float, bool] = (-1e9, False)


def docker_running() -> bool:
    """Whether the Docker daemon answers, asked at most every 10 s. Its
    command can be there while it is not, e.g. Docker Desktop stopped
    under WSL. docker version asks the daemon in a fraction of a second,
    docker info takes seconds there."""
    global _docker
    if time.monotonic() - _docker[0] > 10:
        try:
            up = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, timeout=5).returncode == 0
        except (OSError, subprocess.SubprocessError):
            up = False
        _docker = (time.monotonic(), up)
    return _docker[1]
