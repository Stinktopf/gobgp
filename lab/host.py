"""How busy the host is, and how much of that is the lab.

The lab may share its host with others. Its own share is the CPU time of the
minikube container, which holds every pod, and of every process the lab
started: the web server, runs, analysis, searches of the simulator and
their children, which carry MARK in their environment. The rest of the busy
time is others. Where the container runs but cannot be seen, e.g. under
Docker Desktop, only the whole host is known.
"""

import json
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
MINUTES_KEPT = 7 * 24 * 60  # one mean a minute for a week, kept in a file across restarts
WINDOWS = {"5m": 300, "1h": 3600, "24h": 86400, "7d": 604800}  # what the charts can show, in seconds
KEYS = ("busy", "lab", "others", "memory_mb", "lab_mb", "gpu")  # what a minute keeps


def history_file() -> Path:
    from .config import SETTINGS

    return SETTINGS / "host-history.jsonl"


def _gpu_share(row: dict) -> float | None:
    """The mean utilization of the GPUs of a second, as a share."""
    return sum(g["util"] for g in row["gpus"]) / len(row["gpus"]) / 100 if row.get("gpus") else None


PEAKS = ("busy", "lab", "memory_mb", "lab_mb", "gpu")  # what a minute keeps the lowest and highest second of


def _minute(rows: list[dict], t: int) -> dict | None:
    """The mean of the seconds of a minute, None for a value one second lacks,
    and the lowest and highest second, so that a peak shows also in a week."""
    rows = [{**r, "gpu": _gpu_share(r)} for r in rows if r.get("busy") is not None]
    if not rows:
        return None
    present = lambda key: [r[key] for r in rows if r.get(key) is not None]
    mean = lambda key: None if any(r.get(key) is None for r in rows) else sum(r[key] for r in rows) / len(rows)
    out = {"t": t, **{k: mean(k) for k in KEYS}}
    for k in PEAKS:
        if values := present(k):
            out[k + "_min"], out[k + "_max"] = min(values), max(values)
    return out


def _load_minutes() -> list[dict]:
    """The minutes of the last week from the file, which is cut to them."""
    path, since = history_file(), time.time() - MINUTES_KEPT * 60
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    rows = []
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("t", 0) >= since:
            rows.append(row)
    if len(rows) < len(lines) - 60:  # cut once more than an hour fell out
        try:
            tmp = path.with_suffix(".tmp")
            tmp.write_text("".join(json.dumps(r) + "\n" for r in rows))
            tmp.replace(path)
        except OSError:
            pass
    return rows[-MINUTES_KEPT:]


def _keep_minute(row: dict) -> None:
    try:
        history_file().parent.mkdir(parents=True, exist_ok=True)
        with open(history_file(), "a") as f:
            f.write(json.dumps(row) + "\n")
    except OSError:
        pass
MARK = "OBGP_LAB_OWN"  # in the environment of every process of the lab


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


def cpu_times_of(cores: list[int]) -> tuple[float, float] | None:
    """Busy and total CPU time of these CPUs so far, in seconds, from their lines of /proc/stat."""
    wanted, busy, total = {f"cpu{c}" for c in cores}, 0.0, 0.0
    try:
        with open("/proc/stat") as f:
            for line in f:
                name, *rest = line.split()
                if name in wanted:
                    values = [float(x) for x in rest]
                    idle = values[3] + (values[4] if len(values) > 4 else 0)
                    busy, total = busy + sum(values) - idle, total + sum(values)
    except (OSError, ValueError, IndexError):
        return None
    hz = os.sysconf("SC_CLK_TCK")
    return (busy / hz, total / hz) if total else None


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


def cluster_hidden() -> bool:
    """Whether the minikube container runs where its cgroup cannot be seen."""
    try:
        state = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", PROFILE],
                               capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    return state == "true" and lab_cgroup() is None


_marked: dict[tuple[int, int], bool] = {}
SCAN_S = 10.0  # all of /proc is read this often, the known processes of the lab every time
_scanned = -SCAN_S


def own_processes() -> dict[tuple[int, int], tuple[float, float]] | None:
    """The processes of the lab outside the cluster, by pid and start: CPU
    seconds so far and resident MiB. None where /proc cannot be read. A
    process started since the last scan counts from the next one, with all
    its time."""
    global _scanned
    scan = time.monotonic() - _scanned >= SCAN_S
    if scan:
        try:
            pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return None
        _scanned = time.monotonic()
    else:
        pids = [pid for (pid, _), own in _marked.items() if own]
    hz, page = os.sysconf("SC_CLK_TCK"), os.sysconf("SC_PAGE_SIZE")
    out, seen = {}, set()
    for pid in pids:
        try:
            with open(f"/proc/{pid}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            key = (pid, int(fields[19]))
        except (OSError, IndexError, ValueError):
            continue
        seen.add(key)
        if key not in _marked:  # an environment does not change: read once
            if not scan:  # the pid was taken by a new process: found at the next scan
                continue
            try:
                with open(f"/proc/{pid}/environ", "rb") as f:
                    _marked[key] = f"{MARK}=1".encode() in f.read().split(b"\0")
            except OSError:
                _marked[key] = False
        if _marked[key]:
            out[key] = ((int(fields[11]) + int(fields[12])) / hz, int(fields[21]) * page / 2**20)
    for key in set(_marked) - seen:
        if scan or _marked[key]:  # between scans only the lab's own are read
            del _marked[key]
    return out


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


def low_neigh() -> str | None:
    """The limit of the kernel's neighbour table, when below what the large topologies need."""
    from .cluster import NEIGH_LOW, neigh_table

    table = neigh_table()
    return f"{table[1]:,} entries" if table and table[1] < NEIGH_LOW else None


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

    def __init__(self, cores: list[int] | None = None) -> None:
        # The CPUs the cluster is bound to: what others do on them disturbs a measurement, elsewhere it does not.
        self.cores = cores
        self.cores_before = cpu_times_of(cores) if cores else None
        self.group = lab_cgroup()
        self.hidden = self.group is None and cluster_hidden()
        self.found = time.monotonic()
        self.before = cpu_times()
        self.lab_before = lab_cpu_s(self.group)
        self.procs = own_processes()
        self.lab_mb: float | None = None  # memory of the lab at the last read()

    def read(self) -> dict:
        # The cluster may start or restart while the lab runs.
        if self.group is None or not (self.group / "cpu.stat").exists():
            if time.monotonic() - self.found > 10:
                self.group, self.found = lab_cgroup(), time.monotonic()
                self.hidden = self.group is None and cluster_hidden()
                self.lab_before = lab_cpu_s(self.group)
        after, lab_after, procs = cpu_times(), lab_cpu_s(self.group), own_processes()
        # A process not seen before started since: all its time is new. One
        # that ended counts until the read before.
        own = (sum(cpu - self.procs.get(key, (0.0, 0.0))[0] for key, (cpu, _) in procs.items())
               if procs is not None and self.procs is not None else None)
        pods = (lab_after - self.lab_before if self.lab_before is not None and lab_after is not None
                else None if self.group is not None or self.hidden else 0.0)
        out = {"busy": None, "lab": None, "others": None}
        if self.before and after and after[1] > self.before[1]:
            total = after[1] - self.before[1]
            out["busy"] = (after[0] - self.before[0]) / total
            if pods is not None and own is not None:
                out["lab"] = min(out["busy"], max(0.0, (pods + own) / total))
                out["others"] = out["busy"] - out["lab"]
        if self.cores:
            cores_after = cpu_times_of(self.cores)
            if self.cores_before and cores_after and cores_after[1] > self.cores_before[1]:
                busy, total = cores_after[0] - self.cores_before[0], cores_after[1] - self.cores_before[1]
                out["cores_busy"] = busy / total
                if pods is not None:  # bound, the cluster runs on these CPUs only
                    out["others_cores"] = max(0.0, busy - pods) / total
            self.cores_before = cores_after
        pods_mb = lab_memory_mb(self.group)
        self.lab_mb = (None if procs is None or (pods_mb is None and (self.group is not None or self.hidden))
                       else (pods_mb or 0.0) + sum(mb for _, mb in procs.values()))
        self.before, self.lab_before, self.procs = after, lab_after, procs
        return out


class Watch(threading.Thread):
    """The host now, measured every second, for the web interface."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.state: dict = {}
        self.history: deque = deque(maxlen=HISTORY_S)
        self.minutes: deque = deque(_load_minutes(), maxlen=MINUTES_KEPT)
        self.this_minute: tuple[int, list[dict]] = (int(time.time() // 60), [])
        self.gpu_at = 0.0

    def run(self) -> None:
        meter = Meter()
        while True:
            time.sleep(1.0)
            shares = meter.read()
            used, total = memory_mb()
            state = {**shares, "threads": os.cpu_count(), "load": os.getloadavg()[0], "memory_mb": used,
                     "total_mb": total, "lab_mb": meter.lab_mb, "gpus": self.state.get("gpus", []),
                     "gpu_error": self.state.get("gpu_error", False)}
            if time.monotonic() - self.gpu_at > GPU_EVERY_S:
                state["gpus"], self.gpu_at = gpus(), time.monotonic()
                state["gpu_error"] = not state["gpus"] and shutil.which("nvidia-smi") is not None
            self.state = state
            self.history.append(state)
            minute, seconds = self.this_minute
            if (now_minute := int(time.time() // 60)) != minute:
                if (row := _minute(seconds, minute * 60)) is not None:
                    self.minutes.append(row)
                    _keep_minute(row)
                self.this_minute = (now_minute, [])
            self.this_minute[1].append(state)


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


def series(points: int = 120, window: str = "5m") -> dict:
    """The host over a window of WINDOWS as the highest second of equal
    spans, for charts: the share of the lab and above it of the rest, or
    where the lab cannot be seen of all, the memory in use, and the
    utilization of the GPUs, as a share, and the lowest and highest second
    of the window. 5m from the seconds, longer windows from the minutes,
    with None for a span without a minute, e.g. while the web server was down."""
    seconds = WINDOWS.get(window, WINDOWS["5m"])
    watch = _watching()
    if seconds <= HISTORY_S:
        rows = [{**r, "gpu": _gpu_share(r)} for r in list(watch.history)[-seconds:] if r.get("busy") is not None]
        span = max(1, -(-len(rows) // points))
        chunks = [rows[i:i + span] for i in range(0, len(rows), span)]
        seconds = len(rows)
    else:
        start, count = time.time() - seconds, min(points, seconds // 60)
        chunks = [[] for _ in range(count)]
        for r in list(watch.minutes):
            if (i := int((r["t"] - start) * count // seconds)) >= 0 and i < count:
                chunks[i].append(r)
        # The minute that runs, not kept yet, in the last span: the chart reaches now.
        minute, now = getattr(watch, "this_minute", (0, []))
        if (current := _minute(list(now), minute * 60)) is not None and count:
            chunks[-1].append(current)
    # Each span charts its highest second: a mean of minutes hides the peaks a host is watched for.
    # Minutes kept before they had their extremes count with their means.
    top = lambda r, key: r.get(key + "_max", r.get(key))
    low = lambda r, key: r.get(key + "_min", r.get(key))
    rows = [r for c in chunks for r in c]
    has = lambda key: bool(rows) and all(top(r, key) is not None for r in rows)
    peak = lambda c, key: max((v for r in c if (v := top(r, key)) is not None), default=None)
    series = lambda key: [peak(c, key) for c in chunks] if has(key) else []
    split = has("lab")
    busy, lab = series("busy"), series("lab") if split else []
    # The lab's peak, and above it the rest of the host's: the stack reaches the host's peak.
    others = [None if b is None or a is None else max(0.0, b - a) for b, a in zip(busy, lab)] if split else []
    tops = lambda key: [v for r in rows if (v := top(r, key)) is not None]
    lows = lambda key: [v for r in rows if (v := low(r, key)) is not None]
    extremes = {k: (min(lows(k)), max(tops(k))) for k in PEAKS if tops(k)}
    return {"seconds": seconds, "window": window if window in WINDOWS else "5m", "split": split,
            "lab": lab, "others": others, "busy": busy, "memory_mb": series("memory_mb"),
            "lab_mb": series("lab_mb"), "gpu": series("gpu"), "extremes": extremes}


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


def uptime_s() -> float:
    """Seconds since the host booted, a large number where it cannot be read."""
    try:
        return float(Path("/proc/uptime").read_text().split()[0])
    except (OSError, ValueError, IndexError):
        return 1e9


def shutting_down() -> bool:
    """Whether the host is shutting down or rebooting: then nothing starts again."""
    try:
        state = subprocess.run(["systemctl", "is-system-running"], capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    return state == "stopping"


def docker_up_s() -> float:
    """Seconds since the Docker service last started, a large number where
    systemd does not run it, e.g. Docker Desktop: it then counts as settled."""
    try:
        since = subprocess.run(["systemctl", "show", "docker", "--property=ActiveEnterTimestampMonotonic", "--value"],
                               capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return 1e9
    if not since.isdigit() or since == "0":
        return 1e9
    return max(0.0, uptime_s() - int(since) / 1e6)


SYSFS = Path("/sys/devices/system")


def cpu_list(text: str) -> list[int]:
    """The CPUs of a list as the kernel writes it, e.g. "0-3,8,10-11"."""
    out = []
    for part in text.strip().split(","):
        if part:
            a, _, b = part.partition("-")
            out += list(range(int(a), int(b or a) + 1))
    return out


def cpu_text(cpus: list[int]) -> str:
    """A list of CPUs as the kernel and Docker write it, ranges joined."""
    out, cpus = [], sorted(set(cpus))
    for c in cpus:
        if out and c == out[-1][1] + 1:
            out[-1][1] = c
        else:
            out.append([c, c])
    return ",".join(f"{a}-{b}" if a != b else str(a) for a, b in out)


def numa_nodes() -> list[dict]:
    """The NUMA nodes with their online CPUs and memory, one node with all
    CPUs and the host's memory where the kernel tells none, e.g. under WSL."""
    def read(path: Path) -> str:
        try:
            return path.read_text()
        except OSError:
            return ""
    online = set(cpu_list(read(SYSFS / "cpu" / "online"))) or set(range(os.cpu_count() or 1))
    nodes = []
    for d in sorted(SYSFS.glob("node/node[0-9]*"), key=lambda p: int(p.name[4:])):
        cpus = sorted(set(cpu_list(read(d / "cpulist"))) & online)
        mem = next((int(line.split()[-2]) // 1024 for line in read(d / "meminfo").splitlines() if "MemTotal" in line), 0)
        if cpus:
            nodes.append({"node": int(d.name[4:]), "cpus": cpus, "memory_mb": mem})
    return nodes or [{"node": None, "cpus": sorted(online), "memory_mb": memory_mb()[1]}]


def siblings(cpu: int) -> list[int]:
    """The hardware threads of the core of a CPU, the CPU alone where the kernel tells none."""
    try:
        return cpu_list((SYSFS / "cpu" / f"cpu{cpu}" / "topology" / "thread_siblings_list").read_text())
    except (OSError, ValueError):
        return [cpu]


def pick_cores(count: int, memory_mb: int) -> dict:
    """The CPUs the cluster runs on: count of them, whole cores first, on
    the highest NUMA node that has enough, its memory too where it holds the
    cluster's. Always the same on the same host, so that others know which
    CPUs the lab takes and runs meet the same CPUs. Across nodes where none
    has enough, the memory then of all of them."""
    nodes = numa_nodes()
    every = sorted({c for n in nodes for c in n["cpus"]})
    count = max(1, min(count, len(every)))
    one = next((n for n in reversed(nodes) if len(n["cpus"]) >= count), None)
    pool = one["cpus"] if one else every
    chosen: list[int] = []
    for cpu in sorted(pool, reverse=True):  # the highest cores, each with its siblings
        if cpu not in chosen:
            chosen += [s for s in sorted(siblings(cpu), reverse=True) if s in pool and s not in chosen][:count - len(chosen)]
        if len(chosen) >= count:
            break
    local = one is not None and one["node"] is not None and one["memory_mb"] >= memory_mb
    mems = str(one["node"]) if local else cpu_text([n["node"] for n in nodes if n["node"] is not None]) or None
    return {"cpus": cpu_text(chosen), "count": len(chosen), "mems": mems, "node": one["node"] if one else None, "memory_local": local}
