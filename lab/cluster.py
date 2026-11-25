"""The minikube cluster, router images and Helm deployments."""

import ctypes
import fcntl
import functools
import hashlib
import json
import logging
import os
import platform
import re
import select
import signal
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter

from . import config
from .config import ROOT

PROFILE = "obgp-lab"
NAMESPACE = "lab"
RELEASE = "lab"
IMAGE = "obgp-lab/router"
CHART = ROOT / "gobgp-lab"
# Sources gobgpd is built from; everything else of a ref is irrelevant.
DAEMON_SOURCES = ["go.mod", "go.sum", "api", "cmd", "internal", "pkg", "proto"]
# Files of this tree that go into the image besides the daemon.
IMAGE_SOURCES = ["Dockerfile", "pyproject.toml", "uv.lock", "controller/app.py"]
BATCH = 32  # routers per Helm call of a larger topology
PROGRESS_S = 30  # between the log lines of a deploy
TELL_S = 5  # between the looks at the pods while the controllers are told their neighbors
GUARD_S = 5  # between the looks at the node's connection tracking during a deploy
API_SILENT_S = 180  # a Kubernetes API that does not answer this long ends a deploy
CONNTRACK_SHARE = 0.6  # a node's connection tracking fuller than this ends a deploy: when full, the host drops packets
WAVE = 16  # routers told their neighbors at a time, a wave every TELL_S: not all sessions of a large topology in one second
DIAGNOSE_S = 30  # between two looks at the node during a deploy, see Cluster.diagnose
SYSTEM_WEIGHT = 10000  # CPU weight of the node's own services against its pods, the highest cgroups know

log = logging.getLogger("lab")


class Incompatible(RuntimeError):
    """An existing profile must be recreated before it can serve this request."""


NOT_READY = "Kubernetes is not ready"  # what trouble() says when the container runs but its API does not answer


class LabError(RuntimeError):
    """An infrastructure failure. The affected run can be retried."""


class HostLimit(LabError):
    """The cluster reached a limit of the shared host: the Kubernetes API
    stopped answering, the node's connection tracking ran full, the kernel's
    neighbour table is too small for the topology, or the cluster was lost twice. The result ends as failed instead of being
    played again, which would hit the limit again."""


# The kernel keeps one neighbour (ARP) table for all containers of the host. Each router holds an entry for
# every BGP neighbour. When the table is full, the kernel drops packets, even those of the node's own
# Kubernetes API on 127.0.0.1. Setup raises its limits to NEIGH_WANT (gc_thresh1, 2, 3), never lowering one.
NEIGH = Path("/proc/sys/net/ipv4/neigh/default")
NEIGH_STAT = Path("/proc/net/stat/arp_cache")
NEIGH_WANT = (8192, 32768, 65536)
NEIGH_LOW = 16384  # a gc_thresh3 below this is low for the large topologies
NEIGH_SPARE = 0.1  # of gc_thresh3, kept free for the host's other containers


def neigh_table() -> tuple[int, int] | None:
    """Entries of the host's neighbour table now and its limit gc_thresh3, None when unreadable."""
    try:
        limit = int((NEIGH / "gc_thresh3").read_text())
        entries = int(NEIGH_STAT.read_text().splitlines()[1].split()[0], 16)
    except (OSError, ValueError, IndexError):
        return None
    return entries, limit


def neigh_need(topology: dict) -> int:
    """Entries a topology adds to the neighbour table: one per BGP neighbour of each router, one per router on the node."""
    return sum(len(cfg.get("neighbors") or []) + 1 for cfg in topology["routers"].values())


def check_neigh(name: str, topology: dict) -> None:
    """Raises HostLimit before a deploy that would fill the host's neighbour table."""
    if (table := neigh_table()) is None:
        return
    entries, limit = table
    need = neigh_need(topology)
    if entries + need > limit * (1 - NEIGH_SPARE):
        raise HostLimit(f"{name} needs about {need:,} entries in the kernel's neighbour table, which holds {limit:,} "
                        f"with {entries:,} in use: run setup again or raise net.ipv4.neigh.default.gc_thresh3, see docs/setup.md")


# What the node shows of its load, read through Docker, which answers when the Kubernetes API does not.
# Lines that fail print nothing: the node may have cgroups v1, or no such container yet.
NODE_LOOK = r"""
date -u +%FT%TZ; echo; cat /proc/loadavg; echo threads $(ps -eL --no-headers 2>/dev/null | wc -l)
for f in cpu memory io; do echo "node $f: $(tr '\n' ' ' < /sys/fs/cgroup/$f.pressure 2>/dev/null)"; done
for s in kubepods.slice system.slice; do
  echo; echo "$s weight $(cat /sys/fs/cgroup/$s/cpu.weight 2>/dev/null)"; cat /sys/fs/cgroup/$s/cpu.pressure /sys/fs/cgroup/$s/cpu.stat 2>/dev/null
done
echo; echo "conntrack $(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null) of $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
set -- $(sed -n 2p /proc/net/stat/arp_cache 2>/dev/null)
[ -n "$1" ] && echo "neighbour table $((0x$1)) of $(cat /proc/sys/net/ipv4/neigh/default/gc_thresh3 2>/dev/null), full $((0x${13})) times"
ss -s 2>/dev/null | head -3
echo; docker ps -a --filter name=k8s_kube-apiserver --filter name=k8s_etcd --format '{{.Names}} {{.Status}}' 2>/dev/null
echo; ps -eo pid,nlwp,pcpu,rss,comm --sort=-pcpu 2>/dev/null | head -25
"""
# Once the API was lost, also the logs of the API server, etcd and kubelet.
NODE_LOST = r"""
for c in kube-apiserver etcd; do
  id=$(docker ps -aq --filter name=k8s_$c | head -1); echo; echo "== $c"; [ -n "$id" ] && docker logs --tail 150 $id 2>&1
done
echo; echo "== etcd disk"; curl -s --max-time 5 http://127.0.0.1:2381/metrics 2>/dev/null | grep -E '^etcd_disk_(wal_fsync|backend_commit)_duration_seconds_(sum|count)'
echo; echo "== kubelet"; journalctl -u kubelet --since -5min --no-pager 2>/dev/null | tail -200
"""


# One result at a time on the cluster: a second runner would deploy into
# the same namespace. The lock file names the result holding it and the
# pid of its runner. It lies with the state of minikube, as the cluster
# does, so that every lab of the user sees it, whatever its settings.
def lock_file() -> Path:
    home = Path(os.environ["MINIKUBE_HOME"]) if os.environ.get("MINIKUBE_HOME") else Path.home() / ".minikube"
    return home / f"{PROFILE}.lab.lock"


def manually_stopped() -> bool:
    return lock_file().with_suffix(".off").exists()


def set_manually_stopped(stopped: bool) -> None:
    """Called under the cluster claim. Survives web restarts and is shared by checkouts."""
    file = lock_file().with_suffix(".off")
    if stopped:
        file.parent.mkdir(parents=True, exist_ok=True)
        file.touch()
    else:
        file.unlink(missing_ok=True)


class Busy(RuntimeError):
    pass


BUSY = 75  # the exit code then (EX_TEMPFAIL): the queue tries again later


def claim(result: str):
    """Takes the cluster for a result until the returned file is closed; Busy if another holds it."""
    lock_file().parent.mkdir(parents=True, exist_ok=True)
    f = open(lock_file(), "a+")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        f.close()
        running = holder()
        raise Busy("Another cluster operation is running." if running == "__maintenance__"
                   else f"the cluster runs {running or 'another result'}") from None
    f.truncate(0)
    f.write(f"{result} {os.getpid()}")
    f.flush()
    return f


def holding() -> tuple[str, int] | None:
    """The result running on the cluster and the pid of its runner, if any."""
    try:
        with open(lock_file()) as f:
            try:
                fcntl.flock(f, fcntl.LOCK_SH | fcntl.LOCK_NB)
                return None
            except BlockingIOError:
                name, _, pid = f.read().strip().partition(" ")
                return (name, int(pid)) if name and pid.isdigit() else None
    except FileNotFoundError:
        return None


def holder() -> str | None:
    """The result running on the cluster, if any."""
    return (holding() or (None,))[0]


class Interrupted(Exception):
    """A command ended early because the result was stopped; not retried."""


# Set by the runner when its result is stopped; long commands end then.
STOP = threading.Event()


def sh(*args: str, env: dict | None = None, timeout: float | None = None, interruptible: bool = False,
       abort: threading.Event | None = None) -> str:
    """Runs a command; LabError when it fails, takes longer than timeout or
    abort is set. A long one is interruptible: it ends with Interrupted when
    STOP is set; cleaning up never is."""
    deadline = time.monotonic() + timeout if timeout else None
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env) as process:
        while True:
            try:
                stdout, stderr = process.communicate(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                late = deadline is not None and time.monotonic() > deadline
                stopped = interruptible and STOP.is_set()
                aborted = abort is not None and abort.is_set()
                if stopped or late or aborted:
                    _end(process)
                    if stopped:
                        raise Interrupted(f"{' '.join(args[:2])} stopped") from None
                    if aborted:
                        raise LabError(f"{' '.join(args[:3])} aborted") from None
                    raise LabError(f"{' '.join(args[:3])} took longer than {timeout:.0f} s") from None
    result = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    if result.returncode != 0:
        raise LabError(f"{' '.join(args[:3])} failed: {(result.stderr or result.stdout).strip()[-2000:]}")
    return result.stdout


def git(*args: str) -> str:
    return sh("git", "-C", str(ROOT), *args).strip()


def resolve(ref: str) -> str:
    """Returns the commit a git ref points to."""
    try:
        return git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    except LabError:
        raise LabError(f"unknown git ref {ref}. A tag or branch of GitHub needs git fetch --tags first.") from None


def keep() -> tuple[int, int]:
    """Threads and MB the host keeps for Docker, Kubernetes and the system, from the settings."""
    s = config.host_settings()
    return s["keep_cpus"], s["keep_mb"]


MIN_CPUS, MIN_MB = 2, 2048  # the least minikube starts with


def free(have: dict | None = None) -> tuple[int, int]:
    """The CPUs and MiB the lab may use beside what the host keeps."""
    have, (keep_cpus, keep_mb) = have or capacity(), keep()
    return have["cpus"] - keep_cpus, have["memory_mb"] - keep_mb


def _room(have: dict | None = None) -> tuple[int, int]:
    """What minikube may get here: free, or ValueError where that is less than minikube needs."""
    cpus, memory = free(have)
    if cpus < MIN_CPUS or memory < MIN_MB:
        raise ValueError(f"The host keeps too much for minikube, which needs {MIN_CPUS} CPUs and {MIN_MB} MiB beside it. "
                         "Run scripts/reconfigure.sh with smaller reserves.")
    return cpus, memory


def _clamp(want: config.Cluster, room: tuple[int, int]) -> config.Cluster:
    """What is asked for, as far as the room allows, at least what minikube needs."""
    return want.model_copy(update={"cpus": max(MIN_CPUS, min(want.cpus, room[0])),
                                   "memory_mb": max(MIN_MB, min(want.memory_mb, room[1]))})


@dataclass(frozen=True)
class Fit:
    """How an experiment runs on this host: the cluster it gets, None where the
    host keeps too much (problem tells why), the routers its CPUs keep sampling,
    the memory its topologies may use, and each topology left out with its reasons."""

    cluster: config.Cluster | None
    routers: int
    memory_mb: int
    skipped: dict[str, list[str]]
    topologies: int
    problem: str | None = None

    @property
    def too_large(self) -> str | None:
        """Why no topology fits, or None."""
        if self.skipped and len(self.skipped) == self.topologies:
            return "; ".join(f"{t}: {', '.join(why)}" for t, why in self.skipped.items())
        return None

    @property
    def limit(self) -> str:
        """What this host gives a topology, to read next to skipped."""
        return f"at most {self.routers} routers, {self.memory_mb / 1024:,.0f} GiB"


def fit(experiment: config.Experiment) -> Fit:
    """The one rule of how an experiment runs here. Its cluster gets what it asks
    for, as far as the host has it. A topology is left out with every reason:
    more routers than the CPUs its cluster is bound to keep sampling, more memory
    than the lab may use, less than the experiment's memory_min_mb."""
    from . import topology

    have = capacity()
    try:
        got, problem = _clamp(experiment.cluster, _room(have)), None
    except ValueError as error:
        got, problem = None, str(error)
    routers = (got.cpus if got else 0) * config.host_settings()["routers_per_cpu"]
    spare = free(have)[1]
    usable, least = min(experiment.cluster.memory_mb, spare), experiment.cluster.memory_min_mb
    skipped = {}
    for t in experiment.topologies:
        nodes, why = topology.load(t, shared=True)["routers"], []
        if least and spare < least:  # the experiment asks for at least this much, whatever the topology
            why.append(f"at least {least / 1024:,.0f} GiB for the cluster")
        if not got:
            why.append("too few CPUs beside what the host keeps")
        elif len(nodes) > routers:
            why.append(f"{len(nodes)} routers")
        if (need := memory_need(experiment, nodes)) > usable:
            why.append(f"about {need / 1024:,.0f} GiB")
        if why:
            skipped[t] = why
    return Fit(got, routers, usable, skipped, len(experiment.topologies), problem)


def fit_all(experiments: list[config.Experiment]) -> config.Cluster:
    """The cluster to start: as large as the largest of the experiments asks, as far
    as the host allows. A larger profile serves every experiment that needs less."""
    want = config.Cluster(cpus=max((e.cluster.cpus for e in experiments), default=config.Cluster().cpus),
                          memory_mb=max((e.cluster.memory_mb for e in experiments), default=config.Cluster().memory_mb))
    return _clamp(want, _room())


def check_modes(experiment: config.Experiment) -> None:
    """Checks that every git ref exists and that its daemon knows the modes of
    its variant; ValueError if not. An older daemon would ignore the variables
    of a mode and silently run another one."""
    from . import modes

    for v in experiment.variants:
        try:
            commit = resolve(v.ref)
        except LabError as problem:
            raise ValueError(f"{v.name}: {problem}") from None
        for m in modes.get(v.mode).pure:
            mode = modes.get(m)
            # Inspect the actual tree, so rebases, shallow clones and cherry-picks
            # work. An ancestry hash does not establish a daemon's capabilities.
            for need in mode.requires:
                variable, _, value = need.partition("=")
                source = git("show", f"{commit}:internal/pkg/table/opera.go")
                if not re.search(r'os\.Getenv\(\s*"' + re.escape(variable) + r'"\s*\)', source) or value and f'"{value}"' not in source:
                    raise ValueError(f"{v.name}: the daemon at {v.ref} does not know {mode.label} yet. "
                                     f"It must read {need}.")
        if v.per_neighbor and "GOBGP_OPERA_EXPORT" not in git("show", f"{commit}:internal/pkg/table/opera.go"):
            raise ValueError(f"{v.name}: the daemon at {v.ref} has no tables per neighbor yet. It must read GOBGP_OPERA_EXPORT.")
        if v.per_neighbor and v.mode == "bgp" and "NS-BGP" not in git("show", f"{commit}:internal/pkg/table/opera_neighbor.go"):
            raise ValueError(f"{v.name}: the daemon at {v.ref} has no NS-BGP yet, BGP with tables per neighbor.")
        if v.refresh_delay and "GOBGP_OPERA_REFRESH_DELAY_S" not in git("show", f"{commit}:internal/pkg/table/opera.go"):
            raise ValueError(f"{v.name}: the daemon at {v.ref} does not delay route refreshes yet. It must read GOBGP_OPERA_REFRESH_DELAY_S.")
        if experiment.bgp.mrai and not git("ls-tree", commit, "--", "pkg/server/mrai.go"):
            raise ValueError(f"{v.name}: the daemon at {v.ref} does not hold back advertisements yet, it would ignore the MRAI.")


DEFAULT_PODS, SYSTEM_PODS = 110, 30


class Cluster:
    def __init__(self, resources: config.Cluster) -> None:
        self.resources = resources

    def start(self) -> dict:
        """Starts the minikube profile, creating it with the configured
        resources, and returns the resources it has. A larger profile serves
        every experiment that needs less, so experiments of different sizes
        share one cluster; the result records what it ran on."""
        profile = self._profile()
        if profile:
            cfg = profile["Config"]
            have = {"cpus": cfg["CPUs"], "memory_mb": cfg["Memory"]}
            runtime = cfg["KubernetesConfig"]["ContainerRuntime"]
            pods = next((int(o["Value"]) for o in cfg["KubernetesConfig"].get("ExtraOptions") or []
                         if o.get("Component") == "kubelet" and o.get("Key") == "max-pods"), DEFAULT_PODS)
            if have["cpus"] < self.resources.cpus or have["memory_mb"] < self.resources.memory_mb or runtime != "docker" or cfg.get("Driver", "docker") != "docker":
                raise Incompatible(
                    f"minikube profile {PROFILE} has {have['cpus']} CPUs, {have['memory_mb']} MiB and the {runtime} runtime, "
                    f"the experiment needs {self.resources.cpus} CPUs, {self.resources.memory_mb} MiB and docker. "
                    f"Recreate it with: minikube delete -p {PROFILE}"
                )
            if pods < self.max_pods():
                raise Incompatible(f"minikube profile {PROFILE} holds {pods} pods, the experiment may need {self.max_pods()}. "
                                   f"Recreate it with: minikube delete -p {PROFILE}")
            if profile.get("Status") in ("Running", "OK"):
                return have
        else:
            have = {"cpus": self.resources.cpus, "memory_mb": self.resources.memory_mb}
        # The docker runtime lets the lab build images directly in the cluster.
        sh(
            "minikube", "start", "-p", PROFILE, "--driver=docker", "--container-runtime=docker",
            f"--cpus={have['cpus']}", f"--memory={have['memory_mb']}",
            f"--extra-config=kubelet.max-pods={self.max_pods()}", timeout=15 * 60, interruptible=True,
        )
        return have

    def pin(self, cpus: str, mems: str | None) -> dict:
        """Binds the cluster's container to these CPUs and memory nodes, its
        own only, and returns what Docker then holds: without it the cluster
        took any CPU of a shared host, and gobgpd as many threads as the
        host has. Its pods and routers live inside the container's cgroup."""
        try:
            done = subprocess.run(["docker", "update", "--cpuset-cpus", cpus, *(["--cpuset-mems", mems] if mems else []), PROFILE],
                                  capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            raise LabError(f"cannot bind the cluster to CPUs {cpus}: {e}") from None
        if done.returncode:
            raise LabError(f"cannot bind the cluster to CPUs {cpus}: {done.stderr.strip()[-300:]}")
        self.weigh()
        return self.pinned()

    def weigh(self) -> None:
        """Gives the node's own services, kubelet and Docker, as much CPU
        weight as its pods. The node reports all CPUs of the host, so the pods
        weighed some hundred times more: once routers filled the CPUs, kubelet
        and the Docker the API server writes through came last. Inside the
        lab's own container only. Without it the lab runs as before."""
        try:
            sh("docker", "exec", PROFILE, "systemctl", "set-property", "--runtime", "system.slice", f"CPUWeight={SYSTEM_WEIGHT}", timeout=30)
        except LabError as e:
            log.warning("the node's services keep their CPU weight: %s", str(e)[-200:])

    def pinned(self) -> dict:
        """The CPUs and memory nodes Docker binds the cluster's container to, empty for none."""
        found = sh("docker", "inspect", "-f", "{{.HostConfig.CpusetCpus}}|{{.HostConfig.CpusetMems}}", PROFILE, timeout=30).strip()
        cpus, _, mems = found.partition("|")
        return {"cpus": cpus, "mems": mems}

    def trouble(self) -> str | None:
        """Why the cluster cannot serve a run, None when it can: Docker
        down, its container stopped, or Kubernetes not ready. A run that
        failed with one of these failed for the cluster, not for itself."""
        try:
            running = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", PROFILE],
                                     capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            return "Docker does not answer"
        if running.returncode:
            return "Docker does not answer" if "daemon" in running.stderr else f"the container {PROFILE} is gone"
        if running.stdout.strip() != "true":
            return f"the container {PROFILE} is stopped"
        try:
            sh("kubectl", "--context", PROFILE, "get", "--raw", "/readyz", timeout=15)
        except LabError as e:
            return f"{NOT_READY}: {str(e)[-200:]}"
        return None

    def api_answers(self, tries: int = 3, every: float = 10) -> bool:
        """Whether the Kubernetes API answers, asked a few times: a single
        late answer is no reason to delete the cluster."""
        for i in range(tries):
            try:
                sh("kubectl", "--context", PROFILE, "get", "--raw", "/readyz", timeout=15)
                return True
            except LabError:
                if i < tries - 1:
                    time.sleep(every)
        return False

    def clean(self) -> str | None:
        """Removes the routers of any run before. Returns why the cluster
        must be created anew, None when it is clean: its API does not answer,
        or routers of another run do not go."""
        if not self.api_answers():
            return "the Kubernetes API does not answer"
        try:
            self.undeploy()
        except LabError as e:
            return f"routers of another run stay: {str(e)[-200:]}"
        return None

    def diagnose(self, folder: Path, why: str = "") -> None:
        """Writes what the node shows of its load into folder, a file per
        look: during a deploy every DIAGNOSE_S, and once with the logs of the
        API server, etcd and kubelet when the API was lost, so that the
        cause can be read afterwards. A diagnosis never ends a run."""
        try:
            out = sh("docker", "exec", PROFILE, "sh", "-c", NODE_LOOK + (NODE_LOST if why else ""), timeout=60)
        except LabError as e:
            out = f"the node could not be read: {str(e)[-300:]}"
        try:
            folder.mkdir(parents=True, exist_ok=True)
            name = time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + ("-lost" if why else "")
            (folder / f"{name}.txt").write_text((f"{why}\n\n" if why else "") + out)
        except OSError as e:
            log.warning("the diagnosis could not be written: %s", e)

    def max_pods(self) -> int:
        """Pods the node must hold: a router each, as many as fit, and
        Kubernetes itself. Kubernetes holds DEFAULT_PODS unless told."""
        return max(DEFAULT_PODS, self.resources.routers() + SYSTEM_PODS)

    def delete(self) -> None:
        sh("minikube", "delete", "-p", PROFILE, timeout=5 * 60)

    def _profile(self) -> dict | None:
        result = subprocess.run(["minikube", "profile", "list", "-o", "json"], capture_output=True, text=True, timeout=30)
        try:
            profiles = json.loads(result.stdout)
        except ValueError:
            raise LabError(f"Cannot inspect minikube profiles: {result.stderr or result.stdout}") from None
        # minikube returns nonzero even for an empty profile list. Invalid or
        # unreadable profiles are not permission to delete a container.
        for p in profiles.get("invalid") or []:
            if p.get("Name") == PROFILE:
                raise LabError(f"minikube profile {PROFILE} is invalid; repair its metadata before proceeding")
        valid = next((p for p in profiles.get("valid") or [] if p["Name"] == PROFILE), None)
        if result.returncode and not valid and "valid" not in profiles:
            raise LabError(f"Cannot inspect minikube profiles: {result.stderr or result.stdout}")
        return valid

    def _docker_env(self) -> dict:
        env = dict(os.environ)
        for line in sh("minikube", "-p", PROFILE, "docker-env", "--shell", "none").splitlines():
            key, _, value = line.partition("=")
            if key:
                env[key] = value
        return env

    def build(self, commit: str) -> str:
        """Builds the router image with gobgpd from the given commit and returns its tag.

        The tag identifies both the daemon commit and the controller, so an
        image is reused only if neither changed. It is built directly in the
        cluster's Docker daemon.
        """
        sources = hashlib.sha256(b"".join((ROOT / f).read_bytes() for f in IMAGE_SOURCES)).hexdigest()
        tag = f"{commit[:12]}-{sources[:8]}"
        env = self._docker_env()
        if subprocess.run(["docker", "image", "inspect", f"{IMAGE}:{tag}"], env=env, capture_output=True, timeout=120).returncode == 0:
            return tag
        with tempfile.TemporaryDirectory() as src:
            archive = subprocess.run(["git", "-C", str(ROOT), "archive", commit, *DAEMON_SOURCES], capture_output=True, timeout=600)
            if archive.returncode:
                raise LabError(f"git archive {commit} failed: {archive.stderr.decode().strip()}")
            subprocess.run(["tar", "-x", "-C", src], input=archive.stdout, check=True, timeout=600)
            sh("docker", "build", "--build-context", f"daemon={src}", "-t", f"{IMAGE}:{tag}", str(ROOT), env=env, timeout=30 * 60, interruptible=True)
        return tag

    KEEP_IMAGES = 6

    def prune(self, keep: set[str]) -> None:
        """Removes router images beyond the newest few, except those in keep;
        every commit and change of the controller makes a new one."""
        env = self._docker_env()
        if not env.get("DOCKER_HOST") or env.get("DOCKER_HOST") == os.environ.get("DOCKER_HOST"):
            # Never the Docker of the host: its images belong to others too.
            logging.getLogger("lab").warning("minikube docker-env named no Docker of the cluster, old router images are kept")
            return
        lines = sh("docker", "images", IMAGE, "--format", "{{.CreatedAt}}\t{{.Tag}}", env=env).splitlines()
        tags = [line.split("\t")[1] for line in sorted(lines, reverse=True) if "\t" in line]
        old = [t for t in tags[self.KEEP_IMAGES:] if t not in keep]
        if old:
            # Only the lab's own tags: docker rmi also removes the layers no other image uses.
            subprocess.run(["docker", "rmi", *(f"{IMAGE}:{t}" for t in old)], env=env, capture_output=True, timeout=600)

    def deploy(self, name: str, topology: dict, tag: str, mode: dict[str, str], seed: int, bgp: config.Bgp,
               routers: "Routers", refresh_delay: float = 0, per_neighbor: bool = False, progress=None,
               diagnosis: Path | None = None) -> None:
        """Replaces the running routers, each in its pure mode, and waits until
        all BGP sessions are established. per_neighbor gives the OBGP routers
        a table per neighbor, and the routers of a variant all in BGP too: NS-BGP.
        Once all pods run, every controller gets its neighbors' pod addresses
        through `routers`: no router asks DNS, none needs a Service. Looks at
        the node go to the folder diagnosis, see diagnose."""
        from . import modes

        self.undeploy()
        check_neigh(name, topology)
        per = {"GOBGP_OPERA_EXPORT": "neighbor"}
        ns_bgp = set(mode.values()) == {"bgp"}

        def env(m: str) -> dict[str, str]:
            tables = modes.get(m).obgp and m != "obgp-paper" or ns_bgp
            return modes.get(m).env | (per if per_neighbor and tables else {})

        configs = {r: cfg | {"env": env(mode[r])} for r, cfg in topology["routers"].items()}
        for cfg in configs.values():  # gobgpd lists the member ASes of its confederation
            if (c := cfg.get("confederation")) is not None:
                cfg["confedMembers"] = sorted({int(o["asn"]) for o in configs.values() if o.get("confederation") == c})
        # A large topology goes in batches, each Helm call with the pods of all routers so far. Each batch
        # waits for its pods to run. Then every controller gets its neighbors' addresses and starts gobgpd,
        # and the deploy waits until all sessions are up.
        look = (lambda why="": self.diagnose(diagnosis, why)) if diagnosis else None
        watch = Watch(name, len(configs), self._status, self._conntrack, progress=progress, diagnose=look)
        watch.start()
        try:
            for names in batches(list(configs)):
                with tempfile.NamedTemporaryFile("w", suffix=".yaml") as values:
                    json.dump({"routers": configs, "deploy": names}, values)
                    values.flush()
                    sh(
                        "helm", "upgrade", "--install", RELEASE, str(CHART), "--kube-context", PROFILE,
                        "-n", NAMESPACE, "--create-namespace", "-f", values.name,
                        "--set", f"image.repository={IMAGE}", "--set", f"image.tag={tag}", "--set", f"seed={seed}",
                        "--set", f"bgp.holdTime={bgp.hold_time}", "--set", f"bgp.keepalive={bgp.keepalive}",
                        "--set", f"bgp.connectRetry={bgp.connect_retry}", "--set", f"bgp.gracefulRestart={str(bgp.graceful_restart).lower()}",
                        "--set", f"bgp.mrai={bgp.mrai:g}", "--set", f"bgp.refresh={bgp.refresh:g}", "--set", f"bgp.procs={bgp.procs}",
                        "--set", f"probe.periodS={probe_period(len(configs))}",
                        "--set", f"bgp.refreshDelay={refresh_delay:g}",
                        "--set", f"memory.requestMi={config.Cluster.ROUTER_MB}", "--set", f"memory.limitMi={self.resources.router_limit_mb}",
                        timeout=10 * 60, interruptible=True, abort=watch.lost,
                    )
                self._wait_running(len(names), watch)
            # 100 routers took 165 s until all sessions were up.
            self._tell(topology["routers"], routers, watch, timeout=300 + 3 * len(configs), every=TELL_S)
        except LabError as e:
            if watch.lost.is_set():
                raise HostLimit(f"routers of {name} did not become ready: {watch.why}") from None
            raise LabError(f"routers of {name} did not become ready: {e}") from None
        finally:
            watch.stop()

    def _wait_running(self, count: int, watch: "Watch", timeout: float = 300 + 3 * BATCH, every: float = 5) -> None:
        """Waits until `count` pods run, not until they are ready."""
        deadline = time.monotonic() + timeout
        running = 0
        while True:
            if watch.lost.is_set():
                raise LabError(watch.why)
            if STOP.is_set():
                raise Interrupted("deploy stopped")
            try:
                running = self._status()[0].get("Running", 0)
            except LabError:
                pass  # the watch tells when the API is lost
            else:
                if running >= count:
                    return
            if time.monotonic() > deadline:
                raise LabError(f"{running} of {count} pods running after {timeout:.0f} s")
            watch.lost.wait(every)

    def _tell(self, topology: dict[str, dict], routers: "Routers", watch: "Watch", timeout: float, every: float = 5) -> None:
        """Sends every controller its neighbors' pod addresses once all pods
        run with one, WAVE routers every `every` seconds, and waits until all
        routers are ready. A pod that is
        replaced meanwhile has a new address its neighbors do not know: the
        deploy fails. A restarted container keeps its pod and what it was told."""
        deadline = time.monotonic() + timeout
        told: dict[str, tuple[str, str]] = {}  # router -> its pod and address when told
        live: list[dict] = []
        while True:
            if watch.lost.is_set():
                raise LabError(watch.why)
            if STOP.is_set():
                raise Interrupted("deploy stopped")
            try:
                live = self._router_pods()
            except LabError:
                live = []  # the watch tells when the API is lost
            pods = {p["router"]: p for p in live if p["phase"] == "Running" and p["ip"] and not p["gone"]}
            for r, (pod, ip) in told.items():
                if r in pods and (pods[r]["pod"], pods[r]["ip"]) != (pod, ip):
                    raise LabError(f"the pod of {r} was replaced during the deploy, its neighbors know its old address")
            if len(pods) == len(topology):
                if sum(p["ready"] for p in pods.values()) == len(topology):
                    return
                routers.pods = {r: p["pod"] for r, p in pods.items()}
                ips = {r: p["ip"] for r, p in pods.items()}

                def tell(r: str) -> str | None:
                    neighbors = {n["name"]: ips[n["name"]] for n in topology[r].get("neighbors") or []}
                    try:
                        routers.post(r, "/neighbors/addresses", {"addresses": neighbors}, timeout=10)
                    except LabError:
                        return None  # not listening yet: told in the next round
                    return r

                with ThreadPoolExecutor(16) as pool:
                    for r in pool.map(tell, [r for r in topology if r not in told][:WAVE]):
                        if r:
                            told[r] = (pods[r]["pod"], pods[r]["ip"])
            if time.monotonic() > deadline:
                running = sum(p["phase"] == "Running" for p in live)
                ready = sum(p["ready"] for p in live)
                raise LabError(f"{running} of {len(topology)} pods running, {len(told)} told their neighbors, "
                               f"{ready} ready after {timeout:.0f} s")
            watch.lost.wait(every)

    def guard(self, name: str, total: int, on_lost, diagnosis: Path | None = None) -> "Watch":
        """Guards a run as a deploy is guarded: the node's connection tracking
        and whether the Kubernetes API answers. Calls on_lost once lost, after
        a look at the node into the folder diagnosis."""
        look = (lambda why="": self.diagnose(diagnosis, why)) if diagnosis else None
        watch = Watch(name, total, self._status, self._conntrack, quiet=True, on_lost=on_lost, diagnose=look)
        watch.start()
        return watch

    def _router_pods(self) -> list[dict]:
        """The routers' pods: name, router, phase, address, readiness and
        whether they terminate, in a small table even for hundreds."""
        out = sh("kubectl", "--context", PROFILE, "-n", NAMESPACE, "get", "pods", "-l", "app", "--no-headers", "--request-timeout=20s",
                 "-o", "custom-columns=POD:.metadata.name,ROUTER:.metadata.labels.app,PHASE:.status.phase,IP:.status.podIP,"
                 "READY:.status.containerStatuses[0].ready,GONE:.metadata.deletionTimestamp", timeout=30)
        return router_pods(out)

    def undeploy(self, timeout: float = 300) -> None:
        """Removes the routers and waits until their pods are gone; LabError
        when the Kubernetes API does not answer or they stay."""
        deadline = time.monotonic() + timeout
        try:
            subprocess.run(["helm", "uninstall", RELEASE, "--kube-context", PROFILE, "-n", NAMESPACE, "--wait", "--timeout", f"{timeout:.0f}s"],
                           capture_output=True, timeout=timeout + 30)
        except subprocess.TimeoutExpired:
            raise LabError(f"helm uninstall took longer than {timeout:.0f} s") from None
        if self._pods():  # routers whose release is gone, in the lab's own namespace
            sh("kubectl", "--context", PROFILE, "-n", NAMESPACE, "delete", "deployments", "--all", "--wait=false", timeout=60)
        while self._pods():
            if time.monotonic() > deadline:
                raise LabError("routers of the previous run did not terminate")
            time.sleep(2)

    def _conntrack(self) -> tuple[int, int]:
        """Entries in the connection tracking of the cluster's node, its own
        container, and their maximum."""
        out = sh("docker", "exec", PROFILE, "cat", "/proc/sys/net/netfilter/nf_conntrack_count", "/proc/sys/net/netfilter/nf_conntrack_max", timeout=20)
        count, most = (int(v) for v in out.split()[:2])
        return count, most

    def _status(self) -> tuple[dict[str, int], int]:
        """The pods by status and how many are ready, from the table the
        API server prints, which is small even for hundreds of pods."""
        out = sh("kubectl", "--context", PROFILE, "-n", NAMESPACE, "get", "pods", "--no-headers",
                 "--request-timeout=20s", timeout=30)
        return pod_status(out)

    def _pods(self) -> list[dict]:
        out = sh("kubectl", "--context", PROFILE, "-n", NAMESPACE, "get", "pods", "-o", "json", "--request-timeout=60s", timeout=90)
        return json.loads(out)["items"]

    def addresses(self) -> dict[str, str]:
        """Maps the IP addresses of the pods to router names: next hops."""
        return {p["status"]["podIP"]: p["metadata"]["labels"]["app"] for p in self._pods() if p.get("status", {}).get("podIP")}

    def restarts(self) -> tuple[int, list[str]]:
        """How often routers restarted, and those ended for taking too much memory."""
        pods = self._pods()
        statuses = [(p["metadata"]["labels"]["app"], c) for p in pods for c in p["status"].get("containerStatuses", [])]
        oom = sorted({r for r, c in statuses if c.get("lastState", {}).get("terminated", {}).get("reason") == "OOMKilled"})
        return sum(c["restartCount"] for _, c in statuses), oom

    def versions(self) -> dict:
        kube = json.loads(sh("kubectl", "--context", PROFILE, "version", "-o", "json"))
        return {
            "minikube": sh("minikube", "version", "--short").strip(),
            "kubernetes": kube["serverVersion"]["gitVersion"],
            "docker": sh("docker", "version", "--format", "{{.Server.Version}}", env=self._docker_env()).strip(),
        }


def probe_period(routers: int) -> int:
    """Seconds between two readiness probes of a router. A router is ready
    once all its sessions are up, so until then every probe fails and
    writes an event: among many routers less often, which spares the API
    and costs a deploy at most one period."""
    return 2 if routers <= BATCH else 10


def batches(names: list[str], size: int = BATCH) -> list[list[str]]:
    """The routers of each Helm call of a deploy, a batch more each time.
    A topology that fits in one batch goes in one call."""
    return [names[:end] for end in range(size, len(names), size)] + [names]


def router_pods(table: str) -> list[dict]:
    """Parses the table of Cluster._router_pods."""
    pods = []
    for line in table.splitlines():
        if len(cols := line.split()) < 6:
            continue
        pod, router, phase, ip, ready, gone = cols[:6]
        pods.append({"pod": pod, "router": router, "phase": phase, "ip": "" if ip == "<none>" else ip,
                     "ready": ready == "true", "gone": gone != "<none>"})
    return pods


def pod_status(table: str) -> tuple[dict[str, int], int]:
    """Counts the pods of `kubectl get pods --no-headers` by status, and
    those ready: a router is ready once all its sessions are up."""
    statuses: dict[str, int] = {}
    ready = 0
    for line in table.splitlines():
        if len(cols := line.split()) < 3:
            continue
        statuses[cols[2]] = statuses.get(cols[2], 0) + 1
        up, _, of = cols[1].partition("/")
        ready += up == of and up not in ("", "0")
    return statuses, ready


class Watch(threading.Thread):
    """Logs the progress of a deploy every PROGRESS_S and sets lost when
    the Kubernetes API has not answered for API_SILENT_S, which ends the
    Helm calls and waits of the deploy instead of Helm's timeout. Quiet, it
    guards a run: it logs nothing and calls on_lost once lost."""

    def __init__(self, name: str, total: int, status, conntrack=None, every: float = PROGRESS_S, silent: float = API_SILENT_S,
                 clock=time.monotonic, quiet: bool = False, on_lost=None, progress=None, diagnose=None) -> None:
        super().__init__(daemon=True)
        self.diagnose = diagnose  # writes a look at the node, with why once lost; looks only during a deploy
        self.diagnosed = clock()
        self.looking: threading.Thread | None = None
        self.name, self.total, self.status, self.every, self.silent, self.clock = name, total, status, every, silent, clock
        self.conntrack, self.quiet, self.on_lost, self.progress = conntrack, quiet, on_lost, progress
        self.looked = clock()  # when the pods were last looked at
        self.lost = threading.Event()
        self.done = threading.Event()
        self.why = ""
        self.answered = clock()
        self.running = 0

    def run(self) -> None:
        while not self.done.wait(GUARD_S if self.conntrack else self.every) and self.step():
            pass

    def step(self) -> bool:
        """One look at the pods and the node's connection tracking. False once
        the API is lost or the connection tracking nearly full."""
        if self.conntrack:
            try:
                count, most = self.conntrack()
            except (LabError, ValueError):
                count, most = 0, 0
            if most and count > CONNTRACK_SHARE * most:
                self.why = (f"the node's connection tracking held {count} of {most} entries at {self.running} of {self.total} pods running, "
                            "when full the host drops packets")
                return self._lose()
            if self.clock() - self.looked < self.every:
                return True
        self.looked = self.clock()
        try:
            statuses, ready = self.status()
        except LabError:
            silent = self.clock() - self.answered
            if silent < self.silent:
                return True
            self.why = (f"the Kubernetes API stopped answering at {self.running} of {self.total} pods running, "
                        f"no answer for {silent:.0f} s")
            return self._lose()
        self.answered = self.clock()
        self.running = statuses.get("Running", 0)
        if self.diagnose and not self.quiet and self.clock() - self.diagnosed >= DIAGNOSE_S and not (self.looking and self.looking.is_alive()):
            self.diagnosed = self.clock()  # beside the watch, which must go on guarding meanwhile
            self.looking = threading.Thread(target=self.diagnose, daemon=True)
            self.looking.start()
        if self.progress:  # the live view shows how far the deploy got
            self.progress(pods=sum(statuses.values()), running=self.running, ready=ready, total=self.total)
        if not self.quiet:
            by = ", ".join(f"{n} {s}" for s, n in sorted(statuses.items(), key=lambda i: -i[1])) or "none yet"
            log.info("%s: %d of %d pods (%s), %d ready with all sessions up", self.name, sum(statuses.values()), self.total, by, ready)
        return True

    def _lose(self) -> bool:
        if self.diagnose:  # before anything ends: the clean-up may delete the node
            try:
                self.diagnose(self.why)
            except Exception as e:  # noqa: BLE001  a diagnosis never hides the loss
                log.warning("no diagnosis: %s", e)
        self.lost.set()
        if self.on_lost:
            self.on_lost()
        return False

    def stop(self) -> None:
        self.done.set()


def _die_with_parent() -> None:
    """Runs in a child before exec: the kernel ends it when the thread that
    started it ends, with the lab, even by SIGKILL."""
    ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG


class Routers:
    """HTTP access to the router controllers through a single kubectl proxy.

    The proxy ends with the lab, however that ends. If it ends on its own,
    e.g. when the API server restarts, requests fail until ensure() starts
    it again; the runner does so before every attempt of a run, from its
    main thread, which the proxy is tied to.
    """

    START_S = 30
    POOL = 64  # the sampler's requests at once
    CONNECTIONS = POOL + 32  # kept to the proxy: the sampler's and the runner's own beside them, more would be opened and dropped

    def __init__(self) -> None:
        self.proxy: subprocess.Popen | None = None
        self.session = requests.Session()
        self.session.mount("http://", HTTPAdapter(pool_maxsize=self.CONNECTIONS))
        self.pods: dict[str, str] = {}
        self._start()

    def _start(self) -> None:
        # On a shared host anyone can reach a port on 127.0.0.1: the proxy passes only the controllers of the lab's pods,
        # not the cluster with the lab's rights.
        accept = f"--accept-paths=^/api/v1/namespaces/{NAMESPACE}/pods/[^/]+/proxy/.*$"
        proxy = subprocess.Popen(["kubectl", "--context", PROFILE, "proxy", "--port=0", accept], stdout=subprocess.PIPE,
                                 text=True, preexec_fn=_die_with_parent)
        ready, _, _ = select.select([proxy.stdout], [], [], self.START_S)
        line = proxy.stdout.readline() if ready else ""
        if not (match := re.search(r":(\d+)", line)):
            _end(proxy)
            raise LabError(f"kubectl proxy did not start: {line!r}")
        self.proxy = proxy
        self.base = f"http://127.0.0.1:{match.group(1)}/api/v1/namespaces/{NAMESPACE}/pods"

    def ensure(self) -> None:
        """Starts the proxy again if it ended."""
        if self.proxy.poll() is not None:
            self._start()

    def close(self) -> None:
        self.session.close()
        if self.proxy:
            _end(self.proxy)

    def _url(self, router: str, path: str) -> str:
        if self.proxy.poll() is not None:
            raise LabError("kubectl proxy ended")
        return f"{self.base}/{self.pods[router]}:8080/proxy{path}"

    def get(self, router: str, path: str, timeout: float = 2) -> dict:
        try:
            r = self.session.get(self._url(router, path), timeout=timeout)
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as e:
            raise LabError(f"{router} {path}: {e}") from None

    def post(self, router: str, path: str, body: dict | bytes | None = None, timeout: float = 60) -> dict:
        """A request to a router's controller: JSON, or bytes as they are."""
        try:
            data = {"data": body} if isinstance(body, bytes) else {"json": body}
            r = self.session.post(self._url(router, path), **data, timeout=timeout)
            r.raise_for_status()
        except requests.RequestException as e:
            raise LabError(f"{router} {path}: {e}") from None
        return r.json()


def _end(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def host() -> dict:
    """Describes the machine, for the metadata of a dataset. Read once per
    process: pages ask for it often, and the machine does not change meanwhile."""
    return dict(_machine())


@functools.cache
def _machine() -> dict:
    cpu = next((line.split(":", 1)[1].strip() for line in _read("/proc/cpuinfo") if line.startswith("model name")), "")
    mem = next((int(line.split()[1]) // 1024 for line in _read("/proc/meminfo") if line.startswith("MemTotal")), 0)
    return {
        "hostname": platform.node(),
        "kernel": platform.release(),
        "cpus": os.cpu_count(),
        "cpu_model": cpu,
        "memory_mb": mem,
    }


def limits() -> dict:
    """What bounds the routers of this host: the threads and memory for the
    lab, what the host keeps free, the routers the threads keep sampling,
    and those the memory holds. The settings set all but the host."""
    (keep_cpus, keep_mb), (cpus, memory) = keep(), free()
    usable_mb = max(0, memory)
    return {"cpus": max(1, cpus), "headroom": keep_cpus, "per_cpu": config.host_settings()["routers_per_cpu"],
            "memory_mb": usable_mb, "keep_mb": keep_mb, "by_memory": config.Cluster(memory_mb=usable_mb).routers()}


def max_routers() -> int:
    """How many routers this host runs well: as many as its memory holds
    and its CPUs keep sampling."""
    x = limits()
    return min(x["by_memory"], x["cpus"] * x["per_cpu"])


DFZ_PREFIXES = 1_000_000  # a full IPv4 table of the Internet, about, in 2026


def router_mb(router: dict, prefixes: int, senders: int | None = None) -> float:
    """MB a router needs for prefixes: up to one path per prefix from each
    neighbor, or from at most `senders` of them where only that many send."""
    paths = min(len(router.get("neighbors", [])), senders if senders is not None else 10**9)
    return config.Cluster.ROUTER_MB + prefixes * paths * config.Cluster.PATH_KB / 1024


def memory_need(experiment: config.Experiment, routers: dict) -> float:
    """MB a topology needs in an experiment: its routers, and the tables its
    scenarios fill, a path per prefix from each neighbor that sends them."""
    from . import scenario

    each = lambda prefixes, senders: sum(router_mb(r, prefixes, senders) for r in routers.values())
    need = len(routers) * config.Cluster.ROUTER_MB
    for name in experiment.scenarios:
        for step in scenario.each_step(scenario.load(name).steps):
            if step.kind == "announce_real":
                need = max(need, each(step.args.per_router * len(routers), len(routers)))
            elif step.kind == "announce_rib":
                need = max(need, each(step.args.prefixes or DFZ_PREFIXES, step.args.at_most or len(routers)))
    return config.Cluster.SYSTEM_MB + need


def capacity() -> dict:
    """The CPUs and memory the lab may use: all of the host, or what
    host.yaml in the settings allows on a shared one."""
    h, limit = host(), config.host_limit()
    return {"cpus": min(h["cpus"], limit.get("cpus", h["cpus"])),
            "memory_mb": min(h["memory_mb"], limit.get("memory_mb", h["memory_mb"]))}


def _read(path: str) -> list[str]:
    try:
        return Path(path).read_text().splitlines()
    except OSError:
        return []
