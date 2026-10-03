"""The minikube cluster, router images and Helm deployments."""

import ctypes
import fcntl
import hashlib
import json
import os
import platform
import re
import select
import signal
import subprocess
import tempfile
import threading
import time
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


class LabError(RuntimeError):
    """An infrastructure failure. The affected run can be retried."""


# One result at a time on the cluster: a second runner would deploy into
# the same namespace. The lock file names the result holding it and the
# pid of its runner. It lies with the state of minikube, as the cluster
# does, so that every lab of the user sees it, whatever its settings.
def lock_file() -> Path:
    home = Path(os.environ["MINIKUBE_HOME"]) if os.environ.get("MINIKUBE_HOME") else Path.home() / ".minikube"
    return home / f"{PROFILE}.lab.lock"


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
        raise Busy(f"the cluster runs {holder() or 'another result'}") from None
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


def sh(*args: str, env: dict | None = None, timeout: float | None = None, interruptible: bool = False) -> str:
    """Runs a command; LabError when it fails or takes longer than timeout.
    A long one is interruptible: it ends with Interrupted when STOP is set;
    cleaning up never is."""
    deadline = time.monotonic() + timeout if timeout else None
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env) as process:
        while True:
            try:
                stdout, stderr = process.communicate(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                late = deadline is not None and time.monotonic() > deadline
                stopped = interruptible and STOP.is_set()
                if stopped or late:
                    _end(process)
                    if stopped:
                        raise Interrupted(f"{' '.join(args[:2])} stopped") from None
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


def size_for(experiments: list[config.Experiment], host: dict) -> config.Cluster:
    """A cluster for the largest of the experiments, as far as the host allows."""
    cpus = max((e.cluster.cpus for e in experiments), default=config.Cluster().cpus)
    memory = max((e.cluster.memory_mb for e in experiments), default=config.Cluster().memory_mb)
    keep_cpus, keep_mb = keep()
    return config.Cluster(cpus=max(1, min(cpus, host["cpus"] - keep_cpus)),
                          memory_mb=max(2048, min(memory, host["memory_mb"] - keep_mb)))


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
        for m in [v.mode, *modes.get(v.mode).pure]:
            since = modes.get(m).since
            if since and subprocess.run(["git", "-C", str(ROOT), "merge-base", "--is-ancestor", since, commit]).returncode != 0:
                raise ValueError(f"{v.name}: the daemon at {v.ref} does not know {modes.get(m).label} yet. "
                                 f"Choose a git ref from {since} on.")


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
            if have["cpus"] < self.resources.cpus or have["memory_mb"] < self.resources.memory_mb or runtime != "docker":
                raise RuntimeError(
                    f"minikube profile {PROFILE} has {have['cpus']} CPUs, {have['memory_mb']} MB and the {runtime} runtime, "
                    f"the experiment needs {self.resources.cpus} CPUs, {self.resources.memory_mb} MB and docker. "
                    f"Recreate it with: minikube delete -p {PROFILE}"
                )
            if pods < self.max_pods():
                raise RuntimeError(f"minikube profile {PROFILE} holds {pods} pods, the experiment may need {self.max_pods()}. "
                                   f"Recreate it with: minikube delete -p {PROFILE}")
            if profile.get("Status") == "Running":
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

    def max_pods(self) -> int:
        """Pods the node must hold: a router each, as many as fit, and
        Kubernetes itself. Kubernetes holds DEFAULT_PODS unless told."""
        return max(DEFAULT_PODS, self.resources.routers() + SYSTEM_PODS)

    def delete(self) -> None:
        sh("minikube", "delete", "-p", PROFILE, timeout=5 * 60)

    def _profile(self) -> dict | None:
        try:
            profiles = json.loads(sh("minikube", "profile", "list", "-o", "json"))
        except LabError:
            return None
        return next((p for p in profiles.get("valid") or [] if p["Name"] == PROFILE), None)

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
        if subprocess.run(["docker", "image", "inspect", f"{IMAGE}:{tag}"], env=env, capture_output=True).returncode == 0:
            return tag
        with tempfile.TemporaryDirectory() as src:
            archive = subprocess.run(["git", "-C", str(ROOT), "archive", commit, *DAEMON_SOURCES], capture_output=True)
            if archive.returncode:
                raise LabError(f"git archive {commit} failed: {archive.stderr.decode().strip()}")
            subprocess.run(["tar", "-x", "-C", src], input=archive.stdout, check=True)
            sh("docker", "build", "--build-context", f"daemon={src}", "-t", f"{IMAGE}:{tag}", str(ROOT), env=env, timeout=30 * 60, interruptible=True)
        return tag

    KEEP_IMAGES = 6

    def prune(self, keep: set[str]) -> None:
        """Removes router images beyond the newest few, except those in keep;
        every commit and change of the controller makes a new one."""
        env = self._docker_env()
        lines = sh("docker", "images", IMAGE, "--format", "{{.CreatedAt}}\t{{.Tag}}", env=env).splitlines()
        tags = [line.split("\t")[1] for line in sorted(lines, reverse=True) if "\t" in line]
        old = [t for t in tags[self.KEEP_IMAGES:] if t not in keep]
        if old:
            subprocess.run(["docker", "rmi", *(f"{IMAGE}:{t}" for t in old)], env=env, capture_output=True)
            sh("docker", "image", "prune", "-f", env=env)  # the layers only they used

    def deploy(self, name: str, topology: dict, tag: str, mode: dict[str, str], seed: int, bgp: config.Bgp) -> None:
        """Replaces the running routers, each in its pure mode, and waits until
        all BGP sessions are established."""
        from . import modes

        self.undeploy()
        routers = {r: cfg | {"env": modes.get(mode[r]).env} for r, cfg in topology["routers"].items()}
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as values:
            json.dump({"routers": routers}, values)
            values.flush()
            try:
                sh(
                    "helm", "upgrade", "--install", RELEASE, str(CHART), "--kube-context", PROFILE,
                    "-n", NAMESPACE, "--create-namespace", "-f", values.name,
                    "--set", f"image.repository={IMAGE}", "--set", f"image.tag={tag}", "--set", f"seed={seed}",
                    "--set", f"bgp.holdTime={bgp.hold_time}", "--set", f"bgp.keepalive={bgp.keepalive}",
                    "--set", f"bgp.connectRetry={bgp.connect_retry}", "--set", f"bgp.gracefulRestart={str(bgp.graceful_restart).lower()}",
                    "--set", f"memory.requestMi={config.Cluster.ROUTER_MB}", "--set", f"memory.limitMi={self.resources.router_limit_mb}",
                    # 100 routers took 165 s until all sessions were up.
                    "--wait", "--timeout", f"{300 + 3 * len(routers)}s", interruptible=True,
                )
            except LabError as e:
                raise LabError(f"routers of {name} did not become ready: {e}") from None

    def undeploy(self) -> None:
        subprocess.run(
            ["helm", "uninstall", RELEASE, "--kube-context", PROFILE, "-n", NAMESPACE, "--wait"],
            capture_output=True,
        )
        deadline = time.monotonic() + 300
        while self._pods():
            if time.monotonic() > deadline:
                raise LabError("routers of the previous run did not terminate")
            time.sleep(2)

    def _pods(self) -> list[dict]:
        out = sh("kubectl", "--context", PROFILE, "-n", NAMESPACE, "get", "pods", "-o", "json")
        return json.loads(out)["items"]

    def pods(self) -> dict[str, str]:
        """Maps router names to pod names."""
        return {p["metadata"]["labels"]["app"]: p["metadata"]["name"] for p in self._pods()}

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

    def __init__(self) -> None:
        self.proxy: subprocess.Popen | None = None
        self.session = requests.Session()
        self.session.mount("http://", HTTPAdapter(pool_maxsize=64))
        self.pods: dict[str, str] = {}
        self._start()

    def _start(self) -> None:
        proxy = subprocess.Popen(["kubectl", "--context", PROFILE, "proxy", "--port=0"], stdout=subprocess.PIPE,
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
    """Describes the machine, for the metadata of a dataset."""
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
    have, (keep_cpus, keep_mb) = capacity(), keep()
    usable_mb = max(0, have["memory_mb"] - keep_mb)
    return {"cpus": max(1, have["cpus"] - keep_cpus), "headroom": keep_cpus, "per_cpu": config.host_settings()["routers_per_cpu"],
            "memory_mb": usable_mb, "keep_mb": keep_mb, "by_memory": config.Cluster(memory_mb=usable_mb).routers()}


def max_routers() -> int:
    """How many routers this host runs well: as many as its memory holds
    and its CPUs keep sampling."""
    x = limits()
    return min(x["by_memory"], x["cpus"] * x["per_cpu"])


DFZ_PREFIXES = 1_000_000  # a full IPv4 table of the Internet, about, in 2026


def fitted(want: config.Cluster) -> config.Cluster:
    """The cluster an experiment gets here: what it asks for, as far as the host has it."""
    have, (keep_cpus, keep_mb) = capacity(), keep()
    return want.model_copy(update={"cpus": max(1, min(want.cpus, have["cpus"] - keep_cpus)),
                                   "memory_mb": max(2048, min(want.memory_mb, have["memory_mb"] - keep_mb))})


def memory_need(experiment: config.Experiment, routers: dict) -> float:
    """MB a topology needs in an experiment: its routers, and the tables its
    scenarios fill, a path per prefix from each neighbor that sends them."""
    from . import scenario

    each = lambda prefixes, senders: sum(
        config.Cluster.ROUTER_MB + prefixes * min(len(r.get("neighbors", [])), senders) * config.Cluster.PATH_KB / 1024
        for r in routers.values())
    need = len(routers) * config.Cluster.ROUTER_MB
    for name in experiment.scenarios:
        for step in scenario.each_step(scenario.load(name).steps):
            if step.kind == "announce_real":
                need = max(need, each(step.args.per_router * len(routers), len(routers)))
            elif step.kind == "announce_rib":
                need = max(need, each(step.args.prefixes or DFZ_PREFIXES, step.args.at_most or len(routers)))
    return config.Cluster.SYSTEM_MB + need


def oversized(experiment: config.Experiment) -> dict[str, list[str]]:
    """The topologies of an experiment this host cannot run well, each with
    every reason: more routers than its CPUs keep sampling, more memory
    than the lab may use."""
    from . import topology

    have, x, out = capacity(), limits(), {}
    usable = min(experiment.cluster.memory_mb, have["memory_mb"] - keep()[1])
    for t in experiment.topologies:
        routers, why = topology.load(t, shared=True)["routers"], []
        if len(routers) > x["cpus"] * x["per_cpu"]:
            why.append(f"{len(routers)} routers")
        if (need := memory_need(experiment, routers)) > usable:
            why.append(f"about {need / 1024:,.0f} GB")
        if why:
            out[t] = why
    return out


def limit(experiment: config.Experiment) -> str:
    """What this host gives a topology of an experiment, to read next to oversized()."""
    x = limits()
    usable = min(experiment.cluster.memory_mb, capacity()["memory_mb"] - keep()[1])
    return f"at most {x['cpus'] * x['per_cpu']} routers, {usable / 1024:,.0f} GB"


def too_large(experiment: config.Experiment) -> str | None:
    """Why no topology of an experiment fits this host, or None."""
    skipped = oversized(experiment)
    if skipped and len(skipped) == len(experiment.topologies):
        return "; ".join(f"{t}: {', '.join(why)}" for t, why in skipped.items())
    return None


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
