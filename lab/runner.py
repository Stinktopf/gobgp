"""Executes the runs of a dataset.

Every run deploys a fresh topology and plays its scenario step by step.
Infrastructure failures are retried; the outcome of a run, including a
timeout, is always kept. A dataset can be resumed at any time: finished
runs are skipped.
"""

import csv
import gzip
import heapq
import itertools
import logging
import os
import shutil
import tempfile
import threading
import time
import zlib
from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from statistics import mean

from . import analysis, forwarding, host, modes, mrt, prefixes, rib, scenario
from .cluster import NOT_READY, Cluster, HostLimit, Interrupted, LabError, Routers, fit, router_mb
from .config import Cluster as Resources
from .config import Experiment
from .results import COUNTERS, SAMPLE_FIELDS, STOP_FILE, Dataset, RunKey, now, pause_file
from .scenario import Network, Step

log = logging.getLogger("lab")
ATTEMPTS = 3
# The lab is a guest on a shared host: after Docker or the host restarted it
# waits until Docker has run a while and only starts its own cluster again.
# It pauses the queue when Docker does not settle in time, and ends the result
# as failed when its cluster does not come back after a few starts.
DOCKER_SETTLED_S = 5 * 60
RECOVER_WAIT_S = 30 * 60
RECOVER_STARTS = 3
# A result whose cluster is lost this often, counted over an automatic restart
# of the result too, ends as failed: it is played again at most once.
LOSSES = 2


class Cancelled(Exception):
    pass


def stop_requested(dataset: Dataset) -> None:
    """Marks a result as stopped by a person, before its runner gets SIGTERM:
    without the mark a SIGTERM interrupts it, e.g. when the host shuts down,
    and the queue resumes it."""
    (dataset.path / STOP_FILE).touch()


def settle(stop: threading.Event, status: "Status") -> None:
    """Waits while the host shuts down and until Docker answers and has run
    DOCKER_SETTLED_S, as after a restart of Docker or the host."""
    while host.shutting_down() or not host.docker_running() or host.docker_up_s() < DOCKER_SETTLED_S:
        status.update(phase="waiting for Docker to settle")
        if stop.wait(30):
            raise Cancelled


def recover(cluster: Cluster, stop: threading.Event, status: "Status", why: str) -> None:
    """Starts the cluster again after it was lost, as a guest: only its own
    container, once Docker settled, never while the host shuts down. Pauses
    the queue when Docker does not settle within RECOVER_WAIT_S, and ends the
    result with HostLimit after RECOVER_STARTS starts that did not help."""
    log.warning("the cluster is lost (%s): waiting for it, the run is not counted", why)
    deadline = time.monotonic() + RECOVER_WAIT_S
    starts = 0
    while True:
        status.update(phase=f"waiting for the cluster: {why}")
        if stop.wait(30):
            raise Cancelled
        if host.shutting_down() or not host.docker_running() or host.docker_up_s() < DOCKER_SETTLED_S:
            pass
        elif starts >= RECOVER_STARTS:
            raise HostLimit(f"the cluster did not come back after {starts} starts: {why}")
        else:
            starts += 1
            try:
                cluster.start()
            except (LabError, RuntimeError) as e:  # Incompatible too: the lab never deletes it here
                why = str(e)[-200:]
            else:
                if not (why := cluster.trouble()):
                    log.info("the cluster is back")
                    return
        if time.monotonic() > deadline:
            give_up(f"Docker did not settle within {RECOVER_WAIT_S // 60} min: {why}.")


class Losses:
    """The losses of the cluster within one result, also before an automatic
    restart of it. The LOSSES-th ends the result with HostLimit."""

    def __init__(self, dataset: Dataset) -> None:
        last = (dataset.meta.get("interruptions") or [{}])[-1]
        resumed = dataset.status.get("state") == "interrupted" and last.get("lost")
        self.reasons: list[str] = [last["cause"]] if resumed else []

    def add(self, why: str) -> None:
        self.reasons.append(why)
        if len(self.reasons) >= LOSSES:
            raise HostLimit(f"the cluster was lost {len(self.reasons)} times in this result, last: {why}")


def prepare(cluster: Cluster, dataset: Dataset, stop: threading.Event, status: "Status") -> None:
    """Starts the cluster and leaves it clean, before anything runs on it:
    its API answers and its namespace holds no routers of another run. A
    cluster that cannot be cleaned is the lab's own profile: it is deleted
    and created anew, once. Results and other containers stay untouched."""
    from .lifecycle import ensure_cluster

    try:
        dataset.update(cluster=ensure_cluster(cluster))
    except Exception:
        if not (why := cluster.trouble()):
            raise
        if not why.startswith(NOT_READY):  # Docker or the container: waits for them as a guest
            recover(cluster, stop, status, why)
            dataset.update(cluster=ensure_cluster(cluster))
    status.update(phase="checking the cluster")
    if why := cluster.clean():
        log.warning("the cluster is created anew: %s", why)
        status.update(phase=f"creating the cluster anew: {why}")
        cluster.delete()
        dataset.update(cluster=ensure_cluster(cluster))
        if why := cluster.clean():
            raise HostLimit(f"the cluster is not usable even when created anew: {why}")


def tidy(cluster: Cluster, status: "Status | None" = None) -> None:
    """Leaves no routers behind once a result ends, however it ends: their
    Helm release would survive in etcd and bring them back with every start
    of the cluster. Where the container runs but its API does not answer,
    the lab's own profile is deleted, and the next result creates it anew:
    asked first, so that a silent API is not waited for with Helm."""
    say = status.update if status else (lambda **_: None)
    why = cluster.trouble()
    if not (why and why.startswith(NOT_READY)) or cluster.api_answers():
        say(phase="removing the routers")
        try:
            cluster.undeploy()
            return
        except Exception as e:  # noqa: BLE001  cleaning up never ends the runner
            problem = str(e)[-200:]
        why = cluster.trouble()
        if not (why and why.startswith(NOT_READY)) or cluster.api_answers():
            log.warning("the routers stay until the next result: %s", problem)
            return
    log.warning("the Kubernetes API does not answer (%s): the lab's cluster is deleted, the next result creates it anew", why)
    say(phase="deleting the lab's cluster, its Kubernetes API does not answer")
    try:
        cluster.delete()
    except Exception as e:  # noqa: BLE001
        log.warning("the lab's cluster could not be deleted: %s", e)


def sampled(rows: Iterable[dict]) -> Iterator[dict]:
    """The rows of a run, which must hold at least one: a run without samples cannot be measured."""
    rows = iter(rows)
    first = next(rows, None)
    if first is None:
        raise LabError("the run wrote no samples")
    return itertools.chain([first], rows)


def give_up(reason: str) -> None:
    """Pauses the queue with the reason and ends the runner: the result is interrupted and goes on once the queue resumes."""
    log.error("%s Pausing the queue.", reason)
    pause_file().parent.mkdir(parents=True, exist_ok=True)
    pause_file().write_text(reason)
    raise Cancelled


def interrupted(dataset: Dataset, run: str | None, cause: str, lost: bool = False) -> None:
    """Records why and where a result was interrupted, with the boot of the
    host. lost: by a loss of the cluster, which Losses counts."""
    from .service import boot_id

    entry = {"at": now(), "run": run, "cause": cause, "boot": boot_id(), **({"lost": True} if lost else {})}
    dataset.update(interruptions=[*dataset.meta.get("interruptions", []), entry])
    log.warning("interrupted at %s: %s", run or "its start", cause)


def bind(dataset: Dataset, cluster: Cluster) -> None:
    """Binds the cluster to as many CPUs as the experiment's cluster has, of
    one NUMA node where one has enough, and records what Docker then holds.
    The lab is a guest: unbound, oscillating routers took some 70 threads of
    a shared host for a cluster of 25 CPUs. Where Docker cannot bind it, the
    result says so and runs unbound."""
    choice = host.pick_cores(cluster.resources.cpus, cluster.resources.memory_mb)
    try:
        held = cluster.pin(choice["cpus"], choice["mems"])
    except LabError as e:
        log.warning("the cluster runs on any CPU of the host: %s", e)
        held = None
    else:
        log.info("the cluster runs on CPUs %s, memory of node %s", held["cpus"], held["mems"] or "any")
    dataset.update(pinned={**choice, "held": held})


def went_on_after_reboot(dataset: Dataset) -> None:
    """Names a reboot as the cause of the last interruption once the result goes on after one."""
    from .service import boot_id

    entries = dataset.meta.get("interruptions", [])
    if entries and entries[-1].get("boot") not in (None, boot_id()) and not entries[-1].get("rebooted"):
        dataset.update(interruptions=[*entries[:-1], {**entries[-1], "rebooted": True}])
        log.info("going on after a reboot of the host")


HEAP_PROFILE_MB = 1024  # as in the controller: above it a router keeps a heap profile
SILENT_S = 30  # a router that hands over no samples this long fails the run
STATUS_S = 15  # for the prefixes or sessions of a router, which may be busy with many routes
FINAL_S, FINAL_TRIES = 120, 2  # the final check may wait: a busy router still answers, a slow one costs no data
FINAL_PREFIXES = 2000  # the final check reads every route of every router: no Internet tables
HOPS_MAX = 256  # as in the controller: above, the routers follow the next hops of a sample of the prefixes
LOG_NAMES = 6  # routers or links a line of the log names, beyond that it counts them


def told(details: dict) -> str:
    """The routers and links of an event as the log tells them: by name, or counted when many."""
    parts = []
    for kind, items in (("routers", details.get("routers") or []), ("links", ["–".join(link) for link in details.get("links") or []])):
        if items:
            parts.append(", ".join(items) if len(items) <= LOG_NAMES else f"{len(items)} {kind}")
    return ", ".join(parts)


ANNOUNCING = ("announce", "announce_real", "announce_rib", "originate", "replay")


class HostLoad(threading.Thread):
    """How busy the host is while a run plays, in all and by others. All
    routers share one host: when it is saturated, the run measures the host,
    not the protocol, and on a shared host others weigh on it as well."""

    def __init__(self, interval: float = 1.0, clock=time.monotonic, cores: list[int] | None = None) -> None:
        super().__init__(daemon=True)
        self.interval, self.done, self.shares, self.others = interval, threading.Event(), [], []
        self.cores, self.others_cores = cores, []  # the CPUs the cluster is bound to, and others' share of them
        self.clock, self.times = clock, []  # the time of the run of every share

    def run(self) -> None:
        meter = host.Meter(self.cores)
        while not self.done.wait(self.interval):
            m = meter.read()
            if m.get("others_cores") is not None:
                self.others_cores.append(m["others_cores"])
            if m["busy"] is not None:
                self.shares.append(m["busy"])
                self.times.append(self.clock())
            if m["others"] is not None:
                self.others.append(m["others"])

    def stop(self) -> None:
        self.done.set()

    def summary(self) -> dict:
        shares = self.shares or [0.0]
        out = {"cpu_mean": round(mean(shares), 3), "cpu_max": round(max(shares), 3), "cpus": os.cpu_count(),
               # How long the host was at its limit, where it measures itself.
               "saturated_s": round(self.interval * sum(s > analysis.BUSY_HOST for s in self.shares), 1),
               # Over the run, for the charts of the quality of the measurement.
               "series": [[round(t, 1), round(s, 3)] for t, s in zip(self.times, self.shares)]}
        if self.others:
            out.update(others_mean=round(mean(self.others), 3), others_min=round(min(self.others), 3),
                       others_max=round(max(self.others), 3))
        if self.others_cores:  # what others ran on the cluster's own CPUs: what disturbs the measurement
            out.update(cores=host.cpu_text(self.cores), others_cores_mean=round(mean(self.others_cores), 3),
                       others_cores_max=round(max(self.others_cores), 3))
        return out


QUIET_SHARE, QUIET_WAIT_S = 0.3, 30


def quiet_host(stop: threading.Event, cpus: int) -> float | None:
    """Waits until the run before no longer weighs on the next: until the
    lab uses less than QUIET_SHARE of the CPUs of its cluster for two
    seconds, or where its share cannot be seen, the whole host. Others on a
    shared host are not waited for: every run records them. At most
    QUIET_WAIT_S. The share still busy if it did not get quiet, else None."""
    deadline, quiet, share = time.monotonic() + QUIET_WAIT_S, 0, None
    meter, threads = host.Meter(), os.cpu_count() or 1
    while time.monotonic() < deadline and not stop.wait(1.0):
        m = meter.read()
        if m["busy"] is None:
            return None  # cannot tell
        share = m["lab"] * threads / cpus if m["lab"] is not None else m["busy"]
        quiet = quiet + 1 if share < QUIET_SHARE else 0
        if quiet >= 2:
            return None
    return share


class Halt:
    """The stop of a run: set by a Stop of the whole result, or when a
    parallel step failed and its siblings must end too."""

    def __init__(self, outer: threading.Event) -> None:
        self.outer = outer
        self.own = threading.Event()

    def set(self) -> None:
        self.own.set()

    def is_set(self) -> bool:
        return self.outer.is_set() or self.own.is_set()

    def wait(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while not self.is_set():
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            self.own.wait(min(left, 0.2))
        return True


def run(dataset: Dataset, stop: threading.Event) -> None:
    experiment = dataset.experiment
    keys = dataset.keys()
    # Topologies larger than this host runs well would measure the host.
    here = fit(experiment)
    if skipped := here.skipped:
        log.warning("skipped on this host: %s", "; ".join(f"{t}, {', '.join(why)}" for t, why in skipped.items()))
        keys = [k for k in keys if k.topology not in skipped]
    (dataset.path / STOP_FILE).unlink(missing_ok=True)  # of an earlier stop
    went_on_after_reboot(dataset)
    losses = Losses(dataset)  # before the status says running
    status = Status(dataset, total=len(keys), done=sum(map(dataset.is_done, keys)))
    status.update(skipped=skipped, limit=here.limit if skipped else None)
    if status.data["done"] == len(keys):
        status.update(state="finished")
        return
    if here.cluster is None:
        raise ValueError(here.problem)
    cluster = Cluster(here.cluster)
    routers = None
    tags: dict[str, str] = {}

    def setup() -> None:
        """A clean cluster, bound to its CPUs, with the images of all variants: at the start and after a loss."""
        status.update(phase="starting cluster")
        prepare(cluster, dataset, stop, status)
        bind(dataset, cluster)
        for v in experiment.variants:
            status.update(phase=f"building {v.name} ({dataset.commits[v.name][:12]})")
            tags[v.name] = cluster.build(dataset.commits[v.name])
            log.info("image of %s at %s: %s", v.name, dataset.commits[v.name][:12], tags[v.name])

    try:
        settle(stop, status)
        setup()
        cluster.prune(keep=set(tags.values()))
        if "versions" not in dataset.meta:
            dataset.update(versions=cluster.versions())
        if "predictions" not in dataset.meta:
            # What the simulator expects, so that a mode that should not come to rest is judged as predicted.
            status.update(phase="asking the simulator")
            from . import simulate
            try:
                dataset.update(predictions=simulate.predictions(experiment))
            except Exception as e:  # the result runs on, its runs judged without the simulator
                log.warning("no predictions of the simulator: %s", e)
                dataset.update(predictions={"error": str(e)[-300:]})
        routers = Routers()
        for key in keys:
            if dataset.is_done(key):
                continue
            if stop.is_set():
                raise Cancelled
            if pause_file().exists():  # paused: between two runs, so that the host may restart now
                log.info("the queue is paused: interrupted before %s", key)
                raise Cancelled
            if low := host.low_disk(dataset.path):
                # Between runs, so that no run is cut short. Resuming the queue goes on here.
                log.warning("%s Pausing the queue.", low)
                pause_file().write_text(low)
                raise Cancelled
            status.update(current=str(key), run_started=now(), phase="waiting for the run before to settle")
            if (busy := quiet_host(stop, cluster.resources.cpus)) is not None:
                log.info("%s: the lab or host is still %.0f %% busy, starting anyway", key, 100 * busy)
            started = time.monotonic()
            failures = []  # why each attempt before the last failed, kept also for a run that then completed
            attempt = 0
            while attempt < ATTEMPTS:
                attempt += 1
                status.update(attempt=attempt, attempts=ATTEMPTS, failure=failures[-1] if failures else None)
                try:
                    routers.ensure()
                    result, samples = Run(dataset, key, cluster, routers, tags[key.variant], status, stop).execute()
                    break
                except HostLimit:
                    raise  # a limit of the shared host: played again, the run would hit it again
                except LabError as e:
                    if stop.is_set():  # ended from outside: its commands fail as the host shuts down
                        raise Cancelled from e
                    if why := cluster.trouble():
                        # The cluster failed, not the run: not counted, played again from its start on a clean cluster.
                        # The second loss in a result ends it.
                        log.warning("%s: attempt %d failed with the cluster, not counted: %s", key, attempt, e)
                        attempt -= 1
                        losses.add(why)
                        routers.close()
                        routers = None
                        settle(stop, status)  # as a guest: after Docker restarted, it runs a while first
                        setup()
                        routers = Routers()
                        started = time.monotonic()
                        continue
                    log.warning("%s: attempt %d failed: %s", key, attempt, e)
                    failures.append(str(e))
                    result, samples = {"status": "error", "message": str(e)}, []
            took = time.monotonic() - started
            result.update(commit=dataset.commits[key.variant], image=tags[key.variant], attempts=attempt, took_s=round(took, 1))
            if failures:
                result["failures"] = failures
            try:
                dataset.write_run(key, result, samples)
            except (csv.Error, OSError, ValueError) as e:
                # The run is an error, the result goes on, and the spool stays for a look at the samples.
                log.warning("%s: its samples could not be written, they stay in the spool: %s", key, e)
                result = {**result, "status": "error", "message": f"its samples could not be written: {e}"}
                dataset.write_run(key, result, [])
            else:
                for spool in (dataset.path / key.path).glob(".samples-*"):  # also of attempts that failed
                    shutil.rmtree(spool, ignore_errors=True)
            if result["status"] != "error":
                try:  # ready for the charts at once
                    analysis.run_bins(dataset, key, result)
                except Exception as error:
                    log.warning("%s: no series yet: %s", key, error)
            log.info("%s: %s after %.0f s", key, result["status"], took)
            status.finished(error=result["status"] == "error")
        if isinstance(dataset.meta.get("predictions"), dict) and "error" not in dataset.meta["predictions"]:
            # Where a run contradicts the 20 orders of the prediction, more orders first: a miss is not a problem.
            status.update(current=None, run_started=None, phase="asking the simulator in more orders where runs differ")
            from . import simulate
            try:
                simulate.more_orders(dataset)
            except Exception as e:  # the result keeps its predictions of 20 orders
                log.warning("no more orders of the simulator: %s", e)
        status.update(state="finished", current=None, run_started=None, phase=None, attempt=None, failure=None)
    except HostLimit as e:  # ends for good: played again, the result would hit the limit again
        log.error("the result ends as failed: %s", e)
        status.update(state="failed", phase=None, current=None, run_started=None, error=str(e))
    except (Cancelled, Interrupted):
        if (dataset.path / STOP_FILE).exists():
            status.update(state="stopped", phase=None, current=None, run_started=None)
        else:
            try:
                reason = pause_file().read_text().strip() or "the queue was paused"
            except OSError:
                reason = "the runner was ended from outside, e.g. as the host shut down"
            interrupted(dataset, status.data.get("current"), reason)
            status.update(state="interrupted", phase=None)
    except Exception as e:
        if why := cluster.trouble():  # it failed because the cluster did: goes on later once, does not fail
            if losses.reasons:
                reason = f"the cluster was lost {len(losses.reasons) + 1} times in this result, last: {why}: {str(e)[-200:]}"
                log.error("the result ends as failed: %s", reason)
                status.update(state="failed", phase=None, current=None, run_started=None, error=reason)
                return
            interrupted(dataset, status.data.get("current"), f"{why}: {str(e)[-200:]}", lost=True)
            status.update(state="interrupted", phase=None)
            return
        status.update(state="failed", phase=None, current=None, run_started=None, error=str(e))
        raise
    finally:
        if routers:
            routers.close()
        # The result has ended: what the lab does meanwhile shows as its phase, which ends with it.
        tidy(cluster, status)
        if status.data.get("phase"):
            status.update(phase=None)


class Status:
    """Progress of a running dataset, written to status.json."""

    def __init__(self, dataset: Dataset, total: int, done: int) -> None:
        self.dataset = dataset
        self.samples: deque = deque(maxlen=300)
        self.watched: set[str] = set()  # the routers of the current run the live view averages
        self.lock = threading.Lock()  # the sampler and the steps update it concurrently
        self.data = {
            # began: the first start of the result; started: of this session
            "state": "running", "pid": os.getpid(), "began": dataset.status.get("began") or now(), "started": now(), "updated": now(),
            "total": total, "done": done, "errors": 0, "current": None, "run_started": None, "phase": None,
        }
        self.update()

    def update(self, **fields) -> None:
        with self.lock:
            self.data.update(fields, updated=now())
            self.dataset.write_status(self.data)

    def live(self, t: float, latest: dict[str, dict]) -> None:
        """Records the router means of the current run for live monitoring,
        of the watched routers only, as the analysis measures them."""
        rows = [s for r, s in latest.items() if r in self.watched] or list(latest.values())
        self.samples.append({"t": round(t, 1), **{m: round(mean(s[m] for s in rows), 2) for m in COUNTERS}})
        self.update(live=list(self.samples))

    def finished(self, error: bool) -> None:
        self.update(done=self.data["done"] + 1, errors=self.data["errors"] + error)


class Run:
    """One run: deploy the topology, play the scenario, collect the samples."""

    def __init__(self, dataset: Dataset, key: RunKey, cluster: Cluster, routers: Routers, tag: str,
                 status: Status, stop: threading.Event) -> None:
        self.experiment: Experiment = dataset.experiment
        self.key = key
        self.spool = dataset.path / key.path  # where the samples wait until the run ends
        # Looks at the node during the deploy and when the cluster is lost, see Cluster.diagnose.
        self.diagnosis = dataset.path / "diagnosis" / "_".join(key.path.parts)
        self.held = (dataset.meta.get("pinned") or {}).get("held") or {}  # the CPUs the cluster is bound to
        self.cluster = cluster
        self.igp: dict[frozenset, int] = {}  # costs igp steps set in this run
        self.routers = routers
        self.tag = tag
        self.status = status
        self.stop = Halt(stop)
        self.topology = dataset.topology(key.topology)
        self.scenario = dataset.scenario(key.scenario)
        self.network = Network(self.topology["routers"], self.topology["roles"])
        self.origins = tuple(self.network.roles.get("origins", []))
        self.variant = next(v for v in self.experiment.variants if v.name == key.variant)
        self.events: list[dict] = []
        self.current = threading.local()  # the position of the step a thread plays
        self.measurements: list[dict] = []
        self.profiled = ""  # the router of the CPU profile, once asked for
        # What is down, and the (router, peer) link ends each failure acted on,
        # so that up undoes exactly that.
        self.stopped: set[str] = set()
        self.failed: dict[tuple[str, str], list[tuple[str, str]]] = {}
        self.originated: set[str] = set()
        self.announcers: set[str] = set()  # routers with real prefixes
        self.injected: dict[str, set[str]] = {}  # the prefixes of the table each router injected
        self.silent_since: float | None = None  # last failure that BGP only notices by its hold timer
        self.lock = threading.Lock()

    def execute(self) -> tuple[dict, list[dict]]:
        seed = self.experiment.seed * 1000 + self.key.index  # equal for all variants: paired runs
        self.status.samples.clear()
        self.status.update(phase="deploying", live=[], deploy=None)
        deploying = time.monotonic()
        self.modes = self.variant.modes_of(self.topology["routers"], seed)
        self.cluster.deploy(self.key.topology, self.topology, self.tag, self.modes, seed, self.experiment.bgp,
                            self.routers, self.variant.refresh_delay or 0, self.variant.per_neighbor,
                            progress=lambda **p: self.status.update(deploy=p), diagnosis=self.diagnosis)
        log.info("%s: deployed in %.0f s, seed %d", self.key, time.monotonic() - deploying, seed)
        watched = [r for r in self.network.routers if r not in self.origins]
        self.status.watched = set(watched)
        # Every router samples, the origins too for their next hops; the analysis measures the watched ones.
        self.sampler = Sampler(self.routers, sorted(self.network.routers), self.experiment.sampling_of(self.variant.name).interval, self.status.live, self.spool)
        started = now()
        load = HostLoad(clock=self.sampler.now, cores=host.cpu_list(self.held["cpus"]) if self.held.get("cpus") else None)
        load.start()
        self.sampler.start()
        # A full connection tracking or a silent API ends the run, and with it the result.
        guard = self.cluster.guard(str(self.key), len(self.network.routers), on_lost=self.stop.set, diagnosis=self.diagnosis)
        try:
            self.steps(self.scenario.steps, ())
            self.final()
            if guard.lost.is_set():
                raise Cancelled
        except BaseException:
            guard.stop()
            load.stop()
            try:
                self.sampler.stop()
            except LabError:
                pass  # the first problem is the one to report, e.g. a Stop
            if guard.lost.is_set():
                raise HostLimit(f"{self.key}: {guard.why}") from None
            raise
        guard.stop()
        self.sampler.stop()
        load.stop()
        if self.sampler.failed > 0.05 * max(1, self.sampler.count):
            raise LabError(f"{self.sampler.failed} samples failed")
        restarts, oom = self.cluster.restarts()
        if oom:
            raise LabError(f"{', '.join(oom)} took more than {self.experiment.cluster.router_limit_mb} MiB and restarted")
        if restarts:
            raise LabError(f"routers restarted {restarts} times")
        try:  # before the rows are read: they can be read once
            self.keep_heaps(self.sampler.peak_mb)
            self.keep_cpu()
        except Exception:  # noqa: BLE001  a diagnosis, never the end of a run
            log.exception("%s: keeping profiles", self.key)
        addresses, rows = self.cluster.addresses(), self.sampler.rows()
        # Away before the run is written and analysed: routers that oscillate
        # would go on, load the host while the next run waits for quiet and
        # grow until their memory limit ends them. The next deploy is the fallback.
        try:
            self.cluster.undeploy()
        except LabError as e:
            log.warning("%s: the routers stay until the next run: %s", self.key, e)
        rows = sampled(rows)
        return {
            # A failed check outweighs a timeout: the routes were wrong.
            "status": "failed" if any(e["name"] == "expect" and not analysis.check_ok(e) for e in self.events)
                      else "timeout" if any(not m["stable"] for m in self.measurements) else "completed",
            "started": started,
            "duration_s": round(self.sampler.now(), 3),
            "seed": seed,
            "watched": watched,
            # The routers' addresses, so that next hops inside an AS name their router.
            "addresses": addresses,
            # In the order of their start; parallel steps record them as they end.
            "events": sorted(self.events, key=lambda e: e["t"]),
            "measurements": self.measurements,
            "host": load.summary(),
            # Which router ran which mode, where they differ.
            **({"modes": self.modes} if self.variant.mixed else {}),
        }, rows

    def keep_heaps(self, peak_mb: dict[str, float]) -> None:
        """Keeps the heap profile of every router whose memory passed the
        controller's threshold, beside the run, as heap-<router>.pb.gz."""
        import base64

        grown = sorted(r for r, mb in peak_mb.items() if mb >= HEAP_PROFILE_MB)
        for router in grown:
            try:
                h = self.routers.get(router, "/heap", timeout=STATUS_S)
            except LabError as e:
                log.warning("%s: no heap profile of %s: %s", self.key, router, e)
                continue
            if h.get("profile"):
                self.spool.mkdir(parents=True, exist_ok=True)
                (self.spool / f"heap-{router}.pb.gz").write_bytes(base64.b64decode(h["profile"]))
                log.info("%s: kept the heap profile of %s at %.0f MiB", self.key, router, h["rss_mb"])

    def busiest(self) -> str:
        """The router with the most neighbors, the first by name among equals."""
        return min(self.network.routers, key=lambda r: (-len(self.network.routers[r].get("neighbors", [])), r))

    def profile_cpu(self) -> None:
        """Starts the CPU profile the experiment asks for, once per run, at the
        router with the most neighbors: where a busy router spends its time."""
        seconds = self.experiment.sampling.profile_s
        if not seconds or self.profiled:
            return
        self.profiled = self.busiest()
        try:
            self.routers.post(self.profiled, "/cpu", {"seconds": seconds}, timeout=STATUS_S)
        except LabError as e:
            log.warning("%s: no CPU profile of %s: %s", self.key, self.profiled, e)
            return
        log.info("%s: CPU profile of %s for %g s", self.key, self.profiled, seconds)

    def keep_cpu(self) -> None:
        """Keeps the CPU profile beside the run, as cpu-<router>.pb.gz."""
        import base64

        if not (router := self.profiled):
            return
        try:
            c = self.routers.get(router, "/cpu", timeout=STATUS_S)
        except LabError as e:
            log.warning("%s: no CPU profile of %s: %s", self.key, router, e)
            return
        if not c.get("profile"):
            log.warning("%s: no CPU profile of %s: %s", self.key, router, c.get("error") or "not taken yet")
            return
        self.spool.mkdir(parents=True, exist_ok=True)
        (self.spool / f"cpu-{router}.pb.gz").write_bytes(base64.b64decode(c["profile"]))
        log.info("%s: kept the CPU profile of %s", self.key, router)

    # The step engine

    def steps(self, steps: list[Step], position: tuple) -> None:
        for i, step in enumerate(steps):
            if self.stop.is_set():
                raise Cancelled
            self.step(step, position + (i,))

    def step(self, step: Step, position: tuple) -> None:
        self.current.position = position
        self.status.update(phase=step.kind.replace("_", " "))
        getattr(self, f"do_{step.kind}")(step.args, position)
        if step.kind in ANNOUNCING:
            self.watch_hops()
            self.profile_cpu()

    def watch_hops(self) -> None:
        """Above HOPS_MAX prefixes every router follows the next hops of the
        same sample, the prefixes of the lowest hashes, for loops and black
        holes on the way. A sample changes only when announcements do."""
        announced = self.announced()
        if len(announced) <= HOPS_MAX:
            return
        sample = sorted(announced, key=lambda p: (zlib.crc32(p.encode()), p))[:HOPS_MAX]
        if sample == getattr(self, "hops_sample", None):
            return
        at = self.sampler.now()
        for r in sorted(self.network.routers):  # a stopped router too: its controller runs on
            self.routers.post(r, "/hops/watch", {"prefixes": sample})
        self.hops_sample = sample
        self.event("hops_sample", at, prefixes=len(sample), of=len(announced))

    def random(self, position: tuple):
        return scenario.rng(self.experiment.seed, self.key.index, position)

    def event(self, name: str, at: float, **details) -> None:
        """Records an event at the time its action began, with the position of
        its step, which is the same in every variant."""
        step = ".".join(map(str, getattr(self.current, "position", ())))
        with self.lock:
            self.events.append({"name": name, "t": round(at, 3), "step": step, **details})
        log.info("%s: %6.1f s %s", self.key, at, " ".join(filter(None, (name.replace("_", " "), told(details)))))

    def wait(self, seconds: float) -> None:
        if self.stop.wait(max(0.0, seconds)):
            raise Cancelled

    def do_wait(self, seconds: float, position: tuple) -> None:
        self.wait(seconds)

    def do_parallel(self, steps: list[Step], position: tuple) -> None:
        with ThreadPoolExecutor(len(steps)) as pool:
            futures = [pool.submit(self.step, s, position + (j,)) for j, s in enumerate(steps)]
            try:
                for future in as_completed(futures):
                    future.result()
            except BaseException:
                self.stop.set()  # the others end at their next wait
                raise

    def do_repeat(self, r: scenario.Repeat, position: tuple) -> None:
        # The position leaves out the repetition, so random choices repeat as well.
        for _ in range(r.times):
            start = self.sampler.now()
            self.steps(r.steps, position + ("repeat",))
            self.wait(start + r.every - self.sampler.now())

    def do_until_stable(self, u: scenario.UntilStable, position: tuple) -> None:
        deadline = self.sampler.now() + u.timeout
        # A silent failure looks quiet until the hold timer detects it.
        if self.silent_since is not None:
            self.wait(min(deadline, self.silent_since + self.experiment.bgp.hold_time) - self.sampler.now())
            self.silent_since = None
        # Sessions that come back after a restart or up are quiet until the
        # connect retry; that is not stable yet.
        while not self.sessions_up() and self.sampler.now() < deadline:
            self.wait(0.5)
        stable = self.sampler.wait_quiet(self.experiment.quiet_s(self.key.variant), deadline - self.sampler.now(), self.stop)
        if self.stop.is_set():
            raise Cancelled
        self.measurements.append({"stable": stable, "t": round(self.sampler.now(), 3),
                                  "step": ".".join(map(str, position))})
        log.info("%s: %6.1f s %s", self.key, self.sampler.now(), "stable" if stable else f"not stable within {u.timeout:.0f} s")

    def sessions_up(self) -> bool:
        """Whether every session is established that no step took down."""
        down = {end for ends in self.failed.values() for end in ends} | {(b, a) for ends in self.failed.values() for a, b in ends}
        for router in self.network.routers:
            if router in self.stopped:
                continue
            try:
                sessions = self.routers.get(router, "/sessions", timeout=STATUS_S)
            except LabError:
                return False  # too busy to answer: not stable yet
            for neighbor, established in sessions.items():
                if not established and neighbor not in self.stopped and (router, neighbor) not in down:
                    return False
        return True

    # Prefixes

    def announced(self, of: set[str] | None = None) -> set[str]:
        """The distinct prefixes announced anywhere, which every router should
        hold, or only by the routers of."""
        announced = set()
        for r in (set(self.origins) | self.originated | self.announcers) & (of if of is not None else set(self.network.routers)):
            status = self.routers.get(r, "/noise", timeout=STATUS_S)
            announced |= set(status["prefixes"]) | set(status["originated"])
        for r, mine in self.injected.items():
            if of is None or r in of:
                announced |= mine
        return announced

    def prefixes(self) -> int:
        return len(self.announced())

    def do_announce(self, a: scenario.Announce, position: tuple) -> None:
        routers, _ = self.network.targets("announce", a, self.random(position))
        at = self.sampler.now()
        for i, r in enumerate(routers):
            self.routers.post(r, "/noise/start", {
                "block": i, "blocks": len(routers), "rate": a.rate / len(routers),
                "lifetime": a.lifetime, "jitter": a.jitter, "max_active": a.max_active,
                # Only those given, as older images do not know them.
                **{k: v for k, v in (("as_set", a.as_set), ("poison", a.poison), ("communities", a.communities)) if v},
            })
        self.event("announce", at, routers=routers)
        self.wait(at + a.for_ - self.sampler.now())
        at = self.sampler.now()
        for r in routers:
            self.routers.post(r, "/noise/pause")
        self.event("announced", at, routers=routers, expected=self.prefixes())

    def do_announce_real(self, a: scenario.AnnounceReal, position: tuple) -> None:
        random_ = self.random(position)
        routers, _ = self.network.targets("announce_real", a, random_)
        day = prefixes.date_of(self.topology["source"])
        own = prefixes.of({self.network.routers[r]["asn"] for r in routers}, day)
        chosen = {}
        for r in routers:
            if mine := own[self.network.routers[r]["asn"]]:
                chosen[r] = sorted(random_.sample(mine, min(a.per_router, len(mine))))
        if not chosen:
            raise LabError(f"none of the routers announces a prefix on the Internet on {day}")
        self.load(chosen, a.rate, source=f"routeviews-prefix2as/{day}")

    def load(self, chosen: dict[str, list[str]], rate: float, **details) -> None:
        """Announces real prefixes at their routers, at a rate over all of
        them, and waits until every router announced its own."""
        total = sum(len(p) for p in chosen.values())
        self.check_memory(total)
        rate /= len(chosen)
        at = self.sampler.now()
        for r, mine in chosen.items():
            self.routers.post(r, "/noise/load", {"prefixes": mine, "rate": rate})
            self.announcers.add(r)
        self.event("announce", at, routers=sorted(chosen), prefixes=total, **details)
        # With time to spare: routers busy with large tables announce slower
        # than the rate, and 100 prefixes per router took close to a minute.
        deadline = at + max(map(len, chosen.values())) / rate * 4 + 120
        while not self.loaded(chosen):
            if self.sampler.now() > deadline:
                raise LabError("routers did not announce their prefixes in time")
            self.wait(1)
        self.event("announced", self.sampler.now(), routers=sorted(chosen), expected=self.prefixes())

    def loaded(self, chosen: dict[str, list[str]]) -> bool:
        """Whether every router announces its prefixes. A router busy with
        many routes may answer late: then it is not done yet."""
        for r, mine in chosen.items():
            try:
                if self.routers.get(r, "/noise", timeout=STATUS_S)["active"] < len(mine):
                    return False
            except LabError:
                return False
        return True

    def do_replay(self, r: scenario.Replay, position: tuple) -> None:
        """Real prefixes of the routers appear and vanish as a vantage point of
        RIS saw them in a window of time. The prefixes that changed in it
        come first; at the start, those of the day announce."""
        replay = mrt.events(r.collector, r.start, r.minutes)
        asn = {cfg["asn"]: name for name, cfg in self.network.routers.items()}
        day = replay["start"][:10].replace("-", "")
        own = prefixes.of(set(asn), day)
        changed: dict[str, list[str]] = {}
        for _, prefix, origin in replay["changes"]:
            if origin in asn and prefix not in changed.setdefault(asn[origin], []):
                changed[asn[origin]].append(prefix)
        chosen: dict[str, list[str]] = {}
        for a, router in asn.items():
            mine = changed.get(router, [])[:r.per_router]
            mine += [p for p in own[a] if p not in mine][:r.per_router - len(mine)]
            if mine:
                chosen[router] = mine
        if not chosen:
            raise LabError(f"none of the routers announced a prefix on the Internet on {day}")
        wanted = {p for mine in chosen.values() for p in mine}
        self.check_memory(len(wanted))
        # At the start, the prefixes of the day; those new in the window come with it.
        initial = {router: [p for p in mine if p in own[self.network.routers[router]["asn"]]] for router, mine in chosen.items()}
        initial = {router: mine for router, mine in initial.items() if mine}
        if initial:
            self.load(initial, 100, source=f"routeviews-prefix2as/{day}")
        holder = {p: router for router, mine in initial.items() for p in mine}
        at = self.sampler.now()
        steps = [(t, p, o) for t, p, o in replay["changes"] if p in wanted]
        self.event("replay", at, collector=r.collector, vantage=replay["vantage"], window=replay["start"],
                   minutes=r.minutes, speed=r.speed, changes=len(steps))
        i = 0
        while i < len(steps):
            self.wait(at + steps[i][0] / r.speed - self.sampler.now())
            # Everything due by now, in one request per router, so that the
            # replay keeps its pace however many prefixes change at once.
            due = (self.sampler.now() - at) * r.speed
            gone, came = defaultdict(list), defaultdict(list)
            while i < len(steps) and steps[i][0] <= due:
                _, prefix, origin = steps[i]
                i += 1
                new = asn.get(origin)  # None: gone, or from an AS outside of the topology
                old = holder.pop(prefix, None)
                if old == new:
                    if old:
                        holder[prefix] = old
                    continue
                if old:
                    gone[old].append(prefix)
                    if prefix in came[old]:
                        came[old].remove(prefix)
                if new:
                    came[new].append(prefix)
                    holder[prefix] = new
            for router, prefixes_ in gone.items():
                self.routers.post(router, "/noise/withdraw", {"prefixes": prefixes_})
            for router, prefixes_ in came.items():
                if prefixes_:
                    self.routers.post(router, "/noise/load", {"prefixes": prefixes_, "rate": 1000})
                    self.announcers.add(router)
        self.wait(at + r.minutes * 60 / r.speed - self.sampler.now())
        self.event("replayed", self.sampler.now(), expected=self.prefixes())

    def do_announce_rib(self, a: scenario.AnnounceRib, position: tuple) -> None:
        """Routers inject the table their AS had on the Internet, as a peer of
        a RIS collector saw it, the default-free zone. Prefixes from more than
        one router give the others alternative paths."""
        routers, _ = self.network.targets("announce_rib", a, self.random(position))
        asn = {self.network.routers[r]["asn"]: r for r in routers}
        when, files = rib.tables(a.collector, a.at, set(asn))
        if not files:
            raise LabError(f"none of the ASes of {', '.join(routers)} peers with {a.collector}: no table to inject")
        injecting = [r for r in routers if self.network.routers[r]["asn"] in files][:a.at_most]
        tables = {r: rib.read(files[self.network.routers[r]["asn"]]) for r in injecting}
        chosen = rib.pick(set().union(*tables.values()), a.prefixes, self.experiment.seed * 1000 + self.key.index)
        self.check_memory(len(chosen), senders=len(tables))
        at = self.sampler.now()
        for r, table in tables.items():
            lines = "".join(f"{p} {o} {' '.join(map(str, path))}\n" for p, (o, path) in table.items() if p in chosen)
            self.routers.post(r, "/rib/load", gzip.compress(lines.encode(), 3), timeout=300)
            self.injected[r] = chosen & table.keys()
        self.event("announce_rib", at, routers=sorted(tables), prefixes=len(chosen), collector=a.collector,
                   table=f"{when:%Y-%m-%d %H:%M}")
        while True:
            states = {r: self.routers.get(r, "/rib", timeout=STATUS_S) for r in tables}
            if failed := {r: s["error"] for r, s in states.items() if s["error"]}:
                raise LabError(f"routers did not inject their table: {failed}")
            if all(s["done"] for s in states.values()):
                break
            if self.sampler.now() > at + a.timeout:
                raise LabError(f"routers did not inject their table in {a.timeout:.0f} s")
            self.wait(5)
        self.event("announced", self.sampler.now(), routers=sorted(tables), expected=self.prefixes())

    def do_withdraw_rib(self, w: scenario.WithdrawRib, position: tuple) -> None:
        routers, _ = self.network.targets("withdraw_rib", w, self.random(position))
        at = self.sampler.now()
        for r in [r for r in routers if r in self.injected]:
            self.routers.post(r, "/rib/clear", timeout=600)
            del self.injected[r]
        self.event("withdraw", at, routers=routers, percent=100, expected=self.prefixes())

    def check_memory(self, prefixes: int, senders: int | None = None) -> None:
        """Refuses prefixes that would take more memory than a router may use,
        or than the cluster has: a router holds up to one path per prefix and
        neighbor, or, for full tables injected at `senders` routers, from at
        most that many and its own."""
        need = {r: router_mb(cfg, prefixes, senders) for r, cfg in self.network.routers.items()}
        router, most = max(need.items(), key=lambda x: x[1])
        if most > self.experiment.cluster.router_limit_mb:
            raise LabError(f"{prefixes} prefixes would take about {most:.0f} MB at {router}, more than the "
                           f"{self.experiment.cluster.router_limit_mb} MiB a router may use. Announce fewer per router.")
        if (total := Resources.SYSTEM_MB + sum(need.values())) > self.cluster.resources.memory_mb:
            raise LabError(f"{prefixes} prefixes would take about {total:,.0f} MB, more than the "
                           f"{self.cluster.resources.memory_mb:,} MiB of the cluster. Announce fewer per router.")

    def do_withdraw(self, w: scenario.Withdraw, position: tuple) -> None:
        at = self.sampler.now()
        routers, _ = self.network.targets("withdraw", w, self.random(position))
        for r in routers:
            self.routers.post(r, "/noise/drain", {"percent": w.percent})
            if r in self.originated:
                self.routers.post(r, "/originate/clear")
        self.event("withdraw", at, routers=routers, percent=w.percent, expected=self.prefixes())

    def do_originate(self, o: scenario.Originate, position: tuple) -> None:
        random_ = self.random(position)
        routers, _ = self.network.targets("originate", o, random_)
        pool = sorted({p for r in self.network.routers_of(o.like, random_) for p in self.routers.get(r, "/noise", timeout=STATUS_S)["prefixes"]})
        prefixes = sorted(random_.sample(pool, min(o.count, len(pool))))
        at = self.sampler.now()
        for r in routers:
            self.routers.post(r, "/originate", {"prefixes": prefixes, "more_specific": o.more_specific})
            self.originated.add(r)
        self.event("originate", at, routers=routers, prefixes=prefixes, more_specific=o.more_specific, expected=self.prefixes())

    # Failures

    def links_of(self, router: str) -> list[tuple[str, str]]:
        return [tuple(sorted((router, n["name"]))) for n in self.network.routers[router].get("neighbors", [])]

    def fail_link(self, a: str, b: str, mode: str) -> None:
        # session: one end closes the session with a notification.
        # cut: both ends silently drop the other's packets.
        # oneway: only b drops the packets from a.
        ends = {"session": [(a, b)], "cut": [(a, b), (b, a)], "oneway": [(b, a)]}[mode]
        for router, peer in ends:
            self.routers.post(router, f"/peers/{peer}/down", {"mode": mode})
        self.failed.setdefault((a, b), []).extend(ends)

    def do_down(self, d: scenario.Down, position: tuple) -> None:
        at = self.sampler.now()
        routers, links = self.network.targets("down", d, self.random(position))
        for r in routers:
            if d.mode == "session":  # the router stops, its peers see the sessions close
                self.sampler.pause(r)
                self.routers.post(r, "/daemon/stop")
                self.stopped.add(r)
            else:                    # the router is isolated silently
                links += self.links_of(r)
        for a, b in sorted(set(links)):
            self.fail_link(a, b, d.mode)
        if d.mode != "session":
            self.silent_since = self.sampler.now()
        self.event("down", at, routers=routers, links=sorted(set(links)), mode=d.mode)

    def do_degrade(self, d: scenario.Degrade, position: tuple) -> None:
        at = self.sampler.now()
        routers, links = self.network.targets("degrade", d, self.random(position))
        links = sorted(set(links + [link for r in routers for link in self.links_of(r)]))
        body = {"delay_ms": d.delay_ms, "jitter_ms": d.jitter_ms, "loss_pct": d.loss_pct}
        for a, b in links:
            for router, peer in ((a, b), (b, a)):
                self.routers.post(router, f"/peers/{peer}/degrade", body)
            self.failed.setdefault((a, b), []).extend([(a, b), (b, a)])
        self.event("degrade", at, links=links, **body)

    def do_up(self, u: scenario.Up, position: tuple) -> None:
        at = self.sampler.now()
        routers, links = self.network.targets("up", u, self.random(position))
        if not routers and not links:  # everything
            routers, links = sorted(self.stopped), sorted(self.failed)
        else:
            links = sorted(set(links + [link for r in routers for link in self.links_of(r)]))
        restored = []
        for link in links:
            for router, peer in sorted(set(self.failed.pop(link, []))):
                self.routers.post(router, f"/peers/{peer}/up")
                restored.append(link)
        for r in routers:
            if r in self.stopped:
                self.routers.post(r, "/daemon/start")
                self.sampler.resume(r)
                self.stopped.discard(r)
        self.event("up", at, routers=list(routers), links=sorted(set(restored)))

    def do_restart(self, r: scenario.Restart, position: tuple) -> None:
        at = self.sampler.now()
        routers, _ = self.network.targets("restart", r, self.random(position))
        for router in routers:
            self.sampler.pause(router)
            self.routers.post(router, "/daemon/restart", {"graceful": r.graceful})
            self.sampler.resume(router)
        self.event("restart", at, routers=routers, graceful=r.graceful)

    # Policies

    def do_set_preference(self, p: scenario.SetPreference, position: tuple) -> None:
        at = self.sampler.now()
        [router], [(_, neighbor)] = self.network.targets("set_preference", p, self.random(position))
        self.routers.post(router, "/policy/preference", {"neighbor": neighbor, "value": p.value})
        self.event("set_preference", at, routers=[router], neighbor=neighbor, value=p.value)

    def do_prepend(self, p: scenario.Prepend, position: tuple) -> None:
        at = self.sampler.now()
        routers, links = self.network.targets("prepend", p, self.random(position))
        if links:
            [(router, neighbor)] = links
            self.routers.post(router, "/policy/prepend", {"times": p.times, "neighbor": neighbor})
            self.event("prepend", at, routers=[router], neighbor=neighbor, times=p.times)
            return
        for r in routers:
            self.routers.post(r, "/policy/prepend", {"times": p.times})
        self.event("prepend", at, routers=routers, times=p.times)

    def do_set_export(self, p: scenario.SetExport, position: tuple) -> None:
        at = self.sampler.now()
        [router], [(_, neighbor)] = self.network.targets("set_export", p, self.random(position))
        self.routers.post(router, "/policy/export", {"neighbor": neighbor, "allow": p.allow})
        self.event("set_export", at, routers=[router], neighbor=neighbor, allow=p.allow, outside_model=True)

    def do_set_import(self, p: scenario.SetImport, position: tuple) -> None:
        at = self.sampler.now()
        [router], [(_, neighbor)] = self.network.targets("set_import", p, self.random(position))
        self.routers.post(router, "/policy/import", {"neighbor": neighbor, "allow": p.allow})
        self.event("set_import", at, routers=[router], neighbor=neighbor, allow=p.allow, outside_model=True)

    def do_igp(self, g: scenario.Igp, position: tuple) -> None:
        """No IGP runs: the new cost changes the forwarding check, no route."""
        at = self.sampler.now()
        _, [(a, b)] = self.network.targets("igp", g, self.random(position))
        self.igp[frozenset((a, b))] = g.cost
        self.event("igp", at, routers=[a, b], link=f"{a}-{b}", cost=g.cost)

    def do_soft_reset(self, s: scenario.SoftReset, position: tuple) -> None:
        at = self.sampler.now()
        routers, _ = self.network.targets("soft_reset", s, self.random(position))
        for r in routers:
            self.routers.post(r, "/bgp/soft-reset", {"direction": s.direction})
        self.event("soft_reset", at, routers=routers, direction=s.direction)

    # Checks

    def final(self) -> None:
        """What every run checks at its end, whatever its scenario checks,
        once the routes stand still, waiting at most a bounded time: how
        many announced prefixes each router holds, how many it still holds
        that are withdrawn, and which prefixes loop or end at a router
        without a route. stable says whether the routes stood still. A
        stopped router holds nothing. The analysis compares the routes with
        the BGP run of the same seed."""
        quiet = self.experiment.quiet_s(self.key.variant)
        stable = self.sampler.wait_quiet(quiet, max(60.0, 3 * quiet), self.stop)
        if self.stop.is_set():
            raise Cancelled
        at, announced = self.sampler.now(), self.announced()
        if len(announced) > FINAL_PREFIXES:
            self.event("final", at, stable=stable, prefixes=len(announced), skipped=f"more than {FINAL_PREFIXES} prefixes")
            return
        try:
            tables, slowest = self.final_tables()
        except LabError as e:  # a router that never answers: the run stands, its final check does not
            self.event("final", at, stable=stable, prefixes=len(announced), skipped=f"no routes: {e}")
            return
        # Every prefix announced or still held: a withdrawn route that stays may loop too.
        prefixes = announced | {p for t in tables.values() for p in t}
        problems = check_forwarding(forwarding.with_igp(self.network.routers, self.igp), prefixes, tables, self.cluster.addresses(), sorted(tables))
        looping = sorted({p.split(": ", 1)[0] for p in problems if "forwarding loops" in p})
        holes = sorted({p.split(": ", 1)[0] for p in problems if "without a route" in p})
        # Policy at rest: chosen paths that break the relations between the ASes.
        between = forwarding.relations(self.network.routers)
        valleys = {r: sum(not route.get("as_set") and forwarding.valley_free(between, int(self.network.routers[r]["asn"]), route["as_path"]) is False
                          for p, route in t.items() if p in announced) for r, t in tables.items()} if between else {}
        self.event("final", at, stable=stable, prefixes=len(announced), slowest=slowest,
                   valleys={r: n for r, n in valleys.items() if n},
                   held={r: len(announced & set(t)) for r, t in tables.items()},
                   stale={r: len(set(t) - announced) for r, t in tables.items()},
                   loops=len(looping), holes=len(holes), looping=looping, holed=holes, problems=problems[:10])

    def final_tables(self) -> tuple[dict[str, dict], list]:
        """The routes of every router for the final check, read in parallel,
        each router asked up to FINAL_TRIES times with FINAL_S to answer. A
        stopped router holds nothing. Also the slowest router and its
        seconds. Raises LabError when a router never answers."""
        def read(r: str) -> tuple[dict, float]:
            started = time.monotonic()
            for _ in range(FINAL_TRIES - 1):
                try:
                    return self.routers.get(r, "/routes", timeout=FINAL_S), time.monotonic() - started
                except LabError:
                    pass
            return self.routers.get(r, "/routes", timeout=FINAL_S), time.monotonic() - started

        names = [r for r in sorted(self.network.routers) if r not in self.stopped]
        tables: dict[str, dict] = {r: {} for r in self.stopped if r in self.network.routers}
        slowest = ["", 0.0]
        if names:
            with ThreadPoolExecutor(min(len(names), Routers.POOL)) as pool:
                for r, (table, took) in zip(names, pool.map(read, names)):
                    tables[r] = table
                    if took >= slowest[1]:
                        slowest = [r, round(took, 1)]
        return dict(sorted(tables.items())), slowest

    def do_expect(self, e: scenario.Expect, position: tuple) -> None:
        at = self.sampler.now()
        routers, _ = self.network.targets("expect", e, self.random(position))
        names = sorted(self.network.routers) if e.forwarding else routers  # a packet may pass any router
        tables = {r: self.routers.get(r, "/routes", timeout=STATUS_S) for r in names}
        of = set(self.network.routers_of(e.of, self.random(position))) if e.of else None
        problems = check_routes(e, self.announced(of), {r: tables[r] for r in routers},
                                self.network.routers[e.avoid]["asn"] if e.avoid else None)
        if e.forwarding:
            problems += check_forwarding(forwarding.with_igp(self.network.routers, self.igp), self.announced(), tables, self.cluster.addresses(), routers)
        if e.consistent and not self.variant.per_neighbor:  # a table per neighbor sends each its own path
            sent = {r: self.routers.get(r, "/advertised", timeout=STATUS_S) for r in sorted(self.network.routers)}
            problems += check_consistency(self.network.routers, self.announced(), sent)
        # A check the scenario allows this mode to fail does not fail the run.
        allowed = bool(problems and e.may_fail) and modes.may_fail(e.may_fail, self.variant.mode, self.variant.per_neighbor)
        self.event("expect", at, routers=routers, passed=not problems, problems=problems[:10],
                   **({"allowed": True} if allowed else {}), **e.model_dump(exclude={"router", "may_fail"}, exclude_none=True))


def check_routes(e: scenario.Expect, announced: set[str], routes: dict[str, dict], avoid_asn: int | None) -> list[str]:
    """What contradicts an expect step: routes of each router as /routes gives them."""
    problems = []
    for router, table in sorted(routes.items()):
        held = announced & set(table)
        if e.prefixes == "all" and (missing := announced - held):
            problems.append(f"{router} misses {len(missing)} of {len(announced)} prefixes")
        # Every route counts: a withdrawn one no longer announced is held as well, as the final check counts it.
        if e.prefixes == "none" and table:
            problems.append(f"{router} holds {len(table)} prefixes")
        if e.via and (other := sorted({table[p]["from"] or "itself" for p in held} - {e.via})):
            problems.append(f"{router} routes via {', '.join(other)}, not only {e.via}")
        if avoid_asn is not None and (through := [p for p in held if int(avoid_asn) in table[p]["as_path"]]):
            problems.append(f"{router} routes {len(through)} prefixes through {e.avoid}")
    return problems


def check_forwarding(topology: dict, announced: set[str], tables: dict[str, dict], addresses: dict[str, str],
                     starts: list[str]) -> list[str]:
    """Where packets to each announced prefix go from the starts, by the next
    hops of the best routes, as the simulator checks it: lab.forwarding."""
    def hop(router: str, route: dict) -> str | None:
        if route["from"] is None and not route["as_path"]:
            return router  # it announces the prefix itself
        return addresses.get(route.get("next_hop") or "") or route["from"]

    problems = []
    for prefix in sorted(announced):
        hops = {}
        for router, table in tables.items():
            route = table.get(prefix)
            if route is None:
                hops[router] = None
            elif "ingress" in route:  # a table per neighbor: per eBGP neighbor, the route sent to it
                hops[router] = forwarding.Ingress({n: (hop(router, r), (r["as_path"] or [None])[0])
                                                  for n, r in [(None, route), *route["ingress"].items()]})
            else:
                hops[router] = hop(router, route)
        problems += [f"{prefix}: {p}" for p in forwarding.check(topology, hops, starts)]
    return problems


def check_consistency(topology: dict, announced: set[str], sent: dict[str, dict]) -> list[str]:
    """ASes whose routers send their neighbors in other ASes different paths
    to an announced prefix, the own AS and its prepends taken off: as the
    simulator checks it (exportConsistency in internal/pkg/obgpsim)."""
    problems = []
    for prefix in sorted(announced):
        offered: dict[str, set] = {}
        for router, neighbors in sent.items():
            own = int(topology[router]["asn"])
            mine = {own, topology[router].get("confederation")}  # inside its confederation the member AS shows, outside the confederation
            for paths in neighbors.values():
                if (path := paths.get(prefix)) is not None:
                    while path and path[0] in mine:
                        path = path[1:]
                    offered.setdefault(str(own), set()).add(tuple(path))
        problems += [f"{prefix}: AS {asn} offers {len(paths)} different paths" for asn, paths in sorted(offered.items()) if len(paths) > 1]
    return problems


def fetch_interval(routers: int, fetch: float, rate: float) -> float:
    """Seconds between the fetches of the samples of all routers."""
    return max(fetch, routers / rate)


class Sampler(threading.Thread):
    """Collects the samples that every router takes of itself.

    The routers sample at t0 + k * interval on their own clock, corrected
    by its measured offset, so all routers sample at the same times. This
    thread fetches the new samples every FETCH seconds, joins them by time
    and tracks since when nothing changes, for until_stable and the live
    view. The fetches go through the API server: beyond 100 routers they
    come less often, at most RATE a second, beyond LARGE routers at most
    RATE_LARGE, which spares the API of a node full of routers. The samples
    keep their times, so the resolution stays two sampling intervals: only
    the live view and until_stable see them later.
    """

    FETCH = 0.5
    RATE = 200  # fetches a second at most, 100 routers every FETCH
    LARGE, RATE_LARGE = 64, 50

    def __init__(self, routers: Routers, watched: list[str], interval: float,
                 on_tick: Callable[[float, dict], None] | None = None, spool: Path | None = None) -> None:
        super().__init__(daemon=True)
        self.routers = routers
        self.watched = watched
        self.interval = interval
        self.fetch_s = fetch_interval(len(watched), self.FETCH, self.RATE if len(watched) <= self.LARGE else self.RATE_LARGE)
        self.on_tick = on_tick
        # The samples wait on disk, a file per router in the order they came,
        # until rows() merges them: a long run on many routers takes millions.
        if spool:
            spool.mkdir(parents=True, exist_ok=True)
        self.spool = Path(tempfile.mkdtemp(prefix=".samples-", dir=spool))
        self.files = {r: open(self.spool / f"{i}.csv", "w+", newline="") for i, r in enumerate(watched)}
        self.writers = {r: csv.writer(f) for r, f in self.files.items()}
        self.peak_mb: dict[str, float] = {}  # the most resident memory of each router so far
        self.count = 0
        self.latest: dict[str, dict] = {}
        self.paused: set[str] = set()  # stopped routers, which do not sample
        self.seq = {r: 0 for r in watched}
        self.reached: dict[str, float] = {}
        self.pending: dict[float, dict[str, dict]] = {}
        self.ahead: dict[str, deque] = {r: deque() for r in watched}  # each router's samples after its current one
        self.last_t: float | None = None
        self.quiet_since: float | None = None
        self.answered: dict[str, float] = {}  # when each router last handed over its samples
        self.current: dict[str, dict] = {}  # the latest sample of each router, up to the horizon
        self.failures: dict[str, int] = {}
        self.stopped = threading.Event()
        self.error: Exception | None = None  # what ended the thread early
        self.tick = threading.Condition()
        self.pool = ThreadPoolExecutor(min(len(watched), Routers.POOL))
        self.t0 = time.time()

    def now(self) -> float:
        return time.time() - self.t0

    def pause(self, router: str) -> None:
        self.paused.add(router)

    def resume(self, router: str) -> None:
        self.paused.discard(router)
        with self.tick:
            self.current.pop(router, None)  # its last sample is from before it stopped

    def start(self) -> None:
        try:
            offsets = dict(zip(self.watched, self.pool.map(self._offset, self.watched)))
            self.t0 = time.time() + 1.0
            for router, offset in offsets.items():
                self.routers.post(router, "/samples/start", {"t0": self.t0 + offset, "interval": self.interval})
        except BaseException:
            self.pool.shutdown(wait=False, cancel_futures=True)
            raise
        time.sleep(max(0.0, -self.now()))
        super().start()

    def _offset(self, router: str) -> float:
        """How far the clock of a router is ahead, from the fastest of a few requests."""
        best = None
        for _ in range(3):
            sent = time.time()
            remote = self.routers.get(router, "/time")["now"]
            received = time.time()
            if best is None or received - sent < best[0]:
                best = (received - sent, remote - (sent + received) / 2)
        return best[1]

    def run(self) -> None:
        try:
            while not self.stopped.wait(self.fetch_s):
                self.fetch()
        except Exception as e:  # e.g. a full disk for the live view: the run fails, not silently times out
            self.error = e
            self.stopped.set()
            with self.tick:
                self.tick.notify_all()

    def fetch(self) -> None:
        now = time.monotonic()
        for router, data in zip(self.watched, self.pool.map(self._fetch, self.watched)):
            if data is None:
                # Nothing is lost: the next fetch takes what the controller
                # kept. A router silent for long is down, not busy.
                if router not in self.paused and now - self.answered.setdefault(router, now) > SILENT_S:
                    raise LabError(f"{router} did not hand over its samples for {SILENT_S} s")
                continue
            self.answered[router] = now
            self.failures[router] = data["failures"]
            for row in data["samples"]:
                self.seq[router] = row.pop("seq")
                row["router"] = router
                self.writers[router].writerow([row.get(f) for f in SAMPLE_FIELDS])
                if isinstance(mb := row.get("rss_mb"), (int, float)):
                    self.peak_mb[router] = max(mb, self.peak_mb.get(router, 0.0))
                self.count += 1
                self.pending.setdefault(row["t"], {})[router] = row
                self.ahead[router].append(row)
                self.reached[router] = row["t"]
        active = [r for r in self.watched if r not in self.paused]
        if not active or any(r not in self.reached for r in active):
            return
        horizon = min(self.reached[r] for r in active)
        with self.tick:
            for t in sorted(t for t in self.pending if t <= horizon):
                # Busy routers skip times of their own: each stands by its latest
                # sample, as in analysis.ticks, while recent or until a next one
                # that shows no change. Every router has one up to the horizon.
                for router, row in self.pending.pop(t).items():
                    self.current[router] = row
                    self.ahead[router].popleft()
                if any(r not in self.current or not analysis.stands(self.current[r], self.ahead[r][0] if self.ahead[r] else None, t)
                       for r in active):
                    continue
                latest = {r: self.current[r] for r in active}
                unchanged = self.latest.keys() == latest.keys() and all(
                    all(self.latest[r].get(k) == s.get(k) for k in COUNTERS) for r, s in latest.items())
                if not unchanged:
                    self.quiet_since = t
                self.latest, self.last_t = latest, t
            self.tick.notify_all()
        if self.on_tick and self.latest:
            self.on_tick(self.last_t, self.latest)

    def _fetch(self, router: str) -> dict | None:
        try:
            return self.routers.get(router, f"/samples?after={self.seq[router]}", timeout=5)
        except LabError:
            return None

    def stop(self) -> None:
        """Ends the sampling of the routers and collects the last samples;
        a LabError if the sampling failed on the way."""
        def end(router: str) -> None:
            try:
                self.routers.post(router, "/samples/stop", timeout=5)
            except LabError:
                pass
        try:
            list(self.pool.map(end, self.watched))
            self.stopped.set()
            if self.is_alive():
                self.join()
            if not self.error:
                self.fetch()
        finally:
            self.pool.shutdown(cancel_futures=True)
        for f in self.files.values():
            f.flush()
        if self.error:
            raise LabError(f"sampling failed: {self.error}")

    def rows(self) -> Iterator[dict]:
        """The samples of all routers by time, then router, merged from the
        spool as they are written, so that they never are all in memory."""
        readers = []
        for f in self.files.values():
            f.seek(0)
            readers.append(csv.reader(f))
        try:
            for row in heapq.merge(*readers, key=lambda r: (float(r[0]), r[1])):
                yield dict(zip(SAMPLE_FIELDS, row))
        finally:
            for f in self.files.values():
                f.close()

    @property
    def failed(self) -> int:
        """Samples the controllers could not take: what a fetch missed comes with the next one."""
        return sum(self.failures.values())

    def wait_quiet(self, seconds: float, timeout: float, stop: threading.Event) -> bool:
        """Waits until no router has changed its counters for `seconds`, counted from now at the earliest."""
        start = self.now()
        deadline = start + timeout
        with self.tick:
            while not stop.is_set():
                if self.error:
                    raise LabError(f"sampling failed: {self.error}")
                if self.quiet_since is not None and self.last_t - max(self.quiet_since, start) >= seconds:
                    return True
                if self.now() >= deadline:
                    return False
                self.tick.wait(timeout=self.fetch_s)
        return False
