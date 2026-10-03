"""Executes the runs of a dataset.

Every run deploys a fresh topology and plays its scenario step by step.
Infrastructure failures are retried; the outcome of a run, including a
timeout, is always kept. A dataset can be resumed at any time: finished
runs are skipped.
"""

import gzip
import logging
import os
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import mean

from . import analysis, host, mrt, prefixes, rib, scenario
from .cluster import Cluster, Interrupted, LabError, Routers, fitted, limit, oversized
from .config import Cluster as Resources
from .config import Experiment
from .results import COUNTERS, Dataset, RunKey, now
from .scenario import Network, Step

log = logging.getLogger("lab")
ATTEMPTS = 3


class Cancelled(Exception):
    pass


SILENT_S = 30  # a router that hands over no samples this long fails the run
STATUS_S = 15  # for the prefixes or sessions of a router, which may be busy with many routes


class HostLoad(threading.Thread):
    """How busy the host is while a run plays, in all and by others. All
    routers share one host: when it is saturated, the run measures the host,
    not the protocol, and on a shared host others weigh on it as well."""

    def __init__(self, interval: float = 1.0) -> None:
        super().__init__(daemon=True)
        self.interval, self.done, self.shares, self.others = interval, threading.Event(), [], []

    def run(self) -> None:
        meter = host.Meter()
        while not self.done.wait(self.interval):
            m = meter.read()
            if m["busy"] is not None:
                self.shares.append(m["busy"])
            if m["others"] is not None:
                self.others.append(m["others"])

    def stop(self) -> None:
        self.done.set()

    def summary(self) -> dict:
        shares = self.shares or [0.0]
        out = {"cpu_mean": round(mean(shares), 3), "cpu_max": round(max(shares), 3), "cpus": os.cpu_count()}
        if self.others:
            out.update(others_mean=round(mean(self.others), 3), others_min=round(min(self.others), 3),
                       others_max=round(max(self.others), 3))
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
    if skipped := oversized(experiment):
        log.warning("skipped on this host: %s", "; ".join(f"{t}, {', '.join(why)}" for t, why in skipped.items()))
        keys = [k for k in keys if k.topology not in skipped]
    status = Status(dataset, total=len(keys), done=sum(map(dataset.is_done, keys)))
    status.update(skipped=skipped, limit=limit(experiment) if skipped else None)
    if status.data["done"] == len(keys):
        status.update(state="finished")
        return
    cluster = Cluster(fitted(experiment.cluster))
    routers = None
    try:
        status.update(phase="starting cluster")
        dataset.update(cluster=cluster.start())
        tags = {}
        for v in experiment.variants:
            status.update(phase=f"building {v.name} ({dataset.commits[v.name][:12]})")
            tags[v.name] = cluster.build(dataset.commits[v.name])
            log.info("image of %s at %s: %s", v.name, dataset.commits[v.name][:12], tags[v.name])
        cluster.prune(keep=set(tags.values()))
        if "versions" not in dataset.meta:
            dataset.update(versions=cluster.versions())
        routers = Routers()
        for key in keys:
            if dataset.is_done(key):
                continue
            if stop.is_set():
                raise Cancelled
            status.update(current=str(key), run_started=now(), phase="waiting for the run before to settle")
            if (busy := quiet_host(stop, cluster.resources.cpus)) is not None:
                log.info("%s: the lab or host is still %.0f %% busy, starting anyway", key, 100 * busy)
            started = time.monotonic()
            for attempt in range(1, ATTEMPTS + 1):
                try:
                    routers.ensure()
                    result, samples = Run(dataset, key, cluster, routers, tags[key.variant], status, stop).execute()
                    break
                except LabError as e:
                    log.warning("%s: attempt %d failed: %s", key, attempt, e)
                    result, samples = {"status": "error", "message": str(e)}, []
            took = time.monotonic() - started
            result.update(commit=dataset.commits[key.variant], image=tags[key.variant], attempts=attempt, took_s=round(took, 1))
            dataset.write_run(key, result, samples)
            if result["status"] != "error":
                try:  # ready for the charts at once
                    analysis.run_bins(dataset, key, result)
                except Exception as error:
                    log.warning("%s: no series yet: %s", key, error)
            log.info("%s: %s after %.0f s", key, result["status"], took)
            status.finished(error=result["status"] == "error")
        status.update(state="finished", current=None, run_started=None, phase=None)
    except (Cancelled, Interrupted):
        status.update(state="stopped", phase=None)
    except Exception as e:
        status.update(state="failed", phase=None, error=str(e))
        raise
    finally:
        if routers:
            routers.close()
        try:
            cluster.undeploy()
        except Exception:
            pass


class Status:
    """Progress of a running dataset, written to status.json."""

    def __init__(self, dataset: Dataset, total: int, done: int) -> None:
        self.dataset = dataset
        self.samples: deque = deque(maxlen=300)
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
        """Records the router means of the current run for live monitoring."""
        self.samples.append({"t": round(t, 1), **{m: round(mean(s[m] for s in latest.values()), 2) for m in COUNTERS}})
        self.update(live=list(self.samples))

    def finished(self, error: bool) -> None:
        self.update(done=self.data["done"] + 1, errors=self.data["errors"] + error)


class Run:
    """One run: deploy the topology, play the scenario, collect the samples."""

    def __init__(self, dataset: Dataset, key: RunKey, cluster: Cluster, routers: Routers, tag: str,
                 status: Status, stop: threading.Event) -> None:
        self.experiment: Experiment = dataset.experiment
        self.key = key
        self.cluster = cluster
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
        self.status.update(phase="deploying", live=[])
        deploying = time.monotonic()
        self.modes = self.variant.modes_of(self.topology["routers"], seed)
        self.cluster.deploy(self.key.topology, self.topology, self.tag, self.modes, seed, self.experiment.bgp)
        self.routers.pods = self.cluster.pods()
        log.info("%s: deployed in %.0f s, seed %d", self.key, time.monotonic() - deploying, seed)
        watched = [r for r in self.network.routers if r not in self.origins]
        self.sampler = Sampler(self.routers, watched, self.experiment.sampling.interval, self.status.live)
        started = now()
        load = HostLoad()
        load.start()
        self.sampler.start()
        try:
            self.steps(self.scenario.steps, ())
        except BaseException:
            load.stop()
            try:
                self.sampler.stop()
            except LabError:
                pass  # the first problem is the one to report, e.g. a Stop
            raise
        self.sampler.stop()
        load.stop()
        if self.sampler.failed > 0.05 * max(1, len(self.sampler.samples)):
            raise LabError(f"{self.sampler.failed} samples failed")
        restarts, oom = self.cluster.restarts()
        if oom:
            raise LabError(f"{', '.join(oom)} took more than {self.experiment.cluster.router_limit_mb} MB and restarted")
        if restarts:
            raise LabError(f"routers restarted {restarts} times")
        return {
            # A failed check outweighs a timeout: the routes were wrong.
            "status": "failed" if any(e["name"] == "expect" and not e["passed"] for e in self.events)
                      else "timeout" if any(not m["stable"] for m in self.measurements) else "completed",
            "started": started,
            "duration_s": round(self.sampler.now(), 3),
            "seed": seed,
            "watched": watched,
            # In the order of their start; parallel steps record them as they end.
            "events": sorted(self.events, key=lambda e: e["t"]),
            "measurements": self.measurements,
            "host": load.summary(),
            # Which router ran which mode, where they differ.
            **({"modes": self.modes} if self.variant.mixed else {}),
        }, self.sampler.samples

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

    def random(self, position: tuple):
        return scenario.rng(self.experiment.seed, self.key.index, position)

    def event(self, name: str, at: float, **details) -> None:
        """Records an event at the time its action began, with the position of
        its step, which is the same in every variant."""
        step = ".".join(map(str, getattr(self.current, "position", ())))
        with self.lock:
            self.events.append({"name": name, "t": round(at, 3), "step": step, **details})
        what = [*details.get("routers", []), *("–".join(link) for link in details.get("links", []))]
        log.info("%s: %6.1f s %s %s", self.key, at, name.replace("_", " "), ", ".join(what))

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
        stable = self.sampler.wait_quiet(self.experiment.sampling.stable_s, deadline - self.sampler.now(), self.stop)
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

    def announced(self) -> set[str]:
        """The distinct prefixes announced anywhere, which every router should hold."""
        announced = set()
        for r in set(self.origins) | self.originated | self.announcers:
            status = self.routers.get(r, "/noise", timeout=STATUS_S)
            announced |= set(status["prefixes"]) | set(status["originated"])
        for mine in self.injected.values():
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
        need = {r: Resources.ROUTER_MB + prefixes * min(len(cfg.get("neighbors", [])), senders or 10**9) * Resources.PATH_KB / 1024
                for r, cfg in self.network.routers.items()}
        router, most = max(need.items(), key=lambda x: x[1])
        if most > self.experiment.cluster.router_limit_mb:
            raise LabError(f"{prefixes} prefixes would take about {most:.0f} MB at {router}, more than the "
                           f"{self.experiment.cluster.router_limit_mb} MB a router may use. Announce fewer per router.")
        if (total := Resources.SYSTEM_MB + sum(need.values())) > self.cluster.resources.memory_mb:
            raise LabError(f"{prefixes} prefixes would take about {total:,.0f} MB, more than the "
                           f"{self.cluster.resources.memory_mb:,} MB of the cluster. Announce fewer per router.")

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
        routers, _ = self.network.targets("prepend", p, self.random(position))
        for r in routers:
            self.routers.post(r, "/policy/prepend", {"times": p.times})
        self.event("prepend", at, routers=routers, times=p.times)

    def do_set_export(self, p: scenario.SetExport, position: tuple) -> None:
        at = self.sampler.now()
        [router], [(_, neighbor)] = self.network.targets("set_export", p, self.random(position))
        self.routers.post(router, "/policy/export", {"neighbor": neighbor, "allow": p.allow})
        self.event("set_export", at, routers=[router], neighbor=neighbor, allow=p.allow, outside_model=True)

    def do_soft_reset(self, s: scenario.SoftReset, position: tuple) -> None:
        at = self.sampler.now()
        routers, _ = self.network.targets("soft_reset", s, self.random(position))
        for r in routers:
            self.routers.post(r, "/bgp/soft-reset", {"direction": s.direction})
        self.event("soft_reset", at, routers=routers, direction=s.direction)

    # Checks

    def do_expect(self, e: scenario.Expect, position: tuple) -> None:
        at = self.sampler.now()
        routers, _ = self.network.targets("expect", e, self.random(position))
        problems = check_routes(e, self.announced(), {r: self.routers.get(r, "/routes", timeout=STATUS_S) for r in routers},
                                self.network.routers[e.avoid]["asn"] if e.avoid else None)
        self.event("expect", at, routers=routers, passed=not problems, problems=problems[:10],
                   **e.model_dump(exclude={"router"}, exclude_none=True))


def check_routes(e: scenario.Expect, announced: set[str], routes: dict[str, dict], avoid_asn: int | None) -> list[str]:
    """What contradicts an expect step: routes of each router as /routes gives them."""
    problems = []
    for router, table in sorted(routes.items()):
        held = announced & set(table)
        if e.prefixes == "all" and (missing := announced - held):
            problems.append(f"{router} misses {len(missing)} of {len(announced)} prefixes")
        if e.prefixes == "none" and held:
            problems.append(f"{router} holds {len(held)} prefixes")
        if e.via and (other := sorted({table[p]["from"] or "itself" for p in held} - {e.via})):
            problems.append(f"{router} routes via {', '.join(other)}, not only {e.via}")
        if avoid_asn is not None and (through := [p for p in held if int(avoid_asn) in table[p]["as_path"]]):
            problems.append(f"{router} routes {len(through)} prefixes through {e.avoid}")
    return problems


class Sampler(threading.Thread):
    """Collects the samples that every router takes of itself.

    The routers sample at t0 + k * interval on their own clock, corrected
    by its measured offset, so all routers sample at the same times. This
    thread fetches the new samples twice a second, joins them by time and
    tracks since when nothing changes, for until_stable and the live view.
    """

    FETCH = 0.5

    def __init__(self, routers: Routers, watched: list[str], interval: float,
                 on_tick: Callable[[float, dict], None] | None = None) -> None:
        super().__init__(daemon=True)
        self.routers = routers
        self.watched = watched
        self.interval = interval
        self.on_tick = on_tick
        self.samples: list[dict] = []
        self.latest: dict[str, dict] = {}
        self.paused: set[str] = set()  # stopped routers, which do not sample
        self.seq = {r: 0 for r in watched}
        self.reached: dict[str, float] = {}
        self.pending: dict[float, dict[str, dict]] = {}
        self.last_t: float | None = None
        self.quiet_since: float | None = None
        self.answered: dict[str, float] = {}  # when each router last handed over its samples
        self.current: dict[str, dict] = {}  # the latest sample of each router, up to the horizon
        self.failures: dict[str, int] = {}
        self.stopped = threading.Event()
        self.error: Exception | None = None  # what ended the thread early
        self.tick = threading.Condition()
        self.pool = ThreadPoolExecutor(len(watched))
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
            while not self.stopped.wait(self.FETCH):
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
                self.samples.append(row)
                self.pending.setdefault(row["t"], {})[router] = row
                self.reached[router] = row["t"]
        active = [r for r in self.watched if r not in self.paused]
        if not active or any(r not in self.reached for r in active):
            return
        horizon = min(self.reached[r] for r in active)
        with self.tick:
            for t in sorted(t for t in self.pending if t <= horizon):
                # Busy routers skip times of their own: each stands by its
                # latest sample, as in analysis.ticks, if not too old.
                self.current.update(self.pending.pop(t))
                if any(r not in self.current or t - self.current[r]["t"] > analysis.STALE_S for r in active):
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
        self.samples.sort(key=lambda r: (r["t"], r["router"]))
        if self.error:
            raise LabError(f"sampling failed: {self.error}")

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
                self.tick.wait(timeout=self.FETCH)
        return False
