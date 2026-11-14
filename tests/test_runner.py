import threading
import time
from pathlib import Path

import pytest

from lab import config, host, problems, runner, scenario, topology
from lab.cluster import Fit, LabError
from lab.config import Experiment
from lab.results import RunKey


def bare_run():
    run = object.__new__(runner.Run)
    run.stop = runner.Halt(threading.Event())
    run.current = threading.local()
    return run


def test_a_failed_parallel_step_ends_its_siblings():
    run = bare_run()

    def step(kind, position):
        if kind == "fail":
            raise LabError("a router is gone")
        run.wait(30)  # would hold the run for half a minute

    run.step = step
    began = time.monotonic()
    with pytest.raises(LabError, match="a router is gone"):
        run.do_parallel(["fail", "wait"], ())
    assert time.monotonic() - began < 2


def test_a_stop_of_the_result_ends_a_wait():
    outer = threading.Event()
    halt = runner.Halt(outer)
    threading.Timer(0.1, outer.set).start()
    began = time.monotonic()
    assert halt.wait(30) and time.monotonic() - began < 1


def test_a_stop_ends_a_long_command_but_not_a_cleanup(monkeypatch):
    from lab import cluster

    monkeypatch.setattr(cluster, "STOP", threading.Event())
    threading.Timer(0.2, cluster.STOP.set).start()
    began = time.monotonic()
    with pytest.raises(cluster.Interrupted):
        cluster.sh("sleep", "30", interruptible=True)
    assert time.monotonic() - began < 3
    assert cluster.sh("echo", "cleaned") == "cleaned\n"  # STOP is set, and it still runs
    with pytest.raises(LabError, match="longer than"):
        cluster.sh("sleep", "30", timeout=0.5)


# The step engine against routers that record what they are asked.



class Routers:
    def __init__(self, prefixes):
        self.calls, self.prefixes = [], prefixes

    def post(self, router, path, body=None, timeout=60):
        self.calls.append((router, path, body))
        if path == "/noise/load":
            self.prefixes[router] = sorted(set(self.prefixes.get(router, [])) | set(body["prefixes"]))
        if path == "/noise/withdraw":
            self.prefixes[router] = [p for p in self.prefixes.get(router, []) if p not in body["prefixes"]]
        return {}

    routes = {}

    sessions = {}

    def get(self, router, path, timeout=2):
        if path == "/routes":
            return self.routes.get(router, {})
        if path == "/sessions":
            return self.sessions.get(router, {})
        return {"prefixes": self.prefixes.get(router, []), "active": len(self.prefixes.get(router, [])), "originated": []}


class Sampler:
    def __init__(self):
        self.t, self.paused = 0.0, []

    def now(self):
        self.t += 0.1
        return self.t

    def pause(self, router):
        self.paused.append(("pause", router))

    def resume(self, router):
        self.paused.append(("resume", router))

    def wait_quiet(self, seconds, timeout, stop):
        return True


def engine(lab_files, topology_name="bad-gadget"):
    run = object.__new__(runner.Run)
    run.experiment = Experiment.load(config.path("lab-smoke"))
    run.key = RunKey(topology_name, "obgp", "smoke-all", 1)
    t = topology.load(topology_name)
    run.network = scenario.Network(t["routers"], t["roles"])
    run.origins = tuple(run.network.roles.get("origins", []))
    run.routers = Routers({o: ["10.0.0.0/24", "10.0.1.0/24"] for o in run.origins})
    run.sampler = Sampler()
    run.status = type("Status", (), {"update": lambda self, **_: None})()
    run.stop = runner.Halt(threading.Event())
    run.current = threading.local()
    run.lock = threading.Lock()
    run.events, run.measurements = [], []
    run.stopped, run.failed, run.originated, run.silent_since = set(), {}, set(), None
    run.announcers, run.injected = set(), {}
    run.cluster = type("Cluster", (), {"resources": config.Cluster()})()
    run.topology = t
    run.waited = []
    run.wait = run.waited.append
    run.profiled = ""
    return run


def play(run, *steps):
    for i, step in enumerate(scenario.parse({"name": "t", "steps": list(steps)}).steps):
        run.step(step, (i,))
    return run.routers.calls


def test_a_link_goes_down_and_up_with_the_ends_the_mode_names(lab_files):
    run = engine(lab_files)
    calls = play(run, {"down": {"link": "frankfurt-fulda"}})
    assert calls == [("frankfurt", "/peers/fulda/down", {"mode": "session"})]
    run.routers.calls.clear()
    calls = play(run, {"down": {"link": "toronto-fulda", "mode": "cut"}}, {"up": {}})
    assert calls[:2] == [("fulda", "/peers/toronto/down", {"mode": "cut"}), ("toronto", "/peers/fulda/down", {"mode": "cut"})]
    assert sorted(c[:2] for c in calls[2:]) == [("frankfurt", "/peers/fulda/up"), ("fulda", "/peers/toronto/up"), ("toronto", "/peers/fulda/up")]
    assert run.failed == {} and run.silent_since is not None  # a cut is only noticed by the hold timer
    assert [(e["name"], e["step"]) for e in run.events] == [("down", "0"), ("down", "0"), ("up", "1")]


def test_a_router_stops_and_starts_and_is_not_sampled_meanwhile(lab_files):
    run = engine(lab_files)
    calls = play(run, {"down": {"router": "toronto"}}, {"up": {"router": "toronto"}})
    assert [c[:2] for c in calls] == [("toronto", "/daemon/stop"), ("toronto", "/daemon/start")]
    assert run.sampler.paused == [("pause", "toronto"), ("resume", "toronto")] and not run.stopped


def test_a_degraded_link_is_degraded_at_both_ends_and_restored(lab_files):
    run = engine(lab_files)
    calls = play(run, {"degrade": {"link": "toronto-fulda", "delay_ms": 50, "loss_pct": 1}}, {"up": {"link": "toronto-fulda"}})
    body = {"delay_ms": 50, "jitter_ms": 0, "loss_pct": 1}
    assert calls[:2] == [("fulda", "/peers/toronto/degrade", body), ("toronto", "/peers/fulda/degrade", body)]
    assert sorted(c[:2] for c in calls[2:]) == [("fulda", "/peers/toronto/up"), ("toronto", "/peers/fulda/up")]


def test_prefixes_are_announced_copied_and_withdrawn(lab_files):
    run = engine(lab_files)
    calls = play(run, {"announce": {"rate": 2, "for": 8}}, {"originate": {"router": "fulda", "count": 1}},
                 {"withdraw": {"percent": 50, "router": "random"}}, {"withdraw": {"router": "fulda"}})
    origin = run.origins[0]
    assert calls[0] == (origin, "/noise/start", {"block": 0, "blocks": 1, "rate": 2, "lifetime": 60, "jitter": 0.5, "max_active": 90})
    assert calls[1] == (origin, "/noise/pause", None) and run.waited
    copied = calls[2]
    assert copied[:2] == ("fulda", "/originate") and copied[2]["prefixes"][0] in run.routers.prefixes[origin]
    assert calls[-2:] == [("fulda", "/noise/drain", {"percent": 100}), ("fulda", "/originate/clear", None)]
    assert run.events[1]["expected"] == 2


def test_policies_restarts_and_waits(lab_files):
    run = engine(lab_files)
    calls = play(run, {"set_preference": {"router": "frankfurt", "neighbor": "fulda", "value": 300}},
                 {"prepend": {"router": "toronto", "times": 2}}, {"restart": {"router": "frankfurt"}}, {"until_stable": {"timeout": 20}})
    assert calls == [("frankfurt", "/policy/preference", {"neighbor": "fulda", "value": 300}),
                     ("toronto", "/policy/prepend", {"times": 2}), ("frankfurt", "/daemon/restart", {"graceful": False})]
    assert run.sampler.paused == [("pause", "frankfurt"), ("resume", "frankfurt")]
    assert run.measurements[0]["stable"] is True and run.measurements[0]["step"] == "3"


def test_random_choices_are_the_same_in_every_variant(lab_files):
    first, second = engine(lab_files), engine(lab_files)
    second.key = RunKey("bad-gadget", "bgp", "smoke-all", 1)
    step = {"set_preference": {"router": "random", "neighbor": "random", "value": 300}}
    assert play(first, step) == play(second, step)


def test_an_unknown_target_fails_the_step(lab_files):
    with pytest.raises(ValueError, match="unknown router"):
        play(engine(lab_files), {"restart": {"router": "nowhere"}})


def test_exports_soft_resets_and_graceful_restarts(lab_files):
    run = engine(lab_files)
    calls = play(run, {"set_export": {"router": "frankfurt", "neighbor": "fulda"}}, {"soft_reset": {"router": "toronto", "direction": "out"}},
                 {"restart": {"router": "fulda", "graceful": True}}, {"set_export": {"router": "frankfurt", "neighbor": "fulda", "allow": True}})
    assert calls == [("frankfurt", "/policy/export", {"neighbor": "fulda", "allow": False}), ("toronto", "/bgp/soft-reset", {"direction": "out"}),
                     ("fulda", "/daemon/restart", {"graceful": True}), ("frankfurt", "/policy/export", {"neighbor": "fulda", "allow": True})]
    assert [e["name"] for e in run.events] == ["set_export", "soft_reset", "restart", "set_export"] and run.events[2]["graceful"] is True


def test_checks_of_the_routes(lab_files):
    run = engine(lab_files)
    origin = run.origins[0]
    p1, p2 = run.routers.prefixes[origin][:2] if len(run.routers.prefixes[origin]) > 1 else ("10.1.0.0/24", "10.1.1.0/24")
    run.routers.prefixes[origin] = [p1, p2]
    asn = {r: cfg["asn"] for r, cfg in run.network.routers.items()}
    run.routers.routes = {
        "frankfurt": {p1: {"from": "fulda", "as_path": [asn["fulda"], asn[origin]]}, p2: {"from": "fulda", "as_path": [asn["fulda"], asn[origin]]}},
        "toronto": {p1: {"from": "frankfurt", "as_path": [asn["frankfurt"], asn["fulda"], asn[origin]]}},
    }
    play(run, {"expect": {"router": "frankfurt", "via": "fulda"}}, {"expect": {"router": "toronto"}},
         {"expect": {"router": "toronto", "prefixes": "any", "avoid": "fulda"}}, {"expect": {"router": "frankfurt", "prefixes": "none"}})
    checks = [(e["passed"], e["problems"]) for e in run.events if e["name"] == "expect"]
    assert checks == [(True, []), (False, ["toronto misses 1 of 2 prefixes"]), (False, ["toronto routes 1 prefixes through fulda"]),
                      (False, ["frankfurt holds 2 prefixes"])]


def test_until_stable_waits_for_the_sessions_that_should_be_up(lab_files):
    run = engine(lab_files)
    run.wait = lambda seconds: setattr(run.routers, "sessions", {})  # they come up while it waits
    run.routers.sessions = {"frankfurt": {"fulda": False}}
    play(run, {"until_stable": {"timeout": 20}})
    assert run.routers.sessions == {} and run.measurements[0]["stable"] is True

    # A link a step took down does not count.
    run = engine(lab_files)
    run.wait = lambda seconds: pytest.fail("waited for a session that is down on purpose")
    play(run, {"down": {"link": "frankfurt-fulda"}})
    run.routers.sessions = {"frankfurt": {"fulda": False}, "fulda": {"frankfurt": False}}
    play(run, {"until_stable": {"timeout": 20}})


def test_routers_announce_prefixes_of_their_as(lab_files, monkeypatch):
    from lab import caida, prefixes

    rels = caida.Relations("1|10|-1\n1|20|-1\n10|20|0\n", "caida/20260901")
    t = caida.convert(rels, rels.whole_cone(1))
    topology.save("real", t["routers"], t["roles"], t["source"])
    own = {1: ["1.0.0.0/24", "1.0.1.0/24", "1.0.2.0/24"], 10: ["10.0.0.0/16"], 20: []}
    monkeypatch.setattr(prefixes, "of", lambda asns, day: {a: own[a] for a in asns})
    run = engine(lab_files, "real")
    run.routers.prefixes = {}  # only the real ones
    calls = play(run, {"announce_real": {"per_router": 2, "rate": 10}})
    loads = {r: body for r, path, body in calls if path == "/noise/load"}
    assert set(loads) == {"as1", "as10"} and len(loads["as1"]["prefixes"]) == 2 and loads["as10"]["rate"] == 5
    assert [e["name"] for e in run.events] == ["announce", "announced"] and run.events[1]["expected"] == 3
    assert run.events[0]["source"] == "routeviews-prefix2as/20260901"
    # Far too many for a router: refused before anything is announced.
    monkeypatch.setattr(config.Cluster, "PATH_KB", 1e6)
    run = engine(lab_files, "real")
    with pytest.raises(LabError, match="MiB a router may use"):
        play(run, {"announce_real": {}})
    assert not run.routers.calls


def test_real_prefixes_need_a_topology_from_caida(lab_files):
    from lab import scenario as scenarios

    scenarios.path("real-fill").write_text("name: real-fill\nsteps:\n  - announce_real: {}\n")
    e = Experiment.model_validate({"name": "x", "topologies": ["bad-gadget"], "scenarios": ["real-fill"],
                                   "variants": [{"name": "bgp", "ref": "HEAD", "mode": "bgp"}]})
    with pytest.raises(ValueError, match="needs a topology imported from CAIDA"):
        e.check_targets()


def test_a_replay_follows_what_a_vantage_point_saw(lab_files, monkeypatch):
    from lab import caida, mrt, prefixes

    rels = caida.Relations("1|10|-1\n1|20|-1\n10|20|0\n", "caida/20260901")
    t = caida.convert(rels, rels.whole_cone(1))
    topology.save("real", t["routers"], t["roles"], t["source"])
    own = {1: ["1.0.0.0/24", "1.0.1.0/24"], 10: [], 20: []}
    monkeypatch.setattr(prefixes, "of", lambda asns, day: {a: own[a] for a in asns})
    changes = [[0, "1.0.0.0/24", 1],      # seen for the first time: as1 announces it already
               [60, "1.0.0.0/24", 0],     # gone
               [120, "1.0.0.0/24", 10],   # back, from another AS of the topology
               [180, "9.9.9.0/24", 20],   # new in the window
               [200, "8.8.8.0/24", 64999]]  # from an AS outside of the topology
    monkeypatch.setattr(mrt, "events", lambda collector, start, minutes: {
        "collector": collector, "vantage": "192.0.2.1", "start": "2026-09-01 12:00", "minutes": minutes, "changes": changes})
    run = engine(lab_files, "real")
    run.routers.prefixes = {}  # only the real ones
    calls = play(run, {"replay": {"start": "2026-09-01 12:00", "minutes": 5, "speed": 60, "per_router": 2}})
    loads = [(r, path, body["prefixes"]) for r, path, body in calls if path in ("/noise/load", "/noise/withdraw")]
    assert loads == [("as1", "/noise/load", ["1.0.0.0/24", "1.0.1.0/24"]), ("as1", "/noise/withdraw", ["1.0.0.0/24"]),
                     ("as10", "/noise/load", ["1.0.0.0/24"]), ("as20", "/noise/load", ["9.9.9.0/24"])]
    replay = next(e for e in run.events if e["name"] == "replay")
    assert replay["vantage"] == "192.0.2.1" and replay["changes"] == 4
    assert run.events[-1]["name"] == "replayed" and run.events[-1]["expected"] == 3
    assert scenario.timeline(scenario.parse({"name": "r", "steps": [{"replay": {"start": "2026-09-01 12:00", "speed": 60}}]}).steps)[0]["end"] == 30


def test_a_busy_router_is_not_done_yet(lab_files):
    run = engine(lab_files)
    answers = iter([LabError("read timed out"), {"active": 2}])

    def get(router, path, timeout=2):
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer
    run.routers.get = get
    assert not run.loaded({"toronto": ["1.0.0.0/24", "1.0.1.0/24"]})
    assert run.loaded({"toronto": ["1.0.0.0/24", "1.0.1.0/24"]})


def test_a_busy_router_does_not_count_as_stable(lab_files):
    run = engine(lab_files)

    def get(router, path, timeout=2):
        raise LabError("read timed out")
    run.routers.get = get
    assert not run.sessions_up()


def test_a_missed_fetch_loses_no_sample_but_a_silent_router_fails(monkeypatch):
    calls = {"n": 0}

    class Flaky:
        def get(self, router, path, timeout=2):
            calls["n"] += 1
            if calls["n"] == 1:
                raise LabError("read timed out")
            return {"samples": [{"seq": 1, "t": 0.0, "paths": 1}], "failures": 0}

    sampler = runner.Sampler(Flaky(), ["a"], 0.1)
    sampler.fetch()  # missed
    sampler.fetch()  # brings what was missed
    assert sampler.failed == 0 and sampler.count == 1 and [r["t"] for r in sampler.rows()] == ["0.0"]
    sampler.pool.shutdown()

    class Silent:
        def get(self, router, path, timeout=2):
            raise LabError("read timed out")

    sampler = runner.Sampler(Silent(), ["a"], 0.1)
    sampler.fetch()
    monkeypatch.setattr(runner.time, "monotonic", lambda: 10**9)
    with pytest.raises(LabError, match="did not hand over its samples"):
        sampler.fetch()
    sampler.pool.shutdown()


def test_fetches_through_the_api_server_stay_bounded_beyond_100_routers():
    fetch = lambda n: runner.fetch_interval(n, runner.Sampler.FETCH, runner.Sampler.RATE)  # noqa: E731
    assert fetch(5) == fetch(100) == 0.5  # as before
    assert fetch(256) == 1.28 and 256 / fetch(256) == runner.Sampler.RATE
    # Beyond LARGE routers fewer fetches, which spares the API of a full node.
    sampler = runner.Sampler(None, [f"r{i}" for i in range(256)], 0.1)
    assert sampler.fetch_s == 256 / runner.Sampler.RATE_LARGE == 5.12 and sampler.interval == 0.1  # the routers still sample every interval
    sampler.pool.shutdown()
    small = runner.Sampler(None, [f"r{i}" for i in range(runner.Sampler.LARGE)], 0.1)
    assert small.fetch_s == 0.5
    small.pool.shutdown()


def test_samples_wait_on_disk_and_come_out_by_time_then_router(tmp_path):
    class Two:
        def __init__(self):
            self.seq = {"a": 0, "b": 0}

        def get(self, router, path, timeout=2):
            # b hands over two at once, a one at a time, later times first for b.
            n = self.seq[router]
            rows = [{"seq": n + i + 1, "t": round((n + i) * 0.1, 3), "paths": 1} for i in range(2 if router == "b" else 1)]
            self.seq[router] += len(rows)
            return {"samples": rows, "failures": 0}

    sampler = runner.Sampler(Two(), ["b", "a"], 0.1, spool=tmp_path / "run")
    for _ in range(3):
        sampler.fetch()
    assert sampler.spool.parent == tmp_path / "run" and sampler.spool.name.startswith(".samples-")
    rows = list(sampler.rows())
    assert [(r["t"], r["router"]) for r in rows] == [("0.0", "a"), ("0.0", "b"), ("0.1", "a"), ("0.1", "b"), ("0.2", "a"),
                                                      ("0.2", "b"), ("0.3", "b"), ("0.4", "b"), ("0.5", "b")]
    assert rows[0]["paths"] == "1" and rows[0]["rss_mb"] == ""
    sampler.pool.shutdown()


def test_the_heap_check_leaves_the_samples_to_be_written(lab_files, tmp_path):
    # The rows can be read once: the heap check must use the peaks noted while sampling, not the rows.
    class Grown:
        def __init__(self):
            self.n = 0

        def get(self, router, path, timeout=2):
            if path == "/heap":
                return {"rss_mb": 1500.0}
            self.n += 1
            return {"samples": [{"seq": self.n, "t": self.n * 0.1, "rss_mb": 1500.0 if self.n > 1 else 20.0}], "failures": 0}

    sampler = runner.Sampler(Grown(), ["a"], 0.1, spool=tmp_path / "spool")
    sampler.fetch(), sampler.fetch()
    run = engine(lab_files)
    run.spool, run.routers, run.key = tmp_path / "run", sampler.routers, RunKey("bad-gadget", "bgp", "s", 1)
    run.keep_heaps(sampler.peak_mb)
    assert sampler.peak_mb == {"a": 1500.0} and len(list(sampler.rows())) == 2
    sampler.pool.shutdown()


def test_routers_that_answer_at_different_times_still_settle():
    class Staggered:
        def __init__(self):
            self.seq = {"a": 0, "b": 0}

        def get(self, router, path, timeout=2):
            # a answers at even tenths, b at odd ones: never both at once.
            n = self.seq[router] = self.seq[router] + 1
            t = round((2 * n + (router == "b")) * 0.1, 3)
            return {"samples": [{"seq": n, "t": t, "destinations": 5, "paths": 9, "updates_rx": 3}], "failures": 0}

    sampler = runner.Sampler(Staggered(), ["a", "b"], 0.1)
    for _ in range(40):
        sampler.fetch()
    assert sampler.last_t is not None and sampler.last_t - sampler.quiet_since > 3
    sampler.pool.shutdown()


def test_the_load_of_the_host_is_recorded(monkeypatch):
    times = iter([(0, 100), (90, 200), (95, 300)])
    monkeypatch.setattr(host, "lab_cgroup", lambda: None)
    monkeypatch.setattr(host, "cluster_hidden", lambda: True)  # e.g. under Docker Desktop
    monkeypatch.setattr(host, "cpu_times", lambda: next(times, None))
    load = runner.HostLoad(interval=0.01)
    load.start()
    deadline = time.monotonic() + 5  # a busy host starts the thread late
    while len(load.shares) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    load.stop()
    load.join()
    summary = load.summary()
    assert summary["cpu_max"] == 0.9 and summary["cpu_mean"] == 0.475
    assert "others_max" not in summary  # the lab cannot be told apart


def test_the_load_of_others_is_told_from_the_lab(monkeypatch):
    times = iter([(0, 100), (90, 200), (95, 300)])
    lab = iter([0, 30, 30])
    monkeypatch.setattr(host, "lab_cgroup", lambda: Path("/"))
    monkeypatch.setattr(host, "own_processes", dict)
    monkeypatch.setattr(host, "cpu_times", lambda: next(times, None))
    monkeypatch.setattr(host, "lab_cpu_s", lambda group: next(lab, None))
    load = runner.HostLoad(interval=0.01)
    load.start()
    deadline = time.monotonic() + 5
    while len(load.others) < 2 and time.monotonic() < deadline:
        time.sleep(0.01)
    load.stop()
    load.join()
    summary = load.summary()
    assert summary["others_max"] == 0.6 and summary["others_min"] == 0.05


def test_a_run_waits_for_the_lab_not_for_others(monkeypatch):
    # The host is 80 % busy by others, the lab idle: no wait for others.
    busy = iter(range(0, 10**6, 80))
    total = iter(range(0, 10**6, 100))
    monkeypatch.setattr(host, "lab_cgroup", lambda: Path("/"))
    monkeypatch.setattr(host, "own_processes", dict)
    monkeypatch.setattr(host, "cpu_times", lambda: (next(busy), next(total)))
    monkeypatch.setattr(host, "lab_cpu_s", lambda group: 0.0)
    assert runner.quiet_host(threading.Event(), cpus=8) is None


def test_large_announcements_name_one_sample_of_prefixes_to_every_router():
    from types import SimpleNamespace


    posted, events = [], []
    many = {f"10.{i // 256}.{i % 256}.0/24" for i in range(600)}
    me = SimpleNamespace(announced=lambda: many, network=SimpleNamespace(routers={"a": {}, "b": {}}), stopped={"b"},
                         routers=SimpleNamespace(post=lambda r, path, body: posted.append((r, path, len(body["prefixes"])))),
                         sampler=SimpleNamespace(now=lambda: 5.0), event=lambda name, at, **d: events.append((name, d)))
    runner.Run.watch_hops(me)
    runner.Run.watch_hops(me)  # the same announcements: the same sample, sent once
    assert posted == [("a", "/hops/watch", 256), ("b", "/hops/watch", 256)]
    assert events == [("hops_sample", {"prefixes": 256, "of": 600})]
    few = SimpleNamespace(**{**vars(me), "announced": lambda: set(list(many)[:10])})
    runner.Run.watch_hops(few)
    assert len(posted) == 2  # few enough to follow whole


def lab_smoke_result(name):
    import json

    from lab import results

    path = results.PRIVATE / name
    path.mkdir(parents=True)
    e = Experiment.load(config.path("lab-smoke"))
    meta = {"experiment": e.model_dump(mode="json"), "commits": {v.name: "c0ffee" for v in e.variants}, "created": "2026-01-01",
            "versions": {}, "predictions": {}}
    (path / "dataset.json").write_text(json.dumps(meta))
    return results.Dataset(path)


class FakeCluster:
    """A cluster that builds and deploys nothing, and is in trouble or not clean as told."""

    def __init__(self, resources, troubles=(), unclean=(), answers=True, undeploys=True):
        self.resources, self.troubles, self.unclean, self.starts = resources, list(troubles), list(unclean), 0
        self.answers, self.undeploys, self.deleted, self.cleaned = answers, undeploys, 0, 0

    def build(self, commit):
        return "tag"

    def prune(self, keep):
        pass

    def undeploy(self):
        if not self.undeploys:
            raise LabError("kubectl get pods: Unable to connect to the server")

    def clean(self):
        self.cleaned += 1
        return self.unclean.pop(0) if self.unclean else None

    def delete(self):
        self.deleted += 1

    def api_answers(self):
        return self.answers

    def start(self):
        self.starts += 1

    def pin(self, cpus, mems):
        return {"cpus": cpus, "mems": mems or ""}

    def trouble(self):
        return self.troubles.pop(0) if self.troubles else None


def fake_lab(monkeypatch, cluster):
    from lab import analysis, lifecycle

    monkeypatch.setattr(runner, "fit", lambda e: Fit(e.cluster, 1000, 10**6, {}, len(e.topologies)))
    monkeypatch.setattr(runner, "Cluster", lambda resources: cluster)
    monkeypatch.setattr(lifecycle, "ensure_cluster", lambda c: {})
    monkeypatch.setattr(runner, "Routers", lambda: type("R", (), {"ensure": lambda self: None, "close": lambda self: None})())
    monkeypatch.setattr(runner, "quiet_host", lambda stop, cpus: None)
    monkeypatch.setattr(analysis, "run_bins", lambda *a: None)


@pytest.mark.parametrize("stopped_by_hand", [False, True])
def test_a_sigterm_interrupts_unless_a_person_stopped_it(lab_files, monkeypatch, stopped_by_hand):
    d = lab_smoke_result("t-sig")
    fake_lab(monkeypatch, FakeCluster(config.Cluster()))

    class Ended:
        def __init__(self, *a):
            pass

        def execute(self):
            if stopped_by_hand:
                runner.stop_requested(d)
            raise runner.Cancelled  # as when SIGTERM sets stop

    monkeypatch.setattr(runner, "Run", Ended)
    runner.run(d, threading.Event())
    assert d.status["state"] == ("stopped" if stopped_by_hand else "interrupted")
    assert bool(d.meta.get("interruptions")) is not stopped_by_hand


def flaky(times, error="The connection to the server 192.168.49.2:8443 was refused"):
    """A run that fails the first `times` times, then completes."""
    calls = []

    class Flaky:
        def __init__(self, *a):
            pass

        def execute(self):
            calls.append(1)
            if len(calls) <= times:
                raise LabError(error)
            return {"status": "completed"}, []

    return Flaky, calls


def test_a_lost_cluster_costs_no_attempt_and_the_run_plays_again_on_a_clean_cluster(lab_files, monkeypatch):
    d = lab_smoke_result("t-lost")
    cluster = FakeCluster(config.Cluster(), troubles=["the container obgp-lab is stopped"])
    fake_lab(monkeypatch, cluster)
    run, calls = flaky(1)
    monkeypatch.setattr(runner, "Run", run)
    runner.run(d, threading.Event())
    first = d.keys()[0]
    assert cluster.cleaned == 2  # at the start, and before the run played again
    assert d.run(first)["attempts"] == 1 and "failures" not in d.run(first)
    assert d.status["state"] == "finished" and d.status["errors"] == 0


def test_the_cluster_lost_twice_ends_the_result_as_failed(lab_files, monkeypatch):
    d = lab_smoke_result("t-lost-twice")
    cluster = FakeCluster(config.Cluster(), troubles=["Kubernetes is not ready: refused", "Kubernetes is not ready: refused"])
    fake_lab(monkeypatch, cluster)
    run, calls = flaky(5)
    monkeypatch.setattr(runner, "Run", run)
    runner.run(d, threading.Event())
    assert len(calls) == 2 and d.status["state"] == "failed"
    assert d.status["error"] == "the cluster was lost 2 times in this result, last: Kubernetes is not ready: refused"
    assert not d.meta.get("interruptions")  # not restarted by the queue


def test_a_result_interrupted_by_a_lost_cluster_goes_on_once_only(lab_files, monkeypatch):
    d = lab_smoke_result("t-lost-resumed")

    def build_fails(commit):
        raise LabError("docker build: Cannot connect")

    cluster = FakeCluster(config.Cluster(), troubles=["Kubernetes is not ready: refused"])
    cluster.build = build_fails
    fake_lab(monkeypatch, cluster)
    runner.run(d, threading.Event())
    assert d.status["state"] == "interrupted" and d.meta["interruptions"][-1]["lost"]
    # The queue restarts it, and the cluster is lost again: it ends for good.
    cluster.troubles = ["the container obgp-lab is stopped"]
    runner.run(d, threading.Event())
    assert d.status["state"] == "failed" and "lost 2 times in this result" in d.status["error"]
    assert len(d.meta["interruptions"]) == 1


def test_a_limit_of_the_host_ends_the_result_as_failed_and_leaves_no_routers(lab_files, monkeypatch):
    d = lab_smoke_result("t-limit")
    cluster = FakeCluster(config.Cluster())
    undeployed = []
    cluster.undeploy = lambda: undeployed.append(1)
    fake_lab(monkeypatch, cluster)

    class Limited:
        def __init__(self, *a):
            pass

        def execute(self):
            raise runner.HostLimit("routers of t did not become ready: the node's connection tracking held 170000 of 262144 entries")

    monkeypatch.setattr(runner, "Run", Limited)
    runner.run(d, threading.Event())
    assert d.status["state"] == "failed" and "connection tracking" in d.status["error"]
    assert not d.meta.get("interruptions") and undeployed


def test_a_cluster_that_is_not_clean_is_created_anew_once(lab_files, monkeypatch):
    status = type("S", (), {"update": lambda self, **kw: None})()
    d = lab_smoke_result("t-clean")
    fake_lab(monkeypatch, FakeCluster(config.Cluster()))
    clean = FakeCluster(config.Cluster())
    runner.prepare(clean, d, threading.Event(), status)
    assert clean.deleted == 0
    stale = FakeCluster(config.Cluster(), unclean=["routers of another run stay: 128 pods"])
    runner.prepare(stale, d, threading.Event(), status)
    assert stale.deleted == 1 and stale.cleaned == 2
    broken = FakeCluster(config.Cluster(), unclean=["the Kubernetes API does not answer"] * 2)
    with pytest.raises(runner.HostLimit, match="not usable even when created anew: the Kubernetes API does not answer"):
        runner.prepare(broken, d, threading.Event(), status)


@pytest.mark.parametrize("trouble, answers, deleted", [
    (None, True, 0),  # routers that do not go: the next result cleans up
    ("the container obgp-lab is stopped", False, 0),  # a host that shuts down keeps its cluster
    ("Kubernetes is not ready: refused", True, 0),  # it answers again
    ("Kubernetes is not ready: refused", False, 1),
])
def test_routers_that_cannot_be_removed_take_the_lab_cluster_with_them_only_when_its_api_is_dead(trouble, answers, deleted):
    cluster = FakeCluster(config.Cluster(), troubles=[trouble] if trouble else [], answers=answers, undeploys=False)
    runner.tidy(cluster)
    assert cluster.deleted == deleted


def test_a_silent_api_takes_the_lab_cluster_without_waiting_for_helm_and_the_page_says_so():
    cluster = FakeCluster(config.Cluster(), troubles=["Kubernetes is not ready: refused"], answers=False)
    undeployed, phases = [], []
    cluster.undeploy = lambda: undeployed.append(1)
    runner.tidy(cluster, type("S", (), {"update": lambda self, **kw: phases.append(kw["phase"])})())
    assert cluster.deleted == 1 and not undeployed
    assert phases == ["deleting the lab's cluster, its Kubernetes API does not answer"]
    healthy, phases = FakeCluster(config.Cluster()), []
    runner.tidy(healthy, type("S", (), {"update": lambda self, **kw: phases.append(kw["phase"])})())
    assert healthy.deleted == 0 and phases == ["removing the routers"]


def test_recovery_starts_only_its_own_cluster_a_few_times(lab_files, monkeypatch):
    never = type("Stop", (), {"wait": lambda self, s: False})()
    status = type("S", (), {"update": lambda self, **kw: None})()
    cluster = FakeCluster(config.Cluster(), troubles=[None])
    runner.recover(cluster, never, status, "Docker does not answer")
    assert cluster.starts == 1
    cluster = FakeCluster(config.Cluster(), troubles=["the container obgp-lab is stopped"] * 10)
    with pytest.raises(runner.HostLimit, match=f"did not come back after {runner.RECOVER_STARTS} starts"):
        runner.recover(cluster, never, status, "Docker does not answer")
    assert cluster.starts == runner.RECOVER_STARTS


def test_recovery_waits_while_the_host_shuts_down(lab_files, monkeypatch):
    waits = []

    class Stop:
        def wait(self, s):
            waits.append(s)
            return len(waits) > 2  # SIGTERM arrives as the host goes down

    monkeypatch.setattr(host, "shutting_down", lambda: True)
    cluster = FakeCluster(config.Cluster())
    status = type("S", (), {"update": lambda self, **kw: None})()
    with pytest.raises(runner.Cancelled):
        runner.recover(cluster, Stop(), status, "Docker does not answer")
    assert cluster.starts == 0


def test_going_on_after_a_reboot_names_it(lab_files, monkeypatch):
    from lab import service

    d = lab_smoke_result("t-boot")
    monkeypatch.setattr(service, "boot_id", lambda: "before")
    runner.interrupted(d, "noble-eu/bgp/fill-60/1", "the runner was ended from outside")
    monkeypatch.setattr(service, "boot_id", lambda: "after")
    runner.went_on_after_reboot(d)
    assert d.meta["interruptions"][-1]["rebooted"] is True


def test_old_router_images_are_never_pruned_in_the_docker_of_the_host(monkeypatch):
    from lab import cluster

    calls = []
    monkeypatch.setattr(cluster.Cluster, "_docker_env", lambda self: dict(cluster.os.environ))  # docker-env named nothing
    monkeypatch.setattr(cluster, "sh", lambda *a, **kw: calls.append(a) or "")
    monkeypatch.setattr(cluster.subprocess, "run", lambda *a, **kw: calls.append(a))
    cluster.Cluster(config.Cluster()).prune(keep=set())
    assert calls == []


class Guard:
    """The guard of a run, lost as told."""

    def __init__(self, why=""):
        self.why, self.lost = why, threading.Event()
        if why:
            self.lost.set()

    def stop(self):
        pass


@pytest.mark.parametrize("lost", [False, True])
def test_the_routers_go_away_before_the_run_is_written(lab_files, monkeypatch, lost):
    # Routers that oscillate would go on after the run, load the host and grow until their memory limit ends them.
    from collections import deque

    order = []
    guard = Guard("the node's connection tracking held 170000 of 262144 entries" if lost else "")

    class Deployed:
        resources = config.Cluster()

        def deploy(self, *a, **kw):
            order.append("deploy")

        def pods(self):
            return {}

        def restarts(self):
            return 0, []

        def addresses(self):
            order.append("addresses")
            return {"10.0.0.1": "r1"}

        def undeploy(self):
            order.append("undeploy")

        def guard(self, name, total, on_lost, diagnosis=None):
            order.append("guarded")
            return guard

    class Sampled:
        failed, count = 0, 10

        def __init__(self, *a):
            pass

        def start(self):
            pass

        def stop(self):
            order.append("sampler stopped")

        def now(self):
            return 1.0

        def rows(self):
            order.append("rows")
            return [{"t": 0.5}]

    monkeypatch.setattr(runner, "Sampler", Sampled)
    monkeypatch.setattr(runner, "HostLoad", lambda clock, cores=None: type("L", (), {"start": lambda s: None, "stop": lambda s: None, "summary": lambda s: {}})())
    run = engine(lab_files)
    run.cluster = Deployed()
    run.variant = run.experiment.variants[0]
    run.diagnosis = None
    run.scenario = type("Scenario", (), {"steps": []})()
    run.steps = lambda steps, position: order.append("steps")
    run.spool = lab_files / "spool"
    run.held = {}
    run.tag = "tag"
    run.status = type("Status", (), {"samples": deque(), "watched": set(), "update": lambda self, **_: None, "live": lambda self, *a: None})()
    run.final = lambda: order.append("final")
    if lost:  # a full connection tracking or a silent API during the run ends it, and the result
        with pytest.raises(runner.HostLimit, match="connection tracking held 170000"):
            run.execute()
        assert order == ["deploy", "guarded", "steps", "final", "sampler stopped"]
        return
    result, rows = run.execute()
    assert order == ["deploy", "guarded", "steps", "final", "sampler stopped", "addresses", "rows", "undeploy"]
    assert result["addresses"] == {"10.0.0.1": "r1"} and list(rows) == [{"t": 0.5}]


def test_a_check_of_some_origins_counts_only_their_prefixes(lab_files):
    # A router that learns only one origin's prefixes, as x-c of gao-rexford-23, misses none of its own.
    run = engine(lab_files)
    first, second = run.origins[0], run.origins[1] if len(run.origins) > 1 else None
    run.routers.prefixes = {first: ["10.0.0.0/24"], **({second: ["10.9.0.0/24"]} if second else {})}
    assert run.announced({first}) == {"10.0.0.0/24"}
    assert run.announced() == {"10.0.0.0/24", *(["10.9.0.0/24"] if second else [])}
    with pytest.raises(ValueError, match="unknown router or role"):
        run.network.targets("expect", scenario.Expect(router="all", of="nobody"), None)


def test_the_cluster_is_bound_to_its_cpus_and_says_so_where_it_cannot(lab_files, monkeypatch):
    d = lab_smoke_result("t-bind")
    monkeypatch.setattr(host, "pick_cores", lambda count, memory: {"cpus": "10-11", "count": 2, "mems": "0", "node": 0, "memory_local": True})
    cluster = FakeCluster(config.Cluster(cpus=2))
    runner.bind(d, cluster)
    assert d.meta["pinned"]["held"] == {"cpus": "10-11", "mems": "0"}

    def refused(cpus, mems):
        raise LabError("Docker cannot")
    cluster.pin = refused
    runner.bind(d, cluster)
    assert d.meta["pinned"]["held"] is None and d.meta["pinned"]["cpus"] == "10-11"


def test_heap_profiles_of_grown_routers_are_kept_beside_the_run(lab_files, tmp_path):
    run = engine(lab_files)
    run.spool = tmp_path / "run"
    asked = []
    run.routers.get = lambda router, path, timeout=2: asked.append(router) or {"rss_mb": 1500.0, "profile": "cHJvZmlsZQ=="}
    run.key = RunKey("bad-gadget", "bgp", "s", 1)
    run.keep_heaps({"a": 1500.5, "b": 30.0})
    assert asked == ["a"] and (tmp_path / "run" / "heap-a.pb.gz").read_bytes() == b"profile"


def test_a_paused_queue_interrupts_between_two_runs(lab_files, monkeypatch):
    from lab import results

    d = lab_smoke_result("t-pause")
    fake_lab(monkeypatch, FakeCluster(config.Cluster()))
    played = []

    class Plays:
        def __init__(self, *a):
            pass

        def execute(self):
            played.append(1)
            results.pause_file().parent.mkdir(parents=True, exist_ok=True)
            results.pause_file().write_text("")  # paused while the first run plays
            return {"status": "completed"}, []

    monkeypatch.setattr(runner, "Run", Plays)
    runner.run(d, threading.Event())
    assert played == [1] and d.status["state"] == "interrupted" and d.status["done"] == 1


def test_a_run_without_samples_is_an_error():
    with pytest.raises(LabError, match="no samples"):
        runner.sampled(iter([]))
    assert list(runner.sampled(iter([{"t": "0"}, {"t": "1"}]))) == [{"t": "0"}, {"t": "1"}]
    assert problems.cause("the run wrote no samples")[0] == "samples"


def test_the_runner_the_run_count_and_the_fit_leave_out_the_same_topologies(lab_files, monkeypatch):
    import json

    from lab import cluster

    d = lab_smoke_result("t-fit")
    meta = json.loads((d.path / "dataset.json").read_text())
    meta["experiment"]["topologies"] = ["bad-gadget", "noble-eu"]
    meta["experiment"]["variants"] = meta["experiment"]["variants"][:1]
    (d.path / "dataset.json").write_text(json.dumps(meta))
    d = type(d)(d.path)
    fake_lab(monkeypatch, FakeCluster(config.Cluster()))
    monkeypatch.setattr(runner, "fit", cluster.fit)
    monkeypatch.setattr(cluster, "capacity", lambda: {"cpus": 6, "memory_mb": 64000})  # 2 bound CPUs keep 8 routers
    here = cluster.fit(d.experiment)
    assert list(here.skipped) == ["noble-eu"] and here.skipped["noble-eu"] == ["28 routers"]
    played = []

    class Plays:
        def __init__(self, dataset, key, *a):
            played.append(key.topology)

        def execute(self):
            return {"status": "completed"}, [{"t": 0}]

    monkeypatch.setattr(runner, "Run", Plays)
    runner.run(d, threading.Event())
    assert set(played) == {"bad-gadget"} and d.status["total"] == d.experiment.runs_total(here.skipped) == len(played)
    assert d.status["skipped"] == here.skipped and d.status["limit"] == here.limit


def test_the_log_names_a_few_routers_and_counts_many():
    from lab.runner import told
    assert told({"routers": ["r1", "r2"], "links": [("r1", "r2")]}) == "r1, r2, r1–r2"
    assert told({"routers": [f"as{i}" for i in range(128)]}) == "128 routers" and told({}) == ""


def test_a_router_that_samples_rarely_at_rest_does_not_hide_the_rest():
    # b samples every 30 s at rest, a every second: rest shows once b's next sample shows no change.
    rows = {"a": [{"seq": i + 1, "t": float(i), "destinations": 1, "paths": 1, "updates_rx": 5} for i in range(31)],
            "b": [{"seq": 1, "t": 0.0, "destinations": 1, "paths": 2, "updates_rx": 9},
                  {"seq": 2, "t": 30.0, "destinations": 1, "paths": 2, "updates_rx": 9}]}

    class Routers:
        def get(self, router, path, timeout=2):
            return {"samples": [dict(r) for r in rows[router]], "failures": 0}

    sampler = runner.Sampler(Routers(), ["a", "b"], 1.0)
    sampler.fetch()
    assert sampler.last_t == 30.0 and sampler.quiet_since == 0.0  # every second a tick, none a change
    sampler.pool.shutdown()


def test_the_final_check_waits_for_a_busy_router_and_asks_it_again(lab_files):
    run = engine(lab_files)
    names = sorted(run.network.routers)
    first, last = names[0], names[-1]
    asked = []

    class Busy(Routers):
        def get(self, router, path, timeout=2):
            asked.append((router, timeout))
            if router == first and asked.count((first, timeout)) == 1:
                raise runner.LabError(f"{router} /routes: Read timed out")
            return {"10.0.0.0/24": {"router": router}}

    run.routers = Busy({})
    run.stopped = {last}
    tables, slowest = run.final_tables()
    assert list(tables) == names and tables[last] == {} and all(tables[r] for r in names[:-1])
    assert {t for _, t in asked} == {runner.FINAL_S}
    assert [r for r, _ in asked].count(first) == 2 and last not in [r for r, _ in asked]
    assert slowest[0] in names[:-1]


def test_the_final_check_gives_up_on_a_router_that_never_answers(lab_files):
    run = engine(lab_files)

    class Silent(Routers):
        def get(self, router, path, timeout=2):
            raise runner.LabError(f"{router} /routes: Read timed out")

    run.routers = Silent({})
    with pytest.raises(runner.LabError):
        run.final_tables()


def test_a_run_profiles_the_router_with_the_most_neighbors_once_and_keeps_the_profile(lab_files, tmp_path):
    import base64
    run = engine(lab_files)
    run.experiment = run.experiment.model_copy(update={"sampling": run.experiment.sampling.model_copy(update={"profile_s": 30})})
    run.spool = tmp_path
    busiest = max(sorted(run.network.routers), key=lambda r: len(run.network.routers[r].get("neighbors", [])))
    run.profile_cpu()
    run.profile_cpu()
    assert [c for c in run.routers.calls if c[1] == "/cpu"] == [(busiest, "/cpu", {"seconds": 30})]
    run.routers.get = lambda router, path, timeout=2: {"seconds": 30, "taken": 1.0, "profile": base64.b64encode(b"pprof").decode()}
    run.keep_cpu()
    assert (tmp_path / f"cpu-{busiest}.pb.gz").read_bytes() == b"pprof"


def test_a_run_takes_no_cpu_profile_unless_the_experiment_asks(lab_files):
    run = engine(lab_files)
    run.profile_cpu()
    run.keep_cpu()
    assert not [c for c in run.routers.calls if c[1] == "/cpu"]
