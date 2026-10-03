import threading
import time
from pathlib import Path

import pytest

from lab import config, host, runner, scenario, topology
from lab.cluster import LabError
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
    with pytest.raises(LabError, match="more than the 512 MB a router may use"):
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
    assert sampler.failed == 0 and [r["t"] for r in sampler.samples] == [0.0]
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
    monkeypatch.setattr(host, "cpu_times", lambda: next(times, None))
    load = runner.HostLoad(interval=0.01)
    load.start()
    time.sleep(0.2)
    load.stop()
    load.join()
    summary = load.summary()
    assert summary["cpu_max"] == 0.9 and summary["cpu_mean"] == 0.475
    assert "others_max" not in summary  # the lab cannot be told apart


def test_the_load_of_others_is_told_from_the_lab(monkeypatch):
    times = iter([(0, 100), (90, 200), (95, 300)])
    lab = iter([0, 30, 30])
    monkeypatch.setattr(host, "lab_cgroup", lambda: Path("/"))
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
    monkeypatch.setattr(host, "cpu_times", lambda: (next(busy), next(total)))
    monkeypatch.setattr(host, "lab_cpu_s", lambda group: 0.0)
    assert runner.quiet_host(threading.Event(), cpus=8) is None
