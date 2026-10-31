import re

from lab import config, notify
from lab.config import Experiment


class Posted:
    def __init__(self, status=204):
        self.calls, self.status = [], status

    def __call__(self, url, json, timeout):
        self.calls.append(json)
        return type("R", (), {"status_code": self.status, "raise_for_status": lambda r: None, "json": lambda r: {}})()


def result(state, **status):
    status = {"state": state, "done": 3, "total": 4, "began": "2026-09-30T10:00:00+00:00", "updated": "2026-09-30T11:05:00+00:00", **status}
    return type("D", (), {"name": "r-1", "status": status, "experiment": Experiment.load(config.path("lab-smoke")),
                          "meta": {"commits": dict.fromkeys(["bgp", "obgp", "obgp-hard", "obgp-np", "obgp-paper"], "be5fb3fb4db6")}})()


def test_problems_do_not_reveal_the_token(lab_files, monkeypatch):
    def fail(url, json, timeout):
        raise notify.requests.ConnectionError(f"cannot reach {url}")
    monkeypatch.setattr(notify.requests, "post", fail)
    problems = notify.test({"discord": "https://discord.com/api/webhooks/1/abc"})
    assert problems and "abc" not in problems[0]
    assert notify.masked("https://discord.com/api/webhooks/1/abc") == "https://discord.com/api/webhooks/1/…"
    notify.save({"discord": "https://discord.com/api/webhooks/1/abc"})
    assert notify.file().stat().st_mode & 0o777 == 0o600


def test_failed_checks_name_the_runs_and_the_first_problem(monkeypatch):
    from lab import analysis

    e = Experiment.load(config.path("lab-smoke"))
    failed = [{"topology": "t", "scenario": "smoke-all", "variant": e.variants[0].name, "run": r, "step": "21", "t": 1.0,
               "routers": ["fulda"], "problems": ["fulda holds 2 prefixes"]} for r in (1, 2)]
    monkeypatch.setattr(analysis, "failed_checks", lambda _: failed)
    assert notify._failed_checks(None, e) == f"`{e.variants[0].name}` 2 runs, fulda holds 2 prefixes"
    monkeypatch.setattr(analysis, "failed_checks", lambda _: [])
    assert notify._failed_checks(None, e) is None


def test_a_host_at_its_limit_is_named_with_its_cause(monkeypatch):
    from lab import analysis

    where = {"topology": "noble-eu", "scenario": "fill-60", "variant": "bgp", "oscillating": True}
    limits = {"set": 10.0, "busy": [{**where, "cpu": 0.94}], "slow": [{**where, "hz": 2.63}]}
    monkeypatch.setattr(analysis, "integrity", lambda _: limits)
    assert notify._host_limit(None) == ("Up to 94 % of the CPUs in noble-eu · fill-60 · `bgp`. "
                                        "Sampled down to 2.63 of 10 Hz in noble-eu · fill-60 · `bgp`, times there exact to about 0.4 s. "
                                        "`bgp` oscillated there.")
    monkeypatch.setattr(analysis, "integrity", lambda _: {"set": 10.0, "busy": [], "slow": []})
    assert notify._host_limit(None) is None


def test_the_start_says_how_long_this_and_the_queue_take(lab_files, monkeypatch):
    from lab import estimate, results

    notify.save({"discord": "https://discord.com/api/webhooks/1/abc", "lab": "https://lab.example.org"})
    posted = Posted()
    monkeypatch.setattr(notify.requests, "post", posted)
    monkeypatch.setattr(estimate, "history", dict)
    monkeypatch.setattr(estimate, "remaining_s", lambda d, past: 3600.0)
    monkeypatch.setattr(results, "queued", lambda: ["r-1", "r-2"])
    monkeypatch.setattr(results.Dataset, "find", staticmethod(lambda name: result("queued")))
    notify.result_started(result("running", done=0, total=6))
    notify.result_started(result("running", done=2, total=6))
    notify.result_started(type("D", (), {"name": "r-1", "status": {}, "experiment": Experiment.load(config.path("lab-smoke"))})())
    started, resumed, new = (call["embeds"][0] for call in posted.calls)
    assert new["description"].startswith(f"{Experiment.load(config.path('lab-smoke')).runs_total()} runs, ")  # before the runner wrote its status
    assert started["title"] == "r-1 started" and started["url"] == "https://lab.example.org/results/r-1" and "fields" not in started
    first, queue = started["description"].splitlines()
    assert first.startswith("6 runs, about 1 h 00 min, until ") and queue.startswith("1 more in the queue, next r-2, about 1 h 00 min, all done around ")
    # Discord shows the date and the reader's own time: an end tomorrow is not read as today.
    assert re.search(r"until <t:\d+:f>$", first) and re.search(r"all done around <t:\d+:f>$", queue)
    assert resumed["title"] == "r-1 resumed" and resumed["description"].startswith("2 of 6 runs done, 4 to go")


def test_the_end_says_how_the_runs_ended_and_what_went_wrong(lab_files, monkeypatch):
    from lab import results

    notify.save({"discord": "https://discord.com/api/webhooks/1/abc"})
    posted = Posted()
    monkeypatch.setattr(notify.requests, "post", posted)
    monkeypatch.setattr(results, "queued", list)
    monkeypatch.setattr(notify, "_statuses", lambda d: "2 done · 1 did not come to rest")
    monkeypatch.setattr(notify, "_failed_checks", lambda d, e: None)
    monkeypatch.setattr(notify, "_host_limit", lambda d: None)
    monkeypatch.setattr(notify, "_properties", lambda d: None)
    notify.result_ended(result("running"))
    assert not posted.calls
    notify.result_ended(result("failed", error="the cluster is gone", errors=1))
    notify.result_ended(result("finished"))
    notify.result_ended(result("stopped"))
    failed, finished, stopped = (call["embeds"][0] for call in posted.calls)
    assert posted.calls[0]["content"] == "@here" and failed["description"].splitlines()[0] == "the cluster is gone"
    assert finished["description"] == "3 of 4 runs in 1 h 05 min\n2 done · 1 did not come to rest" and "fields" not in finished
    assert posted.calls[1]["allowed_mentions"] == {"parse": []}
    assert "stopped by hand" in stopped["description"]



def test_unforeseen_broken_properties_and_the_end_of_a_search_are_told(lab_files, monkeypatch):
    from lab import problems, simulation

    found = [{"cause": "loops", "predicted": False, "topology": "t", "variant": "v", "scenario": "s", "run": r} for r in (1, 2)]
    monkeypatch.setattr(problems, "broken", lambda d: found + [{**found[0], "cause": "reach", "predicted": True}])
    assert notify._properties(None) == "Loops at rest 2 runs"
    notify.save({"discord": "https://discord.com/api/webhooks/1/abc"})
    posted = Posted()
    monkeypatch.setattr(notify.requests, "post", posted)
    monkeypatch.setattr(simulation, "problems", lambda e: [{"proof": "contradicts it"}, {"proof": "outside its model"}])
    notify.search_ended({"id": "1", "state": "running"})
    notify.search_ended({"id": "1", "state": "done", "routers": 5})
    notify.search_ended({"id": "2", "state": "failed", "error": "the simulator timed out"})
    done, failed = (call["embeds"][0] for call in posted.calls)
    assert done["description"] == "2 problems on networks up to 5 routers, 1 contradicts the proofs"
    assert failed["description"] == "the simulator timed out" and posted.calls[1]["content"] == "@here"
