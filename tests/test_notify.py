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
                          "meta": {"commits": {"bgp": "be5fb3fb4db6", "obgp": "be5fb3fb4db6", "obgp-np": "be5fb3fb4db6"}}})()


def test_the_end_of_a_result_is_posted(lab_files, monkeypatch):
    notify.save({"discord": "https://discord.com/api/webhooks/1/abc", "lab": "https://lab.example.org"})
    posted = Posted()
    monkeypatch.setattr(notify.requests, "post", posted)
    notify.result_ended(result("running"))
    assert not posted.calls
    notify.result_ended(result("failed", error="the cluster is gone", errors=1))
    body = posted.calls[0]
    embed = body["embeds"][0]
    assert body["content"] == "@here" and embed["color"] == notify.COLORS["failed"]
    assert embed["url"] == "https://lab.example.org/results/r-1" and embed["description"].startswith("the cluster is gone")
    fields = {f["name"]: f["value"] for f in embed["fields"]}
    assert "Took" not in fields and fields["Since"] and fields["Errors"] == "1 run" and fields["Experiment"] == "`lab-smoke`"
    assert fields["Variants"].splitlines() == ["`bgp` BGP · HEAD be5fb3f", "`obgp` OBGP · HEAD be5fb3f", "`obgp-np` OBGP without pruning · HEAD be5fb3f"]
    assert "Whether the lab runs" in embed["description"]
    notify.result_ended(result("finished"))
    assert posted.calls[1]["allowed_mentions"] == {"parse": []}


def test_problems_do_not_reveal_the_token(lab_files, monkeypatch):
    def fail(url, json, timeout):
        raise notify.requests.ConnectionError(f"cannot reach {url}")
    monkeypatch.setattr(notify.requests, "post", fail)
    problems = notify.test({"discord": "https://discord.com/api/webhooks/1/abc"})
    assert problems and "abc" not in problems[0]
    assert notify.masked("https://discord.com/api/webhooks/1/abc") == "https://discord.com/api/webhooks/1/…"
    notify.save({"discord": "https://discord.com/api/webhooks/1/abc"})
    assert notify.file().stat().st_mode & 0o777 == 0o600


def test_the_variants_are_compared_in_a_table(lab_files):
    from lab.results import Dataset

    table = notify._comparison(Dataset.find("ifip-networking-2026"), Dataset.find("ifip-networking-2026").experiment)
    lines = table.strip("`\n").splitlines()
    assert lines[0].split() == ["conv.", "s", "conv.", "admitted", "suppr.", "at", "rest/s", "timeouts"] and [row.split()[0] for row in lines[1:]] == ["bgp", "obgp"]
    assert len(table) < 1024  # the limit of a field in Discord


def test_the_start_of_a_result_is_posted(lab_files, monkeypatch):
    notify.save({"discord": "https://discord.com/api/webhooks/1/abc", "lab": "https://lab.example.org"})
    posted = Posted()
    monkeypatch.setattr(notify.requests, "post", posted)
    notify.result_started(result("running", done=0, total=6))
    notify.result_started(result("running", done=2, total=6))
    started, resumed = (call["embeds"][0] for call in posted.calls)
    assert started["title"] == "r-1 started" and resumed["title"] == "r-1 resumed" and "content" not in posted.calls[0]
    fields = {f["name"]: f["value"] for f in started["fields"]}
    assert fields["Runs"] == "6" and fields["Experiment"] == "`lab-smoke`" and "`obgp-np` OBGP without pruning" in fields["Variants"]
    assert {f["name"]: f["value"] for f in resumed["fields"]}["Runs"] == "2 of 6 done, 4 to go"


def test_a_stopped_result_says_it_was_stopped_by_hand(lab_files, monkeypatch):
    posted = Posted()
    monkeypatch.setattr(notify.requests, "post", posted)
    notify.save({"discord": "https://discord.com/api/webhooks/1/abc"})
    notify.result_ended(result("stopped"))
    embed = posted.calls[0]["embeds"][0]
    fields = {f["name"]: f["value"] for f in embed["fields"]}
    assert "Stopped by hand" in embed["description"] and fields["Runs"] == "3 of 4 done" and "Medians" not in fields


def test_failed_checks_name_the_runs_and_the_first_problem(monkeypatch):
    from lab import analysis

    e = Experiment.load(config.path("lab-smoke"))
    failed = [{"topology": "t", "scenario": "smoke-all", "variant": e.variants[0].name, "run": r, "step": "21", "t": 1.0,
               "routers": ["fulda"], "problems": ["fulda holds 2 prefixes"]} for r in (1, 2)]
    monkeypatch.setattr(analysis, "failed_checks", lambda _: failed)
    assert notify._failed_checks(None, e) == f"`{e.variants[0].name}` 2 runs, first in smoke-all: fulda holds 2 prefixes"
    monkeypatch.setattr(analysis, "failed_checks", lambda _: [])
    assert notify._failed_checks(None, e) is None
