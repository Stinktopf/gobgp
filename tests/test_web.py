import re
from pathlib import Path

import pytest

from lab import analysis, config, scenario, topology
from lab.config import Experiment
from lab.web import common
from lab.web.routes import experiments as experiment_pages
from lab.web.routes import results as result_pages


def test_login_is_required(app):
    from fastapi.testclient import TestClient

    assert TestClient(app).get("/topologies", follow_redirects=False).headers["location"] == "/login"


@pytest.mark.parametrize("path", [
    "/topologies", "/topologies/new", "/topologies/new?like=bad-gadget", "/topologies/bad-gadget", "/topologies/noble-eu",
    "/scenarios/new?like=smoke-all", "/experiments/new?like=smoke", "/partials/dock", "/scenarios", "/scenarios/new", "/scenarios/smoke-all",
    "/experiments", "/experiments/new", "/experiments/ifip-networking-2026", "/results",
    "/results/ifip-networking-2026", "/results/ifip-networking-2026?tab=replay", "/results/ifip-networking-2026?tab=runs",
    "/results/ifip-networking-2026?tab=details", "/results/ifip-networking-2026?tab=quality", "/settings",
])
def test_pages(client, path):
    page = client.get(path)
    assert page.status_code == 200
    if "partials" not in path:
        title = re.search(r"<title>(.*?)</title>", page.text, re.S).group(1)
        assert title.endswith(" · OBGP Lab") and "<" not in title and "\n" not in title


def test_unknown_pages_are_404(client):
    r = client.get("/topologies/nope", headers={"accept": "text/html"})
    assert r.status_code == 404 and "No topology nope." in r.text


def test_topology_save_as_copy_and_rename(client):
    t = topology.load("bad-gadget")
    body = {"routers": t["routers"], "roles": t["roles"], "source": t["source"]}
    assert client.post("/topologies/save", json={**body, "name": "t-a", "original": "bad-gadget", "mode": "copy"}).status_code == 200
    assert topology.path("bad-gadget").exists() and topology.path("t-a").exists()
    assert client.post("/topologies/save", json={**body, "name": "t-b", "original": "t-a", "mode": "rename"}).status_code == 200
    assert not topology.path("t-a").exists()
    used = client.post("/topologies/save", json={**body, "name": "t-c", "original": "noble-eu", "mode": "rename"})
    assert used.status_code == 422 and "copy" in used.json()["problems"][0]


def test_topology_in_use_is_not_deleted(client):
    client.post("/topologies/noble-eu/delete")
    assert topology.path("noble-eu").exists()


def test_scenario_save_and_preview(client):
    steps = [{"announce": {"rate": 1, "for": 5}}, {"down": {"link": "random"}}, {"up": {}}]
    assert client.post("/scenarios/save", json={"name": "t-s", "original": "", "steps": steps}).json() == {"saved": "t-s"}
    assert scenario.load("t-s").steps[0].kind == "announce"
    preview = client.post("/scenarios/preview", json={"steps": steps, "topology": "bad-gadget"}).json()
    assert preview["problems"] == [] and "1" in preview["targets"]
    bad = client.post("/scenarios/preview", json={"steps": [{"parallel": []}]}).json()
    assert bad["problems"]


def test_experiment_builder(client):
    form = {"name": "t-e", "runs": "2", "seed": "1", "topologies": ["bad-gadget"], "scenarios": ["smoke-drain"],
            "v0_name": "bgp", "v0_ref": "HEAD", "v0_mode": "bgp", "v0_interval": "1.0", "v1_name": "half", "v1_ref": "HEAD", "v1_mode": "random-np",
            "v1_share": "50", "v1_interval": "", "cpus": "2", "memory_mb": "4096", "hold_time": "9", "keepalive": "3", "connect_retry": "5",
            "interval": "0.1", "stable_s": "3", "action": "save"}
    assert client.post("/experiments/save", data=form).json() == {"saved": "t-e"}
    assert [v.interval for v in Experiment.load(config.path("t-e")).variants] == [1.0, None]
    e = config.Experiment.load(config.path("t-e"))
    assert [(v.mode, v.share) for v in e.variants] == [("bgp", None), ("random-np", 0.5)]
    assert e.bgp.hold_time == 9
    assert "4 runs" in client.post("/experiments/estimate", data=form).text
    refused = client.post("/experiments/save", data={**form, "name": "t-f", "v0_ref": "no-such-ref"})
    assert refused.status_code == 422 and "unknown git ref" in refused.json()["problems"][0]


def test_settings(client):
    from lab import notify

    hook = "https://discord.com/api/webhooks/123/secret-token"
    assert "error" in client.post("/settings/notify", data={"discord": "https://example.org/x"}, follow_redirects=False).headers["location"]
    client.post("/settings/notify", data={"discord": hook})
    client.post("/settings/notify", data={"discord": ""})  # an empty field keeps it
    assert notify.load() == {"discord": hook, "lab": "http://testserver"}
    page = client.get("/settings").text
    assert "secret-token" not in page and "webhooks/123/…" in page
    client.post("/settings/notify", data={"action": "off"})
    assert notify.load() == {}
    wrong = client.post("/settings/password", data={"current": "nope", "new": "long-enough", "repeat": "long-enough"}, follow_redirects=False)
    assert "wrong" in wrong.headers["location"]
    client.post("/settings/password", data={"current": "test-password", "new": "long-enough", "repeat": "long-enough"})
    from lab.web import auth
    assert auth.check_password("long-enough", auth.load())


def test_new_topologies(client):
    assert 'value="bad-gadget-copy"' in client.get("/topologies/new?like=bad-gadget").text
    r = client.post("/topologies/save", json={"name": "t-empty", "original": "", "routers": {}, "roles": {}})
    assert r.status_code == 200 and topology.load("t-empty")["routers"] == {}


def test_forms_return_to_the_page_they_came_from(client):
    r = client.post("/results/ifip-networking-2026/stop", headers={"referer": "http://testserver/topologies?x=1"}, follow_redirects=False)
    assert r.headers["location"] == "/topologies?x=1"


def test_the_assets_are_served_without_sign_in(app):
    from fastapi.testclient import TestClient

    r = TestClient(app).get("/assets/mark.svg")
    assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg")


def test_a_first_start_sets_an_initial_password_to_change(app, lab_files):
    from fastapi.testclient import TestClient

    from lab.web import auth

    auth.file().unlink(missing_ok=True)
    file = Path(auth.initialize())
    assert file.stat().st_mode & 0o777 == 0o600 and auth.initialize() is None  # only once
    c = TestClient(app)
    assert "initial password" in c.get("/login").text
    c.post("/login", data={"password": file.read_text().strip()})
    assert c.get("/topologies", follow_redirects=False).headers["location"] == "/settings"
    assert "Discord" not in c.get("/settings").text
    assert c.get("/partials/dock", headers={"HX-Request": "true"}).status_code == 204
    new = {"current": file.read_text().strip(), "new": "a-password-of-mine", "repeat": "a-password-of-mine"}
    assert "Password changed" in c.post("/settings/password", data=new).text  # and still signed in
    assert not file.exists() and not auth.must_change(auth.load())


def test_only_private_results_that_do_not_run_are_deleted(client, lab_files, monkeypatch):
    import json

    from lab import cluster, results
    from lab.config import Experiment

    e = Experiment.load(config.path("lab-smoke"))
    path = results.PUBLIC / "t-delete"
    path.mkdir(parents=True)
    (path / "dataset.json").write_text(json.dumps({"experiment": e.model_dump(mode="json"), "commits": {}, "created": "2026-01-01"}))
    d = results.Dataset(path)
    delete = lambda: client.post("/results/t-delete/delete", follow_redirects=False).headers["location"]
    assert "private+first" in delete() and path.exists()
    d.publish(False)
    monkeypatch.setattr(cluster, "holder", lambda: "t-delete")
    assert "Stop+it+first" in delete()
    monkeypatch.setattr(cluster, "holder", lambda: None)
    assert delete() == "/results" and results.Dataset.find("t-delete") is None


def test_results_of_an_older_format_are_listed_and_deleted(client, lab_files):
    import json

    from lab import results

    path = results.PRIVATE / "t-old"
    path.mkdir(parents=True)
    (path / "dataset.json").write_text(json.dumps({"experiment": {"timing": {"announce": 10}}, "created": "2025-01-01"}))
    assert "t-old" in client.get("/results").text
    client.post("/results/t-old/delete", headers={"referer": "http://testserver/results"})
    assert not path.exists()


def test_a_deleted_result_ends_its_polling(client):
    r = client.get("/results/nope/partials/header", headers={"HX-Request": "true"})
    assert r.status_code == 286 and r.headers["HX-Redirect"] == "/results"


def test_checks_are_a_metric_only_of_results_with_checks(client):
    page = client.get("/results/ifip-networking-2026?tab=table").text
    assert "Full reach" in page and ">Checks<" not in page
    assert client.get("/results/ifip-networking-2026/partials/overview?metric=checks").status_code in (200, 286)  # falls back


def test_results_export_for_papers(client):
    summary = client.get("/results/ifip-networking-2026/summary.csv")
    assert summary.status_code == 200 and "attachment" in summary.headers["content-disposition"]
    head, first = summary.text.splitlines()[:2]
    assert head.startswith("topology,scenario,variant,runs,checks_passed,checks_runs,convergence_s_median") and first.split(",")[0] in ("germany50", "bad-gadget", "noble-eu")
    series = client.get("/results/ifip-networking-2026/series.csv?topology=germany50&scenario=full-drain-60").text
    assert series.splitlines()[0] == "t_s,variant,metric,median,ci_low,ci_high,ci_level,router_min,router_max" and ",bgp,paths," in series


def test_runs_lead_to_their_replay(client):
    runs = client.get("/results/ifip-networking-2026?tab=runs").text
    assert "?tab=replay&topology=germany50&scenario=fill-30&run=2&variant=obgp" in runs
    replay = client.get("/results/ifip-networking-2026?tab=replay&topology=germany50&scenario=fill-30&run=2&variant=obgp").text
    assert '<option value="2" selected>' in replay


def test_progress_tells_how_many_runs_are_done(client):
    progress = client.get("/results/ifip-networking-2026/progress").json()
    assert set(progress) == {"done", "state"} and isinstance(progress["done"], int)


def test_the_builder_tells_how_many_routers_a_mix_gives_obgp(client):
    form = {"name": "t-m", "runs": "1", "seed": "1", "topologies": ["adversarial"], "scenarios": ["class-withdraw"],
            "v0_name": "h", "v0_ref": "HEAD", "v0_mode": "hybrid-rp", "v1_name": "r", "v1_ref": "HEAD", "v1_mode": "random-np", "v1_share": "50",
            "cpus": "2", "memory_mb": "4096", "hold_time": "9", "keepalive": "3", "connect_retry": "5", "interval": "0.1", "stable_s": "3"}
    page = client.post("/experiments/estimate", data=form).text
    assert "h: OBGP with refresh pruning on 1 of 9 on adversarial, as the topology marks them" in page
    assert "r: OBGP without pruning on 4 of 9 on adversarial, drawn anew for every run" in page


def test_two_results_compare(client):
    page = client.get("/results/compare?a=ifip-networking-2026&b=ifip-networking-2026&topology=germany50&metric=rib_mean")
    assert page.status_code == 200 and "The same setup, code and files." in page.text and "78 →</span> 78" in page.text
    assert client.get("/results/compare?a=ifip-networking-2026&b=nothing").status_code == 404


def test_a_broken_scenario_does_not_break_the_list(client, lab_files):
    from lab import scenario

    scenario.path("broken").write_text("name: broken\nsteps:\n  - nonsense: {}\n")
    page = client.get("/scenarios")
    assert page.status_code == 200 and "/scenarios/broken/delete" in page.text


def test_static_files_carry_a_version_of_their_content(client):
    page = client.get("/topologies").text
    assert "/static/app.css?v=" in page and 'data-icons="/static/icons.svg?v=' in page


def test_the_limits_of_the_measurements_are_named(client, monkeypatch):
    from lab import analysis

    groups = [{"topology": "t", "scenario": "s", "variant": "v",
               "metrics": {"sample_hz": {"min": 2.0}, "sample_hz_min": {"min": 1.2}, "host_cpu_max": {"max": 0.97}}}]
    monkeypatch.setattr(analysis, "summary", lambda dataset: groups)
    d = type("D", (), {"experiment": type("E", (), {"sampling": type("S", (), {"interval": 0.1})(), "variants": [], "sampling_of": lambda self, v: self.sampling})(), "keys": lambda self: [], "status": {}})()
    s = analysis.integrity(d)
    assert s["slow"] == [{"topology": "t", "scenario": "s", "variant": "v", "oscillating": False, "hz": 1.2}] and s["low"] == 1.2 and s["high"] == 2.0
    assert s["busy"] == [{"topology": "t", "scenario": "s", "variant": "v", "oscillating": False, "cpu": 0.97}] and s["images"] == {}
    assert s["noise"] is None  # a host of its own
    groups[0]["metrics"]["host_others_mean"] = {"median": 0.04, "max": 0.12}
    assert analysis.integrity(d)["noise"] == {"median": 0.04, "max": 0.12}
    groups[0]["metrics"]["oscillates"] = {"median": 1, "min": 1, "max": 1, "n": 1}
    assert analysis.integrity(d)["busy"][0]["oscillating"]  # the cause the page names


def test_run_all_queues_the_checks_first_and_leaves_out_what_does_not_fit(client, monkeypatch):
    from lab import cluster
    from lab.web import app as web

    monkeypatch.setattr(cluster, "capacity", lambda: {"cpus": 16, "memory_mb": 32000})
    queued = []
    monkeypatch.setattr(web.jobs, "enqueue", queued.append)
    page = client.get("/experiments").text
    assert "Run all" in page and re.search(r"1 experiment and \d+ topologies left out", page)  # internet-dfz, germany50 and more
    assert client.post("/experiments/run-all", follow_redirects=False).status_code == 303
    names = [q.rsplit("-", 2)[0] for q in queued]
    assert names[:2] == ["lab-smoke", "lab-calibration"]
    labs = [n.startswith("lab-") for n in names]
    assert labs == sorted(labs, reverse=True)  # every check of the lab before the experiments
    assert "ifip-networking-2026" in names and "internet-dfz" not in names
    assert "internet-scale" in names and "behaviour-failures" in names  # it skips what does not fit
    for which, lab in (("lab", True), ("experiments", False)):
        queued.clear()
        client.post("/experiments/run-all", data={"which": which}, follow_redirects=False)
        assert queued and all(q.startswith("lab-") == lab for q in queued)


def test_the_builder_names_the_topologies_this_host_leaves_out(monkeypatch):
    from lab import cluster

    e = config.Experiment.load(config.path("internet-scale"))
    monkeypatch.setattr(cluster, "oversized", lambda _: {"core-256": ["256 routers"]})
    notes = experiment_pages.host_notes(e)
    assert "core-256 needs 256 routers." in notes and "so the experiment runs without them." in notes
    monkeypatch.setattr(cluster, "oversized", lambda _: {})
    assert 'class="hidden"' in experiment_pages.host_notes(e)


def test_failed_checks_are_counted_per_topology(monkeypatch):
    from lab import analysis

    groups = [{"topology": "a", "statuses": {"failed": 2}}, {"topology": "a", "statuses": {"completed": 1}},
              {"topology": "b", "statuses": {"failed": 1}}]
    monkeypatch.setattr(analysis, "summary", lambda _: groups)
    assert result_pages.failed_by_topology(None) == {"a": 2, "b": 1}


def test_the_table_names_its_methods_and_shows_the_ci(client):
    page = client.get("/results/ifip-networking-2026?tab=table&metric=rib_mean").text
    assert "data-range" in page and "order statistics" in page and "95 % needs 6 runs" in page  # five runs
    page = client.get("/results/ifip-networking-2026?tab=table&metric=rib_mean&baseline=bgp").text
    assert "Wilcoxon" in page and "Hodges–Lehmann" in page  # in the tooltips of the cells


def test_picked_results_are_run_again_once_per_experiment_and_deleted(client, monkeypatch):
    from lab import results
    from lab.web import app as web

    queued = []
    monkeypatch.setattr(web.jobs, "enqueue", queued.append)
    e = config.Experiment.load(config.path("lab-smoke"))
    a, b = results.Dataset.new_name(e), None
    results.Dataset.create(e, a)
    b = a + "-b"
    results.Dataset.create(e, b)
    r = client.post(f"/results/run-again?names={a}&names={b}&names=ifip-networking-2026", follow_redirects=False)
    assert r.status_code == 303 and len(queued) == 2
    assert queued[0].startswith("lab-smoke-") and queued[1].startswith("ifip-networking-2026-")
    r = client.post(f"/results/delete?names={a}&names={b}&names=ifip-networking-2026", follow_redirects=False)
    assert "Not+deleted" in r.headers["location"] and "ifip-networking-2026" in r.headers["location"]
    assert not results.Dataset.find(a) and not results.Dataset.find(b) and results.Dataset.find("ifip-networking-2026")


def test_the_scenario_editor_loads_only_the_topology_it_shows(client):
    page = client.get("/scenarios/smoke-all").text
    assert len(page) < 100_000 and '"routers"' not in page.split('id="topologies-data">')[1].split("</script>")[0]
    data = client.get("/topologies/bad-gadget/data").json()
    assert set(data) == {"routers", "roles"} and "aachen" in data["routers"]
    assert client.get("/topologies/nothing/data").status_code == 404


def test_the_dock_sends_the_parts_of_a_waiting_result_when_it_is_opened(client, monkeypatch):
    from lab import results
    from lab.web import app as web

    ifip = results.Dataset.find("ifip-networking-2026")
    monkeypatch.setattr(web.jobs, "active", lambda: None)
    monkeypatch.setattr(web.jobs, "queue", lambda: ["ifip-networking-2026"])
    dock = client.get("/partials/dock").text
    assert 'hx-get="/partials/dock/parts/ifip-networking-2026"' in dock and "dock-run-completed" not in dock
    parts = client.get("/partials/dock/parts/ifip-networking-2026").text
    # As in the runs of the result: BGP on the bad gadget ends without rest.
    finished = sum(parts.count(f"dock-run-{s}") for s in ("completed", "restless", "allowed", "timeout", "failed", "error"))
    assert finished == len(ifip.statuses()) > 0
    assert "dock-run-failed" in parts and "dock-run-completed" in parts  # without rest a run failed, as with a failed check


def test_one_toggle_chooses_interval_or_router_spread(client):
    table = client.get("/results/ifip-networking-2026?tab=table&metric=rib_mean").text
    assert 'name="band-table"' in table and 'data-range="ci"' in table and 'data-range="routers"' in table
    assert 'value="none"' in table and "93.8 %, 5 runs" in table  # the level in the tooltip of Interval
    charts = client.get("/results/ifip-networking-2026?tab=charts").text
    assert 'name="band-charts"' in charts and "data-spread" not in charts


def test_a_choice_that_gives_nothing_is_greyed_out(client):
    times = client.get("/results/ifip-networking-2026?tab=table&metric=settle_s").text
    assert 'value="routers" data-band disabled' in times and 'value="ci" data-band disabled' not in times  # five runs give an interval
    sizes = client.get("/results/ifip-networking-2026?tab=table&metric=rib_mean").text
    assert 'value="routers" data-band disabled' not in sizes


def test_a_bgp_that_oscillates_never_settles_and_says_so(client):
    page = client.get("/results/ifip-networking-2026?tab=table&topology=bad-gadget&metric=settle_s").text
    assert ">never</span>" in page and "Routes kept changing to the end of every run" in page


def test_values_beside_a_never_are_best_even_when_equal(client):
    page = client.get("/results/ifip-networking-2026?tab=table&topology=bad-gadget&metric=settle_s").text
    row = next(r for r in page.split("<tr") if "scenario=fill-30&" in r or "scenario=fill-30\"" in r)
    import re
    values = re.findall(r'class="([^"]*)" data-value', row)  # the values; their ranges carry the same badge, hidden
    best, never = sum("bg-emerald-100" in c for c in values), row.count(">never</span>")
    assert never == 1 and best == 1 and "bg-rose-100" in row  # OBGP best, the never of BGP worst


def test_values_that_look_the_same_compare_the_same():

    assert common.shown(0.004, "hold_churn") == common.shown(0.0, "hold_churn") == 0
    assert common.shown(2.04, "settle_s", 1) == 2.0 and common.shown(None, "settle_s") is None


def test_sizes_are_neither_best_nor_worst(client):
    import re

    sizes = client.get("/results/ifip-networking-2026?tab=table&metric=rib_mean").text
    assert not any("bg-emerald-100" in c or "bg-rose-100" in c for c in re.findall(r'class="([^"]*)" data-value', sizes))


def test_compare_names_what_only_one_has_and_says_when_nothing_is_shared():
    from lab import results

    ifip = results.Dataset.find("ifip-networking-2026")
    c = result_pages.comparison(ifip, ifip, ifip.experiment.topologies[0], "rib_mean")
    assert c["rows"] and not [d for d in c["differences"] if "only in one" in d[0]]
    assert result_pages.SETTING_NAMES["memory_mb"] == "memory, MiB"


def test_a_listing_fits_its_width():
    from lab.web.common import listing

    assert listing(["bgp", "obgp", "obgp-hard", "obgp-np", "obgp-paper"]) == "bgp, obgp, obgp-hard, …"
    assert listing(["sim-export-filter-obgp-hard-unreachable", "x"]) == "sim-export-filter-obgp-hard…"
    assert all(len(listing(names)) <= 28 + 3 for names in (["a" * 40], ["a" * 10] * 9))


def test_settings_say_whether_docker_runs(client, monkeypatch):
    from lab import host

    monkeypatch.setattr(host, "docker_running", lambda: False)
    page = client.get("/partials/cluster").text
    assert "Docker stopped" in page


def test_runs_say_whether_they_came_to_rest_and_how_they_were_sampled(client):
    from lab.results import Dataset

    d = Dataset.find("ifip-networking-2026")
    rows = result_pages.sampling_table(d)
    assert {r["variant"] for r in rows} == {"bgp", "obgp"} and all(r["runs"] and r["set_hz"] > 0 for r in rows)
    run = rows[0]["runs"][0]  # every run traceable: its slowest router, its longest gap
    assert run["slowest_router"] and run["gap"] > 0 and run["resolution"] == 2 / run["slowest"]
    assert [r["limit"] for r in rows] == sorted((r["limit"] for r in rows), reverse=True)  # at the limit first
    metrics = analysis.run_summary(d)
    key = next(k for k in d.keys() if d.is_done(k) and str(k) in metrics and metrics[str(k)].get("oscillates") == 1)
    facts = result_pages.run_facts(d, key, d.run(key), metrics[str(key)])
    assert facts["settled"] is False and facts["facts"][0].startswith("Sampling: ")  # the title says it did not come to rest
    assert result_pages.run_facts(d, key, {"status": "error"}, {}) == {"settled": None, "allowed": False, "facts": []}
    assert result_pages.run_facts(d, key, {"status": "error", "message": "routers of t did not become ready"}, {})["facts"] == ["routers of t did not become ready"]
    runs = client.get("/results/ifip-networking-2026?tab=runs").text
    assert "Routes still change at the end" in runs and "Rest: after" in runs
    k = next(k for k in d.keys() if d.is_done(k))
    rate = analysis.series(d, k.topology, k.variant, k.scenario)["metrics"]["sample_rate"]  # every second, slowest to fastest router
    assert any(x is not None for x in rate["median"]) and all(lo <= hi for lo, hi in zip(rate["min"], rate["max"]) if lo is not None)
    quality = client.get("/results/ifip-networking-2026?tab=quality").text
    assert 'data-metrics="quality"' in quality
    assert "Measurement quality" in quality and "Slowest router" in quality and "Run 1" in quality


def test_starting_from_the_list_of_experiments_stays_there(client, monkeypatch):

    monkeypatch.setattr("lab.web.routes.experiments.start", lambda name: "r-1")
    assert client.post("/experiments/lab-smoke/start?stay=1", follow_redirects=False).headers["location"] == "/experiments"
    assert client.post("/experiments/lab-smoke/start", follow_redirects=False).headers["location"] == "/results/r-1"


def test_problems_of_several_routers_read_as_one():
    from lab.web.common import problems

    assert problems(["r1 misses 1 of 1 prefixes", "r2 misses 1 of 1 prefixes", "r3 holds 2 prefixes",
                     "10.0.0.0/24: AS 2 offers 2 different paths"]) == [
        "r1, r2 miss 1 of 1 prefixes", "r3 holds 2 prefixes", "10.0.0.0/24: AS 2 offers 2 different paths"]


def test_a_file_that_does_not_load_says_what_is_wrong_where():
    from lab import scenario
    from lab.web.common import load_problem

    with pytest.raises(ValueError) as error:
        scenario.parse({"name": "x", "steps": [{"expect": {"router": "all", "may_fail": ["hybrid-hp"]}}]})
    assert load_problem(error.value) == "step 1 may_fail: hybrid-hp is mixed, name its pure mode obgp-hp"


def test_a_host_at_its_limit_is_one_line_with_a_link_to_the_details(client, monkeypatch):
    from lab import analysis

    where = {"topology": "t", "scenario": "s", "oscillating": True}
    limits = {"set": 10.0, "low": 2.63, "high": 5.1, "busy": [{**where, "variant": "bgp", "cpu": 0.94}],
              "slow": [{**where, "variant": "bgp-1hz", "hz": 2.63}], "shifting": [], "images": {}, "noise": None, "skipped": {}, "limit": None}
    monkeypatch.setattr(analysis, "integrity", lambda dataset: limits)
    html = common.templates.env.get_template("partials/result-header.html").render(
        integrity=limits, result=type("R", (), {"name": "r-1", "meta": {}})(), experiment=type("E", (), {"name": "e", "description": ""})(),
        status={}, failed={}, source=None, problems=[])
    line = " ".join(html.split("Limits of the measurements")[1].split("</li>")[0].split())
    assert "Host at its limit during bgp, bgp-1hz (oscillating): up to 94 % CPU, sampled down to 2.6 of 10 Hz." in line
    assert "tab=quality" in line


def test_every_experiment_saves_unchanged_through_the_builder():
    from starlette.datastructures import FormData


    for path in sorted(config.ROOT.joinpath("experiments").glob("*.yaml")):
        e = Experiment.load(path)
        v = experiment_pages.builder_values(e)
        form = [(k, str(v[k])) for k in ("name", "description", "runs", "seed", "cpus", "memory_mb", "router_limit_mb", "hold_time",
                                          "keepalive", "connect_retry", "mrai", "refresh", "interval", "stable_s")]
        form += [("topologies", t) for t in v["topologies"]] + [("scenarios", s) for s in v["scenarios"]]
        form += [("paired", "on")] if v["paired"] else []
        form += [("graceful_restart", "on")] if v["graceful_restart"] else []
        for i, x in enumerate(v["variants"]):  # as the template fills the row
            form += [(f"v{i}_name", x["name"]), (f"v{i}_ref", x["ref"]), (f"v{i}_mode", x["mode"]),
                     (f"v{i}_share", str(round(x["share"] * 100)) if x["share"] else "50"), (f"v{i}_interval", str(x["interval"] or "")),
                     (f"v{i}_refresh_delay", str(x["refresh_delay"] or ""))] + ([(f"v{i}_per_neighbor", "on")] if x["per_neighbor"] else [])
        for i, w in enumerate(v["sweeps"]):
            form += [(f"s{i}_scenario", w["scenario"]), (f"s{i}_param", w["param"]), (f"s{i}_values", w["values"])]
        form += [(f"primary_{k}", x) for k, x in (v["primary"] or {}).items()]
        assert experiment_pages.parse_builder(FormData(form)).model_dump() == e.model_dump(), path.name


def test_axis_ceiling_is_a_round_value_above_the_data():
    assert common.ceiling([0.013, 0.021], 1, 0.01) == 0.05
    assert common.ceiling([0.0], 1, 0.01) == 0.01
    assert common.ceiling([0.7], 0.5, 0.01) == 0.5
    assert common.ceiling([40 * 1024, 41 * 1024], 1007 * 1024, 1024, 1024) == 50 * 1024


def test_host_charts_scale_to_their_data_with_a_chart_of_the_gpus(monkeypatch):
    series = {"seconds": 600, "split": True, "busy": [0.01, 0.03], "lab": [0.0, 0.01], "others": [0.01, 0.02],
              "memory_mb": [40 * 1024, 42 * 1024], "lab_mb": [0, 1024], "gpu": [0.1, 0.3]}
    monkeypatch.setitem(common.templates.env.globals, "host_series", lambda: series)
    machine = {"busy": 0.02, "lab": 0.01, "others": 0.01, "threads": 255, "total_mb": 1007 * 1024,
               "memory_mb": 42 * 1024, "lab_mb": 1024, "gpus": [{"name": "RTX", "util": 30, "memory_mb": 1024, "total_mb": 24576}]}
    limits = {"cpus": 128, "headroom": 8, "per_cpu": 4, "memory_mb": 512 * 1024, "keep_mb": 32 * 1024, "by_memory": 600}
    html = common.templates.get_template("partials/lab.html").render(
        machine=machine, limits=limits, max_routers=512, cluster_state={"status": "Running"})
    assert "min 1.0 · max 3.0 %" in html and "min 40 · max 42 GiB" in html and "min 10 · max 30 %" in html
    # A large host shows small shares with a decimal, the lab in busy threads against its own.
    assert "2.0 <span" in html and "2.6 of 128" in html
    assert ">5 %</div>" in html and ">50 GiB</div>" in html and ">50 %</div>" in html
    assert "stroke-dasharray" not in html
    assert 'aria-label="GPU over the last minutes"' in html and "lg:grid-cols-3" in html and "1.0 of 24 GiB" in html
    assert html.count("ml-auto") == 1  # the badge of the cluster, on the right


def test_times_are_marked_best_or_worst_only_beyond_their_resolution(client):
    def row(topology, scenario):
        page = client.get(f"/results/ifip-networking-2026?tab=table&topology={topology}&metric=settle_s").text
        return page.split(f"scenario={scenario}\"", 1)[1].split("</tr>", 1)[0]
    assert "bg-emerald-100" not in row("germany50", "full-drain-60")  # 5 against 4 s, exact to 2 s
    assert "bg-emerald-100" in row("noble-eu", "full-drain-60") and "bg-rose-100" in row("noble-eu", "full-drain-60")  # 2 against 36 s


def test_the_table_names_the_primary_comparison_and_corrects_it_by_holm(client, lab_files):
    import json
    import shutil

    from lab import analysis, results

    source = results.Dataset.find("ifip-networking-2026").path
    target = results.PRIVATE / "t-primary"
    shutil.copytree(source, target)
    meta = json.loads((target / "dataset.json").read_text())
    meta["experiment"]["primary"] = {"metric": "rib_mean", "variant": "obgp", "baseline": "bgp"}
    (target / "dataset.json").write_text(json.dumps(meta))
    found = analysis.primary(results.Dataset(target))
    assert found["tested"] == 27 and found["significant"] == 0  # five pairs: p is at least 0.0625
    assert all(c["holm"] >= c["p"] for c in found["cells"] if "holm" in c)
    page = client.get("/results/t-primary?tab=table&topology=noble-eu&metric=rib_mean&baseline=bgp").text
    assert "Primary comparison:" in page and "0 of 27 cells significant at 5 % after Holm" in page and "Holm p: " in page


def test_slow_work_does_not_hold_up_other_requests(client, monkeypatch):
    """Async handlers do their work in the thread pool: a slow generator, estimate or import must
    not keep the event loop from answering others, the watchdog's /login among them."""
    import threading
    import time

    from lab import generate

    monkeypatch.setattr(generate, "generate", lambda *a, **kw: time.sleep(1.5) or ["slow"])
    with client:  # one event loop for both requests
        slow = threading.Thread(target=lambda: client.post("/topologies/generate", data={"model": "x", "sizes": "3"},
                                                           follow_redirects=False))
        slow.start()
        time.sleep(0.2)
        began = time.monotonic()
        assert client.get("/login").status_code == 200
        waited = time.monotonic() - began
        slow.join()
    assert waited < 0.5


def test_a_time_of_day_carries_its_moment_for_the_readers_time_zone():
    from datetime import datetime, timedelta, timezone

    shown = str(common.clock(datetime(2026, 10, 31, 5, 38, tzinfo=timezone.utc) + timedelta(days=3)))
    assert shown.startswith('<time datetime="') and "data-clock" in shown and shown.endswith("</time>")
    assert ">Tue " in shown  # another day than today names its weekday


def test_queued_work_starts_a_switched_off_cluster_only_when_the_person_agreed(client, monkeypatch):
    from lab.web import app as web

    started = []
    monkeypatch.setattr("lab.web.routes.experiments.start", lambda name: "r-1")
    monkeypatch.setattr("lab.web.routes.experiments.cluster.manually_stopped", lambda: True)
    monkeypatch.setattr(web.jobs.cluster_control, "request", lambda action, values=None: started.append(action))
    client.post("/experiments/lab-smoke/start?stay=1", follow_redirects=False)
    assert started == []
    client.post("/experiments/lab-smoke/start?stay=1", data={"start_cluster": "1"}, follow_redirects=False)
    assert started == ["start"]


def test_the_experiments_say_how_long_all_take(client):
    assert " in all</span>" in client.get("/experiments").text
