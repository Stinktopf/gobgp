import re
from pathlib import Path

import pytest

from lab import config, scenario, topology


def test_login_is_required(app):
    from fastapi.testclient import TestClient

    assert TestClient(app).get("/topologies", follow_redirects=False).headers["location"] == "/login"


@pytest.mark.parametrize("path", [
    "/topologies", "/topologies/new", "/topologies/new?like=bad-gadget", "/topologies/bad-gadget", "/topologies/noble-eu",
    "/scenarios/new?like=smoke-all", "/experiments/new?like=smoke", "/partials/dock", "/scenarios", "/scenarios/new", "/scenarios/smoke-all",
    "/experiments", "/experiments/new", "/experiments/ifip-networking-2026", "/results",
    "/results/ifip-networking-2026", "/results/ifip-networking-2026?tab=replay", "/results/ifip-networking-2026?tab=runs",
    "/results/ifip-networking-2026?tab=details", "/settings",
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
            "v0_name": "bgp", "v0_ref": "HEAD", "v0_mode": "bgp", "v1_name": "half", "v1_ref": "HEAD", "v1_mode": "random-np", "v1_share": "50",
            "cpus": "2", "memory_mb": "4096", "hold_time": "9", "keepalive": "3", "connect_retry": "5",
            "interval": "0.1", "stable_s": "3", "action": "save"}
    assert client.post("/experiments/save", data=form).json() == {"saved": "t-e"}
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
    assert "Convergence" in page and ">Checks<" not in page
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
            "v0_name": "h", "v0_ref": "HEAD", "v0_mode": "hybrid", "v1_name": "r", "v1_ref": "HEAD", "v1_mode": "random-np", "v1_share": "50",
            "cpus": "2", "memory_mb": "4096", "hold_time": "9", "keepalive": "3", "connect_retry": "5", "interval": "0.1", "stable_s": "3"}
    page = client.post("/experiments/estimate", data=form).text
    assert "h: OBGP on 1 of 9 on adversarial, as the topology marks them" in page
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
    from lab.web import app as web

    groups = [{"topology": "t", "scenario": "s", "variant": "v",
               "metrics": {"sample_hz": {"min": 2.0}, "sample_hz_min": {"min": 1.2}, "host_cpu_max": {"max": 0.97}}}]
    monkeypatch.setattr(web.analysis, "summary", lambda dataset: groups)
    d = type("D", (), {"experiment": type("E", (), {"sampling": type("S", (), {"interval": 0.1})()})(), "keys": lambda self: [], "status": {}})()
    s = web.integrity(d)
    assert s["slow"] == [{"topology": "t", "scenario": "s", "variant": "v", "hz": 1.2}] and s["low"] == 1.2 and s["high"] == 2.0
    assert s["busy"] == [{"topology": "t", "scenario": "s", "variant": "v", "cpu": 0.97}] and s["images"] == {}


def test_run_all_queues_the_checks_first_and_leaves_out_what_does_not_fit(client, monkeypatch):
    from lab import cluster
    from lab.web import app as web

    monkeypatch.setattr(cluster, "capacity", lambda: {"cpus": 16, "memory_mb": 32000})
    queued = []
    monkeypatch.setattr(web.jobs, "enqueue", queued.append)
    page = client.get("/experiments").text
    assert "Run all" in page and "1 experiment and 5 topologies left out" in page
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
    from lab.web import app as web

    e = config.Experiment.load(config.path("internet-scale"))
    monkeypatch.setattr(cluster, "oversized", lambda _: {"core-256": ["256 routers"]})
    notes = web.host_notes(e)
    assert "core-256 needs 256 routers." in notes and "so the experiment runs without them." in notes
    monkeypatch.setattr(cluster, "oversized", lambda _: {})
    assert 'class="hidden"' in web.host_notes(e)


def test_failed_checks_are_counted_per_topology(monkeypatch):
    from lab import analysis
    from lab.web import app as web

    groups = [{"topology": "a", "statuses": {"failed": 2}}, {"topology": "a", "statuses": {"completed": 1}},
              {"topology": "b", "statuses": {"failed": 1}}]
    monkeypatch.setattr(analysis, "summary", lambda _: groups)
    assert web.failed_by_topology(None) == {"a": 2, "b": 1}


def test_the_table_names_its_methods_and_shows_the_ci(client):
    page = client.get("/results/ifip-networking-2026?tab=table&metric=rib_mean").text
    assert "data-range" in page and "order statistics" in page and "runs reach no 95 %" in page  # five runs
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
    assert parts.count("dock-run-completed") == len(ifip.statuses()) > 0


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
    from lab.web import app as web

    assert web.shown(0.004, "hold_churn") == web.shown(0.0, "hold_churn") == 0
    assert web.shown(2.04, "settle_s", 1) == 2.0 and web.shown(None, "settle_s") is None


def test_sizes_are_neither_best_nor_worst(client):
    import re

    sizes = client.get("/results/ifip-networking-2026?tab=table&metric=rib_mean").text
    assert not any("bg-emerald-100" in c or "bg-rose-100" in c for c in re.findall(r'class="([^"]*)" data-value', sizes))


def test_compare_names_what_only_one_has_and_says_when_nothing_is_shared():
    from lab import results
    from lab.web import app as web

    ifip = results.Dataset.find("ifip-networking-2026")
    c = web.comparison(ifip, ifip, ifip.experiment.topologies[0], "rib_mean")
    assert c["rows"] and not [d for d in c["differences"] if "only in one" in d[0]]
    assert web.SETTING_NAMES["memory_mb"] == "memory, MB"
