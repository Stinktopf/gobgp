"""The Simulation area: searches of the simulator, their findings, and each
finding replayed step by step, in the web interface and for agents."""

import json
import os
import shutil
import threading
from pathlib import Path

import pytest

from lab import simulate, simulation
from lab.web import tokens

EXAMPLE = {"instance": {"family": "gao-rexford", "routers": 4, "origin": 0, "links": [[0, 1], [0, 2], [1, 2], [1, 3]],
                        "customers": [[1, 0], [2, 0], [3, 1]], "peers": [[1, 2]], "seed": 3},
           "finding": {"mode": "obgp-rp", "kind": "unreachable", "routers": [3], "detail": "BGP has a path, this mode none"},
           "results": {}, "count": 37, "of": 200, "in_model": False}
BIG = {**EXAMPLE, "instance": {**EXAMPLE["instance"], "routers": 5}}
LOOP = {**EXAMPLE, "finding": {**EXAMPLE["finding"], "kind": "transient-loop"}}


@pytest.fixture(autouse=True)
def no_search_outlives_its_test():
    yield
    for t in threading.enumerate():
        if t.name.startswith("search-"):
            t.join(5)


@pytest.fixture
def found(monkeypatch):
    monkeypatch.setattr(simulate, "search", lambda *a, **k: [LOOP, BIG, EXAMPLE])


@pytest.fixture
def control_token():
    def use(name, approval=False):
        _, entry = tokens.create(name, "control", 0, approval=approval)
        return tokens.caller.set(entry)
    marks = []
    yield lambda name, approval=False: marks.append(use(name, approval))
    for mark in reversed(marks):
        tokens.caller.reset(mark)


def test_a_search_is_kept_with_its_parameters_and_findings_by_kind(lab_files, found):
    entry = simulation.run(4, 2, "gao-rexford", True, by="test")
    kept = simulation.search(entry["id"])
    assert kept["state"] == "done" and kept["routers"] == 4 and kept["seeds"] == 2 and kept["transient"] and kept["by"] == "test"
    assert [(e["finding"]["kind"], e["instance"]["routers"]) for e in kept["findings"]] == [
        ("unreachable", 4), ("unreachable", 5), ("transient-loop", 4)]
    assert simulation.searches()[0]["found"] == 3 and simulation.searches()[0]["problems"] == 2 and simulation.latest() == entry["id"]


def test_a_case_names_every_mode_that_shows_it_on_its_network_and_plays_its_order_of_messages(lab_files, monkeypatch):
    # The simulator kept this network for obgp-rp, and names every finding on it: obgp-sp too, at router 2.
    both = {**EXAMPLE, "findings": [EXAMPLE["finding"], {**EXAMPLE["finding"], "mode": "obgp-sp", "routers": [2]}]}
    other_seed = {**EXAMPLE, "instance": {**EXAMPLE["instance"], "seed": 1}}
    monkeypatch.setattr(simulate, "search", lambda *a, **k: [BIG, both, other_seed, LOOP])
    kept = simulation.search(simulation.run(4)["id"])
    found = {(c["kind"], c["instance"]["seed"], c["instance"]["routers"]): c for c in simulation.cases(kept)}
    assert found[("unreachable", 3, 4)]["modes"] == ["obgp-rp", "obgp-sp"]
    assert found[("unreachable", 3, 4)]["per_mode"]["obgp-sp"]["routers"] == [2]
    assert found[("unreachable", 1, 4)]["modes"] == ["obgp-rp"]  # another order of messages is another case
    assert [(p["kind"], p["modes"], len(p["examples"]), p["proof"]) for p in simulation.problems(kept)] == [
        ("unreachable", ["obgp-rp", "obgp-sp"], 1, "outside its model"), ("unreachable", ["obgp-rp"], 2, "outside its model"),
        ("transient-loop", ["obgp-rp"], 1, "outside its model")]
    assert simulation.modes_label(["bgp", "obgp-rp", "obgp-sp", "obgp-hp", "obgp-np", "obgp-paper"]) == "bgp and every OBGP mode with one table"
    assert simulation.modes_label(list(simulation.MODES)) == "bgp and every OBGP mode"
    assert simulation.modes_label(["obgp-rp", *simulation.MODES[6:]]) == "obgp-rp, every -pn mode"


def test_the_proofs_are_contradicted_only_by_an_obgp_mode_inside_their_model():
    assert simulation.proof("no-convergence", True, ["obgp-rp"]) == "contradicts it"
    assert simulation.proof("no-convergence", True, ["bgp"]) == "BGP only"
    assert simulation.proof("transient-loop", True, ["obgp-rp"]) == "no claim"
    assert simulation.proof("loop", False, ["obgp-rp"]) == "outside its model"


def test_a_search_waits_in_the_lab_queue_runs_there_and_can_be_stopped(lab_files, monkeypatch):
    from lab.results import queued

    calls = []
    pn = lambda e, tables: {**e, "finding": {**e["finding"], "mode": simulate.per_neighbor(e["finding"]["mode"]) if tables else e["finding"]["mode"]}}
    monkeypatch.setattr(simulate, "search", lambda *a, **k: calls.append(k) or [pn(EXAMPLE, k["tables"]), pn({**EXAMPLE, "finding": {**EXAMPLE["finding"], "mode": "bgp"}}, k["tables"])])
    first = simulation.start()  # checks everything: five routers, the way to rest, both table modes
    entry = simulation.search(first)
    assert entry["state"] == "queued" and entry["routers"] == 5 and entry["transient"] and entry["tables"] == "both"
    assert simulation.queue_name(first) in queued()
    with pytest.raises(ValueError, match="Stop it first"):
        simulation.delete(first)
    done = simulation.execute(first)  # what the worker of the queue does
    assert done["state"] == "done" and [k["tables"] for k in calls] == [False, True] and done["progress"] == 1.0
    # BGP is the same in both passes: it comes from the first only.
    assert [e["finding"]["mode"] for e in done["findings"]] == ["obgp-rp", "bgp", "obgp-rp-pn"]
    second = simulation.start()
    assert simulation.stop(second)["state"] == "stopped" and simulation.queue_name(second) not in queued()


def test_a_search_whose_process_ended_fails_once_and_kills_no_stranger(lab_files, monkeypatch):
    killed = []
    monkeypatch.setattr(simulation.os, "killpg", lambda g, sig: killed.append(g))
    me = os.getpid()
    entry = {**simulation._new(3, 3, "", False, None), "born": 1, "group": me, "group_born": 1}  # a reused id: born differs
    simulation._write(entry)
    assert simulation.search(entry["id"])["state"] == "failed" and simulation.running() is None
    assert simulation._read(simulation._path(entry["id"]))["state"] == "failed" and killed == []


def test_findings_keep_their_ids_whatever_the_order(lab_files, found):
    entry = simulation.run(4)
    by_id = {e["id"]: e["finding"]["kind"] for e in simulation.search(entry["id"])["findings"]}
    assert by_id == {0: "transient-loop", 1: "unreachable", 2: "unreachable"}
    assert simulation.finding(entry["id"], 0)["finding"]["kind"] == "transient-loop"


def test_a_search_is_deleted_with_its_replays(lab_files, found):
    entry = simulation.run(4)
    (simulation.folder() / entry["id"]).mkdir()
    simulation.delete(entry["id"])
    assert simulation.searches() == [] and not (simulation.folder() / entry["id"]).exists()


def test_search_ids_are_digits_only(lab_files):
    for bad in ("../x", "", "1/2", "١٢٣"):
        with pytest.raises(LookupError):
            simulation.search(bad)


def test_bad_parameters_are_refused(lab_files):
    for args in ((9, 3, ""), (3, 0, ""), (3, 3, "nonsense")):
        with pytest.raises(ValueError):
            simulation.check(*args)


def test_a_replay_is_played_once_and_then_kept(lab_files, found, monkeypatch):
    played = []
    monkeypatch.setattr(simulate, "trace", lambda inst, mode: played.append(mode) or {"mode": mode, "instance": inst, "steps": [], "result": {"converged": True}})
    entry = simulation.run(4)
    assert simulation.trace(entry["id"], 0, "bgp") == simulation.trace(entry["id"], 0, "bgp") == {"mode": "bgp", "steps": [], "result": {"converged": True}}
    assert played == ["bgp"]
    with pytest.raises(ValueError):
        simulation.trace(entry["id"], 0, "nonsense")
    with pytest.raises(ValueError, match="disturb"):
        simulation.trace(entry["id"], 0, "obgp-rp", new=False)


def test_the_area_lists_searches_findings_and_opens_a_case(client, lab_files, found):
    entry = simulation.run(4)
    page = client.get("/simulation").text
    assert ">New search</button>" in page and "Routers lose a prefix that BGP reaches" in page
    # The two networks of the same problem are one row that opens the smaller, which offers the other.
    assert f'href="/simulation/{entry["id"]}/2"' in page and f'href="/simulation/{entry["id"]}/1"' not in page and "Delete" in page
    case = client.get(f"/simulation/{entry['id']}/2").text
    assert "lose" in case and "router 3" in case and 'data-mode="right"' in case and "37 of 200" in case
    assert '<option value="1" >Network 2 of 2' in case
    assert client.get(f"/simulation/{entry['id']}/9").status_code == 404
    assert client.get("/simulation?search=123").status_code == 404


def test_a_search_is_queued_stopped_and_deleted_from_the_web_interface(client, lab_files):
    answer = client.post("/simulation/searches", follow_redirects=False)
    assert answer.status_code == 303 and "/simulation?search=" in answer.headers["location"]
    search_id = answer.headers["location"].split("=")[1]
    assert simulation.search(search_id)["state"] == "queued"
    client.post(f"/simulation/{search_id}/stop")
    assert simulation.search(search_id)["state"] == "stopped"
    client.post(f"/simulation/{search_id}/delete")
    assert simulation.searches() == []


def test_a_search_waits_for_an_experiment_and_an_experiment_for_a_search(lab_files, monkeypatch):
    from types import SimpleNamespace

    from lab.web.jobs import Jobs

    jobs = Jobs()
    started = []
    monkeypatch.setattr("lab.web.jobs.subprocess.Popen", lambda args, **k: started.append(args) or SimpleNamespace(poll=lambda: None, args=args))
    search_id = simulation.start()
    monkeypatch.setattr(jobs, "active", lambda: SimpleNamespace(name="r1"))
    jobs._step()
    assert started == []  # an experiment runs: the search waits
    monkeypatch.setattr(jobs, "active", lambda: None)
    monkeypatch.setattr("lab.web.jobs.cluster.holder", lambda: None)
    monkeypatch.setattr("lab.web.jobs.cluster.manually_stopped", lambda: False)
    jobs._step()
    assert started and started[0][-3:] == ["simulate", "resume", search_id]
    jobs._step()
    assert len(started) == 1  # while the search runs nothing else starts


def test_agents_read_findings_and_play_a_case_a_page_at_a_time(lab_files, found, monkeypatch, control_token):
    from lab.web import agent

    steps = [{"kind": "update", "loop": [1, 2] if k == 3 else None, "routers": []} for k in range(10)]
    monkeypatch.setattr(simulate, "trace", lambda inst, mode: {"mode": mode, "steps": steps, "result": {"converged": True}})
    entry = simulation.run(4)
    first = agent.simulation_search(entry["id"])["findings"][0]
    assert first["kind"] == "unreachable" and first["hit"] == [3] and first["count"] == 37 and first["of"] == 200 and first["id"] == 2
    case = agent.simulation_case(entry["id"], 0, start=2, limit=3)
    assert case["mode"] == "obgp-rp" and case["summary"]["steps"] == 10 and case["summary"]["first_loop"] == 3 and len(case["steps"]) == 3
    control_token("careful", approval=True)
    assert "waiting" in agent.start_simulation()
    control_token("quick")
    assert simulation.search(agent.start_simulation()["search"])["state"] == "queued"
    made = agent.simulation_to_lab(entry["id"], 2)
    assert made["experiment"] == simulation.lab_name(entry["id"], 2) and made["runs"] > 0


def test_the_http_api_answers_unknown_searches_with_404_and_read_tokens_cannot_start(client, lab_files, found):
    entry = simulation.run(4)
    reader, _ = tokens.create("reader", "read", 0)
    head = {"Authorization": f"Bearer {reader}"}
    assert client.get("/api/v1/simulation/searches", headers=head).json()[0]["id"] == entry["id"]
    assert client.get("/api/v1/simulation/searches/123", headers=head).status_code == 404
    assert client.get(f"/api/v1/simulation/searches/{entry['id']}/9", headers=head).status_code == 404
    assert client.post("/api/v1/simulation/searches", headers=head).status_code == 403


def test_only_a_control_token_sees_the_tools_that_change_the_simulation():
    import asyncio

    from lab.web import mcp_server

    read = {t.name for t in asyncio.run(mcp_server.server(False).list_tools())}
    control = {t.name for t in asyncio.run(mcp_server.server(True).list_tools())}
    assert {"simulation_searches", "simulation_search", "simulation_case"} <= read
    assert "start_simulation" not in read and {"start_simulation", "stop_simulation", "simulation_to_lab"} <= control


@pytest.mark.skipif(not shutil.which("go"), reason="needs Go to run the simulator")
def test_a_case_is_played_step_by_step(client, lab_files, monkeypatch):
    monkeypatch.setattr(simulate, "search", lambda *a, **k: [EXAMPLE])
    entry = simulation.run(4)
    trace = client.get(f"/simulation/{entry['id']}/0/trace", params={"mode": "obgp-rp"}).json()
    assert trace["steps"] and len(trace["steps"][-1]["routers"]) == 4 and "instance" not in trace
    assert client.get(f"/simulation/{entry['id']}/0/trace", params={"mode": "nonsense"}).status_code == 400
    assert os.path.exists(simulation.folder() / entry["id"] / "0-obgp-rp.json")


def test_tables_per_neighbor_name_their_modes_as_the_lab_does(lab_files, monkeypatch):
    calls = []

    def simulator(args, stdin=None, **_):
        calls.append(args)
        if "-out" in args:
            Path(args[args.index("-out") + 1]).write_text(json.dumps([{**EXAMPLE, "results": {"bgp": {"mode": "bgp"}, "obgp-rp": {"mode": "obgp-rp"}}}]))
        return json.dumps({"mode": "obgp-rp", "steps": [], "result": {}})
    monkeypatch.setattr(simulate, "_simulator", simulator)
    kept = simulation.search(simulation.run(4, tables=True)["id"])
    assert "-per-neighbor" in calls[0] and kept["tables"]
    assert kept["findings"][0]["finding"]["mode"] == "obgp-rp-pn" and set(kept["findings"][0]["results"]) == {"bgp", "obgp-rp-pn"}
    played = simulation.trace(kept["id"], 0, "obgp-rp-pn")
    assert calls[-1][calls[-1].index("-trace") + 1] == "obgp-rp" and "-per-neighbor" in calls[-1] and played["mode"] == "obgp-rp-pn"
    assert simulation.modes_label(["obgp-rp-pn", "obgp-sp-pn", "obgp-hp-pn", "obgp-np-pn", "obgp-paper"]) == "obgp-paper and every -pn mode"
    assert simulation.modes_label(["obgp-rp", "obgp-rp-pn"]) == "obgp-rp, obgp-rp-pn"


def test_a_finding_of_a_case_opens_the_case(client, lab_files, monkeypatch):
    same_network = {**EXAMPLE, "finding": {**EXAMPLE["finding"], "mode": "obgp-sp"}}
    monkeypatch.setattr(simulate, "search", lambda *a, **k: [EXAMPLE, same_network])
    entry = simulation.run(4)
    answer = client.get(f"/simulation/{entry['id']}/1", follow_redirects=False)
    assert answer.status_code == 307 and answer.headers["location"] == f"/simulation/{entry['id']}/0"
    case = client.get(f"/simulation/{entry['id']}/0").text
    assert "obgp-rp, obgp-sp" in case and "in 37 of 200 networks" in case


def test_tables_per_neighbor_are_outside_the_published_proofs():
    assert simulation.proof("no-convergence", True, ["obgp-rp-pn"]) == "outside its model"
    assert simulation.proof("loop", True, ["bgp", "obgp-rp-pn", "obgp-paper"]) == "contradicts it"


def test_filters_communities_and_relations_are_different_causes():
    at_rest = {"obgp-rp": {"best": [[], [65001], [65001], None], "exported": [[], [65001], [65001], None]}}
    unreachable = {"mode": "obgp-rp", "kind": "unreachable", "routers": [3]}
    links = [[0, 1], [0, 2], [1, 2], [1, 3]]
    filtered = {"instance": {"routers": 4, "links": links, "sessions": [{"from": 1, "to": 3, "deny_via": 65001}]}, "finding": unreachable, "results": at_rest}
    related = {"instance": {"routers": 4, "links": links, "customers": [[3, 1]]}, "finding": unreachable, "results": at_rest}
    tagged = {"instance": {"routers": 4, "links": links, "sessions": [{"from": 0, "to": 2, "tag": "0:65004"}]}, "finding": unreachable, "results": at_rest}
    neither = {"instance": {"routers": 4, "links": links}, "finding": unreachable, "results": at_rest}
    assert simulation.cause(filtered, "obgp-rp") == "an export filter drops the offer"
    assert simulation.cause(tagged, "obgp-rp") == "a community withholds the offer"
    imported = {"instance": {"routers": 4, "links": links, "sessions": [{"from": 1, "to": 3, "deny_import": True}]}, "finding": unreachable, "results": at_rest}
    assert simulation.cause(imported, "obgp-rp") == "an import filter drops the offer"
    assert simulation.cause(related, "obgp-rp") == "a relation stops the offer"
    assert simulation.cause(neither, "obgp-rp") == "it does not admit the offer"


def test_a_running_search_shows_how_far_it_is(client, lab_files):
    search_id = simulation.start()
    assert "Queued" in client.get(f"/simulation/{search_id}/state").text
    simulation._update(search_id, state="running", progress=0.25, began="2026-01-01T00:00:00+00:00", pid=os.getpid(), born=simulation._born(os.getpid()))
    shown = client.get(f"/simulation/{search_id}/state").text
    assert "25 %" in shown and "left" in shown
    simulation._update(search_id, state="done")
    assert client.get(f"/simulation/{search_id}/state").headers.get("HX-Refresh") == "true"


def test_a_case_becomes_an_experiment_of_the_lab_with_every_mode(client, lab_files, found):
    from lab import config

    entry = simulation.run(4)
    answer = client.post(f"/simulation/{entry['id']}/2/lab", follow_redirects=False)
    assert answer.status_code == 303 and answer.headers["location"].startswith("/experiments/sim-")
    name = answer.headers["location"].rsplit("/", 1)[1]
    e = config.Experiment.load(config.path(name))
    assert e.topologies == [name] and e.scenarios == [name] and f"/simulation/{entry['id']}/2" in e.description
    assert [v.name for v in e.variants] == list(simulation.MODES)
    assert [v.per_neighbor for v in e.variants] == [m.endswith("-pn") for m in simulation.MODES]
    # Played again it opens the same experiment, with what a person changed since.
    config.save(e.model_copy(update={"runs": 2}))
    assert client.post(f"/simulation/{entry['id']}/2/lab", follow_redirects=False).headers["location"] == f"/experiments/{name}"
    assert config.Experiment.load(config.path(name)).runs == 2
    # The result made from it says how often the simulator saw it, as the lab cannot replay the order of messages.
    assert "obgp-rp 37 of 200" in simulation.seen(f"/simulation/{entry['id']}/2") and simulation.seen("/simulation/1/2") == ""
    # Names come from the whole search id: searches started in the same microsecond of another second differ.
    assert simulation.lab_name("20261031080352337093", 2) != simulation.lab_name("20261031080353337093", 2)


def test_a_worker_that_keeps_dying_fails_its_search_and_a_stop_outlasts_progress(lab_files, monkeypatch):
    from types import SimpleNamespace

    from lab.results import queued
    from lab.web.jobs import Jobs

    search_id = simulation.start()
    dead = lambda: simulation._update(search_id, state="running", pid=os.getpid(), born=1)  # a worker that is gone
    dead()
    assert simulation.search(search_id)["state"] == "queued"  # once: queued again
    dead()
    entry = simulation.search(search_id)
    assert entry["state"] == "failed" and "2 times" in entry["error"]
    # A worker that ends before it began, e.g. at import, counts as well.
    jobs, other = Jobs(), simulation.start()
    jobs.worker = SimpleNamespace(poll=lambda: 1, returncode=1, pid=4242, args=["python", "-m", "lab.cli", "simulate", "resume", other])
    jobs._ended()
    assert simulation.search(other)["state"] == "queued" and simulation.search(other)["deaths"] == 1
    # A worker that took the search up and died is counted once, where it is found dead, not again as it ends.
    simulation._update(other, state="running", pid=4243, born=1)
    assert simulation.search(other)["deaths"] == 2 and simulation.search(other)["state"] == "failed"
    third = simulation.start()
    simulation._update(third, state="running", pid=4244, born=1)
    assert simulation.search(third)["deaths"] == 1
    jobs.worker = SimpleNamespace(poll=lambda: 1, returncode=-9, pid=4244, args=["python", "-m", "lab.cli", "simulate", "resume", third])
    jobs._ended()
    assert simulation.search(third)["deaths"] == 1 and simulation.search(third)["state"] == "queued"
    # A pause requeues the search, its worker ends on purpose: no death.
    fourth = simulation.start()
    simulation._update(fourth, state="running", pid=4245, born=simulation._born(os.getpid()))
    simulation.requeue(fourth)
    jobs.worker = SimpleNamespace(poll=lambda: 1, returncode=-15, pid=4245, args=["python", "-m", "lab.cli", "simulate", "resume", fourth])
    jobs._ended()
    assert simulation.search(fourth).get("deaths", 0) == 0 and simulation.search(fourth)["state"] == "queued"
    # Progress after a stop does not bring the search back.
    simulation._update(other, state="queued")
    simulation._update(other, state="running", pid=os.getpid(), born=simulation._born(os.getpid()))
    simulation.stop(other)
    simulation._update(other, progress=0.5)
    assert simulation.search(other)["state"] == "stopped" and simulation.queue_name(other) not in queued()


def test_searches_run_while_the_cluster_is_stopped(lab_files, monkeypatch):
    from types import SimpleNamespace

    from lab.web.jobs import Jobs

    jobs, started = Jobs(), []
    monkeypatch.setattr("lab.web.jobs.subprocess.Popen", lambda args, **k: started.append(args) or SimpleNamespace(poll=lambda: None, args=args))
    monkeypatch.setattr(jobs, "active", lambda: None)
    monkeypatch.setattr("lab.web.jobs.cluster.holder", lambda: None)
    monkeypatch.setattr("lab.web.jobs.cluster.manually_stopped", lambda: True)
    search_id = simulation.start()
    jobs._step()
    assert started and started[0][-1] == search_id


def test_a_case_shows_its_runs_in_the_lab_per_mode(client, lab_files, found, monkeypatch):
    from types import SimpleNamespace

    from lab import problems
    from lab.results import Dataset, RunKey

    entry = simulation.run(4)
    name = simulation.lab_name(entry["id"], 2)
    keys = [RunKey(name, m, name, i) for m in ("bgp", "obgp-rp") for i in (1, 2)]
    runs = {k: {"status": "completed", "events": [{"name": "expect", "passed": not (k.variant == "obgp-rp" and k.index == 1)}]} for k in keys}
    variants = [SimpleNamespace(name=m) for m in ("bgp", "obgp-rp")]
    d = SimpleNamespace(name=f"{name}-20261031-1200", experiment=SimpleNamespace(name=name, variants=variants), status={"state": "finished"},
                        keys=lambda: keys, is_done=lambda k: True, run=lambda k: runs[k])
    monkeypatch.setattr(Dataset, "all", classmethod(lambda cls: [d]))
    # Run 2 of obgp-rp loses the prefix at its end: the property of the kind counts as well.
    monkeypatch.setattr(problems, "broken", lambda ds: [{"variant": "obgp-rp", "run": 2, "cause": "reach"}, {"variant": "bgp", "run": 1, "cause": "loops"}])
    shown = {m["mode"]: (m["runs"], m["seen"]) for m in simulation.played(entry["id"], 2, "unreachable")[0]["modes"]}
    assert shown == {"bgp": (2, 0), "obgp-rp": (2, 2)}
    page = client.get(f"/simulation/{entry['id']}/2").text
    assert "Open in the lab" in page and "in the lab 2 of 2 runs" in page and f"/results/{d.name}" in page


def test_the_list_of_searches_reads_a_file_again_only_once_it_changed(lab_files, found, monkeypatch):
    entry = simulation.run(4)
    reads = []
    real = simulation._read
    monkeypatch.setattr(simulation, "_read", lambda p: reads.append(p) or real(p))
    assert simulation.searches()[0]["problems"] and simulation.searches()[0]["id"] == entry["id"]
    assert len(reads) <= 1  # the first call may read it, the second does not
    simulation._update(entry["id"], state="stopped")
    assert simulation.searches()[0]["state"] == "stopped"


def test_the_dock_shows_a_search_as_a_search_and_needs_no_cluster(client, lab_files, monkeypatch):
    search_id = simulation.start()
    monkeypatch.setattr("lab.web.context.cluster.manually_stopped", lambda: True)
    dock = client.get("/partials/dock").text
    assert "Simulator search" in dock and f"/simulation?search={search_id}" in dock
    assert "sim:" + search_id not in dock.replace(f'data-name="sim:{search_id}"', "").replace(f'data-job="sim:{search_id}"', "")
    assert "Cluster switched off" not in dock  # no result waits for it
    simulation._update(search_id, state="running", progress=0.5, began="2026-01-01T00:00:00+00:00", pid=os.getpid(), born=simulation._born(os.getpid()))
    dock = client.get("/partials/dock").text
    assert "50 %" in dock and f"/simulation/{search_id}/stop" in dock


def test_a_search_that_began_again_says_so_and_how_many_more_ends_fail_it(client, lab_files):
    search_id = simulation.start()
    simulation._update(search_id, state="running", pid=os.getpid(), born=1)  # its worker is gone
    simulation.search(search_id)
    shown = client.get(f"/simulation/{search_id}/state").text
    assert "began again" in shown and "the process that ran it stopped" in shown and "2 times" in shown
