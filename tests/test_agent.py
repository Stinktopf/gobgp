import time

import pytest

from lab import config, results
from lab.config import Experiment
from lab.web import tokens

MCP = {"accept": "application/json, text/event-stream", "content-type": "application/json"}


def bearer(token):
    return {"authorization": f"Bearer {token}"}


def test_a_token_is_shown_once_kept_as_hash_and_can_expire_or_be_revoked(lab_files):
    token, record = tokens.create("claude", "read", 30)
    assert token.startswith("obgp_") and token not in tokens.file().read_text()
    assert tokens.check(f"Bearer {token}")["id"] == record["id"] and tokens.check(f"Bearer {token}x") is None
    assert tokens.check(token) is None and tokens.check(None) is None
    stored = tokens.load()
    stored[0]["expires"] = int(time.time()) - 1
    tokens._save(stored)
    assert tokens.check(f"Bearer {token}") is None
    tokens.revoke(record["id"])
    assert tokens.load() == []
    with pytest.raises(ValueError):
        tokens.create("", "read", 30)
    with pytest.raises(ValueError):
        tokens.create("x", "admin", 30)


def test_the_api_reads_with_a_token_and_controls_only_with_scope_control(app, lab_files):
    from fastapi.testclient import TestClient

    results.Dataset.create(Experiment.load(config.path("lab-smoke")), "t-agent")
    reader, _ = tokens.create("reader", "read", 0)
    controller, _ = tokens.create("controller", "control", 0)
    c = TestClient(app)
    assert c.get("/api/v1/results").status_code == 401
    listed = c.get("/api/v1/results", headers=bearer(reader)).json()
    assert "t-agent" in [r["name"] for r in listed]
    assert c.get("/api/v1/results/t-agent", headers=bearer(reader)).json()["problems"] == {"error": 0, "check": 0, "property": 0, "retried": 0}
    assert c.get("/api/v1/results/nothing", headers=bearer(reader)).status_code == 404
    assert c.get("/api/v1/results/t-agent/log?grep=(", headers=bearer(reader)).status_code == 422
    assert c.post("/api/v1/queue/pause", headers=bearer(reader)).status_code == 403
    assert c.post("/api/v1/queue/pause", headers=bearer(controller)).json() == {"paused": True}
    assert c.get("/", headers=bearer(reader), follow_redirects=False).headers["location"] == "/login"  # pages need the login


def tools(client, token):
    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    answer = client.post("/mcp", json=call, headers={**MCP, **bearer(token)})
    assert answer.status_code == 200, answer.text
    return {t["name"] for t in answer.json()["result"]["tools"]}


def test_mcp_offers_control_tools_only_to_a_control_token(app, lab_files):
    from fastapi.testclient import TestClient

    reader, _ = tokens.create("reader", "read", 0)
    controller, _ = tokens.create("controller", "control", 0)
    with TestClient(app) as c:
        assert c.post("/mcp", json={}, headers=MCP).status_code == 401
        read = tools(c, reader)
        assert {"status", "version", "results", "metrics", "summary", "runs", "paired", "problems", "log"} <= read
        assert "start_experiment" not in read and "update_lab" not in read
        assert {"start_experiment", "stop_result", "pause_queue", "resume_queue", "update_lab"} <= tools(c, controller)
        call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "results", "arguments": {}}}
        answer = c.post("/mcp", json=call, headers={**MCP, **bearer(reader)}).json()
        assert not answer["result"].get("isError"), answer


def test_the_settings_make_a_token_show_it_once_and_revoke_it(client, lab_files):
    made = client.post("/settings/tokens", data={"name": "claude", "scope": "control", "days": "30"}, follow_redirects=False)
    page = client.get(made.headers["location"]).text
    token = page.split('id="new-token"', 1)[1].split(">", 1)[1].split("<", 1)[0]
    assert token.startswith("obgp_") and "claude mcp add --transport http obgp-lab" in page
    assert tokens.check(f"Bearer {token}")["scope"] == "control"
    assert token not in client.get(made.headers["location"]).text  # once only
    client.post(f"/settings/tokens/{tokens.load()[0]['id']}/revoke")
    assert tokens.check(f"Bearer {token}") is None


def test_the_certificate_is_public_with_its_fingerprint_in_the_settings(app, lab_files):
    import shutil
    import subprocess

    from fastapi.testclient import TestClient

    from lab import config
    from lab.web.routes.settings import certificate_fingerprint

    c = TestClient(app)
    assert c.get("/certificate").status_code == 404  # no HTTPS, no certificate
    if not shutil.which("openssl"):
        return
    config.SETTINGS.mkdir(parents=True, exist_ok=True)
    cert = config.SETTINGS / "tls.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=test",
                    "-keyout", str(config.SETTINGS / "tls.key"), "-out", str(cert)], check=True, capture_output=True)
    assert c.get("/certificate").text == cert.read_text()
    printed = subprocess.run(["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", str(cert)], capture_output=True, text=True).stdout
    assert printed.strip().endswith(certificate_fingerprint())


def test_an_agent_updates_the_lab_only_while_nothing_runs_and_switches_after_a_rewrite(lab_files, monkeypatch):
    from types import SimpleNamespace

    import pytest

    from lab.web import agent

    done = []
    monkeypatch.setattr(agent.threading, "Timer", lambda s, f: SimpleNamespace(start=lambda: done.append("restart")))
    monkeypatch.setattr(agent.update, "update", lambda: done.append("update") or "abc")
    monkeypatch.setattr(agent.update, "switch", lambda b: done.append(f"switch {b}") or "def")
    monkeypatch.setattr(agent.jobs, "active", lambda: SimpleNamespace(name="r1"))
    with pytest.raises(ValueError, match="r1 runs"):
        agent.update_lab()
    monkeypatch.setattr(agent.jobs, "active", lambda: None)
    monkeypatch.setattr(agent.update, "status", lambda fetch: {"branch": "master", "resettable": False})
    assert agent.update_lab() == {"commit": "abc", "restarting": True}
    monkeypatch.setattr(agent.update, "status", lambda fetch: {"branch": "master", "resettable": True})
    agent.update_lab()
    assert done == ["update", "restart", "switch master", "restart"]


def test_what_an_agent_does_is_logged_with_its_token_and_the_result_names_it(app, lab_files):
    from fastapi.testclient import TestClient

    controller, _ = tokens.create("claude", "control", 0)
    with TestClient(app) as c:
        started = c.post("/api/v1/experiments/lab-smoke/start", headers=bearer(controller)).json()["result"]
        call = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "pause_queue", "arguments": {}}}
        assert not c.post("/mcp", json=call, headers={**MCP, **bearer(controller)}).json()["result"].get("isError")
    assert results.Dataset.find(started).meta["started_by"] == "claude"
    assert [(a["token"], a["action"]) for a in tokens.activity()] == [("claude", "paused the queue"), ("claude", f"queued {started}")]


SMOKE = """description: A check of an agent
runs: 1
variants:
  - {name: bgp, mode: bgp}
topologies: [bad-gadget]
scenarios: [smoke-drain]
"""


def test_an_agent_writes_experiments_and_scenarios_but_never_the_papers(lab_files):
    import pytest

    from lab import config, scenario
    from lab.web import agent

    assert agent.save_experiment("agent-check", SMOKE) == {"saved": "agent-check", "runs": 1}
    assert config.path("agent-check").exists() and "bad-gadget" in agent.experiment_of("agent-check")["yaml"]
    with pytest.raises(ValueError, match="mode"):
        agent.save_experiment("agent-check", SMOKE.replace("mode: bgp", "mode: nonsense"))
    with pytest.raises(ValueError, match="mapping"):
        agent.save_experiment("agent-check", "- just a list")
    with pytest.raises(ValueError, match="paper"):
        agent.save_experiment("ifip-networking-2026", SMOKE)
    with pytest.raises(ValueError, match="paper"):
        agent.save_scenario("fill-60", agent.scenario_of("fill-30")["yaml"])
    with pytest.raises(ValueError, match="used by"):
        agent.delete_scenario("smoke-drain")
    assert agent.save_scenario("agent-steps", agent.scenario_of("smoke-drain")["yaml"]) == {"saved": "agent-steps"}
    assert scenario.path("agent-steps").exists()
    assert agent.delete_scenario("agent-steps") == {"deleted": "agent-steps"} and not scenario.path("agent-steps").exists()
    assert agent.delete_experiment("agent-check") == {"deleted": "agent-check"} and not config.path("agent-check").exists()
    assert "for" in agent.vocabulary()["steps"]["announce"] and "obgp-rp" in agent.vocabulary()["modes"]


def test_a_token_that_asks_first_waits_for_a_person_to_approve_or_reject(client, lab_files):
    from lab import config
    from lab.web import agent, approvals

    asking, entry = tokens.create("careful", "control", 0, approval=True)
    tokens.caller.set(entry)
    waiting = agent.save_experiment("agent-check", SMOKE)
    assert waiting["action"] == "save the experiment agent-check" and not config.path("agent-check").exists()
    assert "careful" in client.get("/settings").text and "asks to save the experiment agent-check" in client.get("/settings").text
    client.post(f"/settings/actions/{waiting['waiting']}/approve")
    assert config.path("agent-check").exists() and agent.action(waiting["waiting"])["state"] == "done"
    rejected = agent.delete_experiment("agent-check")
    client.post(f"/settings/actions/{rejected['waiting']}/reject")
    assert config.path("agent-check").exists() and agent.action(rejected["waiting"])["state"] == "rejected"
    assert approvals.waiting() == []
    assert [a["action"] for a in tokens.activity(4)] == ["was refused: delete the experiment agent-check", "asks to delete the experiment agent-check",
                                                        "saved the experiment agent-check", "asks to save the experiment agent-check"]


def test_mcp_tells_an_agent_why_a_change_is_refused(app, lab_files):
    from fastapi.testclient import TestClient

    controller, _ = tokens.create("claude", "control", 0)
    call = {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "delete_experiment", "arguments": {"name": "ifip-networking-2026"}}}
    with TestClient(app) as c:
        answer = c.post("/mcp", json=call, headers={**MCP, **bearer(controller)}).json()["result"]
    assert answer["isError"] and "belongs to the paper's runs" in answer["content"][0]["text"]


def test_an_update_always_waits_and_no_agent_can_approve_itself(app, lab_files):
    from fastapi.testclient import TestClient

    from lab.web import agent, approvals

    direct, entry = tokens.create("claude", "control", 0)
    tokens.caller.set(entry)
    waiting = agent.update_lab()
    assert waiting["action"] == "update the lab" and approvals.get(waiting["waiting"])["state"] == "waiting"
    with TestClient(app) as c:
        assert "decide" not in tools(c, direct) and "approve" not in " ".join(tools(c, direct))
        refused = c.post(f"/settings/actions/{waiting['waiting']}/approve", headers=bearer(direct), follow_redirects=False)
    assert refused.headers["location"] == "/login" and approvals.get(waiting["waiting"])["state"] == "waiting"


def test_agents_may_fill_the_queue_only_up_to_their_budget(lab_files):
    from lab.web import agent, approvals

    _, entry = tokens.create("claude", "control", 0)
    tokens.caller.set(entry)
    tokens.save_limits(0)
    waiting = agent.start("lab-smoke")
    assert "longer than the 0 h agents may fill" in waiting["why"] and approvals.get(waiting["waiting"])["details"].startswith("33 runs, about")
    tokens.save_limits(720)
    assert agent.start("lab-smoke")["result"].startswith("lab-smoke-")


def test_resuming_a_result_counts_against_the_budget_too(lab_files):
    from lab.web import agent

    _, entry = tokens.create("claude", "control", 0)
    tokens.caller.set(entry)
    tokens.save_limits(720)
    result = agent.start("lab-smoke")["result"]
    agent.stop(result)
    tokens.save_limits(0)
    assert "longer than the 0 h agents may fill" in agent.resume(result)["why"]


def test_an_approval_fails_when_the_file_changed_since_the_agent_asked(client, lab_files):
    from lab import config
    from lab.web import agent

    _, entry = tokens.create("careful", "control", 0, approval=True)
    tokens.caller.set(entry)
    waiting = agent.start("lab-smoke")
    config.path("lab-smoke").write_text(config.path("lab-smoke").read_text().replace("runs: 1", "runs: 6"))
    client.post(f"/settings/actions/{waiting['waiting']}/approve")
    outcome = agent.action(waiting["waiting"])
    assert outcome["state"] == "failed" and "changed" in outcome["outcome"]


def test_a_card_on_every_page_asks_and_its_answer_returns_to_that_page(client, lab_files):
    from lab import config
    from lab.web import agent

    _, entry = tokens.create("careful", "control", 0, approval=True)
    tokens.caller.set(entry)
    waiting = agent.save_experiment("agent-check", SMOKE)
    dock = client.get("/partials/dock").text
    assert "careful</span> asks to save the experiment agent-check" in dock and f'data-asks="{waiting["waiting"]}"' in dock
    answer = client.post(f"/settings/actions/{waiting['waiting']}/approve", headers={"referer": "http://testserver/results"}, follow_redirects=False)
    assert answer.headers["location"] == "/results" and config.path("agent-check").exists()
    assert "data-asks" not in client.get("/partials/dock").text


def test_an_update_asked_for_before_the_lab_moved_on_closes_itself(lab_files, monkeypatch):
    from lab.web import agent, approvals

    _, entry = tokens.create("claude", "control", 0)
    tokens.caller.set(entry)
    monkeypatch.setattr(approvals, "head", lambda: "aaaa")
    waiting = agent.update_lab()
    assert [e["id"] for e in approvals.waiting()] == [waiting["waiting"]]
    monkeypatch.setattr(approvals, "head", lambda: "bbbb")  # updated by hand meanwhile
    assert approvals.waiting() == [] and agent.action(waiting["waiting"])["state"] == "obsolete"
