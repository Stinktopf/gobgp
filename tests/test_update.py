import subprocess

import pytest

from lab import update


def run(*args, cwd):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def repos(tmp_path):
    """A GitHub of its own: origin, the lab's clone and another clone that pushes."""
    origin, lab, other = tmp_path / "origin.git", tmp_path / "lab", tmp_path / "other"
    run("init", "--bare", "-b", "main", str(origin), cwd=tmp_path)
    run("clone", str(origin), str(lab), cwd=tmp_path)
    (lab / "a.txt").write_text("1\n")
    run("add", "a.txt", cwd=lab)
    run("commit", "-m", "first", cwd=lab)
    run("push", "origin", "main", cwd=lab)
    run("clone", str(origin), str(other), cwd=tmp_path)
    return lab, other


def push(other, message, name="a.txt", text="2\n"):
    (other / name).write_text(text)
    run("add", name, cwd=other)
    run("commit", "-m", message, cwd=other)
    run("push", "origin", "main", cwd=other)


def test_new_commits_on_the_branch_are_seen_and_taken(repos):
    lab, other = repos
    assert update.status(root=lab)["behind"] == 0
    push(other, "second")
    s = update.status(root=lab)
    assert s["branch"] == "main" and s["behind"] == 1 and s["new"][0].endswith("second") and not s["problem"]
    commit = update.update(root=lab, sync=False)
    assert (lab / "a.txt").read_text() == "2\n" and update.status(root=lab)["behind"] == 0
    assert commit == update.git("rev-parse", "--short", "HEAD", root=lab)
    assert update.update(root=lab, sync=False, allow_current=True) == commit
    with pytest.raises(update.UpdateError, match="up to date"):
        update.update(root=lab, sync=False)


def test_local_changes_or_own_commits_stop_an_update(repos):
    lab, other = repos
    push(other, "second", name="b.txt")
    (lab / "a.txt").write_text("changed here\n")
    with pytest.raises(update.UpdateError, match="local changes, in a.txt"):
        update.update(root=lab, sync=False)
    run("commit", "-am", "own", cwd=lab)
    with pytest.raises(update.UpdateError, match="1 commits GitHub does not have"):
        update.update(root=lab, sync=False)
    assert (lab / "a.txt").read_text() == "changed here\n"  # nothing overwritten


def test_an_unreachable_github_is_said_plainly(repos):
    lab, _ = repos
    run("remote", "set-url", "origin", str(lab.parent / "gone.git"), cwd=lab)
    assert "not reachable" in update.status(root=lab)["problem"]


def test_the_settings_show_the_version_and_update_only_while_nothing_runs(client, monkeypatch):
    from lab.web import app as web

    monkeypatch.setattr("lab.web.context.UPDATES", {"branch": "obgp-fixes", "commit": "abc1234", "date": "2026-10-03", "behind": 2, "ahead": 0,
                                         "new": ["def5678 lab: something"], "dirty": [], "problem": None, "checked": None})
    page = client.get("/settings").text
    assert "Lab version" in page and "2 new commits on GitHub" in page and "lab: something" in page and "Update and restart" in page
    assert "an update of the lab is ready" in client.get("/topologies").text
    monkeypatch.setattr(web.jobs, "active", lambda: type("D", (), {"name": "t-running"})())
    r = client.post("/settings/update", follow_redirects=False)
    assert "t-running+runs" in r.headers["location"]


def test_web_restart_retains_module_launch(monkeypatch):
    calls = []
    monkeypatch.setattr(update.sys, "argv", ["/checkout/lab/cli.py", "serve", "--http", "--port", "8450"])
    monkeypatch.setattr(update.os, "execv", lambda executable, args: calls.append(args))
    update.restart()
    assert calls == [[update.sys.executable, "-m", "lab.cli", "serve", "--http", "--port", "8450"]]


def test_a_deleted_branch_is_switched_to_the_default_branch(repos):
    lab, other = repos
    run("switch", "-c", "feature", cwd=lab)
    run("push", "-u", "origin", "feature", cwd=lab)
    run("push", "origin", "--delete", "feature", cwd=other)
    push(other, "second")
    s = update.status(root=lab)
    assert s["problem"] == "GitHub no longer has the branch feature." and s["resettable"]
    assert [b["name"] for b in s["branches"]] == ["main"] and s["branches"][0]["default"]
    with pytest.raises(update.UpdateError, match="Switch to a branch"):
        update.update(root=lab, sync=False)
    old = update.git("rev-parse", "--short", "HEAD", root=lab)
    update.switch(root=lab, sync=False)
    assert update.git("rev-parse", "--abbrev-ref", "HEAD", root=lab) == "main" and (lab / "a.txt").read_text() == "2\n"
    assert update.git("rev-parse", "--short", f"lab-backup-{old}", root=lab) == old
    s = update.status(root=lab)
    assert not s["problem"] and not s["resettable"] and s["behind"] == 0


def test_rewritten_history_is_switched_and_local_changes_block_it(repos):
    lab, other = repos
    (other / "a.txt").write_text("rewritten\n")
    run("commit", "--amend", "-am", "squashed", cwd=other)
    run("push", "--force", "origin", "main", cwd=other)
    (lab / "a.txt").write_text("changed here\n")
    s = update.status(root=lab)
    assert "was rewritten" in s["problem"] and s["resettable"] and s["dirty"]
    with pytest.raises(update.UpdateError, match="local changes"):
        update.switch(root=lab, sync=False)
    assert (lab / "a.txt").read_text() == "changed here\n"
    run("checkout", "a.txt", cwd=lab)
    update.switch(root=lab, sync=False)
    assert (lab / "a.txt").read_text() == "rewritten\n" and not update.status(root=lab)["problem"]


def test_any_branch_on_github_can_be_switched_to_and_back(repos):
    lab, other = repos
    run("switch", "-c", "feature", cwd=other)
    push(other, "on feature", name="b.txt", text="f\n")
    run("push", "-u", "origin", "feature", cwd=other)
    found = {b["name"]: b for b in update.status(root=lab)["branches"]}
    assert set(found) == {"main", "feature"} and not found["feature"]["switch"]  # a lab without the switch
    update.switch("feature", root=lab, sync=False)
    assert update.git("rev-parse", "--abbrev-ref", "HEAD", root=lab) == "feature" and (lab / "b.txt").exists()
    update.switch(root=lab, sync=False)
    assert update.git("rev-parse", "--abbrev-ref", "HEAD", root=lab) == "main" and not (lab / "b.txt").exists()
    with pytest.raises(update.UpdateError, match="no branch gone"):
        update.switch("gone", root=lab, sync=False)


def test_the_settings_offer_a_switch_unless_something_blocks_it(client, monkeypatch):
    from lab.web import app as web

    base = {"branch": "obgp-fixes", "commit": "abc1234", "date": "2026-10-03", "behind": 0, "ahead": 0, "new": [], "dirty": [],
            "branches": [{"name": "master", "commit": "843c4df", "date": "2026-10-04", "subject": "s", "default": True, "switch": True},
                         {"name": "old", "commit": "cce751f", "date": "2026-10-01", "subject": "s", "default": False, "switch": False}],
            "problem": "GitHub no longer has the branch obgp-fixes.", "resettable": True, "checked": None}
    monkeypatch.setattr("lab.web.context.UPDATES", base)
    page = client.get("/settings").text
    assert "master (default), 843c4df of 2026-10-04</option>" in page and "cce751f of 2026-10-01, no way back in the UI" in page
    assert 'aria-label="Switch branch"' in page
    monkeypatch.setattr("lab.web.context.UPDATES", {**base, "dirty": [" M a.txt"]})
    assert 'aria-label="Switch branch"' not in client.get("/settings").text
    monkeypatch.setattr("lab.web.context.UPDATES", base)
    monkeypatch.setattr(web.jobs, "active", lambda: type("D", (), {"name": "t-running"})())
    r = client.post("/settings/update/switch", data={"branch": "master"}, follow_redirects=False)
    assert "t-running+runs" in r.headers["location"]
