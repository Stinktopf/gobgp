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

    monkeypatch.setattr(web, "UPDATES", {"branch": "obgp-fixes", "commit": "abc1234", "date": "2026-10-03", "behind": 2, "ahead": 0,
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
