import json

from lab import config, results
from lab.config import Experiment
from lab.web import jobs as J


def waiting_result(name):
    path = results.PRIVATE / name
    path.mkdir(parents=True)
    e = Experiment.load(config.path("lab-smoke"))
    (path / "dataset.json").write_text(json.dumps({"experiment": e.model_dump(mode="json"), "commits": {}, "created": "2026-01-01"}))
    (path / "status.json").write_text(json.dumps({"state": "queued"}))
    return results.Dataset(path)


def test_a_cancelled_waiting_result_is_stopped(lab_files, monkeypatch):
    jobs = J.Jobs()
    jobs._save(["t-a", "t-b"])
    d = waiting_result("t-a")
    jobs.stop("t-a")
    assert jobs.queue() == ["t-b"] and d.status["state"] == "stopped"


def test_one_result_at_a_time_on_the_cluster(lab_files):
    from lab import cluster

    assert cluster.holder() is None
    claim = cluster.claim("t-a")
    assert cluster.holder() == "t-a"
    try:
        cluster.claim("t-b")
        raise AssertionError("claimed twice")
    except cluster.Busy as e:
        assert "t-a" in str(e)
    claim.close()
    assert cluster.holder() is None
    cluster.claim("t-b").close()


def test_the_queue_is_reordered(lab_files, monkeypatch):
    jobs = J.Jobs()
    monkeypatch.setattr(jobs, "active", lambda: type("D", (), {"name": "a"})())
    jobs._save(["a", "b", "c", "d"])
    jobs.reorder(["d", "a", "x", "b"])
    assert jobs.queue() == ["a", "d", "b", "c"]


def test_a_damaged_queue_starts_empty(lab_files, monkeypatch):
    results.queue_file().parent.mkdir(parents=True, exist_ok=True)
    results.queue_file().write_text('["a", ')
    assert J.Jobs().queue() == []


def test_a_stale_running_result_is_stopped(lab_files, monkeypatch):
    d = waiting_result("t-stale")
    d.write_status({"state": "running", "pid": 999999})  # its worker is gone
    J.Jobs().stop("t-stale")
    assert d.status["state"] == "stopped"


def test_a_worker_failing_before_it_starts_is_not_retried(lab_files, monkeypatch):
    import subprocess
    import sys

    d = waiting_result("t-early")
    jobs = J.Jobs()
    jobs._save(["t-early"])
    jobs.worker = subprocess.Popen([sys.executable, "-c", "raise SystemExit(1)", "t-early"])
    jobs.worker.wait()
    jobs._step()  # sees the ended worker and starts nothing
    assert d.status["state"] == "failed" and "worker.log" in d.status["error"]
    assert jobs.worker is None and jobs.queue() == []


def test_a_result_that_runs_or_waits_is_neither_moved_nor_deleted(lab_files, monkeypatch):
    import pytest

    from lab import cluster

    d = waiting_result("t-busy")
    J.Jobs()._save(["t-busy"])
    with pytest.raises(ValueError, match="queued"):
        d.publish(True)
    J.Jobs()._save([])
    monkeypatch.setattr(cluster, "holder", lambda: "t-busy")
    with pytest.raises(ValueError, match="running"):
        d.delete()


def test_the_lock_names_the_runner(lab_files):
    import os

    from lab import cluster

    claim = cluster.claim("t-a")
    assert cluster.holding() == ("t-a", os.getpid())
    claim.close()


def test_new_results_get_free_names(lab_files):
    e = Experiment.load(config.path("lab-smoke"))
    first = results.Dataset.new_name(e)
    (results.PRIVATE / first).mkdir(parents=True)
    assert results.Dataset.new_name(e) == f"{first}-2"


def test_a_paused_queue_starts_nothing_and_resumes_in_order(lab_files, monkeypatch):
    from lab import cluster

    monkeypatch.setattr(cluster, "holding", lambda: None)
    jobs = J.Jobs()
    a, b = waiting_result("t-a"), waiting_result("t-b")
    jobs._save(["t-a", "t-b"])
    jobs.pause()
    a.write_status({"state": "stopped"})  # as its runner writes when paused
    jobs._step()
    assert jobs.paused() and jobs.worker is None and jobs.queue() == ["t-a", "t-b"]
    jobs.resume_queue()
    assert not jobs.paused() and a.status["state"] == "queued" and b.status["state"] == "queued"


def test_cancel_all_empties_the_queue_and_keeps_the_runs(lab_files, monkeypatch):
    jobs = J.Jobs()
    a, b = waiting_result("t-a"), waiting_result("t-b")
    jobs._save(["t-a", "t-b"])
    jobs.pause()
    jobs.stop_all()
    assert jobs.queue() == [] and not jobs.paused()
    assert a.status["state"] == "stopped" and b.status["state"] == "stopped" and a.path.exists()


def test_an_empty_queue_is_no_longer_paused(lab_files, monkeypatch):
    from lab import cluster

    monkeypatch.setattr(cluster, "holding", lambda: None)
    jobs = J.Jobs()
    jobs.pause()
    jobs._step()
    assert not jobs.paused()


def test_the_queue_is_paused_and_cancelled_on_the_command_line(lab_files, monkeypatch, capsys):
    import sys

    from lab import cli, cluster

    monkeypatch.setattr(cluster, "holding", lambda: None)
    waiting_result("t-a")
    J.Jobs()._save(["t-a"])
    for action, out in (("pause", "paused: t-a"), ("resume", "t-a"), ("cancel", "the queue is empty")):
        monkeypatch.setattr(sys, "argv", ["lab", "queue", action])
        try:
            cli.main()
        except SystemExit as e:
            assert not e.code
        assert capsys.readouterr().out.strip() == out
