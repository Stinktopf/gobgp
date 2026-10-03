import json

from lab import config, estimate, results
from lab.config import Experiment
from lab.results import Dataset


def test_a_finished_result_takes_nothing(lab_files):
    d = Dataset.find("ifip-networking-2026")
    assert estimate.remaining_s(d) == 0


def test_pending_runs_take_as_long_as_the_same_runs_took(lab_files):
    path = results.PRIVATE / "t-est"
    path.mkdir(parents=True)
    e = Experiment.load(config.path("lab-smoke"))
    (path / "dataset.json").write_text(json.dumps({"experiment": e.model_dump(mode="json"), "commits": {}, "created": "2026-01-01"}))
    (path / "status.json").write_text(json.dumps({"state": "queued"}))
    results.copy_files(path, e)
    d = Dataset(path)
    first, *rest = d.keys()
    (path / first.path).mkdir(parents=True)
    (path / first.path / "run.json").write_text(json.dumps({"status": "completed", "took_s": 100.0}))
    same = [k for k in rest if estimate.kind(k) == estimate.kind(first)]
    others = [k for k in rest if k not in same]
    assert estimate.took(d) == {first: 100.0}
    # The same runs of this result count first, then those of earlier results.
    past = {estimate.kind(k): [1.0] for k in d.keys()}
    assert estimate.remaining_s(d, past) == 100.0 * len(same) + 1.0 * len(others)


def test_without_the_same_runs_the_most_alike_count():
    from lab.results import RunKey

    past = estimate.Past()
    past.add(RunKey("big", "bgp", "fill", 1), 100.0, 60.0)    # deploying big took 40 s
    past.add(RunKey("small", "bgp", "drain", 1), 30.0, 25.0)  # drain takes 25 s
    planned = {"fill": 50.0, "drain": 40.0, "new": 20.0}
    size = lambda t: 30
    # Another variant of the same topology and scenario.
    assert estimate.guess(RunKey("big", "obgp", "fill", 1), {}, past, planned, size) == 100.0
    # The scenario as it took elsewhere, plus deploying this topology.
    assert estimate.guess(RunKey("big", "obgp", "drain", 1), {}, past, planned, size) == 40.0 + 25.0
    # Nothing alike: the plan, with deploying guessed by the size of a topology never deployed.
    guess = estimate.guess(RunKey("other", "bgp", "new", 1), {}, past, planned, size)
    assert guess == estimate.DEPLOY_BASE_S + estimate.DEPLOY_PER_ROUTER_S * 30 + 20.0
