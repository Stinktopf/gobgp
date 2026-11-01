

def test_a_run_cut_short_by_a_reboot_is_not_done_and_runs_again(lab_files):
    from tests.test_jobs import waiting_result

    dataset = waiting_result("t-cut")
    key = dataset.keys()[0]
    (dataset.path / key.path).mkdir(parents=True)
    (dataset.path / key.path / "samples.csv.gz").write_bytes(b"half")  # written before the reboot, run.json not yet
    assert not dataset.is_done(key) and key not in dataset.statuses()
    dataset.write_run(key, {"status": "completed"}, [])
    assert dataset.is_done(key) and dataset.statuses()[key] == "completed"
