"""Imports the data of the IFIP Networking 2026 paper as a dataset.

The runs of the paper were recorded by the former lab scripts. This
converts their reports into the current format. The original files stay
next to the converted runs in original/. Run once with:

    uv run python -m lab.legacy
"""

import json
import math
import sys
from datetime import UTC, datetime

from . import cluster, config
from .config import Experiment, Sampling
from .results import PUBLIC, Dataset, RunKey, copy_files, write_atomic

NAME = "ifip-networking-2026"
RELEASE = "718d9499"  # the commit of the release ifip-networking-2026
TOPOLOGIES = {"germany": "germany50", "bad_gadget": "bad-gadget", "noble-eu": "noble-eu"}
SCENARIOS = [
    "full-drain-30", "full-drain-60", "full-drain-90",
    "partial-drain-25", "partial-drain-50", "partial-drain-75",
    "fill-30", "fill-60", "fill-90",
]
# Event times relative to the start of the recorded window, from the waits of the scripts.
EVENTS = {
    "fill": [("announce", 0), ("announced", 30)],
    "partial_drain": [("announce", -40), ("announced", -10), ("withdraw", 5)],
    "full_drain": [("announce", -60), ("announced", -30), ("withdraw", 5)],
}


def main() -> None:
    path = PUBLIC / NAME
    originals = path / "original"
    if not originals.is_dir():
        sys.exit(f"move the experiments-* directories of the release to {originals} first")
    commit = cluster.resolve(RELEASE)
    experiment = Experiment.load(config.path(NAME))
    copy_files(path, experiment)
    experiment = experiment.model_copy(update={
        "name": NAME,
        "description": "The runs of the paper, imported from the former scripts.",
        "variants": [v.model_copy(update={"ref": RELEASE}) for v in experiment.variants],
        "sampling": Sampling(interval=1.0, stable_s=3.0),  # the scripts sampled once a second
    })
    meta = {
        "experiment": experiment.model_dump(mode="json"),
        "commits": {v.name: commit for v in experiment.variants},
        "created": "2026-01-08T00:00:00+00:00",
        "lab": {"commit": commit, "dirty": False},
        "host": {"description": "minikube with 20 CPUs and 14 GB RAM, Kubernetes 1.32"},
        "imported": {
            "from": "original/",
            "notes": [
                "Runs that did not drain in 60 s were discarded and repeated.",
                "Only the window around the event was recorded. Event times are nominal.",
                "Update counters were not recorded.",
            ],
        },
    }
    write_atomic(path / "dataset.json", json.dumps(meta, indent=2))
    dataset = Dataset(path)
    kinds = {s: s.rsplit("-", 1)[0].replace("-", "_") for s in experiment.scenarios}

    for old, name in TOPOLOGIES.items():
        for group in sorted((originals / f"experiments-{old}").iterdir()):
            variant, seq = group.name.split("-")[:2]
            scenario_name = SCENARIOS[int(seq.removeprefix("seq")) - 1]
            for report_path in sorted(group.glob("*/report_*.json")):
                key = RunKey(name, variant, scenario_name, int(report_path.parent.name))
                run, samples = convert(json.loads(report_path.read_text()), kinds[scenario_name])
                dataset.write_run(key, run, samples)
                print(key)


def convert(report: dict, kind: str) -> tuple[dict, list[dict]]:
    mark = next(s["ts"] for s in report["sequence"] if s.get("gate") == "mark_start")
    responses = [s["action"] for s in report["sequence"] if "action" in s]
    # The former watchers polled at individual offsets. Resample every router
    # onto a common one-second grid, holding the last value.
    series = {pod.split("-")[0]: obs["series"] for pod, obs in report["observers"].items() if obs["series"]}
    first = max(math.ceil(s[0]["ts"] - mark) for s in series.values()) if series else 0
    last = min(math.floor(s[-1]["ts"] - mark) for s in series.values()) if series else -1
    samples = []
    for t in range(first, last + 1):
        for router, points in sorted(series.items()):
            s = [p for p in points if p["ts"] - mark <= t][-1]
            samples.append({
                "t": t, "router": router,
                "destinations": s["num_destinations"], "paths": s["num_paths"],
                "path_len_min": s["path_len_min"], "path_len_avg": s["path_len_avg"], "path_len_max": s["path_len_max"],
            })
    run = {
        "status": "completed",
        "started": datetime.fromtimestamp(mark, UTC).isoformat(timespec="seconds"),
        "duration_s": samples[-1]["t"] if samples else 0,
        "seed": None,
        "watched": sorted(series),
        "events": [{"name": n, "t": t} for n, t in EVENTS[kind]],
        "measurements": [],
    }
    withdraw = next((e for e in run["events"] if e["name"] == "withdraw"), None)
    if kind == "partial_drain":
        drained = [a["result"]["response"] for a in responses if a["path"] == "/noise/drain"]
        withdraw["expected"] = sum(r["remaining"] for r in drained)
        run["events"][1]["expected"] = withdraw["expected"] + sum(r["removed"] for r in drained)
    elif kind == "full_drain":
        run["events"][1]["expected"] = sum(a["result"]["response"]["cleaned_count"] for a in responses if a["path"] == "/noise/stop")
        withdraw["expected"] = 0
        run["measurements"] = [{"after": 2, "stable": True, "t": run["duration_s"]}]
    return run, samples


if __name__ == "__main__":
    main()
