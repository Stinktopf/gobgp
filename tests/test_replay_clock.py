"""The clock of the replay (lab/web/static/clock.js), run with node."""

import json
import shutil
import subprocess

import pytest

from lab import analysis
from lab.config import ROOT
from lab.results import Dataset

CHECK = """
const { make } = require(process.argv[1]);
const runs = JSON.parse(require("fs").readFileSync(0, "utf8"));
const clock = make(runs, true);
const out = { end: clock.end, events: clock.events.map((e) => [e.name, e.c]), marks: {}, monotonic: true };
for (const [name, run] of Object.entries(runs)) {
  let before = -1;
  for (let c = 0; c <= clock.end; c += clock.end / 500) {
    const t = clock.toRun(run, c);
    if (t < before - 1e-9) out.monotonic = false;
    before = t;
  }
  out.marks[name] = run.events.map((e) => clock.fromRun(run, e.t));
}
console.log(JSON.stringify(out));
"""


def play(runs: dict) -> dict:
    if not shutil.which("node"):
        pytest.skip("needs node")
    script = ROOT / "lab" / "web" / "static" / "clock.js"
    done = subprocess.run(["node", "-e", CHECK, str(script)], input=json.dumps(runs), capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def run(*events, end):
    return {"t": [i / 10 for i in range(int(end * 10) + 1)], "events": [dict(zip(("name", "t", "step"), e)) for e in events]}


def test_steps_wait_for_the_slowest_variant():
    # BGP needs 20 s to give up on stability, OBGP 3 s.
    bgp = run(("announce", 0, "0"), ("settled", 20, "1"), ("down", 21, "2"), ("settled", 30, "3"), end=31)
    obgp = run(("announce", 0, "0"), ("settled", 3, "1"), ("down", 4, "2"), ("settled", 8, "3"), end=9)
    out = play({"bgp": bgp, "obgp": obgp})
    assert out["monotonic"] and out["end"] == 31
    # Every mark is at the same clock time in both variants.
    assert out["marks"]["bgp"] == out["marks"]["obgp"] == [0, 20, 21, 30]
    assert [c for _, c in out["events"]] == [0, 20, 21, 30]


def test_parallel_actions_match_in_any_order():
    bgp = run(("down", 5, "1.0"), ("restart", 5, "1.1"), ("settled", 9, "2"), end=10)
    obgp = run(("restart", 5, "1.1"), ("down", 5.2, "1.0"), ("settled", 7, "2"), end=8)
    out = play({"bgp": bgp, "obgp": obgp})
    assert out["monotonic"]
    assert out["marks"]["bgp"][2] == out["marks"]["obgp"][2] == 9.2  # both settle at the same time


def test_the_runs_of_the_paper_stay_in_step(lab_files):
    d = Dataset.find("ifip-networking-2026")
    key = next(k for k in d.keys() if d.is_done(k) and k.variant == d.experiment.variants[0].name)
    runs = {}
    for v in d.experiment.variants:
        r = analysis.replay(d, type(key)(key.topology, v.name, key.scenario, key.index))
        runs[v.name] = {"t": r["t"], "events": r["events"]}
    out = play(runs)
    assert out["monotonic"]
    first, *others = out["marks"].values()
    for marks in others:
        assert marks == pytest.approx(first, abs=1e-6)
