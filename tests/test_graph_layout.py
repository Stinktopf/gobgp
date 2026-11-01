"""The initial layout of topologies without positions (lab/web/static/graph.js), run with node."""

import json
import shutil
import subprocess

import pytest

from lab import topology
from lab.config import ROOT

STATIC = ROOT / "lab" / "web" / "static"
ARRANGE = """
global.cytoscape = require(process.argv[1] + "/cytoscape.min.js");
global.window = { cytoscape };
global.UI = { css: () => "" };
global.document = { addEventListener() {} };
global.addEventListener = () => {};
require(process.argv[1] + "/graph.js");
const t = JSON.parse(require("fs").readFileSync(0, "utf8"));
const again = JSON.parse(JSON.stringify(t));
console.log(JSON.stringify([window.Graph.arrange(t), window.Graph.arrange(again)]));
"""


def arrange(t: dict) -> list[dict]:
    if not shutil.which("node"):
        pytest.skip("needs node")
    done = subprocess.run(["node", "-e", ARRANGE, str(STATIC)], input=json.dumps(t), capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def test_a_large_topology_is_arranged_alike_every_time(lab_files):
    t = topology.load("germany50")
    for r in t["routers"].values():
        r.pop("location", None)
    first, second = arrange(t)
    assert first == second and set(first) == set(t["routers"])
    points = [(p["x"], p["y"]) for p in first.values()]
    assert len(set(points)) == len(points)


def test_a_small_topology_stands_in_rings(lab_files):
    first, _ = arrange(topology.load("bad-gadget"))
    assert first["aachen"] == {"x": 0, "y": 0}  # the origin in the middle
