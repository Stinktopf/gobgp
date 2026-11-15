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


ARRANGE_ALL = ARRANGE.replace(
    "const t = JSON.parse(require(\"fs\").readFileSync(0, \"utf8\"));\nconst again = JSON.parse(JSON.stringify(t));\n"
    "console.log(JSON.stringify([window.Graph.arrange(t), window.Graph.arrange(again)]));",
    "console.log(JSON.stringify(JSON.parse(require(\"fs\").readFileSync(0, \"utf8\")).map((t) => window.Graph.arrange(t))));")


def networks(most: int):
    """Every connected network up to most routers, router 0 the origin, as the simulator's search plays them."""
    from itertools import combinations, product

    for n in range(2, most + 1):
        pairs = list(combinations(range(n), 2))
        for keep in product((False, True), repeat=len(pairs)):
            links = [p for p, k in zip(pairs, keep) if k]
            seen, todo = {0}, [0]
            while todo:
                a = todo.pop()
                for x, y in links:
                    for b in ((y,) if x == a else (x,) if y == a else ()):
                        if b not in seen:
                            seen.add(b)
                            todo.append(b)
            if len(seen) == n:
                routers = {f"r{i}": {"asn": 65001 + i, "neighbors": [{"name": f"r{y if x == i else x}"} for x, y in links if i in (x, y)]}
                           for i in range(n)}
                yield {"routers": routers, "roles": {"origins": ["r0"]}}, links


def test_no_link_passes_over_a_router_in_any_small_network():
    if not shutil.which("node"):
        pytest.skip("needs node")
    cases = list(networks(5))
    done = subprocess.run(["node", "-e", ARRANGE_ALL, str(STATIC)], input=json.dumps([t for t, _ in cases]),
                          capture_output=True, text=True, check=True)
    bad = []
    for (t, links), pos in zip(cases, json.loads(done.stdout)):
        for a, b in links:
            p, q = pos[f"r{a}"], pos[f"r{b}"]
            dx, dy = q["x"] - p["x"], q["y"] - p["y"]
            length = (dx * dx + dy * dy) ** 0.5
            for c in t["routers"]:
                if c in (f"r{a}", f"r{b}"):
                    continue
                r = pos[c]
                s = ((r["x"] - p["x"]) * dx + (r["y"] - p["y"]) * dy) / length ** 2
                d = abs((r["x"] - p["x"]) * dy - (r["y"] - p["y"]) * dx) / length
                if 0 < s < 1 and d < 20:
                    bad.append((links, a, b, c, round(d, 1)))
    assert not bad, f"{len(bad)} links pass over a router, e.g. {bad[:3]}"


def test_a_triangle_around_one_origin_has_equal_sides():
    if not shutil.which("node"):
        pytest.skip("needs node")
    t, _ = next((t, links) for t, links in networks(3) if len(links) == 3)
    done = subprocess.run(["node", "-e", ARRANGE_ALL, str(STATIC)], input=json.dumps([t]), capture_output=True, text=True, check=True)
    p = json.loads(done.stdout)[0]
    side = lambda a, b: ((p[a]["x"] - p[b]["x"]) ** 2 + (p[a]["y"] - p[b]["y"]) ** 2) ** 0.5
    sides = [side("r0", "r1"), side("r0", "r2"), side("r1", "r2")]
    assert max(sides) - min(sides) < 1e-6, sides
