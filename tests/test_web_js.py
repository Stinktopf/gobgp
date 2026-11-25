"""The editor's saving, a pure function of graph.js, run in Node: what it
does not edit stays as the file has it."""

import json
import shutil
import subprocess

import pytest

from lab import topology
from lab.config import ROOT

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="needs node")


def serialize(original: dict, edits: dict | None = None, edge_edits: dict | None = None) -> dict:
    """Saves a topology as the editor would, with edits of nodes and edges
    as the panels make them, else unchanged."""
    nodes = [{"id": n, "asn": r["asn"], "routerId": r["routerId"], "location": r.get("location"), "obgp": r.get("obgp", False),
              "position": r.get("position"), **(edits or {}).get(n, {})} for n, r in original.items()]
    relation = {"customer": "p2c", "provider": "c2p", "peer": "p2p", "sibling": "s2s"}  # as REL in graph.js
    edges, seen = [], set()
    for a, r in original.items():
        for n in r.get("neighbors", []):
            if frozenset((a, n["name"])) in seen:
                continue
            seen.add(frozenset((a, n["name"])))
            back = next(m for m in original[n["name"]]["neighbors"] if m["name"] == a)
            edges.append({"a": a, "b": n["name"], "rel": relation.get(n.get("relation")), "prefA": n.get("localPref"),
                          "prefB": back.get("localPref"), "rrA": n.get("rrClient", False), "rrB": back.get("rrClient", False),
                          "partialA": n.get("partialTransit", False), "partialB": back.get("partialTransit", False),
                          **(edge_edits or {}).get((a, n["name"]), {})})
    script = ("global.window = {}; global.UI = { css: () => '' }; global.addEventListener = () => {};"
              "global.document = { addEventListener() {}, querySelectorAll: () => [] };"
              f"{(ROOT / 'lab/web/static/graph.js').read_text()}\n"
              f"process.stdout.write(JSON.stringify(window.Graph.serialize({json.dumps(original)}, {json.dumps(nodes)}, {json.dumps(edges)})));")
    done = subprocess.run(["node", "-"], input=script, capture_output=True, text=True, check=True)
    return json.loads(done.stdout)


def same(a: dict, b: dict) -> bool:
    """Equal routers, neighbors in any order."""
    norm = lambda t: {n: {**r, "neighbors": sorted(r["neighbors"], key=lambda x: x["name"])} for n, r in t.items()}
    return norm(a) == norm(b)


def test_saving_keeps_igp_meds_leaks_and_confederations():
    routers = {
        "a": {"asn": 65002, "routerId": "10.0.0.1", "confederation": 65500, "igp": [{"name": "b", "cost": 10}],
              "neighbors": [{"name": "b", "peerAs": 65002, "rrClient": True}, {"name": "x", "peerAs": 65001, "med": 7, "relation": "provider"}]},
        "b": {"asn": 65002, "routerId": "10.0.0.2", "confederation": 65500, "igp": [{"name": "a", "cost": 10}],
              "neighbors": [{"name": "a", "peerAs": 65002}, {"name": "c", "peerAs": 65003}]},
        "c": {"asn": 65003, "routerId": "10.0.0.3", "confederation": 65500, "neighbors": [{"name": "b", "peerAs": 65002}]},
        "x": {"asn": 65001, "routerId": "10.0.0.9", "leak": True,
              "neighbors": [{"name": "a", "peerAs": 65500, "relation": "customer"}]},
    }
    assert topology.validate(routers) == []
    saved = serialize(routers)
    assert same(saved, routers)
    assert topology.validate(saved) == []


def test_every_topology_of_the_repository_saves_unchanged():
    for name in topology.names():
        t = topology.load(name, shared=True)
        if len(t["routers"]) > 300:
            continue  # the large ones of the Internet only take long
        assert same(serialize(t["routers"]), t["routers"]), name


def test_the_panels_set_leaks_confederations_igp_and_meds():
    routers = {
        "a": {"asn": 65002, "routerId": "10.0.0.1", "neighbors": [{"name": "b", "peerAs": 65002}, {"name": "x", "peerAs": 65001}]},
        "b": {"asn": 65002, "routerId": "10.0.0.2", "neighbors": [{"name": "a", "peerAs": 65002}]},
        "x": {"asn": 65001, "routerId": "10.0.0.9", "neighbors": [{"name": "a", "peerAs": 65002}]},
    }
    saved = serialize(routers,
                      {"a": {"confederation": 65500, "igp": [{"name": "b", "cost": 3}]}, "b": {"confederation": 65500, "igp": [{"name": "a", "cost": 3}]},
                       "x": {"leak": True}},
                      {("a", "b"): {"rrA": True}, ("a", "x"): {"medA": 20, "viaA": 65009, "tagA": "0:65009"}})
    assert saved["x"]["leak"] is True and saved["a"]["confederation"] == 65500
    assert saved["a"]["igp"] == [{"name": "b", "cost": 3}]
    assert {"name": "x", "peerAs": 65001, "med": 20, "denyVia": 65009, "tag": "0:65009"} in saved["a"]["neighbors"]
    assert {"name": "b", "peerAs": 65002, "rrClient": True} in saved["a"]["neighbors"]
    assert {"name": "a", "peerAs": 65500} in saved["x"]["neighbors"]  # outside, the confederation
    assert topology.validate(saved) == []
    cleared = serialize(saved, {"x": {"leak": False}, "a": {"confederation": None, "igp": []}, "b": {"confederation": None, "igp": []}},
                        {("a", "x"): {"medA": None, "viaA": None, "tagA": None}})
    assert "leak" not in cleared["x"] and "confederation" not in cleared["a"] and "igp" not in cleared["a"]
    assert {"name": "x", "peerAs": 65001} in cleared["a"]["neighbors"]


def test_partial_transit_stays_with_the_provider():
    routers = {"p": {"asn": 1, "routerId": "10.0.0.1", "neighbors": [{"name": "c", "peerAs": 2, "relation": "customer", "partialTransit": True}]},
               "c": {"asn": 2, "routerId": "10.0.0.2", "neighbors": [{"name": "p", "peerAs": 1, "relation": "provider"}]}}
    saved = serialize(routers, {}, {})
    assert saved["p"]["neighbors"] == [{"name": "c", "peerAs": 2, "relation": "customer", "partialTransit": True}]
    assert topology.validate(saved) == []
    peers = serialize(routers, {}, {("p", "c"): {"rel": "p2p", "partialA": False}})  # not a customer any more
    assert "partialTransit" not in peers["p"]["neighbors"][0]


def test_a_route_server_marks_its_neighbors_in_other_ases():
    routers = topology.load("ixp")["routers"]
    assert serialize(routers) == routers  # unchanged as the file has it
    off = serialize(routers, {"rs": {"rs": False}})
    assert not any(m.get("rsClient") for m in off["rs"]["neighbors"])
    on = serialize(off, {"a": {"rs": True}})
    assert {m["name"]: m.get("rsClient", False) for m in on["a"]["neighbors"]} == {"o": True, "rs": True}
