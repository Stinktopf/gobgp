"""The controller beside gobgpd: the configuration it writes. It runs in the
router pods, so gRPC and the generated API are stubbed here."""

import importlib.util
import json
import sys
import tomllib
from types import ModuleType
from unittest.mock import MagicMock

import pytest

from lab.config import ROOT


@pytest.fixture
def controller(monkeypatch):
    def load(name: str, asn: int, neighbors: list[dict], addresses: dict[str, str]):
        for module in ("grpc", "google", "google.protobuf", "google.protobuf.json_format", "api"):
            monkeypatch.setitem(sys.modules, module, MagicMock())
        env = {"POD_IP": "10.1.0.1", "ROUTER_NAME": name, "ASN": str(asn), "ROUTER_ID": "10.0.0.1", "POD_NAMESPACE": "lab",
               "NEIGHBORS_JSON": json.dumps(neighbors), "LAB_SEED": "1", "HOLD_TIME": "9", "KEEPALIVE": "3",
               "CONNECT_RETRY": "5", "GRACEFUL_RESTART": "false", "MRAI": "0"}
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        spec = importlib.util.spec_from_file_location("controller_app", ROOT / "controller" / "app.py")
        app: ModuleType = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, "controller_app", app)
        spec.loader.exec_module(app)
        daemon = app.Daemon()
        daemon.addresses = addresses  # in the pod, resolved from the services of the neighbors
        return app, daemon
    return load


def test_ibgp_neighbors_reflect_and_open_by_name_and_prepending_stays_outside(controller):
    app, daemon = controller("b", 65002, [{"name": "a", "peerAs": 65002, "rrClient": True}, {"name": "c", "peerAs": 65002},
                                          {"name": "x", "peerAs": 65001}],
                             {"a": "10.1.0.2", "c": "10.1.0.3", "x": "10.1.0.9"})
    daemon.prepend = 2
    config = daemon.render()
    neighbors = config.split("[[neighbors]]")[1:]
    a, c, x = (next(n for n in neighbors if f'"{ip}"' in n) for ip in ("10.1.0.2", "10.1.0.3", "10.1.0.9"))
    assert "route-reflector-client = true" in a and 'route-reflector-cluster-id = "10.0.0.1"' in a
    assert "route-reflector" not in c and "route-reflector" not in x
    assert "passive-mode = false" in a and "passive-mode = true" in c  # inside the AS by name: a < b < c
    assert "passive-mode = false" in x  # eBGP by ASN as before
    assert 'neighbor-set-name = "external"' in config and 'neighbor-info-list = ["10.1.0.9"]' in config
    assert 'neighbor-set = "external"' in config.split('name = "prepend"')[1]
    parsed = tomllib.loads(config)  # as gobgpd reads it
    prepend = next(p for p in parsed["policy-definitions"] if p["name"] == "prepend")
    assert prepend["statements"][0]["conditions"]["match-neighbor-set"]["neighbor-set"] == "external"
    assert {"neighbor-set-name": "external", "neighbor-info-list": ["10.1.0.9"]} in parsed["defined-sets"]["neighbor-sets"]


def test_without_ibgp_prepending_applies_to_all_as_before(controller):
    app, daemon = controller("b", 65002, [{"name": "x", "peerAs": 65001}], {"x": "10.1.0.9"})
    daemon.prepend = 1
    config = daemon.render()
    assert 'neighbor-set-name = "external"' not in config and 'name = "prepend"' in config


def test_med_next_hop_self_import_rejection_and_leaks(controller, monkeypatch):
    neighbors = [{"name": "a", "peerAs": 65002}, {"name": "x", "peerAs": 65001, "med": 7, "relation": "provider"},
                 {"name": "y", "peerAs": 65003, "relation": "peer"}]
    addresses = {"a": "10.1.0.2", "x": "10.1.0.9", "y": "10.1.0.8"}
    app, daemon = controller("b", 65002, neighbors, addresses)
    daemon.rejected.add("y")
    parsed = tomllib.loads(daemon.render())
    policies = {p["name"]: p["statements"][0] for p in parsed["policy-definitions"]}
    assert policies["med-x"]["actions"]["bgp-actions"]["set-med"] == "7"
    nhs = policies["next-hop-self"]
    assert nhs["conditions"]["bgp-conditions"]["route-type"] == "external" and nhs["actions"]["bgp-actions"]["set-next-hop"] == "self"
    assert {"neighbor-set-name": "internal", "neighbor-info-list": ["10.1.0.2"]} in parsed["defined-sets"]["neighbor-sets"]
    assert parsed["global"]["apply-policy"]["config"]["import-policy-list"][0] == "reject-y"  # before the Local Preferences
    assert policies["reject-y"]["actions"]["route-disposition"] == "reject-route"
    assert "valley-free" in policies
    app, daemon = controller("b", 65002, neighbors, addresses)
    monkeypatch.setattr(app, "LEAK", True)
    assert "valley-free" not in daemon.render()


def test_without_ibgp_neighbors_no_next_hop_self(controller):
    app, daemon = controller("b", 65002, [{"name": "x", "peerAs": 65001}], {"x": "10.1.0.9"})
    assert "next-hop-self" not in daemon.render()


def test_a_confederation_member_configures_it_and_prepends_outside_only(controller, monkeypatch):
    monkeypatch.setenv("CONFEDERATION", "65500")
    monkeypatch.setenv("CONFED_MEMBERS", "[65002, 65003]")
    app, daemon = controller("b", 65002, [{"name": "c", "peerAs": 65003}, {"name": "x", "peerAs": 65001}],
                             {"c": "10.1.0.3", "x": "10.1.0.9"})
    daemon.prepend = 2
    parsed = tomllib.loads(daemon.render())
    assert parsed["global"]["confederation"]["config"] == {"enabled": True, "identifier": 65500, "member-as-list": [65002, 65003]}
    assert {"neighbor-set-name": "external", "neighbor-info-list": ["10.1.0.9"]} in parsed["defined-sets"]["neighbor-sets"]
    prepend = next(p for p in parsed["policy-definitions"] if p["name"] == "prepend")
    assert prepend["statements"][0]["actions"]["bgp-actions"]["set-as-path-prepend"]["as"] == "65500"


def test_a_path_filter_rejects_routes_through_an_as_towards_one_neighbor(controller):
    app, daemon = controller("b", 65002, [{"name": "x", "peerAs": 65001, "denyVia": 65003}], {"x": "10.1.0.9"})
    parsed = tomllib.loads(daemon.render())
    assert {"as-path-set-name": "via-x", "as-path-list": ["_65003_"]} in parsed["defined-sets"]["bgp-defined-sets"]["as-path-sets"]
    deny = next(p for p in parsed["policy-definitions"] if p["name"] == "deny-via-x")["statements"][0]
    assert deny["conditions"]["match-neighbor-set"]["neighbor-set"] == "x"
    assert deny["conditions"]["bgp-conditions"]["match-as-path-set"] == {"as-path-set": "via-x", "match-set-options": "any"}
    assert deny["actions"]["route-disposition"] == "reject-route"
    assert '"deny-via-x"' in daemon.render().split("export-policy-list")[1].splitlines()[0]


def test_samples_the_lab_fetched_are_dropped(controller):
    app, _ = controller("b", 65002, [], {})
    recorder = app.Recorder()
    recorder.samples.extend({"seq": s, "t": s / 10} for s in range(1, 6))
    assert [r["seq"] for r in recorder.after(0)["samples"]] == [1, 2, 3, 4, 5]
    assert [r["seq"] for r in recorder.after(3)["samples"]] == [4, 5]  # 1 to 3 acknowledged
    assert [r["seq"] for r in recorder.after(3)["samples"]] == [4, 5]  # a failed fetch asks again
    assert len(recorder.samples) == 2 and recorder.after(5)["samples"] == []


def test_the_mrai_holds_back_advertisements_to_other_ases_only(controller, monkeypatch):
    app, daemon = controller("b", 65002, [{"name": "c", "peerAs": 65002}, {"name": "x", "peerAs": 65001}],
                             {"c": "10.1.0.3", "x": "10.1.0.9"})
    assert "minimum-advertisement-interval" not in daemon.render()
    monkeypatch.setattr(app, "MRAI", 30.0)
    timers = {n["config"]["neighbor-address"]: n["timers"]["config"] for n in tomllib.loads(daemon.render())["neighbors"]}
    assert timers["10.1.0.9"]["minimum-advertisement-interval"] == 30
    assert "minimum-advertisement-interval" not in timers["10.1.0.3"]  # inside the AS at once


def test_communities_ask_the_routers_on_the_way_not_to_pass_routes_on(controller):
    app, daemon = controller("b", 65002, [{"name": "a", "peerAs": 65001, "relation": "customer"}, {"name": "c", "peerAs": 65002},
                                          {"name": "x", "peerAs": 65003, "relation": "provider"}],
                             {"a": "10.1.0.2", "c": "10.1.0.3", "x": "10.1.0.9"})
    assert app.community("no-export") == 0xFFFFFF01 and app.community("no-advertise") == 0xFFFFFF02
    assert app.community("0:65003") == 65003 and app.community("65001:100") == 65001 << 16 | 100
    parsed = tomllib.loads(daemon.render())
    sets = {s["neighbor-set-name"]: s["neighbor-info-list"] for s in parsed["defined-sets"]["neighbor-sets"]}
    assert sets["outside"] == ["10.1.0.2", "10.1.0.9"] and sets["as-65003"] == ["10.1.0.9"]  # never the own AS
    policy = next(p for p in parsed["policy-definitions"] if p["name"] == "communities")
    rejects = [(s["conditions"].get("match-neighbor-set", {}).get("neighbor-set"), s["conditions"]["bgp-conditions"]["match-community-set"]["community-set"])
               for s in policy["statements"]]
    assert rejects == [(None, "no-advertise"), ("outside", "no-export"), ("outside", "no-export"), ("as-65001", "not-to-65001"),
                       ("as-65003", "not-to-65003")]
    assert [s["conditions"]["bgp-conditions"].get("route-type") for s in policy["statements"][1:3]] == ["external", "internal"]  # not its own
    assert "communities" in parsed["global"]["apply-policy"]["config"]["export-policy-list"]


def test_the_class_a_route_is_learned_from_replaces_only_the_class(controller):
    app, daemon = controller("b", 65002, [{"name": "x", "peerAs": 65003, "relation": "provider"}], {"x": "10.1.0.9"})
    policy = next(p for p in tomllib.loads(daemon.render())["policy-definitions"] if p["name"] == "in-x")
    first, second = policy["statements"]
    assert first["actions"]["bgp-actions"]["set-community"]["options"] == "remove" and "route-disposition" not in first.get("actions", {})
    assert first["actions"]["bgp-actions"]["set-community"]["set-community-method"]["communities-list"] == ["64999:1", "64999:2", "64999:3"]
    assert second["actions"]["bgp-actions"]["set-community"]["options"] == "add"  # other communities, e.g. no-export, stay
    assert second["actions"]["route-disposition"] == "accept-route"


def test_a_tag_marks_the_routes_learned_from_a_neighbor(controller):
    app, daemon = controller("b", 65002, [{"name": "x", "peerAs": 65003, "relation": "provider", "tag": "0:65004"},
                                          {"name": "y", "peerAs": 65005, "tag": "no-export"}], {"x": "10.1.0.9", "y": "10.1.0.8"})
    policies = {p["name"]: p for p in tomllib.loads(daemon.render())["policy-definitions"]}
    added = lambda name: policies[name]["statements"][-1]["actions"]["bgp-actions"]["set-community"]["set-community-method"]["communities-list"]
    assert added("in-x") == ["64999:3", "0:65004"] and added("in-y") == ["no-export"]
    assert len(policies["in-y"]["statements"]) == 1  # without a relation, no class to replace


def test_prepending_towards_one_neighbor_comes_first_and_all_ends_it(controller):
    app, daemon = controller("b", 65002, [{"name": "c", "peerAs": 65002}, {"name": "x", "peerAs": 65001}, {"name": "y", "peerAs": 65003}],
                             {"c": "10.1.0.3", "x": "10.1.0.9", "y": "10.1.0.8"})
    prepend = lambda: next((p for p in tomllib.loads(daemon.render()).get("policy-definitions", []) if p["name"] == "prepend"), None)
    assert prepend() is None
    daemon.prepend_to["x"] = 3
    daemon.prepend = 1
    statements = prepend()["statements"]
    assert [(s["conditions"]["match-neighbor-set"]["neighbor-set"], s["actions"]["bgp-actions"]["set-as-path-prepend"]["repeat-n"])
            for s in statements] == [("x", 3), ("external", 1)]
    app.daemon = daemon
    daemon.reload = lambda **_: None  # writes gobgpd's configuration in the pod
    app.policy_prepend(app.PrependRequest(times=2))  # towards all: also ends the one towards x
    assert daemon.prepend_to == {} and daemon.prepend == 2


def test_a_route_from_a_sibling_keeps_its_class(controller):
    app, daemon = controller("b", 65002, [{"name": "s", "peerAs": 65009, "relation": "sibling"}, {"name": "t", "peerAs": 65008, "relation": "sibling"},
                                          {"name": "x", "peerAs": 65003, "relation": "provider"}], {"s": "10.1.0.7", "t": "10.1.0.6", "x": "10.1.0.9"})
    parsed = tomllib.loads(daemon.render())
    sets = [s["community-set-name"] for s in parsed["defined-sets"]["bgp-defined-sets"]["community-sets"]]
    assert sets.count("learned-customer") == 1  # once, with two siblings
    statements = next(p for p in parsed["policy-definitions"] if p["name"] == "in-s")["statements"]
    assert [(s["conditions"].get("bgp-conditions", {}).get("match-community-set", {}).get("community-set"), s["actions"]["bgp-actions"]["set-local-pref"])
            for s in statements] == [("learned-customer", 200), ("learned-peer", 150), ("learned-provider", 100), (None, 200)]
    assert statements[-1]["actions"]["bgp-actions"]["set-community"]["set-community-method"]["communities-list"] == ["64999:1"]  # its own: a customer's
    up = next(s for s in parsed["defined-sets"]["neighbor-sets"] if s["neighbor-set-name"] == "peers-and-providers")
    assert up["neighbor-info-list"] == ["10.1.0.9"]  # a sibling gets every route


def test_a_customer_with_partial_transit_gets_routes_of_customers_only(controller):
    app, daemon = controller("b", 65002, [{"name": "c", "peerAs": 65009, "relation": "customer", "partialTransit": True},
                                          {"name": "d", "peerAs": 65008, "relation": "customer"}, {"name": "x", "peerAs": 65003, "relation": "provider"}],
                             {"c": "10.1.0.7", "d": "10.1.0.6", "x": "10.1.0.9"})
    sets = {s["neighbor-set-name"]: s["neighbor-info-list"] for s in tomllib.loads(daemon.render())["defined-sets"]["neighbor-sets"]}
    assert sorted(sets["peers-and-providers"]) == ["10.1.0.7", "10.1.0.9"]  # c as a peer, d as a customer


def test_exactly_one_side_opens_a_session_out_of_a_confederation(controller, monkeypatch):
    # c2 is member 65022 of confederation 65500, x is AS 65030: x sees 65500, so c2 opens, x waits.
    monkeypatch.setenv("CONFEDERATION", "65500")
    monkeypatch.setenv("CONFED_MEMBERS", "[65021, 65022]")
    app, daemon = controller("c2", 65022, [{"name": "x", "peerAs": 65030}, {"name": "c1", "peerAs": 65021}], {"x": "10.1.0.9", "c1": "10.1.0.8"})
    passive = {n["config"]["neighbor-address"]: n["transport"]["config"]["passive-mode"] for n in tomllib.loads(daemon.render())["neighbors"]}
    assert passive == {"10.1.0.9": False, "10.1.0.8": False}  # inside the confederation by member AS: 65022 opens to 65021
    monkeypatch.delenv("CONFEDERATION")
    monkeypatch.setenv("CONFED_MEMBERS", "[]")
    app, daemon = controller("x", 65030, [{"name": "c2", "peerAs": 65500}], {"c2": "10.1.0.2"})
    assert tomllib.loads(daemon.render())["neighbors"][0]["transport"]["config"]["passive-mode"] is True


def test_a_route_server_gives_its_clients_tables_with_its_policies(controller):
    app, daemon = controller("rs", 65100, [{"name": "a", "peerAs": 65002, "rsClient": True},
                                           {"name": "c", "peerAs": 65004, "rsClient": True, "denyVia": 65003}],
                             {"a": "10.1.0.2", "c": "10.1.0.4"})
    config = daemon.render()
    parsed = tomllib.loads(config)  # as gobgpd reads it
    for n in parsed["neighbors"]:
        assert n["route-server"]["config"]["route-server-client"] is True
        # gobgpd applies a route server client's own policies, not the global ones
        assert n["apply-policy"]["config"]["export-policy-list"] == parsed["global"]["apply-policy"]["config"]["export-policy-list"]
        # and sends them every path their filter allows
        assert n["afi-safis"][0]["add-paths"]["config"] == {"receive": True, "send-max": 255}


def test_only_a_route_server_sends_several_paths(controller):
    app, daemon = controller("r1", 65001, [{"name": "r2", "peerAs": 65002}], {"r2": "10.1.0.2"})
    parsed = tomllib.loads(daemon.render())
    assert parsed["neighbors"][0]["afi-safis"][0]["add-paths"]["config"] == {"receive": True}


def test_next_hops_are_written_as_changes_and_read_on_after_a_change(controller, monkeypatch):
    app, _ = controller("b", 65002, [], {})
    table = lambda n: type("T", (), {"num_destination": n})()
    seen = {"p1": "a|", "p2": "."}
    monkeypatch.setattr(app, "hops", lambda: dict(seen))
    clock = [100.0]
    monkeypatch.setattr(app.time, "monotonic", lambda: clock[0])
    cache = {}
    assert app.hops_changed(cache, table(2), (2, 2, 5)) == "* p1=a| p2=."  # the whole table at first
    clock[0] += 0.1
    seen["p1"] = "c|"  # a new best route, the counts unchanged: read again within two seconds
    assert app.hops_changed(cache, table(2), (2, 2, 5)) == "p1=c|"
    clock[0] += 3
    del seen["p1"]
    assert app.hops_changed(cache, table(2), (2, 2, 5)) == ""  # quiet and read lately: not read
    clock[0] += 5
    assert app.hops_changed(cache, table(2), (2, 2, 5)) == "p1=-"  # read every five seconds anyway
    assert app.hops_changed(cache, table(300), (300, 300, 9)) == "!"  # too large to follow, said once
    assert app.hops_changed(cache, table(300), (300, 300, 9)) == ""
    # The lab names a sample: the whole sample at once, then changes again, however large the table.
    assert app.hops_watch({"prefixes": ["p2"]}) == {"watched": 1} and app.WATCHED == ["p2"]
    assert app.hops_changed(cache, table(300), (300, 300, 9)) == "* p2=."
