"""The forwarding check of the lab, the simulator's ported: same networks,
same verdicts (internal/pkg/obgpsim/sim_test.go)."""

from lab import forwarding, runner


def rr_network() -> dict:
    """TestFilteredIBGPLoopsBehindARouteReflector: routers r1, r2 and r4 share AS
    65002 behind reflector r2, IGP links r1-r2 and r1-r4 of cost 10."""
    asn = {"r0": 65001, "r1": 65002, "r2": 65002, "r3": 65004, "r4": 65002}
    igp = {"r1": [{"name": "r2", "cost": 10}, {"name": "r4", "cost": 10}], "r2": [{"name": "r1", "cost": 10}], "r4": [{"name": "r1", "cost": 10}]}
    return {r: {"asn": a, "igp": igp.get(r, [])} for r, a in asn.items()}


def test_the_loop_the_simulator_finds_behind_a_route_reflector():
    # The next hops of OBGP with iBGP filtered in the simulator: r1 to r2, r2 to r4.
    hops = {"r0": "r0", "r1": "r2", "r2": "r4", "r3": "r0", "r4": "r0"}
    assert forwarding.check(rr_network(), hops) == ["forwarding loops between r1, r2"]
    # BGP's: r1 and r2 both to r4, no loop.
    assert forwarding.check(rr_network(), {**hops, "r1": "r4"}) == []


def test_a_next_hop_without_a_route_is_a_black_hole():
    hops = {"r0": "r0", "r1": "r4", "r2": "r4", "r3": "r0", "r4": None}
    assert forwarding.check(rr_network(), hops, ["r1"]) == ["forwarding from r1 ends at a router without a route"]


def test_equal_paths_are_broken_as_the_simulator_breaks_them():
    # r0 to r3 over r1 or r2 at the same cost: the first found, r1, as Floyd-Warshall in the simulator.
    routers = {r: {"asn": 1, "igp": []} for r in ("r0", "r1", "r2", "r3")}
    for a, b in (("r0", "r1"), ("r0", "r2"), ("r1", "r3"), ("r2", "r3")):
        routers[a]["igp"].append({"name": b, "cost": 1})
        routers[b]["igp"].append({"name": a, "cost": 1})
    assert forwarding.shortest(routers)["r0"]["r3"] == "r1"


def test_the_kept_paths_follow_a_changed_cost():
    # Kept for the same links, made again when an igp step changes a cost.
    routers = {r: {"asn": 1, "igp": []} for r in ("r0", "r1", "r2", "r3")}
    for a, b in (("r0", "r1"), ("r0", "r2"), ("r1", "r3"), ("r2", "r3")):
        routers[a]["igp"].append({"name": b, "cost": 1})
        routers[b]["igp"].append({"name": a, "cost": 1})
    assert forwarding.shortest(routers) is forwarding.shortest(routers)
    costlier = forwarding.with_igp(routers, {frozenset(("r0", "r1")): 5})
    assert forwarding.shortest(costlier)["r0"]["r3"] == "r2"
    assert forwarding.shortest(routers)["r0"]["r3"] == "r1"


def test_routes_of_the_routers_become_next_hops():
    tables = {"r0": {"p": {"from": None, "as_path": [], "next_hop": "0.0.0.0"}},
              "r1": {"p": {"from": "r2", "as_path": [65004, 65001], "next_hop": "10.1.0.2"}},
              "r2": {"p": {"from": "r4", "as_path": [65001], "next_hop": "10.1.0.4"}},
              "r3": {"p": {"from": "r0", "as_path": [65001], "next_hop": "10.1.0.0"}},
              "r4": {"p": {"from": "r0", "as_path": [65001], "next_hop": "10.1.0.0"}}}
    addresses = {f"10.1.0.{i}": f"r{i}" for i in range(5)}
    assert runner.check_forwarding(rr_network(), {"p"}, tables, addresses, ["r1"]) == ["p: forwarding loops between r1, r2"]


def test_an_as_whose_borders_send_different_paths_is_inconsistent():
    topology = {"a": {"asn": 65002}, "b": {"asn": 65002}, "x": {"asn": 65001}, "y": {"asn": 65003}}
    same = {"a": {"x": {"p": [65002, 65004, 9]}}, "b": {"y": {"p": [65002, 65002, 65004, 9]}}}  # b prepends: the same path
    assert runner.check_consistency(topology, {"p"}, same) == []
    other = {"a": {"x": {"p": [65002, 65004, 9]}}, "b": {"y": {"p": [65002, 65005, 9]}}}
    assert runner.check_consistency(topology, {"p"}, other) == ["p: AS 65002 offers 2 different paths"]


def test_an_igp_step_changes_the_costs_the_check_uses():
    routers = rr_network()
    changed = forwarding.with_igp(routers, {frozenset(("r1", "r4")): 0})
    assert changed["r1"]["igp"] == [{"name": "r2", "cost": 10}] and changed["r4"]["igp"] == []
    assert routers["r1"]["igp"] == [{"name": "r2", "cost": 10}, {"name": "r4", "cost": 10}]  # the topology stays
    hops = {"r0": "r0", "r1": "r2", "r2": "r4", "r3": "r0", "r4": "r0"}
    assert forwarding.check(changed, hops, ["r1"]) == ["forwarding from r1 ends at a router without a route"]


def test_paths_go_up_over_one_peer_and_down_only():
    routers = {"a": {"asn": 1, "neighbors": [{"name": "b", "relation": "provider"}, {"name": "c", "relation": "peer"}]},
               "b": {"asn": 2, "neighbors": [{"name": "a", "relation": "customer"}, {"name": "c", "relation": "peer"}]},
               "c": {"asn": 3, "neighbors": [{"name": "a", "relation": "peer"}, {"name": "b", "relation": "peer"}, {"name": "d"}]},
               "d": {"asn": 4, "neighbors": [{"name": "c"}]}}
    between = forwarding.relations(routers)
    assert forwarding.valley_free(between, 1, [2, 2, 3]) is True     # up to its provider, over a peer, prepended once
    assert forwarding.valley_free(between, 2, [1]) is True           # down to a customer
    assert forwarding.valley_free(between, 3, [2, 1]) is True        # over a peer, then down
    assert forwarding.valley_free(between, 1, [3, 2]) is False       # over a peer, then over another
    assert forwarding.valley_free(between, 2, [1, 3]) is False       # down, then over a peer
    assert forwarding.valley_free(between, 3, [4]) is None           # no relation: nothing to judge


def triangle() -> dict:
    """The simulator's triangle: three routers, each its own AS."""
    names = ("r0", "r1", "r2")
    return {r: {"asn": 65001 + i, "neighbors": [{"name": n} for n in names if n != r]} for i, r in enumerate(names)}


def test_ns_bgp_forwards_by_ingress():
    # TestNSBGPForwardsByIngress: r1 and r2 route through each other, but each sent the other a route through r0.
    Ingress = forwarding.Ingress
    hops = {"r0": Ingress({None: ("r0", None), "r1": ("r0", None), "r2": ("r0", None)}),
            "r1": Ingress({None: ("r2", 65003), "r2": ("r0", 65001)}),
            "r2": Ingress({None: ("r1", 65002), "r1": ("r0", 65001)})}
    assert forwarding.check(triangle(), hops) == []
    assert forwarding.check(triangle(), {"r0": "r0", "r1": "r2", "r2": "r1"}) == ["forwarding loops between r1, r2"]
    holes = {"r0": Ingress(), "r1": Ingress({None: ("r2", 65003), "r2": ("r0", 65001)}), "r2": Ingress({None: ("r1", 65002)})}
    assert forwarding.check(triangle(), holes) == ["forwarding from r1, r2 ends at a router without a route"]


def test_ns_bgp_tunnels_to_the_exit_inside_an_as():
    # r1 and r2 share AS 65002, r2 borders r3 of AS 65003, the origin. r1's route goes through r2: the
    # tunnel ends at r3, which got the packet from r2, so r2 decides nothing on the way.
    routers = {"r1": {"asn": 65002, "neighbors": [{"name": "r2"}], "igp": [{"name": "r2", "cost": 1}]},
               "r2": {"asn": 65002, "neighbors": [{"name": "r1"}, {"name": "r3"}], "igp": [{"name": "r1", "cost": 1}]},
               "r3": {"asn": 65003, "neighbors": [{"name": "r2"}]}}
    hops = {"r1": forwarding.Ingress({None: ("r2", 65003)}), "r2": forwarding.Ingress({None: ("r1", 65003)}),
            "r3": forwarding.Ingress({None: ("r3", None), "r2": ("r3", None)})}
    assert forwarding.check(routers, hops, ["r1"]) == []
    assert forwarding.exit_of(routers, "r2", 65003) == "r3" and forwarding.exit_of(routers, "r2", 65004) is None
    # A path names a confederation by its ID, and an origin in the own AS ends the tunnel itself.
    assert forwarding.exit_of({**routers, "r3": {**routers["r3"], "confederation": 65500}}, "r2", 65500) == "r3"
    inside = {"r1": forwarding.Ingress({None: ("r2", None)}), "r2": forwarding.Ingress({None: ("r2", None)})}
    assert forwarding.check(routers, inside, ["r1"]) == []


def test_ns_bgp_routes_and_samples_name_the_route_of_each_neighbor():
    from lab import analysis

    addresses = {"10.1.0.0": "r0", "10.1.0.1": "r1", "10.1.0.2": "r2"}
    via = lambda n, asn: {"from": n, "as_path": [asn, 65001] if asn != 65001 else [65001], "next_hop": f"10.1.0.{n[1]}"}
    tables = {"r0": {"p": {"from": None, "as_path": [], "next_hop": "0.0.0.0", "ingress": {"r1": {"from": None, "as_path": [], "next_hop": None},
                                                                                         "r2": {"from": None, "as_path": [], "next_hop": None}}}},
              "r1": {"p": {**via("r2", 65003), "ingress": {"r2": via("r0", 65001)}}},
              "r2": {"p": {**via("r1", 65002), "ingress": {"r1": via("r0", 65001)}}}}
    assert runner.check_forwarding(triangle(), {"p"}, tables, addresses, ["r1", "r2"]) == []
    assert analysis.hop_of("r1", "r2|10.1.0.2|65003;r2>r0|10.1.0.0|65001", addresses) == {None: ("r2", 65003), "r2": ("r0", 65001)}
    assert analysis.hop_of("r0", ".;r1>.", addresses) == {None: ("r0", None), "r1": ("r0", None)}
    # The neighbors sent the route the router uses itself come once, after "=", as they mean the same.
    assert analysis.hop_of("r1", "r2|10.1.0.2|65003;r2>r0|10.1.0.0|65001;=r0,r3", addresses) == \
        analysis.hop_of("r1", "r2|10.1.0.2|65003;r2>r0|10.1.0.0|65001;r0>r2|10.1.0.2|65003;r3>r2|10.1.0.2|65003", addresses)
    assert analysis.hop_of("r1", "r2|10.1.0.2", addresses) == "r2"


def test_ns_bgp_forwards_packets_of_route_server_clients_on_the_route_to_the_route_server():
    # c gets a's route from the transparent route server rs and sends straight to a. a has no table
    # for c: packets of rs's clients take the route a sends rs, as the simulator has it.
    routers = {"o": {"asn": 65001, "neighbors": [{"name": "a"}]},
               "a": {"asn": 65002, "neighbors": [{"name": "o"}, {"name": "rs"}]},
               "rs": {"asn": 65100, "neighbors": [{"name": "a", "rsClient": True}, {"name": "c", "rsClient": True}]},
               "c": {"asn": 65004, "neighbors": [{"name": "rs"}]}}
    Ingress = forwarding.Ingress
    hops = {"o": Ingress({None: ("o", None), "a": ("o", None)}), "a": Ingress({None: ("o", 65001), "rs": ("o", 65001)}),
            "c": Ingress({None: ("a", 65002)})}
    assert forwarding.check(routers, hops, ["c"]) == []
    hops["a"] = Ingress({None: ("o", 65001)})
    assert forwarding.check(routers, hops, ["c"]) == ["forwarding from c ends at a router without a route"]


def test_in_a_mixed_mode_a_router_with_one_table_forwards_on_its_best_route():
    # r1 has tables per neighbor and forwards by ingress, r2 one table: packets from r1 follow r2's best route.
    routers = {"r0": {"asn": 65001, "neighbors": [{"name": "r1"}, {"name": "r2"}]},
               "r1": {"asn": 65002, "neighbors": [{"name": "r0"}, {"name": "r2"}, {"name": "r3"}]},
               "r2": {"asn": 65003, "neighbors": [{"name": "r0"}, {"name": "r1"}]},
               "r3": {"asn": 65004, "neighbors": [{"name": "r1"}]}}
    hops = {"r0": "r0", "r1": forwarding.Ingress({None: ("r0", 65001), "r3": ("r2", 65003)}), "r2": "r0", "r3": "r1"}
    assert forwarding.check(routers, hops) == []
    hops["r2"] = None
    assert forwarding.check(routers, hops) == ["forwarding from r3 ends at a router without a route"]

