import pytest

from lab import generate, topology


def connected(links, n):
    near = {a: set() for a in range(n)}
    for a, b in links:
        near[a].add(b)
        near[b].add(a)
    seen, todo = {0}, [0]
    while todo:
        for b in near[todo.pop()] - seen:
            seen.add(b)
            todo.append(b)
    return len(seen) == n


@pytest.mark.parametrize("model", ["er", "ws", "ba", "waxman", "elmokashfi"])
@pytest.mark.parametrize("n", [12, 60])
def test_every_model_is_connected_and_the_same_for_a_seed(model, n):
    p = generate.params_of(model, {})
    g = generate.graph_of(model, n, 3, p)
    assert connected(g.links, n) and all(0 <= a < b < n for a, b in g.links)
    assert generate.graph_of(model, n, 3, p).links == g.links


def test_erdos_renyi_keeps_its_average_degree_as_it_grows():
    for n in (100, 400):
        g = generate.erdos_renyi(n, degree=6, seed=1)
        assert 5 < 2 * len(g.links) / n < 7


def test_watts_strogatz_is_a_ring_without_rewiring():
    g = generate.watts_strogatz(20, degree=4, rewire=0, seed=1)
    assert len(g.links) == 40 and (0, 1) in g.links and (0, 2) in g.links and (0, 18) in g.links
    with pytest.raises(ValueError):
        generate.watts_strogatz(20, degree=3)


def test_barabasi_albert_has_its_size_and_relations():
    n, m = 100, 2
    g = generate.barabasi_albert(n, m, seed=1, relations=True)
    assert len(g.links) == m * (m + 1) // 2 + (n - m - 1) * m
    opposite = {"peer": "peer", "customer": "provider", "provider": "customer"}
    assert all(g.relation[(b, a)] == opposite[g.relation[(a, b)]] for a, b in g.links)


def test_elmokashfi_has_the_kinds_and_relations_of_the_paper():
    n = 1000
    g = generate.elmokashfi(n, seed=1)
    roles = g.roles
    assert len(roles["tier1"]) == 5 and len(roles["transit"]) == 150 and len(roles["content"]) == 50 and len(roles["stubs"]) == 795
    tier1, stubs = set(roles["tier1"]), set(roles["stubs"])
    assert all(g.relation[(a, b)] == "peer" for a in tier1 for b in tier1 if a != b)
    # Stubs never peer, Tier-1s have no providers.
    assert not any(g.relation[(a, b)] == "peer" for a in stubs for b in range(n) if (a, b) in g.relation)
    assert not any(g.relation[(a, b)] == "provider" for a in tier1 for b in range(n) if (a, b) in g.relation)
    routers, _ = generate.build(n, g)
    assert topology.provider_cycle(routers) is None


def test_generated_topologies_validate_and_are_named_by_their_parameters(lab_files):
    names = generate.generate("ba", [16, 32], seed=2, m="2", relations="on")
    assert names == ["ba-gr-m2-16-s2", "ba-gr-m2-32-s2"]
    for model in ("er", "ws", "waxman"):
        name = generate.generate(model, [30], relations="on")[0]
        t = topology.load(name)
        assert "-gr-" in name and topology.validate(t["routers"], t.get("roles")) == [] and topology.provider_cycle(t["routers"]) is None
        assert any(n.get("relation") == "provider" for r in t["routers"].values() for n in r["neighbors"])
    t = topology.load(names[1])
    assert len(t["routers"]) == 32 and topology.validate(t["routers"], t.get("roles")) == []
    assert generate.generate("waxman", [20]) == ["waxman-a40-b10-20-s1"]
    assert generate.generate("ws", [20], rewire="0,2") == ["ws-k4-r20-20-s1"]  # as a German keyboard types it
    assert generate.generate("elmokashfi", [40]) == ["elmokashfi-40-s1"]
    assert "transit" in topology.load("elmokashfi-40-s1")["roles"]
    assert generate.generate("er", [16, 32], name="flat") == ["flat-16", "flat-32"]
    assert generate.generate("er", [24], name="flat") == ["flat"]
    with pytest.raises(ValueError):
        generate.generate("er", [16], name="Not valid")
    with pytest.raises(FileExistsError):
        generate.generate("waxman", [20])
    with pytest.raises(ValueError):
        generate.generate("ba", [3], m=3)
    with pytest.raises(ValueError):
        generate.generate("ws", [20], rewire="2")


def test_the_web_generates_topologies(client):
    r = client.post("/topologies/generate", data={"model": "er", "sizes": "8, 12", "seed": "4", "degree": "3"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/topologies"
    assert topology.path("er-k3-8-s4").exists() and topology.path("er-k3-12-s4").exists()
    r = client.post("/topologies/generate", data={"model": "er", "sizes": "8", "seed": "4", "degree": "3"}, follow_redirects=False)
    assert "error=" in r.headers["location"]
    page = client.get("/topologies").text
    assert "Generate topologies" in page and "doi.org/10.1038/30918" in page and "Elmokashfi" in page
