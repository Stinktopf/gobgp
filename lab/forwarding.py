"""Where packets go, from the best routes of the routers: the same check as
the simulator's (internal/pkg/obgpsim/oracle.go), so that the lab and the
simulator judge a network alike.

A packet goes to the BGP next hop of the router it is at: over the session
to a neighbor in another AS, or, inside an AS, one IGP hop towards the
next hop over the cheapest links, where the next router decides again. No
IGP runs: the costs of the topology are the IGP. Ties between equally
cheap paths are broken as the simulator breaks them, by the order of the
routers and links in the topology.
"""


def links(routers: dict) -> list[tuple[str, str, int]]:
    """The IGP links of a topology, each once, in the order of the file."""
    out, seen = [], set()
    for name, r in routers.items():
        for link in r.get("igp", []):
            pair = frozenset((name, link["name"]))
            if pair not in seen:
                seen.add(pair)
                out.append((name, link["name"], int(link["cost"])))
    return out


def shortest(routers: dict) -> dict[str, dict[str, str | None]]:
    """The first IGP hop from a router towards another of its AS, or None.
    Floyd-Warshall as in the simulator, keeping the first of equal paths."""
    names = list(routers)
    inf = float("inf")
    dist = {a: {b: (0 if a == b else inf) for b in names} for a in names}
    first = {a: {b: (a if a == b else None) for b in names} for a in names}
    for a, b, cost in links(routers):
        for x, y in ((a, b), (b, a)):
            if cost < dist[x][y]:
                dist[x][y], first[x][y] = cost, y
    for k in names:
        for a in names:
            for b in names:
                if dist[a][k] + dist[k][b] < dist[a][b]:
                    dist[a][b], first[a][b] = dist[a][k] + dist[k][b], first[a][k]
    return first


def check(routers: dict, next_hops: dict[str, str | None], starts: list[str] | None = None) -> list[str]:
    """The problems of forwarding one prefix from the starts, all routers if
    none: next_hops gives for every router the router its best route leads
    to, itself for the origin, None for no route. Loops and black holes, as
    the simulator names them."""
    igp = shortest(routers)
    asn = {name: str(r.get("asn")) for name, r in routers.items()}
    loops, holes = {}, []
    for start in starts if starts is not None else routers:
        if next_hops.get(start) is None:
            continue
        seen, at = [], start
        while True:
            hop = next_hops.get(at)
            if hop == at:
                break  # the origin
            if at in seen:
                cycle = sorted(seen[seen.index(at):])
                loops[tuple(cycle)] = cycle
                break
            seen.append(at)
            nxt = hop
            if hop is not None and hop in asn and asn[hop] == asn[at]:
                nxt = igp[at][hop]
            if hop is None or nxt is None or next_hops.get(nxt) is None:
                holes.append(start)
                break
            at = nxt
    problems = [f"forwarding loops between {', '.join(c)}" for c in loops.values()]
    if holes:
        problems.append(f"forwarding from {', '.join(holes)} ends at a router without a route")
    return problems


def with_igp(routers: dict, costs: dict) -> dict:
    """The routers with the costs igp steps set, 0 taking a link away."""
    if not costs:
        return routers
    out = {}
    for name, r in routers.items():
        links = [{**link, "cost": costs.get(frozenset((name, link["name"])), link["cost"])} for link in r.get("igp", [])]
        out[name] = {**r, "igp": [link for link in links if link["cost"] > 0]}
    return out


def relations(routers: dict) -> dict[tuple[int, int], str]:
    """Between ASes, what the second is to the first: customer, peer, provider or sibling."""
    asn = {name: int(r.get("asn")) for name, r in routers.items() if r.get("asn") is not None}
    return {(asn[name], asn[n["name"]]): n["relation"] for name, r in routers.items() for n in r.get("neighbors", [])
            if n.get("relation") and name in asn and n.get("name") in asn}


def valley_free(between: dict[tuple[int, int], str], own: int, as_path: list[int]) -> bool | None:
    """Whether packets along an AS path go up to providers, over at most one
    peer, then down to customers only, as Gao-Rexford asks. Siblings count
    as neither. None where a hop has no relation: nothing to judge."""
    hops = [own]
    for a in as_path:  # a prepended AS once
        if a != hops[-1]:
            hops.append(a)
    down = False
    for x, y in zip(hops, hops[1:]):
        rel = between.get((x, y))
        if rel is None:
            return None
        if rel == "sibling":
            continue
        if down and rel != "customer":
            return False
        down = down or rel in ("peer", "customer")
    return True
