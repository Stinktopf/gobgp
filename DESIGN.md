# Design

How OBGP is built in this fork and why, held against the proof it rests on:
[*Eliminating Routing Loops and Oscillations in BGP Using Total Ordering*](https://doi.org/10.1109/LCN53696.2022.9843706)
(J.J. Garcia-Luna-Aceves, LCN 2022). Numbers come from `obgp-sim` over every connected topology up to five routers with
three message orders each, unless a line says otherwise. They are counterexamples, not samples.

## The yardstick

- **Order:** a router may use a neighbor's path only if that path is strictly shorter than its own
  advertised one, or as long with a smaller identifier.
- **Import (OBi):** a router admits only paths that keep this order.
- **Export (OBe):** an AS advertises one route, its worst admitted, to all or a subset of its neighbors.
- **iBGP (I-OBGP):** a designated route reflector orders the routes inside an AS, so that the AS
  advertises one route.

If the order holds at every instant, OBGP is loop-free at every instant and stable. Stable means a
route wherever one is reachable under OBGP, not wherever BGP would find one.

Each decision below is marked: **holds** (the proof covers it), **outside, simulated** (not covered,
backed by the simulator) or **outside**.

## Decisions

### Import stricter than the proof

A path is admitted only if it is strictly better than the worst path already admitted. The proof allows
more: any path better than the route the router advertises, which it takes to be the worst admitted
path with the router's own AS in front, one hop longer. A router whose worst admitted path has three
hops would admit any path of up to three hops under the proof, here only those that beat the worst
three-hop one. *Code:* `operaImportAccept` in `internal/pkg/table/opera.go`. *Proof:* holds, it admits
a subset of what the proof allows.

*Why:*

- **No added hop assumed.** The order holds against the worst admitted path itself. It does not rely
  on the advertisement being one hop longer, which is not the case behind a route server, over iBGP or
  between members of a confederation. There the proof's rule lets two routers admit each other's routes
  and oscillate.
- **Fewer lost routes.** Admitting more makes the advertised worst path longer, so neighbors filter or
  reject it more often.
- **Less state.** Fewer admitted paths are the measured gain of OBGP over BGP.

The proof's rule against this one, in the same search:

| | This rule | The proof's | Networks |
|---|---|---|---|
| Oscillation behind route servers | none | 484 | 62,406 |
| Oscillation in iBGP | none | 266 | 76,605 |
| Oscillation in confederations | none | 1,901 | 91,026 |
| Lost route with Gao-Rexford | 7,927 | 10,932 | 413,310 |
| Lost route with tags on the way | 770 | 1,606 | 102,066 |
| Lost route with filters on the AS path | 210 | 448 | 76,302 |

### Refresh pruning by default

A withdrawn path sets the paths that contain its AS sequence aside instead of removing them. Once no
valid path is left, the router asks the neighbors of those paths for their routes again with a route
refresh (RFC 2918), sent behind its own withdrawal. A path comes back only as the neighbor answers it,
so it is current. The router's own import policy, lost sessions and attribute-only updates prune
nothing. *Code:* `Pruning` in `opera.go`, `opera_refresh.go` in `pkg/server`, `GOBGP_OPERA_PRUNING`.

*Why:* hard pruning cannot tell a withdrawal caused by a neighbor's filter from a real one and loses
routes: 3,065 of 25,764 networks with an import filter, 3,065 of 51,528 with an export filter.
Refresh pruning loses none, as soft pruning, which takes set-aside paths back at once. A path taken
back at once may be stale, and forwarding loops until the routes settle. Networks up to five routers
that loop on the way (`obgp-sim -transient`):

| Family | BGP | soft | hard | refresh |
|---|---|---|---|---|
| withdraw | 1,420 of 2,313 | 1,135 | 33 | 48 |
| aggregation | 1,633 of 15,195 | 1,255 | 41 | 50 |
| link-down | 213 of 12,882 | 120 | 8 | 2 |
| export filters | 216 of 51,528 | 163 | 1 | 1 |
| import filters | 213 of 25,764 | 120 | 4 | 2 |
| confederations | 802 of 91,026 | 831 | 260 | 133 |

Up to four routers, Local Preference, leaks and prepending make BGP loop on the way in 93 of 31,632
networks and no OBGP mode. Refresh pruning loops about as rarely as hard pruning and loses what soft
pruning loses. From five routers on, no mode is loop-free at every instant.

*Cost:* a route refresh asks for the whole table of a family. A router asks each neighbor at most once
per `GOBGP_OPERA_REFRESH_S`, 1 s by default, for all destinations that wait. A neighbor answers with
what it knows, which is stale while a withdrawal is still on its way to it. `GOBGP_OPERA_REFRESH_DELAY_S`
lets the first request wait, so that withdrawals elsewhere arrive first, at the price of a path that
comes back that much later. It is 0 by default, the lab measures 1 s against it. Neighbors without the
route refresh capability get soft pruning. *Proof:* stability holds. Loop freedom at every instant
does not, as for every mode.

### Native iBGP

Paths from iBGP peers pass without the import filter, and iBGP withdrawals prune nothing. Route
reflectors work as in RFC 4456 and pass on the export path. *Code:* `FilterIBGP` in `opera.go`,
`GOBGP_OPERA_IBGP=filter` for the paper's code. *Why:* the AS path does not grow inside an AS, so
the filter compares iBGP paths unfairly with paths from other ASes. The paper's code, which filters
them, loops in 72 of 31,734 networks with reflectors and sends two routes per AS in 546.

*Proof:* outside, simulated. The proof assumes one route per AS. Native iBGP shows it in every network
searched: at rest no loop and no AS with two routes in 76,605. On the way every mode loops, BGP too,
while the routers of an AS learn of a change one after the other:

| | Networks | BGP | native | the paper's code |
|---|---|---|---|---|
| Full mesh | 13,137 | 37 | 53 | 20 |
| Route reflectors | 31,734 | 119 | 175 | 88 |
| Route reflectors with a MED | 31,734 | 430 | 353 | 88 |

The paper's code loops less on the way but also at rest. The paper's designated route reflector is not
built: native iBGP needs no configuration and works for full meshes as well as for reflectors.

### AS_SET and confederations

An `AS_SET` is one hop of its members in ascending order, confederation segments are no hop
(RFC 5065). *Code:* `operaHops` in `opera.go`, `GOBGP_OPERA_AS_SET=received` for the paper's code.
*Why:* the same paths compare alike however their sets were written. *Proof:* outside, simulated. The
paper orders AS sequences only. Aggregates lose nothing in 15,195. Confederations lose a route in 9
of 91,026.

### Choice per neighbor

Export filters, Gao-Rexford classes, siblings, partial transit, communities, tags and route leaks
decide which neighbors get the one route. *Proof:* holds, the export rule allows any subset. They cost
reachability, not stability. The worst path may be the one a neighbor must not get, and that neighbor
then gets none:

| Choice | Lost a route in |
|---|---|
| Export filter towards one neighbor | none of 51,528 |
| Export filter on the AS path | 210 of 76,302 |
| Communities of the origin | none of 11,418 |
| Communities tagged on the way | 770 of 102,066 |
| Gao-Rexford | 7,927 of 413,310 |
| Gao-Rexford with siblings | 17,151 of 412,140 |
| Gao-Rexford with partial transit | 7,927 of 412,140 |
| Route leaks, on Gao-Rexford | 42,222 of 1,643,940 |

### Prepending

Prepending towards all neighbors and poisoning lengthen the one route alike. *Proof:* holds. Towards
one neighbor, that neighbor sees a different route. *Proof:* outside, simulated, nothing lost.

### Route servers

GoBGP's route server keeps one table for all clients, chooses a path per client and then applies that
client's export filter. With OBGP it chooses the worst admitted path instead of the best. It adds no AS
and keeps the next hop. *Why as GoBGP has it:* GoBGP chooses before the filter for BGP as well, a choice
per client after its filter (RFC 7947) would be a GoBGP feature of its own. *Proof:* holds. A route
server is no AS, it passes each AS's one route on unchanged.

Clients that filter on the AS path lose a route in 206 of 62,406 networks, 305 with hard pruning, with
no oscillation. BGP loses one too where its best path is the filtered one: gobgpd breaks ties by the age
of a path in whole seconds, so which of two equal paths wins depends on when they arrived. The lab marks
a route server's neighbors with `rsClient: true`. `ixp` in `lab-features` plays the smallest such case.

### Additions to GoBGP

- **MRAI:** GoBGP read it but never applied it. `pkg/server/mrai.go` holds back advertisements per
  peer, withdrawals go out at once. *Proof:* holds, it assumes nothing about timing.
- **Forwarding:** the FIB gets GoBGP's best path, chosen among admitted paths. *Proof:* holds, the
  paper's local preference may choose any admitted path.
- **Fixes:** soft reset out withdraws newly rejected routes, the API marks the best path again, ties
  break by ORIGINATOR_ID and the shorter CLUSTER_LIST (RFC 4456), and a looped update withdraws the
  peer's route before (RFC 4271).

### Left out

- **Add-Path:** several paths per neighbor break the one route per AS.
- **Families other than IPv4 and IPv6 unicast:** they run as plain GoBGP.
- **Mixed deployment** (hybrid and random modes): BGP routers keep neither rule. *Proof:* outside,
  measured in the lab.
