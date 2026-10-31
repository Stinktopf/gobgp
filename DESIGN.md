# Design

How OBGP is built in this fork and why, held against the proof it rests on:
[*Eliminating Routing Loops and Oscillations in BGP Using Total Ordering*](https://doi.org/10.1109/LCN53696.2022.9843706)
(J.J. Garcia-Luna-Aceves, LCN 2022). Where a decision lies outside the proof, `obgp-sim` backs it: it searches every
connected topology up to five routers, with three message orders each, for lost routes, oscillations and loops.

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

In the search the proof's rule oscillates behind route servers, in iBGP and in confederations, this
rule never does. Under policies the proof's rule also loses routes more often.

### Refresh pruning by default

A withdrawn path sets the paths that contain its AS sequence aside instead of removing them. Once no
valid path is left, the router asks the neighbors of those paths for their routes again with a route
refresh (RFC 2918), sent behind its own withdrawal. A path comes back only as the neighbor answers it,
so it is current. The router's own import policy, lost sessions and attribute-only updates prune
nothing. An admitted path sent again with the same AS path, as a route refresh answer or with a new
MED, keeps its place. *Code:* `Pruning` in `opera.go`, `opera_refresh.go` in `pkg/server`, `GOBGP_OPERA_PRUNING`.

*Why:* hard pruning cannot tell a withdrawal caused by a neighbor's filter from a real one and loses
routes behind import and export filters. Refresh pruning loses none there, as soft pruning, which
takes set-aside paths back at once. A path taken back at once may be stale, and forwarding loops
until the routes settle. Refresh pruning loops on the way about as rarely as hard pruning, far less
often than soft pruning or BGP (`obgp-sim -transient`). Every mode loops on the way in some network.

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
them, loops at rest and sends two routes per AS in some networks with reflectors.

*Proof:* outside, simulated. The proof assumes one route per AS. Native iBGP keeps it in every network
searched, at rest without loops. On the way every mode loops, BGP too, while the routers of an AS
learn of a change one after the other. The paper's designated route reflector is not built: native
iBGP needs no configuration and works for full meshes as well as for reflectors.

These loops come from forwarding hop by hop inside the AS, where every router decides again. Over
tunnels to the exit, as with MPLS, the first router sends a packet to the border router of its path.
`obgp-sim -tunnel` forwards so. The lab forwards hop by hop.

### AS_SET and confederations

An `AS_SET` is one hop of its members in ascending order. Members of a confederation count in the
order after the AS path length and are hops for pruning. *Code:* `operaHops`, `confedHops` and
`compareOperaPath` in `opera.go`, `GOBGP_OPERA_AS_SET=received` and `GOBGP_OPERA_CONFED=ignore` for
the paper's code. *Why:* the same paths compare alike however their sets were written. RFC 5065 leaves
members out of the AS path length. Left out of the order too, a hop between members keeps a path as it
was, and a member's withdrawal looks like one of the AS behind it: it prunes the direct path from that
AS as well. Counted, a hop between members makes a path strictly worse, as one between ASes does.
*Proof:* outside, simulated. The paper orders AS sequences only. Aggregates lose nothing in the
search. Confederations lose a route in rare cases and loop on the way less often than with members
left out or with BGP.

### Choice per neighbor

Export filters, Gao-Rexford classes, siblings, partial transit, communities, tags and route leaks
decide which neighbors get the one route. *Proof:* holds, the export rule allows any subset. They cost
reachability, not stability. The worst path may be the one a neighbor must not get, and that neighbor
then gets none. In the search export filters towards one neighbor and communities of the origin
lose nothing. Filters on the AS path, tags on the way, Gao-Rexford with its variants and route leaks
lose a route in some networks.

### A table per neighbor

Off by default, `GOBGP_OPERA_EXPORT=neighbor` turns it on. The router keeps one OBGP table per eBGP
neighbor. Into it go the paths the router's own export policy lets through to that neighbor, and the
neighbor's own paths, which set the threshold but are never sent back. Each table admits, prunes and
asks for route refreshes as the main one does, and the neighbor gets its worst admitted path. A table
built for a neighbor that comes up takes the paths worst first, so that it admits all of them. These
include the paths hard pruning took out of the other tables: hard pruning keeps them aside, never
admits them again and drops them once their neighbor sends again, as the neighbor still sends them.
A policy change asks for route refreshes where a table is left waiting, and a route refresh answer
withdraws what the neighbor may no longer get. The
router forwards on its preferred path among those admitted in any of its tables that are no longer
than any of its exports. iBGP peers and route server clients keep the main table. *Code:*
`opera_neighbor.go` in `internal/pkg/table` and `pkg/server`, `obgp-sim -per-neighbor`, a lab
variant's `per_neighbor: true`.

*Why:* one route per AS is what loses the routes above. A filter by class or by content can forbid
exactly that route. A table per neighbor holds only what that neighbor may get, so a short peer route
no longer keeps a longer customer route out of the table towards a provider. It needs no labels: the
router reads its own export policy, whatever it is built from.

*Why forwarding stays loop-free:* a neighbor that forwards to the router uses a path one AS longer
than what the router exports to it. The router forwards on a path no longer than any of its exports,
so the length falls along every hop whatever the policies, as in OBGP itself. The bound can keep a
router from its preferred path where that path is longer than one of its exports.

*Proof:* outside, simulated. For BGP, [Neighbor-Specific BGP](https://arxiv.org/abs/0906.3846) (Y. Wang,
M. Schapira, J. Rexford, SIGMETRICS 2009) shows that a choice per neighbor keeps BGP stable under
conditions such as Gao-Rexford's and allows more policies.

*Cost:* each table holds its own entry for every path it is fed, the attributes stay shared. With n
eBGP neighbors that is up to n² entries per destination. Neighbors whose export policies decided
alike on every path fed so far share one table, under Gao-Rexford the customers. The first path they
differ on copies the table, and a table built for a neighbor that comes up joins one in the same
state, much as routers group neighbors with the same outbound policy into update groups. So a
shared table decides exactly as a table of its own. *Proof:* as for tables per neighbor, sharing
changes nothing.
*Code:* `OperaFeedAll`, `OperaShare`, tested against tables of their own in every pruning mode.

In the search a table per neighbor loses fewer routes than one table under these choices, in every
pruning mode. No network oscillates or loops at rest. Without export filters a table per neighbor
sends and forwards as the one table, message by message.

### Prepending

Prepending towards all neighbors and poisoning lengthen the one route alike. *Proof:* holds. Towards
one neighbor, that neighbor sees a different route. *Proof:* outside, simulated, nothing lost.

### Route servers

A route server is transparent: it admits and prunes nothing and passes every path on as plain GoBGP
does, adding no AS and keeping the next hop. With Add-Path (RFC 7911) it sends a client every path that
client's filter allows, the filter before the choice as in RFC 7947, section 2.3.2.1. *Code:*
`operaSelects` in `opera.go`, `SetRouteServer` on the route server's tables, `GOBGP_OPERA_RS=admit`
for the paper's code, which admits and exports the worst admitted path, then filters. The lab's
route servers send their clients Add-Path, every router receives it. *Why:* a route server is no AS.
Each client then sees every other client's one route as over a direct session, and the route server
needs no rule of its own. Choosing first, a client's filter can reject exactly the chosen path and
leave it without one, and the route server's own admission drops paths no client would. *Proof:*
holds. Without the route server the clients are directly connected ASes, each with its one route.

Clients that filter on the AS path lose a route in rare cases, with no oscillation and no loop. The
client behind the filter gets only the other client's one route, which may run through the filtered
AS. The paper's code loses more. Without Add-Path a client gets GoBGP's best path its filter allows. The lab marks a
route server's neighbors with `rsClient: true`. `ixp` in `lab-features` plays the smallest such case.

### Additions to GoBGP

- **MRAI:** GoBGP read it but never applied it. `pkg/server/mrai.go` holds back advertisements per
  peer and prefix, per path with Add-Path send. Withdrawals go out at once and drop what waits for
  the prefix. *Proof:* holds, the last message computed is the last one the neighbor gets.
- **Forwarding:** the FIB gets GoBGP's best path, chosen among admitted paths. *Proof:* holds, the
  paper's local preference may choose any admitted path.
- **Fixes:** soft reset out withdraws newly rejected routes, the API marks the best path again, ties
  break by ORIGINATOR_ID and the shorter CLUSTER_LIST (RFC 4456), and a looped update withdraws the
  peer's route before (RFC 4271).

### Left out

- **Add-Path send:** several paths per neighbor break the one route per AS. Configured, it is turned
  off with a warning in the families OBGP selects, before the session announces it. *Code:*
  `operaOnePath` in `pkg/server/server.go`. Receiving Add-Path stays, and a transparent route server
  sends it to its clients.
- **Families other than IPv4 and IPv6 unicast:** they run as plain GoBGP.
- **Mixed deployment** (hybrid and random modes): BGP routers keep neither rule. *Proof:* outside,
  measured in the lab.

## What the router supports

**Works:** yes as with BGP, limited where it loses routes in some networks. **Proof:** whether the
proof of loop freedom and stability covers the feature, see the decisions above. It says nothing
about lost routes, the last column does, for OBGP with refresh pruning (`obgp-rp`) in the networks searched.

| Feature | Works | Proof | What the simulator found |
|---|---|---|---|
| Local Preference, e.g. BAD GADGET | yes | holds | converges where BGP oscillates |
| Import filters, route origin validation | yes | holds | none lost, hard pruning loses some |
| Export filters towards one neighbor | yes | holds | none lost, hard pruning loses some |
| Prepending towards all neighbors | yes | holds | the same longer path for all, a step of the lab |
| Prepending towards one neighbor | yes | simulated | none lost |
| AS path poisoning | yes | holds | none lost |
| Communities of the origin: no-export, not to one AS | yes | holds | none lost |
| Aggregates with an `AS_SET` | yes | simulated | none lost |
| Link and session failures, withdrawals | yes | holds | none lost |
| iBGP in a full mesh or through route reflectors, MED | yes | simulated | at rest no loop and one path per AS |
| Graceful restart, soft reset, MRAI | yes | holds | steps of the lab, MRAI applied since this fork |
| IPv4 and IPv6 unicast, 4-byte ASNs | yes | holds | IPv6 and 2-byte speakers in unit tests |
| Multipath | yes | holds | over admitted paths only |
| Confederations | limited | simulated | rare losses |
| Export filters on the AS path | limited | holds | some losses, fewer with a table per neighbor |
| Route servers, clients filtering on the AS path | limited | holds | rare losses, with Add-Path to the clients |
| Communities tagged on the way, e.g. not to one AS | limited | holds | some losses, fewer with a table per neighbor |
| Gao-Rexford relations, also with partial transit or siblings | limited | holds | some losses, fewer with a table per neighbor |
| Route leaks | limited | holds | some losses, fewer with a table per neighbor |
| Other address families, e.g. VPN or EVPN | no | – | they run as plain GoBGP |
| Add-Path export | no | – | OBGP sends one path per destination |

## Where the modes differ

Where the modes differ, lost routes, or for iBGP loops and ASes that send different paths:

| | `obgp-rp` | `obgp-hp` | `obgp-np` | `obgp-paper` |
|---|---|---|---|---|
| Import filter of the own router | none | some | none | some |
| Export filter towards one neighbor | none | some | none | some |
| Confederations | rare | more | more | more |
| Route servers, clients filtering on the AS path | rare | rare | rare | more |
| iBGP, loops and ASes sending different paths | none | none | none | some |

`obgp-sp` loses what `obgp-rp` loses. Native iBGP prunes nothing on withdrawals over iBGP, which only
say that a router's export path changed.
