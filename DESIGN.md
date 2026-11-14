# Design

How OBGP is built in this fork and why, held against the proof it rests on:
[*Eliminating Routing Loops and Oscillations in BGP Using Total Ordering*](https://doi.org/10.1109/LCN53696.2022.9843706)
(J.J. Garcia-Luna-Aceves, LCN 2022), here *the proof*. Where a decision lies outside it, the simulator
[`obgp-sim`](docs/simulator.md) backs it. *The paper's code* is OBGP as in the IFIP Networking 2026 paper,
mode `obgp-paper`.

## The yardstick

- **Order:** a router may use a neighbor's path only if that path is strictly shorter than its own
  advertised one, or as long with a smaller identifier.
- **Import (OBi):** a router admits only paths that keep this order.
- **Export (OBe):** an AS advertises one route, its worst admitted, to all or a subset of its neighbors.
- **iBGP (I-OBGP):** a designated route reflector orders the routes inside an AS, so that the AS
  advertises one route.

The proof shows: if the order holds at every instant, OBGP is loop-free at every instant and comes to
rest, with a route wherever one is reachable under OBGP, not wherever BGP would find one. Messages in
flight break that premise, so this fork claims loop freedom at rest only.

Each decision below is marked: **holds** (the proof covers it), **outside, simulated** (not covered,
backed by the simulator), **outside, measured** (backed by the lab) or **outside**.

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

### Refresh pruning

A withdrawn path sets the paths that contain its AS sequence aside instead of removing them. Once no
valid path is left, the router sends the neighbors of those paths a route refresh (RFC 2918) behind its
own withdrawal. A path comes back only with the neighbor's answer, so it is current. The router's own import policy, lost sessions and attribute-only updates prune
nothing. An admitted path sent again with the same AS path, as a route refresh answer or with a new
MED, keeps its place. One sent again unchanged, admitted, set aside or pruned in no table and while no
table waits, is skipped before the decision: it changes no table and goes on to no one. *Code:* `Pruning` in `opera.go`, `opera_refresh.go` in `pkg/server`, `GOBGP_OPERA_PRUNING`.

*Why:* hard pruning cannot tell a withdrawal caused by a neighbor's filter from a real one and loses
routes behind import and export filters. Refresh pruning loses none there, nor does soft pruning, which
takes set-aside paths back at once. Such a path may be stale, and forwarding loops until the routes
come to rest. In networks up to five routers, refresh pruning loops on the way about
as rarely as hard pruning, far less often than soft pruning or BGP (`obgp-sim -transient`). Every mode
loops on the way in some network.

*Cost:* a route refresh asks for the whole table of a family, at most once per `GOBGP_OPERA_REFRESH_S`
(1 s) and neighbor, for all destinations that wait. Its unchanged paths cost a lookup each, no
decision and with tables per neighbor no export policy per neighbor (`OperaRedundant`). With Enhanced
Route Refresh (RFC 7313) on both ends a request stays open until its answer ends, so a busy neighbor
is not asked for its whole table again while the last answer is on its way. The end drops the
routes the answer did not repeat. Neighbors without it, or with `GOBGP_OPERA_ENHANCED_REFRESH=off`, are
asked every interval as before. The answer is stale while a withdrawal is still on
its way to that neighbor. `GOBGP_OPERA_REFRESH_DELAY_S` (0 s, the lab compares 1 s) lets the first
request wait for withdrawals elsewhere and brings the path back that much later.
Neighbors without the route refresh capability get soft pruning. *Proof:* holds
for rest and for loop freedom at rest. Loop freedom on the way does not hold, as for every mode.

### Native iBGP

Paths from iBGP peers pass without the import filter, and iBGP withdrawals prune nothing. Route
reflectors work as in RFC 4456 and pass on the export path. *Code:* `FilterIBGP` in `opera.go`,
`GOBGP_OPERA_IBGP=filter` for the paper's code. *Why:* the AS path does not grow inside an AS, so
the filter compares iBGP paths unfairly with paths from other ASes. The paper's code, which filters
them, loops at rest and sends two routes per AS in some networks with reflectors.

*Proof:* outside, simulated. The proof assumes one route per AS. Native iBGP keeps it in every network
searched, at rest without loops. On the way every mode loops, BGP too, while the routers of an AS
learn of a change one after the other. The proof's designated route reflector is not built: native
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
*Proof:* outside, simulated. The proof orders AS sequences only. Aggregates lose nothing in the
search. Confederations lose a route in rare cases and loop on the way less often than with members
left out or with BGP.

### Choice per neighbor

Export filters, Gao-Rexford classes, siblings, partial transit, communities, tags and route leaks
decide which neighbors get the one route. *Proof:* holds, the export rule allows any subset. They cost
reachability, not rest. The worst path may be the one a neighbor must not get, and that neighbor
then gets none. Which choices lose routes in the search: [the table below](#what-the-router-supports).

### A table per neighbor

Off by default, `GOBGP_OPERA_EXPORT=neighbor` turns it on. The router keeps one OBGP table per eBGP
neighbor, fed with the paths its own export policy lets through to that neighbor and with the
neighbor's own paths, which set the threshold but are never sent back. Each table admits, prunes and
asks for route refreshes as the main one does, and the neighbor gets its worst admitted path. A table
built for a neighbor that comes up takes the paths worst first, so that it admits all of them, also
those hard pruning took out of the other tables, as their neighbors still send them. There hard
pruning keeps them aside, never admits them again and drops them once their neighbor sends again.
A policy change asks for route refreshes where a table is left waiting, and a refresh answer
withdraws what the neighbor may no longer get. The router forwards a packet from an eBGP neighbor on
the path it sends that neighbor, as NS-BGP does, and its own packets on its preferred path among those
admitted in any table that are no longer than any of its exports. iBGP peers and route server
clients keep the main table. *Code:*
`opera_neighbor.go` in `internal/pkg/table` and `pkg/server`, `obgp-sim -per-neighbor`, a lab
variant's `per_neighbor: true`.

*Why:* one route per AS is what loses the routes above. A filter by class or by content can forbid
exactly that route. A table per neighbor holds only what that neighbor may get, so a short peer route
no longer keeps a longer customer route out of the table towards a provider. It needs no labels: the
router reads its own export policy, whatever it is built from.

*Why forwarding by ingress:* with one FIB a neighbor's packets follow the router's preferred path, not
the path sent to that neighbor. The bound that keeps one FIB loop-free, no longer than any export, can
rule out the customer route a provider was sent, and the provider's packets then cross a peer link: a
forward valley (`obgp-sim`, kind `forward-valley`), under Gao-Rexford from four routers. By ingress a
packet follows the AS path the router sent, hop by hop: at rest each router sends a path it holds from
its next hop, which sent it exactly the rest of that path. So forwarding is loop-free as AS paths are
and follows the relations as the exports do. The router's own packets join that chain at their next
hop. *Cost:* a FIB per table, shared where the tables are, and tunnels inside an AS, as NS-BGP.
gobgpd installs no FIB, so lab and simulator check forwarding by ingress, as for NS-BGP.

*Proof:* outside, simulated. For BGP, [Neighbor-Specific BGP](https://arxiv.org/abs/0906.3846) (Y. Wang,
M. Schapira, J. Rexford, SIGMETRICS 2009) shows that BGP with a choice per neighbor converges under
conditions such as Gao-Rexford's and allows more policies.

*Cost:* each table holds its own entry for every path it is fed, the attributes stay shared. With n
eBGP neighbors that is up to n² entries per destination. Neighbors whose export policies decided
alike on every path fed so far share one table, under Gao-Rexford the customers. The first path they
differ on copies the table. A table a path brings into the state of another, and a table built for a
neighbor that comes up, joins that one, much as routers group neighbors with the same outbound policy
into update groups. So a
shared table decides exactly as a table of its own. *Proof:* as for tables per neighbor, sharing
changes nothing.
*Code:* `OperaFeedAll`, `operaMerge`, `OperaShare`, tested against tables of their own in every pruning mode.

In the search a table per neighbor loses fewer routes than one table under these choices, in every
pruning mode. No network oscillates, loops at rest or forwards against the relations. Without export
filters a table per neighbor sends as the one table, message by message. With siblings a network of six
routers can lose a route with a table per neighbor too: the table towards a sibling exports its worst
path, a peer path, which the sibling may not pass to its provider.

### NS-BGP as the yardstick

`GOBGP_OPERA_EXPORT=neighbor` with OBGP off runs
[Neighbor-Specific BGP](https://arxiv.org/abs/0906.3846), mode `bgp-pn`. The same tables per neighbor
run BGP's decision, and each neighbor gets the best path of its table. Its own paths and paths through
its AS stay out, as there is no threshold. The router's own choice and its FIB stay the best path of
the main table. iBGP peers and route server clients keep the main table, so iBGP carries each
border router's best path only. *Code:* `opera_neighbor.go`, mode `bgp-pn` of `obgp-sim`, a lab
variant `{mode: bgp, per_neighbor: true}`.

*Why:* OBGP with a table per neighbor answers the same problem as NS-BGP. Both run in the same lab
and simulator, so they compare on the same networks.

*Forwarding:* NS-BGP sends a packet from a neighbor on the route it sent that neighbor, through a
tunnel inside an AS, as its paper does. One FIB cannot. OBGP per neighbor forwards so as well, see
[A table per neighbor](#a-table-per-neighbor). The lab reads next hops, not packets, so lab
and simulator follow each packet together with the neighbor it came from. Inside an AS it goes to the
border router towards the route's next AS, or to the origin if that is in the AS. The controller reads the route sent to each eBGP neighbor from the Adj-RIB-Out and its
next hop from the held path, or from the path as sent where OBGP only set it aside. In a mixed mode the
routers with one table forward on their best route, whoever sent the packet.
*Code:* `walk` in `oracle.go`, `lab/forwarding.py`, `ingress` in `controller/app.py`.

*Proof:* outside. NS-BGP's paper shows that it converges under conditions such as
Gao-Rexford's. In the simulator BAD GADGET built from export filters comes to rest under `bgp-pn`,
the lab's BAD GADGET, built from preferences, does not.

### Prepending

Prepending towards all neighbors and poisoning lengthen the one route alike. *Proof:* holds. Towards
one neighbor, that neighbor sees a different route. *Proof:* outside, simulated, nothing lost.

### Route servers

A route server is transparent: it admits and prunes nothing and passes every path on as plain GoBGP
does, adding no AS and keeping the next hop. With Add-Path (RFC 7911) it sends a client every path that
client's filter allows, the filter before the choice as in RFC 7947, section 2.3.2.1. Without Add-Path
a client gets GoBGP's best path its filter allows. The lab's route servers send Add-Path, which every
router receives, and the lab marks their neighbors with `rsClient: true`. *Code:* `operaSelects` in
`opera.go`, `SetRouteServer` on the route server's tables, `GOBGP_OPERA_RS=admit` for the paper's
code, which admits, exports the worst admitted path, then filters.

*Why:* a route server is no AS. Each client sees every other client's one route as over a direct
session, and the route server needs no rule of its own. Choosing first, a client's filter can reject
exactly the chosen path and leave it without one, and the route server's own admission drops paths
no client would. *Proof:* holds. Without the route server the clients are directly connected ASes,
each with its one route.

Clients that filter on the AS path lose a route in rare cases, with no oscillation and no loop: the
client behind the filter gets only the other client's one route, which may run through the filtered
AS. The paper's code loses more.
`ixp` in `lab-features` plays the smallest such case.

### Additions to GoBGP

- **MRAI:** GoBGP read it but never applied it. `pkg/server/mrai.go` holds back advertisements per
  peer and prefix, per path with Add-Path send. Withdrawals go out at once and drop what waits for
  the prefix. *Proof:* holds, the last message computed is the last one the neighbor gets.
- **Forwarding:** the FIB gets GoBGP's best path, chosen among admitted paths. *Proof:* holds, the
  paper's local preference may choose any admitted path.
- **Fixes:** soft reset out withdraws newly rejected routes, the API marks the best path again, ties
  break by ORIGINATOR_ID and the shorter CLUSTER_LIST (RFC 4456), and a looped update withdraws the
  peer's route before (RFC 4271).
- **Withdrawals between reflectors:** when a new best route may not go to an iBGP neighbor, GoBGP
  withdrew the old one only if it was local or from eBGP. A reflector whose client's route went away
  kept it at the other reflector, which kept its copy in turn: a route that no longer existed, in
  Abilene until the link came back. The old route is now withdrawn whenever it was sent.
  *Proof:* outside, iBGP is outside the model.
- **Reflection between reflectors:** GoBGP set ORIGINATOR_ID and CLUSTER_LIST only towards clients
  and stripped them towards other reflectors. A client then got its own route back as someone
  else's, and with the withdrawal above each reflector preferred the other's copy, by router ID, so
  they took turns withdrawing. A client's route now carries both towards every iBGP neighbor (RFC
  4456, 8 and 9). *Proof:* outside, as above. With both changes Abilene passed every check
  in the lab.
- **Log level warn:** `-l warn` logs only warnings and errors, where GoBGP knew only info and debug.
  The lab starts gobgpd so: a line per session change of hundreds of routers burdened the node.
  *Proof:* holds, it changes no decision.

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
proof of rest and of loop freedom at rest covers the feature, see the decisions above, *simulated* for
outside but backed by the simulator. It says nothing
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
| Route leaks | limited | holds | some losses, fewer with a table per neighbor, with one table packets against the relations in rare cases |
| Other address families, e.g. VPN or EVPN | no | – | they run as plain GoBGP |
| Add-Path export | no | – | OBGP sends one path per destination |

## Where the modes differ

Networks that lose a route, for iBGP networks that loop or where an AS sends different paths:

| | `obgp-rp` | `obgp-hp` | `obgp-np` | `obgp-paper` |
|---|---|---|---|---|
| Import filter of the own router | none | some | none | some |
| Export filter towards one neighbor | none | some | none | some |
| Confederations | rare | more | more | more |
| Route servers, clients filtering on the AS path | rare | rare | rare | more |
| iBGP, loops and ASes sending different paths | none | none | none | some |

`obgp-sp` loses what `obgp-rp` loses. Native iBGP prunes nothing on withdrawals over iBGP, which only
say that a router's export path changed.
