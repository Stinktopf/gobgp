# Simulator

`obgp-sim` plays one prefix on every connected network up to five routers with gobgpd's own decision code.
It compares each mode with BGP and finds where a mode loses a route, loops, forwards against the relations or
never comes to rest. Six routers would take days.

## What it shares with gobgpd

- **Shared:** the table package. Route selection, the route a router offers its neighbors, OBGP's
  admission, pruning and tables per neighbor, NS-BGP, a route server's choice in `obgp-paper`.
  In a mixed mode each router decides with the settings of its own mode, as each router of the lab is a
  gobgpd of its own.
- **Modelled:** export and import policies, communities, iBGP and route reflection, confederations, route
  refresh, a route server passing every path with Add-Path, after the configuration the lab generates.
  Sessions are reliable queues without timers.

## What a search covers

- **Networks:** up to four routers every connected graph in every numbering of the routers, at five one
  graph per shape, router 0 the origin. Numbers matter: they are AS numbers and router IDs.
- **Policies:** Gao-Rexford relations, local preferences (default or 200), IGP costs and MEDs in every
  assignment up to 4,096 per network, Gao-Rexford relations all of them up to five routers, 1,000 distinct
  ones drawn beyond, e.g. local preferences on dense networks of five routers. The other families place
  one policy at a time: a filter, a prepend, a tag, a leaker, a provider giving partial transit.
- **Orders:** 20 per network, drawn by seed. A deviation counts once per network, and each case says in
  how many orders it showed.
- **Forwarding at rest:** the packets of each router go hop by hop: a loop, a black hole and, with
  relations, a forward valley, packets against the relations although the router's path follows them.
- **No rest:** a run without rest that returns to an earlier state, every session with messages served
  and a second passed, has an order without end: repeating it never rests. A run stops at 20,000
  messages otherwise and is undecided. Two states are the same where their times have the same order and their path IDs match up to renaming.
  It is looked for after every message from the 500th to the 1,000th, then after every eighth, not above
  12 routers and not once the state grows past 64 KiB. Counts on the way to rest stop with the cycle and
  differ from searches before November 2026.

What it found: [DESIGN.md](../DESIGN.md#what-the-router-supports). Its limits: no timers, one prefix,
small networks, see [Threats to validity](evaluation.md#threats-to-validity).

## Lab steps in the simulator

A topology and scenario of the lab become instances of the simulator, one per origin and per life of a
prefix: held, withdrawn, expired after a step, copied by `originate`. A lifetime runs only while an
`announce` step at the origin lasts, as the runner pauses the announcer after it. Targets are those the
runner chooses, random ones by the run's seed. A step right after `until_stable` comes once the network is
quiet. Where it never gets quiet, the step comes after a share of the messages, as the runner goes on after
the timeout. Any other
step comes at any point among the messages. The links of one step change in any order, as the sessions that
come back after a restart. Of the steps of a `parallel`, the first that sends comes at the moment of the
step, the others at any point among its messages, in any order where each changes one thing. A `restart`
starts the router with a fresh table and takes all its sessions down at once. A mixed variant plays with the
mode of each router as the runner deploys it: hybrids on the routers the topology marks, random ones on the
routers drawn with the run's seed, so every run has a prediction of its own. Not mapped, and named as such:

- a silent failure with graceful restart whose stale routes may expire before or after a later step, or after the last
- iBGP other than a full mesh or route reflectors with all others as clients, an iBGP session going down
- a route server with neighbors that are not its clients
- `degrade` with full loss or delays at or above the limit, more specific copies
- announcements from routers other than the origins, a later announcement with another `AS_SET`, poison or communities
- prefixes of the Internet: `announce_real`, `announce_rib`, `withdraw_rib`, `replay`

With graceful restart on, a graceful `restart` and a silent failure (`down` with `cut` or `oneway`) keep the
routes stale, as gobgpd's: a restarting router starts empty and sends its routes once it has the End-of-RIB of
every peer, its peers keep its routes until its own End-of-RIB removes those it did not send again. After a
silent failure the ends that find it by their hold timer keep the routes, `oneway` only the end that drops the
packets. They expire where the steps' times show that the restart time, the larger of 30 s and the hold time, ends before the link is
back. A router that restarts is back before it ends.

`degrade` below the limit, `wait` and `soft_reset` map to nothing: some order covers them. An MRAI maps
to coalescing, not to a timer: an update that still waits on a session to another AS gives way to a newer
update or a withdrawal of the same path ID, as gobgpd's MRAI drops a held advertisement. The newer message
goes behind all others on the session, as in gobgpd's order of held advertisements. An update gobgpd sends
at once, as the first of its interval, gives way here too, and a withdrawal waits behind the updates of
other path IDs, which gobgpd sends at once. The mapping in detail: `lab/simulate.py`.

Where a run contradicts the prediction, the simulator plays that cell in 1,000 orders, see
[Problems](evaluation.md#problems). `lab simulate again` and `predict_again` do the same. Simulator and lab
compare on rest alike: at every step that waits for it and at the end.

## In the web UI

- **Search:** the Simulation area starts one with a button. It waits in the lab's queue and needs no cluster.
- **Problems:** grouped by kind, each with the modes that show it, its cause and its networks.
- **Case:** one network played step by step on a map.
  It plays also while an experiment runs, one case at a time, at the lowest priority.
- **Play in the lab:** makes the case an experiment of every mode, with the simulator's prediction as checks.

Searches are in `~/.config/obgp-lab/simulation/searches`.

## Command line

Its tests need `-tags obgpsim` and stay out of CI.

```bash
go run ./cmd/obgp-sim -routers 5 -out examples.json
go test -tags obgpsim -run '^$' -fuzz FuzzInModel ./internal/pkg/obgpsim/
uv run lab simulate fuzz --target FuzzSoft --hours 4
```

| Option | Does |
|---|---|
| `-out` | keeps the smallest example of each deviation per number of routers |
| `-transient` | also checks the way to rest: loops, blocked routers, routers without a route |
| `-tunnel` | forwards inside an AS over tunnels to the exit, as MPLS |
| `-routers`, `-seeds`, `-family` | the largest network, the orders per network, one family only |
| `-per-neighbor` | OBGP with a table per eBGP neighbor |
| `-both-tables` | OBGP with one table and, named `-pn`, with a table per neighbor, in one pass |
| `-workers` | processes that search at once, by default half the cores and at most 32, from the lab every CPU it may use but two |
| `-instance <file> -trace <mode>` | plays one example message by message, with `-json` for the web UI |
| `-instance <file> -modes <list>` | plays only these modes and BGP, a mixed mode by its name in the instance |

| Lab command | Does |
|---|---|
| `lab simulate search` | a search from the command line, shown in the Simulation area, `--tables` as above |
| `lab simulate predict` | what a topology and scenario should show, `--tables` also with a table per neighbor |
| `lab simulate again <result>` | judges a finished result against a new prediction, as MCP `predict_again` |
| `lab simulate compare <result>` | where a result shows what the simulator rules out |
| `lab simulate agree <result>` | per cell and variant: never, sometimes or always without rest on each side, and the same for each deviation at rest, the lab's share with its exact interval, the contradictions at an extreme (also MCP `agreement`) |
| `lab simulate export` | findings as topologies and scenarios |
| `lab simulate fuzz` | fuzzing in Go's Docker image, for servers without Go |
