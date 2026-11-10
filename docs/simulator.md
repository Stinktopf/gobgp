# Simulator

`obgp-sim` plays one prefix on every connected network up to five routers, at five once per graph, with
gobgpd's own decision code. For every family of policies and 20 message orders it compares each mode with BGP,
and finds where a mode loses a route, loops or never comes to rest. Six routers would take days.

## What it shares with gobgpd

- **Shared:** the table package. Route selection, the route a router offers its neighbors, OBGP's
  admission, pruning and tables per neighbor, NS-BGP, a route server's choice in `obgp-paper`.
- **Modelled:** export and import policies, communities, iBGP and route reflection, confederations,
  route refresh, a route server passing every path with Add-Path, after the configuration the lab generates. Sessions are reliable queues without
  timers. A fault in the shared code shows in the lab and the simulator alike, a comparison of the two
  cannot find it.

## What a search covers

- **Networks:** up to four routers every connected graph in every numbering of the routers, at five one
  graph per shape, router 0 the origin. Numbers matter: they are AS numbers and router IDs.
- **Policies:** Gao-Rexford relations, local preferences (default or 200), IGP costs and MEDs in every
  assignment up to 4,096 per network, Gao-Rexford relations all of them up to five routers, 1,000 distinct
  ones drawn beyond, e.g. local preferences on dense networks of five routers. The other families place
  one policy at a time: a filter, a prepend, a tag, a leaker, a provider giving partial transit.
- **Orders:** 20 per network, drawn by seed. A deviation counts once per network, and each case says in
  how many orders it showed.
- **No rest:** a run without rest that returns to an earlier state, every session with messages served
  and a second passed, has an order without end: repeating it never rests. A run stops at 20,000
  messages otherwise and is undecided. The state compares times by their order and path IDs as names.
  It is looked for after every message from the 500th to the 1,000th, then after every eighth, not above
  12 routers and not once the state grows past 64 KiB. Counts on the way to rest stop with the cycle and
  differ from searches before November 2026.

What it found: [DESIGN.md](../DESIGN.md#what-the-router-supports). Its limits: no timers, one prefix,
small networks, see [Threats to validity](evaluation.md#threats-to-validity).

## Lab steps in the simulator

A topology and scenario of the lab become instances of the simulator, one per origin and per life of a
prefix: held, withdrawn, expired after a step, copied by `originate`. A lifetime runs only while an
`announce` step at the origin lasts, as the runner pauses the announcer after it. Targets are those the
runner chooses, random ones by the run's seed. A step right after `until_stable` comes once the network
is quiet, where it never is after a share of the messages, as the runner goes on after the timeout. Any
other step comes at any point among the messages. Not mapped, and named as such:

- graceful restarts, and silent failures and restarts in experiments with graceful restart on
- mixed modes of OBGP and BGP
- iBGP other than a full mesh or route reflectors with all others as clients, an iBGP session going down
- a route server with neighbors that are not its clients
- `degrade` with full loss or delays at or above the limit, more specific copies
- announcements from routers other than the origins, a later announcement with another `AS_SET`, poison or communities
- prefixes of the Internet: `announce_real`, `announce_rib`, `withdraw_rib`, `replay`

`degrade` below the limit, `wait` and `soft_reset` map to nothing: some order covers them. An MRAI
maps, but the simulator has no timers. The mapping in detail: `lab/simulate.py`.

Where a finished run contradicts the prediction, at rest where the simulator never rested or without
rest where it always did, the simulator plays that cell in 1,000 orders, the 20 among them, before the
run counts as unforeseen. `lab simulate again` and `predict_again` do the same.

## In the web UI

- **Search:** the Simulation area starts one with a button. It waits in the lab's queue and needs no cluster.
- **Problems:** grouped by kind, each with the modes that show it, its cause and its networks.
- **Case:** one network played message by message, with every router's table and where its packets go.
  It plays also while an experiment runs, one case at a time, at the lowest priority.
- **Play in the lab:** makes the case an experiment of every mode, with the simulator's prediction as checks.

Searches are kept in `~/.config/obgp-lab/simulation`, also after teardown.

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
| `-per-neighbor` | OBGP with a table per eBGP neighbor |
| `-workers` | processes that search at once, by default half the cores and at most 32, from the lab every CPU it may use but two |
| `-instance <file> -trace <mode>` | plays one example message by message, with `-json` for the web UI |

| Lab command | Does |
|---|---|
| `lab simulate search` | a search from the command line, shown in the Simulation area |
| `lab simulate predict` | what a topology and scenario should show |
| `lab simulate compare <result>` | where a result shows what the simulator rules out |
| `lab simulate agree <result>` | per cell and variant: never, sometimes or always without rest on each side, the lab's share with its exact interval, the contradictions at an extreme (also MCP `agreement`) |
| `lab simulate export` | findings as topologies and scenarios |
| `lab simulate fuzz` | fuzzing in Go's Docker image, for servers without Go |
