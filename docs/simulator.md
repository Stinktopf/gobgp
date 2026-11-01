# Simulator

`obgp-sim` plays one prefix on every connected network up to five routers, with gobgpd's own
decision code. For every family of policies and three message orders it compares each mode with BGP,
and finds where a mode loses a route, loops or never comes to rest. Six routers would take days.

What it found: [DESIGN.md](../DESIGN.md#what-the-router-supports). Its limits: no timers, one prefix,
small networks, see [Threats to validity](evaluation.md#threats-to-validity).

## In the web UI

- **Search:** the Simulation area starts one with a button. It waits in the lab's queue and needs no cluster.
- **Problems:** grouped by kind, each with the modes that show it, its cause and its networks.
- **Case:** one network played message by message, with every router's table and where its packets go.
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
| `-workers` | processes that search at once, by default half the cores and at most 32 |
| `-instance <file> -trace <mode>` | plays one example message by message, with `-json` for the web UI |

| Lab command | Does |
|---|---|
| `lab simulate search` | a search from the command line, shown in the Simulation area |
| `lab simulate predict` | what a topology and scenario should show |
| `lab simulate compare <result>` | where a result shows what the simulator rules out |
| `lab simulate export` | findings as topologies and scenarios |
| `lab simulate fuzz` | fuzzing in Go's Docker image, for servers without Go |

GoBGP compares no IGP costs: between iBGP paths of the same length the router ID decides.
