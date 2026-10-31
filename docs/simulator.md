# Simulator

Its tests need `-tags obgpsim` and stay out of CI.

```bash
go run ./cmd/obgp-sim -routers 5 -out examples.json
go test -tags obgpsim -run '^$' -fuzz FuzzInModel ./internal/pkg/obgpsim/
uv run lab simulate fuzz --target FuzzSoft --hours 4
```

- **`-out`:** the smallest example of each deviation per number of routers, so that a larger network shows beside the smallest.
- **`-transient`:** also tells the way to rest apart: forwarding loops, routers blocked waiting for a route refresh, and routers without a route for a while.
- **`-tunnel`:** forwards inside an AS over tunnels to the exit, as MPLS, instead of hop by hop.
- **`-per-neighbor`:** OBGP with a table per eBGP neighbor, as `GOBGP_OPERA_EXPORT=neighbor`.
- **`-progress`:** reports how far a search is on stderr, which the lab shows.
- **`-instance <file> -trace <mode>`:** plays one example message by message, with `-json` every step with each router's tables, for the lab's Simulation.
- **`lab simulate fuzz`:** runs in Go's Docker image at low priority, for servers without Go.
- **`lab simulate predict`:** what a topology and scenario should show.
- **`lab simulate compare <result>`:** where a result shows what the simulator rules out.
- **`lab simulate export`:** findings as topologies and scenarios.
- **`lab simulate search`:** a search run at once from the command line, kept beside those of the Simulation area, which replays its findings step by step.
