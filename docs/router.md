# Router

gobgpd with OBGP. Without `GOBGP_OPERA_ENABLED` it is plain GoBGP.

```bash
go build -o . ./cmd/gobgpd ./cmd/gobgp
GOBGP_OPERA_ENABLED=true ./gobgpd -f gobgpd.conf
```

Configuration and CLI are [GoBGP's](sources/getting-started.md). The code is in
[`opera.go`](../internal/pkg/table/opera.go), each decision in [DESIGN.md](../DESIGN.md).

## Settings

| Variable | Sets | Default | Other | The paper's |
|---|---|---|---|---|
| `GOBGP_OPERA_PRUNING` | how pruned paths come back | `refresh` | `soft`, `hard`, `off` | `hard` |
| `GOBGP_OPERA_REFRESH_S` | seconds between refreshes to one neighbor | `1` | | |
| `GOBGP_OPERA_REFRESH_DELAY_S` | seconds the first refresh waits | `0` | | |
| `GOBGP_OPERA_IBGP` | how iBGP paths are admitted | `native` | `filter` | `filter` |
| `GOBGP_OPERA_AS_SET` | the order inside an `AS_SET` | `canonical` | `received` | `received` |
| `GOBGP_OPERA_CONFED` | confederation hops in the order | `count` | `ignore` | `ignore` |
| `GOBGP_OPERA_RS` | what a route server does | `transparent` | `admit` | `admit` |
| `GOBGP_OPERA_EXPORT` | tables for the export | `one` | `neighbor` | `one` |

## Modes

Lab and simulator name combinations of these settings as modes.

| Mode | Routers run |
|---|---|
| `bgp` | GoBGP's standard selection |
| `obgp-rp` | OBGP with the defaults, refresh pruning |
| `obgp-sp`, `obgp-hp`, `obgp-np` | the same with soft, hard or no pruning |
| `obgp-rp-pn`, `obgp-sp-pn`, `obgp-hp-pn`, `obgp-np-pn` | the same with a table per eBGP neighbor |
| `obgp-paper` | every setting as in the paper |
| `bgp-pn` | NS-BGP: BGP with a table per eBGP neighbor, forwarding per ingress |
| `hybrid-…`, `random-…` | one of these on some routers, BGP on the others |

In an experiment a table per neighbor is a flag: `{mode: obgp-rp, per_neighbor: true}` is `obgp-rp-pn`,
`{mode: bgp, per_neighbor: true}` is `bgp-pn`. The simulator takes `-per-neighbor`, and `bgp-pn` as a mode.

## Limitations

- **One export path:** a neighbor that may not get it gets none. A table per neighbor gives it the worst path it may get.
- **Tags on the way:** the export path can carry a tag the best path has not.
- **Gao-Rexford:** paths rank by length, not by class, so a router can lose routes for its providers. A table per neighbor loses fewer.
- **Order:** which paths are admitted depends on the order they arrive in.
- **Local Preference:** it chooses only among admitted paths.
- **Loops on the way:** forwarding can loop until routes settle, less often than with BGP.
- **Confederations:** gobgpd does not compare IGP costs, so OBGP loses a route in rare cases.
- **GoBGP's tests:** four server tests fail by design, as they count candidate paths.

Per feature and policy: [DESIGN.md](../DESIGN.md#what-the-router-supports).
