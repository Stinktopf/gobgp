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
| `GOBGP_OPERA_ENHANCED_REFRESH` | Enhanced Route Refresh (RFC 7313) offered | `on` | `off` | `off` |

With OBGP on, the router offers Enhanced Route Refresh (RFC 7313). Where a neighbor offers it too, the
router asks it again only once the last answer has ended, or after 5 minutes without its end, and drops
the routes that answer did not repeat. Its answers then go out at once, also with an MRAI.

## Modes

Lab and simulator name combinations of these settings as modes.

| Mode | Routers run |
|---|---|
| `bgp` | GoBGP's standard selection |
| `obgp-rp` | OBGP with the defaults, refresh pruning |
| `obgp-sp`, `obgp-hp`, `obgp-np` | the same with soft, hard or no pruning |
| `obgp-rp-pn`, `obgp-sp-pn`, `obgp-hp-pn`, `obgp-np-pn` | the same with a table per eBGP neighbor, forwarding per ingress |
| `obgp-paper` | every setting as in the IFIP Networking 2026 paper, one table |
| `bgp-pn` | NS-BGP: BGP with a table per eBGP neighbor, forwarding per ingress |
| `hybrid-…`, `random-…` | one of these on some routers, BGP on the others |

In an experiment a table per neighbor is a flag: `{mode: obgp-rp, per_neighbor: true}` is `obgp-rp-pn`,
`{mode: bgp, per_neighbor: true}` is `bgp-pn`. The simulator takes `-per-neighbor`, and `bgp-pn` as a mode.

## Limitations

Every OBGP mode:

- **Order:** which paths are admitted depends on the order they arrive in.
- **Local Preference:** it chooses only among admitted paths.
- **Tags on the way:** the export path can carry a tag the best path has not. A table per neighbor (`-pn`) loses
  fewer routes.
- **Loops on the way:** forwarding can loop until routes come to rest, BGP too. The simulator finds it in fewer
  networks than with BGP in most families, see [DESIGN.md](../DESIGN.md#native-ibgp).
- **GoBGP's tests:** four server tests fail by design, as they count candidate paths.

Some modes:

- **One export path** (one table): a neighbor that may not get it gets none. With `-pn` it gets the worst path it
  may get.
- **Gao-Rexford** (one table): paths rank by length, not by class, so a router can lose routes for its providers.
  With `-pn` none up to five routers, except with route leaks. With siblings a network of six routers can lose one, see [DESIGN.md](../DESIGN.md#a-table-per-neighbor).
- **Forwarding per ingress** (`-pn`): packets from a neighbor follow the path sent to it, as with NS-BGP. That needs
  a FIB per table and tunnels inside an AS, which gobgpd does not install: lab and simulator check forwarding so.
  With one FIB the packets of a provider could cross a peer link. With one table the simulator finds that only
  with route leaks.
- **Confederations:** gobgpd compares no IGP costs, so OBGP loses a route in rare cases.

Per feature and policy, and where the pruning modes differ: [DESIGN.md](../DESIGN.md#what-the-router-supports).
