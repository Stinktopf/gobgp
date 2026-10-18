<p align="center">
  <picture>
    <source srcset="assets/logo-router-dark.png" media="(prefers-color-scheme: dark)">
    <img src="assets/logo-router-light.png" alt="OBGP Router" width="336">
  </picture>
</p>

<p align="center"><b>An oscillation-free BGP router based on <a href="https://github.com/osrg/gobgp">GoBGP</a>,<br>
and the lab that measures it.</b></p>

<p align="center">
<a href="https://doi.org/10.23919/IFIPNetworking70592.2026.11578986">IFIP Networking 2026</a> ·
<a href="https://opendl.ifip-tc6.org/db/conf/networking/networking2026/1571247489.pdf">Paper</a> ·
<a href="vis">Figures</a> ·
<a href="results/public/ifip-networking-2026">Data</a>
</p>

Preference cycles make BGP oscillate. OBGP ([LCN 2022](https://doi.org/10.1109/LCN53696.2022.9843706),
[ICC 2022](https://doi.org/10.1109/ICC45855.2022.9839159)) orders route import and export
strictly, so it cannot. BGP messages are unchanged, so OBGP works with any BGP speaker.

This repository holds three parts:

- **Router:** gobgpd with OBGP, every part switchable back to the paper's code.
- **Lab:** BGP and OBGP on real routers in minikube, from topology to statistics, in a web UI.
- **Simulator:** gobgpd's decision code on every small network, to find where OBGP deviates from BGP.

## How it works

Paths are ordered by AS path length, ties broken by ASN.

- **Import:** a path is admitted only if it is better than the worst admitted one.
- **Export:** peers get the worst admitted path, so a better one never changes what they see.
- **Re-admission:** rejected paths come back once no valid path is left.
- **Pruning:** a withdrawn or changed path sets aside the paths containing its old AS sequence.
- **iBGP:** paths from the own AS skip the import filter but count for the threshold, so it holds
  for the whole AS.
- **Forwarding:** the FIB gets GoBGP's usual best path, loop-free once routes settle since the
  export path length decreases along every hop. While they settle, see [DESIGN.md](DESIGN.md).

## Results

On `germany50`, `BAD GADGET` and `noble-eu`, BGP oscillated indefinitely in both cyclic topologies
and OBGP converged. OBGP admitted 27–51 % fewer paths on average, and `noble-eu` drained in about
3 s instead of 29–42 s. These runs had no MRAI.

## What the OBGP router supports

**Yes** works as with BGP, **limited** loses routes in rare cases. Numbers count the networks where
OBGP as built (`obgp-rp`) loses a route, of every connected topology up to five routers with three
message orders each. The simulator plays them exactly, they are counterexamples, not samples.
**Proof** tells whether the proof of loop freedom and stability covers it, why is in
[DESIGN.md](DESIGN.md).

| Feature | OBGP | Proof | |
|---|---|---|---|
| Local Preference, e.g. BAD GADGET | yes | holds | converges where BGP oscillates, in 1,428 of 46,260 |
| Import filters, route origin validation | yes | holds | none, hard pruning loses 3,065 of 25,764 |
| Export filters towards one neighbor | yes | holds | none, hard pruning loses 3,065 of 51,528 |
| Prepending towards all neighbors | yes | holds | the same longer path for all, a step of the lab |
| Prepending towards one neighbor | yes | simulated | none of 51,528 |
| AS path poisoning | yes | holds | none of 9,105 |
| Communities of the origin: no-export, not to one AS | yes | holds | none of 11,418 |
| Aggregates with an `AS_SET` | yes | simulated | none of 15,195 |
| Link and session failures, withdrawals | yes | holds | none |
| iBGP in a full mesh or through route reflectors, MED | yes | simulated | at rest no loop and one path per AS in 76,605, loops on the way see below |
| Graceful restart, soft reset, MRAI | yes | holds | steps of the lab, MRAI applied since this fork |
| IPv4 and IPv6 unicast, 4-byte ASNs | yes | holds | IPv6 and 2-byte speakers in unit tests |
| Multipath | yes | holds | over admitted paths only |
| Confederations | limited | simulated | 9 of 91,026 (0.01 %) |
| Export filters on the AS path | limited | holds | 210 of 76,302 (0.3 %) |
| Route servers, clients filtering on the AS path | limited | holds | 206 of 62,406 (0.3 %) |
| Communities tagged on the way, e.g. not to one AS | limited | holds | 770 of 102,066 (0.8 %), see below |
| Gao-Rexford relations | limited | holds | 7,927 of 413,310 (1.9 %), see below |
| Gao-Rexford with partial transit | limited | holds | 7,927 of 412,140 (1.9 %), as without |
| Route leaks | limited | holds | 42,222 of 1,643,940 (2.6 %), as Gao-Rexford, and 35 % fewer routers on a leaked path than BGP |
| Gao-Rexford with siblings | limited | holds | 17,151 of 412,140 (4.2 %) |
| Other address families, e.g. VPN or EVPN | no | – | they run as plain GoBGP |
| Add-Path export | no | – | OBGP sends one path per destination |

## Usage

```bash
go build -o . ./cmd/gobgpd ./cmd/gobgp
GOBGP_OPERA_ENABLED=true ./gobgpd -f gobgpd.conf
```

Without the variable the daemon is plain GoBGP. The code is in [`opera.go`](internal/pkg/table/opera.go),
configuration and CLI are [GoBGP's](docs/sources/getting-started.md). Each variable switches one part
back to the paper's code:

| Variable | Default | The paper's | Also |
|---|---|---|---|
| `GOBGP_OPERA_PRUNING` | `refresh`: pruned paths wait, come back by route refresh when no other is left | `hard`: removed | `soft`: come back at once, `off` |
| `GOBGP_OPERA_REFRESH_S` | `1`: seconds between route refreshes to one neighbor | | |
| `GOBGP_OPERA_REFRESH_DELAY_S` | `0`: seconds the first route refresh to a neighbor waits | | |
| `GOBGP_OPERA_IBGP` | `native` | `filter` | |
| `GOBGP_OPERA_AS_SET` | `canonical` | `received` | |

Lab and simulator name the same modes: `obgp-rp` as built, `obgp-sp`, `obgp-hp` and `obgp-np` with
soft, hard or no pruning, `obgp-paper` as in the paper. `hybrid-…` runs a mode on the routers a topology
marks and `random-…` on a share drawn for every run, BGP on the others. The experiments of the lab run
`bgp`, every OBGP mode and `obgp-rp` with a refresh delay of 1 s, the semantics ones also `hybrid-rp`
and `random-rp`. Calibration and sampling run `bgp` and `obgp-rp`, the paper's runs `bgp` and `obgp-paper`.

## Lab

<p align="center">
  <picture>
    <source srcset="assets/readme/process-dark.svg" media="(prefers-color-scheme: dark)">
    <img src="assets/readme/process-light.svg" alt="Topologies, scenarios, experiments, results, wrapped" width="980">
  </picture>
</p>

The lab runs BGP and OBGP in minikube, one pod per router, with every feature of the table above.

- **Topologies:** draw them in the editor, import them from [SNDlib](https://sndlib.put.poznan.pl) or
  [CAIDA](https://www.caida.org/catalog/datasets/as-relationships/) with siblings from its organizations,
  or generate them (Erdős–Rényi, Watts–Strogatz, Barabási–Albert, Waxman, Elmokashfi). Customers,
  peers, providers, siblings and partial transit, several routers per AS, confederations, IGP costs,
  MED and tags.
- **Scenarios:** steps that announce, also with communities, an `AS_SET` or poisoned ASes, withdraw,
  fail and degrade links and routers, change policies, and check reachability, forwarding without
  loops and one path per AS.
- **Internet data:** full IPv4 tables of the Default-Free Zone and replays of updates from
  [RIPE RIS](https://ris.ripe.net).
- **Experiments:** one per question below. Paired runs share their seeds and alternate which protocol
  runs first, Wilcoxon signed-rank tests and Hodges–Lehmann estimates give confidence intervals. A
  variant may sample at its own rate. Each result keeps its inputs, seeds and software versions.
- **Web UI:** groups with drag and drop, live views and replays of runs, a queue that waits for
  Docker, an idle GPU and free disk, comparisons of results, Wrapped, and Discord notifications.
- **Simulator:** `lab simulate predict` tells what a run should show, `lab simulate compare` holds a
  result against it, `lab simulate export` turns the simulator's findings into topologies and scenarios.

| Question | Experiment |
|---|---|
| Does OBGP converge where BGP oscillates, in every mode? | [`behaviour-oscillation`](experiments/behaviour-oscillation.yaml) |
| Does it still converge, and how fast, with an MRAI of 30 s? | [`behaviour-mrai`](experiments/behaviour-mrai.yaml) |
| Does it admit fewer paths and drain faster? | [`ifip-networking-2026`](experiments/ifip-networking-2026.yaml) |
| Does it stay stable under failures? | [`behaviour-failures`](experiments/behaviour-failures.yaml) |
| Do Gao-Rexford policies hold, also in partial deployment? | [`semantics-gao-rexford`](experiments/semantics-gao-rexford.yaml) |
| Does it keep BGP's semantics in the cases of the Go tests? | [`semantics-adversarial`](experiments/semantics-adversarial.yaml) |
| Where does it fail outside its model or inside an AS? | [`semantics-limits`](experiments/semantics-limits.yaml) |
| Does it scale to 256 networks of the Internet's core, and to full tables? | [`internet-scale`](experiments/internet-scale.yaml), [`internet-dfz`](experiments/internet-dfz.yaml) |
| Does the lab work? | [`lab-smoke`](experiments/lab-smoke.yaml), [`lab-features`](experiments/lab-features.yaml) |
| Does the lab measure right? | [`lab-calibration`](experiments/lab-calibration.yaml), [`lab-sampling`](experiments/lab-sampling.yaml) |

### Running it

On a Linux laptop or server:

```bash
git clone https://github.com/Stinktopf/gobgp.git && cd gobgp/scripts && ./setup.sh
```

Setup asks for resources, HTTPS and a password. Open the printed URL and try **lab-smoke**.

| Action | Command |
|---|---|
| Repair installation | `./setup.sh` |
| Install as a guest on a shared server, never sudo | `./setup.sh --no-sudo` |
| Reconfigure or reset password | `./reconfigure.sh` |
| Update and restart the web UI | `./update.sh` |
| Switch to a branch on GitHub, default without a name | `./update.sh --branch [name]` |
| Start | `./start.sh` |
| Stop cluster and web UI | `./stop.sh` |
| Remove runtime, keep results | `./teardown.sh` |
| Remove recorded installation changes | `./uninstall.sh` |

A crontab line starts the web UI again after a reboot or crash, at most three times an hour. Stop
keeps it off until Start. Updates come from GitHub, also from another branch.
Teardown keeps settings, uninstall removes what setup installed and nothing else. Add `--purge` to
either to delete private results.

<details>
<summary>Remote access</summary>

HTTPS: use the server's hostname or IP and the printed port. The self-signed certificate triggers a
browser warning.

HTTP: run this on your computer and keep it open, then open <http://localhost:8443>:

```bash
ssh -N -L 8443:127.0.0.1:8443 USER@SERVER
```

</details>

<details>
<summary>Windows with WSL</summary>

Docker Desktop must run, with WSL integration on for the distribution. So that WSL gives freed memory
back to Windows, run this in PowerShell once, then start Docker Desktop again. If `.wslconfig`
exists, add the line under `[experimental]` instead.

```powershell
Set-Content -Path "$env:USERPROFILE\.wslconfig" -Value "[experimental]`r`nautoMemoryReclaim=gradual"
wsl --shutdown
```

</details>

## Simulation

A simulator plays one prefix between routers that run gobgpd's decision code, in the lab's modes,
messages in random order. It searches every policy family on every connected topology up to a size
for networks where a mode deviates from BGP, and fuzzes larger ones. It does not model timers. Its
tests need `-tags obgpsim` and stay out of CI.

```bash
go run ./cmd/obgp-sim -routers 5 -out examples.json
go test -tags obgpsim -run '^$' -fuzz FuzzInModel ./internal/pkg/obgpsim/
uv run lab simulate fuzz --target FuzzSoft --hours 4
```

`-transient` also counts forwarding loops on the way. `-instance <file> -trace <mode>` plays one example
message by message, with the path and next hop of every router after each. `lab simulate fuzz` runs in
Go's Docker image at low priority, for servers without Go. `lab simulate predict` tells what a topology
and scenario of the lab should show, `lab simulate compare <result>` names where the lab's runs show
what the simulator rules out, `lab simulate export` turns findings into both.

Where the modes differ, networks that lose a route, or for iBGP that loop or send different paths:

| | `obgp-rp` | `obgp-hp` | `obgp-np` | `obgp-paper` |
|---|---|---|---|---|
| Import filter of the own router | none | 3,065 of 25,764 | none | 3,065 |
| Export filter towards one neighbor | none | 3,065 of 51,528 | none | 3,065 |
| Confederations | 9 of 91,026 | 11,311 | 326 | 2,811 |
| iBGP, loops and ASes sending different paths | none of 76,605 | none | none | 143 and 1,365 |

`obgp-sp` loses what `obgp-rp` loses. Native iBGP prunes nothing on withdrawals over iBGP, which only
say that a router's export path changed.

## Changes since the paper

BGP messages are unchanged. `obgp-paper` keeps the paper's behaviour wherever a switch exists. Every
change, why it was made and whether the proof still covers it: [DESIGN.md](DESIGN.md).

## Limitations

- **One export path:** all neighbors get the same path. A neighbor that may not get it gets none, also
  when it may get another one. Gao-Rexford classes and filters by neighbor are handled, tags on the
  way are not: the export path can carry a tag the best path has not.
- **Gao-Rexford:** paths rank by length, not by the class of the neighbor. A router that admits a peer's
  short route first rejects its customer's longer one and has none for its providers. This depends
  on the message order. The smallest case has four routers (`gao-rexford` in `obgp-sim`).
- **Order:** admission depends on the order paths arrive in. Local Preference chooses only among
  admitted paths.
- **Loops on the way:** with refresh pruning, forwarding can loop until routes settle, far less often
  than with BGP. Hard pruning loops about as rarely, soft pruning about as often as BGP. Local
  Preference, leaks and prepending never make OBGP loop, they make BGP loop in 93 of 31,632 up to four
  routers. Inside an AS every mode loops on the way: through route reflectors in 175 of 31,734
  networks, BGP in 119, with a MED in 353, BGP in 430.
- **Confederations:** gobgpd does not compare IGP costs, so two members can each prefer the path
  through the other, and OBGP loses a route in rare cases.
- **Lab:** native iBGP and the features since the paper are checked in the simulator and in
  `lab-features`, their experiments are yet to run. All routers share one host, results warn where
  routers sampled too seldom. CAIDA infers relations from paths and gets some wrong.
- **Tests:** four GoBGP server tests fail by design with OBGP, since they count candidate paths.

## Citation

```bibtex
@inproceedings{nickel2026obgp,
  author    = {Nickel, Lucas Immanuel and Rieger, Sebastian and Moghaddassian, Morteza and Garcia-Luna-Aceves, J. J.},
  title     = {Making {BGP-4} More Efficient and Oscillation-Free},
  booktitle = {2026 IFIP Networking Conference (IFIP Networking)},
  year      = {2026},
  pages     = {1--9},
  doi       = {10.23919/IFIPNetworking70592.2026.11578986}
}
```

## Acknowledgments

This work was supported by a fellowship of the German Academic Exchange Service (DAAD) and by
the Canada Excellence Research Chair in Intelligent Digital Infrastructures at the University
of Toronto, funded by the Tri-agency Institutional Programs Secretariat.

## License

[Apache License 2.0](LICENSE), like GoBGP. Logos and icons are in [`assets/`](assets).
