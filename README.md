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
strictly, so it cannot. BGP messages are unchanged, so OBGP interoperates at the protocol level
with any BGP speaker.

## How it works

Paths are ordered by AS path length, ties broken by ASN.

- **Import:** a path is admitted only if it is better than the worst admitted one.
- **Re-admission:** rejected paths come back once no valid path is left.
- **Export:** peers get the worst admitted path, so a better one never changes what they see.
- **Pruning:** a withdrawn or changed path removes the paths containing its old AS sequence.
- **Forwarding:** the FIB gets GoBGP's usual best path, loop-free since the export path length
  decreases along every hop.

## Results

Compared with GoBGP on `germany50`, `BAD GADGET` and `noble-eu`, BGP oscillated indefinitely in both
cyclic topologies and OBGP converged. OBGP admitted 27–51 % fewer paths on average, and `noble-eu`
drained in about 3 s instead of 29–42 s.

## Usage

```bash
go build -o . ./cmd/gobgpd ./cmd/gobgp
GOBGP_OPERA_ENABLED=true ./gobgpd -f gobgpd.conf
```

Without the variable, the daemon is plain GoBGP. `GOBGP_OPERA_PRUNING=false` turns pruning off. The code is in [`opera.go`](internal/pkg/table/opera.go),
configuration and CLI are [GoBGP's](docs/sources/getting-started.md).

## Lab

<p align="center">
  <picture>
    <source srcset="assets/readme/process-dark.svg" media="(prefers-color-scheme: dark)">
    <img src="assets/readme/process-light.svg" alt="Topologies, scenarios, experiments, results, wrapped" width="980">
  </picture>
</p>

Build a network in the editor, import one from [SNDlib](https://sndlib.put.poznan.pl) or
[CAIDA](https://www.caida.org/catalog/datasets/as-relationships/), or generate one with
Erdős–Rényi, Watts–Strogatz, Barabási–Albert, Waxman or Elmokashfi. The lab runs BGP and
OBGP on it in minikube, with one pod per router. To work with real Internet routing data, it can load
full IPv4 routing tables from the Default-Free Zone (DFZ) and replay prefix announcements
and withdrawals from [RIPE RIS](https://ris.ripe.net) MRT dumps.

Each comparison uses the same random seeds and varies which protocol runs first.
Wilcoxon signed-rank tests and Hodges–Lehmann estimates show how consistent the differences
are and how large they are, with confidence intervals. Turn pruning off or vary a parameter
across runs to see what changes. Separate experiments check the measurements against known
values and test whether sampling itself affects the results. Each result keeps its inputs,
seeds and software versions for later inspection.

| Question | Experiment |
|---|---|
| Does OBGP converge where BGP oscillates? | [`behaviour-oscillation`](experiments/behaviour-oscillation.yaml) |
| Does it admit fewer paths and drain faster? | [`ifip-networking-2026`](experiments/ifip-networking-2026.yaml) |
| Do Gao-Rexford policies hold, also in partial deployment? | [`semantics-gao-rexford`](experiments/semantics-gao-rexford.yaml) |
| Where do the guarantees end? | [`semantics-adversarial`](experiments/semantics-adversarial.yaml) |
| Does it stay stable under failures? | [`behaviour-failures`](experiments/behaviour-failures.yaml) |
| Does it scale to 256 networks of the Internet's core? | [`internet-scale`](experiments/internet-scale.yaml) |
| Does it scale to full IPv4 DFZ tables? | [`internet-dfz`](experiments/internet-dfz.yaml) |
| Does the lab work? | [`lab-smoke`](experiments/lab-smoke.yaml) |
| Does the lab measure right? | [`lab-calibration`](experiments/lab-calibration.yaml), [`lab-sampling-1hz`](experiments/lab-sampling-1hz.yaml), [`-10hz`](experiments/lab-sampling-10hz.yaml) |

### Running it

On a Linux laptop or server:

```bash
git clone https://github.com/Stinktopf/gobgp.git && cd gobgp/scripts && ./setup.sh
```

Setup asks for resources, HTTPS and a password. Open the printed URL and try **lab-smoke**.

| Action | Command |
|---|---|
| Repair installation | `./setup.sh` |
| Reconfigure or reset password | `./reconfigure.sh` |
| Update and restart the web UI | `./update.sh` |
| Start | `./start.sh` |
| Stop cluster and web UI | `./stop.sh` |
| Remove runtime, keep results | `./teardown.sh` |
| Remove recorded installation changes | `./uninstall.sh` |

Teardown keeps settings. Uninstall also removes recorded tools and settings, preserving
pre-existing or subsequently changed resources. Add `--purge` to either to delete private results.

<details>
<summary>Remote access</summary>

HTTPS: use the server's hostname or IP and the printed port. The self-signed
certificate encrypts traffic but triggers a browser warning.

HTTP: run this on your computer and keep it open:

```bash
ssh -N -L 8443:127.0.0.1:8443 USER@SERVER
```

Use your SSH login for `USER@SERVER`, then open <http://localhost:8443>.
If the server uses another port, change the second `8443`.

</details>

## Changes since the paper

BGP messages are unchanged.

- Rejected paths are re-admitted when no valid path is left.
- Pruning skips attribute-only updates and lost sessions, and can be turned off.
- The FIB gets the local best path instead of the export path.
- OBGP applies to IPv4 and IPv6 unicast only.
- Two GoBGP fixes: soft reset out withdraws newly rejected routes, the API marks the best path again.

## Limitations

- **Model:** one export path per destination for all neighbors, export eligibility by Gao-Rexford class
  only. A neighbor whose class may not get that path gets none. Filters per neighbor are outside the
  model, and with pruning they can remove paths still valid via another peer.
- **Behaviour:** admission depends on the order paths arrive in. Local Preference chooses only among
  admitted paths.
- **Not supported:** `AS_SET`, confederations, Add-Path export, route server mode. iBGP is not evaluated.
- **Tests:** four GoBGP server tests fail by design with OBGP, since they count candidate paths.
- **Measurements:** all routers share one host, and busy routers sample less often. Results warn
  where that matters and name topologies too large for the host. Claims at 5 % need six paired runs.
  CAIDA infers who is customer, provider or peer from BGP paths, and some relations it gets wrong.

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
