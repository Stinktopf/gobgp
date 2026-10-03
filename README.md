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

Emulates topologies on minikube, one pod per router, drawn in its editor, from [SNDlib](https://sndlib.put.poznan.pl),
[CAIDA](https://www.caida.org/catalog/datasets/as-relationships/) and [RIPE RIS](https://ris.ripe.net) or from
five generators, and compares BGP, OBGP and OBGP without pruning in runs paired by seed, also over sweeps of a
parameter.

| Question | Experiment |
|---|---|
| Does OBGP converge where BGP oscillates? | [`behaviour-oscillation`](experiments/behaviour-oscillation.yaml) |
| Does it admit fewer paths and drain faster? | [`ifip-networking-2026`](experiments/ifip-networking-2026.yaml) |
| Do Gao-Rexford policies hold, also in partial deployment? | [`semantics-gao-rexford`](experiments/semantics-gao-rexford.yaml) |
| Where do the guarantees end? | [`semantics-adversarial`](experiments/semantics-adversarial.yaml) |
| Does it stay stable under failures? | [`behaviour-failures`](experiments/behaviour-failures.yaml) |
| Does it scale to 256 networks of the Internet's core? | [`internet-scale`](experiments/internet-scale.yaml) |
| Does it scale to full Internet tables? | [`internet-dfz`](experiments/internet-dfz.yaml) |
| Does the lab measure right? | [`lab-calibration`](experiments/lab-calibration.yaml), [`lab-sampling-1hz`](experiments/lab-sampling-1hz.yaml), [`-10hz`](experiments/lab-sampling-10hz.yaml) |

### Running it

| Host | Needs |
|---|---|
| Laptop | Docker, 4 CPUs, 6 GB |
| Own server | Ubuntu or Debian, root |
| Shared server | Docker, and once from an admin `scripts/allow-user.sh` |

The full evaluation needs 128 CPUs and 512 GB. Smaller hosts skip what does not fit.

**Set up.** First, on every host:

```bash
git clone https://github.com/Stinktopf/gobgp.git && cd gobgp
```

Laptop, interface on <http://localhost:8443>:

```bash
scripts/setup-user.sh --install
```

Own server, `https://<ip>:8443` with a self-signed certificate and an initial password:

```bash
sudo scripts/setup-host.sh
```

Shared server, an admin allows the user once, then the user sets up without sudo:

```bash
sudo scripts/allow-user.sh <user>
LAB_CPUS=128 LAB_MEMORY_GB=512 scripts/setup-user.sh --install
```

The interface is at `https://<host>:8443`, or through `ssh -L 8443:localhost:8443 <host>`. If 8443 is taken,
it takes the next free port and says which.

Once it runs, the settings update the lab from GitHub.

**Tear down.** Both keep the results, `--purge` deletes them too. Laptop and shared server:

```bash
scripts/teardown-user.sh
```

Own server:

```bash
sudo scripts/teardown-host.sh
```

On a shared server, the admin may then take the permission back:

```bash
sudo scripts/allow-user.sh <user> --undo
```

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
