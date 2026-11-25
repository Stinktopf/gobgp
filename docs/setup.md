# Setup

The lab needs a Linux host with Docker. Setup asks for resources, HTTPS and a password, then prints
the address of the web UI.

```bash
git clone https://github.com/Stinktopf/gobgp.git && cd gobgp/scripts && ./setup.sh
```

Then open the address and run `lab-smoke`.

## Scripts

All in `scripts/`.

| Action | Command |
|---|---|
| Install or repair | `./setup.sh` |
| Install as a guest on a shared server, without sudo | `./setup.sh --no-sudo` |
| Change settings or reset the password | `./reconfigure.sh` |
| Start | `./start.sh` |
| Stop cluster and web UI | `./stop.sh` |
| Update, restart only the web UI, keep the cluster | `./update.sh` |
| Switch to a branch on GitHub | `./update.sh --branch [name]` |
| Command line, e.g. `ls` or `summary <result>` | `./lab.sh ls` |
| Remove the runtime, keep results | `./teardown.sh` |
| Undo what setup installed | `./uninstall.sh` |

- **Results:** teardown and uninstall keep them, the simulator's searches and the stars and notes too. `teardown --purge` deletes private results, `uninstall --purge` also the searches, stars and notes.
- **Watchdog:** a crontab line restarts the web UI after a reboot or crash. Stop and teardown keep it off until Start.
- **Restarts:** a result cut short by a shutdown, a restart of Docker or a lost cluster goes on by itself and
  plays the cut run again, once the host has run 15 minutes and Docker 5. The lab then starts only its own cluster.
- **Failed for the host:** a result ends as failed, with a notification, when its cluster is lost a second time,
  when the cluster does not come back after 3 starts, or at a limit of the host. It is not restarted.
- **Docker:** when Docker does not settle within 30 minutes, the lab pauses the queue.
- **Clean cluster:** after every result the lab removes its routers, or deletes its own minikube profile at once
  when the Kubernetes API does not answer. Meanwhile the result shows its end state and what the lab does. Before
  every result it checks that the Kubernetes API answers and that no routers of another run stay. Otherwise it
  deletes its own minikube profile and creates it anew. Results and other containers stay.
- **Pause:** the running result ends its current run, then waits. A host can be restarted then without
  losing a run.

## Host size

- **Threads:** the experiments plan half a thread per router, as BGP that oscillates keeps every router busy.
  The lab admits at most the routers per thread set in Settings, 4 by default, and leaves the host 4 threads
  and 4 GiB.
- **CPUs:** each result binds the cluster to as many CPUs as its experiment names, whole cores of the
  highest NUMA node that has enough, its memory too where the node holds it. Others on the host keep
  the rest. gobgpd runs below the controller that samples it.
- **Memory:** some 100 MiB per router, a limit of 4 GiB per router, more with full tables.
- **Deploy:** above 32 routers the routers start in batches of 32 and learn their neighbors' addresses in waves.
  Routers use no DNS and no Service. `bgp.procs` sets the threads that run Go code in each gobgpd, `internet-scale`
  sets 2.
- **Host limits:** a deploy or run ends when the Kubernetes API does not answer for 3 minutes or the node's connection
  tracking passes 60 %, since a full one makes the host drop packets. Its result ends as failed. During a deploy
  the lab writes the node's load every 30 s to `diagnosis/` in the result, and on an API loss, also during a run,
  the logs of the API server, etcd and kubelet.
- **Neighbour table:** the kernel keeps one ARP table for all containers of the host, 1,024 entries by default.
  Each router holds an entry per BGP neighbor: `core-64` needs about 2,000, `core-128` about 4,600. A full table
  drops packets, also those of the Kubernetes API. Setup raises the limits to 8,192, 32,768 and 65,536 in
  `/etc/sysctl.d/90-obgp-lab-neigh.conf` and never lowers one. With `--no-sudo` it prints the commands for an
  administrator. A deploy that would fill the table ends its result before the first pod.

| Experiments | Routers, at most | Threads | Memory, at least |
|---|---|---|---|
| `lab-*`, `semantics-*` | 28 | 14 | |
| `behaviour-*`, `ifip-networking-2026` | 50 | 25 | |
| `internet-scale` | 128 | 128 | 256 GiB |
| `internet-dfz` | 32, with full tables | 64 | 460 GiB |

A smaller host skips the topologies that do not fit. The Internet experiments set the least they
need, so that they run only where they measure right.

## Remote access

- **HTTPS:** the server's host name and the printed port. The certificate is self-signed. Settings
  offers it for download: trusted once, the browser stops warning.
- **HTTP:** binds to localhost. Forward the printed port, here 8443, then open <http://localhost:8443>.

```bash
ssh -N -L 8443:127.0.0.1:8443 USER@SERVER
```

## Windows with WSL

Docker Desktop must run with WSL integration on. So that WSL gives freed memory back, run this in
PowerShell once, then restart Docker Desktop.

```powershell
Set-Content -Path "$env:USERPROFILE\.wslconfig" -Value "[experimental]`r`nautoMemoryReclaim=gradual"
wsl --shutdown
```
