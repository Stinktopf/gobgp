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
| Update and restart the web UI | `./update.sh` |
| Switch to a branch on GitHub | `./update.sh --branch [name]` |
| Command line, e.g. `ls` or `summary <result>` | `./lab.sh ls` |
| Remove the runtime, keep results | `./teardown.sh` |
| Undo what setup installed | `./uninstall.sh` |

- **Results:** teardown and uninstall keep them. `--purge` also deletes private results.
- **Watchdog:** a crontab line restarts the web UI after a reboot or crash. Stop keeps it off until Start.
- **Restarts:** only Stop ends a result. One cut short by a shutdown, a restart of Docker or a lost cluster
  goes on by itself and plays the cut run again, once the host has run 15 minutes and Docker 5. The lab
  then starts only its own cluster. After 30 minutes or three losses within an hour it pauses the queue.
- **Pause:** the running result ends its current run, then waits. A host can be restarted then without
  losing a run.
- **Updates:** restart only the web UI and keep the cluster.

## Host size

- **Threads:** half a thread per router, as BGP that oscillates keeps every router busy.
- **CPUs:** each result binds the cluster to as many CPUs as its experiment names, whole cores of the
  highest NUMA node that has enough, its memory too where the node holds it. Others on the host keep
  the rest. gobgpd runs below the controller that samples it.
- **Memory:** some 100 MiB per router, up to 4 GiB while it oscillates, more with full tables.

| Experiments | Routers, at most | Threads |
|---|---|---|
| `lab-*`, `semantics-*` | 28 | 14 |
| `behaviour-*`, `ifip-networking-2026` | 50 | 25 |
| `internet-scale` | 256 | 128 |
| `internet-dfz` | 32, with full tables in some 360 GiB | 64 |

A smaller host skips the topologies that do not fit. The internet experiments set the least they
need, so that they run only where they measure right.

## Remote access

- **HTTPS:** the server's host name and the printed port. The certificate is self-signed. Settings
  offers it for download: trusted once, the browser stops warning.
- **HTTP:** binds to localhost. Forward the port, then open <http://localhost:8443>.

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
