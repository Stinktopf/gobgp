# Running the lab

Setup asks for resources, HTTPS and a password, then prints the address of the web UI.

| Action | Command |
|---|---|
| Repair installation | `./setup.sh` |
| Install as a guest on a shared server, never sudo | `./setup.sh --no-sudo` |
| Reconfigure or reset password | `./reconfigure.sh` |
| Command line, e.g. `ls` or `summary <result>` | `./lab.sh ls` |
| Update and restart the web UI | `./update.sh` |
| Switch to a branch on GitHub, default without a name | `./update.sh --branch [name]` |
| Start | `./start.sh` |
| Stop cluster and web UI | `./stop.sh` |
| Remove runtime, keep results | `./teardown.sh` |
| Remove recorded installation changes | `./uninstall.sh` |

- **Watchdog:** a crontab line starts the web UI again after a reboot or crash, at most three times an hour.
  A busy web UI gets 30 seconds to answer. One of another checkout is left alone, see `watch.log`.
- **Stop:** keeps the watchdog off until Start.
- **Teardown:** keeps settings and results.
- **Uninstall:** removes what setup installed, and nothing else.
- **`--purge`:** with either, also deletes private results.

## How large a host

- **Threads:** half a thread per router, as BGP that oscillates keeps every router busy.
- **Memory:** some 100 MiB per router, up to 4 GiB while it oscillates, more with full tables.

| Experiments | Routers, at most | Threads |
|---|---|---|
| `lab-*`, `semantics-*` | 28 | 14 |
| `behaviour-*`, `ifip-networking-2026` | 50 | 25 |
| `internet-scale` | 256 | 128 |
| `internet-dfz` | 32, with full tables in some 360 GiB | 64 |

## Metrics

| Metric | Unit | Meaning |
|---|---|---|
| Full reach | s | until every router holds every prefix, routes may still change |
| Settle | s | until no router changes anything and no update is sent |
| Never at rest | runs | routes still change at the end |
| Not reached | routes | router and prefix pairs without a route at the end |
| Loops, black holes | prefixes | whose packets loop, or end at a router without a route, at the end |
| Withdrawn kept | routes | router and prefix pairs still held after their withdrawal |
| Loops on the way | s | in which packets to some prefix looped |
| Black holes on the way | s | in which packets to some prefix ended at a router without a route |
| Followed | prefixes | the sample the two above count on, on tables above 256 prefixes |
| Blocked | s | in which a router had a prefix with a valid path set aside and no route |
| Blocked | prefixes | the most at one router at once |
| Session drops | drops | sessions that fell from established, both ends count |
| Drops no step explains | drops | of sessions no down, degrade or restart touched |
| Updates at rest | updates/s | per router after the last step, zero when routes stand still |
| Routes | prefixes | with a selected route, the Loc-RIB of RFC 4271 |
| Known | prefixes | with a path admitted or set aside |
| Adj-RIB-In | paths | received from all neighbors |
| Admitted | paths | what the import admits, the Loc-RIB of the paper |
| Set aside | paths | OBGP keeps without admitting them |
| Memory | MiB | resident memory of the daemon |

A path is one AS path to a prefix from one neighbor, a route the path selected for a prefix. Loops and
black holes on the way come from the next hops each router samples on every change. Above 256 prefixes
every router follows the same sample of 256 from the time the announcements are done.

- **Rest:** a state counts once it holds 3 s (`stable_s`). With an MRAI it must hold one and a half MRAI, as routers pause between MRAI waves.
- **Seeds:** paired variants share them. A seed fixes a scenario's random choices and the order of the variants in a round.
- **Primary comparison:** an experiment names it, e.g. `primary: {metric: hold_churn, variant: obgp-rp, baseline: bgp}`.

## Problems

Every run is checked at its end, once its routes stand still or a bounded time passed, whatever its
scenario checks. The reference is the BGP run of the same seed, where it came to rest.

- **Predicted:** as a result begins, the simulator plays every topology and scenario it can, 20 orders of messages per mode. A run without rest is as predicted where the simulator saw its mode not come to rest in some order, e.g. BGP on BAD GADGET. Where it always comes to rest, a run without rest is a problem.
- **Checks:** a check names the modes that may fail it, those the simulator sees fail it. Its failure foretells only problems of the same kind, a lost route a lost route, a loop a loop.
- **Unforeseen rest:** a run at rest where the simulator never comes to rest is a problem of its own: lab and simulator disagree.

| Problem | When |
|---|---|
| Routes still change at the end | updates go on after the rest |
| No rest in time | a step or the final check waited for rest in vain |
| Loops at rest | packets to a prefix loop at the end |
| Fewer routes than BGP | a router holds fewer prefixes than in the reference |
| No BGP run at rest to compare with | a run misses prefixes and the reference never came to rest |
| Black holes, withdrawn routes BGP has not | more than in the reference, or any without one |
| Paths against the relations | chosen paths that break up, one peer, down, more than in the reference, paths with an `AS_SET` left out |
| Loops or black holes on the way, longer than BGP | longer than in the reference by more than two sampling intervals |
| Routers wait without a route | blocked longer than two sampling intervals, under refresh pruning longer than its wait for a route refresh |
| Sessions fell without a step for it | drops of sessions no down, degrade or restart touched |
| At rest, the simulator never is | a run came to rest where the simulator never does |
| No final check | skipped, for tables above 2000 prefixes |

Discord, if set in Settings, tells the end of every result with its problems no check foretold, and
the end of every search of the simulator.

## Simulation

The first area of the web UI, before the lab's stages.

- **Search:** one button. Every connected network up to five routers, every family of policies, three message orders, the way to rest, one table and tables per neighbor. Six routers would take days.
- **Queue:** a search waits in the lab's queue beside the results and needs no cluster. It shows how far it is and how long it still takes, and goes on after a restart of the web server or a pause. A worker that dies twice fails its search, and a search that began again says so.
- **Storage:** `~/.config/obgp-lab/simulation`, kept by teardown.
- **Problems:** one group per kind, one row per problem: the modes that show it, its cause where the result tells it, and its networks. Causes are an export filter, an import filter, a community, a relation, or a router that does not admit the offer.
- **Case:** the mode with the problem large, the one to compare small beside it. Both move message by message after the same events, and the small one shows its rest where the large one rests. Beside them every step, the key moments and the network. Below, per router and neighbor, what it receives, what it takes of it, and what it sends or why not.
- **Marks:** routers of the problem ringed, loops red, a router waiting for a route refresh violet. The mode menus show the modes with the problem in red.
- **In the lab:** Play in the lab makes the case an experiment of every mode, with the simulator's prediction as checks. Its results show under the case, per mode the runs with the problem. The lab cannot replay the simulator's order of messages, so a problem of few orders may not show.

## Remote access

- **HTTPS:** the server's host name or IP, and the printed port.
- **HTTP:** forward the port, then open <http://localhost:8443>.

```bash
ssh -N -L 8443:127.0.0.1:8443 USER@SERVER
```

## Windows with WSL

- **Docker Desktop:** must run, with WSL integration on.
- **Memory:** so that WSL gives freed memory back, run this in PowerShell once, then restart Docker Desktop.

```powershell
Set-Content -Path "$env:USERPROFILE\.wslconfig" -Value "[experimental]`r`nautoMemoryReclaim=gradual"
wsl --shutdown
```
