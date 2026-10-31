# OBGP

GoBGP fork with OBGP (oscillation-free BGP) and a lab that measures it.

## Map

- `internal/pkg/table/opera.go`: OBGP itself. Switched on by `GOBGP_OPERA_ENABLED`, pruning by
  `GOBGP_OPERA_PRUNING=refresh|soft|hard|off` (refresh default, hard the paper's), `GOBGP_OPERA_REFRESH_S`, `GOBGP_OPERA_REFRESH_DELAY_S` (per variant `refresh_delay`), `GOBGP_OPERA_IBGP=filter` for the paper's iBGP, `GOBGP_OPERA_AS_SET=received` for the
  paper's AS_SET order, `GOBGP_OPERA_CONFED`, `GOBGP_OPERA_RS` and `GOBGP_OPERA_EXPORT=neighbor` (a table per eBGP
  neighbor, `opera_neighbor.go`, variant `per_neighbor`) as in the README. Lab modes `obgp-rp`, `obgp-sp`, `obgp-hp`, `obgp-np`, `obgp-paper`, each also hybrid and random.
- `DESIGN.md`: every design decision, why, and whether the proof of [3] covers it. Update it with each new one.
  It also holds what the router supports, where the modes differ and the limitations in detail.
- `docs/lab.md` operation and metrics, `docs/agents.md` agents and their limits, `docs/simulator.md`. The README stays short.
- `pkg/server/mrai.go`: the MRAI, which GoBGP read but never applied, set per experiment with `bgp.mrai`.
- `internal/pkg/obgpsim/`, `cmd/obgp-sim/`: simulator of one prefix with the real decision code, BGP vs OBGP, counterexample search. Not in GitHub Actions.
- `lab/`: the lab in Python, `uv run lab …`.
  - `cli.py` commands, `runner.py` runs, `cluster.py` minikube, Helm and what fits the host, `host.py` host load
  - `lifecycle.py` shared setup/configuration and runtime operations, `service.py` web process ownership, `terminal.py` terminal output
  - `uninstall.py` ownership inventory and rollback of recorded installation changes
  - `web/cluster_control.py` cluster controls and idle shutdown, `web/jobs.py` queue, `web/auth.py` passwords,
    `web/groups.py` groups of the main views, moves kept in the settings
  - `scenario.py` steps, `topology.py`, `modes.py`, `forwarding.py` forwarding and valley-free checks as the simulator's, `simulate.py` lab and simulator in each other's terms,
    `simulation.py` searches of the Simulation area in the lab's queue, their problems, and cases played in the lab (`sim-<search>-<case>`, git-ignored)
  - `config.py` experiments and settings, `analysis.py` metrics (bump `VERSION` when they change), `results.py`, `estimate.py`, `calibration.py`
  - `problems.py` which runs failed and why, the properties every run is checked for, judged against the simulator's predictions a result keeps (docs/lab.md, Problems), `web/agent.py` what agents read and do, `web/tokens.py`, `web/approvals.py` changes that wait for a person, `web/mcp_server.py` MCP, `web/routes/api.py` API
  - `legacy.py`: imports the paper's runs into `results/public/ifip-networking-2026`, run once
  - `caida.py`, `prefixes.py`, `mrt.py`, `rib.py`, `sndlib.py`: Internet data
  - `generate.py`: generated topologies (Erdős–Rényi, Watts–Strogatz, Barabási–Albert, Waxman, Elmokashfi)
  - `notify.py` Discord, ends of results and searches, `update.py` updates from GitHub, `web/` FastAPI, Jinja2, htmx, Tailwind
- `controller/app.py`: beside gobgpd in every router pod, samples (next hops, a sample of prefixes on large tables, session drops) and executes steps.
- `gobgp-lab/` Helm chart and topologies, `experiments/`, `scenarios/`.
- `results/`: large, do not read. Use `uv run lab ls` and `uv run lab summary <result>`.

## Commands

Paths below are relative to the repository root. The README starts inside `scripts/` and uses `./…sh`.

- Install/repair: `scripts/setup.sh`. Change saved choices or reset a forgotten password: `scripts/reconfigure.sh`.
- Runtime: `scripts/start.sh`, `scripts/stop.sh`, `scripts/update.sh`, `scripts/teardown.sh`, `scripts/uninstall.sh`.
  Command line on a server, without uv on the path: `scripts/lab.sh ls`.
- Tests: `uv run --group dev pytest -q`, `go test ./internal/pkg/table/`, simulator `go test -tags obgpsim ./internal/pkg/obgpsim/`
- CSS after template changes: `scripts/dev/build-css.sh`
- Layout: `scripts/dev/screens.sh [dir] [page or /path]` screenshots pages at phone and desktop width, with the local searches
- Development web only: `uv run lab serve --http`. Normal startup uses the scripts. Templates reload, Python changes need a restart.

## Lifecycle

- Reuse `lifecycle.py` and the existing cluster claim. Never recreate an active experiment's cluster or kill an unrelated process.
- Setup persists resource budgets, host reserves and web access. Reconfigure prompts with saved defaults and can reset the password without the old one. Non-interactive runs never prompt.
- HTTPS uses a self-signed certificate. HTTP binds to localhost. Print a usable browser URL, never the wildcard listen address.
- Searches of the simulator share the queue with results but need no cluster: they run while it is stopped. Queuing a result while the cluster is switched off asks to start it.
- UI cluster controls leave the web server online. Idle stops allow automatic wake on queued work. Explicit Stop disables wake until Start. Default idle timeout is 30 minutes, saved timeouts take precedence.
- A watchdog line in the user's crontab restarts the web server after reboots and crashes. Stop and teardown keep it off until start.
- Script, UI and MCP updates restart only the web server and preserve cluster state. Local changes block updates. After a rewritten history a branch switch is needed, MCP updates switch by themselves.
- Setup/start/update preserve results and configuration. Teardown removes runtime, `--purge` additionally removes private results. Public results and settings remain.
- Uninstall uses `~/obgp-lab/installed.txt` to undo recorded changes. Never remove unowned or changed tools, unrelated containers, shared caches or packages that APT needs for other software. Keep results unless `--purge` is explicit. Old installations have incomplete host provenance.
- Helpers are in `scripts/internal/`, asset tools in `scripts/dev/`. Keep wrappers thin.

## Rules

- Discuss before coding: agree on files and commits first.
- English everywhere. Texts short and plain, no semicolons in prose.
- One experiment per question of the evaluation, listed in the README. `ifip-networking-2026`, its
  scenarios and topologies stay unchanged.
- Never pool modes. State n and the resolution (two sampling intervals) with every claim.
- The local machine is small: ask before any local run, `lab-smoke` at most. Large runs go to the
  server, through the lab's MCP with the user's token and only when asked. Never ssh or run commands
  on remote hosts.
- Usage is paid: no polling loops, monitors or subagents unless asked, read only what is needed, short answers.
- Never move or rename files in `vis/`, it is linked from outside.
- No secrets, host names or addresses in the repo.
- Commit as agreed. Push the current branch only when asked.
- GitHub Actions: fast tests only, no minikube.
