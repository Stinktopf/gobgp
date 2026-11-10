# OBGP

GoBGP fork with OBGP (oscillation-free BGP) and a lab that measures it.

## Map

- `internal/pkg/table/opera.go`: OBGP itself, `opera_neighbor.go` a table per eBGP neighbor. Its `GOBGP_OPERA_*`
  settings and the lab modes (`obgp-rp`, `-sp`, `-hp`, `-np`, `-paper`, hybrid, random, `bgp-pn` for NS-BGP) are in docs/router.md.
- `DESIGN.md`: every design decision, why, and whether the proof of [3] covers it. Update it with each new one.
  It also holds what the router supports, where the modes differ and the limitations in detail.
- `docs/router.md` settings, modes, limitations, `docs/setup.md` operation and host sizes, `docs/evaluation.md` questions, runs, metrics, problems, statistics, threats, `docs/agents.md` agents and their limits, `docs/simulator.md`. The README stays short, each fact in one file only.
- `pkg/server/mrai.go`: the MRAI, which GoBGP read but never applied, set per experiment with `bgp.mrai`.
- `internal/pkg/obgpsim/`, `cmd/obgp-sim/`: simulator of one prefix with the real decision code, BGP vs OBGP, counterexample search. Not in GitHub Actions.
- `lab/`: the lab in Python, `uv run lab …`.
  - `cli.py` commands, `runner.py` runs, `cluster.py` minikube, Helm and what fits the host, `host.py` host load
  - `lifecycle.py` shared setup/configuration and runtime operations, `service.py` web process ownership, `terminal.py` terminal output
  - `uninstall.py` ownership inventory and rollback of recorded installation changes
  - `remote.py` `lab pull`: results and searches of another lab on this machine, via its MCP tool `download`
  - `web/cluster_control.py` cluster controls and idle shutdown, `web/jobs.py` queue, `web/auth.py` passwords,
    `web/groups.py` groups of the main views, moves kept in the settings
  - `scenario.py` steps, `topology.py`, `modes.py`, `forwarding.py` forwarding and valley-free checks as the simulator's, `simulate.py` lab and simulator in each other's terms,
    `simulation.py` searches of the Simulation area in the lab's queue, their problems, and cases played in the lab (`sim-<search>-<case>`, git-ignored)
  - `config.py` experiments and settings, `analysis.py` metrics (bump `VERSION` when they change), `results.py`, `estimate.py`, `calibration.py`
  - `problems.py` which runs failed and why, the properties every run is checked for, judged against the simulator's predictions a result keeps (docs/evaluation.md, Problems), `web/agent.py` what agents read and do, `web/tokens.py`, `web/approvals.py` changes that wait for a person, `web/mcp_server.py` MCP, `web/routes/api.py` API
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
- Usage display for Claude Code, opt-in: `scripts/dev/claude-usage/install.sh`.
- Development web only: `uv run lab serve --http`. Templates reload, Python changes need a restart. The scripts start the server with `--managed`: templates and static files stay as at its start.

## Lifecycle

- Reuse `lifecycle.py` and the existing cluster claim. Never recreate an active experiment's cluster or kill an unrelated process.
- Setup persists resource budgets, host reserves and web access. Reconfigure prompts with saved defaults and can reset the password without the old one. Non-interactive runs never prompt.
- Print a usable browser URL, never the wildcard listen address.
- Queuing a result while the cluster is switched off asks to start it.
- UI cluster controls leave the web server online. Idle stops allow automatic wake on queued work. Explicit Stop disables wake until Start. Default idle timeout is 30 minutes, saved timeouts take precedence.
- Stop and teardown keep the crontab watchdog off until start.
- Script, UI and MCP updates restart only the web server and preserve cluster state. Local changes block updates. After a rewritten history a branch switch is needed, MCP updates switch by themselves.
- Setup, start and update keep results and configuration. Public results and settings always remain.
- The lab is a guest on a shared host: it never stops, restarts or prunes Docker and touches only its own container,
  profile and the images inside minikube. Recovery only starts its own cluster.
- Uninstall uses `~/obgp-lab/installed.txt` to undo recorded changes. Never remove unowned or changed tools, unrelated containers, shared caches or packages that APT needs for other software. Keep results unless `--purge` is explicit. Old installations have incomplete host provenance.
- Helpers are in `scripts/internal/`, asset tools in `scripts/dev/`. Keep wrappers thin.

## Rules

- Discuss before coding: agree on files and commits first. A material change to an agreed approach
  (behaviour, interface, files or scope) needs new approval before it is made, not a report after.
- Judge work by its content, not its exit code: open the result, look at a changed page once (`scripts/dev/screens.sh`).
- Small steps, each with its own check. Read the whole diff before a squash.
- Writing: the Google developer documentation style and ASD-STE100 as guidance only: one term per concept, precise
  conditions, assumptions, evidence and conclusions kept apart.
- English everywhere. Texts short and plain, no semicolons in prose. No middle dots (·) as separators in UI texts or labels: commas, short sentences or line breaks instead.
- Terms as in docs/evaluation.md: *rest* is a state without route changes or updates for the hold time, *settle* the time
  until rest, *converge* to come to rest (also the simulator's `converged`), *oscillate* never to rest. The metric key
  `convergence_s` is Full reach, not rest.
- One experiment per question of the evaluation, listed with its question in docs/evaluation.md. `ifip-networking-2026`, its
  scenarios and topologies stay unchanged.
- The local machine is small: ask before any local run, `lab-smoke` at most. Large runs go to the
  server, through the lab's MCP with the user's token and only when asked. Never ssh or run commands
  on remote hosts.
- Usage is paid: no polling loops, monitors or subagents unless asked, read only what is needed, short answers.
- Never move or rename files in `vis/`, it is linked from outside.
- No secrets, host names or addresses in the repo.
- Commit as agreed. Push the current branch only when asked.
- GitHub Actions: fast tests only, no minikube.

## Claims

Every claim names its level and keeps the weakest level it rests on. New evidence, not wording, raises it.

- **Assumption:** a condition of a model, e.g. Gao-Rexford policies, one prefix, no timers. Name those a claim needs.
- **Proven:** a proof covers it, within its assumptions. Cite the proof. Outside them the claim is unproven, not false.
- **Enumerated:** `obgp-sim` checked every network within a bound (routers, policy families), at five routers once
  per graph up to renumbering. Exhaustive over those networks only. Message orders are sampled by seed: "not found in k orders" does not mean impossible. An order
  without end is shown by a recurring state, "still busy after 20,000 messages" only bounds. Findings on the
  way need `-transient`.
- **Measured:** lab runs, one host, one implementation. State n, the resolution (two sampling intervals) and the
  interval. Never pool modes.
- Levels that disagree stay open until investigated. Neither side wins by default.
