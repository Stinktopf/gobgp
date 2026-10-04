# OBGP

GoBGP fork with OBGP (oscillation-free BGP) and a lab that measures it.

## Map

- `internal/pkg/table/opera.go`: OBGP itself. Switched on by `GOBGP_OPERA_ENABLED`, pruning off by
  `GOBGP_OPERA_PRUNING=false`.
- `lab/`: the lab in Python, `uv run lab …`.
  - `cli.py` commands, `runner.py` runs, `cluster.py` minikube, Helm and what fits the host, `host.py` host load
  - `lifecycle.py` shared setup/configuration and runtime operations, `service.py` web process ownership, `terminal.py` terminal output
  - `uninstall.py` ownership inventory and rollback of recorded installation changes
  - `web/cluster_control.py` cluster controls and idle shutdown, `web/jobs.py` queue, `web/auth.py` passwords
  - `scenario.py` steps, `topology.py`, `modes.py`
  - `analysis.py` metrics (bump `VERSION` when they change), `results.py`, `estimate.py`, `calibration.py`
  - `caida.py`, `prefixes.py`, `mrt.py`, `rib.py`, `sndlib.py`: Internet data
  - `generate.py`: generated topologies (Erdős–Rényi, Watts–Strogatz, Barabási–Albert, Waxman, Elmokashfi)
  - `notify.py` Discord, `update.py` updates from GitHub, `wrapped.py` Wrapped, `web/` FastAPI, Jinja2, htmx, Tailwind
- `controller/app.py`: beside gobgpd in every router pod, samples and executes steps.
- `gobgp-lab/` Helm chart and topologies, `experiments/`, `scenarios/`.
- `results/`: large, do not read. Use `uv run lab ls` and `uv run lab summary <result>`.

## Commands

Paths below are relative to the repository root. The README starts inside `scripts/` and uses `./…sh`.

- Install/repair: `scripts/setup.sh`. Change saved choices or reset a forgotten password: `scripts/reconfigure.sh`.
- Runtime: `scripts/start.sh`, `scripts/stop.sh`, `scripts/update.sh`, `scripts/teardown.sh`, `scripts/uninstall.sh`.
- Tests: `uv run --group dev pytest -q`, `go test ./internal/pkg/table/`
- CSS after template changes: `scripts/dev/build-css.sh`
- Development web only: `uv run lab serve --http`. Normal startup uses the scripts. Templates reload, Python changes need a restart.

## Lifecycle

- Reuse `lifecycle.py` and the existing cluster claim. Never recreate an active experiment's cluster or kill an unrelated process.
- Setup persists resource budgets, host reserves and web access. Reconfigure prompts with saved defaults and can reset the password without the old one. Non-interactive runs never prompt.
- HTTPS uses a self-signed certificate. HTTP binds to localhost. Print a usable browser URL, never the wildcard listen address.
- UI cluster controls leave the web server online. Idle stops allow automatic wake on queued work. Explicit Stop disables wake until Start. Default idle timeout is 30 minutes, saved timeouts take precedence.
- Script and UI updates restart only the web server and preserve cluster state. Local changes or divergent history block updates.
- Setup/start/update preserve results and configuration. Teardown removes runtime, `--purge` additionally removes private results. Public results and settings remain.
- Uninstall uses `~/obgp-lab/installed.txt` to undo recorded changes. Never remove unowned or changed tools, unrelated containers, shared caches or packages that APT needs for other software. Keep results unless `--purge` is explicit. Old installations have incomplete host provenance.
- Helpers are in `scripts/internal/`, asset tools in `scripts/dev/`. Keep wrappers thin.

## Rules

- Discuss before coding: agree on files and commits first.
- English everywhere. Texts short and plain, no semicolons in prose.
- One experiment per question of the evaluation, listed in the README. `ifip-networking-2026`, its
  scenarios and topologies stay unchanged.
- Never pool modes. State n and the resolution (two sampling intervals) with every claim.
- The local machine is small: ask before any local run, `lab-smoke` at most. Large runs are started by
  the user on a server. Never run commands on remote hosts.
- Usage is paid: no polling loops, monitors or subagents unless asked, read only what is needed, short answers.
- Never move or rename files in `vis/`, it is linked from outside.
- No secrets, host names or addresses in the repo.
- Commit as agreed. Push the current branch only when asked.
- GitHub Actions: fast tests only, no minikube.
