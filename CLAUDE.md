# OBGP

GoBGP fork with OBGP (oscillation-free BGP) and a lab that measures it.

## Map

- `internal/pkg/table/opera.go`: OBGP itself. Switched on by `GOBGP_OPERA_ENABLED`, pruning off by
  `GOBGP_OPERA_PRUNING=false`.
- `lab/`: the lab in Python, `uv run lab …`.
  - `cli.py` commands, `runner.py` runs, `cluster.py` minikube, Helm and what fits the host, `host.py` host load
  - `scenario.py` steps, `topology.py`, `modes.py`
  - `analysis.py` metrics (bump `VERSION` when they change), `results.py`, `estimate.py`, `calibration.py`
  - `caida.py`, `prefixes.py`, `mrt.py`, `rib.py`, `sndlib.py`: Internet data
  - `generate.py`: generated topologies (Erdős–Rényi, Watts–Strogatz, Barabási–Albert, Waxman, Elmokashfi)
  - `notify.py` Discord, `update.py` updates from GitHub, `wrapped.py` Wrapped, `web/` FastAPI, Jinja2, htmx, Tailwind
- `controller/app.py`: beside gobgpd in every router pod, samples and executes steps.
- `gobgp-lab/` Helm chart and topologies, `experiments/`, `scenarios/`.
- `results/`: large, do not read. Use `uv run lab ls` and `uv run lab summary <result>`.

## Commands

- Tests: `uv run --group dev pytest -q`, `go test ./internal/pkg/table/`
- CSS after template changes: `scripts/build-css.sh`
- Web: `uv run lab serve --http`. Templates reload, Python changes need a restart.

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
