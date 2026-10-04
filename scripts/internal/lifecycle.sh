#!/bin/sh
# Internal dispatcher. No dependency/network work during start, stop or teardown.
set -eu
repo="$(cd "$(dirname "$0")/../.." && pwd)"
PATH="$HOME/obgp-lab/bin:$HOME/.local/bin:$PATH"
export PATH
UV_CACHE_DIR="${UV_CACHE_DIR:-$HOME/obgp-lab/cache/uv}"
UV_PYTHON_INSTALL_DIR="${UV_PYTHON_INSTALL_DIR:-$HOME/obgp-lab/python}"
export UV_CACHE_DIR UV_PYTHON_INSTALL_DIR
cd "$repo"
[ -x .venv/bin/python ] || { echo "Run scripts/setup.sh first." >&2; exit 1; }
exec .venv/bin/python -m lab.lifecycle "$@"
