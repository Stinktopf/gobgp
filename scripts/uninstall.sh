#!/bin/sh
set -eu
repo="$(cd "$(dirname "$0")/.." && pwd)"
if [ -x "$repo/.venv/bin/python" ]; then
  exec "$(dirname "$0")/internal/lifecycle.sh" uninstall "$@"
fi
cd "$repo"
exec python3 -m lab.uninstall "$@"
