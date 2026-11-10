#!/bin/sh
# The lab's command line with the uv that setup installed, e.g. ./lab.sh ls or ./lab.sh summary <result>.
set -eu
repo="$(cd "$(dirname "$0")/.." && pwd)"
PATH="$HOME/obgp-lab/bin:$HOME/.local/bin:$PATH"
export PATH
exec uv run --project "$repo" lab "$@"
