#!/bin/sh
# Screenshots of every page and tab at phone and desktop width, in light and
# dark, for work on the layout. Starts a web server of its own with settings
# of its own. Local only. Usage: screens.sh [directory] [page filter or /path]
# CHROMIUM may name a Chromium to use instead of Playwright's own.
set -eu
repo="$(cd "$(dirname "$0")/../.." && pwd)"
if [ -z "${CHROMIUM:-}" ]; then
  uv run --project "$repo" --with playwright playwright install chromium >/dev/null
fi
exec uv run --project "$repo" --with playwright python "$repo/scripts/dev/screens.py" "$@"
