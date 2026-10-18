#!/bin/sh
set -eu
exec "$(dirname "$0")/internal/lifecycle.sh" teardown "$@"
