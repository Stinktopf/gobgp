#!/bin/sh
# First install, repair and configuration, for the current checkout and user.
set -eu
repo="$(cd "$(dirname "$0")/.." && pwd)"
PATH="$HOME/obgp-lab/bin:$HOME/.local/bin:$PATH"
export PATH
for arg in "$@"; do
  case "$arg" in
    --non-interactive) OBGP_NONINTERACTIVE=1; export OBGP_NONINTERACTIVE ;;
    --help|-h) exec "$repo/scripts/internal/lifecycle.sh" setup "$@" ;;
  esac
done
status=0
"$repo/scripts/internal/bootstrap.sh" || status=$?
if [ "$status" -eq 76 ] && [ "${OBGP_GROUP_REFRESHED:-0}" != 1 ]; then
  if [ -t 0 ] && [ "${OBGP_NONINTERACTIVE:-0}" != 1 ]; then
    exec sudo -u "$(id -un)" env OBGP_GROUP_REFRESHED=1 PATH="$PATH" LAB_CPUS="${LAB_CPUS:-}" LAB_MEMORY_GB="${LAB_MEMORY_GB:-}" XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}" "$repo/scripts/setup.sh" "$@"
  else
    exec sudo -n -u "$(id -un)" env OBGP_GROUP_REFRESHED=1 PATH="$PATH" LAB_CPUS="${LAB_CPUS:-}" LAB_MEMORY_GB="${LAB_MEMORY_GB:-}" XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}" "$repo/scripts/setup.sh" "$@"
  fi
fi
[ "$status" -eq 0 ] || exit "$status"
exec "$repo/scripts/internal/lifecycle.sh" setup "$@"
