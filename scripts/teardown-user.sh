#!/bin/sh
# Removes what scripts/setup-user.sh created, and nothing else.
#
#   scripts/teardown-user.sh          removes the cluster and the tools, keeps the checkout and its results
#   scripts/teardown-user.sh --purge  also removes ~/obgp-lab with the checkout and its results
#
# Docker, other containers and images, groups and kernel settings stay as
# they are.
set -eu

base="$HOME/obgp-lab"
log="$base/installed.txt"
purge=no
case "${1:-}" in
  --purge) purge=yes ;;
  "") ;;
  *) echo "usage: $0 [--purge]" >&2; exit 2 ;;
esac
PATH="$base/bin:$PATH"
[ -f "$log" ] || { echo "no $log: setup-user.sh installed nothing here" >&2; exit 1; }

if [ "$purge" = yes ]; then
  printf "Delete %s with all its results? [y/N] " "$base"
  read -r answer
  [ "$answer" = y ] || exit 1
fi

# The newest entries first, so that the cluster goes before its tools.
tac "$log" | while read -r kind what; do
  case "$kind" in
    minikube) echo "  cluster $what"; minikube delete -p "$what" >/dev/null 2>&1 || true ;;
    image) echo "  image $what"; docker image ls -q "$what" | sort -u | xargs -r docker image rm >/dev/null 2>&1 || true ;;
    file) echo "  $what"; rm -f "$what" ;;
    dir) echo "  $what"; rm -rf "$what" ;;
    line) echo "  the PATH line in $what"; sed -i '/# obgp-lab$/d' "$what" ;;
    process) echo "  the web interface"; [ -s "$what" ] && { kill -- "-$(cat "$what")" 2>/dev/null || kill "$(cat "$what")" 2>/dev/null; }; rm -f "$what" ;;
  esac
done
rm -f "$log"
rmdir "$base/bin" 2>/dev/null || true

if [ "$purge" = yes ]; then
  rm -rf "$base"
  echo "All removed."
else
  echo "Removed. The checkout and its results stay in $base."
fi
