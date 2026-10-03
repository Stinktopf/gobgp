#!/bin/sh
# Undoes scripts/setup-host.sh.
#
#   sudo scripts/teardown-host.sh [--purge] [--tools] [--yes] [user]
#
# Stops the web interface and any running experiment of the user (default:
# lab), deletes the minikube cluster and removes the service and the kernel
# limits. The checkout with its results stays, unless --purge is given,
# which also deletes the user with its home: the checkout, the private
# results and the settings. --tools also removes minikube, kubectl, Helm
# and uv from /usr/local/bin; Docker stays, as other software may use it.
# --yes skips the question before --purge.
set -eu

purge=no tools=no yes=no user=lab
for arg in "$@"; do
  case "$arg" in
    --purge) purge=yes ;;
    --tools) tools=yes ;;
    --yes) yes=yes ;;
    -*) echo "unknown option $arg" >&2; exit 2 ;;
    *) user="$arg" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
exists() { id "$user" >/dev/null 2>&1; }
as_user() { sudo -u "$user" -H sh -c "$1"; }

if [ "$purge" = yes ] && [ "$yes" = no ]; then
  home="$(getent passwd "$user" | cut -d: -f6 || true)"
  printf 'Delete the user %s and %s, with every private result? Type the user name: ' "$user" "${home:-its home}"
  read -r answer
  [ "$answer" = "$user" ] || { echo "nothing done" >&2; exit 1; }
fi

echo "== service obgp-lab"
if command -v systemctl >/dev/null && [ -f /etc/systemd/system/obgp-lab.service ]; then
  systemctl disable --now obgp-lab || true
  rm -f /etc/systemd/system/obgp-lab.service
  systemctl daemon-reload
fi

echo "== running experiments"
# The service leaves them running on purpose (KillMode=process); they stop
# at their next step, which keeps their results consistent.
if exists && pkill -TERM -u "$user" -f "lab(\.cli)? (run|resume)"; then
  for _ in $(seq 30); do
    pgrep -u "$user" -f "lab(\.cli)? (run|resume)" >/dev/null || break
    sleep 2
  done
  pkill -KILL -u "$user" -f "lab(\.cli)? (run|resume)" || true
fi

echo "== minikube cluster obgp-lab"
if exists && command -v minikube >/dev/null; then
  as_user "minikube delete -p obgp-lab" || true
  as_user "rm -f \"\${MINIKUBE_HOME:-\$HOME/.minikube}/obgp-lab.lab.lock\"" || true
fi

echo "== kernel limits"
if [ -f /etc/sysctl.d/90-obgp-lab.conf ]; then
  rm -f /etc/sysctl.d/90-obgp-lab.conf
  sysctl --system >/dev/null || echo "  sysctl could not reload; the limits end with the next boot"
fi

if [ "$purge" = yes ] && exists; then
  echo "== user $user"
  pkill -KILL -u "$user" || true
  userdel --remove "$user" 2>/dev/null || userdel "$user"
fi

if [ "$tools" = yes ]; then
  echo "== minikube, kubectl, helm, uv"
  rm -f /usr/local/bin/minikube /usr/local/bin/kubectl /usr/local/bin/helm /usr/local/bin/uv /usr/local/bin/uvx
fi

echo
if [ "$purge" = yes ]; then
  echo "Done. The lab is gone from this host."
else
  echo "Done. The checkout and its results are kept; --purge deletes them with the user $user."
fi
