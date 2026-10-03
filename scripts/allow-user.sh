#!/bin/sh
# For an admin of a shared host, once: lets a user run the lab. Adds the user
# to the docker group and raises the inotify limits minikube needs, in one file
# under /etc/sysctl.d. Nothing else on the host changes.
#
#   sudo scripts/allow-user.sh <user>          allows
#   sudo scripts/allow-user.sh <user> --undo   takes both back
set -eu

conf=/etc/sysctl.d/90-obgp-lab.conf
user="${1:-}"
[ -n "$user" ] || { echo "usage: sudo $0 <user> [--undo]" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "Run it with sudo." >&2; exit 1; }
id "$user" >/dev/null 2>&1 || { echo "No user $user." >&2; exit 1; }

if [ "${2:-}" = "--undo" ]; then
  gpasswd -d "$user" docker >/dev/null 2>&1 || true
  rm -f "$conf"
  sysctl --system >/dev/null
  echo "$user is no longer in the docker group, the limits are as before."
  exit 0
fi

getent group docker >/dev/null || { echo "Docker is not installed: install it first." >&2; exit 1; }
usermod -aG docker "$user"
printf 'fs.inotify.max_user_instances = 8192\nfs.inotify.max_user_watches = 1048576\n' > "$conf"
sysctl --system >/dev/null
echo "Done. $user logs in again, then runs scripts/setup-user.sh --install."
