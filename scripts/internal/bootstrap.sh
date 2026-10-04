#!/bin/sh
# Internal: repair prerequisites and reuse the per-user tool installer.
set -eu
# Match the Python lifecycle styling before its environment is installed.
cyan='' green='' reset=''
if [ -t 1 ] && [ "${NO_COLOR+x}" != x ] && [ "${TERM:-}" != dumb ]; then
  cyan="$(printf '\033[1;36m')"
  green="$(printf '\033[32m')"
  reset="$(printf '\033[0m')"
fi
heading() { printf '\n%s› %s%s\n' "$cyan" "$1" "$reset"; }
info() { printf '  %s\n' "$1"; }
ok() { printf '  %s✓ %s%s\n' "$green" "$1" "$reset"; }
repo="$(cd "$(dirname "$0")/../.." && pwd)"
base="$HOME/obgp-lab"
bin="$base/bin"
log="$base/installed.txt"
PATH="$bin:$HOME/.local/bin:$PATH"
export PATH
[ "$(uname -s)" = Linux ] || { echo "The lab needs Linux (including a Linux VM on macOS/Windows)." >&2; exit 1; }
[ "$(id -u)" -ne 0 ] || { echo "Run setup as your normal user. It uses sudo where needed." >&2; exit 1; }
interactive=no
if [ -t 0 ] && [ "${OBGP_NONINTERACTIVE:-0}" != 1 ]; then interactive=yes; fi
as_root() {
  if [ "$interactive" = yes ]; then sudo "$@"; else sudo -n "$@"; fi
}
mkdir -p "$bin"
touch "$log"
record() { grep -qxF "$1" "$log" || echo "$1" >> "$log"; }
record_hash() { record "sha256 $(sha256sum "$1" | cut -d ' ' -f1) $1"; }
# Keep new uv downloads inside the installation, unless explicitly configured otherwise.
if [ -z "${UV_CACHE_DIR:-}" ]; then
  [ -e "$base/cache" ] || record "dir $base/cache"
  UV_CACHE_DIR="$base/cache/uv"; export UV_CACHE_DIR
fi
if [ -z "${UV_PYTHON_INSTALL_DIR:-}" ]; then
  [ -e "$base/python" ] || record "dir $base/python"
  UV_PYTHON_INSTALL_DIR="$base/python"; export UV_PYTHON_INSTALL_DIR
fi
heading "Host prerequisites"
packages=""
for tool in git curl tar openssl; do
  command -v "$tool" >/dev/null || packages="$packages $tool"
done
command -v docker >/dev/null || packages="$packages docker.io"
if [ -n "$packages" ]; then
  command -v apt-get >/dev/null || { echo "Install Docker, git, curl, tar and openssl with your distribution's package manager." >&2; exit 1; }
  as_root apt-get update -q
  dpkg-query -W -f='${binary:Package} ${Version} ${db:Status-Status}\n' | awk '$3 == "installed" {print $1}' > "$base/packages.before"
  # Package names above are fixed, not user input.
  status=0
  # shellcheck disable=SC2086
  as_root env DEBIAN_FRONTEND=noninteractive apt-get install --no-upgrade -y -o Dpkg::Options::=--force-confold $packages ca-certificates conntrack || status=$?
  dpkg-query -W -f='${binary:Package} ${Version} ${db:Status-Status}\n' > "$base/packages.after"
  awk 'FILENAME == ARGV[1] {old[$1]=1; next} $3 == "installed" && !($1 in old) {print "package " $1 " " $2}' "$base/packages.before" "$base/packages.after" >> "$log"
  rm -f "$base/packages.before" "$base/packages.after"
  [ "$status" -eq 0 ] || exit "$status"
fi
if ! docker info >/dev/null 2>&1; then
  info "Checking Docker daemon and permissions with sudo."
  if ! as_root docker info >/dev/null; then
    as_root systemctl start docker
    record "docker-started $(systemctl show docker --property=ActiveEnterTimestampMonotonic --value)"
  fi
  if ! docker info >/dev/null 2>&1; then
    member=no
    case " $(id -nG) " in *" docker "*) member=yes ;; esac
    as_root usermod -aG docker "$(id -un)"
    [ "$member" = yes ] || record "docker-group $(id -un)"
    # The entry point re-execs with refreshed supplementary groups.
    exit 76
  fi
fi
ok "Docker is accessible"
[ -f /sys/fs/cgroup/cgroup.controllers ] || { echo "Enable cgroup v2 before running the lab." >&2; exit 1; }
instances="$(cat /proc/sys/fs/inotify/max_user_instances)"
watches="$(cat /proc/sys/fs/inotify/max_user_watches)"
if [ "$instances" -lt 1024 ] || [ "$watches" -lt 524288 ]; then
  if ! grep -q '^inotify-before ' "$log"; then
    if [ -e /etc/sysctl.d/90-obgp-lab.conf ]; then
      cp /etc/sysctl.d/90-obgp-lab.conf "$base/inotify.before"
      record_hash "$base/inotify.before"
      record "inotify-existing"
    fi
    record "inotify-before $instances $watches"
  fi
  # Never lower limits set by the administrator of a shared host.
  [ "$instances" -ge 8192 ] || instances=8192
  [ "$watches" -ge 1048576 ] || watches=1048576
  printf 'fs.inotify.max_user_instances = %s\nfs.inotify.max_user_watches = %s\n' "$instances" "$watches" | as_root tee /etc/sysctl.d/90-obgp-lab.conf >/dev/null
  as_root sysctl -p /etc/sysctl.d/90-obgp-lab.conf
  record "inotify-after $instances $watches"
  record_hash /etc/sysctl.d/90-obgp-lab.conf
fi
ok "Kernel limits checked"
heading "Tools"
info "Missing tools will be installed into $bin"
arch="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
fetch() { echo "  $2"; curl -fsSLo "$bin/$2" "$1"; chmod +x "$bin/$2"; record "file $bin/$2"; record_hash "$bin/$2"; }
command -v minikube >/dev/null || fetch "https://storage.googleapis.com/minikube/releases/latest/minikube-linux-$arch" minikube
command -v kubectl >/dev/null || fetch "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/$arch/kubectl" kubectl
if ! command -v helm >/dev/null; then
  echo "  helm"
  curl -fsSL "https://get.helm.sh/helm-v3.22.0-linux-$arch.tar.gz" | tar -xzO "linux-$arch/helm" > "$bin/helm"
  chmod +x "$bin/helm"
  record "file $bin/helm"
  record_hash "$bin/helm"
fi
if ! command -v uv >/dev/null; then
  echo "  uv"
  curl -fsSL https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="$bin" UV_NO_MODIFY_PATH=1 sh >/dev/null
  record "file $bin/uv"
  record "file $bin/uvx"
  record_hash "$bin/uv"
  record_hash "$bin/uvx"
fi
for tool in minikube kubectl helm uv; do
  ok "$tool  $(command -v "$tool")"
done
[ -e "$repo/.venv" ] || record "dir $repo/.venv"
if [ ! -x "$repo/.venv/bin/python" ]; then
  heading "Python environment"
info "Downloading Python and dependencies if needed"
  (cd "$repo" && uv sync)
else
  ok "Python environment found"
  info "Dependencies will be checked after configuration"
fi
