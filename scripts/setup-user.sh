#!/bin/sh
# Prepares the lab for the current user on a shared Linux host, without sudo.
#
#   scripts/setup-user.sh            checks what the lab needs, changes nothing
#   scripts/setup-user.sh --install  also installs what is missing and starts the cluster
#
# On a host shared with others, LAB_CPUS and LAB_MEMORY_GB bound what the lab
# may take, e.g. LAB_CPUS=128 LAB_MEMORY_GB=512 scripts/setup-user.sh --install
#
# Run it from a checkout: git clone https://github.com/Stinktopf/gobgp.git && cd gobgp
#
# It installs only tools that are missing, only into ~/obgp-lab/bin, and lists
# everything it creates in ~/obgp-lab/installed.txt. scripts/teardown-user.sh
# removes exactly that, also the one marked PATH line it adds to ~/.bashrc.
# Docker, other containers, groups and kernel settings are never changed: on a
# shared host an admin runs scripts/allow-user.sh once.
set -eu

base="$HOME/obgp-lab"
bin="$base/bin"
log="$base/installed.txt"
repo="$(cd "$(dirname "$0")/.." && pwd)"
install=no
case "${1:-}" in
  --install) install=yes ;;
  "") ;;
  *) echo "usage: $0 [--install]" >&2; exit 2 ;;
esac
PATH="$bin:$PATH"
export PATH

missing=0
ok() { echo "  ok    $1"; }
bad() { echo "  MISSING $1"; printf '        %s\n' "$2"; missing=$((missing + 1)); }
info() { echo "  info  $1"; }

echo "== Check"
if [ "$(uname -s)" = Linux ]; then ok "Linux $(uname -m)"; else bad "Linux" "The lab runs on Linux only."; fi
for tool in git curl tar; do
  if command -v "$tool" >/dev/null; then ok "$tool"; else bad "$tool" "sudo apt-get install $tool"; fi
done
if docker info >/dev/null 2>&1; then
  ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
elif command -v docker >/dev/null; then
  bad "access to Docker" "sudo usermod -aG docker $USER, then log in again"
else
  bad "Docker" "https://docs.docker.com/engine/install/"
fi
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then ok "cgroup v2"; else bad "cgroup v2" "minikube limits CPUs and memory only with cgroup v2."; fi
instances="$(cat /proc/sys/fs/inotify/max_user_instances)"
watches="$(cat /proc/sys/fs/inotify/max_user_watches)"
if [ "$instances" -ge 1024 ] && [ "$watches" -ge 524288 ]; then
  ok "inotify ($instances instances, $watches watches)"
else
  bad "inotify for more than a few routers ($instances instances, $watches watches)" \
      "an admin: printf 'fs.inotify.max_user_instances = 8192\\nfs.inotify.max_user_watches = 1048576\\n' | sudo tee /etc/sysctl.d/90-obgp-lab.conf && sudo sysctl --system"
fi
if command -v ss >/dev/null && ss -ltnH 2>/dev/null | awk '{print $4}' | grep -q ':8443$'; then
  bad "port 8443 is taken" "serve the lab on a free port with lab serve --port"
else
  ok "port 8443 free"
fi
for tool in minikube kubectl helm uv; do
  if command -v "$tool" >/dev/null; then ok "$tool ($(command -v "$tool"))"; else info "$tool missing, --install puts it into $bin"; fi
done

echo "== Load"
threads="$(nproc)"
info "$threads threads, load $(cut -d' ' -f1-3 /proc/loadavg)"
info "$(awk '/MemAvailable/ {printf "%d GB memory available", $2 / 1048576}' /proc/meminfo)"
info "$(df -BG --output=avail "$HOME" | tail -1 | tr -d ' ') free in $HOME"
if command -v nvidia-smi >/dev/null; then
  nvidia-smi --query-gpu=name,utilization.gpu,memory.used --format=csv,noheader | while read -r gpu; do info "GPU $gpu"; done
fi
if docker info >/dev/null 2>&1; then info "$(docker ps -q | wc -l) containers running, the lab leaves them alone"; fi

if [ "$install" = no ]; then
  [ "$missing" -eq 0 ] && echo "All there. Install with: $0 --install" || echo "$missing missing, see above."
  exit 0
fi
[ "$missing" -eq 0 ] || { echo "Fix what is missing first." >&2; exit 1; }

echo "== Install into $base"
mkdir -p "$bin"
touch "$log"
# Lists a path or image once, so that teardown-user.sh removes it.
record() { grep -qxF "$1" "$log" || echo "$1" >> "$log"; }
# Directories the tools create in $HOME, if they were not there before.
for dir in "$HOME/.minikube" "$HOME/.kube" "$HOME/.cache/uv" "$HOME/.local/share/uv"; do
  [ -e "$dir" ] || record "dir $dir"
done
kicbase="gcr.io/k8s-minikube/kicbase"
[ -n "$(docker image ls -q "$kicbase")" ] || record "image $kicbase"

arch="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
fetch() { echo "  $2"; curl -fsSLo "$bin/$2" "$1"; chmod +x "$bin/$2"; record "file $bin/$2"; }
command -v minikube >/dev/null || fetch "https://storage.googleapis.com/minikube/releases/latest/minikube-linux-$arch" minikube
command -v kubectl >/dev/null || fetch "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/$arch/kubectl" kubectl
if ! command -v helm >/dev/null; then
  echo "  helm"
  curl -fsSL "https://get.helm.sh/helm-v3.22.0-linux-$arch.tar.gz" | tar -xzO "linux-$arch/helm" > "$bin/helm"
  chmod +x "$bin/helm"
  record "file $bin/helm"
fi
if ! command -v uv >/dev/null; then
  echo "  uv"
  curl -fsSL https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="$bin" UV_NO_MODIFY_PATH=1 sh >/dev/null
  record "file $bin/uv"
  record "file $bin/uvx"
fi
[ -e "$repo/.venv" ] || record "dir $repo/.venv"
(cd "$repo" && uv sync --quiet)

settings="${XDG_CONFIG_HOME:-$HOME/.config}/obgp-lab"
if [ -n "${LAB_CPUS:-}${LAB_MEMORY_GB:-}" ]; then
  [ -e "$settings" ] || record "dir $settings"
  mkdir -p "$settings"
  [ -e "$settings/host.yaml" ] || record "file $settings/host.yaml"
  { [ -z "${LAB_CPUS:-}" ] || echo "cpus: $LAB_CPUS"
    [ -z "${LAB_MEMORY_GB:-}" ] || echo "memory_mb: $((LAB_MEMORY_GB * 1024))"; } > "$settings/host.yaml"
  echo "  the lab may use: $(tr '\n' ' ' < "$settings/host.yaml")"
fi

# The tools on the PATH of later shells too, one marked line that teardown-user.sh removes.
if ! grep -q "# obgp-lab" "$HOME/.bashrc" 2>/dev/null; then
  echo "export PATH=\"$bin:\$PATH\"  # obgp-lab" >> "$HOME/.bashrc"
  record "line $HOME/.bashrc"
fi

echo "== Cluster"
# As large as the largest experiment needs, not as large as the host.
docker container inspect obgp-lab >/dev/null 2>&1 || record "minikube obgp-lab"
(cd "$repo" && uv run lab cluster)

# A password of one's own, asked once: other users of the host reach localhost too.
if [ ! -e "$settings/web.json" ] && [ -t 0 ]; then
  echo "== Password of the web interface"
  (cd "$repo" && uv run lab passwd)
fi

# The web interface, in a session of its own so that it outlives the login;
# started once, teardown-user.sh stops it.
# On a shared host (LAB_CPUS or LAB_MEMORY_GB given) with HTTPS on every address,
# reachable from its network, on the first free port from 8443; else on localhost.
echo "== Web interface"
pidfile="$base/serve.pid"
portfile="$base/serve.port"
address="$(hostname -I | cut -d' ' -f1)"
if [ -s "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
  echo "  runs already"
else
  if [ -n "${LAB_CPUS:-}${LAB_MEMORY_GB:-}" ]; then
    port=8443
    while ss -ltnH "sport = :$port" | grep -q .; do port=$((port + 1)); done
    args="--port $port"
  else
    port=8443
    args="--http"
  fi
  echo "$port" > "$portfile"
  record "file $portfile"
  # shellcheck disable=SC2086
  (cd "$repo" && setsid nohup "$(command -v uv)" run lab serve $args > "$base/serve.log" 2>&1 < /dev/null & echo $! > "$pidfile")
  record "process $pidfile"
  echo "  started, log in $base/serve.log"
fi
port="$(cat "$portfile" 2>/dev/null || echo 8443)"

if [ -n "${LAB_CPUS:-}${LAB_MEMORY_GB:-}" ]; then
  url="https://$address:$port"
  outside="ssh -L $port:localhost:$port $USER@$address, then https://localhost:$port"
else
  url="http://localhost:$port"
  outside="-"
fi
cat <<EOF
== Done
Web interface:         $url
Or through:            $outside
After a reboot:        $repo/scripts/setup-user.sh --install
Remove:                $repo/scripts/teardown-user.sh
EOF
