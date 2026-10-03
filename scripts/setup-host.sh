#!/bin/sh
# Prepares an Ubuntu host to run the lab and its web interface.
#
#   sudo scripts/setup-host.sh [user]
#
# Installs Docker, minikube, kubectl, Helm and uv, adds the user (default:
# lab) to the docker group, checks out the branch $BRANCH (default:
# master) of $REPO (default: GitHub) in its home, and installs the web
# interface as the systemd service obgp-lab on port 8443, with a random
# initial password it prints at the end. It starts the minikube cluster as
# large as the largest experiment needs and the host allows, so that it
# serves every experiment. Running it again updates the tools and the
# service; the checkout and the cluster are left as they are.
# scripts/teardown-host.sh undoes it.
set -eu

user="${1:-lab}"
branch="${BRANCH:-master}"
repo_url="${REPO:-https://github.com/Stinktopf/gobgp.git}"

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
command -v apt-get >/dev/null || { echo "needs Ubuntu or Debian" >&2; exit 1; }
arch="$(dpkg --print-architecture)"

echo "== packages"
apt-get update -q
apt-get install -yq docker.io git curl openssl ca-certificates conntrack
systemctl enable --now docker

echo "== minikube, kubectl, helm, uv"
curl -fsSLo /usr/local/bin/minikube "https://storage.googleapis.com/minikube/releases/latest/minikube-linux-$arch"
chmod +x /usr/local/bin/minikube
kube="$(curl -fsSL https://dl.k8s.io/release/stable.txt)"
curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/$kube/bin/linux/$arch/kubectl"
chmod +x /usr/local/bin/kubectl
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | DESIRED_VERSION=v3.22.0 bash
curl -fsSL https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh

echo "== kernel limits for many pods"
# Every router pod watches files; the defaults run out beyond a few dozen pods.
cat > /etc/sysctl.d/90-obgp-lab.conf <<EOF
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 1048576
EOF
sysctl --system >/dev/null

echo "== user $user"
id "$user" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$user"
usermod -aG docker "$user"
home="$(getent passwd "$user" | cut -d: -f6)"
dir="$home/obgp"
[ -d "$dir/.git" ] || sudo -u "$user" git clone --branch "$branch" "$repo_url" "$dir"
sudo -u "$user" sh -c "cd '$dir' && uv sync --quiet"

echo "== minikube cluster obgp-lab"
sudo -u "$user" -H sh -c "cd '$dir' && uv run lab cluster"

echo "== service obgp-lab"
cat > /etc/systemd/system/obgp-lab.service <<EOF
[Unit]
Description=OBGP Lab web interface
After=network-online.target docker.service
Wants=network-online.target

[Service]
User=$user
WorkingDirectory=$dir
ExecStart=/usr/local/bin/uv run lab serve --host 0.0.0.0 --port 8443
Restart=on-failure
# Experiments run in their own process and survive restarts of the service.
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable obgp-lab
systemctl restart obgp-lab

# The first start sets a random password, to be changed at the first sign-in.
initial="$home/.config/obgp-lab/initial-password"
for _ in $(seq 30); do [ -f "$initial" ] && break; sleep 1; done

echo
echo "Done. Open https://$(hostname -f):8443 and accept its self-signed certificate."
if [ -f "$initial" ]; then
  echo "Initial password: $(cat "$initial")"
fi
echo
echo "Next, optionally:"
echo "  sudo -iu $user sh -c 'cd obgp && uv run lab check experiments/ifip-networking-2026.yaml'"
echo "  sudo -iu $user sh -c 'cd obgp && uv run lab notify --discord <webhook URL>'"
