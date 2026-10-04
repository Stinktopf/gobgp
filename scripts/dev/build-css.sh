#!/bin/sh
# Builds lab/web/static/app.css from lab/web/styles.css with the standalone
# Tailwind CLI, which is downloaded once. Needed when the styles or the
# classes in templates and scripts change; CI checks that it is current.
set -eu
version=v4.3.3
bin="${XDG_CACHE_HOME:-$HOME/.cache}/obgp-lab/tailwindcss-$version"
if [ ! -x "$bin" ]; then
  mkdir -p "$(dirname "$bin")"
  curl -fsSL -o "$bin" "https://github.com/tailwindlabs/tailwindcss/releases/download/$version/tailwindcss-linux-x64"
  chmod +x "$bin"
fi
cd "$(dirname "$0")/../../lab/web"
"$bin" -i styles.css -o static/app.css --minify "$@"
