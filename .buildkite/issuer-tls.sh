#!/usr/bin/env bash
set -euo pipefail
[[ "${BUILDKITE:-}" == true && "$(uname -s)-$(uname -m)" == Linux-x86_64 ]]
apt_command=(apt-get)
if [[ $(id -u) != 0 ]]; then apt_command=(sudo -n apt-get); fi
DEBIAN_FRONTEND=noninteractive "${apt_command[@]}" install -y --no-install-recommends libnss3-tools xvfb python3-pyatspi at-spi2-core dbus-x11
export PLAYWRIGHT_BROWSERS_PATH="$CASTALIA_CI_TOOLS/playwright"
node node_modules/playwright-core/cli.js install --with-deps chromium
export CASTALIA_EXTENSION_DIRECTORY="$PWD/build/castalia-wallet-browser-acceptance"
dbus-run-session -- xvfb-run -a node node_modules/tsx/dist/cli.mjs scripts/smoke-extension-independent-issuers.mts
