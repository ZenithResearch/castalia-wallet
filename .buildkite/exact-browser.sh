#!/usr/bin/env bash
set -euo pipefail
[[ "${BUILDKITE:-}" == true && "$(uname -s)-$(uname -m)" == Linux-x86_64 ]]
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p build/qualification-input "$work/current" "$work/main8"
cp build/castalia-wallet-browser-acceptance.tar.gz build/qualification-input/current.tar.gz
expected=$(sha256sum build/qualification-input/current.tar.gz | cut -d ' ' -f1)
buildkite-agent artifact upload build/qualification-input/current.tar.gz
buildkite-agent artifact download build/qualification-input/current.tar.gz "$work/current/" --build "$BUILDKITE_BUILD_ID" --step "$BUILDKITE_JOB_ID"
buildkite-agent artifact download build/castalia-wallet-browser-acceptance.tar.gz "$work/main8/" --build 01a10543-49f1-4107-98c0-0e4b1b668354 --step 01a10543-6768-4552-bcb6-c1cc0f6762bb
python3 scripts/restore-qualification-archive.py "$work/current/build/qualification-input/current.tar.gz" "$expected" "$work/candidate"
python3 scripts/restore-qualification-archive.py "$work/main8/build/castalia-wallet-browser-acceptance.tar.gz" 7bae0541ee74e15d5e10048757e90243c79d0c4560504edd5f6842b236c0083d "$work/baseline"
export CASTALIA_EXTENSION_DIRECTORY="$work/candidate/castalia-wallet-browser-acceptance"
export PLAYWRIGHT_BROWSERS_PATH="$CASTALIA_CI_TOOLS/playwright"
export CASTALIA_NATIVE_PERMISSION_TEST=1 ACCESSIBILITY_ENABLED=1 NO_AT_BRIDGE=0
node scripts/check-browser-artifact.mjs "$expected"
for journey in custody registration files credential-presentation provider-profiles; do
  dbus-run-session -- xvfb-run -a node node_modules/tsx/dist/cli.mjs "scripts/smoke-extension-$journey.mts" 2>&1 | tee "build/buildkite-verify/chrome-$journey.log"
done
export CASTALIA_UPGRADE_BASELINE="$work/baseline/castalia-wallet-v3-ci-contract"
dbus-run-session -- xvfb-run -a node node_modules/tsx/dist/cli.mjs scripts/smoke-extension-upgrade.mts 2>&1 | tee build/buildkite-verify/chrome-upgrade-production.log
export CASTALIA_UPGRADE_BASELINE="$work/baseline/castalia-wallet-browser-acceptance" CASTALIA_UPGRADE_LEGACY=1
dbus-run-session -- xvfb-run -a node node_modules/tsx/dist/cli.mjs scripts/smoke-extension-upgrade.mts 2>&1 | tee build/buildkite-verify/chrome-upgrade-legacy.log
node scripts/check-browser-artifact.mjs "$expected"
