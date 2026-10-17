#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
: "${BUILDKITE_COMMIT:?Run this bootstrap from a Buildkite checkout}"
[[ $(git rev-parse HEAD) == "$BUILDKITE_COMMIT" ]]
[[ -z $(git status --porcelain) ]]
export CASTALIA_CI_TOOLS
CASTALIA_CI_TOOLS=$(mktemp -d "${TMPDIR:-/tmp}/castalia-wallet-buildkite.XXXXXXXX")
finish() {
  local result=$?
  # Preserve diagnostics for failed gates too. No profiles, keys or browser HOME.
  if ! tar -C build -czf build/wallet-qualification-evidence.tar.gz buildkite-verify; then result=1; fi
  rm -rf -- "$CASTALIA_CI_TOOLS"
  exit "$result"
}
trap finish EXIT
mkdir -p build/buildkite-verify
# Keep root keys, production issuer settings and native bridges out of this job.
unset CASTALIA_PRESENTATION_TRUST_PINS_JSON CASTALIA_ZENITH_MEMBERSHIP_ISSUER_URL \
  CASTALIA_ZENITH_MEMBERSHIP_ISSUER_KEY_ID CASTALIA_ZENITH_MEMBERSHIP_ISSUER_PUBLIC_KEY
export npm_config_audit=false
export npm_config_fund=false
# shellcheck source=.buildkite/bootstrap.sh
source .buildkite/bootstrap.sh > >(tee build/buildkite-verify/bootstrap.log) 2>&1
bash .buildkite/checks.sh
