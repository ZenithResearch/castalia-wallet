#!/usr/bin/env bash
# Keep the same gates as .github/workflows/verify.yml. No deploy or live issuer.
set -euo pipefail
mkdir -p build/buildkite-verify
run() {
  local name=$1
  shift
  printf '\n--- %s\n' "$name"
  "$@" 2>&1 | tee "build/buildkite-verify/$name.log"
}
archive_digest() {
  sha256sum "$1" | tee "$1.sha256"
}
{
  git rev-parse HEAD
  node --version
  npm --version
  rustc --version
  cargo --version
  wasm-pack --version
  python --version
  wasm-bindgen --version
  wasm-opt --version
  sha256sum "$CASTALIA_CANONICAL_BIN/wasm-bindgen" "$CASTALIA_CANONICAL_BIN/wasm-opt"
  sha256sum Cargo.lock package-lock.json .github/workflows/verify.yml .buildkite/*.sh .buildkite/pipeline.yml
} > build/buildkite-verify/provenance.txt
run dependencies npm ci --no-audit --no-fund
run ci-policy node --test scripts/verify-ci-workflow.test.mjs scripts/verify-buildkite.test.mjs
run membership-contract node --test scripts/verify-d0-contract.test.mjs
run node-tests npm test
run types npm run typecheck
run packages npm run build
run extension-validation npm run validate:extension-package
export CASTALIA_EXTENSION_OUTPUT=build/castalia-wallet-v3-ci-contract
run fixture-package npm run package:production-extension
run fixture-inspection npm run inspect:production-extension
run reproduction node scripts/reproduce-extension.mjs
run browser-acceptance-package npm run package:browser-acceptance-extension
run acceptance-archive tar -C build -czf build/castalia-wallet-browser-acceptance.tar.gz \
  castalia-wallet-v3-ci-contract castalia-wallet-v3-ci-contract.contents.sha256 \
  castalia-wallet-browser-acceptance castalia-wallet-browser-acceptance.contents.sha256 castalia-wallet-browser-acceptance.provenance.json
run acceptance-archive-digest archive_digest \
  build/castalia-wallet-browser-acceptance.tar.gz
run independent-issuer-tls bash .buildkite/issuer-tls.sh
run exact-package-chrome bash .buildkite/exact-browser.sh
run rust-format cargo fmt --all -- --check
run native-tests cargo test --locked --workspace --all-targets
run clippy cargo clippy --locked --workspace --all-targets -- -D warnings
run vector-dependencies python -m pip install --disable-pip-version-check \
  'blake3==1.0.8' 'argon2-cffi==25.1.0' 'cryptography==46.0.5' 'rfc8785==0.1.4'
run custody-vector python scripts/verify-custody-vector.py
run retained-source git diff --exit-code
printf '%s\n' 'Portable checks passed. Loaded Chrome custody acceptance remains a separate manual gate.'
