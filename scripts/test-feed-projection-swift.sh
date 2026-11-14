#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo 'Usage: bash scripts/test-feed-projection-swift.sh /absolute/libcastalia_wallet_native.a /absolute/test-output-directory' >&2
  exit 2
fi
root="$(cd "$(dirname "$0")/.." && pwd)"
library="$1"
output="$2"
case "$library" in /*) ;; *) echo 'Library path must be absolute' >&2; exit 2;; esac
case "$output" in /*) ;; *) echo 'Output path must be absolute' >&2; exit 2;; esac
test -f "$library"
mkdir -p "$output" "$root/target/swift-feed-projection-module-cache"
swiftc -module-cache-path "$root/target/swift-feed-projection-module-cache" \
  -I "$root/crates/castalia-wallet-native/include" \
  "$root/tests/native/FeedProjectionSmoke.swift" "$library" \
  -framework Security -o "$output/feed-projection-swift"
"$output/feed-projection-swift" "$root/contracts/feeds/v1/projection-conformance.json"
