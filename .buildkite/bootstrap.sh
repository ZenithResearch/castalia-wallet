#!/usr/bin/env bash
# Sourced by verify.sh; downloads are checked before execution/extraction.
set -euo pipefail

[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  printf '%s\n' 'Buildkite bootstrap requires Linux x86_64.' >&2
  exit 1
}
: "${CASTALIA_CI_TOOLS:?verify.sh must allocate the temporary tools directory}"
readonly NODE_VERSION=20.20.0
readonly PYTHON_VERSION=3.12.15
readonly RUSTUP_VERSION=1.28.2
export RUSTUP_TOOLCHAIN=1.85.1
export CARGO_BUILD_JOBS=2
export CARGO_HOME="$CASTALIA_CI_TOOLS/cargo"
export RUSTUP_HOME="$CASTALIA_CI_TOOLS/rustup"
export PATH="$CASTALIA_CI_TOOLS/node/bin:$CASTALIA_CI_TOOLS/python/bin:$CARGO_HOME/bin:$PATH"

apt_command=(apt-get)
if [[ $(id -u) != 0 ]]; then apt_command=(sudo -n apt-get); fi
"${apt_command[@]}" update
DEBIAN_FRONTEND=noninteractive "${apt_command[@]}" install -y --no-install-recommends \
  build-essential ca-certificates curl git pkg-config xz-utils \
  libssl-dev zlib1g-dev libffi-dev libbz2-dev libreadline-dev \
  libsqlite3-dev liblzma-dev libncurses-dev uuid-dev

fetch_checked() {
  local url=$1 destination=$2 digest=$3
  curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --retry 3 --connect-timeout 30 --max-time 600 "$url" --output "$destination"
  printf '%s  %s\n' "$digest" "$destination" | sha256sum --check
}

fetch_checked "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-x64.tar.xz" \
  "$CASTALIA_CI_TOOLS/node.tar.xz" \
  4f48b52acf42130844a3a75e94da0e9629009d09e4101b2304895c24f3fbe609
mkdir "$CASTALIA_CI_TOOLS/node"
tar --extract --xz --file "$CASTALIA_CI_TOOLS/node.tar.xz" \
  --directory "$CASTALIA_CI_TOOLS/node" --strip-components=1

fetch_checked "https://static.rust-lang.org/rustup/archive/$RUSTUP_VERSION/x86_64-unknown-linux-gnu/rustup-init" \
  "$CASTALIA_CI_TOOLS/rustup-init" \
  20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
chmod 0755 "$CASTALIA_CI_TOOLS/rustup-init"
"$CASTALIA_CI_TOOLS/rustup-init" -y --no-modify-path --profile minimal --default-toolchain none
rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal \
  --component rustfmt --component clippy --target wasm32-unknown-unknown

fetch_checked 'https://github.com/wasm-bindgen/wasm-pack/releases/download/v0.14.0/wasm-pack-v0.14.0-x86_64-unknown-linux-musl.tar.gz' \
  "$CASTALIA_CI_TOOLS/wasm-pack.tar.gz" \
  278a8d668085821f4d1a637bd864f1713f872b0ae3a118c77562a308c0abfe8d
mkdir "$CASTALIA_CI_TOOLS/wasm-pack"
tar --extract --gzip --file "$CASTALIA_CI_TOOLS/wasm-pack.tar.gz" \
  --directory "$CASTALIA_CI_TOOLS/wasm-pack" --strip-components=1
install -m 0755 "$CASTALIA_CI_TOOLS/wasm-pack/wasm-pack" "$CARGO_HOME/bin/wasm-pack"

# Official release archives and their extracted executable hashes are both pinned.
fetch_checked 'https://github.com/wasm-bindgen/wasm-bindgen/releases/download/0.2.127/wasm-bindgen-0.2.127-x86_64-unknown-linux-musl.tar.gz' \
  "$CASTALIA_CI_TOOLS/bindgen.tar.gz" \
  61d4a7dc85acfa0d2354ccc0b8361928c7e52a746d17f28ebaa795ed3dc1614a
fetch_checked 'https://github.com/WebAssembly/binaryen/releases/download/version_117/binaryen-version_117-x86_64-linux.tar.gz' \
  "$CASTALIA_CI_TOOLS/binaryen.tar.gz" \
  3dc677006555b355ea2da5e82602065a161d5e83eaefd3f759afa00b96e83212
mkdir "$CASTALIA_CI_TOOLS/bindgen" "$CASTALIA_CI_TOOLS/binaryen" "$CASTALIA_CI_TOOLS/canonical-bin"
tar -xzf "$CASTALIA_CI_TOOLS/bindgen.tar.gz" -C "$CASTALIA_CI_TOOLS/bindgen" --strip-components=1
tar -xzf "$CASTALIA_CI_TOOLS/binaryen.tar.gz" -C "$CASTALIA_CI_TOOLS/binaryen" --strip-components=1
install -m 0755 "$CASTALIA_CI_TOOLS/bindgen/wasm-bindgen" "$CASTALIA_CI_TOOLS/canonical-bin/wasm-bindgen"
install -m 0755 "$CASTALIA_CI_TOOLS/binaryen/bin/wasm-opt" "$CASTALIA_CI_TOOLS/canonical-bin/wasm-opt"
export CASTALIA_CANONICAL_BIN="$CASTALIA_CI_TOOLS/canonical-bin"
export PATH="$CASTALIA_CANONICAL_BIN:$PATH"
printf '%s  %s\n' \
  f36dbe1938e78a79ce34d0ab3700907555161e293954f6f35bf6785a2f0cf916 "$CASTALIA_CANONICAL_BIN/wasm-bindgen" \
  621b5a984f16d0323ea7aa8b389ac9ccda0950ddee5de0e99292970129f571ed "$CASTALIA_CANONICAL_BIN/wasm-opt" | sha256sum --check

# The hosted image need not include Python3.12. Build the pinned official source
# without PGO/LTO; this is the independent vector verifier, not a product runtime.
fetch_checked "https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tar.xz" \
  "$CASTALIA_CI_TOOLS/python.tar.xz" \
  c2c4321961fab0fb999d66e0cecf521c2ab3994c7992873ea99e306c1094fd5a
mkdir "$CASTALIA_CI_TOOLS/python-source"
tar --extract --xz --file "$CASTALIA_CI_TOOLS/python.tar.xz" \
  --directory "$CASTALIA_CI_TOOLS/python-source" --strip-components=1
(
  cd "$CASTALIA_CI_TOOLS/python-source"
  ./configure --prefix="$CASTALIA_CI_TOOLS/python" --with-ensurepip=install
  make -j2
  make install
)
ln -s python3.12 "$CASTALIA_CI_TOOLS/python/bin/python"

[[ $(node --version) == v20.20.0 ]]
[[ $(python --version) == 'Python 3.12.15' ]]
[[ $(rustc --version) == 'rustc 1.85.1 '* ]]
[[ $(wasm-pack --version) == 'wasm-pack 0.14.0' ]]
