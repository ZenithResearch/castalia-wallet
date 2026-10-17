# Wallet Buildkite verification

`.buildkite/pipeline.yml` adds a native Buildkite lane for the existing portable
`Verify` gates. The GitHub workflows remain unchanged. The lane was introduced from
`3250a20e00dd2958a432206eaf2bdc09d7e2c381`. Its tool provisioning preserves custody,
membership and recovery contracts. The manual acceptance gate now also requires
the additive generic credential-presentation v2 surface described below.

The pipeline uses the existing `linux-small` queue (2 CPUs, 4 GiB) in the
`bananawalnut` organization. Configure its initial step as
`buildkite-agent pipeline upload .buildkite/pipeline.yml`. The agent checks out
source; `verify.sh` refuses a dirty checkout or a commit different from
`BUILDKITE_COMMIT`. Only Wallet repository access is needed. No issuer credentials,
real wallet files, native messaging bridge, deployment credentials, or production
GitHub environment is needed.

## Clean-worker tools

The [default hosted Linux image](https://buildkite.com/docs/agent/buildkite-hosted/linux)
is Ubuntu-based; preinstalled language versions are not trusted by this pipeline.
The bootstrap installs Ubuntu compiler/TLS/archive development prerequisites, then
checks each fixed download SHA-256 before extraction or execution:

| Tool | Version | Download SHA-256 |
| --- | --- | --- |
| Node, Linux x64 | 20.20.0 | `4f48b52acf42130844a3a75e94da0e9629009d09e4101b2304895c24f3fbe609` |
| rustup-init, Linux x64 | 1.28.2 | `20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c` |
| wasm-pack, Linux musl x64 | 0.14.0 | `278a8d668085821f4d1a637bd864f1713f872b0ae3a118c77562a308c0abfe8d` |
| CPython source | 3.12.15 | `c2c4321961fab0fb999d66e0cecf521c2ab3994c7992873ea99e306c1094fd5a` |

Node's digest comes from its [official release checksum list](https://nodejs.org/dist/v20.20.0/SHASUMS256.txt).
The rustup bootstrap uses its [versioned official checksum](https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init.sha256)
and installs Rust **1.85.1**, rustfmt, Clippy and `wasm32-unknown-unknown` through
Rust's toolchain distribution checks. wasm-pack retains the digest already checked
by GitHub Verify. Python pins the current security patch within the existing 3.12
series using the [official 3.12.15 source checksum](https://www.python.org/downloads/release/python-31215/),
then compiles without PGO/LTO using two jobs. There is no system Python replacement.

Tools and Python verification dependencies live in a per-job temporary directory
and are removed on exit. Cargo compilation is limited to two jobs. The Python
verification dependencies retain the exact existing GitHub Verify versions.
Ubuntu prerequisite packages and Python transitive dependencies retain their
upstream resolution behavior; this is not a hermetic operating-system image.
The checked npm/Cargo lockfiles are retained and verified unchanged at completion.
No vulnerability audit or blanket dependency upgrade is introduced.

## Gate and artifact parity

`checks.sh` runs the existing CI-policy and D0 contract tests, full Node suite
(including actual generated WASM tests), workspace types, extension build and
package validation, v3 fixture package/inspection, Rust formatting, locked native
tests, strict Clippy, and the independent Python custody vector verifier. It
stops immediately on failure. The extra Buildkite contract tests verify the
checksum rejection and runner failure behavior without provisioning tools locally.

Every command writes a separate log. Source revision, actual tool versions,
lockfile hashes and CI-source hashes are recorded in
`build/buildkite-verify/provenance.txt`. Buildkite retains these logs and the exact
inspected package plus its content-tree digest. It starts with zero trusted providers.

## Exact browser artifacts

`package:browser-acceptance-extension` verifies and copies the exact production bytes. Its provenance sidecar stays outside the package; neither issuer strings nor WASM bytes are rewritten. The source and acceptance content-tree digests must match.

Run custody, registration-v2, Files, generic credential-presentation and provider-profile smokes against that same package, using `CASTALIA_EXTENSION_DIRECTORY`. The generic smoke imports synthetic authority pins through Wallet settings. The provider-profile smoke imports two unrelated synthetic membership issuers through the same UI and requests the real Chrome optional host permission. Connection never enrolls. Registration v2 signs a proposal with no local eligibility claim; receiver verification remains mandatory.

Record source revision, package digest, browser version, fixture origins/keys and each result before and after testing. All fixtures use disposable browser profiles and test identities. An automated headed-browser result is distinct from a person's manual approval and native host-permission acceptance. The Buildkite manual block remains pending until its required evidence is supplied; portable CI does not clear it.

No deploy, publication, merge, live issuer, real wallet, Sia or installed native service is exercised by this pipeline. Source rights and release qualification remain independent.
