> Historical reference. The Wallet implementations described below were retired after `58d32a40559ffff0a9d99411f967b0889524c994`. See [the retirement boundary](wallet-application-adapter-retirement.md). These commands are not available in current Wallet packages. Historical bytes and evidence below are unchanged.

# Wallet SDK/Arena reconciliation evidence — 2026-10-02

## Locked-build follow-up

The build wrapper now runs `cargo metadata --locked --format-version 1` before
calling `wasm-pack build ... -- --locked`. This preflight is necessary with
wasm-pack 0.14.0: its metadata step can create or repair a lockfile before the
forwarded compilation flag is applied. The regression tests reproduced both
missing- and stale-lock mutations with the old wrapper, then confirmed that the
new wrapper rejects them without creating or rewriting `Cargo.lock` or producing
an artifact. Process-level tests also check command order, forwarded arguments
and preserved tool-launch diagnostics. Native CI tests and Clippy now use
`--locked`; the reviewed workflow checksum was updated for those two changes.

This follow-up preserves the public protocol commit, all dependency locks and the
existing Node 20.20.0 / Rust 1.85.1 / wasm-pack 0.14.0 pins. Verification used those
exact versions, locked wasm-bindgen 0.2.127, and Python 3.12.12:

| Check | Result |
| --- | --- |
| `node --test scripts/verify-ci-workflow.test.mjs` | 8 passed, including real Cargo missing/stale-lock failures |
| `npm test` | 190 passed, including 124 extension tests and actual WASM Work/Arena, custody and lifecycle cases |
| `cargo test --locked --workspace --all-targets` | 31 passed with Rust 1.85.1; offline cached dependencies |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Passed with Rust 1.85.1; offline cached dependencies |
| `npm run typecheck`, `npm run build`, `npm run validate:extension-package` | Passed |
| CI-fixture production packaging and strict inspection | Passed, 21 files; no production issuer or deployment |
| `python scripts/verify-custody-vector.py` | `CUSTODY_INTEROP_VECTOR_OK` with the four existing CI-pinned Python dependencies in a disposable environment |
| Persistent Chrome custody smoke | Passed with Chrome for Testing 153.0.8010.12: create, lock/unlock, encrypted export, restart and import retained the synthetic identity |
| `cargo fmt --all -- --check`, `git diff --check` | Passed |

Reproducibility evidence:

- `Cargo.lock` SHA-256: `a5f1f2c858765bf6fd5c24785a49771e57af2665081b46a442aadf9db96e423c`.
- `package-lock.json` SHA-256: `cd4969dba25ae37d3a9b4bd44d3e7901e6e510606a2be328ffbba4d593a69608`.
- Generated WASM SHA-256: `030bc19a5db611a9729e0390581a68624753da5dadcf5fa0c62403e6319511e8`, byte-identical to the previous candidate.
- Fixture-trust production content-tree SHA-256: `5a417a2fc37a5935d12b18f70ce0b316fbda9391a82d3156da70127ef7b2966f`.

The Chrome check used a new temporary profile and synthetic recovery data, which
the harness removed afterwards. This evidence does not replace installed native
host / live receiver qualification or production custody review. The prior paired
SDK artifact evidence below remains historical; that harness was not rerun for
this build-only change.

## Prior reconciliation evidence

Final runtime/test source commit: `2ef9e128aef78a9216c975cf37e263da356e6581`; the
paired-artifact qualification and persistent Chrome custody smoke ran with a clean
working tree. The subsequent evidence commit changes documentation only. The full
workspace matrix initially ran on `ab782a47dea27d2b6907512d7d9c55a5bd28d043`; after
production packaging was separated, all 124 extension tests were repeated.

## Reviewed sources and disposition

- Baseline: `castalia-wallet/main@f03a90e`.
- SDK/headless source: `205fae8`, including the common headless signer lineage once.
- Arena source: `ef58017`; its request rules moved into the public shared Devgraph
  protocol instead of restoring the removed copied Wallet parser.
- Public protocol pin: `59a0141cefb22f3a5084a13d12c44e1e22f36ab1`,
  [Devgraph PR #7](https://github.com/ZenithResearch/devgraph/pull/7).
- SDK consent/lifecycle semantics are preserved. The integration adds the public
  pin and Arena coverage across native, encrypted custody, presentation and actual
  WASM adapters. Compile-time guards exclude native SDK preview entry points from
  production packages; strict loopback issuer inspection remains unchanged. Hermes
  runtime changes are deferred.

## Checks

| Command | Result |
| --- | --- |
| `cargo +1.96.0 test --locked --offline -p castalia-wallet-devgraph-presentation --test presentation` | 4 passed |
| `cargo +1.96.0 test --locked --offline --workspace` | 31 passed |
| `cargo +1.85.1 clippy --locked --offline --workspace --all-targets -- -D warnings` | Passed with the CI Rust version |
| `npm test` | 186 passed; includes actual WASM signatures and denial/lifecycle checks |
| `npm run typecheck` | Passed |
| `npm run build` | Passed |
| `npm run validate:extension-package` | Passed |
| `cargo +1.96.0 fmt --all --check` and `git diff --check` | Passed |
| Paired SDK artifact harness | 9 lifecycle scenarios passed; 9 signatures verified; 48 synthetic native calls |
| Production package + strict inspection with an explicit CI-only HTTPS issuer | Passed; 21 files, no loopback endpoint or raw compiler modules |
| `npm run smoke:extension-custody` with an explicit installed Chromium executable | Passed in a disposable synthetic profile; encrypted export/restart/import retained identity |

JavaScript checks used Node 24.18.0. WASM was rebuilt with Rust 1.85.1,
wasm-pack 0.14.0 and locked wasm-bindgen 0.2.127. Build outputs stayed outside Git.
The immutable custody-v1 fixture and existing hybrid recovery identity tests
passed. Native raw-file recovery remains distinct from extension encrypted
recovery; neither is reinterpreted as a portable data vault.

## Paired artifact

The existing private `devgraph-web-0.1.0-preview.2.tgz` was used only as a local
synthetic qualification input; no SDK source or tarball is published by this PR.

- Candidate SHA-256: `097b4e3275cf282a25cee23dcf413898a85f41af9f8689873e007cf1e7200b6e`.
- Wallet WASM SHA-256: `030bc19a5db611a9729e0390581a68624753da5dadcf5fa0c62403e6319511e8`.
- Harness: `node --import ./node_modules/tsx/dist/loader.mjs apps/chrome-extension/test/devgraph-sdk-integration.mts --sdk-tarball <explicit-candidate.tgz> --output <local-evidence.json>`.

The harness loads both actual WASM runtimes, the provider and bundled content
script. Browser APIs and native endpoints are synthetic. It covers repeat reads,
fresh consent, expired authorization, cancellation with late responses, failed
reconnect and duplicate recovery, stale-port cleanup and disposal acknowledgement.
It preserves unknown execute outcomes without automatic mutation retries.

## Persistent Chrome custody

The final runtime commit passed the repository smoke using Google Chrome for
Testing 153.0.8010.12, selected with `CASTALIA_CHROMIUM_EXECUTABLE`. The smoke
created its own temporary extension copy and synthetic user profile, exercised
create/unlock and encrypted recovery export, closed and reopened the browser,
then imported and confirmed identity continuity. It did not use an existing user
profile, wallet or private key.

## Remaining external gates

The evidence above does not install a native host, provision a grant, exercise a
live receiver, deploy, or publish the private SDK. A real paired
Chrome/native/secS/receiver qualification remains required before enabling or
releasing the separate native preview feature. It does not block integrating
that source while the production package excludes the preview runtime and native
permissions. Protocol parsing support does not imply an Arena SDK UI or current
Arena grants.

The immutable public protocol pin remains
`59a0141cefb22f3a5084a13d12c44e1e22f36ab1`. Devgraph PR #7 was closed without
merging; its pinned commit is retained in the replacement
[Devgraph PR #10](https://github.com/ZenithResearch/devgraph/pull/10). Keep that
commit reachable during integration. Candidate source integration does not
establish final release pins or qualify a live native bridge.
