# Wallet application-adapter retirement

This candidate removes obsolete Devgraph-specific code from Wallet. It builds on Wallet #30 (`58d32a40559ffff0a9d99411f967b0889524c994`), preserving the generic presentation v2 transcript, zero default trust, provider capabilities, Member Key derivation, custody, signing recovery, Files operations and membership formats.

## Ownership and compatibility

| Surface | Wallet candidate | Application migration owner |
| --- | --- | --- |
| `castalia.wallet.devgraph`, `requestDevgraphIssueCreatePresentation` | Removed from provider and types; raw requests fail as unknown methods | Devgraph client |
| `prepareDevgraphWork`, `signDevgraphWork`, `devgraphActorId` | Removed from native/WASM core exports | Devgraph canonical request construction and historical verification |
| `castalia-wallet-devgraph-issue-create-v1`, `castalia-wallet-devgraph-work-v1` | Dedicated crate and commands removed | Devgraph terminal/host integration |
| Native-host transport, SDK-preview route admission, application confirmation windows | Removed from browser source and packaging | Devgraph client/host integration |
| `presentCredential`, generic terminal signer | Retained unchanged, fresh approval required | Compatible browser/terminal applications |
| secS issuer/grants and receiver execution | No changes in this PR | secS and Devgraph |

This is deliberate entry-point retirement, not an envelope migration. There is no fallback from old methods to generic signatures. Clients must detect `credential_presentation_v2` and provide the separately versioned credential-bound request; issuer trust still requires explicit approval. Wallet does not execute application mutations or reconcile their dispatch status.

The replacement generic contract is qualified with independent synthetic applications. Installed Devgraph/secS migration acceptance remains owned by their migration/release process in a separate session. This PR neither claims that acceptance nor changes live installed services. Coordinate deployment only after that separate migration gate; no merge or deployment is authorized here.

## Preservation and provenance

The last retained implementation is immutable Wallet commit `58d32a40559ffff0a9d99411f967b0889524c994`. All branches, PR history and both local Git stores remain preserved. A verified private source backup precedes editing. The old source/tests can be recovered with Git at that revision; [removed paths and SHA-256 hashes](vectors/retired-application-signing/removed-paths.json) identify the retired files.

[Historical Work/Arena request and presentation vectors](vectors/retired-application-signing/provenance.json) were copied byte-for-byte from the retired crates into documentation. Existing [Issue v1 vectors](vectors/devgraph-issue-create-v1/README.md) are unchanged. No executable Wallet package imports these vectors or the old protocol crate. Their continued protocol verification/relocation belongs to Devgraph; this PR does not pretend to have moved private application code into a public repository.

Cargo.lock only removes the retired crates and protocol edge; remaining versions/checksums and the npm lockfile are unchanged. Application-neutral custody epoch notifications retain their behavior under generic internal names.

## Review and qualification

Source checks cover the entire browser source, core/provider types, Rust core and dependency manifests. Native/WASM tests retain generic credential vectors, custody/recovery, Files bindings and approval failures. New negative tests reject old provider methods even for an unlocked, approved caller and inspect actual WASM exports. Package inspection rejects obsolete adapter files, names and native messaging code even when their content digest is freshly generated.

Canonical builds remain Linux x86_64 with the reviewed Rust/Node/binding/optimizer pins. Loaded Chrome acceptance must use the exact canonical downloaded package; local test passes alone do not qualify it. Historical and new acceptance artifacts must be recorded separately. Installed-runtime and production release qualification remain separate gates.
