# Shared recovery session and native preview

The native Zenith iOS app and public Castalia Web use `castalia-wallet-core::recovery_session::RecoverySession`. The core and presentation crates are MIT licensed. The native C ABI is a host integration boundary; these operations are not application provider capabilities and do not change the generic presentation signing contract or desktop extension UI.

## Compatibility inventory

| Contract | Source/consumers | Compatibility |
| --- | --- | --- |
| `castalia.wallet-custody.v1` and legacy recovery input | Existing Wallet core and Web WASM | Frozen encryption, derivation, signature bytes; no automatic raw-key return in new Web creation |
| `castalia.castaway.v1` / contents v1 | Pinned public Web TypeScript in `contracts/portable-web`, shared Rust portable module | Identity, v3 proofs, v4 scoped proofs, descriptor-only accounts; no unknown sections or authority |
| v3/v4 membership | Pinned public contracts, Rust, Devgraph receiver | Existing ordered transcripts preserved; public fixtures use disposable keys |
| `castalia.wallet-local.v1` | Rust encrypted session; native SQLite and Web IndexedDB | New local-only snapshot; not a portable file; trust and read credentials never exported |
| Native ABI 1 | `castalia-wallet-native/include/CastaliaWallet.h` | Opaque owned session/result handles, bounded JSON; hosts must check ABI and free results |
| `castalia.read-access-challenge.v1` | Rust internal signer, Devgraph-owned adapter | New domain-separated exact challenge approval; no generic arbitrary-sign entrypoint |

Pinned Web provenance contains its upstream revision and exact SHA-256 source hashes. `scripts/portable-contracts.test.mjs` checks those pins. Rust portable tests consume the frozen v3 vector and a disposable v4 vector independently verified by public TypeScript and Python. No new fixture contains private signing keys.

## Transaction protocol

1. Create a session and `observe` the encrypted stored snapshot, or unlock it. Empty and existing stores are distinct.
2. `prepare_create`, `prepare_restore`, `prepare_legacy`, `prepare_data`, `prepare_trust`, and `verify_backup` validate before returning an opaque token and public preview. A new preparation invalidates the old one even if it fails. Prepared data remains in memory.
3. After member confirmation, `commit_candidate` requires the token and expected revision and returns the complete encrypted snapshot. The host atomically compares current storage against the expected old state and writes the candidate.
4. Only after durable completion, `confirm_commit` accepts the exact token/snapshot bytes and installs the candidate session. On cancellation, storage failure, stale state or navigation, cancel/free the candidate. If storage committed just before a lock, unlock the committed record; never retry a speculative partial write.

Native hosts serialize calls and use an immediate lifecycle cancellation gate. Web keeps the session in a worker, aborts in-flight IndexedDB transactions and fences queued messages. Freeing a session drops custody and zeroizing buffers; platform string copies cannot promise universal memory erasure. No request, file, password, root, or credential should be logged.

`prepare_existing` is a **host-only** migration of an already stored encrypted Web wallet. The worker reads legacy confirmation from its own record; it is never page-controlled input. `prepare_data.previous_contents` is the worker's current decrypted/validated portable projection, used to reconcile existing sealed profile/proof sections before staging a merge. Neither command is exposed through the Wallet application provider.

## Recovery and trust

New passwords require 12 characters. Existing valid backup passwords remain accepted. Encrypted-file restore sets tested-backup metadata; legacy raw-key restore does not. New-wallet membership/read-approval signing is denied until verification. Existing confirmed Web wallets remain eligible but untested. A file cannot replace an installed identity, install issuer trust, activate a proof, or reinstate Work access.

Trust policies are separately approved. Unknown sections, malformed or duplicate fields, mismatched identities/descriptors, invalid signatures and untrusted scopes fail the whole import. Existing omitted proofs are preserved; replaced proofs/profile are disclosed. Reapproving identical trust preserves existing access; changing trust invalidates active membership and read authority.

## Native read access

Wallet remains application-neutral: `approve_read_access` checks schema, own identity/installation, HTTPS origin, expiry and nonce, and signs the complete JCS request with domain `castalia/read-access-approval/v1\0`. Application details are included in the signed disclosure. The native Devgraph client validates its narrower scope/result contract; the receiver checks membership, proof of possession, policy, replay and grant limits.

Only an approved request can stage a matching returned credential. The host stores the complete encrypted snapshot after its result validation. `read_access` only returns a credential for the exact origin before expiry; `forget_read_access` removes it. Portable data/recovery exports omit installation identifiers and access credentials. No mutation signing path is added.

## Verification and remaining gates

Run `cargo fmt --all -- --check`, `cargo test --workspace --locked --offline`, `npm test`, and `npm run typecheck`. Build `castalia-wallet-native` for all XCFramework targets. The `recovery_contract_driver` example is a bounded test helper used by Devgraph's disposable cross-language suite, not a packaged signer or unattended approval substitute.

Source tests and Simulator launch do not qualify physical-device Files interactions, accessibility, or custody security. Exact-artifact iPhone qualification and usability review remain required. No production activation, extension interface replacement, identity switching, key rotation, grant expansion, or change to existing generic Wallet consent is included.
