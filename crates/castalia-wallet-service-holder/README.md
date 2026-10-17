# Opt-in native service-holder preparation

This standalone Rust package validates public owner configuration and audience-bound Runtime/Service challenges. It implements [owner-private raw32 service custody](custody.md) and a bounded `ServiceIdentityHandle::present_current_service_challenge` source operation. The operation derives configuration and time from actual CURRENT-bound custody under one retained shared lease, signs only the frozen holder transcript, reloads exact state/configuration and checks the final original window before returning a compact proof. It does not independently qualify Native evidence, issue a context or activate installed authority. Legacy preparation/presentation methods accepting caller owner configuration or time remain denied.

The generic Wallet workspace remains unchanged apart from explicit exclusions. Its human presentation, browser/native ABI, member encrypted custody and exact `url = 2.5.2` dependency remain independent. This package uses the reviewed native source's exact `url = 2.5.8` in its own lock. `default-members` or an optional feature would not separate Cargo lock resolution; this package is deliberately an excluded workspace, selected by manifest path.

## Run from the repository root

Requires cached Rust dependencies and Python 3.11+ for source verification. The tests create disposable temporary raw32 stores with native OS entropy and remove them after use. They do not provision a live identity, install a binary, assign trust, sign for a production receiver or contact a provider.

```sh
python3 crates/castalia-wallet-service-holder/tools/verify_sources.py
python3 crates/castalia-wallet-service-holder/tools/fixture_goldens.py
python3 crates/castalia-wallet-service-holder/tools/test_verify_sources.py
python3 crates/castalia-wallet-service-holder/tools/verify_package_ids.py
python3 crates/castalia-wallet-service-holder/tools/test_verify_package_ids.py
cargo test --manifest-path crates/castalia-wallet-service-holder/Cargo.toml --offline --locked
cargo test --manifest-path crates/castalia-wallet-service-holder/vendor/secS-service-b/Cargo.toml -p castalia-wallet-private-files --offline --locked
cargo build --manifest-path crates/castalia-wallet-service-holder/Cargo.toml --offline --locked --all-targets
cargo clippy --manifest-path crates/castalia-wallet-service-holder/Cargo.toml --offline --locked --all-targets -- -D warnings
cargo fmt --manifest-path crates/castalia-wallet-service-holder/Cargo.toml -- --check
cargo test --manifest-path crates/castalia-wallet-service-holder/Cargo.toml --offline --locked --features hostile-json-features
node --test scripts/presentation-boundary.test.mjs scripts/provider-neutrality.test.mjs
```

Root `cargo test --workspace` continues to target the five generic Wallet packages. It does not test this opt-in package. The source-only tests here include Wallet validation, the explicitly synthetic issuer/journal chain, and retained native owner/evidence/private-file tests. They are not a complete native workspace or installed-chain qualification run. Generic `npm test` and `npm run typecheck` remain separate required checks; missing local dependencies must be reported without treating source tests as replacements.

## Immutable native source and dependency boundary

`vendor/secS-service-b` is the complete 311-file export of reviewed Native commit `3484dc40b86f0497ca5d34d2545a5f1b652fb660`, regenerated from its actual Git archive (tree `9b993e2fc2145f865cd01fb00eee590fec5e0b7f`, archive SHA256 `21ad9b736977f02b82c30d08032f5a805392c99d5ad57838330176cfb6685700`). The adjacent `.source.json` pins every file and records actual committed provenance. Dirty postcommit worktree content is excluded. Source integrity does not establish installed authority.

The selected server, core, contract, permissions and private-files dependencies resolve within that one new complete export. Both server and holder resolve `vendor/castalia-wallet-private-files-9cc8140` to one actual Cargo package ID. The package-ID tool checks real locked/offline metadata, exact canonical manifests, the shared FS edge and acyclicity. Registry rows and the generic Wallet graph remain at the bounded baseline for this migration; later companion/security-floor composition requires separate explicit provenance updates. The nested FS sidecar preserves Wallet origin and its absent license metadata; Native MIT attribution is not assigned to those source bytes.

The retained `../../vendor/secS-magik-7e32f13` is the complete 302-file export of native commit `7e32f132549236ec78ebd9ec8bf364ec66b33721`. The adjacent `.source.json` records its origin, exact commit/tree, deterministic Git archive hash, every file hash and retained MIT license. It is a locally reviewed source pin; remote publication and production qualification are not claimed. No mutable checkout, operator path or `file://` dependency is used.

The wrapper reuses the actual native codec, static public reader, complete descriptor/fingerprint, policy evaluator and schema-bundle oracle. Direct production dependencies are the native server/core/contract APIs, the actual Wallet private-files crate, OS entropy through `getrandom`, `zeroize` for secret buffers, Serde/JSON, SHA256 and Ed25519 with its `zeroize` feature explicitly enabled. Extra journal/fixture imports are dev-dependencies. Its dependency on the full native `server` library carries a larger host-side dependency surface (including SQLite/Tokio) than a future pure protocol extraction. It neither re-exports the server nor invokes a generic signer or key loader. No existing generic Wallet crate depends on this package or the native server. Holder imports of Native snapshot/journal/evidence modules remain test-only; the selected Native server keeps its own codec/owner/journal/evidence modules private.

The holder workspace excludes the new Native workspace roots; the generic root exclusions remain byte-for-byte unchanged. This preserves inherited native workspace dependency resolution, including Wallet's private-files crate. The holder now uses its additive service-only retained-directory/locking module. Existing generic private-file read/Output implementation and callers remain unchanged. The approved route remains a dedicated Frank identity with owner-private raw seed-file custody; no Member Key/encrypted recovery migration occurs.

## Public fixtures and regeneration

`tests/fixtures/SOURCE.json` pins the public owner-input schema/configuration, independent delegation policies and schema-bundle goldens. Native public signed vectors and numeric producer requests are consumed unchanged from the pinned source export. No operator configuration or real credential is stored here. The known disposable issuer/holder seeds appear only in `cfg(test)` Rust code.

To reproduce fixture metadata, run `tools/fixture_goldens.py` in check mode. It independently reconstructs the complete sorted Wallet policy preimages and native schema/static-reader bundle. The descriptor oracle preimage is frozen; the Rust tests compare it against the actual native fingerprint. To update reviewed public policy/schema metadata, edit the public inputs and run:

```sh
python3 crates/castalia-wallet-service-holder/tools/fixture_goldens.py --write
```

This writes metadata only, never keys or signatures. A fixture change then deliberately fails source verification until `SOURCE.json`, verifier hash pins and independent native golden review are updated together. Do not regenerate or replace signed native vectors to conceal a binding mismatch. For a native source update, export a separately reviewed exact commit with `git archive --format=tar <commit>`, record the complete file/hash/license provenance outside the export, and repeat both producer and consumer checks. Do not patch vendored native bytes locally or change generic Wallet dependency pins to make resolution pass.

The source verifier also detects extra native files, changed public/challenge/custody fixtures, absolute include paths, generic-lock drift, holder registry source/version/checksum drift from the native lock, and changes to the existing generic boundary guard. It pins the accepted private-files service module and the original helper with its one additive export; no existing helper behavior is replaced. The closed metadata readers reserve the pinned Serde JSON numeric-map token so `arbitrary_precision` feature unification cannot admit noninteger metadata. Re-run both feature profiles when changing that pinned dependency; opaque application request numbers remain unchanged. It verifies source integrity only and never creates an authority token.

## Current-custody holder proof

The new exact-challenge-only method accepts no owner configuration, clock, key, digest or qualification flag. It authenticates actual stored CURRENT/STATE/OWNER-INPUT/seed bindings, expected CAS, active epoch and the whole original issuer/holder/delegation window. The issuer signature and frozen request/schema/descriptor bindings must validate before signing. The same actual custody lease remains held through signing, strict self-verification, bounded encoding, exact metadata reload, owner/policy recomputation and final clock/window validation. No raw seed, signing key or arbitrary-message callback is exported, and signing never upgrades its shared lock or writes CLOCK.

Native evidence snapshot, epoch, permission and registry digests remain issuer-authenticated opaque bindings covered by the holder transcript. A holder signature does not independently authenticate their current Native provenance. NI05 must still match the actual persisted challenge and independently loaded current Native evidence/policy before issuing any execution context. The selected immutable Native export does not contain the current Native Pending producer, so these holder tests do not establish that current cross-component composition.

Five disposable real-custody regressions cover Runtime and Service proof verification and exact repeat, valid opposite-application/signed substitution denial, lifecycle-invalidated handles, post-sign public-owner substitution, retained exclusive-lock exclusion and post-sign expiry/rollback. A separate Cargo integration control invokes the normal library without `cfg(test)` through public APIs, uses the real OS clock and generated holder custody, and independently verifies both application proofs and policy digests. Its known public issuer/evidence bindings remain synthetic, so it does not establish current Native issuance or installed authority. They create fresh OS-random temporary service identities; they never read an installed identity. Independent source review found no actionable findings and ran no code. This source capability is separate from direct-Mac installed admission; no VM is required by this API.

## Current metadata and retained administration

The service-specific filesystem module now provides `ServiceRoot::lock_public_shared()` and `ServiceLease::public_observation()`. The first retains the real shared custody lock; the second borrows the same exclusive lease. Both expose only bounded canonical CURRENT-selected public CURRENT/CLOCK/STATE/optional OWNER-INPUT bytes, safe file/root/lock/directory identities and the actual shared epoch. There is no seed read, arbitrary path/revision selector, raw lease, callback, assertion constructor or Clone operation on either observation view. The filesystem checks the closed CURRENT locator and storage safety. Full state hashes, key/domain/policy validation remain the custody/native consumer's responsibility; a metadata view does not attest secret health or authority.

`ServiceIdentityStore::begin_administration()` returns the opaque non-Clone `ServiceAdministrationSession`, tied to its actual store and retained exclusive custody lease. Its configure, rotate, revoke and reconcile methods reuse the existing CAS, entropy, clock, publication, epoch, poison and recovery mechanics under that one lease. Existing store methods remain compatible one-acquisition wrappers. Public identity and metadata reads deny publication uncertainty; explicit session reconciliation observes actual CURRENT without releasing/reacquiring the lock. Unreferenced revision cleanup still requires the existing explicit owner operation between mutations.

An observation's immutable borrow must end before a mutable CLOCK/publication operation; recapture uses the still-held session:

```rust,no_run
# use castalia_wallet_service_holder::custody::{CustodyError, ServiceIdentityStore};
# fn inspect_and_reconcile(store: &ServiceIdentityStore) -> Result<(), CustodyError> {
let mut session = store.begin_administration()?;
{
    let observation = session.public_observation()?;
    observation.revalidate().map_err(CustodyError::from)?;
    let _selected_revision = observation.metadata().state_revision();
}
let _actual_current = session.reconcile_current()?;
let current = session.public_observation()?;
current.revalidate().map_err(CustodyError::from)?;
# Ok(())
# }
```

This stage implements the Wallet observer/session mechanics only. Coupled native transition fencing, native publication/recovery, typed issuer signing and qualified proof/context composition remain separate implementation stages. No success token, readiness toggle, native transition stub or live identity is added. The retained observation/session source and exact two filesystem hash updates are independently accepted in commit `9cc8140`. The unchanged verifier logic now checks those reviewed module/test bytes and reports source integrity with no errors; all ten tamper tests pass. Source integrity is not installed authority or production signing qualification.

## Work still required

Actual current Native issuer/holder/completion composition, target descriptor admission and installed adversarial qualification remain unfinished. The storage lifecycle and holder signature do not close those authority boundaries. Empty-obligation fixtures demonstrate a protocol case; zero actual production descriptors are qualified by them. Gate 1 stays open.
