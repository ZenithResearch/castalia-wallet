# Opt-in native service-holder preparation

## Empty workspace authoring — 18 October 2026

The selected immutable Native export is `vendor/secS-service-authority-d1ff595`, commit `d1ff595c214f68a6b1c8b763708d82d6c1eff620`, with342 complete committed files and Git-tree modes. Its raw Git archive SHA256 is `06557745d1b3489eaa19ebadb55f1adfd510d7c375d5aeac6c5978369440947d`. Native's1,093 workspace tests (one existing opt-in ignore),14 query controls, strict Clippy and formatting pass; focused counts overlap. Native source qualification is separate from this pending Wallet composition/installed activation. All historical exports, including a710, remain independently checked and unchanged.

Fresh-query support now includes existing `process.get` (0x60), preserving current policy, Wallet delegation/custody and original-window checks. The other eight reads remain supported; `effect.get`, commands and Service requests deny through Query. Parsing support grants no permission. The separate standalone `../castalia-wallet-workspace-setup` provisions only five authoring/catalog scopes using the selected immutable source and one shared filesystem package. It creates no process, run, actor, result issuer, capture or provider and loads no review workflow. Its owner window is at most one hour, with the existing explicit512-row journal capacity. The local-review companion remains optional and unchanged apart from selecting the same immutable dependency source.

## Current finite pilot composition and owner setup — 17 October 2026

Wallet and its create-only owner-setup companion now select the complete342-file Native export `a7100a7`; historical `eb8d839` and older exports remain unchanged and verified. Both registry locks retain all186 original registry rows and one shared private-files package identity. Setup explicitly pins `journal_capacity=local_review_pilot_512` into the command authority, Wallet configuration and final master hash chain. Native defaults remain32holder/256global; the opt-in profile changes no byte, Pending, replay, expiry, history or permission boundary.

Physical-Mac qualification passes111holder tests per default/hostile profile,18setup tests per profile,23private-files tests,37source controls and16package controls, actual locked/offline metadata, unchanged public goldens, both all-target builds, strict Clippy and formatting. Counts overlap. Actual setup RED retained17passes/one missing-capacity failure; source/package RED retained5/one expected failures before consistent selection. Source was identical before/after the complete final run and every owned process group was empty. Generic npm remains39passes/5existing failures and type checking is unavailable because `tsc` is absent; those are not native qualification passes.

The companion creates separate native holder/command-issuer/result-party custody only through reviewed Native/Wallet APIs, uses a maximum one-hour fixed review scope, writes intent first and COMPLETE/master last, and retains partial state on failure. It does not start services, create a run or enable a provider. Actual new nine-handler/recovery integration, trusted installation/finite owner activation, selected real input and first useful workflow remain pending. No VM prerequisite or Gate/status completion.

Evidence: `/Volumes/home/bananawalnut/repos/process-execution-evidence/2026-10-14/wallet-capacity-setup-qualified-20261017/manifest.json`.

## Historical query and configuration-pin checkpoint — 17 October 2026

The normal Wallet command now supports explicit fresh Runtime query acquisition and an optional same-read SHA-256 command-configuration pin. Frank must choose the pinned form. Issue/resume retain request uniqueness and the original authorization window; queries use fresh Native challenge/session/nonce identity, including repeated identical read bytes. The eight permitted reader profiles add no permission grant. Unsupported reads, commands and Service requests deny through Query. There is no unpinned, reissue or signer fallback.

The selected complete immutable Native export is eb8d839. All 333 source files match its qualified commit; historical 20d/afeb/B/A exports remain unchanged and checked. All 186 registry rows, root generic files, frozen public goldens and the single shared private-files package identity remain unchanged.

Physical-Mac final qualification passes 111 tests per default/hostile profile: 87 unit, one holder-only and 23 actual Native/Wallet/command controls, zero failures or ignores. The 23 selected private-files tests, all-target build, strict Clippy and formatting also pass. Source integrity has 32 passing controls and package identity has 15, plus actual locked/offline metadata in both profiles and unchanged public goldens. Focused query/pin counts overlap. All six groups are reaped/empty and runtime/test source is byte-identical before/after. An earlier full run passed default tests/build but strict Clippy rejected a lazy fallback in the new test fixture; only that fixture expression changed, then all required Rust checks were rerun. The missing-pin API, unsupported-query and unprotected-export test-first failures are retained. The initial package-control invocation's isolated-import error is a runner error, retained and corrected without changing tested source.

Exact source, both ordinary command binaries, executed test artifacts, logs, proposals/reviews and earlier attempts are retained at `/Volumes/home/bananawalnut/repos/process-execution-evidence/2026-10-14/wallet-query-pin-qualified-20261017/manifest.json`. Generic npm/typecheck remain separate checks with their actual results recorded there. These are actual disposable OS-generated custody/clock tests, not installed receiver/provider qualification. Frank's adapter, actual helper/receiver fresh admission, replay/cursor reconciliation, finite live issuer/public pins, trusted installation and accountable result/provider execution remain open. No live role, identity, service/profile or Gate/workflow status changes. No VM gate is required.

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
cargo test --manifest-path crates/castalia-wallet-service-holder/vendor/secS-service-authority-a7100a7/Cargo.toml -p castalia-wallet-private-files --offline --locked
cargo build --manifest-path crates/castalia-wallet-service-holder/Cargo.toml --offline --locked --all-targets
cargo clippy --manifest-path crates/castalia-wallet-service-holder/Cargo.toml --offline --locked --all-targets -- -D warnings
cargo fmt --manifest-path crates/castalia-wallet-service-holder/Cargo.toml -- --check
cargo test --manifest-path crates/castalia-wallet-service-holder/Cargo.toml --offline --locked --features hostile-json-features
node --test scripts/presentation-boundary.test.mjs scripts/provider-neutrality.test.mjs
```

Root `cargo test --workspace` continues to target the five generic Wallet packages. It does not test this opt-in package. The source-only tests here include Wallet validation, the explicitly synthetic issuer/journal chain, and retained native owner/evidence/private-file tests. They are not a complete native workspace or installed-chain qualification run. Generic `npm test` and `npm run typecheck` remain separate required checks; missing local dependencies must be reported without treating source tests as replacements.

## Immutable native source and dependency boundary

`vendor/secS-service-authority-afeb6e6` is the historical complete 331-file export of reviewed Native commit `afeb6e60f5e3b062e503e545c8d6417c0c3ca9e7` (tree `263285b41e2ef7fb18861538aac61aef479c79d7`, Git archive SHA256 `4572662f3935df2d571184c684d169032aee2903660352d2dff91181c31f03a5`). Its adjacent `.source.json` pins all files. The export includes the public current-custody Native startup, issue and complete APIs. Dirty postcommit worktree content is excluded. Source integrity does not establish installed authority.

The historical `vendor/secS-service-b` remains the unchanged complete 311-file export of Native commit `3484dc40b86f0497ca5d34d2545a5f1b652fb660`. Its adjacent source manifest remains checked independently. Four test-only copied Native modules retain this historical source closure; current Native composition uses the selected server's ordinary public API instead. No vendored file is patched to expose private Native APIs.

The historical complete 332-file export `vendor/secS-service-authority-20d064d` remains unchanged and independently checked: Native commit `20d064ddbcb9b021a46fdccf00b1d5e6be236025`, tree `e3e85d0460177428c2df8be5924f2cd27ca49063`, Git archive SHA256 `f469f9785c092fe7e6f24e279d0b055475da1ce0bd2b2433dca01a2566a87661`. It supplies the retained explicit no-create resume and same-read pinned startup checkpoint below; it is no longer the selected dependency closure.

The previously selected complete333-file query export is `vendor/secS-service-authority-eb8d839`, Native commit `eb8d839a805f64d9d1d0e280896d03f9b95239bc`, tree `31f0c46ac292753ca8fbc5df2e07da09c3a23a0d`, Git archive SHA256 `4a7f072256b8ef1682f1279fd6e50bf2afbc514b6af93cb57b26aff92aa2fa8f`. It adds explicit fresh acquisition/completion for the closed eight Runtime query readers while preserving original issue/resume/complete semantics, Packet v0 and schema-4 context. All four historical complete exports remain immutable and checked. Five holder dependency paths select this new export. The server and holder resolve its unchanged `vendor/castalia-wallet-private-files-9cc8140` to one actual Cargo package ID; no duplicate FS package, server-to-holder edge or generic Wallet dependency is introduced. All 186 registry rows, generic root files, frozen fixtures and historical test-only module paths remain unchanged. The nested FS sidecar retains Wallet origin and the recorded absence of license metadata; Native MIT attribution is not assigned to those bytes. Native source qualification does not establish this Wallet composition, a live role, installed receiver admission or provider readiness; those checks remain required after repin.

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

Native evidence snapshot, epoch, permission and registry digests remain issuer-authenticated opaque bindings covered by the holder transcript. A holder signature does not independently authenticate their current Native provenance. NI05 must still match the actual persisted challenge and independently loaded current Native evidence/policy before issuing any execution context. The selected immutable Native export contains the actual Pending producer. The historical synthetic holder tests still do not establish current cross-component composition; that requires the separate ordinary-library exchange control.

Five disposable real-custody regressions cover Runtime and Service proof verification and exact repeat, valid opposite-application/signed substitution denial, lifecycle-invalidated handles, post-sign public-owner substitution, retained exclusive-lock exclusion and post-sign expiry/rollback. A separate Cargo integration control invokes the normal library without `cfg(test)` through public APIs, uses the real OS clock and generated holder custody, and independently verifies both application proofs and policy digests. Its known public issuer/evidence bindings remain synthetic, so it does not establish current Native issuance or installed authority. They create fresh OS-random temporary service identities; they never read an installed identity. Independent source review found no actionable findings and ran no code. This source capability is separate from direct-Mac installed admission; no VM is required by this API.

## Ordinary-library Native exchange control

`tests/current_native_wallet_exchange.rs` composes the selected normal Native library with actual Wallet custody and the OS clock for both Runtime and Service. It generates disposable issuer and holder keys through their public create-only APIs, explicitly cleans the retired Wallet revision after configuration, captures actual current public metadata, publishes a finite Native owner policy, and opens the public owner-configured authority. Public request fixtures supply request bytes only. No public fixture issuer secret or copied Native claim is used to issue a challenge.

The controls cover exact issue retry, strict issuer and holder signature verification, exact Packet v0 payload/opcode, context request binding, cached completion and restart, changed request/proof denial, actual Wallet revocation, and expiry of the original window. These use empty-obligation disposable descriptors. They do not cover the Python authority helper, receiver admission, a durable exchange command, installed startup or a useful provider workflow. The source-bound macOS run passed all four exchange controls, all 87 holder unit tests and the separate holder-only integration control: 92 tests per default/hostile feature profile, zero failures. The selected private-files package separately passed 23 tests. All-target build, strict Clippy and formatting passed. Structural checks passed all 22 source-tamper and 13 package-ID controls, with unchanged fixture goldens. Counts across profiles and focused reruns overlap; they are not unique aggregate coverage. Exact source, executable archives, logs and retained failed/interrupted history are in `/Volumes/home/bananawalnut/repos/process-execution-evidence/2026-10-14/wallet-current-native-composition-qualified-20261017/manifest.json`. Generic npm still has its disclosed 39-pass/5-failure baseline and typecheck cannot find `tsc`; these Rust checks do not replace them.

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

The current Native dependency composition, ordinary-library exchanges and explicit issue/resume command passed the bounded source validation below. Target descriptor admission, actual helper/receiver composition and installed adversarial qualification remain unfinished. The storage lifecycle and holder signature do not close those authority boundaries. Empty-obligation fixtures demonstrate a protocol case; zero actual production descriptors are qualified by them. Gate 1 stays open.

## Prior issue/resume command checkpoint

The normal binary `castalia-wallet-service` is selected explicitly in this excluded package. See [the command contract](service-command.md) for its owner-private startup configuration, exact stdin/stdout contract and separate issue/resume modes. It composes the actual Wallet holder operation with Native's public issuer and persisted journal; it adds no Wallet journal or generic signer. The caller retains the exact request bytes needed for recovery.

The separately qualified historical `20d064d` checkpoint provides the additive `ServiceResume`, `ServiceAuthority::resume` and same-read `open_pinned_owner_configuration` APIs. All 332 files match that separately qualified committed Native source; the historical exports remain unchanged. The test-first check failed because the explicit binary target was missing. With the implementation applied, all ten focused normal-binary controls passed. After removing one unused retained test field, full physical-Mac validation passed 87 unit, one holder-only and 14 actual Native/Wallet/command integration tests in each of the default and hostile-JSON profiles: 102 per profile, zero failures or ignored tests. The selected private-files package separately passed 23 tests. All-target build, strict Clippy and formatting passed. Source tamper checks passed 27 controls; package-ID checks passed 14, with unchanged fixture goldens, all 186 registry rows and the shared FS package identity.

Both application profiles cover exact issue/resume, lost delivery at public API boundaries, discarded stdout, original expiry, revocation/owner changes, exact identity/configuration pins and unsafe config/CLI/input denial. The public-boundary loss controls do not claim actual process-kill fault injection. Counts across profiles/focused reruns overlap. Exact source, test executables, the normal command binaries, logs, RED/guard history and source review are retained in `/Volumes/home/bananawalnut/repos/process-execution-evidence/2026-10-14/wallet-service-command-qualified-20261017/manifest.json`. Generic npm/typecheck results remain separate and disclosed in that packet.

These are source-bound command checks with disposable OS-generated custody. They provision no live identity or issuer role and do not qualify installed helper/receiver admission, target descriptors, trusted startup, normalized results or a live provider. The selected Native query API now prepares explicit fresh read acquisition, but the supported Wallet query mode and installed adapter still require their own current composition and validation. Issue is request-unique and resume retains the original replay identity; neither may silently renew a polling call. Gate 1 remains open; no VM requirement is introduced.
