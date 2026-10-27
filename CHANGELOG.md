# Changelog

## [Unreleased]

### Added

- Reuse the secS resource-selector primitive for public Core selection review and conservative narrowing — retain exact object/hierarchy distinctions without changing custody, signed v1 permissions or stored grants.

### Added

- Qualify saved live-collection grants through encrypted backup/restore and equal or narrower same-Wallet derivation — future resource coverage reuses existing Core scopes without migrating fixed grants or enabling delegation.

### Added

- Exercise independently scoped holder-grant actions through encrypted backup/restore and same-holder derivation — ensure app rule editors cannot mix another rule’s scope into a saved credential. Signed formats and Core behavior are unchanged.


- Add Core 0.4.1 public service-access-point verification and browser consent routing — a verified service can reuse canonical authority through multiple access points while preserving site-specific consent, custody, and all existing grant/backup bytes.

- Add Wallet Core 0.4 reusable provider grants with the shared secS verifier, encrypted reviewed storage and grant backups. The same Wallet can derive equal or narrower finite credentials; onward delegation remains disabled. Existing formats retain their bytes. The new populated local-state snapshot requires the new Core, and live qualification is still pending.

### Fixed

- Keep grant backup conflict checks compatible with the pinned Rust1.85.1 toolchain, without changing conflict rejection or storage behavior.

- Align shared root/credential/presentation size and nesting budgets, so same-scope self-derivation remains transportable through the native verifier.


- Bound saved grant collections to the backup parser's capacity, so an accepted collection cannot produce an unrestorable grant backup.

### Fixed

- Refresh the read-only source verifier’s reviewed workspace lock hash for the shared core0.3.0 dependency closure — keeps exact source checks and tamper rejection aligned with the qualified producer, without changing holder locks or authority.

- Keep identity descriptions and edit/import controls in a readable responsive layout — long Nostr keys and provider identifiers must not run into form labels or action buttons.

- Validate full Castaway public descriptors in the shared core — blocks hidden authority fields in browser/extension imports without treating stored public proofs as trusted membership.

### Added

- Add a Wallet-owned Chrome identity editor and reviewed Castaway import/export — uses the same core validation as native and Web, preserves original custody and saved accounts, and never exposes identities through application-origin provider methods.

- Add shared descriptor-only Wallet identities and Castaway v2 readers/writers — preserves stable public account references across native and browser clients without importing sessions, keys or authority. Existing v1 data/recovery formats remain compatible; imports reject account conflicts without writes.

### Removed

- Retire the rewards bridge and rewards-specific identity database from the active workspace — reward workflows belong in applications, while future Wallet identities must share a portable contract across browser and native clients. Existing custody and account data are unchanged.

### Fixed

- Update the generic lockfile integrity pin for the reviewed Transfer dependency closure — source packaging checks must accept this exact lockfile while rejecting later tampering.

- Publish native graph/operator and first-owner consent dependencies used by Zenith Transfer — the public application pinned a private-only Wallet commit and could not be built from public sources.

### Fixed
- Prefetch the exact locked holder dependencies before running offline identity checks in clean CI — keeps the metadata tests strict without depending on a workstation cache.

### Added
- Published the retired stateless Wallet presentation contract in Wallet’s own compatibility subtree — permits public verifier builds while keeping custody unchanged and source out of unrelated repositories.

### Changed
- Published the reviewed clean Wallet baseline — makes its complete immutable Native composition inspectable while preserving private history and installed custody.

### Added
- Clean public source baseline — make component implementation inspectable while preserving private history, live state and qualification evidence.
