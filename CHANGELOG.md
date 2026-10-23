# Changelog

## [Unreleased]

### Fixed

- Publish native graph/operator and first-owner consent dependencies used by Zenith Transfer — the public application pinned a private-only Wallet commit and could not be built from public sources.

### Fixed
- Prefetch the exact locked holder dependencies before running offline identity checks in clean CI — keeps the metadata tests strict without depending on a workstation cache.

### Added
- Published the retired stateless Wallet presentation contract in Wallet’s own compatibility subtree — permits public verifier builds while keeping custody unchanged and source out of unrelated repositories.

### Changed
- Published the reviewed clean Wallet baseline — makes its complete immutable Native composition inspectable while preserving private history and installed custody.

### Added
- Clean public source baseline — make component implementation inspectable while preserving private history, live state and qualification evidence.
