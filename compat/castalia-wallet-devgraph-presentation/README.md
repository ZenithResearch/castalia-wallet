# Retired Devgraph presentation compatibility

This selected source supports the public verification-only Runtime helper pinned
to secS-magik 11e7128. The Rust implementation is byte-identical to Wallet revision
3216144; `SOURCE.json` records both manifest versions and the explicit dependency
binding. It does not join the active Wallet workspace or alter current custody,
membership, signing authority or immutable Native exports. It contains no
operator configuration or private key. The active Wallet presentation crate owns
current behavior. No source from this crate is copied into another project repo.
