# Shared Wallet baseline

The canonical producer is https://github.com/ZenithResearch/castalia-wallet. Consumers must pin one reviewed commit from this repository and record built artifact hashes. Core 0.2.0 retains existing custody, recovery, provider, native and extension interfaces and adds the finite WebWalletCustody adapter over the same OpenedWallet implementation. Existing v1 encrypted formats and signing transcripts are unchanged.

The rewards-specific identities and rewards-bridge packages imported during alignment have been retired and removed from the active workspace; historical provenance remains in wallet-source-imports.json. See rewards-retirement-and-portable-identities.md. The Matrix companion candidate retains its source here. Matrix fixtures remain synthetic examples rather than live Matrix custody qualification. Retained DevGraph presentation compatibility source remains isolated under compat; its old signing bytes and protocol dependency stay unchanged.

An updated source pin alone grants no membership or access, migrates no existing Wallet storage, and does not expand issuer policy. Arena metadata authority is an application contract with explicit Arena identifiers, separate from Work selectors.
