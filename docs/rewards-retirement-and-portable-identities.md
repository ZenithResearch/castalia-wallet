# Rewards retirement and portable Wallet identities

Decision date: October 23, 2026. Rewards integration is deprecated. Implementation update: core0.3.0 now implements the descriptor-only Wallet identities subset and Castaway v2 described in [the shared contract](../contracts/wallet-identities/v1/README.md). The broader CWS-001 custody profile remains proposed. Existing application records require explicit reviewed copying; no automatic migration is performed by installing the update.

## Retired work

The `@castalia-wallet/rewards-bridge` connect-only Solana disclosure protocol and `@castalia-wallet/identities` X/GitHub rewards database are removed from the active workspace. They were imported from uncommitted local authoring sources during shared-core alignment, rather than merged from a dedicated rewards branch. Their last public source is commit `575895f70e4cbdc982b7c9271b468470271dbb0b`; the original provenance remains in `wallet-source-imports.json`. They are not supported dependencies or a recommended identity model. Historical source retention does not enable them in a release.

Reward eligibility, offers, claims, payout selection and reward receipts belong primarily to applications. Wallet supplies independently reviewed identity, disclosure and bounded signing primitives. This decision does not remove membership, graph credentials, existing public chain descriptors, or generic identity-section encryption. No account data, browser database, custody file, trust configuration or grant is deleted or migrated.

## One portable identity model

Browser Wallet, extension, iOS Wallet and Transfer must use the same versioned public identity/account-reference contract and shared core readers. Future X/GitHub accounts for Gallery belong alongside supported Nostr/Matrix identity references, with provider-specific validation. Rewards must not define a second account identity store. Applications can hold their own domain records referencing those stable account identities.

The existing proposed [CWS-001 connected-account profile](https://github.com/ZenithResearch/castalia-wallet/blob/docs/castalia-connected-accounts-standard-20261018/docs/standards/cws-001/connected-accounts.md) is the review starting point, not a shipped schema or permission to extend strict v1. Review the current Zenith Ontology account/identity types before freezing a successor; do not create competing semantics under UI labels. The connected-account draft does not yet include X/GitHub and needs an explicitly reviewed revision before claiming their support.

Keep these boundaries explicit:

- **Portable descriptions:** stable record ID, Wallet association, provider namespace, canonical public identifier, and typed provider-specific public fields. Display names are not identity. Association alone does not prove control or current verification. Export/import and disclosure require the person's consent.
- **Private authority:** independent keys and account recovery secrets remain in reviewed custody/recovery formats. Public account descriptors do not recover a Nostr private key or restore Matrix authentication. Do not put secrets or encrypted authority capsules in data-only Castaway.
- **Application state:** active Matrix connections, tokens, device stores, browser sessions, Tailscale state, rewards eligibility and claims remain outside this Wallet identity contract. Restoring a reference does not authenticate, publish, grant access, or initiate a reward action.

## Compatibility and implementation order

The implemented `castalia.castaway-contents.v1` parser enumerates its sections strictly. Its current identity/profile, membership and chain-account data must keep their exact meaning. The native `zenith.identity-account.v1` registry and retired browser `castalia.identity-database.v1/v2` snapshots are different existing records, not interchangeable portable Wallet identities. Neither legacy store is serialized directly. The reviewed migration copies supported public references into the common Wallet identities section while retaining original records; the common Castaway exporter includes that new section.

1. Inventory existing public identity/profile contracts, persisted native registry records, and browser snapshots. Define provider namespaces and stable identity mapping without merging by labels or generating replacement Wallet roots.
2. Review a versioned portable descriptor extension with the existing ontology/CWS work. Specify bounds, owner binding, duplicate/conflict handling, provenance, independent verification state, and secret exclusion. Do not add fields or sections to a strict v1 parser while retaining its identifier.
3. Implement shared-core readers and old-file compatibility before enabling new writers. Exercise the same synthetic vectors independently through native and browser consumers, including unchanged legacy recovery.
4. Provide an explicit migration preview from existing app-level references. Preserve original data until the new durable commit and actual exported-file roundtrip succeed. Read-only or unknown records must not silently disappear; reject unsupported formats without mutation where opaque preservation is not supported.
5. Enable the same account model and import/export UI across browser and iOS Wallet, then Transfer. Distinguish local saving, Castaway export, secret recovery coverage and provider reauthentication. Do not advertise portable identities until cross-client tests pass.

Acceptance includes browser-to-native and native-to-browser roundtrips, legacy backups, provider-specific negative cases, holder mismatch, duplicates/conflicts, malformed/unknown versions, hidden authority, cancelled/stale imports, lock transitions and failed persistence leaving existing Wallet/account data intact. Account records must not revive origin approvals, membership trust, credentials or application sessions automatically.
