# Wallet Identities

Wallet-owned encrypted identity-record foundation for Claimable Rewards. This is
not a reward-eligibility verifier, custody implementation, or arbitrary signer.

`IdentityDatabase` uses the existing Wallet custody worker's
`sealIdentitySection` / `openIdentitySection` methods. No private key crosses this
interface. Its normalized records are encrypted together in one authenticated
snapshot so cross-table references update atomically. IndexedDB contains only
owner-key/revision metadata and ciphertext; account/resource lookup uses unlocked
memory. Lock the database whenever the custody worker locks or is destroyed.

The IndexedDB adapter performs a transactional compare-and-swap. A stale tab must
unlock/reload before retrying an update; it must not overwrite another tab's data.
Schema v1 remains readable. The explicit v2 migration replaces the historical
`dreggReceiptHash` field with a closed, versioned `receiptReference` distinguishing
`dregg-native` history from `service-v1` commitments. No native evidence is invented.
The reader accepts both versions before any Castaway export is enabled; importing
v2 upgrades a v1 snapshot transactionally, and later v1 imports remain supported.
Unsupported future versions fail without writes. Imports merge by IDs
and reject conflicting records, duplicate stable subjects, foreign-key errors,
unknown fields and wrong owners. Matching names never merge accounts.

Both UTF-8 plaintext (including the snapshot wrapper) and the complete encrypted
envelope are limited to 1,048,576 bytes. JavaScript string length is not a byte
limit, and base64/JSON overhead makes the usable plaintext capacity smaller.
Before committing a snapshot, the exact ciphertext is reopened, parsed and
compared with the proposed records. Oversized, unreadable or altered results do
not replace the prior snapshot. Browser custody independently rejects oversized
encrypted output. The custody root, derivation paths and stored v1 format remain
unchanged. Previously unreadable records fail without deletion or overwrite.

Stored attestation digests and payout observations are references, not authority.
Import does not verify a provider signature or chain finality. Render imported
facts as unverified until the relevant verifier independently checks them. A
disconnected account and its historical receipts remain in the database.

## Integration status

Browser Wallet screens, explicit claim/transfer approval operations, encrypted
Castaway transport, and recovery/export integration are **not wired yet**. Existing
Castaway formats/readers and derivation paths are unchanged. Do not enable this
store for real-value receiving until recovery also restores spending access.

All Castaway readers (TypeScript and Rust/Wasm) must understand the versioned
identity section before any writer emits it. Importing custody and identity data
requires one recoverable transaction/journal across both stores. A partial import
must neither replace the existing Wallet nor silently discard identity records.
Never include OAuth tokens, private keys, or redeemable signed permits in identity
records or public evidence. The schema deliberately admits none of those fields.

## Checks

From the Wallet workspace root:

```sh
npm run test --workspace packages/identities
npm run typecheck --workspace packages/identities
npm run build --workspace packages/identities
```

Tests use ephemeral keys and a standards-style IndexedDB harness. The custody
regressions load the actual browser Wasm from the sibling castalia-web checkout;
build it with that repository's scripts/build-wallet-wasm.mjs first. An optional
CASTALIA_WEB_ROOT selects another checkout. Missing artifacts fail; no fake
cipher is substituted. Tests exercise large ASCII/Unicode records, the encrypted
envelope boundary, lock/reload and preservation on failures. They do not qualify
worker messaging, a live browser UI or identity-record Castaway recovery.
