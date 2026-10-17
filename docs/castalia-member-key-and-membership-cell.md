# Castalia Member Key and Zenith-Signed Membership

Status: active centralized-compatible v3 architecture for Join

Dregg permissionless v2 remains implemented as a versioned, dormant forward-compatible cell path. It is not reinterpreted, deleted, or called by the active v3 provider. The former authority-owned `CASTMEM1` application contract remains legacy compatibility only; see [Castalia Membership v1 Contract Decisions](castalia-membership-v1-contract.md).

## Core invariant

```text
member controls a Castalia Member Key
+
Wallet and Web verify an Active credential signed by a pinned Zenith issuer
=
active Castalia base membership v3
```

Anyone may become a member. There is no individual/institution selection, application, approval queue, Pending state, Control decision, role assignment, or capability grant in Join. Zenith authenticates membership today by signing a deterministic public credential. That centralized trust is explicit and represented by a versioned trust policy rather than hidden inside a Web session.

## Member Key and recovery

Wallet generates one OS-random 32-byte identity seed inside extension-owned execution. That seed is the Ed25519 private seed and is also supplied as `xi` to FIPS 204 `ML-DSA.KeyGen`, exactly matching Dregg's `MlDsaKey::from_ed25519_seed` / `AgentCipherclerk::from_key_bytes` identity construction. The result is one portable Dregg-hybrid identity with Ed25519 and ML-DSA-65 signing halves, not two unrelated private keys.

The seed remains inside the encrypted durable custody record. The `.castalia-recovery` export is another encrypted copy of that root signing authority, so importing an existing recovery file restores the same Ed25519 public key, the same 1,952-byte ML-DSA-65 public key, the same Dregg cell-key commitment, and the same preview Cardano, EVM, and Solana chain keys.

Wallet derives account index zero for Cardano mainnet, Ethereum mainnet, Robinhood Chain mainnet (`eip155:4663`), and Solana mainnet-beta inside Rust/WASM with versioned, chain-specific BLAKE3 domains. Ethereum and Robinhood deliberately share one secp256k1 key/address while retaining distinct network identities. The extension UI receives public descriptors only. These addresses are preview-only: balances, deposits, transaction construction, and signing are not enabled, and the derivation does not claim BIP-39, BIP-44, CIP-1852, or hardware-wallet interoperability.

The planned [`.castaway` portable vault](castaway-portable-vault.md) is a separate application-neutral encrypted data container for non-authority ontology-typed primitives and objects that can move between compatible wallet applications. It may carry public account descriptors, but it never carries raw chain keys, a recovery root, or an encrypted signing-authority capsule. `.castalia-recovery` remains the dedicated portable root-authority artifact. Opening a vault must not install a key or create membership. No current extension Wallet build emits or consumes that vault format.

The classical public Member Key is 32 bytes encoded as 64 lowercase hexadecimal characters. The hybrid public descriptor additionally carries the ML-DSA-65 public key as unpadded base64url and Dregg's domain-separated 32-byte key commitment as lowercase hex. The passphrase encrypts and unlocks the stored seed; it does not derive the identity. Castalia Web, Zenith, Dregg, Control, Matrix, logs, and membership credentials receive no private key, seed, or passphrase.

After setup, the Chrome-owned Wallet popup displays that complete 64-character Ed25519 public Member Key for operator policy binding. Copying uses a user-activated button with a selectable-field fallback and does not unlock custody, request a signature, or expose the encrypted seed, private signing keys, passphrase, or recovery material.

The active v3 Zenith membership credential still authenticates the Ed25519 owner anchor only. This is an explicit compatibility boundary: it does not downgrade Wallet custody or generate a second identity, but it also does not claim that Zenith has attested the ML-DSA half. See [Dregg Hybrid Identity](dregg-hybrid-identity.md).

## Exact v3 contract

Wallet proves possession by signing:

```text
"castalia/zenith-membership-join/v3\0" || ownerPublicKey
```

It posts this exact request to `POST /v3/memberships` on the compiled issuer origin:

```json
{
  "schema": "castalia.zenith-membership-issuance-request.v3",
  "version": 3,
  "ownerPublicKey": "<32-byte lowercase hex>",
  "signatureSuite": "Ed25519",
  "signature": "<64-byte unpadded base64url>"
}
```

The membership identifier is issuer-independent:

```text
SHA-256("castalia/zenith-membership-id/v3\0" || ownerPublicKey)
```

Zenith verifies the possession proof and signs a fixed-field credential containing only schema, version, membership ID, owner key, `active` status, issuer ID, issuer key ID, signature suite, and issuer signature. There is no creation time, expiry, application state, role, capability, delegation, session, or mutable lifecycle field. A retry for one Member Key returns byte-identical credential JSON.

The canonical vector is [castalia-zenith-membership-v3.vector.json](vectors/castalia-zenith-membership-v3.vector.json). Its adjacent SHA-256 sidecar pins the exact bytes. The checked-in issuer key is an RFC 8032 test fixture and production packaging rejects it.

## Join ceremony

1. Web accepts Join only when the provider advertises `membershipJoinProtocol: "castalia.zenith-membership.v3"`.
2. A user action in Web asks Wallet to open a Chrome-owned popup; automatic page calls are rejected and the ceremony is never rendered in page-owned DOM.
3. Wallet creates or unlocks the durable hybrid Member Key, deriving both signing halves from the one encrypted seed.
4. Wallet signs the exact v3 possession transcript and submits only public material to the configured Zenith issuer.
5. Zenith verifies the Member Key signature and returns its deterministic signed credential.
6. Wallet independently verifies the credential schema, owner, deterministic membership ID, pinned issuer identity/key, and Ed25519 issuer signature.
7. The Chrome-owned popup displays the exact initiating Web origin. At completion Wallet re-reads the initiating tab and origin, requires an exact match, persists the public credential under `castalia-zenith-membership-v3`, and approves only that origin for the browser session. Non-loopback origins must use HTTPS.
8. Wallet hands the full public credential to Web. Web independently repeats the same strict verification before displaying **Membership active**. A no-detail readiness event may call `getMembership()`, which reverifies the persisted credential before returning it.

Pages cannot choose or override the issuer URL, issuer trust root, Member Key, membership ID, or credential. Those values are compiled into the reviewed extension package or derived from the unlocked Member Key.

## Persistence and recovery

The encrypted custody record and public v3 credential persist in `chrome.storage.local`. Locking clears decrypted signing authority from service-worker memory but does not erase either durable record. Unlocking restores the same Member Key, and `getMembership()` revalidates the saved credential.

Importing `.castalia-recovery` clears identity-bound session approvals and cached membership before installing the recovered key. Rejoining with the same key derives the same membership ID and receives the same deterministic credential. A genuinely new key is a new identity and receives a different membership ID.

Wallet versions between commits `f7418f4` and `b38bb31` misnamed the same `castalia.wallet-custody.v1` recovery container `Castaway-<timestamp>.castaway`. Those files remain signing authority, not portable vaults. They must be handled through the legacy migration described in [Castaway Portable Vault](castaway-portable-vault.md), then re-exported as `.castalia-recovery`.

## Trust and rotation

Zenith is the only production membership issuer in the initial policy. Wallet and Web pin an `(issuerId, issuerKeyId, Ed25519 publicKey)` trust root and fail closed for every other signer. The trust policy is an array so a future reviewed release can overlap old and new keys or add another compatible issuer. Adding trust always requires a new reviewed Wallet and Web build; an issuer response cannot add its own authority.

Compromise of the Zenith issuer key could mint credentials for arbitrary public keys, so the production private key must live only in the issuer secret store, be backed up separately, and support rotation. Compromise does not expose Member Key private material.

## Version boundaries

- **v3 active:** Zenith-signed deterministic credential described here.
- **v2 dormant:** Dregg permissionless immutable Active cell, retained in `@castalia-wallet/dregg-adapter` and its pinned vector for a future decentralized deployment.
- **v1 legacy:** authority-owned application/lifecycle and Control presentation helpers retained only for older consumers.

No stored v1 or v2 object is decoded as v3. The new credential uses a new provider marker, storage key, schemas, domains, vector, and verification path.

## Required invariants

1. The shared identity seed, derived private signing keys, and passphrases never leave Wallet custody.
2. Zenith verifies the exact possession transcript before signing.
3. Wallet and Web independently verify the exact credential and pinned issuer.
4. One Member Key derives one issuer-independent membership ID.
5. Retry is deterministic and does not create a duplicate record or session.
6. Creating or importing a replacement identity clears cached v3 membership.
7. Active membership is not a Web session, cookie, Matrix credential, role, capability, delegation, or infrastructure authorization.
8. Web cannot report success before cryptographic credential verification.
9. Production packages reject fixture trust roots, loopback endpoints, broad host permissions, and descriptor drift.
10. Any contract change requires synchronized issuer, Wallet, Web, vector, negative-test, and documentation updates.
11. Origin approval requires a Chrome-owned, non-embeddable disclosure plus exact completion-time binding to the initiating tab and origin; page styling, clickjacking, or navigation cannot transfer approval.

## Related documents

- [Castalia Wallet architecture](architecture.md)
- [Extension Wallet and Start Flow](ephemeral-extension-wallet-start-flow.md)
- [Dormant Dregg membership integration](dregg-membership-integration.md)
- [Legacy Castalia Membership v1 Decisions](castalia-membership-v1-contract.md)
- [Castaway Portable Vault](castaway-portable-vault.md)
