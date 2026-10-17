# Castalia Membership v1 Contract Decisions

Status: legacy compatibility contract; superseded for Join by Zenith-signed membership v3

This authority-owned application/lifecycle profile is no longer the active Castalia Join path. It remains documented and implemented only so existing v1 cells and downstream decoders are not silently broken. New members use the Zenith-signed v3 contract described in [Castalia Member Key and Zenith-Signed Membership](castalia-member-key-and-membership-cell.md). The public member-owned `CASTMEM2` contract remains a separate dormant v2 compatibility path.

Machine-readable profile: [`contracts/castalia-membership-v1.json`](contracts/castalia-membership-v1.json)

This document closes the D0 design gate for the first production-shaped local implementation. It fixes the bytes and authority boundaries that W1, W2, D1, D2, and Castalia Control consume. Changing any decision below requires a versioned migration and new cross-language vectors; it must not silently reinterpret an enrolled identity.

## Accepted v1 Member Key

The v1 container stores one OS-random 32-byte Ed25519 seed generated inside Castalia Wallet's extension-owned execution context. Current Wallet builds also deterministically expand that same seed into the ML-DSA-65 half of a Dregg-hybrid identity; this is additive and does not reinterpret any serialized v1 bytes.

- The canonical public anchor is exactly 32 raw Ed25519 public-key bytes.
- JSON transports encode those bytes as 64 lowercase hexadecimal characters.
- The private key may be exported only into the wallet's encrypted custody payload as PKCS#8 DER. No API returns plaintext PKCS#8, seed bytes, or a `CryptoKey` handle to Castalia Web.
- The key proves possession for membership enrollment and fresh web-session exchange. It may be accepted as a bounded policy issuer only where that consumer explicitly accepts this suite.
- The legacy v1 membership contract does not claim to bind or verify the PQ half. Current Wallet custody can sign the PQ half of Dregg's hybrid turn authorization, while the authority-owned v1 application path remains retired compatibility code.

Reason: the frozen v1 wire names Ed25519 because that is the only public anchor it serializes. Dregg intentionally derives its ML-DSA-65 key from the same private seed, so current Wallet builds can add the hybrid runtime identity without changing that wire or stranding a recovery file. Trade-off: v1 membership itself remains classical-only and must not be described as a PQ-attested credential.

## Accepted custody profile

Castalia Wallet owns an encrypted durable record and explicit encrypted `.castalia-recovery` export/import. Existing `.castalia-wallet` files remain import-compatible. The `.castaway` extension names the separate future [Castaway Portable Vault](castaway-portable-vault.md), an application-neutral encrypted collection of Zenith Ontology primitives and objects, and is not accepted by the recovery-file picker.

The merged `f7418f4` Wallet build briefly emitted the custody-v1 container as `Castaway-<timestamp>.castaway` before `b38bb31` corrected the presentation name. Those historical files are recoverable legacy custody artifacts, not Castaway vaults, and require the explicit migration documented in the portable-vault design.

```text
castalia.wallet-custody.v1
header:
  schema, keySuite, publicKey, kdf parameters, aead parameters, createdAt
ciphertext plaintext:
  PKCS#8 private key DER, key ID, creation metadata
```

The user supplies the unlock passphrase. The wallet applies:

- Argon2id v19;
- 16-byte random salt;
- 64 MiB memory;
- 3 iterations;
- parallelism 1;
- 32-byte derived key;
- AES-256-GCM with a fresh 12-byte nonce and 128-bit tag;
- canonical UTF-8 JSON of the header, excluding ciphertext, as associated data.

The serialized format is byte-normative:

- Normalize the passphrase to Unicode NFC, then encode UTF-8; reject an empty result.
- Serialize JSON with RFC 8785 JCS. Reject duplicate/unknown fields instead of canonicalizing an ambiguous object.
- Encode binary values as unpadded base64url (RFC 4648 section 5).
- The outer object has exactly `schema`, `keySuite`, `publicKey`, `createdAt`, `kdf`, `aead`, and `ciphertext`.
- `schema` is `castalia.wallet-custody.v1`; the frozen `keySuite` value is `Ed25519`; `publicKey` is 64 lowercase hex; `createdAt` is unsigned Unix epoch milliseconds. `keySuite` describes the serialized PKCS#8 seed container, not the complete current runtime identity descriptor.
- `kdf` contains `name`, `version`, `salt`, `memoryKiB`, `iterations`, `parallelism`, and `derivedKeyBytes`; `aead` contains `name`, `nonce`, and `tagBits`.
- Associated data is the JCS encoding of the outer object without `ciphertext`.
- The encrypted plaintext is the JCS object `{schema,keyId,privateKeyPkcs8,createdAt}`. Its schema is `castalia.wallet-secret.v1`; `keyId` is lowercase BLAKE3 hex of the raw public key; PKCS#8 DER is unpadded base64url; both timestamps must match.
- AES-GCM output appends the 16-byte authentication tag to the ciphertext before the combined bytes are base64url encoded.

Plaintext private material and the derived encryption key are memory-only. Explicit lock, extension restart, or key replacement clears them. Browser reload locks the wallet but does not erase the encrypted record. Export/import operates only on the encrypted versioned container.

Reason: extension ownership keeps ordinary webpage JavaScript outside the unlock and signing perimeter while encrypted export makes loss recovery possible. Trade-off: users must protect both the passphrase and every backup; a copied export is another copy of the same signing authority. Deleting one file does not revoke another copy, so lifecycle replacement remains necessary after compromise.

## Two cell identifiers

### `applicantOfficialDreggCellId`

This is the applicant's Dregg identity coordinate committed into the membership application. Castalia Web never supplies it.

Castalia Control asks its pinned Dregg adapter to resolve or provision it using:

```text
tokenId = BLAKE3(
  UTF8(networkId) || 0x00 ||
  UTF8("castalia-official-cell-v1") || 0x00 ||
  U32_LE(profileVersion)
)

applicantOfficialDreggCellId =
  CellId::derive_raw(ownerPublicKey, tokenId)
```

`CellId::derive_raw` is Dregg's legacy Ed25519 identity derivation:

```text
BLAKE3 derive_key context "dregg-cell-id-v1"
material ownerPublicKey || tokenId
```

The network ID and profile version come from Control's pinned deployment profile. Neither is caller-selectable.

### `membershipCellId`

This is the Castalia-owned `CASTMEM1` cell created by the authority-bound factory.

```text
birthTokenId = BLAKE3(
  UTF8("castalia/membership-birth-token/v1") || 0x00 ||
  factoryId ||
  applicationCommitment ||
  U64_LE(birthNonce)
)

membershipCellId =
  CellId::derive_raw(castaliaAuthorityPublicKey, birthTokenId)
```

The birth nonce is generated and durably reserved by Control's outbox transaction. It is never a browser nonce. Dregg must either adopt this canonical birth-token function or expose its equivalent as one authoritative API before C2; Control and Web must not independently improvise it.

For the local v1 source profile, D1 must expose the canonical `Effect::CreateCellFromFactory { factory_vk, owner_pubkey, token_id, params }` path whose executor creates the cell as `CellId::derive_raw(owner_pubkey, token_id)`. Control must not call the legacy `dregg_create_from_factory` tool, which derives identity from factory VK, a caller-facing cell name, or receipt-chain nonce. The pinned source head, source fingerprints, authority, factory, child program/VK, network/federation identities, and explicit local non-claims are in [`contracts/castalia-local-v1-source-profile.json`](contracts/castalia-local-v1-source-profile.json). Because that source profile describes a dirty prototype, D1 must land or reproduce those exact semantics before any consumer can call the dependency satisfied.

The two functions are intentionally non-circular:

- `applicantOfficialDreggCellId` depends on the applicant key and pinned identity profile, not the application commitment.
- `membershipCellId` depends on the completed application commitment and institutional birth nonce.

Reason: separating the applicant's identity cell from Castalia's institutional cell prevents application bytes from containing an identifier recursively derived from themselves. Trade-off: Control needs one extra trusted Dregg resolution step before it can construct an application.

## Authority and trust profile

### Castalia Control

Control owns challenge issuance, exact transcript verification, admission records, replay state, the durable outbox, and coordination of institutional lifecycle operations. It does not hold the Member Key.

Factory birth and lifecycle turns pass through one narrow Dregg adapter. The adapter receives canonical operation inputs only. Operator signing material is loaded from process-local secret configuration or an external signer, never browser configuration, request JSON, logs, or the application database. Operator HTTP requests use the repository-owned `Castalia-Operator-V1` Ed25519 header transcript defined in the machine contract; its timestamp, one-use nonce, exact method/path, and JCS body hash are all signed. The local source profile pins a deterministic RFC 8032 fixture public key only for tests; its private seed is forbidden outside tests.

### Control binding signer

Control uses a dedicated Ed25519 binding-signing key, separate from the Dregg lifecycle/operator authority. The binding domain is:

```text
castalia/control-membership-binding/v1 || 0x00
```

The wallet pins the reviewed binding public key by release/profile. Unknown key IDs fail closed. Castalia Web cannot supply or override this trust root.

The checked-in local fixture uses the RFC 8032 test-vector-1 Ed25519 public key under ID `castalia-control-local-fixture-ed25519-1`. It is test-only; its published seed must never become a non-test secret. A staging or production profile must replace the complete profile through review and cannot inherit a fixture trust claim.

### Dregg trust

The wallet profile pins network/federation identity, Castalia authority key, factory ID, child program/VK, and the accepted receipt/checkpoint verification profile. A caller-selected node URL is transport input, not a trust root. D2 must provide authenticated receipt bytes, continuity, and freshness before the wallet may call a Dregg read independent verification.

Reason: separating Control response authentication from Dregg institutional authority limits the consequences of each key and makes substitution tests mechanically meaningful. Trade-off: release/profile rotation needs explicit trust-root migration and overlapping verification periods rather than silent configuration replacement.

## Trusted fields and wire surfaces

The repository-owned machine-readable v1 contract and local source profile are self-contained: they freeze route paths, every nested wire-object field/type/order, application/challenge/presentation/binding/session transcript bytes, closed enums and errors, field provenance, lifecycle state machine, recoverable outbox saga, numerical bounds, concrete fixture roots, and test semantics. Implementers must generate or hand-write owning-repo schemas from those checked-in objects and prove byte compatibility; the vault plan is explanatory context, not a runtime or byte-level dependency:

- browser provides only `ownerPublicKey` in the issuance-challenge JSON body; the legacy v1 `membershipClass` slot is fixed by the Control profile and is never selected by the member;
- origin comes from the normalized allowlisted `Origin` header;
- policy fields, factory/program IDs, timestamps, nonce, and official-cell coordinate come from Control or its pinned Dregg adapter;
- unknown or duplicate fields reject before cryptographic work;
- Join claims success only after `POST /v1/memberships` returns an authenticated Active membership for the same Member Key; an orchestration row or Pending cell is not success;
- Active status alone never creates a web session: the same Member Key must answer a fresh, single-use Control session challenge bound to the exact Active generation and receipt.

## Migration rules

Any change to key suite, public encoding, custody schema, KDF/AEAD parameters, identity-cell profile, birth-token function, signed domain, or trust-root semantics requires:

1. a new explicit version;
2. positive and one-field-tampered cross-language vectors;
3. an import/replacement policy;
4. no fallback that accepts v1 bytes under v2 meaning;
5. an authority-recognized replacement ceremony when the Member Key changes.

## D0 acceptance record

This is a historical acceptance record for the frozen v1 membership wire: the user accepted extension-owned encrypted Ed25519 PKCS#8 custody with passphrase unlock and encrypted recovery export/import while hybrid/PQ signing was then out of scope. Current Wallet runtime derives Dregg's ML-DSA-65 half from that same recovered seed without changing or reinterpreting the v1 bytes; the v1 membership credential itself remains classical-only.

D0 creates no wallet, membership, cell, or session. It only fixes the contracts those implementation nodes must follow.
