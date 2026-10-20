# CWS-001: Wallet files, typed sections and schema publications

Revision: **0.2.0-draft**, October 18, 2026.

Status: **Public shape proposal. Existing v1 contracts are documented separately from proposed, unimplemented extension formats. No installed wallet or current file is changed.**

## 1. Scope and layers

The Castalia Wallet Standard defines wallet file shapes, where each class of value is stored, and how developers publish schemas for a new connection type. Matrix and Nostr are examples; they are not the boundary of the standard.

There are three layers:

1. **File envelope:** artifact identity, owner, encryption profile and encrypted payload type.
2. **Typed payload/sections:** root custody or publisher-typed entries inside authenticated encryption.
3. **Schema publication:** versioned value definitions and their assigned storage classes, resolved by a future SDK through explicitly installed, pinned packages.

File extensions are presentation hints. Validated content discriminators and authenticated bytes determine meaning. This proposal introduces no generic `.castalia` filename that conflates recovery authority with portable data.

## 2. Where things belong

| Artifact/storage | Contents | Excluded |
| --- | --- | --- |
| `.castalia-recovery` | Encrypted root; in a future version, covered independent private/recovery material | Live device sessions, application grants and automatically restored provider trust |
| `.castaway` | Encrypted profile data, public credentials, account descriptions and approved non-authority entries | Seeds, private keys, recovery material, bearer tokens, encrypted authority capsules and reusable signing handles |
| Installation-local protected store | Sessions/tokens, Matrix device crypto state, approvals, Tailscale node/join state, Hermes key | Portable recovery promises without a separately reviewed export profile |
| Schema publication package | Public definitions of field shapes, versions, storage classes and request/result shapes | Actual account secrets/session values or executable adapters |

A private schema definition documents a secret's **shape**; it does not permit a secret instance in public data. Encryption alone does not turn authority into ordinary Castaway data. Exporters MUST construct allowlisted projections rather than serialize a custody object and remove a few known secret names.

## 3. Current v1 shapes

These [structural companions](catalogue.json) document current source contracts without expanding parser acceptance. Cryptographic checks, key/address derivation, signatures, duplicate-property rejection, byte bounds and canonical encoding remain additional mandatory checks.

| Layer | JSON Schema | Current discriminator |
| --- | --- | --- |
| Recovery envelope | [wallet-custody-v1](schemas/wallet-custody-v1.schema.json) | `castalia.wallet-custody.v1` |
| Recovery encrypted plaintext | [wallet-secret-v1](schemas/wallet-secret-v1.schema.json) | `castalia.wallet-secret.v1` |
| Portable data envelope | [castaway-envelope-v1](schemas/castaway-envelope-v1.schema.json) | `castalia.castaway.v1` |

Recovery has exactly `schema`, `keySuite`, `publicKey`, `createdAt`, `kdf`, `aead`, and `ciphertext`. Its plaintext has exactly `schema`, `keyId`, `privateKeyPkcs8`, and `createdAt`. Root public key, BLAKE3 key ID and creation time must agree across authenticated layers. Existing chain derivation domains and encoding rules remain unchanged.

The current Castaway envelope has exactly `schema`, `contentsSchema`, `ownerPublicKey`, `exportedAt`, `kdf`, `aead`, and `ciphertext`. Its decrypted `castalia.castaway-contents.v1` has exactly `schema`, `version`, and `sections`; `sections.identity` is required, while `memberships`, `scopedMemberships`, and `chainAccounts` are optional. Unknown sections fail closed.

The complete nested v1 payload remains defined by the checksum-pinned [Web types/parsers](../../../contracts/portable-web/src/castaway.ts), [shared Rust portable implementation](../../../crates/castalia-wallet-core/src/portable.rs), and their membership dependencies. These new JSON Schemas cover the outer envelopes and root secret, **not a complete replacement for nested v1 payload validators**. SDKs must retain those validators for v1.

See [native recovery](../../native-recovery-session.md), [custody-v1 decisions](../../castalia-membership-v1-contract.md), [Castaway portability](../../castaway-portable-vault.md) and [provider profiles](../../provider-profiles-v1.md). The implemented portable subset and separately planned general Castaway vault have different scopes. Historical custody files misnamed `.castaway` retain the established content-validated legacy recovery path.

## 4. Proposed extensible shapes

These identifiers deliberately contain `draft`. Existing v1 readers/writers MUST NOT accept or emit them as v1. They are candidates for SDK/codec review, not deployed formats.

| Proposed layer | JSON Schema |
| --- | --- |
| Expanded recovery envelope | [wallet-custody-v2-draft](schemas/wallet-custody-v2-draft.schema.json) |
| Its encrypted root, private entries and coverage | [wallet-secrets-v2-draft](schemas/wallet-secrets-v2-draft.schema.json) |
| Extensible data envelope | [castaway-envelope-v2-draft](schemas/castaway-envelope-v2-draft.schema.json) |
| Its encrypted data-only entries | [castaway-contents-v2-draft](schemas/castaway-contents-v2-draft.schema.json) |
| Shared fields and typed-entry wrapper | [common definitions](schemas/common.schema.json) |

The candidate recovery envelope adds authenticated `contentsSchema` and changes its discriminator to `castalia.wallet-custody.v2-draft`. `keySuite: Ed25519` names the root anchor, not every connected account's algorithm. Its plaintext shape is:

```text
castalia.wallet-secrets.v2-draft
  version: 2
  ownerMemberKey
  root: existing castalia.wallet-secret.v1 shape
  custodyRevision
  entries[]: publisher-typed private recovery parts
  coverage[]: account recovery sources, included entry IDs and dependencies
```

The candidate Castaway envelope uses `castalia.castaway.v2-draft` and `castalia.castaway-contents.v2-draft`. Its plaintext has exactly `schema`, `version: 2`, `ownerMemberKey`, and `entries`. The [synthetic payload example](examples/castaway-v2-draft.contents.json) contains one publisher-defined connection description and no authority.

Both candidates retain Argon2id v19 (16-byte salt, 64 MiB, three iterations, parallelism one, 32-byte output) and AES-256-GCM (12-byte nonce, 128-bit tag). The complete header except `ciphertext`, including discriminators, is RFC 8785 JCS associated data. Payload JSON is JCS before encryption; binary values use canonical unpadded base64url. Fresh salt/nonce and the existing NFC passphrase rule apply. Independently generated encryption/decryption and downgrade vectors are required before stability. Schema matching cannot authenticate or decrypt a file.

Whole encoded artifacts are bounded to 1 MiB before parsing. Duplicate properties, unsupported identifiers, ambiguous encodings, failed authentication and mismatched holder/root/entry bindings fail without mutation. Existing custody timestamps use unsigned 64-bit values; SDKs need lossless handling or explicit rejection of unrepresentable values. Candidate counters and Castaway timestamps use safe unsigned JSON integers. JSON Schema alone cannot enforce lexical integer encoding, base64 residual bits, JCS bytes or private-key consistency.

## 5. Typed-entry wrapper

Each entry has exactly `entryId`, `publication`, `partId`, and `value`. `publication` has exactly `id`, `version`, and `sha256`, pinning the exact publication manifest bytes. The wrapper is standard; the publisher defines `value` through the selected part's schema.

Use the [checked data example](examples/castaway-v2-draft.contents.json) for actual JSON. Entry IDs must be unique within a payload. An SDK MUST validate both wrapper and typed value, resolve the exact installed publication/part/schema, and enforce its storage class before accepting it. No entry can override its destination or the core root/encryption profile.

Holder fields must agree across authenticated layers, but attribution is not proof of control of a remote account. Protocol-specific possession and issuer checks remain necessary. An entry import does not grant access, contact an endpoint, log in, publish or execute a command.

## 6. Publishing a connection schema

The [schema-publication contract](schemas/schema-publication-v1-draft.schema.json) is the SDK-facing publication shape. A publisher distributes a manifest and its referenced JSON Schema files. The [complete fictitious package](examples/example-connection/publication.json) demonstrates:

- `account`: non-authority description, assigned to `castaway`;
- `recovery`: independent private recovery material, assigned to `recovery`;
- `session`: access-token shape, assigned to `device-local`;
- a declared read operation with pinned request/result schemas and `requiresApproval: true`.

The manifest declares `profileId`, `profileVersion`, publisher origin, title, parts, optional operation declarations (the array may be empty), and required wallet profiles. Each part declares `partId`, `storage`, `contentClass`, `valueSchema`, and `requiredForRecovery`. Schema references carry `$id`, a package-relative path and SHA-256 of **exact UTF-8 bytes**. Changed bytes require a new profile version and updated digest. Reusing an ID/version for different bytes is an integrity conflict.

| `storage` | `contentClass` | Allowed destination |
| --- | --- | --- |
| `castaway` | `data` | Candidate Castaway entries only |
| `recovery` | `authority` | Candidate encrypted recovery entries only |
| `device-local` | `session` | Host protected storage; never either portable artifact |

The installed publication determines routing; file contents cannot override it. `requiredForRecovery` applies only to authority parts and is false for data/session parts. A partial backup must disclose omitted selected account material regardless of that flag. Publishers cannot insert parts into strict v1 sections or redefine the wallet root, encryption, approvals or trust policy.

Publishing a schema does not establish publisher authenticity, install code, approve a connection or prove a data classification safe. A malicious `contentClass: data` declaration cannot launder secrets into Castaway. Wallets explicitly approve understood, reviewed packages/classifications; arbitrary unknown packages are not active-import targets. There is no universal registry, brand or membership requirement.

### SDK resolution/discovery contract

1. Inspect the discriminator and select an explicitly supported envelope/payload profile.
2. Authenticate/decrypt in wallet-owned execution. Keep private recovery plaintext outside ordinary application-origin code.
3. Resolve exact publication ID/version/digest from installed packages; check manifest, schema `$id`s and byte digests.
4. Resolve `$ref` dependencies offline within the package or explicitly pinned standard resources. An identifier is not permission to fetch a URL. Forbid uncontrolled remote loading, executable code, path traversal and symlinks outside the package.
5. Validate values, route parts to their allowed store, and check holder/identity/coverage/protocol semantics. Unknown profiles/versions fail without active-state mutation. Keeping an original opaque encrypted file does not mean importing or re-exporting unknown values as safe data.
6. Preview changes, obtain consent and atomically commit against the expected revision. Do not install only the recognized half of a failed import.
7. Advertise only installed, understood profile/operation versions. Request/result schemas describe bytes; separately supported adapters and fresh account/operation/origin-bound approval authorize use. Packages contain no downloaded implementation.

Schema packages are bounded to 4 MiB, individual schema files to 64 KiB, reference closure to 64 resources and depth 64. Values must satisfy the artifact bound plus their own schema limits. Validators disable networking and enforce evaluation/time/resource limits. Namespace ownership and package authenticity require independent trust; hashes prove integrity only. Publication versions use the shared SemVer shape, including optional prerelease and build metadata. Version matching compares the complete string, including build metadata, with no automatic semver-range negotiation.

## 7. Recovery inventory

The root and typed private entries live together inside candidate recovery encryption. Each selected account's coverage source is `included`, `root-derived`, `external`, or `excluded`. Included entry IDs must exist in that payload and belong to the account. Root-derived coverage requires an implemented pinned derivation; external coverage names dependencies; exclusion gives a reason. Account/entry IDs must be unique and referentially consistent. Required private material must not be silently omitted.

`custodyRevision` tracks secret material/recovery metadata, independently of unrelated UI/local-store revisions. Adding/replacing independent secrets invalidates the prior complete-backup claim. Verification reopens the actual artifact and compares authenticated coverage/material to current custody; checking the Member Key alone is insufficient. A stale completion token cannot verify a newer revision.

An older root backup cannot contain an independent Matrix/Nostr secret added later. A newer backup cannot rewrite or revoke older copies. Sessions require new-device authentication; external signers and remote history backups remain external dependencies.

## 8. Connection profiles and compatibility

The [connected-account profile](connected-accounts.md) retains Matrix/Nostr/chain specifics and the existing [descriptor schema](connected-accounts.v1-draft.schema.json). It can be a value contract in a suitably published data part; it is not the entire file standard or a new v1 section.

Publishers can define other types through the same publication/entry wrapper, without a new core envelope for every service. Changing the root model, primitive encryption profile or top-level format still requires a separate standard version/migration. A schema package cannot introduce a backdoor recovery root. Current strict v1 parsers and byte contracts remain authoritative; expanded draft shapes require new codecs and explicit migration.

## 9. Validation and adoption

In an isolated Python environment with `jsonschema` 4.x, run `python3 docs/standards/cws-001/validate.py` for account-descriptor cases and `python3 docs/standards/cws-001/validate-files.py` for file/publication checks. These cover meta-schemas, offline references, synthetic package integrity, wrapper/value validation, routing, negative cases and the existing public custody-v1 envelope vector. They do not ship an SDK or test cryptographic recovery.

The `Wallet standard schemas` CI job runs both validators independently of the application build gates.

Stability requires independent cross-language encryption vectors, private-encoding review, coverage invariants, cancellation/storage/downgrade tests, validator resource controls, two-consumer native/Web interoperability and physical-device acceptance. SDK implementation, package resolution in installed wallets and Matrix/Nostr adapters remain unimplemented. Reuse/contribution policy is still an explicit decision under [the baseline notice](../../../NOTICE.public-baseline.md); no new license is granted by this draft.

Canonical v1 source contracts win over these structural companions in any disagreement. No installed wallet, current backup, signing method, application approval or provider trust changes merely because this draft is published.
