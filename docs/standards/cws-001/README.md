# CWS-001: Connected accounts and recovery

Revision: **0.1.0-draft**

Published draft date: **October 18, 2026**

Status: **Proposed; not an implemented recovery format or a conformance claim**

## 1. Purpose and scope

A person must be able to add an account from a phone or another compatible wallet without replacing their existing Castalia identity. This proposal covers public account descriptions, private custody, recovery coverage, explicit import consent and account-specific authorization. Initial account families are Cardano, EVM, Solana, Nostr and Matrix.

A connected account is a local association between a wallet and a protocol identity. It is not automatically a membership, verified ownership proof, login session, spending permission or approval to publish messages. Connecting an account MUST NOT give an application generic signing access.

The [descriptor schema](connected-accounts.v1-draft.schema.json) and [structural cases](structural-cases.json) are review artifacts. No current wallet decoder accepts this draft identifier. This document specifies recovery requirements but deliberately does not freeze a new cryptographic recovery envelope, private-key derivation or signing transcript.

## 2. Existing contracts and compatibility

The following remain unchanged:

| Existing artifact | Meaning retained |
| --- | --- |
| `castalia.wallet-custody.v1`, normally `.castalia-recovery` | Encrypted root signing authority with frozen KDF, AEAD, key encoding and associated-data bytes |
| Existing chain-account derivations | Versioned, domain-separated derivations from the wallet root; current public addresses remain descriptor-only previews |
| `castalia.castaway.v1` / `castalia.castaway-contents.v1` in the native/Web recovery session | Strictly enumerated portable identity/proof/public-descriptor sections; no unknown sections or private authority |
| Future general `.castaway` vault | Separate non-authority data-portability design; no secret keys, recovery material, bearer credentials or encrypted authority capsules |
| Local encrypted snapshots and device Keychain | Installation-specific persistence, distinct from an exported recovery artifact |

The implemented portable subset and the future general Castaway design are different scopes; this proposal does not claim either implements CWS-001. Historical custody files with a misleading `.castaway` filename MUST continue through the established content-validated legacy recovery path.

An implementation MUST NOT insert account secrets into the existing v1 plaintext object or add a new section to a strict v1 parser while retaining its identifier. Expanded secret custody requires a separately versioned, reviewed format, including changes to local snapshots where necessary. Existing backups MUST restore the same original wallet even if no connected-account information exists. Missing information means absent or unavailable, never a newly generated replacement identity.

The sources of these boundaries are [native recovery](../../native-recovery-session.md), [membership/custody v1](../../castalia-membership-v1-contract.md), [Member Key and chain accounts](../../castalia-member-key-and-membership-cell.md), [provider profiles](../../provider-profiles-v1.md), and [Castaway](../../castaway-portable-vault.md).

## 3. Four storage classes

| Class | Examples | Required treatment |
| --- | --- | --- |
| Public account description | Protocol, network, address/public key, Matrix user ID and reviewed homeserver | Allowlisted descriptor; disclose only with the person's approval |
| Portable private authority or recovery material | Imported Nostr key; Matrix secret-storage or cross-signing recovery material | Encrypted wallet-owned custody; include in the selected account's recovery coverage |
| Device/session state | Access/refresh tokens, current Matrix device crypto store, application approvals, Hermes key, Tailscale node/join state | Installation-specific protected storage; excluded from the portable account profile and restored through explicit reauthentication/re-enrollment |
| External authority | Hardware signer or Nostr remote signer | Record the dependency; never claim the wallet backup contains the external signing key |

Encryption alone does not turn private authority into ordinary data. A `.castaway` exporter MUST exclude secrets, encrypted secret capsules and reusable signing/bearer handles at every nesting level. It MUST construct descriptors from typed, allowlisted public fields rather than serializing a custody object and removing known secret names. Structural JSON validation cannot discover every secret hidden inside arbitrary text.

Account lists link identities across services. An exporter MUST NOT treat them as freely public merely because each public key is public. A requesting origin receives only selected descriptors after approval. `ownerMemberKey` is an attribution field, not proof that the person controls every listed account. Import MUST initially treat such control claims as unverified.

## 4. Public descriptor draft

The exact draft discriminator is `castalia.connected-accounts.v1-draft`; `version` is the integer `1`; `authority` is exactly `descriptor-only`. It MUST NOT be advertised as stable `v1`.

The [JSON Schema 2020-12 document](connected-accounts.v1-draft.schema.json) defines the closed structural allowlist. The authenticated document has one holder key and up to 128 records. Each record has:

- `accountId`: a UUID allocated by the wallet and preserved in subsequent exports/recovery; it is not a capability or proof;
- `kind`: a registered protocol family;
- `networkId`: the protocol/network namespace;
- `identifier`: the protocol's public account identifier;
- `publicKey`, where applicable: the declared suite, encoding and public bytes;
- `homeserver`, only for Matrix: a reviewed HTTPS origin, without embedded credentials, path, query or fragment.

The entire input MUST be bounded to 1 MiB before parsing, use UTF-8, and reject duplicate JSON properties, unknown fields, unknown versions and unknown families. Account IDs MUST be unique. Nostr's `identifier` MUST equal its x-only public key. Matrix's network namespace MUST identify the server-name portion of its user ID; the homeserver origin may legitimately differ through Matrix discovery. URI and protocol normalization, valid curve points, address checksums and account-control verification require additional semantic validation. Passing the JSON schema alone is insufficient.

Descriptors MUST NOT contain local secret references, derivation roots, private keys, recovery keys, access tokens, approval grants, executable adapters or signed commands. Import MUST NOT fetch a URL, log in, publish an event, approve a provider, replace custody or activate an account merely because those bytes were present. Unknown authenticated data is preserved only where the containing format explicitly supports safe opaque preservation; otherwise the import fails without mutation.

An illustrative descriptor is available in [examples/matrix-and-nostr.json](examples/matrix-and-nostr.json). All fixture identifiers are synthetic or published public test values; no fixture is an account credential or ownership proof.

## 5. Protocol profiles

### 5.1 Existing chain accounts

Cardano, EVM and Solana retain their current derivation identifiers and public descriptors. This draft defines no new address derivation, signing authority or financial capability. An imported independent chain key MUST NOT be labeled root-derived. A historical root backup cannot restore an unrelated key imported later.

Ethereum and another EVM network may share one existing key while retaining separate network/account records. A recovery inventory MUST distinguish the underlying secret from the public records it supports so that duplicated descriptors do not imply duplicated independent recovery secrets.

### 5.2 Nostr

The public identifier is the 32-byte x-only secp256k1 public key used by Nostr's BIP-340 event signatures. Display encodings such as `npub` are derived presentations; private encodings never belong in a descriptor.

A wallet MAY create a fresh independent key, import an existing key within its custody boundary, or connect to an external signer. This draft standardizes no root-derived Nostr key. A future derivation profile requires a separate, versioned, reviewed algorithm and cross-implementation vectors; it MUST NOT reuse the Member Key or EVM secret as the Nostr secret.

NIP-49 encrypted private-key import/export, if supported, is an authority-transfer ceremony. NIP-46 remote-signer connection secrets are also credentials and stay outside Castaway. A remote signer requires its own recovery/reconnection path. Implementations must explicitly negotiate supported event-signing and encryption operations; an account record grants none of them. See [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md), [NIP-49](https://github.com/nostr-protocol/nips/blob/master/49.md) and [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md).

### 5.3 Matrix

The public identity is the Matrix user ID plus its server namespace and reviewed homeserver. It is not a single blockchain-style signing key. Account authentication, per-device cryptographic state, cross-signing and encrypted-history recovery are separate concerns.

A compatible integration MUST use Matrix's own account/device verification and secret-storage mechanisms. Wallet-owned portable recovery may protect the secret-storage key and applicable cross-signing/backup recovery secrets. The Castalia root MUST never be supplied to the homeserver or an ordinary client as its Matrix credential.

Restoring these secrets does not itself log in. A restored installation MUST establish an appropriate device session, verify it, and restore room keys through Matrix's supported mechanisms. A recovery key does not contain message history or guarantee that a server still has the relevant backup. This profile excludes copying live access tokens, ratchets or an active device identity between installations. Message-history archives, if offered, require a separate reviewed format and disclosure.

See the [Matrix client-server specification](https://spec.matrix.org/v1.19/client-server-api/), especially secret storage, cross-signing, device management and server-side key backup.

## 6. Adding an account after recovery

A conforming interface MUST provide a flow equivalent to:

1. Unlock the existing wallet and choose Add connected account.
2. Select the protocol and create, authenticate, import or connect to an external signer through its explicit ceremony.
3. Review public identity, secret custody destination, recovery coverage and any remote dependency. A secret must never be requested through an ordinary application-origin form.
4. Validate the candidate inside wallet-owned execution; bind it to the existing holder and current storage revision.
5. Obtain confirmation, durably commit atomically, then update the visible account list. Cancellation, stale state or failure MUST leave prior custody intact.
6. Offer an updated recovery backup when portable secret coverage has changed, then verify the actual exported artifact.

There is no requirement to create a new Castalia root. Importing a standalone account secret MUST NOT replace the wallet root, erase other accounts or inherit application permissions. Importing a data-only descriptor MUST NOT mark private custody as installed.

## 7. Recovery coverage and freshness

A future full recovery profile MUST authenticate an internal inventory binding the holder, custody revision, account IDs, supported protocol/derivation versions, included portable secrets and explicit exclusions/dependencies. Public headers SHOULD reveal only what a compatible decryptor needs; service IDs and the account inventory belong inside authenticated encryption. A custody revision here tracks secret material and recovery metadata, independently of unrelated UI edits or installation-local snapshot revisions. Actual secret encoding and cryptographic envelope bytes remain a prerequisite for a later stable profile, not defined by this descriptor schema.

For each account, the wallet MUST distinguish:

- recoverable from included root under an implemented, pinned derivation;
- recoverable from included independent encrypted secret material;
- dependent on external authentication, signer or remote backup;
- explicitly excluded or unavailable.

A wallet MUST NOT display “all accounts backed up” while omitting a selected account's portable secrets. A deliberately partial export must name its exclusions before confirmation. Public descriptors alone are not private recovery coverage. External dependencies must remain visible even when all portable secrets are included.

Adding, importing, replacing or rotating independent recovery material MUST invalidate any prior complete-backup claim. Changing a label need not invalidate cryptographic coverage; the UI must separately disclose stale descriptive metadata. Verification MUST reopen the actual supplied file, authenticate it, and compare its covered material/account inventory to the current committed custody revision. Matching only the Member Key is insufficient. A stale verification token MUST NOT clear the newer backup requirement.

An old backup remains valid for exactly what it contains. A deterministic derived identity may be reproducible from an older root backup only when the required derivation profile and metadata are recoverable. An imported Nostr key or independently initialized Matrix secret added after export is absent from that old file. Exporting a newer backup cannot update or revoke older copies.

## 8. Authorization, removal and lifecycle

Wallet-owned signing/secret use MUST bind approval to the selected account, exact operation, requesting origin/application, recipient/receiver, material being signed or disclosed, freshness and relevant protocol context. A Matrix login, Nostr account association, Castalia membership and Devgraph read grant do not confer one another's permissions. Unknown operations fail closed; approvals and provider trust MUST NOT silently return with a backup.

Locking, background transitions or identity changes MUST cancel pending ceremonies and invalidate stale callbacks. Approval has to remain valid at the commit/use boundary. Restore/import MUST use the existing staged-preview, expected-revision, durable-commit discipline or an equivalent transaction protocol.

“Remove from this wallet” MUST explain which local data is deleted and MUST NOT claim to revoke a Matrix device/session, remove a Nostr event from relays, rotate a chain key or destroy copied recovery files. Remote revocation and key rotation require their own confirmed protocol operations. Account replacement MUST invalidate account-bound approvals without changing unrelated identities.

## 9. Conformance and implementation gates

Conformance is profile-specific. Implementations may claim only the tested revision and subset, never generic “CWS compliant” based on descriptor validation alone.

| Level | Required evidence |
| --- | --- |
| Descriptor reader/writer | Strict bounded parser, structural fixtures, protocol semantic/cryptographic checks, no private fields or import side effects, consented disclosure |
| Account custody adapter | Protocol-specific create/import/use with wallet-owned private execution, exact consent, cancellation and durable transactional tests |
| Expanded recovery | A newly versioned envelope/secret encoding with reviewed KDF/AEAD/AAD, independent cryptographic vectors, authenticated coverage and stale-backup tests |
| Cross-wallet recovery | At least two independently exercised consumers, including native and Web where claimed, preserving identity and distinguishing fresh session setup from recovered authority |

Required negative cases include wrong password, corruption, duplicate properties, unknown schema/family, holder mismatch, duplicate/conflicting account IDs, wrong protocol identifier, hidden private authority, stale revision, cancellation, lost storage commit acknowledgement, missing external signer, expired Matrix session and an older backup that lacks a newly imported secret. Tests MUST show failures leave prior custody and approvals intact. The [structural cases](structural-cases.json) cover only structural admission, not cryptographic or device qualification.

Release order is shared-core/versioned custody design, reviewed account adapters, native/Web UI and migration, independent cross-wallet vectors, then a stable specification decision. No installed iPhone, browser adapter, current backup, existing trust root or signing method changes merely because this draft is published.

## 10. Reproducing structural checks

Use an isolated Python environment with `jsonschema` 4.x, then run:

```sh
python3 docs/standards/cws-001/validate.py
```

The validator checks the schema, the synthetic example and expected structural admission/rejection cases. It is a development aid, not a production parser, account-control verifier, cryptographic conformance suite or test of an installed wallet. Protocol semantic checks and the runtime gates above remain mandatory.

## 11. Open decisions before a stable release

- Explicit standards-document/schema licensing and contribution/IP policy, consistent with [the public baseline notice](../../../NOTICE.public-baseline.md); this draft grants no new reuse license.
- Expanded recovery envelope, private payload and authenticated inventory encodings; bounded KDF/AEAD profiles and cross-language vectors.
- Exact Matrix SDK integration, portable secret set, local crypto-store protection and external-backup availability checks.
- Nostr supported signing/encryption methods, standalone authority import formats, and external-signer reconnection behavior.
- Whether a future Nostr root-derivation profile is desirable; privacy/linkability implications require explicit review.
- Registry evolution, independently verified account-control proofs, disclosure policy and unknown-profile interoperability.
- Security review and physical-device acceptance for storage, permission prompts, QR/Files/USB transfer, recovery, accessibility and cancellation.

This draft has no runtime adoption claim. Its purpose is to make those implementation choices reviewable before a shared custody format or connected-account API is shipped.
