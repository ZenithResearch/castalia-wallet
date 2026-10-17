# Castaway Portable Vault

Status: design contract v0.1; no conforming encoder or decoder is implemented yet

## Canonical definition

A `.castaway` file is an application-neutral encrypted data vault that a person can move between Castalia-compatible wallet applications. It can contain supported non-authority primitives and objects expressed through the versioned Zenith Ontology, including identity data, public credentials, public account descriptors, knowledge objects, rights envelopes, relationships, receipts, and application state.

The filename extension names the portable vault contract. It does not name one wallet implementation, one key type, one network, or one account.

```text
person-controlled encrypted vault
            |
            +-- ontology-typed primitives
            +-- ontology-typed objects
            +-- relationships and provenance
            +-- rights and disclosure policy
            +-- public account descriptors
            +-- no private authority or recovery material
            |
      any compatible wallet
```

## Boundary with wallet recovery

`.castaway` and `.castalia-recovery` are deliberately different artifacts:

| Artifact              | Purpose                                                                               | Portability boundary                                                                 |
| --------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `.castalia-recovery`  | Restore Castalia Wallet's encrypted root signing authority                            | Castalia Wallet custody implementations that understand `castalia.wallet-custody.v1` |
| `.castaway`           | Carry a user's encrypted, ontology-typed vault between compatible wallet applications | Any implementation conforming to the future Castaway vault contract                  |
| Membership credential | Public proof that an issuer recognized one Member Key                                 | Verifiers of that exact credential version                                           |
| Web session or cookie | Temporary relying-application state                                                   | One application/session boundary; never a vault                                      |

A recovery file is not a miniature Castaway vault, and Castaway is not an extensible recovery container. The recovery root may deterministically restore several chain keys without copying those keys into Castaway. A Castaway vault may contain public account descriptors, but it must never contain an encrypted authority capsule, root seed, private key, mnemonic, recovery key, bearer secret, signing capability, or executable object. Merely opening a vault must never install a key, grant a capability, approve an origin, create a session, or claim membership.

This is a custody and artifact-semantics boundary, not an unlinkability claim. The current chain accounts share one deterministic wallet root and may be linked to the Member Key through membership-payment activity. The separation still prevents a routine data export from becoming spend authority or an additional recovery path.

## Data model

The exact wire encoding remains to be frozen. A conforming format must nevertheless preserve these semantic layers:

1. **Vault envelope** — format identity, version, encryption profile, bounds, and the minimum metadata needed to select a compatible decryptor.
2. **Vault manifest** — the ontology release or compatible profile needed to understand the entries, plus integrity commitments to the encrypted payload.
3. **Entries** — primitives or objects with stable identity, an ontology type identifier, schema/version information, and a value or encrypted attachment reference.
4. **Relationships** — typed edges between entries. Applications must not infer relationship meaning from display names.
5. **Provenance and rights** — source, authorship, transformation history, disclosure scope, retention, revocation semantics, and redistribution constraints where applicable.
6. **Authority exclusion** — an explicit validation boundary that admits ordinary data, public credentials, and public descriptors while rejecting private signing authority, bearer secrets, recovery material, and executable content.

Unknown ontology types must be preserved as opaque authenticated entries when safe to do so. A wallet must not discard data simply because its current interface cannot render it, and it must not execute, install, or disclose an unknown entry.

## Portability invariants

1. The person controls the vault file and chooses when it is exported, copied, imported, or disclosed.
2. The same authenticated bytes retain the same semantic type across compatible applications.
3. The Zenith Ontology supplies meaning; a particular wallet's UI labels do not become the data model.
4. Wallet implementations may render different projections while preserving the underlying entries and relationships.
5. Import is fail-closed, bounded, and non-mutating until the envelope, authentication, manifest, and selected operations validate.
6. Data portability excludes authority portability. Public credentials require type-specific verification and presentation, while private keys, recovery material, bearer secrets, signing capabilities, and executable objects are invalid Castaway entries.
7. A vault does not create Castalia membership, a Web session, Matrix access, a Dregg cell, or a capability merely by containing related objects.
8. Encryption protects confidentiality at rest; it does not prove provenance, truth, safety, authorization, or network acceptance.
9. Exporting a vault creates another copy. Deleting one copy cannot revoke other copies.
10. Compatible applications must preserve unsupported authenticated entries or explicitly refuse the import; silent lossy conversion is forbidden.

## Security requirements

- The outer format must carry a distinct Castaway magic/schema identifier before v1 is declared stable.
- Encryption must authenticate the format version, manifest commitment, entry index, and all non-secret routing metadata.
- KDF and AEAD profiles must be versioned, bounded, and resistant to attacker-selected resource exhaustion.
- Parsers must reject duplicate fields, ambiguous encodings, path traversal, external fetches, and unbounded decompression before exposing plaintext.
- Private data entries remain inside wallet-owned execution. Web pages receive only individually approved projections.
- Public account descriptors may travel in Castaway; root seeds, mnemonics, recovery keys, raw private keys, encrypted key capsules, bearer secrets, and signing interfaces are rejected everywhere in the format, not merely in descriptor-only sections.
- Importers must verify public credentials before presenting them and must reject authority-bearing or executable entries before mutating wallet state.
- Applications must treat ontology identifiers and schema versions as data, never as permission to dynamically execute downloaded code.
- A failed import must leave the existing vault, keys, memberships, approvals, and application state unchanged.

## Historical `.castaway` recovery exports

Castalia Wallet commit `f7418f4` emitted files named `Castaway-<timestamp>.castaway`, but their contents were the single-purpose `castalia.wallet-custody.v1` recovery container. Commit `b38bb31` corrected new exports to `.castalia-recovery` so `.castaway` could name this broader vault.

Those historical files are recoverable authority and must not be discarded. They are also not Castaway vaults.

A compatible migration path must:

1. recognize the exact bounded `castalia.wallet-custody.v1` structure as a legacy recovery artifact;
2. authenticate it with the user's passphrase through the custody implementation;
3. restore the same identity without exposing plaintext key material;
4. offer a freshly randomized `.castalia-recovery` export; and
5. never reinterpret the legacy container as a general ontology-entry collection.

Until that migration UI ships, a user may preserve the original file, copy it, and rename only the copy from `.castaway` to `.castalia-recovery`; the encrypted container bytes are unchanged and the custody parser remains authoritative.

## Work required before wire-format v1

- publish stable Castaway and Zenith Ontology identifiers;
- freeze the canonical envelope and entry encodings;
- choose the versioned KDF, AEAD, size, streaming, and attachment profiles;
- specify content identity, relationship encoding, provenance, and rights envelopes;
- define safe opaque preservation and selective export;
- freeze authority-exclusion rules and negative fixtures proving that recovery, private-key, bearer-secret, signing-capability, and executable entries fail closed;
- publish positive, negative, downgrade, truncation, and resource-exhaustion vectors;
- prove at least two independent wallet implementations can round-trip unknown entries without loss; and
- ship the historical recovery migration before any new `.castaway` file is emitted.

No current build should claim Castaway compatibility until those gates are complete.

## Related documents

- [Castalia Member Key and Zenith-Signed Membership](castalia-member-key-and-membership-cell.md)
- [Dregg Hybrid Identity](dregg-hybrid-identity.md)
- [Security Model](security-model.md)
- [Portable Data Is the Part of Web3 We Still Owe People](articles/portable-data-and-web3.md)
