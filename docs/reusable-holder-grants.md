# Reusable grants and Wallet Core 0.4

Status: source integration in progress, not an installed or deployed release.
The shared Rust contract is exported from the exact secS revision recorded in
`vendor/secs-grant-contract/SOURCE.json`. The same implementation validates both
native and Chrome/WASM credentials; the UI never signs or decides attenuation.
Old custody, recovery, read credential, membership, provider-profile and Packet
formats retain their existing bytes and interpretation.

A provider signs a reusable grant scoped to its canonical service and recipient
Wallet. A recipient explicitly reviews and saves it before use. The Wallet may
produce a finite same-holder credential with equal permissions, fewer correlated
permission records, or narrower descendant path roots. Opaque conditions remain
exact; there is no arbitrary predicate implication engine. Another recipient,
permission widening, lifetime widening and onward delegation are rejected.
Transport URLs are not grant authority. Origin consent and TLS remain separate.
A provider must use a shared canonical registry across its access points, check
current assignment/revision/revocation and graph ancestry, and atomically consume
presentation nonces. A saved signature is not proof of current active status.

## Storage and backup

Native Core stores accepted records in the encrypted, versioned SQLite snapshot
through its existing prepare/CAS/confirm transaction. Browser storage holds only
a Wallet-key-encrypted grant bundle, serialized under the custody operation queue.
The new encrypted grant backup is separate from a recovery key file and a Castaway
identity-data file. It contains the signed grants and recorded public issuer pins,
not the Wallet signing key. The same recovered Wallet can decrypt it. Import is
reviewed, validates every signed record, rejects conflicts and never installs
runtime issuer trust or revives revoked access. A device-bound grant may still
need a new provider grant for a replacement installation.

New readers accept old Wallet snapshots without a grant section. Once new grants
are saved, older cores with closed local-state decoders cannot read that newer
snapshot; they must fail closed. Keep the prior encrypted snapshot and versioned
app rollback evidence. Do not silently write a reduced snapshot through an old
core or claim the old recovery/identity exports contain the new grant database.

## Interfaces

Native session commands: `review_holder_grant`, `prepare_holder_grant`,
`holder_grants`, `holder_grant`, `derive_holder_credential`,
`present_holder_credential`, `forget_holder_grant`, `export_holder_grant_backup`,
`prepare_holder_grant_backup`. They expose closed typed requests and no key or
arbitrary-signing callback. A save is committed only after UI review.

Chrome advertises `holder_grant_v1`. Its document-bound `readAccess` operations
are `save_grant`, `use_grant` and `present_grant`. Saving and opening a new
connection require a top-level gesture and Wallet approval. Unknown origins cannot
read grant state. Handles are scoped to origin/tab/document/custody epoch and are
cancelled by lock, navigation or trust changes. Only the exact extension-owned
Wallet page may list, back up or restore grants. Page code receives a request
presentation, not the encrypted database, a signing key or an enumeration API.

Core validation is not an installed process-isolation claim. The separately
planned macOS signer process and iOS signer-app cutover remain unfinished.
The generic contract can represent service permissions, but the first DevGraph
adapter here qualifies reads; existing write authority is not automatically
replaced or widened by a saved read grant. Native app packaging, full suites,
negative boundaries and actual Tailscale qualification are required before release.

## Service and route identity

Core 0.4.1 verifies the shared issuer-signed `secs.service-access-point.v1`
binding. A binding authenticates an HTTPS access point, fixed protocol prefix
and stable authority receiver for a canonical service; it grants no access.
Chrome keeps site approval and document/installation binding on the actual origin.
Only an already-approved issuer/caller can translate consent to the signed
authority receiver. No translated trust pin is persisted, no site is approved
automatically, and existing legacy pending actions retain their original receiver.

The public `servicePresentationContext` WASM helper and native
`verify_service_access_point` command verify public metadata without unlocking
or altering custody. Existing read APIs and credential bytes remain unchanged.
Providers still check current assignments, revocation and replay on every use.
Deployment and real-device qualification remain distinct from source tests.
