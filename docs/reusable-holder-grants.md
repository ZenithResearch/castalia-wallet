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
cancelled by lock, document replacement, path/query navigation or trust changes.
Changing only the fragment of the same document retains the connection without
changing its expiry. Only the exact extension-owned
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


## Current and future resources

The existing signed `Scope::All` covers the live resource collection selected by
that permission's unchanged opaque provider conditions. It is not an inventory
of IDs at issuance. A saved grant survives encrypted backup/restore and can
produce an equal same-Wallet credential or narrow to a path for an item created
later. A fixed path cannot become `All`. Provider adapters enforce collection
meaning and current status; Core never guesses predicate implication. No Core
runtime, pin, signed format, backup migration or onward delegation change is
needed for the DevGraph current-and-future Arena selector.

## Resource selection prerequisite (source-only)

Core's Rust `resource_selection::review` and `can_narrow` now use the shared
`secs.resource-selector.v1` primitive. It distinguishes exact objects from
descendants and All, binds explicit kinds to a verified canonical service, and
retains hierarchy guards during exact narrowing. Unknown implications are rejected;
Core never trusts a client graph to prove ancestry. The source is pinned in the
existing vendored-source manifest and common media vectors run on both sides.

This is unsigned public selection review, not a custody operation or grant. It
adds no browser/native command, signer capability, stored Wallet field or backup
migration. Existing holder-grant v1 permissions still accept only All/Paths; the
new selector cannot be inserted into them. Operation/constraint/holder/lifetime
checks and disabled onward delegation stay unchanged. Provider effect plans and
a separately versioned signed integration must be implemented before issuance.
No app is rebuilt or installed and no source pin used by installed apps changes.

## Correlated compound resource review

Core also reuses the shared in-process EffectContract/EffectRule/RoleSelection
types and `can_narrow_effect_rule`. Every role narrows one complete parent
rule: A→B and C→D cannot yield A→D. The installed provider declares the full
effect roles and cardinality; caller metadata is not trusted authority.

These are unsigned Rust review helpers, not new signing/storage/transport APIs.
The provider must resolve actual source/destination and affected resources, fence
policy and resource versions, recheck the SAME rule before/after mutation and
roll back on failed postconditions. Operation/holder/validity/revocation/replay
checks remain mandatory. Database execution adapters and signed integration are
still unimplemented here; existing v1 grants and encrypted backups are unchanged.

## Scoped holder v2 candidate

Core and the existing native JSON/Chrome WASM operations now accept separately
versioned v2 grants, credentials and presentations. Complete role selectors narrow
one parent permission; onward delegation remains disabled. Existing v1 serialized
records, encrypted custody, backup owner checks and explicit save consent remain.
A failed v2 verification never retries as v1. New clients must be coordinated with
providers before offering v2; old clients refuse it. This is source integration,
not an installed app, production migration or released package. The DevGraph
adapter currently issues reusable read grants; writes retain the existing signed
projection path with paired receiver checks. Generic role-specific administration
and holder-derived write issuance remain follow-up gates.

## Chrome saved-grant management

Wallet → Saved grants & backup shows a compact card for each locally saved
canonical service. A card displays its service identifier, permission count and
validity period; opening it reveals issuer, identity binding, grant ID, revision,
permission restrictions and every original claim. Service names and claims are
rendered as text. The Wallet does not infer current server approval from a saved
record: “Saved in Wallet” describes local storage only. An expired or future
validity period is labeled using the local clock, without changing verification.

Update access expands a guide to the existing service-driven flow: open the
service, choose Sign in with Wallet → Saved access help → Check saved access →
Check approved access, review the result and Save grant in Wallet. The guide
itself does not contact the service. Saving an approved replacement overwrites
that service’s local record; removing the old copy first is unnecessary. Then
review a fresh browser session to use the updated permissions. Refresh on the
saved-grants page reloads local Wallet storage; it does not fetch a new approval.

Remove from Wallet opens the existing one-shot, exact-record removal review.
Confirmation removes only that service’s encrypted local grant. It does not
revoke server approval, delete copies in old backups, clear recovery journals,
or end credentials already issued to applications. Applications retain their
separate sign-out and service-side revocation paths. Cancellation changes no
records; an uncertain confirmation asks the user to refresh and inspect rather
than automatically repeating removal. Wallet invalidation clears the page and
late list replies cannot restore private card details after lock or identity
change. This UI changes no signed formats, custody operations or permissions.

`node --import tsx scripts/smoke-grant-cards.mts` checks the actual page in a
new disposable headless browser profile with a synthetic extension-runtime
fixture. It covers collapsed details, update guidance, removal, lost confirmation,
late replies after lock, text injection and narrow layouts. It accesses no real
Wallet or service. Pass `CASTALIA_CHROMIUM_EXECUTABLE` to select a browser and
`GRANT_CARDS_SCREENSHOT_DIRECTORY` to retain synthetic screenshots. Pass
`GRANT_CARDS_EXTENSION_DIRECTORY` to verify and exercise an exact packaged UI
instead of bundling from source. The separate
packaged native-backed session smoke retains its existing signing and fresh-grant
coverage with selectors matching these controls.
