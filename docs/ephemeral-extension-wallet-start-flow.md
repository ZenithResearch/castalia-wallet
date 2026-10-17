# Legacy Ephemeral Extension Wallet and Start Flow

Status: retired prototype; retained only as compatibility context

The original `/start` prototype used a disposable service-worker key, signed a local onboarding presentation, and stopped before membership issuance. That is no longer the active Join architecture. Do not use this document to infer current custody, membership, or user-facing behavior.

The active contract is [Castalia Member Key and Zenith-Signed Membership](castalia-member-key-and-membership-cell.md). The Dregg permissionless v2 and authority-owned v1 paths remain versioned compatibility code.

## Why the prototype was retired

The prototype deliberately proved only that an extension-held key could sign a bounded challenge. It could not support the current product invariant because:

- the key was disposable rather than encrypted durable custody;
- local proof of possession was not a Castalia membership;
- no Dregg membership cell was issued;
- the page could not recover the same identity after a worker or browser restart.

Those limitations are not properties of the current Wallet.

## Active `/start` boundary

The current flow is:

1. Castalia Web requires `membershipJoinProtocol: "castalia.zenith-membership.v3"` and refuses older providers with an explicit Wallet update message.
2. Castalia Web asks Wallet to open a Chrome-owned popup outside page-owned DOM.
3. Wallet creates or unlocks its encrypted durable Dregg-hybrid Member Key. Ed25519 and ML-DSA-65 are deterministically rooted in the same recovery seed.
4. Wallet signs the fixed Zenith v3 possession transcript.
5. Zenith verifies possession and returns the deterministic signed Active credential.
6. Wallet verifies its exact owner, issuer trust root, membership ID, fields, and issuer signature.
7. Wallet persists the public credential and approves the initiating Web origin only after the Chrome-owned popup discloses it and Wallet revalidates the initiating tab at completion.
8. Wallet emits `castalia:wallet:membership-flow-ready` with the full public credential.
9. Web independently verifies that credential and displays success. A no-detail event retains a `getMembership()` fallback that reverifies persisted v3 state.

The event summary contains only:

```text
schema = castalia.zenith-membership-credential.v3
version = 3
membershipId
ownerPublicKey
status = active
issuerId
issuerKeyId
signatureSuite = Ed25519
issuerSignature
```

It contains no private key, passphrase, recovery material, signature, generic capability, Web credential, or Matrix credential.

## Current ownership

| Surface | Current responsibility |
| --- | --- |
| Castalia Web | Opens Wallet and validates the bounded verified membership summary. It does not handle keys or issue membership. |
| Page provider/content script | Projects bounded methods, binds requests to the observed origin, mounts extension UI, and relays the verified ready summary. |
| Embedded Wallet view | Runs the user-visible create/unlock/join ceremony inside the extension origin. |
| Extension service worker | Owns encrypted durable custody, signing, Zenith issuance, credential verification, public credential persistence, Chrome-owned popup lifecycle, and exact-origin approval after completion-time initiating-tab revalidation. |
| Zenith membership issuer | Verifies Member Key possession and signs the deterministic public credential. It creates no browser session or role. |
| Dregg node | Not called by active v3 Join. Permissionless v2 remains dormant forward-compatible code. |
| Castalia Control | Not part of permissionless base Join. It may later coordinate narrower consequential roles or operations. |

## Compatibility retained from the prototype

Some provider methods and local challenge-verification helpers remain because older consumers may still import them. They do not run in the active `/start` Join path and must not be presented as the current membership mechanism.

The current Join path still does **not** create:

- a Castalia Web login cookie or authenticated browser session;
- a Matrix account, access token, device, room membership, or E2EE state;
- a role, moderation grant, service authorization, infrastructure capability, or `dga1_` policy.

Base membership proves the durable Member Key plus a verified Zenith-signed Active credential only.
