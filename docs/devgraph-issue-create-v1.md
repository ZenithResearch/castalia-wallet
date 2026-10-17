> Historical reference. The Wallet implementations described below were retired after `58d32a40559ffff0a9d99411f967b0889524c994`. See [the retirement boundary](wallet-application-adapter-retirement.md). These commands are not available in current Wallet packages. Historical bytes and evidence below are unchanged.

# Devgraph Issue-create Wallet presentation v1

Status: DG-W bounded signer implemented; no CLI, transport, secS deployment, or end-to-end Issue creation claim

Castalia Wallet exposes exactly one Devgraph operation:
`castalia.wallet.requestDevgraphIssueCreatePresentation`. It constructs and
signs the Wallet presentation for `devgraph.issue.create.v1`; it is not a
generic Work signer, generic RPC method, bearer credential, or Devgraph HTTP
client.

## Provider request

The provider accepts this camel-case caller envelope:

```json
{
  "request": {
    "id": "issue-example",
    "kind": "Issue",
    "title": "Example Issue",
    "description": "",
    "priority": 0,
    "artifact_ids": [],
    "external_link_ids": []
  },
  "idempotencyKey": "issue-example-create-0001",
  "sessionId": "<base64url-no-pad 16 bytes>",
  "nonce": "<base64url-no-pad 12 bytes>",
  "issuedAt": 1800000000,
  "expiresAt": 1800000060
}
```

`description`, `priority`, `artifact_ids`, and `external_link_ids` may be
omitted and materialize as `""`, `0`, `[]`, and `[]`. Unknown fields reject.
The two identifier lists must be dense ordinary arrays with exactly their
indexed elements; sparse holes and non-index own properties reject instead of
being reinterpreted as JSON `null` or silently discarded.
Identifiers, safe-integer bounds, the 60-second maximum validity window, exact
expiry, Unicode no-normalization, array order, and request-size limits match
the secS/Devgraph v1 contract.

The caller cannot supply audience, operation, resource, request digest,
idempotency digest, policy, scope, receiver key, route, URL, handler, database,
or Work kind. Wallet fixes or derives all signed authority fields:

- `audience = devgraph://receiver-local`;
- `operation = devgraph.issue.create.v1`;
- `resource = Issue/<validated request id>`;
- `request_digest_sha256 = SHA-256("devgraph.issue.create.request.v1\0" || RFC8785_JCS(materialized request))`;
- `idempotency_key_digest_sha256 = SHA-256(exact raw idempotency key)`.

The returned object is exactly
`devgraph.issue.create.wallet-presentation.v1`. Its signature preimage is:

```text
UTF8("devgraph.issue.create.wallet-presentation.v1/signature\0") ||
RFC8785_JCS(presentation_without_signature)
```

The output carries the Wallet root's raw 32-byte Ed25519 public key and
64-byte signature as unpadded base64url. The private seed, signer handle, raw
idempotency key, `.castaway`, and ML-DSA-65 material never enter the response.
This v1 operation is classical Ed25519 authorization and makes no hybrid/PQ
attestation claim.

## Approval boundary

The page call requires active user interaction plus an already approved
origin, set-up Wallet, and unlocked Member Key. The service worker opens a
dedicated Chrome-owned popup that displays:

- the exact initiating origin and operation;
- resource, title, description, priority, artifact IDs, and external-link IDs;
- request and idempotency-key digests;
- issue and expiry times.

The approval broker is memory-only, single-pending, one-shot, and bounded by
the signed presentation expiry. Popup close, worker loss, timeout, denial,
reload/reclaim, malformed input, or a second pending request fail closed. After
approval, Wallet reacquires its custody FIFO, re-reads setup, unlock, origin
approval, and the raw Member Key, then requires the same initiating tab origin
and exact prepared bindings before revalidating expiry and calling the
extension-owned raw Ed25519 signer. The FIFO is intentionally released during
the human popup wait, so a lock, origin revocation, or identity import that
arrives before approval completes wins the queue order and prevents signing.

The popup is not web-accessible and does not share the membership onboarding
or generic `signChallenge` transcript.

## Shared vector

[`vectors/devgraph-issue-create-v1/`](vectors/devgraph-issue-create-v1/)
contains byte-identical copies of the authoritative Devgraph DG-V request,
idempotency-key, and Wallet-presentation fixtures from Devgraph merge
`2ba578fe05855e983e04bc10d766d2fff8b12319`. The Wallet test reconstructs the
signature from the fixture-only Ed25519 seed and compares the canonical
presentation byte-for-byte.

This signer is only DG-W. secS must still verify the presentation and
receiver-owned policy and emit its signed authority projection. Devgraph must
then independently verify that projection and alone owns Issue validation,
mutation, idempotency, audit, and `EventReceipt`.
