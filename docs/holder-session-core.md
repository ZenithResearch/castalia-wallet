# Finite holder sessions in Wallet Core

This is a source candidate for `secs.holder-session.v1`, using the vendored
secS contract pinned in `vendor/secs-grant-contract/SOURCE.json`. It adds no
production trust profile, exchanges no installed grant and enables no receiver.
The browser bridge is documented separately in `browser-holder-sessions.md`.

## Authority and custody

The Wallet retains its reusable v2 grant and long-term holder key. After exact
human review, that key authorizes a challenge bound to a different temporary
application key. The issuer returns a finite credential containing parent
references, exact permissions, origin, audience and fixed expiry. It contains
neither the parent grant nor either private key. The application proves each
call using its temporary key. Onward delegation and silent renewal are disabled.

The receiver must check its current canonical parent registry, policy revision,
revocation, replay state and resource constraints on every operation. Verifying
the finite issuer signature alone is insufficient. Access points are routes to
one pinned canonical service; they are not separate credential authorities.

Core deliberately does not infer read semantics from operation names or an
unsigned capabilities response. Display the exact operations under “Temporary
session” or “Temporary access”. A provider's trusted profile and receiver own
the operation catalogue and any read-only restriction.

The hard end is fixed before consent and bounded by parent validity, parent
maximum credential lifetime, the requested duration and receiver policy. Use,
Wallet locking, reconnecting and status reconciliation cannot extend it. An
already-issued result may be installed after the review deadline, but only
before its original hard end. Expiry edits require a fresh reviewed challenge
before dispatch; an uncertain exchange must recover the original result.

## Compatibility

Existing signed v1/v2 formats, saved grants, encrypted backups and same-holder
derivation keep their previous behavior. This new exchange accepts v2 parents
only. A saved v1 parent produces `holder_session_parent_unsupported`, not an
implicit conversion. A missing grant produces `grant_not_saved`. Choosing the
new exchange must not silently fall back to another signing flow after dispatch.

`permissions:null` in a private prepare request asks the trusted receiver for
its read catalogue intersected with the parent. It never means copy every
parent permission. An explicit array is exact request intent: the receiver must
preserve it, including order, or reject it. Consumers must compare the returned
challenge against that explicit array before consent; being within the parent
is necessary but is not sufficient to preserve the user's request intent.

## Typed Core approval

`holder_sessions::PreparedHolderSession::prepare` receives an unlocked Wallet,
its reviewed saved grant, the exact issuer challenge, trusted context, approving
Wallet installation and current time. It verifies parent ownership, issuer,
service, installation, time, scope and challenge bindings. Its public summary is
`castalia.holder-session-review.v1`; no root grant is included. `approve` consumes
the prepared value, rechecks the holder key, deadline and temporary possession
proof, and returns a **broker-private** authorization containing the parent.

These additive WASM exports use JSON strings for closed typed inputs and decimal
strings for time:

| Export | Arguments | Result |
| --- | --- | --- |
| `reviewHolderSessionAuthorization` | stored, challenge, callerOrigin, audience, installation, now | Public review summary |
| `approveHolderSessionAuthorization` | stored, challenge, sessionSignature, callerOrigin, audience, installation, now | Private authorization; never a page response |
| `verifyHolderSessionCredential` | issuerPin, credential, expectedChallenge, now | Public signature/binding receipt; usable while Wallet is locked |

The extension must obtain the caller origin from its browser event, use a
previously trusted issuer/access-point profile, enforce explicit request intent,
obtain human consent, consume its pending approval before dispatch and keep the
authorization off page messaging, journals and logs. Public receipt validation
does not establish current server-side parent validity or revocation status.

## Native recovery session API

The following commands are private host APIs, not model-facing MCP tools:

| Operation | Inputs beyond `operation` | Result |
| --- | --- | --- |
| `holder_session_capabilities` | none | Additive protocol metadata; does not unlock |
| `holder_session_parent_reference` | service, now | Public parent references, issuer pin, validity and lifetime cap |
| `build_holder_session_prepare` | service, request_id, session_public_key, session_installation_id, context, permissions, requested_ttl_seconds, now | `castalia.holder-session-private-prepare.v1` with the root-containing private HTTP body |
| `prepare_holder_session_authorization` | service, challenge, context, now | One-use token plus public summary |
| `approve_holder_session_authorization` | token, session_signature, now | Private authorization |

The service must equal both the saved issuer pin and the signed parent service.
The approving Wallet installation and fresh application installation are distinct
bindings. The latter is never substituted for the Wallet's installation.
Approval is consumed even on a wrong token. Lock, malformed input and a new
preparation invalidate pending consent. Public state and capabilities inspection
preserve an approval; unrelated commands invalidate it. Existing recovery state shape and
owner-bootstrap commands are unchanged.

Only a pinned private broker may receive the root-containing prepare and approval
results. It must resolve HTTP paths from the previously verified access-point
prefix, never a model/page-selected URL or a product constant in Core.

## Separate native temporary-key helper

`castalia-holder-session-agent --profile-file <private-file>` is an additive
binary. The existing owner-bootstrap session helper is unchanged. Its profile
has exactly:

```json
{
  "schema": "castalia.holder-session-agent-profile.v1",
  "provider": {"issuer":"example", "key_id":"example-key", "public_key":"<64 lowercase hex>", "service":"service:example"},
  "context": {"origin":"https://example.invalid", "audience":"example"},
  "maximum_session_seconds": 600
}
```

Use a pinned executable and protected profile over inherited private pipes.
No TCP listener, seed import, parent-grant input or arbitrary signer exists.
Its closed newline-delimited request is:

```json
{"schema":"castalia.holder-session-agent-command.v1","request_id":"<32 lowercase hex>","body":{"operation":"create_session","expires_at":1234567890}}
```

The closed body operations are `create_session`, `prove_possession`,
`install_credential`, `present_call`, `status_proof` and `close_session`.
Creation returns `session_handle`, `session_public_key`,
`session_installation_id`, `maximum_expires_at` and `service`. All subsequent
operations require that handle; possession/status additionally receive the exact
retained challenge, installation receives the finite credential and reviewed
challenge, and presentation receives the typed service call. The helper chooses
its clock, randomness, pin and context. No caller may supply a signing seed.

Results use `castalia.holder-session-agent-result.v1`, the correlated request ID,
`ok` and either `value` or `error`. Successful command retries return their
original result; conflicting bytes under the same ID fail. Frames are bounded
to 131072 bytes, with at most eight sessions and 256 retained outcomes.
Malformed or oversized framing terminates the process. EOF drops its in-memory
keys. Closing reports `server_revocation_confirmed:false`; it does not revoke
server state. A restarted helper cannot recover an old session key or handle.

Native consumers must keep proofs, finite tokens and private authorizations out
of model-facing responses and generic logs. A public MCP result should contain
only an opaque client-bound handle, fixed expiry and business result. Keep the
new provider registration separate from the old owner-bootstrap protocol.

## Qualification boundary

Synthetic shared vectors cover byte-exact signatures; Core tests exercise typed
review, one-use approval, canonical service binding, public receipt validation,
late result installation and fixed expiry. Native process tests use real
temporary keys and disposable parents to exercise possession, installation,
proofs, status and close. Those tests do not qualify any production parent,
installed application, HTTP receiver or live permissions. Consumer/source pins
and receiver qualification remain required before activation.


## Portable native application custody

The additive C ABI in `crates/castalia-wallet-native/include/CastaliaWallet.h`
provides the same temporary-key engine on iPhone/iPad without launching a helper:

- `castalia_holder_session_abi_version()` returns 1. Existing root ABI stays 1.
- `castalia_holder_session_new(profile_bytes, length)` returns an opaque custody
  handle, or 0. The closed profile is exactly
  `castalia.holder-session-agent-profile.v1` with provider pin, context and
  maximum session seconds. Native application configuration must independently
  validate the provider/context before creating custody; token self-claims are
  not configuration.
- `castalia_holder_session_invoke(custody, command_bytes, length)` accepts only
  the existing holder-session-agent v1 closed command envelope and returns an
  opaque result handle, or 0 for invalid handle/pointer/size/capacity. Decode the
  existing correlated `castalia.holder-session-agent-result.v1` JSON directly;
  it is not nested inside the root RecoverySession result envelope.
- `castalia_result_length/copy/free` read/dispose that result, as for root calls.
- `castalia_holder_session_free(custody)` destroys all of its temporary keys and
  original outcomes. Reusing a freed handle cannot recover a key. It does not
  revoke the issuer's parent or confirm server-side revocation.

Root RecoverySession handles and application custody handles have separate,
noninterchangeable registries and monotonic IDs. Root lock/free never locks an
application key. The app must free application custody on explicit disconnect,
app/process exit and terminal session loss; no key or handle is persisted.
Fresh business calls/status use fresh command IDs and proof nonces; an exact
command retry returns its original result, not a newly signed proof. There are
at most 16 custody handles, 8 temporary keys per custody, 256 original successful
command outcomes per custody and 32 outstanding shared C result handles. Profile
and command limits are 65,536 and 131,072 bytes. Errors never echo input material.

The macOS `castalia-holder-session-agent` now delegates to the same portable
Core engine. Its file admission, framing, fixed clock, JSON wire and owner-free
scope remain unchanged. There is no new seed import/export, raw signer, arbitrary
key operation or root-Wallet command in either adapter. The iOS in-process handle
is a custody/API boundary, not a separate OS process or hardware isolation claim.
The issuer must still verify current parent/revision/revocation/replay on reads.
