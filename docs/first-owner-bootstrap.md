# One-time first-administrator bootstrap

Scope: bootstrap the exact selected resource. No new listener, retargeting,
member grant, private-key export, or child delegation. This is separate from the
future complete credential ontology.

States: uninitialized -> setup authorization armed -> exact Wallet claim prepared
-> first admin grant active + setup authorization consumed in one transaction.
An existing administrator prevents arming again. Expiry never renews itself.

The installation owner arms a short-lived 256-bit setup authorization over a
protected local setup channel. Only its digest is stored. The server binds a
120-second challenge to the exact resource UUID, endpoint, configuration and
registration digests, intended Wallet key and fixed initial admin grant. The
Wallet reviews and signs canonical challenge bytes using the domain
`zenith/resource-owner-approval/v1\0`. The native private key stays in Wallet.
The server validates the signature, current setup authorization and unchanged
resource binding. It atomically records the grant, signed claim and bootstrap
consumption, with no member Work execution rights implied.

The initial admin grant is resource-wide, until revoked, and permits only the
existing administrative operation family: access.inbox, access.review,
access.decide, access.status. It is bound to that Wallet key. Onward delegation
is false; future admin attenuation needs a separately versioned contract.
This server-retained admin grant is not yet a portable issuer-signed credential;
claims about issuance, Wallet storage and endpoint enforcement require the
matching integration and installed evidence.

Response loss: exact original proof may retrieve the same retained result, with
no second grant or new authorization. Concurrent redemption can create only one
admin grant. A different Wallet, changed resource/URL/configuration, signature
mutation, expired challenge, wrong/consumed setup secret or unknown authority
field must fail closed. Failed commit must leave neither active admin nor burned
authorization. The consumed setup token must never be usable to issue more
credentials or enroll another administrator.

All methods in the initial backend module are internal. No unauthenticated HTTP
bootstrap endpoint is introduced. Production arming/claiming requires its own
exact operator review and native Wallet consent. Health/discovery may remain
available while operational/admin/member endpoints are uninitialized. Upgrading
an existing installed graph must preserve its historical grants and fail closed
rather than automatically claiming/replacing its owner.

## Integration and migration gates

The setup authorization is a random one-time token, not another Wallet identity
or an exported owner key. Its short deadline and the two-minute review challenge
do not limit the administrator grant: that grant remains until revoked. An
explicit review refresh changes only the challenge nonce/timestamps, preserves
the intended Wallet/grant, and cannot extend or rearm the setup authorization.

The selected resource/configuration binding must be resolved independently from
OS-owned configuration at every transaction and again immediately before commit.
`BootstrapStore` requires that resolver; a claim is never its own source of truth.
The installed adapter must serialize configuration changes against activation.
A registry listing, same-machine HTTP connection or absent bootstrap database is
not proof that an existing installation has no owner. Existing owner/operator
state must be inspected before arming; conflicting historical authority stops
setup rather than being silently replaced.

Castalia adds optional capability `resource_owner_protocol` with value
`zenith.resource-owner.v1`. Native commands `prepare_resource_owner_v1` and
`approve_resource_owner_v1` are separate from operator/member consent. Preparation
returns the complete verified binding/admin grant and a one-shot review token,
without a signature. Approval signs only the retained exact challenge. Lock,
cancel, another operation, wrong token and expired review invalidate approval.
The established backup-verification requirement remains; Zenith membership is
not required. Old encrypted snapshots and membership bytes are unchanged. Older
cores without this marker produce an update-required error; no signing fallback.
No new browser provider method or unknown-origin access is introduced.

Transfer independently compares the native summary to the prepared claim and
checks the returned Ed25519 proof against the same transcript. The shared public
synthetic vector must match Python, Rust and Swift byte for byte. The vector's
known test seed must never be used for an installed key or production authority.

Installed acceptance still requires the fixed local setup adapter, owner-backed
operator policy verification, a reviewed runtime update for the exact selected
resource, native review and successful authenticated administration. There must
be no new listener or origin substitution hidden in registration. The existing
HTTP private API and legacy agent access are preserved during source development;
production operational/admin/member gating needs its own reviewed cutover.
No installed first-owner claim or active endpoint is established by unit tests.

Future attenuation and optional onward-delegation require explicit, versioned
limits and enforcement. The v1 grant rejects extra permissions, scope fields,
delegation and unknown authority fields; it must never be interpreted as a
delegation-capable credential just because a later client can express one.

Here `access.decide` is the resource owner's explicit service permission to issue
or revoke member access under that resource's policy. It does not make this
administrator grant attenuable or permit issuing child administrator grants.
Onward delegation of an existing credential remains disabled in the MVP.
