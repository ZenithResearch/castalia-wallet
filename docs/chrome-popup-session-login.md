# Chrome popup session login

Castalia 0.0.8 introduced the optional `session_login_v1` provider capability. Existing
connection, read-access, grant backup, native clients and signed secS formats stay
compatible. Capability advertisement also requires Chrome's document-context API.
This is a browser host composition over unchanged Wallet Core; it is not a new
signed authorization format or an operating-system security boundary.

## Ceremony and ownership

The application's single login gesture opens an extension-owned popup. The popup
owns a dedicated private Worker, unlocks the existing encrypted custody record,
and checks trusted provider pins. Unlock-and-continue discloses public Wallet
identity and proposed session permissions. The reusable parent and root signing
material are never returned to the page. Closing the popup terminates its Worker.

A missing parent can be requested, obtained and explicitly saved in this popup.
Requesting access, obtaining an approved parent, saving it, and approving the
finite application session are separate decisions. Enrollment currently supports
explicitly optional membership; required or unspecified membership fails closed.
No automatic enrollment, grant save or replacement request is sent.

The page generates its own nonexportable Ed25519 child key and public correlation
ID. Wallet prepares the existing `secs.holder-session.v1` challenge. The page
proves possession of that child, and the popup displays the exact permissions and
hard expiry before authorizing the issuer exchange. Only the verified finite
credential returns to the page. This existing profile is read-only and disables
onward delegation. More general operations require a separately versioned review.

Wallet defaults to 900 seconds, clamped to the caller's requested upper bound,
verified issuer capabilities, signed parent maximum, remaining parent validity
and the existing 3600-second transport bound. Version 0.0.9 reads the canonical
`castalia.grant-validity.v1` modes: `dated` has a required integer `not_after`;
`until_revoked` has no `not_after` field. An unbounded parent never makes the child
unbounded. Unknown fields/modes, future starts and malformed expiry values fail
closed; an expired dated parent cannot open a session. The human can choose a shorter or
longer available duration before the challenge is created. Current policy is
rechecked before preparation; the final exact expiry is reviewed separately.

## Additive provider transport

`readAccess` accepts:

- `open_session_login`: canonical service, public child key/installation,
  requested lifetime, optional trusted-profile proposal, signed access-point
  binding and acquisition descriptors; returns a public prepared challenge.
- `complete_session_login`: the same login ID, exact challenge and child proof;
  returns the existing `castalia.holder-session-opened.v1` wrapper.
- `cancel_session_login`: cancels only the original document's correlated
  attempt. Its dispatch flag refers to the session exchange, not parent issuance.

Application descriptors remain data. `access_request` uses schema
`castalia.session-login-access.v1`, literal `challenge_path`, `action_path`, optional
`catalog_path`, an exact `request_schema` tag and 1–4 unique `result_schemas` tags.
The opaque action has submit/status, original request ID, holder/installation and
null intent. Wallet Core verifies the existing signed access-request challenge.
A retained unknown request can be explicitly reviewed and sent again using the
same request ID; status checking never creates a new request.

`grant_acquisition` uses schema `castalia.session-login-grant.v1`, literal
`challenge_path`/`grant_path`, fixed `grant_schema: secs.holder-grant.v2`, an exact
`result_schema` tag and `membership_requirement: optional|required`. Wrapper tags
are bounded versioned ASCII identifiers, not authority. The result must have
exactly `{schema, grant}`; Core still verifies the signed grant, service, issuer,
holder, validity and derivation restrictions. No application adapter, operation
catalogue, endpoint-specific authority or hierarchy implementation lives here.
All paths stay on the reviewed origin and verified binding prefix.

## Cancellation and mutation ordering

During human review, no service-worker port heartbeat or critical lease is held.
Service-worker suspension cannot erase the popup's signer. Explicit Wallet lock,
identity replacement, trust changes or grant changes invalidate its snapshot.

Each explicit signing/dispatch/save phase acquires a memory-only permit in the
same FIFO used by global custody mutations. Acquisition verifies the Chrome-owned
popup/document, original page document and complete encrypted/public snapshot.
The private Worker checks the live permit before root signing and network dispatch.
A phase lasts at most 20 seconds; no permit is persisted as authority. A broken
control channel or deadline terminates the private Worker. Abnormal queue release
requires confirmed absence of that exact owner document, never a reused window.
Indeterminate fencing blocks later custody mutations rather than assuming success.

A crash registry contains only public cleanup coordinates. Startup recovery fences
old owner documents before allowing mutations; it never restores an approval.
Recovery drains accepted encrypted-save jobs before deleting registry evidence or
releasing the FIFO. The save CAS verifies original owner, exact grant revision and
complete snapshot digest, then preserves every other canonical-service grant.
Public recovery journals are serialized across popup documents using Web Locks.

## Uncertain outcomes and storage

The existing encrypted Wallet grant format is unchanged. No root, parent, signed
enrollment, consent decision or signing permit is placed in a plaintext journal.
Only bounded public original-request references are retained in extension session
storage. The original enrollment's request ID and challenge digest are recorded
before dispatch. A lost result can retry the exact private authorization while its
popup remains open, without another root signature or automatic save.

Closing before a parent is saved destroys that private authorization. Challenge
expiry does not prove that issuance failed: the next attempt warns about the
unresolved original and requires an explicit new-reviewed-attempt decision.
Saving a known result clears only its own journal row. A stale local parent stays
saved when issuer preparation fails; explicit check/request actions remain
available, with no inferred revocation or automatic replacement.

Version 0.0.9 makes **Check approved access** the primary recovery action before
requesting new permissions. A missing encrypted local entry, a preserved older
parent format, and a failed parent/service check have distinct messages. A new
request's pending/active status never substitutes for checking existing approved
access. An assignment change can invalidate an old parent while the same holder
still has approved access: obtaining the updated parent, saving it and authorizing
a child each require their existing explicit review. No request, signature,
issuance, save or replacement runs merely because recovery is displayed.

For an uncertain session exchange, the page retains its original child checkpoint
and uses the issuer's original-result status API. It must not discard that key or
start a replacement simply because a response is lost. Closing the popup locks
root custody but does not extend or automatically revoke an already issued child.

## Qualification

`smoke:extension-popup-login` uses a fresh disposable Chrome profile and the exact
packaged extension, native issuer and actual consumer modules selected through
explicit environment paths. It checks popup-only first use, encrypted parent save,
parent/result loss and closure, worker suspension, explicit lock, exact child
recovery, scoped reads, hard expiry, replay, revocation, IndexedDB reload and logout. The regression
fixture requests a canonical until-revoked parent before native signing and uses
a model-validated disposable member registry to exercise an actual assignment
epoch change. It verifies locked/reloaded login reuses the identical encrypted
parent with zero reissuance, and explicitly reviewed updated-parent delivery
leaves the old encrypted record untouched until Save, without a new access request.
It never loads a personal Chrome profile or changes installed apps/live grants.
Unit tests additionally exercise context spoofing, closed request shapes, mutation
CAS, stale cleanup/window reuse, delayed writes and failed recovery barriers.
