# Finite application sessions

Status: browser candidate under qualification. The production bridge is guarded
by `HOLDER_SESSION_EXCHANGE_QUALIFIED=false`. The new capability is not advertised
or installed. The server must separately enable and qualify the matching issuer,
current-parent verifier, replay protection and application profile.

Ordinary holder-grant v1/v2 derivation keeps its existing same-holder key rule.
This additive exchange is a distinct issuer decision: a v2 grant holder approves
an application-owned temporary key for one finite session. It does not modify the
parent grant, enable onward delegation or export the holder's private key.

## Custody and time

| Material | Custodian and lifetime |
| --- | --- |
| Long-term Wallet key and saved reusable grant | Existing encrypted Wallet custody and grant backup. |
| Current parent assignment and revocation state | Canonical issuer registry, checked on every session read. |
| Temporary application proof key | Application memory, separate from Wallet custody. No recovery or Castaway export. |
| Session credential | Application memory; fixed signed expiry, exact permissions and parent references only. |

The approved challenge binds the parent ID, digest and revision; issuer and
canonical service; actual caller origin and receiver audience; approving Wallet
installation; a distinct application installation and temporary public key; exact
permissions; request/nonce; and a fixed expiry. Wallet and the temporary key sign
different domain-separated transcripts. The issuer credential contains no parent
grant or approval signature.

Expiry is capped by the requested duration, issuer cap, parent validity end and
the parent's current maximum credential lifetime. Reads, view changes and Wallet
lock cannot move it. Per-call proofs use fresh nonces and last at most 60 seconds,
never beyond that expiry. A new session requires new explicit Wallet consent.
Closing local custody is not server revocation; every receiver still checks the
current parent, exact scope, issuer, context, time and replay state.

The first DevGraph profile is read-only. Its trusted receiver selects the exact
read subset for an omitted/null permission request and rejects explicit write,
administrative or unknown operations. Wallet's shared contract does not infer
read semantics from opaque operation names or an unsigned capability label. Its
confirmation therefore says **Temporary session** and displays the exact scope.
An application must not admit this credential on a write or administration route.

## Browser bridge

`prepare_holder_session` requires an unlocked Wallet and approved top-level
origin. It accepts a canonical service, temporary public key, distinct client
installation, requested duration, optional permissions and optional signed
service access-point binding. The extension privately reads its saved grant and
prepares an issuer challenge. Only an opaque preparation ID and public challenge
return to the page; the parent remains inside the extension-to-issuer exchange.

The page prepares its temporary-key possession signature before enabling consent.
`open_holder_session` requires a fresh top-level gesture and Wallet confirmation.
It consumes that exact preparation before signing or dispatch; simultaneous or
replayed calls cannot approve twice. Core repeats holder, scope, installation,
context and time checks. The extension verifies the returned issuer credential
against the exact reviewed challenge before returning only the finite credential.

The application then signs exact calls with its own key. These calls do not need
the root Wallet to remain unlocked. Disconnect or document departure must drop
application custody, including when a document enters the browser's back/forward
cache. Same-document fragment navigation keeps the original key and expiry.

After an uncertain exchange, the page retains the original challenge and key for
the signed status operation. Status may recover only the original credential;
it cannot issue, renew, replace the key or extend expiry. Invalid, expired or
revoked outcomes never silently fall back to another signer or create a session.

## Private transport and compatibility

Issuer pins and audience come from the approved provider store. Core verifies a
supplied signed access-point binding before its prefix is used. The only derived
paths are `<verified prefix>/holder-sessions/v1/{capabilities,challenges,exchange,status}`.
Without a binding, only the fixed root protocol on an already-approved HTTPS
origin is supported. A page cannot supply another URL or custom path.

Requests omit cookies, ambient authorization and referrers, forbid redirects and
bound body size and duration. Responses reject duplicate properties, floating
point encodings and oversized JSON before typed Core validation. Any CORS support
belongs only to these new protocol paths and conveys no authority.

This slice accepts v2 parents. A verified saved v1 grant may continue through its
existing Wallet-bound flow before any new-session approval. There is no automatic
grant conversion, server default change or privilege expansion. Old signed bytes,
membership, custody, identities, recovery and backup formats remain unchanged.

The browser's nonextractable WebCrypto key prevents raw export through that API.
Compromised same-origin code can still use an active key. Short fixed expiry,
minimal scope and receiver checks remain necessary; this is not an XSS or
production-custody certification. Cross-language vectors, full Wallet tests,
disposable actual-extension tests and matched receiver tests are required before
enabling the candidate. A source test is not an installed user approval.
