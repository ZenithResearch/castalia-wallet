# Wallet rewards bridge v1

Wallet owns this connection contract. It is browser-only, versioned and closed:
`wallet.rewards.request.v1`, `wallet.rewards.ready.v1`, and
`wallet.rewards.response.v1`. There were no earlier bridge readers or persisted
bridge records. Unknown versions, fields and operations reject. Consumers share
this parser rather than independently reconstructing the wire format.

Only `connect` is supported. A response contains `walletPublicKey`,
`solanaPublicKey` and `solanaAddress`, or one bounded error: `denied`, `expired`,
`wallet_unavailable`. Public descriptors are not proof of possession or social
control. This contract cannot sign a claim, accept an offer or transfer funds.
Never add an arbitrary signing operation to this interface.

The caller pins the Wallet origin and `/wallet/rewards` path. A random 128-bit
request ID and canonical caller origin go in the fragment; no return URL is
accepted. Wallet checks an explicit exact-origin allowlist and the actual opener.
It sends `ready`; the client checks origin, source and ID before posting the
request. Wallet admits one request, at most 300 seconds old, with at most 2048
UTF-8 bytes. It checks freshness again at consent. Messages always specify the
exact target origin, never `*`. The client removes listeners/timers after any
terminal result or closed/timed-out popup. Connection permission is not saved.

The browser Wallet UI requires setup/unlock, confirmed recovery and explicit
consent for the displayed public data. It rereads custody before disclosure,
denies embedded frames, and does not mount custody for an unallowed origin.
Production allowlists remain empty. Locked Wallet snapshots and fixture previews
do not bypass approval. Custody keys, derivations and exports are unchanged.

`fixtures/connection-v1.json` is the public cross-consumer fixture. Build `dist`
before installing a consuming repository's local file dependency. Browser
integration lives in the existing `castalia-web/apps/web`, not legacy Castalia.

For future bounded signing, introduce an explicitly versioned operation only
after independently verified escrow terms, recipient control, fresh native
eligibility and a Wallet-owned exact-terms confirmation are implemented. Updating
both consumers and negative fixtures is mandatory; connect never implies consent.
