# K3 native-admin fixture v4

This additive, default-off capability signs only the exact Add and Disable
administration fixtures for the source-pinned composed Kettle. It is part of K3
native review qualification, not the separate K4 ledger/security qualification.
All v3 source, public vectors, transcript domains, dispatch and consumer pins
remain unchanged. The new binary is `castalia-kettle-admin-fixture`; fresh
native custody has an immutable role selected at `open`: `controller`, `recovery`,
or `feePayer`. It provides no key import/export, saved-account signer, generic
signing command, application activation, or human approval ceremony.

The immutable source profile uses exactly the v3 execution/code/descriptor/content
pins, with schema `castalia.cardano-fixture-execution-profile.v4`. See the
[v3 qualification boundary](kettle-native-fixture-v3.md) for those pins and the
independent owner-observation requirements. Both native actions use only the
actual published Kettle V3 code reference. The companion hash is retained as the
pinned policy descriptor's executable; administration does not invoke it.

## Current native authority and exact roles

The admitted common transaction has two normal inputs (singleton state and one
plain enterprise ADA payer), one Kettle code reference, one payer-owned collateral
input, and two outputs (0 complete state continuation, 1 exact payer change).
The sole actual Spend redeemer points to the normal singleton's ledger ordinal.
The outer action is constructor 5; its sole child is Add constructor 0 or Disable
constructor 1. No mint, companion execution, payment output, foreign script purpose,
semantic reference, certificate, reward, governance, or auxiliary effect is admitted.
All original normal/reference/collateral sets are complete, disjoint and ordered
by exact outpoint. Every output and script reference is inspected from original
bytes. Full protected Value, authority and reserve are preserved, epoch advances
exactly once, and only the authenticated registry root changes.

Add requires the exact independently admitted synthetic genesis outpoint
`11` repeated 32 bytes, output 0, epoch 0, and empty root for the pinned scope. The
absent leaf becomes the exact pinned descriptor/content, enabled status, bounded
ordered caps with paid zero, and initial use commitment. Actual required signers
are exactly the current controller and the distinct fee payer. A controller-role
session verifies that its own derived public payment credential is that current
controller; a payer-role session verifies ownership of all external normal and
collateral inputs and their exact change/return.

Disable requires the actual accepted Registered output 0, epoch 2, a matching
independently observed Add/Registered history, the live enabled authenticated
record, positive prior paid in at least one cap, and use different from initial.
It changes only enabled to false, preserving descriptor, every cap/paid counter,
and use commitment. Actual required signers are exactly two distinct current
roster credentials and the distinct fee payer. Each recovery-role native session
must itself be one of those two actual selected current credentials. One key
cannot count twice. Merely proposed, outsider or earlier credentials do not
satisfy current membership; an actually executed roster replacement is needed
before labeling a negative as an outgoing-quorum trace.

The selected fixture keeps controller, roster credentials and payer disjoint.
Roster order and all entries are preserved; its valid size is 2–16. These are
explicit native fixture admission restrictions, not a change to the compiled
current-authority kernel or a claim that all overlapping-role shapes are supported.
The fee payer never supplies controller or recovery authority by paying fees.

## Shared original-body review and independent sessions

All required signer keys are sorted and inserted into the body before evaluation,
costing, review or approval. Add projects exactly two actual vkey witnesses;
Disable projects exactly three. With the closed unsigned witness map and tagged
vkey set, the projected additions are 207 and 308 bytes respectively. The sole
reference program is decoded, hash checked and size checked at 15,122 bytes,
therefore its first-band reference fee is 226,830 lovelace. The pinned rational
linear/execution floor and 150% collateral rule are checked natively. The owner
also independently evaluates the exact original script-data hash and purpose,
fees, reference fees, minimum outputs and protocol limits. Actual assembled
witness counts and encoded size must equal the projection before submission.

Every session independently authenticates its profile and current context and
inspects the same original unsigned body. The common review is byte-for-byte
identical across all participants; only native-derived participation differs.
The coordinator prepares all intended roles, compares their common review hashes,
original body/envelope hashes and identical authenticated context digests, verifies
fresh live heads, and then requests each handle-only signature. It verifies every
returned public key and signature against that one original body, assembles the
exact required distinct key set, and independently preflights before submitting.
An available key or required signer entry is not a second approval.

Approval is not an atomic distributed operation. If one participant has already
emitted its witness and another later denies, the first witness cannot be revoked.
The coordinator withholds submission and invalidates remaining handles; it must
not claim that no prior signature exists. Exact body equality prevents combining
witnesses for different bodies. Unreported ledger changes remain a race handled
by fresh observation and eventual ledger spent-input rejection, not by a claim
that a handle-only native call observes the network.

The owner is a synthetic fixture observation/admission signer. Multiple independent
native custody keys demonstrate distinct cryptographic participation; they do not
represent independently consenting humans or qualified real-account consent.

## Frozen v4 wire shape

All three transcript domains use `/v4` plus one NUL byte; statements use JCS.
Profile statement fields are `schema`, `sessionId`, `epoch`, `network`, `role`,
`profile`. Context statement fields match v3 with schema `.v4`. Admission fields
match v3 with schema `.v4`, plus `role` and `commonReviewHash`; the normal
`reviewHash` also covers the entire role-specific review. A profile's hash binds
its immutable role and session, so a receipt from another role/session cannot be
reused even if the synthetic owner verification key is the same.

Context schema is `castalia.cardano-fixture-review-context.v4`, with
`observedSlot`, `history`, and four original `utxos`. UTxO row shape/order matches
v3. The closed history union is:

- `{kind: "fixtureGenesis", stateRef}` for Add, with the fixed genesis ref above.
- `{kind: "acceptedRegisteredPour", acceptedAddRef, acceptedPourRef,
  descriptorDataHex, sourceContentDataHex, priorRecordDataHex}` for Disable.
  The two refs are distinct output-0 refs; `acceptedPourRef` is the live consumed
  state and the included prior record equals the actual typed redeemer record.

The owner retains and replays actual accepted Add/Registered originals. These
history fields are independently signed observations, not native reconstruction
of a chain receipt. Original observation freshness, TTL, generation and handle
rules match the v3 lifecycle: eight pending handles, 64 consumed admissions per
context, expiry sweeps pending only, one-use approval consumes before checking,
and authenticated context advance/explicit epoch invalidation revokes handles.
Close permanently destroys that session's fresh custody. Unknown fields and
legacy-v3 fallback are rejected; JSON framing is bounded before deserialization.

The role-neutral common review schema is
`castalia.cardano-fixture-common-review.v4`. Its executable public corpus records:

- Action kind; original body/envelope/script-data hashes; state, payer, collateral
  and code refs; descriptor/content, prior/next record, proof and state Data bytes;
  root/use/epoch before and after; exact controller/roster, selected authority,
  payer and sorted required signer credentials.
- Projected witness count/size, reference bytes, minimum/actual fee and exact payer,
  change, collateral input/return/at-risk and reserve amounts.
- Complete state before/after and payer-change address/Value arrays, caps with
  `maximum`, `paidBefore`, `paidAfter`, and the sole declared indexed redeemer.

Prior record/use are null for absence on Add; displayed paidBefore zero is
initialization, not evidence of a preexisting record. Amounts/epochs are decimal
strings; counts/indices are safe numbers. ADA sorts before native units, key sets
sort lexically, and the full recovery roster retains its original state order.
The outer review is `{schema: "castalia.cardano-fixture-review.v4", common,
commonReviewHash, participation: {paymentKeyHash, role}}`, with common hash
SHA-256 of JCS common. Native code derives participation; the caller cannot replace
it at prepare or approve.

## Bounded combined trace

The selected integration is native Add (controller + native payer), then the
unchanged v3 native Registered signer consuming that very same actual Add head,
then native Disable (two independent current recovery sessions + native payer).
The v3 payer may be a different fresh native account; no shared private key or
custody import is introduced merely to keep fee-payer identity constant. One
isolated synthetic provider and observation owner retain the complete trace.
Running a separate preexisting fixture that creates another Add would not qualify
this combined trace. Code publication remains real measured signed publication,
never preloaded reference outputs.

Principal support/topups remain zero; author/request routes, recovery/roster
updates, production bootstrap, real accounts, D6/D7 choices, and general native
policy admission are outside this milestone. Negative evidence must distinguish
owner preflight refusal, native role/admission refusal, witness assembly refusal,
compiled VM rejection, and phase-one missing-signer/stale-input rejection. A
malformed preparation is not reported as a rejected ledger settlement.


## Public corpus and native verification

The public vector `tests/fixtures/kettle-admin-fixture-v4.json` has SHA-256
`e12a87cec64e4039ba44469bf2f9e50e1e2054a0c22b708d65e7d1a8ec09c9b6`.
Its Add common-review JCS hash is
`5897170d5456ff7f64fad969df4259cf38bfdf63770e80a3d75edd482a894e2e`;
Disable is `4d706f16cd2f2d568e0579d9b2ce4488e7a8a9efb96accd0ca8087d23071c8f7`.
All five native role views must match those complete independent Web common
reviews. The raw byte variants have SHA-256
`22fbe2e397ec7d6e2a6addbd854f2769313564338d8f29584e1cbe2a39f0d11d`.
They include fees below the full two/three-witness floor while still sufficient
for one witness, reordered signer sets, duplicate key aliases, and prior status
reseating. These are native parser refusals, not asserted settled transactions.

Rust custody tests rebind only public fixture credentials to freshly generated
native accounts to exercise two/three-session equality, distinct actual signatures,
and receipt/handle isolation. That local rebinding is not a fresh ledger receipt;
the separate live integration must build and settle its own complete trace.

Reproduce from this repository with an existing compatible private build target:

```sh
cargo test --locked --offline -p castalia-wallet-core --features funding-fixtures --test kettle_admin_fixture_v4 -- --test-threads=2
cargo test --locked --offline -p castalia-wallet-core --features funding-fixtures -- --test-threads=2
cargo check --locked --offline -p castalia-wallet-core
cargo build --locked --offline -p castalia-wallet-core --features funding-fixtures --bin castalia-kettle-admin-fixture
```

The additive source starts from Wallet commit
`e65fa3075722c3fa6b95afdafb311da4f6cd85f4`. Internal typed inspection helpers are
local copies to preserve the exact frozen v3 implementation and visibility;
the bounded raw CBOR parser and private fresh-custody primitives remain shared.
This is not an assertion that broad JavaScript/application checks pass without
those workspaces' installed dependencies.
