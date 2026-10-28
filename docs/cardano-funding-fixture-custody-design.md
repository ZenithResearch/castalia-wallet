# Funding fixture custody — reviewed bounded design

Status: bounded opt-in native fixture custody is implemented with the reviewed
synthetic-owner capability boundary below. Independent verifier/ledger integration
qualification remains distinct; this is not a production Wallet permission or
human-consent path. It belongs to the existing custody-witness/fixture Tasks.

## Limit authority before adding signing

The integration harness needs actual shared-core-derived Cardano witnesses,
not CML signatures mislabeled as Wallet evidence. Introduce a separate explicit
fixture session, gated from default production transports. Its only public
constructor creates a fresh disposable wallet through shared-core custody.
It accepts no seed, existing wallet/vault, recovery file, key path, imported
container or arbitrary root from a caller. No public OpenedWallet signing API is
added. Real saved Wallet data and signer profiles remain inaccessible.

The session exposes public account material and bounded funding preparation,
fixture approval, cancellation and close. Closing drops unlocked authority and
invalidates prepared handles. Optional recovery tests may restore only an opaque
in-memory checkpoint created by this same fixture session; no externally supplied
recovery container is admitted. Identity/profile changes invalidate handles.

The approval transport is a test harness ceremony. Its output must be labelled
fixture approval, never trusted human Wallet consent. Production/native/browser
rollout and real-wallet capability require a separately reviewed provider path.

## Context and prepared transaction

A trusted fixture owner pins an immutable synthetic execution profile: backend
and exact version, effective protocol parameters/cost models, slot mapping,
fixture ledger provenance, explicit testnet context and profile digest. A raw
Shelley genesis reference has its own explicit hash kind; it is not a claim that
the synthetic ledger was bootstrapped from or authenticated as a public node.

Preparation receives a complete unsigned/sparsely witnessed Cardano transaction,
a supported funding action descriptor and independently resolved fixture-ledger
normal/reference/collateral-input context. The fixture transport obtains that context from
its validating ledger rather than accepting a webpage's assertions. Context
updates invalidate stale prepared transactions before witness generation.

The shared-core preparation boundary must:

- Bound raw CBOR, nesting depth, resolved-context size, input counts and pending
  preparations. Reject malformed/duplicate or unsupported map fields, non-funding
  operations, ambiguous indices/keys and `is_valid=false`.
- Preserve the exact original transaction-body bytes and hash them under the
  Cardano ledger signing rule; never sign a reconstructed/canonicalized body.
- Check testnet address/body context, required signer membership for the selected
  derived payment key, exact input references and the admitted fund/script/action
  binding. Reject mainnet, unsupported governance/certificates/withdrawals,
  unknown scripts and unlisted transaction features.
- Verify the body’s `script_data_hash` against the exact inspected redeemers,
  datums and pinned language views before admitting an action. A review of witness
  payload A cannot approve a body committing to replacement payload B. The closed
  supported-action variants bind the exact applied script, state asset, resolved
  fund inputs, authority, output roles and terms; caller-labelled scripts do not
  establish admission. A trusted fixture-verifier capability may attest this
  commitment only within the explicitly documented synthetic owner boundary.
- Bind the original body hash, full action/purpose terms, resolved input digest,
  profile digest, session identity/epoch and short monotonic expiry into one
  opaque, session-owned, single-use prepared handle. A supplied expected hash
  alone is not semantic admission.
- Produce a public review summary derived from those same inspected bytes, not
  independently supplied prose. Witness sets/redeemer data remain subject to the
  exact script-data/body commitment and validating ledger checks.

Approval accepts only the opaque handle, consumes it before further checks,
rechecks profile/context/session/expiry from the fixture owner’s trusted state, and
uses only the internally derived Cardano payment key to create its ledger witness.
Return public key and signature or encoded witness set, never the root/child key.
Changing the requested transaction after preparation requires a new preparation;
nonce reuse, stale handles or signing another body reject. Wallet member identity
and credential-presentation transcripts supply no ledger authorization.

## Transport and evidence

A local native fixture process may keep fresh sessions in memory and communicate
through a bounded stdin/stdout protocol. It must not expose a network listener,
load real saved Wallet profiles or log secrets. Error output is bounded and
private-key material never appears in responses. Input framing/EOF and process
failure close the fixture authority. External test harness code cannot import a
real wallet by calling an alternative constructor.

Tests must prove actual shared-core witness verification in the independent
validating ledger; wrong body/key/network/profile/context, expired/reused handle,
lock/cancel/identity changes, malformed CBOR and disallowed operations reject.
Preserve nonminimal original body encoding in a valid golden case. Preparation denials produce no witness. Separately, independent backend negative
tests re-sign non-signature mutations to exercise the intended ledger rule; that
backend testing requirement must never introduce a signer admission bypass.

This design does not replace a production financial transaction inspector. If
safe bounded funding inspection or independent context binding cannot be
implemented, leave the custody Task open rather than publish an arbitrary
signer under a fixture name. The ledger-design and authority/security roundtables accepted the fresh-only
architecture with the commitment, closed-action, context-ownership and handle-only
amendments incorporated here. Defer optional checkpoint recovery initially.
Broader production authority requires a separate explicit decision.

## Implemented disposable fixture transport checkpoint

The opt-in Cargo feature is **funding-fixtures**. Default core/WASM/native builds
do not expose this module or build its binary. Enable the synthetic transport:

~~~sh
cargo run --locked -p castalia-wallet-core --features funding-fixtures \
  --bin castalia-cardano-funding-fixture -- \
  --owner-verification-key <fixture-owner-public-Ed25519-key-hex>
~~~

The launch key is PUBLIC verifier material, never a custody root or signer key.
No listener or command accepts a root, saved wallet, vault or recovery container.
The open command creates fresh shared-core custody in memory; the process admits
one session only, even after close. EOF/framing failure discard custody.
Optional checkpoint restore remains absent.

Commands are closed newline-delimited JSON, at most 131,072 bytes including the
newline; incomplete/oversized frames close the process. Responses have
{ok:true,result} or {ok:false,error}, with bounded static errors.

- open: networkJson is the original JSON string accepted by the closed network
  parser, preserving duplicate-field rejection. Returns ID, epoch/public account.
- setProfile: profile and ownerSignature; installs the signed profile once.
- setContext: generation, digest, ownerSignature; increasing generation clears
  pending preparations.
- inspect: transactionHex; returns computed statement/review, never a witness.
- prepare: transactionHex, ownerSignature; verifies that exact admission and
  returns an opaque handle and byte-derived review.
- approve: handle only; consumes before checking expiry/current context.
- cancel: handle. invalidate clears handles/context and increases epoch.
  close discards authority permanently.

### Trusted synthetic owner capability

The Rust inspector is deliberately narrow. It does not independently recompute
Cardano script-data hashes, validate fund-state transitions or authenticate a
node. A pinned fixture owner must independently resolve normal, reference and
collateral inputs from its validating ledger, recompute script-data commitments,
and enforce pinned actual script/action/state/output/value rules before issuing
an admission receipt. Merely signing what inspect returned is not verification.
The owner-verifier implementation and actual ledger evidence remain required
provider qualification; Rust structural unit vectors do not establish them.

The owner signs complete RFC 8785 JCS statement bytes prefixed with the exact
UTF-8 domain including its final zero byte. Ed25519 verification is strict.
Signatures are 64 bytes in lowercase hex. The exact three domains:

~~~text
castalia/cardano-fixture-profile/v1\0
castalia/cardano-fixture-context/v1\0
castalia/cardano-fixture-admission/v1\0
~~~

ProfileStatement fields: schema (castalia.cardano-fixture-profile.v1), sessionId,
epoch, exact network and profile. Profile fields: schema
(castalia.cardano-fixture-execution-profile.v1), backend (scalus-1.4.1),
executionProfileDigest and sorted unique allowedScriptHashes (1–16).
profileDigest is SHA-256 of JCS of the full profile statement. The execution
digest identifies the owner's full immutable synthetic manifest.

ContextStatement fields: schema (castalia.cardano-fixture-context.v1), sessionId,
epoch, profileDigest, generation, digest. The owner defines and pins the closed
snapshot encoding, including resolved normal/reference/collateral inputs and
effective slot/parameter context. Generations/epochs use JSON-safe integers.

AdmissionStatement fields: schema (castalia.cardano-fixture-admission.v1),
sessionId, epoch, profileDigest, contextGeneration, contextDigest, paymentKeyHash,
transactionBodyHash, transactionEnvelopeHash, reviewHash. Body hash is BLAKE2b-256
of the exact original CBOR body slice. Envelope hash is SHA-256 of all original
transaction bytes; review hash is SHA-256 of JCS review. Fields are computed
internally, never accepted as a caller assertion.

Review fields: kind, fundScriptHash, stateAssetName, redeemerDataHex, purpose
(string/null). Redeemer bytes are the original Data subslice. Supported kinds are
Teapot bootstrap, controller restoration, roster replacement and direct payout.
New request/Marsh actions reject until a reviewed admission revision qualifies
them. The external verifier must check that its independently inspected review
and these exact bytes agree.

### Concrete bounds and invalidation

Raw transactions: 32,768 bytes; parsing depth: 32; nodes: 8,192; entries per CBOR
map: 128; outputs and combined input references: 64; redeemers: 32; required
signers: 16. Decoded duplicate map keys reject, including nonminimal integer
aliases. Only admitted transaction/witness fields are supported. Mainnet, false
validity, auxiliary metadata, governance, certificates, withdrawals, unsupported
scripts/actions reject. Tag 24 accepts byte-string children for real inline
datums. Nonminimal body bytes are preserved.

At most eight preparations and 64 used admissions are retained per context.
Each statement prepares once. Context advance/invalidation clears bounded
capability state; old signatures remain invalid through generation/epoch binding.
Handles expire after 30 monotonic seconds by default, with a 60-second API
ceiling; tests may use shorter durations. Cancel/close/epoch/context changes and
expiry prevent witnesses. No API exposes a generic payment signer or caller-
chosen signing preimage.

Structural tests use explicit synthetic CBOR/script placeholders and trusted
test-owner receipts. They establish capability/byte/custody boundaries, not
genuine script-data admission, human consent or settlement. Separate Scalus/CML
checks must use compiled scripts and prove independent owner verification and
shared-core witness acceptance.

The feature explicitly refuses wasm32 compilation. Prepared records retain only
the committed original body hash and immutable authorization context, not the
complete original transaction. This is safe within this boundary because approve
accepts only a handle, never a replacement body, and the trusted owner admission
binds the exact inspected envelope/action. The eventual assembler must retain
and submit those original bytes; witness generation is not submission.

## Verification at this implementation checkpoint

The new interface first failed its targeted compilation baseline before the
module/transport existed. Thirteen targeted tests then passed, including actual
payment witness verification, nonminimal body binding, owner/context/epoch and
handle replay rejection, cancellation/expiry, map/reference aliases, equal Data
at different offsets, pending limits, closed JSON and native framing/import
rejection. A later failing CBOR float-alias regression was reproduced and fixed;
only literal supported simple-value encodings are now accepted.

The required npm regression suite passed all 289 tests, including a fresh default
WASM build and 200 extension checks. The first typecheck began before generated
workspace/WASM artifacts existed and failed on those missing imports; rerunning
after the test build passed. No TypeScript source, lock, transport permission or
private recovery format was changed. Rust formatting and diff checks passed.
The final locked feature-enabled core regression suite passed all 79 tests,
including the 13 fixture tests, after the float-alias fix. No commit, real-key
operation or deployment is performed.
