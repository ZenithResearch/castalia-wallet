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

## Version two: typed fund roles and authenticated resolved review

The opt-in fixture adds a separately versioned execution profile and admission
transcript. The original execution-profile v1 and its admission v1 remain
restricted to their original Teapot bootstrap/control/direct-payout actions;
they cannot reinterpret new request or Marsh constructors. Account and network
v1 descriptors are unchanged. Fresh sessions have no persisted profile migration.

Execution-profile v2 replaces `allowedScriptHashes` with sorted unique
`allowedScripts`: entries have `hash` and `role` (`teapot` or `marsh`). A Marsh
entry additionally requires `creatorKeyHash`; a Teapot entry forbids it. The
trusted owner must derive that creator binding by applying the exact qualified
Marsh template to its seed, creator and fixed Teapot parameters, then comparing
the resulting script. A caller's script/creator labels are not qualification.
The native profile signature attests this narrowly documented synthetic binding;
Rust does not infer an immutable creator from the Marsh receiver datum.

V2 `inspect` and `prepare` additionally require a `reviewContext` object:

~~~json
{
  "schema": "castalia.cardano-fixture-review-context.v1",
  "utxos": [
    {"txHash": "<64 lowercase hex>", "outputIndex": 0, "utxoCborHex": "<original UTxO pair CBOR>"}
  ]
}
~~~

It has at most three entries and at most 32,768 total decoded CBOR bytes, sorted
by transaction hash and numeric output index. The original transaction has its
separate 32,768-byte bound. Native line framing is now bounded at 262,144 bytes
including newline so both hex payloads fit; oversize or incomplete frames close
the process. No root/import/recovery commands are added.

The owner independently resolves each entry from the actual validating ledger
snapshot. Rust checks the exact pair reference against the supplied reference
and the original body's normal/reference input sets, rejects duplicates and
unrelated entries, and authenticates the exact protocol NFT at its enterprise
script address before decoding inline role data. The full independently resolved
snapshot remains the owner's context digest; the bounded subset is separately
committed. It supplies exactly the necessary current fund/request evidence and,
when needed, a genuine selected normal key-input payer. A collateral or reference
input cannot establish normal payer participation.

Required role coverage:

| Action | Required resolved review evidence |
| --- | --- |
| Teapot bootstrap | None; new state is inspected from original output bytes |
| Request creation | Authentic initialized fund reference |
| Request revision | Authentic initialized fund reference and consumed request |
| Linked payout | Authentic consumed fund state and selected consumed request |
| Teapot control/direct payout | Authentic consumed fund state |
| Marsh bootstrap | Authentic initialized Teapot reference |
| Marsh reset/release | Authentic consumed Marsh state |

A selected input-payer role needs its actual normal key input in the remaining
slot. Controller, current recovery member and request-author labels derive only
from the relevant authenticated state/request role. For Marsh, controller derives
only from the qualified immutable profile creator binding. The creator can sign
without owning any normal payment input while another wallet funds fees. An
extra required signer or witness alone establishes no participation role.

The v2 review has `schema` (`castalia.cardano-fixture-review.v2`), `kind`,
`fundRole`, `fundScriptHash`, `stateAssetName`, `stateDatumHex`, `redeemers`,
`purpose`, `request` and `participation`. Redeemers are sorted by ledger tag
(spend before mint) then numeric index, and preserve each original Data slice.
The state datum is the genuine current input/reference state or the inspected
initial state at bootstrap. A request carries exact `assetName`, `authorKeyHash`,
canonical decimal `revision`, original inline `datumHex`, `inputReference`
(or null) and continuation/created `outputIndex` (or null). Its exact bounded
amounts, destination/datum and UTF-8 purpose derive from those same bytes.
Linked review reads the consumed request rather than accepting caller prose.
Raw CBOR review is fixture evidence, not a production financial display.

V2 supports only the agreed constructor families. Linked payout alone may mix
identical spend Action4 redeemers with exactly one matching MintRetire2; its
selected input reference and request burn agree. Other mixed/unlisted families
reject. Request creation inspects the minted output; author-only revision
inspects both the authentic prior anchor and its same-token next revision.
The trusted owner's exact compiled phase-two/value/script-data commitment checks
remain mandatory; structural native review is not independent ledger validation.

Profile/context statement domains remain v1 and bind the explicit v2 profile.
The new admission schema/domain are `castalia.cardano-fixture-admission.v2` and
`castalia/cardano-fixture-admission/v2\0`. Its fields are the v1 admission fields
plus `reviewContextHash`, SHA-256 of RFC8785 JCS of the exact bounded subset.
Rust recomputes that hash, the original body/envelope hashes and the derived
review hash before verifying the owner capability. Substituted/missing evidence,
changed terms, stale context, wrong profile/domain or reused preparation cannot
obtain a witness. Original body bytes are never reconstructed for signing.

### V2 verification checkpoint

The complete locked feature-enabled core regression command
`cargo test --locked -p castalia-wallet-core --features funding-fixtures`
passed all 86 tests with no warnings. This includes the unchanged 13 v1 fixture
cases and seven new v2 capability tests. The new structural tests demonstrate
signed creation/revision/linked review, exact request terms, missing/substituted/
duplicate context rejection, mixed-retirement rejection, creator participation
without a normal payment input, and actual normal-payer evidence rather than
an extra signer assertion. They use explicit placeholder script bytes and do
not themselves prove compiled execution.

Separate cross-repository integration uses the fixed Aiken blueprint and actual
fresh shared-core-derived native witnesses. The independently validating backend
accepted eight compiled transactions covering Teapot bootstrap, Marsh bootstrap/
reset/release, request creation/revision/linked payout and two-quorum controller
recovery. Marsh creator and its paying wallet were distinct: the creator had no
normal key input. Request authors likewise used a separate sponsor. Native and
backend reviews/admission statements matched exactly for every participant;
missing/wrong evidence, absent receipts and reused handles denied witnesses.
Those are synthetic-ledger qualification results, not public-network submission,
production Wallet consent, confirmations or a proof that every maximum-sized
source candidate fits a ledger transaction. The producer and this consumer
remain subject to independent final source review before their source pin is
advanced.
