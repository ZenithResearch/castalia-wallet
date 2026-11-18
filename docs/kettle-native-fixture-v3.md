# K3 native Registered-pour fixture v3

This is a separate, default-off native fixture capability for one current Kettle
Registered pour after one genuinely accepted Add in the independently observed
synthetic ledger. It returns a real custody-held Cardano payment witness, labeled
`synthetic-fixture-approval-only`. Fixture-owner admission is not human consent,
production chain observation, or authority to administer the Kettle.

The new `castalia-kettle-funding-fixture` binary uses fresh disposable custody only.
It accepts no saved Wallet, root/private key, seed, account import, or generic
signing command. Existing v1/v2 dispatch, membership contracts, application and
WASM surfaces, persisted Wallet formats, and historical consumer pins are
unchanged. The existing `funding-fixtures` feature remains disabled by default
and forbidden on WASM. No production origin or UI activates this module.

## Source-admitted scope

The immutable profile is `KettleFixtureProfile::qualified()` and is installed
only after an independent fixture-owner signature. The native checker requires
exact equality with the following closed profile, including its descriptor and
source-content Data bytes; caller-signed arbitrary executable hashes are rejected.

| Item | Pin |
| --- | --- |
| Base Wallet | PR 28, `b0cd2dfc95602f6d2fb63b89efed148688881a1e` |
| K2 scripts JSON SHA-256 | `2102de0164ee3b09f925f451338e978dfb6825090d0d6038ab26746488cb00f3` |
| Kettle V3 hash | `5d50ccd67901c146fc4938371e1ff877d42864833218acf735cb5261` |
| Applied companion V3 hash | `ec17adcfd67ff9c84f4d9d4a0c516482ff5de676c0d9cfda1ed530bf` |
| Scalus 1.4.1 effective execution profile | `e293f4cdadf53d216024ba45c822f6c85562d7335e28bfa2c8ad6068e50cf95f` |
| Synthetic network | testnet magic 2, raw Shelley genesis hash `12` repeated 32 times |
| Deployment / scope seed | `cf` repeated 32 times / `ce` repeated 32 times, index 0 |
| Public raw vector SHA-256 | `8c73807c8f316f998fa3822764aaa035c8e435cbd6d94f316a360887ca671630` |
| Web review JCS SHA-256 | `389fbd725f23f1082ddf08b5072553546289ed4af0471fffd9a5198eb14038da` |
| Shared raw variants SHA-256 | `75a3b853070dda32d705a2d4f1138a0d2071d8a44fb5a752e995d134eee9f755` |

The profile identifies policy `drink` version 1, the applied companion, parameters
`aa`, constraints `bb`, schema `fixture input bytes`, schema version/codec 1,
input bound 4, and asset bound 2. Digests and sparse-map paths use the existing K1
transcripts and canonical Plutus Data encoding. Initial state is the actual
accepted Add output 0, epoch 1, with the single enabled initial-use record, zero
paid counters, and empty compressed path. The successor is epoch 2 and preserves
controller, roster, reserve, and complete principal Value except the exact payout.
This deliberately does not admit later uses, native Add/Disable/admin, proposals,
multiple native signers, arbitrary policy implementations, arbitrary histories,
or every P1 recipient/input shape.

## Independent observation and signing boundary

The fixture owner must reconstruct the pinned compiled scripts and execution
profile; actually publish both scripts through signed transactions; submit the
Add and retain its original body/redeemer/content; resolve the live singleton by
exact outpoint; and resolve the complete, disjoint normal/reference/collateral
sets from its ledger. Before admission, the owner independently verifies original
script-data integrity, both actual Spend evaluations, network/cost profile,
protocol limits, minimum output ADA, reference-script pricing, and original-body
signature requirements. It must refresh or invalidate the authenticated context
immediately before requesting handle-only approval.

The native inspector does not execute a VM or independently authenticate a chain
receipt. `acceptedAdd` is an authenticated owner observation, checked against the
current normal state input, pinned descriptor/content, epoch, root, and leaf. A
signature from an arbitrary caller is insufficient: the process owner key is
fixed at launch, while the executable/descriptor profile is separately pinned in
native code. This does not qualify an unaudited production indexer or provider.

Exactly three normal inputs are admitted: actual Kettle state, actual companion
carrier, and a plain ADA-only enterprise payer. Exactly two reference inputs hold
the separately hash-checked V3 programs; a role-shaped datum is not code. Exactly
one collateral input belongs to that same native payer. All six outpoints are
unique and the supplied originals match the exact body sets and ledger order.
The original body must name the native payer as its sole explicit required signer
before costing. That signer pays fees and assumes collateral liability; it does
not supply controller, recovery, author, or policy authority.

Exactly two Spend redeemers point to the actual state/carrier input ordinals and
mutually bind state ref, registered action, authenticated record, payout terms,
next-use digest, and new root. Mint, foreign purpose, governance, certificate,
withdrawal, and auxiliary-data effects are excluded. Output roles are fixed:
0 state continuation, 1 exact enterprise-key NoDatum payout, 2 exact ADA carrier
refund to its keeper, 3 native payer change. Whole principal conservation and
`payer input = fee + payer change` are independently checked. Retained support and
recipient topups are zero. D6/D7 allocation and product payability are not decided.

The review distinguishes successful fee payment from invalid-script collateral
liability. The sole collateral input and exact plain return both belong to the
native payer; their difference equals declared total collateral and is at least
150% of the fee. No return or alternate collateral owner is admitted here.

For this exact code pair, raw V3 sizes are 15,122 + 6,069 = 21,191 bytes, within
the first 25,600-byte reference-fee band. Native requires a single-map unsigned
witness set, adds 106 bytes for the expected tagged singleton vkey witness, and
bounds the resulting envelope to 16,384 bytes. Its pinned fee floor is
`155381 + 44*projectedSize + ceil((577000*memory + 721*steps)/10000000) + 15*21191`.
The fixed vector floor is 1,202,764 lovelace against an actual fee of 1,202,940.
The owner still performs independent ledger/VM/minimum-fee checks. This formula
is not a general Conway fee library or permission to add other witnesses.

## Versioned transport and immutable review

The JSON-lines CLI takes only `--owner-verification-key PUBLIC_HEX`, and exposes
`open`, `setProfile`, `setContext`, `inspect`, `prepare`, `approve`, `cancel`,
`invalidate`, and `close`. Every command and nested DTO rejects unknown fields.
`inspect` and `prepare` require `reviewContext`; there is no legacy fallback.
Input framing is limited to 262,144 bytes including newline before JSON parsing.
The actual unsigned transaction is limited to 16,384 bytes, resolved originals to
32,768 aggregate bytes, Data to 4,096 bytes, and parsing to the existing bounded
CBOR depth/node limits. Duplicate keys, including differently encoded aliases,
are rejected. Data commitments preserve map order, while supported constructor
and list encodings normalize only through the frozen Data encoder; state and
redeemer Data must already have that canonical encoding. The admitted action
grammar uses typed arrays and constructors; the internal ordered serializer does
not qualify arbitrary Plutus Data maps for this capability.

All statements are JCS UTF-8 signed with Ed25519 after the named domain followed
by one NUL byte. Public type definitions and the full positive corpus are the
executable contract examples:

- Profile domain `castalia/cardano-fixture-profile/v3`: statement fields
  `schema`, `sessionId`, `epoch`, `network`, `profile`; schema is
  `castalia.cardano-fixture-profile.v3`. SHA-256 of JCS is `profileDigest`.
- Context domain `castalia/cardano-fixture-context/v3`: fields `schema`,
  `sessionId`, `epoch`, `profileDigest`, `generation`, `digest`; schema is
  `castalia.cardano-fixture-context.v3`. Digest is SHA-256 of the entire closed
  `castalia.cardano-fixture-review-context.v3` observation.
- Admission domain `castalia/cardano-fixture-admission/v3`: fields `schema`,
  `sessionId`, `epoch`, `profileDigest`, `contextGeneration`, `contextDigest`,
  `paymentKeyHash`, `transactionBodyHash`, `transactionEnvelopeHash`, `reviewHash`,
  `reviewContextHash`; schema is `castalia.cardano-fixture-admission.v3`.
  Body hash is BLAKE2b-256 of the original body slice; envelope/review/context
  digests are SHA-256, with JCS for JSON values.

The context contains `schema`, `observedSlot`, `acceptedAdd`, and `utxos`.
`acceptedAdd` contains its `txHash`, `outputIndex`, `descriptorDataHex`, and
`sourceContentDataHex`. Each UTxO contains `role`, `txHash`, `outputIndex`, and
`utxoCborHex`, ordered normal, reference, collateral, then outpoint. Native requires
`observedSlot < TTL <= observedSlot + 120` and optional validity start no later
than observation. Context generation is independently authenticated, strictly
increasing within the current session epoch, and bounded to a safe JSON integer.

The review includes original body/script-data hashes, six role refs, original
Data hex, public controller/roster, before/after epochs and roots, prior/next use,
action digest, exact amount arrays and cap deltas, both declared budgets, separate
fee/collateral exposure, and original purpose bytes plus strict UTF-8 text. ADA
sorts before native asset units; amounts are decimal strings. The independent
Web review must equal every field before the owner signs admission.

`prepare` validates exact immutable bytes and the admission signature, then consumes
the admission hash and returns a random opaque handle plus review. `approve`
accepts only that handle, consumes it before any further check, and signs only its
stored original body hash. Cancellation and failed/expired approval never restore
an admission. Expired pending records are swept before the eight-handle capacity
check; up to 64 consumed admissions remain recorded per authenticated context.
Only authenticated context advance or explicit session epoch invalidation clears
that ledger, so no silent eviction reauthorizes an old admission. Close revokes all
handles and destroys this session's custody; a closed process session cannot reopen.

Handle TTL starts after successful prepare (30 seconds normally, maximum 60).
Observation freshness is separate: an unused stamped review can remain valid
while that independently authenticated context remains current. A new signed
observation can intentionally reauthorize the same intent. Handle-only approval
cannot discover unreported ledger changes, and emitted signatures cannot be
revoked. Exact live-head refresh plus ledger spent-input rules own the remaining
race/replay boundary. Synthetic test admission is never reported as human review.

## Reproduction and validation

From the Wallet repository root, with an existing compatible disposable target:

```sh
cargo test --locked --offline -p castalia-wallet-core --features funding-fixtures --test kettle_fixture_v3 -- --test-threads=2
cargo test --locked --offline -p castalia-wallet-core --features funding-fixtures -- --test-threads=2
cargo check --locked --offline -p castalia-wallet-core
cargo build --locked --offline -p castalia-wallet-core --features funding-fixtures --bin castalia-kettle-funding-fixture
```

The fixed public vector carries original accepted Add and publication envelopes
and no private key. Its payer is the published synthetic `7a` repeated 28 bytes;
there is no corresponding payer secret in this corpus. Native unit tests rebind
public payer fields to a newly generated custody account solely to test signature
and handle behavior; this is explicitly not a VM settlement assertion. Actual
live integration instead builds and preflights a fresh original transaction for
the returned native public account, obtains its native witness, and submits that
original signed envelope through the independently observed synthetic ledger.

The shared byte variants exercise duplicate/aliased body, witness, policy and
asset keys, unsorted original inputs, duplicate Spend pointers, and a balanced fee
below the actual reference minimum. Additional native tests cover exact complete
review equality, mutated roles/profile/root/use/authority/payout/collateral,
session/domain/body/review/context authentication, consumed admission capacity,
expiry/cancel/invalidate/close, real public-key verification of the original-body
witness, and bounded closed CLI dispatch. No existing saved contract migration or
production activation is included. Broader application checks require the
repository's existing dependency setup; no dependency installation is implied.
