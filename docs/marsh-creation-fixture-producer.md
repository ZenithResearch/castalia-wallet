# Marsh creation holder fixture producer

This additive Rust API is available only with `castalia-wallet-core` feature
`funding-fixtures` (default off). It produces a custody-held MemberKey signature
over the frozen A3 creation transcript and a separate A4 membership trust path.
It is synthetic qualification, not an end-user consent ceremony, saved-account
signing, a Cardano witness, ledger admission, or actual Marsh minting.

The baseline is canonical `ZenithResearch/castalia-wallet` commit
`459122ad15f86a049b0adab45ed07c3f187d3957`. The Web reference source is
`packages/funding-ledger/src/marsh-creation-authority.ts`; public A3 vectors are
copied byte-for-byte into `tests/fixtures/marsh-creation-authority-v1.json`.
The A4 path vectors are copied from Web's
`contracts/cardano/qualification/marsh-creation-trust-rust-20261117.tsv`.
Neither fixture contains private keys or real credentials. Deterministic issuer
and admission keys in Rust tests are disposable test keys; each tested Wallet
MemberKey is freshly generated inside custody.

## API and trust boundary

`FundingFixtureSession::fresh` owns an ephemeral `OpenedWallet` and its derived
account-zero Cardano descriptor. No new root import, private-key export, generic
signing, CLI, WASM, native product, or installed application surface is added.
`member_key()` returns the public MemberKey only.

1. `marsh_profile_statement(raw)` validates a closed object containing A3
   `deployment` and `membershipTrustPolicy`. It binds the full manifest,
   independently computed A4 count/commitment, exact own payment descriptor,
   session ID, and epoch. `install_marsh_profile(raw, signature)` authenticates
   that statement under `MARSH_PROFILE_DOMAIN` with the session's separately
   supplied **synthetic fixture admission signer**. The profile is immutable;
   replacement attempts fail. Neither a credential nor a holder request chooses
   a trust root. This profile is independent of the historical Scalus fixture
   profile and does not change historical transaction review.
2. `marsh_context_statement(generation, digest)` and `set_marsh_context` bind an
   independently observed context under `MARSH_CONTEXT_DOMAIN`. Generation must
   increase in the current epoch. A new observation clears pending Marsh handles
   and consumed admission capabilities. Epoch invalidation removes the context.
3. `inspect_marsh_creation(raw)` accepts exactly `{context, credential}`. It
   bounds raw JSON to 65,536 bytes and rejects duplicate/unknown fields. It
   validates the full A3 grammar, base-v3 issuer signature under the admitted
   exact issuer tuple, credential owner equal to the custody MemberKey, initial
   controller equal to the custody-derived payment hash, and exact admitted
   deployment/network. It returns the complete immutable review statement,
   credential commitment, transcript hash, A4 path, descriptor, and observed
   generation. The existing portable strict verifier remains unchanged.
4. The independent synthetic signer authenticates that entire review with
   `MARSH_ADMISSION_DOMAIN`. `prepare_marsh_creation(raw, signature)` recomputes
   inspection, verifies that signature, and stores its frozen bytes and identity
   binding. A capability is consumed once; there are at most eight pending Marsh
   preparations and 64 used admissions per observation. Prepare reclaims expired
   pending slots without releasing their consumed admission hashes. Exhausting
   the 64-admission ledger requires a new authenticated observation or epoch
   before a new review can prepare. The existing session TTL
   is bounded to 60 seconds and defaults to 30 seconds. It starts when prepare
   stores the handle, not when inspection or the synthetic signature occurs.
5. `approve_marsh_creation(handle)` consumes the handle before subsequent
   checks, verifies epoch/context/TTL, and signs only the retained A3 bytes with
   the private MemberKey held inside the existing Wallet. It accepts no changed
   terms, key, network, or profile. The returned `proof` is exactly the frozen A3
   `{schema, credential, holderSignature}` object. `trustPath` is separate and
   the outer result is labelled `synthetic-fixture-approval-only`.
6. `cancel_marsh_creation`, context replacement, session `invalidate`, and
   `close` revoke affected handles. The session cannot replace custody or recover
   a root. Closing drops custody and all subsequent operations fail. A profile
   replacement is unsupported, so no pending handle can survive such a change.

Fixture context freshness is supplied independently by the synthetic admission
authority. An unused signed review has no separate wall-clock expiry and can
remain valid while its session, epoch, profile, and observed context stay current.
Cancellation or handle expiry does not permit reusing its consumed admission in
that observation. A new signed observation invalidates the old review and can
intentionally authorize the same logical intent through a newly signed review.
These local rules do not establish chain replay prevention: actual ledger seed
consumption and final transaction admission own that guarantee.

A3 hashes/transcripts and existing base-v3 signed bytes are unchanged. A4 sorts
1–128 unique exact issuer/key-ID pairs, validates their public keys, fills all
128 Merkle slots, and authenticates the candidate key using seven sibling hashes
against the admitted count-bound commitment. Canonical compressed points,
non-small-order points, and strict Dalek signatures are required. This states
no new prime-subgroup requirement.

The holder message binds logical projected addresses. It cannot independently
resolve a ledger seed, authenticate Kettle state, establish phase-one address
validity, inspect final transaction outputs, or attest a user's independent
backup. Those checks remain with the independently qualified adapter and later
O3/W6 integration. The synthetic signer must independently inspect the resolved
context rather than merely echo caller claims. No claim about actual human
approval follows from an authenticated fixture signature.

## Verification

```sh
cargo test --offline --locked -p castalia-wallet-core --features funding-fixtures --test marsh_creation
cargo test --offline --locked -p castalia-wallet-core --features funding-fixtures
cargo check --offline --locked -p castalia-wallet-core --no-default-features
```

Focused tests compare all three frozen A3 issuer/commitment/holder byte vectors,
reject the eight frozen hostile proofs, compare all four independent A4 path
vectors (counts 1/2/128), mutate every creation context leaf, verify fresh
custody-produced proofs, and reject cancelled, expired, consumed, stale,
foreign-session, wrong-signer, mismatched-profile, credential, MemberKey,
controller, and root cases. They exercise inline byte/depth/integer/map bounds,
closed raw parsing, immutable review data, manifest ordering, and path bounds.
The fresh positive test emits a public `MARSH_PUBLIC_VECTOR` only under test
output; the Web reference verifier can independently verify that JSON. Synthetic
proof verification does not close actual creation mint or native product consent
qualification. D6 allocation and D7 exact-claim approval remain separate.
