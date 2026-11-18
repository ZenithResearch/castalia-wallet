# Current Kettle approval fixture v2

The optional native `funding-fixtures` feature builds `castalia-kettle-current-approval-v2-fixture`. The local launcher provisions one observer public key and one role per fresh, disposable payment credential. The observer owns the active branch and authenticates current liveness and measured script costs. Rust resolves the selected outputs from their original normal creating transactions and derives the action and its effects from the original candidate.

The c043 execution profile is `36e0ba818c65428a8c30bc5a4885af4e35e9148d53bb22383e7d1301442d1779`. The v2 approval profile hashes the UTF-8 text `castalia/kettle-current-approval/v2`, one zero byte, and that lowercase profile ID as ASCII. Its SHA-256 is `d426292b5dd828a345872343f56a22a99a949114fa7123d71faa14c4f477fbc5`.

| Action | Required native participation in the qualified fixture | Reviewed effect |
| --- | --- | --- |
| Add | Current controller and fee payer | Add a descriptor at an absent registry key with its stated caps |
| Registered | Fee payer | Execute the bound Kettle and companion purposes and pay the exact authorized debit from ordinary funding |
| Disable | Two distinct current recovery credentials and fee payer | Disable an enabled record and retain its paid quantities and use history |
| Direct | Current controller and fee payer | Pay the approved fixed terms and return any unselected ordinary principal |
| Restore | Two distinct current recovery credentials and fee payer | Replace the controller and preserve the consumed recovery roster |
| Replace | Two distinct outgoing recovery credentials and fee payer | Install the specified recovery roster and preserve the controller |
| Create | Request author and fee payer | Consume the ordinary payer seed, mint the derived request marker and fund its separate reserve |
| Revise | Current request author and fee payer | Consume the live request, preserve its marker and exact reserve, and advance the revision |
| Proposal Pay | Current controller and fee payer | Pay the live request, burn its marker and return the full reserve to its author at a separate output |

Create and Revise use the current singleton as a reference and leave it live. Other actions spend the singleton and name its successor. Current fixed payouts select one or two NoDatum funding outputs and use an enterprise payment-key recipient, NoDatum, one or two positive ordered debit rows, and a 1–64 byte UTF-8 purpose. The selected state retains its singleton and protected 5 ADA. The request reserve comes from the original request output. The admission checks all consumed and continuing principal quantities, regardless of which Kettle equation the underlying valid ledger supplies.

The three policy actions call the v1 pure reviewer on an internally derived, Spend-only projection. The v2 disclosure contains its entire result. Only the v2 source, session, role, intent and one-use release receipt can authorize this process. The six fixed and request actions bind the authentic normal or reference singleton, exact request and funding Spend pointers, actual request Mint policy and the complete output roles. The payer is distinct from the current controller and roster, and from the author on Create and Revise. The profile accepts a shared author and payment recipient while preserving their separate output roles.

The original transaction limit is 16,384 bytes. Up to eight distinct original creator envelopes total at most 65,536 bytes. The process limits each input frame to 196,608 bytes including its newline. The closed original witness map, `a105`, carries the exact redeemer bytes. Each measured Spend or Mint is matched by ledger purpose and ordinal and covered by its declared positive budget. The v1 and v2 paths share the original script-data integrity check and the fee calculation for the pinned Scalus backend. The final tagged VKey count, fees, reference byte charges, output minima, collateral return and risk all receive independent checks. The source retains the accepted history behind its observation. Rust verifies the exact selected creator, live request marker, its seed-derived name and all fields without replaying an unbounded chain of revisions in an approval command.

One-use handles expire after 30 seconds. The observer serializes source mutation during the final independent review, witness release, assembly and submission. The Wallet signs the transaction body. Canceling a group can prevent submission while an already released witness remains valid under its original body and validity interval. This family is a default-off synthetic local facility.

Run `cargo test --locked --offline -p castalia-wallet-core --features funding-fixtures --lib current_approval` for scoped v1/v2 regressions. The matching Castalia Web experiment qualifies the independently rechecked semantic reviews and genuine local custody flow.


The resolved Wallet corpus reconstructs the nine full Web reviews from the same original bytes. Its 15 unique creator envelopes are stored once and verified by digest on reconstruction. The complete Web capture has SHA-256 `bb2d8c4bd526e1ba2ece65f1521e2c73a729f0f35de2f7a1dffbd5ad73db5a20`; the portable resolved corpus has SHA-256 `d21b113b7230a299f32773866d171300a38c7460c7c1dc9f81b0cfcb01094267`. These read-only examples use deterministic host credentials. The separate Web settlement archive uses fresh native credentials and binds the executable digest.
