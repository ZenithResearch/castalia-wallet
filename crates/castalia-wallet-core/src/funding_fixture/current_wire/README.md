# Current Kettle fixture wire reader

The native-only `funding-fixtures` feature exposes two read-only Rust functions. `decode_original_transaction` accepts the lowercase hex of one original four-field envelope. Its serializable observation matches `castalia.kettle-current-wire.v1` in Castalia Web. `transaction_id()` hashes the exact original body with Blake2b-256. `decode_original_output` accepts one original encoded output and measures its spans from byte zero. Every span identifies the offset, byte length and SHA-256 of the original slice.

The 16,384-byte input limit applies before hex decoding. Each input role and output array accepts up to 256 members. Plutus Data traversal permits depth 32 and 256 entries per collection. The decoded output Value accepts unsigned 64-bit holdings. Mint quantities use signed 64-bit integers. Quantities in the JSON observation are decimal strings. Spend and Mint pointers use the ledger order of normal outpoints and mint policies respectively. The reader retains the original input, asset, witness and redeemer order in the observation.

`scalus_output_values()` separately reports the measured Scalus 1.4.1 fixture representation and normalized 5,000-byte Value limit. A 5,041-byte original Value from the shared corpus normalizes to 40 bytes. A normal transaction tag records a byte-level observation. Establishing a live output's origin and acceptance requires its creating transaction, the output index and an independently authenticated ledger observation.

## Reproduce the comparison

```sh
cargo test --locked --offline -p castalia-wallet-core --lib --features funding-fixtures current_wire
```

The test reads the included public synthetic envelopes and expected observations. Its source is Castalia Web's `packages/funding-ledger/experiments/kettle-current-wire/corpus.json`, SHA-256 `283f5d6c41925c8046a86d06da7fce4bb73cc94b2182868d4883b949936f5034`. For each source-reference entry, `file` is relative to that Web corpus and `pointer` selects the original envelope in the named JSON file. The portable copy retains the source reference and adds the resolved hex. Literal entries retain their original bytes. No downloads or environment variables are needed.

The 46 successful cases compare SHA-256 of the original envelope, Blake2b-256 of the original body, SHA-256 of the recursively key-sorted compact JSON observation, and Scalus compatibility for all outputs and collateral return. The remaining 32 cases compare the rejection category. The source manifest’s `cmlAvailable` field records a separate Web-side CML round-trip observation. Rust computes the original body ID directly for every successful case.

Stored Wallet profiles, approvals and native fixture commands continue to use their previous readers. The module has no custody, admission or signing entry point.
