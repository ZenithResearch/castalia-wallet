# Public Cardano funding account descriptor v1

Status: partial non-production adapter-contract implementation. No transaction
construction, signing, provider endpoint, chain connectivity or funds operation
is enabled by this slice. Existing preview descriptors and production claims
remain unchanged.

## Interface and custody boundary

`OpenedWallet::cardano_funding_account(&CardanoFundingNetworkV1)` returns public
account-zero material only. It reuses the existing private
`castalia/chain-account/cardano-payment/v1` derivation; the Member Key is not the
payment key. The root and derived signing material remain within shared Rust
custody. No new method exports a key or signs bytes. This Rust-only interface
adds no browser, WASM or native transport capability.

The returned `castalia.cardano-funding-account.v1` descriptor contains exactly:
`schema`, `authority` (`descriptor-only`), `network`, `keySuite` (`Ed25519`),
`derivation`, `accountIndex` (zero), `paymentPublicKey` (32-byte lowercase hex),
`paymentKeyHash` (28-byte lowercase hex), and `address`.

This is a separate additive public type. It is not added to the private portable
format or the legacy `zenith.chain-accounts-section.v1`. Existing recovery bytes,
Member Key protocols, core version and consumer pins are unchanged.

## Explicit deployment context

`CardanoFundingNetworkV1::testnet(magic, genesis_hash)` creates a shape-validated
profile. `from_json` accepts at most 1,024 bytes and rejects unknown, missing or
duplicate fields, noncanonical hash strings, implicit networks and non-integer
magic. The exact input fields are:

```json
{
  "schema": "castalia.cardano-funding-network.v1",
  "network": "testnet",
  "networkMagic": 42,
  "genesisKind": "shelley-genesis-raw-json-blake2b256",
  "genesisHash": "2222222222222222222222222222222222222222222222222222222222222222"
}
```

These values are synthetic test context, not a claimed live network. Magic is an
unsigned 32-bit value; genesis hash is exactly 32 lowercase hexadecimal bytes.
The mandatory `genesisKind` has exactly one admitted literal:
`shelley-genesis-raw-json-blake2b256`. Its `genesisHash` means **Blake2b-256 of the
exact raw Shelley genesis file bytes**. Do not use JCS, re-serialized JSON,
normalized whitespace, a changed newline, another genesis file or a synthetic
emulator manifest. Missing or unknown kinds reject without a fallback.
`testnet_from_shelley_genesis_bytes(magic, raw)` computes that component directly;
it does not parse or validate the file, check its declared magic, or admit a node.

This matches pinned cardano-node
[`Protocol/Shelley.hs`, lines 122–149](https://github.com/IntersectMBO/cardano-node/blob/c9f353671277463521bcee5f9b4a40fa0096a9b5/cardano-node/src/Cardano/Node/Protocol/Shelley.hs#L122),
which hashes the raw bytes before JSON decoding, and
[`Types.hs`, line 206](https://github.com/IntersectMBO/cardano-node/blob/c9f353671277463521bcee5f9b4a40fa0096a9b5/cardano-node/src/Cardano/Node/Types.hs#L206),
which selects Blake2b-256. This is inspected public source, not node execution.
The pinned public mainnet Shelley file's 2,486 bytes independently hash to
`1a3be38bcbb7911969283716ad7aa550250226b76a61fc51cc9a9a35d9276d81`,
matching that revision's configured `ShelleyGenesisHash`; this comparison enables
no mainnet operation. Scalus conformance fixtures bind a separately tagged
synthetic manifest and must not label it a real Shelley genesis file.

Mainnet is deliberately rejected by this non-production profile. The existing
mainnet-only preview account output remains available and unchanged.

Testnet enterprise addresses use Shelley header byte `0x60` and Bech32 HRP
`addr_test`, per [CIP-19](https://cips.cardano.org/cip/CIP-0019). All test networks
share that address network tag. Consequently the same root yields the same
payment key and Shelley address across testnet contexts, while descriptor
comparison retains the exact magic and genesis hash. No unlinkability claim is
made. Neither a caller-provided hash nor an address verifies a connected node;
the later admitted provider must independently establish its pinned network and
genesis and current chain/fork. A matching file component alone does not
establish current ledger identity, node authenticity or fork membership.

## Independent synthetic conformance evidence

The existing published custody fixture
`docs/contracts/castalia-wallet-custody-v1.vector.json` supplies the synthetic
root through its encrypted container; no real wallet data or new private key
fixture was used.

An independent derivation check used JavaScript `@noble/hashes` 2.3.0 BLAKE3
context mode over `root || U32_BE(0) || U32_BE(0)`, with UTF-8 context
`castalia/chain-account/cardano-payment/v1`. Node's OpenSSL-backed Ed25519
implementation derived the public key from that result. Python standard-library
Blake2b with digest size 28 and an independent Bech32 encoder produced:

| Field | Expected public value |
| --- | --- |
| Payment public key | `672395b53d8af83efcc51cbced2341c6ddee66b6e8451dce08e260fc7190de2b` |
| Payment-key hash | `9c55c12c407940403cf9295e029d7ccc39aa2c3820b4f74d6a92be4e` |
| Testnet address | `addr_test1vzw9tsfvgpu5qspuly54uq5a0nxrn23v8qstfa6dd2ftunsh5zp2k` |
| Legacy mainnet address | `addr1vxw9tsfvgpu5qspuly54uq5a0nxrn23v8qstfa6dd2ftunsvuka9n` |

Before refactoring, the unchanged canonical Wallet source emitted legacy
`chain_accounts()` JCS bytes with SHA-256
`72e6e96c846aa13699d25bdbb11f9bd47ce18327e82182ac41ecf4b4d82f2b21`
for that fixture. The regression test preserves those exact bytes after the
private public-material helper is shared. The test suite also checks network
separation, malformed profiles, Member Key separation and encrypted recovery
stability without membership. These vectors qualify public derivation only;
they do not establish transaction witnesses, ledger admission, a live testnet or
independent security review.

## Verification at this slice

- TDD: the new integration test first failed because the new types/method were
  absent; all seven descriptor tests then passed.
- `cargo test -p castalia-wallet-core -- --test-threads=2`: all 64 Rust unit and
  integration tests passed, with zero failures; documentation tests had no cases.
- The strengthened valid-JSON size-bound test was rerun in the targeted suite
  after the full suite began; all seven tests passed again.
- Targeted Rust formatting checks and `git diff --check` passed.
- No TypeScript/package inputs changed. npm, WASM/native application builds,
  transaction signing, ledger execution, node connection and testnet operations
  were not run or qualified.

Independent source post-review and the remaining adapter-contract/ledger work are
required before broader completion. No commit or deployment is recorded here.

## Genesis-kind amendment

Before any consumer adoption, the network profile gained mandatory `genesisKind`
and exact raw-file hash semantics. Python's independent `hashlib.blake2b` with
digest size 32 supplied three byte-level vectors: compact synthetic JSON with a
newline, the same JSON with whitespace, and compact JSON without a newline. They
produce different hashes and distinct descriptors. These tiny byte vectors are
not complete live Shelley configurations. The new raw-byte helper hashes only;
its output stays `descriptor-only` and creates no signer or network admission.

The original seven descriptor tests were updated for the required field; two
new tests reject missing/unknown kinds and verify the independent raw-byte
vectors. The old seven-test/64-test checkpoint above remains historical.

Amendment verification: the nine targeted descriptor tests and all 66 shared-core
unit/integration tests passed. Targeted Rust formatting and diff checks passed.
The exact legacy descriptor-byte hash and core version 0.4.1 regression remain
green. No signer, transport, private-format, dependency, source-pin or deployment
change was added.
