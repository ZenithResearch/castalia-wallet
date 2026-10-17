# Security model

## Current claim

Castalia Wallet controls one encrypted durable identity seed and deterministically reconstructs Dregg-compatible Ed25519 and ML-DSA-65 signing halves after passphrase unlock. It can prove Ed25519 possession for Zenith membership v3 and can produce Dregg's deterministic ML-DSA turn-signature half inside the Rust/Wasm custody core. It does not yet expose a website-callable Dregg transaction signer, prove production capability standing, or provide hardware-backed/high-value custody.

These are implemented source-level claims, not a blanket production or security certification. [Production claims](production-claims.md) defines the exact allowed release language and the evidence required to promote a capability.

## Storage posture

Chrome extension storage is not treated as final high-value custody. The 32-byte identity root is persisted only inside the versioned passphrase envelope: Argon2id derives an AES-256-GCM key and the canonical header is authenticated as associated data. Unlock reconstructs both private signing halves in extension-owned service-worker memory; lock or reload drops the opened wallet. `.castalia-recovery` is another encrypted copy of the same root authority and must be protected accordingly.

The planned `.castaway` format is a portable encrypted data vault for non-authority ontology-typed primitives and objects. It is not implemented by the current extension custody parser. Future import must authenticate and classify entries before mutation, preserve safe unsupported data without execution, verify public credentials before presentation, and reject recovery material, private keys, bearer secrets, signing capabilities, and executable content. `.castalia-recovery` remains the dedicated portable root-authority artifact. See [Castaway Portable Vault](castaway-portable-vault.md).

The frozen custody-v1 header still says `keySuite: "Ed25519"` because it serializes Ed25519 PKCS#8. The embedded seed is also Dregg's ML-DSA `xi`; no independent PQ secret or second backup exists.

## Fail-closed requirements

Signing and privacy-revealing reads reject when:

- setup is incomplete;
- wallet is locked;
- origin is unapproved;
- method is unknown;
- payload is malformed;
- proof/private path is requested before support exists;
- page tries to spoof origin.
- a Dregg hybrid identity cannot be reconstructed exactly from the recovered seed.
- an imported vault or recovery artifact cannot be authenticated and classified without mutating existing state.

Unknown origins may detect provider availability only.

## Sensitive artifacts that must not enter git

- generated extension bundles;
- Chrome profile state;
- raw private keys;
- real credentials;
- local secret-bearing environment files.
