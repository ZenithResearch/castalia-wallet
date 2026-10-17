# Castalia Wallet Agent Rules

Preserve original private histories and follow the local product, custody and test rules below.

## Product boundary

- Product name is **Castalia Wallet**, never Zenith Wallet.
- Checkpoint A is proof of wallet possession only. Do not claim production ZK proofs, production custody, broad capability browsing, or Gallery/Moons federation.
- Chrome extension keys are disposable/dev custody unless a later custody review approves stronger storage.
- Read and preserve [`docs/castalia-member-key-and-membership-cell.md`](docs/castalia-member-key-and-membership-cell.md) whenever changing wallet generation, custody, enrollment, membership status, recovery, rotation, `dga1_` policy issuance, or the `/start` flow. Provider neutrality supersedes the former mandatory-Zenith configuration rule. A fresh package has no trusted profiles; retain historical protocol bytes and Zenith as an optional legitimate issuer. The active v3 invariant is member control of the Castalia Member Key **plus** a verified Active credential signed by the issuer explicitly trusted in the selected runtime provider profile; neither key possession nor a credential alone is membership. Dregg permissionless v2 remains a distinct dormant compatibility path and must not be reinterpreted as v3.
- For v1 implementation, also read and preserve [`docs/castalia-membership-v1-contract.md`](docs/castalia-membership-v1-contract.md) and [`docs/contracts/castalia-membership-v1.json`](docs/contracts/castalia-membership-v1.json). These freeze the accepted Ed25519 encoding, extension-owned encrypted custody profile, non-circular cell identifiers, Control/Dregg authority split, and pinned trust roots; changing them requires a versioned migration and replacement vectors.

## Security boundary

- Unknown origins may detect provider availability only.
- Signing and privacy-revealing reads require setup, unlock, supported method, and approved origin.
- Do not commit generated extension bundles, local browser profiles, secrets, raw private keys, or test fixtures containing real credentials.
- Keep Castalia Web, Castalia Control, Dregg nodes, secS, Matrix, logs, receipts, and membership cells outside the private-key custody boundary.

## Testing

Use TDD for production code. Run targeted tests first, then `npm test` and `npm run typecheck`.
