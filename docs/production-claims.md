# Production claims

Status: canonical release-language boundary for the Castalia Wallet Chrome extension

## Current release label

Castalia Wallet is a **tested pre-production identity and membership wallet with preview multi-chain account derivation**. It must not be described as a production-ready financial wallet, independently audited custody, hardware-backed custody, or suitable for significant funds.

Automated tests and package inspection prove only the behavior exercised at an exact source revision. A protected production-package run proves only the exact artifact digest produced by that run. Neither becomes release evidence for a later commit, and neither substitutes for clean-device owner acceptance or independent security review.

## Claims supported by the implemented evidence

| Surface            | Claim that may be made                                                                                                                                                                                                                                               | Required boundary                                                                                                                                                                                |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Extension custody  | The extension creates an operating-system-random identity seed, persists only its authenticated Argon2id/AES-256-GCM container, and drops unlocked authority on lock, reload, or service-worker restart.                                                             | Chrome extension storage is not hardware-backed or approved for high-value custody.                                                                                                              |
| Recovery           | `.castalia-recovery` is an independently randomized encrypted copy of the root authority and restores the same Member Key, Dregg-hybrid identity material, and preview chain accounts. Import replacement requires explicit confirmation and clears prior approvals. | The file is signing authority, not membership, admission, a profile export, or Castaway data.                                                                                                    |
| Membership         | A Chrome-owned approval ceremony binds the observed initiating tab and origin before the extension proves Member Key possession to the explicitly selected runtime issuer and verifies the returned v3 credential.                                                             | A verified credential is not a Web login, Matrix identity, Control approval, role, capability, or production Dregg standing. Live membership depends on an available, correctly operated issuer. |
| Devgraph operation | The provider can approve and sign the exact `devgraph.issue.create.v1` presentation with bounded request, digest, origin, tab, Member Key, expiry, and idempotency bindings.                                                                                         | This is not a generic Devgraph, Work, transaction, or arbitrary-message signer, and Wallet does not own the resulting mutation or receipt.                                                       |
| Chain descriptors  | Rust/WASM custody deterministically derives public preview descriptors for Cardano mainnet, Ethereum mainnet, Robinhood Chain mainnet, and Solana mainnet-beta without exporting private chain keys. Every displayed network label includes **Preview**.                                               | Always say **preview**. Balances, deposits, transaction construction, signing, broadcasting, and third-party wallet interoperability are not implemented.                                        |
| Castaway           | The extension documents and enforces the distinction between ordinary portable data and recovery authority.                                                                                                                                                          | The current extension does not encode, decode, import, export, or claim conformance to `.castaway`; Castalia Web implements only its own bounded v1 slice.                                       |

Ethereum and Robinhood Chain intentionally share one EVM key and address while retaining separate network account IDs. All preview accounts derive from the same wallet root. The product therefore makes no anonymity or unlinkability promise; membership-payment activity may link a chain account to the Member Key.

## Claims that are not permitted yet

Do not claim that Castalia Wallet:

- is production-ready, independently audited, unhackable, hardware-grade, or safe for significant funds;
- supports receiving, holding, displaying balances, sending, swapping, bridging, staking, or signing chain transactions;
- implements BIP-39, BIP-44, CIP-1852, hardware-wallet, or third-party wallet interoperability;
- provides anonymous or unlinkable chain identities;
- backs up authority in `.castaway` or conforms to the Castaway vault format;
- provides production zero-knowledge proofs, general post-quantum transaction protection, arbitrary signing, or full Dregg capability possession; or
- creates a Castalia Web session, Matrix access, Control authorization, community admission, or infrastructure authority.

## Evidence required to change the label

Before using **production-ready** for any extension scope, record all of the following for the exact release revision:

1. A successful protected production-package run with zero built-in issuer trust and separately reviewed runtime profiles, plus the artifact content-tree digest and named owner acceptance.
2. A clean-profile Chrome installation of that exact artifact covering create, lock, reload, unlock, recovery, identity replacement, origin approval, membership, corrupted input, and update behavior.
3. Independent application-security and cryptographic review of MV3 lifecycle handling, popup/tab/origin binding, custody FIFO, recovery design, KDF parameters, seed use, and supply chain.
4. Recovery drills and migration evidence for historical misnamed `.castaway` recovery files.
5. Signed distribution, update, rollback, monitoring, incident-response, and issuer-key-operations evidence.
6. For each chain promoted beyond preview: independent derivation vectors, testnet funding and recovery, balance/RPC behavior, transaction construction, human approval, signing, broadcast, fee/nonce or UTXO handling, replay protection, and failure tests.

Passing only the chain gates may promote one named network capability. It does not automatically promote another network, Castaway compatibility, production Dregg capability standing, or high-value custody.

## Release record

Every release claim must name or link:

- the exact Git commit;
- the protected workflow run and artifact digest;
- the explicitly approved runtime profile, issuer origin, key identifier, and public-key fingerprint;
- the clean-device acceptance record;
- the security-review version and unresolved-risk disposition; and
- the explicitly enabled capabilities and retained non-claims.

## Approved short-form copy

> Castalia Wallet provides tested local Chrome custody for a recoverable Castalia identity. It derives deterministic preview addresses for Cardano, Ethereum, Robinhood Chain, and Solana while keeping private chain keys inside extension custody. Multi-chain receiving, balances, and transaction signing are not yet enabled, and Chrome custody is not intended for high-value assets.

See [Security model](security-model.md), [Checkpoint A security gates](security-gate-status.md), and [Castaway Portable Vault](castaway-portable-vault.md).
