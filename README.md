# Castalia Wallet

Castalia Wallet is the user-facing authority surface for Castalia capability identity. Its first checkpoint is narrow: prove wallet possession through a Chrome extension that can be called by the current Zenith Review/Auth SDK path.

This is **Castalia Wallet**, not Zenith Wallet. Zenith is the builder/supporting infrastructure provider. Castalia remains the civic/ecosystem identity surface.

The active membership and custody contract is [Castalia Member Key and Zenith-Signed Membership](docs/castalia-member-key-and-membership-cell.md). Wallet keeps one OS-random identity seed in encrypted extension custody and derives Dregg's Ed25519 + ML-DSA-65 hybrid identity from it. After explicit runtime profile approval and separate join consent, it proves Ed25519 possession to the selected issuer and independently verifies the returned deterministic v3 credential; Castalia Web verifies the same credential again. A hybrid Member Key, `.castalia-recovery` file, `.castaway` vault, Zenith membership credential, dormant Dregg v2 cell, `dga1_` policy, Web session, and Matrix identity are distinct objects and must not be collapsed.

`.castalia-recovery` is the narrow encrypted signing-authority backup implemented today. [`.castaway`](docs/castaway-portable-vault.md) is the planned application-neutral encrypted data vault for non-authority ontology-typed primitives, public credentials, and public account descriptors; it never carries recovery material or signing authority, and no current extension build claims conformance to that draft format.

The [Castalia Wallet Standard](docs/standards/README.md) publishes versioned interoperability proposals. Its first public draft, [CWS-001: Wallet files, typed sections and schema publications](docs/standards/cws-001/README.md), defines where data, recovery authority and device sessions belong, plus versioned file shapes and publisher-defined connection schemas for a future SDK; it does not activate adapters or change installed recovery files.

Release posture: this is a tested pre-production identity and membership wallet with preview multi-chain derivation, not a production-ready financial wallet. The canonical allowed claims, prohibited claims, and exact-release promotion gates are in [Production claims](docs/production-claims.md).

## Current Architecture Direction (2026-05-29)

**Castalia Wallet** is the credential and ownership bridge in the system.

### Core Model

- **Dregg** is the generic capability layer (capabilities, proofs, revocation, authority, HubFS).
- The **secS-magik repository** provides the RPC layer. The interface definition remains exactly as it is today. Implementation of this RPC layer will go through Dregg.
- The **Wallet** (this repository) holds credentials and serves as the ownership proof surface. It lives inside secS-magik implementations as the bridge to Dregg.
- The wallet is used in **secZ** contexts.
- **secC** is the generic client.
- The **secDaemon** role (sourced from the secS-magik repository) is the auth layer and gateway into Hub sections. It requires a record of ownership, best proven via ZK proof of wallet ownership against Dregg (or address authentication as fallback).

This direction unifies the browser extension work with the broader machine-to-machine capability rails.

See the canonical planning surface for the complete evolving model, including RPC interface preservation and implementation path:
https://github.com/bananawalnut/claude-hub/blob/main/capture/2026-05-29-castalia-wallet-rust-api-as-secZ-layer-for-secS-magik.md

### Repository Structure (High Level)

- `apps/chrome-extension/` — MV3 browser surface exercising the wallet-as-bridge.
- `packages/` — Core helpers, provider types, adapters (including future Dregg adapter and secS-magik integration points).

## Checkpoint A

Checkpoint A is green only when both conditions are true:

1. A browser can request a proof-of-possession challenge, the user can approve it in the wallet, and the wallet can sign it with a local disposable/dev key.
2. Dregg/Cipherclerk bugs that would make that flow insecure, broken, or misleading are fixed upstream or bypassed by documented local safe Castalia implementations.

Checkpoint A does not prove full Dregg capability possession. It does not ship production ZK proofs. It does not approve high-value custody in Chrome.

## Repository map

```text
castalia-wallet/
  apps/
    chrome-extension/       # MV3 browser wallet surface for Checkpoint A
  packages/
    core/                   # Pure challenge, key, verification, storage-state helpers
    dregg-adapter/          # Dormant permissionless-v2 Dregg compatibility path
    zenith-membership/      # Active v3 contract, verifier, and issuer client
    provider-types/         # Stable browser/provider TypeScript contract
    zenith-auth-bridge/     # Adapter to current Zenith Review/Auth SDK semantics
  docs/
    architecture.md
    devgraph-issue-create-v1.md
    devgraph-headless-issue-create-v1.md
    castaway-portable-vault.md
    castalia-member-key-and-membership-cell.md
    production-claims.md
    security-model.md
    secs-magik-layer.md
    upstream-dregg-contributions.md
    clean-start-inventory.md
```

## Safety gates

- Unknown origins can detect provider availability only.
- Membership issuance requires setup, unlock, the fixed possession transcript, and an explicitly approved runtime issuer trust policy.
- [Generic graph access](docs/browser-graph-access.md) adds explicit access requests and verified read connections using the shared core; a receiver grant remains required.
- Applications use the generic credential-bound presentation v2 interface. Wallet verifies the approved issuer and exact request/disclosure bindings and requires fresh consent; request semantics and execution belong to the application.
- The generic `castalia-wallet-present-credential-v2` terminal signer requires interactive approval. Application-specific signing methods, CLI and native bridge have been [retired](docs/wallet-application-adapter-retirement.md); old clients must explicitly migrate.
- Unsupported proof/private paths fail closed.
- Member Key custody is encrypted and durable; lock/reload clears decrypted authority from service-worker memory.
- No generated extension bundles, browser profiles, secrets, raw private keys, or real credentials belong in git.
- No current extension build emits or consumes the future `.castaway` vault format; historical recovery files with that extension require the documented migration path.
- The extension shows descriptor-only preview addresses for Cardano, Ethereum, Robinhood Chain, and Solana. The existing `.castalia-recovery` root reproduces them; balances, deposits, and transaction signing remain disabled.

## Commands

```bash
npm install
npm test
npm run typecheck
npm run build
```

The [Buildkite verification lane](docs/buildkite-ci.md) runs the existing portable checks with pinned tools; loaded Chrome acceptance remains a separate manual gate.

## Non-goals for first implementation

- No iOS wallet.
- No Mac/on-device wallet implementation.
- No production ZK proof claims.
- No high-value production key custody in Chrome extension.
- No broad capability browser or federation explorer.
- No installing the scanned Cipherclerk zip as a personal wallet.
- No Gallery Hub launch requirement.

> The Castalia Wallet is intentionally designed to be consumable both as a browser extension (via Wasm) and as a library imported by secS-magik implementations (including server layers in the Hub and UI surfaces that implement secZ).

Runtime provider configuration and migration are documented in [Provider profiles](docs/provider-profiles-v1.md). A fresh package has zero trusted issuers. Zenith and other compatible issuers use the same settings, capabilities and approval flow.

## Opt-in native service-holder source

The separately selected [service-holder package](crates/castalia-wallet-service-holder/README.md) has its own Cargo workspace/lock and checksum-pinned native source. It validates public service challenges and provides owner-private raw32 service custody; it is excluded from the generic Wallet build, does not change human/member custody, and provides no production signing or authority qualification.

## Public deployment

Use the [Zenith Hub lightweight deployer](https://github.com/ZenithResearch/zenith-hub-lightweight)
for the shared Apple-silicon Mac installer and operator UI. Component source lives
under [ZenithResearch](https://github.com/ZenithResearch). Installation does not
provision native identities, grant command authority, or enable external effects.
See `NOTICE.public-baseline.md` for the scope of this clean publication.

## Zenith Transfer native dependency

The public workspace includes the reviewed graph-access v2, native operator consent,
and first-resource-owner consent implementation required by Zenith Transfer.
`TRANSFER-NATIVE-SOURCE.json` records source provenance and public file hashes;
private Git history and installed Wallet state are excluded. The owner test vector
uses a synthetic resource UUID and the same signed public fixture as Transfer.
See `docs/first-owner-bootstrap.md` for the consent and compatibility boundary.

```sh
cargo test --locked -p castalia-wallet-core -p castalia-wallet-native -p castalia-wallet-presentation
cargo build --locked --release --target aarch64-apple-darwin -p castalia-wallet-native
```
