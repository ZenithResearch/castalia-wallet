# Dregg membership integration

Status: dormant compatibility. The authority-owned binding below is legacy v1, while the permissionless v2 adapter/vector remain preserved for a future Dregg-backed release. Active Join is Zenith-signed v3 and is defined in [Castalia Member Key and Zenith-Signed Membership](castalia-member-key-and-membership-cell.md). The active provider advertises `membershipJoinProtocol: "castalia.zenith-membership.v3"`; no stored v1 or v2 record is reinterpreted as v3.

## Scope

The retained adapter can bind one issued Castalia membership cell to an extension session, but the active v3 provider does not expose this legacy binding as current membership.

This adapter is the read/verification half of the canonical [Castalia Member Key and Membership Cell Architecture](castalia-member-key-and-membership-cell.md). It does not create the Member Key, approve admission, or make the cell alone sufficient for authentication. It proves that the configured authoritative cell is bound to the wallet's current key and reports its lifecycle state.

The wallet does not discover membership by scanning the ledger. Issuance supplies three public coordinates:

- membership cell ID;
- Castalia authority public key;
- immutable membership application commitment.

The wallet stores those coordinates with the node URL in `chrome.storage.session`. The binding resets when the extension reloads, alongside the disposable key and origin approvals.

## Binding document

The side panel accepts this JSON shape through **Bind issued membership**:

```json
{
  "nodeUrl": "http://127.0.0.1:8765",
  "expectation": {
    "cellId": "<32-byte lowercase-compatible hex>",
    "authorityPublicKey": "<32-byte lowercase-compatible hex>",
    "applicationCommitment": "<32-byte lowercase-compatible hex>",
    "application": {
      "factoryId": "<32-byte hex>",
      "programId": "<32-byte hex>",
      "officialDreggCellId": "<32-byte hex>",
      "ownerPublicKey": "<wallet raw Ed25519 public key hex>",
      "applicationKind": 7,
      "applicationVersion": 1,
      "applicationNonce": 1,
      "membershipClass": 2,
      "jurisdictionCode": 840,
      "applicationFlags": 0,
      "createdAt": 1700000000
    }
  }
}
```

Binding succeeds only after the extension recomputes the canonical BLAKE3 application commitment, confirms that `ownerPublicKey` is the current wallet's raw Ed25519 key, fetches the configured cell, and verifies it. Generating a fresh wallet key clears any previous binding. Plain HTTP is accepted only for loopback development; non-loopback nodes require HTTPS.

## Verified cell contract

`@castalia-wallet/dregg-adapter` reads only:

`GET /api/cell/{issuedCellId}`

It rejects the response unless all of the following hold:

- the requested and returned cell IDs match;
- the cell exists;
- the cell public key matches the configured Castalia authority;
- the cell carries a `Cases` program and exactly 16 fields;
- the `CASTMEM1` magic and schema version are exact;
- commitment fields 8–11 reconstruct the issued application commitment;
- the supplied canonical application envelope hashes to that commitment;
- the committed application owner key matches the current wallet key;
- lifecycle status is one of Pending, Active, Suspended, Revoked, or Expired;
- timestamps are monotonic;
- a lifecycle generation greater than zero has a persistent receipt-chain head;
- balance and nonce are non-negative safe integers.

This is online source-of-truth verification against the configured node. It is not yet an offline inclusion-proof verifier. HTTPS deployment, endpoint identity, and Castalia authority coordinates are therefore part of the wallet's trust configuration.

## Browser provider

Approved origins may call:

```js
const membership = await window.castaliaWallet.getMembership()
```

The page supplies no node URL, cell ID, authority key, or commitment. Any payload attached to the provider request is ignored. The service worker always uses the wallet-held session binding.

Unknown origins may call only `isAvailable()`. Membership status requires setup, unlock, and explicit origin approval.

Current Castalia Web onboarding uses `getStatus()` and `createAuthenticationPresentation()`. The extension maps those methods onto the same setup/approval state and `signChallenge()` implementation. The returned `castalia.wallet-presentation.v1` payload is the serialized canonical signature presentation; Castalia Web still labels it `pending-server-verification` and does not issue a browser session.

## Local live-node smoke

Build and unit-test the adapter:

```sh
npm test --workspace @castalia-wallet/dregg-adapter
npm run typecheck --workspace @castalia-wallet/dregg-adapter
```

The Dregg process restart test supports an opt-in live fixture handshake through `CASTALIA_WALLET_LIVE_SNAPSHOT`. Once the node reaches Active generation 1, it writes the binding document and waits for `<snapshot>.done`.

In the wallet worktree, query that live node and acknowledge it:

```sh
npm run smoke:dregg-membership -- /tmp/castalia-wallet-live-snapshot-current.json
```

The smoke command succeeds only after the adapter verifies Active generation 1 and a persistent receipt head. The node test then continues through shutdown, same-directory restart, suspend, resume, and revoke.

## Build and load

```sh
npm run build --workspace @castalia-wallet/chrome-extension
npm run validate:extension-package
```

Load `apps/chrome-extension` as an unpacked extension for local acceptance. Its
manifest permits loopback node access only, and the adapter falls back to
`http://127.0.0.1:8420` when it is compiled outside the extension bundler.

After the production HTTPS endpoint exists, create a separate pinned package:

```sh
npm run package:production-extension -- https://NODE_HOSTNAME
```

The package is written to `build/castalia-wallet-production`. Its service
worker embeds that exact HTTPS origin and its manifest grants only
`https://NODE_HOSTNAME/*`; localhost is absent. Load that output directory as
the production unpacked extension. Because unpacked extension identity is
path-bound, export the encrypted recovery file from the local package and
import it into the production package when the same Member Key must be kept.
