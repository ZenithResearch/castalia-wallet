# Loading the Castalia Wallet Chrome Extension (Unpacked)

This document describes the local acceptance package and the separately pinned
production package.

## Prerequisites

- Chrome (or Chromium-based browser) with Developer mode enabled.
- The Wallet monorepo must have dependencies installed (`npm install` at root).
- The core package must build (it is a workspace dependency).

## Local acceptance package

1. Open Chrome and go to `chrome://extensions/`.
2. Enable "Developer mode" (top right toggle).
3. Click "Load unpacked".
4. Select the `apps/chrome-extension` folder inside the Wallet worktree.
5. The extension "Castalia Wallet" should appear in the list.

## Verification After Loading

- The extension icon should appear in the toolbar (or in the puzzle piece menu).
- Clicking the icon should open the Castalia side panel.
- A new extension profile should offer **Create wallet**. After setup, the panel
  should show **Wallet ready** (or **Wallet locked** after locking) and the
  wallet's public identity.
- With Castalia Web focused, **Connect this site** should approve only that
  origin. The page can then open the wallet-owned Zenith membership
  flow; it never receives the private key or passphrase.
- Open DevTools on a page (F12) → Application → Service Workers to inspect the background service worker.
- Check the console for any errors on load.

## Production package

After the Zenith issuer HTTPS endpoint and production public key are live, run:

```sh
npm run package:production-extension -- \
  https://ISSUER_HOSTNAME \
  ISSUER_KEY_ID \
  32_BYTE_ISSUER_PUBLIC_KEY_HEX
```

Load this stable directory instead of the source directory:

```text
build/castalia-wallet-production
```

The production service worker is compiled with the exact issuer origin, issuer
key ID, and Ed25519 public key. The generated manifest grants only that HTTPS
origin. Production packaging rejects the checked-in test fixture key and does
not retain localhost host permissions.

An unpacked extension loaded from a different directory may receive a different
Chrome extension ID and therefore separate storage. To retain the same durable
Member Key, export the encrypted recovery file from the local extension and
import it into the production extension before joining the production ledger.

## Production owner acceptance

Use a clean Chrome profile and the stable production package directory above:

1. Create the wallet and Member Key with a passphrase.
2. Export the encrypted `.castalia-recovery` file and keep it off-machine.
3. Open `https://castalia.zenith-research.ca/start`, connect that site, and
   complete the wallet-owned membership flow.
4. Require Castalia Web to show **Membership active** only after the wallet has
   independently verified the exact Zenith-signed v3 credential.
5. Reload, lock, unlock, and retry issuance. The identity, membership ID, and
   credential must remain unchanged; retry creates no duplicate or session.
6. Clear the extension state, import the recovery file, and rejoin. The same
   Member Key must reacquire the same deterministic membership.

Do not confuse this recovery export with the planned `.castaway` portable
vault. If an older Wallet produced `Castaway-<timestamp>.castaway`, preserve the
original and follow the legacy custody migration in
`../../docs/castaway-portable-vault.md`; that file contains recovery authority,
not a general vault.

Do not treat localhost or fixture-signed membership as production membership.
The production extension must pin only the deployed HTTPS issuer and its
reviewed non-fixture public key.

## Troubleshooting

- If the extension fails to load: Check that `dist/` exists and was built from the root monorepo (`npm run build --workspace @castalia-wallet/chrome-extension`).
- Type errors or missing modules: Run `npm run typecheck --workspace @castalia-wallet/chrome-extension` from the monorepo root.
- Content script not injecting: Ensure the page matches `<all_urls>` and reload the tab after loading the extension.

## Related

- Active membership contract: `../../docs/castalia-member-key-and-membership-cell.md`
- Dormant Dregg compatibility: `../../docs/dregg-membership-integration.md`
- Portable encrypted vault design: `../../docs/castaway-portable-vault.md`

Last updated: 2026-08-31
