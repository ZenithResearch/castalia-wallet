# Checkpoint A demo

This demo proves the Checkpoint A contract without claiming production Dregg capability possession, production ZK proofs, or high-value custody.

## Preconditions

- Castalia Wallet repo: `/example/operator/repos/castalia-wallet`
- Dregg fork: `/example/operator/repos/dregg`
- Review SDK wallet worktree: `/example/operator/repos/zenith-review-sdk-castalia-wallet`
- Node 20+

## Automated proof path

### 1. Castalia Wallet tests and validation

```bash
cd /example/operator/repos/castalia-wallet
npm test
npm run typecheck
npm run build
npm run validate:extension-package
npm run validate:extension-manifest
```

Expected:

- core challenge tests pass;
- disposable/dev key signing tests pass;
- public-key-as-signature regression test passes;
- extension bridge validation tests pass;
- provider/content-script message contract tests pass;
- service-worker request handler returns a verifiable `SignaturePresentation`;
- package/source validation passes;
- manifest/API permission drift validation passes;
- typecheck and build pass.

### 2. Review/Auth SDK wallet seam tests

```bash
cd /example/operator/repos/zenith-review-sdk-castalia-wallet
npm test
npm run typecheck
npm run build
```

Expected:

- `createWalletAuthChallenge()` binds nonce, origin, audience, operation, issue time, and expiry;
- `authenticateWithCastaliaWallet()` calls a mock Castalia provider's `signChallenge()` explicitly;
- `verifyWalletPresentation()` checks challenge-field equality and delegates signature verification;
- unavailable provider fails closed.

## Loaded browser demo

The extension has now been loaded in Playwright-managed Chromium against the local current-main `bananawalnut/castalia-web` development server. The proven runtime path is:

1. Build the extension with `npm run build`.
2. Load Castalia Wallet extension locally from `apps/chrome-extension` in Chrome extension developer mode.
3. Open the current Castalia Web main fixture and its Rust/WASM wallet-onboarding seam.
4. Test page calls provider availability.
5. Test page creates a wallet auth challenge with nonce, origin, audience, timestamp/expiry, operation, and domain/version.
6. Extension computes the true page origin, validates method/payload, checks setup/unlock/approval state, and prompts or uses the approved dev origin state.
7. The isolated test profile approves the exact loopback origin.
8. Extension signs the onboarding challenge with its disposable/dev key.
9. A strict-PQ local Dregg node issues membership to that wallet's raw Ed25519 owner key.
10. The page retrieves Active membership generation 1 and signs a second possession challenge.
11. SDK verifies signature against public key and exact challenge fields.
12. Negative cases fail closed:
   - locked wallet;
   - setup incomplete;
   - unapproved origin;
   - malformed method;
   - unsupported proof/private request;
   - page-supplied origin spoof;
   - tampered challenge.

## Non-claims

- This does not prove production Dregg subject/capability possession.
- This does not prove production ZK proof generation.
- This does not approve high-value Chrome custody.
- This does not launch Gallery/Moons federation.
