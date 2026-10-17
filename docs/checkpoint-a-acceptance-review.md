# Checkpoint A acceptance review

Review date: 2026-05-28.

## Verdict

`green for automated Checkpoint A proof` — the repo and integration boundaries are clean, tests pass, executable security gates exist, and the extension provider path now has a testable provider → content-script message contract plus service-worker request handler that produces a verifiable `SignaturePresentation`.

Remaining caveat: this is automated/source-level proof, not a manually loaded Chrome-profile demo. The next packaging/browser pass should load the extension in Chrome and exercise the same path through real `window.postMessage` / `chrome.runtime` plumbing.

## Verification commands run

### Castalia Wallet

```bash
cd /example/operator/repos/castalia-wallet
npm test
npm run typecheck
npm run build
npm run validate:extension-package
npm run validate:extension-manifest
git status --short
```

Result:

- `npm test`: pass.
- `npm run typecheck`: pass.
- `npm run build`: pass.
- `npm run validate:extension-package`: pass.
- `npm run validate:extension-manifest`: pass.
- `git status --short`: clean after committing this checkpoint.

### Dregg fork

```bash
git -C /example/operator/repos/dregg status --short
```

Result:

- clean.

### Review SDK wallet worktree

```bash
cd /example/operator/repos/zenith-review-sdk-castalia-wallet
npm test
npm run typecheck
npm run build
git status --short
```

Result:

- `npm test`: pass.
- `npm run typecheck`: pass.
- `npm run build`: pass.
- `git status --short`: clean.

## Acceptance criteria review

| Criterion | Status | Evidence / blocker |
|---|---|---|
| Castalia Wallet Chrome extension can prove wallet possession through a challenge signed after user approval. | automated green / manual browser pending | `apps/chrome-extension/test/service-worker.test.ts` proves validated sign requests produce verifiable `SignaturePresentation` responses using the disposable/dev key; `apps/chrome-extension/test/provider-message-contract.test.ts` proves provider and content-script message contracts. Manual loaded-extension approval UX remains the next browser pass. |
| Web SDK path can request and verify possession proof without depending on extension internals. | green | `/example/operator/repos/zenith-review-sdk-castalia-wallet` commit `5657dc5` adds `createWalletAuthChallenge`, `authenticateWithCastaliaWallet`, and `verifyWalletPresentation`; tests pass. |
| Possession flow fails closed for locked/setup incomplete/unapproved origin/unknown method/unsupported proof/private/page-origin spoofing. | green | `apps/chrome-extension/test/bridge.test.ts` and `apps/chrome-extension/test/service-worker.test.ts`. |
| Dregg/Cipherclerk A2 bugs are fixed upstream, PR-prepared, or bypassed with documented local equivalents. | partial | D1 inventory and local bypass requirements are documented in `docs/upstream-dregg-contributions.md`; no upstream PR branches created yet. Castalia local code currently avoids Dregg broken paths. |
| No known A-relevant Dregg/Cipherclerk security concern remains untracked. | green | All known A2 gates are tracked in `docs/upstream-dregg-contributions.md` and `docs/security-gate-status.md`. |
| Repo states are clean or intentionally dirty with named branches/commits/stashes. | green | `castalia-wallet`, `dregg`, and isolated Review SDK worktree are clean. Original Review SDK dirty worktree is documented as pre-existing and untouched. |
| No secrets, raw keys, local browser state, or generated extension bundles are committed. | green | No generated extension bundles/profile state committed; keys are generated in tests only. |
| Storage posture is documented as disposable/dev-first, not production custody. | green | `docs/security-model.md`; README; key tests. |
| secS-magik docs name Zenith as initial surface and treat Moons/Gallery federation as future design question. | green | `docs/secs-magik-layer.md`. |

## Security gate status

See `docs/security-gate-status.md`.

Current status is `green for automated/source-level Checkpoint A proof` with one explicit caveat: loaded-Chrome manual demo remains a browser-packaging follow-up, not an automated gate.

Green proof commands:

1. `npm test`
2. `npm run typecheck`
3. `npm run build`
4. `npm run validate:extension-package`
5. `npm run validate:extension-manifest`

## Non-blocking notes

- The clean-start inventory to-do is complete: all three repos/surfaces are inventoried and boundary-protected.
- The SDK seam is complete in an isolated worktree and can be integrated later without touching the dirty review-audio-fallback worktree.
- Dregg remains read-only/clean; no upstream fix branches have been created yet.
