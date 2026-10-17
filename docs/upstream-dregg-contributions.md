# Upstream Dregg contributions

Dregg/Cipherclerk fixes are part of Checkpoint A if they affect safe wallet possession. This file tracks whether each issue is resolved upstream, locally bypassed in Castalia Wallet, both, or not applicable.

## D1 source inventory summary

Inventory date: 2026-05-28.

Dregg repo:

- Path: `/example/operator/repos/dregg`
- Branch: `main`
- Original D1 HEAD: `6425a0b0ff0f817f3470761192448d0e301d06f8`
- Synced HEAD after PR-train refresh: `04755129b4ade0d69999809319e5b430a556695b`
- Origin: `git@github.com:bananawalnut/dregg.git`
- Upstream: `git@github.com:emberian/dregg.git`
- Upstream `main`: `04755129b4ade0d69999809319e5b430a556695b`
- Working tree after D1 and sync refresh: clean

Dregg extension source surfaces:

- `/example/operator/repos/dregg/extension/manifest.json`
- `/example/operator/repos/dregg/extension/package.json`
- `/example/operator/repos/dregg/extension/build.mjs`
- `/example/operator/repos/dregg/extension/src/background.ts`
- `/example/operator/repos/dregg/extension/src/content.ts`
- `/example/operator/repos/dregg/extension/src/page.ts`
- `/example/operator/repos/dregg/extension/src/types.ts`
- `/example/operator/repos/dregg/extension/tests/e2e/*.spec.ts`

Downloaded Cipherclerk artifact surfaces:

- `/example/operator/Downloads/dregg-cipherclerk/manifest.json`
- `/example/operator/Downloads/dregg-cipherclerk/dist/background.js`
- `/example/operator/Downloads/dregg-cipherclerk/dist/content.js`
- `/example/operator/Downloads/dregg-cipherclerk/dist/page.js`
- `/example/operator/Downloads/dregg-cipherclerk/dist/popup-script.js`
- `/example/operator/Downloads/dregg-cipherclerk/dregg_wasm.js`
- `/example/operator/Downloads/dregg-cipherclerk/dregg_wasm_bg.wasm`

## A2 gate table

| Gate | Source evidence | Gates A? | Resolution path | Branch/PR | Status | Castalia workaround remains? |
|---|---|---:|---|---|---|---|
| Package/source drift validation | Source has `extension/package.json`, `build.mjs`, `src/*`; artifact has `dist/*` and no package metadata/source/provenance; source and artifact `popup.html` differ. Upstream sync `6425a0b0..04755129` did not touch this PR's files. | yes | both: Castalia package validation plus upstream PR candidate | `fix/extension-package-validation` / upstream issue [#7](https://github.com/emberian/dregg/issues/7) / upstream PR [#10](https://github.com/emberian/dregg/pull/10) | PR branch rebased onto `04755129` and force-pushed at `df1c17f6`; `npm run validate:extension-package`, `npm run typecheck`, and `npm run build` passed locally after rebase; GitHub Check passed, Format/Clippy/Security Audit/No-Unchecked-Auth failed in broader repo checks, and OS test jobs were still running when recorded | Castalia local validation remains until upstream PR lands/merges. |
| Manifest/API permission drift | Source/artifact manifests used `chrome.alarms` without `alarms` permission; broad `<all_urls>` content/web-accessible exposure remains for later review. Upstream sync did not touch `extension/manifest*.json`. | yes | both: Castalia manifest validation plus upstream PR candidate | `fix/mv3-permissions` / upstream issue [#8](https://github.com/emberian/dregg/issues/8) | stacked local branch committed at `e19dc629`; hold upstream PR until PR [#10](https://github.com/emberian/dregg/pull/10) lands or the branch is unstacked/rebased for a clean diff | Castalia local validation remains until upstream PR lands/merges. |
| Page bridge correctness | `extension/src/content.ts` now validates nonce-scoped request envelopes without `CustomEvent.isTrusted`, preserves content-script-computed `_origin`, and validator checks page/content method parity. Upstream sync changed `extension/src/background.ts`, `page.ts`, and `types.ts`, but not `content.ts`. | yes | local safe bridge in Castalia plus upstream PR candidate | `fix/page-bridge-origin-validation` / upstream issue [#9](https://github.com/emberian/dregg/issues/9) | stacked local branch committed at `fa53123a`; hold upstream PR until PR [#10](https://github.com/emberian/dregg/pull/10) and the MV3 permission branch land or the branch is unstacked/rebased for a clean diff; re-check against the changed upstream page/types/background surfaces before opening | Castalia local bridge remains the Checkpoint A path until upstream PR lands/merges. |
| Signing integrity | `signTurn` requires secret key then fails closed for v3; `signTurnV3` fails closed; `createBearerCap` appears to pass `cc.publicKey` as `delegatorKeyHex` and lacks setup/secret-key checks. | yes | local regression tests plus upstream PR candidate | `fix/signing-integrity-regression` | local green / upstream not started | Castalia local signing tests remain until upstream PR lands. |
| Demo/proof labeling | `background.ts` uses `generate_demo_stark_proof`; WASM wrapper labels demo functions, but page/API result boundary does not clearly fail closed or label proof as demo. | yes | local fail-closed proof/private paths plus upstream PR candidate | `fix/demo-proof-labeling` | local green / upstream not started | Castalia fails proof/private paths closed for Checkpoint A. |
| Origin approval gate | Restricted methods require per-origin allowlist and popup nonce approval; wildcard migration exists. Privacy reads remain unrestricted. | yes | local Castalia origin approval gate; upstream method-sensitivity review | `fix/page-bridge-origin-validation` | local green / upstream not started | Castalia local origin approval remains the Checkpoint A path. |
| Locked/setup state gate | Many operations check locked/setup; `createBearerCap` lacks setup/secret-key checks; `authorize` lacks setup check before demo proof; read paths are open. | yes | local Castalia locked/setup gate for all sensitive operations; upstream targeted fixes | `fix/signing-integrity-regression` | local green / upstream not started | Castalia local setup/lock gate remains the Checkpoint A path. |
| Privacy-read gate | `discoverServices`, `resolvePath`, `storageQuota`, `federationStatus`, `listKnownFederations` are unrestricted in `content.ts`. | yes | local Castalia privacy-read denial before origin approval plus upstream PR candidate | `fix/privacy-read-gating` | local green / upstream not started | Castalia local denial/gating remains until upstream PR lands. |

## Checkpoint A implication

Current Dregg/Cipherclerk is useful source material and upstream-fix material, not a safe provider baseline for Castalia Wallet. Castalia does not reuse the current page bridge, proof path, privacy-read exposure, or suspicious bearer-cap signing path for Checkpoint A; local fail-closed wrappers/tests are now the active safe replacement.

Dregg upstream contribution branches now exist locally for package/source validation, MV3 permission drift, and page bridge correctness. The fork/local `main` has been synced from `6425a0b0` to upstream `04755129` (14 upstream commits). Upstream PR [#10](https://github.com/emberian/dregg/pull/10) is open for `fix/extension-package-validation` and was rebased onto the synced base at `df1c17f6`; the MV3 and page-bridge branches remain intentionally held because they are stacked on the validation-script PR and should either be opened after #10 lands or be unstacked/rebased before PR submission.

Sync diff notes: the 14 upstream commits reset root docs/status, remove remaining JS/fabricated playground/studio paths, extend protocol-coverage gates, update explorer/playground/runtime surfaces, and change `extension/src/background.ts`, `extension/src/page.ts`, and `extension/src/types.ts`. They did not touch PR #10 files, `extension/manifest*.json`, or `extension/src/content.ts`; the page-bridge branch still needs an explicit re-check against the changed upstream page/types/background surfaces before PR #9 is opened.

## Candidate upstream branches

- `fix/extension-package-validation`: upstream issue [#7](https://github.com/emberian/dregg/issues/7), upstream PR [#10](https://github.com/emberian/dregg/pull/10), rebased/force-pushed at `df1c17f6`; adds `extension/scripts/validate-extension-package.mjs` and `npm run validate:extension-package` for package/source drift checks. Local validation, typecheck, and build passed after rebase; GitHub Check passed, Format/Clippy/Security Audit/No-Unchecked-Auth failed in broader repo checks, and OS test jobs were still running when recorded.
- `fix/mv3-permissions`: upstream issue [#8](https://github.com/emberian/dregg/issues/8), committed locally at `e19dc629`; extends validation to classify `chrome.<api>` usage, reject missing required permissions, and add `alarms` to Chrome/Firefox manifests. Stacked on #10; open after #10 lands or after creating a clean unstacked diff.
- `fix/page-bridge-origin-validation`: upstream issue [#9](https://github.com/emberian/dregg/issues/9), committed locally at `fa53123a`; removes the `event.isTrusted` bridge gate, validates page request envelopes, preserves content-script-computed origin, and adds validator coverage for page/content method drift. Stacked on the prior two branches; open after the dependency PRs land or after creating a clean unstacked diff.
- `fix/signing-integrity-regression`: prove public key bytes cannot produce valid bearer/signature output and require setup/secret key where appropriate.
- `fix/demo-proof-labeling`: prevent demo proof bytes from being exposed as production proof/capability results.
- `fix/privacy-read-gating`: gate service/federation/quota/path reads behind approved origin or explicit non-sensitive classification.
