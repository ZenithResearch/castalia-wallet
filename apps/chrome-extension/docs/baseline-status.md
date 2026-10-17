# Castalia Wallet Chrome Extension - Baseline Status (2026-05-29)

## Current Verified State (Waves 1-3 Progress)

- **Build & Typecheck**: ✅ Passing (core + extension after all wave fixes)
- **Existing Tests**: ✅ All 17 tests passing (core contract + validation)
- **Service Worker Foundation + Lifecycle**: Solid (per-session reset onInstalled/onStartup wired)
- **Popup ↔ SW Messaging**: ✅ Implemented (Wave 3)
- **Popup UI**: Basic interactive status + action buttons (demo quality)
- **Session State Model**: ✅ Implemented + reviewed (Wave 2)

## Wave 2 Review (T0.2 + T1.2) — Completed & Verified 2026-05-29

(See previous version for full details — summary: state model solid after import/key/chrome fixes; typecheck green; ready for integration.)

## Wave 3 Execution (T0.4 + T1.3 + T1.4) — In Progress / Core Delivered

**T0.4 baseline/docs**: Already strong (this file + LOADING.md + capture plans). Minor updates applied during review.

**T1.3 + T1.4: Bidirectional popup messaging + state consumption**

- Added full typed PopupMessage protocol and chrome.runtime.onMessage listener in `service-worker.ts`.
- Actions fully wired: GET_STATE, SETUP (fresh key), UNLOCK, LOCK, APPROVE/REVOKE origin → all delegate to `sessionState` and return fresh snapshot.
- Lifecycle: `onInstalled` + `onStartup` now call `sessionState.clearForReload()` — enforces the "reset on every reload" invariant.
- Adapter helper `getCurrentExtensionStateForProvider()` prepared for future provider path migration (uses in-memory keyPair).
- Popup (`popup.ts` + `popup.html`):
  - On load: queries state, renders live status (setup/unlocked/approved list/pubkey/subject).
  - Buttons for all actions (Setup always fresh; approve uses demo origin for now; revoke last).
  - Reactive: after every action, re-fetches and re-renders.
  - Explicit note about per-session reset.
- Typecheck + build: green.
- This makes the extension **loadable and interactive** for manual Checkpoint A demo (R19).

**Remaining for full Wave 3 / Phase 1 exit**:
- Real origin detection in popup (chrome.tabs.query for active tab).
- Full provider request listener in SW (bridge from content-script messages to handleProviderRequest using the adapter).
- Test page harness (Phase 4).
- Polish error states + docs.
- Manual loaded-Chrome verification + update of Checkpoint A acceptance review.

**Status**: Wave 3 core (messaging + popup reactivity + lifecycle reset) complete and verified. Extension is now meaningfully runnable for the possession proof demo. Ready for remaining Phase 1 items and full manual test.

## Next (Phase 2+ / remaining waves)

- Wire the actual provider message path (content-script → SW → handleProviderRequest using session adapter).
- Create minimal test-harness page inside the repo.
- Update capture/2026-05-28-castalia-wallet-checkpoint-a-multi-repo-scope.md and implementation-plan with evidence.
- User performs the loaded unpacked manual demo (Setup → approve origin → signChallenge from test page) and decides on Checkpoint A green.

## Related Documents
- Full Option B plan: `capture/2026-05-29-castalia-wallet-runnable-demo-plan.md`
- DAG plan: `.hermes/plans/2026-05-29_203500-phase-0-1-dag-subagent-coordination.md`
- LOADING.md
- Parent spec: capture/2026-05-28-castalia-wallet-checkpoint-a-multi-repo-scope.md

**Status as of 2026-05-29 (Wave 3 messaging delivered)**: Strong, runnable foundation. Per-session safety invariants enforced in both lifecycle and UI. Proceeding to provider wiring + harness for final Checkpoint A evidence.
### Wave 3/4 Continuation (2026-05-29) — Provider Runtime Bridge

**Completed:**
- Full content-script ↔ service-worker provider request bridge wired.
- `content-script.ts` now listens for page `postMessage`, normalizes, forwards via `chrome.runtime.sendMessage` to SW, and relays responses back.
- `service-worker.ts` now has dedicated listener for `CASTALIA_PROVIDER_REQUEST` messages from content script, uses the session-state adapter (`getCurrentExtensionStateForProvider()`), calls the existing `handleProviderRequest`, and responds.
- Export added in `provider.ts` for `CASTALIA_WALLET_RESPONSE`.
- Typecheck + build: green.

This completes the runtime plumbing needed for a webpage (or test harness) to actually call `isAvailable`, `getSubject`, and `signChallenge` through the Castalia provider.

The extension is now in a state where a simple test page can exercise the full possession flow (with the interactive popup handling setup/approval).

Next: Create minimal test-harness page + manual demo run.

### Phase 4: Test Harness Page (Completed 2026-05-29)

Created `test-harness/index.html` — a self-contained, minimal test page that:
- Dynamically exercises the full Castalia provider via the new content-script bridge.
- Provides buttons for `isAvailable()`, `getSubject()`, and `signChallenge()` (with editable JSON payload).
- Shows clear success/error results with timestamps.
- Includes step-by-step instructions for the manual demo flow (Setup → Approve origin → Call methods).

This completes the "Test Harness Page" deliverable from the Option B runnable demo plan.

The harness is designed to be opened in a normal tab while the extension is loaded unpacked. Combined with the interactive popup and full provider plumbing, this enables the loaded-Chrome manual demonstration required for R19 / Checkpoint A closure.

## Architecture Evolution Note (2026-05-29)

During the Wave 3 provider bridge implementation, the question of using Rust compiled to WebAssembly for the service worker (or at minimum the crypto core) was raised.

A full feasibility analysis, recommended hybrid architecture (thin JS service worker + Rust Wasm for keygen/signing + session invariants), tradeoffs, and integration path have been captured in the vault:

- [[../../../capture/2026-05-29-castalia-wallet-rust-wasm-feasibility-hybrid-architecture|2026-05-29-castalia-wallet-rust-wasm-feasibility-hybrid-architecture]] (canonical)

**Positioning**: This is recorded as a high-value post-Checkpoint A evolution item (after the current runnable demo and R19 manual verification succeed). The pure JS + Web Crypto path remains the implementation for the immediate Checkpoint A gate.

No changes to the current Wave 2/3 plan or build process are required.
