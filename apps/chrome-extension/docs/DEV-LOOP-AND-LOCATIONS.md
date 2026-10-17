# Castalia Wallet Extension — File Locations & Development Loop

## Where the code actually runs on your machine

### Source (what you and the agent edit)
`/example/operator/repos/castalia-wallet/apps/chrome-extension/src/`

Key files:
- `popup.ts` + `popup.html`          → The UI you are looking at right now
- `service-worker.ts`                → Background logic, session state, crypto, provider handling
- `content-script.ts`                → Bridge between web pages and the service worker
- `state/session-state.ts`           → The per-session fresh-key + approval model
- `crypto-browser.ts`                → Web Crypto implementation (replaces node:crypto for the browser)

### Built output (what Chrome loads)
`/example/operator/repos/castalia-wallet/apps/chrome-extension/dist/`

This is the only thing Chrome cares about after you load the extension unpacked.

The bundler (`scripts/bundle-castalia-extension.mjs`) takes your TypeScript in `src/` and produces clean, self-contained ESM files in `dist/` with no bare specifiers.

### Manifest (the contract with Chrome)
`/example/operator/repos/castalia-wallet/apps/chrome-extension/manifest.json`

This tells Chrome:
- Use `dist/service-worker.js` as the MV3 background
- Inject `dist/content-script.js` into every page
- Show `src/popup.html` when the user clicks the icon
- Make `dist/provider.js` available to web pages

## The Development Loop (the "AI programming phone" loop)

1. **Edit** source files in `src/` (you or the agent via tools)
2. **Build**:
   ```bash
   cd /example/operator/repos/castalia-wallet
   node scripts/bundle-castalia-extension.mjs
   ```
3. **Reload in Chrome**:
   - Go to `chrome://extensions/`
   - Find "Castalia Wallet"
   - Click the circular reload icon
4. **Test**:
   - Click the extension icon (opens this popup)
   - Open the test harness (`test-harness/index.html`)
   - Use DevTools on the service worker for logs
5. **Repeat**

The agent (me) can do steps 1 and 2 for you using tools. You only need to do step 3 (reload) and step 4 (test/observe).

## Architecture in one picture (for this Checkpoint A demo)

- **Popup** (this window) ← talks to Service Worker via chrome.runtime.sendMessage
- **Service Worker** (isolated background process) ← holds the real state + does signing
- **Content Script** (injected into every web page) ← forwards messages between pages and the SW
- **Provider** (injected into pages via web_accessible_resources) ← what a website calls (`isAvailable`, `signChallenge`, etc.)

All per-session rules (fresh key on Setup, approvals reset on reload) live in `state/session-state.ts` and are enforced in the service worker.

This is why reloading the extension in chrome://extensions/ instantly resets everything you see in the popup.
