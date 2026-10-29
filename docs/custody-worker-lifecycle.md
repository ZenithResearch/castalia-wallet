# Chrome custody and panel lifecycle

The encrypted Wallet record persists in extension storage. Its decrypted root
lives only in the extension service worker. Browser termination of that worker
therefore requires an explicit unlock; it must not restore decrypted authority
from storage or a page. This does not change an already issued finite browser
read session or its original expiry.

The side panel and popup observe public custody status through the passive
`castalia-custody-panel-v1` port. Only exact extension-owned top-level
`src/sidepanel.html` and `src/popup.html` callers may subscribe. The worker projects
setup/lock state, the public Member Key and public account descriptors; no root,
password, encrypted record, command, grant or approval is accepted by this channel.

The worker sends a snapshot on connection and after a custody change. Revision
fences reject stale asynchronous snapshots. Worker disconnection immediately
removes the panel's Ready assertion and protected controls. A visible/focused
panel or an explicit **Check Wallet** action reads fresh state; disconnect itself
never retries. There are no periodic messages, timers, alarms or hidden keepalive.
This follows the [Chrome worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle): opening a port alone does not reset idle timers.

Existing explicit lock/reload behavior, provider consent, encrypted recovery,
identity, membership and saved-grant formats remain unchanged. Unlocking does not
approve an origin, issue a grant, renew a child session or sign an operation.
The user must still approve the separate exact Wallet request.

`custody-panel-state.test.ts` exercises caller restrictions, public projection,
state ordering, disconnect, stale-worker messages and malformed snapshots.
The disposable packaged-browser regression is:

```sh
CASTALIA_EXTENSION_DIRECTORY=/absolute/reviewed/package \
CASTALIA_HEADLESS=1 npm run smoke:extension-custody-lifecycle
```

It creates a synthetic Wallet in a fresh temporary browser profile, tests two
panels, stops only that test worker, then verifies explicit check and unlock of
the same identity. It never uses a personal browser profile. The existing
`smoke:extension-holder-session` qualification separately checks that root lock
cannot extend or renew finite child authority, and that replay, revocation and
original-result recovery retain their boundaries.
