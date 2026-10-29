# Generic browser graph access

The public Chrome extension exposes the shared Rust core's application-neutral
access-request and read-connection contracts. Applications discover
`access_request_v1`, `graph_access_v2` and `read_access_v1` with `getCapabilities()`
and call `readAccess()`. Generic mutation signing remains `presentCredential()`;
retired application-specific signers and native messaging remain absent.

Connection, provider trust, access-request consent and read consent are separate
Wallet-owned decisions. A fresh package trusts no issuer. The observed top-level
Chrome document supplies the caller; pages cannot supply an authoritative origin.
Identity requires an unlocked Wallet and approved origin. New request and read
consent require a fresh user gesture. Accepting a read credential independently
checks its issuer signature and exact holder, installation, audience, receiver,
permissions and validity before any read proof is available.

`approve_graph_v2` allows a request without community membership when no profile
was selected. The receiver still determines eligibility and enforces the grant.
The legacy `approve` path keeps its membership check. Handles cannot cross those
paths, documents, tabs, custody epochs or origins. Reloading or leaving the
document, changing its path or query, lock, custody or trust changes invalidate
them. Fragment-only navigation within the same Chrome document keeps the current
connection and its original absolute expiry; it cannot renew access. Credentials
and handles are memory-only; signing
keys remain inside encrypted Wallet custody. Request consent never grants access.

Starting with Chrome extension 0.0.2, `read_setup_status_v1` lets a connected site
check whether its exact provider profile is still approved. Returning users can
reuse that setup without repeating server review. Locked or unconnected Wallets
reveal no installed trust. First connections, changed profiles and revoked trust
still require Wallet review; read consent and server grant checks remain separate.
Older extensions keep their existing setup flow. See
[the setup-status contract](shared-read-authority.md#returning-browser-setup).

This additive bridge preserves existing request, credential and signing bytes.
It does **not** migrate legacy receiver/origin-bound credentials into canonical
service credentials or unify receiver stores. A future service-identity contract
must version that migration and retain independent transport admission checks.

## Building and qualification

Use the organization repository, `https://github.com/ZenithResearch/castalia-wallet`.
Run `npm ci`, `npm test`, `npm run typecheck`, `npm run package:production-extension`
and `npm run inspect:production-extension`. Do not copy a personal checkout's
`dist/` or an installed browser profile into the public package.

The package allowlist includes the read-consent HTML and bundle. In Chrome,
update the existing extension directory and Reload it to preserve its installation
and encrypted Wallet. Refresh the application tab afterward. A replacement
installation has a new installation identity and may need its own access request.

`scripts/smoke-extension-graph-access.mts` loads the exact package into disposable
Chrome and uses DevGraph's actual read client against a synthetic service. Set
`CASTALIA_EXTENSION_DIRECTORY` and `DEVGRAPH_SOURCE_DIRECTORY`; optionally set
`CASTALIA_CHROMIUM_EXECUTABLE` and `CASTALIA_HEADLESS=1`. It exercises provider
approval, connection, no-grant denial, exact access-request signing, verified read
credential acceptance, a signed scoped read, reload without repeated setup consent
and denial after lock. The unchanged
package digest is checked before and after. This is integration evidence, not a
real user's consent, live grant or production-custody qualification.

The fixed public custody fixture driver supports DevGraph's independent receiver
tests through `CASTALIA_ACCESS_REQUEST_FIXTURE_DRIVER`. It cannot load user custody
and is never shipped inside the extension package.
