# Runtime provider profiles

Shared contract: bananawalnut/castalia-wallet-auth@066ce4ed0cc4e7e698dc41dda62e731f83aa6c87 (PR #3). `packages/provider-types/src/provider-profiles.ts` and `provider-profile-store.ts` retain those sources, changing only the generic-presentation import path. Existing license and contribution evidence remains separate from technical checks.

Fresh installs have no trusted profiles. Open **Providers and memberships** in Wallet, import a bounded profile or review a site's proposal, inspect its keys and origins, and choose membership trust and/or request-credential trust independently. A site's proposal is limited to its own origin. Exact issuer host permission is requested from Chrome only after the user's membership choice. Redirects and cookies are prohibited during enrollment. Removal of permission or trust invalidates pending ceremonies.

Connect, approve a provider, and join are separate ceremonies. Wallet stores public membership proofs under profile + holder + credential digest. V3 membership IDs intentionally do not distinguish issuers. Removing trust retains the proof while blocking use; replacing custody clears identity-bound proofs and per-origin selections. Existing legacy storage and signed bytes remain untouched. An older API works only after the user explicitly chooses a compatibility profile for that origin.

Generic operation credentials remain transient. Trust profiles do not grant receiver authority or install executable adapters. Registered namespaces, application policy, live revocation and resource state are independently checked by receivers. Unsupported peers fail explicitly. Headless approval and its independently configured issuer pins retain their existing interactive-only contract; no global Zenith requirement is introduced.

Trust is not recovered from the signing seed or `.castaway`; restore custody and approve desired provider profiles afresh. No recovery format, signing domain, public Member Key or historical ontology URI changes. Zenith is an ordinary optional issuer. Names, wallet branding, membership and payment do not grant operational privileges.

Buildkite verifies the portable candidate. Loaded Chrome, native permission UI, installed runtime and production qualification are reported separately. No deployment or release is implied.
