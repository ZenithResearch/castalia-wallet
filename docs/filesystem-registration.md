# Files registration provider boundary

`requestRegistrationV2({ manifest, consent })`, advertised as `registration_proposal_v2`, signs the unchanged typed filesystem manifest with fresh Wallet consent. It does not inspect membership eligibility. The receiving service independently verifies trusted base-v3 membership for genesis and current controller/revision authority for updates. V4 community membership does not establish eligibility.

The old v1 API remains an explicit compatibility path: it resolves the requesting origin's selected profile and still verifies that profile's base credential. No profile is selected automatically; consumers never silently downgrade. Existing signing bytes, recovery, namespace schemas and Files key operations are unchanged.

The registration Chrome smoke runs actual WASM with zero trusted profiles, explicit consent, independent signature verification, denial, replay and navigation cancellation. It does not register anything remotely. The shared contract stays pinned to a public immutable candidate; source rights and final release pins remain separate gates.

## Historical notice and qualification record (unchanged scope)

The following record covers its stated older revisions. It does not assign their acceptance or permission conclusions to this candidate.

The previous shared candidate was reviewed in `ZenithResearch/castalia-filesystem#3`. Its complete 60-file package reproduces across two local clean builds and both hosted builds with manifest SHA-256 `d5df1106b054f7e8458403ba2d39f765910d6463ec2978e27c0303cfb242db29`; that artifact reproducibility gate is closed. Wallet imports only the registration ESM contract from the immutable source archive. The remaining distribution/license and final merged-pin gates are unchanged.


## AGPL notices and the registration distribution boundary (2026-10-03)

The production and developer-preview extension packages include the filesystem
AGPL text, a source notice, and unchanged editable copies of the four registration
runtime modules plus their declaration. The popup links to the notice. The
notice binds the library to the same immutable source archive as the dependency;
that archive includes the complete library, tests, provenance, and build scripts.
Package inspection rejects missing or modified notices even if a new content-tree
digest was generated. This verifies shipped evidence, not legal ownership.

The registration entry imports `address.mjs`, `registration-crypto.mjs`, and
`registration-membership.mjs`. This module graph does not import the browser
storage adapter, ZIP implementation, or filesystem WASM. Acquiring the complete
Git archive does not mean those other modules are bundled in the extension.
The Wallet verifier/fixture origin referenced by the library still lacks a
covering grant in the scoped evidence. No new grant has been supplied.

AGPL sections 1 and 4–6 require preserving applicable notices and providing the
covered work's corresponding source for distribution; section 13 separately
addresses qualifying remote interaction with a modified program. Source
availability must cover the actual combined work where applicable, not merely a
library boundary selected by packaging. The private Wallet application's broader
license and combined-work boundary remain unresolved distribution questions.
Shipping these library notices does not license unrelated Wallet code or settle
those questions. There is no mandatory counsel approval gate; seek targeted
advice if contribution or distribution facts cannot resolve them.

Reference: <https://www.gnu.org/licenses/agpl-3.0.html>. This change does not alter
consent, signing bytes, membership eligibility, custody, or recovery formats.


The 2026-10-03 notice refresh pins `31d6005a23d9e2e343eb57127d7aeee67543f14f` (complete upstream package manifest SHA-256 `33bed126e7a2d8fcd5072628576eed96adec170fbf0bd81504c801f25e41e045`). Wallet consumes its source archive and ships only the registration entry and corresponding notice/source subset. The full upstream WASM package is not an extension input.
