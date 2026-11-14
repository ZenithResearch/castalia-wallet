# Castaway feed configuration — development contract

This directory is the canonical synthetic fixture set for reader-first feed support. It is not an issued ontology release, new permission, public feed catalog or production v3 writer. Existing Castaway v1/v2 and checksum-pinned portable-web artifacts remain unchanged.

The intended section is `sections.feeds`, with `schema: "castalia.feeds-section.v1"`, integer version 1, subscriptions, collections and newest-first preferences. A feed-bearing vault targets matching Castaway outer/inner v3. Legacy sections retain their meanings; v3 requires feeds (including empty) and permits walletIdentities without losing them. Unsupported versions/sections fail the whole import.

`conformance.json` contains original raw JSON strings, including duplicate and escaped-duplicate properties. Each reader must consume raw input before object conversion and agree on all 102 verdicts. Accepted values preserve string/array values and order; normalizing JSON serialization alone is not a data change. `section.json` is a synthetic positive example, not an endpoint that should be fetched.

## Section rules

- Exact keys at every level. Raw version values use integer JSON lexemes; decimal/exponent values and rounded floating aliases are rejected before Number conversion. No authority, credentials, executable renderer URLs, cache or polling state.
- Canonical lowercase hyphenated UUIDs, version 1–8 and RFC variant 8/9/a/b. Nil/max IDs are rejected. IDs are unique separately within subscriptions and collections. Collection references are unique within each subscription and must resolve.
- At most 256 subscriptions, 64 collections and 16 collection references per subscription. Collections are exactly id/title records.
- Labels may be empty or whitespace (no custom label); preserve Unicode exactly, including combining forms and ZWJ. Reject Unicode Cc control characters and lone surrogates. Labels are at most 512 UTF-8 bytes.
- URLs are at most 2,048 UTF-8 bytes and must equal their parsed serialized form byte for byte: lowercase ASCII HTTPS/DNS host, implicit default port, no userinfo/query/fragment, no IP literal, trailing host dot, malformed percent escapes, backslash, whitespace or parser-rewritten path/host. Parser-stable escaped path bytes retain their case.
- Initial suffix denylist: localhost, local, internal, home, lan, corp, test, invalid, example, onion and arpa, including subdomains. Public example.org/net/com are admissible syntax. DNS resolution and actual public-address checks belong to the transport; syntax validation grants no fetch permission and cannot prove a path contains no secret.
- Compact serialized section is at most 256 KiB UTF-8. Standalone raw feed JSON has the same input-byte limit. The whole encrypted artifact remains bounded at 1 MiB, including envelope/base64 overhead and all preserved sections; wallet commit/export must preflight the complete candidate without truncation.
- Formats: auto/rss/atom. Disclosure: private/selected. Enabled is a portable preference, never permission to fetch on a new host.

## Preservation and rollout

No imported section means no feed change; empty import does not infer deletion. Wallet import is additive/idempotent, with conflicts resolved before any mutation. Replacement/removal is an explicit reviewed host edit. Older imports and account edits preserve committed newer sections and cannot downgrade v3.

A selected projection includes only reviewed subscriptions and explicitly reviewed collection labels/memberships; strip unselected references from the projection without changing its source. Local activation is separate. No whole vault or identity/Member Key is disclosed by default.

Reader tests must preserve legacy positive/negative fixtures, reject wrong owner/version/unknown sections, and decrypt independently created synthetic v3 files. Production v3 encryption/export stays refused until host persistence, native admission and cross-client fixtures qualify. Later stages cover atomic canceled/stale/conflicting imports, size preflight, restart and credential-free public transport/redirect/proxy behavior.

The independent TypeScript reader in Castalia Web mirrors these bytes under `packages/castaway-contract/fixtures/feeds-v1`. Update the canonical set and mirror deliberately, and record exact source/digests when publishing. Broader plan: Book Nook `docs/FEEDS.md`; work ownership: `Project/castalia-portable-feeds` in DevGraph.

## Independently encrypted synthetic files

`encrypted-v3.json` contains eight authenticated synthetic vectors: populated, empty and conflicting-title files are individually valid; raw duplicate properties, outer/inner mismatch, wrong inner owner, future version and unknown section are invalid. A valid standalone conflicting file must still fail reconciliation against different existing values. The inputs contain only the publicly known encrypted custody vector and public test passwords. Never use them for real custody.

The fixture was independently produced using Node 24.20.0 built-in Argon2id and OpenSSL AES-256-GCM, after checking the historical custody-vector derived key. Canonical header/plaintext keys are ASCII and use the existing JCS profile; nonce values are distinct per case. Both actual rebuilt WASM host adapters decrypt/validate the expected verdicts. These are test artifacts, not a production v3 export API or a supported-client rollout claim.

## Pure selected projection — development SDK

`castalia_wallet_core::feed_projection::PreparedFeedProjectionV1` provides a pure,
opaque Rust preparation. This increment adds no browser/native host method,
capability advertisement, custody command, persistence, signing or transmission.
Production v3 admission/export guards remain in place. Neither a successful
projection nor its preview is evidence of user consent or an approved origin.

```rust
use castalia_wallet_core::feed_projection::PreparedFeedProjectionV1;

fn selected_section(
    original_source_json: &str,
    choices_json: &str,
    current_source_json: &str,
    trusted_origin: &str,
) -> Result<serde_json::Value, &'static str> {
    let prepared = PreparedFeedProjectionV1::prepare(
        original_source_json, choices_json, trusted_origin,
    )?;
    // A host must separately review prepared.destination_origin() and
    // prepared.preview_json(), then recheck consent and its live requester.
    prepared.confirm(current_source_json, trusted_origin)
}
```

The choices-only input has exactly `schema`, `subscriptionIds`, `collectionIds`
and `memberships`. Its schema is `castalia.feed-projection-selection.v1`.
Each membership is exactly `{subscriptionId, collectionIds}`. Every chosen
subscription requires one explicit membership record, including an empty list.
IDs must resolve to the strictly validated source section. Sources must already
be marked `disclosure: "selected"` by a separate reviewed configuration edit.
Duplicate/unknown/private selections, invented memberships, missing membership
choices and memberships without explicitly selected labels fail closed.
Unselected sources, unselected memberships and orphan labels are omitted without
changing the source. Selection order never reorders source arrays or strings.
Empty selection is valid and produces an empty section, not a deletion request.

Source and choices are original raw JSON strings, each bounded to 256 KiB; the
existing duplicate-key/Unicode/recursion-limited parser runs before typed
conversion. Choices allow at most 256 sources, 64 labels and 16 memberships per
source. Confirmation consumes the prepared value and requires identical source
bytes and destination: even a whitespace-only source change is stale. The SHA-256
source fingerprint is private. The handle cannot be cloned, serialized or
deserialized; `preview_json()` returns only the selected existing
`castalia.feeds-section.v1`, not a new envelope or approval token. JSON object key
order/whitespace may change, but string contents and array order are preserved.

The destination is a separate caller-trusted input, not a field in the selection.
It must be at most 2,048 bytes and equal its parsed canonical tuple origin exactly:
HTTPS, or HTTP for exact `localhost`, `127.0.0.1` or `[::1]`. This matches Wallet
host syntax, including canonical HTTPS ports/IPs; it does not establish approval
or public network reachability. Paths, trailing slash, userinfo, query, fragment,
opaque origins and parser-normalized spellings fail. Host adapters retain their
existing origin allowlists and may be stricter. They must bind the real requesting
document/destination, wallet revision, custody epoch, expiry and cancellation,
then obtain explicit consent before delivery. No destination is embedded in the
selected section. Plaintext data does not enforce a recipient or grant fetch access.

`projection-conformance.json` contains 46 original-JSON preparation cases and
three exact-source/origin confirmation cases. It is synthetic development data,
not a host qualification. The existing 102 section cases and encrypted vectors
remain unchanged. Rust tests also check section/selection byte bounds, count
bounds and raw depth/duplicate/Unicode failures.

For the existing Book Nook adapter, replace the choices schema with
`booknook.feed-disclosure-selection.v1`, add its required `origin`, and compare
the existing `booknook.selected-feeds.v1` wrapper's `feeds` to `expectedSection`.
Common positive cases are `source-order-unicode-explicit-memberships`, `ascii-idn`,
`empty-prunes-labels` and `labels-do-not-imply-membership`. The other six positive
origins deliberately exercise Wallet's wider syntax and must remain rejected by
Book Nook's existing public-HTTPS policy. Book Nook's configuration-revision fence
remains separate from this primitive's exact-byte fence. Do not repin or replace
its published wrapper based solely on shared fixture agreement.

Accepting-host import remains additive by default with explicit same-ID conflict
choices; absent/empty incoming data never implies removal. Replacement/removal is
a separate reviewed local configuration edit. Validation, preview and commit must
remain network-free, and activation requires a separate host action.


### Standalone foreign projection bindings

`WasmFeedProjectionV1` exposes this same primitive independently of `WasmWallet`.
Its constructor accepts original `Uint8Array` source and selection bytes plus the
separate caller-trusted origin. `destinationOrigin()` and `previewJson()` read
only the prepared data. `confirm(currentSourceBytes, trustedOrigin)` takes the
internal prepared value before validating the supplied UTF-8 bytes, bounds or
origin, so a failed confirmation cannot be replayed. `dispose()` is idempotent;
subsequent preview/confirmation calls fail. Release the generated wrapper with
`free()` when finished. No serialized object can recreate a preparation.

The native header adds `castalia_feed_projection_abi_version() == 1` and
`castalia_feed_projection_prepare`, `_preview`, `_confirm`, and `_free` without
changing the existing main ABI version. Prepare accepts original UTF-8 pointer /
length pairs (256 KiB source and selection, 2,048-byte origin); null, empty and
oversize inputs fail before reads. The caller must keep every accepted input
buffer readable for the duration of its call. Inputs are copied/parsed, never
retained. Preparation IDs use the existing global monotonic handle allocator in
a separate family with 16 live preparations per process. Cross-family IDs fail
closed; these process-local IDs are neither credentials nor approval tokens.

Preview and confirmation return an existing result handle containing raw selected
section JSON, or zero on failure. Read/copy/free it with `castalia_result_*`;
this preserves the existing shared 32-result capacity. Confirmation removes the
preparation before validating inputs or allocating its result, including when the
result table is full. Exactly one concurrent confirmer can consume it. Free is
idempotent and only affects its own handle family. Callers should clear their
owned preparation ID when confirming and release it on cancellation/deinit.

`tests/native/FeedProjectionSmoke.swift` is an executor-confined test consumer of
the actual C header and freshly built static library. It is not a shipped host
adapter. `bash scripts/test-feed-projection-swift.sh /absolute/library.a
/absolute/output-directory` runs it. The extension test executes the rebuilt web
WASM target **in Node**, while `scripts/test-feed-projection-node.mjs` runs the
same assertions against a separately rebuilt nodejs target. Neither qualifies a
browser/native consent surface. Both replay the frozen 46 preparation and three
confirmation cases; the native ABI tests additionally exercise cross-family IDs,
null/invalid pointers with rejected lengths, quotas, result copying and concurrent
consumption. The generated TypeScript export is checked by
`tests/feed-projection-types.ts`.

These bindings do not add provider methods/capabilities or change supported-host
allowlists, v3 production guards, custody, recovery, credentials, grants, signing,
transport or persistence. Real host adapters still must bind their actual trusted
destination, current source/revision, session lifetime and explicit consent before
delivering any selected data. Inert additive accepting-host import remains later
work; an empty selected section never authorizes deletion.

### Unregistered selected-feed host controller

The Wallet-private source adapter now retains an exact encrypted-record snapshot, owner, custody epoch and revision. Its one-shot synchronous consume fence refuses same-revision resealing and changed context. The selected-feed controller uses the actual WASM preparation and existing custody queue/confirmation broker, releases the queue during consent, then rechecks supported and approved trusted origin, document/tab, owner, epoch, expiry, observed-clock monotonicity and original encrypted snapshot before consuming and delivering once. The produced preview is immutable in-process. Canceled work retains its capacity slot until it actually exits; independent cleanup errors do not strand consent or leak other resources.

[Focused host-domain evidence](../../../docs/feed-projection-host-evidence.json) includes60 source/controller tests in the final511-pass repository suite, four existing gated skips, and full typecheck. Tests use real Rust encryption/WASM with synthetic trusted documents and confirmation windows. Of46 preparation vectors,42 enter the controller and4 invalid raw sources are rejected by real encrypted preflight. Actual browser/native origin authenticity, a read-only serialized consent view, connected lifecycle invalidation and accepting-host additive import need separate qualification. All host mutations must use the same queue or invalidate epoch/context; this is not a generic cross-process CAS. No method, capability, service-worker route, v3 writer or app pin is enabled here.
