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
