# Castalia Wallet Standard

The Castalia Wallet Standard (CWS) defines the envelopes, payload sections, storage classes and schema-publication format for person-controlled wallet files across native and Web implementations. It is provider-neutral: Castalia membership, an infrastructure provider, a connected account and an application's authorization are separate concepts.

## Proposals

| ID | Title | Revision | Status |
| --- | --- | --- | --- |
| [CWS-001](cws-001/README.md) | Wallet files, typed sections and schema publications | 0.2.0-draft, October 18, 2026 | Current v1 envelope companions plus proposed extensible file/publication schemas; SDK, account adapters and expanded recovery codecs unimplemented |

`MUST`, `MUST NOT`, `SHOULD` and `MAY` express requirements on a future implementation claiming the named profile. Publishing a draft does not qualify an installed wallet, ratify an external protocol, or approve production custody. Each profile must state its implementation and compatibility evidence separately.

## Changes and adoption

Propose changes through a pull request with the problem, affected producers/consumers, stored-file impact, examples and negative cases. A draft may change; exact consumers must pin its revision. A stable wire identifier requires reviewed encoders/decoders, independently produced vectors, migration coverage and interoperability evidence. Incompatible changes require a new schema identifier and explicit migration; no implementation may silently reinterpret stored authority.

Existing custody-v1, chain derivations, native ABI, provider approvals, signing domains and `.castaway` contracts remain authoritative until a versioned implementation explicitly replaces them. CWS documents these boundaries rather than treating a proposal as a migration.
