# Generic credential-bound presentations

`castalia-wallet-presentation` validates the application-neutral
`castalia.credential-presentation-request.v2` contract. It has no application
operation parser, executable profile, private key, transport, or policy engine.
Applications supply opaque request bytes plus a disclosure and an issuer-signed
credential. Wallet checks an independently configured issuer/key/audience/caller
pin, the current holder identity, both content digests, signature, and expiry.
The disclosure is authenticated by that issuer; Wallet does not independently
interpret application semantics or grant execution authority.

The canonical interoperability vector is
[`vectors/credential-presentation-v2.json`](vectors/credential-presentation-v2.json).
Its seeds are public synthetic test material. The fixture records the exact
canonical JSON, signing transcripts, and deterministic Ed25519 signatures.
`cargo run -p castalia-wallet-presentation --example generate_fixture` prints
that synthetic fixture without changing files or using real custody.

## Byte contract

Objects are closed and use snake_case. Canonical JSON is UTF-8, has sorted ASCII
field names, standard JSON string escaping, and no whitespace. Time fields are
integer Unix seconds in the JavaScript safe range. Keys and SHA-256 digests are
64 lowercase hexadecimal characters; Ed25519 signatures are 128 lowercase
hexadecimal characters; nonces are 32 lowercase hexadecimal characters. Opaque
request bytes use standard padded base64. Signed strings are never normalized.
Rust ingress rejects duplicate fields at every nesting level, unknown fields,
noncanonical encodings, floats, unsafe integers, and invalid Unicode scalars.

The credential claims contain `schema`, `issuer`, `key_id`,
`holder_public_key`, `audience`, `caller`, `request_digest_sha256`,
`disclosure_digest_sha256`, `policy_digest_sha256`, `nonce`, `issued_at`, and
`expires_at`. The enclosing credential contains only `claims` and `signature`.
Its signature transcript is:

```text
UTF8("castalia.request-credential.v1/signature\0") || canonicalJSON(claims)
```

The presentation request contains only `schema`, `request_bytes_base64`,
`disclosure`, and `credential`. Request digests are SHA-256 of the decoded opaque
bytes. A disclosure has a `title` and `statements`; its digest is SHA-256 of its
canonical JSON. The credential digest covers the entire canonical credential,
including its issuer signature.

The unsigned presentation contains `schema`, `holder_public_key`, `issuer`,
`key_id`, `audience`, `caller`, `request_digest_sha256`,
`credential_digest_sha256`, `disclosure_digest_sha256`, `nonce`, `issued_at`, and
`expires_at`. The output adds only `signature`. Its transcript is:

```text
UTF8("castalia.credential-presentation.v2/signature\0") || canonicalJSON(unsigned)
```

The decoded request is bounded to 131,072 bytes and the entire envelope to
262,144 bytes. Disclosure titles are 1–160 UTF-8 bytes; 1–144 statements contain
1–512 UTF-8 bytes each. Display strings reject C0/C1 and bidi control characters.
Issuer, key ID, audience and terminal caller ID are 1–200 printable ASCII bytes.
Browser caller IDs are exact canonical HTTPS origins, with HTTP permitted only
for loopback. A trust pin contains only `issuer`, `key_id`, `public_key`,
`audience`, and `callers`; no request can install or override a pin.

A credential lives at most 120 seconds. Preparation is single-use, expires no
later than its credential, and is capped at 120 seconds. Approval creates fresh
randomness and a current timestamp. The resulting presentation lives at most
60 seconds and never outlives its credential. The receiver must independently
verify the original request, credential, disclosure and presentation, and apply
its own policy and replay checks.

## Browser custody

`WasmWallet.prepareCredentialPresentation(raw, pinsJson, expectedCallerJson,
nowSeconds)` independently validates the request and returns an owned
`WasmCredentialPresentation`. `summary()` returns the verified generic disclosure
and bindings; `canonicalRequest()` returns an owned copy. Both trusted pins and
expected caller come from the privileged extension runtime, not page input.

`approveCredentialPresentation(handle, nowSeconds)` consumes the handle even on
failure. It rechecks the custody instance, lock epoch, identity, expiry and clock,
then creates fresh nonce/time and returns canonical presentation JSON. `dispose()`
ends an unapproved preparation. The browser runtime separately rechecks its exact
origin, document and connection around Chrome-owned consent.

Existing encrypted custody, `.castalia-recovery`, membership and legacy v1
presentation bytes remain unchanged. Generic v2 uses distinct schemas and
transcripts; it never treats a v1 proof as v2.

## Interactive native custody

```text
castalia-wallet-present-credential-v2 \
  --request-file /absolute/private/request.json \
  --trust-config-file /absolute/private/trust.json \
  --presentation-output /absolute/private/new-presentation.json
```

The explicit current raw32 profile uses `CASTALIA_SIGNING_KEY_FILE` for an
existing private 32-byte seed file and `CASTALIA_SIGNING_PUBLIC_KEY` for its
64-character lowercase public pin. The binary never sources `.env`, creates a
key, accepts a different custody format, or takes approval from stdin. Every use
requires the exact response `APPROVE` on `/dev/tty`; without a controlling terminal
it returns `approval_required` and creates no output. It rechecks the private
trust configuration after consent, before loading and verifying the private key.

The owner-private trust file is:

```json
{
  "schema": "castalia.wallet-presentation-trust.v1",
  "caller": { "kind": "terminal", "id": "operator-configured-client" },
  "pins": [{
    "issuer": "operator-configured-issuer",
    "key_id": "operator-configured-key",
    "public_key": "<64 lowercase hexadecimal characters>",
    "audience": "operator-configured-audience",
    "callers": [{ "kind": "terminal", "id": "operator-configured-client" }]
  }]
}
```

All file paths are absolute. The shared descriptor-relative file protections
reject unsafe ownership/permissions, symlinks, hardlinks and oversized inputs.
Output is atomically create-only with mode 0600. Private buffers are zeroized;
stdout/stderr contain bounded status codes. The terminal displays only the public
validated disclosure and bindings. The retired headless v1 commands previously
used the same helper; current packages retain only the generic command.


## Application migration and release gate

Wallet's [application-specific adapters are removed](wallet-application-adapter-retirement.md) in the current candidate. Source and package checks cover the complete Wallet production surface, and actual-WASM tests assert that only the generic presentation contract remains. Historical signed bytes are preserved as documentation fixtures, without executable legacy handlers.

Devgraph owns migration acceptance for its replacement browser and terminal clients: isolated issuer → interactive generic Wallet approval → authority projection → guarded receiver, including denial, expiry, replay, stale resources and uncertain dispatch. That separate migration gate coordinates application rollout; it does not add application policy or installed services to Wallet's generic contract qualification. This Wallet PR does not change live installed services or claim installed-runtime acceptance.

Final browser acceptance uses the exact canonical package with disposable identities. Source or synthetic acceptance never installs real trust or qualifies existing live profiles.

## Historical validation recorded before adapter retirement

- Rust 1.85.1: 43 workspace tests pass, including the unchanged custody, recovery,
  membership, Issue, Work and Arena vectors; strict workspace Clippy and formatting
  checks pass.
- Node 20.20.0: 32 focused tests pass across generic consent, actual WASM, the
  shared confirmation broker, and provider contracts. This includes 15 handler
  tests, seven of which force cancellation during awaited boundaries, and three
  actual-WASM tests with independent Node signature verification.
- Wallet's generic Rust verifier independently accepts 23 secS-produced synthetic
  credential/request/disclosure/presentation vectors and regenerates their exact
  presentation bytes and signatures. The generic implementation does not depend
  on an application-specific verifier or adapter.

These counts describe the stated source checks. Final packaged Chrome evidence
and isolated native-chain evidence are separate release records and must identify
their exact source and artifact versions.

The candidate packaged Chrome run passed all **17 cases** under Node 20.20.0 and
Chrome for Testing 153.0.8010.12. Its 35-file content-tree digest was unchanged
before and after the run:
`785008259b48927d230bdd1b0c94b0cab7ca3f4a0e58f3dd92fc772a00403fd5`.
The added runtime checks reject a concurrent second document without replacing
its predecessor's approval, abort pending presentation on worker restart, reject
approval from the stale popup, retain session replay reservations across restart,
and allow a fresh credential after unlocking the same durable identity. A forced
worker stop can leave the old popup visible; its approval resolves only to
`confirmation_unavailable`. The harness dismisses that inert window after testing.
This synthetic local candidate run does not clear the Buildkite manual block or
retire legacy clients. Buildkite still requires all six exact-artifact smoke
results and the candidate source revision in its operator attestation.

The four targeted Buildkite tests pass, including mutation checks proving that
generic v2 evidence cannot be replaced by a comment, an optional field, or a
conditional bypass of the manual block.
