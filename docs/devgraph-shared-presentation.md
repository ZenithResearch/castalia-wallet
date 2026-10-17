> Historical reference. The Wallet implementations described below were retired after `58d32a40559ffff0a9d99411f967b0889524c994`. See [the retirement boundary](wallet-application-adapter-retirement.md). These commands are not available in current Wallet packages. Historical bytes and evidence below are unchanged.

# Shared named Work presentation

`castalia-wallet-devgraph-presentation` is the single Wallet-owned v1 presentation
schema, transcript, completion and public-verification implementation. The native
`castalia-wallet-devgraph-work-v1` signer and extension `WasmWallet` use it together
with Devgraph's immutable-pinned `devgraph-work-protocol` crate. The former copied
Wallet request parser has been removed. Legacy Issue-create v1 remains a separate
compatibility path.

The library owns no key, filesystem, clock, randomness, network, grant or replay
state. `prepare` accepts a checked `WorkRequest`, validated idempotency key, public
key, safe timestamp, session and nonce. `complete` consumes the opaque prepared
transcript and verifies the supplied signature against its bound public key.
`Presentation::parse` rejects duplicate/unknown fields, noncanonical encodings,
unsafe time ranges and oversize input. `verify_binding` additionally verifies the
request, key, time and Ed25519 signature; this is proof of request possession,
not authorization and not a cryptographic execution receipt.

Canonical encoding comes from the same Devgraph function for both unsigned and
signed values. Tests captured fixed synthetic presentations from the original
native signer before extraction and compare all eleven operation vectors. The
adverse `serde_json/preserve_order,serde_json/arbitrary_precision` test run must
remain byte-identical. No protocol, custody container or stored-record migration
is introduced.

## Extension custody adapter

`WasmWallet.prepareDevgraphWork(rawBytes, idempotencyKey, nowSeconds)` independently
parses original bytes inside Rust/WASM and returns an owned `WasmDevgraphWork`.
The clock parameter is canonical decimal text to prevent numeric narrowing at
the JS/WASM boundary. Clock and randomness belong to the trusted extension
adapter; applications do not choose presentation parameters. Its `summary()`
contains the full normalized request, exact operation, all resources, request/key
digests, public actor and audience for Chrome-owned consent. This handle owns only
validated intent, the actor and custody epoch, and a 120-second approval deadline;
it creates no signed timestamp, session or nonce before approval.

`WasmWallet.signDevgraphWork(prepared, nowSeconds)` consumes the preparation and
generates a fresh session, nonce and 60-second signed lifetime after the final
custody recheck, and returns only the canonical public presentation JSON. It rejects
approval at or after the 120-second deadline, clock rollback,
locked custody, identity changes, cross-instance handles and preparations from a
previous lock/unlock epoch. `dispose()` clears a prepared request; `free()` frees
the WASM handle. No native raw seed or encrypted recovery container crosses this
API, and no page-facing generic signer is added.

The operation adapter alone does not qualify a browser route: extension
origin/document consent, native messaging, secS policy/replay and the guarded
Devgraph receiver are independently required. Extension custody retains its
existing disposable/developer status.

## Chrome native bridge developer artifact

`npm run package:devgraph-preview-extension` produces
`build/castalia-wallet-devgraph-preview`. The artifact adds only the nativeMessaging
and webNavigation permissions needed for native transport and exact Chrome document
checks. The production manifest remains unchanged. Load the artifact explicitly in
a disposable Chrome profile, read its actual extension ID from Chrome, and register
that ID with the separately provisioned `org.devgraph.wallet_bridge` host. Packaging
installs no native host, signer, grant or credential.

Production packaging sets `CASTALIA_DEVGRAPH_PREVIEW=false` at build time, removes
the native SDK entry points, and copies only the self-contained production bundles.
Its strict loopback/issuer inspection is unchanged. Normal developer builds keep
the preview entry points; they still need the separately packaged permissions and
explicit native-host setup described above.

The page API is `window.castaliaWallet.devgraph({v:1,request_id,action,...})`. It uses
a dedicated content-script port which is invalidated on navigation, custody lock,
identity replacement, origin revocation and disconnect. Only the top-level exact
`http://127.0.0.1:8080/sdk-preview/` document is accepted. Reads require a separate
Chrome-owned approval valid at most 15 minutes; signing shows the complete Rust
normalized request and all derived bindings. Consent never holds the custody FIFO.
Before signing, Wallet rechecks the document, actor, custody epoch and connection.
The native host independently enforces installed issuer/profile continuity and
current grants after consent; the guarded receiver repeats its final identity check.

Page actions never accept presentation/projection bytes, URLs, headers, credentials
or issuer configuration. Rust/WASM constructs and signs the presentation; the
extension sends it only to native authority issuance. Opaque attempt handles are
single-use. Responses use maximum 48 KiB canonical base64url chunks with strict
sequence/total/ack checks and 128 KiB envelopes. Four reads and one mutation are
active per connection; request-ID replay state is capped at 65,536 controls, after
which explicit reconnect is required. No prefetch or mutation retry occurs.

Provider errors retain safe `code` and `dispatched` metadata. A lost port, timeout or
invalid response after execute is unknown; a native explicit pre-dispatch denial
can establish false. Cancellation invalidates IDs before accepting late results.
The extension cannot roll back a mutation already committed by Devgraph.

Automated native, actual WASM, bridge/framing/denial and Chrome-API mock tests do not
replace the separately recorded real Chrome/macOS native-host qualification.

## SDK lifecycle regression qualification

The preview now treats top-level document replacement, path/query/fragment departure
and browser metadata inspection failures as terminal connection revocation. Returning
to the preview needs a new connection and explicit consent. Cleanup belongs to its
original port and prompt; delayed disposal cannot close a replacement connection.
An accepted direct provider disposal revokes authority first, delivers its final
`{disposed:true}` response, then lets the owning content router close the port. A
bounded transport fallback applies if that peer stalls; authority is already dead.
Unused authorization expires at its exact deadline and frees capacity for renewed
consent. A pending execution or response stream retains its mutation slot until
completion or cancellation, even if the signed authorization has since expired.

Run the combined artifact qualification with an explicit candidate SDK tarball after
building this extension. The harness loads the installed SDK and both actual WASM
runtimes, the real provider and content-script bundle, preview runtime, bridge and
NativeControl. Only browser APIs and native endpoints use synthetic fixture ports.

```sh
node --import ./node_modules/tsx/dist/loader.mjs \
  apps/chrome-extension/test/devgraph-sdk-integration.mts \
  --sdk-tarball /absolute/path/devgraph-web-0.1.0-preview.2.tgz \
  --output /absolute/path/paired-artifact-evidence.json
```

The candidate is installed offline in a temporary consumer with lifecycle scripts
disabled. Missing candidate input fails the run. Evidence records source revisions,
artifact hashes, exercised recovery/cancellation sequences, actual Wallet signature
verification and ordinary resource cleanup before emergency fixture cleanup. This
harness does not qualify a live installed Chrome/native/secS/receiver deployment.


## Reconciled Arena request support

The public immutable-pinned Devgraph protocol owns both Work and Arena request
parsing. This preserves the native Arena behavior from `ef58017` without restoring
the removed Wallet-owned parser. Arena create, patch, archive and member.set use
`devgraph.arena-request.v1\0` request digests. The presentation schema/signature
domain stays `devgraph.work.wallet-presentation.v1`; operations and all old/new
Arena resources remain bound. Task parent changes include an explicitly supplied
previous Arena while older Work bytes remain unchanged.

The same synthetic Arena vectors run through native CLI signing, shared
presentation verification, encrypted custody and actual WASM. Parser support
alone does not qualify an SDK UI or installed native host for Arena, change grants,
or add a live browser route. Existing consent/revocation, custody-v1 recovery,
raw-native recovery and execute-uncertainty behavior are retained. Hermes's older
runtime signer and challenge-clock changes are outside this reconciliation.
