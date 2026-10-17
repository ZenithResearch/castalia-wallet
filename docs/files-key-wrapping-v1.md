# Files key wrapping v1

This additive interface protects a random 32-byte Files data key using the existing recoverable Ed25519 seed. It does not change custody-v1, `.castalia-recovery`, `.castaway`, membership, Work/Arena, registration signatures, or snapshot-v1. `.castaway` remains data/proof storage and does not become signing recovery.

The browser encrypts an immutable revision with a fresh data key. Custody derives a separate wrapping key with `BLAKE3 derive_key("castalia/files-key-wrap/v1", recovered_seed32)`, then uses AES-256-GCM with a random 12-byte nonce. The encrypted key is 48 bytes including the authentication tag. The canonical binding bytes are authenticated data. Wrapping keys and the recovered seed never leave custody.

## Frozen binding and envelope

Binding fields serialize in this exact order (not general sorted JSON):

1. `schema`: `castalia.files-key-binding.v1`
2. `ownerMemberKey`: lowercase 32-byte hex
3. `serviceId`: lowercase 32-byte hex; pinned index-service identity
4. `storageAccountId`: opaque ASCII matching `[A-Za-z0-9._~-]{1,128}`, without normalization
5. `namespaceId`: lowercase 32-byte hex
6. `workspaceId`: lowercase 32-byte hex
7. `submissionId`: lowercase 32-byte hex
8. `revisionId`: lowercase 32-byte hex, allocated before encryption

The envelope has exactly `schema` (`castalia.files-key-envelope.v1`), `binding`, `nonce` (canonical unpadded base64url, 12 bytes), and `ciphertext` (canonical unpadded base64url, 48 bytes). Unwrap requires an independently supplied expected binding; both the binding comparison and authenticated decryption must succeed. Unknown fields, alternate encodings, another owner, and substituted scope fail closed.

The requesting website origin is deliberately absent from the derivation and binding: recovering the same Member Key can decrypt the envelope from another authorized site. Endpoint rotation likewise does not change the service identity. Each invocation separately binds and discloses its exact requesting origin, service audience, account and revision.

## Narrow provider and consent

Compatible providers expose `filesKeyProtocol = "castalia.files-key-wrap.v1"`, `wrapFilesKey`, `unwrapFilesKey`, and `requestFilesServiceAuthentication`. The wire data key is canonical unpadded base64url of exactly 32 bytes. Unwrap releases that data key only to the approved request; it never exports a wrapping key or signing seed.

Every operation includes exact `requestId`, `origin`, `audience`, `nonce`, `issuedAtMs`, `expiresAtMs`, and `requestDigest` consent fields. The lifetime is at most 120 seconds. Request IDs/nonces are reserved before approval; denial and interruption consume them. The request digest is SHA-256 of UTF-8 `castalia/files-key-request/v1\0` followed by fixed-order JSON `{operation,body}` after strict normalization. The only operations are `wrap`, `unwrap`, and `authenticate`. `buildFilesConsent` constructs this transcript; callers must not substitute an independently interpreted digest.

Chrome requires an approved actual top-level sender and its own fresh confirmation window. The bridge bounds active connections, admits one request per connection and cancels on navigation, disconnect, lock, identity replacement and origin revocation. It does not depend on transient page activation surviving a multi-dialog shipping flow. The inline browser provider uses an explicit application confirmation and session/mount invalidation; it is not an extension-level isolation boundary.

Authentication signs only the existing eight-field Wallet Auth challenge, in order: `audience`, `domain`, `expiresAt`, `issuedAt`, `nonce`, `operation`, `origin`, `version`. The domain is `castalia-wallet`, operation is `castalia.wallet.signChallenge`, version is 1, and audience is exactly `castalia-files://index/<hex32>` or `castalia-files://gateway/<hex32>`. Its exact origin and at-most-120-second canonical UTC interval are checked again immediately before signing. The returned Ed25519 SignaturePresentation preserves the existing DID/PEM subject encoding. Services must enforce nonce single use and storage authority; neither a profile nor membership credential supplies that authority.

## Recovery, memory and compatibility evidence

The public synthetic vector uses a declared disposable seed and data key, includes an existing-format encrypted custody record and raw Web recovery key, and freezes one deterministic envelope. These fixture values must never protect real data. Both custody implementations restore the same Member Key and decrypt the same vector. Actual-WASM provider tests additionally wrap randomly, export existing encrypted recovery under a different passphrase, restore into fresh custody and unwrap. Native negative cases cover every binding field, wrong root, malformed/unknown fields and authentication failure. Consent tests cover denial/replay, input mutation, expiry, navigation, revocation and disposal.

The seed copy, derived wrapping key and decrypted Rust key use `Zeroizing`. Wrap accepts an owned input vector that is wiped. Unwrap copies into a JS-owned `Uint8Array` while the Rust plaintext is still guarded, then wipes the Rust buffer. The direct `js-sys` dependency selects its already-locked version; no package versions are upgraded. The provider wipes its temporary decoded/raw data-key arrays after use. JavaScript strings and the caller's intentional data-key copies cannot be reliably erased by this interface, and browser-runtime qualification remains separate from these source tests.

The narrow Rust module and provider contract are intentionally mirrored across Wallet and Web, using the same new public vector. Their binding order, domains and challenge bytes must change together through a new version if compatibility would break. The Files package coordinator uses this same consent contract; it must not reinterpret the bindings.

## First-use and remaining boundaries

Personal namespace registration requires the existing compatible-wallet registration API and verified active base-v3 membership. The inline Web provider does not add a generic signer or invent missing issuance: it supports Files operations only for the same Member Key with an already accepted personal binding discovered through the configured index. Selecting another wallet is explicit. Zenith organization registration remains a separate manual ceremony.

Tests do not establish a live operator's authorization, Sia payment agreement, production endpoint trust, availability, or rights to inherited source material. These remain separate acceptance inputs. No production service, real wallet, or recovery format is migrated by this change.

## Loaded-browser qualification

`npm run smoke:extension-files` uses two new, disposable Chrome profiles, an extension copied to a temporary directory, and locally intercepted HTTPS sites. It creates a wallet through its own UI, verifies Chrome-owned wrap disclosure, replay rejection, denial and navigation cancellation, exports the unchanged encrypted recovery format, imports that recovery through the UI in the second fresh profile, then unwraps the retained envelope from a different approved origin. The recovered provider also signs a scoped service-authentication challenge; the harness independently verifies its Ed25519 signature. The final lock check rejects `getSubject`. It uses a synthetic data key and never accesses a real wallet or Sia endpoint. Set `CASTALIA_EXTENSION_DIRECTORY` to test an exact packaged extension instead of the working development bundle.

The implementation check passed in Chrome for Testing 153.0.8010.12. Installed Chrome Stable 154.0.8037.97 ignored the unpacked-extension launch flags, so that attempted run did not exercise custody and is not acceptance evidence. The existing `smoke:extension-custody` remains the separate persistence/recovery check. These local checks do not establish production packaging, operator authorization, live storage or payment acceptance.
