# Dregg Hybrid Identity

Status: active Wallet custody profile; additive to Zenith membership v3

## One root, two signing halves

```text
                         extension-owned memory
                                  |
                    OS-random 32-byte identity seed
                         /                    \
                        /                      \
          Ed25519 SigningKey            ML-DSA.KeyGen(xi=seed)
                  |                       /                 \
        32-byte public key     1,952-byte public key   ML-DSA private key
                  \                       /
                   \                     /
                    Dregg hybrid identity
                    classical AND post-quantum
```

Wallet does not generate an independent post-quantum secret. Dregg defines the hybrid identity by supplying the same 32-byte Ed25519 seed as `xi` to deterministic FIPS 204 ML-DSA-65 key generation. Wallet pins `fips204` 0.4.6, the exact fallback implementation/version used by Dregg, and uses the same construction.

Hosted Wallet tests also pin Dregg's NIST ACVP ML-DSA-65 `tcId 26` seed and the SHA-256 digest of its 1,952-byte public key. Any derivation drift between the Wallet implementation and Dregg's Lean/NIST fixture fails CI.

This makes the encrypted Wallet seed directly usable by Dregg's `AgentCipherclerk::from_key_bytes`. A future Dregg recovery importer can decrypt a user-approved `.castalia-recovery` file and pass the recovered 32 bytes to that API without translating or rotating the identity. Wallet does not expose those bytes to page JavaScript or export them as plaintext.

A future [`.castaway` vault](castaway-portable-vault.md) may carry the public Dregg identity descriptor, but it never carries the Dregg seed, either private signing half, recovery material, or an encrypted signing-authority capsule. `.castalia-recovery` is the portable artifact that restores the same hybrid authority.

## Public descriptor

An unlocked hybrid-capable provider adds `dreggHybridIdentity` to `getSubject()`:

```text
version                       = 1
signatureSuite                = Ed25519+ML-DSA-65
ed25519PublicKey              = 32-byte lowercase hex
mlDsa65PublicKey              = 1,952-byte unpadded base64url
mlDsa65PublicKeyCommitment    = 32-byte lowercase hex
derivation                    = dregg.hybrid-from-ed25519-seed.v1
```

The commitment is the exact Dregg cell commitment:

```text
BLAKE3 derive_key context "dregg-cell-ml-dsa-key-v1"
material U32_LE(1952) || mlDsa65PublicKey
```

The provider-v1 field is optional only so older consumers keep decoding. The current Wallet always supplies it while unlocked.

## Dregg signing compatibility

For a Dregg canonical turn-signing message `M`, Wallet custody can produce:

```text
ed25519Signature = Ed25519.Sign(seed, M)
mlDsa65Signature = ML-DSA.Sign_deterministic(
  key = ML-DSA.KeyGen(xi=seed),
  ctx = "dregg-hybrid-turn-v1",
  message = M,
  rnd = 32 zero bytes
)
```

Those are the two halves of Dregg's `Authorization::HybridSignature`. The low-level PQ signer remains inside the Rust/Wasm custody core; page providers do not receive a generic arbitrary-signing method. A user-confirmed Dregg transaction API must supply the canonical Dregg message and transaction disclosure before this capability is exposed to websites.

## Membership boundary

Zenith membership v3 remains a centrally authenticated Ed25519 credential. It binds the classical owner key and does not attest the ML-DSA public key. That is forward-compatible because the owner key is still the classical half of the same Dregg identity, but it is not a post-quantum membership claim.

If membership itself must later be PQ-bound, introduce a new exact contract version that carries the ML-DSA key/commitment and verifies both possession signatures. Do not add fields to the strict v3 decoder or reinterpret a stored v3 credential.

## Recovery compatibility

The frozen `castalia.wallet-custody.v1` container says `keySuite: "Ed25519"` because it serializes the Ed25519 PKCS#8 form. The embedded 32-byte private seed is also the complete Dregg hybrid identity root. Existing `.castalia-recovery` files therefore gain the deterministic PQ half on unlock without a migration, a second backup, or a new identity.

Historical `Castaway-*.castaway` exports from the short-lived presentation-name release contain this same custody-v1 seed envelope. They are legacy recovery artifacts, not instances of the future portable vault format.
