import base64
import json
import unicodedata
from pathlib import Path

import blake3
import rfc8785
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
VECTOR = json.loads((ROOT / "docs/contracts/castalia-wallet-custody-v1.vector.json").read_text())


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def derive_and_decrypt(container: dict, passphrase: str) -> dict:
    header = {key: container[key] for key in ("schema", "keySuite", "publicKey", "createdAt", "kdf", "aead")}
    kdf = header["kdf"]
    key = hash_secret_raw(
        unicodedata.normalize("NFC", passphrase).encode("utf-8"),
        decode(kdf["salt"]),
        kdf["iterations"],
        kdf["memoryKiB"],
        kdf["parallelism"],
        kdf["derivedKeyBytes"],
        Type.ID,
        version=kdf["version"],
    )
    plaintext_bytes = AESGCM(key).decrypt(
        decode(header["aead"]["nonce"]),
        decode(container["ciphertext"]),
        rfc8785.dumps(header),
    )
    plaintext = json.loads(plaintext_bytes)
    private_key = serialization.load_der_private_key(decode(plaintext["privateKeyPkcs8"]), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("wrong key algorithm")
    public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if public_key.hex() != container["publicKey"]:
        raise ValueError("outer public key mismatch")
    if blake3.blake3(public_key).hexdigest() != plaintext["keyId"]:
        raise ValueError("key ID mismatch")
    if plaintext["createdAt"] != container["createdAt"]:
        raise ValueError("creation timestamp mismatch")
    return {"key": key, "plaintext": plaintext_bytes, "public_key": public_key}


result = derive_and_decrypt(VECTOR["container"], VECTOR["inputs"]["passphraseUnicode"])
assert result["key"].hex() == VECTOR["intermediates"]["derivedKeyHex"]
assert result["plaintext"].hex() == VECTOR["intermediates"]["plaintextUtf8Hex"]
assert rfc8785.dumps(VECTOR["container"]).hex() == VECTOR["finalContainerJcsUtf8Hex"]

for mutation in ("publicKey", "ciphertext"):
    tampered = json.loads(json.dumps(VECTOR["container"]))
    if mutation == "publicKey":
        tampered[mutation] = ("0" if tampered[mutation][0] != "0" else "1") + tampered[mutation][1:]
    else:
        raw = bytearray(decode(tampered[mutation]))
        raw[0] ^= 1
        tampered[mutation] = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    try:
        derive_and_decrypt(tampered, VECTOR["inputs"]["passphraseUnicode"])
    except (InvalidTag, ValueError):
        pass
    else:
        raise AssertionError(f"{mutation} tamper accepted")

# Re-encrypt a different valid Ed25519 key under a valid tag to prove import-time key consistency.
mismatch = json.loads(json.dumps(VECTOR["container"]))
header = {key: mismatch[key] for key in ("schema", "keySuite", "publicKey", "createdAt", "kdf", "aead")}
other = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
other_der = other.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
plaintext = json.loads(bytes.fromhex(VECTOR["intermediates"]["plaintextUtf8Hex"]))
plaintext["privateKeyPkcs8"] = base64.urlsafe_b64encode(other_der).rstrip(b"=").decode()
mismatch["ciphertext"] = base64.urlsafe_b64encode(
    AESGCM(result["key"]).encrypt(
        decode(header["aead"]["nonce"]), rfc8785.dumps(plaintext), rfc8785.dumps(header)
    )
).rstrip(b"=").decode()
try:
    derive_and_decrypt(mismatch, VECTOR["inputs"]["passphraseUnicode"])
except ValueError:
    pass
else:
    raise AssertionError("authenticated mismatched private key accepted")

print("CUSTODY_INTEROP_VECTOR_OK")
