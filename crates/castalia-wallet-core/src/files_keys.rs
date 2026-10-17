//! Additive Files wrapping. Existing custody/recovery and signing bytes are unchanged.
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const DOMAIN: &str = "castalia/files-key-wrap/v1";
const BINDING_SCHEMA: &str = "castalia.files-key-binding.v1";
const ENVELOPE_SCHEMA: &str = "castalia.files-key-envelope.v1";
const MAX_JSON: usize = 4096;
type Result<T> = core::result::Result<T, &'static str>;
const INVALID: &str = "invalid_files_key";

// This field order is the new contract's canonical order, not a general JSON serializer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FilesKeyBinding {
    schema: String,
    owner_member_key: String,
    service_id: String,
    storage_account_id: String,
    namespace_id: String,
    workspace_id: String,
    submission_id: String,
    revision_id: String,
}

impl FilesKeyBinding {
    fn parse(raw: &str, owner: &str) -> Result<Self> {
        if raw.len() > MAX_JSON {
            return Err(INVALID);
        }
        let value: Self = serde_json::from_str(raw).map_err(|_| INVALID)?;
        if value.schema != BINDING_SCHEMA
            || value.owner_member_key != owner
            || [
                &value.owner_member_key,
                &value.service_id,
                &value.namespace_id,
                &value.workspace_id,
                &value.submission_id,
                &value.revision_id,
            ]
            .iter()
            .any(|s| !hex32(s))
            || value.storage_account_id.is_empty()
            || value.storage_account_id.len() > 128
            || !value
                .storage_account_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._~-".contains(&b))
        {
            return Err(INVALID);
        }
        Ok(value)
    }

    fn bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| INVALID)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    binding: FilesKeyBinding,
    nonce: String,
    ciphertext: String,
}

fn hex32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn decode<const N: usize>(encoded: &str) -> Result<[u8; N]> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| INVALID)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(INVALID);
    }
    bytes.try_into().map_err(|_| INVALID)
}

fn wrapping_key(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(DOMAIN, seed))
}

pub fn wrap(seed: &[u8; 32], owner: &str, raw_binding: &str, key: &[u8]) -> Result<String> {
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    wrap_with_nonce(seed, owner, raw_binding, key, nonce)
}

fn wrap_with_nonce(
    seed: &[u8; 32],
    owner: &str,
    raw_binding: &str,
    key: &[u8],
    nonce: [u8; 12],
) -> Result<String> {
    if key.len() != 32 {
        return Err(INVALID);
    }
    let binding = FilesKeyBinding::parse(raw_binding, owner)?;
    let aad = binding.bytes()?;
    let wrapping_key = wrapping_key(seed);
    let cipher = Aes256Gcm::new_from_slice(wrapping_key.as_ref()).map_err(|_| INVALID)?;
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: key,
                aad: &aad,
            },
        )
        .map_err(|_| INVALID)?;
    serde_json::to_string(&Envelope {
        schema: ENVELOPE_SCHEMA.into(),
        binding,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
    .map_err(|_| INVALID)
}

pub fn unwrap(
    seed: &[u8; 32],
    owner: &str,
    raw_binding: &str,
    raw_envelope: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let expected = FilesKeyBinding::parse(raw_binding, owner)?;
    if raw_envelope.len() > MAX_JSON {
        return Err(INVALID);
    }
    let envelope: Envelope = serde_json::from_str(raw_envelope).map_err(|_| INVALID)?;
    if envelope.schema != ENVELOPE_SCHEMA || envelope.binding != expected {
        return Err(INVALID);
    }
    let nonce = decode::<12>(&envelope.nonce)?;
    let ciphertext = decode::<48>(&envelope.ciphertext)?;
    let aad = expected.bytes()?;
    let wrapping_key = wrapping_key(seed);
    let cipher = Aes256Gcm::new_from_slice(wrapping_key.as_ref()).map_err(|_| INVALID)?;
    let key = Zeroizing::new(
        cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| INVALID)?,
    );
    if key.len() != 32 {
        return Err(INVALID);
    }
    Ok(key)
}

// Existing Wallet Auth canonical bytes. This narrow signer cannot sign another operation.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ServiceChallenge {
    audience: String,
    domain: String,
    expires_at: String,
    issued_at: String,
    nonce: String,
    operation: String,
    origin: String,
    version: u32,
}

pub fn service_auth_bytes(
    raw: &str,
    origin: &str,
    kind: &str,
    id: &str,
    now_ms: u64,
) -> Result<Vec<u8>> {
    if raw.len() > MAX_JSON
        || !["index", "gateway"].contains(&kind)
        || !hex32(id)
        || origin.is_empty()
    {
        return Err(INVALID);
    }
    let challenge: ServiceChallenge = serde_json::from_str(raw).map_err(|_| INVALID)?;
    let issued = timestamp(&challenge.issued_at)?;
    let expires = timestamp(&challenge.expires_at)?;
    if challenge.domain != "castalia-wallet"
        || challenge.version != 1
        || challenge.operation != "castalia.wallet.signChallenge"
        || challenge.origin != origin
        || challenge.audience != format!("castalia-files://{kind}/{id}")
        || !(16..=128).contains(&challenge.nonce.len())
        || challenge
            .nonce
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && b != b'_' && b != b'-')
        || issued > now_ms
        || expires <= now_ms
        || expires <= issued
        || expires - issued > 120_000
    {
        return Err(INVALID);
    }
    serde_json::to_vec(&challenge).map_err(|_| INVALID)
}

fn timestamp(value: &str) -> Result<u64> {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
    {
        return Err(INVALID);
    }
    let number = |start: usize, end: usize| -> Result<u64> {
        let part = &bytes[start..end];
        if !part.iter().all(u8::is_ascii_digit) {
            return Err(INVALID);
        }
        Ok(part.iter().fold(0, |n, b| n * 10 + u64::from(b - b'0')))
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    let millisecond = number(20, 23)?;
    let leap = |y: u64| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if year < 1970
        || !(1..=12).contains(&month)
        || day == 0
        || day > months[(month - 1) as usize]
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(INVALID);
    }
    let mut days = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>();
    days += months[..(month - 1) as usize].iter().sum::<u64>() + day - 1;
    Ok((((days * 24 + hour) * 60 + minute) * 60 + second) * 1000 + millisecond)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    fn fixture() -> (String, String) {
        let owner = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes(),
        );
        let binding = json!({"schema":BINDING_SCHEMA,"ownerMemberKey":owner,"serviceId":"11".repeat(32),
            "storageAccountId":"fixture-account","namespaceId":"22".repeat(32),"workspaceId":"33".repeat(32),
            "submissionId":"44".repeat(32),"revisionId":"55".repeat(32)}).to_string();
        (owner, binding)
    }
    #[test]
    fn files_key_public_cross_custody_vector() {
        let (owner, binding) = fixture();
        let encoded = wrap_with_nonce(&[7; 32], &owner, &binding, &[9; 32], [3; 12]).unwrap();
        let value: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            value["ciphertext"],
            "RH3pQVXl40LUAjuuzFgRoRlMRFBJBFQWf-7PN_FTypQzSBaQ9o2B34-fCfUuPVHB"
        );
        for field in ["nonce", "ciphertext"] {
            let mut changed = value.clone();
            let mut bytes = URL_SAFE_NO_PAD
                .decode(changed[field].as_str().unwrap())
                .unwrap();
            bytes[0] ^= 1;
            changed[field] = json!(URL_SAFE_NO_PAD.encode(bytes));
            assert!(unwrap(&[7; 32], &owner, &binding, &changed.to_string()).is_err());
        }
    }
    #[test]
    fn files_key_randomized_roundtrip_and_root_separation() {
        let (owner, binding) = fixture();
        let a = wrap(&[7; 32], &owner, &binding, &[9; 32]).unwrap();
        let b = wrap(&[7; 32], &owner, &binding, &[9; 32]).unwrap();
        assert_ne!(a, b);
        assert_eq!(
            unwrap(&[7; 32], &owner, &binding, &a).unwrap().as_slice(),
            &[9; 32]
        );
        assert!(unwrap(&[8; 32], &owner, &binding, &a).is_err());
        assert_ne!(
            *wrapping_key(&[7; 32]),
            blake3::derive_key("castalia/castaway-local-section/v1", &[7; 32])
        );
        for size in [0, 31, 33, 64] {
            assert!(wrap(&[7; 32], &owner, &binding, &vec![9; size]).is_err());
        }
    }
    #[test]
    fn files_key_binds_every_field_and_rejects_malformed_envelopes() {
        let (owner, binding) = fixture();
        let encoded = wrap(&[7; 32], &owner, &binding, &[9; 32]).unwrap();
        for name in [
            "ownerMemberKey",
            "serviceId",
            "namespaceId",
            "workspaceId",
            "submissionId",
            "revisionId",
        ] {
            let mut changed: Value = serde_json::from_str(&binding).unwrap();
            changed[name] = json!("66".repeat(32));
            assert!(unwrap(&[7; 32], &owner, &changed.to_string(), &encoded).is_err());
            let mut envelope: Value = serde_json::from_str(&encoded).unwrap();
            envelope["binding"] = changed.clone();
            assert!(
                unwrap(
                    &[7; 32],
                    &owner,
                    &changed.to_string(),
                    &envelope.to_string()
                )
                .is_err()
            );
        }
        for account in ["other-account", "", "with space", "é"] {
            let mut changed: Value = serde_json::from_str(&binding).unwrap();
            changed["storageAccountId"] = json!(account);
            assert!(unwrap(&[7; 32], &owner, &changed.to_string(), &encoded).is_err());
        }
        for name in ["schema", "nonce", "ciphertext"] {
            let mut changed: Value = serde_json::from_str(&encoded).unwrap();
            changed[name] = json!("invalid");
            assert!(unwrap(&[7; 32], &owner, &binding, &changed.to_string()).is_err());
        }
        assert!(
            unwrap(
                &[7; 32],
                &owner,
                &binding,
                &encoded.replacen('{', "{\"extra\":1,", 1)
            )
            .is_err()
        );
        assert!(
            wrap(
                &[7; 32],
                &owner,
                &binding.replacen('{', "{\"schema\":\"duplicate\",", 1),
                &[9; 32]
            )
            .is_err()
        );
    }
    #[test]
    fn files_auth_is_only_the_existing_scoped_challenge_format() {
        let id = "11".repeat(32);
        let challenge = json!({"audience":format!("castalia-files://index/{id}"),"domain":"castalia-wallet",
            "expiresAt":"2026-10-03T00:02:00.000Z","issuedAt":"2026-10-03T00:00:00.000Z","nonce":"public-test-nonce",
            "operation":"castalia.wallet.signChallenge","origin":"https://castalia.example","version":1});
        let now = timestamp("2026-10-03T00:00:01.000Z").unwrap();
        let bytes = service_auth_bytes(
            &challenge.to_string(),
            "https://castalia.example",
            "index",
            &id,
            now,
        )
        .unwrap();
        assert_eq!(bytes, challenge.to_string().as_bytes());
        for field in [
            "audience",
            "domain",
            "origin",
            "operation",
            "issuedAt",
            "expiresAt",
        ] {
            let mut changed = challenge.clone();
            changed[field] = json!("invalid");
            assert!(
                service_auth_bytes(
                    &changed.to_string(),
                    "https://castalia.example",
                    "index",
                    &id,
                    now
                )
                .is_err()
            );
        }
        assert!(
            service_auth_bytes(
                &challenge.to_string(),
                "https://castalia.example",
                "gateway",
                &id,
                now
            )
            .is_err()
        );
        assert!(
            service_auth_bytes(
                &challenge.to_string(),
                "https://castalia.example",
                "index",
                &id,
                now + 120_000
            )
            .is_err()
        );
        assert!(timestamp("2026-02-29T00:00:00.000Z").is_err());
        assert_eq!(timestamp("1970-01-01T00:00:00.000Z"), Ok(0));
    }
}
