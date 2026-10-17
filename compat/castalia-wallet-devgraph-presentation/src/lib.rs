//! Shared native/WASM presentation contract. Custody, clocks and randomness live
//! in adapters. This library cannot select a key, URL, audience or issuer.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use devgraph_work_protocol::{
    WorkRequest, canonical_json, digest, idempotency_key_digest, strict_json,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub type Result<T> = core::result::Result<T, &'static str>;
pub const SCHEMA: &str = "devgraph.work.wallet-presentation.v1";
pub const AUDIENCE: &str = "devgraph://receiver-local";
pub const MAX_SAFE: u64 = 9_007_199_254_740_991;
const SIGNATURE_DOMAIN: &[u8] = b"devgraph.work.wallet-presentation.v1/signature\0";

/// Exact unsigned v1 fields. Private construction prevents unchecked transcripts.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedPresentation {
    actor_public_key: String,
    actor_signature_suite: String,
    audience: String,
    expires_at: u64,
    idempotency_key_digest_sha256: String,
    issued_at: u64,
    nonce: String,
    operation: String,
    request_digest_sha256: String,
    resources: Vec<String>,
    schema: String,
    schema_version: u64,
    session_id: String,
}

impl UnsignedPresentation {
    pub fn actor_public_key(&self) -> &str {
        &self.actor_public_key
    }
    pub fn actor_signature_suite(&self) -> &str {
        &self.actor_signature_suite
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn idempotency_key_digest_sha256(&self) -> &str {
        &self.idempotency_key_digest_sha256
    }
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn request_digest_sha256(&self) -> &str {
        &self.request_digest_sha256
    }
    pub fn resources(&self) -> &[String] {
        &self.resources
    }
    pub fn schema(&self) -> &str {
        &self.schema
    }
    pub fn schema_version(&self) -> u64 {
        self.schema_version
    }
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn signature_transcript(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = SIGNATURE_DOMAIN.to_vec();
        bytes.extend(canonical_json(self)?);
        Ok(bytes)
    }
    fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA
            || self.schema_version != 1
            || self.audience != AUDIENCE
            || self.actor_signature_suite != "Ed25519"
            || self.expires_at > MAX_SAFE
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > 60
            || !hex_digest(&self.request_digest_sha256)
            || !hex_digest(&self.idempotency_key_digest_sha256)
        {
            return Err("invalid_work_presentation");
        }
        decode64::<32>(&self.actor_public_key)?;
        decode64::<16>(&self.session_id)?;
        decode64::<12>(&self.nonce)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Presentation {
    #[serde(flatten)]
    unsigned: UnsignedPresentation,
    signature: String,
}
impl Presentation {
    /// Raw strict parser preserves duplicate-key rejection before materialization.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut value = strict_json(raw, 16_384).map_err(|_| "invalid_work_presentation")?;
        let signature = value
            .as_object_mut()
            .ok_or("invalid_work_presentation")?
            .remove("signature")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or("invalid_work_presentation")?;
        let unsigned: UnsignedPresentation =
            serde_json::from_value(value).map_err(|_| "invalid_work_presentation")?;
        unsigned.validate()?;
        decode64::<64>(&signature)?;
        Ok(Self {
            unsigned,
            signature,
        })
    }
    pub fn unsigned(&self) -> &UnsignedPresentation {
        &self.unsigned
    }
    pub fn signature(&self) -> &str {
        &self.signature
    }
    pub fn canonical(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }
}

/// Owned checked transcript. A signature must verify against its bound public key.
#[derive(Debug)]
pub struct PreparedPresentation {
    unsigned: UnsignedPresentation,
    transcript: Vec<u8>,
}
impl PreparedPresentation {
    pub fn unsigned(&self) -> &UnsignedPresentation {
        &self.unsigned
    }
    pub fn signature_transcript(&self) -> &[u8] {
        &self.transcript
    }
}

pub fn prepare(
    request: &WorkRequest,
    key: &str,
    public_key: &[u8; 32],
    now: u64,
    session: &[u8; 16],
    nonce: &[u8; 12],
) -> Result<PreparedPresentation> {
    if now > MAX_SAFE - 60 {
        return Err("invalid_clock");
    }
    VerifyingKey::from_bytes(public_key).map_err(|_| "invalid_wallet_signature")?;
    let unsigned = UnsignedPresentation {
        actor_public_key: base64url(public_key),
        actor_signature_suite: "Ed25519".into(),
        audience: AUDIENCE.into(),
        expires_at: now + 60,
        idempotency_key_digest_sha256: idempotency_key_digest(key)?,
        issued_at: now,
        nonce: base64url(nonce),
        operation: request.operation().into(),
        request_digest_sha256: request.request_digest(),
        resources: request.resources().to_vec(),
        schema: SCHEMA.into(),
        schema_version: 1,
        session_id: base64url(session),
    };
    let transcript = unsigned.signature_transcript()?;
    Ok(PreparedPresentation {
        unsigned,
        transcript,
    })
}

pub fn complete(prepared: PreparedPresentation, signature: &[u8; 64]) -> Result<Presentation> {
    let public = decode64::<32>(prepared.unsigned.actor_public_key())?;
    VerifyingKey::from_bytes(&public)
        .map_err(|_| "invalid_wallet_signature")?
        .verify_strict(&prepared.transcript, &Signature::from_bytes(signature))
        .map_err(|_| "invalid_wallet_signature")?;
    Ok(Presentation {
        unsigned: prepared.unsigned,
        signature: base64url(signature),
    })
}

/// Verifies the public signature and all request/key/time bindings. It does not
/// authorize grants, reserve replay state or authenticate an execution response.
pub fn verify_binding(
    request: &WorkRequest,
    presentation: &Presentation,
    key: &str,
    now: u64,
) -> Result<[u8; 32]> {
    if now > MAX_SAFE - 60 {
        return Err("invalid_clock");
    }
    let unsigned = presentation.unsigned();
    unsigned.validate()?;
    if unsigned.operation() != request.operation()
        || unsigned.resources() != request.resources()
        || unsigned.request_digest_sha256() != request.request_digest()
        || unsigned.idempotency_key_digest_sha256() != idempotency_key_digest(key)?
        || unsigned.issued_at() > now
        || unsigned.expires_at() <= now
    {
        return Err("invalid_work_presentation");
    }
    let public = decode64::<32>(unsigned.actor_public_key())?;
    let signature = decode64::<64>(presentation.signature())?;
    VerifyingKey::from_bytes(&public)
        .map_err(|_| "invalid_wallet_signature")?
        .verify_strict(
            &unsigned.signature_transcript()?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| "invalid_wallet_signature")?;
    Ok(public)
}

pub fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn decode64<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != (N * 4).div_ceil(3) {
        return Err("invalid_work_presentation");
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "invalid_work_presentation")?;
    if base64url(&bytes) != value {
        return Err("invalid_work_presentation");
    }
    bytes.try_into().map_err(|_| "invalid_work_presentation")
}
pub fn actor_id(public_key: &[u8; 32]) -> String {
    format!("pubkey:sha256:{}", digest(b"", public_key))
}
fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
