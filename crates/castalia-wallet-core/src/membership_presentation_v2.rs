use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const APPLICATION_DOMAIN: &[u8] = b"castalia/member-application/v1\0";
const ENROLLMENT_DOMAIN: &[u8] = b"castalia/wallet-membership-enrollment/v2\0";
const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PresentationError {
    #[error("invalid_membership_presentation")]
    Invalid,
}
type Result<T> = core::result::Result<T, PresentationError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MemberApplicationV1 {
    pub factory_id: String,
    pub program_id: String,
    pub applicant_official_dregg_cell_id: String,
    pub owner_public_key: String,
    pub application_kind: u64,
    pub application_version: u64,
    pub application_nonce: u64,
    pub membership_class: u64,
    pub jurisdiction_code: u64,
    pub application_flags: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EnrollmentChallengeV2 {
    pub version: u64,
    pub challenge_id: String,
    pub nonce: String,
    pub origin: String,
    pub audience: String,
    pub operation: String,
    pub owner_public_key: String,
    pub application_commitment: String,
    pub signature_suite: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MembershipPresentationV2 {
    pub schema: String,
    pub owner_public_key: String,
    pub challenge: EnrollmentChallengeV2,
    pub signature_suite: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy)]
pub struct VerificationContext<'a> {
    pub expected_origin: &'a str,
    pub expected_audience: &'a str,
    pub now_ms: u64,
}

fn application(value: &Value) -> Result<MemberApplicationV1> {
    let app: MemberApplicationV1 =
        serde_json::from_value(value.clone()).map_err(|_| PresentationError::Invalid)?;
    for value in [
        app.application_kind,
        app.application_version,
        app.application_nonce,
        app.membership_class,
        app.jurisdiction_code,
        app.application_flags,
        app.created_at,
    ] {
        if value > MAX_SAFE {
            return Err(PresentationError::Invalid);
        }
    }
    if app.application_kind != 7
        || app.application_version != 1
        || app.application_nonce == 0
        || !matches!(app.membership_class, 1 | 2)
        || app.application_flags != 0
    {
        return Err(PresentationError::Invalid);
    }
    for value in [
        &app.factory_id,
        &app.program_id,
        &app.applicant_official_dregg_cell_id,
        &app.owner_public_key,
    ] {
        hex32(value)?;
    }
    Ok(app)
}

fn validate_challenge(challenge: &EnrollmentChallengeV2) -> Result<()> {
    if challenge.version != 2
        || challenge.operation != "castalia.membership.enroll"
        || challenge.signature_suite != 1
        || challenge.issued_at > MAX_SAFE
        || challenge.expires_at > MAX_SAFE
        || challenge.expires_at <= challenge.issued_at
        || challenge.expires_at - challenge.issued_at > 300_000
    {
        return Err(PresentationError::Invalid);
    }
    b64_exact::<16>(&challenge.challenge_id)?;
    b64_exact::<16>(&challenge.nonce)?;
    canonical_origin(&challenge.origin)?;
    if challenge.audience.is_empty()
        || challenge.audience != challenge.audience.nfc().collect::<String>()
    {
        return Err(PresentationError::Invalid);
    }
    hex32(&challenge.owner_public_key)?;
    hex32(&challenge.application_commitment)?;
    Ok(())
}

fn hex32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(PresentationError::Invalid);
    }
    hex::decode(value)
        .map_err(|_| PresentationError::Invalid)?
        .try_into()
        .map_err(|_| PresentationError::Invalid)
}
fn b64_exact<const N: usize>(value: &str) -> Result<[u8; N]> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PresentationError::Invalid)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(PresentationError::Invalid);
    }
    decoded.try_into().map_err(|_| PresentationError::Invalid)
}
fn canonical_origin(value: &str) -> Result<()> {
    if value.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(PresentationError::Invalid);
    }
    let parsed = url::Url::parse(value).map_err(|_| PresentationError::Invalid)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(PresentationError::Invalid);
    }
    let host = parsed.host_str().ok_or(PresentationError::Invalid)?;
    if host.ends_with('.') {
        return Err(PresentationError::Invalid);
    }
    let canonical = parsed.origin().ascii_serialization();
    if canonical != value {
        return Err(PresentationError::Invalid);
    }
    Ok(())
}
fn u64le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}
fn framed(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length: u32 = value
        .len()
        .try_into()
        .map_err(|_| PresentationError::Invalid)?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}

pub fn canonical_member_application_bytes(value: &Value) -> Result<Vec<u8>> {
    let app = application(value)?;
    let mut out = APPLICATION_DOMAIN.to_vec();
    for value in [
        &app.factory_id,
        &app.program_id,
        &app.applicant_official_dregg_cell_id,
        &app.owner_public_key,
    ] {
        out.extend_from_slice(&hex32(value)?);
    }
    for value in [
        app.application_kind,
        app.application_version,
        app.application_nonce,
        app.membership_class,
        app.jurisdiction_code,
        app.application_flags,
        app.created_at,
    ] {
        u64le(&mut out, value);
    }
    Ok(out)
}
pub fn commit_member_application(value: &Value) -> Result<[u8; 32]> {
    Ok(*blake3::hash(&canonical_member_application_bytes(value)?).as_bytes())
}
pub fn canonical_membership_enrollment_challenge_bytes(
    challenge_value: &Value,
    application_value: &Value,
) -> Result<Vec<u8>> {
    let challenge: EnrollmentChallengeV2 =
        serde_json::from_value(challenge_value.clone()).map_err(|_| PresentationError::Invalid)?;
    validate_challenge(&challenge)?;
    let app = application(application_value)?;
    if challenge.owner_public_key != app.owner_public_key
        || hex::encode(commit_member_application(application_value)?)
            != challenge.application_commitment
    {
        return Err(PresentationError::Invalid);
    }
    let mut out = ENROLLMENT_DOMAIN.to_vec();
    u64le(&mut out, challenge.version);
    framed(&mut out, &b64_exact::<16>(&challenge.challenge_id)?)?;
    framed(&mut out, &b64_exact::<16>(&challenge.nonce)?)?;
    framed(&mut out, challenge.origin.as_bytes())?;
    framed(&mut out, challenge.audience.as_bytes())?;
    framed(&mut out, challenge.operation.as_bytes())?;
    framed(&mut out, &hex32(&challenge.owner_public_key)?)?;
    framed(&mut out, &hex32(&challenge.application_commitment)?)?;
    u64le(&mut out, challenge.signature_suite);
    u64le(&mut out, challenge.issued_at);
    u64le(&mut out, challenge.expires_at);
    Ok(out)
}
pub fn parse_membership_presentation_v2(encoded: &[u8]) -> Result<MembershipPresentationV2> {
    serde_json::from_slice(encoded).map_err(|_| PresentationError::Invalid)
}
pub fn verify_membership_presentation_v2(
    presentation: &MembershipPresentationV2,
    application: &Value,
    context: VerificationContext<'_>,
) -> Result<()> {
    if presentation.schema != "castalia.wallet-membership-presentation.v2"
        || presentation.signature_suite != "Ed25519"
        || presentation.owner_public_key != presentation.challenge.owner_public_key
    {
        return Err(PresentationError::Invalid);
    }
    validate_challenge(&presentation.challenge)?;
    if presentation.challenge.origin != context.expected_origin
        || presentation.challenge.audience != context.expected_audience
        || presentation.challenge.issued_at > context.now_ms.saturating_add(5_000)
        || context.now_ms > presentation.challenge.expires_at
    {
        return Err(PresentationError::Invalid);
    }
    let challenge_value =
        serde_json::to_value(&presentation.challenge).map_err(|_| PresentationError::Invalid)?;
    let transcript =
        canonical_membership_enrollment_challenge_bytes(&challenge_value, application)?;
    let key = VerifyingKey::from_bytes(&hex32(&presentation.owner_public_key)?)
        .map_err(|_| PresentationError::Invalid)?;
    let signature = Signature::from_bytes(&b64_exact::<64>(&presentation.signature)?);
    key.verify(&transcript, &signature)
        .map_err(|_| PresentationError::Invalid)
}

use unicode_normalization::UnicodeNormalization;
