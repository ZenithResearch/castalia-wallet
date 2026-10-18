//! Additive, verifier-free service holder wire profile. All decoded values are
//! UNTRUSTED. This module owns no keys and grants no authority. Exact request
//! bytes are retained; the application reader and native current policy guard
//! remain separate. Existing caller-proof-v1 and Packet v0 are unchanged.
use alloc::{string::String, vec::Vec};
use sha2::{Digest, Sha256};

pub const PROFILE: &str = "secs-service-holder-proof-v1";
pub const PAYLOAD_MODE: &str = "native-plaintext-request-v1";
pub const CHALLENGE_DOMAIN: &[u8] = b"secs-service-challenge-v1/signature\0";
pub const HOLDER_DOMAIN: &[u8] = b"secs-service-holder-proof-v1/signature\0";
pub const PROOF_TAG: &[u8] = b"secs-service-holder-proof-v1\0";
pub const MAX_PROOF_BYTES: usize = 16_384;
pub const MAX_RUNTIME_REQUEST_BYTES: usize = 2_097_152;
pub const MAX_SERVICE_REQUEST_BYTES: usize = 65_536;
pub const MAX_SAFE_TIME: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    Malformed,
    Oversized,
    InvalidBinding,
    InvalidWindow,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceApplication {
    RuntimeV1,
    ServiceV1,
}
impl ServiceApplication {
    pub fn wire_id(self) -> &'static str {
        match self {
            Self::RuntimeV1 => "runtime-v1",
            Self::ServiceV1 => "service-v1",
        }
    }
    pub fn audience(self) -> &'static str {
        match self {
            Self::RuntimeV1 => "runtime://receiver-local",
            Self::ServiceV1 => "service-management",
        }
    }
    pub fn max_request_bytes(self) -> usize {
        match self {
            Self::RuntimeV1 => MAX_RUNTIME_REQUEST_BYTES,
            Self::ServiceV1 => MAX_SERVICE_REQUEST_BYTES,
        }
    }
}

/// Untrusted signed evidence claims, never an evidence approval. Native owner
/// inputs must independently match these exact observations/digests/horizons.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceEvidenceBindings {
    pub required_evidence_digest: [u8; 32],
    pub evidence_snapshot_digest: [u8; 32],
    pub evidence_observations_digest: [u8; 32],
    pub evidence_adapter_profiles_digest: [u8; 32],
    pub evidence_source_epoch_digest: [u8; 32],
    pub evidence_valid_not_before: u64,
    pub evidence_valid_until: u64,
    pub evidence_observed_at: u64,
    pub evidence_revocation_checked_at: u64,
    pub evidence_revocation_fresh_until: u64,
}
/// Public construction and decoding represent only untrusted wire claims.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceChallengeClaims {
    pub application: ServiceApplication,
    pub issuer_node_id: String,
    pub issuer_key_id: String,
    pub audience: String,
    pub operation: String,
    pub resource: String,
    pub opcode: u8,
    pub request_length: u64,
    pub request_sha256: [u8; 32],
    pub schema_bundle_sha256: [u8; 32],
    pub descriptor_fingerprint: [u8; 32],
    pub handler_id: String,
    pub holder_subject_id: String,
    pub holder_key_id: String,
    pub holder_public_key_fingerprint: [u8; 32],
    pub receiver_policy_digest: [u8; 32],
    pub permission_policy_digest: [u8; 32],
    pub registry_snapshot_digest: [u8; 32],
    pub challenge_id: [u8; 32],
    pub session_id: [u8; 16],
    pub nonce: [u8; 12],
    pub ttl_seconds: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub evidence: ServiceEvidenceBindings,
}
impl core::fmt::Debug for ServiceChallengeClaims {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServiceChallengeClaims")
            .field("application", &self.application)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct UntrustedSignedServiceChallenge {
    pub claims: ServiceChallengeClaims,
    pub request_bytes: Vec<u8>,
    pub issuer_signature: [u8; 64],
}
#[derive(Clone, PartialEq, Eq)]
pub struct UntrustedServiceHolderProof {
    pub claims: ServiceChallengeClaims,
    pub issuer_signature: [u8; 64],
    pub holder_policy_digest: [u8; 32],
    pub holder_signature: [u8; 64],
}
// Diagnostics deliberately omit request/signature/transcript bytes.
impl core::fmt::Debug for UntrustedSignedServiceChallenge {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UntrustedSignedServiceChallenge")
            .field("application", &self.claims.application)
            .field("request_length", &self.claims.request_length)
            .finish_non_exhaustive()
    }
}
impl core::fmt::Debug for UntrustedServiceHolderProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UntrustedServiceHolderProof")
            .field("application", &self.claims.application)
            .finish_non_exhaustive()
    }
}
fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
fn text_valid(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
fn valid_operation(app: ServiceApplication, operation: &str, opcode: u8) -> bool {
    const RUNTIME: &[(&str, u8)] = &[
        ("process.draft.put", 0x40),
        ("process.publish", 0x41),
        ("run.create", 0x42),
        ("run.cancel", 0x43),
        ("run.retry", 0x44),
        ("artifact.put", 0x45),
        ("actor.register", 0x46),
        ("actor.advertise", 0x47),
        ("executor.claim", 0x48),
        ("executor.heartbeat", 0x49),
        ("executor.complete", 0x4a),
        ("executor.fail", 0x4b),
        ("executor.release", 0x4c),
        ("handoff.consume", 0x4d),
        ("executor.effect.intent", 0x4e),
        ("executor.effect.dispatch", 0x4f),
        ("executor.effect.observe", 0x50),
        ("effect.resolve", 0x51),
        ("process.get", 0x60),
        ("version.get", 0x61),
        ("run.get", 0x62),
        ("work.list", 0x63),
        ("events.list", 0x64),
        ("artifact.get", 0x65),
        ("receipt.get", 0x66),
        ("output.get", 0x67),
        ("effect.get", 0x68),
        ("attempt.get", 0x69),
    ];
    const SERVICE: &[&str] = &[
        "request.create",
        "request.qualify",
        "request.accept",
        "request.reject",
        "request.convert",
        "case.plan",
        "case.close",
        "case.plan.approve",
        "case.plan.revise",
        "request.execution",
        "case.summary",
        "case.plan-history",
    ];
    match app {
        ServiceApplication::RuntimeV1 => operation
            .strip_prefix("runtime.")
            .and_then(|x| x.strip_suffix(".v1"))
            .is_some_and(|raw| {
                RUNTIME
                    .iter()
                    .any(|(op, code)| *op == raw && *code == opcode)
            }),
        ServiceApplication::ServiceV1 => {
            opcode >= 0x40
                && operation
                    .strip_prefix("service.")
                    .and_then(|x| x.strip_suffix(".v1"))
                    .is_some_and(|raw| SERVICE.contains(&raw))
        }
    }
}
impl ServiceChallengeClaims {
    pub fn validate(&self) -> Result<(), CodecError> {
        if !text_valid(&self.issuer_node_id, 128) {
            return Err(CodecError::Malformed);
        }
        if !text_valid(&self.issuer_key_id, 128) {
            return Err(CodecError::Malformed);
        }
        if !text_valid(&self.audience, 200) {
            return Err(CodecError::Malformed);
        }
        if !text_valid(&self.operation, 200) {
            return Err(CodecError::Malformed);
        }
        if !text_valid(&self.resource, 1024) {
            return Err(CodecError::Malformed);
        }
        if !text_valid(&self.handler_id, 256) {
            return Err(CodecError::Malformed);
        }
        if !text_valid(&self.holder_subject_id, 128) {
            return Err(CodecError::Malformed);
        }
        if !text_valid(&self.holder_key_id, 128) {
            return Err(CodecError::Malformed);
        }
        if self.audience != self.application.audience()
            || !valid_operation(self.application, &self.operation, self.opcode)
            || self.handler_id.starts_with("dev/")
            || self.request_length == 0
            || self.request_length > self.application.max_request_bytes() as u64
            || self.session_id == [0; 16]
            || self.nonce == [0; 12]
            || self.challenge_id == [0; 32]
        {
            return Err(CodecError::InvalidBinding);
        }
        if self.issued_at == 0
            || self.expires_at > MAX_SAFE_TIME
            || !(1..=60).contains(&self.ttl_seconds)
            || self.issued_at.checked_add(self.ttl_seconds) != Some(self.expires_at)
        {
            return Err(CodecError::InvalidWindow);
        }
        let e = &self.evidence;
        if e.evidence_valid_not_before > self.issued_at
            || e.evidence_valid_until < self.expires_at
            || e.evidence_valid_until > MAX_SAFE_TIME
            || e.evidence_observed_at == 0
            || e.evidence_observed_at > self.issued_at
            || e.evidence_revocation_checked_at == 0
            || e.evidence_revocation_checked_at > self.issued_at
            || e.evidence_revocation_fresh_until < self.expires_at
            || e.evidence_revocation_fresh_until > MAX_SAFE_TIME
        {
            return Err(CodecError::InvalidWindow);
        }
        Ok(())
    }
}
fn field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
fn encode_claims(c: &ServiceChallengeClaims, out: &mut Vec<u8>) {
    field(out, "profile", PROFILE.as_bytes());
    field(out, "application", c.application.wire_id().as_bytes());
    field(out, "payload_mode", PAYLOAD_MODE.as_bytes());
    field(out, "issuer_node_id", c.issuer_node_id.as_bytes());
    field(out, "issuer_key_id", c.issuer_key_id.as_bytes());
    field(out, "audience", c.audience.as_bytes());
    field(out, "operation", c.operation.as_bytes());
    field(out, "resource", c.resource.as_bytes());
    field(out, "opcode", &[c.opcode]);
    field(out, "request_length", &c.request_length.to_be_bytes());
    field(out, "request_sha256", &c.request_sha256);
    field(out, "schema_bundle_sha256", &c.schema_bundle_sha256);
    field(out, "descriptor_fingerprint", &c.descriptor_fingerprint);
    field(out, "handler_id", c.handler_id.as_bytes());
    field(out, "holder_subject_id", c.holder_subject_id.as_bytes());
    field(out, "holder_key_id", c.holder_key_id.as_bytes());
    field(
        out,
        "holder_public_key_fingerprint",
        &c.holder_public_key_fingerprint,
    );
    field(out, "receiver_policy_digest", &c.receiver_policy_digest);
    field(out, "permission_policy_digest", &c.permission_policy_digest);
    field(out, "registry_snapshot_digest", &c.registry_snapshot_digest);
    field(
        out,
        "required_evidence_digest",
        &c.evidence.required_evidence_digest,
    );
    field(
        out,
        "evidence_snapshot_digest",
        &c.evidence.evidence_snapshot_digest,
    );
    field(
        out,
        "evidence_observations_digest",
        &c.evidence.evidence_observations_digest,
    );
    field(
        out,
        "evidence_adapter_profiles_digest",
        &c.evidence.evidence_adapter_profiles_digest,
    );
    field(
        out,
        "evidence_source_epoch_digest",
        &c.evidence.evidence_source_epoch_digest,
    );
    field(
        out,
        "evidence_valid_not_before",
        &c.evidence.evidence_valid_not_before.to_be_bytes(),
    );
    field(
        out,
        "evidence_valid_until",
        &c.evidence.evidence_valid_until.to_be_bytes(),
    );
    field(
        out,
        "evidence_observed_at",
        &c.evidence.evidence_observed_at.to_be_bytes(),
    );
    field(
        out,
        "evidence_revocation_checked_at",
        &c.evidence.evidence_revocation_checked_at.to_be_bytes(),
    );
    field(
        out,
        "evidence_revocation_fresh_until",
        &c.evidence.evidence_revocation_fresh_until.to_be_bytes(),
    );
    field(out, "challenge_id", &c.challenge_id);
    field(out, "session_id", &c.session_id);
    field(out, "nonce", &c.nonce);
    field(out, "ttl_seconds", &c.ttl_seconds.to_be_bytes());
    field(out, "issued_at", &c.issued_at.to_be_bytes());
    field(out, "expires_at", &c.expires_at.to_be_bytes());
}
struct Reader<'a> {
    rest: &'a [u8],
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], tag: &[u8]) -> Result<Self, CodecError> {
        Ok(Self {
            rest: bytes.strip_prefix(tag).ok_or(CodecError::Malformed)?,
        })
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if n > self.rest.len() {
            return Err(CodecError::Malformed);
        }
        let (a, b) = self.rest.split_at(n);
        self.rest = b;
        Ok(a)
    }
    fn field(&mut self, name: &str, max: usize) -> Result<&'a [u8], CodecError> {
        let n = u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| CodecError::Malformed)?,
        ) as usize;
        if n != name.len() || self.take(n)? != name.as_bytes() {
            return Err(CodecError::Malformed);
        }
        let n = u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| CodecError::Malformed)?,
        ) as usize;
        if n > max {
            return Err(CodecError::Oversized);
        }
        self.take(n)
    }
    fn fixed<const N: usize>(&mut self, name: &str) -> Result<[u8; N], CodecError> {
        self.field(name, N)?
            .try_into()
            .map_err(|_| CodecError::Malformed)
    }
    fn number(&mut self, name: &str) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.fixed(name)?))
    }
    fn text(&mut self, name: &str, max: usize) -> Result<String, CodecError> {
        Ok(String::from(
            core::str::from_utf8(self.field(name, max)?).map_err(|_| CodecError::Malformed)?,
        ))
    }
    fn constant(&mut self, name: &str, value: &str) -> Result<(), CodecError> {
        if self.field(name, value.len())? != value.as_bytes() {
            return Err(CodecError::Malformed);
        }
        Ok(())
    }
    fn finish(self) -> Result<(), CodecError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(CodecError::Malformed)
        }
    }
}
fn decode_claims(r: &mut Reader<'_>) -> Result<ServiceChallengeClaims, CodecError> {
    r.constant("profile", PROFILE)?;
    let application = match r.field("application", 10)? {
        b"runtime-v1" => ServiceApplication::RuntimeV1,
        b"service-v1" => ServiceApplication::ServiceV1,
        _ => return Err(CodecError::Malformed),
    };
    r.constant("payload_mode", PAYLOAD_MODE)?;
    let issuer_node_id = r.text("issuer_node_id", 128)?;
    let issuer_key_id = r.text("issuer_key_id", 128)?;
    let audience = r.text("audience", 200)?;
    let operation = r.text("operation", 200)?;
    let resource = r.text("resource", 1024)?;
    let opcode = r.fixed::<1>("opcode")?[0];
    let request_length = r.number("request_length")?;
    let request_sha256 = r.fixed("request_sha256")?;
    let schema_bundle_sha256 = r.fixed("schema_bundle_sha256")?;
    let descriptor_fingerprint = r.fixed("descriptor_fingerprint")?;
    let handler_id = r.text("handler_id", 256)?;
    let holder_subject_id = r.text("holder_subject_id", 128)?;
    let holder_key_id = r.text("holder_key_id", 128)?;
    let holder_public_key_fingerprint = r.fixed("holder_public_key_fingerprint")?;
    let receiver_policy_digest = r.fixed("receiver_policy_digest")?;
    let permission_policy_digest = r.fixed("permission_policy_digest")?;
    let registry_snapshot_digest = r.fixed("registry_snapshot_digest")?;
    let required_evidence_digest = r.fixed("required_evidence_digest")?;
    let evidence_snapshot_digest = r.fixed("evidence_snapshot_digest")?;
    let evidence_observations_digest = r.fixed("evidence_observations_digest")?;
    let evidence_adapter_profiles_digest = r.fixed("evidence_adapter_profiles_digest")?;
    let evidence_source_epoch_digest = r.fixed("evidence_source_epoch_digest")?;
    let evidence_valid_not_before = r.number("evidence_valid_not_before")?;
    let evidence_valid_until = r.number("evidence_valid_until")?;
    let evidence_observed_at = r.number("evidence_observed_at")?;
    let evidence_revocation_checked_at = r.number("evidence_revocation_checked_at")?;
    let evidence_revocation_fresh_until = r.number("evidence_revocation_fresh_until")?;
    let challenge_id = r.fixed("challenge_id")?;
    let session_id = r.fixed("session_id")?;
    let nonce = r.fixed("nonce")?;
    let ttl_seconds = r.number("ttl_seconds")?;
    let issued_at = r.number("issued_at")?;
    let expires_at = r.number("expires_at")?;
    let c = ServiceChallengeClaims {
        application,
        issuer_node_id,
        issuer_key_id,
        audience,
        operation,
        resource,
        opcode,
        request_length,
        request_sha256,
        schema_bundle_sha256,
        descriptor_fingerprint,
        handler_id,
        holder_subject_id,
        holder_key_id,
        holder_public_key_fingerprint,
        receiver_policy_digest,
        permission_policy_digest,
        registry_snapshot_digest,
        challenge_id,
        session_id,
        nonce,
        ttl_seconds,
        issued_at,
        expires_at,
        evidence: ServiceEvidenceBindings {
            required_evidence_digest,
            evidence_snapshot_digest,
            evidence_observations_digest,
            evidence_adapter_profiles_digest,
            evidence_source_epoch_digest,
            evidence_valid_not_before,
            evidence_valid_until,
            evidence_observed_at,
            evidence_revocation_checked_at,
            evidence_revocation_fresh_until,
        },
    };
    c.validate()?;
    Ok(c)
}
/// Exact fixed issuer transcript, including raw request bytes last. No JSON
/// reserialization or signing; application schema validation is native server work.
pub fn challenge_transcript(
    claims: &ServiceChallengeClaims,
    request: &[u8],
) -> Result<Vec<u8>, CodecError> {
    claims.validate()?;
    if request.len() as u64 != claims.request_length
        || hash(request) != claims.request_sha256
        || core::str::from_utf8(request).is_err()
    {
        return Err(CodecError::InvalidBinding);
    }
    let mut out = Vec::with_capacity(request.len() + 4096);
    out.extend_from_slice(CHALLENGE_DOMAIN);
    encode_claims(claims, &mut out);
    field(&mut out, "request_bytes", request);
    Ok(out)
}
pub fn holder_transcript(
    proof: &UntrustedServiceHolderProof,
    request: &[u8],
) -> Result<Vec<u8>, CodecError> {
    let challenge = challenge_transcript(&proof.claims, request)?;
    let mut out = Vec::with_capacity(challenge.len() + 160);
    out.extend_from_slice(HOLDER_DOMAIN);
    field(&mut out, "issuer_signature", &proof.issuer_signature);
    field(
        &mut out,
        "holder_policy_digest",
        &proof.holder_policy_digest,
    );
    out.extend_from_slice(&challenge);
    Ok(out)
}
impl UntrustedSignedServiceChallenge {
    pub fn encode_inner(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = challenge_transcript(&self.claims, &self.request_bytes)?;
        field(&mut out, "issuer_signature", &self.issuer_signature);
        if out.len() > self.claims.application.max_request_bytes() + MAX_PROOF_BYTES {
            return Err(CodecError::Oversized);
        }
        Ok(out)
    }
    pub fn decode_inner(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_RUNTIME_REQUEST_BYTES + MAX_PROOF_BYTES {
            return Err(CodecError::Oversized);
        }
        let mut r = Reader::new(bytes, CHALLENGE_DOMAIN)?;
        let claims = decode_claims(&mut r)?;
        let request_bytes = r
            .field("request_bytes", claims.application.max_request_bytes())?
            .to_vec();
        let issuer_signature = r.fixed("issuer_signature")?;
        r.finish()?;
        challenge_transcript(&claims, &request_bytes)?;
        Ok(Self {
            claims,
            request_bytes,
            issuer_signature,
        })
    }
}
impl UntrustedServiceHolderProof {
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.claims.validate()?;
        let mut out = Vec::with_capacity(4096);
        out.extend_from_slice(PROOF_TAG);
        encode_claims(&self.claims, &mut out);
        field(&mut out, "issuer_signature", &self.issuer_signature);
        field(&mut out, "holder_policy_digest", &self.holder_policy_digest);
        field(&mut out, "holder_signature", &self.holder_signature);
        if out.len() > MAX_PROOF_BYTES {
            return Err(CodecError::Oversized);
        }
        Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(CodecError::Oversized);
        }
        let mut r = Reader::new(bytes, PROOF_TAG)?;
        let claims = decode_claims(&mut r)?;
        let issuer_signature = r.fixed("issuer_signature")?;
        let holder_policy_digest = r.fixed("holder_policy_digest")?;
        let holder_signature = r.fixed("holder_signature")?;
        r.finish()?;
        Ok(Self {
            claims,
            issuer_signature,
            holder_policy_digest,
            holder_signature,
        })
    }
}
#[cfg(test)]
const CLAIM_FIELD_NAMES: &[&str] = &[
    "profile",
    "application",
    "payload_mode",
    "issuer_node_id",
    "issuer_key_id",
    "audience",
    "operation",
    "resource",
    "opcode",
    "request_length",
    "request_sha256",
    "schema_bundle_sha256",
    "descriptor_fingerprint",
    "handler_id",
    "holder_subject_id",
    "holder_key_id",
    "holder_public_key_fingerprint",
    "receiver_policy_digest",
    "permission_policy_digest",
    "registry_snapshot_digest",
    "required_evidence_digest",
    "evidence_snapshot_digest",
    "evidence_observations_digest",
    "evidence_adapter_profiles_digest",
    "evidence_source_epoch_digest",
    "evidence_valid_not_before",
    "evidence_valid_until",
    "evidence_observed_at",
    "evidence_revocation_checked_at",
    "evidence_revocation_fresh_until",
    "challenge_id",
    "session_id",
    "nonce",
    "ttl_seconds",
    "issued_at",
    "expires_at",
    "request_bytes",
];
#[cfg(test)]
#[path = "service_holder_proof_tests.rs"]
mod tests;
