//! Isolated typed no-external-obligation preimages. Not a qualified evidence
//! adapter or execution capability; nonempty descriptor obligations always deny.
use crate::manifest::OperationDescriptor;
use libsec_core::service_holder_proof::{ServiceEvidenceBindings, MAX_SAFE_TIME};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceError {
    UnsupportedRequiredEvidence,
    InvalidWindow,
    Changed,
}
#[derive(Clone)]
pub(crate) struct EvidenceInput {
    pub owner: [u8; 32],
    pub descriptor: [u8; 32],
    pub subject: String,
    pub audience: String,
    pub operation: String,
    pub resource: String,
    pub request: [u8; 32],
    pub start: u64,
    pub end: u64,
    pub observed: u64,
}
/// Validated no-required-evidence data only. Cannot authorize signing/execution.
/// No Deserialize/public constructor; missing adapters cannot create this value.
pub struct PreparedNoRequiredEvidence {
    bytes: Vec<u8>,
    bindings: ServiceEvidenceBindings,
}
impl PreparedNoRequiredEvidence {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn bindings(&self) -> &ServiceEvidenceBindings {
        &self.bindings
    }
}
pub(crate) fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
fn encode(input: &EvidenceInput, source: [u8; 32]) -> PreparedNoRequiredEvidence {
    let mut required = b"secs-service-required-evidence-v1\0".to_vec();
    field(&mut required, "descriptor_fingerprint", &input.descriptor);
    field(&mut required, "kind", b"none");
    let mut profiles = b"secs-service-evidence-profiles-v1\0".to_vec();
    field(&mut profiles, "profile", b"secs-service-evidence-none-v1");
    field(&mut profiles, "verifier_source_sha256", &source);
    let mut epoch = b"secs-service-evidence-source-epoch-v1\0".to_vec();
    field(&mut epoch, "owner_bundle_sha256", &input.owner);
    let mut bindings = ServiceEvidenceBindings {
        required_evidence_digest: hash(&required),
        evidence_snapshot_digest: [0; 32],
        evidence_observations_digest: hash(b"secs-service-evidence-observations-v1\0"),
        evidence_adapter_profiles_digest: hash(&profiles),
        evidence_source_epoch_digest: hash(&epoch),
        evidence_valid_not_before: input.start,
        evidence_valid_until: input.end,
        evidence_observed_at: input.observed,
        evidence_revocation_checked_at: input.observed,
        evidence_revocation_fresh_until: input.end,
    };
    let mut bytes = b"secs-service-evidence-snapshot-v1\0".to_vec();
    for (name, value) in [
        ("kind", b"no_required_evidence".as_slice()),
        ("source_profile", b"secs-service-evidence-none-v1"),
        ("verifier_source_sha256", &source),
        ("owner_bundle_sha256", &input.owner),
        ("descriptor_fingerprint", &input.descriptor),
        ("subject", input.subject.as_bytes()),
        ("audience", input.audience.as_bytes()),
        ("operation", input.operation.as_bytes()),
        ("resource", input.resource.as_bytes()),
        ("request_sha256", &input.request),
        (
            "required_evidence_digest",
            &bindings.required_evidence_digest,
        ),
        (
            "evidence_observations_digest",
            &bindings.evidence_observations_digest,
        ),
        (
            "evidence_adapter_profiles_digest",
            &bindings.evidence_adapter_profiles_digest,
        ),
        (
            "evidence_source_epoch_digest",
            &bindings.evidence_source_epoch_digest,
        ),
    ] {
        field(&mut bytes, name, value);
    }
    for (name, value) in [
        ("valid_not_before", input.start),
        ("valid_until", input.end),
        ("observed_at", input.observed),
        ("revocation_checked_at", input.observed),
        ("revocation_fresh_until", input.end),
    ] {
        field(&mut bytes, name, &value.to_be_bytes());
    }
    bindings.evidence_snapshot_digest = hash(&bytes);
    PreparedNoRequiredEvidence { bytes, bindings }
}
pub(crate) fn prepare_none(
    descriptor: &OperationDescriptor,
    input: &EvidenceInput,
) -> Result<PreparedNoRequiredEvidence, EvidenceError> {
    if !descriptor.required_credentials.is_empty()
        || !descriptor.required_capabilities.is_empty()
        || !descriptor.accepted_evidence.is_empty()
        || descriptor.required_authority_mode.is_some()
    {
        return Err(EvidenceError::UnsupportedRequiredEvidence);
    }
    if input.observed == 0
        || input.start > input.observed
        || input.observed >= input.end
        || input.end > MAX_SAFE_TIME
    {
        return Err(EvidenceError::InvalidWindow);
    }
    Ok(encode(input, hash(include_bytes!("service_evidence.rs"))))
}
pub(crate) fn revalidate_none(
    descriptor: &OperationDescriptor,
    input: &EvidenceInput,
    original: &PreparedNoRequiredEvidence,
    now: u64,
) -> Result<(), EvidenceError> {
    if now < input.observed || now >= input.end {
        return Err(EvidenceError::InvalidWindow);
    }
    if prepare_none(descriptor, input)?.bytes != original.bytes {
        return Err(EvidenceError::Changed);
    }
    Ok(())
}
#[cfg(test)]
#[path = "service_evidence_tests.rs"]
mod tests;
