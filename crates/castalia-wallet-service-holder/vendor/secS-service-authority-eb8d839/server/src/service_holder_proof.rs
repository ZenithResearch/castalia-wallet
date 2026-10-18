//! Verification-only additive service holder origin/binding guard. No signer,
//! custody, replay consumption, issuer, context or production readiness API.
//! Current pins must be independently owner-loaded; this module cannot attest
//! their provenance, coherent reload or qualified evidence freshness.
use crate::caller::CallerKey;
use crate::identity::{PublicVerifierKey, VerificationKeyStatus};
use crate::manifest::{ReceiverManifest, TargetKind};
use ed25519_dalek::Signature;
use libsec_core::service_holder_proof::{
    challenge_transcript, holder_transcript, ServiceApplication, ServiceChallengeClaims,
    ServiceEvidenceBindings, UntrustedServiceHolderProof, MAX_SAFE_TIME,
};
use libsec_core::ZenithPacket;
use secs_permissions::PermissionPolicy;
use secs_service_call_contract::{Application, ReceiverPolicy, ServiceIntent};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceProofError {
    InvalidWire,
    RegistryBound,
    UnknownOrAliasedKey,
    InvalidKey,
    InvalidWindow,
    NativeBinding,
    Denied,
    InvalidSignature,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidityWindow {
    pub not_before: u64,
    pub not_after: u64,
}
impl ValidityWindow {
    fn contains(self, c: &ServiceChallengeClaims, now: u64) -> bool {
        self.not_before < self.not_after
            && self.not_after <= MAX_SAFE_TIME
            && self.not_before <= c.issued_at
            && c.expires_at <= self.not_after
            && now >= self.not_before
            && now < self.not_after
    }
}
/// Owner public records only. A different node/ID cannot alias the same public
/// material in this initial service profile. Any duplicate or alias rejects
/// the whole constructor, including unrelated entries. Generic v1 stays unchanged.
#[derive(Clone, Debug)]
pub struct ServiceIssuerKey {
    pub node_id: String,
    pub key: PublicVerifierKey,
}
#[derive(Clone, Debug, Default)]
pub struct ServiceIssuerKeyRegistry {
    keys: HashMap<String, ServiceIssuerKey>,
}
#[derive(Clone, Debug, Default)]
pub struct ServiceHolderKeyRegistry {
    keys: HashMap<String, CallerKey>,
}
fn label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
impl ServiceIssuerKeyRegistry {
    pub fn from_keys(
        keys: impl IntoIterator<Item = ServiceIssuerKey>,
    ) -> Result<Self, ServiceProofError> {
        let mut registry = Self::default();
        let mut materials = HashMap::<[u8; 32], String>::new();
        for (index, key) in keys.into_iter().enumerate() {
            if index >= 32 || !label(&key.node_id) || !label(&key.key.key_id) {
                return Err(ServiceProofError::RegistryBound);
            }
            if registry.keys.contains_key(&key.key.key_id) {
                return Err(ServiceProofError::UnknownOrAliasedKey);
            }
            if materials
                .insert(key.key.public_key.to_bytes(), key.key.key_id.clone())
                .is_some()
            {
                return Err(ServiceProofError::UnknownOrAliasedKey);
            }
            registry.keys.insert(key.key.key_id.clone(), key);
        }
        Ok(registry)
    }
    pub fn get(&self, id: &str) -> Option<&ServiceIssuerKey> {
        self.keys.get(id)
    }
}
impl ServiceHolderKeyRegistry {
    /// Distinct active keys for one stable subject are permitted; repeated
    /// public material under different IDs or subjects and duplicate IDs deny.
    pub fn from_keys(keys: impl IntoIterator<Item = CallerKey>) -> Result<Self, ServiceProofError> {
        let mut registry = Self::default();
        let mut materials = HashMap::<[u8; 32], String>::new();
        for (index, key) in keys.into_iter().enumerate() {
            if index >= 32 || !label(&key.subject_id) || !label(&key.key_id) {
                return Err(ServiceProofError::RegistryBound);
            }
            if registry.keys.contains_key(&key.key_id) {
                return Err(ServiceProofError::UnknownOrAliasedKey);
            }
            if materials
                .insert(key.public_key.to_bytes(), key.key_id.clone())
                .is_some()
            {
                return Err(ServiceProofError::UnknownOrAliasedKey);
            }
            registry.keys.insert(key.key_id.clone(), key);
        }
        Ok(registry)
    }
    pub fn get(&self, id: &str) -> Option<&CallerKey> {
        self.keys.get(id)
    }
}
/// Independent, current native-owner inputs; never build these pins/windows
/// by copying untrusted proof fields. The future coherent snapshot/evidence
/// adapter and recorded challenge store must establish provenance and freshness.
/// Immutable borrowing is not a guard against external persistent-state change.
pub struct CurrentServiceProofState<'a> {
    pub application: ServiceApplication,
    pub issuer_node_id: &'a str,
    pub issuer_keys: &'a ServiceIssuerKeyRegistry,
    pub holder_keys: &'a ServiceHolderKeyRegistry,
    pub manifest: &'a ReceiverManifest,
    pub receiver_policy: &'a ReceiverPolicy,
    pub permissions: &'a PermissionPolicy,
    pub permission_policy_digest: [u8; 32],
    pub registry_snapshot_digest: [u8; 32],
    pub evidence: &'a ServiceEvidenceBindings,
    pub wallet_policy_digest: [u8; 32],
    pub wallet_validity: ValidityWindow,
    pub recorded_challenge_digest: [u8; 32],
}
/// Sealed successful cryptographic origin/binding result. Not an evidence
/// approval, execution permission, replay token or context-signing capability.
/// No Deserialize or public constructor. Claims are immutable after verification.
/// ```compile_fail
/// use server::service_holder_proof::AuthenticatedServiceHolder;
/// let forged = AuthenticatedServiceHolder { claims: panic!(), challenge_sha256: [0;32], packet_sha256: [0;32] };
/// ```
#[derive(Clone)]
pub struct AuthenticatedServiceHolder {
    claims: ServiceChallengeClaims,
    challenge_sha256: [u8; 32],
    packet_sha256: [u8; 32],
}
impl std::fmt::Debug for AuthenticatedServiceHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedServiceHolder")
            .field("application", &self.claims.application)
            .finish_non_exhaustive()
    }
}
impl AuthenticatedServiceHolder {
    pub fn claims(&self) -> &ServiceChallengeClaims {
        &self.claims
    }
    pub fn challenge_sha256(&self) -> [u8; 32] {
        self.challenge_sha256
    }
    pub fn packet_sha256(&self) -> [u8; 32] {
        self.packet_sha256
    }
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex_digest(text: &str) -> Result<[u8; 32], ServiceProofError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ServiceProofError::NativeBinding);
    }
    let mut out = [0; 32];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let hex = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        out[i] = (hex(pair[0]) << 4) | hex(pair[1]);
    }
    Ok(out)
}
fn native_application(app: ServiceApplication) -> Application {
    match app {
        ServiceApplication::RuntimeV1 => Application::Runtime,
        ServiceApplication::ServiceV1 => Application::Service,
    }
}
/// Frozen accepted public bundle: fixed domain; F(application, wire profile);
/// F(schema filename, SHA256(raw file)) in filename order; F(reader_profile,
/// secs-service-call-contract/v1); F(reader_source_sha256, exact static reader
/// source SHA256). F is the proof codec's u16BE/u32BE length-delimited field.
/// A schema OR static reader source change requires a new bundle and challenge.
pub fn schema_bundle_digest(app: ServiceApplication) -> [u8; 32] {
    let mut bytes = b"secs-service-public-contract-bundle-v1\0".to_vec();
    let mut field = |name: &str, value: &[u8]| {
        bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value);
    };
    field("application", app.wire_id().as_bytes());
    match app {
        ServiceApplication::RuntimeV1 => field(
            "runtime-v1.schema.json",
            &digest(include_bytes!(
                "../../crates/secs-service-call-contract/schemas/runtime-v1.schema.json"
            )),
        ),
        ServiceApplication::ServiceV1 => {
            field("service.command.v1.schema.json",&digest(include_bytes!("../../crates/secs-service-call-contract/schemas/service.command.v1.schema.json")));
            field(
                "service.query.v1.schema.json",
                &digest(include_bytes!(
                    "../../crates/secs-service-call-contract/schemas/service.query.v1.schema.json"
                )),
            );
        }
    }
    field("reader_profile", b"secs-service-call-contract/v1");
    field(
        "reader_source_sha256",
        &digest(include_bytes!(
            "../../crates/secs-service-call-contract/src/lib.rs"
        )),
    );
    digest(&bytes)
}
fn key_window(
    start: Option<u64>,
    end: Option<u64>,
    revoked_at: Option<u64>,
    c: &ServiceChallengeClaims,
    now: u64,
) -> Result<(), ServiceProofError> {
    let window = ValidityWindow {
        not_before: start.ok_or(ServiceProofError::InvalidWindow)?,
        not_after: end.ok_or(ServiceProofError::InvalidWindow)?,
    };
    if !window.contains(c, now) || revoked_at.is_some_and(|t| t < c.expires_at || t <= now) {
        return Err(ServiceProofError::InvalidWindow);
    }
    Ok(())
}
/// Verify against a coherent native-owner snapshot, with the actual final clock
/// supplied after blocking checks. Pure synchronous verification performs no I/O.
/// A successful result may be verified repeatedly: replay is NOT consumed here.
pub fn verify_service_holder_proof_v1(
    packet: &ZenithPacket,
    state: &CurrentServiceProofState<'_>,
    final_now: u64,
) -> Result<AuthenticatedServiceHolder, ServiceProofError> {
    let proof = UntrustedServiceHolderProof::decode(&packet.proof)
        .map_err(|_| ServiceProofError::InvalidWire)?;
    let c = &proof.claims;
    if c.application != state.application
        || c.issuer_node_id != state.issuer_node_id
        || packet.mac != [0; 16]
        || packet.session_id != c.session_id
        || packet.nonce != c.nonce
        || packet.opcode != c.opcode
        || packet.claim_ttl != c.ttl_seconds
    {
        return Err(ServiceProofError::NativeBinding);
    }
    if final_now < c.issued_at
        || final_now >= c.expires_at
        || !state.wallet_validity.contains(c, final_now)
    {
        return Err(ServiceProofError::InvalidWindow);
    }
    if c.schema_bundle_sha256 != schema_bundle_digest(c.application)
        || c.permission_policy_digest != state.permission_policy_digest
        || c.registry_snapshot_digest != state.registry_snapshot_digest
        || &c.evidence != state.evidence
        || proof.holder_policy_digest != state.wallet_policy_digest
    {
        return Err(ServiceProofError::NativeBinding);
    }
    let issuer = state
        .issuer_keys
        .get(&c.issuer_key_id)
        .ok_or(ServiceProofError::UnknownOrAliasedKey)?;
    let holder = state
        .holder_keys
        .get(&c.holder_key_id)
        .ok_or(ServiceProofError::UnknownOrAliasedKey)?;
    if issuer.node_id != c.issuer_node_id
        || issuer.key.status != VerificationKeyStatus::Active
        || issuer.key.algorithm != "ed25519"
        || !issuer.key.production_authority
        || issuer.key.replaced_by.is_some()
        || holder.subject_id != c.holder_subject_id
        || holder.status != VerificationKeyStatus::Active
        || holder.algorithm != "ed25519"
        || digest(holder.public_key.as_bytes()) != c.holder_public_key_fingerprint
    {
        return Err(ServiceProofError::InvalidKey);
    }
    // This profile also separates issuer and holder key purposes. Reuse of
    // public material anywhere across their owner registries fails closed.
    if state.issuer_keys.keys.values().any(|i| {
        state
            .holder_keys
            .keys
            .values()
            .any(|h| i.key.public_key == h.public_key)
    }) {
        return Err(ServiceProofError::InvalidKey);
    }
    key_window(
        issuer.key.not_before,
        issuer.key.not_after,
        issuer.key.revoked_at,
        c,
        final_now,
    )?;
    key_window(
        holder.not_before,
        holder.not_after,
        holder.revoked_at,
        c,
        final_now,
    )?;
    let intent = ServiceIntent::parse(native_application(c.application), &packet.encrypted_payload)
        .map_err(|_| ServiceProofError::NativeBinding)?;
    if intent.operation() != c.operation
        || intent.resource() != c.resource
        || hex_digest(intent.request_digest())? != c.request_sha256
    {
        return Err(ServiceProofError::NativeBinding);
    }
    let descriptor = state
        .manifest
        .lookup(c.opcode)
        .map_err(|_| ServiceProofError::NativeBinding)?;
    descriptor
        .validate()
        .map_err(|_| ServiceProofError::NativeBinding)?;
    if descriptor.name.as_str() != c.operation
        || descriptor.target_kind != TargetKind::ReceiverProductionHandler
        || descriptor.dev_binding
        || descriptor.handler_id != c.handler_id
        || descriptor.max_ttl_seconds < c.ttl_seconds
        || hex_digest(
            descriptor
                .authorization_fingerprint()
                .strip_prefix("descriptor:sha256:")
                .ok_or(ServiceProofError::NativeBinding)?,
        )? != c.descriptor_fingerprint
    {
        return Err(ServiceProofError::NativeBinding);
    }
    // Prepare current receiver policy against the entire immutable original
    // window, including future denies. Never accept a silently shortened TTL.
    let prepared = state
        .receiver_policy
        .prepare(
            &intent,
            &holder.subject_id,
            &holder.key_id,
            c.issued_at,
            c.ttl_seconds,
        )
        .map_err(|_| ServiceProofError::Denied)?;
    if prepared.expires_at() != c.expires_at
        || prepared.audience() != c.audience
        || prepared.opcode() != c.opcode
        || prepared.handler_id() != c.handler_id
        || hex_digest(prepared.descriptor_fingerprint())? != c.descriptor_fingerprint
        || hex_digest(prepared.policy_digest())? != c.receiver_policy_digest
    {
        return Err(ServiceProofError::NativeBinding);
    }
    // Permission timestamps are integer seconds. Exhaustive <=60-second
    // evaluation covers every future deny/allow gap in this exact window.
    for second in c.issued_at..c.expires_at {
        state
            .permissions
            .evaluate(
                &holder.subject_id,
                c.opcode,
                &c.operation,
                &c.resource,
                second,
            )
            .map_err(|_| ServiceProofError::Denied)?;
    }
    let challenge = challenge_transcript(c, &packet.encrypted_payload)
        .map_err(|_| ServiceProofError::NativeBinding)?;
    let challenge_sha256 = digest(&challenge);
    if challenge_sha256 != state.recorded_challenge_digest {
        return Err(ServiceProofError::NativeBinding);
    }
    issuer
        .key
        .public_key
        .verify_strict(&challenge, &Signature::from_bytes(&proof.issuer_signature))
        .map_err(|_| ServiceProofError::InvalidSignature)?;
    holder
        .public_key
        .verify_strict(
            &holder_transcript(&proof, &packet.encrypted_payload)
                .map_err(|_| ServiceProofError::InvalidWire)?,
            &Signature::from_bytes(&proof.holder_signature),
        )
        .map_err(|_| ServiceProofError::InvalidSignature)?;
    let packet_sha256 =
        digest(&bincode::serialize(packet).map_err(|_| ServiceProofError::InvalidWire)?);
    Ok(AuthenticatedServiceHolder {
        claims: proof.claims,
        challenge_sha256,
        packet_sha256,
    })
}
#[cfg(test)]
#[path = "service_holder_proof_tests.rs"]
mod tests;
