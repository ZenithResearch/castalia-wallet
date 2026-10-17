use super::*;
use alloc::{string::ToString, vec};

pub(super) fn sample_claims(request: &[u8]) -> ServiceChallengeClaims {
    ServiceChallengeClaims {
        application: ServiceApplication::RuntimeV1,
        issuer_node_id: "node:fixture".to_string(),
        issuer_key_id: "issuer:fixture".to_string(),
        audience: "runtime://receiver-local".to_string(),
        operation: "runtime.run.create.v1".to_string(),
        resource: "runs/run-1".to_string(),
        opcode: 0x42,
        request_length: request.len() as u64,
        request_sha256: hash(request),
        schema_bundle_sha256: [3; 32],
        descriptor_fingerprint: [4; 32],
        handler_id: "runtime/run.create.v1".to_string(),
        holder_subject_id: "holder:fixture".to_string(),
        holder_key_id: "holder:key".to_string(),
        holder_public_key_fingerprint: [5; 32],
        receiver_policy_digest: [6; 32],
        permission_policy_digest: [7; 32],
        registry_snapshot_digest: [8; 32],
        evidence: ServiceEvidenceBindings {
            required_evidence_digest: [9; 32],
            evidence_snapshot_digest: [10; 32],
            evidence_observations_digest: [11; 32],
            evidence_adapter_profiles_digest: [12; 32],
            evidence_source_epoch_digest: [13; 32],
            evidence_valid_not_before: 90,
            evidence_valid_until: 200,
            evidence_observed_at: 99,
            evidence_revocation_checked_at: 99,
            evidence_revocation_fresh_until: 200,
        },
        challenge_id: [14; 32],
        session_id: [15; 16],
        nonce: [16; 12],
        ttl_seconds: 60,
        issued_at: 100,
        expires_at: 160,
    }
}
fn proof(request: &[u8]) -> UntrustedServiceHolderProof {
    UntrustedServiceHolderProof {
        claims: sample_claims(request),
        issuer_signature: [17; 64],
        holder_policy_digest: [18; 32],
        holder_signature: [19; 64],
    }
}
#[test]
fn service_holder_codecs_roundtrip_exact_numeric_bytes() {
    let raw = br#"{"value":1.2300e+5,"large":184467440737095516160}"#;
    let p = proof(raw);
    let encoded = p.encode().unwrap();
    assert_eq!(UntrustedServiceHolderProof::decode(&encoded).unwrap(), p);
    let challenge = UntrustedSignedServiceChallenge {
        claims: p.claims.clone(),
        request_bytes: raw.to_vec(),
        issuer_signature: p.issuer_signature,
    };
    assert_eq!(
        UntrustedSignedServiceChallenge::decode_inner(&challenge.encode_inner().unwrap()).unwrap(),
        challenge
    );
    assert!(challenge_transcript(&p.claims, raw).unwrap().ends_with(raw));
    assert!(holder_transcript(&p, raw).unwrap().ends_with(raw));
    assert!(crate::caller_proof::decode_caller_proof(&encoded).is_none());
}
#[test]
fn service_holder_rejects_truncated_extended_duplicate_reordered_wire() {
    let p = proof(b"{}").encode().unwrap();
    for end in 0..p.len() {
        assert!(
            UntrustedServiceHolderProof::decode(&p[..end]).is_err(),
            "prefix {end}"
        );
    }
    let mut extra = p.clone();
    extra.push(0);
    assert!(UntrustedServiceHolderProof::decode(&extra).is_err());
    let mut huge = p.clone();
    huge.resize(MAX_PROOF_BYTES + 1, 0);
    assert!(UntrustedServiceHolderProof::decode(&huge).is_err());
    let mut name = p.clone();
    let pos = name.windows(7).position(|w| w == b"profile").unwrap();
    name[pos] = b'X';
    assert!(UntrustedServiceHolderProof::decode(&name).is_err());
    let mut duplicate = p.clone();
    duplicate.splice(
        PROOF_TAG.len()..PROOF_TAG.len(),
        p[PROOF_TAG.len()..PROOF_TAG.len() + 9].iter().copied(),
    );
    assert!(UntrustedServiceHolderProof::decode(&duplicate).is_err());
}
#[test]
fn service_holder_time_entropy_and_evidence_bounds() {
    let p = proof(b"{}");
    let mut bad = vec![];
    for ttl in [0, 61, u64::MAX] {
        let mut x = p.clone();
        x.claims.ttl_seconds = ttl;
        bad.push(x);
    }
    let mut x = p.clone();
    x.claims.session_id = [0; 16];
    bad.push(x);
    let mut x = p.clone();
    x.claims.nonce = [0; 12];
    bad.push(x);
    let mut x = p.clone();
    x.claims.challenge_id = [0; 32];
    bad.push(x);
    let mut x = p.clone();
    x.claims.expires_at = 159;
    bad.push(x);
    let mut x = p.clone();
    x.claims.issued_at = 0;
    bad.push(x);
    let mut x = p.clone();
    x.claims.evidence.evidence_valid_until = 159;
    bad.push(x);
    let mut x = p.clone();
    x.claims.evidence.evidence_revocation_fresh_until = 159;
    bad.push(x);
    let mut x = p.clone();
    x.claims.evidence.evidence_observed_at = 101;
    bad.push(x);
    let mut x = p.clone();
    x.claims.evidence.evidence_revocation_checked_at = 101;
    bad.push(x);
    let mut x = p.clone();
    x.claims.evidence.evidence_valid_not_before = 101;
    bad.push(x);
    let mut x = p.clone();
    x.claims.evidence.evidence_valid_until = MAX_SAFE_TIME + 1;
    bad.push(x);
    for x in bad {
        assert!(x.encode().is_err());
    }
}
#[test]
fn service_holder_closed_profile_limits_and_digest() {
    let p = proof(b"{}");
    let mut x = p.clone();
    x.claims.audience = "service-management".to_string();
    assert!(x.encode().is_err());
    let mut x = p.clone();
    x.claims.operation = "runtime.membership.provision.v1".to_string();
    assert!(x.encode().is_err());
    let mut x = p.clone();
    x.claims.opcode = 0x44;
    assert!(x.encode().is_err());
    let mut x = p.clone();
    x.claims.holder_key_id = "x".repeat(129);
    assert!(x.encode().is_err());
    let mut x = p.clone();
    x.claims.resource = "x".repeat(1025);
    assert!(x.encode().is_err());
    let mut x = p.clone();
    x.claims.handler_id = "dev/fixture".to_string();
    assert!(x.encode().is_err());
    let mut x = p.clone();
    x.claims.issuer_node_id = "bad\0name".to_string();
    assert!(x.encode().is_err());
    assert!(challenge_transcript(&p.claims, b"[]").is_err());
    let mut x = p.clone();
    x.claims.request_length = MAX_RUNTIME_REQUEST_BYTES as u64 + 1;
    assert!(x.encode().is_err());
    let mut x = p.clone();
    x.claims.application = ServiceApplication::ServiceV1;
    x.claims.audience = "service-management".to_string();
    x.claims.operation = "service.request.create.v1".to_string();
    x.claims.opcode = 0x79;
    assert!(x.encode().is_ok());
    x.claims.opcode = 0x0b;
    assert!(x.encode().is_err());
    x.claims.opcode = 0x79;
    x.claims.request_length = MAX_SERVICE_REQUEST_BYTES as u64 + 1;
    assert!(x.encode().is_err());
}
#[test]
fn service_holder_maximum_requests_preserved_without_duplicate_proof_payload() {
    let raw = vec![b' '; MAX_RUNTIME_REQUEST_BYTES];
    let p = proof(&raw);
    let transcript = challenge_transcript(&p.claims, &raw).unwrap();
    assert!(transcript.len() > MAX_RUNTIME_REQUEST_BYTES);
    assert!(p.encode().unwrap().len() < MAX_PROOF_BYTES);
    let challenge = UntrustedSignedServiceChallenge {
        claims: p.claims,
        request_bytes: raw.clone(),
        issuer_signature: p.issuer_signature,
    };
    assert_eq!(
        UntrustedSignedServiceChallenge::decode_inner(&challenge.encode_inner().unwrap())
            .unwrap()
            .request_bytes,
        raw
    );
}
#[test]
fn service_holder_every_signed_field_is_present_and_bound() {
    let raw = b"{}";
    let p = proof(raw);
    let challenge = challenge_transcript(&p.claims, raw).unwrap();
    let mut reader = Reader::new(&challenge, CHALLENGE_DOMAIN).unwrap();
    for name in CLAIM_FIELD_NAMES {
        assert!(
            !reader
                .field(name, MAX_RUNTIME_REQUEST_BYTES)
                .unwrap()
                .is_empty(),
            "{name}"
        );
    }
    assert!(reader.finish().is_ok());
    let holder = holder_transcript(&p, raw).unwrap();
    assert!(holder.starts_with(HOLDER_DOMAIN));
    let mut changed = p.clone();
    changed.holder_policy_digest[0] ^= 1;
    assert_ne!(holder, holder_transcript(&changed, raw).unwrap());
    changed = p.clone();
    changed.issuer_signature[0] ^= 1;
    assert_ne!(holder, holder_transcript(&changed, raw).unwrap());
}
