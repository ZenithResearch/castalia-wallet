//! Disposable codec controls only. These child-only constructors are excluded
//! from production and create neither authority guards nor journal state.
use super::*;
use libsec_core::service_holder_proof::{
    challenge_transcript, ServiceChallengeClaims, UntrustedSignedServiceChallenge,
};
fn binding(policy: &HeldNativePolicy<'_, '_>, window: OriginalServiceWindow) -> SigningBinding {
    let i = policy.selected_issuer(window).unwrap();
    SigningBinding {
        lineage: policy.lineage(),
        application: policy.application(),
        node: i.node_id.clone(),
        key: i.key.key_id.clone(),
        public: i.key.public_key.to_bytes(),
        window,
    }
}
fn frozen_challenge(application: ServiceApplication) -> UntrustedSignedServiceChallenge {
    let raw: &[u8] = match application {
        ServiceApplication::RuntimeV1 => {
            include_bytes!("../tests/fixtures/service-holder-proof-v1/challenge.bin")
        }
        ServiceApplication::ServiceV1 => {
            include_bytes!("../tests/fixtures/service-holder-proof-v1/service/challenge.bin")
        }
    };
    let challenge = UntrustedSignedServiceChallenge::decode_inner(raw).unwrap();
    assert_eq!(challenge.claims.application, application);
    assert_eq!(challenge.claims.audience, application.audience());
    challenge
}
pub(crate) fn challenge_codec_fixture(
    policy: &HeldNativePolicy<'_, '_>,
    window: OriginalServiceWindow,
) -> (
    ServiceChallengeSignaturePreimage,
    ServiceChallengeClaims,
    Vec<u8>,
) {
    let original = frozen_challenge(policy.application());
    let mut claims = original.claims;
    let b = binding(policy, window);
    claims.issuer_node_id = b.node.clone();
    claims.issuer_key_id = b.key.clone();
    claims.issued_at = window.issued_at();
    claims.expires_at = window.expires_at();
    claims.ttl_seconds = window.expires_at() - window.issued_at();
    claims.evidence.evidence_valid_not_before = window.issued_at() - 1;
    claims.evidence.evidence_valid_until = window.expires_at();
    claims.evidence.evidence_observed_at = window.issued_at() - 1;
    claims.evidence.evidence_revocation_checked_at = window.issued_at() - 1;
    claims.evidence.evidence_revocation_fresh_until = window.expires_at();
    let transcript = challenge_transcript(&claims, &original.request_bytes).unwrap();
    (
        ServiceChallengeSignaturePreimage {
            binding: b,
            transcript,
        },
        claims,
        original.request_bytes,
    )
}
pub(crate) fn context_codec_fixture(
    policy: &HeldNativePolicy<'_, '_>,
    window: OriginalServiceWindow,
) -> PreparedServiceContext {
    // App-matching frozen codec data only: no production authority, holder
    // validation, journal state or qualified owner/evidence construction.
    let original = frozen_challenge(policy.application());
    let claims = original.claims;
    let packet = libsec_core::ZenithPacket {
        session_id: claims.session_id,
        nonce: claims.nonce,
        opcode: claims.opcode,
        proof: vec![],
        claim_ttl: window.expires_at() - window.issued_at(),
        encrypted_payload: original.request_bytes,
        mac: [0; 16],
    };
    let packet_hash = crate::service_wallet_source::hash(&bincode::serialize(&packet).unwrap());
    PreparedServiceContext {
        binding: binding(policy, window),
        context: VerifiedCallContext {
            schema_version: VERIFIED_CALL_CONTEXT_SCHEMA_VERSION,
            context_id: "ni02-codec-fixture".into(),
            packet_hash,
            session_id: packet.session_id,
            nonce: packet.nonce,
            opcode: packet.opcode,
            operation: claims.operation,
            resource: Some(claims.resource),
            subject: crate::verifier::VerifiedSubject {
                subject_id: claims.holder_subject_id,
                key_id: claims.holder_key_id,
            },
            audience: policy.application().audience().into(),
            evidence_summary: vec![],
            proof_metadata: None,
            capability_result: "fixture-only".into(),
            credential_result: "fixture-only".into(),
            issued_at: window.issued_at(),
            expires_at: window.expires_at(),
            descriptor_fingerprint: format!(
                "descriptor:sha256:{}",
                crate::service_wallet_source::hex(&claims.descriptor_fingerprint)
            ),
            replay_scope: "session_opcode_nonce".into(),
            handler_id: Some(claims.handler_id),
        },
    }
}
#[test]
fn window_is_only_bounded_original_data() {
    for (start, end) in [
        (0, 1),
        (10, 10),
        (10, 9),
        (10, 71),
        (MAX_SAFE_TIME, MAX_SAFE_TIME + 1),
    ] {
        assert!(OriginalServiceWindow::new(start, end).is_none());
    }
    assert!(OriginalServiceWindow::new(10, 70).is_some());
}
