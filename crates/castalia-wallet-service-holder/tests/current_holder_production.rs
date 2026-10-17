//! External integration control: the Wallet library is compiled without cfg(test).
//! Disposable OS-generated holder custody plus PUBLIC issuer seed 41 only.
//! This is not Native issuance, current-evidence/context or installed qualification.
use castalia_wallet_service_holder::custody::{
    Application, NewServiceIdentity, ServiceIdentityStore,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use libsec_core::service_holder_proof::{
    challenge_transcript, holder_transcript, ServiceApplication, UntrustedServiceHolderProof,
    UntrustedSignedServiceChallenge, MAX_SAFE_TIME,
};
use secs_service_call_contract::{
    Application as ContractApplication, ReceiverPolicy, ServiceIntent,
};
use serde_json::{json, Value};
use server::{
    manifest::{OpcodeRange, OperationDescriptor, OperationName, ReplayScope, TargetKind},
    privacy::DisclosurePolicy,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    time::{SystemTime, UNIX_EPOCH},
};

fn clock() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!((1..=MAX_SAFE_TIME).contains(&now));
    now
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex32(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64);
    let mut out = [0; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap();
    }
    out
}
fn canonical(value: &Value) -> Vec<u8> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(fields) => Value::Object(
                fields
                    .iter()
                    .map(|(name, value)| (name.clone(), sorted(value)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(values) => Value::Array(values.iter().map(sorted).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&sorted(value)).unwrap()
}

#[test]
fn current_holder_works_through_public_non_test_library_api() {
    for app in [Application::Runtime, Application::Service] {
        let initial = clock();
        let root = tempfile::Builder::new()
            .prefix("wallet-holder-public-control-")
            .tempdir_in(std::env::temp_dir().canonicalize().unwrap())
            .unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = ServiceIdentityStore::create(
            root.path(),
            NewServiceIdentity {
                application: app,
                subject_id: "service:disposable-public-integration".into(),
                not_before: initial.checked_sub(300).unwrap(),
                not_after: initial.checked_add(3600).unwrap(),
            },
        )
        .unwrap();
        let public = store.public_identity().unwrap();
        let (wire_app, contract_app, app_name, fixture): (_, _, _, &[u8]) = match app {
            Application::Runtime => (ServiceApplication::RuntimeV1, ContractApplication::Runtime,
                "runtime", include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),
                "/vendor/secS-service-b/server/tests/fixtures/service-holder-proof-v1/challenge.bin"))),
            Application::Service => (ServiceApplication::ServiceV1, ContractApplication::Service,
                "service", include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),
                "/vendor/secS-service-b/server/tests/fixtures/service-holder-proof-v1/service/challenge.bin"))),
        };
        let mut challenge = UntrustedSignedServiceChallenge::decode_inner(fixture).unwrap();
        assert_eq!(challenge.claims.application, wire_app);
        let original_request = challenge.request_bytes.clone();
        let issuer = SigningKey::from_bytes(&[41; 32]); // Known PUBLIC fixture material.
        let issuer_node = "node:public-holder-integration";
        let issuer_key = "issuer:public-holder-integration";
        let handler = format!("fixture/{}", challenge.claims.operation);
        let descriptor = OperationDescriptor {
            opcode: challenge.claims.opcode,
            name: OperationName::new(challenge.claims.operation.clone()),
            payload_schema: Some("application/json".into()),
            output_profile: None,
            target_kind: TargetKind::ReceiverProductionHandler,
            required_credentials: vec![],
            required_capabilities: vec![],
            accepted_evidence: vec![],
            required_authority_mode: None,
            replay_scope: ReplayScope::SessionOpcodeNonce,
            max_ttl_seconds: 60,
            handler_id: handler.clone(),
            dev_binding: false,
            range: OpcodeRange::OperatorDefined,
            disclosure_policy: DisclosurePolicy::deny_by_default("fixture", 1),
        };
        let fingerprint = descriptor.authorization_fingerprint();
        let fingerprint = fingerprint.strip_prefix("descriptor:sha256:").unwrap();
        let mut owner: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/wallet-owner-input.fixture.json"
        )))
        .unwrap();
        owner["generation"] = json!(public.state_revision + 1);
        owner["application"] = json!(app_name);
        owner["valid_not_before"] = json!(public.not_before);
        owner["valid_until"] = json!(public.not_after);
        owner["issuer_node_id"] = json!(issuer_node);
        owner["selected_issuer_key_id"] = json!(issuer_key);
        owner["issuers"] = json!([{"node_id":issuer_node,"key_id":issuer_key,
            "public_key_hex":hex(issuer.verifying_key().as_bytes()),"algorithm":"ed25519",
            "status":"active","not_before":public.not_before,"not_after":public.not_after,
            "revoked_at":null,"replaced_by":null}]);
        owner["holder"] = json!({"subject_id":public.subject_id,"generation":public.key_generation,
            "key_id":public.key_id,"public_key_hex":public.public_key_hex,"algorithm":"ed25519",
            "status":"active","not_before":public.not_before,"not_after":public.not_after,
            "revoked_at":null,"replaced_by":null});
        owner["descriptors"] = json!([{"opcode":descriptor.opcode,"name":descriptor.name.as_str(),
            "payload_schema":"application/json","output_profile":null,
            "target_kind":"receiver_production_handler","required_credentials":[],
            "required_capabilities":[],"accepted_evidence":[],"required_authority_mode":null,
            "replay_scope":"session_opcode_nonce","max_ttl_seconds":60,"handler_id":handler,
            "dev_binding":false,"range":"operator_defined",
            "disclosure_policy":{"policy_id":"fixture","policy_version":1,"permissions":[]}}]);
        let policy = &mut owner["delegation_policy"];
        policy["application"] = json!(app_name);
        policy["audience"] = json!(wire_app.audience());
        policy["not_before"] = json!(public.not_before);
        policy["not_after"] = json!(public.not_after);
        policy["principals"] = json!([{"subject_id":public.subject_id,"key_id":public.key_id,
            "not_before":public.not_before,"not_after":public.not_after,"revoked":false}]);
        policy["descriptors"] = json!([{"operation":challenge.claims.operation,
            "opcode":descriptor.opcode,"fingerprint":fingerprint,"handler_id":handler,
            "max_ttl_seconds":60}]);
        for rule in policy["rules"].as_array_mut().unwrap() {
            rule["subject_id"] = json!(public.subject_id);
            rule["key_id"] = json!(public.key_id);
            rule["operation"] = json!(challenge.claims.operation);
            rule["resource"] = json!(challenge.claims.resource);
            rule["not_before"] = json!(if rule["effect"] == "deny" {
                initial + 1800
            } else {
                public.not_before
            });
            rule["not_after"] = json!(public.not_after);
        }
        let owner_bytes = canonical(&owner);
        let active = store.configure(public.expected(), &owner_bytes).unwrap();
        let handle = store.open_identity(active.expected()).unwrap();
        let issued = clock();
        let expires = issued.checked_add(60).unwrap();
        assert!(
            expires <= initial + 1800,
            "control must finish before its future deny"
        );
        challenge.claims.issuer_node_id = issuer_node.into();
        challenge.claims.issuer_key_id = issuer_key.into();
        challenge.claims.holder_subject_id = active.subject_id.clone();
        challenge.claims.holder_key_id = active.key_id.clone();
        challenge.claims.holder_public_key_fingerprint = unhex32(&active.public_key_sha256);
        challenge.claims.descriptor_fingerprint = unhex32(fingerprint);
        challenge.claims.handler_id = handler;
        challenge.claims.issued_at = issued;
        challenge.claims.expires_at = expires;
        challenge.claims.ttl_seconds = 60;
        challenge.claims.request_length = original_request.len() as u64;
        challenge.claims.request_sha256 = Sha256::digest(&original_request).into();
        // Only rebase signed fixture horizons; Native evidence digests stay opaque.
        challenge.claims.evidence.evidence_valid_not_before = active.not_before;
        challenge.claims.evidence.evidence_valid_until = expires;
        challenge.claims.evidence.evidence_observed_at = issued;
        challenge.claims.evidence.evidence_revocation_checked_at = issued;
        challenge.claims.evidence.evidence_revocation_fresh_until = expires;
        let issuer_transcript = challenge_transcript(&challenge.claims, &original_request).unwrap();
        challenge.issuer_signature = issuer.sign(&issuer_transcript).to_bytes();
        issuer
            .verifying_key()
            .verify_strict(
                &issuer_transcript,
                &Signature::from_bytes(&challenge.issuer_signature),
            )
            .unwrap();
        let expected_claims = challenge.claims.clone();
        let expected_signature = challenge.issuer_signature;
        let intent = ServiceIntent::parse(contract_app, &original_request).unwrap();
        assert_eq!(intent.operation(), expected_claims.operation);
        assert_eq!(intent.resource(), expected_claims.resource);
        let policy_bytes = canonical(&owner["delegation_policy"]);
        let policy = ReceiverPolicy::parse(&policy_bytes).unwrap();
        let prepared = policy
            .prepare(&intent, &active.subject_id, &active.key_id, issued, 60)
            .unwrap();
        assert_eq!(prepared.expires_at(), expires);
        let expected_policy: [u8; 32] = Sha256::digest(&policy_bytes).into();
        assert_eq!(unhex32(prepared.policy_digest()), expected_policy);
        let encoded = handle
            .present_current_service_challenge(&challenge)
            .unwrap();
        let proof = UntrustedServiceHolderProof::decode(&encoded).unwrap();
        assert!(encoded.len() <= 16_384);
        assert_eq!(proof.claims, expected_claims);
        assert_eq!(proof.issuer_signature, expected_signature);
        assert_eq!(proof.holder_policy_digest, expected_policy);
        assert_eq!(challenge.request_bytes, original_request);
        let holder_public = VerifyingKey::from_bytes(&unhex32(&active.public_key_hex)).unwrap();
        holder_public
            .verify_strict(
                &holder_transcript(&proof, &original_request).unwrap(),
                &Signature::from_bytes(&proof.holder_signature),
            )
            .unwrap();
        assert_eq!(
            handle
                .present_current_service_challenge(&challenge)
                .unwrap(),
            encoded
        );
        assert_eq!(
            (proof.claims.issued_at, proof.claims.expires_at),
            (issued, expires)
        );
    }
}
