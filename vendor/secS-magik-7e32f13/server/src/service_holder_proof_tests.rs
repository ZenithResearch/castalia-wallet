use super::*;
use crate::caller::CallerKeyRegistry;
use crate::manifest::{OpcodeRange, OperationDescriptor, OperationName, ReplayScope};
use crate::privacy::DisclosurePolicy;
use ed25519_dalek::{Signer, SigningKey};
use libsec_core::service_holder_proof::{holder_transcript, UntrustedSignedServiceChallenge};
use secs_permissions::{
    AuthoritySource, PermissionEffect, PermissionRecord, PermissionStatus, ResourceScope,
};
use serde_json::json;
// Public disposable fixture seeds ONLY under cfg(test). Never production keys.
struct Fixture {
    packet: ZenithPacket,
    claims: ServiceChallengeClaims,
    issuers: ServiceIssuerKeyRegistry,
    holders: ServiceHolderKeyRegistry,
    manifest: ReceiverManifest,
    policy: ReceiverPolicy,
    permissions: PermissionPolicy,
    evidence: ServiceEvidenceBindings,
    issuer: SigningKey,
    holder: SigningKey,
}
impl Fixture {
    fn new(application: ServiceApplication) -> Self {
        let issuer = SigningKey::from_bytes(&[41; 32]);
        let holder = SigningKey::from_bytes(&[42; 32]);
        let (operation,resource,opcode,raw)=match application {
            ServiceApplication::RuntimeV1=>("runtime.run.create.v1","runs/run-1",0x42,format!(r#"{{ "schema":"runtime.command.v1", "operation":"run.create", "request_id":"fixture", "resource":"runs/run-1", "expected_version":null, "payload":{{ "run_id":"run-1", "pin":{{ "process_id":"p", "process_version":"v", "compilation_hash":"{}" }}, "inputs":{{ "decimal":1.2300e+5,"large":184467440737095516160,"nul":"\u0000" }} }} }}"#,"a".repeat(64)).into_bytes()),
            ServiceApplication::ServiceV1=>("service.request.create.v1","requests/request-1",0x79,include_bytes!("../../crates/secs-service-call-contract/tests/fixtures/service-create.json").to_vec()),
        };
        let descriptor = OperationDescriptor {
            opcode,
            name: OperationName::new(operation),
            payload_schema: Some("application/json".into()),
            output_profile: None,
            target_kind: TargetKind::ReceiverProductionHandler,
            required_credentials: vec!["fixture.credential".into()],
            required_capabilities: vec![],
            accepted_evidence: vec!["fixture.evidence".into()],
            required_authority_mode: None,
            replay_scope: ReplayScope::SessionOpcodeNonce,
            max_ttl_seconds: 60,
            handler_id: format!("fixture/{operation}"),
            dev_binding: false,
            range: OpcodeRange::OperatorDefined,
            disclosure_policy: DisclosurePolicy::deny_by_default("fixture", 1),
        };
        let fp = descriptor
            .authorization_fingerprint()
            .strip_prefix("descriptor:sha256:")
            .unwrap()
            .to_owned();
        let handler = descriptor.handler_id.clone();
        let policy=ReceiverPolicy::parse(&serde_json::to_vec(&json!({"schema":"secs.service-receiver-policy.v1","application":if application==ServiceApplication::RuntimeV1{"runtime"}else{"service"},"audience":application.audience(),"not_before":90,"not_after":200,"max_ttl_seconds":60,"principals":[{"subject_id":"holder:fixture","key_id":"holder:key","not_before":90,"not_after":200,"revoked":false}],"descriptors":[{"operation":operation,"opcode":opcode,"fingerprint":fp,"handler_id":handler,"max_ttl_seconds":60}],"rules":[{"subject_id":"holder:fixture","key_id":"holder:key","operation":operation,"resource":resource,"resource_match":"exact","effect":"allow","not_before":90,"not_after":200,"active":true}]})).unwrap()).unwrap();
        let intent = ServiceIntent::parse(native_application(application), &raw).unwrap();
        assert_eq!(intent.resource(), resource);
        let prepared = policy
            .prepare(&intent, "holder:fixture", "holder:key", 100, 60)
            .unwrap();
        let evidence = ServiceEvidenceBindings {
            required_evidence_digest: [1; 32],
            evidence_snapshot_digest: [2; 32],
            evidence_observations_digest: [3; 32],
            evidence_adapter_profiles_digest: [4; 32],
            evidence_source_epoch_digest: [5; 32],
            evidence_valid_not_before: 90,
            evidence_valid_until: 200,
            evidence_observed_at: 99,
            evidence_revocation_checked_at: 99,
            evidence_revocation_fresh_until: 200,
        };
        let claims = ServiceChallengeClaims {
            application,
            issuer_node_id: "node:fixture".into(),
            issuer_key_id: "issuer:key".into(),
            audience: application.audience().into(),
            operation: operation.into(),
            resource: resource.into(),
            opcode,
            request_length: raw.len() as u64,
            request_sha256: digest(&raw),
            schema_bundle_sha256: schema_bundle_digest(application),
            descriptor_fingerprint: hex_digest(&fp).unwrap(),
            handler_id: handler,
            holder_subject_id: "holder:fixture".into(),
            holder_key_id: "holder:key".into(),
            holder_public_key_fingerprint: digest(holder.verifying_key().as_bytes()),
            receiver_policy_digest: hex_digest(prepared.policy_digest()).unwrap(),
            permission_policy_digest: [7; 32],
            registry_snapshot_digest: [8; 32],
            evidence: evidence.clone(),
            challenge_id: [14; 32],
            session_id: [15; 16],
            nonce: [16; 12],
            ttl_seconds: 60,
            issued_at: 100,
            expires_at: 160,
        };
        let issuer_signature = issuer
            .sign(&challenge_transcript(&claims, &raw).unwrap())
            .to_bytes();
        let mut proof = UntrustedServiceHolderProof {
            claims: claims.clone(),
            issuer_signature,
            holder_policy_digest: [18; 32],
            holder_signature: [0; 64],
        };
        proof.holder_signature = holder
            .sign(&holder_transcript(&proof, &raw).unwrap())
            .to_bytes();
        let packet = ZenithPacket {
            session_id: claims.session_id,
            nonce: claims.nonce,
            opcode,
            proof: proof.encode().unwrap(),
            claim_ttl: 60,
            encrypted_payload: raw,
            mac: [0; 16],
        };
        let issuers = ServiceIssuerKeyRegistry::from_keys([ServiceIssuerKey {
            node_id: "node:fixture".into(),
            key: PublicVerifierKey::configured_production_authority(
                "issuer:key",
                "ed25519",
                issuer.verifying_key(),
            )
            .with_validity_window(Some(90), Some(200)),
        }])
        .unwrap();
        let holders = ServiceHolderKeyRegistry::from_keys([CallerKey::active(
            "holder:key",
            "holder:fixture",
            holder.verifying_key(),
        )
        .with_validity_window(Some(90), Some(200))])
        .unwrap();
        let permissions =
            PermissionPolicy::new([grant(&claims, PermissionEffect::Allow, 90, 200)]).unwrap();
        Self {
            packet,
            claims,
            issuers,
            holders,
            manifest: ReceiverManifest::new([descriptor]),
            policy,
            permissions,
            evidence,
            issuer,
            holder,
        }
    }
    fn state(&self) -> CurrentServiceProofState<'_> {
        CurrentServiceProofState {
            application: self.claims.application,
            issuer_node_id: "node:fixture",
            issuer_keys: &self.issuers,
            holder_keys: &self.holders,
            manifest: &self.manifest,
            receiver_policy: &self.policy,
            permissions: &self.permissions,
            permission_policy_digest: [7; 32],
            registry_snapshot_digest: [8; 32],
            evidence: &self.evidence,
            wallet_policy_digest: [18; 32],
            wallet_validity: ValidityWindow {
                not_before: 90,
                not_after: 200,
            },
            recorded_challenge_digest: digest(
                &challenge_transcript(&self.claims, &self.packet.encrypted_payload).unwrap(),
            ),
        }
    }
    fn resign(&mut self, claims: ServiceChallengeClaims) {
        let raw = &self.packet.encrypted_payload;
        let issuer_signature = self
            .issuer
            .sign(&challenge_transcript(&claims, raw).unwrap())
            .to_bytes();
        let mut p = UntrustedServiceHolderProof {
            claims,
            issuer_signature,
            holder_policy_digest: [18; 32],
            holder_signature: [0; 64],
        };
        p.holder_signature = self
            .holder
            .sign(&holder_transcript(&p, raw).unwrap())
            .to_bytes();
        self.packet.proof = p.encode().unwrap();
    }
}
fn grant(
    c: &ServiceChallengeClaims,
    effect: PermissionEffect,
    start: u64,
    end: u64,
) -> PermissionRecord {
    PermissionRecord {
        caller_id: c.holder_subject_id.clone(),
        opcode: c.opcode,
        operation: c.operation.clone(),
        resource: ResourceScope::Exact {
            value: c.resource.clone(),
        },
        effect,
        not_before: start,
        not_after: end,
        status: PermissionStatus::Active,
        authority_source: AuthoritySource::ReceiverLocal,
    }
}
#[test]
fn service_holder_valid_native_origin_for_both_profiles() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app);
        let authenticated = verify_service_holder_proof_v1(&f.packet, &f.state(), 101).unwrap();
        assert_eq!(authenticated.claims(), &f.claims);
        assert_eq!(
            authenticated.packet_sha256(),
            digest(&bincode::serialize(&f.packet).unwrap())
        );
        assert!(verify_service_holder_proof_v1(&f.packet, &f.state(), 100).is_ok());
        assert!(verify_service_holder_proof_v1(&f.packet, &f.state(), 160).is_err());
        assert!(verify_service_holder_proof_v1(&f.packet, &f.state(), 99).is_err());
        assert!(
            crate::caller::verify_caller_proof(&f.packet, &CallerKeyRegistry::default(), 101)
                .is_err()
        );
    }
}
#[test]
fn service_holder_packet_mutations_fail() {
    let f = Fixture::new(ServiceApplication::RuntimeV1);
    for change in 0..6 {
        let mut p = f.packet.clone();
        match change {
            0 => p.mac[0] = 1,
            1 => p.session_id[0] ^= 1,
            2 => p.nonce[0] ^= 1,
            3 => p.opcode ^= 1,
            4 => p.claim_ttl -= 1,
            _ => p.encrypted_payload.push(b' '),
        }
        assert!(verify_service_holder_proof_v1(&p, &f.state(), 101).is_err());
    }
    let mut p = f.packet.clone();
    let end = p.proof.len() - 1;
    p.proof[end] ^= 1;
    assert!(verify_service_holder_proof_v1(&p, &f.state(), 101).is_err());
}
#[test]
fn service_holder_whole_window_current_evidence_and_native_pins_required() {
    let f = Fixture::new(ServiceApplication::RuntimeV1);
    let mut state = f.state();
    state.wallet_validity.not_after = 105;
    assert!(verify_service_holder_proof_v1(&f.packet, &state, 101).is_err());
    let mut state = f.state();
    state.registry_snapshot_digest[0] ^= 1;
    assert!(verify_service_holder_proof_v1(&f.packet, &state, 101).is_err());
    let mut state = f.state();
    state.permission_policy_digest[0] ^= 1;
    assert!(verify_service_holder_proof_v1(&f.packet, &state, 101).is_err());
    let mut state = f.state();
    state.wallet_policy_digest[0] ^= 1;
    assert!(verify_service_holder_proof_v1(&f.packet, &state, 101).is_err());
    let mut state = f.state();
    state.recorded_challenge_digest[0] ^= 1;
    assert!(verify_service_holder_proof_v1(&f.packet, &state, 101).is_err());
    for field in 0..5 {
        let mut e = f.evidence.clone();
        match field {
            0 => e.evidence_snapshot_digest[0] ^= 1,
            1 => e.evidence_observations_digest[0] ^= 1,
            2 => e.evidence_adapter_profiles_digest[0] ^= 1,
            3 => e.evidence_source_epoch_digest[0] ^= 1,
            _ => e.required_evidence_digest[0] ^= 1,
        };
        let mut state = f.state();
        state.evidence = &e;
        assert!(verify_service_holder_proof_v1(&f.packet, &state, 101).is_err());
    }
    let mut e = f.evidence.clone();
    e.evidence_valid_until = 105;
    let mut state = f.state();
    state.evidence = &e;
    assert!(verify_service_holder_proof_v1(&f.packet, &state, 101).is_err());
}
#[test]
fn service_holder_actual_permission_future_deny_and_gap_fail() {
    let mut f = Fixture::new(ServiceApplication::RuntimeV1);
    f.permissions = PermissionPolicy::new([
        grant(&f.claims, PermissionEffect::Allow, 90, 200),
        grant(&f.claims, PermissionEffect::Deny, 120, 121),
    ])
    .unwrap();
    assert!(verify_service_holder_proof_v1(&f.packet, &f.state(), 101).is_err());
    f.permissions = PermissionPolicy::new([
        grant(&f.claims, PermissionEffect::Allow, 90, 120),
        grant(&f.claims, PermissionEffect::Allow, 121, 200),
    ])
    .unwrap();
    assert!(verify_service_holder_proof_v1(&f.packet, &f.state(), 101).is_err());
}
#[test]
fn service_holder_key_alias_duplicate_rotation_and_subject_semantics() {
    let f = Fixture::new(ServiceApplication::RuntimeV1);
    let key = f.holders.get("holder:key").unwrap().clone();
    for alias in [
        key.clone(),
        CallerKey {
            key_id: "alias".into(),
            subject_id: "other:subject".into(),
            ..key.clone()
        },
        CallerKey {
            public_key: SigningKey::from_bytes(&[44; 32]).verifying_key(),
            ..key.clone()
        },
    ] {
        let unrelated = CallerKey {
            key_id: "unrelated".into(),
            public_key: SigningKey::from_bytes(&[45; 32]).verifying_key(),
            ..key.clone()
        };
        assert!(ServiceHolderKeyRegistry::from_keys([key.clone(), alias, unrelated]).is_err());
    }
    let distinct = CallerKey {
        key_id: "rotation:key".into(),
        public_key: SigningKey::from_bytes(&[43; 32]).verifying_key(),
        ..key.clone()
    };
    let holders = ServiceHolderKeyRegistry::from_keys([key.clone(), distinct]).unwrap();
    let mut s = f.state();
    s.holder_keys = &holders;
    assert!(verify_service_holder_proof_v1(&f.packet, &s, 101).is_ok());
    let issuer = f.issuers.get("issuer:key").unwrap().clone();
    for alias in [
        issuer.clone(),
        ServiceIssuerKey {
            node_id: "node:alias".into(),
            key: PublicVerifierKey {
                key_id: "issuer:alias".into(),
                ..issuer.key.clone()
            },
        },
        ServiceIssuerKey {
            key: PublicVerifierKey {
                public_key: SigningKey::from_bytes(&[44; 32]).verifying_key(),
                ..issuer.key.clone()
            },
            ..issuer.clone()
        },
    ] {
        let unrelated = ServiceIssuerKey {
            node_id: "node:unrelated".into(),
            key: PublicVerifierKey {
                key_id: "issuer:unrelated".into(),
                public_key: SigningKey::from_bytes(&[45; 32]).verifying_key(),
                ..issuer.key.clone()
            },
        };
        assert!(ServiceIssuerKeyRegistry::from_keys([issuer.clone(), alias, unrelated]).is_err());
    }
    let mut replaced = issuer.clone();
    replaced.key.replaced_by = Some("new:key".into());
    let issuers = ServiceIssuerKeyRegistry::from_keys([replaced]).unwrap();
    let mut s = f.state();
    s.issuer_keys = &issuers;
    assert!(verify_service_holder_proof_v1(&f.packet, &s, 101).is_err());
    assert!(ServiceHolderKeyRegistry::from_keys(vec![key; 33]).is_err());
    assert!(ServiceIssuerKeyRegistry::from_keys(vec![issuer; 33]).is_err());
}
#[test]
fn service_holder_explicit_exclusive_key_windows_status_suite_and_issuer() {
    let f = Fixture::new(ServiceApplication::RuntimeV1);
    let base = f.holders.get("holder:key").unwrap().clone();
    for variant in 0..7 {
        let mut k = base.clone();
        match variant {
            0 => k.status = VerificationKeyStatus::Revoked,
            1 => k.not_after = Some(101),
            2 => k.not_after = Some(159),
            3 => k.not_before = Some(101),
            4 => k.revoked_at = Some(150),
            5 => k.not_after = None,
            _ => k.algorithm = "other".into(),
        };
        let holders = ServiceHolderKeyRegistry::from_keys([k]).unwrap();
        let mut state = f.state();
        state.holder_keys = &holders;
        assert!(verify_service_holder_proof_v1(&f.packet, &state, 101).is_err());
    }
    let base = f.issuers.get("issuer:key").unwrap().clone();
    for variant in 0..7 {
        let mut k = base.clone();
        match variant {
            0 => k.key.status = VerificationKeyStatus::Expired,
            1 => k.key.not_after = Some(101),
            2 => k.key.not_after = Some(159),
            3 => k.key.not_before = None,
            4 => k.key.revoked_at = Some(150),
            5 => k.key.production_authority = false,
            _ => k.node_id = "wrong:node".into(),
        };
        let issuers = ServiceIssuerKeyRegistry::from_keys([k]).unwrap();
        let mut state = f.state();
        state.issuer_keys = &issuers;
        assert!(verify_service_holder_proof_v1(&f.packet, &state, 101).is_err());
    }
}
#[test]
fn service_holder_signed_bindings_cannot_select_native_state() {
    let mut f = Fixture::new(ServiceApplication::RuntimeV1);
    for field in 0..8 {
        let mut c = f.claims.clone();
        match field {
            0 => c.schema_bundle_sha256[0] ^= 1,
            1 => c.descriptor_fingerprint[0] ^= 1,
            2 => c.handler_id = "other/handler".into(),
            3 => c.holder_public_key_fingerprint[0] ^= 1,
            4 => c.issuer_node_id = "other:node".into(),
            5 => c.receiver_policy_digest[0] ^= 1,
            6 => c.holder_subject_id = "other:subject".into(),
            _ => c.resource = "runs/other".into(),
        };
        f.resign(c);
        assert!(verify_service_holder_proof_v1(&f.packet, &f.state(), 101).is_err());
    }
}
#[test]
fn service_holder_public_deterministic_vectors_match() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app);
        let p = UntrustedServiceHolderProof::decode(&f.packet.proof).unwrap();
        let challenge = UntrustedSignedServiceChallenge {
            claims: f.claims.clone(),
            request_bytes: f.packet.encrypted_payload.clone(),
            issuer_signature: p.issuer_signature,
        };
        let vectors = [
            ("challenge.bin", challenge.encode_inner().unwrap()),
            ("proof.bin", f.packet.proof.clone()),
            (
                "issuer-transcript.bin",
                challenge_transcript(&f.claims, &f.packet.encrypted_payload).unwrap(),
            ),
            (
                "holder-transcript.bin",
                holder_transcript(&p, &f.packet.encrypted_payload).unwrap(),
            ),
            ("packet.bin", bincode::serialize(&f.packet).unwrap()),
            (
                "issuer-public.bin",
                f.issuer.verifying_key().as_bytes().to_vec(),
            ),
            (
                "holder-public.bin",
                f.holder.verifying_key().as_bytes().to_vec(),
            ),
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/service-holder-proof-v1");
        let root = if app == ServiceApplication::ServiceV1 {
            root.join("service")
        } else {
            root
        };
        if std::env::var_os("UPDATE_SERVICE_HOLDER_VECTORS").as_deref()
            == Some(std::ffi::OsStr::new("1"))
        {
            std::fs::create_dir_all(&root).unwrap();
            for (name, bytes) in &vectors {
                std::fs::write(root.join(name), bytes).unwrap();
            }
        }
        for (name, bytes) in vectors {
            assert_eq!(std::fs::read(root.join(name)).unwrap(), bytes, "{name}");
        }
    }
}

#[test]
fn service_holder_independent_bundle_golden_vectors() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../tests/fixtures/service-holder-proof-v1/bundle-vectors.json"
    ))
    .unwrap();
    for vector in v["vectors"].as_array().unwrap() {
        let app = if vector["application"] == "runtime-v1" {
            ServiceApplication::RuntimeV1
        } else {
            ServiceApplication::ServiceV1
        };
        let expected = hex_digest(vector["sha256"].as_str().unwrap()).unwrap();
        assert_eq!(schema_bundle_digest(app), expected);
    }
}
#[test]
fn service_holder_all_wire_fields_and_signatures_bind() {
    let f = Fixture::new(ServiceApplication::RuntimeV1);
    let wire = &f.packet.proof;
    let mut cursor = libsec_core::service_holder_proof::PROOF_TAG.len();
    let mut checked = 0;
    while cursor < wire.len() {
        let n = u16::from_be_bytes(wire[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2 + n;
        let len = u32::from_be_bytes(wire[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        assert!(len > 0);
        let mut packet = f.packet.clone();
        packet.proof[cursor + len - 1] ^= 1;
        assert!(verify_service_holder_proof_v1(&packet, &f.state(), 101).is_err());
        cursor += len;
        checked += 1;
    }
    assert_eq!(checked, 39); // 36 fixed claims plus issuer signature, policy, holder signature.
}
#[test]
fn service_holder_equal_window_ends_allowed_and_cross_purpose_key_reuse_denied() {
    let mut f = Fixture::new(ServiceApplication::RuntimeV1);
    let mut c = f.claims.clone();
    c.evidence.evidence_valid_until = 160;
    c.evidence.evidence_revocation_fresh_until = 160;
    f.resign(c.clone());
    f.claims = c;
    f.evidence = f.claims.evidence.clone();
    let mut state = f.state();
    state.wallet_validity.not_after = 160;
    assert!(verify_service_holder_proof_v1(&f.packet, &state, 159).is_ok());
    let issuer = ServiceIssuerKey {
        node_id: "node:fixture".into(),
        key: PublicVerifierKey::configured_production_authority(
            "issuer:key",
            "ed25519",
            f.holder.verifying_key(),
        )
        .with_validity_window(Some(90), Some(200)),
    };
    let issuers = ServiceIssuerKeyRegistry::from_keys([issuer]).unwrap();
    let mut state = f.state();
    state.issuer_keys = &issuers;
    assert!(verify_service_holder_proof_v1(&f.packet, &state, 101).is_err());
}

#[test]
fn service_holder_public_raw_byte_limits_and_untrusted_reader_denial() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let mut f = Fixture::new(app);
        f.packet
            .encrypted_payload
            .resize(app.max_request_bytes(), b' ');
        let mut c = f.claims.clone();
        c.request_length = f.packet.encrypted_payload.len() as u64;
        c.request_sha256 = digest(&f.packet.encrypted_payload);
        f.resign(c.clone());
        f.claims = c;
        assert!(verify_service_holder_proof_v1(&f.packet, &f.state(), 101).is_ok());
        let mut oversized = f.packet.clone();
        oversized.encrypted_payload.push(b' ');
        assert!(verify_service_holder_proof_v1(&oversized, &f.state(), 101).is_err());
    }
    let mut f = Fixture::new(ServiceApplication::RuntimeV1);
    f.packet.encrypted_payload = b"{}".to_vec();
    let mut c = f.claims.clone();
    c.request_length = 2;
    c.request_sha256 = digest(b"{}");
    f.resign(c.clone());
    f.claims = c;
    assert!(verify_service_holder_proof_v1(&f.packet, &f.state(), 101).is_err());
}
