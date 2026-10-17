//! Disposable, explicitly unqualified custody. This module is compiled only by cfg(test).
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use libsec_core::service_holder_proof::{holder_transcript, UntrustedServiceHolderProof};
use serde_json::json;

pub(crate) fn input() -> Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/wallet-owner-input.fixture.json"
    ))
    .unwrap()
}
pub(crate) fn owner(v: &Value) -> ValidatedWalletOwnerInput {
    ValidatedWalletOwnerInput::parse(&serde_json::to_vec(v).unwrap()).unwrap()
}
pub(crate) fn challenge(v: &Value) -> UntrustedSignedServiceChallenge {
    let mut c = UntrustedSignedServiceChallenge::decode_inner(include_bytes!(
        "../vendor/secS-service-b/server/tests/fixtures/service-holder-proof-v1/challenge.bin"
    ))
    .unwrap();
    c.claims.descriptor_fingerprint = hex32(
        v["delegation_policy"]["descriptors"][0]["fingerprint"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    resign(&mut c);
    c
}
pub(crate) fn resign(c: &mut UntrustedSignedServiceChallenge) {
    c.issuer_signature = SigningKey::from_bytes(&[41; 32])
        .sign(&challenge_transcript(&c.claims, &c.request_bytes).unwrap())
        .to_bytes();
}
/// In-memory disposable key only. Not native custody or an implementation of a production port.
pub(crate) struct SyntheticHandle {
    key: SigningKey,
    generation: u64,
    last_now: u64,
}
impl SyntheticHandle {
    pub(crate) fn new() -> Self {
        Self {
            key: SigningKey::from_bytes(&[42; 32]),
            generation: 1,
            last_now: 0,
        }
    }
    fn current(&mut self, input: &ValidatedWalletOwnerInput, now: u64) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::Clock);
        }
        self.last_now = now;
        if self.generation != input.holder.generation
            || self.key.verifying_key() != input.holder.key.public
        {
            return Err(Error::Changed);
        }
        Ok(())
    }
    pub(crate) fn prepare(
        &mut self,
        input: &ValidatedWalletOwnerInput,
        c: &UntrustedSignedServiceChallenge,
        now: u64,
    ) -> Result<PreparedServiceHolderProof, Error> {
        self.current(input, now)?;
        Ok(PreparedServiceHolderProof {
            _private: (),
            validated: validate_service_challenge(input, c, now)?,
        })
    }
    pub(crate) fn present(
        &mut self,
        input: &ValidatedWalletOwnerInput,
        p: PreparedServiceHolderProof,
        mut clock: impl FnMut() -> u64,
    ) -> Result<Vec<u8>, Error> {
        let now = clock();
        self.current(input, now)?;
        let current = validate_service_challenge(input, &p.validated.challenge, now)?;
        if current.owner_digest != p.validated.owner_digest
            || current.wallet_policy_digest != p.validated.wallet_policy_digest
        {
            return Err(Error::Changed);
        }
        let now = clock();
        self.current(input, now)?;
        validate_service_challenge(input, &current.challenge, now)?;
        let mut proof = UntrustedServiceHolderProof {
            claims: current.challenge.claims.clone(),
            issuer_signature: current.challenge.issuer_signature,
            holder_policy_digest: current.wallet_policy_digest,
            holder_signature: [0; 64],
        };
        let transcript = holder_transcript(&proof, &current.challenge.request_bytes)
            .map_err(|_| Error::Invalid)?;
        proof.holder_signature = self.key.sign(&transcript).to_bytes();
        self.key
            .verifying_key()
            .verify_strict(&transcript, &Signature::from_bytes(&proof.holder_signature))
            .map_err(|_| Error::InvalidSignature)?;
        let final_now = clock();
        self.current(input, final_now)?;
        validate_service_challenge(input, &current.challenge, final_now)?;
        proof.encode().map_err(|_| Error::Invalid)
    }
}
#[test]
fn independent_native_policy_descriptor_and_bundle_goldens_match() {
    let vectors: Value =
        serde_json::from_str(include_str!("../tests/fixtures/delegation-goldens.json")).unwrap();
    let v = input();
    let o = owner(&v);
    let c = challenge(&v);
    let valid = validate_service_challenge(&o, &c, 100).unwrap();
    assert_eq!(
        hex(&valid.wallet_policy_digest),
        vectors["vectors"][0]["sha256"]
    );
    assert_eq!(
        o.descriptors[&66].authorization_fingerprint(),
        format!(
            "descriptor:sha256:{}",
            vectors["descriptor_sha256"].as_str().unwrap()
        )
    );
    for vector in vectors["vectors"].as_array().unwrap() {
        let mut v = input();
        v["delegation_policy"] = vector["policy"].clone();
        let r = validate_service_challenge(&owner(&v), &c, 100);
        assert_eq!(
            r.is_ok(),
            vector["request_case"]["accepts_original_expiry_160"]
                .as_bool()
                .unwrap()
        );
    }
    let bundle: Value =
        serde_json::from_str(include_str!("../tests/fixtures/bundle-oracle.json")).unwrap();
    for (i, app) in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            hex(&schema_bundle_digest(app)),
            bundle["vectors"][i]["sha256"]
        );
    }
}
#[test]
fn legacy_caller_configuration_ports_remain_denied() {
    let v = input();
    let o = owner(&v);
    let c = challenge(&v);
    let mut h = SyntheticHandle::new();
    let p = h.prepare(&o, &c, 100).unwrap();
    crate::custody_tests::assert_legacy_ports_deny(p);
    let p = h.prepare(&o, &c, 100).unwrap();
    let proof = h.present(&o, p, || 101).unwrap();
    let proof = UntrustedServiceHolderProof::decode(&proof).unwrap();
    assert_eq!(
        proof.holder_policy_digest,
        validate_service_challenge(&o, &c, 100)
            .unwrap()
            .wallet_policy_digest
    );
    h.key
        .verifying_key()
        .verify_strict(
            &holder_transcript(&proof, &c.request_bytes).unwrap(),
            &Signature::from_bytes(&proof.holder_signature),
        )
        .unwrap();
}
#[test]
fn all_nonempty_obligations_deny_even_valid_issuer_signature() {
    for field in [
        "required_credentials",
        "required_capabilities",
        "accepted_evidence",
        "required_authority_mode",
    ] {
        let mut v = input();
        v["descriptors"][0][field] = if field == "required_authority_mode" {
            json!("signed_source")
        } else {
            json!(["fixture.required"])
        };
        let descriptor = native_descriptor(&v["descriptors"][0]).unwrap();
        v["delegation_policy"]["descriptors"][0]["fingerprint"] = json!(descriptor
            .authorization_fingerprint()
            .trim_start_matches("descriptor:sha256:"));
        let c = challenge(&v);
        assert!(matches!(
            validate_service_challenge(&owner(&v), &c, 100),
            Err(Error::UnsupportedRequiredEvidence)
        ));
    }
}
#[test]
fn exact_signature_request_bundle_and_owner_bindings_deny_mutation() {
    let v = input();
    let o = owner(&v);
    let c = challenge(&v);
    for case in 0..11 {
        let mut bad = c.clone();
        match case {
            0 => bad.issuer_signature[0] ^= 1,
            1 => bad.request_bytes.push(b' '),
            2 => bad.claims.schema_bundle_sha256[0] ^= 1,
            3 => bad.claims.holder_subject_id = "other".into(),
            4 => bad.claims.holder_public_key_fingerprint[0] ^= 1,
            5 => bad.claims.issuer_key_id = "other".into(),
            6 => bad.claims.audience = "service://receiver-local".into(),
            7 => bad.claims.descriptor_fingerprint[0] ^= 1,
            8 => bad.claims.handler_id = "other".into(),
            9 => bad.claims.resource = "runs/other".into(),
            _ => bad.claims.opcode = 67,
        };
        assert!(
            validate_service_challenge(&o, &bad, 100).is_err(),
            "case{case}"
        );
    }
}
#[test]
fn current_wallet_scope_and_full_window_never_borrow_receiver_consent() {
    let v = input();
    let c = challenge(&v);
    for case in 0..7 {
        let mut bad = v.clone();
        match case {
            0 => bad["delegation_policy"]["rules"][0]["effect"] = json!("deny"),
            1 => bad["delegation_policy"]["rules"][1]["not_before"] = json!(150),
            2 => bad["holder"]["not_after"] = json!(150),
            3 => bad["issuers"][0]["revoked_at"] = json!(150),
            4 => bad["holder"]["revoked_at"] = json!(100),
            5 => bad["valid_until"] = json!(150),
            _ => bad["delegation_policy"]["principals"][0]["revoked"] = json!(true),
        };
        assert!(
            validate_service_challenge(&owner(&bad), &c, 100).is_err(),
            "case{case}"
        );
    }
    for now in [0, 99, 160, MAX_SAFE_TIME + 1] {
        assert!(validate_service_challenge(&owner(&v), &c, now).is_err());
    }
}
#[test]
fn changed_generation_policy_handle_and_post_sign_clock_cannot_export() {
    let v = input();
    let o = owner(&v);
    let c = challenge(&v);
    let mut h = SyntheticHandle::new();
    let p = h.prepare(&o, &c, 100).unwrap();
    let mut later = [100, 100, 160].into_iter();
    assert!(h.present(&o, p, || later.next().unwrap()).is_err());
    let mut h = SyntheticHandle::new();
    let p = h.prepare(&o, &c, 100).unwrap();
    let mut changed = v.clone();
    changed["generation"] = json!(2);
    assert!(matches!(
        h.present(&owner(&changed), p, || 101),
        Err(Error::Changed)
    ));
    let mut h = SyntheticHandle::new();
    let p = h.prepare(&o, &c, 100).unwrap();
    h.generation = 2;
    assert!(h.present(&o, p, || 101).is_err());
    let mut h = SyntheticHandle::new();
    let p = h.prepare(&o, &c, 100).unwrap();
    let mut later = [101, 100].into_iter();
    assert!(h.present(&o, p, || later.next().unwrap()).is_err());
}
#[test]
fn closed_metadata_nested_unknown_duplicates_and_aliases_deny() {
    let v = input();
    for path in [vec![], vec!["holder"], vec!["delegation_policy"]] {
        let mut bad = v.clone();
        let mut at = &mut bad;
        for key in path {
            at = &mut at[key];
        }
        at["approved"] = json!(true);
        assert!(ValidatedWalletOwnerInput::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    for raw in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":[{"b":1,"b":2}]}"#,
        br#"{"a":1.0}"#,
        br#"{"a":-1}"#,
    ] {
        assert!(strict_json(raw).is_err());
    }
    for case in 0..5 {
        let mut bad = v.clone();
        match case {
            0 => bad["issuers"][0]["key_id"] = bad["holder"]["key_id"].clone(),
            1 => bad["issuers"][0]["public_key_hex"] = bad["holder"]["public_key_hex"].clone(),
            2 => bad["holder"]
                .as_object_mut()
                .unwrap()
                .remove("revoked_at")
                .map(|_| ())
                .unwrap(),
            3 => {
                bad["descriptors"][0]["output_profile"] = json!({"schema_id":"x","max_output_bytes":1,"max_execution_response_bytes":2,"extra":1})
            }
            _ => bad["holder"]["public_key_hex"] = json!("00".repeat(32)),
        };
        assert!(ValidatedWalletOwnerInput::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
}
#[test]
fn exact_metadata_and_public_payload_bounds() {
    assert!(strict_json(&vec![b' '; 262145]).is_err());
    let entries = |n| format!("[{}]", vec!["0"; n].join(","));
    assert!(strict_json(entries(4096).as_bytes()).is_ok());
    assert!(strict_json(entries(4097).as_bytes()).is_err());
    let v = input();
    let o = owner(&v);
    let mut c = challenge(&v);
    c.request_bytes.resize(2_097_152, b' ');
    c.claims.request_length = c.request_bytes.len() as u64;
    c.claims.request_sha256 = hash(&c.request_bytes);
    resign(&mut c);
    assert!(validate_service_challenge(&o, &c, 100).is_ok());
    c.request_bytes.push(b' ');
    assert!(validate_service_challenge(&o, &c, 100).is_err());
}

pub(crate) fn descriptor(v: &Value) -> OperationDescriptor {
    native_descriptor(v).unwrap()
}
#[test]
fn actual_runtime_and_service_producer_bytes_are_never_reserialized() {
    let vectors:Value=serde_json::from_str(include_str!("../vendor/secS-service-b/crates/secs-service-call-contract/tests/fixtures/producer-numeric-requests.json")).unwrap();
    for vector in vectors["requests"].as_array().unwrap() {
        let mut v = input();
        let service = vector["application"] == "service";
        let app = if service {
            Application::Service
        } else {
            Application::Runtime
        };
        let wire = if service {
            ServiceApplication::ServiceV1
        } else {
            ServiceApplication::RuntimeV1
        };
        let raw = vector["request"].as_str().unwrap().as_bytes();
        let intent = ServiceIntent::parse(app, raw).unwrap();
        let opcode = if service { 0x79 } else { 0x42 };
        v["application"] = vector["application"].clone();
        v["delegation_policy"]["application"] = vector["application"].clone();
        v["delegation_policy"]["audience"] = json!(wire.audience());
        v["descriptors"][0]["name"] = json!(intent.operation());
        v["descriptors"][0]["opcode"] = json!(opcode);
        v["descriptors"][0]["handler_id"] = json!(format!("fixture/{}", intent.operation()));
        let d = native_descriptor(&v["descriptors"][0]).unwrap();
        let fp = d
            .authorization_fingerprint()
            .trim_start_matches("descriptor:sha256:")
            .to_owned();
        let pd = &mut v["delegation_policy"]["descriptors"][0];
        pd["operation"] = json!(intent.operation());
        pd["opcode"] = json!(opcode);
        pd["handler_id"] = json!(d.handler_id);
        pd["fingerprint"] = json!(fp);
        for r in v["delegation_policy"]["rules"].as_array_mut().unwrap() {
            r["operation"] = json!(intent.operation());
            r["resource"] = json!(intent.resource());
        }
        let mut c = UntrustedSignedServiceChallenge::decode_inner(include_bytes!(
            "../vendor/secS-service-b/server/tests/fixtures/service-holder-proof-v1/challenge.bin"
        ))
        .unwrap();
        c.claims.application = wire;
        c.claims.audience = wire.audience().into();
        c.claims.operation = intent.operation().into();
        c.claims.resource = intent.resource().into();
        c.claims.opcode = opcode;
        c.claims.handler_id = d.handler_id;
        c.claims.descriptor_fingerprint = hex32(&fp).unwrap();
        c.claims.schema_bundle_sha256 = schema_bundle_digest(wire);
        c.request_bytes = raw.to_vec();
        c.claims.request_length = raw.len() as u64;
        c.claims.request_sha256 = hash(raw);
        resign(&mut c);
        let o = owner(&v);
        let validated = validate_service_challenge(&o, &c, 100).unwrap();
        assert_eq!(validated.request_bytes(), raw);
        assert_eq!(hex(&hash(raw)), vector["sha256"]);
        if service {
            c.request_bytes.resize(65536, b' ');
            c.claims.request_length = 65536;
            c.claims.request_sha256 = hash(&c.request_bytes);
            resign(&mut c);
            assert!(validate_service_challenge(&o, &c, 100).is_ok());
            c.request_bytes.push(b' ');
            assert!(validate_service_challenge(&o, &c, 100).is_err());
        }
    }
}
#[test]
fn every_nested_object_is_closed_and_every_nullable_field_is_explicit() {
    fn paths(v: &Value, path: Vec<String>, out: &mut Vec<Vec<String>>) {
        match v {
            Value::Object(m) => {
                out.push(path.clone());
                for (k, v) in m {
                    let mut p = path.clone();
                    p.push(k.clone());
                    paths(v, p, out);
                }
            }
            Value::Array(a) => {
                for (i, v) in a.iter().enumerate() {
                    let mut p = path.clone();
                    p.push(i.to_string());
                    paths(v, p, out);
                }
            }
            _ => {}
        }
    }
    fn at<'a>(mut v: &'a mut Value, path: &[String]) -> &'a mut Value {
        for k in path {
            v = if v.is_array() {
                &mut v[k.parse::<usize>().unwrap()]
            } else {
                &mut v[k]
            };
        }
        v
    }
    let v = input();
    let mut all = Vec::new();
    paths(&v, vec![], &mut all);
    for path in all {
        let mut bad = v.clone();
        at(&mut bad, &path)["approved"] = json!(true);
        assert!(ValidatedWalletOwnerInput::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        let keys = at(&mut bad, &path)
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| *k != "approved")
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            let mut bad = v.clone();
            at(&mut bad, &path).as_object_mut().unwrap().remove(&key);
            assert!(
                ValidatedWalletOwnerInput::parse(&serde_json::to_vec(&bad).unwrap()).is_err(),
                "{path:?}/{key}"
            );
        }
    }
    for depth in [16, 17] {
        let raw = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert_eq!(strict_json(raw.as_bytes()).is_ok(), depth == 16);
    }
}

#[test]
fn strict_metadata_number_profiles_do_not_depend_on_serde_features() {
    for raw in [
        b"0".as_slice(),
        b"9007199254740991",
        br#"{"n":0,"tag":"$serde_json::private::Number"}"#,
        br#"[0,9007199254740991,"prefix $serde_json::private::Number suffix"]"#,
    ] {
        assert!(strict_json(raw).is_ok(), "valid metadata: {:?}", raw);
    }
    let mut accepted = Vec::new();
    for value in [
        "1.0",
        "1e0",
        "1.000",
        "-0",
        "-0.0",
        "-1",
        "9007199254740992",
        "18446744073709551616",
    ] {
        for raw in [
            value.to_owned(),
            format!("{{\"n\":{value}}}"),
            format!("[{value}]"),
            format!("{{\"n\":[{{\"value\":{value}}}]}}"),
        ] {
            if strict_json(raw.as_bytes()).is_ok() {
                accepted.push(raw);
            }
        }
    }
    for raw in [
        br#"{"$serde_json::private::Number":"1.0"}"#.as_slice(),
        br#"{"nested":{"$serde_json::private::Number":"1"}}"#,
        br#"[{"$serde_json::private::Number":"1e0"}]"#,
        br#"{"\u0024serde_json::private::Number":"-0"}"#,
    ] {
        if strict_json(raw).is_ok() {
            accepted.push(String::from_utf8(raw.to_vec()).unwrap());
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted forbidden metadata: {accepted:?}"
    );
}

#[test]
fn public_owner_lower_bound_rejects_negative_zero_and_noninteger_lexemes() {
    let raw = serde_json::to_string(&input()).unwrap();
    assert!(ValidatedWalletOwnerInput::parse(raw.as_bytes()).is_ok());
    let mut accepted = Vec::new();
    for value in [
        "-0",
        "-0.0",
        "1.0",
        "1e0",
        "9007199254740992",
        "18446744073709551616",
    ] {
        let changed = raw.replacen(
            "\"valid_not_before\":0",
            &format!("\"valid_not_before\":{value}"),
            1,
        );
        assert_ne!(changed, raw);
        if ValidatedWalletOwnerInput::parse(changed.as_bytes()).is_ok() {
            accepted.push(value);
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted owner lower-bound lexemes: {accepted:?}"
    );
}
