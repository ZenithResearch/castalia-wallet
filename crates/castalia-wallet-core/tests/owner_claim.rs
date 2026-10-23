use castalia_wallet_core::recovery_session::RecoverySession;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Value, json};

fn call(s: &mut RecoverySession, command: Value) -> Value {
    s.invoke(&command.to_string()).expect("native operation")
}
fn commit(s: &mut RecoverySession, preview: Value) {
    let c = call(
        s,
        json!({"operation":"commit_candidate", "token":preview["token"], "expected_revision":preview["expected_revision"]}),
    );
    call(
        s,
        json!({"operation":"confirm_commit", "token":preview["token"], "snapshot":c["snapshot"]}),
    );
}
fn ready() -> RecoverySession {
    let mut s = RecoverySession::new();
    let p = call(
        &mut s,
        json!({"operation":"prepare_create", "password":"test password 123", "created_at":1, "expected_revision":0}),
    );
    commit(&mut s, p);
    let backup = call(
        &mut s,
        json!({"operation":"export_recovery", "password":"backup password 123"}),
    );
    let p = call(
        &mut s,
        json!({"operation":"verify_backup", "password":"backup password 123", "file":backup["file"]}),
    );
    commit(&mut s, p);
    s
}
fn challenge(s: &mut RecoverySession) -> Value {
    let identity = call(s, json!({"operation":"graph_access_identity_v2"}));
    json!({"schema":"zenith.resource-owner-challenge.v1",
        "binding":{"resource_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "endpoint":"http://127.0.0.1:8080", "configuration_sha256":"aa".repeat(32), "registration_sha256":"bb".repeat(32)},
        "claim_id":"cc".repeat(16), "nonce":"dd".repeat(32), "issued_at":100, "expires_at":220,
        "admin_grant":{"schema":"zenith.resource-admin-grant.v1", "grant_id":"ee".repeat(32), "holder_public_key":identity["subject_public_key"], "resource_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "operations":["access.inbox","access.review","access.decide","access.status"], "validity":{"mode":"until_revoked"}, "onward_delegation":false}})
}
fn prepare(s: &mut RecoverySession, c: &Value) -> Value {
    call(
        s,
        json!({"operation":"prepare_resource_owner_v1", "challenge":c.to_string(), "binding":c["binding"], "now":101}),
    )
}

#[test]
fn owner_review_has_no_signature_and_consent_signs_only_exact_claim_once() {
    let mut s = ready();
    assert_eq!(
        call(&mut s, json!({"operation":"state"}))["resource_owner_protocol"],
        "zenith.resource-owner.v1"
    );
    let c = challenge(&mut s);
    let p = prepare(&mut s, &c);
    assert_eq!(p["summary"]["binding"], c["binding"]);
    assert_eq!(p["summary"]["admin_grant"], c["admin_grant"]);
    assert!(p.get("signature").is_none());
    let signed = call(
        &mut s,
        json!({"operation":"approve_resource_owner_v1", "token":p["token"], "now":102}),
    );
    assert_eq!(signed["schema"], "zenith.resource-owner-proof.v1");
    assert_eq!(signed["challenge"], c);
    let public: [u8; 32] = hex::decode(c["admin_grant"]["holder_public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signature =
        Signature::from_slice(&hex::decode(signed["signature"].as_str().unwrap()).unwrap())
            .unwrap();
    let mut message = b"zenith/resource-owner-approval/v1\0".to_vec();
    message.extend(serde_jcs::to_vec(&c).unwrap());
    VerifyingKey::from_bytes(&public)
        .unwrap()
        .verify(&message, &signature)
        .unwrap();
    assert!(
        s.invoke(
            &json!({"operation":"approve_resource_owner_v1", "token":p["token"], "now":103})
                .to_string()
        )
        .is_err()
    );
    assert!(
        !call(&mut s, json!({"operation":"state"}))["membership_active"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn owner_claim_rejects_target_authority_wallet_json_and_time_changes() {
    let mut s = ready();
    let original = challenge(&mut s);
    let mut c = original.clone();
    c["binding"]["endpoint"] = json!("http://127.0.0.1:8181");
    assert!(s.invoke(&json!({"operation":"prepare_resource_owner_v1", "challenge":c.to_string(), "binding":original["binding"], "now":101}).to_string()).is_err());
    for (field, value) in [
        ("onward_delegation", json!(true)),
        ("operations", json!(["access.inbox", "work.patch"])),
        ("holder_public_key", json!("ff".repeat(32))),
        ("extra_authority", json!(true)),
    ] {
        let mut c = original.clone();
        c["admin_grant"][field] = value;
        assert!(s.invoke(&json!({"operation":"prepare_resource_owner_v1", "challenge":c.to_string(), "binding":c["binding"], "now":101}).to_string()).is_err());
    }
    for now in [99, 220, 9_007_199_254_740_992u64] {
        assert!(s.invoke(&json!({"operation":"prepare_resource_owner_v1", "challenge":original.to_string(), "binding":original["binding"], "now":now}).to_string()).is_err());
    }
    let duplicate = original.to_string().replacen(
        "\"issued_at\":100",
        "\"issued_at\":100,\"issued_at\":101",
        1,
    );
    assert!(s.invoke(&json!({"operation":"prepare_resource_owner_v1", "challenge":duplicate, "binding":original["binding"], "now":101}).to_string()).is_err());
    let mut c = original.clone();
    c["binding"]["endpoint"] = json!("http://192.168.1.77:8080");
    assert!(s.invoke(&json!({"operation":"prepare_resource_owner_v1", "challenge":c.to_string(), "binding":c["binding"], "now":101}).to_string()).is_err());
}

#[test]
fn owner_preview_is_invalidated_by_lock_cancel_wrong_token_or_another_operation() {
    let mut s = ready();
    let c = challenge(&mut s);
    for invalidation in [
        json!({"operation":"cancel"}),
        json!({"operation":"identity"}),
        json!({"operation":"prepare_resource_owner_v1", "challenge":"{}", "binding":c["binding"], "now":101}),
    ] {
        let p = prepare(&mut s, &c);
        let _ = s.invoke(&invalidation.to_string());
        assert!(
            s.invoke(
                &json!({"operation":"approve_resource_owner_v1", "token":p["token"], "now":102})
                    .to_string()
            )
            .is_err()
        );
    }
    let p = prepare(&mut s, &c);
    assert!(
        s.invoke(
            &json!({"operation":"approve_resource_owner_v1", "token":"wrong", "now":102})
                .to_string()
        )
        .is_err()
    );
    assert!(
        s.invoke(
            &json!({"operation":"approve_resource_owner_v1", "token":p["token"], "now":102})
                .to_string()
        )
        .is_err()
    );
    let p = prepare(&mut s, &c);
    assert!(
        s.invoke(
            &json!({"operation":"approve_resource_owner_v1", "token":p["token"], "now":220})
                .to_string()
        )
        .is_err()
    );
    let p = prepare(&mut s, &c);
    call(&mut s, json!({"operation":"lock"}));
    assert!(
        s.invoke(
            &json!({"operation":"approve_resource_owner_v1", "token":p["token"], "now":102})
                .to_string()
        )
        .is_err()
    );
}

#[test]
fn python_server_vector_matches_native_owner_signature_byte_for_byte() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let vector: Value =
        serde_json::from_str(include_str!("fixtures/first-owner-bootstrap.vector.json")).unwrap();
    // Public test seed, not an installed Wallet or authority.
    let seed = [0x42u8; 32];
    let mut hash = blake3::Hasher::new();
    hash.update(b"castalia/recovery-key/v1\0");
    hash.update(&seed);
    let legacy = format!(
        "castalia-recovery-key-v1.{}.{}",
        URL_SAFE_NO_PAD.encode(seed),
        URL_SAFE_NO_PAD.encode(&hash.finalize().as_bytes()[..4])
    );
    let mut s = RecoverySession::new();
    let p = call(
        &mut s,
        json!({"operation":"prepare_legacy", "key":legacy, "password":"test password 123", "created_at":1, "expected_revision":0}),
    );
    commit(&mut s, p);
    let backup = call(
        &mut s,
        json!({"operation":"export_recovery", "password":"backup password 123"}),
    );
    let p = call(
        &mut s,
        json!({"operation":"verify_backup", "password":"backup password 123", "file":backup["file"]}),
    );
    commit(&mut s, p);
    let c = &vector["proof"]["challenge"];
    let p = prepare(&mut s, c);
    let result = call(
        &mut s,
        json!({"operation":"approve_resource_owner_v1", "token":p["token"], "now":102}),
    );
    assert_eq!(result, vector["proof"]);
    let mut transcript = b"zenith/resource-owner-approval/v1\0".to_vec();
    transcript.extend(serde_jcs::to_vec(c).unwrap());
    assert_eq!(hex::encode(transcript), vector["transcript_hex"]);
}
