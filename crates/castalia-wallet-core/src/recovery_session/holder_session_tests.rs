use super::*;
use ed25519_dalek::SigningKey;
fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../../vendor/secs-grant-contract/tests/fixtures/holder-session-v1.json"
    ))
    .unwrap()
}
fn ready() -> RecoverySession {
    let v = vector();
    let mut s = RecoverySession::new();
    s.wallet = Some(OpenedWallet::from_signing_key(
        SigningKey::from_bytes(&[62; 32]),
        90,
    ));
    s.custody = Some("synthetic test custody".into());
    s.local.backup_verified = true;
    s.local.installation_id = "66".repeat(16);
    let stored =
        crate::portable_holder_grants::StoredGrant::V2(crate::scoped_holder_grants::StoredGrant {
            pin: serde_json::from_value(v["pin"].clone()).unwrap(),
            grant: serde_json::from_value(v["parent_grant"].clone()).unwrap(),
            saved_at: 100,
        });
    s.local
        .holder_grants
        .insert("service:example".into(), stored);
    s
}
fn prepare(s: &mut RecoverySession) -> Value {
    let v = vector();
    s.invoke(&json!({"operation":"prepare_holder_session_authorization","service":"service:example","challenge":v["challenge"],"context":v["context"],"now":101}).to_string()).unwrap()
}
#[test]
fn native_parent_reference_and_state_do_not_export_parent_and_approval_is_one_shot() {
    let mut s = ready();
    let reference=s.invoke(r#"{"operation":"holder_session_parent_reference","service":"service:example","now":101}"#).unwrap();
    assert!(reference.get("parent_grant").is_none());
    assert_eq!(
        reference["parent_grant_id"],
        vector()["parent_grant"]["claims"]["grant_id"]
    );
    let p = prepare(&mut s);
    s.invoke(r#"{"operation":"state"}"#).unwrap();
    let command=json!({"operation":"approve_holder_session_authorization","token":p["token"],"session_signature":vector()["authorization"]["session_signature"],"now":102}).to_string();
    let authorization = s.invoke(&command).unwrap();
    assert_eq!(authorization, vector()["authorization"]);
    assert!(s.invoke(&command).is_err());
}
#[test]
fn native_lock_malformed_input_and_failed_new_prepare_invalidate_holder_consent() {
    for variant in 0..3 {
        let mut s = ready();
        let p = prepare(&mut s);
        match variant {
            0 => {
                s.invoke(r#"{"operation":"lock"}"#).unwrap();
            }
            1 => {
                assert!(s.invoke("{}").is_err());
            }
            _ => {
                let mut bad = vector()["challenge"].clone();
                bad["expires_at"] = json!(401);
                assert!(s.invoke(&json!({"operation":"prepare_holder_session_authorization","service":"service:example","challenge":bad,"context":vector()["context"],"now":101}).to_string()).is_err());
            }
        }
        assert!(s.invoke(&json!({"operation":"approve_holder_session_authorization","token":p["token"],"session_signature":vector()["authorization"]["session_signature"],"now":102}).to_string()).is_err());
    }
}
#[test]
fn private_preparation_keeps_root_out_of_public_reference_and_fixes_installations() {
    let mut s = ready();
    let v = vector();
    let r=s.invoke(&json!({"operation":"build_holder_session_prepare","service":"service:example","request_id":"44".repeat(16),"session_public_key":v["challenge"]["session_public_key"],"session_installation_id":"77".repeat(16),"context":v["context"],"permissions":null,"requested_ttl_seconds":300,"now":101}).to_string()).unwrap();
    assert_eq!(r["schema"], "castalia.holder-session-private-prepare.v1");
    assert_eq!(r["body"]["schema"], "secs.holder-session-prepare.v1");
    assert_eq!(r["body"]["parent_grant"], v["parent_grant"]);
    assert_eq!(r["body"]["installation_id"], "66".repeat(16));
    assert_eq!(r["body"]["session_installation_id"], "77".repeat(16));
    assert!(
        r["body"]["permissions"].is_null(),
        "default selection must stay receiver-owned"
    );
}

#[test]
fn saved_parent_cannot_be_selected_under_another_canonical_service() {
    let mut s = ready();
    let stored = s.local.holder_grants.remove("service:example").unwrap();
    s.local.holder_grants.insert("service:other".into(), stored);
    let v = vector();
    for command in [
        json!({"operation":"holder_session_parent_reference","service":"service:other","now":101}),
        json!({"operation":"build_holder_session_prepare","service":"service:other","request_id":"44".repeat(16),"session_public_key":v["challenge"]["session_public_key"],"session_installation_id":"77".repeat(16),"context":v["context"],"permissions":null,"requested_ttl_seconds":300,"now":101}),
        json!({"operation":"prepare_holder_session_authorization","service":"service:other","challenge":v["challenge"],"context":v["context"],"now":101}),
    ] {
        assert!(s.invoke(&command.to_string()).is_err(), "{command}");
    }
}
