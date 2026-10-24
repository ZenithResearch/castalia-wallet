use castalia_wallet_core::recovery_session::RecoverySession;
use ed25519_dalek::SigningKey;
use secs_grant_contract::*;
use serde_json::{Value, json};
fn call(s: &mut RecoverySession, v: Value) -> Value {
    s.invoke(&v.to_string()).unwrap()
}
fn commit(s: &mut RecoverySession, p: Value) -> String {
    let c = call(
        s,
        json!({"operation":"commit_candidate","token":p["token"],"expected_revision":p["expected_revision"]}),
    );
    let snapshot = c["snapshot"].as_str().unwrap().to_string();
    call(
        s,
        json!({"operation":"confirm_commit","token":p["token"],"snapshot":snapshot}),
    );
    snapshot
}
fn ready() -> RecoverySession {
    let mut s = RecoverySession::new();
    let p = call(
        &mut s,
        json!({"operation":"prepare_create","password":"disposable grant wallet password","created_at":1,"expected_revision":0}),
    );
    commit(&mut s, p);
    let b = call(
        &mut s,
        json!({"operation":"export_recovery","password":"disposable backup password"}),
    );
    let p = call(
        &mut s,
        json!({"operation":"verify_backup","file":b["file"],"password":"disposable backup password"}),
    );
    commit(&mut s, p);
    s
}
fn grant(s: &mut RecoverySession) -> (IssuerPin, Grant) {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let owner = call(s, json!({"operation":"state"}))["public_key"]
        .as_str()
        .unwrap()
        .to_owned();
    let pin = IssuerPin {
        issuer: "provider:fixture".into(),
        key_id: "key:v1".into(),
        public_key: hex::encode(issuer.verifying_key().to_bytes()),
        service: "service:fixture".into(),
    };
    let claims = GrantClaims {
        schema: GRANT.into(),
        grant_id: "11".repeat(16),
        revision: "22".repeat(32),
        issuer: pin.issuer.clone(),
        key_id: pin.key_id.clone(),
        service: pin.service.clone(),
        holder_public_key: owner,
        installation_id: None,
        validity: Validity::UntilRevoked { not_before: 100 },
        max_credential_lifetime_seconds: 3600,
        onward_delegation: false,
        permissions: vec![Permission {
            operation: "work.read".into(),
            resource: "work".into(),
            scope: Scope::All,
            constraints: json!({}),
        }],
    };
    let g = issue_grant(&pin, claims, &issuer, 100).unwrap();
    (pin, g)
}
#[test]
fn persisted_grant_derives_after_restart_and_backup_is_encrypted() {
    let mut s = ready();
    let (pin, g) = grant(&mut s);
    let review = call(
        &mut s,
        json!({"operation":"review_holder_grant","pin":pin,"grant":g,"now":101}),
    );
    assert_eq!(review["service"], pin.service);
    let p = call(
        &mut s,
        json!({"operation":"prepare_holder_grant","pin":pin,"grant":g,"now":101}),
    );
    let snapshot = commit(&mut s, p);
    assert!(!snapshot.contains("service:fixture"));
    let backup = call(&mut s, json!({"operation":"export_holder_grant_backup"}));
    assert!(!backup.to_string().contains("service:fixture"));
    call(&mut s, json!({"operation":"lock"}));
    assert!(s.invoke(&json!({"operation":"derive_holder_credential","service":pin.service,"permissions":null,"expires_at":300,"now":102}).to_string()).is_err());
    call(
        &mut s,
        json!({"operation":"unlock","snapshot":snapshot,"password":"disposable grant wallet password"}),
    );
    let c = call(
        &mut s,
        json!({"operation":"derive_holder_credential","service":pin.service,"permissions":null,"expires_at":300,"now":102}),
    );
    let credential: Credential = serde_json::from_value(c.clone()).unwrap();
    verify_credential(&pin, &credential, 103).unwrap();
    let envelope = call(
        &mut s,
        json!({"operation":"present_holder_credential","service":pin.service,"credential":c,"call":{"operation":"work.read","resource":"work","parameters":{}},"now":103}),
    );
    let proof: Proof = serde_json::from_value(envelope["proof"].clone()).unwrap();
    verify_presentation(&pin, &credential, &envelope["call"], &proof, 104).unwrap();
    let p = call(
        &mut s,
        json!({"operation":"forget_holder_grant","service":pin.service}),
    );
    commit(&mut s, p);
    let p = call(
        &mut s,
        json!({"operation":"prepare_holder_grant_backup","file":backup["file"]}),
    );
    commit(&mut s, p);
    assert_eq!(
        call(&mut s, json!({"operation":"holder_grants"}))["grants"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn wrong_wallet_scope_expiry_and_failed_prepare_preserve_storage() {
    let mut s = ready();
    let (pin, g) = grant(&mut s);
    let mut other = ready();
    assert!(
        other
            .invoke(
                &json!({"operation":"prepare_holder_grant","pin":pin,"grant":g,"now":101})
                    .to_string()
            )
            .is_err()
    );
    let p = call(
        &mut s,
        json!({"operation":"prepare_holder_grant","pin":pin,"grant":g,"now":101}),
    );
    let mut bad = g.clone();
    bad.signature = "00".repeat(64);
    assert!(
        s.invoke(
            &json!({"operation":"prepare_holder_grant","pin":pin,"grant":bad,"now":101})
                .to_string()
        )
        .is_err()
    );
    assert!(s.invoke(&json!({"operation":"commit_candidate","token":p["token"],"expected_revision":p["expected_revision"]}).to_string()).is_err());
    assert!(
        call(&mut s, json!({"operation":"holder_grants"}))["grants"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let p = call(
        &mut s,
        json!({"operation":"prepare_holder_grant","pin":pin,"grant":g,"now":101}),
    );
    commit(&mut s, p);
    let mut rights = g.claims.permissions.clone();
    rights[0].operation = "work.write".into();
    assert!(s.invoke(&json!({"operation":"derive_holder_credential","service":pin.service,"permissions":rights,"expires_at":300,"now":102}).to_string()).is_err());
    assert!(s.invoke(&json!({"operation":"derive_holder_credential","service":pin.service,"permissions":null,"expires_at":4000,"now":102}).to_string()).is_err());
}
