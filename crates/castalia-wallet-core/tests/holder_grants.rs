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

#[test]
fn stored_collection_must_fit_its_own_backup_parser() {
    use castalia_wallet_core::holder_grants::{StoredGrant, validate_capacity};
    let mut session = ready();
    let (pin, grant) = grant(&mut session);
    let stored = StoredGrant {
        pin,
        grant,
        saved_at: 101,
    };
    let mut collection = std::collections::BTreeMap::new();
    collection.insert("service:fixture".into(), stored.clone());
    assert!(validate_capacity(&collection).is_ok());
    for index in 0..128 {
        let mut record = stored.clone();
        record.grant.claims.permissions[0].constraints =
            json!({"fixture_padding":"x".repeat(1024)});
        collection.insert(format!("service:fixture:{index}"), record);
    }
    assert_eq!(validate_capacity(&collection), Err("grant_capacity"));
    collection.remove("service:fixture");
    assert_eq!(collection.len(), 128);
    assert_eq!(validate_capacity(&collection), Err("grant_capacity"));
}

#[test]
fn public_service_binding_verification_never_unlocks_or_changes_wallet() {
    let mut s = RecoverySession::new();
    let before = call(&mut s, json!({"operation":"state"}));
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let pin = IssuerPin {
        issuer: "provider:fixture".into(),
        key_id: "key:v1".into(),
        public_key: hex::encode(issuer.verifying_key().to_bytes()),
        service: "service:fixture".into(),
    };
    let binding = issue_access_point(
        &pin,
        AccessPointClaims {
            schema: ACCESS_POINT.into(),
            issuer: pin.issuer.clone(),
            key_id: pin.key_id.clone(),
            service: pin.service.clone(),
            origin: "https://graph.example:9443".into(),
            authority_receiver: "https://127.0.0.1:58754".into(),
            prefix: "/service/v1".into(),
            not_before: 100,
            not_after: 1000,
        },
        &issuer,
        101,
    )
    .unwrap();
    let command = json!({"operation":"verify_service_access_point","pin":pin,"binding":binding,"origin":"https://graph.example:9443","now":102});
    let verified = call(&mut s, command.clone());
    assert_eq!(verified["service"], "service:fixture");
    let mut bad = command;
    bad["origin"] = "https://evil.example".into();
    assert!(s.invoke(&bad.to_string()).is_err());
    assert_eq!(before, call(&mut s, json!({"operation":"state"})));
}

#[test]
fn service_alias_requires_current_browser_trust_and_exact_provider_signature() {
    use castalia_wallet_core::service_access_point::presentation_context;
    use castalia_wallet_presentation::{Caller, TrustPin};
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../vendor/secs-grant-contract/tests/fixtures/access-point.json"
    ))
    .unwrap();
    let pin: IssuerPin = serde_json::from_value(vector["pin"].clone()).unwrap();
    let binding: secs_grant_contract::AccessPointBinding =
        serde_json::from_value(vector["binding"].clone()).unwrap();
    let caller = Caller {
        kind: "browser".into(),
        id: binding.claims.origin.clone(),
    };
    let trusted = TrustPin {
        issuer: pin.issuer,
        key_id: pin.key_id,
        public_key: pin.public_key,
        audience: "devgraph".into(),
        callers: vec![caller.clone()],
    };
    let (translated, canonical) =
        presentation_context(&[trusted.clone()], &caller, &binding, 102).unwrap();
    assert_eq!(canonical.id, binding.claims.authority_receiver);
    assert_eq!(translated[0].callers, vec![canonical]);
    assert!(presentation_context(&[], &caller, &binding, 102).is_err());
    assert!(
        presentation_context(
            &[trusted.clone()],
            &Caller {
                kind: "browser".into(),
                id: "https://other.example".into()
            },
            &binding,
            102
        )
        .is_err()
    );
    assert!(presentation_context(&[trusted], &caller, &binding, 1000).is_err());
}

#[test]
fn wallet_backup_and_derivation_preserve_independent_action_scopes() {
    let mut session = ready();
    let (pin, original) = grant(&mut session);
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let mut claims = original.claims;
    let read = Permission {
        operation: "service.object.read".into(),
        resource: "objects".into(),
        scope: Scope::Paths {
            roots: vec![vec![Node {
                kind: "Container".into(),
                id: "a".into(),
            }]],
        },
        constraints: json!({"include_archived":false}),
    };
    let mut write = read.clone();
    write.operation = "service.object.patch".into();
    write.scope = Scope::Paths {
        roots: vec![vec![Node {
            kind: "Container".into(),
            id: "b".into(),
        }]],
    };
    claims.permissions = vec![read.clone(), write.clone()];
    let root = issue_grant(&pin, claims, &issuer, 100).unwrap();
    let prepared = call(
        &mut session,
        json!({"operation":"prepare_holder_grant","pin":pin,"grant":root,"now":101}),
    );
    commit(&mut session, prepared);
    let backup = call(
        &mut session,
        json!({"operation":"export_holder_grant_backup"}),
    );
    let removed = call(
        &mut session,
        json!({"operation":"forget_holder_grant","service":pin.service}),
    );
    commit(&mut session, removed);
    let restored = call(
        &mut session,
        json!({"operation":"prepare_holder_grant_backup","file":backup["file"]}),
    );
    commit(&mut session, restored);
    let derive = |permissions: Vec<Permission>| {
        json!({"operation":"derive_holder_credential","service":pin.service,"permissions":permissions,"expires_at":300,"now":102}).to_string()
    };
    let credential: Credential = serde_json::from_value(
        session
            .invoke(&derive(vec![read.clone(), write.clone()]))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        credential.claims.permissions,
        vec![read.clone(), write.clone()]
    );
    verify_credential(&pin, &credential, 103).unwrap();
    let mut narrower = write.clone();
    if let Scope::Paths { roots } = &mut narrower.scope {
        roots[0].push(Node {
            kind: "Folder".into(),
            id: "p".into(),
        });
    }
    let credential: Credential =
        serde_json::from_value(session.invoke(&derive(vec![narrower])).unwrap()).unwrap();
    verify_credential(&pin, &credential, 103).unwrap();
    let mut crossed = write.clone();
    crossed.scope = read.scope.clone();
    assert!(session.invoke(&derive(vec![crossed])).is_err());
    let mut crossed = read;
    crossed.scope = write.scope;
    assert!(session.invoke(&derive(vec![crossed])).is_err());
    assert!(!root.claims.onward_delegation);
}

#[test]
fn saved_live_collection_grant_can_derive_for_an_item_created_later() {
    let mut session = ready();
    let (pin, original) = grant(&mut session);
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let mut claims = original.claims;
    claims.permissions[0].operation = "catalog.item.get".into();
    claims.permissions[0].scope = Scope::All;
    let root = issue_grant(&pin, claims, &issuer, 100).unwrap();
    let prepared = call(
        &mut session,
        json!({"operation":"prepare_holder_grant","pin":pin,"grant":root,"now":101}),
    );
    commit(&mut session, prepared);
    let backup = call(
        &mut session,
        json!({"operation":"export_holder_grant_backup"}),
    );
    let imported = call(
        &mut session,
        json!({"operation":"prepare_holder_grant_backup","file":backup["file"]}),
    );
    commit(&mut session, imported);
    let mut narrower = root.claims.permissions.clone();
    narrower[0].scope = Scope::Paths {
        roots: vec![vec![Node {
            kind: "CollectionItem".into(),
            id: "created-later".into(),
        }]],
    };
    let derived = call(
        &mut session,
        json!({"operation":"derive_holder_credential","service":pin.service,"permissions":narrower,"expires_at":300,"now":102}),
    );
    let credential: Credential = serde_json::from_value(derived).unwrap();
    verify_credential(&pin, &credential, 103).unwrap();
    assert_eq!(credential.claims.permissions, narrower);
    let equal = call(
        &mut session,
        json!({"operation":"derive_holder_credential","service":pin.service,"permissions":null,"expires_at":300,"now":103}),
    );
    let equal: Credential = serde_json::from_value(equal).unwrap();
    assert_eq!(equal.claims.permissions[0].scope, Scope::All);
    assert!(!equal.grant.claims.onward_delegation);
}
