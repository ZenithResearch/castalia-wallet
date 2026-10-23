use castalia_wallet_core::recovery_session::RecoverySession;
use serde_json::json;

fn call(s: &mut RecoverySession, v: serde_json::Value) -> serde_json::Value {
    s.invoke(&v.to_string()).expect("operation succeeds")
}
fn create(s: &mut RecoverySession) -> serde_json::Value {
    call(
        s,
        json!({"operation":"prepare_create", "password":"local password 123", "created_at":1, "expected_revision":0}),
    )
}
fn commit(s: &mut RecoverySession, preview: &serde_json::Value) -> String {
    let candidate = call(
        s,
        json!({"operation":"commit_candidate", "token":preview["token"], "expected_revision":preview["expected_revision"]}),
    );
    let snapshot = candidate["snapshot"].as_str().unwrap().to_owned();
    call(
        s,
        json!({"operation":"confirm_commit", "token":preview["token"], "snapshot":snapshot}),
    );
    snapshot
}
#[test]
fn creation_is_staged_and_verification_gates_enrollment() {
    let mut s = RecoverySession::new();
    let p = create(&mut s);
    assert_eq!(
        call(&mut s, json!({"operation":"state"}))["unlocked"],
        false
    );
    let first = commit(&mut s, &p);
    assert!(s.invoke(r#"{"operation":"membership_request"}"#).is_err());
    let backup = call(
        &mut s,
        json!({"operation":"export_recovery","password":"backup password 123"}),
    );
    assert!(!backup.to_string().contains("privateKeyPkcs8"));
    assert!(
        s.invoke(
            &json!({"operation":"verify_backup","file":backup["file"],"password":"wrong"})
                .to_string()
        )
        .is_err()
    );
    let verified = call(
        &mut s,
        json!({"operation":"verify_backup","file":backup["file"],"password":"backup password 123"}),
    );
    assert!(
        s.invoke(r#"{"operation":"membership_request"}"#).is_err(),
        "verification must persist before eligibility"
    );
    let saved = commit(&mut s, &verified);
    assert_ne!(first, saved);
    assert_eq!(
        call(&mut s, json!({"operation":"state"}))["backup_verified"],
        true
    );
    assert!(
        s.invoke(r#"{"operation":"membership_request"}"#).is_err(),
        "separate trust approval required"
    );
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/portable-web/zenith-v3.vector.json"
    ))
    .unwrap();
    let trust = call(
        &mut s,
        json!({"operation":"prepare_trust","trust":{"v3":{"schema":"castalia.zenith-membership-trust-policy.v1","version":1,"roots":[{"issuerId":"zenith-research","keyId":vector["issuerKeyId"],"signatureSuite":"Ed25519","publicKey":vector["issuerPublicKey"]}]}}}),
    );
    commit(&mut s, &trust);
    assert_eq!(
        call(&mut s, json!({"operation":"membership_request"}))["schema"],
        "castalia.zenith-membership-issuance-request.v3"
    );
    call(&mut s, json!({"operation":"lock"}));
    assert!(s.invoke(r#"{"operation":"membership_request"}"#).is_err());
    call(
        &mut s,
        json!({"operation":"unlock","snapshot":saved,"password":"local password 123"}),
    );
    assert_eq!(
        call(&mut s, json!({"operation":"state"}))["backup_verified"],
        true
    );
}
#[test]
fn restore_checks_identity_reencrypts_and_cancel_has_no_commit() {
    let mut original = RecoverySession::new();
    let p = create(&mut original);
    commit(&mut original, &p);
    let key = call(&mut original, json!({"operation":"state"}))["public_key"].clone();
    let backup = call(
        &mut original,
        json!({"operation":"export_recovery","password":"backup password 123"}),
    );
    let mut target = RecoverySession::new();
    let p = call(
        &mut target,
        json!({"operation":"prepare_restore","file":backup["file"],"file_password":"backup password 123","password":"new local password","expected_revision":0}),
    );
    assert_eq!(p["public_key"], key);
    let snapshot = commit(&mut target, &p);
    assert_eq!(
        call(&mut target, json!({"operation":"state"}))["backup_verified"],
        true
    );
    assert!(target.invoke(&json!({"operation":"prepare_restore","file":backup["file"],"file_password":"backup password 123","password":"new local password","expected_revision":1}).to_string()).is_err());
    call(&mut target, json!({"operation":"lock"}));
    assert!(
        target
            .invoke(
                &json!({"operation":"unlock","snapshot":snapshot,"password":"local password 123"})
                    .to_string()
            )
            .is_err()
    );
    call(
        &mut target,
        json!({"operation":"unlock","snapshot":snapshot,"password":"new local password"}),
    );
    assert_eq!(
        call(&mut target, json!({"operation":"state"}))["public_key"],
        key
    );
    let mut cancelled = RecoverySession::new();
    let p = create(&mut cancelled);
    call(&mut cancelled, json!({"operation":"lock"}));
    assert!(
        cancelled
            .invoke(
                &json!({"operation":"commit_candidate","token":p["token"],"expected_revision":0})
                    .to_string()
            )
            .is_err()
    );
}
#[test]
fn bounded_closed_operations_and_revision_checks() {
    let mut s = RecoverySession::new();
    assert!(
        s.invoke(r#"{"operation":"sign","message":"arbitrary"}"#)
            .is_err()
    );
    assert!(s.invoke(r#"{"operation":"prepare_create","password":"short","created_at":1,"expected_revision":0}"#).is_err());
    assert!(s.invoke(r#"{"operation":"state","extra":1}"#).is_err());
    let p = create(&mut s);
    assert!(
        s.invoke(
            &json!({"operation":"commit_candidate","token":p["token"],"expected_revision":12})
                .to_string()
        )
        .is_err()
    );
    commit(&mut s, &p);
    let mut other = RecoverySession::new();
    let q = create(&mut other);
    commit(&mut other, &q);
    let wrong = call(
        &mut other,
        json!({"operation":"export_recovery","password":"backup password 123"}),
    );
    assert!(s.invoke(&json!({"operation":"verify_backup","file":wrong["file"],"password":"backup password 123"}).to_string()).is_err());
}

#[test]
fn data_and_legacy_restore_are_staged_and_do_not_bypass_backup_gate() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let seed = [7u8; 32];
    let mut hash = blake3::Hasher::new();
    hash.update(b"castalia/recovery-key/v1\0");
    hash.update(&seed);
    let key = format!(
        "castalia-recovery-key-v1.{}.{}",
        URL_SAFE_NO_PAD.encode(seed),
        URL_SAFE_NO_PAD.encode(&hash.finalize().as_bytes()[..4])
    );
    let mut source = RecoverySession::new();
    let p = call(
        &mut source,
        json!({"operation":"prepare_legacy","key":key,"password":"local password 123","created_at":1,"expected_revision":0}),
    );
    commit(&mut source, &p);
    assert_eq!(
        call(&mut source, json!({"operation":"state"}))["backup_verified"],
        false
    );
    assert!(
        source
            .invoke(r#"{"operation":"membership_request"}"#)
            .is_err()
    );
    let backup = call(
        &mut source,
        json!({"operation":"export_recovery","password":"backup password 123"}),
    );
    let data = call(
        &mut source,
        json!({"operation":"export_data","password":"data password 123","exported_at":2}),
    );
    let mut target = RecoverySession::new();
    assert!(target.invoke(&json!({"operation":"prepare_restore","file":backup["file"],"file_password":"backup password 123","password":"target password 123","expected_revision":0,"data_file":data["file"],"data_password":"wrong"}).to_string()).is_err());
    assert_eq!(
        call(&mut target, json!({"operation":"state"}))["configured"],
        false
    );
    let p = call(
        &mut target,
        json!({"operation":"prepare_restore","file":backup["file"],"file_password":"backup password 123","password":"target password 123","expected_revision":0,"data_file":data["file"],"data_password":"data password 123"}),
    );
    let snapshot = commit(&mut target, &p);
    assert!(!snapshot.contains("displayName"));
    let summary = call(&mut target, json!({"operation":"data_summary"}));
    assert_eq!(
        summary["contents"]["sections"]["identity"]["subject"]["memberKey"],
        p["public_key"]
    );
    assert!(summary["active_membership"].is_null());
    let p = call(
        &mut target,
        json!({"operation":"prepare_data","file":data["file"],"password":"data password 123"}),
    );
    call(&mut target, json!({"operation":"cancel"}));
    assert!(
        target
            .invoke(
                &json!({"operation":"commit_candidate","token":p["token"],"expected_revision":1})
                    .to_string()
            )
            .is_err()
    );
}

#[test]
fn historical_short_password_and_failed_preparation_preserve_boundaries() {
    let (_, historical) = castalia_wallet_core::create_wallet("old", 1).unwrap();
    let mut restored = RecoverySession::new();
    let preview = call(
        &mut restored,
        json!({
            "operation":"prepare_restore", "file":historical.as_str(),
            "file_password":"old", "password":"new local password", "expected_revision":0
        }),
    );
    // Extension-independent content classification accepts the old custody
    // envelope; an attempted replacement invalidates the earlier preview.
    assert!(
        restored
            .invoke(
                &json!({
                    "operation":"prepare_restore", "file":" ".repeat(1_048_577),
                    "file_password":"old", "password":"new local password", "expected_revision":0
                })
                .to_string()
            )
            .is_err()
    );
    assert!(restored.invoke(&json!({"operation":"commit_candidate", "token":preview["token"], "expected_revision":0}).to_string()).is_err());
    assert_eq!(
        call(&mut restored, json!({"operation":"state"}))["configured"],
        false
    );
    let preview = call(
        &mut restored,
        json!({
            "operation":"prepare_restore", "file":historical.as_str(),
            "file_password":"old", "password":"new local password", "expected_revision":0
        }),
    );
    commit(&mut restored, &preview);
    assert_eq!(
        call(&mut restored, json!({"operation":"state"}))["backup_verified"],
        true
    );
    let mut migrated = RecoverySession::new();
    let preview = call(
        &mut migrated,
        json!({"operation":"prepare_existing", "file":historical.as_str(),"password":"old","legacy_confirmed":true,"expected_revision":0}),
    );
    commit(&mut migrated, &preview);
    let state = call(&mut migrated, json!({"operation":"state"}));
    assert_eq!(state["backup_eligible"], true);
    assert_eq!(state["backup_verified"], false);
}

#[test]
fn graph_access_needs_backup_and_wallet_control_not_community_membership() {
    let mut s = RecoverySession::new();
    let preview = create(&mut s);
    commit(&mut s, &preview);
    assert!(
        s.invoke(r#"{"operation":"graph_access_identity_v2"}"#)
            .is_err()
    );
    let backup = call(
        &mut s,
        json!({"operation":"export_recovery","password":"backup password 123"}),
    );
    let verified = call(
        &mut s,
        json!({"operation":"verify_backup","file":backup["file"],"password":"backup password 123"}),
    );
    commit(&mut s, &verified);
    assert_eq!(
        call(&mut s, json!({"operation":"state"}))["membership_active"],
        false
    );
    assert_eq!(
        s.invoke(r#"{"operation":"read_access_identity"}"#)
            .unwrap_err(),
        "membership_required",
        "Historical native API retains its membership gate"
    );
    let identity = call(&mut s, json!({"operation":"graph_access_identity_v2"}));
    let receiver = "https://graph.example.test";
    let pin = json!({"issuer":"fixture","receiver":receiver,"key_id":"fixture","public_key":"22".repeat(32),"audience":"devgraph"});
    let challenge = json!({"schema":"castalia.access-request-challenge.v1","challenge_id":"aa".repeat(16),"nonce":"A".repeat(43),"issuer":"fixture","receiver":receiver,"subject_public_key":identity["subject_public_key"],"installation_id":identity["installation_id"],"operation":"access.request","issued_at":100,"expires_at":220,"details":{"intent":null}});
    let prepared = call(
        &mut s,
        json!({"operation":"prepare_graph_access_request_v2","challenge":challenge.to_string(),"pin":pin,"now":101}),
    );
    let approved = call(
        &mut s,
        json!({"operation":"approve_graph_access_request_v2","token":prepared["token"],"now":102}),
    );
    assert_eq!(
        approved["proof"],
        json!({}),
        "No synthetic membership proof"
    );
    assert_eq!(approved["challenge"], challenge);
    assert!(s.invoke(&json!({"operation":"approve_graph_access_request_v2","token":prepared["token"],"now":103}).to_string()).is_err(),"Consent is one shot");
    assert_eq!(
        s.invoke(
            &json!({"operation":"graph_read_credential_v2","receiver":receiver,"now":103})
                .to_string()
        )
        .unwrap_err(),
        "access_setup_required"
    );
    assert!(
        s.invoke(r#"{"operation":"membership_request"}"#).is_err(),
        "Graph access is not membership"
    );
    call(&mut s, json!({"operation":"lock"}));
    assert_eq!(
        s.invoke(r#"{"operation":"graph_access_identity_v2"}"#)
            .unwrap_err(),
        "wallet_locked"
    );
}

#[test]
fn native_operator_consent_is_explicit_one_shot_and_lifecycle_bound() {
    let mut s = RecoverySession::new();
    let p = create(&mut s);
    commit(&mut s, &p);
    let backup = call(
        &mut s,
        json!({"operation":"export_recovery","password":"backup password 123"}),
    );
    let verified = call(
        &mut s,
        json!({"operation":"verify_backup","file":backup["file"],"password":"backup password 123"}),
    );
    commit(&mut s, &verified);
    let identity = call(&mut s, json!({"operation":"graph_access_identity_v2"}));
    let pin = json!({"issuer":"fixture","receiver":"https://graph.example.test","key_id":"fixture","public_key":"22".repeat(32),"audience":"devgraph"});
    let challenge = |op: &str| json!({"schema":"castalia.access-request-challenge.v1","challenge_id":"aa".repeat(16),"nonce":"A".repeat(43),"issuer":"fixture","receiver":"https://graph.example.test","subject_public_key":identity["subject_public_key"],"installation_id":identity["installation_id"],"operation":op,"issued_at":100,"expires_at":220,"details":{"action":{"schema":"devgraph.access-operator-action.v1","action":"inbox","action_id":"bb".repeat(16)},"policy_revision":1,"policy_digest_sha256":"cc".repeat(32)}});
    assert_eq!(
        call(&mut s, json!({"operation":"state"}))["operator_access_protocol"],
        "castalia.operator-access.v1"
    );
    for op in [
        "access.inbox",
        "access.review",
        "access.decide",
        "access.status",
    ] {
        let c = challenge(op);
        let prepared = call(
            &mut s,
            json!({"operation":"prepare_operator_access_v1","challenge":c.to_string(),"pin":pin,"now":101}),
        );
        assert_eq!(
            prepared["summary"]["native_protocol"],
            "castalia.operator-access.v1"
        );
        assert_eq!(prepared["summary"]["details"], c["details"]);
        let approved = call(
            &mut s,
            json!({"operation":"approve_operator_access_v1","token":prepared["token"],"now":102}),
        );
        assert_eq!(approved["challenge"], c);
        assert!(approved["signature"].as_str().is_some());
        assert!(s.invoke(&json!({"operation":"approve_operator_access_v1","token":prepared["token"],"now":103}).to_string()).is_err());
        if op != "access.status" {
            assert!(s.invoke(&json!({"operation":"prepare_graph_access_request_v2","challenge":c.to_string(),"pin":pin,"now":101}).to_string()).is_err(),"Member API stays narrow");
        }
    }
    assert!(s.invoke(&json!({"operation":"prepare_operator_access_v1","challenge":challenge("access.request").to_string(),"pin":pin,"now":101}).to_string()).is_err());
    let prepare = |s: &mut RecoverySession| {
        call(
            s,
            json!({"operation":"prepare_operator_access_v1","challenge":challenge("access.decide").to_string(),"pin":pin,"now":101}),
        )
    };
    let p = prepare(&mut s);
    assert!(
        s.invoke(
            &json!({"operation":"approve_operator_access_v1","token":p["token"],"now":220})
                .to_string()
        )
        .is_err()
    );
    assert!(
        s.invoke(
            &json!({"operation":"approve_operator_access_v1","token":p["token"],"now":102})
                .to_string()
        )
        .is_err()
    );
    let p = prepare(&mut s);
    call(&mut s, json!({"operation":"lock"}));
    assert!(
        s.invoke(
            &json!({"operation":"approve_operator_access_v1","token":p["token"],"now":102})
                .to_string()
        )
        .is_err()
    );
}
