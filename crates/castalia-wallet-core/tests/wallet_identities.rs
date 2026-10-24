use castalia_wallet_core::{
    create_wallet,
    portable::{self, Trust},
    wallet_identities,
};
use serde_json::{Value, json};

fn section(owner: &str) -> Value {
    json!({"schema":"castalia.wallet-identities.v1","version":1,"ownerMemberKey":owner,"authority":"descriptor-only","accounts":[
        {"accountId":"018d0000-0000-4000-8000-000000000001","kind":"matrix","label":"Chat","identifier":"@alice:example.test","server":"https://matrix.example.test"},
        {"accountId":"018d0000-0000-4000-8000-000000000002","kind":"nostr","label":"Public identity","identifier":"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","server":"wss://relay.example.test"},
        {"accountId":"018d0000-0000-4000-8000-000000000003","kind":"github","label":"Gallery","identifier":"1234567","server":""},
        {"accountId":"018d0000-0000-4000-8000-000000000004","kind":"x","label":"Social","identifier":"2345678","server":""}
    ]})
}

#[test]
fn strict_descriptors_preserve_all_provider_ids_and_reject_authority() {
    let owner = "11".repeat(32);
    let records = section(&owner);
    assert_eq!(
        records,
        serde_json::from_str::<Value>(include_str!(
            "../../../contracts/wallet-identities/v1/section.json"
        ))
        .unwrap()
    );
    assert_eq!(
        wallet_identities::validate(&records, &owner).unwrap(),
        records
    );
    assert!(wallet_identities::validate(&records, &"22".repeat(32)).is_err());
    for (field, value) in [
        ("privateKey", json!("secret")),
        ("accessToken", json!("secret")),
        ("verified", json!(true)),
    ] {
        let mut bad = records.clone();
        bad["accounts"][0][field] = value;
        assert!(wallet_identities::validate(&bad, &owner).is_err());
    }
    for (field, value) in [
        ("server", "https://user:secret@matrix.example.test"),
        ("identifier", "alice"),
        ("kind", "tailscale"),
    ] {
        let mut bad = records.clone();
        bad["accounts"][0][field] = json!(value);
        assert!(wallet_identities::validate(&bad, &owner).is_err());
    }
    for server in [
        "https://@matrix.example.test",
        "https://matrix.example.test:0",
        "https:matrix.example.test",
        "https://matrix.example.test/path",
    ] {
        let mut bad = records.clone();
        bad["accounts"][0]["server"] = json!(server);
        assert!(wallet_identities::validate(&bad, &owner).is_err());
    }
    let mut bad = records.clone();
    bad["accounts"][1]["identifier"] = json!("nsec1secret");
    assert!(wallet_identities::validate(&bad, &owner).is_err());
    let mut bad = records.clone();
    bad["accounts"][2]["identifier"] = json!("a-username");
    assert!(wallet_identities::validate(&bad, &owner).is_err());
}

#[test]
fn merge_is_idempotent_and_never_overwrites_existing_accounts() {
    let owner = "11".repeat(32);
    let records = section(&owner);
    assert_eq!(
        wallet_identities::merge(&records, &records, &owner).unwrap(),
        records
    );
    let mut incoming = records.clone();
    incoming["accounts"][0]["label"] = json!("Changed elsewhere");
    assert!(wallet_identities::merge(&records, &incoming, &owner).is_err());
    let mut duplicate = records.clone();
    duplicate["accounts"][1] = duplicate["accounts"][0].clone();
    duplicate["accounts"][1]["accountId"] = json!("018d0000-0000-4000-8000-000000000099");
    assert!(wallet_identities::validate(&duplicate, &owner).is_err());
}

#[test]
fn native_and_web_roundtrip_v2_without_changing_legacy_v1() {
    let (wallet, _) = create_wallet("long local password", 1).unwrap();
    let legacy = portable::empty_contents(&wallet, 1).unwrap();
    let mut contents = legacy.clone();
    contents["schema"] = json!("castalia.castaway-contents.v2");
    contents["version"] = json!(2);
    contents["sections"]["walletIdentities"] = section(&wallet.public_key_hex());
    portable::validate(&wallet, &contents, &Trust::default()).unwrap();
    let native =
        portable::export(&wallet, &contents, "backup password", 2, &Trust::default()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&native).unwrap()["schema"],
        "castalia.castaway.v2"
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            &wallet
                .import_castaway(native.as_bytes(), "backup password")
                .unwrap()
        )
        .unwrap(),
        contents
    );
    let web = wallet
        .export_castaway(&contents.to_string(), "backup password", 3)
        .unwrap();
    assert_eq!(
        portable::import(&wallet, &web, "backup password", &Trust::default()).unwrap(),
        contents
    );
    let old = portable::export(&wallet, &legacy, "backup password", 2, &Trust::default()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&old).unwrap()["schema"],
        "castalia.castaway.v1"
    );
    assert_eq!(
        portable::import(&wallet, &old, "backup password", &Trust::default()).unwrap(),
        legacy
    );
    let mut mislabeled = contents.clone();
    mislabeled["schema"] = json!("castalia.castaway-contents.v1");
    mislabeled["version"] = json!(1);
    assert!(portable::validate(&wallet, &mislabeled, &Trust::default()).is_err());
    assert!(
        wallet
            .export_castaway(&mislabeled.to_string(), "backup password", 2)
            .is_err()
    );
}

#[test]
fn session_stages_preserves_and_merges_records_across_recovery_and_old_imports() {
    use castalia_wallet_core::recovery_session::RecoverySession;
    fn call(s: &mut RecoverySession, value: Value) -> Value {
        s.invoke(&value.to_string()).unwrap()
    }
    fn commit(s: &mut RecoverySession, preview: &Value) -> String {
        let candidate = call(
            s,
            json!({"operation":"commit_candidate","token":preview["token"],"expected_revision":preview["expected_revision"]}),
        );
        let snapshot = candidate["snapshot"].as_str().unwrap().to_owned();
        call(
            s,
            json!({"operation":"confirm_commit","token":preview["token"],"snapshot":snapshot}),
        );
        snapshot
    }
    let mut original = RecoverySession::new();
    let preview = call(
        &mut original,
        json!({"operation":"prepare_create","password":"long local password","created_at":1,"expected_revision":0}),
    );
    commit(&mut original, &preview);
    let identity = call(&mut original, json!({"operation":"identity"}));
    let owner = identity["ownerPublicKey"].as_str().unwrap();
    let old_file = call(
        &mut original,
        json!({"operation":"export_data","password":"backup password","exported_at":2}),
    );
    let records = section(owner);
    let preview = call(
        &mut original,
        json!({"operation":"prepare_wallet_identities","identities":records,"expected_revision":1}),
    );
    assert_eq!(preview["wallet_identities"], records);
    assert_eq!(
        call(&mut original, json!({"operation":"wallet_identities"}))["accounts"],
        json!([])
    );
    call(&mut original, json!({"operation":"cancel"}));
    assert!(original.invoke(&json!({"operation":"commit_candidate","token":preview["token"],"expected_revision":1}).to_string()).is_err());
    let preview = call(
        &mut original,
        json!({"operation":"prepare_wallet_identities","identities":records,"expected_revision":1}),
    );
    let snapshot = commit(&mut original, &preview);
    assert_eq!(
        call(&mut original, json!({"operation":"wallet_identities"})),
        records
    );
    assert!(original.invoke(&json!({"operation":"prepare_wallet_identities","identities":records,"expected_revision":1}).to_string()).is_err());
    let old_import = call(
        &mut original,
        json!({"operation":"prepare_data","file":old_file["file"],"password":"backup password"}),
    );
    assert_eq!(old_import["wallet_identities"], records);
    commit(&mut original, &old_import);
    let recovery = call(
        &mut original,
        json!({"operation":"export_recovery","password":"recovery password"}),
    );
    let file = call(
        &mut original,
        json!({"operation":"export_data","password":"backup password","exported_at":3}),
    );
    let mut target = RecoverySession::new();
    let restored = call(
        &mut target,
        json!({"operation":"prepare_restore","file":recovery["file"],"file_password":"recovery password","password":"new local password","expected_revision":0,"data_file":file["file"],"data_password":"backup password"}),
    );
    assert_eq!(restored["wallet_identities"], records);
    commit(&mut target, &restored);
    assert_eq!(call(&mut target, json!({"operation":"identity"})), identity);
    assert_eq!(
        call(&mut target, json!({"operation":"wallet_identities"})),
        records
    );
    let mut reloaded = RecoverySession::new();
    call(
        &mut reloaded,
        json!({"operation":"unlock","snapshot":snapshot,"password":"long local password"}),
    );
    assert_eq!(
        call(&mut reloaded, json!({"operation":"wallet_identities"})),
        records
    );
    call(&mut reloaded, json!({"operation":"lock"}));
    assert!(
        reloaded
            .invoke(r#"{"operation":"wallet_identities"}"#)
            .is_err()
    );
    assert!(
        reloaded
            .invoke(r#"{"operation":"chain_accounts"}"#)
            .is_err()
    );
}

#[test]
fn portable_descriptor_checks_exclude_hidden_authority_without_activating_proofs() {
    use sha2::{Digest, Sha256};
    let (wallet, _) = create_wallet("long local password", 1).unwrap();
    let mut contents = portable::with_wallet_identities(
        &portable::empty_contents(&wallet, 1).unwrap(),
        &section(&wallet.public_key_hex()),
        &wallet.public_key_hex(),
    )
    .unwrap();
    let mut id = b"castalia/zenith-membership-id/v3\0".to_vec();
    id.extend(hex::decode(wallet.public_key_hex()).unwrap());
    contents["sections"]["memberships"] = json!([{"schema":"castalia.zenith-membership-credential.v3","version":3,"membershipId":hex::encode(Sha256::digest(id)),"ownerPublicKey":wallet.public_key_hex(),"status":"active","issuerId":"synthetic","issuerKeyId":"untrusted-fixture","signatureSuite":"Ed25519","issuerSignature":"A".repeat(86)}]);
    portable::validate_descriptors(&wallet, &contents).unwrap();
    assert!(portable::validate(&wallet, &contents, &Trust::default()).is_err());
    let mut hidden = contents.clone();
    hidden["sections"]["identity"]["subject"]["privateKey"] = json!("forbidden");
    assert!(
        wallet
            .validate_castaway_descriptors(&hidden.to_string())
            .is_err()
    );
    assert!(
        wallet
            .export_castaway(&hidden.to_string(), "backup password", 2)
            .is_err()
    );
    hidden = contents.clone();
    hidden["sections"]["memberships"][0]["bearerToken"] = json!("forbidden");
    assert!(
        wallet
            .validate_castaway_descriptors(&hidden.to_string())
            .is_err()
    );
}
