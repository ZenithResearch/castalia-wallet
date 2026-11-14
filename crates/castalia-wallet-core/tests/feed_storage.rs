use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use castalia_wallet_core::{
    OpenedWallet, create_wallet, import_wallet,
    portable::{self, Trust},
    recovery_session::RecoverySession,
    wallet_identities,
};
use serde_json::{Value, json};

fn feeds() -> Value {
    serde_json::from_str(include_str!("../../../contracts/feeds/v1/section.json")).unwrap()
}
fn data(wallet: &OpenedWallet) -> Value {
    let mut contents = portable::empty_contents(wallet, 1).unwrap();
    contents["schema"] = json!("castalia.castaway-contents.v3");
    contents["version"] = json!(3);
    contents["sections"]["feeds"] = feeds();
    contents
}
fn file(owner: &str, contents: &Value) -> String {
    let salt = [19u8; 16];
    let nonce = [23u8; 12];
    let mut header = json!({"schema":"castalia.castaway.v3","contentsSchema":"castalia.castaway-contents.v3","ownerPublicKey":owner,"exportedAt":2,
        "kdf":{"name":"Argon2id","version":19,"salt":B64.encode(salt),"memoryKiB":65536,"iterations":3,"parallelism":1,"derivedKeyBytes":32},
        "aead":{"name":"AES-256-GCM","nonce":B64.encode(nonce),"tagBits":128}});
    let mut key = [0u8; 32];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 1, Some(32)).unwrap(),
    )
    .hash_password_into(b"backup password", &salt, &mut key)
    .unwrap();
    let ciphertext = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &serde_jcs::to_vec(contents).unwrap(),
                aad: &serde_jcs::to_vec(&header).unwrap(),
            },
        )
        .unwrap();
    header["ciphertext"] = json!(B64.encode(ciphertext));
    serde_jcs::to_string(&header).unwrap()
}
fn call(session: &mut RecoverySession, request: Value) -> Value {
    session.invoke(&request.to_string()).unwrap()
}
fn commit(session: &mut RecoverySession, preview: &Value) -> String {
    let candidate = call(
        session,
        json!({"operation":"commit_candidate","token":preview["token"],"expected_revision":preview["expected_revision"]}),
    );
    let snapshot = candidate["snapshot"].as_str().unwrap().to_owned();
    call(
        session,
        json!({"operation":"confirm_commit","token":preview["token"],"snapshot":snapshot}),
    );
    snapshot
}
fn setup() -> (Box<OpenedWallet>, Box<RecoverySession>, String) {
    let mut session = Box::new(RecoverySession::new());
    let preview = call(
        &mut session,
        json!({"operation":"prepare_create","password":"long local password","created_at":1,"expected_revision":0}),
    );
    let snapshot = commit(&mut session, &preview);
    // Obtain the independent test encryptor outside invoke's large debug frame.
    let recovery = call(
        &mut session,
        json!({"operation":"export_recovery","password":"long local password"}),
    );
    let wallet = Box::new(
        import_wallet(
            recovery["file"].as_str().unwrap().as_bytes(),
            "long local password",
        )
        .unwrap(),
    );
    (wallet, session, snapshot)
}
fn summary(session: &mut RecoverySession) -> Value {
    call(session, json!({"operation":"data_summary"}))["contents"].clone()
}
fn import(session: &mut RecoverySession, file: &str, previous: Option<&Value>) -> Value {
    let mut request = json!({"operation":"prepare_data","file":file,"password":"backup password"});
    if let Some(previous) = previous {
        request["previous_contents"] = previous.clone();
    }
    call(session, request)
}

fn run_storage_test(test: fn()) {
    // Exact reviewed-main production code reproduces the 2 MiB overflow with
    // this debug harness: the unoptimized dispatcher alone reserves ~1.2 MiB.
    // Release tests deliberately run on the unchanged default test thread stack.
    #[cfg(debug_assertions)]
    {
        if let Err(error) = std::thread::Builder::new()
            .name("feed-storage-debug".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(test)
            .unwrap()
            .join()
        {
            std::panic::resume_unwind(error);
        }
    }
    #[cfg(not(debug_assertions))]
    test();
}

#[test]
fn feed_candidates_preserve_committed_data_across_cancel_legacy_empty_and_identity_edits() {
    run_storage_test(feed_candidates_preserve);
}
fn feed_candidates_preserve() {
    let (wallet, mut session, initial) = setup();
    let contents = data(&wallet);
    let incoming = file(&wallet.public_key_hex(), &contents);
    let legacy = portable::empty_contents(&wallet, 1).unwrap();
    let old_file =
        portable::export(&wallet, &legacy, "backup password", 2, &Trust::default()).unwrap();
    let preview = import(&mut session, &incoming, None);
    assert_eq!(
        preview["imported_feed_subscriptions"],
        contents["sections"]["feeds"]["subscriptions"]
            .as_array()
            .unwrap()
            .len()
    );
    assert_eq!(
        preview["imported_feed_collections"],
        contents["sections"]["feeds"]["collections"]
            .as_array()
            .unwrap()
            .len()
    );
    assert_eq!(
        preview["memberships"]["feeds"],
        contents["sections"]["feeds"]
    );
    assert!(summary(&mut session).is_null());
    let staged = call(
        &mut session,
        json!({"operation":"commit_candidate","token":preview["token"],"expected_revision":preview["expected_revision"]}),
    );
    assert!(summary(&mut session).is_null());
    call(&mut session, json!({"operation":"cancel"}));
    assert!(session.invoke(&json!({"operation":"confirm_commit","token":preview["token"],"snapshot":staged["snapshot"]}).to_string()).is_err());
    let mut unchanged = Box::new(RecoverySession::new());
    call(
        &mut unchanged,
        json!({"operation":"unlock","snapshot":initial,"password":"long local password"}),
    );
    assert!(summary(&mut unchanged).is_null());
    let preview = import(&mut session, &incoming, None);
    let persisted = commit(&mut session, &preview);
    assert_eq!(summary(&mut session), contents);
    call(&mut session, json!({"operation":"lock"}));
    call(
        &mut session,
        json!({"operation":"unlock","snapshot":persisted,"password":"long local password"}),
    );
    assert_eq!(summary(&mut session), contents);
    let older = import(&mut session, &old_file, Some(&legacy));
    assert_eq!(older["imported_feed_subscriptions"], 0);
    assert_eq!(older["memberships"]["feeds"], contents["sections"]["feeds"]);
    commit(&mut session, &older);
    let mut empty = contents.clone();
    empty["sections"]["feeds"]["subscriptions"] = json!([]);
    empty["sections"]["feeds"]["collections"] = json!([]);
    let preview = import(&mut session, &file(&wallet.public_key_hex(), &empty), None);
    commit(&mut session, &preview);
    assert_eq!(
        summary(&mut session)["sections"]["feeds"],
        contents["sections"]["feeds"]
    );
    let revision = call(&mut session, json!({"operation":"state"}))["revision"].clone();
    let edit = call(
        &mut session,
        json!({"operation":"prepare_wallet_identities","identities":wallet_identities::empty(&wallet.public_key_hex()),"expected_revision":revision}),
    );
    assert_eq!(edit["memberships"]["feeds"], contents["sections"]["feeds"]);
    let snapshot = commit(&mut session, &edit);
    assert_eq!(summary(&mut session)["version"], 3);
    assert_eq!(
        session
            .invoke(
                &json!({"operation":"export_data","password":"backup password","exported_at":2})
                    .to_string()
            )
            .unwrap_err(),
        "feed_writer_not_qualified"
    );
    assert_eq!(
        call(&mut session, json!({"operation":"state"}))["membership_active"],
        false
    );
    let mut reopened = Box::new(RecoverySession::new());
    call(
        &mut reopened,
        json!({"operation":"unlock","snapshot":snapshot,"password":"long local password"}),
    );
    assert_eq!(summary(&mut reopened), summary(&mut session));
}

#[test]
fn conflicting_feed_import_invalidates_old_preview_and_exact_confirmation_is_required() {
    run_storage_test(conflicting_feed_import);
}
fn conflicting_feed_import() {
    let (wallet, mut session, _) = setup();
    let contents = data(&wallet);
    let incoming = file(&wallet.public_key_hex(), &contents);
    let first = import(&mut session, &incoming, None);
    commit(&mut session, &first);
    let previous = summary(&mut session);
    let pending = import(&mut session, &incoming, None);
    let mut bad = contents.clone();
    bad["sections"]["feeds"]["subscriptions"][0]["title"] = json!("Conflicting title");
    let conflict = file(&wallet.public_key_hex(), &bad);
    assert_eq!(
        session
            .invoke(
                &json!({"operation":"prepare_data","file":conflict,"password":"backup password"})
                    .to_string()
            )
            .unwrap_err(),
        "feed_conflict"
    );
    assert!(session.invoke(&json!({"operation":"commit_candidate","token":pending["token"],"expected_revision":pending["expected_revision"]}).to_string()).is_err());
    assert_eq!(summary(&mut session), previous);
    let review = import(&mut session, &incoming, None);
    assert!(session.invoke(&json!({"operation":"commit_candidate","token":review["token"],"expected_revision":0}).to_string()).is_err());
    let candidate = call(
        &mut session,
        json!({"operation":"commit_candidate","token":review["token"],"expected_revision":review["expected_revision"]}),
    );
    assert!(session.invoke(&json!({"operation":"confirm_commit","token":review["token"],"snapshot":"not the persisted candidate"}).to_string()).is_err());
    assert_eq!(summary(&mut session), previous);
    call(
        &mut session,
        json!({"operation":"confirm_commit","token":review["token"],"snapshot":candidate["snapshot"]}),
    );
    assert!(session.invoke(&json!({"operation":"confirm_commit","token":review["token"],"snapshot":candidate["snapshot"]}).to_string()).is_err());
}

#[test]
fn restore_with_synthetic_v3_data_is_reviewed_and_reopens_without_activation() {
    run_storage_test(restore_with_synthetic_v3_data);
}
fn restore_with_synthetic_v3_data() {
    let (wallet, _) = create_wallet("long local password", 1).unwrap();
    let recovery = wallet.export_randomized("recovery password").unwrap();
    let contents = data(&wallet);
    let mut session = Box::new(RecoverySession::new());
    let preview = call(
        &mut session,
        json!({"operation":"prepare_restore", "file":recovery.as_str(), "file_password":"recovery password", "password":"new local password", "expected_revision":0, "data_file":file(&wallet.public_key_hex(), &contents), "data_password":"backup password"}),
    );
    assert_eq!(preview["memberships"], contents["sections"]);
    assert_eq!(preview["imported_feed_subscriptions"], 1);
    assert_eq!(preview["imported_feed_collections"], 1);
    assert_eq!(
        call(&mut session, json!({"operation":"state"}))["configured"],
        false
    );
    let snapshot = commit(&mut session, &preview);
    assert_eq!(summary(&mut session), contents);
    assert_eq!(
        call(&mut session, json!({"operation":"state"}))["membership_active"],
        false
    );
    call(&mut session, json!({"operation":"lock"}));
    call(
        &mut session,
        json!({"operation":"unlock","snapshot":snapshot,"password":"new local password"}),
    );
    assert_eq!(summary(&mut session), contents);
}
