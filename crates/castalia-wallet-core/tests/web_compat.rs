use castalia_wallet_core::{
    create_wallet, import_wallet, web_compat::restore_wallet_from_recovery_key,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::json;

#[test]
fn web_recovery_keeps_the_same_identity_accounts_and_membership_bytes() {
    let (wallet, file) = create_wallet("existing web password", 42).unwrap();
    let (restored, _) =
        restore_wallet_from_recovery_key(&wallet.recovery_key(), "new password", 84).unwrap();
    let imported = import_wallet(file.as_bytes(), "existing web password").unwrap();
    assert_eq!(restored.public_key_hex(), wallet.public_key_hex());
    assert_eq!(
        restored.chain_accounts().unwrap(),
        wallet.chain_accounts().unwrap()
    );
    assert_eq!(
        restored.ml_dsa_public_key_base64url(),
        wallet.ml_dsa_public_key_base64url()
    );
    assert_eq!(imported.recovery_key(), wallet.recovery_key());
    let key = VerifyingKey::from_bytes(
        &hex::decode(wallet.public_key_hex())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let mut transcript = b"castalia/zenith-membership-join/v3\0".to_vec();
    transcript.extend(hex::decode(wallet.public_key_hex()).unwrap());
    key.verify(
        &transcript,
        &Signature::from_bytes(&wallet.sign_zenith_membership_join()),
    )
    .unwrap();
    assert!(wallet.sign_scoped_membership_join("not-a-scope").is_err());
    let mut invalid = wallet.recovery_key().to_string();
    invalid.push('A');
    assert!(restore_wallet_from_recovery_key(&invalid, "password", 1).is_err());
}

#[test]
fn web_identity_and_castaway_are_data_only_owner_bound_and_recoverable() {
    let (wallet, _) = create_wallet("web password", 1).unwrap();
    let (other, _) = create_wallet("other password", 1).unwrap();
    let value = r#"{"schema":"example.identity.v1","name":"Unicode 🐠"}"#;
    let encrypted = wallet.seal_identity_section(value).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            &wallet.open_identity_section(encrypted.as_bytes()).unwrap()
        )
        .unwrap(),
        serde_json::from_str::<serde_json::Value>(value).unwrap()
    );
    assert!(other.open_identity_section(encrypted.as_bytes()).is_err());
    let contents = json!({"schema":"castalia.castaway-contents.v1","version":1,"sections":{"identity":{},"memberships":[],"scopedMemberships":[]}}).to_string();
    let file = wallet
        .export_castaway(&contents, "portable password", 2)
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            &wallet
                .import_castaway(file.as_bytes(), "portable password")
                .unwrap()
        )
        .unwrap(),
        serde_json::from_str::<serde_json::Value>(&contents).unwrap()
    );
    assert!(
        other
            .import_castaway(file.as_bytes(), "portable password")
            .is_err()
    );
    let forbidden = json!({"schema":"castalia.castaway-contents.v1","version":1,"sections":{"identity":{},"privateKey":"forbidden"}}).to_string();
    assert!(
        wallet
            .export_castaway(&forbidden, "portable password", 2)
            .is_err()
    );
}

#[test]
fn framed_folder_backups_survive_recovery_and_reject_tampering() {
    let (wallet, _) = create_wallet("web password", 1).unwrap();
    let (restored, _) =
        restore_wallet_from_recovery_key(&wallet.recovery_key(), "restored password", 2).unwrap();
    let (other, _) = create_wallet("other password", 1).unwrap();
    let zip = vec![37u8; 1024 * 1024 + 17];
    let encrypted = wallet.seal_files_backup(&zip).unwrap();
    assert_eq!(restored.open_files_backup(&encrypted).unwrap(), zip);
    assert!(other.open_files_backup(&encrypted).is_err());
    let mut changed = encrypted.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert!(wallet.open_files_backup(&changed).is_err());
    assert!(
        wallet
            .open_files_backup(&encrypted[..encrypted.len() - 1])
            .is_err()
    );
    let mut extra = encrypted;
    extra.push(0);
    assert!(wallet.open_files_backup(&extra).is_err());
    assert!(wallet.seal_files_backup(&[]).is_err());
}
