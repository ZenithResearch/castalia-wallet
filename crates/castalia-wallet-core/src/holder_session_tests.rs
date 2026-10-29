use crate::{
    OpenedWallet, holder_sessions::PreparedHolderSession, portable_holder_grants::StoredGrant,
    scoped_holder_grants,
};
use ed25519_dalek::SigningKey;
use secs_grant_contract::{self as c, holder_sessions as s};
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../vendor/secs-grant-contract/tests/fixtures/holder-session-v1.json"
    ))
    .unwrap()
}
fn setup() -> (OpenedWallet, StoredGrant, s::Challenge, s::Context) {
    let v = vector();
    let wallet = OpenedWallet::from_signing_key(SigningKey::from_bytes(&[62; 32]), 90);
    let stored = StoredGrant::V2(scoped_holder_grants::StoredGrant {
        pin: serde_json::from_value(v["pin"].clone()).unwrap(),
        grant: serde_json::from_value(v["parent_grant"].clone()).unwrap(),
        saved_at: 100,
    });
    (
        wallet,
        stored,
        serde_json::from_value(v["challenge"].clone()).unwrap(),
        serde_json::from_value(v["context"].clone()).unwrap(),
    )
}

#[test]
fn typed_holder_review_discloses_exact_public_authority_and_approval_matches_vector() {
    let (wallet, stored, challenge, context) = setup();
    let prepared = PreparedHolderSession::prepare(
        &wallet,
        stored,
        challenge,
        context,
        "66666666666666666666666666666666",
        101,
    )
    .unwrap();
    let summary = prepared.summary();
    assert_eq!(summary["schema"], "castalia.holder-session-review.v1");
    assert_eq!(summary["expires_at"], 400);
    assert_eq!(summary["hard_expiry"], true);
    assert_eq!(summary["onward_delegation"], false);
    assert!(summary.get("parent_grant").is_none());
    assert!(summary.get("grant").is_none());
    let approval = prepared
        .approve(
            &wallet,
            vector()["authorization"]["session_signature"]
                .as_str()
                .unwrap()
                .into(),
            102,
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(approval).unwrap(),
        vector()["authorization"]
    );
}

#[test]
fn approval_rechecks_wallet_identity_expiry_installation_and_session_possession() {
    let (wallet, stored, challenge, context) = setup();
    assert!(
        PreparedHolderSession::prepare(
            &wallet,
            stored.clone(),
            challenge.clone(),
            context.clone(),
            &"aa".repeat(16),
            101
        )
        .is_err()
    );
    let prepared = PreparedHolderSession::prepare(
        &wallet,
        stored.clone(),
        challenge.clone(),
        context.clone(),
        &"66".repeat(16),
        101,
    )
    .unwrap();
    assert!(prepared.approve(&wallet, "00".repeat(64), 102).is_err());
    let prepared = PreparedHolderSession::prepare(
        &wallet,
        stored.clone(),
        challenge.clone(),
        context.clone(),
        &"66".repeat(16),
        101,
    )
    .unwrap();
    let other = OpenedWallet::from_signing_key(SigningKey::from_bytes(&[65; 32]), 90);
    assert!(
        prepared
            .approve(
                &other,
                vector()["authorization"]["session_signature"]
                    .as_str()
                    .unwrap()
                    .into(),
                102
            )
            .is_err()
    );
    let prepared =
        PreparedHolderSession::prepare(&wallet, stored, challenge, context, &"66".repeat(16), 101)
            .unwrap();
    assert!(
        prepared
            .approve(
                &wallet,
                vector()["authorization"]["session_signature"]
                    .as_str()
                    .unwrap()
                    .into(),
                220
            )
            .is_err()
    );
}

#[test]
fn public_finite_token_validation_is_exact_and_independent_of_owner_unlock() {
    let v = vector();
    let pin = serde_json::from_value(v["pin"].clone()).unwrap();
    let token: s::Credential = serde_json::from_value(v["credential"].clone()).unwrap();
    let challenge = serde_json::from_value(v["challenge"].clone()).unwrap();
    crate::holder_sessions::verify_returned_credential(&pin, &token, &challenge, 103).unwrap();
    let mut different = challenge.clone();
    different.expires_at = 399;
    assert!(
        crate::holder_sessions::verify_returned_credential(&pin, &token, &different, 103).is_err()
    );
    assert!(
        crate::holder_sessions::verify_returned_credential(&pin, &token, &challenge, 400).is_err()
    );
    assert_eq!(
        token.claims.challenge_digest,
        c::digest(&challenge).unwrap()
    );
}

#[test]
fn isolated_temporary_custody_uses_finite_token_after_owner_is_dropped() {
    let (wallet, stored, mut challenge, context) = setup();
    let pin = serde_json::from_value(vector()["pin"].clone()).unwrap();
    let mut session = crate::session_signer::HolderSessionKey::create(
        pin,
        context.clone(),
        "aa".repeat(16),
        100,
        500,
    )
    .unwrap();
    challenge.session_public_key = session.public_key();
    challenge.session_installation_id = "aa".repeat(16);
    let pop = session.prove_possession(&challenge, 101).unwrap();
    let prepared = PreparedHolderSession::prepare(
        &wallet,
        stored,
        challenge.clone(),
        context.clone(),
        &"66".repeat(16),
        101,
    )
    .unwrap();
    let authorization = prepared.approve(&wallet, pop, 102).unwrap();
    let issuer = SigningKey::from_bytes(&[61; 32]);
    let token = s::issue(
        &serde_json::from_value(vector()["pin"].clone()).unwrap(),
        &authorization,
        "bc".repeat(16),
        &context,
        &issuer,
        102,
    )
    .unwrap();
    session
        // Recovering an already-issued result may finish after the review window.
        // Its original hard end remains unchanged.
        .install_credential(token.clone(), &challenge, 221)
        .unwrap();
    drop(wallet);
    let call = vector()["call"].clone();
    let one = session.present_call(&call, 222).unwrap();
    let two = session.present_call(&call, 222).unwrap();
    assert_ne!(one["proof"]["nonce"], two["proof"]["nonce"]);
    assert_eq!(one["credential"], serde_json::to_value(token).unwrap());
    assert!(one.get("parent_grant").is_none());
    assert!(
        session.prove_possession(&challenge, 223).is_err(),
        "issued key cannot open another session"
    );
    assert!(session.present_call(&call, 400).is_err());
    session.close();
    assert!(session.present_call(&call, 223).is_err());
}
