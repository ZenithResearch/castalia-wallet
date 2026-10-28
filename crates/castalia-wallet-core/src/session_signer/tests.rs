use super::SessionKey;
use ed25519_dalek::SigningKey;
use secs_grant_contract::{IssuerPin, Validity, scoped_grants as c};
use serde_json::json;

fn issuer() -> (SigningKey, IssuerPin) {
    let key = SigningKey::from_bytes(&[78; 32]);
    let pin = IssuerPin {
        issuer: "fixture-provider".into(),
        key_id: "fixture-key".into(),
        service: "service:fixture".into(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
    };
    (key, pin)
}
fn permission() -> c::Permission {
    serde_json::from_value(
        json!({"operation":"fixture.read","resource":"fixture:objects",
      "roles":[{"role":"target","selector":{"schema":"secs.resource-selector.v1",
      "service":"service:fixture","kinds":["Object"],"selection":{"mode":"objects",
      "refs":[{"kind":"Object","id":"one"}]}}}],"constraints":{}}),
    )
    .unwrap()
}
fn grant(session: &SessionKey, end: u64) -> c::Grant {
    let (key, pin) = issuer();
    c::issue_grant(
        &pin,
        c::GrantClaims {
            schema: c::GRANT.into(),
            grant_id: "11".repeat(16),
            revision: "22".repeat(32),
            issuer: pin.issuer.clone(),
            key_id: pin.key_id.clone(),
            service: pin.service.clone(),
            holder_public_key: session.public_key(),
            installation_id: Some("33".repeat(16)),
            validity: Validity::Dated {
                not_before: 1000,
                not_after: end,
            },
            max_credential_lifetime_seconds: 60,
            onward_delegation: false,
            permissions: vec![permission()],
        },
        &key,
        1000,
    )
    .unwrap()
}
fn session() -> SessionKey {
    SessionKey::create(issuer().1, "33".repeat(16), 1000, 4600).unwrap()
}

#[test]
fn fresh_identity_native_grant_and_proof_are_verified_by_secs() {
    let mut first = session();
    let second = session();
    assert_ne!(first.public_key(), second.public_key());
    let root = grant(&first, 4600);
    first
        .install_grant(root, 4600, &[permission()], 1000)
        .unwrap();
    let call =
        json!({"operation":"fixture.read","resource":"fixture:objects","parameters":{"id":"one"}});
    let bundle = first.present_call(&call, 1000).unwrap();
    let credential: c::Credential = serde_json::from_value(bundle["credential"].clone()).unwrap();
    let proof = serde_json::from_value(bundle["proof"].clone()).unwrap();
    c::verify_credential(&issuer().1, &credential, 1000).unwrap();
    c::verify_presentation(&issuer().1, &credential, &call, &proof, 1000).unwrap();
    assert_eq!(credential.claims.expires_at, 1060);
    assert_eq!(credential.claims.holder_public_key, first.public_key());
    assert!(!credential.grant.claims.onward_delegation);
}

#[test]
fn root_installation_cannot_change_holder_expiry_or_replace_a_retained_grant() {
    let mut first = session();
    let second = session();
    assert!(
        first
            .install_grant(grant(&second, 4600), 4600, &[permission()], 1000)
            .is_err()
    );
    assert!(
        first
            .install_grant(grant(&first, 4600), 4500, &[permission()], 1000)
            .is_err()
    );
    assert!(
        first
            .install_grant(grant(&first, 4600), 4600, &[], 1000)
            .is_err()
    );
    let root = grant(&first, 4600);
    first
        .install_grant(root.clone(), 4600, &[permission()], 1000)
        .unwrap();
    first
        .install_grant(root, 4600, &[permission()], 1001)
        .unwrap(); // exact original recovery only
    assert!(
        first
            .install_grant(grant(&first, 4500), 4500, &[permission()], 1001)
            .is_err()
    );
}

#[test]
fn session_member_consent_cannot_sign_owner_admin_challenge() {
    let session = session();
    let pin = crate::read_access::IssuerPin {
        issuer: issuer().1.issuer,
        key_id: issuer().1.key_id,
        public_key: issuer().1.public_key,
        receiver: "https://fixture.invalid".into(),
        audience: "fixture-service".into(),
    };
    let challenge = json!({"schema":"castalia.access-request-challenge.v1",
        "challenge_id":"11".repeat(16),"nonce":"AA".to_owned()+&"A".repeat(41),
        "issuer":pin.issuer,"receiver":pin.receiver,"subject_public_key":session.public_key(),
        "installation_id":"33".repeat(16),"operation":"access.decide",
        "issued_at":1000,"expires_at":1120,"details":{}});
    assert!(
        session
            .approve_member_request(&challenge.to_string(), &pin, 1000)
            .is_err()
    );
    let mut changed = challenge;
    changed["operation"] = json!("access.request");
    let mut wrong_pin = pin;
    wrong_pin.public_key = "00".repeat(32);
    assert!(
        session
            .approve_member_request(&changed.to_string(), &wrong_pin, 1000)
            .is_err()
    );
}

#[test]
fn expiry_close_and_unapproved_operations_stop_signing() {
    let mut key = session();
    let call = json!({"operation":"fixture.read","resource":"fixture:objects","parameters":{}});
    assert!(key.present_call(&call, 1000).is_err());
    key.install_grant(grant(&key, 1060), 1060, &[permission()], 1000)
        .unwrap();
    assert!(
        key.present_call(
            &json!({"operation":"fixture.write","resource":"fixture:objects","parameters":{}}),
            1000
        )
        .is_err()
    );
    assert!(key.present_call(&call, 1060).is_err());
    key.close();
    assert!(key.present_call(&call, 1001).is_err());
    assert!(
        key.install_grant(grant(&session(), 4600), 4600, &[permission()], 1001)
            .is_err()
    );
}
