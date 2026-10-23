use castalia_wallet_core::{browser_read::PreparedReadAccess, create_wallet};
use castalia_wallet_presentation::{Caller, TrustPin, read_authority::*};
use ed25519_dalek::SigningKey;
use serde_json::json;

fn fixture() -> (
    castalia_wallet_core::OpenedWallet,
    SigningKey,
    Policy,
    String,
    Vec<TrustPin>,
    Caller,
) {
    let (wallet, _) = create_wallet("disposable passphrase", 1).unwrap();
    let issuer = SigningKey::from_bytes(&[9; 32]);
    let policy = Policy {
        schema: "castalia.read-policy.v1".into(),
        issuer: "fixture".into(),
        key_id: "test".into(),
        public_key: hex::encode(issuer.verifying_key().to_bytes()),
        receiver: "https://server.example.test".into(),
        audience: "example".into(),
        max_lifetime_seconds: 600,
        permissions: vec![Permission {
            operation: "example.list".into(),
            resource: "https://server.example.test/work".into(),
            constraints: json!({"items":["one"]}),
        }],
    };
    let caller = Caller {
        kind: "browser".into(),
        id: "https://app.example.test".into(),
    };
    let pins = vec![TrustPin {
        issuer: policy.issuer.clone(),
        key_id: policy.key_id.clone(),
        public_key: policy.public_key.clone(),
        audience: policy.audience.clone(),
        callers: vec![caller.clone()],
    }];
    let raw=json!({"schema":"castalia.read-access-challenge.v1","request_id":"33".repeat(16),
        "nonce":"A".repeat(43),"subject_public_key":wallet.public_key_hex(),"installation_id":"22".repeat(16),
        "issuer":"fixture","receiver":policy.receiver,"issued_at":100,"expires_at":220,
        "credential_expires_at":700,"details":{"authority_policy":policy}}).to_string();
    (wallet, issuer, policy, raw, pins, caller)
}

#[test]
fn custody_approval_and_issuer_result_are_required_before_read_proofs() {
    let (wallet, issuer, policy, raw, pins, caller) = fixture();
    let prepared = PreparedReadAccess::prepare(
        &raw,
        &wallet.public_key_hex(),
        &"22".repeat(16),
        &pins,
        &caller,
        101,
    )
    .unwrap();
    let approved = prepared.approve(&wallet, 102).unwrap();
    let claims = Claims {
        schema: "castalia.read-credential.v1".into(),
        credential_id: "44".repeat(16),
        holder_public_key: wallet.public_key_hex(),
        installation_id: "22".repeat(16),
        issuer: policy.issuer.clone(),
        key_id: policy.key_id.clone(),
        receiver: policy.receiver.clone(),
        audience: policy.audience.clone(),
        policy_digest: policy.digest().unwrap(),
        permissions: policy.permissions.clone(),
        issued_at: 103,
        expires_at: 700,
    };
    let credential = issue(&policy, claims, &issuer, 103).unwrap();
    let connection = approved.accept(credential, 104).unwrap();
    let call = Call {
        operation: "example.list".into(),
        resource: "https://server.example.test/work".into(),
        parameters: json!({"limit":1}),
    };
    let proof = connection
        .present(&wallet, &call, "55".repeat(16), 105)
        .unwrap();
    assert!(
        verify_call(
            &policy,
            &connection.access.credential,
            &call,
            &proof,
            true,
            105
        )
        .is_ok()
    );
    let wrong = Call {
        operation: "example.write".into(),
        ..call
    };
    assert!(
        connection
            .present(&wallet, &wrong, "66".repeat(16), 105)
            .is_err()
    );
    assert!(
        connection
            .present(&wallet, &wrong, "77".repeat(16), 701)
            .is_err()
    );
}

#[test]
fn read_approval_rejects_untrusted_pin_wrong_origin_identity_and_expiry() {
    let (wallet, _, _, raw, pins, caller) = fixture();
    for (owner, device, now) in [
        ("00".repeat(32), "22".repeat(16), 101),
        (wallet.public_key_hex(), "00".repeat(16), 101),
        (wallet.public_key_hex(), "22".repeat(16), 221),
    ] {
        assert!(PreparedReadAccess::prepare(&raw, &owner, &device, &pins, &caller, now).is_err());
    }
    let wrong = Caller {
        id: "https://evil.example.test".into(),
        ..caller.clone()
    };
    assert!(
        PreparedReadAccess::prepare(
            &raw,
            &wallet.public_key_hex(),
            &"22".repeat(16),
            &pins,
            &wrong,
            101
        )
        .is_err()
    );
    assert!(
        PreparedReadAccess::prepare(
            &raw,
            &wallet.public_key_hex(),
            &"22".repeat(16),
            &[],
            &caller,
            101
        )
        .is_err()
    );
}
