use castalia_wallet_core::{
    access_request::PreparedAccessRequest, create_wallet, read_access::IssuerPin,
};
use serde_json::{Value, json};
fn fixture() -> (castalia_wallet_core::OpenedWallet, IssuerPin, Value) {
    let (wallet, _) = create_wallet("disposable native request passphrase", 1).unwrap();
    let pin = IssuerPin {
        issuer: "test-issuer".into(),
        receiver: "https://graph.example.test".into(),
        key_id: "test-key".into(),
        public_key: "22".repeat(32),
        audience: "devgraph".into(),
    };
    let c = json!({"schema":"castalia.access-request-challenge.v1","challenge_id":"aa".repeat(16),"nonce":"A".repeat(43),"issuer":pin.issuer,"receiver":pin.receiver,"subject_public_key":wallet.public_key_hex(),"installation_id":"bb".repeat(16),"operation":"access.request","issued_at":100,"expires_at":220,"details":{"request":{"request_id":"cc".repeat(16),"intent":null}}});
    (wallet, pin, c)
}
#[test]
fn native_request_uses_the_shared_transcript_without_a_browser_caller() {
    let (wallet, pin, c) = fixture();
    let prepared = PreparedAccessRequest::prepare_native(
        &c.to_string(),
        &wallet.public_key_hex(),
        &"bb".repeat(16),
        &pin,
        100,
    )
    .unwrap();
    assert_eq!(prepared.summary()["details"], c["details"]);
    assert_eq!(prepared.approve(&wallet, 101).unwrap()["challenge"], c);
}
#[test]
fn native_request_rejects_operator_actions_and_changed_identity_origin_or_time() {
    let (wallet, pin, c) = fixture();
    for (field, value) in [
        ("operation", json!("access.decide")),
        ("operation", json!("access.inbox")),
        ("operation", json!("access.review")),
        ("receiver", json!("https://other.example.test")),
        ("issuer", json!("other")),
        ("subject_public_key", json!("33".repeat(32))),
        ("installation_id", json!("dd".repeat(16))),
        ("expires_at", json!(221)),
        ("details", json!({"n":1.5})),
    ] {
        let mut changed = c.clone();
        changed[field] = value;
        assert!(
            PreparedAccessRequest::prepare_native(
                &changed.to_string(),
                &wallet.public_key_hex(),
                &"bb".repeat(16),
                &pin,
                100
            )
            .is_err(),
            "{field}"
        );
    }
    let mut status = c.clone();
    status["operation"] = json!("access.status");
    let prepared = PreparedAccessRequest::prepare_native(
        &status.to_string(),
        &wallet.public_key_hex(),
        &"bb".repeat(16),
        &pin,
        100,
    )
    .unwrap();
    assert!(prepared.approve(&wallet, 220).is_err());
}
