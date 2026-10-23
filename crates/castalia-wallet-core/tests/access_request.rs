use castalia_wallet_core::{access_request::PreparedAccessRequest, browser_read::ReadSigner};
use castalia_wallet_presentation::{Caller, TrustPin};
use serde_json::{Value, json};

struct Signer;
impl ReadSigner for Signer {
    fn read_public_key(&self) -> String {
        "11".repeat(32)
    }
    fn read_sign(&self, bytes: &[u8]) -> Result<[u8; 64], &'static str> {
        assert!(bytes.starts_with(b"castalia/access-request-approval/v1\0"));
        Ok([7; 64])
    }
}
fn fixture() -> (Value, Caller, Vec<TrustPin>) {
    let caller = Caller {
        kind: "browser".into(),
        id: "https://example.test".into(),
    };
    let pins = vec![TrustPin {
        issuer: "fixture".into(),
        key_id: "key".into(),
        public_key: "22".repeat(32),
        audience: "service".into(),
        callers: vec![caller.clone()],
    }];
    let challenge = json!({"schema":"castalia.access-request-challenge.v1","challenge_id":"aa".repeat(16),"nonce":"A".repeat(43),"issuer":"fixture","receiver":caller.id,"subject_public_key":"11".repeat(32),"installation_id":"bb".repeat(16),"operation":"access.request","issued_at":100,"expires_at":220,"details":{"schema":"example.request.v1","intent":null}});
    (challenge, caller, pins)
}
#[test]
fn neutral_request_is_exact_disclosed_and_one_shot() {
    let (raw, caller, pins) = fixture();
    let prepared = PreparedAccessRequest::prepare(
        &raw.to_string(),
        &"11".repeat(32),
        &"bb".repeat(16),
        &pins,
        &caller,
        100,
    )
    .unwrap();
    let summary = prepared.summary();
    assert_eq!(summary["operation"], "access.request");
    assert_eq!(summary["details"], raw["details"]);
    assert_eq!(prepared.approve(&Signer, 101).unwrap()["challenge"], raw);
}
#[test]
fn request_denies_wrong_identity_receiver_pin_time_and_unsafe_details() {
    let (raw, caller, pins) = fixture();
    for (field, value) in [
        ("receiver", json!("https://wrong.test")),
        ("subject_public_key", json!("33".repeat(32))),
        ("installation_id", json!("cc".repeat(16))),
        ("operation", json!("sign.arbitrary")),
        ("expires_at", json!(221)),
        ("details", json!({"value":1.5})),
    ] {
        let mut changed = raw.clone();
        changed[field] = value;
        assert!(
            PreparedAccessRequest::prepare(
                &changed.to_string(),
                &"11".repeat(32),
                &"bb".repeat(16),
                &pins,
                &caller,
                100
            )
            .is_err(),
            "{field}"
        );
    }
    assert!(
        PreparedAccessRequest::prepare(
            &raw.to_string(),
            &"11".repeat(32),
            &"bb".repeat(16),
            &[],
            &caller,
            100
        )
        .is_err()
    );
    let p = PreparedAccessRequest::prepare(
        &raw.to_string(),
        &"11".repeat(32),
        &"bb".repeat(16),
        &pins,
        &caller,
        100,
    )
    .unwrap();
    assert!(p.approve(&Signer, 220).is_err());
}
