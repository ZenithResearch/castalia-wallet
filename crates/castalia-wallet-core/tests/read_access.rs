use castalia_wallet_core::read_access::Challenge;
use serde_json::json;

#[test]
fn approvals_bind_identity_receiver_installation_and_expiry() {
    let owner = "11".repeat(32);
    let device = "22".repeat(16);
    let challenge = json!({"schema":"castalia.read-access-challenge.v1","request_id":"33".repeat(16),"nonce":"A".repeat(43),"subject_public_key":owner,"installation_id":device,"issuer":"test","receiver":"https://example.test","details":{"schema":"devgraph.native-read-scope.v1","policy_digest":"44".repeat(32),"read_grants":[]},"issued_at":100,"expires_at":220,"credential_expires_at":3700});
    let parsed = Challenge::parse(
        &challenge.to_string(),
        &owner,
        &device,
        "https://example.test",
        101,
    )
    .unwrap();
    assert!(
        parsed
            .transcript()
            .unwrap()
            .starts_with(b"castalia/read-access-approval/v1\0")
    );
    for (key, value) in [
        ("subject_public_key", json!("00".repeat(32))),
        ("installation_id", json!("00".repeat(16))),
        ("receiver", json!("https://evil.test")),
        ("expires_at", json!(100)),
        ("credential_expires_at", json!(100000)),
    ] {
        let mut wrong = challenge.clone();
        wrong[key] = value;
        assert!(
            Challenge::parse(
                &wrong.to_string(),
                &owner,
                &device,
                "https://example.test",
                101
            )
            .is_err()
        );
    }
    assert!(
        Challenge::parse(
            &challenge.to_string(),
            &owner,
            &device,
            "https://example.test",
            221
        )
        .is_err()
    );
    assert!(
        Challenge::parse(
            &challenge.to_string(),
            &owner,
            &device,
            "https://example.test",
            99
        )
        .is_err()
    );
}
