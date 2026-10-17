use castalia_wallet_core::{
    VerificationContext, canonical_member_application_bytes,
    canonical_membership_enrollment_challenge_bytes, commit_member_application,
    parse_membership_presentation_v2, verify_membership_presentation_v2,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTOR_JSON: &str =
    include_str!("../../../docs/vectors/castalia-wallet-membership-presentation-v2.vector.json");
const VECTOR_CHECKSUM: &str = include_str!(
    "../../../docs/vectors/castalia-wallet-membership-presentation-v2.vector.json.sha256"
);

#[test]
fn reproduces_v2_application_challenge_signature_and_tamper_rejections() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(VECTOR_JSON.as_bytes())),
        VECTOR_CHECKSUM.split_whitespace().next().unwrap()
    );
    let application = vector["application"].clone();
    let challenge = vector["challenge"].clone();
    assert_eq!(
        hex::encode(canonical_member_application_bytes(&application).unwrap()),
        vector["expected"]["applicationTranscriptHex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        hex::encode(commit_member_application(&application).unwrap()),
        vector["expected"]["applicationCommitment"]
            .as_str()
            .unwrap()
    );
    let transcript =
        canonical_membership_enrollment_challenge_bytes(&challenge, &application).unwrap();
    assert_eq!(
        hex::encode(&transcript),
        vector["expected"]["challengeTranscriptHex"]
            .as_str()
            .unwrap()
    );
    let domain = b"castalia/wallet-membership-enrollment/v2";
    assert_eq!(transcript[domain.len()], 0);

    let encoded = serde_json::to_vec(&vector["presentation"]).unwrap();
    let presentation = parse_membership_presentation_v2(&encoded).unwrap();
    verify_membership_presentation_v2(
        &presentation,
        &application,
        VerificationContext {
            expected_origin: challenge["origin"].as_str().unwrap(),
            expected_audience: challenge["audience"].as_str().unwrap(),
            now_ms: challenge["issuedAt"].as_u64().unwrap(),
        },
    )
    .unwrap();

    let tampered = vector["tamperedCases"].as_array().unwrap();
    assert_eq!(tampered.len(), 2);
    for case in tampered {
        let presentation =
            parse_membership_presentation_v2(&serde_json::to_vec(&case["presentation"]).unwrap())
                .unwrap();
        assert!(
            verify_membership_presentation_v2(
                &presentation,
                &case["application"],
                VerificationContext {
                    expected_origin: challenge["origin"].as_str().unwrap(),
                    expected_audience: challenge["audience"].as_str().unwrap(),
                    now_ms: challenge["issuedAt"].as_u64().unwrap(),
                },
            )
            .is_err(),
            "checked-in tamper artifact accepted: {}",
            case["name"].as_str().unwrap()
        );
    }

    let duplicate = String::from_utf8(encoded)
        .unwrap()
        .replacen(
            "\"schema\":\"castalia.wallet-membership-presentation.v2\"",
            "\"schema\":\"castalia.wallet-membership-presentation.v2\",\"schema\":\"castalia.wallet-membership-presentation.v2\"",
            1,
        );
    assert!(parse_membership_presentation_v2(duplicate.as_bytes()).is_err());

    for field in [
        "challengeId",
        "nonce",
        "origin",
        "audience",
        "operation",
        "ownerPublicKey",
        "applicationCommitment",
        "signatureSuite",
        "issuedAt",
        "expiresAt",
    ] {
        let mut tampered = vector["presentation"].clone();
        let current = tampered["challenge"][field].clone();
        tampered["challenge"][field] = if let Some(value) = current.as_u64() {
            Value::from(value + 1)
        } else {
            Value::from(format!("{}x", current.as_str().unwrap()))
        };
        let parsed =
            parse_membership_presentation_v2(&serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(
            verify_membership_presentation_v2(
                &parsed,
                &application,
                VerificationContext {
                    expected_origin: challenge["origin"].as_str().unwrap(),
                    expected_audience: challenge["audience"].as_str().unwrap(),
                    now_ms: challenge["issuedAt"].as_u64().unwrap(),
                },
            )
            .is_err(),
            "tampered {field} accepted"
        );
    }
}
