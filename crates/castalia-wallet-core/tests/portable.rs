use castalia_wallet_core::{
    create_wallet,
    portable::{self, Trust},
};
use serde_json::json;

#[test]
fn identity_roundtrip_rejects_authority_and_wrong_owner() {
    let (wallet, _) = create_wallet("long local password", 1).unwrap();
    let contents = portable::empty_contents(&wallet, 1).unwrap();
    let file =
        portable::export(&wallet, &contents, "backup password", 2, &Trust::default()).unwrap();
    assert_eq!(
        portable::import(&wallet, &file, "backup password", &Trust::default()).unwrap(),
        contents
    );
    assert!(portable::import(&wallet, &file, "wrong", &Trust::default()).is_err());
    let (other, _) = create_wallet("other local password", 1).unwrap();
    assert!(portable::import(&other, &file, "backup password", &Trust::default()).is_err());
    let mut injected = contents.clone();
    injected["sections"]["privateKey"] = json!("not allowed");
    assert!(portable::validate(&wallet, &injected, &Trust::default()).is_err());
    injected = contents.clone();
    injected["sections"]["identity"]["subject"]["fields"]["displayName"]["disclosure"] =
        json!("public");
    assert!(portable::validate(&wallet, &injected, &Trust::default()).is_err());
    injected = contents.clone();
    injected["sections"]["chainAccounts"]["accounts"][0]["address"] = json!("fake");
    assert!(portable::validate(&wallet, &injected, &Trust::default()).is_err());
    assert!(portable::parse_unique(r#"{"x":1,"x":2}"#).is_err());
}

#[test]
fn existing_web_membership_vector_matches_and_requires_independent_trust() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/portable-web/zenith-v3.vector.json"
    ))
    .unwrap();
    let owner = vector["ownerPublicKey"].as_str().unwrap();
    let proof = &vector["credential"];
    let trust = Trust {
        v3: Some(
            json!({"schema":"castalia.zenith-membership-trust-policy.v1","version":1,"roots":[{"issuerId":"zenith-research","keyId":vector["issuerKeyId"],"signatureSuite":"Ed25519","publicKey":vector["issuerPublicKey"]}]}),
        ),
        v4: None,
    };
    portable::verify_proof(proof, owner, &trust, false).unwrap();
    assert!(portable::verify_proof(proof, owner, &Trust::default(), false).is_err());
    let mut tampered = proof.clone();
    tampered["membershipId"] = json!("00".repeat(32));
    assert!(portable::verify_proof(&tampered, owner, &trust, false).is_err());
    tampered = proof.clone();
    tampered["issuerSignature"] = json!("A".repeat(86));
    assert!(portable::verify_proof(&tampered, owner, &trust, false).is_err());
    assert!(portable::verify_proof(proof, &"11".repeat(32), &trust, false).is_err());
}

#[test]
fn public_typescript_scoped_vector_matches_rust() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/portable-web/zenith-v4.vector.json"
    ))
    .unwrap();
    let trust = Trust {
        v3: None,
        v4: Some(vector["trust"].clone()),
    };
    let owner = vector["ownerPublicKey"].as_str().unwrap();
    portable::verify_proof(&vector["credential"], owner, &trust, true).unwrap();
    assert!(portable::verify_proof(&vector["credential"], owner, &Trust::default(), true).is_err());
    let mut invalid = vector["credential"].clone();
    invalid["scopeId"] = json!("00".repeat(32));
    assert!(portable::verify_proof(&invalid, owner, &trust, true).is_err());
}
