use base64::{Engine as _, engine::general_purpose::STANDARD};
use castalia_wallet_presentation::{
    Caller, canonical_json, complete, prepare_request, verify_presentation,
};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

mod common;
use common::fixture;

#[test]
fn exact_credential_and_approved_presentation_verify() {
    let (raw, pins, caller, holder) = fixture();
    let prepared = prepare_request(
        &raw,
        &pins,
        &caller,
        &hex::encode(holder.verifying_key().as_bytes()),
        1800000000,
    )
    .unwrap();
    let summary: Value = serde_json::from_slice(&prepared.summary().unwrap()).unwrap();
    assert_eq!(summary["disclosure"]["title"], "Fixture request");
    let prepared = prepared
        .prepare_presentation(1800000090, &[33; 16])
        .unwrap();
    let signature = holder.sign(prepared.signature_transcript()).to_bytes();
    let presentation = complete(prepared, &signature).unwrap().canonical().unwrap();
    let value: Value = serde_json::from_slice(&presentation).unwrap();
    assert_eq!(value["issued_at"], 1800000090u64);
    assert_eq!(value["expires_at"], 1800000120u64);
    verify_presentation(&raw, &presentation, &pins, &caller, 1800000091).unwrap();
    assert!(verify_presentation(&raw, &presentation, &pins, &caller, 1800000120).is_err());
}

#[test]
fn alterations_unknown_fields_duplicates_and_untrusted_issuers_fail() {
    let (raw, pins, caller, holder) = fixture();
    let public = hex::encode(holder.verifying_key().as_bytes());
    for mode in [
        "bytes",
        "disclosure",
        "credential",
        "unknown",
        "holder",
        "audience",
    ] {
        let mut value: Value = serde_json::from_slice(&raw).unwrap();
        match mode {
            "bytes" => value["request_bytes_base64"] = json!(STANDARD.encode(b"different")),
            "disclosure" => value["disclosure"]["title"] = json!("Substituted"),
            "credential" => value["credential"]["signature"] = json!("00".repeat(64)),
            "unknown" => value["extra"] = json!(true),
            "holder" => value["credential"]["claims"]["holder_public_key"] = json!("00".repeat(32)),
            _ => value["credential"]["claims"]["audience"] = json!("other"),
        }
        assert!(
            prepare_request(
                &canonical_json(&value).unwrap(),
                &pins,
                &caller,
                &public,
                1800000000
            )
            .is_err(),
            "{mode}"
        );
    }
    let duplicate =
        String::from_utf8(raw.clone())
            .unwrap()
            .replacen('{', "{\"schema\":\"duplicate\",", 1);
    assert!(prepare_request(duplicate.as_bytes(), &pins, &caller, &public, 1800000000).is_err());
    assert!(prepare_request(&raw, &[], &caller, &public, 1800000000).is_err());
    assert!(
        prepare_request(
            &raw,
            &pins,
            &Caller {
                kind: "terminal".into(),
                id: "other".into()
            },
            &public,
            1800000000
        )
        .is_err()
    );
    assert!(prepare_request(&raw, &pins, &caller, &public, 1799999999).is_err());
    assert!(prepare_request(&raw, &pins, &caller, &public, 1800000120).is_err());
}

#[test]
fn approval_expiry_clock_rollback_and_wrong_signer_fail() {
    let (raw, pins, caller, holder) = fixture();
    let public = hex::encode(holder.verifying_key().as_bytes());
    for now in [1799999999, 1800000120] {
        let request = prepare_request(&raw, &pins, &caller, &public, 1800000000).unwrap();
        assert!(request.prepare_presentation(now, &[33; 16]).is_err());
    }
    let request = prepare_request(&raw, &pins, &caller, &public, 1800000000).unwrap();
    let prepared = request.prepare_presentation(1800000001, &[33; 16]).unwrap();
    let signature = SigningKey::from_bytes(&[44; 32])
        .sign(prepared.signature_transcript())
        .to_bytes();
    assert!(complete(prepared, &signature).is_err());
}

fn resign(request: &mut Value) {
    request["credential"]["claims"]["disclosure_digest_sha256"] =
        castalia_wallet_presentation::digest(&canonical_json(&request["disclosure"]).unwrap())
            .into();
    let raw = STANDARD
        .decode(request["request_bytes_base64"].as_str().unwrap())
        .unwrap();
    request["credential"]["claims"]["request_digest_sha256"] =
        castalia_wallet_presentation::digest(&raw).into();
    let mut transcript = castalia_wallet_presentation::CREDENTIAL_DOMAIN.to_vec();
    transcript.extend(canonical_json(&request["credential"]["claims"]).unwrap());
    request["credential"]["signature"] = hex::encode(
        SigningKey::from_bytes(&[11; 32])
            .sign(&transcript)
            .to_bytes(),
    )
    .into();
}
#[test]
fn validly_signed_unsafe_disclosures_and_oversize_requests_fail() {
    let (raw, pins, caller, holder) = fixture();
    let public = hex::encode(holder.verifying_key().as_bytes());
    for title in [
        "\u{0000}", "\u{001b}", "\u{0085}", "\u{061c}", "\u{200e}", "\u{200f}", "\u{202e}",
        "\u{2066}",
    ] {
        let mut request: Value = serde_json::from_slice(&raw).unwrap();
        request["disclosure"]["title"] = title.into();
        resign(&mut request);
        assert!(
            prepare_request(
                &canonical_json(&request).unwrap(),
                &pins,
                &caller,
                &public,
                1800000000
            )
            .is_err()
        );
    }
    for (length, valid) in [(131072, true), (131073, false)] {
        let mut request: Value = serde_json::from_slice(&raw).unwrap();
        request["request_bytes_base64"] = STANDARD.encode(vec![1u8; length]).into();
        resign(&mut request);
        assert_eq!(
            prepare_request(
                &canonical_json(&request).unwrap(),
                &pins,
                &caller,
                &public,
                1800000000
            )
            .is_ok(),
            valid
        );
    }
    for (count, valid) in [(144, true), (145, false)] {
        let mut request: Value = serde_json::from_slice(&raw).unwrap();
        request["disclosure"]["statements"] = json!(vec!["a"; count]);
        resign(&mut request);
        assert_eq!(
            prepare_request(
                &canonical_json(&request).unwrap(),
                &pins,
                &caller,
                &public,
                1800000000
            )
            .is_ok(),
            valid
        );
    }
}
#[test]
fn strict_nested_json_numbers_encodings_and_trust_bounds_fail_closed() {
    let (raw, pins, caller, holder) = fixture();
    let public = hex::encode(holder.verifying_key().as_bytes());
    let raw = String::from_utf8(raw).unwrap();
    for text in [
        raw.replace(
            "\"issuer\":\"fixture-issuer\"",
            "\"issuer\":\"other\",\"issuer\":\"fixture-issuer\"",
        ),
        raw.replace("\"issued_at\":1800000000", "\"issued_at\":1800000000.0"),
        raw.replace("\"issued_at\":1800000000", "\"issued_at\":18e8"),
        raw.replace("\"issued_at\":1800000000", "\"issued_at\":9007199254740992"),
        raw.replace("\"issued_at\":1800000000", "\"issued_at\":-1"),
        raw.replace("b3BhcXVlIHJlcXVlc3Q=", "b3BhcXVlIHJlcXVlc3Q"),
        raw.replace("\"claims\":{", "\"claims\":{\"extra\":true,"),
        raw.replace("Fixture request", "\\ud800"),
    ] {
        assert!(
            prepare_request(text.as_bytes(), &pins, &caller, &public, 1800000000).is_err(),
            "{text}"
        );
    }
    let trust = castalia_wallet_presentation::TrustConfig {
        schema: "castalia.wallet-presentation-trust.v1".into(),
        caller,
        pins,
    };
    let trust = String::from_utf8(canonical_json(&trust).unwrap()).unwrap();
    assert!(
        castalia_wallet_presentation::TrustConfig::parse(
            trust
                .replace(
                    "\"issuer\":\"fixture-issuer\"",
                    "\"issuer\":\"other\",\"issuer\":\"fixture-issuer\""
                )
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        castalia_wallet_presentation::TrustConfig::parse(vec![b' '; 262145].as_slice()).is_err()
    );
}
#[test]
fn caller_origins_are_exact_and_cleartext_is_loopback_only() {
    for (id, valid) in [
        ("https://example.com", true),
        ("http://localhost", true),
        ("http://127.0.0.1:8080", true),
        ("http://[::1]:8080", true),
        ("http://example.com", false),
        ("https://example.com/", false),
        ("https://example.com:443", false),
        ("https://Example.com", false),
        ("https://user@example.com", false),
        ("https://example.com?x", false),
        ("https://example.com.", false),
    ] {
        assert_eq!(
            Caller {
                kind: "browser".into(),
                id: id.into()
            }
            .validate()
            .is_ok(),
            valid,
            "{id}"
        );
    }
}
#[test]
fn public_interoperability_vector_retains_exact_bytes() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../docs/vectors/credential-presentation-v2.json"
    ))
    .unwrap();
    let trust = castalia_wallet_presentation::TrustConfig::parse(
        &canonical_json(&vector["trust_config"]).unwrap(),
    )
    .unwrap();
    let request = canonical_json(&vector["request"]).unwrap();
    assert_eq!(
        request,
        vector["canonical_request"].as_str().unwrap().as_bytes()
    );
    let holder = SigningKey::from_bytes(
        &castalia_wallet_presentation::decode_hex::<32>(
            vector["holder_seed_hex"].as_str().unwrap(),
        )
        .unwrap(),
    );
    let prepared = prepare_request(
        &request,
        &trust.pins,
        &trust.caller,
        &hex::encode(holder.verifying_key().as_bytes()),
        vector["now"].as_u64().unwrap(),
    )
    .unwrap()
    .prepare_presentation(
        vector["approved_at"].as_u64().unwrap(),
        &castalia_wallet_presentation::decode_hex::<16>(
            vector["presentation_nonce_hex"].as_str().unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        hex::encode(prepared.signature_transcript()),
        vector["presentation_signing_bytes_hex"]
    );
    let signature = holder.sign(prepared.signature_transcript()).to_bytes();
    let presentation = complete(prepared, &signature).unwrap().canonical().unwrap();
    assert_eq!(
        presentation,
        vector["canonical_presentation"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
    verify_presentation(
        &request,
        &presentation,
        &trust.pins,
        &trust.caller,
        vector["approved_at"].as_u64().unwrap(),
    )
    .unwrap();
}
