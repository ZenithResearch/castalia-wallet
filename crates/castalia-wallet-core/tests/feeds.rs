use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use castalia_wallet_core::{
    create_wallet, feeds,
    portable::{self, Trust},
    wallet_identities,
};
use serde_json::{Value, json};

fn id(n: usize) -> String {
    format!("b41ef5e8-0e06-43e0-aa47-{n:012x}")
}
fn section() -> Value {
    json!({"schema":"castalia.feeds-section.v1","version":1,
        "subscriptions":[{"id":id(1),"url":"https://example.org/feed.xml","format":"auto","title":"Reading essays","enabled":true,"collectionIds":[id(2)],"disclosure":"private"}],
        "collections":[{"id":id(2),"title":"Essays"}],"preferences":{"order":"newest-first"}})
}

#[test]
fn canonical_shared_raw_vectors_agree_and_preserve_accepted_values() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../contracts/feeds/v1/conformance.json")).unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 102);
    let mut accepted = 0;
    for case in cases {
        let raw = case["raw"].as_str().unwrap();
        let result = feeds::parse(raw);
        assert_eq!(
            result.is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}: {result:?}",
            case["id"]
        );
        if let Ok(value) = result {
            accepted += 1;
            assert_eq!(
                value,
                serde_json::from_str::<Value>(raw).unwrap(),
                "{}",
                case["id"]
            );
        }
    }
    assert_eq!(accepted, 17);
}
fn contents(wallet: &castalia_wallet_core::OpenedWallet) -> Value {
    let mut value = portable::empty_contents(wallet, 1).unwrap();
    value["schema"] = json!("castalia.castaway-contents.v3");
    value["version"] = json!(3);
    value["sections"]["feeds"] = section();
    value
}
// Independent, synthetic encryption only: production v3 writers stay disabled.
fn synthetic_file(owner: &str, raw: &str, version: u64) -> String {
    let salt = [19u8; 16];
    let nonce = [23u8; 12];
    let mut header = json!({"schema":format!("castalia.castaway.v{version}"),"contentsSchema":format!("castalia.castaway-contents.v{version}"),"ownerPublicKey":owner,"exportedAt":2,
        "kdf":{"name":"Argon2id","version":19,"salt":B64.encode(salt),"memoryKiB":65536,"iterations":3,"parallelism":1,"derivedKeyBytes":32},
        "aead":{"name":"AES-256-GCM","nonce":B64.encode(nonce),"tagBits":128}});
    let mut key = [0u8; 32];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 1, Some(32)).unwrap(),
    )
    .hash_password_into(b"backup password", &salt, &mut key)
    .unwrap();
    let ciphertext = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: raw.as_bytes(),
                aad: &serde_jcs::to_vec(&header).unwrap(),
            },
        )
        .unwrap();
    header["ciphertext"] = json!(B64.encode(ciphertext));
    serde_jcs::to_string(&header).unwrap()
}

#[test]
fn exact_feeds_preserve_unicode_order_and_inert_preferences() {
    let mut value = section();
    value["subscriptions"][0]["title"] = json!("Cafe\u{301} 📚");
    for format in ["auto", "rss", "atom"] {
        value["subscriptions"][0]["format"] = json!(format);
        for disclosure in ["private", "selected"] {
            value["subscriptions"][0]["disclosure"] = json!(disclosure);
            assert_eq!(feeds::validate(&value).unwrap(), value);
            assert_eq!(feeds::parse(&value.to_string()).unwrap(), value);
        }
    }
    let mut second = value["subscriptions"][0].clone();
    second["id"] = json!(id(3));
    value["subscriptions"]
        .as_array_mut()
        .unwrap()
        .insert(0, second);
    assert_eq!(feeds::validate(&value).unwrap(), value);
}

#[test]
fn closed_shapes_reject_secrets_wrong_types_duplicates_and_dangling_membership() {
    let original = section();
    let mut cases = vec![];
    for target in ["root", "subscription", "collection", "preferences"] {
        let mut bad = original.clone();
        match target {
            "root" => bad["privateKey"] = json!("forbidden"),
            "subscription" => bad["subscriptions"][0]["accessToken"] = json!("forbidden"),
            "collection" => bad["collections"][0]["renderer"] = json!("forbidden"),
            _ => bad["preferences"]["script"] = json!("forbidden"),
        }
        cases.push(bad);
    }
    for (field, value) in [
        ("format", json!("html")),
        ("enabled", json!(1)),
        ("disclosure", json!("public")),
        ("id", json!(id(1).to_uppercase())),
        ("collectionIds", json!([id(2), id(2)])),
        ("collectionIds", json!([id(9)])),
    ] {
        let mut bad = original.clone();
        bad["subscriptions"][0][field] = value;
        cases.push(bad);
    }
    let mut bad = original.clone();
    bad["preferences"]["order"] = json!("random");
    cases.push(bad);
    let mut bad = original.clone();
    bad["version"] = json!(1.0);
    cases.push(bad);
    let mut bad = original.clone();
    bad["subscriptions"]
        .as_array_mut()
        .unwrap()
        .push(original["subscriptions"][0].clone());
    cases.push(bad);
    let mut bad = original.clone();
    bad["collections"]
        .as_array_mut()
        .unwrap()
        .push(original["collections"][0].clone());
    cases.push(bad);
    for bad in cases {
        assert!(feeds::validate(&bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn public_canonical_endpoint_policy_and_utf8_limits() {
    for url in [
        "http://example.org/feed",
        "https://example.org/feed?q=public",
        "https://example.org/feed?",
        "https://example.org/feed#",
        "https://user:secret@example.org/feed",
        "https://@example.org/feed",
        "https://example.org:444/feed",
        "https://127.0.0.1/feed",
        "https://2130706433/feed",
        "https://[::1]/feed",
        "https://localhost/feed",
        "https://printer.local/feed",
        "https://host/feed",
        "https:example.org/feed",
        "https://EXAMPLE.org/feed",
        "https://example.org./feed",
        "https://ex%61mple.org/feed",
        "https://example.org/a\\b",
    ] {
        let mut bad = section();
        bad["subscriptions"][0]["url"] = json!(url);
        assert!(feeds::validate(&bad).is_err(), "accepted {url}");
    }
    let mut value = section();
    value["subscriptions"][0]["url"] =
        json!(format!("https://example.org/{}", "a".repeat(2048 - 20)));
    assert_eq!(
        value["subscriptions"][0]["url"].as_str().unwrap().len(),
        2048
    );
    feeds::validate(&value).unwrap();
    value["subscriptions"][0]["url"] = json!(format!(
        "{}a",
        value["subscriptions"][0]["url"].as_str().unwrap()
    ));
    assert!(feeds::validate(&value).is_err());
    value = section();
    value["subscriptions"][0]["title"] = json!("é".repeat(256));
    feeds::validate(&value).unwrap();
    value["subscriptions"][0]["title"] = json!("é".repeat(257));
    assert!(feeds::validate(&value).is_err());
    for text in ["line\nbreak", "\u{0}", "\u{85}"] {
        value = section();
        value["collections"][0]["title"] = json!(text);
        assert!(feeds::validate(&value).is_err());
    }
}

#[test]
fn count_and_serialized_section_bounds_fail_without_truncation() {
    let mut value = section();
    value["subscriptions"] = json!(
        (0..256)
            .map(|n| {
                let mut s = section()["subscriptions"][0].clone();
                s["id"] = json!(id(n + 100));
                s
            })
            .collect::<Vec<_>>()
    );
    feeds::validate(&value).unwrap();
    value["subscriptions"]
        .as_array_mut()
        .unwrap()
        .push(section()["subscriptions"][0].clone());
    assert!(feeds::validate(&value).is_err());
    value = section();
    value["collections"] = json!(
        (0..64)
            .map(|n| json!({"id":id(n+2),"title":"Collection"}))
            .collect::<Vec<_>>()
    );
    value["subscriptions"][0]["collectionIds"] =
        json!((0..16).map(|n| id(n + 2)).collect::<Vec<_>>());
    feeds::validate(&value).unwrap();
    value["subscriptions"][0]["collectionIds"]
        .as_array_mut()
        .unwrap()
        .push(json!(id(18)));
    assert!(feeds::validate(&value).is_err());
    value["subscriptions"][0]["collectionIds"] = json!([]);
    value["collections"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":id(99),"title":"Overflow"}));
    assert!(feeds::validate(&value).is_err());
    value = section();
    value["subscriptions"] = json!(
        (0..256)
            .map(|n| {
                let mut s = section()["subscriptions"][0].clone();
                s["id"] = json!(id(n + 100));
                s["url"] = json!(format!("https://example.org/{}", "a".repeat(1800)));
                s
            })
            .collect::<Vec<_>>()
    );
    assert!(feeds::validate(&value).is_err());
    assert!(feeds::parse(&format!("{}{}", section(), " ".repeat(256 * 1024))).is_err());
}

#[test]
fn exact_section_byte_boundary_is_accepted_and_one_more_byte_rejects() {
    let mut value = section();
    value["subscriptions"] = json!(
        (0..256)
            .map(|n| {
                let mut subscription = section()["subscriptions"][0].clone();
                subscription["id"] = json!(id(n + 100));
                subscription["url"] = json!("https://example.org/");
                subscription
            })
            .collect::<Vec<_>>()
    );
    let mut remaining = feeds::MAX_SECTION_BYTES - value.to_string().len();
    for subscription in value["subscriptions"].as_array_mut().unwrap() {
        let url = subscription["url"].as_str().unwrap();
        let add = remaining.min(2048 - url.len());
        subscription["url"] = json!(format!("{url}{}", "a".repeat(add)));
        remaining -= add;
    }
    assert_eq!(remaining, 0);
    let raw = value.to_string();
    assert_eq!(raw.len(), feeds::MAX_SECTION_BYTES);
    assert_eq!(feeds::parse(&raw).unwrap(), value);
    let last = value["subscriptions"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap();
    last["url"] = json!(format!("{}a", last["url"].as_str().unwrap()));
    assert_eq!(value.to_string().len(), feeds::MAX_SECTION_BYTES + 1);
    assert_eq!(feeds::validate(&value).unwrap_err(), "feeds_too_large");
    assert_eq!(
        feeds::parse(&value.to_string()).unwrap_err(),
        "feeds_too_large"
    );
}

#[test]
fn whole_artifact_preflight_matches_real_legacy_encryption_and_rejects_overflow() {
    let (wallet, _) = create_wallet("long local password", 1).unwrap();
    let legacy = portable::empty_contents(&wallet, 1).unwrap();
    let actual = portable::export(
        &wallet,
        &legacy,
        "backup password",
        9_007_199_254_740_991,
        &Trust::default(),
    )
    .unwrap();
    assert_eq!(
        portable::preflight_export_size(&legacy).unwrap(),
        actual.len()
    );
    let v2 = portable::with_wallet_identities(
        &legacy,
        &wallet_identities::empty(&wallet.public_key_hex()),
        &wallet.public_key_hex(),
    )
    .unwrap();
    let actual = portable::export(
        &wallet,
        &v2,
        "backup password",
        9_007_199_254_740_991,
        &Trust::default(),
    )
    .unwrap();
    assert_eq!(portable::preflight_export_size(&v2).unwrap(), actual.len());
    let mut oversized = contents(&wallet);
    oversized["sections"]["identity"]["subject"]["fields"]["biography"]["value"] =
        json!("x".repeat(786_432));
    assert_eq!(
        portable::preflight_export_size(&oversized).unwrap_err(),
        "file_too_large"
    );
}

#[test]
fn raw_json_duplicates_and_lone_surrogates_fail_before_validation() {
    let raw = section().to_string();
    assert!(
        feeds::parse(&raw.replacen("\"version\":1", "\"version\":1,\"version\":1", 1)).is_err()
    );
    assert!(feeds::parse(&raw.replace("Reading essays", "\\ud800")).is_err());
    assert!(feeds::parse(&raw.replace("Reading essays", "\\udc00")).is_err());
    assert!(feeds::parse(&raw.replace("Reading essays", "\\u0000")).is_err());
}

#[test]
fn v3_is_strict_legacy_stays_frozen_and_identity_edit_cannot_downgrade() {
    let (wallet, _) = create_wallet("long local password", 1).unwrap();
    let value = contents(&wallet);
    portable::validate(&wallet, &value, &Trust::default()).unwrap();
    assert_eq!(portable::contents_version(&value).unwrap(), 3);
    let edited = portable::with_wallet_identities(
        &value,
        &wallet_identities::empty(&wallet.public_key_hex()),
        &wallet.public_key_hex(),
    )
    .unwrap();
    assert_eq!(edited["schema"], "castalia.castaway-contents.v3");
    assert_eq!(edited["version"], 3);
    assert_eq!(edited["sections"]["feeds"], value["sections"]["feeds"]);
    portable::validate(&wallet, &edited, &Trust::default()).unwrap();
    for version in [1, 2] {
        let mut bad = edited.clone();
        bad["schema"] = json!(format!("castalia.castaway-contents.v{version}"));
        bad["version"] = json!(version);
        assert!(portable::validate(&wallet, &bad, &Trust::default()).is_err());
    }
    let mut bad = value.clone();
    bad["sections"].as_object_mut().unwrap().remove("feeds");
    assert!(portable::validate(&wallet, &bad, &Trust::default()).is_err());
    let mut bad = value.clone();
    bad["sections"]["rootAuthority"] = json!("forbidden");
    assert!(portable::validate(&wallet, &bad, &Trust::default()).is_err());
    let mut bad = value.clone();
    bad["sections"]["identity"]["subject"]["memberKey"] = json!("11".repeat(32));
    assert!(portable::validate(&wallet, &bad, &Trust::default()).is_err());
    assert_eq!(
        portable::export(&wallet, &value, "backup password", 2, &Trust::default()).unwrap_err(),
        "feed_writer_not_qualified"
    );
    assert_eq!(
        wallet
            .export_castaway(&value.to_string(), "backup password", 2)
            .unwrap_err()
            .to_string(),
        "feed_writer_not_qualified"
    );
}

#[test]
fn both_reader_paths_open_synthetic_v3_and_reject_authenticated_malformed_contents() {
    let (wallet, _) = create_wallet("long local password", 1).unwrap();
    let value = contents(&wallet);
    let owner = wallet.public_key_hex();
    let file = synthetic_file(&owner, &value.to_string(), 3);
    assert_eq!(
        portable::import(&wallet, &file, "backup password", &Trust::default()).unwrap(),
        value
    );
    let with_identities =
        portable::with_wallet_identities(&value, &wallet_identities::empty(&owner), &owner)
            .unwrap();
    let file_with_identities = synthetic_file(&owner, &with_identities.to_string(), 3);
    assert_eq!(
        portable::import(
            &wallet,
            &file_with_identities,
            "backup password",
            &Trust::default()
        )
        .unwrap(),
        with_identities
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            &wallet
                .import_castaway(file_with_identities.as_bytes(), "backup password")
                .unwrap()
        )
        .unwrap(),
        with_identities
    );
    let duplicate_envelope =
        file.replacen("\"exportedAt\":2", "\"exportedAt\":2,\"exportedAt\":2", 1);
    assert!(
        portable::import(
            &wallet,
            &duplicate_envelope,
            "backup password",
            &Trust::default()
        )
        .is_err()
    );
    assert!(
        wallet
            .import_castaway(duplicate_envelope.as_bytes(), "backup password")
            .is_err()
    );
    let mut wrong_owner: Value = serde_json::from_str(&file).unwrap();
    wrong_owner["ownerPublicKey"] = json!("11".repeat(32));
    assert!(
        portable::import(
            &wallet,
            &wrong_owner.to_string(),
            "backup password",
            &Trust::default()
        )
        .is_err()
    );
    assert!(
        wallet
            .import_castaway(wrong_owner.to_string().as_bytes(), "backup password")
            .is_err()
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            &wallet
                .import_castaway(file.as_bytes(), "backup password")
                .unwrap()
        )
        .unwrap(),
        value
    );
    let mut malformed = value.clone();
    malformed["sections"]["feeds"]["subscriptions"][0]["accessToken"] = json!("forbidden");
    let duplicate = value.to_string().replacen(
        "\"feeds\":",
        &format!("\"feeds\":{},\"feeds\":", section()),
        1,
    );
    for (raw, version) in [
        (malformed.to_string(), 3),
        (value.to_string(), 2),
        (portable::empty_contents(&wallet, 1).unwrap().to_string(), 3),
        (duplicate, 3),
    ] {
        let file = synthetic_file(&owner, &raw, version);
        assert!(portable::import(&wallet, &file, "backup password", &Trust::default()).is_err());
        assert!(
            wallet
                .import_castaway(file.as_bytes(), "backup password")
                .is_err()
        );
    }
}
