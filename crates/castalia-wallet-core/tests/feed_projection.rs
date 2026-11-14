use castalia_wallet_core::{feed_projection::PreparedFeedProjectionV1, feeds};
use serde_json::{Value, json};

const ORIGIN: &str = "https://reader.example.org";
const SELECTION_SCHEMA: &str = "castalia.feed-projection-selection.v1";

fn id(n: usize) -> String {
    format!("b41ef5e8-0e06-43e0-aa47-{n:012x}")
}
fn source() -> Value {
    json!({"schema":feeds::SCHEMA,"version":1,
        "subscriptions":[
            {"id":id(2),"url":"https://example.org/two.xml","format":"atom","title":" Cafe\u{301} 📚 ","enabled":true,"collectionIds":[id(12),id(11)],"disclosure":"selected"},
            {"id":id(1),"url":"https://example.org/one.xml","format":"rss","title":"","enabled":false,"collectionIds":[id(11)],"disclosure":"selected"},
            {"id":id(3),"url":"https://example.org/private.xml","format":"auto","title":"Private source","enabled":true,"collectionIds":[id(13)],"disclosure":"private"}],
        "collections":[{"id":id(12),"title":"  "},{"id":id(11),"title":"Cafe\u{301}"},{"id":id(13),"title":"Private label"}],
        "preferences":{"order":"newest-first"}})
}
fn selection() -> Value {
    json!({"schema":SELECTION_SCHEMA,"subscriptionIds":[id(1),id(2)],"collectionIds":[id(11),id(12),id(13)],
        "memberships":[{"subscriptionId":id(1),"collectionIds":[]},{"subscriptionId":id(2),"collectionIds":[id(11),id(12)]}]})
}
fn prepare(section: &Value, choices: &Value) -> PreparedFeedProjectionV1 {
    PreparedFeedProjectionV1::prepare(&section.to_string(), &choices.to_string(), ORIGIN).unwrap()
}

#[test]
fn selection_preserves_source_order_unicode_and_explicit_memberships() {
    let original = source();
    let raw = original.to_string();
    let pending = prepare(&original, &selection());
    assert_eq!(pending.destination_origin(), ORIGIN);
    let preview: Value = serde_json::from_str(&pending.preview_json()).unwrap();
    let confirmed = pending.confirm(&raw, ORIGIN).unwrap();
    assert_eq!(confirmed, preview);
    feeds::validate(&confirmed).unwrap();
    assert_eq!(confirmed["subscriptions"][0], original["subscriptions"][0]);
    let mut second = original["subscriptions"][1].clone();
    second["collectionIds"] = json!([]);
    assert_eq!(
        confirmed["subscriptions"],
        json!([original["subscriptions"][0], second])
    );
    assert_eq!(
        confirmed["collections"],
        json!([original["collections"][0], original["collections"][1]])
    );
    assert_eq!(original.to_string(), raw);
    assert!(!confirmed.to_string().contains("Private"));
    assert!(!confirmed.to_string().contains(ORIGIN));
    assert_eq!(confirmed.as_object().unwrap().len(), 5);
}

#[test]
fn selected_labels_do_not_imply_membership_and_orphans_are_pruned() {
    let mut choices = selection();
    choices["memberships"][1]["collectionIds"] = json!([]);
    let output = prepare(&source(), &choices)
        .confirm(&source().to_string(), ORIGIN)
        .unwrap();
    assert_eq!(output["collections"], json!([]));
    assert!(
        output["subscriptions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["collectionIds"] == json!([]))
    );
}

#[test]
fn empty_selection_is_valid_even_with_known_but_unreferenced_labels() {
    let choices = json!({"schema":SELECTION_SCHEMA,"subscriptionIds":[],"collectionIds":[id(13)],"memberships":[]});
    let output = prepare(&source(), &choices)
        .confirm(&source().to_string(), ORIGIN)
        .unwrap();
    assert_eq!(
        output,
        json!({"schema":feeds::SCHEMA,"version":1,"subscriptions":[],"collections":[],"preferences":{"order":"newest-first"}})
    );
}

#[test]
fn unknown_duplicate_private_or_implicit_choices_fail() {
    let mut bad = Vec::new();
    for field in ["subscriptionIds", "collectionIds"] {
        let mut v = selection();
        v[field] = json!([id(999)]);
        bad.push(v);
        let mut v = selection();
        let first = v[field][0].clone();
        v[field].as_array_mut().unwrap().push(first);
        bad.push(v);
        let mut v = selection();
        v[field] = json!(null);
        bad.push(v);
    }
    let mut v = selection();
    v["subscriptionIds"] = json!([id(3)]);
    v["memberships"] = json!([{"subscriptionId":id(3),"collectionIds":[]}]);
    bad.push(v);
    let mut v = selection();
    v["memberships"][0]["subscriptionId"] = json!(id(2));
    bad.push(v);
    let mut v = selection();
    v["memberships"][0]["subscriptionId"] = json!(id(999));
    bad.push(v);
    let mut v = selection();
    v["memberships"][0]["collectionIds"] = json!([id(11), id(11)]);
    bad.push(v);
    let mut v = selection();
    v["memberships"][0]["collectionIds"] = json!([id(12)]);
    bad.push(v);
    let mut v = selection();
    v["collectionIds"] = json!([id(12)]);
    bad.push(v);
    let mut v = selection();
    v["memberships"] = json!([]);
    bad.push(v);
    let mut v = selection();
    v["memberships"][0]["extra"] = json!(true);
    bad.push(v);
    let mut v = selection();
    v["origin"] = json!(ORIGIN);
    bad.push(v);
    let mut v = selection();
    v["schema"] = json!("castalia.feed-projection-selection.v2");
    bad.push(v);
    let mut v = selection();
    v.as_object_mut().unwrap().remove("schema");
    bad.push(v);
    for choices in bad {
        assert!(
            PreparedFeedProjectionV1::prepare(&source().to_string(), &choices.to_string(), ORIGIN)
                .is_err(),
            "accepted {choices}"
        );
    }
}

#[test]
fn confirmation_binds_exact_bytes_and_origin_including_unselected_changes() {
    let original = source();
    let raw = original.to_string();
    let choices = selection().to_string();
    let mut modified = original.clone();
    modified["subscriptions"][2]["title"] = json!("Changed private source");
    for current in [
        format!("{raw} "),
        serde_json::to_string_pretty(&original).unwrap(),
        modified.to_string(),
        "{}".into(),
        "".into(),
    ] {
        let pending = PreparedFeedProjectionV1::prepare(&raw, &choices, ORIGIN).unwrap();
        assert_eq!(
            pending.confirm(&current, ORIGIN).unwrap_err(),
            "stale_feed_projection"
        );
    }
    for origin in [
        "https://other.example.org",
        "https://reader.example.org/",
        "https://READER.example.org",
        "http://localhost",
    ] {
        let pending = PreparedFeedProjectionV1::prepare(&raw, &choices, ORIGIN).unwrap();
        assert_eq!(
            pending.confirm(&raw, origin).unwrap_err(),
            "stale_feed_projection"
        );
    }
}

#[test]
fn origin_syntax_matches_existing_wallet_tuple_policy_not_source_endpoint_policy() {
    for origin in [
        ORIGIN,
        "https://reader.example.org:8443",
        "https://[2001:db8::1]",
        "https://127.0.0.1",
        "http://localhost",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "https://xn--bcher-kva.example.org",
    ] {
        let pending = PreparedFeedProjectionV1::prepare(
            &source().to_string(),
            &selection().to_string(),
            origin,
        )
        .unwrap();
        assert_eq!(pending.destination_origin(), origin);
        assert!(pending.confirm(&source().to_string(), origin).is_ok());
    }
    for origin in [
        "",
        "null",
        "https://reader.example.org/",
        "https://reader.example.org/path",
        "https://reader.example.org?",
        "https://reader.example.org#",
        "https://reader.example.org:443",
        "https://READER.example.org",
        "https://bücher.example.org",
        "https://user@reader.example.org",
        "https://@reader.example.org",
        "https://user:pass@reader.example.org",
        "http://example.org",
        "http://127.0.0.2",
        "http://localhost.example.org",
        "http://localhost.",
        "http://[::ffff:127.0.0.1]",
        "http://127.0.0.1:80",
        "https:reader.example.org",
        "file:///tmp/feeds",
        "data:text/plain,hello",
        "blob:https://reader.example.org/id",
        " https://reader.example.org",
        "https://reader.example.org\n",
    ] {
        assert!(
            PreparedFeedProjectionV1::prepare(
                &source().to_string(),
                &selection().to_string(),
                origin
            )
            .is_err(),
            "accepted {origin:?}"
        );
    }
    assert!(
        PreparedFeedProjectionV1::prepare(
            &source().to_string(),
            &selection().to_string(),
            &format!("https://{}", "a".repeat(2048))
        )
        .is_err()
    );
}

#[test]
fn raw_json_duplicate_escaped_duplicate_depth_unicode_and_trailing_data_fail() {
    let raw = selection().to_string();
    let duplicate = raw.replacen(
        "\"schema\":",
        "\"schema\":\"castalia.feed-projection-selection.v1\",\"schema\":",
        1,
    );
    let escaped = raw.replacen(
        "\"schema\":",
        "\"sch\\u0065ma\":\"castalia.feed-projection-selection.v1\",\"schema\":",
        1,
    );
    let nested = raw.replacen(
        "\"subscriptionId\":",
        "\"subscriptionId\":\"ignored\",\"subscriptionId\":",
        1,
    );
    let deep = format!("{}0{}", "[".repeat(256), "]".repeat(256));
    for choices in [
        duplicate,
        escaped,
        nested,
        deep,
        format!("{raw}{{}}"),
        raw.replace(&id(1), "\\ud800"),
        "".into(),
    ] {
        assert!(
            PreparedFeedProjectionV1::prepare(&source().to_string(), &choices, ORIGIN).is_err()
        );
    }
    let raw = source().to_string();
    for section in [
        raw.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
        raw.replacen("\"version\":1", "\"ver\\u0073ion\":1,\"version\":1", 1),
        format!("{}0{}", "[".repeat(256), "]".repeat(256)),
        raw.replace("Private source", "\\ud800"),
        format!("{raw}{{}}"),
        String::new(),
    ] {
        assert!(
            PreparedFeedProjectionV1::prepare(&section, &selection().to_string(), ORIGIN).is_err()
        );
    }
}

#[test]
fn byte_and_collection_selection_limits_are_enforced_before_projection() {
    let raw = source().to_string();
    let choices = selection().to_string();
    let padded_source = format!("{raw}{}", " ".repeat(feeds::MAX_SECTION_BYTES - raw.len()));
    let padded_choices = format!(
        "{choices}{}",
        " ".repeat(feeds::MAX_SECTION_BYTES - choices.len())
    );
    PreparedFeedProjectionV1::prepare(&padded_source, &padded_choices, ORIGIN)
        .unwrap()
        .confirm(&padded_source, ORIGIN)
        .unwrap();
    assert!(PreparedFeedProjectionV1::prepare(&(padded_source + " "), &choices, ORIGIN).is_err());
    assert!(PreparedFeedProjectionV1::prepare(&raw, &(padded_choices + " "), ORIGIN).is_err());
    for (field, count) in [("subscriptionIds", 257), ("collectionIds", 65)] {
        let mut bad = selection();
        bad[field] = json!((0..count).map(|n| id(n + 1000)).collect::<Vec<_>>());
        assert!(PreparedFeedProjectionV1::prepare(&raw, &bad.to_string(), ORIGIN).is_err());
    }
    let mut bad = selection();
    bad["memberships"][0]["collectionIds"] =
        json!((0..17).map(|n| id(n + 1000)).collect::<Vec<_>>());
    assert!(PreparedFeedProjectionV1::prepare(&raw, &bad.to_string(), ORIGIN).is_err());
}

#[test]
fn invalid_source_cannot_be_hidden_by_selecting_nothing() {
    let empty =
        json!({"schema":SELECTION_SCHEMA,"subscriptionIds":[],"collectionIds":[],"memberships":[]})
            .to_string();
    let mut bad = source();
    bad["subscriptions"][2]["credential"] = json!("synthetic secret field");
    assert!(PreparedFeedProjectionV1::prepare(&bad.to_string(), &empty, ORIGIN).is_err());
    let mut bad = source();
    bad["subscriptions"][2]["url"] = json!("http://127.0.0.1/private");
    assert!(PreparedFeedProjectionV1::prepare(&bad.to_string(), &empty, ORIGIN).is_err());
}

#[test]
fn synthetic_shared_projection_vectors_match_original_bytes() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../contracts/feeds/v1/projection-conformance.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let raw = case["sourceRaw"].as_str().unwrap();
        let selection = case["selectionRaw"].as_str().unwrap();
        let origin = case["origin"].as_str().unwrap();
        let result = PreparedFeedProjectionV1::prepare(raw, selection, origin);
        assert_eq!(
            result.is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}",
            case["id"]
        );
        if let Ok(pending) = result {
            assert_eq!(
                serde_json::from_str::<Value>(&pending.preview_json()).unwrap(),
                case["expectedSection"],
                "{}",
                case["id"]
            );
            assert_eq!(
                pending.confirm(raw, origin).unwrap(),
                case["expectedSection"],
                "{}",
                case["id"]
            );
        }
    }
    for case in fixture["confirmationCases"].as_array().unwrap() {
        let pending = PreparedFeedProjectionV1::prepare(
            case["sourceRaw"].as_str().unwrap(),
            case["selectionRaw"].as_str().unwrap(),
            case["origin"].as_str().unwrap(),
        )
        .unwrap();
        let result = pending.confirm(
            case["currentSourceRaw"].as_str().unwrap(),
            case["confirmOrigin"].as_str().unwrap(),
        );
        assert_eq!(
            result.is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}",
            case["id"]
        );
    }
}

#[test]
fn existing_raw_section_fixture_verdicts_are_unchanged_for_empty_projection() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../contracts/feeds/v1/conformance.json")).unwrap();
    let empty =
        json!({"schema":SELECTION_SCHEMA,"subscriptionIds":[],"collectionIds":[],"memberships":[]})
            .to_string();
    for case in fixture["cases"].as_array().unwrap() {
        let raw = case["raw"].as_str().unwrap();
        let result = PreparedFeedProjectionV1::prepare(raw, &empty, ORIGIN);
        assert_eq!(
            result.is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}",
            case["id"]
        );
        if let Ok(pending) = result {
            let output = pending.confirm(raw, ORIGIN).unwrap();
            assert_eq!(output["subscriptions"], json!([]));
            assert_eq!(output["collections"], json!([]));
            feeds::validate(&output).unwrap();
        }
    }
}
