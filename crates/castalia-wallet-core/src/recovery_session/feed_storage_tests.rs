use super::*;

fn section(start: usize, count: usize, url_padding: usize) -> Value {
    json!({"schema":crate::feeds::SCHEMA,"version":1,"subscriptions":(start..start+count).map(|n|json!({"id":format!("b41ef5e8-0e06-43e0-aa47-{n:012x}"),"url":format!("https://example.org/{}","a".repeat(url_padding)),"format":"rss","title":"","enabled":true,"collectionIds":[],"disclosure":"private"})).collect::<Vec<_>>(),"collections":[],"preferences":{"order":"newest-first"}})
}

#[test]
fn committed_previous_and_incoming_merge_in_order_with_combined_limits() {
    let committed = section(3, 1, 0);
    let previous = section(2, 1, 0);
    let incoming = section(1, 1, 0);
    let merged = merge_feed_sections([Some(&committed), Some(&previous), Some(&incoming)])
        .unwrap()
        .unwrap();
    assert_eq!(
        merged["subscriptions"],
        json!([
            committed["subscriptions"][0],
            previous["subscriptions"][0],
            incoming["subscriptions"][0]
        ])
    );
    assert_eq!(
        merge_feed_sections([Some(&merged), Some(&merged), None])
            .unwrap()
            .unwrap(),
        merged
    );
    assert!(merge_feed_sections([None, None, None]).unwrap().is_none());
    let empty = section(1, 0, 0);
    assert_eq!(
        merge_feed_sections([Some(&empty), None, Some(&empty)]).unwrap(),
        Some(empty)
    );
    assert_eq!(
        merge_feed_sections([Some(&section(1, 256, 0)), None, Some(&section(300, 1, 0))])
            .unwrap_err(),
        "feed_limit"
    );
    assert_eq!(
        merge_feed_sections([
            Some(&section(1, 128, 1600)),
            None,
            Some(&section(300, 128, 1600))
        ])
        .unwrap_err(),
        "feeds_too_large"
    );
    let mut a = section(1, 0, 0);
    a["collections"] = json!(
        (1..=64)
            .map(|n| json!({"id":format!("b41ef5e8-0e06-43e0-aa47-{n:012x}"),"title":""}))
            .collect::<Vec<_>>()
    );
    let mut b = section(1, 0, 0);
    b["collections"] = json!([{"id":"b41ef5e8-0e06-43e0-aa47-000000000099","title":""}]);
    assert_eq!(
        merge_feed_sections([Some(&a), None, Some(&b)]).unwrap_err(),
        "feed_limit"
    );
    b["collections"][0]["id"] = a["collections"][0]["id"].clone();
    b["collections"][0]["title"] = json!("Different");
    assert_eq!(
        merge_feed_sections([Some(&a), None, Some(&b)]).unwrap_err(),
        "feed_conflict"
    );
}

#[test]
fn whole_artifact_preflight_fails_before_encrypted_candidate_installation() {
    let (wallet, custody) = create_wallet("long local password", 1).unwrap();
    let mut contents = portable::empty_contents(&wallet, 1).unwrap();
    contents["schema"] = json!("castalia.castaway-contents.v3");
    contents["version"] = json!(3);
    contents["sections"]["feeds"] = section(1, 0, 0);
    // Exercise the common persistence guard directly with an oversized internal
    // candidate, even though public ingress also rejects this malformed profile.
    contents["sections"]["identity"]["subject"]["fields"]["biography"]["value"] =
        json!("x".repeat(786_432));
    let local = LocalState {
        contents: Some(contents),
        ..LocalState::default()
    };
    let mut session = RecoverySession::new();
    assert_eq!(
        session
            .prepare(Some(wallet), custody.to_string(), local)
            .unwrap_err(),
        "file_too_large"
    );
    assert!(session.pending.is_none());
    assert!(session.wallet.is_none());
    assert!(session.custody.is_none());
    assert!(session.local.contents.is_none());
    assert_eq!(session.revision, 0);
}
