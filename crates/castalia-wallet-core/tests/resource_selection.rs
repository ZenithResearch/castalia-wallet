use castalia_wallet_core::resource_selection::{can_narrow, review};
use serde_json::json;
#[test]
fn wallet_uses_shared_exact_selection_and_does_not_treat_it_as_a_grant() {
    let all=json!({"schema":"secs.resource-selector.v1","service":"service-a","kinds":["work:Task"],"selection":{"mode":"all"}}).to_string();
    let exact=json!({"schema":"secs.resource-selector.v1","service":"service-a","kinds":["work:Task"],"selection":{"mode":"objects","refs":[{"kind":"work:Task","id":"task-a"}]}}).to_string();
    assert!(review(&all, "service-a").is_ok());
    assert!(can_narrow(&exact, &all, "service-a").unwrap());
    assert!(!can_narrow(&all, &exact, "service-a").unwrap());
    assert!(review(&exact, "other-service").is_err());
    assert!(serde_json::from_str::<secs_grant_contract::Grant>(&exact).is_err());
}
#[test]
fn wallet_cannot_drop_hierarchy_guard_during_exact_narrowing() {
    let parent=json!({"schema":"secs.resource-selector.v1","service":"service-a","kinds":["work:Task"],"selection":{"mode":"descendants","hierarchy":{"relation":"work:containment.v1","roots":[{"kind":"work:Project","id":"p"}],"include_self":false}}}).to_string();
    let exact=json!({"schema":"secs.resource-selector.v1","service":"service-a","kinds":["work:Task"],"selection":{"mode":"objects","refs":[{"kind":"work:Task","id":"t"}]}}).to_string();
    assert!(!can_narrow(&exact, &parent, "service-a").unwrap());
}

#[test]
fn core_and_receiver_share_media_selection_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../vendor/secs-grant-contract/tests/fixtures/resource-selectors.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        assert_eq!(
            can_narrow(
                &case["child"].to_string(),
                &case["parent"].to_string(),
                case["service"].as_str().unwrap()
            )
            .unwrap(),
            case["within"].as_bool().unwrap()
        );
    }
}
