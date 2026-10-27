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

#[test]
fn core_narrows_complete_compound_pairs_without_combining_parents() {
    use castalia_wallet_core::resource_selection::{
        EffectContract, EffectRule, RoleContract, RoleSelection, can_narrow_effect_rule,
    };
    let c = EffectContract {
        service: "service-a".into(),
        operation: "media:move.v1".into(),
        roles: ["source", "destination"]
            .iter()
            .map(|name| RoleContract {
                name: (*name).into(),
                kinds: vec!["media:Folder".into()],
                minimum: 1,
                maximum: 1,
            })
            .collect(),
    };
    let rule = |from: &str, to: &str| {
        EffectRule{service:"service-a".into(),operation:"media:move.v1".into(),roles:[("source",from),("destination",to)].iter().map(|(role,id)|RoleSelection{role:(*role).into(),selector:review(&json!({"schema":"secs.resource-selector.v1","service":"service-a","kinds":["media:Folder"],"selection":{"mode":"objects","refs":[{"kind":"media:Folder","id":id}]}}).to_string(),"service-a").unwrap()}).collect()}
    };
    assert!(can_narrow_effect_rule(&rule("a", "b"), &rule("a", "b"), &c).unwrap());
    assert!(!can_narrow_effect_rule(&rule("a", "d"), &rule("a", "b"), &c).unwrap());
    assert!(!can_narrow_effect_rule(&rule("a", "d"), &rule("c", "d"), &c).unwrap());
}
