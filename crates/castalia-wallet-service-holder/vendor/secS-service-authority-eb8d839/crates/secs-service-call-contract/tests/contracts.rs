use secs_service_call_contract::{Application, ReceiverPolicy, ServiceIntent};
use serde_json::{json, Value};
const REQUEST: &[u8] = include_bytes!("fixtures/runtime-claim.json");
fn policy_json() -> Value {
    serde_json::from_slice(include_bytes!("fixtures/runtime-policy.json")).unwrap()
}
fn policy(v: &Value) -> ReceiverPolicy {
    ReceiverPolicy::parse(&serde_json::to_vec(v).unwrap()).unwrap()
}
fn intent() -> ServiceIntent {
    ServiceIntent::parse(Application::Runtime, REQUEST).unwrap()
}

#[test]
fn derives_exact_public_request_binding_and_seals_policy_snapshot() {
    let i = intent();
    assert_eq!(i.operation(), "runtime.executor.claim.v1");
    assert_eq!(i.resource(), "runs/run-1/steps/step-1");
    let p = policy(&policy_json())
        .prepare(&i, "fixture-frank", "fixture-holder", 200, 60)
        .unwrap();
    assert_eq!(p.audience(), "runtime://receiver-local");
    assert_eq!(p.opcode(), 72);
    assert_eq!(p.expires_at(), 260);
    assert_eq!(p.subject_id(), "fixture-frank");
    assert_eq!(p.key_id(), "fixture-holder");
    assert_eq!(p.handler_id(), "runtime/executor.claim");
    assert_eq!(p.descriptor_fingerprint(), "a".repeat(64));
    assert_eq!(p.request_digest(), i.request_digest());
    assert_eq!(
        serde_json::from_slice::<Value>(p.request_bytes()).unwrap(),
        serde_json::from_slice::<Value>(REQUEST).unwrap()
    );
    assert!(!format!("{p:?}").contains("lease_ms"));
}
#[test]
fn wrong_application_and_request_selected_authority_are_rejected() {
    assert!(ServiceIntent::parse(Application::Service, REQUEST).is_err());
    for field in [
        "audience",
        "subject_id",
        "key_id",
        "opcode",
        "policy",
        "handler_id",
        "proof",
        "namespace",
    ] {
        let mut v: Value = serde_json::from_slice(REQUEST).unwrap();
        v[field] = json!("injected");
        assert!(
            ServiceIntent::parse(Application::Runtime, &serde_json::to_vec(&v).unwrap()).is_err()
        );
    }
}
#[test]
fn changed_resource_payload_and_invalid_public_shapes_fail_before_preparation() {
    let mut v: Value = serde_json::from_slice(REQUEST).unwrap();
    v["resource"] = json!("runs/other/steps/step-1");
    assert!(ServiceIntent::parse(Application::Runtime, &serde_json::to_vec(&v).unwrap()).is_err());
    v = serde_json::from_slice(REQUEST).unwrap();
    v["payload"]["extra"] = json!(1);
    assert!(ServiceIntent::parse(Application::Runtime, &serde_json::to_vec(&v).unwrap()).is_err());
    v = serde_json::from_slice(REQUEST).unwrap();
    v["payload"]["lease_ms"] = json!(true);
    assert!(ServiceIntent::parse(Application::Runtime, &serde_json::to_vec(&v).unwrap()).is_err());
}
#[test]
fn duplicate_fields_even_inside_payload_and_typed_nonintegers_reject() {
    let raw = String::from_utf8(REQUEST.to_vec()).unwrap().replace(
        "\"lease_ms\": 120000",
        "\"lease_ms\":120000,\"lease_ms\":120001",
    );
    assert!(ServiceIntent::parse(Application::Runtime, raw.as_bytes()).is_err());
    for replacement in ["1.0", "1e0"] {
        let raw = String::from_utf8(REQUEST.to_vec()).unwrap().replace(
            "\"expected_version\": 1",
            &format!("\"expected_version\": {replacement}"),
        );
        assert!(ServiceIntent::parse(Application::Runtime, raw.as_bytes()).is_err());
    }
    assert!(ServiceIntent::parse(Application::Runtime,br#"{"schema":"runtime.query.v1","operation":"run.get","payload":{"run_id":"run-1"},"operation":"version.get"}"#).is_err());
}
#[test]
fn query_resource_is_derived_and_distinct_wire_bytes_remain_distinct() {
    let raw =
        br#"{"schema":"runtime.query.v1","operation":"run.get","payload":{"run_id":"run-1"}}"#;
    let i = ServiceIntent::parse(Application::Runtime, raw).unwrap();
    let reordered =
        br#"{"payload":{"run_id":"run-1"},"operation":"run.get","schema":"runtime.query.v1"}"#;
    assert_eq!(i.request_bytes(), raw);
    assert_eq!(
        ServiceIntent::parse(Application::Runtime, reordered)
            .unwrap()
            .request_bytes(),
        reordered
    );
    assert_ne!(
        i.request_digest(),
        ServiceIntent::parse(Application::Runtime, reordered)
            .unwrap()
            .request_digest()
    );
    assert_eq!(i.resource(), "runs/run-1");
}
#[test]
fn empty_rules_unknown_principal_revocation_and_wrong_scope_deny() {
    let i = intent();
    let mut v = policy_json();
    v["rules"] = json!([]);
    assert!(policy(&v)
        .prepare(&i, "fixture-frank", "fixture-holder", 200, 60)
        .is_err());
    let p = policy(&policy_json());
    assert!(p.prepare(&i, "other", "fixture-holder", 200, 60).is_err());
    assert!(p.prepare(&i, "fixture-frank", "other", 200, 60).is_err());
    v = policy_json();
    v["principals"][0]["revoked"] = json!(true);
    assert!(policy(&v)
        .prepare(&i, "fixture-frank", "fixture-holder", 200, 60)
        .is_err());
    v = policy_json();
    v["rules"][0]["resource"] = json!("runs/other/steps/step-1");
    assert!(policy(&v)
        .prepare(&i, "fixture-frank", "fixture-holder", 200, 60)
        .is_err());
}
#[test]
fn matching_deny_wins_and_future_deny_caps_expiry() {
    let mut v = policy_json();
    let mut deny = v["rules"][0].clone();
    deny["effect"] = json!("deny");
    v["rules"].as_array_mut().unwrap().push(deny.clone());
    assert!(policy(&v)
        .prepare(&intent(), "fixture-frank", "fixture-holder", 200, 60)
        .is_err());
    deny["not_before"] = json!(220);
    v["rules"][1] = deny;
    assert_eq!(
        policy(&v)
            .prepare(&intent(), "fixture-frank", "fixture-holder", 200, 60)
            .unwrap()
            .expires_at(),
        220
    );
}
#[test]
fn exclusive_expiry_and_all_current_windows_cap_authority() {
    for field in ["root", "principal", "allow", "descriptor"] {
        let mut v = policy_json();
        match field {
            "root" => v["not_after"] = json!(215),
            "principal" => v["principals"][0]["not_after"] = json!(215),
            "allow" => v["rules"][0]["not_after"] = json!(215),
            _ => v["descriptors"][0]["max_ttl_seconds"] = json!(15),
        };
        assert_eq!(
            policy(&v)
                .prepare(&intent(), "fixture-frank", "fixture-holder", 200, 60)
                .unwrap()
                .expires_at(),
            215
        );
    }
    let p = policy(&policy_json());
    for now in [0, 99, 800, 900, 1000, u64::MAX] {
        assert!(p
            .prepare(&intent(), "fixture-frank", "fixture-holder", now, 60)
            .is_err());
    }
    for ttl in [0, 61, u64::MAX] {
        assert!(p
            .prepare(&intent(), "fixture-frank", "fixture-holder", 200, ttl)
            .is_err());
    }
}
#[test]
fn exact_prefix_matching_has_explicit_slash_boundary() {
    let mut v = policy_json();
    v["rules"][0]["resource"] = json!("runs/run-1/");
    v["rules"][0]["resource_match"] = json!("prefix");
    assert!(policy(&v)
        .prepare(&intent(), "fixture-frank", "fixture-holder", 200, 60)
        .is_ok());
    v["rules"][0]["resource"] = json!("runs/run-1");
    assert!(ReceiverPolicy::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    for scope in ["*", "/", "runs/../", "runs//", "cases/"] {
        v["rules"][0]["resource"] = json!(scope);
        assert!(ReceiverPolicy::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    }
}
#[test]
fn trusted_descriptors_are_closed_and_never_replace_public_opcode_meaning() {
    for (field, value) in [
        ("audience", json!("service-management")),
        ("application", json!("frank-result")),
    ] {
        let mut v = policy_json();
        v[field] = value;
        assert!(ReceiverPolicy::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    for (field, value) in [
        ("opcode", json!(68)),
        ("operation", json!("membership.provision")),
        ("fingerprint", json!("invalid")),
        ("handler_id", json!("dev/echo")),
    ] {
        let mut v = policy_json();
        v["descriptors"][0][field] = value;
        assert!(ReceiverPolicy::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    }
    let mut v = policy_json();
    let duplicate = v["descriptors"][0].clone();
    v["descriptors"].as_array_mut().unwrap().push(duplicate);
    assert!(ReceiverPolicy::parse(&serde_json::to_vec(&v).unwrap()).is_err());
}
#[test]
fn service_public_request_has_separate_resource_and_unallocated_route_denies() {
    let i = ServiceIntent::parse(
        Application::Service,
        include_bytes!("fixtures/service-create.json"),
    )
    .unwrap();
    assert_eq!(i.operation(), "service.request.create.v1");
    assert_eq!(i.resource(), "requests/request-1");
    let mut v = policy_json();
    v["application"] = json!("service");
    v["audience"] = json!("service-management");
    v["descriptors"] = json!([]);
    v["rules"] = json!([]);
    assert!(policy(&v)
        .prepare(&i, "fixture-frank", "fixture-holder", 200, 60)
        .is_err());
    v["descriptors"] = json!([{"operation":"service.request.create.v1","opcode":80,"fingerprint":"b".repeat(64),"handler_id":"service/request.create","max_ttl_seconds":60}]);
    v["rules"] = json!([{"subject_id":"fixture-frank","key_id":"fixture-holder","operation":"service.request.create.v1","resource":"requests/request-1","resource_match":"exact","effect":"allow","not_before":100,"not_after":800,"active":true}]);
    let prepared = policy(&v)
        .prepare(&i, "fixture-frank", "fixture-holder", 200, 60)
        .unwrap();
    assert_eq!(prepared.opcode(), 80);
    assert_eq!(prepared.audience(), "service-management");
    // This allocation is synthetic owner input, never installed or defaulted.
}
#[test]
fn no_namespace_wildcards_duplicate_policy_fields_or_unbounded_inputs() {
    let mut v = policy_json();
    v["rules"][0]["operation"] = json!("runtime.*");
    assert!(ReceiverPolicy::parse(&serde_json::to_vec(&v).unwrap()).is_err());
    let raw = String::from_utf8(serde_json::to_vec(&policy_json()).unwrap())
        .unwrap()
        .replace("\"active\":true", "\"active\":true,\"active\":false");
    assert!(ReceiverPolicy::parse(raw.as_bytes()).is_err());
    assert!(ServiceIntent::parse(Application::Runtime, &vec![b' '; 2_097_153]).is_err());
}

#[test]
fn every_public_runtime_fixture_retains_bytes_and_matches_resource_projection() {
    let f: Value =
        serde_json::from_slice(include_bytes!("fixtures/runtime-consumer-v1.json")).unwrap();
    for request in f["commands"]
        .as_array()
        .unwrap()
        .iter()
        .chain(f["queries"].as_array().unwrap())
    {
        let i = ServiceIntent::parse(Application::Runtime, &serde_json::to_vec(request).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", request["operation"]));
        if let Some(resource) = request.get("resource").and_then(Value::as_str) {
            assert_eq!(i.resource(), resource);
        }
    }
}
#[test]
fn all_published_service_queries_are_admitted_and_old_native_substitutions_are_not() {
    for (operation, kind, id) in [
        ("request.execution", "ServiceRequest", "request-1"),
        ("case.summary", "Case", "case-1"),
        ("case.plan-history", "Case", "case-1"),
    ] {
        let v = json!({"schema":"service.query.v1","request_id":"q-1","operation":operation,"resource":{"kind":kind,"id":id},"payload":if operation=="case.plan-history" {json!({"after_revision":0,"limit":10})}else{json!({})}});
        assert!(
            ServiceIntent::parse(Application::Service, &serde_json::to_vec(&v).unwrap()).is_ok(),
            "{operation}"
        );
    }
    let mut raw = include_bytes!("fixtures/service-create.json").to_vec();
    raw.resize(65_537, b' ');
    assert!(ServiceIntent::parse(Application::Service, &raw).is_err());
}
#[test]
fn protocol_and_schema_copy_digests_are_pinned() {
    use sha2::{Digest, Sha256};
    let m: Value = serde_json::from_slice(include_bytes!("../schemas/provenance.json")).unwrap();
    for (name, bytes) in [
        (
            "runtime-v1.schema.json",
            include_bytes!("../schemas/runtime-v1.schema.json").as_slice(),
        ),
        (
            "service.command.v1.schema.json",
            include_bytes!("../schemas/service.command.v1.schema.json").as_slice(),
        ),
        (
            "service.query.v1.schema.json",
            include_bytes!("../schemas/service.query.v1.schema.json").as_slice(),
        ),
    ] {
        let f = m["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == name)
            .unwrap();
        let hash: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(f["sha256"], hash);
    }
}

#[test]
fn exact_producer_numeric_request_bytes_survive_without_rounding_or_canonical_rewrite() {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/producer-numeric-requests.json")).unwrap();
    for entry in fixture["requests"].as_array().unwrap() {
        let app = if entry["application"] == "runtime" {
            Application::Runtime
        } else {
            Application::Service
        };
        let raw = entry["request"].as_str().unwrap().as_bytes();
        let i = ServiceIntent::parse(app, raw).unwrap();
        assert_eq!(i.request_bytes(), raw);
        assert_eq!(i.request_digest(), entry["sha256"].as_str().unwrap());
        let mut native_policy = policy_json();
        native_policy["application"] = entry["application"].clone();
        native_policy["audience"] = json!(if app == Application::Runtime {
            "runtime://receiver-local"
        } else {
            "service-management"
        });
        native_policy["descriptors"][0]["operation"] = json!(i.operation());
        native_policy["descriptors"][0]["opcode"] = json!(if app == Application::Runtime {
            0x42
        } else {
            0x50
        });
        native_policy["rules"][0]["operation"] = json!(i.operation());
        native_policy["rules"][0]["resource"] = json!(i.resource());
        let prepared = policy(&native_policy)
            .prepare(&i, "fixture-frank", "fixture-holder", 200, 60)
            .unwrap();
        assert_eq!(prepared.request_bytes(), raw);
        assert_eq!(prepared.request_digest(), i.request_digest());
    }
}
#[test]
fn request_whitespace_order_and_numeric_lexemes_are_retained_exactly() {
    for number in [
        "1.0",
        "1e-7",
        "1E+20",
        "-0.0",
        "0.10000000000000001",
        "1267650600228229401496703205376",
        "-1267650600228229401496703205376",
        "5e-324",
    ] {
        let raw = format!(
            r#"{{ "schema":"runtime.command.v1", "operation":"run.create", "request_id":"numbers", "resource":"runs/run-1", "expected_version":null, "payload":{{ "run_id":"run-1", "pin":{{ "process_id":"p", "process_version":"v", "compilation_hash":"{}" }}, "inputs":{{ "n":{} }} }} }}"#,
            "0".repeat(64),
            number
        );
        let i = ServiceIntent::parse(Application::Runtime, raw.as_bytes()).unwrap();
        assert_eq!(i.request_bytes(), raw.as_bytes());
    }
}
#[test]
fn finite_numeric_admission_does_not_weaken_typed_contract_or_policy_bounds() {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/producer-numeric-requests.json")).unwrap();
    let valid = fixture["requests"][1]["request"].as_str().unwrap();
    for version in ["1.0", "true", "9007199254740992"] {
        let raw = valid.replace(
            "\"expected_version\":1",
            &format!("\"expected_version\":{version}"),
        );
        assert!(ServiceIntent::parse(Application::Service, raw.as_bytes()).is_err());
    }
    let mut policy = policy_json();
    policy["max_ttl_seconds"] = json!(61);
    assert!(ReceiverPolicy::parse(&serde_json::to_vec(&policy).unwrap()).is_err());
    for number in ["NaN", "Infinity", "1e400"] {
        let raw = fixture["requests"][0]["request"]
            .as_str()
            .unwrap()
            .replace("1.25", number);
        assert!(ServiceIntent::parse(Application::Runtime, raw.as_bytes()).is_err());
    }
}

#[test]
fn service_lifecycle_and_planning_text_match_current_static_reader() {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/service-static-text-profile.json"))
            .unwrap();
    for entry in fixture["cases"].as_array().unwrap() {
        let raw = entry["request"].as_str().unwrap().as_bytes();
        let accepted = ServiceIntent::parse(Application::Service, raw).is_ok();
        assert_eq!(
            accepted,
            entry["reader_accepts"].as_bool().unwrap(),
            "{}",
            entry["name"]
        );
    }
}
#[test]
fn runtime_opaque_escaped_nul_remains_valid_and_exact() {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/producer-numeric-requests.json")).unwrap();
    let raw = fixture["requests"][0]["request"]
        .as_str()
        .unwrap()
        .replace("🌸", "\\u0000");
    assert!(raw.contains("\\u0000"));
    let i = ServiceIntent::parse(Application::Runtime, raw.as_bytes()).unwrap();
    assert_eq!(i.request_bytes(), raw.as_bytes());
}

#[test]
fn service_request_local_carry_forward_targets_match_current_static_reader() {
    let fixture: Value = serde_json::from_slice(include_bytes!(
        "fixtures/service-planning-static-selections.json"
    ))
    .unwrap();
    for entry in fixture["cases"].as_array().unwrap() {
        let accepted = ServiceIntent::parse(
            Application::Service,
            entry["request"].as_str().unwrap().as_bytes(),
        )
        .is_ok();
        assert_eq!(
            accepted,
            entry["reader_accepts"].as_bool().unwrap(),
            "{}",
            entry["name"]
        );
    }
}
