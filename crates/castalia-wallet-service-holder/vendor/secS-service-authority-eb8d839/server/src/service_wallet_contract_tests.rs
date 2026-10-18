use super::*;
use serde_json::Value;
fn refs() -> Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/service-wallet-contract-v3/reference-vectors.json"
    ))
    .unwrap()
}
fn transitions() -> Value {
    serde_json::from_str(include_str!(
        "../tests/fixtures/service-wallet-contract-v3/transition-vectors.json"
    ))
    .unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    crate::service_authority_snapshot::canonical(v)
}
fn text<'a>(v: &'a Value, name: &str) -> &'a str {
    v[name].as_str().unwrap()
}
#[test]
fn all_five_frozen_reference_bytes_hashes_and_lineage_frames() {
    for v in refs()["vectors"].as_array().unwrap() {
        let r = WalletReference::parse(text(v, "reference_utf8").as_bytes()).unwrap();
        assert_eq!(r.canonical_bytes(), text(v, "reference_utf8").as_bytes());
        assert_eq!(hex(&r.reference_digest()), text(v, "reference_sha256"));
        assert_eq!(hex(&r.lineage_preimage()), text(v, "lineage_preimage_hex"));
        assert_eq!(hex(&r.lineage_digest()), text(v, "lineage_sha256"));
    }
}
#[test]
fn four_complete_retained_policy_outcome_target_and_twelve_marker_vectors() {
    for v in transitions()["vectors"].as_array().unwrap() {
        let p = TargetPolicy::parse(text(v, "target_policy_utf8").as_bytes()).unwrap();
        assert_eq!(hex(&p.digest()), text(v, "target_policy_sha256"));
        let outcome = OutcomeRecord::parse(text(v, "outcome_utf8").as_bytes()).unwrap();
        let cas = NativeCas::parse(&bytes(&v["outcome_record"]["old_native_cas"])).unwrap();
        let derived = p.derive_target(&cas, outcome.reference()).unwrap();
        assert_eq!(
            derived.canonical_bytes(),
            text(v, "target_native_utf8").as_bytes()
        );
        assert_eq!(hex(&derived.digest()), text(v, "target_native_sha256"));
        TargetBundle::parse(text(v, "old_native_utf8").as_bytes()).unwrap();
        for stage in v["marker_stages"].as_array().unwrap() {
            let marker = TransitionMarker::parse(text(stage, "marker_utf8").as_bytes()).unwrap();
            assert_eq!(
                marker.canonical_bytes(),
                text(stage, "marker_utf8").as_bytes()
            );
            assert_eq!(
                hex(&marker.binding_preimage(&p).unwrap()),
                text(v, "policy_binding_preimage_hex")
            );
            assert_eq!(
                hex(&hash(&marker.binding_preimage(&p).unwrap())),
                text(v, "policy_binding_sha256")
            );
            outcome.verify(&marker, &p).unwrap();
            verify_retained_transition(
                &marker,
                &p,
                text(v, "old_native_utf8").as_bytes(),
                Some(&outcome),
                Some(text(v, "target_native_utf8").as_bytes()),
            )
            .unwrap();
        }
    }
}

fn policy() -> Value {
    transitions()["vectors"][0]["target_policy"].clone()
}
fn active_reference() -> Value {
    refs()["vectors"][1]["reference"].clone()
}
fn rich_policy() -> Value {
    let mut p = policy();
    p["descriptors"][0]["output_profile"] = serde_json::json!({"schema_id":"fixture.output.v1","max_output_bytes":1024,"max_execution_response_bytes":4096});
    p["descriptors"][0]["required_credentials"] = serde_json::json!(["membership-required"]);
    p["descriptors"][0]["required_capabilities"] = serde_json::json!(["fixture.run"]);
    p["descriptors"][0]["accepted_evidence"] = serde_json::json!(["membership_credential"]);
    p["descriptors"][0]["required_authority_mode"] = serde_json::json!("signed_source");
    p["descriptors"][0]["disclosure_policy"]["permissions"] = serde_json::json!([{"class":"subject_identity","surface":"handler_context","representation":"redacted_digest"}]);
    p
}
fn object_paths(v: &Value, at: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            out.push(at.into());
            for (k, x) in m {
                object_paths(
                    x,
                    &format!("{at}/{}", k.replace('~', "~0").replace('/', "~1")),
                    out,
                );
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                object_paths(x, &format!("{at}/{i}"), out);
            }
        }
        _ => {}
    }
}
#[test]
fn every_complete_policy_object_is_closed_and_every_native_nullable_is_explicit() {
    let p = rich_policy();
    TargetPolicy::parse(&bytes(&p)).unwrap();
    let mut paths = Vec::new();
    object_paths(&p, "", &mut paths);
    let mut missing = 0;
    for path in &paths {
        let fields: Vec<_> = p
            .pointer(path)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for field in fields {
            let mut bad = p.clone();
            bad.pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(&field);
            assert!(
                TargetPolicy::parse(&bytes(&bad)).is_err(),
                "missing {path}/{field}"
            );
            missing += 1;
        }
        let mut bad = p.clone();
        bad.pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::json!(true));
        assert!(TargetPolicy::parse(&bytes(&bad)).is_err(), "unknown {path}");
    }
    assert!(paths.len() >= 13);
    assert!(missing >= 100);
}
#[test]
fn reference_and_all_marker_outcome_nested_objects_require_exact_fields() {
    for v in refs()["vectors"].as_array().unwrap() {
        for name in v["reference"].as_object().unwrap().keys() {
            let mut bad = v["reference"].clone();
            bad.as_object_mut().unwrap().remove(name);
            assert!(
                WalletReference::parse(&bytes(&bad)).is_err(),
                "reference missing {name}"
            );
        }
        let mut bad = v["reference"].clone();
        bad["extra"] = serde_json::json!(true);
        assert!(WalletReference::parse(&bytes(&bad)).is_err());
    }
    let all = transitions();
    for v in all["vectors"].as_array().unwrap() {
        for record in v["marker_stages"].as_array().unwrap() {
            let m = &record["marker"];
            let mut paths = Vec::new();
            object_paths(m, "", &mut paths);
            for path in &paths {
                for name in m.pointer(path).unwrap().as_object().unwrap().keys() {
                    let mut bad = m.clone();
                    bad.pointer_mut(path)
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove(name);
                    assert!(
                        TransitionMarker::parse(&bytes(&bad)).is_err(),
                        "marker missing {path}/{name}"
                    );
                }
                let mut bad = m.clone();
                bad.pointer_mut(path)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert("extra".into(), serde_json::json!(0));
                assert!(
                    TransitionMarker::parse(&bytes(&bad)).is_err(),
                    "marker unknown {path}"
                );
            }
        }
        let o = &v["outcome_record"];
        let mut paths = Vec::new();
        object_paths(o, "", &mut paths);
        for path in paths {
            for name in o.pointer(&path).unwrap().as_object().unwrap().keys() {
                let mut bad = o.clone();
                bad.pointer_mut(&path)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(name);
                assert!(
                    OutcomeRecord::parse(&bytes(&bad)).is_err(),
                    "outcome missing {path}/{name}"
                );
            }
            let mut bad = o.clone();
            bad.pointer_mut(&path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("extra".into(), serde_json::json!(0));
            assert!(OutcomeRecord::parse(&bytes(&bad)).is_err());
        }
    }
}
#[test]
fn unsigned_lexical_integers_duplicates_synthetic_maps_and_canonical_bytes_deny() {
    let r = bytes(&active_reference());
    let original = String::from_utf8(r.clone()).unwrap();
    for number in [
        "-0",
        "-1",
        "2.0",
        "2e0",
        "9007199254740992",
        "{\"$serde_json::private::Number\":\"2\"}",
    ] {
        let bad = original.replace(
            "\"state_revision\":2",
            &format!("\"state_revision\":{number}"),
        );
        assert_ne!(bad, original);
        assert!(WalletReference::parse(bad.as_bytes()).is_err(), "{number}");
    }
    assert!(WalletReference::parse(&[r.as_slice(), b" "].concat()).is_err());
    let p = String::from_utf8(bytes(&policy())).unwrap();
    for bad in [
        p.replace("\"not_before\":0", "\"not_before\":0,\"not_before\":0"),
        p.replace("\"not_before\":0", "\"not_before\":0.0"),
        p.replace("\"not_before\":0", "\"not_before\":0e0"),
        p.replace("\"not_before\":0", "\"not_before\":-0"),
        p.replace(
            "\"not_before\":0",
            "\"not_before\":{\"$serde_json::private::Number\":\"0\"}",
        ),
    ] {
        assert!(TargetPolicy::parse(bad.as_bytes()).is_err());
    }
    let m = transitions()["vectors"][0]["marker_stages"][0]["marker_utf8"]
        .as_str()
        .unwrap()
        .to_owned();
    for bad in [
        m.replace("\"generation\":1", "\"generation\":1,\"generation\":1"),
        m.replace("\"generation\":1", "\"generation\":1e0"),
        m.replace("\"generation\":1", "\"generation\":-0"),
    ] {
        assert!(TransitionMarker::parse(bad.as_bytes()).is_err());
    }
}
#[test]
fn three_reference_states_null_tags_key_identity_windows_and_integer_bounds() {
    let a = active_reference();
    WalletReference::parse(&bytes(&a)).unwrap();
    for (name, value) in [
        ("owner_input_sha256", Value::Null),
        ("delegation_policy_sha256", Value::Null),
        ("revoked_at", serde_json::json!(1)),
        ("key_id", serde_json::json!("holder:key")),
        ("public_key_sha256", serde_json::json!("0".repeat(64))),
        ("public_key_hex", serde_json::json!("0".repeat(64))),
        ("not_after", serde_json::json!(0)),
        ("not_before", serde_json::json!(180)),
        ("state_revision", serde_json::json!(0)),
        ("key_generation", serde_json::json!(3)),
        ("state", serde_json::json!("unknown")),
        ("application", serde_json::json!("frank")),
        ("purpose", serde_json::json!("member-key")),
        ("current_sha256", serde_json::json!("A".repeat(64))),
    ] {
        let mut bad = a.clone();
        bad[name] = value;
        assert!(WalletReference::parse(&bytes(&bad)).is_err(), "{name}");
    }
    for idx in [0, 2, 4] {
        let base = refs()["vectors"][idx]["reference"].clone();
        for name in ["owner_input_sha256", "delegation_policy_sha256"] {
            let mut bad = base.clone();
            bad[name] = serde_json::json!("0".repeat(64));
            assert!(WalletReference::parse(&bytes(&bad)).is_err());
        }
    }
    let mut bad = refs()["vectors"][4]["reference"].clone();
    bad["revoked_at"] = Value::Null;
    assert!(WalletReference::parse(&bytes(&bad)).is_err());
    let mut max = a.clone();
    max["state_revision"] = serde_json::json!(MAX_SAFE_TIME);
    max["key_generation"] = serde_json::json!(MAX_SAFE_TIME);
    max["not_after"] = serde_json::json!(MAX_SAFE_TIME);
    WalletReference::parse(&bytes(&max)).unwrap();
    max["not_after"] = serde_json::json!(MAX_SAFE_TIME + 1);
    assert!(WalletReference::parse(&bytes(&max)).is_err());
}
#[test]
fn exact_existing_resource_support_and_distinct_owner_vs_pure_parser_limits() {
    let base = policy();
    let limit = "runs/".to_owned() + &vec!["a".repeat(128); 508].join("/");
    assert_eq!(limit.len(), 65536);
    let over = "runs/".to_owned()
        + &([
            vec!["a".repeat(127)],
            vec!["a".repeat(128); 507],
            vec!["b".into()],
        ]
        .concat())
        .join("/");
    assert_eq!(over.len(), 65537);
    for (resource, full, pure) in [
        (
            "runs/".to_owned() + &vec!["a".repeat(100); 12].join("/"),
            true,
            true,
        ),
        (limit, true, true),
        (over, false, true),
        ("runs/".to_owned() + &"a".repeat(128), true, true),
        ("runs/".to_owned() + &"a".repeat(129), false, false),
        ("unallocated/x".into(), false, false),
        ("runs/a//b".into(), false, false),
        ("runs/a/../b".into(), false, false),
    ] {
        let mut p = base.clone();
        p["receiver_policy"]["rules"][0]["resource"] = serde_json::json!(resource);
        assert_eq!(
            secs_service_call_contract::ReceiverPolicy::parse(&bytes(&p["receiver_policy"]))
                .is_ok(),
            pure
        );
        assert_eq!(TargetPolicy::parse(&bytes(&p)).is_ok(), full);
    }
    for (n, ok) in [(1024, true), (1025, false)] {
        let mut p = base.clone();
        p["permissions"][0]["resource"]["value"] = serde_json::json!("x".repeat(n));
        assert_eq!(TargetPolicy::parse(&bytes(&p)).is_ok(), ok);
    }
}
#[test]
fn actual_strict_reader_total_string_depth_and_key_array_bounds() {
    let raw = bytes(&serde_json::json!([
        "a".repeat(65536),
        "b".repeat(65536),
        "c".repeat(65536),
        "d".repeat(65536 - 13)
    ]));
    assert_eq!(raw.len(), POLICY_LIMIT);
    strict_value(&raw).unwrap();
    assert!(strict_value(&[raw.as_slice(), b" "].concat()).is_err());
    strict_value(&bytes(&serde_json::json!("a".repeat(65536)))).unwrap();
    assert!(strict_value(&bytes(&serde_json::json!("a".repeat(65537)))).is_err());
    let mut node = serde_json::json!(0);
    for _ in 0..16 {
        node = serde_json::json!([node]);
    }
    strict_value(&bytes(&node)).unwrap();
    assert!(strict_value(&bytes(&serde_json::json!([node]))).is_err());
    strict_value(&bytes(&serde_json::json!(vec![0; 4096]))).unwrap();
    assert!(strict_value(&bytes(&serde_json::json!(vec![0; 4097]))).is_err());
    let mut map = serde_json::Map::new();
    map.insert("a".repeat(256), serde_json::json!(0));
    strict_value(&bytes(&Value::Object(map.clone()))).unwrap();
    map.insert("b".repeat(257), serde_json::json!(0));
    assert!(strict_value(&bytes(&Value::Object(map))).is_err());
}
#[test]
fn full_native_output_disclosure_obligations_deny_rows_and_array_order_are_retained() {
    let p = rich_policy();
    let parsed = TargetPolicy::parse(&bytes(&p)).unwrap();
    assert_eq!(parsed.canonical_bytes(), bytes(&p));
    assert_eq!(
        parsed.value["descriptors"][0]["required_credentials"],
        p["descriptors"][0]["required_credentials"]
    );
    assert_eq!(
        parsed.value["receiver_policy"]["rules"][1]["effect"],
        "deny"
    );
    let mut reverse = p.clone();
    reverse["receiver_policy"]["rules"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let alternate = TargetPolicy::parse(&bytes(&reverse)).unwrap();
    assert_ne!(parsed.digest(), alternate.digest());
    for (path, value) in [
        (
            "/descriptors/0/output_profile/max_output_bytes",
            serde_json::json!(0),
        ),
        (
            "/descriptors/0/disclosure_policy/policy_version",
            serde_json::json!(0),
        ),
        (
            "/descriptors/0/required_credentials",
            serde_json::json!(["same", "same"]),
        ),
        (
            "/descriptors/0/accepted_evidence",
            serde_json::json!(vec!["x"; 17]),
        ),
        (
            "/descriptors/0/handler_id",
            serde_json::json!("dev/command"),
        ),
        ("/descriptors/0/opcode", serde_json::json!(63)),
        ("/descriptors/0/dev_binding", serde_json::json!(true)),
        (
            "/permissions/0/authority_source",
            serde_json::json!("dregg_backed"),
        ),
        (
            "/receiver_policy/descriptors/0/fingerprint",
            serde_json::json!("x".repeat(64)),
        ),
    ] {
        let mut bad = p.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(TargetPolicy::parse(&bytes(&bad)).is_err(), "{path}");
    }
    let mut duplicated = p.clone();
    let row = duplicated["descriptors"][0]["disclosure_policy"]["permissions"][0].clone();
    duplicated["descriptors"][0]["disclosure_policy"]["permissions"]
        .as_array_mut()
        .unwrap()
        .push(row);
    assert!(TargetPolicy::parse(&bytes(&duplicated)).is_err());
}
#[test]
fn actual_native_registries_counts_status_key_material_and_selected_issuer_reused() {
    let p = policy();
    for (path, value) in [
        (
            "/issuers/0/public_key_hex",
            serde_json::json!("0".repeat(64)),
        ),
        ("/issuers/0/status", serde_json::json!("bogus")),
        ("/issuers/0/algorithm", serde_json::json!("other")),
        ("/selected_issuer_key_id", serde_json::json!("missing")),
        ("/issuer_node_id", serde_json::json!("different")),
        (
            "/holders/0/public_key_hex",
            p["issuers"][0]["public_key_hex"].clone(),
        ),
        ("/holders/0/key_id", p["issuers"][0]["key_id"].clone()),
        ("/issuers", serde_json::json!([])),
        ("/descriptors", serde_json::json!([])),
        ("/valid_until", serde_json::json!(0)),
    ] {
        let mut bad = p.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(TargetPolicy::parse(&bytes(&bad)).is_err(), "{path}");
    }
    let mut duplicates = p.clone();
    duplicates["holders"]
        .as_array_mut()
        .unwrap()
        .push(p["holders"][0].clone());
    assert!(TargetPolicy::parse(&bytes(&duplicates)).is_err());
    let mut permission = p.clone();
    permission["permissions"]
        .as_array_mut()
        .unwrap()
        .push(p["permissions"][0].clone());
    assert!(TargetPolicy::parse(&bytes(&permission)).is_err());
    let mut zero = p.clone();
    zero["holders"] = serde_json::json!([]);
    let parsed = TargetPolicy::parse(&bytes(&zero)).unwrap();
    let active = WalletReference::parse(&bytes(&active_reference())).unwrap();
    let cas=NativeCas::parse(br#"{"bundle_sha256":"0000000000000000000000000000000000000000000000000000000000000000","generation":1}"#).unwrap();
    assert!(parsed.derive_target(&cas, &active).is_err());
    let inactive = WalletReference::parse(&bytes(&refs()["vectors"][0]["reference"])).unwrap();
    let target = parsed.derive_target(&cas, &inactive).unwrap();
    assert_eq!(target.reference.state(), WalletState::Unconfigured);
}
#[test]
fn target_derivation_never_reselects_body_current_key_or_generation_and_overflow_denies() {
    let p = TargetPolicy::parse(&bytes(&policy())).unwrap();
    let a = WalletReference::parse(&bytes(&active_reference())).unwrap();
    let max = NativeCas::parse(&bytes(
        &serde_json::json!({"generation":MAX_SAFE_TIME,"bundle_sha256":"0".repeat(64)}),
    ))
    .unwrap();
    assert!(p.derive_target(&max, &a).is_err());
    let v = transitions();
    let second = &v["vectors"][1];
    let rotation = TargetPolicy::parse(text(second, "target_policy_utf8").as_bytes()).unwrap();
    let outcome = OutcomeRecord::parse(text(second, "outcome_utf8").as_bytes()).unwrap();
    let cas = NativeCas::parse(&bytes(&second["outcome_record"]["old_native_cas"])).unwrap();
    let target = rotation.derive_target(&cas, outcome.reference()).unwrap();
    for name in POLICY_FIELDS {
        assert_eq!(target.value[*name], rotation.value[*name]);
    }
    assert_ne!(
        target.value["holders"][0]["key_id"],
        target.reference.value["key_id"]
    );
    let mut injected = policy();
    injected["generation"] = serde_json::json!(2);
    assert!(TargetPolicy::parse(&bytes(&injected)).is_err());
    injected.as_object_mut().unwrap().remove("generation");
    injected["wallet_current"] = active_reference();
    assert!(TargetPolicy::parse(&bytes(&injected)).is_err());
    let mut changed = active_reference();
    changed["delegation_policy_sha256"] = serde_json::json!("0".repeat(64));
    let different = WalletReference::parse(&bytes(&changed)).unwrap();
    assert!(p.derive_target(&cas, &different).is_err());
}
#[test]
fn every_retained_policy_and_record_substitution_denies_exact_transition_bindings() {
    let all = transitions();
    let v = &all["vectors"][0];
    let marker =
        TransitionMarker::parse(text(&v["marker_stages"][1], "marker_utf8").as_bytes()).unwrap();
    let p = TargetPolicy::parse(text(v, "target_policy_utf8").as_bytes()).unwrap();
    let o = OutcomeRecord::parse(text(v, "outcome_utf8").as_bytes()).unwrap();
    for (path, value) in [
        ("/receiver_policy/rules/0/effect", serde_json::json!("deny")),
        (
            "/receiver_policy/rules/1/not_before",
            serde_json::json!(170),
        ),
        (
            "/descriptors/0/required_credentials",
            serde_json::json!(["membership-required"]),
        ),
        ("/holders/0/status", serde_json::json!("revoked")),
        ("/issuers/0/production_authority", serde_json::json!(false)),
        ("/valid_until", serde_json::json!(179)),
    ] {
        let mut substituted = policy();
        *substituted.pointer_mut(path).unwrap() = value;
        let q = TargetPolicy::parse(&bytes(&substituted)).unwrap();
        assert!(marker.binding_preimage(&q).is_err());
        assert!(o.verify(&marker, &q).is_err());
    }
    for name in [
        "transition_id",
        "old_wallet_reference_sha256",
        "request_sha256",
        "target_policy_sha256",
    ] {
        let mut bad = v["outcome_record"].clone();
        bad[name] = serde_json::json!(if name == "transition_id" {
            "0".repeat(32)
        } else {
            "0".repeat(64)
        });
        let candidate = OutcomeRecord::parse(&bytes(&bad)).unwrap();
        assert!(candidate.verify(&marker, &p).is_err(), "{name}");
    }
    let old = text(v, "old_native_utf8").as_bytes();
    let target = text(v, "target_native_utf8").as_bytes();
    assert!(
        verify_retained_transition(&marker, &p, &old[..old.len() - 1], Some(&o), Some(target))
            .is_err()
    );
    assert!(verify_retained_transition(
        &marker,
        &p,
        old,
        Some(&o),
        Some(&target[..target.len() - 1])
    )
    .is_err());
    assert!(verify_retained_transition(&marker, &p, old, None, None).is_err());
    assert!(verify_retained_transition(&marker, &p, old, Some(&o), None).is_err());
    let mut target_value = v["target_native_bundle"].clone();
    target_value["generation"] = serde_json::json!(3);
    assert!(
        verify_retained_transition(&marker, &p, old, Some(&o), Some(&bytes(&target_value)))
            .is_err()
    );
    let mut changed = v["outcome_record"].clone();
    changed["observed_at"] = serde_json::json!(119);
    let earlier = OutcomeRecord::parse(&bytes(&changed)).unwrap();
    assert!(earlier.verify(&marker, &p).is_err());
}
#[test]
fn unchanged_abort_and_reconcile_are_explicit_and_keep_new_native_generation() {
    let all = transitions();
    let v = &all["vectors"][0];
    let mut m = v["marker_stages"][0]["marker"].clone();
    m["mutation"] = serde_json::json!("reconcile");
    m["request"]["owner_input_sha256"] = Value::Null;
    let mut p = policy();
    p["holders"] = serde_json::json!([]);
    let policy = TargetPolicy::parse(&bytes(&p)).unwrap();
    m["target_policy"]["sha256"] = serde_json::json!(hex(&policy.digest()));
    m["target_policy"]["bytes"] = serde_json::json!(policy.raw.len());
    m["request"]["target_policy_sha256"] = serde_json::json!(hex(&policy.digest()));
    let marker = TransitionMarker::parse(&bytes(&m)).unwrap();
    let mut outcome = v["outcome_record"].clone();
    outcome["mutation"] = m["mutation"].clone();
    outcome["wallet_reference"] = m["old_wallet_reference"].clone();
    outcome["relation"] = serde_json::json!("reconciled_unchanged");
    outcome["request_sha256"] = serde_json::json!(hex(&hash(&bytes(&m["request"]))));
    outcome["target_policy_sha256"] = m["target_policy"]["sha256"].clone();
    let o = OutcomeRecord::parse(&bytes(&outcome)).unwrap();
    o.verify(&marker, &policy).unwrap();
    let target = policy.derive_target(&marker.cas, o.reference()).unwrap();
    assert_eq!(target.value["generation"], 2);
    assert_eq!(
        target.reference.canonical_bytes(),
        marker.old.canonical_bytes()
    );
    verify_retained_transition(
        &marker,
        &policy,
        text(v, "old_native_utf8").as_bytes(),
        Some(&o),
        Some(target.canonical_bytes()),
    )
    .unwrap();
    outcome["relation"] = serde_json::json!("explicit_abort_unchanged");
    OutcomeRecord::parse(&bytes(&outcome))
        .unwrap()
        .verify(&marker, &policy)
        .unwrap();
    outcome["wallet_reference"] = active_reference();
    assert!(OutcomeRecord::parse(&bytes(&outcome))
        .unwrap()
        .verify(&marker, &policy)
        .is_err());
}
#[test]
fn startup_pin_is_closed_minimum_and_exact_reference_data_only() {
    let r = WalletReference::parse(&bytes(&active_reference())).unwrap();
    let v = serde_json::json!({"schema":"secs.wallet-current-startup-pin.v2","store_id":r.value["store_id"],"minimum_state_revision":2,"minimum_key_generation":1,"expected_wallet_reference_sha256":hex(&r.reference_digest())});
    StartupPin::parse(&bytes(&v))
        .unwrap()
        .compare_reference(&r)
        .unwrap();
    for (name, value) in [
        ("minimum_state_revision", serde_json::json!(3)),
        ("minimum_key_generation", serde_json::json!(2)),
        (
            "expected_wallet_reference_sha256",
            serde_json::json!("0".repeat(64)),
        ),
        ("store_id", serde_json::json!("0".repeat(32))),
    ] {
        let mut wrong = v.clone();
        wrong[name] = value;
        assert!(StartupPin::parse(&bytes(&wrong))
            .unwrap()
            .compare_reference(&r)
            .is_err());
    }
    for name in v.as_object().unwrap().keys() {
        let mut missing = v.clone();
        missing.as_object_mut().unwrap().remove(name);
        assert!(StartupPin::parse(&bytes(&missing)).is_err());
    }
}

#[test]
fn prepared_transition_counter_overflow_and_revoked_mutations_deny() {
    let all = transitions();
    let base = all["vectors"][0]["marker_stages"][0]["marker"].clone();
    let mut overflow = base.clone();
    overflow["old_native_cas"]["generation"] = serde_json::json!(MAX_SAFE_TIME);
    assert!(matches!(
        TransitionMarker::parse(&bytes(&overflow)),
        Err(ContractError::Bounds)
    ));
    for kind in ["configure", "rotate", "revoke"] {
        let mut m = base.clone();
        m["old_wallet_reference"] = refs()["vectors"][4]["reference"].clone();
        m["mutation"] = serde_json::json!(kind);
        if kind != "configure" {
            m["request"]["owner_input_sha256"] = Value::Null;
        }
        if kind == "rotate" {
            m["request"]["requested_not_before"] = serde_json::json!(0);
            m["request"]["requested_not_after"] = serde_json::json!(180);
        }
        assert!(
            matches!(
                TransitionMarker::parse(&bytes(&m)),
                Err(ContractError::Relation)
            ),
            "{kind}"
        );
    }
    let mut m = base;
    m["old_wallet_reference"] = refs()["vectors"][4]["reference"].clone();
    m["mutation"] = serde_json::json!("reconcile");
    m["request"]["owner_input_sha256"] = Value::Null;
    TransitionMarker::parse(&bytes(&m)).unwrap();
}
