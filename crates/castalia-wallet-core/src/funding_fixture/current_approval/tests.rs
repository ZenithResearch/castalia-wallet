use super::*;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;

#[test]
fn current_scoped_registry_witnesses_reproduce_accepted_multi_policy_roots() {
    let rows: Json = serde_json::from_str(include_str!("map-vectors.json")).unwrap();
    for head in rows.as_array().unwrap() {
        for row in head["records"].as_array().unwrap() {
            let id = data::bytes(&hex::decode(row["id"].as_str().unwrap()).unwrap());
            let raw = hex::decode(row["dataHex"].as_str().unwrap()).unwrap();
            let record = cbor::parse(&raw).unwrap();
            assert_eq!(data::data(&record).unwrap(), raw);
            assert_eq!(
                hex::encode(data::commit("castalia/kettle-policy-record/v1", &record).unwrap()),
                row["commitment"]
            );
            let mut path: Proof = serde_json::from_value(row["proof"].clone()).unwrap();
            assert_eq!(
                data::map_root(&id, Some(&record), &path).unwrap(),
                head["root"]
            );
            assert_ne!(data::map_root(&id, None, &path).unwrap(), head["root"]);
            path.siblings.clear();
            assert!(data::map_root(&id, Some(&record), &path).is_err());
        }
    }
}

fn profile(session: &ApprovalSession, key: &SigningKey) -> Signed<ProfileStatement> {
    let mut t = session.identity();
    t["schema"] = json!("castalia.kettle-current-approval-profile.v1");
    t["profileId"] = json!(PROFILE);
    t["sourceId"] = json!("a1".repeat(32));
    let preimage =
        super::super::fixture_transcript("castalia.kettle-current-approval-profile.v1\0", &t)
            .unwrap();
    Signed {
        statement: serde_json::from_value(t).unwrap(),
        signature_hex: hex::encode(key.sign(&preimage).to_bytes()),
    }
}
#[test]
fn independently_provisioned_observer_and_immutable_fresh_participant() {
    let observer = SigningKey::generate(&mut OsRng);
    let other = SigningKey::generate(&mut OsRng);
    let mut s =
        ApprovalSession::fresh(observer.verifying_key().to_bytes(), Role::Controller).unwrap();
    let second =
        ApprovalSession::fresh(observer.verifying_key().to_bytes(), Role::Recovery).unwrap();
    let public = s.info().unwrap();
    assert_ne!(public["keyHash"], second.info().unwrap()["keyHash"]);
    assert!(s.install(&profile(&s, &other)).is_err());
    assert!(s.install(&profile(&second, &observer)).is_err());
    let correct = profile(&s, &observer);
    s.install(&correct).unwrap();
    assert!(s.install(&correct).is_err());
    s.lock();
    assert!(s.info().is_err());
}
#[test]
fn exact_language_view_and_closed_nullable_context() {
    let view = hex::decode(include_str!("cost_view.hex").trim()).unwrap();
    assert_eq!(view.len(), 963);
    assert_eq!(
        sha(&view),
        "fe3ede5057e3fa1b886b64ae6309310816c8a505d964087836dfe9dad048b2a5"
    );
    let mut p = json!({"id":"41","record":null,"content":null,"proof":{"bitmap":"00".repeat(32),"siblings":[]}});
    assert!(serde_json::from_value::<PolicyEvidence>(p.clone()).is_ok());
    p.as_object_mut().unwrap().remove("record");
    assert!(serde_json::from_value::<PolicyEvidence>(p).is_err());
}

#[test]
fn payer_participation_cannot_count_toward_a_distinct_recovery_quorum() {
    let payer = "aa".repeat(28);
    let first = "bb".repeat(28);
    let second = "cc".repeat(28);
    let outsider = "dd".repeat(28);
    let roles = json!({"action":"disable","requiredSignerKeyHashes":[payer,first,second],
        "recoveryKeyHashes":[payer,first,second,outsider],"outputEffects":[{"address":format!("60{payer}")}]});
    assert!(participates(Role::FeePayer, &payer, &roles));
    assert!(!participates(Role::Recovery, &payer, &roles));
    assert!(participates(Role::Recovery, &first, &roles));
    assert!(!participates(Role::Recovery, &outsider, &roles));
}

#[test]
fn three_accepted_cross_runtime_originals_reproduce_the_complete_common_review() {
    let data: Json = serde_json::from_str(include_str!("vectors.json")).unwrap();
    assert_eq!(
        data["schema"],
        "castalia.kettle-current-approval-vectors.v1"
    );
    let cases = data["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let raw = case["original"].as_str().unwrap();
        let c: ReviewContext = serde_json::from_value(case["context"].clone()).unwrap();
        let observed = inspect_public(raw, &c).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(observed, case["review"], "{name}: original review");
    }
}

#[test]
fn original_redeemer_integrity_and_current_origin_evidence_are_checked_independently() {
    let fixtures: Json = serde_json::from_str(include_str!("vectors.json")).unwrap();
    let x = &fixtures["cases"][1];
    let raw = x["original"].as_str().unwrap();
    let c: ReviewContext = serde_json::from_value(x["context"].clone()).unwrap();
    let expected = inspect_public(raw, &c).unwrap();
    let mut bytes = hex::decode(raw).unwrap();
    // The fixture's last declared step count ends immediately before the normal tag/null.
    let last = bytes.len() - 3;
    bytes[last] ^= 1;
    let altered = hex::encode(&bytes);
    let parsed = current_wire::decode_original_transaction(&altered).unwrap();
    assert_eq!(parsed.transaction_id(), expected["transactionBodyHash"]);
    assert_eq!(
        inspect_public(&altered, &c).unwrap_err().0,
        "unsigned original current action"
    );
    let mut current = c.clone();
    current.envelope_sha256 = sha(&bytes);
    assert_eq!(
        inspect_public(&altered, &current).unwrap_err().0,
        "original script-data integrity"
    );
    let mut missing = c.clone();
    missing.creators.pop();
    assert_eq!(
        inspect_public(raw, &missing).unwrap_err().0,
        "exact number of original creators"
    );
    let mut duplicate = c.clone();
    duplicate.creators[1] = duplicate.creators[0].clone();
    assert_eq!(
        inspect_public(raw, &duplicate).unwrap_err().0,
        "sorted exact creating transaction set"
    );
    let mut unmeasured = c.clone();
    unmeasured.evaluated[0].memory = "0".into();
    assert_eq!(
        inspect_public(raw, &unmeasured).unwrap_err().0,
        "unmeasured or underdeclared purpose"
    );
    let mut underdeclared = c;
    underdeclared.evaluated[0].steps = "10000000000".into();
    assert!(inspect_public(raw, &underdeclared).is_err());
}

#[test]
fn typed_data_aliases_have_one_commitment_while_originals_remain_distinct() {
    for (aliased, canonical) in [
        ("d866820080", "d87980"),
        ("d8669f079fffff", "d9050080"),
        ("d87981c24101", "d8799f01ff"),
        ("d87981c34101", "d8799f21ff"),
        ("d86682187f80", "d9057880"),
    ] {
        let original = hex::decode(aliased).unwrap();
        let n = data_reader::read(&original);
        let expected = hex::decode(canonical).unwrap();
        assert_eq!(data::data(&n.unwrap()).unwrap(), expected);
        assert_ne!(sha(&original), sha(&expected));
    }
    for invalid in [
        "c249010000000000000000",
        "d86682188080",
        "d866820001",
        "d86683008000",
        "a20100c2410100",
    ] {
        assert!(
            data_reader::read(&hex::decode(invalid).unwrap()).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn shared_missing_principal_and_original_script_data_cases_fail_at_independent_checks() {
    let fixtures: Json = serde_json::from_str(include_str!("vectors.json")).unwrap();
    let deltas: Json = serde_json::from_str(include_str!("negative-deltas.json")).unwrap();
    let registered = &fixtures["cases"][1];
    for row in deltas["cases"].as_array().unwrap() {
        let mut raw = hex::decode(registered["original"].as_str().unwrap()).unwrap();
        let offset = usize::try_from(row["offset"].as_u64().unwrap()).unwrap();
        let before = hex::decode(row["before"].as_str().unwrap()).unwrap();
        let after = hex::decode(row["after"].as_str().unwrap()).unwrap();
        assert_eq!(raw[offset..offset + before.len()], before);
        raw.splice(offset..offset + before.len(), after);
        let mut context: ReviewContext =
            serde_json::from_value(registered["context"].clone()).unwrap();
        context.source_id = row["sourceId"].as_str().unwrap().to_owned();
        context.envelope_sha256 = sha(&raw);
        assert_eq!(row["envelopeSha256"], context.envelope_sha256);
        let reason = match row["name"].as_str().unwrap() {
            "changed-script-data" => "original script-data integrity",
            "native-only-residual-deficit" => "full native principal balance",
            name => panic!("unexpected shared fixture {name}"),
        };
        assert_eq!(
            inspect_public(&hex::encode(raw), &context).unwrap_err().0,
            reason
        );
    }
}
