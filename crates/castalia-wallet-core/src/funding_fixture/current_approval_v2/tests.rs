use super::*;

#[test]
fn fixed_approval_identity_and_evidence_are_versioned() {
    let mut preimage = b"castalia/kettle-current-approval/v2\0".to_vec();
    preimage.extend(super::super::current_approval::PROFILE.as_bytes());
    assert_eq!(sha(&preimage), PROFILE);
    assert!(serde_json::from_value::<Evidence>(json!({"kind":"none","policy":{}})).is_err());
    assert!(
        serde_json::from_value::<Evidence>(json!({"kind":"current-request","id":"41"})).is_err()
    );
}

fn signed_profile(
    session: &ApprovalSession,
    key: &ed25519_dalek::SigningKey,
    text_schema: &str,
    signature_domain: &str,
    profile_id: &str,
) -> Signed<ProfileStatement> {
    use ed25519_dalek::Signer;
    let mut value = session.identity();
    value["schema"] = json!(text_schema);
    value["sourceId"] = json!("11".repeat(32));
    value["profileId"] = json!(profile_id);
    let mut signed = signature_domain.as_bytes().to_vec();
    signed.push(0);
    signed.extend(canonical(&value).unwrap());
    Signed {
        statement: serde_json::from_value(value).unwrap(),
        signature_hex: hex::encode(key.sign(&signed).to_bytes()),
    }
}

#[test]
fn install_requires_the_current_domain_identity_source_and_real_session() {
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    let observer = SigningKey::generate(&mut OsRng);
    let other = SigningKey::generate(&mut OsRng);
    let old_schema = "castalia.kettle-current-approval-profile.v1";
    let new_schema = "castalia.kettle-current-approval-profile.v2";
    let mut session =
        ApprovalSession::fresh(observer.verifying_key().to_bytes(), Role::Author).unwrap();
    let other_session =
        ApprovalSession::fresh(observer.verifying_key().to_bytes(), Role::Controller).unwrap();
    for denied in [
        signed_profile(
            &session,
            &observer,
            old_schema,
            old_schema,
            super::super::current_approval::PROFILE,
        ),
        signed_profile(&session, &observer, new_schema, old_schema, PROFILE),
        signed_profile(
            &session,
            &observer,
            new_schema,
            new_schema,
            super::super::current_approval::PROFILE,
        ),
        signed_profile(&session, &other, new_schema, new_schema, PROFILE),
        signed_profile(&other_session, &observer, new_schema, new_schema, PROFILE),
    ] {
        assert!(session.install(&denied).is_err());
    }
    session
        .install(&signed_profile(
            &session, &observer, new_schema, new_schema, PROFILE,
        ))
        .unwrap();
    session.lock();
    assert!(session.info().is_err());
}

#[test]
fn all_three_v1_policy_semantics_are_reused_but_v2_owns_the_full_review_and_grant() {
    let corpus: Json =
        serde_json::from_str(include_str!("../current_approval/vectors.json")).unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        let mut context = case["context"].clone();
        context["evidence"] = context.as_object_mut().unwrap().remove("policy").unwrap();
        context["evidence"]["kind"] = json!("policy");
        context["profileId"] = json!(PROFILE);
        context["schema"] = json!("castalia.kettle-current-approval-context.v2");
        let mut current: ReviewContext = serde_json::from_value(context.clone()).unwrap();
        let original = case["original"].as_str().unwrap();
        let derived = inspect_public(original, &current).unwrap();
        assert_eq!(derived["effects"]["review"], case["review"]);
        assert_eq!(derived["contextDigest"], sha(&canonical(&current).unwrap()));
        assert_ne!(derived["contextDigest"], case["review"]["contextDigest"]);
        let old: super::super::current_approval::ReviewContext =
            serde_json::from_value(case["context"].clone()).unwrap();
        assert!(
            serde_json::from_value::<ReviewContext>(serde_json::to_value(old).unwrap()).is_err()
        );
        current.evaluated[0].purpose = "mint".into();
        assert!(inspect_public(original, &current).is_err());
        current.evaluated[0].purpose = "spend".into();
        current.evidence = Evidence::None {};
        assert!(inspect_public(original, &current).is_err());
    }
}

fn original_context(fixture: &Json, row: &Json) -> ReviewContext {
    let mut decoded = row["context"].clone();
    for creator in decoded["creators"].as_array_mut().unwrap() {
        let hash = creator
            .as_object_mut()
            .unwrap()
            .remove("envelopeSha256")
            .unwrap();
        let raw = fixture["creators"][hash.as_str().unwrap()]
            .as_str()
            .unwrap();
        assert_eq!(sha(&hex::decode(raw).unwrap()), hash);
        creator["original"] = json!(raw);
    }
    serde_json::from_value(decoded).unwrap()
}

#[test]
fn nine_original_actions_match_the_entire_independent_web_review() {
    let fixture: Json = serde_json::from_str(include_str!("vectors.json")).unwrap();
    let mut actions = std::collections::BTreeSet::new();
    for row in fixture["cases"].as_array().unwrap() {
        let c = original_context(&fixture, row);
        let observed = inspect_public(row["original"].as_str().unwrap(), &c)
            .unwrap_or_else(|e| panic!("{}: {e}", row["name"]));
        assert_eq!(observed, row["review"], "{}", row["name"]);
        actions.insert(observed["action"].as_str().unwrap().to_string());
    }
    assert_eq!(
        actions,
        [
            "add",
            "registered",
            "disable",
            "direct",
            "restore",
            "replace",
            "create",
            "revise",
            "proposalPay"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}

#[test]
fn request_provenance_evaluation_and_participation_follow_the_actual_action() {
    let fixture: Json = serde_json::from_str(include_str!("vectors.json")).unwrap();
    for row in fixture["cases"].as_array().unwrap() {
        let mut c = original_context(&fixture, row);
        let original = row["original"].as_str().unwrap();
        let review = &row["review"];
        let action = review["action"].as_str().unwrap();
        let k = review["requiredSignerKeyHashes"].as_array().unwrap();
        let payer = review["outputEffects"].as_array().unwrap().last().unwrap()["address"]
            .as_str()
            .unwrap()
            .strip_prefix("60")
            .unwrap();
        for key in k {
            let own = key.as_str().unwrap();
            let expected = if own == payer {
                Role::FeePayer
            } else {
                match action {
                    "create" | "revise" => Role::Author,
                    "restore" | "replace" | "disable" => Role::Recovery,
                    "direct" | "proposalPay" | "add" => Role::Controller,
                    _ => panic!("unexpected signer"),
                }
            };
            for role in [
                Role::FeePayer,
                Role::Recovery,
                Role::Controller,
                Role::Author,
            ] {
                assert_eq!(
                    participates(role, own, review),
                    role == expected,
                    "{action} role {role:?}"
                );
            }
        }
        if action == "proposalPay" {
            let author = review["effects"]["before"]["author"].as_str().unwrap();
            assert!(
                !participates(Role::Author, author, review),
                "the author does not approve Pay"
            );
        }
        if action == "replace" {
            let old = review["stateBefore"]["roster"].as_array().unwrap();
            let new = review["stateAfter"]["roster"].as_array().unwrap();
            let future = new
                .iter()
                .find(|key| !old.contains(key))
                .expect("genuinely new roster key");
            assert!(
                !participates(Role::Recovery, future.as_str().unwrap(), review),
                "future-only recovery credential"
            );
        }
        match &mut c.evidence {
            Evidence::RequestAbsence { id } => *id = "00".repeat(32),
            Evidence::CurrentRequest { seed, .. } => seed.output_index ^= 1,
            Evidence::None {} => {
                c.evidence = Evidence::RequestAbsence {
                    id: "00".repeat(32),
                }
            }
            Evidence::Policy { id, .. } => *id = "ff".repeat(32),
        }
        assert!(
            inspect_public(original, &c).is_err(),
            "{action} wrong evidence"
        );
        if action == "proposalPay" {
            let mut c = original_context(&fixture, row);
            let mint = c
                .evaluated
                .iter_mut()
                .find(|p| p.purpose == "mint")
                .unwrap();
            mint.purpose = "spend".into();
            assert!(
                inspect_public(original, &c).is_err(),
                "Spend pointer cannot discharge Mint"
            );
        }
    }
}

#[test]
fn exact_shared_proposal_refusals_cover_purpose_identity_and_author_refund_separation() {
    let corpus: Json = serde_json::from_str(include_str!("vectors.json")).unwrap();
    let pay = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["review"]["action"] == "proposalPay")
        .unwrap();
    let baseline = serde_json::to_value(original_context(&corpus, pay)).unwrap();
    let negatives: Json = serde_json::from_str(include_str!("refusals.json")).unwrap();
    for row in negatives["cases"].as_array().unwrap() {
        let mut current = baseline.clone();
        for (k, v) in row["contextChanges"].as_object().unwrap() {
            assert!(matches!(
                k.as_str(),
                "sourceId" | "envelopeSha256" | "evaluated"
            ));
            current[k] = v.clone();
        }
        let context: ReviewContext = serde_json::from_value(current).unwrap();
        let raw = row["original"].as_str().unwrap();
        assert_eq!(sha(&hex::decode(raw).unwrap()), context.envelope_sha256);
        let error = inspect_public(raw, &context).unwrap_err().0;
        match row["name"].as_str().unwrap() {
            "same-address-author-return-ordinal-alias" => {
                assert_eq!(error, "protected output index")
            }
            "missing-Mint-substituted-duplicate-Spend" => {
                assert_eq!(error, "ordered distinct evaluated pointers")
            }
            "mint-pointer-outside-policy" => assert_eq!(error, "current transaction wire"),
            _ => panic!("unknown shared refusal"),
        }
    }
}
