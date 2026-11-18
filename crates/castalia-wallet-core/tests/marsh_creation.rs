#![cfg(feature = "funding-fixtures")]
use castalia_wallet_core::marsh_creation::{
    credential_commitment, holder_transcript, issuer_transcript, verify_creation,
};
use serde_json::Value;
fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/marsh-creation-authority-v1.json")).unwrap()
}
#[test]
fn frozen_independent_a3_vectors() {
    let v = vectors();
    for case in v["positive"].as_array().unwrap() {
        let credential = &case["proof"]["credential"];
        assert_eq!(
            hex::encode(issuer_transcript(credential).unwrap()),
            case["issuerTranscriptHex"]
        );
        assert_eq!(
            hex::encode(credential_commitment(credential).unwrap()),
            case["credentialCommitmentHex"]
        );
        assert_eq!(
            hex::encode(holder_transcript(&case["context"], credential).unwrap()),
            case["holderTranscriptHex"]
        );
        verify_creation(&case["context"], &case["proof"], &v["admission"]).unwrap();
    }
    for case in v["negative"].as_array().unwrap() {
        assert!(
            verify_creation(
                &v["positive"][0]["context"],
                &case["proof"],
                &v["admission"]
            )
            .is_err(),
            "{}",
            case["name"]
        );
    }
}

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use castalia_wallet_core::{
    CardanoFundingNetworkV1,
    funding_fixture::{
        FundingFixtureSession, MARSH_ADMISSION_DOMAIN, MARSH_CONTEXT_DOMAIN, MARSH_PROFILE_DOMAIN,
        fixture_transcript,
    },
    marsh_creation::{parse, trust_commitment, trust_path, verify_trust_path},
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;
fn owner_signature(key: &SigningKey, domain: &str, statement: &Value) -> String {
    hex::encode(
        key.sign(&fixture_transcript(domain, statement).unwrap())
            .to_bytes(),
    )
}
fn fixture(ttl: Duration) -> (FundingFixtureSession, SigningKey, Value, Value) {
    // Public disposable issuer/admission keys. Wallet MemberKey is fresh, never exported.
    let owner = SigningKey::from_bytes(&[73; 32]);
    let issuer = SigningKey::from_bytes(&[74; 32]);
    let mut session = FundingFixtureSession::fresh_with_ttl(
        owner.verifying_key().to_bytes(),
        CardanoFundingNetworkV1::testnet(270544960, &"11".repeat(32)).unwrap(),
        ttl,
    )
    .unwrap();
    let mut admission = vectors()["admission"].clone();
    admission["membershipTrustPolicy"]["roots"] = json!([{"issuerId":"fixture","keyId":"key","signatureSuite":"Ed25519","publicKey":hex::encode(issuer.verifying_key().to_bytes())}]);
    let statement = session
        .marsh_profile_statement(&admission.to_string())
        .unwrap();
    session
        .install_marsh_profile(
            &admission.to_string(),
            &owner_signature(&owner, MARSH_PROFILE_DOMAIN, &statement),
        )
        .unwrap();
    observe(&mut session, &owner, 0);
    let mut context = vectors()["positive"][0]["context"].clone();
    context["initialController"] = json!(session.info().account.payment_key_hash());
    let member = session.member_key().unwrap();
    let mut m = b"castalia/zenith-membership-id/v3\0".to_vec();
    m.extend(hex::decode(&member).unwrap());
    let mut c = json!({"schema":"castalia.zenith-membership-credential.v3","version":3,"membershipId":hex::encode(Sha256::digest(m)),"ownerPublicKey":member,"status":"active","issuerId":"fixture","issuerKeyId":"key","signatureSuite":"Ed25519","issuerSignature":B64.encode([0u8;64])});
    c["issuerSignature"] =
        json!(B64.encode(issuer.sign(&issuer_transcript(&c).unwrap()).to_bytes()));
    (
        session,
        owner,
        json!({"context":context,"credential":c}),
        admission,
    )
}
fn observe(s: &mut FundingFixtureSession, owner: &SigningKey, g: u64) {
    let st = s.marsh_context_statement(g, &"ab".repeat(32)).unwrap();
    s.set_marsh_context(
        g,
        &"ab".repeat(32),
        &owner_signature(owner, MARSH_CONTEXT_DOMAIN, &st),
    )
    .unwrap();
}
fn prepare(s: &mut FundingFixtureSession, owner: &SigningKey, r: &Value) -> String {
    let st = s.inspect_marsh_creation(&r.to_string()).unwrap();
    s.prepare_marsh_creation(
        &r.to_string(),
        &owner_signature(owner, MARSH_ADMISSION_DOMAIN, &st),
    )
    .unwrap()
    .handle
}
#[test]
fn custody_proof_is_exact_verifiable_and_one_shot() {
    let (mut s, owner, r, admission) = fixture(Duration::from_secs(30));
    let handle = prepare(&mut s, &owner, &r);
    let result = s.approve_marsh_creation(&handle).unwrap();
    assert_eq!(result.label, "synthetic-fixture-approval-only");
    println!(
        "MARSH_PUBLIC_VECTOR:{}",
        json!({"context":r["context"],"proof":result.proof,"admission":admission,"trustPath":result.trust_path,"issuerTranscriptHex":hex::encode(issuer_transcript(&r["credential"]).unwrap()),"credentialCommitmentHex":hex::encode(credential_commitment(&r["credential"]).unwrap()),"holderTranscriptHex":hex::encode(holder_transcript(&r["context"],&r["credential"]).unwrap()),"scope":"public fresh disposable custody; synthetic admission only"})
    );
    verify_creation(&r["context"], &result.proof, &admission).unwrap();
    verify_trust_path(
        &r["credential"],
        &result.trust_path,
        &trust_commitment(&admission["membershipTrustPolicy"]).unwrap(),
    )
    .unwrap();
    assert!(s.approve_marsh_creation(&handle).is_err());
    assert!(
        s.prepare_marsh_creation(
            &r.to_string(),
            &owner_signature(
                &owner,
                MARSH_ADMISSION_DOMAIN,
                &s.inspect_marsh_creation(&r.to_string()).unwrap()
            )
        )
        .is_err()
    );
    for field in [
        "initialController",
        "seed",
        "deployment",
        "initialReceiver",
        "fixedKettle",
        "initialSecondary",
    ] {
        let mut altered = r["context"].clone();
        altered[field] = Value::Null;
        assert!(verify_creation(&altered, &result.proof, &admission).is_err());
    }
}
#[test]
fn cancellation_close_invalidation_expiry_and_session_isolation() {
    for action in 0..5 {
        let (mut s, owner, r, _) = fixture(if action == 4 {
            Duration::from_nanos(1)
        } else {
            Duration::from_secs(30)
        });
        let handle = prepare(&mut s, &owner, &r);
        match action {
            0 => {
                assert!(s.cancel_marsh_creation(&handle));
            }
            1 => s.close(),
            2 => s.invalidate().unwrap(),
            3 => observe(&mut s, &owner, 1),
            _ => {}
        }
        assert!(s.approve_marsh_creation(&handle).is_err());
        assert!(s.approve_marsh_creation(&handle).is_err());
    }
    let (mut s, owner, r, _) = fixture(Duration::from_secs(30));
    let handle = prepare(&mut s, &owner, &r);
    let (mut other, _, _, _) = fixture(Duration::from_secs(30));
    assert!(other.approve_marsh_creation(&handle).is_err());
    assert!(s.approve_marsh_creation(&handle).is_ok());
}
#[test]
fn admission_authentication_and_frozen_review_reject_substitution() {
    let (mut s, owner, r, admission) = fixture(Duration::from_secs(30));
    let inspected = s.inspect_marsh_creation(&r.to_string()).unwrap();
    let signature = owner_signature(&owner, MARSH_ADMISSION_DOMAIN, &inspected);
    let wrong = SigningKey::from_bytes(&[75; 32]);
    assert!(
        s.prepare_marsh_creation(
            &r.to_string(),
            &owner_signature(&wrong, MARSH_ADMISSION_DOMAIN, &inspected)
        )
        .is_err()
    );
    for field in [
        "ownerPublicKey",
        "membershipId",
        "issuerId",
        "issuerKeyId",
        "issuerSignature",
    ] {
        let mut changed = r.clone();
        changed["credential"][field] = json!("00");
        assert!(
            s.prepare_marsh_creation(&changed.to_string(), &signature)
                .is_err()
        );
    }
    let mut changed = r.clone();
    changed["context"]["initialController"] = json!("56".repeat(28));
    assert!(s.inspect_marsh_creation(&changed.to_string()).is_err());
    changed = r.clone();
    changed["context"]["seed"]["outputIndex"] = json!(257);
    assert!(
        s.prepare_marsh_creation(&changed.to_string(), &signature)
            .is_err()
    );
    let p = s
        .prepare_marsh_creation(&r.to_string(), &signature)
        .unwrap();
    let mut public_review = p.review;
    public_review["context"] = changed["context"].clone();
    let proof = s.approve_marsh_creation(&p.handle).unwrap();
    verify_creation(&r["context"], &proof.proof, &admission).unwrap();
    assert!(verify_creation(&changed["context"], &proof.proof, &admission).is_err());
    let mut path = proof.trust_path;
    path.candidate_key = hex::encode(wrong.verifying_key().to_bytes());
    assert!(
        verify_trust_path(
            &r["credential"],
            &path,
            &trust_commitment(&admission["membershipTrustPolicy"]).unwrap()
        )
        .is_err()
    );
    assert!(
        s.install_marsh_profile(&admission.to_string(), &signature)
            .is_err()
    );
}
#[test]
fn profile_is_independent_authenticated_network_bound_and_closed() {
    let owner = SigningKey::from_bytes(&[73; 32]);
    let mut s = FundingFixtureSession::fresh(
        owner.verifying_key().to_bytes(),
        CardanoFundingNetworkV1::testnet(270544960, &"11".repeat(32)).unwrap(),
    )
    .unwrap();
    let admission = vectors()["admission"].clone();
    let statement = s.marsh_profile_statement(&admission.to_string()).unwrap();
    assert!(
        s.install_marsh_profile(&admission.to_string(), &"00".repeat(64))
            .is_err()
    );
    for k in ["magic", "genesis", "discriminator"] {
        let mut altered = admission.clone();
        match k {
            "magic" => altered["deployment"]["network"]["id"]["magic"] = json!(42),
            "genesis" => altered["deployment"]["network"]["genesisDigest"] = json!("22".repeat(32)),
            _ => altered["deployment"]["discriminator"] = json!("33".repeat(32)),
        };
        assert!(
            s.install_marsh_profile(
                &altered.to_string(),
                &owner_signature(&owner, MARSH_PROFILE_DOMAIN, &statement)
            )
            .is_err()
        );
    }
    assert!(parse("{\"credential\":{},\"credential\":{}}").is_err());
    assert!(parse(&" ".repeat(65537)).is_err());
    s.install_marsh_profile(
        &admission.to_string(),
        &owner_signature(&owner, MARSH_PROFILE_DOMAIN, &statement),
    )
    .unwrap();
    let ctx = s.marsh_context_statement(0, &"ab".repeat(32)).unwrap();
    assert!(
        s.set_marsh_context(0, &"ab".repeat(32), &"00".repeat(64))
            .is_err()
    );
    s.set_marsh_context(
        0,
        &"ab".repeat(32),
        &owner_signature(&owner, MARSH_CONTEXT_DOMAIN, &ctx),
    )
    .unwrap();
    assert!(
        s.set_marsh_context(
            0,
            &"ab".repeat(32),
            &owner_signature(&owner, MARSH_CONTEXT_DOMAIN, &ctx)
        )
        .is_err()
    );
}
#[test]
fn trust_manifest_bounds_padding_and_exact_tuple() {
    let mut policy = vectors()["admission"]["membershipTrustPolicy"].clone();
    let key = policy["roots"][0]["publicKey"].clone();
    policy["roots"]=json!((0..128).map(|i|json!({"issuerId":"fixture","keyId":format!("key-{i:03}"),"signatureSuite":"Ed25519","publicKey":key})).collect::<Vec<_>>());
    let (commit, path) = trust_path(&policy, "fixture", "key-127").unwrap();
    assert_eq!(path.index, 127);
    assert_eq!(commit.count, 128);
    let c = json!({"issuerId":"fixture","issuerKeyId":"key-127"});
    verify_trust_path(&c, &path, &commit).unwrap();
    let mut wrong = commit.clone();
    wrong.count = 127;
    assert!(verify_trust_path(&c, &path, &wrong).is_err());
    wrong = commit.clone();
    wrong.commitment = "00".repeat(32);
    assert!(verify_trust_path(&c, &path, &wrong).is_err());
    let mut p = path.clone();
    p.siblings.pop();
    assert!(verify_trust_path(&c, &p, &commit).is_err());
    let other = json!({"issuerId":"other","issuerKeyId":"key-127"});
    assert!(verify_trust_path(&other, &path, &commit).is_err());
    policy["roots"].as_array_mut().unwrap().reverse();
    assert_eq!(
        trust_path(&policy, "fixture", "key-127").unwrap(),
        (commit, path)
    );
    let duplicate = policy["roots"][0].clone();
    policy["roots"][1] = duplicate;
    assert!(trust_commitment(&policy).is_err());
    policy["roots"] = json!([]);
    assert!(trust_commitment(&policy).is_err());
}
#[test]
fn inline_data_bounds_and_canonical_values() {
    let v = vectors();
    let base = &v["positive"][0];
    let c = &base["proof"]["credential"];
    let mut context = base["context"].clone();
    let data_path = &mut context["initialReceiver"]["datum"];
    *data_path = json!({"kind":"inline","value":{"kind":"bytes","hex":"00".repeat(2045)}});
    assert!(holder_transcript(&context, c).is_ok());
    context["initialReceiver"]["datum"]["value"]["hex"] = json!("00".repeat(2046));
    assert!(holder_transcript(&context, c).is_err());
    for value in [
        "-0",
        "00",
        "+1",
        "1.0",
        "115792089237316195423570985008687907853269984665640564039457584007913129639936",
    ] {
        context["initialReceiver"]["datum"] =
            json!({"kind":"inline","value":{"kind":"int","value":value}});
        assert!(holder_transcript(&context, c).is_err());
    }
    let entry = json!([{"kind":"int","value":"1"},{"kind":"int","value":"0"}]);
    context["initialReceiver"]["datum"] =
        json!({"kind":"inline","value":{"kind":"map","entries":[entry.clone(),entry]}});
    assert!(holder_transcript(&context, c).is_err());
    let mut tree = json!({"kind":"int","value":"0"});
    for _ in 0..15 {
        tree = json!({"kind":"list","items":[tree]});
    }
    context["initialReceiver"]["datum"] = json!({"kind":"inline","value":tree.clone()});
    assert!(holder_transcript(&context, c).is_ok());
    context["initialReceiver"]["datum"]["value"] = json!({"kind":"list","items":[tree]});
    assert!(holder_transcript(&context, c).is_err());
    context = base["context"].clone();
    context["seed"]["outputIndex"] = json!(-0.0);
    assert!(holder_transcript(&context, c).is_err());
    context = base["context"].clone();
    context["unknown"] = json!(true);
    assert!(holder_transcript(&context, c).is_err());
}

#[test]
fn independent_frozen_a4_paths_match_all_bytes() {
    let base = vectors()["admission"]["membershipTrustPolicy"].clone();
    for line in include_str!("fixtures/marsh-creation-trust-v1.tsv").lines() {
        let columns: Vec<_> = line.split('\t').collect();
        let mut policy = base.clone();
        let selected = if columns[0] == "current" {
            "current-key"
        } else {
            "historical-key"
        };
        if columns[0] == "single" {
            policy["roots"] = json!([base["roots"][0].clone()]);
        }
        if columns[0] == "full" {
            let mut roots:Vec<_>=(0..126).map(|i|json!({"issuerId":format!("a{}","k".repeat(63)),"keyId":format!("{}{i:03}","k".repeat(61)),"signatureSuite":"Ed25519","publicKey":base["roots"][0]["publicKey"]})).collect();
            roots.extend(base["roots"].as_array().unwrap().clone());
            policy["roots"] = json!(roots);
        }
        let (commit, path) = trust_path(&policy, "fixture-issuer", selected).unwrap();
        assert_eq!(commit.count.to_string(), columns[1]);
        assert_eq!(commit.commitment, columns[2]);
        assert_eq!(path.index.to_string(), columns[3]);
        assert_eq!(path.candidate_key, columns[4]);
        assert_eq!(path.siblings, columns[5..]);
    }
}
#[test]
fn every_context_leaf_is_bound_by_frozen_holder_signature() {
    fn leaves(v: &Value, path: Vec<String>, out: &mut Vec<Vec<String>>) {
        match v {
            Value::Object(o) => {
                for (k, v) in o {
                    let mut p = path.clone();
                    p.push(k.clone());
                    leaves(v, p, out);
                }
            }
            Value::Array(a) => {
                for (i, v) in a.iter().enumerate() {
                    let mut p = path.clone();
                    p.push(i.to_string());
                    leaves(v, p, out);
                }
            }
            _ => out.push(path),
        }
    }
    let v = vectors();
    for case in v["positive"].as_array().unwrap() {
        let mut paths = vec![];
        leaves(&case["context"], vec![], &mut paths);
        for path in paths {
            let mut c = case["context"].clone();
            let mut at = &mut c;
            for p in &path {
                at = if at.is_array() {
                    &mut at[p.parse::<usize>().unwrap()]
                } else {
                    &mut at[p]
                };
            }
            *at = match at {
                Value::String(s) => {
                    let mut x = s.clone();
                    if x.is_empty() {
                        x.push_str("00");
                    } else {
                        let end = x.pop().unwrap();
                        x.push(if end == '0' { '1' } else { '0' });
                    }
                    json!(x)
                }
                Value::Number(n) => json!(n.as_u64().unwrap() + 1),
                _ => Value::Null,
            };
            assert!(
                verify_creation(&c, &case["proof"], &v["admission"]).is_err(),
                "mutated {path:?}"
            );
        }
    }
}

#[test]
fn same_admission_signer_cannot_transfer_profile_context_or_review_between_sessions() {
    let (source, owner, source_request, admission) = fixture(Duration::from_secs(30));
    let profile_signature = owner_signature(
        &owner,
        MARSH_PROFILE_DOMAIN,
        &source
            .marsh_profile_statement(&admission.to_string())
            .unwrap(),
    );
    let context_signature = owner_signature(
        &owner,
        MARSH_CONTEXT_DOMAIN,
        &source.marsh_context_statement(0, &"ab".repeat(32)).unwrap(),
    );
    let review_signature = owner_signature(
        &owner,
        MARSH_ADMISSION_DOMAIN,
        &source
            .inspect_marsh_creation(&source_request.to_string())
            .unwrap(),
    );
    let mut target = FundingFixtureSession::fresh(
        owner.verifying_key().to_bytes(),
        source.info().account.network().clone(),
    )
    .unwrap();
    assert_ne!(source.info().session_id, target.info().session_id);
    assert!(
        target
            .install_marsh_profile(&admission.to_string(), &profile_signature)
            .is_err()
    );
    let own_profile = target
        .marsh_profile_statement(&admission.to_string())
        .unwrap();
    target
        .install_marsh_profile(
            &admission.to_string(),
            &owner_signature(&owner, MARSH_PROFILE_DOMAIN, &own_profile),
        )
        .unwrap();
    assert!(
        target
            .set_marsh_context(0, &"ab".repeat(32), &context_signature)
            .is_err()
    );
    observe(&mut target, &owner, 0);
    let mut request = source_request.clone();
    request["context"]["initialController"] = json!(target.info().account.payment_key_hash());
    request["credential"]["ownerPublicKey"] = json!(target.member_key().unwrap());
    let mut membership = b"castalia/zenith-membership-id/v3\0".to_vec();
    membership.extend(hex::decode(target.member_key().unwrap()).unwrap());
    request["credential"]["membershipId"] = json!(hex::encode(Sha256::digest(membership)));
    let issuer = SigningKey::from_bytes(&[74; 32]);
    request["credential"]["issuerSignature"] = json!(
        B64.encode(
            issuer
                .sign(&issuer_transcript(&request["credential"]).unwrap())
                .to_bytes()
        )
    );
    // Target has valid own credentials and identical logical intent; only the source
    // session's authorization capability is supplied. Reject it before any handle.
    target.inspect_marsh_creation(&request.to_string()).unwrap();
    assert!(
        target
            .prepare_marsh_creation(&request.to_string(), &review_signature)
            .is_err()
    );
    let handle = prepare(&mut target, &owner, &request);
    let proof = target.approve_marsh_creation(&handle).unwrap();
    verify_creation(&request["context"], &proof.proof, &admission).unwrap();
}

#[test]
fn cancelled_or_expired_admission_cannot_reprepare_without_new_observation() {
    for expiry in [false, true] {
        let (mut s, owner, request, _) = fixture(if expiry {
            Duration::from_nanos(1)
        } else {
            Duration::from_secs(30)
        });
        let review = s.inspect_marsh_creation(&request.to_string()).unwrap();
        let signature = owner_signature(&owner, MARSH_ADMISSION_DOMAIN, &review);
        let handle = s
            .prepare_marsh_creation(&request.to_string(), &signature)
            .unwrap()
            .handle;
        if expiry {
            assert!(s.approve_marsh_creation(&handle).is_err());
        } else {
            assert!(s.cancel_marsh_creation(&handle));
        }
        assert!(
            s.prepare_marsh_creation(&request.to_string(), &signature)
                .is_err()
        );
        assert!(s.approve_marsh_creation(&handle).is_err());
        observe(&mut s, &owner, 1);
        // A generation advance invalidates the old signed review as well as its handle.
        assert!(
            s.prepare_marsh_creation(&request.to_string(), &signature)
                .is_err()
        );
        // The synthetic authority may deliberately reauthorize the same intent in a
        // new observation. This is local capability control, not ledger seed replay.
        let fresh_handle = prepare(&mut s, &owner, &request);
        assert!(s.cancel_marsh_creation(&fresh_handle));
    }
}

#[test]
fn malformed_issuer_proofs_and_weak_member_keys_reject_at_custody_ingress() {
    let (mut s, owner, request, admission) = fixture(Duration::from_secs(30));
    let review = s.inspect_marsh_creation(&request.to_string()).unwrap();
    let authorization = owner_signature(&owner, MARSH_ADMISSION_DOMAIN, &review);
    let mut weak_r = [0u8; 64];
    weak_r[0] = 1;
    let mut noncanonical_s = B64
        .decode(request["credential"]["issuerSignature"].as_str().unwrap())
        .unwrap();
    noncanonical_s[32..].fill(255);
    for signature in [
        "invalid".to_owned(),
        format!(
            "{}=",
            request["credential"]["issuerSignature"].as_str().unwrap()
        ),
        B64.encode([0u8; 64]),
        B64.encode(weak_r),
        B64.encode(noncanonical_s),
    ] {
        let mut changed = request.clone();
        changed["credential"]["issuerSignature"] = json!(signature);
        assert!(s.inspect_marsh_creation(&changed.to_string()).is_err());
        assert!(
            s.prepare_marsh_creation(&changed.to_string(), &authorization)
                .is_err()
        );
    }
    let mut weak_key = [0u8; 32];
    weak_key[0] = 1;
    let mut changed = request.clone();
    changed["credential"]["ownerPublicKey"] = json!(hex::encode(weak_key));
    let mut membership = b"castalia/zenith-membership-id/v3\0".to_vec();
    membership.extend(weak_key);
    changed["credential"]["membershipId"] = json!(hex::encode(Sha256::digest(membership)));
    let issuer = SigningKey::from_bytes(&[74; 32]);
    changed["credential"]["issuerSignature"] = json!(
        B64.encode(
            issuer
                .sign(&issuer_transcript(&changed["credential"]).unwrap())
                .to_bytes()
        )
    );
    assert!(s.inspect_marsh_creation(&changed.to_string()).is_err());
    assert!(
        s.prepare_marsh_creation(&changed.to_string(), &authorization)
            .is_err()
    );
    let mut weak_profile = admission.clone();
    weak_profile["membershipTrustPolicy"]["roots"][0]["publicKey"] = json!(hex::encode(weak_key));
    let mut new_session = FundingFixtureSession::fresh(
        owner.verifying_key().to_bytes(),
        s.info().account.network().clone(),
    )
    .unwrap();
    assert!(
        new_session
            .marsh_profile_statement(&weak_profile.to_string())
            .is_err()
    );
    assert!(
        new_session
            .install_marsh_profile(&weak_profile.to_string(), &authorization)
            .is_err()
    );
    // Invalid requests did not consume the valid original authorization or sign them.
    let handle = s
        .prepare_marsh_creation(&request.to_string(), &authorization)
        .unwrap()
        .handle;
    let proof = s.approve_marsh_creation(&handle).unwrap();
    verify_creation(&request["context"], &proof.proof, &admission).unwrap();
}

#[test]
fn expired_handles_free_pending_capacity_without_releasing_consumed_admissions() {
    let (mut s, owner, request, _) = fixture(Duration::from_nanos(1));
    let mut expired = Vec::new();
    for index in 0..8 {
        let mut r = request.clone();
        r["context"]["seed"]["outputIndex"] = json!(index);
        let review = s.inspect_marsh_creation(&r.to_string()).unwrap();
        let signature = owner_signature(&owner, MARSH_ADMISSION_DOMAIN, &review);
        let handle = s
            .prepare_marsh_creation(&r.to_string(), &signature)
            .unwrap()
            .handle;
        expired.push((r, signature, handle));
    }
    let mut distinct = request.clone();
    distinct["context"]["seed"]["outputIndex"] = json!(8);
    let handle = prepare(&mut s, &owner, &distinct);
    assert!(s.cancel_marsh_creation(&handle));
    for (r, signature, handle) in expired {
        assert!(s.approve_marsh_creation(&handle).is_err());
        assert!(
            s.prepare_marsh_creation(&r.to_string(), &signature)
                .is_err()
        );
    }
    assert_eq!(
        s.inspect_marsh_creation(&distinct.to_string()).unwrap()["contextGeneration"],
        json!(0)
    );
}

#[test]
fn expiration_preserves_bounded_consumed_ledger_until_signed_context_advance() {
    let (mut s, owner, request, _) = fixture(Duration::from_nanos(1));
    for index in 0..64 {
        let mut r = request.clone();
        r["context"]["seed"]["outputIndex"] = json!(index);
        prepare(&mut s, &owner, &r);
    }
    let mut next = request.clone();
    next["context"]["seed"]["outputIndex"] = json!(64);
    let old_review = s.inspect_marsh_creation(&next.to_string()).unwrap();
    let old_signature = owner_signature(&owner, MARSH_ADMISSION_DOMAIN, &old_review);
    assert!(
        s.prepare_marsh_creation(&next.to_string(), &old_signature)
            .is_err()
    );
    observe(&mut s, &owner, 1);
    assert!(
        s.prepare_marsh_creation(&next.to_string(), &old_signature)
            .is_err()
    );
    let fresh = prepare(&mut s, &owner, &next);
    assert!(s.cancel_marsh_creation(&fresh));
}
