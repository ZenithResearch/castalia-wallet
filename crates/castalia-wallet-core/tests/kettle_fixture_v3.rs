#![cfg(feature = "funding-fixtures")]
//! Disposable synthetic custody tests. No real account, key import or human consent.
use castalia_wallet_core::{
    CardanoFundingNetworkV1, funding_fixture::kettle::KettleFixtureSession,
};

#[test]
fn fresh_public_account_and_permanent_close_are_bounded() {
    let owner = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
    let network = CardanoFundingNetworkV1::testnet(2, &"12".repeat(32)).unwrap();
    let mut session =
        KettleFixtureSession::fresh(owner.verifying_key().to_bytes(), network).unwrap();
    assert_eq!(session.info().account.payment_key_hash().len(), 56);
    assert!(session.approve(&"00".repeat(32)).is_err());
    session.close();
    assert!(session.invalidate().is_err());
    assert!(session.approve(&"00".repeat(32)).is_err());
}

#[test]
fn public_original_vector_matches_independent_web_review() {
    use castalia_wallet_core::funding_fixture::kettle::{
        KettleFixtureProfile, KettleReviewContext, inspect_public_fixture,
    };
    let v: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/kettle-fixture-v3.json")).unwrap();
    let p: KettleFixtureProfile = serde_json::from_value(v["profile"].clone()).unwrap();
    let c: KettleReviewContext = serde_json::from_value(v["context"].clone()).unwrap();
    assert_eq!(p, KettleFixtureProfile::qualified());
    let review = inspect_public_fixture(
        v["transactionHex"].as_str().unwrap(),
        &p,
        &c,
        v["paymentKeyHash"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(review, v["review"]);
}

use castalia_wallet_core::funding_fixture::kettle::{
    ADMISSION_DOMAIN_V3, CONTEXT_DOMAIN_V3, KettleFixtureProfile, KettleReviewContext,
    PROFILE_DOMAIN_V3, inspect_public_fixture,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;

fn vector() -> Value {
    serde_json::from_str(include_str!("fixtures/kettle-fixture-v3.json")).unwrap()
}
fn digest(v: &impl serde::Serialize) -> String {
    hex::encode(Sha256::digest(serde_jcs::to_vec(v).unwrap()))
}
fn sign(owner: &SigningKey, domain: &str, v: &Value) -> String {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.extend(serde_jcs::to_vec(v).unwrap());
    hex::encode(owner.sign(&bytes).to_bytes())
}
fn context(v: &Value) -> KettleReviewContext {
    serde_json::from_value(v["context"].clone()).unwrap()
}
fn profile(v: &Value) -> KettleFixtureProfile {
    serde_json::from_value(v["profile"].clone()).unwrap()
}
fn open(owner: &SigningKey, ttl: Duration) -> KettleFixtureSession {
    KettleFixtureSession::fresh_with_ttl(
        owner.verifying_key().to_bytes(),
        CardanoFundingNetworkV1::testnet(2, &"12".repeat(32)).unwrap(),
        ttl,
    )
    .unwrap()
}
fn install(s: &mut KettleFixtureSession, owner: &SigningKey, v: &Value, generation: u64) {
    let p = profile(v);
    let sig = sign(owner, PROFILE_DOMAIN_V3, &s.profile_statement(&p).unwrap());
    s.set_profile(p, &sig).unwrap();
    advance(s, owner, v, generation);
}
fn advance(s: &mut KettleFixtureSession, owner: &SigningKey, v: &Value, generation: u64) {
    let hash = digest(&context(v));
    let sig = sign(
        owner,
        CONTEXT_DOMAIN_V3,
        &s.context_statement(generation, &hash).unwrap(),
    );
    s.set_context(generation, &hash, &sig).unwrap();
}
// This mutates only public fixture bytes to the fresh native public credential.
// It is a custody/parser unit vector, not a new VM/ledger settlement assertion.
fn own_vector(s: &KettleFixtureSession) -> Value {
    let mut v = vector();
    let old = v["paymentKeyHash"].as_str().unwrap().to_owned();
    let own = s.info().account.payment_key_hash();
    v["transactionHex"] = json!(v["transactionHex"].as_str().unwrap().replace(&old, own));
    for u in v["context"]["utxos"].as_array_mut().unwrap() {
        u["utxoCborHex"] = json!(u["utxoCborHex"].as_str().unwrap().replace(&old, own));
    }
    v["paymentKeyHash"] = json!(own);
    v
}
fn admission(s: &KettleFixtureSession, owner: &SigningKey, v: &Value) -> String {
    let i = s
        .inspect(v["transactionHex"].as_str().unwrap(), &context(v))
        .unwrap();
    sign(owner, ADMISSION_DOMAIN_V3, &i.statement)
}
fn prepare(s: &mut KettleFixtureSession, owner: &SigningKey, v: &Value) -> String {
    let sig = admission(s, owner, v);
    s.prepare(v["transactionHex"].as_str().unwrap(), &context(v), &sig)
        .unwrap()
        .handle
}
fn reject(v: &Value) -> bool {
    inspect_public_fixture(
        v["transactionHex"].as_str().unwrap(),
        &profile(v),
        &context(v),
        v["paymentKeyHash"].as_str().unwrap(),
    )
    .is_err()
}
fn replace_tx(v: &mut Value, old: &str, new: &str) {
    let tx = v["transactionHex"].as_str().unwrap();
    assert!(tx.contains(old));
    v["transactionHex"] = json!(tx.replace(old, new));
}
fn different_ttl(v: &Value, ttl: u8) -> Value {
    let mut changed = v.clone();
    let old = "031864";
    let new = format!("0318{ttl:02x}");
    assert_eq!(
        changed["transactionHex"]
            .as_str()
            .unwrap()
            .matches(old)
            .count(),
        1
    );
    replace_tx(&mut changed, old, &new);
    changed
}

#[test]
fn authentic_native_witness_is_for_original_body_and_handle_is_one_use() {
    let owner = SigningKey::from_bytes(&[72; 32]);
    let mut s = open(&owner, Duration::from_secs(30));
    let v = own_vector(&s);
    install(&mut s, &owner, &v, 1);
    let inspected = s
        .inspect(v["transactionHex"].as_str().unwrap(), &context(&v))
        .unwrap();
    let sig = sign(&owner, ADMISSION_DOMAIN_V3, &inspected.statement);
    let p = s
        .prepare(v["transactionHex"].as_str().unwrap(), &context(&v), &sig)
        .unwrap();
    assert_eq!(p.review, inspected.review);
    let witness = s.approve(&p.handle).unwrap();
    assert_eq!(witness.label, "synthetic-fixture-approval-only");
    assert_eq!(
        witness.transaction_body_hash,
        inspected.statement["transactionBodyHash"]
    );
    let public: [u8; 32] = hex::decode(witness.public_key).unwrap().try_into().unwrap();
    let signature = Signature::from_slice(&hex::decode(witness.signature).unwrap()).unwrap();
    VerifyingKey::from_bytes(&public)
        .unwrap()
        .verify_strict(
            &hex::decode(witness.transaction_body_hash).unwrap(),
            &signature,
        )
        .unwrap();
    assert!(s.approve(&p.handle).is_err());
    assert!(
        s.prepare(v["transactionHex"].as_str().unwrap(), &context(&v), &sig)
            .is_err()
    );
}
#[test]
fn cancel_expiry_context_advance_invalidate_and_close_revoke() {
    let owner = SigningKey::from_bytes(&[73; 32]);
    let mut s = open(&owner, Duration::from_millis(20));
    let v = own_vector(&s);
    install(&mut s, &owner, &v, 1);
    let sig = admission(&s, &owner, &v);
    let h = prepare(&mut s, &owner, &v);
    assert!(s.cancel(&h));
    assert!(!s.cancel(&h));
    assert!(s.approve(&h).is_err());
    assert!(
        s.prepare(v["transactionHex"].as_str().unwrap(), &context(&v), &sig)
            .is_err()
    );
    advance(&mut s, &owner, &v, 2);
    let h = prepare(&mut s, &owner, &v);
    std::thread::sleep(Duration::from_millis(30));
    assert!(s.approve(&h).is_err());
    assert!(
        s.prepare(
            v["transactionHex"].as_str().unwrap(),
            &context(&v),
            &admission(&s, &owner, &v)
        )
        .is_err()
    );
    advance(&mut s, &owner, &v, 3);
    let sig = admission(&s, &owner, &v);
    let h = prepare(&mut s, &owner, &v);
    advance(&mut s, &owner, &v, 4);
    assert!(s.approve(&h).is_err());
    assert!(
        s.prepare(v["transactionHex"].as_str().unwrap(), &context(&v), &sig)
            .is_err()
    );
    let h = prepare(&mut s, &owner, &v);
    s.invalidate().unwrap();
    assert!(s.approve(&h).is_err());
    assert!(
        s.inspect(v["transactionHex"].as_str().unwrap(), &context(&v))
            .is_err()
    );
    advance(&mut s, &owner, &v, 1);
    let h = prepare(&mut s, &owner, &v);
    s.close();
    assert!(s.approve(&h).is_err());
    assert!(
        s.inspect(v["transactionHex"].as_str().unwrap(), &context(&v))
            .is_err()
    );
}
#[test]
fn expired_queue_frees_capacity_without_reusing_consumed_admission() {
    let owner = SigningKey::from_bytes(&[74; 32]);
    let mut s = open(&owner, Duration::from_secs(2));
    let v = own_vector(&s);
    install(&mut s, &owner, &v, 1);
    let mut handles = vec![];
    for ttl in 93..=100 {
        handles.push(prepare(&mut s, &owner, &different_ttl(&v, ttl)));
    }
    let ninth = different_ttl(&v, 92);
    let sig = admission(&s, &owner, &ninth);
    assert!(
        s.prepare(
            ninth["transactionHex"].as_str().unwrap(),
            &context(&ninth),
            &sig
        )
        .is_err()
    );
    std::thread::sleep(Duration::from_millis(2100));
    let h = prepare(&mut s, &owner, &ninth);
    assert!(s.approve(&h).is_ok());
    for h in handles {
        assert!(s.approve(&h).is_err());
    }
    assert!(
        s.prepare(
            v["transactionHex"].as_str().unwrap(),
            &context(&v),
            &admission(&s, &owner, &v)
        )
        .is_err()
    );
}
#[test]
fn consumed_admission_bound_requires_authenticated_context_advance() {
    let owner = SigningKey::from_bytes(&[75; 32]);
    let mut s = open(&owner, Duration::from_secs(30));
    let v = own_vector(&s);
    install(&mut s, &owner, &v, 1);
    for ttl in 37..=100 {
        let h = prepare(&mut s, &owner, &different_ttl(&v, ttl));
        assert!(s.cancel(&h));
    }
    let unused = different_ttl(&v, 36);
    assert!(
        s.prepare(
            unused["transactionHex"].as_str().unwrap(),
            &context(&unused),
            &admission(&s, &owner, &unused)
        )
        .is_err()
    );
    advance(&mut s, &owner, &v, 2);
    let h = prepare(&mut s, &owner, &unused);
    assert!(s.approve(&h).is_ok());
}
#[test]
fn authentication_is_session_epoch_generation_body_and_review_bound() {
    let owner = SigningKey::from_bytes(&[76; 32]);
    let mut a = open(&owner, Duration::from_secs(30));
    let mut b = open(&owner, Duration::from_secs(30));
    let av = own_vector(&a);
    let bv = own_vector(&b);
    let p = profile(&av);
    let pa = sign(&owner, PROFILE_DOMAIN_V3, &a.profile_statement(&p).unwrap());
    assert!(b.set_profile(p.clone(), &pa).is_err());
    install(&mut a, &owner, &av, 1);
    install(&mut b, &owner, &bv, 1);
    let hash = digest(&context(&bv));
    let ca = sign(
        &owner,
        CONTEXT_DOMAIN_V3,
        &a.context_statement(2, &hash).unwrap(),
    );
    assert!(b.set_context(2, &hash, &ca).is_err());
    let sa = admission(&a, &owner, &av);
    assert!(
        b.prepare(bv["transactionHex"].as_str().unwrap(), &context(&bv), &sa)
            .is_err()
    );
    let changed = different_ttl(&av, 99);
    assert!(
        a.prepare(
            changed["transactionHex"].as_str().unwrap(),
            &context(&changed),
            &sa
        )
        .is_err()
    );
    let i = a
        .inspect(av["transactionHex"].as_str().unwrap(), &context(&av))
        .unwrap();
    let mut forged = i.statement.clone();
    forged["reviewHash"] = json!("00".repeat(32));
    let bad = sign(&owner, ADMISSION_DOMAIN_V3, &forged);
    assert!(
        a.prepare(av["transactionHex"].as_str().unwrap(), &context(&av), &bad)
            .is_err()
    );
    let wrong_domain = sign(
        &owner,
        "castalia/cardano-fixture-admission/v2\0",
        &i.statement,
    );
    assert!(
        a.prepare(
            av["transactionHex"].as_str().unwrap(),
            &context(&av),
            &wrong_domain
        )
        .is_err()
    );
    let mut bad_context = context(&av);
    bad_context.observed_slot += 1;
    assert!(
        a.inspect(av["transactionHex"].as_str().unwrap(), &bad_context)
            .is_err()
    );
    for sig in ["".to_string(), "00".repeat(64), "ff".repeat(64)] {
        assert!(
            a.prepare(av["transactionHex"].as_str().unwrap(), &context(&av), &sig)
                .is_err()
        );
    }
    assert!(a.set_profile(p, &pa).is_err());
}
#[test]
fn malformed_network_owner_and_closed_dtos_fail_before_signing() {
    let owner = SigningKey::from_bytes(&[77; 32]);
    assert!(
        KettleFixtureSession::fresh(
            [0; 32],
            CardanoFundingNetworkV1::testnet(2, &"12".repeat(32)).unwrap()
        )
        .is_err()
    );
    assert!(
        KettleFixtureSession::fresh(
            owner.verifying_key().to_bytes(),
            CardanoFundingNetworkV1::testnet(1, &"12".repeat(32)).unwrap()
        )
        .is_err()
    );
    let v = vector();
    let mut p = v["profile"].clone();
    p["extra"] = json!(true);
    assert!(serde_json::from_value::<KettleFixtureProfile>(p).is_err());
    let mut c = v["context"].clone();
    c["extra"] = json!(true);
    assert!(serde_json::from_value::<KettleReviewContext>(c).is_err());
    let mut c = v["context"].clone();
    c["utxos"][0]["extra"] = json!(true);
    assert!(serde_json::from_value::<KettleReviewContext>(c).is_err());
}
#[test]
fn original_roles_identity_state_and_accounting_substitutions_reject() {
    let base = vector();
    for field in [
        "executionProfileDigest",
        "scriptArtifactSha256",
        "kettleScriptHash",
        "companionScriptHash",
        "deploymentId",
        "descriptorDataHex",
        "sourceContentDataHex",
    ] {
        let mut v = base.clone();
        v["profile"][field] = json!("00");
        assert!(reject(&v), "profile {field}");
    }
    let mut v = base.clone();
    v["paymentKeyHash"] = json!("79".repeat(28));
    assert!(reject(&v));
    let mut v = base.clone();
    v["context"]["acceptedAdd"]["txHash"] = json!("01".repeat(32));
    assert!(reject(&v));
    let mut v = base.clone();
    v["context"]["utxos"].as_array_mut().unwrap().swap(0, 1);
    assert!(reject(&v));
    let mut v = base.clone();
    v["context"]["observedSlot"] = json!(100);
    assert!(reject(&v));
    for field in ["afterRoot", "priorUse", "actionDigest", "controllerKeyHash"] {
        let mut v = base.clone();
        let old = base["review"][field].as_str().unwrap();
        let replacement = "00".repeat(old.len() / 2);
        replace_tx(&mut v, old, &replacement);
        assert!(reject(&v), "{field}");
    }
    let mut v = base.clone();
    replace_tx(&mut v, "1a05e38604", "1a05e38605");
    assert!(reject(&v));
    let mut v = base.clone();
    replace_tx(&mut v, "1a00e4e1c0", "1a00e4e1c1");
    assert!(reject(&v));
    let mut v = base.clone();
    replace_tx(&mut v, "5a5a5a5a", "595a5a5a");
    assert!(reject(&v));
    let mut v = base.clone();
    let tx = v["transactionHex"].as_str().unwrap().to_string();
    v["transactionHex"] = json!(tx + "00");
    assert!(reject(&v));
}

#[test]
fn shared_original_byte_variants_reject_before_admission() {
    let variants: Value =
        serde_json::from_str(include_str!("fixtures/kettle-fixture-v3-variants.json")).unwrap();
    assert_eq!(
        variants["vectorSha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "fixtures/kettle-fixture-v3.json"
        )))
    );
    for case in variants["cases"].as_array().unwrap() {
        let mut v = vector();
        let target = if case["target"] == "transactionHex" {
            &mut v["transactionHex"]
        } else {
            &mut v["context"]["utxos"][case["contextIndex"].as_u64().unwrap() as usize]["utxoCborHex"]
        };
        let mut raw = hex::decode(target.as_str().unwrap()).unwrap();
        let mut previous = usize::MAX;
        for edit in case["edits"].as_array().unwrap() {
            let offset = edit["offset"].as_u64().unwrap() as usize;
            let remove = edit["remove"].as_u64().unwrap() as usize;
            assert!(offset < previous);
            previous = offset;
            raw.splice(
                offset..offset + remove,
                hex::decode(edit["insertHex"].as_str().unwrap()).unwrap(),
            );
        }
        *target = json!(hex::encode(raw));
        let result = inspect_public_fixture(
            v["transactionHex"].as_str().unwrap(),
            &profile(&v),
            &context(&v),
            v["paymentKeyHash"].as_str().unwrap(),
        );
        let err = result.expect_err(case["name"].as_str().unwrap());
        if case["name"] == "balancedFeeBelowReferenceMinimum" {
            assert_eq!(
                err.0,
                "K3 fee omits execution, linear or actual reference-code cost"
            );
        }
    }
}

#[test]
fn separate_cli_is_closed_and_bounded_without_v2_fallback() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    fn run(input: &[u8]) -> Vec<Value> {
        let owner = SigningKey::from_bytes(&[78; 32]);
        let mut child = Command::new(env!("CARGO_BIN_EXE_castalia-kettle-funding-fixture"))
            .args([
                "--owner-verification-key",
                &hex::encode(owner.verifying_key().to_bytes()),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect()
    }
    let result=run(b"{\"command\":\"inspect\",\"transactionHex\":\"00\"}\n{\"command\":\"sign\",\"hash\":\"00\"}\n{\"command\":\"close\",\"unreviewed\":true}\n");
    assert_eq!(result.len(), 3);
    for r in result {
        assert_eq!(
            r,
            json!({"ok":false,"error":"invalid closed fixture command"})
        );
    }
    let mut oversized = vec![b' '; 262144];
    oversized.push(b'\n');
    let result = run(&oversized);
    assert_eq!(
        result,
        vec![json!({"ok":false,"error":"invalid bounded input framing"})]
    );
}
