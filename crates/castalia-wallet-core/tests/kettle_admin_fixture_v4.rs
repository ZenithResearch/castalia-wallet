#![cfg(feature = "funding-fixtures")]
//! Native-admin fixture custody only; no human consent or production bootstrap.
use castalia_wallet_core::{
    CardanoFundingNetworkV1,
    funding_fixture::kettle_admin::{AdminFixtureSession, AdminRole},
};
#[test]
fn native_admin_role_is_immutable_and_close_permanent() {
    let owner = ed25519_dalek::SigningKey::from_bytes(&[81; 32]);
    let mut s = AdminFixtureSession::fresh(
        owner.verifying_key().to_bytes(),
        CardanoFundingNetworkV1::testnet(2, &"12".repeat(32)).unwrap(),
        AdminRole::Controller,
    )
    .unwrap();
    assert_eq!(s.info().role, AdminRole::Controller);
    assert_eq!(s.info().account.payment_key_hash().len(), 56);
    assert!(s.approve("unknown").is_err());
    s.close();
    assert!(s.invalidate().is_err());
}

use castalia_wallet_core::funding_fixture::kettle_admin::{
    AdminFixtureProfile, AdminReviewContext, CONTEXT_DOMAIN_V4, PROFILE_DOMAIN_V4,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
fn owner_sign(owner: &SigningKey, domain: &str, v: &Value) -> String {
    let mut b = domain.as_bytes().to_vec();
    b.extend(serde_jcs::to_vec(v).unwrap());
    hex::encode(owner.sign(&b).to_bytes())
}
fn fresh(owner: &SigningKey, role: AdminRole) -> AdminFixtureSession {
    AdminFixtureSession::fresh(
        owner.verifying_key().to_bytes(),
        CardanoFundingNetworkV1::testnet(2, &"12".repeat(32)).unwrap(),
        role,
    )
    .unwrap()
}
#[test]
fn profile_and_observation_receipts_bind_independent_native_role_sessions() {
    let owner = SigningKey::from_bytes(&[82; 32]);
    let mut controller = fresh(&owner, AdminRole::Controller);
    let mut recovery = fresh(&owner, AdminRole::Recovery);
    let p = AdminFixtureProfile::qualified();
    let cs = controller.profile_statement(&p).unwrap();
    assert_eq!(cs["role"], "controller");
    let sig = owner_sign(&owner, PROFILE_DOMAIN_V4, &cs);
    assert!(recovery.set_profile(p.clone(), &sig).is_err());
    controller.set_profile(p.clone(), &sig).unwrap();
    let rs = recovery.profile_statement(&p).unwrap();
    recovery
        .set_profile(p.clone(), &owner_sign(&owner, PROFILE_DOMAIN_V4, &rs))
        .unwrap();
    let context_digest = "01".repeat(32);
    let cs = controller.context_statement(1, &context_digest).unwrap();
    let sig = owner_sign(&owner, CONTEXT_DOMAIN_V4, &cs);
    assert!(recovery.set_context(1, &context_digest, &sig).is_err());
    controller.set_context(1, &context_digest, &sig).unwrap();
    assert!(controller.set_context(1, &context_digest, &sig).is_err());
    let mut copied = controller.info();
    copied.role = AdminRole::Recovery;
    assert_eq!(controller.info().role, AdminRole::Controller);
    assert!(controller.set_profile(p, &"00".repeat(64)).is_err());
}
#[test]
fn admin_profile_and_history_closed_shapes_reject_legacy_or_extras() {
    let mut p = serde_json::to_value(AdminFixtureProfile::qualified()).unwrap();
    p["extra"] = json!(true);
    assert!(serde_json::from_value::<AdminFixtureProfile>(p).is_err());
    assert!(serde_json::from_value::<AdminRole>(json!("controllerAndPayer")).is_err());
    let mut ctx = json!({"schema":"castalia.cardano-fixture-review-context.v4","observedSlot":10,"history":{"kind":"fixtureGenesis","stateRef":{"txHash":"11".repeat(32),"outputIndex":0}},"utxos":[]});
    ctx["history"]["unreviewed"] = json!(true);
    assert!(serde_json::from_value::<AdminReviewContext>(ctx).is_err());
    let owner = SigningKey::from_bytes(&[83; 32]);
    let mut s = fresh(&owner, AdminRole::FeePayer);
    let mut p = AdminFixtureProfile::qualified();
    p.schema = "castalia.cardano-fixture-execution-profile.v3".into();
    assert!(s.profile_statement(&p).is_err());
    p = AdminFixtureProfile::qualified();
    p.companion_script_hash = "00".repeat(28);
    assert!(s.set_profile(p, &"00".repeat(64)).is_err());
}
#[test]
fn admin_cli_requires_immutable_open_role_and_rejects_unknown_commands() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let owner = SigningKey::from_bytes(&[84; 32]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_castalia-kettle-admin-fixture"))
        .args([
            "--owner-verification-key",
            &hex::encode(owner.verifying_key().to_bytes()),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"{\"command\":\"open\",\"networkJson\":\"{}\"}\n{\"command\":\"close\",\"extra\":true}\n{\"command\":\"setRole\",\"role\":\"recovery\"}\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let lines = String::from_utf8(output.stdout).unwrap();
    let values = lines
        .lines()
        .map(|s| serde_json::from_str::<Value>(s).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(values.len(), 3);
    assert!(
        values
            .iter()
            .all(|v| v == &json!({"ok":false,"error":"invalid closed fixture command"}))
    );
}

use castalia_wallet_core::funding_fixture::kettle_admin::inspect_public_fixture;
use sha2::{Digest, Sha256};
fn vector() -> Value {
    serde_json::from_str(include_str!("fixtures/kettle-admin-fixture-v4.json")).unwrap()
}
fn digest(v: &impl serde::Serialize) -> String {
    hex::encode(Sha256::digest(serde_jcs::to_vec(v).unwrap()))
}
#[test]
fn exact_original_vectors_match_all_five_independent_role_reviews() {
    let v = vector();
    let profile: AdminFixtureProfile = serde_json::from_value(v["profile"].clone()).unwrap();
    assert_eq!(profile, AdminFixtureProfile::qualified());
    for (kind, role, key_field, index) in [
        ("add", AdminRole::Controller, "controllerKeyHash", None),
        ("add", AdminRole::FeePayer, "feePayerKeyHash", None),
        (
            "disable",
            AdminRole::Recovery,
            "authoritySignerKeyHashes",
            Some(0),
        ),
        (
            "disable",
            AdminRole::Recovery,
            "authoritySignerKeyHashes",
            Some(1),
        ),
        ("disable", AdminRole::FeePayer, "feePayerKeyHash", None),
    ] {
        let part = &v[kind];
        let ctx: AdminReviewContext = serde_json::from_value(part["context"].clone()).unwrap();
        let key = if let Some(i) = index {
            part["common"][key_field][i].as_str().unwrap()
        } else {
            part["common"][key_field].as_str().unwrap()
        };
        let result = inspect_public_fixture(
            part["transactionHex"].as_str().unwrap(),
            &profile,
            &ctx,
            key,
            role,
        )
        .unwrap();
        assert_eq!(result["common"], part["common"], "{kind} {role:?}");
        assert_eq!(result["commonReviewHash"], digest(&part["common"]));
        assert_eq!(
            result["participation"],
            json!({"paymentKeyHash":key,"role":role})
        );
    }
}

use castalia_wallet_core::funding_fixture::kettle_admin::ADMISSION_DOMAIN_V4;
use ed25519_dalek::{Signature, VerifyingKey};
use std::time::Duration;
fn typed_context(v: &Value) -> AdminReviewContext {
    serde_json::from_value(v["context"].clone()).unwrap()
}
fn set_observation(s: &mut AdminFixtureSession, owner: &SigningKey, v: &Value, generation: u64) {
    let d = digest(&typed_context(v));
    let statement = s.context_statement(generation, &d).unwrap();
    s.set_context(
        generation,
        &d,
        &owner_sign(owner, CONTEXT_DOMAIN_V4, &statement),
    )
    .unwrap();
}
fn install(s: &mut AdminFixtureSession, owner: &SigningKey, v: &Value) {
    let p = AdminFixtureProfile::qualified();
    let statement = s.profile_statement(&p).unwrap();
    s.set_profile(p, &owner_sign(owner, PROFILE_DOMAIN_V4, &statement))
        .unwrap();
    set_observation(s, owner, v, 1);
}
fn sig(s: &AdminFixtureSession, owner: &SigningKey, v: &Value) -> String {
    let inspected = s
        .inspect(v["transactionHex"].as_str().unwrap(), &typed_context(v))
        .unwrap();
    owner_sign(owner, ADMISSION_DOMAIN_V4, &inspected.statement)
}
fn prepared(s: &mut AdminFixtureSession, owner: &SigningKey, v: &Value) -> String {
    let signature = sig(s, owner, v);
    s.prepare(
        v["transactionHex"].as_str().unwrap(),
        &typed_context(v),
        &signature,
    )
    .unwrap()
    .handle
}
// Public parser/custody unit rebinding only, not a new ledger-settlement claim.
// Real integration independently builds, preflights and settles its own body.
fn rebind(kind: &str, pairs: &[(&str, String)]) -> Value {
    let all = vector();
    let mut v = all[kind].clone();
    let mut required = v["common"]["requiredSignerKeyHashes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    for (old, new) in pairs {
        let tx = v["transactionHex"].as_str().unwrap();
        assert!(tx.contains(old));
        v["transactionHex"] = json!(tx.replace(old, new));
        for u in v["context"]["utxos"].as_array_mut().unwrap() {
            if u["role"] != "reference" {
                u["utxoCborHex"] = json!(u["utxoCborHex"].as_str().unwrap().replace(old, new));
            }
        }
        for k in &mut required {
            if k == old {
                *k = new.clone();
            }
        }
    }
    let set_hex = |keys: &[String]| {
        format!(
            "d90102{:02x}{}",
            0x80 + keys.len(),
            keys.iter().map(|k| format!("581c{k}")).collect::<String>()
        )
    };
    let before = set_hex(&required);
    required.sort();
    let after = set_hex(&required);
    let tx = v["transactionHex"].as_str().unwrap();
    assert_eq!(tx.matches(&before).count(), 1);
    v["transactionHex"] = json!(tx.replace(&before, &after));
    v
}
fn check_witness(
    s: &AdminFixtureSession,
    w: &castalia_wallet_core::funding_fixture::FixtureWitness,
    body: &str,
) {
    assert_eq!(w.label, "synthetic-fixture-approval-only");
    assert_eq!(w.transaction_body_hash, body);
    let public: [u8; 32] = hex::decode(&w.public_key).unwrap().try_into().unwrap();
    let signature = Signature::from_slice(&hex::decode(&w.signature).unwrap()).unwrap();
    VerifyingKey::from_bytes(&public)
        .unwrap()
        .verify_strict(&hex::decode(body).unwrap(), &signature)
        .unwrap();
    use blake2::{
        Blake2bVar,
        digest::{Update, VariableOutput},
    };
    let mut h = Blake2bVar::new(28).unwrap();
    h.update(&public);
    let mut hash = [0; 28];
    h.finalize_variable(&mut hash).unwrap();
    assert_eq!(hex::encode(hash), s.info().account.payment_key_hash());
}
#[test]
fn independent_two_and_three_native_sessions_review_one_body_and_sign_own_roles() {
    let owner = SigningKey::from_bytes(&[85; 32]);
    let all = vector();
    for kind in ["add", "disable"] {
        let roles = if kind == "add" {
            vec![AdminRole::Controller, AdminRole::FeePayer]
        } else {
            vec![
                AdminRole::Recovery,
                AdminRole::Recovery,
                AdminRole::FeePayer,
            ]
        };
        let mut sessions = roles.iter().map(|r| fresh(&owner, *r)).collect::<Vec<_>>();
        let common = &all[kind]["common"];
        let mut old = if kind == "add" {
            vec![common["controllerKeyHash"].as_str().unwrap()]
        } else {
            common["authoritySignerKeyHashes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap())
                .collect()
        };
        old.push(common["feePayerKeyHash"].as_str().unwrap());
        let pairs = old
            .iter()
            .zip(&sessions)
            .map(|(k, s)| (*k, s.info().account.payment_key_hash().to_owned()))
            .collect::<Vec<_>>();
        let v = rebind(kind, &pairs);
        for s in &mut sessions {
            install(s, &owner, &v);
        }
        let inspections = sessions
            .iter()
            .map(|s| {
                s.inspect(v["transactionHex"].as_str().unwrap(), &typed_context(&v))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for i in &inspections {
            assert_eq!(i.review["common"], inspections[0].review["common"]);
            assert_eq!(
                i.review["commonReviewHash"],
                inspections[0].review["commonReviewHash"]
            );
            assert_eq!(
                i.statement["contextDigest"],
                inspections[0].statement["contextDigest"]
            );
        }
        let wrong_receipt = owner_sign(&owner, ADMISSION_DOMAIN_V4, &inspections[0].statement);
        assert!(
            sessions[1]
                .prepare(
                    v["transactionHex"].as_str().unwrap(),
                    &typed_context(&v),
                    &wrong_receipt
                )
                .is_err()
        );
        let handles = sessions
            .iter_mut()
            .map(|s| prepared(s, &owner, &v))
            .collect::<Vec<_>>();
        assert!(sessions[1].approve(&handles[0]).is_err());
        let body = inspections[0].statement["transactionBodyHash"]
            .as_str()
            .unwrap();
        let mut public = std::collections::BTreeSet::new();
        for (s, h) in sessions.iter_mut().zip(handles) {
            let witness = s.approve(&h).unwrap();
            check_witness(s, &witness, body);
            assert!(public.insert(witness.public_key));
            assert!(s.approve(&h).is_err());
        }
        assert_eq!(public.len(), roles.len());
    }
}
fn sole_payer(owner: &SigningKey, ttl: Duration) -> (AdminFixtureSession, Value) {
    let s = AdminFixtureSession::fresh_with_ttl(
        owner.verifying_key().to_bytes(),
        CardanoFundingNetworkV1::testnet(2, &"12".repeat(32)).unwrap(),
        AdminRole::FeePayer,
        ttl,
    )
    .unwrap();
    let v = vector();
    let old = v["add"]["common"]["feePayerKeyHash"].as_str().unwrap();
    let own = s.info().account.payment_key_hash().to_owned();
    let part = rebind("add", &[(old, own)]);
    (s, part)
}
fn ttl(v: &Value, expiry: u8) -> Value {
    let mut v = v.clone();
    let tx = v["transactionHex"].as_str().unwrap();
    assert_eq!(tx.matches("031864").count(), 1);
    v["transactionHex"] = json!(tx.replace("031864", &format!("0318{expiry:02x}")));
    v
}
#[test]
fn admin_cancel_expiry_body_domain_generation_and_close_revoke_handles() {
    let owner = SigningKey::from_bytes(&[86; 32]);
    let (mut s, v) = sole_payer(&owner, Duration::from_millis(30));
    install(&mut s, &owner, &v);
    let original = sig(&s, &owner, &v);
    let handle = prepared(&mut s, &owner, &v);
    assert!(s.cancel(&handle));
    assert!(s.approve(&handle).is_err());
    assert!(
        s.prepare(
            v["transactionHex"].as_str().unwrap(),
            &typed_context(&v),
            &original
        )
        .is_err()
    );
    set_observation(&mut s, &owner, &v, 2);
    let handle = prepared(&mut s, &owner, &v);
    std::thread::sleep(Duration::from_millis(45));
    assert!(s.approve(&handle).is_err());
    assert!(
        s.prepare(
            v["transactionHex"].as_str().unwrap(),
            &typed_context(&v),
            &sig(&s, &owner, &v)
        )
        .is_err()
    );
    set_observation(&mut s, &owner, &v, 3);
    let inspected = s
        .inspect(v["transactionHex"].as_str().unwrap(), &typed_context(&v))
        .unwrap();
    let changed = ttl(&v, 99);
    let old = owner_sign(&owner, ADMISSION_DOMAIN_V4, &inspected.statement);
    assert!(
        s.prepare(
            changed["transactionHex"].as_str().unwrap(),
            &typed_context(&changed),
            &old
        )
        .is_err()
    );
    let mut role_forged = inspected.statement.clone();
    role_forged["role"] = json!("controller");
    assert!(
        s.prepare(
            v["transactionHex"].as_str().unwrap(),
            &typed_context(&v),
            &owner_sign(&owner, ADMISSION_DOMAIN_V4, &role_forged)
        )
        .is_err()
    );
    let wrong_domain = owner_sign(
        &owner,
        "castalia/cardano-fixture-admission/v3\0",
        &inspected.statement,
    );
    assert!(
        s.prepare(
            v["transactionHex"].as_str().unwrap(),
            &typed_context(&v),
            &wrong_domain
        )
        .is_err()
    );
    let h = prepared(&mut s, &owner, &v);
    set_observation(&mut s, &owner, &v, 4);
    assert!(s.approve(&h).is_err());
    assert!(
        s.prepare(
            v["transactionHex"].as_str().unwrap(),
            &typed_context(&v),
            &old
        )
        .is_err()
    );
    let h = prepared(&mut s, &owner, &v);
    s.invalidate().unwrap();
    assert!(s.approve(&h).is_err());
    set_observation(&mut s, &owner, &v, 1);
    let h = prepared(&mut s, &owner, &v);
    s.close();
    assert!(s.approve(&h).is_err());
}
#[test]
fn admin_expired_queue_and_consumed_capacity_do_not_silently_reauthorize() {
    let owner = SigningKey::from_bytes(&[87; 32]);
    let (mut s, v) = sole_payer(&owner, Duration::from_secs(2));
    install(&mut s, &owner, &v);
    let mut handles = vec![];
    for n in 93..=100 {
        handles.push(prepared(&mut s, &owner, &ttl(&v, n)));
    }
    let ninth = ttl(&v, 92);
    assert!(
        s.prepare(
            ninth["transactionHex"].as_str().unwrap(),
            &typed_context(&ninth),
            &sig(&s, &owner, &ninth)
        )
        .is_err()
    );
    std::thread::sleep(Duration::from_millis(2100));
    let h = prepared(&mut s, &owner, &ninth);
    assert!(s.approve(&h).is_ok());
    for h in handles {
        assert!(s.approve(&h).is_err());
    }
    assert!(
        s.prepare(
            v["transactionHex"].as_str().unwrap(),
            &typed_context(&v),
            &sig(&s, &owner, &v)
        )
        .is_err()
    );
    set_observation(&mut s, &owner, &v, 2);
    for n in 37..=100 {
        let h = prepared(&mut s, &owner, &ttl(&v, n));
        assert!(s.cancel(&h));
    }
    let next = ttl(&v, 36);
    assert!(
        s.prepare(
            next["transactionHex"].as_str().unwrap(),
            &typed_context(&next),
            &sig(&s, &owner, &next)
        )
        .is_err()
    );
    set_observation(&mut s, &owner, &v, 3);
    let h = prepared(&mut s, &owner, &next);
    assert!(s.approve(&h).is_ok());
}

fn inspect_part(
    part: &Value,
    role: AdminRole,
    key: &str,
) -> Result<Value, castalia_wallet_core::funding_fixture::FixtureError> {
    inspect_public_fixture(
        part["transactionHex"].as_str().unwrap(),
        &AdminFixtureProfile::qualified(),
        &typed_context(part),
        key,
        role,
    )
}
fn payer_rejects(part: &Value) -> bool {
    inspect_part(
        part,
        AdminRole::FeePayer,
        part["common"]["feePayerKeyHash"].as_str().unwrap(),
    )
    .is_err()
}
fn replace_tx(part: &mut Value, old: &str, new: &str) {
    let tx = part["transactionHex"].as_str().unwrap();
    assert!(tx.contains(old));
    part["transactionHex"] = json!(tx.replace(old, new));
}
fn replace_required(part: &mut Value, keys: &[String]) {
    let old = part["common"]["requiredSignerKeyHashes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let encode = |ks: &[String]| {
        format!(
            "d90102{:02x}{}",
            0x80 + ks.len(),
            ks.iter().map(|k| format!("581c{k}")).collect::<String>()
        )
    };
    replace_tx(part, &encode(&old), &encode(keys));
}
#[test]
fn shared_original_admin_byte_variants_reject_in_matching_categories() {
    let variants: Value = serde_json::from_str(include_str!(
        "fixtures/kettle-admin-fixture-v4-variants.json"
    ))
    .unwrap();
    assert_eq!(
        variants["vectorSha256"],
        hex::encode(Sha256::digest(include_bytes!(
            "fixtures/kettle-admin-fixture-v4.json"
        )))
    );
    let all = vector();
    for case in variants["cases"].as_array().unwrap() {
        let mut p = all[case["action"].as_str().unwrap()].clone();
        let target = if case["target"] == "transactionHex" {
            &mut p["transactionHex"]
        } else {
            &mut p["context"]["utxos"][case["contextIndex"].as_u64().unwrap() as usize]["utxoCborHex"]
        };
        let mut raw = hex::decode(target.as_str().unwrap()).unwrap();
        let mut previous = usize::MAX;
        for e in case["edits"].as_array().unwrap() {
            let at = e["offset"].as_u64().unwrap() as usize;
            assert!(at < previous);
            previous = at;
            raw.splice(
                at..at + e["remove"].as_u64().unwrap() as usize,
                hex::decode(e["insertHex"].as_str().unwrap()).unwrap(),
            );
        }
        *target = json!(hex::encode(raw));
        let err = inspect_part(
            &p,
            AdminRole::FeePayer,
            p["common"]["feePayerKeyHash"].as_str().unwrap(),
        )
        .expect_err(case["name"].as_str().unwrap());
        if case["name"].as_str().unwrap().contains("Underprices") {
            assert_eq!(err.0, "admin fee below exact projected/reference minimum");
        }
    }
}
#[test]
fn native_role_and_current_required_signer_sets_cannot_substitute_quorum() {
    let all = vector();
    let add = &all["add"];
    let disable = &all["disable"];
    let controller = disable["common"]["controllerKeyHash"].as_str().unwrap();
    let payer = disable["common"]["feePayerKeyHash"].as_str().unwrap();
    let r1 = disable["common"]["authoritySignerKeyHashes"][0]
        .as_str()
        .unwrap();
    let r2 = disable["common"]["authoritySignerKeyHashes"][1]
        .as_str()
        .unwrap();
    assert!(inspect_part(add, AdminRole::Recovery, controller).is_err());
    assert!(inspect_part(add, AdminRole::Controller, payer).is_err());
    assert!(inspect_part(disable, AdminRole::Controller, controller).is_err());
    assert!(inspect_part(disable, AdminRole::Recovery, payer).is_err());
    assert!(inspect_part(disable, AdminRole::Recovery, &"99".repeat(28)).is_err());
    // These are absent/duplicate/outsider/current-controller substitutions, not an
    // asserted outgoing quorum after a roster transition that was never executed.
    for mut keys in [
        vec![r1.to_string(), payer.to_string()],
        vec![r1.to_string(), r1.to_string(), payer.to_string()],
        vec![r1.to_string(), "99".repeat(28), payer.to_string()],
        vec![r2.to_string(), controller.to_string(), payer.to_string()],
    ] {
        keys.sort();
        let mut p = disable.clone();
        replace_required(&mut p, &keys);
        assert!(payer_rejects(&p));
    }
    let mut p = add.clone();
    let mut keys = vec![r1.to_string(), payer.to_string()];
    keys.sort();
    replace_required(&mut p, &keys);
    assert!(payer_rejects(&p));
}
#[test]
fn current_history_state_accounting_and_registry_mutations_reject() {
    let all = vector();
    let mut p = all["add"].clone();
    p["context"]["history"]["stateRef"]["txHash"] = json!("22".repeat(32));
    assert!(payer_rejects(&p));
    let mut p = all["disable"].clone();
    p["context"]["history"]["acceptedAddRef"] = p["context"]["history"]["acceptedPourRef"].clone();
    assert!(payer_rejects(&p));
    for kind in ["add", "disable"] {
        let base = &all[kind];
        let mut p = base.clone();
        p["context"]["utxos"].as_array_mut().unwrap().swap(0, 1);
        assert!(payer_rejects(&p));
        let mut p = base.clone();
        p["context"]["observedSlot"] = json!(100);
        assert!(payer_rejects(&p));
        for field in ["afterRoot", "controllerKeyHash"] {
            let mut p = base.clone();
            let old = base["common"][field].as_str().unwrap();
            replace_tx(&mut p, old, &"00".repeat(old.len() / 2));
            assert!(payer_rejects(&p));
        }
        let mut p = base.clone();
        let next = base["common"]["nextStateDatumHex"].as_str().unwrap();
        let corrupt = next.replace("1a004c4b40", "1a004c4b41");
        assert_ne!(next, corrupt);
        replace_tx(&mut p, next, &corrupt);
        assert!(payer_rejects(&p));
        let mut p = base.clone();
        let coin = base["common"]["payerChangeLovelace"]
            .as_str()
            .unwrap()
            .parse::<u32>()
            .unwrap();
        replace_tx(
            &mut p,
            &format!("1a{coin:08x}"),
            &format!("1a{:08x}", coin + 1),
        );
        assert!(payer_rejects(&p));
        let mut p = base.clone();
        let coin = base["common"]["collateralReturnLovelace"]
            .as_str()
            .unwrap()
            .parse::<u32>()
            .unwrap();
        replace_tx(
            &mut p,
            &format!("1a{coin:08x}"),
            &format!("1a{:08x}", coin + 1),
        );
        assert!(payer_rejects(&p));
    }
    let mut p = all["disable"].clone();
    let prior = p["common"]["priorRecordDataHex"]
        .as_str()
        .unwrap()
        .to_owned();
    let reset = prior.replace("1a004c4b40", "00");
    assert_ne!(prior, reset);
    replace_tx(&mut p, &prior, &reset);
    p["context"]["history"]["priorRecordDataHex"] = json!(reset);
    let err = inspect_part(
        &p,
        AdminRole::FeePayer,
        p["common"]["feePayerKeyHash"].as_str().unwrap(),
    )
    .unwrap_err();
    assert_eq!(err.0, "admin authenticated prior membership");
    let mut p = all["disable"].clone();
    let prior = p["common"]["priorRecordDataHex"]
        .as_str()
        .unwrap()
        .to_owned();
    let reset = prior.replace(
        p["common"]["priorUse"].as_str().unwrap(),
        all["add"]["common"]["nextUse"].as_str().unwrap(),
    );
    replace_tx(&mut p, &prior, &reset);
    p["context"]["history"]["priorRecordDataHex"] = json!(reset);
    assert!(payer_rejects(&p));
}
