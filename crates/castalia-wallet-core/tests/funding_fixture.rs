#![cfg(feature = "funding-fixtures")]
use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use castalia_wallet_core::{
    CardanoFundingNetworkV1,
    funding_fixture::{
        ADMISSION_DOMAIN, CONTEXT_DOMAIN, FixtureProfile, FundingFixtureSession, PROFILE_DOMAIN,
        fixture_transcript,
    },
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};
fn head(major: u8, n: u64) -> Vec<u8> {
    if n < 24 {
        vec![major * 32 + n as u8]
    } else if n <= 255 {
        vec![major * 32 + 24, n as u8]
    } else if n <= 65535 {
        let mut v = vec![major * 32 + 25];
        v.extend((n as u16).to_be_bytes());
        v
    } else {
        let mut v = vec![major * 32 + 26];
        v.extend((n as u32).to_be_bytes());
        v
    }
}
fn bytes(b: &[u8]) -> Vec<u8> {
    let mut v = head(2, b.len() as u64);
    v.extend(b);
    v
}
fn array(items: Vec<Vec<u8>>) -> Vec<u8> {
    let mut v = head(4, items.len() as u64);
    for i in items {
        v.extend(i);
    }
    v
}
fn map(items: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
    let mut v = head(5, items.len() as u64);
    for (k, value) in items {
        v.extend(head(0, k));
        v.extend(value);
    }
    v
}
fn script_hash() -> String {
    let mut out = [0; 28];
    let mut h = Blake2bVar::new(28).unwrap();
    h.update(&[3, 1, 2, 3]);
    h.finalize_variable(&mut out).unwrap();
    hex::encode(out)
}
fn profile() -> FixtureProfile {
    FixtureProfile {
        schema: "castalia.cardano-fixture-execution-profile.v1".into(),
        backend: "scalus-1.4.1".into(),
        execution_profile_digest: "11".repeat(32),
        allowed_script_hashes: vec![script_hash()],
        allowed_scripts: vec![],
    }
}
fn signature(owner: &SigningKey, domain: &str, statement: &Value) -> String {
    hex::encode(
        owner
            .sign(&fixture_transcript(domain, statement).unwrap())
            .to_bytes(),
    )
}
fn new_session(owner: &SigningKey, ttl: Duration) -> FundingFixtureSession {
    let network = CardanoFundingNetworkV1::testnet(42, &"22".repeat(32)).unwrap();
    FundingFixtureSession::fresh_with_ttl(owner.verifying_key().to_bytes(), network, ttl).unwrap()
}
fn install(s: &mut FundingFixtureSession, owner: &SigningKey) {
    let p = profile();
    let statement = s.profile_statement(&p).unwrap();
    s.set_profile(p, &signature(owner, PROFILE_DOMAIN, &statement))
        .unwrap();
    context(s, owner, 0);
}
fn context(s: &mut FundingFixtureSession, owner: &SigningKey, n: u64) {
    let statement = s.context_statement(n, &"33".repeat(32)).unwrap();
    s.set_context(
        n,
        &"33".repeat(32),
        &signature(owner, CONTEXT_DOMAIN, &statement),
    )
    .unwrap();
}
// Deliberately structural CBOR unit vectors, NOT valid scripts or ledger-admission evidence.
// Trusted owner semantics are qualified by the separate independent validating-backend suite.
fn transaction(s: &FundingFixtureSession, mutation: &str) -> String {
    let payment = hex::decode(s.info().account.payment_key_hash()).unwrap();
    let mut address = vec![if mutation == "address-mainnet" {
        0x61
    } else {
        0x60
    }];
    address.extend(&payment);
    let input = array(vec![bytes(&[0xaa; 32]), head(0, 0)]);
    let inputset = if mutation == "duplicate-reference" {
        array(vec![input, array(vec![bytes(&[0xaa; 32]), vec![0x18, 0]])])
    } else {
        array(vec![input])
    };
    let outputs = if mutation == "inline-datum" || mutation == "malformed-tag24" {
        let mut tagged = vec![0xd8, 24];
        tagged.extend(if mutation == "inline-datum" {
            bytes(&[0xd8, 121, 0x80])
        } else {
            head(0, 1)
        });
        array(vec![map(vec![
            (0, bytes(&address)),
            (1, head(0, 5_000_000)),
            (2, array(vec![head(0, 1), tagged])),
        ])])
    } else {
        array(vec![array(vec![bytes(&address), head(0, 5_000_000)])])
    };
    let signer = if mutation == "signer" {
        vec![1u8; 28]
    } else {
        payment
    };
    let mut fields = vec![
        (0, inputset),
        (1, outputs),
        (
            2,
            head(
                0,
                mutation
                    .strip_prefix("fee-")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(200_000),
            ),
        ),
        (11, bytes(&[0x44; 32])),
        (14, array(vec![bytes(&signer)])),
        (
            15,
            head(0, if mutation == "network-mainnet" { 1 } else { 0 }),
        ),
    ];
    if mutation == "nonminimal" {
        fields[2].1 = vec![0x1b, 0, 0, 0, 0, 0, 3, 0x0d, 0x40];
    }
    if mutation == "withdrawal" {
        fields.push((5, vec![0xa0]));
    }
    if mutation == "duplicate" {
        fields.push((0, array(vec![])));
    }
    if mutation == "nonminimal-duplicate" {
        fields.push((24, head(0, 0)));
    } // Separate case below constructs key alias.
    let mut mint = vec![0xa1];
    mint.extend(bytes(&hex::decode(script_hash()).unwrap()));
    mint.push(0xa1);
    mint.extend(bytes(b"TEAPOT_STATE_V1"));
    mint.push(1);
    fields.push((9, mint));
    let mut body = map(fields);
    if mutation == "nonminimal-key-duplicate" {
        // map has 7 entries; add duplicate key 0 using a nonminimal integer encoding.
        body[0] += 1;
        body.extend([0x18, 0]);
        body.extend(array(vec![]));
    }
    let data = if mutation == "unknown-action" {
        vec![0xd8, 0x7c, 0x80]
    } else {
        vec![0xd8, 0x79, 0x80]
    };
    let redeemer = array(vec![
        head(0, 1),
        head(0, 0),
        data,
        array(vec![head(0, 1000), head(0, 1000)]),
    ]);
    let redeemers = if mutation == "multiple-restore" {
        let data = array(vec![bytes(&[2; 28]), head(0, 0)]);
        let mut constructor = vec![0xd8, 121];
        constructor.extend(data);
        array(vec![
            array(vec![
                head(0, 0),
                head(0, 0),
                constructor.clone(),
                array(vec![head(0, 1000), head(0, 1000)]),
            ]),
            array(vec![
                head(0, 0),
                head(0, 1),
                constructor,
                array(vec![head(0, 1000), head(0, 1000)]),
            ]),
        ])
    } else {
        array(vec![redeemer])
    };
    let witness = map(vec![(5, redeemers), (7, array(vec![bytes(&[1, 2, 3])]))]);
    let mut encoded = array(vec![
        body,
        witness,
        if mutation == "float-validity" {
            vec![0xfb, 0, 0, 0, 0, 0, 0, 0, 21]
        } else {
            vec![if mutation == "invalid-flag" {
                0xf4
            } else {
                0xf5
            }]
        },
        vec![0xf6],
    ]);
    if mutation == "trailing" {
        encoded.push(0);
    }
    hex::encode(encoded)
}
fn prepare(s: &mut FundingFixtureSession, owner: &SigningKey, tx: &str) -> String {
    let inspection = s.inspect(tx).unwrap();
    s.prepare(
        tx,
        &signature(owner, ADMISSION_DOMAIN, &inspection.statement),
    )
    .unwrap()
    .handle
}
#[test]
fn fresh_fixture_is_distinct_and_exposes_only_public_account() {
    let owner = SigningKey::generate(&mut OsRng);
    let a = new_session(&owner, Duration::from_secs(30));
    let b = new_session(&owner, Duration::from_secs(30));
    assert_ne!(a.info().session_id, b.info().session_id);
    assert_ne!(
        a.info().account.payment_key_hash(),
        b.info().account.payment_key_hash()
    );
    let text = serde_json::to_string(a.info()).unwrap();
    assert!(!text.contains("privateKey"));
    assert!(!text.contains("seed"));
    assert!(!text.contains("passphrase"));
}
#[test]
fn actual_derived_payment_witness_verifies_and_handle_is_single_use() {
    let owner = SigningKey::generate(&mut OsRng);
    let mut s = new_session(&owner, Duration::from_secs(30));
    install(&mut s, &owner);
    let tx = transaction(&s, "valid");
    let inspection = s.inspect(&tx).unwrap();
    assert_eq!(inspection.review.kind, "teapot-bootstrap");
    assert_eq!(inspection.review.redeemer_data_hex, "d87980");
    let handle = prepare(&mut s, &owner, &tx);
    let witness = s.approve(&handle).unwrap();
    assert_eq!(witness.label, "synthetic-fixture-approval-only");
    assert_eq!(witness.public_key, s.info().account.payment_public_key());
    let key = VerifyingKey::from_bytes(
        &hex::decode(&witness.public_key)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let sig = Signature::from_slice(&hex::decode(&witness.signature).unwrap()).unwrap();
    key.verify_strict(&hex::decode(&witness.transaction_body_hash).unwrap(), &sig)
        .unwrap();
    assert_eq!(
        witness.transaction_body_hash,
        inspection.statement["transactionBodyHash"]
    );
    assert!(s.approve(&handle).is_err());
}
#[test]
fn untrusted_owner_wrong_body_and_review_substitution_cannot_prepare() {
    let owner = SigningKey::generate(&mut OsRng);
    let outsider = SigningKey::generate(&mut OsRng);
    let mut s = new_session(&owner, Duration::from_secs(30));
    install(&mut s, &owner);
    let tx = transaction(&s, "valid");
    let i = s.inspect(&tx).unwrap();
    assert!(
        s.prepare(&tx, &signature(&outsider, ADMISSION_DOMAIN, &i.statement))
            .is_err()
    );
    let mut changed = i.statement.clone();
    changed["reviewHash"] = json!("00".repeat(32));
    assert!(
        s.prepare(&tx, &signature(&owner, ADMISSION_DOMAIN, &changed))
            .is_err()
    );
    let mut changed = i.statement.clone();
    changed["transactionBodyHash"] = json!("00".repeat(32));
    assert!(
        s.prepare(&tx, &signature(&owner, ADMISSION_DOMAIN, &changed))
            .is_err()
    );
    assert!(
        s.prepare(
            &transaction(&s, "nonminimal"),
            &signature(&owner, ADMISSION_DOMAIN, &i.statement)
        )
        .is_err()
    );
    assert!(s.approve(&"00".repeat(32)).is_err());
}
#[test]
fn denies_malformed_duplicate_unsupported_and_nonfunding_transactions_without_witness() {
    let owner = SigningKey::generate(&mut OsRng);
    let mut s = new_session(&owner, Duration::from_secs(30));
    install(&mut s, &owner);
    for mode in [
        "address-mainnet",
        "network-mainnet",
        "signer",
        "withdrawal",
        "duplicate",
        "duplicate-reference",
        "nonminimal-key-duplicate",
        "unknown-action",
        "invalid-flag",
        "float-validity",
        "trailing",
    ] {
        assert!(s.inspect(&transaction(&s, mode)).is_err(), "{mode}");
    }
    for raw in [
        "",
        "00",
        "84a0a0f5f6",
        "ff",
        "zz",
        "a".repeat(65538).as_str(),
    ] {
        assert!(s.inspect(raw).is_err());
    }
}
#[test]
fn original_nonminimal_body_bytes_are_bound_not_canonicalized() {
    let owner = SigningKey::generate(&mut OsRng);
    let mut s = new_session(&owner, Duration::from_secs(30));
    install(&mut s, &owner);
    let normal = transaction(&s, "valid");
    let nonminimal = transaction(&s, "nonminimal");
    let a = s.inspect(&normal).unwrap();
    let b = s.inspect(&nonminimal).unwrap();
    assert_ne!(
        a.statement["transactionBodyHash"],
        b.statement["transactionBodyHash"]
    );
    let handle = prepare(&mut s, &owner, &nonminimal);
    assert_eq!(
        s.approve(&handle).unwrap().transaction_body_hash,
        b.statement["transactionBodyHash"]
    );
}
#[test]
fn profile_is_pinned_once_and_context_updates_and_epoch_invalidation_remove_handles() {
    let owner = SigningKey::generate(&mut OsRng);
    let mut s = new_session(&owner, Duration::from_secs(30));
    install(&mut s, &owner);
    let p = profile();
    let statement = s.profile_statement(&p).unwrap();
    assert!(
        s.set_profile(p, &signature(&owner, PROFILE_DOMAIN, &statement))
            .is_err()
    );
    let tx = transaction(&s, "valid");
    let handle = prepare(&mut s, &owner, &tx);
    context(&mut s, &owner, 1);
    assert!(s.approve(&handle).is_err());
    let i = s.inspect(&tx).unwrap();
    let handle = prepare(&mut s, &owner, &tx);
    s.invalidate().unwrap();
    assert!(s.approve(&handle).is_err());
    assert!(s.inspect(&tx).is_err());
    context(&mut s, &owner, 2);
    assert!(
        s.prepare(&tx, &signature(&owner, ADMISSION_DOMAIN, &i.statement))
            .is_err()
    );
    let handle = prepare(&mut s, &owner, &tx);
    s.close();
    assert!(s.approve(&handle).is_err());
    assert!(s.inspect(&tx).is_err());
}
#[test]
fn cancellation_expiry_and_cross_session_handle_reuse_reject() {
    let owner = SigningKey::generate(&mut OsRng);
    let mut s = new_session(&owner, Duration::from_millis(1));
    install(&mut s, &owner);
    let tx = transaction(&s, "valid");
    let handle = prepare(&mut s, &owner, &tx);
    std::thread::sleep(Duration::from_millis(3));
    assert!(s.approve(&handle).is_err());
    assert!(s.approve(&handle).is_err());
    let mut b = new_session(&owner, Duration::from_secs(30));
    install(&mut b, &owner);
    let tx = transaction(&b, "valid");
    let handle = prepare(&mut b, &owner, &tx);
    assert!(s.approve(&handle).is_err());
    assert!(b.cancel(&handle));
    assert!(!b.cancel(&handle));
    assert!(b.approve(&handle).is_err());
}
#[test]
fn denies_profile_context_and_signature_replay() {
    let owner = SigningKey::generate(&mut OsRng);
    let outsider = SigningKey::generate(&mut OsRng);
    let mut s = new_session(&owner, Duration::from_secs(30));
    let p = profile();
    let st = s.profile_statement(&p).unwrap();
    assert!(
        s.set_profile(p.clone(), &signature(&outsider, PROFILE_DOMAIN, &st))
            .is_err()
    );
    s.set_profile(p, &signature(&owner, PROFILE_DOMAIN, &st))
        .unwrap();
    let st = s.context_statement(0, &"33".repeat(32)).unwrap();
    assert!(
        s.set_context(
            0,
            &"33".repeat(32),
            &signature(&outsider, CONTEXT_DOMAIN, &st)
        )
        .is_err()
    );
    context(&mut s, &owner, 0);
    assert!(
        s.set_context(0, &"33".repeat(32), &signature(&owner, CONTEXT_DOMAIN, &st))
            .is_err()
    );
    let tx = transaction(&s, "valid");
    let i = s.inspect(&tx).unwrap();
    let signature = signature(&owner, ADMISSION_DOMAIN, &i.statement);
    s.prepare(&tx, &signature).unwrap();
    assert!(s.prepare(&tx, &signature).is_err());
}
#[test]
fn native_transport_rejects_import_commands_and_closes_on_oversized_framing() {
    let owner = SigningKey::generate(&mut OsRng);
    let mut child = Command::new(env!("CARGO_BIN_EXE_castalia-cardano-funding-fixture"))
        .args([
            "--owner-verification-key",
            &hex::encode(owner.verifying_key().to_bytes()),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    writeln!(
        input,
        "{}",
        json!({"command":"importWallet","seed":"forbidden"})
    )
    .unwrap();
    input.write_all(&vec![b'x'; 262146]).unwrap();
    drop(input);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let rows: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["ok"], false);
    assert_eq!(rows[1]["ok"], false);
}

#[test]
fn caps_preparations_and_rejects_unsafe_generation_and_profile_shapes() {
    let owner = SigningKey::generate(&mut OsRng);
    let mut s = new_session(&owner, Duration::from_secs(30));
    install(&mut s, &owner);
    assert!(s.context_statement(u64::MAX, &"33".repeat(32)).is_err());
    let p = json!({"schema":"castalia.cardano-fixture-execution-profile.v1","backend":"scalus-1.4.1","executionProfileDigest":"11".repeat(32),"allowedScriptHashes":[script_hash()],"privateKey":"forbidden"});
    assert!(serde_json::from_value::<FixtureProfile>(p).is_err());
    let duplicate = format!(
        "{{\"schema\":\"castalia.cardano-fixture-execution-profile.v1\",\"backend\":\"scalus-1.4.1\",\"backend\":\"other\",\"executionProfileDigest\":\"{}\",\"allowedScriptHashes\":[\"{}\"]}}",
        "11".repeat(32),
        script_hash()
    );
    assert!(serde_json::from_str::<FixtureProfile>(&duplicate).is_err());
    assert!(
        FundingFixtureSession::fresh_with_ttl(
            owner.verifying_key().to_bytes(),
            CardanoFundingNetworkV1::testnet(42, &"22".repeat(32)).unwrap(),
            Duration::from_secs(61)
        )
        .is_err()
    );
}

#[test]
fn accepts_actual_inline_datum_wrapper_but_rejects_nonbyte_tag24() {
    let owner = SigningKey::generate(&mut OsRng);
    let mut s = new_session(&owner, Duration::from_secs(30));
    install(&mut s, &owner);
    assert!(s.inspect(&transaction(&s, "inline-datum")).is_ok());
    assert!(s.inspect(&transaction(&s, "malformed-tag24")).is_err());
}

#[test]
fn identical_action_data_at_distinct_offsets_compares_semantically() {
    let owner = SigningKey::generate(&mut OsRng);
    let mut s = new_session(&owner, Duration::from_secs(30));
    install(&mut s, &owner);
    let inspected = s.inspect(&transaction(&s, "multiple-restore")).unwrap();
    assert_eq!(inspected.review.kind, "teapot-restore-controller");
}
#[test]
fn pending_preparations_are_bounded_and_cancel_frees_one_slot() {
    let owner = SigningKey::generate(&mut OsRng);
    let mut s = new_session(&owner, Duration::from_secs(30));
    install(&mut s, &owner);
    let mut handles = Vec::new();
    for n in 200000..200008 {
        let tx = transaction(&s, &format!("fee-{n}"));
        handles.push(prepare(&mut s, &owner, &tx));
    }
    let next = transaction(&s, "fee-200008");
    let i = s.inspect(&next).unwrap();
    assert!(
        s.prepare(&next, &signature(&owner, ADMISSION_DOMAIN, &i.statement))
            .is_err()
    );
    assert!(s.cancel(&handles[0]));
    let handle = s
        .prepare(&next, &signature(&owner, ADMISSION_DOMAIN, &i.statement))
        .unwrap()
        .handle;
    assert!(s.approve(&handle).is_ok());
}
