#![cfg(feature = "funding-fixtures")]
//! Structural owner-capability tests. Script bytes are explicit placeholders;
//! only the independent Scalus integration establishes actual ledger admission.
use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use castalia_wallet_core::{
    CardanoFundingNetworkV1,
    funding_fixture::{
        ADMISSION_DOMAIN_V2, CONTEXT_DOMAIN, FixtureAllowedScript, FixtureProfile,
        FixtureReviewContext, FixtureReviewUtxo, FundingFixtureSession, PROFILE_DOMAIN,
        fixture_transcript,
    },
};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use serde_json::Value;
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
fn array(a: Vec<Vec<u8>>) -> Vec<u8> {
    let mut v = head(4, a.len() as u64);
    for n in a {
        v.extend(n);
    }
    v
}
fn map(a: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    let mut v = head(5, a.len() as u64);
    for (k, n) in a {
        v.extend(k);
        v.extend(n);
    }
    v
}
fn fields(a: Vec<(u64, Vec<u8>)>) -> Vec<u8> {
    map(a.into_iter().map(|(k, v)| (head(0, k), v)).collect())
}
fn data(c: u64, a: Vec<Vec<u8>>) -> Vec<u8> {
    let mut v = head(6, 121 + c);
    v.extend(array(a));
    v
}
fn digest(raw: &[u8], n: usize) -> Vec<u8> {
    let mut v = vec![0; n];
    let mut h = Blake2bVar::new(n).unwrap();
    h.update(raw);
    h.finalize_variable(&mut v).unwrap();
    v
}
fn script_hash() -> String {
    hex::encode(digest(&[3, 1, 2, 3], 28))
}
fn key(s: &FundingFixtureSession) -> Vec<u8> {
    hex::decode(s.info().account.payment_key_hash()).unwrap()
}
fn reference(byte: u8) -> Vec<u8> {
    array(vec![bytes(&[byte; 32]), head(0, 0)])
}
fn data_ref(byte: u8) -> Vec<u8> {
    data(0, vec![bytes(&[byte; 32]), head(0, 0)])
}
fn address_data(key: &[u8]) -> Vec<u8> {
    data(0, vec![data(0, vec![bytes(key)]), data(1, vec![])])
}
fn state_datum(s: &FundingFixtureSession, marsh: bool) -> Vec<u8> {
    if marsh {
        data(
            0,
            vec![
                head(0, 1),
                address_data(&[0x55; 28]),
                data(0, vec![]),
                array(
                    (0..4)
                        .map(|_| data(0, vec![bytes(&[]), bytes(&[]), head(0, 0)]))
                        .collect(),
                ),
                head(0, 0),
                head(0, 5_000_000),
            ],
        )
    } else {
        data(
            0,
            vec![
                head(0, 1),
                bytes(&key(s)),
                array(vec![bytes(&[0x55; 28]), bytes(&[0x66; 28])]),
                head(0, 0),
                head(0, 5_000_000),
            ],
        )
    }
}
fn output(address: Vec<u8>, name: &[u8], datum: &[u8], coin: u64) -> Vec<u8> {
    let policy = hex::decode(script_hash()).unwrap();
    let value = if name.is_empty() {
        head(0, coin)
    } else {
        array(vec![
            head(0, coin),
            map(vec![(bytes(&policy), map(vec![(bytes(name), head(0, 1))]))]),
        ])
    };
    let mut tagged = head(6, 24);
    tagged.extend(bytes(datum));
    fields(vec![
        (0, bytes(&address)),
        (1, value),
        (2, array(vec![head(0, 1), tagged])),
    ])
}
fn script_output(name: &[u8], datum: &[u8]) -> Vec<u8> {
    let mut a = vec![0x70];
    a.extend(hex::decode(script_hash()).unwrap());
    output(a, name, datum, 5_000_000)
}
fn req_datum(s: &FundingFixtureSession, rev: u64, purpose: &str) -> Vec<u8> {
    data(
        1,
        vec![
            bytes(&key(s)),
            head(0, rev),
            address_data(&[0x44; 28]),
            data(0, vec![]),
            array(vec![data(
                0,
                vec![bytes(&[]), bytes(&[]), head(0, 1_000_000)],
            )]),
            bytes(purpose.as_bytes()),
        ],
    )
}
fn signed(owner: &SigningKey, domain: &str, v: &Value) -> String {
    hex::encode(
        owner
            .sign(&fixture_transcript(domain, v).unwrap())
            .to_bytes(),
    )
}
fn session(marsh: bool, creator_matches: bool) -> (SigningKey, FundingFixtureSession) {
    let owner = SigningKey::generate(&mut OsRng);
    let mut s = FundingFixtureSession::fresh(
        owner.verifying_key().to_bytes(),
        CardanoFundingNetworkV1::testnet(42, &"22".repeat(32)).unwrap(),
    )
    .unwrap();
    let profile = FixtureProfile {
        schema: "castalia.cardano-fixture-execution-profile.v2".into(),
        backend: "scalus-1.4.1".into(),
        execution_profile_digest: "11".repeat(32),
        allowed_script_hashes: vec![],
        allowed_scripts: vec![FixtureAllowedScript {
            hash: script_hash(),
            role: if marsh { "marsh" } else { "teapot" }.into(),
            creator_key_hash: if marsh {
                Some(if creator_matches {
                    s.info().account.payment_key_hash().into()
                } else {
                    "99".repeat(28)
                })
            } else {
                None
            },
        }],
    };
    let st = s.profile_statement(&profile).unwrap();
    s.set_profile(profile, &signed(&owner, PROFILE_DOMAIN, &st))
        .unwrap();
    let st = s.context_statement(0, &"33".repeat(32)).unwrap();
    s.set_context(0, &"33".repeat(32), &signed(&owner, CONTEXT_DOMAIN, &st))
        .unwrap();
    (owner, s)
}
fn evidence(byte: u8, output: Vec<u8>) -> FixtureReviewUtxo {
    FixtureReviewUtxo {
        tx_hash: hex::encode([byte; 32]),
        output_index: 0,
        utxo_cbor_hex: hex::encode(array(vec![reference(byte), output])),
    }
}
fn context(utxos: Vec<FixtureReviewUtxo>) -> FixtureReviewContext {
    FixtureReviewContext {
        schema: "castalia.cardano-fixture-review-context.v1".into(),
        utxos,
    }
}
fn tx(
    s: &FundingFixtureSession,
    inputs: Vec<u8>,
    refs: Option<Vec<u8>>,
    outputs: Vec<Vec<u8>>,
    mint: Option<(&[u8], bool)>,
    redeemers: Vec<(u64, u64, Vec<u8>)>,
) -> String {
    let mut body = vec![
        (0, inputs),
        (1, array(outputs)),
        (2, head(0, 200_000)),
        (11, bytes(&[0x44; 32])),
        (14, array(vec![bytes(&key(s))])),
        (15, head(0, 0)),
    ];
    if let Some(r) = refs {
        body.push((18, r));
    }
    if let Some((name, burn)) = mint {
        body.push((
            9,
            map(vec![(
                bytes(&hex::decode(script_hash()).unwrap()),
                map(vec![(
                    bytes(name),
                    if burn { vec![0x20] } else { head(0, 1) },
                )]),
            )]),
        ));
    }
    let r = array(
        redeemers
            .into_iter()
            .map(|(tag, index, action)| {
                array(vec![
                    head(0, tag),
                    head(0, index),
                    action,
                    array(vec![head(0, 1000), head(0, 1000)]),
                ])
            })
            .collect(),
    );
    hex::encode(array(vec![
        fields(body),
        fields(vec![(5, r), (7, array(vec![bytes(&[1, 2, 3])]))]),
        vec![0xf5],
        vec![0xf6],
    ]))
}
fn create(s: &FundingFixtureSession) -> (String, FixtureReviewContext) {
    let request = script_output(&[0x77; 32], &req_datum(s, 0, "Original purpose"));
    let tx = tx(
        s,
        array(vec![reference(0xaa)]),
        Some(array(vec![reference(0xbb)])),
        vec![request],
        Some((&[0x77; 32], false)),
        vec![(
            1,
            0,
            data(1, vec![data_ref(0xaa), bytes(&key(s)), head(0, 0)]),
        )],
    );
    (
        tx,
        context(vec![evidence(
            0xbb,
            script_output(b"TEAPOT_STATE_V1", &state_datum(s, false)),
        )]),
    )
}
fn revise(s: &FundingFixtureSession) -> (String, FixtureReviewContext) {
    let tx = tx(
        s,
        array(vec![reference(0xaa)]),
        Some(array(vec![reference(0xbb)])),
        vec![script_output(
            &[0x77; 32],
            &req_datum(s, 1, "Revised purpose"),
        )],
        None,
        vec![(0, 0, data(3, vec![head(0, 0)]))],
    );
    (
        tx,
        context(vec![
            evidence(
                0xaa,
                script_output(&[0x77; 32], &req_datum(s, 0, "Original purpose")),
            ),
            evidence(
                0xbb,
                script_output(b"TEAPOT_STATE_V1", &state_datum(s, false)),
            ),
        ]),
    )
}
fn linked(s: &FundingFixtureSession, mismatch: bool) -> (String, FixtureReviewContext) {
    let a = data(
        4,
        vec![
            data_ref(0xbb),
            head(0, 0),
            array(vec![]),
            head(0, 1),
            head(0, 2),
            head(0, 0),
        ],
    );
    let r = data(2, vec![data_ref(if mismatch { 0xaa } else { 0xbb })]);
    let tx = tx(
        s,
        array(vec![reference(0xaa), reference(0xbb)]),
        None,
        vec![script_output(b"TEAPOT_STATE_V1", &state_datum(s, false))],
        Some((&[0x77; 32], true)),
        vec![(0, 0, a.clone()), (0, 1, a), (1, 0, r)],
    );
    (
        tx,
        context(vec![
            evidence(
                0xaa,
                script_output(b"TEAPOT_STATE_V1", &state_datum(s, false)),
            ),
            evidence(
                0xbb,
                script_output(&[0x77; 32], &req_datum(s, 7, "Latest approved purpose")),
            ),
        ]),
    )
}
#[test]
fn v2_create_revision_linked_review_terms_are_derived_and_signed() {
    let (owner, mut s) = session(false, false);
    for (tx, ctx) in [create(&s), revise(&s), linked(&s, false)] {
        let inspected = s.inspect_with_context(&tx, &ctx).unwrap();
        let review = serde_json::to_value(&inspected.review).unwrap();
        assert_eq!(review["schema"], "castalia.cardano-fixture-review.v2");
        assert!(!review["request"]["datumHex"].as_str().unwrap().is_empty());
        assert!(s.inspect(&tx).is_err());
        let sig = signed(&owner, ADMISSION_DOMAIN_V2, &inspected.statement);
        let prepared = s.prepare_with_context(&tx, &ctx, &sig).unwrap();
        let witness = s.approve(&prepared.handle).unwrap();
        assert_eq!(
            witness.transaction_body_hash,
            inspected.statement["transactionBodyHash"]
        );
        assert!(s.approve(&prepared.handle).is_err());
    }
    let (tx, ctx) = linked(&s, false);
    let i = s.inspect_with_context(&tx, &ctx).unwrap();
    assert_eq!(i.review.purpose.as_deref(), Some("Latest approved purpose"));
    assert_eq!(i.review.extension["request"]["revision"], "7");
}
#[test]
fn v2_missing_substituted_duplicate_or_unrelated_context_never_prepares() {
    let (owner, mut s) = session(false, false);
    let (tx, ctx) = revise(&s);
    let inspected = s.inspect_with_context(&tx, &ctx).unwrap();
    let sig = signed(&owner, ADMISSION_DOMAIN_V2, &inspected.statement);
    let mut variants = vec![context(vec![]), context(vec![ctx.utxos[0].clone()])];
    let mut changed = ctx.clone();
    changed.utxos[0].tx_hash = "cc".repeat(32);
    variants.push(changed);
    let mut duplicate = ctx.clone();
    duplicate.utxos.push(ctx.utxos[1].clone());
    variants.push(duplicate);
    let mut raw = ctx.clone();
    raw.utxos[0].utxo_cbor_hex = hex::encode(array(vec![
        reference(0xbb),
        script_output(&[0x77; 32], &req_datum(&s, 0, "Original purpose")),
    ]));
    variants.push(raw);
    for v in variants {
        assert!(s.prepare_with_context(&tx, &v, &sig).is_err());
    }
}
#[test]
fn v2_context_purpose_substitution_invalidates_original_owner_capability() {
    let (owner, mut s) = session(false, false);
    let (tx, ctx) = linked(&s, false);
    let i = s.inspect_with_context(&tx, &ctx).unwrap();
    let sig = signed(&owner, ADMISSION_DOMAIN_V2, &i.statement);
    let mut substituted = ctx.clone();
    substituted.utxos[1] = evidence(
        0xbb,
        script_output(&[0x77; 32], &req_datum(&s, 7, "Attacker supplied prose")),
    );
    let changed = s.inspect_with_context(&tx, &substituted).unwrap();
    assert_ne!(
        changed.statement["reviewContextHash"],
        i.statement["reviewContextHash"]
    );
    assert_ne!(changed.review.purpose, i.review.purpose);
    assert!(s.prepare_with_context(&tx, &substituted, &sig).is_err());
}
#[test]
fn v2_unexpected_mixed_retirement_never_prepares() {
    let (_, s) = session(false, false);
    let (tx, ctx) = linked(&s, true);
    assert!(s.inspect_with_context(&tx, &ctx).is_err());
}
#[test]
fn v2_marsh_creator_without_normal_key_input_is_controller_from_immutable_profile() {
    let (_, s) = session(true, true);
    let state = script_output(b"MARSH_STATE_V1", &state_datum(&s, true));
    let action = data(
        0,
        vec![address_data(&[0x44; 28]), data(0, vec![]), head(0, 0)],
    );
    let tx = tx(
        &s,
        array(vec![reference(0xaa)]),
        None,
        vec![state.clone()],
        None,
        vec![(0, 0, action)],
    );
    let i = s
        .inspect_with_context(&tx, &context(vec![evidence(0xaa, state)]))
        .unwrap();
    assert_eq!(i.review.extension["participation"]["role"], "controller");
}
#[test]
fn v2_marsh_payer_needs_actual_normal_input_not_required_signer_only() {
    let (_, s) = session(true, false);
    let state = script_output(b"MARSH_STATE_V1", &state_datum(&s, true));
    let action = data(
        0,
        vec![address_data(&[0x44; 28]), data(0, vec![]), head(0, 0)],
    );
    let tx = tx(
        &s,
        array(vec![reference(0xaa), reference(0xbb)]),
        None,
        vec![state.clone()],
        None,
        vec![(0, 0, action)],
    );
    let ctx = context(vec![evidence(0xaa, state.clone())]);
    assert!(s.inspect_with_context(&tx, &ctx).is_err());
    let mut address = vec![0x60];
    address.extend(key(&s));
    let payer = output(address, &[], &data(0, vec![]), 10_000_000);
    let i = s
        .inspect_with_context(
            &tx,
            &context(vec![evidence(0xaa, state), evidence(0xbb, payer)]),
        )
        .unwrap();
    assert_eq!(i.review.extension["participation"]["role"], "input-payer");
}
#[test]
fn v2_profile_cannot_mix_roles_or_omit_marsh_creator_binding() {
    let (owner, s) = session(false, false);
    let mut profile = FixtureProfile {
        schema: "castalia.cardano-fixture-execution-profile.v2".into(),
        backend: "scalus-1.4.1".into(),
        execution_profile_digest: "11".repeat(32),
        allowed_script_hashes: vec![],
        allowed_scripts: vec![FixtureAllowedScript {
            hash: script_hash(),
            role: "marsh".into(),
            creator_key_hash: None,
        }],
    };
    assert!(s.profile_statement(&profile).is_err());
    profile.allowed_scripts[0].creator_key_hash = Some("99".repeat(28));
    assert!(s.profile_statement(&profile).is_ok());
    profile.allowed_script_hashes.push(script_hash());
    assert!(s.profile_statement(&profile).is_err());
    let _ = owner;
}
