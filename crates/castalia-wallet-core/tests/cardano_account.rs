use castalia_wallet_core::{CardanoFundingNetworkV1, import_wallet};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

fn fixture_wallet() -> castalia_wallet_core::OpenedWallet {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../docs/contracts/castalia-wallet-custody-v1.vector.json"
    ))
    .unwrap();
    import_wallet(
        &serde_json::to_vec(&vector["container"]).unwrap(),
        vector["inputs"]["passphraseUnicode"].as_str().unwrap(),
    )
    .unwrap()
}
fn network(magic: u32, byte: &str) -> CardanoFundingNetworkV1 {
    CardanoFundingNetworkV1::testnet(magic, &byte.repeat(32)).unwrap()
}
fn profile() -> Value {
    json!({"schema":"castalia.cardano-funding-network.v1", "network":"testnet", "networkMagic":42, "genesisKind":"shelley-genesis-raw-json-blake2b256", "genesisHash":"22".repeat(32)})
}
#[test]
fn matches_independent_public_payment_and_address_vector() {
    let wallet = fixture_wallet();
    let account = wallet.cardano_funding_account(&network(42, "22")).unwrap();
    assert_eq!(
        account.payment_public_key(),
        "672395b53d8af83efcc51cbced2341c6ddee66b6e8451dce08e260fc7190de2b"
    );
    assert_eq!(
        account.payment_key_hash(),
        "9c55c12c407940403cf9295e029d7ccc39aa2c3820b4f74d6a92be4e"
    );
    assert_eq!(
        account.address(),
        "addr_test1vzw9tsfvgpu5qspuly54uq5a0nxrn23v8qstfa6dd2ftunsh5zp2k"
    );
    assert_ne!(account.payment_public_key(), wallet.public_key_hex());
    let encoded = serde_json::to_value(&account).unwrap();
    assert_eq!(encoded["schema"], "castalia.cardano-funding-account.v1");
    assert_eq!(encoded["keySuite"], "Ed25519");
    assert_eq!(encoded["accountIndex"], 0);
    assert_eq!(encoded["authority"], "descriptor-only");
    assert_eq!(
        encoded["derivation"],
        "castalia.cardano-payment-from-member-root.v1"
    );
    assert_eq!(encoded.as_object().unwrap().len(), 9);
}
#[test]
fn preserves_exact_legacy_descriptor_bytes_and_core_version() {
    let wallet = fixture_wallet();
    assert_eq!(
        hex::encode(Sha256::digest(wallet.chain_accounts().unwrap().as_bytes())),
        "72e6e96c846aa13699d25bdbb11f9bd47ce18327e82182ac41ecf4b4d82f2b21"
    );
    assert_eq!(castalia_wallet_core::wallet_core_version(), "0.4.1");
    let legacy: Value = serde_json::from_str(&wallet.chain_accounts().unwrap()).unwrap();
    assert_eq!(
        legacy["accounts"][0]["address"],
        "addr1vxw9tsfvgpu5qspuly54uq5a0nxrn23v8qstfa6dd2ftunsvuka9n"
    );
    assert_eq!(
        legacy["accounts"][0]["publicKey"],
        wallet
            .cardano_funding_account(&network(42, "22"))
            .unwrap()
            .payment_public_key()
    );
}
#[test]
fn network_context_remains_distinct_when_testnet_address_is_identical() {
    let wallet = fixture_wallet();
    let a = wallet.cardano_funding_account(&network(1, "22")).unwrap();
    let b = wallet.cardano_funding_account(&network(2, "22")).unwrap();
    let c = wallet.cardano_funding_account(&network(1, "33")).unwrap();
    assert_eq!(a.address(), b.address());
    assert_eq!(a.address(), c.address());
    assert_eq!(a.payment_public_key(), b.payment_public_key());
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.network().network_magic(), 1);
    assert_eq!(a.network().genesis_hash(), "22".repeat(32));
}
#[test]
fn accepts_explicit_testnet_magic_bounds_and_roundtrips_profile() {
    for magic in [0, 1, u32::MAX] {
        let n = network(magic, "22");
        assert_eq!(
            CardanoFundingNetworkV1::from_json(&serde_json::to_vec(&n).unwrap()).unwrap(),
            n
        );
    }
}
#[test]
fn rejects_mainnet_and_ambiguous_numeric_or_network_profiles() {
    for field in [json!("mainnet"), json!("preview"), json!(0), json!(null)] {
        let mut p = profile();
        p["network"] = field;
        assert!(CardanoFundingNetworkV1::from_json(&serde_json::to_vec(&p).unwrap()).is_err());
    }
    for magic in [
        json!(-1),
        json!(4294967296_u64),
        json!(1.0),
        json!("1"),
        json!(null),
    ] {
        let mut p = profile();
        p["networkMagic"] = magic;
        assert!(CardanoFundingNetworkV1::from_json(&serde_json::to_vec(&p).unwrap()).is_err());
    }
}
#[test]
fn rejects_malformed_genesis_and_unknown_missing_or_duplicate_fields() {
    for hash in [
        "",
        "aa",
        &"A".repeat(64),
        &"g".repeat(64),
        &"a".repeat(63),
        &"a".repeat(65),
    ] {
        assert!(CardanoFundingNetworkV1::testnet(42, hash).is_err());
    }
    for key in [
        "schema",
        "network",
        "networkMagic",
        "genesisKind",
        "genesisHash",
    ] {
        let mut p = profile();
        p.as_object_mut().unwrap().remove(key);
        assert!(CardanoFundingNetworkV1::from_json(&serde_json::to_vec(&p).unwrap()).is_err());
    }
    let mut p = profile();
    p["schema"] = json!("castalia.cardano-funding-network.v2");
    assert!(CardanoFundingNetworkV1::from_json(&serde_json::to_vec(&p).unwrap()).is_err());
    let mut p = profile();
    p["privateKey"] = json!("forbidden");
    assert!(CardanoFundingNetworkV1::from_json(&serde_json::to_vec(&p).unwrap()).is_err());
    let duplicate =
        serde_json::to_string(&profile())
            .unwrap()
            .replacen("{", "{\"networkMagic\":42,", 1);
    assert!(CardanoFundingNetworkV1::from_json(duplicate.as_bytes()).is_err());
    let valid = serde_json::to_vec(&profile()).unwrap();
    for length in [1023, 1024] {
        let mut padded = valid.clone();
        padded.resize(length, b' ');
        assert!(CardanoFundingNetworkV1::from_json(&padded).is_ok());
    }
    let mut too_large = valid;
    too_large.resize(1025, b' ');
    assert!(CardanoFundingNetworkV1::from_json(&too_large).is_err());
    assert!(CardanoFundingNetworkV1::from_json(b"\xff").is_err());
}
#[test]
fn encrypted_recovery_restores_payment_descriptor_without_membership() {
    let original = fixture_wallet();
    let before = original
        .cardano_funding_account(&network(42, "22"))
        .unwrap();
    let encrypted = original
        .export_randomized("synthetic recovery passphrase")
        .unwrap();
    let restored = import_wallet(encrypted.as_bytes(), "synthetic recovery passphrase").unwrap();
    assert_eq!(
        restored
            .cardano_funding_account(&network(42, "22"))
            .unwrap(),
        before
    );
    assert_eq!(restored.public_key_hex(), original.public_key_hex());
    assert_eq!(
        restored.chain_accounts().unwrap(),
        original.chain_accounts().unwrap()
    );
}

#[test]
fn requires_exact_genesis_kind_without_legacy_fallback() {
    let mut missing = profile();
    missing.as_object_mut().unwrap().remove("genesisKind");
    assert!(CardanoFundingNetworkV1::from_json(&serde_json::to_vec(&missing).unwrap()).is_err());
    for kind in [
        json!("byron-genesis"),
        json!("shelley-genesis-jcs-blake2b256"),
        json!(""),
        json!(null),
    ] {
        let mut p = profile();
        p["genesisKind"] = kind;
        assert!(CardanoFundingNetworkV1::from_json(&serde_json::to_vec(&p).unwrap()).is_err());
    }
}
#[test]
fn shelley_genesis_hashes_exact_raw_bytes_without_json_normalization() {
    let cases: [(&[u8], &str); 3] = [
        (
            b"{\"networkMagic\":42}\n",
            "0e6d731dfa72410679c920fec96cde3c3a9bde6367170a906ff38664a235e27a",
        ),
        (
            b"{ \"networkMagic\": 42 }\n",
            "c98ea17f08bf7df162fc3053094dc6e2e9d17ffabd4bcac64f9b5853dbf92bef",
        ),
        (
            b"{\"networkMagic\":42}",
            "679feafaa0d16e522d28260a5b9c1c0a72f5789fb34490732e1d2514e98412a6",
        ),
    ];
    let mut profiles = Vec::new();
    for (raw, expected) in cases {
        let n = CardanoFundingNetworkV1::testnet_from_shelley_genesis_bytes(42, raw).unwrap();
        assert_eq!(n.genesis_hash(), expected);
        assert_eq!(n.genesis_kind(), "shelley-genesis-raw-json-blake2b256");
        assert_eq!(
            serde_json::to_value(&n).unwrap()["genesisKind"],
            "shelley-genesis-raw-json-blake2b256"
        );
        profiles.push(n);
    }
    assert_ne!(profiles[0], profiles[1]);
    assert_ne!(profiles[0], profiles[2]);
}
