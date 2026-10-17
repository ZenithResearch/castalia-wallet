use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use castalia_wallet_core::{
    CustodyError, DeterministicWalletMaterial, create_wallet, create_wallet_for_vector,
    import_wallet,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use fips204::{
    ml_dsa_65,
    traits::{SerDes as _, Verifier as _},
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const VECTOR_JSON: &str =
    include_str!("../../../docs/contracts/castalia-wallet-custody-v1.vector.json");

#[test]
fn imports_exact_d0_vector_and_reproduces_identity() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).unwrap();
    let container = serde_json::to_string(&vector["container"]).unwrap();
    let recreated = create_wallet_for_vector(
        vector["inputs"]["passphraseUnicode"].as_str().unwrap(),
        vector["container"]["createdAt"].as_u64().unwrap(),
        DeterministicWalletMaterial {
            seed: hex::decode(vector["inputs"]["ed25519SeedHex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            salt: hex::decode(vector["inputs"]["saltHex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
            nonce: hex::decode(vector["inputs"]["nonceHex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        },
    )
    .unwrap();
    assert_eq!(
        hex::encode(recreated.as_bytes()),
        vector["finalContainerJcsUtf8Hex"].as_str().unwrap()
    );

    let opened = import_wallet(
        container.as_bytes(),
        vector["inputs"]["passphraseUnicode"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        opened.public_key_hex(),
        vector["intermediates"]["publicKey"]
    );
    assert_eq!(
        opened.key_id_hex(),
        "6c31041268f471609c79f5f2dbcc38e4a4ab2f4d416109a4e09fcf50fd0f0062"
    );
    assert_eq!(
        opened.created_at(),
        vector["container"]["createdAt"].as_u64().unwrap()
    );
}

#[test]
fn rejects_d0_tamper_with_one_closed_error() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).unwrap();
    let mut container = vector["container"].clone();
    container["publicKey"] = Value::String(format!(
        "0{}",
        &container["publicKey"].as_str().unwrap()[1..]
    ));

    assert_eq!(
        import_wallet(
            serde_json::to_string(&container).unwrap().as_bytes(),
            vector["inputs"]["passphraseUnicode"].as_str().unwrap()
        )
        .unwrap_err(),
        CustodyError::InvalidWalletFile,
    );
}

#[test]
fn rejects_empty_passphrase_and_noncanonical_container_shapes() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).unwrap();
    let encoded = serde_json::to_vec(&vector["container"]).unwrap();
    assert!(matches!(
        import_wallet(&encoded, ""),
        Err(CustodyError::InvalidWalletFile)
    ));

    let unknown =
        String::from_utf8(encoded.clone())
            .unwrap()
            .replacen("{", "{\"unknown\":true,", 1);
    assert!(matches!(
        import_wallet(
            unknown.as_bytes(),
            vector["inputs"]["passphraseUnicode"].as_str().unwrap()
        ),
        Err(CustodyError::InvalidWalletFile)
    ));

    let duplicate = String::from_utf8(encoded).unwrap().replacen(
        "{",
        "{\"schema\":\"castalia.wallet-custody.v1\",",
        1,
    );
    assert!(matches!(
        import_wallet(
            duplicate.as_bytes(),
            vector["inputs"]["passphraseUnicode"].as_str().unwrap()
        ),
        Err(CustodyError::InvalidWalletFile)
    ));
}

#[test]
fn unlocked_member_key_signs_with_its_public_identity() {
    let (wallet, _) = create_wallet("correct horse", 1_700_000_000_123).unwrap();
    let message = b"checkpoint-a-v1-challenge-bytes";
    let signature = wallet.sign(message).unwrap();
    let public: [u8; 32] = hex::decode(wallet.public_key_hex())
        .unwrap()
        .try_into()
        .unwrap();
    VerifyingKey::from_bytes(&public)
        .unwrap()
        .verify(message, &Signature::from_bytes(&signature))
        .unwrap();
}

#[test]
fn existing_recovery_seed_restores_the_dregg_hybrid_identity() {
    let vector: Value = serde_json::from_str(VECTOR_JSON).unwrap();
    let container = serde_json::to_vec(&vector["container"]).unwrap();
    let passphrase = vector["inputs"]["passphraseUnicode"].as_str().unwrap();

    let first = import_wallet(&container, passphrase).unwrap();
    let second = import_wallet(&container, passphrase).unwrap();
    let public_bytes = URL_SAFE_NO_PAD
        .decode(first.ml_dsa_public_key_base64url())
        .unwrap();

    assert_eq!(public_bytes.len(), ml_dsa_65::PK_LEN);
    assert_eq!(
        first.ml_dsa_public_key_base64url(),
        second.ml_dsa_public_key_base64url(),
    );
    assert_eq!(
        first.ml_dsa_public_key_commitment_hex(),
        second.ml_dsa_public_key_commitment_hex(),
    );

    let message = b"dregg canonical turn signing message";
    let signature = first.sign_dregg_pq(message).unwrap();
    assert_eq!(signature.len(), ml_dsa_65::SIG_LEN);
    let public_key =
        ml_dsa_65::PublicKey::try_from_bytes(public_bytes.try_into().unwrap()).unwrap();
    let signature: [u8; ml_dsa_65::SIG_LEN] = signature.try_into().unwrap();
    assert!(public_key.verify(message, &signature, b"dregg-hybrid-turn-v1"));
}

#[test]
fn dregg_nist_acvp_mldsa65_keygen_vector_is_byte_exact() {
    // Dregg pins this NIST ACVP ML-DSA-65 tcId 26 seed and public key in
    // metatheory/Dregg2/Crypto/MlDsaKeygenAcvp.lean. Pinning the public-key
    // digest here makes a Wallet/Dregg derivation drift fail in hosted CI
    // without copying 1,952 bytes of fixture text into a second repository.
    let seed: [u8; 32] =
        hex::decode("a991fd42b071d49c48ae3e75c647459e0daad1e1ba356a04801912d3294bcff8")
            .unwrap()
            .try_into()
            .unwrap();
    let encoded = create_wallet_for_vector(
        "acvp-wallet-vector",
        1_700_000_000_000,
        DeterministicWalletMaterial {
            seed,
            salt: [0x51; 16],
            nonce: [0x62; 12],
        },
    )
    .unwrap();
    let wallet = import_wallet(encoded.as_bytes(), "acvp-wallet-vector").unwrap();
    let public_bytes = URL_SAFE_NO_PAD
        .decode(wallet.ml_dsa_public_key_base64url())
        .unwrap();

    assert_eq!(
        hex::encode(Sha256::digest(public_bytes)),
        "b1a7d0d2f0d7a04b9d5ffccd9bd578864dab4a01cdd7f70a05cd1f4f0672e43a",
    );
}
