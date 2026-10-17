use bech32::{Bech32, Hrp};
use blake2::{Blake2bVar, digest::VariableOutput};
use ed25519_dalek::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::Serialize;
use sha3::{Digest as _, Keccak256};
use zeroize::{Zeroize, Zeroizing};

use super::{CustodyError, Result, closed, jcs_to_vec};

pub const CHAIN_ACCOUNTS_SCHEMA: &str = "zenith.chain-accounts-section.v1";
pub const CHAIN_ACCOUNT_DERIVATION_SCHEMA: &str = "castalia.chain-account-derivation.v1";
const CHAIN_ACCOUNT_AUTHORITY: &str = "descriptor-only";
const CHAIN_ACCOUNT_RECOVERY: &str = "castalia.wallet-custody.v1";
const CARDANO_DERIVATION: &str = "castalia.cardano-payment-from-member-root.v1";
const EVM_DERIVATION: &str = "castalia.evm-from-member-root.v1";
const SOLANA_DERIVATION: &str = "castalia.solana-from-member-root.v1";
const CARDANO_KEY_DOMAIN: &str = "castalia/chain-account/cardano-payment/v1";
const EVM_KEY_DOMAIN: &str = "castalia/chain-account/evm/v1";
const SOLANA_KEY_DOMAIN: &str = "castalia/chain-account/solana/v1";
const CHAIN_KEY_ID_DOMAIN: &str = "castalia/chain-key-id/v1";
const CHAIN_ACCOUNT_ID_DOMAIN: &str = "castalia/chain-account-id/v1";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChainAccountsSection {
    pub schema: String,
    pub version: u32,
    pub owner_member_key: String,
    pub authority: String,
    pub recovery: String,
    pub accounts: Vec<ChainAccountDescriptor>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChainAccountDescriptor {
    pub account_id: String,
    pub key_id: String,
    pub family: String,
    pub network_id: String,
    pub address: String,
    pub public_key: String,
    pub key_suite: String,
    pub derivation_schema: String,
    pub derivation: String,
    pub account_index: u32,
    pub status: String,
}

pub(crate) fn derive_chain_accounts(root: &[u8; 32], owner: &str) -> Result<String> {
    let account_index = 0;
    let cardano_signing_key = SigningKey::from_bytes(&derived_chain_seed(
        root,
        CARDANO_KEY_DOMAIN,
        account_index,
        0,
    ));
    let cardano_public = cardano_signing_key.verifying_key().to_bytes();
    let cardano_public_hex = hex::encode(cardano_public);
    let mut payment_hash = [0_u8; 28];
    let mut hasher = Blake2bVar::new(payment_hash.len()).map_err(closed)?;
    blake2::digest::Update::update(&mut hasher, &cardano_public);
    hasher
        .finalize_variable(&mut payment_hash)
        .map_err(closed)?;
    let mut cardano_address_bytes = Vec::with_capacity(29);
    cardano_address_bytes.push(0x61);
    cardano_address_bytes.extend_from_slice(&payment_hash);
    let cardano_address =
        bech32::encode::<Bech32>(Hrp::parse("addr").map_err(closed)?, &cardano_address_bytes)
            .map_err(closed)?;

    let evm_secret = derived_evm_secret(root, account_index)?;
    let evm_public = evm_secret.public_key();
    let evm_compressed = evm_public.to_sec1_bytes();
    let evm_uncompressed = evm_public.to_encoded_point(false);
    let evm_hash = Keccak256::digest(&evm_uncompressed.as_bytes()[1..]);
    let evm_address = format!("0x{}", hex::encode(&evm_hash[12..]));
    let evm_public_hex = hex::encode(evm_compressed.as_ref());

    let solana_signing_key = SigningKey::from_bytes(&derived_chain_seed(
        root,
        SOLANA_KEY_DOMAIN,
        account_index,
        0,
    ));
    let solana_public = solana_signing_key.verifying_key().to_bytes();
    let solana_public_hex = hex::encode(solana_public);
    let solana_address = bs58::encode(solana_public).into_string();

    let cardano_key_id = chain_key_id("Ed25519", &cardano_public_hex);
    let evm_key_id = chain_key_id("secp256k1", &evm_public_hex);
    let solana_key_id = chain_key_id("Ed25519", &solana_public_hex);
    let descriptor = |family: &str,
                      network_id: &str,
                      address: &str,
                      public_key: &str,
                      key_suite: &str,
                      key_id: &str,
                      derivation: &str| ChainAccountDescriptor {
        account_id: chain_account_id(network_id, address),
        key_id: key_id.into(),
        family: family.into(),
        network_id: network_id.into(),
        address: address.into(),
        public_key: public_key.into(),
        key_suite: key_suite.into(),
        derivation_schema: CHAIN_ACCOUNT_DERIVATION_SCHEMA.into(),
        derivation: derivation.into(),
        account_index,
        status: "preview".into(),
    };
    let accounts = vec![
        descriptor(
            "cardano",
            "cardano:mainnet",
            &cardano_address,
            &cardano_public_hex,
            "Ed25519",
            &cardano_key_id,
            CARDANO_DERIVATION,
        ),
        descriptor(
            "evm",
            "eip155:1",
            &evm_address,
            &evm_public_hex,
            "secp256k1",
            &evm_key_id,
            EVM_DERIVATION,
        ),
        descriptor(
            "evm",
            "eip155:4663",
            &evm_address,
            &evm_public_hex,
            "secp256k1",
            &evm_key_id,
            EVM_DERIVATION,
        ),
        descriptor(
            "solana",
            "solana:mainnet-beta",
            &solana_address,
            &solana_public_hex,
            "Ed25519",
            &solana_key_id,
            SOLANA_DERIVATION,
        ),
    ];
    let section = ChainAccountsSection {
        schema: CHAIN_ACCOUNTS_SCHEMA.into(),
        version: 1,
        owner_member_key: owner.into(),
        authority: CHAIN_ACCOUNT_AUTHORITY.into(),
        recovery: CHAIN_ACCOUNT_RECOVERY.into(),
        accounts,
    };
    String::from_utf8(jcs_to_vec(&section)?).map_err(closed)
}

fn derived_chain_seed(root: &[u8; 32], domain: &str, account_index: u32, attempt: u32) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(root);
    hasher.update(&account_index.to_be_bytes());
    hasher.update(&attempt.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn derived_evm_secret(root: &[u8; 32], account_index: u32) -> Result<k256::SecretKey> {
    for attempt in 0..=u32::MAX {
        let mut candidate = Zeroizing::new(derived_chain_seed(
            root,
            EVM_KEY_DOMAIN,
            account_index,
            attempt,
        ));
        if let Ok(secret) = k256::SecretKey::from_slice(candidate.as_ref()) {
            candidate.zeroize();
            return Ok(secret);
        }
    }
    Err(CustodyError::InvalidWalletFile)
}

fn stable_chain_id(domain: &str, parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    for part in parts {
        hasher.update(&(part.len() as u32).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn chain_key_id(key_suite: &str, public_key: &str) -> String {
    stable_chain_id(CHAIN_KEY_ID_DOMAIN, &[key_suite, public_key])
}

fn chain_account_id(network_id: &str, address: &str) -> String {
    stable_chain_id(CHAIN_ACCOUNT_ID_DOMAIN, &[network_id, address])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_public_accounts_without_exporting_private_keys() {
        let root = [0x42; 32];
        let owner = SigningKey::from_bytes(&root).verifying_key().to_bytes();
        let section: serde_json::Value =
            serde_json::from_str(&derive_chain_accounts(&root, &hex::encode(owner)).unwrap())
                .unwrap();
        assert_eq!(section["schema"], CHAIN_ACCOUNTS_SCHEMA);
        assert_eq!(section["accounts"].as_array().unwrap().len(), 4);
        let ethereum = section["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|account| account["networkId"] == "eip155:1")
            .unwrap();
        let robinhood = section["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|account| account["networkId"] == "eip155:4663")
            .unwrap();
        assert_eq!(ethereum["address"], robinhood["address"]);
        assert_eq!(ethereum["keyId"], robinhood["keyId"]);
        assert!(
            section["accounts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|account| account.get("privateKey").is_none())
        );
    }
}
