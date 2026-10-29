//! Public-only funding descriptors. No ledger signing, network discovery or membership gate.
use bech32::{Bech32, Hrp};
use blake2::{Blake2bVar, digest::VariableOutput};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{CustodyError, OpenedWallet, Result, chain_accounts::cardano_payment_public, closed};

const NETWORK_SCHEMA: &str = "castalia.cardano-funding-network.v1";
const GENESIS_KIND: &str = "shelley-genesis-raw-json-blake2b256";
const MAX_NETWORK_PROFILE_BYTES: usize = 1024;

/// Explicit caller-supplied deployment context, not evidence of an authenticated node.
///
/// This non-production profile admits testnets only. Magic and genesis are not
/// encoded in a Shelley address; the later provider must independently verify both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardanoFundingNetworkV1 {
    schema: String,
    network: String,
    network_magic: u32,
    genesis_kind: String,
    genesis_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NetworkInput {
    schema: String,
    network: String,
    network_magic: u32,
    genesis_kind: String,
    genesis_hash: String,
}

impl CardanoFundingNetworkV1 {
    /// Construct shape-validated context. This does not admit a network or a node.
    pub fn testnet(network_magic: u32, genesis_hash: &str) -> Result<Self> {
        if genesis_hash.len() != 64
            || !genesis_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CustodyError::InvalidWalletFile);
        }
        Ok(Self {
            schema: NETWORK_SCHEMA.into(),
            network: "testnet".into(),
            network_magic,
            genesis_kind: GENESIS_KIND.into(),
            genesis_hash: genesis_hash.into(),
        })
    }

    /// Hash exactly the supplied raw Shelley genesis file bytes, without parsing,
    /// JSON normalization or newline changes. This binds one public file component
    /// only; it does not validate the file, its magic, a node or its chain/fork.
    pub fn testnet_from_shelley_genesis_bytes(network_magic: u32, raw: &[u8]) -> Result<Self> {
        let mut hash = [0_u8; 32];
        let mut hasher = Blake2bVar::new(hash.len()).map_err(closed)?;
        blake2::digest::Update::update(&mut hasher, raw);
        hasher.finalize_variable(&mut hash).map_err(closed)?;
        Self::testnet(network_magic, &hex::encode(hash))
    }

    /// Bounded closed JSON input; duplicate, unknown and missing fields reject.
    pub fn from_json(raw: &[u8]) -> Result<Self> {
        if raw.is_empty() || raw.len() > MAX_NETWORK_PROFILE_BYTES {
            return Err(CustodyError::InvalidWalletFile);
        }
        let input: NetworkInput = serde_json::from_slice(raw).map_err(closed)?;
        if input.schema != NETWORK_SCHEMA
            || input.network != "testnet"
            || input.genesis_kind != GENESIS_KIND
        {
            return Err(CustodyError::InvalidWalletFile);
        }
        Self::testnet(input.network_magic, &input.genesis_hash)
    }

    pub fn network_magic(&self) -> u32 {
        self.network_magic
    }
    pub fn genesis_kind(&self) -> &str {
        &self.genesis_kind
    }
    pub fn genesis_hash(&self) -> &str {
        &self.genesis_hash
    }
}

/// A public descriptor, not possession proof, network admission or spending authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardanoFundingAccountV1 {
    schema: String,
    authority: String,
    network: CardanoFundingNetworkV1,
    key_suite: String,
    derivation: String,
    account_index: u32,
    payment_public_key: String,
    payment_key_hash: String,
    address: String,
}

impl CardanoFundingAccountV1 {
    pub fn network(&self) -> &CardanoFundingNetworkV1 {
        &self.network
    }
    pub fn payment_public_key(&self) -> &str {
        &self.payment_public_key
    }
    pub fn payment_key_hash(&self) -> &str {
        &self.payment_key_hash
    }
    pub fn address(&self) -> &str {
        &self.address
    }
}

impl OpenedWallet {
    /// Derive account zero using the existing private derivation domain.
    ///
    /// The selected context changes the descriptor, not the payment key. This
    /// intentionally makes no network unlinkability claim. No signing is enabled.
    pub fn cardano_funding_account(
        &self,
        network: &CardanoFundingNetworkV1,
    ) -> Result<CardanoFundingAccountV1> {
        let root = Zeroizing::new(self.signing_key.to_bytes());
        let (public, hash) = cardano_payment_public(&root)?;
        let mut address_bytes = [0_u8; 29];
        address_bytes[0] = 0x60; // Shelley enterprise key address, testnet tag zero.
        address_bytes[1..].copy_from_slice(&hash);
        let address =
            bech32::encode::<Bech32>(Hrp::parse("addr_test").map_err(closed)?, &address_bytes)
                .map_err(closed)?;
        Ok(CardanoFundingAccountV1 {
            schema: "castalia.cardano-funding-account.v1".into(),
            authority: "descriptor-only".into(),
            network: network.clone(),
            key_suite: "Ed25519".into(),
            derivation: "castalia.cardano-payment-from-member-root.v1".into(),
            account_index: 0,
            payment_public_key: hex::encode(public),
            payment_key_hash: hex::encode(hash),
            address,
        })
    }
}
