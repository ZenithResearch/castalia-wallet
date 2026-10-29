pub mod access_request;
pub mod resource_selection;
pub mod service_access_point;
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey, pkcs8::DecodePrivateKey};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen as _, SerDes as _, Signer as _},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

pub mod browser_read;
mod credential_presentation;
pub use credential_presentation::WasmCredentialPresentation;
mod files_keys;
pub mod portable;
pub mod read_access;
pub mod recovery_session;
pub mod wallet_identities;
pub mod web_compat;
pub use web_compat::WebWalletCustody;
mod resource_owner;

#[wasm_bindgen]
pub fn wallet_core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

mod cardano_account;
pub use cardano_account::{CardanoFundingAccountV1, CardanoFundingNetworkV1};
mod chain_accounts;
mod membership_presentation_v2;
pub use chain_accounts::*;
pub use membership_presentation_v2::*;

const OUTER_SCHEMA: &str = "castalia.wallet-custody.v1";
const SECRET_SCHEMA: &str = "castalia.wallet-secret.v1";
const MAX_WALLET_BYTES: usize = 1_048_576;
const DREGG_HYBRID_TURN_PQ_CONTEXT: &[u8] = b"dregg-hybrid-turn-v1";
const DREGG_ML_DSA_KEY_COMMITMENT_DOMAIN: &str = "dregg-cell-ml-dsa-key-v1";
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CustodyError {
    #[error("invalid_wallet_file")]
    InvalidWalletFile,
}

type Result<T> = core::result::Result<T, CustodyError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct KdfHeader {
    name: String,
    version: u32,
    salt: String,
    #[serde(rename = "memoryKiB")]
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    derived_key_bytes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AeadHeader {
    name: String,
    nonce: String,
    tag_bits: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Header {
    schema: String,
    key_suite: String,
    public_key: String,
    created_at: u64,
    kdf: KdfHeader,
    aead: AeadHeader,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Container {
    schema: String,
    key_suite: String,
    public_key: String,
    created_at: u64,
    kdf: KdfHeader,
    aead: AeadHeader,
    ciphertext: String,
}

impl Container {
    fn header(&self) -> Header {
        Header {
            schema: self.schema.clone(),
            key_suite: self.key_suite.clone(),
            public_key: self.public_key.clone(),
            created_at: self.created_at,
            kdf: self.kdf.clone(),
            aead: self.aead.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SecretPlaintext {
    schema: String,
    key_id: String,
    private_key_pkcs8: String,
    created_at: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct DeterministicWalletMaterial {
    pub seed: [u8; 32],
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
}

pub struct OpenedWallet {
    signing_key: SigningKey,
    ml_dsa_signing_key: ml_dsa_65::PrivateKey,
    ml_dsa_public_key: [u8; ml_dsa_65::PK_LEN],
    created_at: u64,
}

impl core::fmt::Debug for OpenedWallet {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OpenedWallet")
            .field("public_key", &self.public_key_hex())
            .field("created_at", &self.created_at)
            .finish_non_exhaustive()
    }
}

impl OpenedWallet {
    fn from_signing_key(signing_key: SigningKey, created_at: u64) -> Self {
        // This is byte-for-byte the same derivation used by
        // dregg_pq::MlDsaKey::from_ed25519_seed: ML-DSA.KeyGen receives the
        // existing Ed25519 seed as xi. There is one identity root, not two
        // independently recoverable secrets.
        let (ml_dsa_public_key, ml_dsa_signing_key) =
            ml_dsa_65::KG::keygen_from_seed(&signing_key.to_bytes());
        Self {
            signing_key,
            ml_dsa_signing_key,
            ml_dsa_public_key: ml_dsa_public_key.into_bytes(),
            created_at,
        }
    }

    /// Wrap one Files data key under the recovered signing root and exact public scope.
    pub fn wrap_files_key(&self, binding: &str, key: &[u8]) -> Result<String> {
        let seed = Zeroizing::new(self.signing_key.to_bytes());
        crate::files_keys::wrap(&seed, &self.public_key_hex(), binding, key).map_err(closed)
    }

    pub fn unwrap_files_key(&self, binding: &str, envelope: &str) -> Result<Zeroizing<Vec<u8>>> {
        let seed = Zeroizing::new(self.signing_key.to_bytes());
        crate::files_keys::unwrap(&seed, &self.public_key_hex(), binding, envelope).map_err(closed)
    }

    pub fn sign_files_service_authentication(
        &self,
        challenge: &str,
        origin: &str,
        kind: &str,
        service_id: &str,
        now_ms: u64,
    ) -> Result<[u8; 64]> {
        let bytes =
            crate::files_keys::service_auth_bytes(challenge, origin, kind, service_id, now_ms)
                .map_err(closed)?;
        Ok(self.signing_key.sign(&bytes).to_bytes())
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn key_id_hex(&self) -> String {
        blake3::hash(&self.signing_key.verifying_key().to_bytes())
            .to_hex()
            .to_string()
    }

    pub fn ml_dsa_public_key_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.ml_dsa_public_key)
    }

    pub fn ml_dsa_public_key_commitment_hex(&self) -> String {
        let mut hasher = blake3::Hasher::new_derive_key(DREGG_ML_DSA_KEY_COMMITMENT_DOMAIN);
        hasher.update(&(self.ml_dsa_public_key.len() as u32).to_le_bytes());
        hasher.update(&self.ml_dsa_public_key);
        hasher.finalize().to_hex().to_string()
    }

    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        Ok(self.signing_key.sign(message).to_bytes())
    }

    /// Produce the post-quantum half of Dregg's hybrid turn authorization.
    ///
    /// The context and deterministic all-zero FIPS randomness exactly match
    /// `dregg_turn::pq::MlDsaTurnKey::sign`, so Dregg can consume this half
    /// alongside the Ed25519 signature over the same canonical turn message.
    pub fn sign_dregg_pq(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.ml_dsa_signing_key
            .try_sign_with_seed(&[0_u8; 32], message, DREGG_HYBRID_TURN_PQ_CONTEXT)
            .map(|signature| signature.to_vec())
            .map_err(closed)
    }

    pub fn export_randomized(&self, passphrase: &str) -> Result<Zeroizing<String>> {
        let mut salt = [0_u8; 16];
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        encrypt_wallet(&self.signing_key, passphrase, self.created_at, salt, nonce)
    }

    pub fn chain_accounts(&self) -> Result<String> {
        derive_chain_accounts(&self.signing_key.to_bytes(), &self.public_key_hex())
    }
}

pub fn create_wallet(
    passphrase: &str,
    created_at: u64,
) -> Result<(OpenedWallet, Zeroizing<String>)> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(seed.as_mut());
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let signing_key = SigningKey::from_bytes(&seed);
    let encoded = encrypt_wallet(&signing_key, passphrase, created_at, salt, nonce)?;
    Ok((
        OpenedWallet::from_signing_key(signing_key, created_at),
        encoded,
    ))
}

pub fn create_wallet_for_vector(
    passphrase: &str,
    created_at: u64,
    material: DeterministicWalletMaterial,
) -> Result<Zeroizing<String>> {
    let signing_key = SigningKey::from_bytes(&material.seed);
    encrypt_wallet(
        &signing_key,
        passphrase,
        created_at,
        material.salt,
        material.nonce,
    )
}

fn encrypt_wallet(
    signing_key: &SigningKey,
    passphrase: &str,
    created_at: u64,
    salt: [u8; 16],
    nonce: [u8; 12],
) -> Result<Zeroizing<String>> {
    let public_key = signing_key.verifying_key().to_bytes();
    let header = Header {
        schema: OUTER_SCHEMA.into(),
        key_suite: "Ed25519".into(),
        public_key: hex::encode(public_key),
        created_at,
        kdf: KdfHeader {
            name: "Argon2id".into(),
            version: 19,
            salt: URL_SAFE_NO_PAD.encode(salt),
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
            derived_key_bytes: 32,
        },
        aead: AeadHeader {
            name: "AES-256-GCM".into(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            tag_bits: 128,
        },
    };
    let aad = jcs_to_vec(&header)?;
    let mut pkcs8 = Zeroizing::new(Vec::with_capacity(48));
    pkcs8.extend_from_slice(&ED25519_PKCS8_PREFIX);
    pkcs8.extend_from_slice(&signing_key.to_bytes());
    let secret = SecretPlaintext {
        schema: SECRET_SCHEMA.into(),
        key_id: blake3::hash(&public_key).to_hex().to_string(),
        private_key_pkcs8: URL_SAFE_NO_PAD.encode(pkcs8.as_slice()),
        created_at,
    };
    let mut plaintext = Zeroizing::new(jcs_to_vec(&secret)?);
    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(closed)?;
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(closed)?;
    plaintext.zeroize();
    let container = Container {
        schema: header.schema,
        key_suite: header.key_suite,
        public_key: header.public_key,
        created_at: header.created_at,
        kdf: header.kdf,
        aead: header.aead,
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    Ok(Zeroizing::new(
        String::from_utf8(jcs_to_vec(&container)?).map_err(closed)?,
    ))
}

pub fn import_wallet(encoded: &[u8], passphrase: &str) -> Result<OpenedWallet> {
    if encoded.is_empty() || encoded.len() > MAX_WALLET_BYTES {
        return Err(CustodyError::InvalidWalletFile);
    }
    let container: Container = serde_json::from_slice(encoded).map_err(closed)?;
    validate_header(&container)?;
    let salt = decode_exact::<16>(&container.kdf.salt)?;
    let nonce = decode_exact::<12>(&container.aead.nonce)?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(container.ciphertext.as_bytes())
        .map_err(closed)?;
    if ciphertext.len() < 16 {
        return Err(CustodyError::InvalidWalletFile);
    }
    let aad = jcs_to_vec(&container.header())?;
    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(closed)?;
    let plaintext = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        .map_err(closed)?;
    let mut plaintext = Zeroizing::new(plaintext);
    let secret: SecretPlaintext = serde_json::from_slice(&plaintext).map_err(closed)?;
    if secret.schema != SECRET_SCHEMA || secret.created_at != container.created_at {
        return Err(CustodyError::InvalidWalletFile);
    }
    let mut pkcs8 = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(secret.private_key_pkcs8.as_bytes())
            .map_err(closed)?,
    );
    let signing_key = SigningKey::from_pkcs8_der(&pkcs8).map_err(closed)?;
    let derived_public = signing_key.verifying_key().to_bytes();
    let outer_public = decode_hex_32(&container.public_key)?;
    let derived_key_id = blake3::hash(&derived_public);
    let claimed_key_id = decode_hex_32(&secret.key_id)?;
    if !bool::from(derived_public.ct_eq(&outer_public))
        || !bool::from(derived_key_id.as_bytes().ct_eq(&claimed_key_id))
    {
        return Err(CustodyError::InvalidWalletFile);
    }
    plaintext.zeroize();
    pkcs8.zeroize();
    Ok(OpenedWallet::from_signing_key(
        signing_key,
        container.created_at,
    ))
}

fn validate_header(container: &Container) -> Result<()> {
    if container.schema != OUTER_SCHEMA
        || container.key_suite != "Ed25519"
        || container.kdf.name != "Argon2id"
        || container.kdf.version != 19
        || container.kdf.memory_kib != 65_536
        || container.kdf.iterations != 3
        || container.kdf.parallelism != 1
        || container.kdf.derived_key_bytes != 32
        || container.aead.name != "AES-256-GCM"
        || container.aead.tag_bits != 128
    {
        return Err(CustodyError::InvalidWalletFile);
    }
    decode_hex_32(&container.public_key)?;
    Ok(())
}

fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let normalized: Zeroizing<String> = Zeroizing::new(passphrase.nfc().collect());
    if normalized.is_empty() {
        return Err(CustodyError::InvalidWalletFile);
    }
    let params = Params::new(65_536, 3, 1, Some(32)).map_err(closed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(normalized.as_bytes(), salt, key.as_mut())
        .map_err(closed)?;
    Ok(key)
}

fn decode_exact<const N: usize>(encoded: &str) -> Result<[u8; N]> {
    let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(closed)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(CustodyError::InvalidWalletFile);
    }
    decoded.try_into().map_err(closed)
}

fn decode_hex_32(encoded: &str) -> Result<[u8; 32]> {
    if encoded.len() != 64
        || encoded
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(CustodyError::InvalidWalletFile);
    }
    hex::decode(encoded)
        .map_err(closed)?
        .try_into()
        .map_err(closed)
}

fn closed<T>(_: T) -> CustodyError {
    CustodyError::InvalidWalletFile
}

fn jcs_to_vec(value: &impl Serialize) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(closed)?;
    serde_jcs::to_vec(&value).map_err(closed)
}

#[wasm_bindgen]
pub struct WasmWallet {
    inner: Option<OpenedWallet>,
    work_epoch: std::rc::Rc<()>,
}

#[wasm_bindgen]
impl WasmWallet {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: None,
            work_epoch: std::rc::Rc::new(()),
        }
    }

    #[wasm_bindgen(js_name = create)]
    pub fn create(
        &mut self,
        passphrase: &str,
        created_at: u64,
    ) -> core::result::Result<String, JsValue> {
        let (wallet, encoded) = create_wallet(passphrase, created_at).map_err(js_closed)?;
        self.work_epoch = std::rc::Rc::new(());
        self.inner = Some(wallet);
        Ok(encoded.to_string())
    }

    #[wasm_bindgen(js_name = unlock)]
    pub fn unlock(
        &mut self,
        encoded: &[u8],
        passphrase: &str,
    ) -> core::result::Result<String, JsValue> {
        let wallet = import_wallet(encoded, passphrase).map_err(js_closed)?;
        let public_key = wallet.public_key_hex();
        self.work_epoch = std::rc::Rc::new(());
        self.inner = Some(wallet);
        Ok(public_key)
    }

    #[wasm_bindgen(js_name = exportRandomized)]
    pub fn export_randomized(&self, passphrase: &str) -> core::result::Result<String, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .export_randomized(passphrase)
            .map(|value| value.to_string())
            .map_err(js_closed)
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> core::result::Result<String, JsValue> {
        self.inner
            .as_ref()
            .map(OpenedWallet::public_key_hex)
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))
    }

    #[wasm_bindgen(js_name = mlDsaPublicKey)]
    pub fn ml_dsa_public_key(&self) -> core::result::Result<String, JsValue> {
        self.inner
            .as_ref()
            .map(OpenedWallet::ml_dsa_public_key_base64url)
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))
    }

    #[wasm_bindgen(js_name = mlDsaPublicKeyCommitment)]
    pub fn ml_dsa_public_key_commitment(&self) -> core::result::Result<String, JsValue> {
        self.inner
            .as_ref()
            .map(OpenedWallet::ml_dsa_public_key_commitment_hex)
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))
    }

    #[wasm_bindgen(js_name = chainAccounts)]
    pub fn chain_accounts(&self) -> core::result::Result<String, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .chain_accounts()
            .map_err(js_closed)
    }

    #[wasm_bindgen(js_name = validateCastawayDescriptors)]
    pub fn validate_castaway_descriptors(
        &self,
        value: &str,
    ) -> core::result::Result<String, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .validate_castaway_descriptors(value)
            .map_err(js_closed)
    }
    #[wasm_bindgen(js_name = validateWalletIdentities)]
    pub fn validate_wallet_identities(&self, value: &str) -> core::result::Result<String, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .validate_wallet_identities(value)
            .map_err(js_closed)
    }
    #[wasm_bindgen(js_name = mergeWalletIdentities)]
    pub fn merge_wallet_identities(
        &self,
        current: &str,
        incoming: &str,
    ) -> core::result::Result<String, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .merge_wallet_identities(current, incoming)
            .map_err(js_closed)
    }
    #[wasm_bindgen(js_name = sealIdentitySection)]
    pub fn seal_identity_section(&self, value: &str) -> core::result::Result<String, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .seal_identity_section(value)
            .map(|v| v.to_string())
            .map_err(js_closed)
    }
    #[wasm_bindgen(js_name = openIdentitySection)]
    pub fn open_identity_section(&self, value: &[u8]) -> core::result::Result<String, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .open_identity_section(value)
            .map(|v| v.to_string())
            .map_err(js_closed)
    }
    #[wasm_bindgen(js_name = exportCastaway)]
    pub fn export_castaway(
        &self,
        value: &str,
        password: &str,
        now: u64,
    ) -> core::result::Result<String, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .export_castaway(value, password, now)
            .map(|v| v.to_string())
            .map_err(js_closed)
    }
    #[wasm_bindgen(js_name = importCastaway)]
    pub fn import_castaway(
        &self,
        value: &[u8],
        password: &str,
    ) -> core::result::Result<String, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .import_castaway(value, password)
            .map(|v| v.to_string())
            .map_err(js_closed)
    }
    #[wasm_bindgen(js_name = wrapFilesKey)]
    pub fn wrap_files_key(
        &self,
        binding: &str,
        key: Vec<u8>,
    ) -> core::result::Result<String, JsValue> {
        let key = Zeroizing::new(key);
        self.inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .wrap_files_key(binding, &key)
            .map_err(js_closed)
    }

    #[wasm_bindgen(js_name = unwrapFilesKey)]
    pub fn unwrap_files_key(
        &self,
        binding: &str,
        envelope: &str,
    ) -> core::result::Result<js_sys::Uint8Array, JsValue> {
        let key = self
            .inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .unwrap_files_key(binding, envelope)
            .map_err(js_closed)?;
        // Copy to the approved JS result before Zeroizing wipes the WASM plaintext.
        Ok(js_sys::Uint8Array::from(key.as_slice()))
    }

    #[wasm_bindgen(js_name = signFilesServiceAuthentication)]
    pub fn sign_files_service_authentication(
        &self,
        challenge: &str,
        origin: &str,
        kind: &str,
        service_id: &str,
        now_ms: u64,
    ) -> core::result::Result<Vec<u8>, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .sign_files_service_authentication(challenge, origin, kind, service_id, now_ms)
            .map(|signature| signature.to_vec())
            .map_err(js_closed)
    }

    #[wasm_bindgen(js_name = sign)]
    pub fn sign(&self, message: &[u8]) -> core::result::Result<Vec<u8>, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .sign(message)
            .map(|signature| signature.to_vec())
            .map_err(js_closed)
    }

    #[wasm_bindgen(js_name = signDreggPq)]
    pub fn sign_dregg_pq(&self, message: &[u8]) -> core::result::Result<Vec<u8>, JsValue> {
        self.inner
            .as_ref()
            .ok_or_else(|| js_closed(CustodyError::InvalidWalletFile))?
            .sign_dregg_pq(message)
            .map_err(js_closed)
    }

    pub fn lock(&mut self) {
        self.work_epoch = std::rc::Rc::new(());
        self.inner = None;
    }
}

impl Default for WasmWallet {
    fn default() -> Self {
        Self::new()
    }
}

fn js_closed(_: CustodyError) -> JsValue {
    JsValue::from_str("invalid_wallet_file")
}

/// Worker-owned recovery session. Native and WASM adapters share its state machine.
#[wasm_bindgen]
pub struct WasmRecoverySession {
    inner: recovery_session::RecoverySession,
}
#[wasm_bindgen]
impl WasmRecoverySession {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: recovery_session::RecoverySession::new(),
        }
    }
    pub fn invoke(&mut self, request: &str) -> std::result::Result<String, JsValue> {
        self.inner
            .invoke(request)
            .and_then(|value| serde_json::to_string(&value).map_err(|_| "encoding_failed"))
            .map_err(JsValue::from_str)
    }
}
impl Default for WasmRecoverySession {
    fn default() -> Self {
        Self::new()
    }
}

pub mod holder_grants;
pub mod holder_session_custody;
#[cfg(test)]
mod holder_session_tests;
pub mod holder_sessions;
pub mod portable_holder_grants;
pub mod scoped_holder_grants;
pub mod session_signer;

#[cfg(all(feature = "funding-fixtures", target_arch = "wasm32"))]
compile_error!("funding-fixtures is a native-only synthetic test interface");
#[cfg(all(feature = "funding-fixtures", not(target_arch = "wasm32")))]
pub mod funding_fixture;
