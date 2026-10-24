//! First-party Web adapter over the same custody core as native and extension.
//! Retains the published Web v1 formats; it does not install trust or membership.
use crate::{
    CustodyError, OpenedWallet, Result, closed, create_wallet, decode_exact, derive_key,
    import_wallet, portable::parse_unique,
};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const MAX: usize = 1_048_576;
const MAGIC: &[u8] = b"castalia.files-folder-backup.v1\0";
const FRAME: usize = 1_048_576;
const MAX_ZIP: usize = 128 * FRAME;
const HEADER: usize = MAGIC.len() + 4 + 12 + 12 + 56;
const LOCAL_DOMAIN: &str = "castalia/castaway-local-section/v1";
const BACKUP_DOMAIN: &str = "castalia/files-folder-backup/wrapping/v1";

fn invalid() -> CustodyError {
    CustodyError::InvalidWalletFile
}
fn exact(value: &Value, fields: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != fields.len() || fields.iter().any(|k| !object.contains_key(*k)) {
        return Err(invalid());
    }
    Ok(())
}
fn object(raw: &str) -> Result<Value> {
    if raw.is_empty() || raw.len() > MAX {
        return Err(invalid());
    }
    let value = parse_unique(raw).map_err(closed)?;
    if !value.is_object() {
        return Err(invalid());
    }
    Ok(value)
}
fn canonical(value: &Value) -> Result<Vec<u8>> {
    serde_jcs::to_vec(value).map_err(closed)
}
fn aead(nonce: &[u8; 12]) -> Value {
    json!({"name":"AES-256-GCM","nonce":B64.encode(nonce),"tagBits":128})
}
fn nonce(value: &Value) -> Result<[u8; 12]> {
    exact(value, &["name", "nonce", "tagBits"])?;
    if value["name"] != "AES-256-GCM" || value["tagBits"] != 128 {
        return Err(invalid());
    }
    decode_exact(value["nonce"].as_str().ok_or_else(invalid)?)
}
fn encrypt(key: &[u8], nonce: &[u8; 12], aad: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
    Aes256Gcm::new_from_slice(key)
        .map_err(closed)?
        .encrypt(nonce.into(), Payload { msg: bytes, aad })
        .map_err(closed)
}
fn decrypt(key: &[u8], nonce: &[u8; 12], aad: &[u8], bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    Aes256Gcm::new_from_slice(key)
        .map_err(closed)?
        .decrypt(nonce.into(), Payload { msg: bytes, aad })
        .map(Zeroizing::new)
        .map_err(closed)
}
fn seal(
    mut header: Value,
    value: &Value,
    key: &[u8],
    nonce: &[u8; 12],
) -> Result<Zeroizing<String>> {
    let plaintext = Zeroizing::new(canonical(value)?);
    let bytes = encrypt(key, nonce, &canonical(&header)?, &plaintext)?;
    header["ciphertext"] = json!(B64.encode(bytes));
    let encoded = serde_jcs::to_string(&header).map_err(closed)?;
    if encoded.len() > MAX {
        return Err(invalid());
    }
    Ok(Zeroizing::new(encoded))
}
fn open(mut envelope: Value, key: &[u8]) -> Result<Zeroizing<String>> {
    let nonce = nonce(&envelope["aead"])?;
    let encoded = envelope
        .as_object_mut()
        .ok_or_else(invalid)?
        .remove("ciphertext")
        .ok_or_else(invalid)?;
    let encoded = encoded.as_str().ok_or_else(invalid)?;
    let bytes = B64.decode(encoded).map_err(closed)?;
    if B64.encode(&bytes) != encoded || bytes.len() < 16 {
        return Err(invalid());
    }
    let plaintext = decrypt(key, &nonce, &canonical(&envelope)?, &bytes)?;
    let text = Zeroizing::new(String::from_utf8(plaintext.to_vec()).map_err(closed)?);
    object(&text)?;
    Ok(text)
}
fn data_contents(value: &Value) -> Result<()> {
    exact(value, &["schema", "version", "sections"])?;
    if value["schema"] != "castalia.castaway-contents.v1" || value["version"] != 1 {
        return Err(invalid());
    }
    let sections = value["sections"].as_object().ok_or_else(invalid)?;
    if !sections.get("identity").is_some_and(Value::is_object)
        || sections.keys().any(|k| {
            ![
                "identity",
                "memberships",
                "scopedMemberships",
                "chainAccounts",
            ]
            .contains(&k.as_str())
        })
        || ["memberships", "scopedMemberships"]
            .iter()
            .any(|k| sections.get(*k).is_some_and(|v| !v.is_array()))
    {
        return Err(invalid());
    }
    if let Some(value) = sections.get("chainAccounts") {
        let section: crate::ChainAccountsSection =
            serde_json::from_value(value.clone()).map_err(closed)?;
        if section.schema != "zenith.chain-accounts-section.v1"
            || section.version != 1
            || section.authority != "descriptor-only"
            || section.recovery != "castalia.wallet-custody.v1"
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub fn restore_wallet_from_recovery_key(
    key: &str,
    password: &str,
    created_at: u64,
) -> Result<(OpenedWallet, Zeroizing<String>)> {
    let parts: Vec<_> = key.split('.').collect();
    if parts.len() != 3 || parts[0] != "castalia-recovery-key-v1" {
        return Err(invalid());
    }
    let seed = Zeroizing::new(decode_exact::<32>(parts[1])?);
    let checksum = decode_exact::<4>(parts[2])?;
    let mut h = blake3::Hasher::new();
    h.update(b"castalia/recovery-key/v1\0");
    h.update(seed.as_ref());
    if !bool::from(checksum.ct_eq(&h.finalize().as_bytes()[..4])) {
        return Err(invalid());
    }
    let wallet = OpenedWallet::from_signing_key(SigningKey::from_bytes(&seed), created_at);
    let file = wallet.export_randomized(password)?;
    Ok((wallet, file))
}

impl OpenedWallet {
    fn web_key(&self, domain: &str) -> Zeroizing<[u8; 32]> {
        let seed = Zeroizing::new(self.signing_key.to_bytes());
        Zeroizing::new(blake3::derive_key(domain, seed.as_ref()))
    }
    pub fn recovery_key(&self) -> Zeroizing<String> {
        let seed = Zeroizing::new(self.signing_key.to_bytes());
        let mut h = blake3::Hasher::new();
        h.update(b"castalia/recovery-key/v1\0");
        h.update(seed.as_ref());
        Zeroizing::new(format!(
            "castalia-recovery-key-v1.{}.{}",
            B64.encode(seed.as_ref()),
            B64.encode(&h.finalize().as_bytes()[..4])
        ))
    }
    pub fn sign_zenith_membership_join(&self) -> [u8; 64] {
        let mut bytes = b"castalia/zenith-membership-join/v3\0".to_vec();
        bytes.extend(self.signing_key.verifying_key().to_bytes());
        self.signing_key.sign(&bytes).to_bytes()
    }
    pub fn sign_scoped_membership_join(&self, scope: &str) -> Result<[u8; 64]> {
        let scope = crate::decode_hex_32(scope)?;
        let mut bytes = b"castalia/scoped-membership-join/v4\0".to_vec();
        bytes.extend(self.signing_key.verifying_key().to_bytes());
        bytes.extend(scope);
        Ok(self.signing_key.sign(&bytes).to_bytes())
    }
    pub fn seal_identity_section(&self, raw: &str) -> Result<Zeroizing<String>> {
        let value = object(raw)?;
        let mut n = [0; 12];
        OsRng.fill_bytes(&mut n);
        seal(
            json!({"schema":"castalia.castaway-local-section.v1","ownerPublicKey":self.public_key_hex(),"keyDerivation":"BLAKE3-DERIVE-KEY","aead":aead(&n)}),
            &value,
            self.web_key(LOCAL_DOMAIN).as_ref(),
            &n,
        )
    }
    pub fn open_identity_section(&self, raw: &[u8]) -> Result<Zeroizing<String>> {
        let value = object(std::str::from_utf8(raw).map_err(closed)?)?;
        exact(
            &value,
            &[
                "schema",
                "ownerPublicKey",
                "keyDerivation",
                "aead",
                "ciphertext",
            ],
        )?;
        if value["schema"] != "castalia.castaway-local-section.v1"
            || value["ownerPublicKey"] != self.public_key_hex()
            || value["keyDerivation"] != "BLAKE3-DERIVE-KEY"
        {
            return Err(invalid());
        }
        open(value, self.web_key(LOCAL_DOMAIN).as_ref())
    }
    pub fn export_castaway(
        &self,
        raw: &str,
        password: &str,
        time: u64,
    ) -> Result<Zeroizing<String>> {
        let value = object(raw)?;
        data_contents(&value)?;
        let mut salt = [0; 16];
        let mut n = [0; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut n);
        seal(
            json!({"schema":"castalia.castaway.v1","contentsSchema":"castalia.castaway-contents.v1","ownerPublicKey":self.public_key_hex(),"exportedAt":time,"kdf":{"name":"Argon2id","version":19,"salt":B64.encode(salt),"memoryKiB":65536,"iterations":3,"parallelism":1,"derivedKeyBytes":32},"aead":aead(&n)}),
            &value,
            derive_key(password, &salt)?.as_ref(),
            &n,
        )
    }
    pub fn import_castaway(&self, raw: &[u8], password: &str) -> Result<Zeroizing<String>> {
        let value = object(std::str::from_utf8(raw).map_err(closed)?)?;
        exact(
            &value,
            &[
                "schema",
                "contentsSchema",
                "ownerPublicKey",
                "exportedAt",
                "kdf",
                "aead",
                "ciphertext",
            ],
        )?;
        if value["schema"] != "castalia.castaway.v1"
            || value["contentsSchema"] != "castalia.castaway-contents.v1"
            || value["ownerPublicKey"] != self.public_key_hex()
            || value["exportedAt"].as_u64().is_none()
        {
            return Err(invalid());
        }
        let kdf: crate::KdfHeader = serde_json::from_value(value["kdf"].clone()).map_err(closed)?;
        if kdf.name != "Argon2id"
            || kdf.version != 19
            || kdf.memory_kib != 65536
            || kdf.iterations != 3
            || kdf.parallelism != 1
            || kdf.derived_key_bytes != 32
        {
            return Err(invalid());
        }
        let key = derive_key(password, &decode_exact::<16>(&kdf.salt)?)?;
        let plaintext = open(value, key.as_ref())?;
        data_contents(&object(&plaintext)?)?;
        Ok(plaintext)
    }
    pub fn seal_files_backup(&self, zip: &[u8]) -> Result<Vec<u8>> {
        if zip.is_empty() || zip.len() > MAX_ZIP {
            return Err(invalid());
        }
        let mut key = Zeroizing::new([0; 32]);
        let mut wrap = [0; 12];
        let mut frame = [0; 12];
        OsRng.fill_bytes(key.as_mut());
        OsRng.fill_bytes(&mut wrap);
        OsRng.fill_bytes(&mut frame);
        let mut header = MAGIC.to_vec();
        header.extend((FRAME as u32).to_be_bytes());
        header.extend(wrap);
        header.extend(frame);
        let mut wrapped = Zeroizing::new(key.to_vec());
        wrapped.extend((zip.len() as u64).to_be_bytes());
        header.extend(encrypt(
            self.web_key(BACKUP_DOMAIN).as_ref(),
            &wrap,
            &header,
            &wrapped,
        )?);
        let mut result = header.clone();
        for (index, chunk) in zip.chunks(FRAME).enumerate() {
            let mut nonce = frame;
            nonce[8..].copy_from_slice(&(index as u32).to_be_bytes());
            let mut aad = header.clone();
            aad.extend((index as u32).to_be_bytes());
            aad.extend((chunk.len() as u32).to_be_bytes());
            aad.push(u8::from(index == (zip.len() - 1) / FRAME));
            result.extend((chunk.len() as u32).to_be_bytes());
            result.extend(encrypt(key.as_ref(), &nonce, &aad, chunk)?);
        }
        Ok(result)
    }
    pub fn open_files_backup(&self, file: &[u8]) -> Result<Vec<u8>> {
        if file.len() < HEADER
            || file.len() > HEADER + MAX_ZIP + (MAX_ZIP / FRAME + 1) * 20
            || !file.starts_with(MAGIC)
        {
            return Err(invalid());
        }
        let offset = MAGIC.len();
        if file[offset..offset + 4] != (FRAME as u32).to_be_bytes() {
            return Err(invalid());
        }
        let wrap: [u8; 12] = file[offset + 4..offset + 16].try_into().map_err(closed)?;
        let frame: [u8; 12] = file[offset + 16..offset + 28].try_into().map_err(closed)?;
        let unwrapped = decrypt(
            self.web_key(BACKUP_DOMAIN).as_ref(),
            &wrap,
            &file[..HEADER - 56],
            &file[HEADER - 56..HEADER],
        )?;
        if unwrapped.len() != 40 {
            return Err(invalid());
        }
        let total = u64::from_be_bytes(unwrapped[32..40].try_into().map_err(closed)?);
        if total == 0 || total > MAX_ZIP as u64 {
            return Err(invalid());
        }
        let total = total as usize;
        let count = total.div_ceil(FRAME);
        let mut result = Vec::with_capacity(total);
        let mut cursor = HEADER;
        for index in 0..count {
            let length = u32::from_be_bytes(
                file.get(cursor..cursor + 4)
                    .ok_or_else(invalid)?
                    .try_into()
                    .map_err(closed)?,
            ) as usize;
            cursor += 4;
            if length != (total - result.len()).min(FRAME) {
                return Err(invalid());
            }
            let bytes = file.get(cursor..cursor + length + 16).ok_or_else(invalid)?;
            let mut nonce = frame;
            nonce[8..].copy_from_slice(&(index as u32).to_be_bytes());
            let mut aad = file[..HEADER].to_vec();
            aad.extend((index as u32).to_be_bytes());
            aad.extend((length as u32).to_be_bytes());
            aad.push(u8::from(index + 1 == count));
            let plain = decrypt(&unwrapped[..32], &nonce, &aad, bytes)?;
            result.extend_from_slice(&plain);
            cursor += length + 16;
        }
        if cursor != file.len() || result.len() != total {
            return Err(invalid());
        }
        Ok(result)
    }
}

#[wasm_bindgen]
#[derive(Default)]
pub struct WebWalletCustody {
    inner: Option<OpenedWallet>,
}
fn js_closed(_: CustodyError) -> JsValue {
    JsValue::from_str("invalid_wallet_file")
}
impl WebWalletCustody {
    fn wallet(&self) -> core::result::Result<&OpenedWallet, JsValue> {
        self.inner.as_ref().ok_or_else(|| js_closed(invalid()))
    }
}
#[wasm_bindgen]
impl WebWalletCustody {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn create(&mut self, password: &str, time: u64) -> core::result::Result<String, JsValue> {
        let (w, file) = create_wallet(password, time).map_err(js_closed)?;
        self.inner = Some(w);
        Ok(file.to_string())
    }
    #[wasm_bindgen(js_name=restoreFromRecoveryKey)]
    pub fn restore(
        &mut self,
        key: &str,
        password: &str,
        time: u64,
    ) -> core::result::Result<String, JsValue> {
        let (w, file) = restore_wallet_from_recovery_key(key, password, time).map_err(js_closed)?;
        self.inner = Some(w);
        Ok(file.to_string())
    }
    pub fn unlock(&mut self, file: &[u8], password: &str) -> core::result::Result<String, JsValue> {
        let w = import_wallet(file, password).map_err(js_closed)?;
        let public = w.public_key_hex();
        self.inner = Some(w);
        Ok(public)
    }
    #[wasm_bindgen(js_name=exportRandomized)]
    pub fn export(&self, password: &str) -> core::result::Result<String, JsValue> {
        self.wallet()?
            .export_randomized(password)
            .map(|v| v.to_string())
            .map_err(js_closed)
    }
    #[wasm_bindgen(js_name=publicKey)]
    pub fn public_key(&self) -> core::result::Result<String, JsValue> {
        Ok(self.wallet()?.public_key_hex())
    }
    #[wasm_bindgen(js_name=mlDsaPublicKey)]
    pub fn ml_dsa_public_key(&self) -> core::result::Result<String, JsValue> {
        Ok(self.wallet()?.ml_dsa_public_key_base64url())
    }
    #[wasm_bindgen(js_name=mlDsaPublicKeyCommitment)]
    pub fn commitment(&self) -> core::result::Result<String, JsValue> {
        Ok(self.wallet()?.ml_dsa_public_key_commitment_hex())
    }
    #[wasm_bindgen(js_name=chainAccounts)]
    pub fn accounts(&self) -> core::result::Result<String, JsValue> {
        self.wallet()?.chain_accounts().map_err(js_closed)
    }
    #[wasm_bindgen(js_name=recoveryKey)]
    pub fn recovery_key(&self) -> core::result::Result<String, JsValue> {
        Ok(self.wallet()?.recovery_key().to_string())
    }
    #[wasm_bindgen(js_name=signZenithMembershipJoin)]
    pub fn join(&self) -> core::result::Result<Vec<u8>, JsValue> {
        Ok(self.wallet()?.sign_zenith_membership_join().to_vec())
    }
    #[wasm_bindgen(js_name=signScopedMembershipJoin)]
    pub fn scoped_join(&self, scope: &str) -> core::result::Result<Vec<u8>, JsValue> {
        self.wallet()?
            .sign_scoped_membership_join(scope)
            .map(|v| v.to_vec())
            .map_err(js_closed)
    }
    #[wasm_bindgen(js_name=signDreggPq)]
    pub fn sign_dregg_pq(&self, bytes: &[u8]) -> core::result::Result<Vec<u8>, JsValue> {
        self.wallet()?.sign_dregg_pq(bytes).map_err(js_closed)
    }
    #[wasm_bindgen(js_name=sealIdentitySection)]
    pub fn seal_identity(&self, value: &str) -> core::result::Result<String, JsValue> {
        self.wallet()?
            .seal_identity_section(value)
            .map(|v| v.to_string())
            .map_err(js_closed)
    }
    #[wasm_bindgen(js_name=openIdentitySection)]
    pub fn open_identity(&self, value: &[u8]) -> core::result::Result<String, JsValue> {
        self.wallet()?
            .open_identity_section(value)
            .map(|v| v.to_string())
            .map_err(js_closed)
    }
    #[wasm_bindgen(js_name=exportCastaway)]
    pub fn export_data(
        &self,
        value: &str,
        password: &str,
        time: u64,
    ) -> core::result::Result<String, JsValue> {
        self.wallet()?
            .export_castaway(value, password, time)
            .map(|v| v.to_string())
            .map_err(js_closed)
    }
    #[wasm_bindgen(js_name=importCastaway)]
    pub fn import_data(
        &self,
        value: &[u8],
        password: &str,
    ) -> core::result::Result<String, JsValue> {
        self.wallet()?
            .import_castaway(value, password)
            .map(|v| v.to_string())
            .map_err(js_closed)
    }
    #[wasm_bindgen(js_name=sealFilesBackup)]
    pub fn seal_files(&self, value: &[u8]) -> core::result::Result<Vec<u8>, JsValue> {
        self.wallet()?.seal_files_backup(value).map_err(js_closed)
    }
    #[wasm_bindgen(js_name=openFilesBackup)]
    pub fn open_files(&self, value: &[u8]) -> core::result::Result<Vec<u8>, JsValue> {
        self.wallet()?.open_files_backup(value).map_err(js_closed)
    }
    pub fn lock(&mut self) {
        self.inner = None;
    }
}
