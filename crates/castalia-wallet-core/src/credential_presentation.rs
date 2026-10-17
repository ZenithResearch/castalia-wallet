//! Generic issuer-authorized presentations in existing custody. No application schemas.
use crate::{OpenedWallet, WasmWallet};
use castalia_wallet_presentation::{
    Caller, MAX_ENVELOPE_BYTES, MAX_SAFE, PreparedRequest, TrustPin, complete, parse,
    prepare_request,
};
use ed25519_dalek::Signer as _;
use wasm_bindgen::prelude::*;
type Result<T> = core::result::Result<T, &'static str>;

impl OpenedWallet {
    pub fn prepare_credential_presentation(
        &self,
        raw: &[u8],
        pins: &[TrustPin],
        caller: &Caller,
        now: u64,
    ) -> Result<PreparedRequest> {
        prepare_request(raw, pins, caller, &self.public_key_hex(), now)
    }
    pub fn approve_credential_presentation(
        &self,
        request: PreparedRequest,
        now: u64,
        nonce: &[u8; 16],
    ) -> Result<Vec<u8>> {
        if request.holder_public_key() != self.public_key_hex() {
            return Err("credential_identity_changed");
        }
        let prepared = request.prepare_presentation(now, nonce)?;
        let signature = self
            .signing_key
            .sign(prepared.signature_transcript())
            .to_bytes();
        complete(prepared, &signature)?.canonical()
    }
}
#[wasm_bindgen]
pub struct WasmCredentialPresentation {
    inner: Option<PreparedRequest>,
    epoch: std::rc::Rc<()>,
}
#[wasm_bindgen]
impl WasmCredentialPresentation {
    pub fn summary(&self) -> core::result::Result<String, JsValue> {
        let bytes = self
            .inner
            .as_ref()
            .ok_or_else(|| closed("disposed_credential_request"))?
            .summary()
            .map_err(closed)?;
        String::from_utf8(bytes).map_err(|_| closed("encoding_failed"))
    }
    #[wasm_bindgen(js_name = canonicalRequest)]
    pub fn canonical_request(&self) -> core::result::Result<Vec<u8>, JsValue> {
        Ok(self
            .inner
            .as_ref()
            .ok_or_else(|| closed("disposed_credential_request"))?
            .canonical_request()
            .to_vec())
    }
    pub fn dispose(&mut self) {
        self.inner = None;
    }
}
#[wasm_bindgen]
impl WasmWallet {
    #[wasm_bindgen(js_name = prepareCredentialPresentation)]
    pub fn prepare_credential_presentation(
        &self,
        raw: &[u8],
        trusted_pins_json: &str,
        expected_caller_json: &str,
        now_seconds: &str,
    ) -> core::result::Result<WasmCredentialPresentation, JsValue> {
        let now = clock(now_seconds).map_err(closed)?;
        let wallet = self.inner.as_ref().ok_or_else(|| closed("wallet_locked"))?;
        let pins: Vec<TrustPin> =
            parse(trusted_pins_json.as_bytes(), MAX_ENVELOPE_BYTES).map_err(closed)?;
        let caller: Caller = parse(expected_caller_json.as_bytes(), 1024).map_err(closed)?;
        let prepared = wallet
            .prepare_credential_presentation(raw, &pins, &caller, now)
            .map_err(closed)?;
        Ok(WasmCredentialPresentation {
            inner: Some(prepared),
            epoch: std::rc::Rc::clone(&self.work_epoch),
        })
    }
    #[wasm_bindgen(js_name = approveCredentialPresentation)]
    pub fn approve_credential_presentation(
        &self,
        prepared: &mut WasmCredentialPresentation,
        now_seconds: &str,
    ) -> core::result::Result<String, JsValue> {
        let request = prepared
            .inner
            .take()
            .ok_or_else(|| closed("disposed_credential_request"))?;
        let now = clock(now_seconds).map_err(closed)?;
        if !std::rc::Rc::ptr_eq(&prepared.epoch, &self.work_epoch) {
            return Err(closed("credential_identity_changed"));
        }
        let wallet = self.inner.as_ref().ok_or_else(|| closed("wallet_locked"))?;
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| closed("randomness_unavailable"))?;
        let bytes = wallet
            .approve_credential_presentation(request, now, &nonce)
            .map_err(closed)?;
        String::from_utf8(bytes).map_err(|_| closed("encoding_failed"))
    }
}
fn clock(value: &str) -> Result<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("invalid_clock");
    }
    let now: u64 = value.parse().map_err(|_| "invalid_clock")?;
    if now > MAX_SAFE - 120 {
        return Err("invalid_clock");
    }
    Ok(now)
}
fn closed(code: &'static str) -> JsValue {
    JsValue::from_str(code)
}
