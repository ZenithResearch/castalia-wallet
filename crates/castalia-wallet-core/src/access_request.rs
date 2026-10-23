//! Generic access-request consent, distinct from credential issuance and signing.
//! The service interprets details. Wallet discloses and binds them without
//! recognizing product names, granting rights, or exposing arbitrary signing.
use crate::{WasmWallet, browser_read::ReadSigner};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use castalia_wallet_presentation::{Caller, TrustPin, parse};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;
type Result<T> = core::result::Result<T, &'static str>;

pub const DOMAIN: &[u8] = b"castalia/access-request-approval/v1\0";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    schema: String,
    challenge_id: String,
    nonce: String,
    issuer: String,
    receiver: String,
    subject_public_key: String,
    installation_id: String,
    operation: String,
    issued_at: u64,
    expires_at: u64,
    details: Value,
}
fn hex_id(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn portable(value: &Value, depth: usize) -> bool {
    if depth > 16 {
        return false;
    }
    match value {
        Value::Number(n) => n
            .as_i64()
            .is_some_and(|v| v.unsigned_abs() <= 9_007_199_254_740_991),
        Value::Array(a) => a.iter().all(|v| portable(v, depth + 1)),
        Value::Object(o) => o
            .iter()
            .all(|(k, v)| k.is_ascii() && portable(v, depth + 1)),
        _ => true,
    }
}
fn parse_challenge(
    raw: &str,
    owner: &str,
    installation: &str,
    expected_receiver: &str,
    now: u64,
) -> Result<Challenge> {
    let value: Value = parse(raw.as_bytes(), 16384)?;
    if !portable(&value, 0) {
        return Err("invalid_access_request");
    }
    let c: Challenge = serde_json::from_value(value).map_err(|_| "invalid_access_request")?;
    let receiver = url::Url::parse(&c.receiver).map_err(|_| "invalid_access_request")?;
    if receiver.scheme() != "https"
        || receiver.origin().ascii_serialization() != c.receiver
        || expected_receiver != c.receiver
        || c.schema != "castalia.access-request-challenge.v1"
        || c.subject_public_key != owner
        || !hex_id(owner, 64)
        || c.installation_id != installation
        || !hex_id(installation, 32)
        || !hex_id(&c.challenge_id, 32)
        || c.issuer.is_empty()
        || c.issuer.len() > 256
        || !c.issuer.is_ascii()
        || c.issuer.bytes().any(|b| b.is_ascii_control())
        || c.issued_at > now
        || now >= c.expires_at
        || c.expires_at.checked_sub(c.issued_at) != Some(120)
        || !c.details.is_object()
        || !matches!(
            c.operation.as_str(),
            "access.request" | "access.status" | "access.inbox" | "access.review" | "access.decide"
        )
    {
        return Err("invalid_access_request");
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(&c.nonce)
        .map_err(|_| "invalid_access_request")?;
    if nonce.len() != 32 || URL_SAFE_NO_PAD.encode(nonce) != c.nonce {
        return Err("invalid_access_request");
    }
    Ok(c)
}

pub struct PreparedAccessRequest {
    challenge: Challenge,
    origin: String,
}
impl PreparedAccessRequest {
    pub fn prepare(
        raw: &str,
        owner: &str,
        installation: &str,
        pins: &[TrustPin],
        caller: &Caller,
        now: u64,
    ) -> Result<Self> {
        caller.validate()?;
        if caller.kind != "browser" {
            return Err("invalid_access_request");
        }
        let c = parse_challenge(raw, owner, installation, &caller.id, now)?;
        if !pins
            .iter()
            .any(|p| p.issuer == c.issuer && p.callers.contains(caller))
        {
            return Err("issuer_setup_required");
        }
        Ok(Self {
            challenge: c,
            origin: caller.id.clone(),
        })
    }
    /// Native consent uses the reviewed server pin, never a fabricated browser
    /// caller. This surface can request access or query its status, not decide
    /// grants or sign work. Browser transcript bytes remain unchanged.
    pub fn prepare_native(
        raw: &str,
        owner: &str,
        installation: &str,
        pin: &crate::read_access::IssuerPin,
        now: u64,
    ) -> Result<Self> {
        Self::prepare_native_for(raw, owner, installation, pin, now, false)
    }
    /// Explicit native operator consent. This does not grant administrator
    /// rights: the resource independently checks every signed action.
    pub fn prepare_native_operator(
        raw: &str,
        owner: &str,
        installation: &str,
        pin: &crate::read_access::IssuerPin,
        now: u64,
    ) -> Result<Self> {
        Self::prepare_native_for(raw, owner, installation, pin, now, true)
    }
    fn prepare_native_for(
        raw: &str,
        owner: &str,
        installation: &str,
        pin: &crate::read_access::IssuerPin,
        now: u64,
        operator: bool,
    ) -> Result<Self> {
        let c = parse_challenge(raw, owner, installation, &pin.receiver, now)?;
        if c.issuer != pin.issuer
            || !hex_id(&pin.public_key, 64)
            || pin.key_id.is_empty()
            || pin.key_id.len() > 256
            || pin.audience.is_empty()
            || pin.audience.len() > 256
            || !pin.key_id.is_ascii()
            || !pin.audience.is_ascii()
            || pin
                .key_id
                .bytes()
                .chain(pin.audience.bytes())
                .any(|b| b.is_ascii_control())
            || !(if operator {
                matches!(
                    c.operation.as_str(),
                    "access.inbox" | "access.review" | "access.decide" | "access.status"
                )
            } else {
                matches!(c.operation.as_str(), "access.request" | "access.status")
            })
        {
            return Err("invalid_access_request");
        }
        Ok(Self {
            origin: pin.receiver.clone(),
            challenge: c,
        })
    }
    pub fn summary(&self) -> Value {
        json!({"kind":"access_request","origin":self.origin,"issuer":self.challenge.issuer,
            "receiver":self.challenge.receiver,"operation":self.challenge.operation,
            "details":self.challenge.details,"expires_at":self.challenge.expires_at,
            "approval_expires_at":self.challenge.expires_at})
    }
    pub fn approve(self, wallet: &impl ReadSigner, now: u64) -> Result<Value> {
        if wallet.read_public_key() != self.challenge.subject_public_key
            || now < self.challenge.issued_at
            || now >= self.challenge.expires_at
        {
            return Err("access_approval_expired");
        }
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(serde_jcs::to_vec(&self.challenge).map_err(|_| "invalid_access_request")?);
        let signature = URL_SAFE_NO_PAD.encode(wallet.read_sign(&bytes)?);
        Ok(json!({"challenge":self.challenge,"signature":signature}))
    }
}
#[wasm_bindgen]
pub struct WasmAccessRequest {
    inner: Option<PreparedAccessRequest>,
    epoch: std::rc::Rc<()>,
}
#[wasm_bindgen]
impl WasmAccessRequest {
    pub fn summary(&self) -> core::result::Result<String, JsValue> {
        self.inner
            .as_ref()
            .map(|p| p.summary().to_string())
            .ok_or_else(|| JsValue::from_str("access_approval_unavailable"))
    }
    pub fn dispose(&mut self) {
        self.inner = None;
    }
}
#[wasm_bindgen]
impl WasmWallet {
    #[wasm_bindgen(js_name=prepareAccessRequest)]
    pub fn prepare_access_request(
        &self,
        raw: &str,
        installation: &str,
        pins: &str,
        caller: &str,
        now: &str,
    ) -> core::result::Result<WasmAccessRequest, JsValue> {
        let error = |e: &'static str| JsValue::from_str(e);
        let wallet = self.inner.as_ref().ok_or_else(|| error("wallet_locked"))?;
        let pins: Vec<TrustPin> = parse(pins.as_bytes(), 65536).map_err(error)?;
        let caller: Caller = parse(caller.as_bytes(), 1024).map_err(error)?;
        let clock: u64 = now.parse().map_err(|_| error("invalid_clock"))?;
        let prepared = PreparedAccessRequest::prepare(
            raw,
            &wallet.public_key_hex(),
            installation,
            &pins,
            &caller,
            clock,
        )
        .map_err(error)?;
        Ok(WasmAccessRequest {
            inner: Some(prepared),
            epoch: std::rc::Rc::clone(&self.work_epoch),
        })
    }
    #[wasm_bindgen(js_name=approveAccessRequest)]
    pub fn approve_access_request(
        &self,
        request: &mut WasmAccessRequest,
        now: &str,
    ) -> core::result::Result<String, JsValue> {
        let error = |e: &'static str| JsValue::from_str(e);
        let wallet = self.inner.as_ref().ok_or_else(|| error("wallet_locked"))?;
        if !std::rc::Rc::ptr_eq(&self.work_epoch, &request.epoch) {
            return Err(error("access_context_changed"));
        }
        let p = request
            .inner
            .take()
            .ok_or_else(|| error("access_approval_unavailable"))?;
        let clock: u64 = now.parse().map_err(|_| error("invalid_clock"))?;
        Ok(p.approve(wallet, clock).map_err(error)?.to_string())
    }
}
