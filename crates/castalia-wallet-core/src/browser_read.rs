//! Application-neutral browser read access in the existing custody core.
//! A page never receives key bytes, a signing handle, or arbitrary-signing RPCs.
use crate::{
    OpenedWallet, WasmWallet,
    read_access::{Challenge, SignedAccess},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use castalia_wallet_presentation::{
    Caller, TrustPin, parse,
    read_authority::{Call, Credential, Policy, Proof},
};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;
type Result<T> = core::result::Result<T, &'static str>;

/// Native custody adapter only. Implementations never expose this trait to pages.
pub trait ReadSigner {
    fn read_public_key(&self) -> String;
    fn read_sign(&self, message: &[u8]) -> Result<[u8; 64]>;
}
impl ReadSigner for OpenedWallet {
    fn read_public_key(&self) -> String {
        self.public_key_hex()
    }
    fn read_sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        self.sign(message).map_err(|_| "signing_failed")
    }
}

pub struct PreparedReadAccess {
    challenge: Challenge,
    policy: Policy,
    caller: Caller,
}
pub struct ApprovedReadAccess {
    challenge: Challenge,
    policy: Policy,
    caller: Caller,
    signature: String,
}
pub struct ReadConnection {
    pub access: SignedAccess,
    caller: Caller,
}
impl PreparedReadAccess {
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
            return Err("invalid_caller");
        }
        // Parse with a fixed upper bound before inspecting the unsigned proposal.
        let value: Value = parse(raw.as_bytes(), 16384)?;
        let policy: Policy = serde_json::from_value(
            value
                .get("details")
                .and_then(|d| d.get("authority_policy"))
                .cloned()
                .ok_or("invalid_read_policy")?,
        )
        .map_err(|_| "invalid_read_policy")?;
        policy.validate()?;
        if !pins.iter().any(|p| {
            p.issuer == policy.issuer
                && p.key_id == policy.key_id
                && p.public_key == policy.public_key
                && p.audience == policy.audience
                && p.callers.contains(caller)
        }) {
            return Err("issuer_setup_required");
        }
        let challenge = Challenge::parse(raw, owner, installation, &policy.receiver, now)?;
        if challenge.issuer != policy.issuer
            || challenge
                .credential_expires_at
                .saturating_sub(challenge.issued_at)
                > policy.max_lifetime_seconds
        {
            return Err("invalid_read_policy");
        }
        Ok(Self {
            challenge,
            policy,
            caller: caller.clone(),
        })
    }
    pub fn summary(&self) -> Value {
        json!({"origin":self.caller.id,"issuer":self.policy.issuer,"receiver":self.policy.receiver,"permissions":self.policy.permissions,"expires_at":self.challenge.credential_expires_at,"approval_expires_at":self.challenge.expires_at})
    }
    pub fn approve(self, wallet: &impl ReadSigner, now: u64) -> Result<ApprovedReadAccess> {
        if self.challenge.subject_public_key != wallet.read_public_key()
            || now < self.challenge.issued_at
            || now >= self.challenge.expires_at
        {
            return Err("read_approval_expired");
        }
        let signature = URL_SAFE_NO_PAD.encode(wallet.read_sign(&self.challenge.transcript()?)?);
        Ok(ApprovedReadAccess {
            challenge: self.challenge,
            policy: self.policy,
            caller: self.caller,
            signature,
        })
    }
}
impl ApprovedReadAccess {
    pub fn approval(&self) -> Value {
        json!({"challenge":self.challenge,"signature":self.signature})
    }
    pub fn accept(self, credential: Credential, now: u64) -> Result<ReadConnection> {
        let access = SignedAccess::accept(&self.challenge, self.policy, credential, now)?;
        Ok(ReadConnection {
            access,
            caller: self.caller,
        })
    }
}
impl ReadConnection {
    pub fn caller(&self) -> &Caller {
        &self.caller
    }
    pub fn present(
        &self,
        wallet: &impl ReadSigner,
        call: &Call,
        nonce: String,
        now: u64,
    ) -> Result<Proof> {
        let mut proof = self.access.unsigned_call(
            call,
            nonce,
            &wallet.read_public_key(),
            &self.access.credential.claims.installation_id,
            now,
        )?;
        proof.signature = hex::encode(wallet.read_sign(&proof.transcript()?)?);
        Ok(proof)
    }
}

enum Stage {
    Prepared(PreparedReadAccess),
    Approved(ApprovedReadAccess),
    Connected(ReadConnection),
}
#[wasm_bindgen]
pub struct WasmReadAccess {
    inner: Option<Stage>,
    epoch: std::rc::Rc<()>,
}
#[wasm_bindgen]
impl WasmReadAccess {
    pub fn summary(&self) -> core::result::Result<String, JsValue> {
        match self.inner.as_ref() {
            Some(Stage::Prepared(p)) => Ok(p.summary().to_string()),
            _ => Err(closed("read_approval_unavailable")),
        }
    }
    pub fn dispose(&mut self) {
        self.inner = None;
    }
}
fn closed(code: &'static str) -> JsValue {
    JsValue::from_str(code)
}
fn clock(raw: &str) -> Result<u64> {
    if raw.is_empty()
        || raw.len() > 1 && raw.starts_with('0')
        || !raw.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("invalid_clock");
    }
    let now: u64 = raw.parse().map_err(|_| "invalid_clock")?;
    if now > 9_007_199_254_740_871 {
        return Err("invalid_clock");
    }
    Ok(now)
}
impl WasmWallet {
    fn check_read_epoch(&self, access: &WasmReadAccess) -> Result<()> {
        if self.inner.is_none() {
            return Err("wallet_locked");
        }
        if !std::rc::Rc::ptr_eq(&self.work_epoch, &access.epoch) {
            return Err("read_context_changed");
        }
        Ok(())
    }
}
#[wasm_bindgen]
impl WasmWallet {
    #[wasm_bindgen(js_name=prepareReadAccess)]
    pub fn prepare_read_access(
        &self,
        raw: &str,
        installation: &str,
        pins_json: &str,
        caller_json: &str,
        now: &str,
    ) -> core::result::Result<WasmReadAccess, JsValue> {
        let wallet = self.inner.as_ref().ok_or_else(|| closed("wallet_locked"))?;
        let pins: Vec<TrustPin> = parse(pins_json.as_bytes(), 65536).map_err(closed)?;
        let caller: Caller = parse(caller_json.as_bytes(), 1024).map_err(closed)?;
        let prepared = PreparedReadAccess::prepare(
            raw,
            &wallet.public_key_hex(),
            installation,
            &pins,
            &caller,
            clock(now).map_err(closed)?,
        )
        .map_err(closed)?;
        Ok(WasmReadAccess {
            inner: Some(Stage::Prepared(prepared)),
            epoch: std::rc::Rc::clone(&self.work_epoch),
        })
    }
    #[wasm_bindgen(js_name=approveReadAccess)]
    pub fn approve_read_access(
        &self,
        access: &mut WasmReadAccess,
        now: &str,
    ) -> core::result::Result<String, JsValue> {
        self.check_read_epoch(access).map_err(closed)?;
        let Some(Stage::Prepared(prepared)) = access.inner.take() else {
            return Err(closed("read_approval_unavailable"));
        };
        let approved = prepared
            .approve(self.inner.as_ref().unwrap(), clock(now).map_err(closed)?)
            .map_err(closed)?;
        let result = approved.approval().to_string();
        access.inner = Some(Stage::Approved(approved));
        Ok(result)
    }
    #[wasm_bindgen(js_name=acceptReadCredential)]
    pub fn accept_read_credential(
        &self,
        access: &mut WasmReadAccess,
        raw: &str,
        now: &str,
    ) -> core::result::Result<String, JsValue> {
        self.check_read_epoch(access).map_err(closed)?;
        let credential: Credential = parse(raw.as_bytes(), 65536).map_err(closed)?;
        let Some(Stage::Approved(approved)) = access.inner.take() else {
            return Err(closed("read_approval_unavailable"));
        };
        let connection = approved
            .accept(credential, clock(now).map_err(closed)?)
            .map_err(closed)?;
        let result=json!({"receiver":connection.access.policy.receiver,"expires_at":connection.access.credential.claims.expires_at}).to_string();
        access.inner = Some(Stage::Connected(connection));
        Ok(result)
    }
    #[wasm_bindgen(js_name=presentReadCall)]
    pub fn present_read_call(
        &self,
        access: &WasmReadAccess,
        call_json: &str,
        origin: &str,
        now: &str,
    ) -> core::result::Result<String, JsValue> {
        self.check_read_epoch(access).map_err(closed)?;
        let Some(Stage::Connected(connection)) = access.inner.as_ref() else {
            return Err(closed("read_access_required"));
        };
        if connection.caller.id != origin {
            return Err(closed("invalid_caller"));
        }
        let call: Call = parse(call_json.as_bytes(), 16384).map_err(closed)?;
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| closed("randomness_unavailable"))?;
        let proof = connection
            .present(
                self.inner.as_ref().unwrap(),
                &call,
                hex::encode(nonce),
                clock(now).map_err(closed)?,
            )
            .map_err(closed)?;
        Ok(
            json!({"credential":connection.access.credential,"call":call,"proof":proof})
                .to_string(),
        )
    }
}
