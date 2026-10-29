//! Typed holder consent for a fixed session challenge. This does not persist or
//! export a Wallet key, alter a saved grant, choose an issuer or perform HTTP.
//! The host must use its approved provider pins/context and personal consent UI.
use crate::{OpenedWallet, WasmWallet, portable_holder_grants::StoredGrant, scoped_holder_grants};
use secs_grant_contract::{self as c, IssuerPin, Result, holder_sessions as s};
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;

/// No Clone/Serialize/Debug: the private parent is not a display or journal item.
pub struct PreparedHolderSession {
    stored: scoped_holder_grants::StoredGrant,
    challenge: s::Challenge,
    context: s::Context,
    review_digest: String,
}
impl PreparedHolderSession {
    pub fn prepare(
        wallet: &OpenedWallet,
        stored: StoredGrant,
        challenge: s::Challenge,
        context: s::Context,
        installation: &str,
        now: u64,
    ) -> Result<Self> {
        let stored = match stored {
            StoredGrant::V2(stored) => stored,
            StoredGrant::V1(_) => return Err("holder_session_parent_unsupported"),
        };
        scoped_holder_grants::StoredGrant::review(
            wallet,
            stored.pin.clone(),
            stored.grant.clone(),
            installation,
            now,
        )?;
        if challenge.installation_id != installation {
            return Err("holder_session_installation_changed");
        }
        s::review_challenge(&stored.pin, &stored.grant, &challenge, &context, now)?;
        let review_digest = c::digest(&challenge)?;
        Ok(Self {
            stored,
            challenge,
            context,
            review_digest,
        })
    }

    pub fn summary(&self) -> Value {
        let c = &self.challenge;
        json!({"schema":"castalia.holder-session-review.v1","issuer_pin":self.stored.pin,
            "parent_grant_id":c.parent_grant_id,"parent_grant_digest":c.parent_grant_digest,
            "parent_revision":c.parent_revision,"holder_public_key":c.holder_public_key,
            "installation_id":c.installation_id,"session_public_key":c.session_public_key,
            "session_installation_id":c.session_installation_id,"origin":c.origin,"audience":c.audience,
            "permissions":c.permissions,"not_before":c.issued_at,"expires_at":c.expires_at,
            "review_deadline":c.review_deadline,"review_digest_sha256":self.review_digest,
            "hard_expiry":true,"onward_delegation":false})
    }

    /// Consumes a prepared review. Output is broker-private, never page/MCP data.
    pub fn approve(
        self,
        wallet: &OpenedWallet,
        session_signature: String,
        now: u64,
    ) -> Result<s::Authorization> {
        s::authorize(
            &self.stored.pin,
            self.stored.grant,
            self.challenge,
            session_signature,
            &self.context,
            &wallet.signing_key,
            now,
        )
    }
}

/// Public receipt validation remains usable after the owner Wallet is locked.
pub fn verify_returned_credential(
    pin: &IssuerPin,
    credential: &s::Credential,
    expected: &s::Challenge,
    now: u64,
) -> Result<()> {
    if c::canonical(expected)? != c::canonical(&credential.claims.challenge)? {
        return Err("holder_session_review_changed");
    }
    s::verify_credential(
        pin,
        credential,
        &s::Context {
            origin: expected.origin.clone(),
            audience: expected.audience.clone(),
        },
        now,
    )
}

fn js(e: &str) -> JsValue {
    JsValue::from_str(e)
}
fn clock(raw: &str) -> Result<u64> {
    if raw.is_empty()
        || !raw.bytes().all(|b| b.is_ascii_digit())
        || raw.len() > 1 && raw.starts_with('0')
    {
        return Err("invalid_clock");
    }
    raw.parse()
        .ok()
        .filter(|n| *n <= 9_007_199_254_740_991)
        .ok_or("invalid_clock")
}
fn web_context(origin: &str, audience: &str) -> Result<s::Context> {
    castalia_wallet_presentation::Caller {
        kind: "browser".into(),
        id: origin.into(),
    }
    .validate()?;
    Ok(s::Context {
        origin: origin.into(),
        audience: audience.into(),
    })
}

#[wasm_bindgen]
impl WasmWallet {
    #[wasm_bindgen(js_name=reviewHolderSessionAuthorization)]
    pub fn review_holder_session_authorization(
        &self,
        stored: &str,
        challenge: &str,
        caller_origin: &str,
        audience: &str,
        installation: &str,
        time: &str,
    ) -> std::result::Result<String, JsValue> {
        let wallet = self.inner.as_ref().ok_or_else(|| js("wallet_locked"))?;
        let prepared = PreparedHolderSession::prepare(
            wallet,
            c::parse(stored.as_bytes()).map_err(js)?,
            c::parse(challenge.as_bytes()).map_err(js)?,
            web_context(caller_origin, audience).map_err(js)?,
            installation,
            clock(time).map_err(js)?,
        )
        .map_err(js)?;
        serde_json::to_string(&prepared.summary()).map_err(|_| js("encoding_failed"))
    }

    /// Explicit bindings are separate ABI arguments so callers cannot omit them.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name=approveHolderSessionAuthorization)]
    pub fn approve_holder_session_authorization(
        &self,
        stored: &str,
        challenge: &str,
        session_signature: &str,
        caller_origin: &str,
        audience: &str,
        installation: &str,
        time: &str,
    ) -> std::result::Result<String, JsValue> {
        let wallet = self.inner.as_ref().ok_or_else(|| js("wallet_locked"))?;
        let now = clock(time).map_err(js)?;
        let prepared = PreparedHolderSession::prepare(
            wallet,
            c::parse(stored.as_bytes()).map_err(js)?,
            c::parse(challenge.as_bytes()).map_err(js)?,
            web_context(caller_origin, audience).map_err(js)?,
            installation,
            now,
        )
        .map_err(js)?;
        let authorization = prepared
            .approve(wallet, session_signature.into(), now)
            .map_err(js)?;
        serde_json::to_string(&authorization).map_err(|_| js("encoding_failed"))
    }

    #[wasm_bindgen(js_name=verifyHolderSessionCredential)]
    pub fn verify_holder_session_credential(
        &self,
        pin: &str,
        credential: &str,
        challenge: &str,
        time: &str,
    ) -> std::result::Result<String, JsValue> {
        let pin = c::parse(pin.as_bytes()).map_err(js)?;
        let credential: s::Credential = c::parse(credential.as_bytes()).map_err(js)?;
        let challenge = c::parse(challenge.as_bytes()).map_err(js)?;
        verify_returned_credential(&pin, &credential, &challenge, clock(time).map_err(js)?)
            .map_err(js)?;
        serde_json::to_string(&json!({"schema":"castalia.holder-session-credential-verified.v1",
            "credential_digest":c::digest(&credential).map_err(js)?,"service":credential.claims.challenge.service,
            "session_public_key":credential.claims.challenge.session_public_key,
            "session_installation_id":credential.claims.challenge.session_installation_id,
            "expires_at":credential.claims.challenge.expires_at})).map_err(|_|js("encoding_failed"))
    }
}
