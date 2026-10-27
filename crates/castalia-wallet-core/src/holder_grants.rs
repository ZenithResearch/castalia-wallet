//! Typed reusable grant custody. All signing stays inside the shared Wallet Core.
use crate::OpenedWallet;
use rand_core::{OsRng, RngCore};
use secs_grant_contract::{self as contract, Credential, Grant, IssuerPin, Permission, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredGrant {
    pub pin: IssuerPin,
    pub grant: Grant,
    pub saved_at: u64,
}
impl StoredGrant {
    pub fn review(
        wallet: &OpenedWallet,
        pin: IssuerPin,
        grant: Grant,
        installation: &str,
        now: u64,
    ) -> Result<Self> {
        contract::verify_grant(&pin, &grant, now)?;
        if grant.claims.holder_public_key != wallet.public_key_hex()
            || grant
                .claims
                .installation_id
                .as_deref()
                .is_some_and(|i| i != installation)
        {
            return Err("wrong_grant_holder");
        }
        Ok(Self {
            pin,
            grant,
            saved_at: now,
        })
    }
    pub fn summary(&self) -> Value {
        json!({"schema":"castalia.holder-grant-review.v1","service":self.pin.service,"issuer":self.pin.issuer,"holder_public_key":self.grant.claims.holder_public_key,"grant_id":self.grant.claims.grant_id,"revision":self.grant.claims.revision,"validity":self.grant.claims.validity,"permissions":self.grant.claims.permissions,"onward_delegation":false,"max_credential_lifetime_seconds":self.grant.claims.max_credential_lifetime_seconds})
    }
    pub fn derive(
        &self,
        wallet: &OpenedWallet,
        permissions: Option<Vec<Permission>>,
        installation: &str,
        now: u64,
        expires: u64,
    ) -> Result<Credential> {
        let mut id = [0; 16];
        OsRng.fill_bytes(&mut id);
        contract::derive_credential(
            &self.pin,
            self.grant.clone(),
            permissions.unwrap_or_else(|| self.grant.claims.permissions.clone()),
            Some(installation.into()),
            hex::encode(id),
            now,
            expires,
            &wallet.signing_key,
        )
    }
    pub fn present(
        &self,
        wallet: &OpenedWallet,
        credential: &Credential,
        call: &Value,
        now: u64,
    ) -> Result<Value> {
        if contract::digest(&self.grant)? != credential.claims.grant_digest {
            return Err("grant_changed");
        }
        // Never provide a signature for an operation outside this credential.
        let allowed = credential.claims.permissions.iter().any(|p| {
            Some(p.operation.as_str()) == call["operation"].as_str()
                && Some(p.resource.as_str()) == call["resource"].as_str()
        });
        if !allowed {
            return Err("read_not_permitted");
        }
        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        let proof = contract::present(
            &self.pin,
            credential,
            call,
            hex::encode(nonce),
            now,
            &wallet.signing_key,
        )?;
        Ok(json!({"credential":credential,"call":call,"proof":proof}))
    }
}

pub fn parse_backup(
    wallet: &OpenedWallet,
    raw: &str,
) -> Result<std::collections::BTreeMap<String, StoredGrant>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Backup {
        schema: String,
        owner_public_key: String,
        grants: std::collections::BTreeMap<String, StoredGrant>,
    }
    let b: Backup = contract::parse(raw.as_bytes())?;
    if b.schema != "castalia.holder-grant-backup.v1"
        || b.owner_public_key != wallet.public_key_hex()
        || b.grants.len() > 128
    {
        return Err("invalid_grant_backup");
    }
    for (service, g) in &b.grants {
        if service != &g.pin.service || g.grant.claims.holder_public_key != wallet.public_key_hex()
        {
            return Err("invalid_grant_backup");
        }
        contract::verify_grant(&g.pin, &g.grant, g.saved_at)?;
    }
    Ok(b.grants)
}

use crate::WasmWallet;
use wasm_bindgen::prelude::*;
fn js(e: &str) -> JsValue {
    JsValue::from_str(e)
}
fn now(raw: &str) -> Result<u64> {
    if raw.is_empty()
        || !raw.bytes().all(|b| b.is_ascii_digit())
        || raw.len() > 1 && raw.starts_with('0')
    {
        return Err("invalid_clock");
    }
    raw.parse::<u64>()
        .ok()
        .filter(|n| *n <= 9007199254740991)
        .ok_or("invalid_clock")
}
#[wasm_bindgen]
impl WasmWallet {
    /// The adapter supplies issuer pins from its approved provider store, never the page.
    #[wasm_bindgen(js_name=reviewHolderGrant)]
    pub fn review_holder_grant(
        &self,
        raw: &str,
        pins: &str,
        caller: &str,
        installation: &str,
        time: &str,
    ) -> std::result::Result<String, JsValue> {
        let wallet = self.inner.as_ref().ok_or_else(|| js("wallet_locked"))?;
        let g: crate::portable_holder_grants::Grant =
            contract::parse(raw.as_bytes()).map_err(js)?;
        let caller: castalia_wallet_presentation::Caller =
            castalia_wallet_presentation::parse(caller.as_bytes(), 1024).map_err(js)?;
        caller.validate().map_err(js)?;
        let pins: Vec<castalia_wallet_presentation::TrustPin> =
            castalia_wallet_presentation::parse(pins.as_bytes(), 65536).map_err(js)?;
        let pin = pins
            .iter()
            .find(|p| {
                p.issuer == g.issuer().0 && p.key_id == g.issuer().1 && p.callers.contains(&caller)
            })
            .ok_or_else(|| js("issuer_setup_required"))?;
        let pin = IssuerPin {
            issuer: pin.issuer.clone(),
            key_id: pin.key_id.clone(),
            public_key: pin.public_key.clone(),
            service: g.issuer().2.into(),
        };
        let stored = crate::portable_holder_grants::StoredGrant::review(
            wallet,
            pin,
            g,
            installation,
            now(time).map_err(js)?,
        )
        .map_err(js)?;
        serde_json::to_string(&json!({"stored":stored,"summary":stored.summary()}))
            .map_err(|_| js("encoding_failed"))
    }
    #[wasm_bindgen(js_name=deriveHolderCredential)]
    pub fn derive_holder_credential(
        &self,
        stored: &str,
        permissions: &str,
        installation: &str,
        time: &str,
        expires: &str,
    ) -> std::result::Result<String, JsValue> {
        let w = self.inner.as_ref().ok_or_else(|| js("wallet_locked"))?;
        let stored: crate::portable_holder_grants::StoredGrant =
            contract::parse(stored.as_bytes()).map_err(js)?;
        let p: Option<crate::portable_holder_grants::Permissions> =
            contract::parse(permissions.as_bytes()).map_err(js)?;
        let c = stored
            .derive(
                w,
                p,
                installation,
                now(time).map_err(js)?,
                now(expires).map_err(js)?,
            )
            .map_err(js)?;
        serde_json::to_string(&c).map_err(|_| js("encoding_failed"))
    }
    #[wasm_bindgen(js_name=presentHolderCredential)]
    pub fn present_holder_credential(
        &self,
        stored: &str,
        credential: &str,
        call: &str,
        time: &str,
    ) -> std::result::Result<String, JsValue> {
        let w = self.inner.as_ref().ok_or_else(|| js("wallet_locked"))?;
        let stored: crate::portable_holder_grants::StoredGrant =
            contract::parse(stored.as_bytes()).map_err(js)?;
        let c: crate::portable_holder_grants::Credential =
            contract::parse(credential.as_bytes()).map_err(js)?;
        let call: Value = contract::parse(call.as_bytes()).map_err(js)?;
        serde_json::to_string(
            &stored
                .present(w, &c, &call, now(time).map_err(js)?)
                .map_err(js)?,
        )
        .map_err(|_| js("encoding_failed"))
    }
    #[wasm_bindgen(js_name=validateHolderGrantBackup)]
    pub fn validate_holder_grant_backup(&self, raw: &str) -> std::result::Result<String, JsValue> {
        let w = self.inner.as_ref().ok_or_else(|| js("wallet_locked"))?;
        let grants = crate::portable_holder_grants::parse_backup(w, raw).map_err(js)?;
        serde_json::to_string(&grants).map_err(|_| js("encoding_failed"))
    }
}

#[wasm_bindgen]
impl WasmWallet {
    #[wasm_bindgen(js_name=reviewHolderDerivation)]
    pub fn review_holder_derivation(
        &self,
        stored: &str,
        permissions: &str,
        installation: &str,
        time: &str,
        expires: &str,
    ) -> std::result::Result<String, JsValue> {
        let w = self.inner.as_ref().ok_or_else(|| js("wallet_locked"))?;
        let g: crate::portable_holder_grants::StoredGrant =
            contract::parse(stored.as_bytes()).map_err(js)?;
        let start = now(time).map_err(js)?;
        let end = now(expires).map_err(js)?;
        let p: Option<crate::portable_holder_grants::Permissions> =
            contract::parse(permissions.as_bytes()).map_err(js)?;
        let summary = g
            .review_derivation(w, p, installation, start, end)
            .map_err(js)?;
        Ok(summary.to_string())
    }
}

/// Reserve backup envelope space so every accepted collection can be restored
/// through the same bounded parser, rather than exporting an unreadable file.
pub fn validate_capacity<T: Serialize>(
    grants: &std::collections::BTreeMap<String, T>,
) -> Result<()> {
    if grants.len() > 128
        || serde_json::to_vec(grants)
            .map_err(|_| "encoding_failed")?
            .len()
            > 130_000
    {
        return Err("grant_capacity");
    }
    Ok(())
}

/// Public issuer-signed destination authentication, with no Wallet key access.
#[wasm_bindgen(js_name = verifyServiceAccessPoint)]
pub fn verify_service_access_point(
    pin: &str,
    binding: &str,
    origin: &str,
    at: &str,
) -> std::result::Result<String, JsValue> {
    let pin: IssuerPin = contract::parse(pin.as_bytes()).map_err(js)?;
    let binding: contract::AccessPointBinding = contract::parse(binding.as_bytes()).map_err(js)?;
    contract::verify_access_point(&pin, &binding, origin, now(at).map_err(js)?).map_err(js)?;
    serde_json::to_string(&binding.claims).map_err(|_| js("invalid_service_binding"))
}
