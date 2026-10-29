//! Ephemeral session custody. Not a member Wallet or owner-key delegation.

use crate::{access_request::PreparedAccessRequest, browser_read::ReadSigner};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use castalia_wallet_presentation::read_authority::Policy;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use secs_grant_contract::{IssuerPin, Result, scoped_grants as contract};
use serde_json::{Value, json};
mod holder;
pub use holder::HolderSessionKey;

const SAFE: u64 = 9_007_199_254_740_991;

/// A fresh, finite, nonexportable identity. No Clone/Debug/Serialize or seed
/// accessor. Dropping/closing the key invokes dalek's zeroize-on-drop custody.
/// This is an application session, not membership, account recovery or an OS
/// isolation boundary. Broker/helper envelopes must never become MCP output.
pub struct SessionKey {
    key: Option<SigningKey>,
    public: String,
    pin: IssuerPin,
    installation: String,
    created_at: u64,
    maximum_expiry: u64,
    grant: Option<contract::Grant>,
}

impl SessionKey {
    pub fn create(
        pin: IssuerPin,
        installation: String,
        now: u64,
        maximum_expiry: u64,
    ) -> Result<Self> {
        let bytes: [u8; 32] = hex::decode(&pin.public_key)
            .map_err(|_| "invalid_session_profile")?
            .try_into()
            .map_err(|_| "invalid_session_profile")?;
        let issuer = VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid_session_profile")?;
        if issuer.is_weak()
            || hex::encode(bytes) != pin.public_key
            || installation.len() != 32
            || !installation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || [&pin.issuer, &pin.key_id, &pin.service].iter().any(|s| {
                s.is_empty()
                    || s.len() > 256
                    || !s.bytes().all(|b| b.is_ascii_graphic() && b != b'*')
            })
            || now >= maximum_expiry
            || maximum_expiry > SAFE
        {
            return Err("invalid_session_profile");
        }
        let key = SigningKey::generate(&mut OsRng);
        let public = hex::encode(key.verifying_key().as_bytes());
        Ok(Self {
            key: Some(key),
            public,
            pin,
            installation,
            created_at: now,
            maximum_expiry,
            grant: None,
        })
    }

    pub fn public_key(&self) -> String {
        self.public.clone()
    }

    fn current_key(&self, now: u64) -> Result<&SigningKey> {
        if now < self.created_at || now >= self.maximum_expiry {
            return Err("session_expired");
        }
        self.key.as_ref().ok_or("session_closed")
    }

    fn receiver_pin(&self, pin: &crate::read_access::IssuerPin) -> Result<()> {
        if pin.issuer != self.pin.issuer
            || pin.key_id != self.pin.key_id
            || pin.public_key != self.pin.public_key
        {
            return Err("session_provider_changed");
        }
        Ok(())
    }

    /// Closed member access.request/status only. This cannot sign owner decisions.
    /// Both the challenge and receiver pin are broker-internal, never model input.
    pub fn approve_member_request(
        &self,
        raw: &str,
        pin: &crate::read_access::IssuerPin,
        now: u64,
    ) -> Result<Value> {
        self.current_key(now)?;
        self.receiver_pin(pin)?;
        PreparedAccessRequest::prepare_native(raw, &self.public, &self.installation, pin, now)?
            .approve(&SessionReadSigner(self), now)
    }

    /// Existing domain-separated enrollment PoP. The issuer still checks the
    /// operator-approved assignment; this signature grants no access by itself.
    pub fn approve_enrollment(
        &self,
        raw: &str,
        pin: &crate::read_access::IssuerPin,
        now: u64,
    ) -> Result<Value> {
        let key = self.current_key(now)?;
        self.receiver_pin(pin)?;
        let challenge = crate::read_access::Challenge::parse(
            raw,
            &self.public,
            &self.installation,
            &pin.receiver,
            now,
        )?;
        let policy: Policy = serde_json::from_value(
            challenge
                .details
                .get("authority_policy")
                .cloned()
                .ok_or("invalid_read_policy")?,
        )
        .map_err(|_| "invalid_read_policy")?;
        pin.check(&policy)?;
        if challenge.issuer != self.pin.issuer
            || challenge.credential_expires_at > self.maximum_expiry
            || challenge
                .credential_expires_at
                .saturating_sub(challenge.issued_at)
                > policy.max_lifetime_seconds
        {
            return Err("invalid_session_enrollment");
        }
        let signature = URL_SAFE_NO_PAD.encode(key.sign(&challenge.transcript()?).to_bytes());
        Ok(json!({"challenge":challenge,"signature":signature}))
    }

    /// Verify a freshly issuer-signed root against the retained reviewed scope.
    /// There is no conversion/derivation from another holder's Wallet grant.
    /// An exact retry recovers the retained original; replacement requires a new
    /// explicit session, never silently swapping its grant or approved lifetime.
    pub fn install_grant(
        &mut self,
        grant: contract::Grant,
        reviewed_expiry: u64,
        reviewed_permissions: &[contract::Permission],
        now: u64,
    ) -> Result<()> {
        self.current_key(now)?;
        contract::verify_grant(&self.pin, &grant, now)?;
        if grant.claims.holder_public_key != self.public
            || grant.claims.installation_id.as_deref() != Some(self.installation.as_str())
            || grant.claims.validity.end() != Some(reviewed_expiry)
            || reviewed_expiry > self.maximum_expiry
            || grant.claims.permissions != reviewed_permissions
        {
            return Err("session_grant_binding_mismatch");
        }
        if let Some(original) = &self.grant {
            if secs_grant_contract::digest(original)? != secs_grant_contract::digest(&grant)? {
                return Err("session_grant_changed");
            }
        } else {
            self.grant = Some(grant);
        }
        Ok(())
    }

    /// Broker-internal envelope, not an MCP/tool result. Fresh native secS/Core
    /// proofs bind the exact call. The provider must independently check current
    /// revocation/policy, replay, selectors and transactional paired effects.
    pub fn present_call(&self, call: &Value, now: u64) -> Result<Value> {
        let key = self.current_key(now)?;
        let grant = self.grant.as_ref().ok_or("session_grant_required")?;
        let object = call.as_object().ok_or("invalid_session_call")?;
        if object.len() != 3
            || !["operation", "resource", "parameters"]
                .iter()
                .all(|name| object.contains_key(*name))
            || !call["parameters"].is_object()
            || !grant.claims.permissions.iter().any(|p| {
                Some(p.operation.as_str()) == call["operation"].as_str()
                    && Some(p.resource.as_str()) == call["resource"].as_str()
            })
        {
            return Err("session_call_not_permitted");
        }
        secs_grant_contract::canonical(call)?;
        let expires = now.checked_add(60).ok_or("invalid_session_clock")?.min(
            grant
                .claims
                .validity
                .end()
                .ok_or("finite_session_required")?,
        );
        let mut id = [0; 16];
        OsRng.fill_bytes(&mut id);
        let credential = contract::derive_credential(
            &self.pin,
            grant.clone(),
            grant.claims.permissions.clone(),
            Some(self.installation.clone()),
            hex::encode(id),
            now,
            expires,
            key,
        )?;
        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        let proof = contract::present(&self.pin, &credential, call, hex::encode(nonce), now, key)?;
        let envelope = json!({"credential":credential,"call":call,"proof":proof});
        if secs_grant_contract::canonical(&envelope)?.len() > 130000 {
            return Err("session_envelope_too_large");
        }
        Ok(envelope)
    }

    pub fn close(&mut self) {
        self.grant = None;
        self.key = None;
    }
}

// Private adapter: no publicly callable arbitrary-sign trait on SessionKey.
struct SessionReadSigner<'a>(&'a SessionKey);
impl ReadSigner for SessionReadSigner<'_> {
    fn read_public_key(&self) -> String {
        self.0.public_key()
    }
    fn read_sign(&self, bytes: &[u8]) -> Result<[u8; 64]> {
        Ok(self
            .0
            .key
            .as_ref()
            .ok_or("session_closed")?
            .sign(bytes)
            .to_bytes())
    }
}

#[cfg(test)]
mod tests;
