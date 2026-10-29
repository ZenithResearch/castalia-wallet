//! Separate temporary-key mode. The owner-bootstrap API is not exposed here.
use super::{IssuerPin, OsRng, Result, RngCore, SessionKey, Value, json};
use secs_grant_contract::{self as c, holder_sessions as s};

/// No owner key, reusable grant, key import/export, Clone, Debug or Serialize.
pub struct HolderSessionKey {
    key: SessionKey,
    context: s::Context,
    reviewed: Option<s::Challenge>,
    credential: Option<s::Credential>,
}
impl HolderSessionKey {
    pub fn create(
        pin: IssuerPin,
        context: s::Context,
        installation: String,
        now: u64,
        maximum_expiry: u64,
    ) -> Result<Self> {
        for text in [&context.origin, &context.audience] {
            if text.is_empty()
                || text.len() > 256
                || !text.bytes().all(|b| b.is_ascii_graphic() && b != b'*')
            {
                return Err("invalid_session_context");
            }
        }
        Ok(Self {
            key: SessionKey::create(pin, installation, now, maximum_expiry)?,
            context,
            reviewed: None,
            credential: None,
        })
    }
    pub fn public_key(&self) -> String {
        self.key.public_key()
    }

    fn check_challenge(&self, c: &s::Challenge, now: u64) -> Result<()> {
        self.key.current_key(now)?;
        if c.service != self.key.pin.service
            || c.issuer != self.key.pin.issuer
            || c.key_id != self.key.pin.key_id
            || c.origin != self.context.origin
            || c.audience != self.context.audience
            || c.session_public_key != self.key.public
            || c.session_installation_id != self.key.installation
            || c.issued_at < self.key.created_at
            || c.expires_at > self.key.maximum_expiry
        {
            return Err("session_review_changed");
        }
        Ok(())
    }

    pub fn prove_possession(&mut self, challenge: &s::Challenge, now: u64) -> Result<String> {
        self.check_challenge(challenge, now)?;
        if self.credential.is_some() {
            return Err("session_already_issued");
        }
        if let Some(original) = &self.reviewed {
            if c::canonical(original)? != c::canonical(challenge)? {
                return Err("session_review_changed");
            }
        }
        let proof = s::prove_possession(challenge, self.key.current_key(now)?, now)?;
        self.reviewed = Some(challenge.clone());
        Ok(proof)
    }

    pub fn install_credential(
        &mut self,
        credential: s::Credential,
        reviewed: &s::Challenge,
        now: u64,
    ) -> Result<()> {
        self.check_challenge(reviewed, now)?;
        let original = self.reviewed.as_ref().ok_or("session_review_required")?;
        if c::canonical(original)? != c::canonical(reviewed)? {
            return Err("session_review_changed");
        }
        crate::holder_sessions::verify_returned_credential(
            &self.key.pin,
            &credential,
            reviewed,
            now,
        )?;
        if let Some(retained) = &self.credential {
            if c::digest(retained)? != c::digest(&credential)? {
                return Err("session_credential_changed");
            }
        } else {
            self.key.maximum_expiry = reviewed.expires_at;
            self.credential = Some(credential);
        }
        Ok(())
    }

    pub fn present_call(&self, call: &Value, now: u64) -> Result<Value> {
        let key = self.key.current_key(now)?;
        let credential = self
            .credential
            .as_ref()
            .ok_or("session_credential_required")?;
        if !call["parameters"].is_object() {
            return Err("invalid_session_call");
        }
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let proof = s::present(
            &self.key.pin,
            credential,
            call,
            hex::encode(nonce),
            &self.context,
            now,
            key,
        )?;
        Ok(json!({"credential":credential,"call":call,"proof":proof}))
    }

    pub fn status_proof(&self, challenge: &s::Challenge, now: u64) -> Result<s::StatusRequest> {
        self.check_challenge(challenge, now)?;
        if c::canonical(self.reviewed.as_ref().ok_or("session_review_required")?)?
            != c::canonical(challenge)?
        {
            return Err("session_review_changed");
        }
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        s::prove_status(
            challenge,
            hex::encode(nonce),
            now,
            self.key.current_key(now)?,
        )
    }

    pub fn close(&mut self) {
        self.credential = None;
        self.reviewed = None;
        self.key.close();
    }
}
