//! Application-neutral read-access approval. The application owns the disclosure
//! schema and server protocol. This core binds approval to the unlocked identity,
//! installation, receiver, expiry and exact canonical disclosure; never a mutation.
use crate::portable::{Result, parse_unique};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use castalia_wallet_presentation::read_authority::{Call, Credential, Policy, Proof};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerPin {
    pub issuer: String,
    pub key_id: String,
    pub public_key: String,
    pub receiver: String,
    pub audience: String,
}
impl IssuerPin {
    pub fn check(&self, policy: &Policy) -> Result<()> {
        policy.validate()?;
        if self.issuer != policy.issuer
            || self.key_id != policy.key_id
            || self.public_key != policy.public_key
            || self.receiver != policy.receiver
            || self.audience != policy.audience
        {
            return Err("issuer_setup_required");
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAccess {
    pub policy: Policy,
    pub credential: Credential,
    pub details: Value,
}
impl SignedAccess {
    pub fn accept(
        approved: &Challenge,
        policy: Policy,
        credential: Credential,
        now: u64,
    ) -> Result<Self> {
        castalia_wallet_presentation::read_authority::verify_credential(&policy, &credential, now)?;
        let claims = &credential.claims;
        if now >= approved.expires_at
            || claims.holder_public_key != approved.subject_public_key
            || claims.installation_id != approved.installation_id
            || claims.receiver != approved.receiver
            || claims.issuer != approved.issuer
            || claims.permissions != policy.permissions
            || claims.issued_at < approved.issued_at
            || claims.expires_at > approved.credential_expires_at
        {
            return Err("invalid_credential");
        }
        Ok(Self {
            policy,
            credential,
            details: approved.details.clone(),
        })
    }
    pub fn unsigned_call(
        &self,
        call: &Call,
        nonce: String,
        owner: &str,
        device: &str,
        now: u64,
    ) -> Result<Proof> {
        castalia_wallet_presentation::read_authority::verify_credential(
            &self.policy,
            &self.credential,
            now,
        )?;
        if self.credential.claims.holder_public_key != owner
            || self.credential.claims.installation_id != device
            || !self
                .credential
                .claims
                .permissions
                .iter()
                .any(|p| p.operation == call.operation && p.resource == call.resource)
        {
            return Err("read_not_permitted");
        }
        Proof::unsigned(&self.credential, call, nonce, now)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub schema: String,
    pub request_id: String,
    pub nonce: String,
    pub subject_public_key: String,
    pub installation_id: String,
    pub issuer: String,
    pub receiver: String,
    pub details: Value,
    pub issued_at: u64,
    pub expires_at: u64,
    pub credential_expires_at: u64,
}
impl Challenge {
    pub fn parse(
        raw: &str,
        owner: &str,
        installation: &str,
        receiver: &str,
        now: u64,
    ) -> Result<Self> {
        if raw.len() > 16384 {
            return Err("request_too_large");
        }
        parse_unique(raw)?;
        let value: Self = serde_json::from_str(raw).map_err(|_| "invalid_request")?;
        let url = url::Url::parse(receiver).map_err(|_| "invalid_receiver")?;
        if url.scheme() != "https"
            || url.origin().ascii_serialization() != receiver
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err("invalid_receiver");
        }
        if value.schema != "castalia.read-access-challenge.v1"
            || value.subject_public_key != owner
            || value.installation_id != installation
            || value.receiver != receiver
            || value.request_id.len() != 32
            || !value.request_id.bytes().all(|b| b.is_ascii_hexdigit())
            || value.issuer.is_empty()
            || value.issuer.len() > 256
            || value.issued_at > now
            || value.expires_at <= now
            || value.expires_at.saturating_sub(value.issued_at) > 120
            || value.credential_expires_at <= now
            || value.credential_expires_at.saturating_sub(value.issued_at) > 86400
        {
            return Err("invalid_request");
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&value.nonce)
            .map_err(|_| "invalid_request")?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value.nonce {
            return Err("invalid_request");
        }
        Ok(value)
    }
    pub fn transcript(&self) -> Result<Vec<u8>> {
        let mut bytes = b"castalia/read-access-approval/v1\0".to_vec();
        bytes.extend(serde_jcs::to_vec(self).map_err(|_| "invalid_request")?);
        Ok(bytes)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredAccess {
    pub issuer: String,
    pub receiver: String,
    pub expires_at: u64,
    pub secret: String,
    pub metadata: Value,
}

impl Drop for StoredAccess {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}
