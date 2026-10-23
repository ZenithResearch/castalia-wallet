//! First-owner consent, distinct from membership and operator access proofs.
//! The host supplies an OS-verified binding; this module never discovers an
//! owner, exports a key, arms bootstrap authority or sends a network request.
use crate::{OpenedWallet, portable};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::IpAddr;
use url::Url;

const DOMAIN: &[u8] = b"zenith/resource-owner-approval/v1\0";
const MAX_SAFE: u64 = 9_007_199_254_740_991;
const OPS: [&str; 4] = [
    "access.inbox",
    "access.review",
    "access.decide",
    "access.status",
];
type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    resource_id: String,
    endpoint: String,
    configuration_sha256: String,
    registration_sha256: String,
}
impl Binding {
    fn validate(&self) -> Result<()> {
        let id = self.resource_id.as_bytes();
        if id.len() != 36
            || !id.iter().enumerate().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    *c == b'-'
                } else {
                    hex_byte(*c)
                }
            })
            || !hex_string(&self.configuration_sha256, 64)
            || !hex_string(&self.registration_sha256, 64)
        {
            return Err("invalid_owner_binding");
        }
        let endpoint = &self.endpoint;
        if endpoint.len() > 2048
            || !endpoint.is_ascii()
            || endpoint
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b < 32 || b == b'\\' || b == b'%')
        {
            return Err("invalid_owner_binding");
        }
        let url = Url::parse(endpoint).map_err(|_| "invalid_owner_binding")?;
        if !["http", "https"].contains(&url.scheme())
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.origin().ascii_serialization() != *endpoint
            || url.port() == Some(0)
        {
            return Err("invalid_owner_binding");
        }
        if url.scheme() == "http"
            && !url
                .host_str()
                .unwrap_or("")
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false)
        {
            return Err("invalid_owner_binding");
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Validity {
    mode: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdminGrant {
    schema: String,
    grant_id: String,
    holder_public_key: String,
    resource_id: String,
    operations: Vec<String>,
    validity: Validity,
    onward_delegation: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    schema: String,
    binding: Binding,
    claim_id: String,
    nonce: String,
    issued_at: u64,
    expires_at: u64,
    admin_grant: AdminGrant,
}

pub(crate) struct PreparedOwnerClaim {
    challenge: Challenge,
}
impl PreparedOwnerClaim {
    pub(crate) fn prepare(
        raw: &str,
        binding: &Binding,
        public_key: &str,
        now: u64,
    ) -> Result<Self> {
        if raw.len() > 16384 {
            return Err("owner_claim_too_large");
        }
        portable::parse_unique(raw).map_err(|_| "invalid_owner_claim")?;
        let c: Challenge = serde_json::from_str(raw).map_err(|_| "invalid_owner_claim")?;
        binding.validate()?;
        if c.binding != *binding {
            return Err("owner_binding_changed");
        }
        if c.schema != "zenith.resource-owner-challenge.v1"
            || !hex_string(&c.claim_id, 32)
            || !hex_string(&c.nonce, 64)
            || c.admin_grant.schema != "zenith.resource-admin-grant.v1"
            || !hex_string(&c.admin_grant.grant_id, 64)
            || c.admin_grant.holder_public_key != public_key
            || !hex_string(public_key, 64)
            || c.admin_grant.resource_id != binding.resource_id
            || c.admin_grant.operations != OPS
            || c.admin_grant.validity.mode != "until_revoked"
            || c.admin_grant.onward_delegation
            || c.expires_at > MAX_SAFE
            || c.expires_at <= c.issued_at
            || c.expires_at - c.issued_at > 120
        {
            return Err("invalid_owner_claim");
        }
        let prepared = Self { challenge: c };
        prepared.check_time(now)?;
        Ok(prepared)
    }
    fn check_time(&self, now: u64) -> Result<()> {
        if now > MAX_SAFE || now < self.challenge.issued_at || now >= self.challenge.expires_at {
            return Err("owner_claim_expired");
        }
        Ok(())
    }
    pub(crate) fn summary(&self) -> Value {
        json!({"kind":"first_resource_administrator", "native_protocol":"zenith.resource-owner.v1",
            "binding":self.challenge.binding, "admin_grant":self.challenge.admin_grant,
            "claim_id":self.challenge.claim_id, "expires_at":self.challenge.expires_at,
            "setup_authorization_consumed_on_activation":true})
    }
    pub(crate) fn approve(self, wallet: &OpenedWallet, now: u64) -> Result<Value> {
        self.check_time(now)?;
        if wallet.public_key_hex() != self.challenge.admin_grant.holder_public_key {
            return Err("owner_wallet_changed");
        }
        let mut transcript = DOMAIN.to_vec();
        transcript.extend(serde_jcs::to_vec(&self.challenge).map_err(|_| "encoding_failed")?);
        let signature = wallet.sign(&transcript).map_err(|_| "signing_failed")?;
        Ok(
            json!({"schema":"zenith.resource-owner-proof.v1", "challenge":self.challenge,
            "signature":hex::encode(signature)}),
        )
    }
}
fn hex_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}
fn hex_string(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(hex_byte)
}
