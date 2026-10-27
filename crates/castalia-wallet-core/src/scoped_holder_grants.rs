//! Typed reusable grant custody. All signing stays inside the shared Wallet Core.
use crate::OpenedWallet;
use contract::{Credential, Grant, Permission};
use rand_core::{OsRng, RngCore};
use secs_grant_contract::{IssuerPin, Result, scoped_grants as contract};
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
        if secs_grant_contract::digest(&self.grant)? != credential.claims.grant_digest {
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
