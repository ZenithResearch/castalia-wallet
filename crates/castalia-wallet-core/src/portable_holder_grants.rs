//! Dual-reader boundary. Untagged storage preserves every v1 signed byte/field.
//! New v2 authority never converts to a v1 scope or falls back after a failure.
use crate::{OpenedWallet, holder_grants as v1, scoped_holder_grants as v2};
use secs_grant_contract::{self as c1, IssuerPin, Result, scoped_grants as c2};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Grant {
    V1(c1::Grant),
    V2(c2::Grant),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Credential {
    V1(c1::Credential),
    V2(c2::Credential),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Permissions {
    V1(Vec<c1::Permission>),
    V2(Vec<c2::Permission>),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StoredGrant {
    V1(v1::StoredGrant),
    V2(v2::StoredGrant),
}
impl Grant {
    pub fn issuer(&self) -> (&str, &str, &str) {
        match self {
            Self::V1(g) => (&g.claims.issuer, &g.claims.key_id, &g.claims.service),
            Self::V2(g) => (&g.claims.issuer, &g.claims.key_id, &g.claims.service),
        }
    }
}
impl StoredGrant {
    pub fn review(w: &OpenedWallet, pin: IssuerPin, g: Grant, i: &str, now: u64) -> Result<Self> {
        match g {
            Grant::V1(g) => Ok(Self::V1(v1::StoredGrant::review(w, pin, g, i, now)?)),
            Grant::V2(g) => Ok(Self::V2(v2::StoredGrant::review(w, pin, g, i, now)?)),
        }
    }
    pub fn pin(&self) -> &IssuerPin {
        match self {
            Self::V1(g) => &g.pin,
            Self::V2(g) => &g.pin,
        }
    }
    pub fn holder(&self) -> &str {
        match self {
            Self::V1(g) => &g.grant.claims.holder_public_key,
            Self::V2(g) => &g.grant.claims.holder_public_key,
        }
    }
    pub fn verify(&self, now: u64) -> Result<()> {
        match self {
            Self::V1(g) => c1::verify_grant(&g.pin, &g.grant, now),
            Self::V2(g) => c2::verify_grant(&g.pin, &g.grant, now),
        }
    }
    pub fn saved_at(&self) -> u64 {
        match self {
            Self::V1(g) => g.saved_at,
            Self::V2(g) => g.saved_at,
        }
    }
    pub fn summary(&self) -> Value {
        match self {
            Self::V1(g) => g.summary(),
            Self::V2(g) => g.summary(),
        }
    }
    pub fn derive(
        &self,
        w: &OpenedWallet,
        p: Option<Permissions>,
        i: &str,
        now: u64,
        end: u64,
    ) -> Result<Credential> {
        match (self, p) {
            (Self::V1(g), None) => Ok(Credential::V1(g.derive(w, None, i, now, end)?)),
            (Self::V1(g), Some(Permissions::V1(p))) => {
                Ok(Credential::V1(g.derive(w, Some(p), i, now, end)?))
            }
            (Self::V2(g), None) => Ok(Credential::V2(g.derive(w, None, i, now, end)?)),
            (Self::V2(g), Some(Permissions::V2(p))) => {
                Ok(Credential::V2(g.derive(w, Some(p), i, now, end)?))
            }
            _ => Err("grant_version_mismatch"),
        }
    }
    pub fn present(
        &self,
        w: &OpenedWallet,
        c: &Credential,
        call: &Value,
        now: u64,
    ) -> Result<Value> {
        match (self, c) {
            (Self::V1(g), Credential::V1(c)) => g.present(w, c, call, now),
            (Self::V2(g), Credential::V2(c)) => g.present(w, c, call, now),
            _ => Err("grant_version_mismatch"),
        }
    }
    pub fn review_derivation(
        &self,
        w: &OpenedWallet,
        p: Option<Permissions>,
        i: &str,
        now: u64,
        end: u64,
    ) -> Result<Value> {
        let (validity, max, permissions) = match (self, p) {
            (Self::V1(g), p) => {
                v1::StoredGrant::review(w, g.pin.clone(), g.grant.clone(), i, now)?;
                let selected = match p {
                    None => g.grant.claims.permissions.clone(),
                    Some(Permissions::V1(p)) => p,
                    _ => return Err("grant_version_mismatch"),
                };
                c1::permissions_within(&selected, &g.grant.claims.permissions)?;
                (
                    &g.grant.claims.validity,
                    g.grant.claims.max_credential_lifetime_seconds,
                    json!(selected),
                )
            }
            (Self::V2(g), p) => {
                v2::StoredGrant::review(w, g.pin.clone(), g.grant.clone(), i, now)?;
                let selected = match p {
                    None => g.grant.claims.permissions.clone(),
                    Some(Permissions::V2(p)) => p,
                    _ => return Err("grant_version_mismatch"),
                };
                c2::permissions_within(&selected, &g.grant.claims.permissions)?;
                (
                    &g.grant.claims.validity,
                    g.grant.claims.max_credential_lifetime_seconds,
                    json!(selected),
                )
            }
        };
        if end <= now
            || end > 9_007_199_254_740_991
            || end - now > max
            || validity.end().is_some_and(|e| end > e)
        {
            return Err("invalid_credential_lifetime");
        }
        let mut s = self.summary();
        s["permissions"] = permissions;
        s["expires_at"] = json!(end);
        Ok(s)
    }
}
pub fn parse_backup(
    w: &OpenedWallet,
    raw: &str,
) -> Result<std::collections::BTreeMap<String, StoredGrant>> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Backup {
        schema: String,
        owner_public_key: String,
        grants: std::collections::BTreeMap<String, StoredGrant>,
    }
    let b: Backup = c1::parse(raw.as_bytes())?;
    if b.schema != "castalia.holder-grant-backup.v1"
        || b.owner_public_key != w.public_key_hex()
        || b.grants.len() > 128
    {
        return Err("invalid_grant_backup");
    }
    for (service, g) in &b.grants {
        if service != &g.pin().service || g.holder() != w.public_key_hex() {
            return Err("invalid_grant_backup");
        }
        g.verify(g.saved_at())?;
    }
    Ok(b.grants)
}
