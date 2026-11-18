//! Current local nine-action approval. All session grants use v2 domains.
pub use super::current_approval::Signed;
use super::current_approval::{Creator, Evaluation, Head, Outpoint, Proof, fixed_v2};
use super::{FixtureError, FixtureResult, canonical, lower_hex, sha};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};

pub const PROFILE: &str = "d426292b5dd828a345872343f56a22a99a949114fa7123d71faa14c4f477fbc5";

fn ensure(ok: bool, msg: &'static str) -> FixtureResult<()> {
    if ok { Ok(()) } else { Err(FixtureError(msg)) }
}
fn decode_fixed<const N: usize>(s: &str) -> FixtureResult<[u8; N]> {
    ensure(lower_hex(s, N), "current lowercase fixed-width hex")?;
    let mut buf = [0; N];
    hex::decode_to_slice(s, &mut buf).map_err(|_| FixtureError("invalid fixed hex"))?;
    Ok(buf)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(in crate::funding_fixture) enum Evidence {
    None {},
    Policy {
        id: String,
        #[serde(deserialize_with = "explicit_optional_hex")]
        record: Option<String>,
        #[serde(deserialize_with = "explicit_optional_hex")]
        content: Option<String>,
        proof: Proof,
    },
    RequestAbsence {
        id: String,
    },
    CurrentRequest {
        id: String,
        seed: Outpoint,
        outpoint: Outpoint,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewContext {
    pub(in crate::funding_fixture) schema: String,
    pub(in crate::funding_fixture) profile_id: String,
    pub(in crate::funding_fixture) source_id: String,
    pub(in crate::funding_fixture) point: String,
    pub(in crate::funding_fixture) generation: u64,
    pub(in crate::funding_fixture) slot: u64,
    pub(in crate::funding_fixture) head: Head,
    pub(in crate::funding_fixture) envelope_sha256: String,
    pub(in crate::funding_fixture) creators: Vec<Creator>,
    pub(in crate::funding_fixture) evidence: Evidence,
    pub(in crate::funding_fixture) evaluated: Vec<Evaluation>,
}

use super::{FixtureWitness, FundingFixtureSession, nonce};
use ed25519_dalek::VerifyingKey;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Role {
    Controller,
    Recovery,
    FeePayer,
    Author,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileStatement {
    schema: String,
    session_id: String,
    session_epoch: u64,
    role: Role,
    key_hash: String,
    profile_id: String,
    source_id: String,
}
macro_rules! statement{
    ($name:ident $(,$extra:ident:$ty:ty)*)=>{
        #[derive(Debug,Serialize,Deserialize)]
        #[serde(rename_all="camelCase",deny_unknown_fields)]
        pub struct $name{
            schema:String,session_id:String,session_epoch:u64,role:Role,key_hash:String,source_id:String,
            point:String,generation:u64,context_digest:String,transaction_body_hash:String,
            transaction_envelope_hash:String,common_review_hash:String,$($extra:$ty,)*
        }
    }
}
statement!(Intent);
statement!(Release,handle:String);
struct Pending {
    handle: String,
    base: Json,
    expires: Instant,
    body: [u8; 32],
}

fn participates(role: Role, own: &str, review: &Json) -> bool {
    if !review["requiredSignerKeyHashes"]
        .as_array()
        .is_some_and(|keys| keys.iter().any(|key| key == own))
    {
        return false;
    }
    let payer_address = review["outputEffects"]
        .as_array()
        .and_then(|outputs| outputs.last())
        .and_then(|out| out["address"].as_str());
    let is_payer = payer_address.and_then(|addr| addr.strip_prefix("60")) == Some(own);
    let action = review["action"].as_str().unwrap_or("");
    match role {
        Role::FeePayer => is_payer,
        Role::Controller => {
            !is_payer
                && matches!(action, "add" | "direct" | "proposalPay")
                && review["stateBefore"]["controller"] == own
        }
        Role::Recovery => {
            !is_payer
                && matches!(action, "disable" | "restore" | "replace")
                && review["stateBefore"]["roster"]
                    .as_array()
                    .is_some_and(|keys| keys.iter().any(|k| k == own))
        }
        Role::Author => {
            !is_payer
                && match action {
                    "create" => review["effects"]["after"]["author"] == own,
                    "revise" => review["effects"]["before"]["author"] == own,
                    _ => false,
                }
        }
    }
}

/// One fresh process-local payment credential. The fixture has no key import, saved vault or key export.
pub struct ApprovalSession {
    inner: FundingFixtureSession,
    role: Role,
    source: Option<String>,
    anchor: Option<(u64, String)>,
    pending: Option<Pending>,
}
impl ApprovalSession {
    pub fn fresh(observer: [u8; 32], role: Role) -> FixtureResult<Self> {
        let k = VerifyingKey::from_bytes(&observer)
            .map_err(|_| FixtureError("invalid startup observer"))?;
        ensure(!k.is_weak(), "weak observer key")?;
        let network = crate::CardanoFundingNetworkV1::testnet(2, &"12".repeat(32))
            .map_err(|_| FixtureError("synthetic network"))?;
        Ok(Self {
            inner: FundingFixtureSession::fresh(observer, network)?,
            role,
            source: None,
            anchor: None,
            pending: None,
        })
    }
    fn identity(&self) -> Json {
        let info = self.inner.info();
        json!({"sessionId":info.session_id,"sessionEpoch":info.epoch,"role":self.role,"keyHash":info.account.payment_key_hash()})
    }
    pub fn info(&self) -> FixtureResult<Json> {
        self.inner.active()?;
        let mut i = self.identity();
        i["paymentPublicKey"] = json!(self.inner.info().account.payment_public_key());
        i["address"] = json!(self.inner.info().account.address());
        Ok(i)
    }
    fn verify<T: Serialize>(&self, receipt: &Signed<T>, expected: &Json) -> FixtureResult<()> {
        let supplied = serde_json::to_value(&receipt.statement)
            .map_err(|_| FixtureError("current signed statement"))?;
        ensure(
            &supplied == expected,
            "wrong session role, challenge or statement",
        )?;
        let domain = expected["schema"]
            .as_str()
            .ok_or(FixtureError("missing statement schema"))?
            .to_string()
            + "\0";
        self.inner
            .verify(&domain, &supplied, &receipt.signature_hex)
    }
    pub fn install(&mut self, receipt: &Signed<ProfileStatement>) -> FixtureResult<()> {
        self.inner.active()?;
        ensure(
            self.source.is_none() && lower_hex(&receipt.statement.source_id, 32),
            "immutable observer source",
        )?;
        let mut expected = self.identity();
        expected["schema"] = json!("castalia.kettle-current-approval-profile.v2");
        expected["profileId"] = json!(PROFILE);
        expected["sourceId"] = json!(receipt.statement.source_id);
        self.verify(receipt, &expected)?;
        self.source = Some(receipt.statement.source_id.clone());
        Ok(())
    }
    pub fn inspect(&self, original: &str, c: &ReviewContext) -> FixtureResult<Json> {
        self.inner.active()?;
        ensure(
            self.source.as_ref() == Some(&c.source_id),
            "wrong or uninstalled source incarnation",
        )?;
        if let Some((generation, point)) = &self.anchor {
            ensure(
                c.generation > *generation || (c.generation == *generation && &c.point == point),
                "stale source generation",
            )?;
        }
        let review = fixed_v2::inspect(original, c)?;
        let own = self.inner.info().account.payment_key_hash();
        ensure(
            participates(self.role, own, &review),
            "fresh native payment credential must actually participate",
        )?;
        Ok(review)
    }
    pub fn prepare(
        &mut self,
        original: &str,
        c: &ReviewContext,
        receipt: &Signed<Intent>,
    ) -> FixtureResult<Json> {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| Instant::now() >= p.expires)
        {
            self.pending = None;
        }
        ensure(self.pending.is_none(), "one pending consent")?;
        let review = self.inspect(original, c)?;
        let mut expected = self.identity();
        for k in [
            "contextDigest",
            "transactionBodyHash",
            "transactionEnvelopeHash",
        ] {
            expected[k] = review[k].clone();
        }
        expected["schema"] = json!("castalia.kettle-current-approval-intent.v2");
        expected["sourceId"] = json!(c.source_id);
        expected["point"] = json!(c.point);
        expected["generation"] = json!(c.generation);
        let common_hash = sha(&canonical(&review)?);
        expected["commonReviewHash"] = json!(common_hash);
        self.verify(receipt, &expected)?;
        let handle = nonce();
        self.pending = Some(Pending {
            handle: handle.clone(),
            base: expected,
            expires: Instant::now() + Duration::from_secs(30),
            body: decode_fixed::<32>(
                review["transactionBodyHash"]
                    .as_str()
                    .ok_or(FixtureError("missing admission body"))?,
            )?,
        });
        self.anchor = Some((c.generation, c.point.clone()));
        Ok(json!({"handle":handle,"commonReviewHash":common_hash}))
    }
    pub fn release(&mut self, receipt: &Signed<Release>) -> FixtureResult<FixtureWitness> {
        self.inner.active()?;
        let p = self
            .pending
            .take()
            .ok_or(FixtureError("no pending current consent"))?;
        ensure(Instant::now() < p.expires, "expired current consent")?;
        let mut expected = p.base;
        expected["schema"] = json!("castalia.kettle-current-approval-release.v2");
        expected["handle"] = json!(p.handle);
        self.verify(receipt, &expected)?;
        let w = self
            .inner
            .wallet
            .as_ref()
            .ok_or(FixtureError("closed native fixture"))?;
        let root = Zeroizing::new(w.signing_key.to_bytes());
        let (public, signature) =
            crate::chain_accounts::cardano_payment_fixture_witness(&root, &p.body);
        Ok(FixtureWitness {
            label: "synthetic-fixture-approval-only".into(),
            transaction_body_hash: hex::encode(p.body),
            public_key: hex::encode(public),
            signature: hex::encode(signature),
        })
    }
    pub fn cancel(&mut self, handle: &str) -> bool {
        if self.pending.as_ref().is_some_and(|p| p.handle == handle) {
            self.pending = None;
            true
        } else {
            false
        }
    }
    pub fn lock(&mut self) {
        self.pending = None;
        self.inner.close();
    }
}

/// Independent static cross-runtime comparison; this entry point cannot issue a signature.
pub fn inspect_public(original: &str, context: &ReviewContext) -> FixtureResult<Json> {
    fixed_v2::inspect(original, context)
}

fn explicit_optional_hex<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}

#[cfg(test)]
mod tests;
