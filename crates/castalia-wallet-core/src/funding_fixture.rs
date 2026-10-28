//! Opt-in disposable synthetic fixture custody. Never a production permission/consent API.
mod cbor;
use crate::{CardanoFundingAccountV1, CardanoFundingNetworkV1, OpenedWallet};
use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use cbor::{Node, Value};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub const PROFILE_DOMAIN: &str = "castalia/cardano-fixture-profile/v1\0";
pub const CONTEXT_DOMAIN: &str = "castalia/cardano-fixture-context/v1\0";
pub const ADMISSION_DOMAIN: &str = "castalia/cardano-fixture-admission/v1\0";
const STATE_TOKEN: &str = "544541504f545f53544154455f5631";
const MAX_TX: usize = 32768;
const MAX_PENDING: usize = 8;
const MAX_JSON_INTEGER: u64 = 9_007_199_254_740_991;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureError(pub &'static str);
impl std::fmt::Display for FixtureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for FixtureError {}
pub type FixtureResult<T> = std::result::Result<T, FixtureError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FixtureProfile {
    pub schema: String,
    pub backend: String,
    pub execution_profile_digest: String,
    pub allowed_script_hashes: Vec<String>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureInfo {
    pub session_id: String,
    pub epoch: u64,
    pub account: CardanoFundingAccountV1,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FixtureReview {
    pub kind: String,
    pub fund_script_hash: String,
    pub state_asset_name: String,
    pub redeemer_data_hex: String,
    pub purpose: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureInspection {
    pub statement: JsonValue,
    pub review: FixtureReview,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixturePreparation {
    pub handle: String,
    pub review: FixtureReview,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureWitness {
    pub label: String,
    pub transaction_body_hash: String,
    pub public_key: String,
    pub signature: String,
}
struct Context {
    generation: u64,
    digest: String,
}
struct Prepared {
    body_hash: [u8; 32],
    epoch: u64,
    context_generation: u64,
    context_digest: String,
    deadline: Instant,
}
/// No import, deserialization, recovery, cloning or private-material export constructor exists.
pub struct FundingFixtureSession {
    wallet: Option<OpenedWallet>,
    owner: VerifyingKey,
    info: FixtureInfo,
    profile: Option<FixtureProfile>,
    profile_digest: Option<String>,
    context: Option<Context>,
    pending: BTreeMap<String, Prepared>,
    used_admissions: BTreeSet<String>,
    ttl: Duration,
}
fn canonical<T: Serialize>(v: &T) -> FixtureResult<Vec<u8>> {
    serde_jcs::to_vec(v).map_err(|_| FixtureError("cannot encode fixture statement"))
}
pub fn fixture_transcript<T: Serialize>(domain: &str, v: &T) -> FixtureResult<Vec<u8>> {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.extend(canonical(v)?);
    Ok(bytes)
}
fn sha(v: &[u8]) -> String {
    hex::encode(Sha256::digest(v))
}
fn hash32(raw: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut h = Blake2bVar::new(32).expect("fixed digest");
    Update::update(&mut h, raw);
    h.finalize_variable(&mut out).expect("fixed digest");
    out
}
fn lower_hex(s: &str, n: usize) -> bool {
    s.len() == n * 2
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn nonce() -> String {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    hex::encode(n)
}
impl FundingFixtureSession {
    pub fn fresh(owner: [u8; 32], network: CardanoFundingNetworkV1) -> FixtureResult<Self> {
        Self::fresh_with_ttl(owner, network, Duration::from_secs(30))
    }
    /// A shorter TTL is useful for expiry tests; the fixed upper bound cannot be extended.
    pub fn fresh_with_ttl(
        owner: [u8; 32],
        network: CardanoFundingNetworkV1,
        ttl: Duration,
    ) -> FixtureResult<Self> {
        if ttl.is_zero() || ttl > Duration::from_secs(60) {
            return Err(FixtureError("invalid fixture TTL"));
        }
        let owner =
            VerifyingKey::from_bytes(&owner).map_err(|_| FixtureError("invalid fixture owner"))?;
        let wallet = OpenedWallet::from_signing_key(SigningKey::generate(&mut OsRng), 0);
        let account = wallet
            .cardano_funding_account(&network)
            .map_err(|_| FixtureError("cannot derive fixture account"))?;
        Ok(Self {
            wallet: Some(wallet),
            owner,
            info: FixtureInfo {
                session_id: nonce(),
                epoch: 0,
                account,
            },
            profile: None,
            profile_digest: None,
            context: None,
            pending: BTreeMap::new(),
            used_admissions: BTreeSet::new(),
            ttl,
        })
    }
    pub fn info(&self) -> &FixtureInfo {
        &self.info
    }
    fn active(&self) -> FixtureResult<()> {
        if self.wallet.is_some() {
            Ok(())
        } else {
            Err(FixtureError("fixture session closed"))
        }
    }
    fn verify(&self, domain: &str, statement: &JsonValue, signature: &str) -> FixtureResult<()> {
        if !lower_hex(signature, 64) {
            return Err(FixtureError("invalid owner signature"));
        }
        let bytes = hex::decode(signature).map_err(|_| FixtureError("invalid owner signature"))?;
        let sig =
            Signature::from_slice(&bytes).map_err(|_| FixtureError("invalid owner signature"))?;
        self.owner
            .verify_strict(&fixture_transcript(domain, statement)?, &sig)
            .map_err(|_| FixtureError("untrusted fixture admission"))
    }
    pub fn profile_statement(&self, profile: &FixtureProfile) -> FixtureResult<JsonValue> {
        self.active()?;
        if profile.schema != "castalia.cardano-fixture-execution-profile.v1"
            || profile.backend != "scalus-1.4.1"
            || !lower_hex(&profile.execution_profile_digest, 32)
            || profile.allowed_script_hashes.is_empty()
            || profile.allowed_script_hashes.len() > 16
            || !profile
                .allowed_script_hashes
                .iter()
                .all(|h| lower_hex(h, 28))
            || !profile
                .allowed_script_hashes
                .windows(2)
                .all(|p| p[0] < p[1])
        {
            return Err(FixtureError("invalid synthetic execution profile"));
        }
        Ok(
            json!({"schema":"castalia.cardano-fixture-profile.v1","sessionId":self.info.session_id,"epoch":self.info.epoch,"network":self.info.account.network(),"profile":profile}),
        )
    }
    pub fn set_profile(
        &mut self,
        profile: FixtureProfile,
        signature: &str,
    ) -> FixtureResult<String> {
        if self.profile.is_some() {
            return Err(FixtureError("fixture profile immutable"));
        }
        let statement = self.profile_statement(&profile)?;
        self.verify(PROFILE_DOMAIN, &statement, signature)?;
        let digest = sha(&canonical(&statement)?);
        self.profile = Some(profile);
        self.profile_digest = Some(digest.clone());
        Ok(digest)
    }
    pub fn context_statement(&self, generation: u64, digest: &str) -> FixtureResult<JsonValue> {
        self.active()?;
        if generation > MAX_JSON_INTEGER {
            return Err(FixtureError("unsafe context generation"));
        }
        if !lower_hex(digest, 32) {
            return Err(FixtureError("invalid context digest"));
        }
        let profile = self
            .profile_digest
            .as_ref()
            .ok_or(FixtureError("profile not installed"))?;
        Ok(
            json!({"schema":"castalia.cardano-fixture-context.v1","sessionId":self.info.session_id,"epoch":self.info.epoch,"profileDigest":profile,"generation":generation,"digest":digest}),
        )
    }
    pub fn set_context(
        &mut self,
        generation: u64,
        digest: &str,
        signature: &str,
    ) -> FixtureResult<()> {
        let statement = self.context_statement(generation, digest)?;
        self.verify(CONTEXT_DOMAIN, &statement, signature)?;
        if self
            .context
            .as_ref()
            .is_some_and(|c| generation <= c.generation)
        {
            return Err(FixtureError("stale context generation"));
        }
        self.pending.clear();
        self.used_admissions.clear();
        self.context = Some(Context {
            generation,
            digest: digest.into(),
        });
        Ok(())
    }
    pub fn inspect(&self, transaction_hex: &str) -> FixtureResult<FixtureInspection> {
        self.active()?;
        let profile = self
            .profile
            .as_ref()
            .ok_or(FixtureError("profile not installed"))?;
        let context = self
            .context
            .as_ref()
            .ok_or(FixtureError("context not installed"))?;
        if transaction_hex.is_empty()
            || transaction_hex.len() > MAX_TX * 2
            || transaction_hex.len() % 2 != 0
            || !lower_hex(transaction_hex, transaction_hex.len() / 2)
        {
            return Err(FixtureError("invalid bounded transaction hex"));
        }
        let bytes =
            hex::decode(transaction_hex).map_err(|_| FixtureError("invalid transaction hex"))?;
        let (body_hash, review) =
            inspect_envelope(&bytes, profile, self.info.account.payment_key_hash())?;
        let statement = json!({"schema":"castalia.cardano-fixture-admission.v1","sessionId":self.info.session_id,"epoch":self.info.epoch,"profileDigest":self.profile_digest,"contextGeneration":context.generation,"contextDigest":context.digest,"paymentKeyHash":self.info.account.payment_key_hash(),"transactionBodyHash":hex::encode(body_hash),"transactionEnvelopeHash":sha(&bytes),"reviewHash":sha(&canonical(&review)?)});
        Ok(FixtureInspection { statement, review })
    }
    pub fn prepare(
        &mut self,
        transaction_hex: &str,
        owner_signature: &str,
    ) -> FixtureResult<FixturePreparation> {
        if self.pending.len() >= MAX_PENDING {
            return Err(FixtureError("too many pending preparations"));
        }
        let inspected = self.inspect(transaction_hex)?;
        // This signature is an explicitly trusted SYNTHETIC verifier capability, not an end-user assertion.
        // Its issuer must independently verify script_data_hash, action semantics and resolved context.
        self.verify(ADMISSION_DOMAIN, &inspected.statement, owner_signature)?;
        let admission_id = sha(&canonical(&inspected.statement)?);
        if self.used_admissions.len() >= 64 || !self.used_admissions.insert(admission_id) {
            return Err(FixtureError("reused or exhausted admission capability"));
        }
        let hash = hex::decode(
            inspected.statement["transactionBodyHash"]
                .as_str()
                .ok_or(FixtureError("missing inspected hash"))?,
        )
        .map_err(|_| FixtureError("invalid inspected hash"))?;
        let body_hash = hash
            .try_into()
            .map_err(|_| FixtureError("invalid inspected hash"))?;
        let context = self
            .context
            .as_ref()
            .ok_or(FixtureError("context not installed"))?;
        let handle = nonce();
        self.pending.insert(
            handle.clone(),
            Prepared {
                body_hash,
                epoch: self.info.epoch,
                context_generation: context.generation,
                context_digest: context.digest.clone(),
                deadline: Instant::now() + self.ttl,
            },
        );
        Ok(FixturePreparation {
            handle,
            review: inspected.review,
        })
    }
    pub fn approve(&mut self, handle: &str) -> FixtureResult<FixtureWitness> {
        // Consume before all subsequent checks. No body, key, profile or context is supplied by the caller.
        let prepared = self
            .pending
            .remove(handle)
            .ok_or(FixtureError("unknown or consumed handle"))?;
        self.active()?;
        let context = self
            .context
            .as_ref()
            .ok_or(FixtureError("context not installed"))?;
        if prepared.epoch != self.info.epoch
            || prepared.context_generation != context.generation
            || prepared.context_digest != context.digest
            || Instant::now() >= prepared.deadline
        {
            return Err(FixtureError("stale fixture preparation"));
        }
        let wallet = self
            .wallet
            .as_ref()
            .ok_or(FixtureError("fixture session closed"))?;
        let root = Zeroizing::new(wallet.signing_key.to_bytes());
        let (public, signature) =
            crate::chain_accounts::cardano_payment_fixture_witness(&root, &prepared.body_hash);
        Ok(FixtureWitness {
            label: "synthetic-fixture-approval-only".into(),
            transaction_body_hash: hex::encode(prepared.body_hash),
            public_key: hex::encode(public),
            signature: hex::encode(signature),
        })
    }
    pub fn cancel(&mut self, handle: &str) -> bool {
        self.pending.remove(handle).is_some()
    }
    pub fn invalidate(&mut self) -> FixtureResult<()> {
        self.active()?;
        self.pending.clear();
        self.used_admissions.clear();
        self.context = None;
        if self.info.epoch >= MAX_JSON_INTEGER {
            return Err(FixtureError("fixture epoch exhausted"));
        }
        self.info.epoch += 1;
        Ok(())
    }
    pub fn close(&mut self) {
        self.pending.clear();
        self.used_admissions.clear();
        self.context = None;
        self.wallet.take();
    }
}

fn check_refs(node: &Node) -> FixtureResult<usize> {
    let refs = node.set()?;
    if refs.len() > 64 {
        return Err(FixtureError("too many input references"));
    }
    let mut seen = Vec::new();
    for node in refs {
        let r = node.array()?;
        if r.len() != 2
            || r[0].bytes()?.len() != 32
            || r[1].int()? < 0
            || r[1].int()? > u32::MAX.into()
        {
            return Err(FixtureError("invalid input reference"));
        }
        if seen.contains(&node) {
            return Err(FixtureError("duplicate input reference"));
        }
        seen.push(node);
    }
    Ok(refs.len())
}
fn check_output(node: &Node) -> FixtureResult<()> {
    let address = match &node.value {
        Value::Array(a) if a.len() == 2 || a.len() == 3 => a[0].bytes()?,
        Value::Map(_) => {
            node.closed_map(&[0, 1, 2])?;
            node.required(0)?.bytes()?
        }
        _ => return Err(FixtureError("unsupported output shape")),
    };
    if address.is_empty() || address[0] & 15 != 0 || address[0] >> 4 > 7 {
        return Err(FixtureError("unsupported or non-testnet address"));
    }
    Ok(())
}
fn inspect_envelope(
    raw: &[u8],
    profile: &FixtureProfile,
    payment_hash: &str,
) -> FixtureResult<([u8; 32], FixtureReview)> {
    let parsed = cbor::parse(raw)?;
    let tx = parsed.array()?;
    if tx.len() != 4 || tx[2].value != Value::Bool(true) || tx[3].value != Value::Null {
        return Err(FixtureError("unsupported transaction envelope"));
    }
    let body = &tx[0];
    body.closed_map(&[0, 1, 2, 3, 8, 9, 11, 13, 14, 15, 16, 17, 18])?;
    if check_refs(body.required(0)?)? == 0 {
        return Err(FixtureError("no consumed inputs"));
    }
    let mut total = body.required(0)?.set()?.len();
    for k in [13, 18] {
        if let Some(refs) = body.field(k)? {
            total += check_refs(refs)?;
        }
    }
    if total > 64 {
        return Err(FixtureError("too many resolved inputs"));
    }
    if let Some(network) = body.field(15)? {
        if network.int()? != 0 {
            return Err(FixtureError("mainnet body rejected"));
        }
    }
    if body.required(2)?.int()? < 0 {
        return Err(FixtureError("negative transaction fee"));
    }
    if body.required(11)?.bytes()?.len() != 32 {
        return Err(FixtureError("invalid script data hash"));
    }
    let outputs = body.required(1)?.array()?;
    if outputs.is_empty() || outputs.len() > 64 {
        return Err(FixtureError("unsupported output count"));
    }
    for output in outputs {
        check_output(output)?;
    }
    if let Some(collateral) = body.field(16)? {
        check_output(collateral)?;
    }
    let signers = body.required(14)?.set()?;
    if signers.is_empty() || signers.len() > 16 {
        return Err(FixtureError("unsupported signer count"));
    }
    let mut seen = Vec::new();
    for signer in signers {
        let b = signer.bytes()?;
        if b.len() != 28 || seen.contains(&b) {
            return Err(FixtureError("invalid or duplicate required signer"));
        }
        seen.push(b);
    }
    let selected =
        hex::decode(payment_hash).map_err(|_| FixtureError("invalid payment credential"))?;
    if !seen.contains(&selected.as_slice()) {
        return Err(FixtureError("derived payment signer missing"));
    }
    let witnesses = &tx[1];
    witnesses.closed_map(&[0, 4, 5, 7])?;
    let scripts = witnesses.required(7)?.set()?;
    if scripts.len() != 1 {
        return Err(FixtureError("exactly one admitted V3 script required"));
    }
    let script = scripts[0].bytes()?;
    let mut hash = [0u8; 28];
    let mut hasher = Blake2bVar::new(28).expect("fixed digest");
    Update::update(&mut hasher, &[3]);
    Update::update(&mut hasher, script);
    hasher.finalize_variable(&mut hash).expect("fixed digest");
    let script_hash = hex::encode(hash);
    if !profile.allowed_script_hashes.contains(&script_hash) {
        return Err(FixtureError("script not admitted by fixture owner"));
    }
    let redeemers = witnesses.required(5)?.array()?;
    if redeemers.is_empty() || redeemers.len() > 32 {
        return Err(FixtureError("unsupported redeemer count"));
    }
    let mut first: Option<&Node> = None;
    let mut common_tag = None;
    let mut indices = Vec::new();
    for r in redeemers {
        let fields = r.array()?;
        if fields.len() != 4 {
            return Err(FixtureError("unsupported redeemer shape"));
        }
        let tag = fields[0].int()?;
        let index = fields[1].int()?;
        if !(0..=1).contains(&tag) || index < 0 || index >= 64 || indices.contains(&(tag, index)) {
            return Err(FixtureError("invalid redeemer index"));
        }
        indices.push((tag, index));
        if common_tag.is_some_and(|old| old != tag) {
            return Err(FixtureError("mixed funding actions unsupported"));
        }
        common_tag = Some(tag);
        if first.is_some_and(|old| old != &fields[2]) {
            return Err(FixtureError("differing funding actions"));
        }
        first = first.or(Some(&fields[2]));
        let budget = fields[3].array()?;
        if budget.len() != 2
            || budget
                .iter()
                .any(|n| n.int().is_err() || n.int().unwrap_or(-1) < 0)
        {
            return Err(FixtureError("invalid execution budget"));
        }
    }
    let data = first.ok_or(FixtureError("missing funding action"))?;
    let (constructor, fields) = data.constructor()?;
    let (kind, purpose) = match (common_tag, constructor, fields.len()) {
        (Some(1), 0, 0) => {
            if redeemers.len() != 1 || body.field(9)?.is_none() {
                return Err(FixtureError("invalid bootstrap action"));
            }
            ("teapot-bootstrap", None)
        }
        (Some(0), 0, 2) => ("teapot-restore-controller", None),
        (Some(0), 1, 2) => ("teapot-replace-recovery", None),
        (Some(0), 2, 8) => {
            let purpose = fields[3].bytes()?;
            if purpose.is_empty() || purpose.len() > 512 {
                return Err(FixtureError("invalid funding purpose"));
            }
            let purpose = std::str::from_utf8(purpose)
                .map_err(|_| FixtureError("invalid UTF-8 funding purpose"))?;
            ("teapot-direct-payout", Some(purpose.to_owned()))
        }
        _ => return Err(FixtureError("unsupported funding action")),
    };
    Ok((
        hash32(&raw[body.start..body.end]),
        FixtureReview {
            kind: kind.into(),
            fund_script_hash: script_hash,
            state_asset_name: STATE_TOKEN.into(),
            redeemer_data_hex: hex::encode(&raw[data.start..data.end]),
            purpose,
        },
    ))
}
