//! Private, unqualified public Wallet/native metadata and retained-record codec.
//! Parsing proves bounded syntax and mathematical consistency only. These values
//! authenticate no filesystem, clock, caller, policy selection or execution.
//! No keys, signatures, owner source, lease, publication or qualification API.
use crate::service_authority_snapshot::{
    canonical, strict_value, validate_unqualified_policy_body,
};
use ed25519_dalek::VerifyingKey;
use libsec_core::service_holder_proof::MAX_SAFE_TIME;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const REFERENCE_PROFILE: &str = "secs.wallet-current-reference.v2";
const POLICY_PROFILE: &str = "secs.wallet-native-target-policy.v1";
const BUNDLE_PROFILE: &str = "secs.service-owner-bundle.v2";
const MARKER_PROFILE: &str = "secs.wallet-current-transition.v3";
const OUTCOME_PROFILE: &str = "secs.wallet-current-outcome.v3";
const REFERENCE_LIMIT: usize = 4096;
const RECORD_LIMIT: usize = 16384;
const POLICY_LIMIT: usize = 262144;
const POLICY_FIELDS: &[&str] = &[
    "valid_not_before",
    "valid_until",
    "application",
    "issuer_node_id",
    "selected_issuer_key_id",
    "issuers",
    "holders",
    "descriptors",
    "permissions",
    "receiver_policy",
];
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContractError {
    Invalid,
    Bounds,
    Binding,
    Relation,
}
type Result<T> = std::result::Result<T, ContractError>;
fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
fn decoded_hex(s: &str, length: usize) -> Result<Vec<u8>> {
    if s.len() != length * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ContractError::Invalid);
    }
    (0..length)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ContractError::Invalid))
        .collect()
}
fn digest(v: &Value) -> Result<[u8; 32]> {
    decoded_hex(string(v, 64)?, 32)?
        .try_into()
        .map_err(|_| ContractError::Invalid)
}
fn string(v: &Value, max: usize) -> Result<&str> {
    v.as_str()
        .filter(|s| {
            !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
        })
        .ok_or(ContractError::Invalid)
}
fn integer(v: &Value, positive: bool) -> Result<u64> {
    v.as_u64()
        .filter(|n| *n <= MAX_SAFE_TIME && (!positive || *n != 0))
        .ok_or(ContractError::Invalid)
}
fn closed(v: &Value, fields: &[&str]) -> Result<()> {
    let map = v.as_object().ok_or(ContractError::Invalid)?;
    if map.len() != fields.len() || fields.iter().any(|f| !map.contains_key(*f)) {
        return Err(ContractError::Invalid);
    }
    Ok(())
}
fn decode(raw: &[u8], limit: usize) -> Result<Value> {
    if raw.is_empty() || raw.len() > limit {
        return Err(ContractError::Bounds);
    }
    let v = strict_value(raw).map_err(|_| ContractError::Invalid)?;
    if canonical(&v) != raw {
        return Err(ContractError::Invalid);
    }
    Ok(v)
}
fn window(start: &Value, end: &Value) -> Result<()> {
    if integer(start, false)? >= integer(end, true)? {
        return Err(ContractError::Invalid);
    }
    Ok(())
}
fn frame(out: &mut Vec<u8>, name: &str, value: &[u8]) -> Result<()> {
    let n = u16::try_from(name.len()).map_err(|_| ContractError::Bounds)?;
    let size = u32::try_from(value.len()).map_err(|_| ContractError::Bounds)?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
fn nullable_bytes(v: &Value, time: bool) -> Result<Vec<u8>> {
    if v.is_null() {
        return Ok(vec![0]);
    }
    let mut result = vec![1];
    if time {
        result.extend_from_slice(&integer(v, true)?.to_be_bytes());
    } else {
        result.extend_from_slice(&digest(v)?);
    }
    Ok(result)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalletState {
    Active,
    Unconfigured,
    Revoked,
}
/// Caller-provided public metadata only; even Active is not source or authority.
#[derive(Debug)]
pub(crate) struct WalletReference {
    value: Value,
    raw: Vec<u8>,
    state: WalletState,
}
impl WalletReference {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self> {
        Self::from_value(decode(raw, REFERENCE_LIMIT)?)
    }
    fn from_value(v: Value) -> Result<Self> {
        closed(
            &v,
            &[
                "schema",
                "store_id",
                "subject_id",
                "purpose",
                "application",
                "state_revision",
                "key_generation",
                "state",
                "current_sha256",
                "custody_state_sha256",
                "key_id",
                "public_key_hex",
                "public_key_sha256",
                "not_before",
                "not_after",
                "revoked_at",
                "owner_input_sha256",
                "delegation_policy_sha256",
            ],
        )?;
        if v["schema"] != REFERENCE_PROFILE
            || v["purpose"] != "secs-service-holder-proof.v1"
            || !matches!(v["application"].as_str(), Some("runtime" | "service"))
        {
            return Err(ContractError::Invalid);
        }
        decoded_hex(string(&v["store_id"], 32)?, 16)?;
        string(&v["subject_id"], 128)?;
        let revision = integer(&v["state_revision"], true)?;
        let generation = integer(&v["key_generation"], true)?;
        if generation > revision {
            return Err(ContractError::Invalid);
        }
        digest(&v["current_sha256"])?;
        digest(&v["custody_state_sha256"])?;
        let public = digest(&v["public_key_hex"])?;
        let key = VerifyingKey::from_bytes(&public).map_err(|_| ContractError::Invalid)?;
        if key.is_weak()
            || digest(&v["public_key_sha256"])? != hash(&public)
            || string(&v["key_id"], 87)?
                != format!("service-ed25519:sha256:{}", hex(&hash(&public)))
        {
            return Err(ContractError::Invalid);
        }
        window(&v["not_before"], &v["not_after"])?;
        let state = match v["state"].as_str() {
            Some("active") if v["revoked_at"].is_null() => {
                digest(&v["owner_input_sha256"])?;
                digest(&v["delegation_policy_sha256"])?;
                WalletState::Active
            }
            Some("unconfigured")
                if v["revoked_at"].is_null()
                    && v["owner_input_sha256"].is_null()
                    && v["delegation_policy_sha256"].is_null() =>
            {
                WalletState::Unconfigured
            }
            Some("revoked")
                if v["owner_input_sha256"].is_null() && v["delegation_policy_sha256"].is_null() =>
            {
                integer(&v["revoked_at"], true)?;
                WalletState::Revoked
            }
            _ => return Err(ContractError::Invalid),
        };
        let raw = canonical(&v);
        if raw.len() > REFERENCE_LIMIT {
            return Err(ContractError::Bounds);
        }
        Ok(Self {
            value: v,
            raw,
            state,
        })
    }
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub(crate) fn reference_digest(&self) -> [u8; 32] {
        hash(&self.raw)
    }
    pub(crate) fn state(&self) -> WalletState {
        self.state
    }
    pub(crate) fn lineage_preimage(&self) -> Vec<u8> {
        // Every width/name below is statically bounded by the closed reference.
        self.encode_lineage().expect("validated bounded reference")
    }
    fn encode_lineage(&self) -> Result<Vec<u8>> {
        let mut out = b"secs-wallet-current-observation-v2\0".to_vec();
        for name in ["store_id", "subject_id", "purpose", "application"] {
            frame(
                &mut out,
                name,
                self.value[name]
                    .as_str()
                    .ok_or(ContractError::Invalid)?
                    .as_bytes(),
            )?;
        }
        for name in ["state_revision", "key_generation"] {
            frame(
                &mut out,
                name,
                &integer(&self.value[name], true)?.to_be_bytes(),
            )?;
        }
        frame(
            &mut out,
            "state",
            self.value["state"]
                .as_str()
                .ok_or(ContractError::Invalid)?
                .as_bytes(),
        )?;
        for name in ["current_sha256", "custody_state_sha256"] {
            frame(&mut out, name, &digest(&self.value[name])?)?;
        }
        frame(
            &mut out,
            "key_id",
            self.value["key_id"]
                .as_str()
                .ok_or(ContractError::Invalid)?
                .as_bytes(),
        )?;
        for name in ["public_key_hex", "public_key_sha256"] {
            frame(&mut out, name, &digest(&self.value[name])?)?;
        }
        for name in ["not_before", "not_after"] {
            frame(
                &mut out,
                name,
                &integer(&self.value[name], name == "not_after")?.to_be_bytes(),
            )?;
        }
        for name in [
            "revoked_at",
            "owner_input_sha256",
            "delegation_policy_sha256",
        ] {
            frame(
                &mut out,
                name,
                &nullable_bytes(&self.value[name], name == "revoked_at")?,
            )?;
        }
        Ok(out)
    }
    pub(crate) fn lineage_digest(&self) -> [u8; 32] {
        hash(&self.lineage_preimage())
    }
}
#[derive(Debug)]
pub(crate) struct StartupPin {
    value: Value,
}
impl StartupPin {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self> {
        let v = decode(raw, REFERENCE_LIMIT)?;
        closed(
            &v,
            &[
                "schema",
                "store_id",
                "minimum_state_revision",
                "minimum_key_generation",
                "expected_wallet_reference_sha256",
            ],
        )?;
        if v["schema"] != "secs.wallet-current-startup-pin.v2" {
            return Err(ContractError::Invalid);
        }
        decoded_hex(string(&v["store_id"], 32)?, 16)?;
        integer(&v["minimum_state_revision"], true)?;
        integer(&v["minimum_key_generation"], true)?;
        digest(&v["expected_wallet_reference_sha256"])?;
        Ok(Self { value: v })
    }
    /// Compares unqualified data only; authenticating the pin/source is Stage C.
    pub(crate) fn compare_reference(&self, reference: &WalletReference) -> Result<()> {
        if self.value["store_id"] != reference.value["store_id"]
            || integer(&reference.value["state_revision"], true)?
                < integer(&self.value["minimum_state_revision"], true)?
            || integer(&reference.value["key_generation"], true)?
                < integer(&self.value["minimum_key_generation"], true)?
            || digest(&self.value["expected_wallet_reference_sha256"])?
                != reference.reference_digest()
        {
            return Err(ContractError::Binding);
        }
        Ok(())
    }
}
#[derive(Debug)]
pub(crate) struct NativeCas {
    value: Value,
}
impl NativeCas {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self> {
        Self::from_value(decode(raw, REFERENCE_LIMIT)?)
    }
    fn from_value(v: Value) -> Result<Self> {
        closed(&v, &["generation", "bundle_sha256"])?;
        integer(&v["generation"], true)?;
        digest(&v["bundle_sha256"])?;
        Ok(Self { value: v })
    }
    fn generation(&self) -> Result<u64> {
        integer(&self.value["generation"], true)
    }
    fn next(&self) -> Result<u64> {
        self.generation()?
            .checked_add(1)
            .filter(|g| *g <= MAX_SAFE_TIME)
            .ok_or(ContractError::Bounds)
    }
}
/// Exact complete owner-selected policy bytes; not authenticated selection.
#[derive(Debug)]
pub(crate) struct TargetPolicy {
    value: Value,
    raw: Vec<u8>,
}
fn body(v: &Value) -> Value {
    let mut result = serde_json::Map::new();
    for name in POLICY_FIELDS {
        result.insert((*name).into(), v[*name].clone());
    }
    Value::Object(result)
}
impl TargetPolicy {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self> {
        let v = decode(raw, POLICY_LIMIT)?;
        let mut names = POLICY_FIELDS.to_vec();
        names.extend(["schema", "native_bundle_profile"]);
        closed(&v, &names)?;
        if v["schema"] != POLICY_PROFILE || v["native_bundle_profile"] != BUNDLE_PROFILE {
            return Err(ContractError::Invalid);
        }
        validate_unqualified_policy_body(body(&v), true).map_err(|_| ContractError::Invalid)?;
        Ok(Self {
            value: v,
            raw: raw.into(),
        })
    }
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        hash(&self.raw)
    }
    /// Fixed mathematical transformation only. Old CAS/current data are not
    /// authenticated here and this return value grants no publication authority.
    pub(crate) fn derive_target(
        &self,
        old: &NativeCas,
        current: &WalletReference,
    ) -> Result<TargetBundle> {
        let mut v = body(&self.value);
        let m = v.as_object_mut().ok_or(ContractError::Invalid)?;
        m.insert("schema".into(), json!(BUNDLE_PROFILE));
        m.insert("generation".into(), json!(old.next()?));
        m.insert("wallet_current".into(), current.value.clone());
        TargetBundle::parse(&canonical(&v))
    }
}
#[derive(Debug)]
pub(crate) struct TargetBundle {
    value: Value,
    raw: Vec<u8>,
    reference: WalletReference,
}
impl TargetBundle {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self> {
        let v = decode(raw, POLICY_LIMIT)?;
        let mut names = POLICY_FIELDS.to_vec();
        names.extend(["schema", "generation", "wallet_current"]);
        closed(&v, &names)?;
        if v["schema"] != BUNDLE_PROFILE {
            return Err(ContractError::Invalid);
        }
        integer(&v["generation"], true)?;
        let reference = WalletReference::from_value(v["wallet_current"].clone())?;
        if v["application"] != reference.value["application"] {
            return Err(ContractError::Binding);
        }
        validate_unqualified_policy_body(body(&v), reference.state != WalletState::Active)
            .map_err(|_| ContractError::Invalid)?;
        if reference.state == WalletState::Active {
            let w = &reference.value;
            if digest(&w["delegation_policy_sha256"])? != hash(&canonical(&v["receiver_policy"])) {
                return Err(ContractError::Binding);
            }
            let holder = v["holders"]
                .as_array()
                .ok_or(ContractError::Invalid)?
                .iter()
                .find(|h| {
                    h["key_id"] == w["key_id"]
                        && h["subject_id"] == w["subject_id"]
                        && h["public_key_hex"] == w["public_key_hex"]
                        && h["status"] == "active"
                        && h["revoked_at"].is_null()
                })
                .ok_or(ContractError::Binding)?;
            let principal = v["receiver_policy"]["principals"]
                .as_array()
                .ok_or(ContractError::Invalid)?
                .iter()
                .find(|p| {
                    p["key_id"] == w["key_id"]
                        && p["subject_id"] == w["subject_id"]
                        && p["revoked"] == false
                })
                .ok_or(ContractError::Binding)?;
            let start = integer(&v["valid_not_before"], false)?;
            let end = integer(&v["valid_until"], true)?;
            for bounds in [
                (w, "not_before", "not_after"),
                (holder, "not_before", "not_after"),
                (principal, "not_before", "not_after"),
                (&v["receiver_policy"], "not_before", "not_after"),
            ] {
                if integer(&bounds.0[bounds.1], false)? > start
                    || integer(&bounds.0[bounds.2], true)? < end
                {
                    return Err(ContractError::Binding);
                }
            }
        }
        Ok(Self {
            value: v,
            raw: raw.into(),
            reference,
        })
    }
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        hash(&self.raw)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mutation {
    Configure,
    Rotate,
    Revoke,
    Reconcile,
}
fn mutation(v: &Value) -> Result<Mutation> {
    match v.as_str() {
        Some("configure") => Ok(Mutation::Configure),
        Some("rotate") => Ok(Mutation::Rotate),
        Some("revoke") => Ok(Mutation::Revoke),
        Some("reconcile") => Ok(Mutation::Reconcile),
        _ => Err(ContractError::Invalid),
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    Configured,
    Rotated,
    Revoked,
    Reconciled,
    Aborted,
}
fn relation(v: &Value) -> Result<Relation> {
    match v.as_str() {
        Some("configured") => Ok(Relation::Configured),
        Some("rotated_unconfigured") => Ok(Relation::Rotated),
        Some("revoked") => Ok(Relation::Revoked),
        Some("reconciled_unchanged") => Ok(Relation::Reconciled),
        Some("explicit_abort_unchanged") => Ok(Relation::Aborted),
        _ => Err(ContractError::Invalid),
    }
}
fn request(v: &Value, kind: Mutation) -> Result<()> {
    closed(
        v,
        &[
            "owner_input_sha256",
            "requested_not_before",
            "requested_not_after",
            "target_policy_sha256",
        ],
    )?;
    digest(&v["target_policy_sha256"])?;
    match kind {
        Mutation::Configure => {
            digest(&v["owner_input_sha256"])?;
            if !v["requested_not_before"].is_null() || !v["requested_not_after"].is_null() {
                return Err(ContractError::Invalid);
            }
        }
        Mutation::Rotate => {
            if !v["owner_input_sha256"].is_null() {
                return Err(ContractError::Invalid);
            }
            window(&v["requested_not_before"], &v["requested_not_after"])?;
        }
        Mutation::Revoke | Mutation::Reconcile => {
            if !v["owner_input_sha256"].is_null()
                || !v["requested_not_before"].is_null()
                || !v["requested_not_after"].is_null()
            {
                return Err(ContractError::Invalid);
            }
        }
    }
    Ok(())
}
fn reference_relation(
    old: &WalletReference,
    new: &WalletReference,
    kind: Mutation,
    intent: &Value,
    r: Relation,
) -> Result<()> {
    if matches!(r, Relation::Reconciled | Relation::Aborted) {
        if old.raw != new.raw || (r == Relation::Reconciled && kind != Mutation::Reconcile) {
            return Err(ContractError::Relation);
        }
        return Ok(());
    }
    if old.state == WalletState::Revoked {
        return Err(ContractError::Relation);
    }
    for name in ["store_id", "subject_id", "purpose", "application"] {
        if old.value[name] != new.value[name] {
            return Err(ContractError::Relation);
        }
    }
    let rev = integer(&old.value["state_revision"], true)?
        .checked_add(1)
        .filter(|n| *n <= MAX_SAFE_TIME)
        .ok_or(ContractError::Bounds)?;
    if integer(&new.value["state_revision"], true)? != rev
        || old.value["current_sha256"] == new.value["current_sha256"]
        || old.value["custody_state_sha256"] == new.value["custody_state_sha256"]
    {
        return Err(ContractError::Relation);
    }
    match (kind, r) {
        (Mutation::Configure, Relation::Configured) => {
            if old.state == WalletState::Revoked
                || new.state != WalletState::Active
                || new.value["owner_input_sha256"] != intent["owner_input_sha256"]
            {
                return Err(ContractError::Relation);
            }
            for name in [
                "key_generation",
                "key_id",
                "public_key_hex",
                "public_key_sha256",
                "not_before",
                "not_after",
            ] {
                if old.value[name] != new.value[name] {
                    return Err(ContractError::Relation);
                }
            }
        }
        (Mutation::Rotate, Relation::Rotated) => {
            let generation = integer(&old.value["key_generation"], true)?
                .checked_add(1)
                .filter(|g| *g <= MAX_SAFE_TIME)
                .ok_or(ContractError::Bounds)?;
            if new.state != WalletState::Unconfigured
                || integer(&new.value["key_generation"], true)? != generation
                || new.value["key_id"] == old.value["key_id"]
                || new.value["public_key_hex"] == old.value["public_key_hex"]
                || new.value["not_before"] != intent["requested_not_before"]
                || new.value["not_after"] != intent["requested_not_after"]
            {
                return Err(ContractError::Relation);
            }
        }
        (Mutation::Revoke, Relation::Revoked) => {
            if old.state == WalletState::Revoked || new.state != WalletState::Revoked {
                return Err(ContractError::Relation);
            }
            for name in [
                "key_generation",
                "key_id",
                "public_key_hex",
                "public_key_sha256",
                "not_before",
                "not_after",
            ] {
                if old.value[name] != new.value[name] {
                    return Err(ContractError::Relation);
                }
            }
        }
        _ => return Err(ContractError::Relation),
    }
    Ok(())
}
#[derive(Debug)]
pub(crate) struct TransitionMarker {
    value: Value,
    raw: Vec<u8>,
    old: WalletReference,
    cas: NativeCas,
}
impl TransitionMarker {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self> {
        let v = decode(raw, RECORD_LIMIT)?;
        closed(
            &v,
            &[
                "schema",
                "transition_id",
                "stage",
                "mutation",
                "old_wallet_reference",
                "old_native_cas",
                "old_native_image_sha256",
                "request",
                "started_at",
                "observed_outcome",
                "target_native",
                "target_policy",
            ],
        )?;
        if v["schema"] != MARKER_PROFILE {
            return Err(ContractError::Invalid);
        }
        decoded_hex(string(&v["transition_id"], 32)?, 16)?;
        integer(&v["started_at"], true)?;
        let kind = mutation(&v["mutation"])?;
        request(&v["request"], kind)?;
        let old = WalletReference::from_value(v["old_wallet_reference"].clone())?;
        let cas = NativeCas::from_value(v["old_native_cas"].clone())?;
        cas.next()?;
        if old.state == WalletState::Revoked && kind != Mutation::Reconcile {
            return Err(ContractError::Relation);
        }
        if digest(&v["old_native_image_sha256"])? != digest(&cas.value["bundle_sha256"])? {
            return Err(ContractError::Binding);
        }
        closed(&v["target_policy"], &["profile", "sha256", "bytes"])?;
        let size = integer(&v["target_policy"]["bytes"], true)?;
        if v["target_policy"]["profile"] != POLICY_PROFILE
            || size > POLICY_LIMIT as u64
            || digest(&v["target_policy"]["sha256"])?
                != digest(&v["request"]["target_policy_sha256"])?
        {
            return Err(ContractError::Binding);
        }
        match v["stage"].as_str() {
            Some("prepared") if v["observed_outcome"].is_null() && v["target_native"].is_null() => {
            }
            Some("outcome_recorded" | "native_published") => {
                let o = &v["observed_outcome"];
                closed(
                    o,
                    &[
                        "wallet_reference",
                        "relation",
                        "outcome_sha256",
                        "target_policy_sha256",
                    ],
                )?;
                digest(&o["outcome_sha256"])?;
                let current = WalletReference::from_value(o["wallet_reference"].clone())?;
                reference_relation(
                    &old,
                    &current,
                    kind,
                    &v["request"],
                    relation(&o["relation"])?,
                )?;
                let t = &v["target_native"];
                closed(
                    t,
                    &["native_cas", "target_image_sha256", "target_policy_sha256"],
                )?;
                let target = NativeCas::from_value(t["native_cas"].clone())?;
                if target.generation()? != cas.next()?
                    || digest(&t["target_image_sha256"])? != digest(&target.value["bundle_sha256"])?
                    || digest(&o["target_policy_sha256"])? != digest(&v["target_policy"]["sha256"])?
                    || digest(&t["target_policy_sha256"])? != digest(&v["target_policy"]["sha256"])?
                {
                    return Err(ContractError::Binding);
                }
            }
            _ => return Err(ContractError::Invalid),
        }
        Ok(Self {
            value: v,
            raw: raw.into(),
            old,
            cas,
        })
    }
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.raw
    }
    fn verify_policy(&self, policy: &TargetPolicy) -> Result<()> {
        if digest(&self.value["target_policy"]["sha256"])? != policy.digest()
            || integer(&self.value["target_policy"]["bytes"], true)? != policy.raw.len() as u64
            || policy.value["application"] != self.old.value["application"]
        {
            return Err(ContractError::Binding);
        }
        Ok(())
    }
    pub(crate) fn binding_preimage(&self, policy: &TargetPolicy) -> Result<Vec<u8>> {
        self.verify_policy(policy)?;
        let mut out = b"secs-wallet-transition-target-policy-v1\0".to_vec();
        frame(&mut out, "profile", POLICY_PROFILE.as_bytes())?;
        frame(&mut out, "native_bundle_profile", BUNDLE_PROFILE.as_bytes())?;
        frame(&mut out, "target_policy_sha256", &policy.digest())?;
        frame(
            &mut out,
            "target_policy_bytes",
            &(policy.raw.len() as u64).to_be_bytes(),
        )?;
        frame(
            &mut out,
            "old_native_generation",
            &self.cas.generation()?.to_be_bytes(),
        )?;
        frame(
            &mut out,
            "old_native_bundle_sha256",
            &digest(&self.cas.value["bundle_sha256"])?,
        )?;
        frame(
            &mut out,
            "old_wallet_reference_sha256",
            &self.old.reference_digest(),
        )?;
        frame(
            &mut out,
            "mutation",
            self.value["mutation"]
                .as_str()
                .ok_or(ContractError::Invalid)?
                .as_bytes(),
        )?;
        frame(
            &mut out,
            "wallet_request_sha256",
            &hash(&canonical(&self.value["request"])),
        )?;
        frame(
            &mut out,
            "transition_id",
            &decoded_hex(string(&self.value["transition_id"], 32)?, 16)?,
        )?;
        Ok(out)
    }
}
#[derive(Debug)]
pub(crate) struct OutcomeRecord {
    value: Value,
    raw: Vec<u8>,
    current: WalletReference,
}
impl OutcomeRecord {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self> {
        let v = decode(raw, RECORD_LIMIT)?;
        closed(
            &v,
            &[
                "schema",
                "transition_id",
                "old_wallet_reference_sha256",
                "old_native_cas",
                "mutation",
                "request_sha256",
                "wallet_reference",
                "relation",
                "observed_at",
                "target_policy_sha256",
            ],
        )?;
        if v["schema"] != OUTCOME_PROFILE {
            return Err(ContractError::Invalid);
        }
        decoded_hex(string(&v["transition_id"], 32)?, 16)?;
        digest(&v["old_wallet_reference_sha256"])?;
        NativeCas::from_value(v["old_native_cas"].clone())?;
        mutation(&v["mutation"])?;
        relation(&v["relation"])?;
        digest(&v["request_sha256"])?;
        integer(&v["observed_at"], true)?;
        digest(&v["target_policy_sha256"])?;
        let current = WalletReference::from_value(v["wallet_reference"].clone())?;
        Ok(Self {
            value: v,
            raw: raw.into(),
            current,
        })
    }
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub(crate) fn reference(&self) -> &WalletReference {
        &self.current
    }
    pub(crate) fn verify(&self, marker: &TransitionMarker, policy: &TargetPolicy) -> Result<()> {
        marker.verify_policy(policy)?;
        let v = &self.value;
        let m = &marker.value;
        if v["transition_id"] != m["transition_id"]
            || v["old_native_cas"] != m["old_native_cas"]
            || v["mutation"] != m["mutation"]
            || digest(&v["old_wallet_reference_sha256"])? != marker.old.reference_digest()
            || digest(&v["request_sha256"])? != hash(&canonical(&m["request"]))
            || digest(&v["target_policy_sha256"])? != policy.digest()
            || integer(&v["observed_at"], true)? < integer(&m["started_at"], true)?
        {
            return Err(ContractError::Binding);
        }
        if !self.current.value["revoked_at"].is_null()
            && integer(&self.current.value["revoked_at"], true)? > integer(&v["observed_at"], true)?
        {
            return Err(ContractError::Binding);
        }
        reference_relation(
            &marker.old,
            &self.current,
            mutation(&m["mutation"])?,
            &m["request"],
            relation(&v["relation"])?,
        )?;
        if m["stage"] != "prepared" {
            let observed = &m["observed_outcome"];
            if observed["wallet_reference"] != v["wallet_reference"]
                || observed["relation"] != v["relation"]
                || digest(&observed["outcome_sha256"])? != hash(&self.raw)
            {
                return Err(ContractError::Binding);
            }
        }
        Ok(())
    }
}
/// Pure retained-byte consistency checks. No actual root, CURRENT, lease, CAS
/// publication or sampled time is attested. Stage C must independently read and
/// authenticate those sources under its concrete retained administration sessions.
pub(crate) fn verify_retained_transition(
    marker: &TransitionMarker,
    policy: &TargetPolicy,
    old_raw: &[u8],
    outcome: Option<&OutcomeRecord>,
    target_raw: Option<&[u8]>,
) -> Result<()> {
    marker.verify_policy(policy)?;
    let old = TargetBundle::parse(old_raw)?;
    if old.digest() != digest(&marker.cas.value["bundle_sha256"])?
        || old.value["generation"] != marker.cas.value["generation"]
        || old.reference.raw != marker.old.raw
    {
        return Err(ContractError::Binding);
    }
    match (outcome, target_raw) {
        (None, None) if marker.value["stage"] == "prepared" => Ok(()),
        (Some(outcome), Some(target_raw)) => {
            outcome.verify(marker, policy)?;
            let derived = policy.derive_target(&marker.cas, &outcome.current)?;
            if derived.raw != target_raw {
                return Err(ContractError::Binding);
            }
            if marker.value["stage"] != "prepared" {
                let t = &marker.value["target_native"];
                if digest(&t["target_image_sha256"])? != derived.digest()
                    || integer(&t["native_cas"]["generation"], true)?
                        != integer(&derived.value["generation"], true)?
                {
                    return Err(ContractError::Binding);
                }
            }
            Ok(())
        }
        _ => Err(ContractError::Binding),
    }
}
#[cfg(test)]
#[path = "service_wallet_contract_tests.rs"]
mod tests;
