//! Isolated bounded native-owner input reader and cooperative generation lease.
//! No issuer, custody, evidence qualification or deployment admission. Even valid
//! source and signatures cannot fill the missing qualified Wallet/context ports.
use crate::{
    caller::CallerKey,
    dregg_authority::AuthorityMode,
    identity::{PublicVerifierKey, VerificationKeyStatus},
    manifest::{
        OpcodeRange, OperationDescriptor, OperationName, OutputProfile, ReceiverManifest,
        ReplayScope, TargetKind,
    },
    privacy::{
        DisclosurePermission, DisclosurePolicy, DisclosureRepresentation, ForbiddenFieldClass,
        PrivacySurface,
    },
    service_challenge_store::{AuthorityGuard, Clock, GuardInput, JournalError},
    service_evidence::{self, EvidenceInput, PreparedNoRequiredEvidence},
    service_holder_proof::{
        schema_bundle_digest, ServiceHolderKeyRegistry, ServiceIssuerKey, ServiceIssuerKeyRegistry,
    },
    work_private_files as private,
};
use ed25519_dalek::{Signature, VerifyingKey};
use libsec_core::service_holder_proof::{
    challenge_transcript, ServiceApplication, UntrustedSignedServiceChallenge, MAX_SAFE_TIME,
};
use secs_permissions::{
    AuthoritySource, PermissionEffect, PermissionPolicy, PermissionRecord, PermissionStatus,
    ResourceScope,
};
use secs_service_call_contract::{Application, ReceiverPolicy, ServiceIntent};
use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
const MAX_BUNDLE: u64 = 262_144;
const FILE: &str = "owner-generation.json";
const LOCK: &str = ".service-owner.lock";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    UnsafeSource,
    Busy,
    Invalid,
    Changed,
    Clock,
    Window,
    Denied,
    UnsupportedRequiredEvidence,
    InvalidSignature,
    MissingQualifiedWalletAndContextIssuer,
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(text: &str) -> Result<[u8; 32], SnapshotError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SnapshotError::Invalid);
    }
    let mut result = [0; 32];
    for (i, v) in result.iter_mut().enumerate() {
        *v = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| SnapshotError::Invalid)?;
    }
    Ok(result)
}
fn ascii(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
fn window(start: u64, end: u64) -> bool {
    start < end && end <= MAX_SAFE_TIME
}
fn key_status(s: &str) -> Result<VerificationKeyStatus, SnapshotError> {
    match s {
        "active" => Ok(VerificationKeyStatus::Active),
        "revoked" => Ok(VerificationKeyStatus::Revoked),
        "expired" => Ok(VerificationKeyStatus::Expired),
        "unknown" => Ok(VerificationKeyStatus::Unknown),
        "not_yet_valid" => Ok(VerificationKeyStatus::NotYetValid),
        _ => Err(SnapshotError::Invalid),
    }
}
// Explicit key sort, independent of serde_json preserve_order feature unification.
pub(crate) fn canonical(v: &Value) -> Vec<u8> {
    fn append(v: &Value, out: &mut Vec<u8>) {
        match v {
            Value::Object(map) => {
                out.push(b'{');
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(k).expect("string"));
                    out.push(b':');
                    append(&map[*k], out);
                }
                out.push(b'}');
            }
            Value::Array(a) => {
                out.push(b'[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    append(v, out);
                }
                out.push(b']');
            }
            _ => out.extend(serde_json::to_vec(v).expect("value")),
        }
    }
    let mut out = Vec::new();
    append(v, &mut out);
    out
}
fn projection(domain: &[u8], v: &Value) -> Vec<u8> {
    let mut bytes = domain.to_vec();
    bytes.extend(canonical(v));
    bytes
}
struct Seed(usize);
impl<'de> DeserializeSeed<'de> for Seed {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        if self.0 > 16 {
            return Err(de::Error::custom("depth"));
        }
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed {
    type Value = Value;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("bounded unique metadata")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        if v > MAX_SAFE_TIME {
            Err(E::custom("integer"))
        } else {
            Ok(v.into())
        }
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        if v.len() > 65_536 {
            Err(E::custom("string"))
        } else {
            Ok(Value::String(v.into()))
        }
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        self.visit_str(&v)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut a = Vec::new();
        while let Some(v) = seq.next_element_seed(Seed(self.0 + 1))? {
            if a.len() >= 4096 {
                return Err(de::Error::custom("array"));
            }
            a.push(v);
        }
        Ok(Value::Array(a))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some(k) = map.next_key::<String>()? {
            // serde_json 1.0.150 arbitrary_precision numbers use this map token.
            // It is never a valid field in the closed owner metadata profile.
            if k == "$serde_json::private::Number" {
                return Err(de::Error::custom("numeric metadata token"));
            }
            if values.len() >= 4096 || k.len() > 256 || values.contains_key(&k) {
                return Err(de::Error::custom("duplicate/key bound"));
            }
            values.insert(k, map.next_value_seed(Seed(self.0 + 1))?);
        }
        Ok(Value::Object(values))
    }
}
pub(crate) fn strict_value(raw: &[u8]) -> Result<Value, SnapshotError> {
    if raw.len() as u64 > MAX_BUNDLE {
        return Err(SnapshotError::Invalid);
    }
    let mut d = serde_json::Deserializer::from_slice(raw);
    let v = Seed(0)
        .deserialize(&mut d)
        .map_err(|_| SnapshotError::Invalid)?;
    d.end().map_err(|_| SnapshotError::Invalid)?;
    Ok(v)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    schema: String,
    generation: u64,
    valid_not_before: u64,
    valid_until: u64,
    application: String,
    issuer_node_id: String,
    selected_issuer_key_id: String,
    issuers: Vec<Issuer>,
    holders: Vec<Holder>,
    descriptors: Vec<Descriptor>,
    permissions: Vec<Permission>,
    receiver_policy: Value,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Issuer {
    node_id: String,
    key_id: String,
    public_key_hex: String,
    algorithm: String,
    status: String,
    not_before: u64,
    not_after: u64,
    revoked_at: Option<u64>,
    replaced_by: Option<String>,
    production_authority: bool,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Holder {
    key_id: String,
    subject_id: String,
    public_key_hex: String,
    algorithm: String,
    status: String,
    not_before: u64,
    not_after: u64,
    revoked_at: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    opcode: u8,
    name: String,
    payload_schema: Option<String>,
    output_profile: Option<Output>,
    target_kind: String,
    required_credentials: Vec<String>,
    required_capabilities: Vec<String>,
    accepted_evidence: Vec<String>,
    required_authority_mode: Option<AuthorityMode>,
    replay_scope: String,
    max_ttl_seconds: u64,
    handler_id: String,
    dev_binding: bool,
    range: String,
    disclosure_policy: Disclosure,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    schema_id: String,
    max_output_bytes: usize,
    max_execution_response_bytes: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Disclosure {
    policy_id: String,
    policy_version: u16,
    permissions: Vec<DisclosureRule>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisclosureRule {
    class: ForbiddenFieldClass,
    surface: PrivacySurface,
    representation: DisclosureRepresentation,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Permission {
    caller_id: String,
    opcode: u8,
    operation: String,
    resource: Scope,
    effect: PermissionEffect,
    not_before: u64,
    not_after: u64,
    status: PermissionStatus,
    authority_source: AuthoritySource,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Scope {
    Exact { value: String },
    Prefix { prefix: String },
}
fn labels(values: &[String]) -> bool {
    values.len() <= 16
        && values.iter().all(|s| ascii(s, 200))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}
impl Descriptor {
    fn native(self) -> Result<OperationDescriptor, SnapshotError> {
        if self.opcode < 64
            || !ascii(&self.name, 200)
            || self.target_kind != "receiver_production_handler"
            || self.replay_scope != "session_opcode_nonce"
            || self.range != "operator_defined"
            || self.dev_binding
            || !(1..=60).contains(&self.max_ttl_seconds)
            || !ascii(&self.handler_id, 256)
            || self.handler_id.starts_with("dev/")
            || self.payload_schema.as_ref().is_some_and(|s| !ascii(s, 256))
            || !labels(&self.required_credentials)
            || !labels(&self.required_capabilities)
            || !labels(&self.accepted_evidence)
            || !ascii(&self.disclosure_policy.policy_id, 128)
            || self.disclosure_policy.policy_version == 0
            || self.disclosure_policy.permissions.len() > 64
        {
            return Err(SnapshotError::Invalid);
        }
        let mut seen = BTreeSet::new();
        let mut permissions = Vec::new();
        for rule in self.disclosure_policy.permissions {
            if !seen.insert((
                rule.class.as_str(),
                rule.surface.as_str(),
                rule.representation.as_str(),
            )) {
                return Err(SnapshotError::Invalid);
            }
            permissions.push(DisclosurePermission::new(
                rule.class,
                rule.surface,
                rule.representation,
            ));
        }
        let output_profile = match self.output_profile {
            None => None,
            Some(o) => {
                if !ascii(&o.schema_id, 256)
                    || o.max_output_bytes == 0
                    || o.max_execution_response_bytes == 0
                    || o.max_output_bytes as u64 > MAX_SAFE_TIME
                    || o.max_execution_response_bytes as u64 > MAX_SAFE_TIME
                {
                    return Err(SnapshotError::Invalid);
                }
                Some(OutputProfile {
                    schema_id: o.schema_id,
                    max_output_bytes: o.max_output_bytes,
                    max_execution_response_bytes: o.max_execution_response_bytes,
                })
            }
        };
        let d = OperationDescriptor {
            opcode: self.opcode,
            name: OperationName::new(self.name),
            payload_schema: self.payload_schema,
            output_profile,
            target_kind: TargetKind::ReceiverProductionHandler,
            required_credentials: self.required_credentials,
            required_capabilities: self.required_capabilities,
            accepted_evidence: self.accepted_evidence,
            required_authority_mode: self.required_authority_mode,
            replay_scope: ReplayScope::SessionOpcodeNonce,
            max_ttl_seconds: self.max_ttl_seconds,
            handler_id: self.handler_id,
            dev_binding: false,
            range: OpcodeRange::OperatorDefined,
            disclosure_policy: DisclosurePolicy {
                policy_id: self.disclosure_policy.policy_id,
                policy_version: self.disclosure_policy.policy_version,
                permissions,
            },
        };
        d.validate().map_err(|_| SnapshotError::Invalid)?;
        Ok(d)
    }
}
struct Snapshot {
    generation: u64,
    start: u64,
    end: u64,
    app: ServiceApplication,
    issuer_node: String,
    issuer_id: String,
    issuers: ServiceIssuerKeyRegistry,
    holders: ServiceHolderKeyRegistry,
    issuer_rows: Vec<Issuer>,
    holder_rows: Vec<Holder>,
    manifest: ReceiverManifest,
    receiver: ReceiverPolicy,
    permissions: PermissionPolicy,
    permission_preimage: Vec<u8>,
}
fn key(raw: &str) -> Result<VerifyingKey, SnapshotError> {
    let k = VerifyingKey::from_bytes(&digest(raw)?).map_err(|_| SnapshotError::Invalid)?;
    if k.is_weak() {
        return Err(SnapshotError::Invalid);
    }
    Ok(k)
}
fn require_explicit_policy_nullables(value: &Value) -> Result<(), SnapshotError> {
    // Option<T> fields must still be explicitly present, including nested DTOs.
    fn required(v: &Value, names: &[&str]) -> Result<(), SnapshotError> {
        if names.iter().any(|n| v.get(n).is_none()) {
            Err(SnapshotError::Invalid)
        } else {
            Ok(())
        }
    }
    for x in value
        .get("issuers")
        .and_then(Value::as_array)
        .ok_or(SnapshotError::Invalid)?
    {
        required(x, &["revoked_at", "replaced_by"])?;
    }
    for x in value
        .get("holders")
        .and_then(Value::as_array)
        .ok_or(SnapshotError::Invalid)?
    {
        required(x, &["revoked_at"])?;
    }
    for x in value
        .get("descriptors")
        .and_then(Value::as_array)
        .ok_or(SnapshotError::Invalid)?
    {
        required(
            x,
            &[
                "payload_schema",
                "output_profile",
                "required_authority_mode",
            ],
        )?;
    }
    Ok(())
}
// Full closed existing policy body, with no generation/source/authority fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyBody {
    valid_not_before: u64,
    valid_until: u64,
    application: String,
    issuer_node_id: String,
    selected_issuer_key_id: String,
    issuers: Vec<Issuer>,
    holders: Vec<Holder>,
    descriptors: Vec<Descriptor>,
    permissions: Vec<Permission>,
    receiver_policy: Value,
}
struct ValidatedPolicyBody {
    start: u64,
    end: u64,
    app: ServiceApplication,
    issuer_node: String,
    issuer_id: String,
    issuers: ServiceIssuerKeyRegistry,
    holders: ServiceHolderKeyRegistry,
    issuer_rows: Vec<Issuer>,
    holder_rows: Vec<Holder>,
    manifest: ReceiverManifest,
    receiver: ReceiverPolicy,
    permissions: PermissionPolicy,
    permission_preimage: Vec<u8>,
}
fn parse_policy_body(
    b: PolicyBody,
    allow_empty_holders: bool,
) -> Result<ValidatedPolicyBody, SnapshotError> {
    if !window(b.valid_not_before, b.valid_until)
        || !ascii(&b.issuer_node_id, 128)
        || !ascii(&b.selected_issuer_key_id, 128)
        || b.issuers.is_empty()
        || b.issuers.len() > 32
        || (!allow_empty_holders && b.holders.is_empty())
        || b.holders.len() > 32
        || b.descriptors.is_empty()
        || b.descriptors.len() > 256
        || b.permissions.len() > 1024
    {
        return Err(SnapshotError::Invalid);
    }
    let app = match b.application.as_str() {
        "runtime" => ServiceApplication::RuntimeV1,
        "service" => ServiceApplication::ServiceV1,
        _ => return Err(SnapshotError::Invalid),
    };
    let mut materials = BTreeSet::new();
    let mut all_key_ids = BTreeSet::new();
    let mut issuers = Vec::new();
    let mut holders = Vec::new();
    for i in &b.issuers {
        if !all_key_ids.insert(i.key_id.clone())
            || !ascii(&i.node_id, 128)
            || !ascii(&i.key_id, 128)
            || i.algorithm != "ed25519"
            || !window(i.not_before, i.not_after)
            || i.revoked_at.is_some_and(|v| v > MAX_SAFE_TIME)
            || i.replaced_by.as_ref().is_some_and(|s| !ascii(s, 128))
        {
            return Err(SnapshotError::Invalid);
        }
        let public = key(&i.public_key_hex)?;
        if !materials.insert(public.to_bytes()) {
            return Err(SnapshotError::Invalid);
        }
        let mut k = PublicVerifierKey::active(&i.key_id, "ed25519", public)
            .with_validity_window(Some(i.not_before), Some(i.not_after))
            .with_revoked_at(i.revoked_at);
        k.status = key_status(&i.status)?;
        k.production_authority = i.production_authority;
        k.replaced_by = i.replaced_by.clone();
        issuers.push(ServiceIssuerKey {
            node_id: i.node_id.clone(),
            key: k,
        });
    }
    for h in &b.holders {
        if !all_key_ids.insert(h.key_id.clone())
            || !ascii(&h.subject_id, 128)
            || !ascii(&h.key_id, 128)
            || h.algorithm != "ed25519"
            || !window(h.not_before, h.not_after)
            || h.revoked_at.is_some_and(|v| v > MAX_SAFE_TIME)
        {
            return Err(SnapshotError::Invalid);
        }
        let public = key(&h.public_key_hex)?;
        if !materials.insert(public.to_bytes()) {
            return Err(SnapshotError::Invalid);
        }
        holders.push(
            CallerKey::active(&h.key_id, &h.subject_id, public)
                .with_status(key_status(&h.status)?)
                .with_validity_window(Some(h.not_before), Some(h.not_after))
                .with_revoked_at(h.revoked_at),
        );
    }
    let issuers =
        ServiceIssuerKeyRegistry::from_keys(issuers).map_err(|_| SnapshotError::Invalid)?;
    let holders =
        ServiceHolderKeyRegistry::from_keys(holders).map_err(|_| SnapshotError::Invalid)?;
    if issuers
        .get(&b.selected_issuer_key_id)
        .is_none_or(|i| i.node_id != b.issuer_node_id)
    {
        return Err(SnapshotError::Invalid);
    }
    let mut descriptors = Vec::new();
    let mut codes = BTreeSet::new();
    let mut names = BTreeSet::new();
    for d in b.descriptors {
        if !codes.insert(d.opcode) || !names.insert(d.name.clone()) {
            return Err(SnapshotError::Invalid);
        }
        descriptors.push(d.native()?);
    }
    let mut records = Vec::new();
    let mut unique = BTreeSet::new();
    for p in &b.permissions {
        let scope = match &p.resource {
            Scope::Exact { value } => ResourceScope::Exact {
                value: value.clone(),
            },
            Scope::Prefix { prefix } => ResourceScope::Prefix {
                prefix: prefix.clone(),
            },
        };
        let resource = match &p.resource {
            Scope::Exact { value } => value,
            Scope::Prefix { prefix } => prefix,
        };
        if !ascii(&p.caller_id, 128)
            || !ascii(&p.operation, 200)
            || !ascii(resource, 1024)
            || !window(p.not_before, p.not_after)
            || p.authority_source != AuthoritySource::ReceiverLocal
            || !unique.insert(canonical(
                &serde_json::to_value(p).map_err(|_| SnapshotError::Invalid)?,
            ))
        {
            return Err(SnapshotError::Invalid);
        }
        records.push(PermissionRecord {
            caller_id: p.caller_id.clone(),
            opcode: p.opcode,
            operation: p.operation.clone(),
            resource: scope,
            effect: p.effect,
            not_before: p.not_before,
            not_after: p.not_after,
            status: p.status,
            authority_source: p.authority_source,
        });
    }
    let permission_preimage = projection(
        b"secs-service-permission-snapshot-v1\0",
        &json!({"records":records}),
    );
    let permissions = PermissionPolicy::new(records).map_err(|_| SnapshotError::Invalid)?;
    let receiver = ReceiverPolicy::parse(&canonical(&b.receiver_policy))
        .map_err(|_| SnapshotError::Invalid)?;
    Ok(ValidatedPolicyBody {
        start: b.valid_not_before,
        end: b.valid_until,
        app,
        issuer_node: b.issuer_node_id,
        issuer_id: b.selected_issuer_key_id,
        issuers,
        holders,
        issuer_rows: b.issuers,
        holder_rows: b.holders,
        manifest: ReceiverManifest::new(descriptors),
        receiver,
        permissions,
        permission_preimage,
    })
}
/// Pure complete policy validation only. The inactive-v2 empty-holder case
/// changes data validation, never authority. No source/generation/lease is made.
pub(crate) fn validate_unqualified_policy_body(
    value: Value,
    allow_empty_holders: bool,
) -> Result<(), SnapshotError> {
    require_explicit_policy_nullables(&value)?;
    let body: PolicyBody = serde_json::from_value(value).map_err(|_| SnapshotError::Invalid)?;
    parse_policy_body(body, allow_empty_holders).map(|_| ())
}

fn parse_bundle(raw: &[u8]) -> Result<Snapshot, SnapshotError> {
    let value = strict_value(raw)?;
    require_explicit_policy_nullables(&value)?;
    let b: Bundle = serde_json::from_value(value).map_err(|_| SnapshotError::Invalid)?;
    if b.schema != "secs.service-owner-bundle.v1"
        || b.generation == 0
        || b.generation > MAX_SAFE_TIME
    {
        return Err(SnapshotError::Invalid);
    }
    let generation = b.generation;
    let policy = parse_policy_body(
        PolicyBody {
            valid_not_before: b.valid_not_before,
            valid_until: b.valid_until,
            application: b.application,
            issuer_node_id: b.issuer_node_id,
            selected_issuer_key_id: b.selected_issuer_key_id,
            issuers: b.issuers,
            holders: b.holders,
            descriptors: b.descriptors,
            permissions: b.permissions,
            receiver_policy: b.receiver_policy,
        },
        false,
    )?;
    Ok(Snapshot {
        generation,
        start: policy.start,
        end: policy.end,
        app: policy.app,
        issuer_node: policy.issuer_node,
        issuer_id: policy.issuer_id,
        issuers: policy.issuers,
        holders: policy.holders,
        issuer_rows: policy.issuer_rows,
        holder_rows: policy.holder_rows,
        manifest: policy.manifest,
        receiver: policy.receiver,
        permissions: policy.permissions,
        permission_preimage: policy.permission_preimage,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn identity(f: &File) -> Result<Identity, SnapshotError> {
    let m = f.metadata().map_err(|_| SnapshotError::UnsafeSource)?;
    Ok(Identity {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    })
}
fn directory_id(path: &Path) -> Result<(u64, u64), SnapshotError> {
    let m = std::fs::symlink_metadata(path).map_err(|_| SnapshotError::UnsafeSource)?;
    if !m.is_dir() {
        return Err(SnapshotError::UnsafeSource);
    }
    Ok((m.dev(), m.ino()))
}
/// Independent native startup configuration, not an RPC constructor or token.
/// The expected whole-file/generation pins must come from the owner. This reader
/// cannot establish deployment approval, persistent anti-rollback or custody.
pub struct OwnerSource {
    root: PathBuf,
    _directory: private::Directory,
    root_id: (u64, u64),
    generation: u64,
    pin: [u8; 32],
    floor: AtomicU64,
}
impl OwnerSource {
    pub fn open(
        root: &Path,
        expected_generation: u64,
        expected_sha256: [u8; 32],
    ) -> Result<Self, SnapshotError> {
        if expected_generation == 0
            || expected_generation > MAX_SAFE_TIME
            || expected_sha256 == [0; 32]
        {
            return Err(SnapshotError::Invalid);
        }
        let directory = private::Directory::open(root).map_err(|_| SnapshotError::UnsafeSource)?;
        Ok(Self {
            root: root.into(),
            _directory: directory,
            root_id: directory_id(root)?,
            generation: expected_generation,
            pin: expected_sha256,
            floor: AtomicU64::new(0),
        })
    }
    fn observe(&self, clock: &dyn Clock) -> Result<u64, SnapshotError> {
        let now = clock.now();
        if now == 0 || now > MAX_SAFE_TIME {
            return Err(SnapshotError::Clock);
        }
        let old = self.floor.fetch_max(now, Ordering::SeqCst);
        if now < old {
            Err(SnapshotError::Clock)
        } else {
            Ok(now)
        }
    }
    fn read(&self) -> Result<(Vec<u8>, Identity), SnapshotError> {
        if directory_id(&self.root)? != self.root_id {
            return Err(SnapshotError::Changed);
        }
        let _d = private::Directory::open(&self.root).map_err(|_| SnapshotError::UnsafeSource)?;
        let mut file = private::open(&self.root.join(FILE), MAX_BUNDLE)
            .map_err(|_| SnapshotError::UnsafeSource)?;
        let before = identity(&file)?;
        let mut bytes = Vec::with_capacity(before.len as usize);
        (&mut file)
            .take(MAX_BUNDLE + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SnapshotError::UnsafeSource)?;
        if before != identity(&file)?
            || bytes.len() as u64 != before.len
            || bytes.len() as u64 > MAX_BUNDLE
            || hash(&bytes) != self.pin
        {
            return Err(SnapshotError::Changed);
        }
        Ok((bytes, before))
    }
    pub fn lease<'a>(&'a self, clock: &dyn Clock) -> Result<OwnerLease<'a>, SnapshotError> {
        let lock = private::lock(&self.root.join(LOCK), false).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                SnapshotError::Busy
            } else {
                SnapshotError::UnsafeSource
            }
        })?;
        let lock_id = identity(&lock)?;
        if lock_id.len != 0 {
            return Err(SnapshotError::UnsafeSource);
        }
        let (raw, id) = self.read()?;
        let snapshot = parse_bundle(&raw)?;
        if snapshot.generation != self.generation {
            return Err(SnapshotError::Changed);
        }
        let now = self.observe(clock)?;
        if now < snapshot.start || now >= snapshot.end {
            return Err(SnapshotError::Window);
        }
        let lease = OwnerLease {
            source: self,
            _lock: lock,
            lock_id,
            file_id: id,
            snapshot,
            observed_at: now,
        };
        lease.revalidate(clock)?;
        Ok(lease)
    }
}
/// Holds actual shared OS lock until dropped; no Clone/Deserialize. All owner
/// writers must honor that same lock. Does not resist a hostile same-UID writer.
pub struct OwnerLease<'a> {
    source: &'a OwnerSource,
    _lock: File,
    lock_id: Identity,
    file_id: Identity,
    snapshot: Snapshot,
    observed_at: u64,
}
/// Pure validated binding data; not caller authentication, Wallet approval or an
/// execution/signing capability. The future qualified owner adapter is absent.
pub struct PreparedOwnerBindings {
    pub(crate) evidence: PreparedNoRequiredEvidence,
    input: EvidenceInput,
    opcode: u8,
    permission: [u8; 32],
    registry: [u8; 32],
    receiver: [u8; 32],
}
impl PreparedOwnerBindings {
    pub fn evidence(&self) -> &PreparedNoRequiredEvidence {
        &self.evidence
    }
    pub fn permission_digest(&self) -> [u8; 32] {
        self.permission
    }
    pub fn registry_digest(&self) -> [u8; 32] {
        self.registry
    }
    pub fn receiver_digest(&self) -> [u8; 32] {
        self.receiver
    }
}
impl OwnerLease<'_> {
    pub fn revalidate(&self, clock: &dyn Clock) -> Result<u64, SnapshotError> {
        let lock = private::open(&self.source.root.join(LOCK), 0)
            .map_err(|_| SnapshotError::UnsafeSource)?;
        if identity(&lock)? != self.lock_id {
            return Err(SnapshotError::Changed);
        }
        drop(lock);
        let (_, id) = self.source.read()?;
        if id != self.file_id {
            return Err(SnapshotError::Changed);
        }
        let now = self.source.observe(clock)?;
        if now < self.observed_at || now < self.snapshot.start || now >= self.snapshot.end {
            return Err(SnapshotError::Window);
        }
        Ok(now)
    }
    pub fn permission_preimage(&self) -> &[u8] {
        &self.snapshot.permission_preimage
    }
    fn issuer(&self) -> Result<&ServiceIssuerKey, SnapshotError> {
        self.snapshot
            .issuers
            .get(&self.snapshot.issuer_id)
            .ok_or(SnapshotError::Denied)
    }
    fn key_window(
        start: Option<u64>,
        end: Option<u64>,
        revoked: Option<u64>,
        issued: u64,
        expires: u64,
        now: u64,
    ) -> Result<(), SnapshotError> {
        let (start, end) = (
            start.ok_or(SnapshotError::Window)?,
            end.ok_or(SnapshotError::Window)?,
        );
        if !window(start, end)
            || start > issued
            || expires > end
            || now < start
            || now >= end
            || revoked.is_some_and(|r| r < expires || r <= now)
        {
            return Err(SnapshotError::Window);
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_original(
        &self,
        raw: &[u8],
        subject: &str,
        key_id: &str,
        issued: u64,
        ttl: u64,
        observed: u64,
        clock: &dyn Clock,
    ) -> Result<PreparedOwnerBindings, SnapshotError> {
        let now = self.revalidate(clock)?;
        let end = issued.checked_add(ttl).ok_or(SnapshotError::Window)?;
        if !(1..=60).contains(&ttl)
            || issued < self.snapshot.start
            || end > self.snapshot.end
            || issued == 0
            || observed == 0
            || observed > issued
            || issued > now
            || now >= end
        {
            return Err(SnapshotError::Window);
        }
        let issuer = self.issuer()?;
        let holder = self
            .snapshot
            .holders
            .get(key_id)
            .ok_or(SnapshotError::Denied)?;
        if issuer.key.status != VerificationKeyStatus::Active
            || !issuer.key.production_authority
            || issuer.key.replaced_by.is_some()
            || holder.status != VerificationKeyStatus::Active
            || holder.subject_id != subject
        {
            return Err(SnapshotError::Denied);
        }
        Self::key_window(
            issuer.key.not_before,
            issuer.key.not_after,
            issuer.key.revoked_at,
            issued,
            end,
            now,
        )?;
        Self::key_window(
            holder.not_before,
            holder.not_after,
            holder.revoked_at,
            issued,
            end,
            now,
        )?;
        let intent = ServiceIntent::parse(
            match self.snapshot.app {
                ServiceApplication::RuntimeV1 => Application::Runtime,
                ServiceApplication::ServiceV1 => Application::Service,
            },
            raw,
        )
        .map_err(|_| SnapshotError::Invalid)?;
        let prepared = self
            .snapshot
            .receiver
            .prepare(&intent, subject, key_id, issued, ttl)
            .map_err(|_| SnapshotError::Denied)?;
        if prepared.expires_at() != end {
            return Err(SnapshotError::Window);
        }
        let descriptor = self
            .snapshot
            .manifest
            .lookup(prepared.opcode())
            .map_err(|_| SnapshotError::Denied)?;
        let fp = descriptor.authorization_fingerprint();
        let fp = digest(
            fp.strip_prefix("descriptor:sha256:")
                .ok_or(SnapshotError::Invalid)?,
        )?;
        if descriptor.name.as_str() != prepared.operation()
            || descriptor.handler_id != prepared.handler_id()
            || hex(&fp) != prepared.descriptor_fingerprint()
            || ttl > descriptor.max_ttl_seconds
            || prepared.audience() != self.snapshot.app.audience()
        {
            return Err(SnapshotError::Denied);
        }
        for t in issued..end {
            self.snapshot
                .permissions
                .evaluate(
                    subject,
                    descriptor.opcode,
                    intent.operation(),
                    intent.resource(),
                    t,
                )
                .map_err(|_| SnapshotError::Denied)?;
        }
        let input = EvidenceInput {
            owner: self.source.pin,
            descriptor: fp,
            subject: subject.into(),
            audience: prepared.audience().into(),
            operation: intent.operation().into(),
            resource: intent.resource().into(),
            request: hash(raw),
            // Observation can precede the later challenge issue time. Its finite
            // horizon begins at actual owner/key validity, never at a reset timestamp.
            start: self
                .snapshot
                .start
                .max(issuer.key.not_before.ok_or(SnapshotError::Window)?)
                .max(holder.not_before.ok_or(SnapshotError::Window)?),
            end,
            observed,
        };
        let evidence =
            service_evidence::prepare_none(descriptor, &input).map_err(|error| match error {
                service_evidence::EvidenceError::UnsupportedRequiredEvidence => {
                    SnapshotError::UnsupportedRequiredEvidence
                }
                service_evidence::EvidenceError::InvalidWindow => SnapshotError::Window,
                service_evidence::EvidenceError::Changed => SnapshotError::Changed,
            })?;
        let issuer_row = self
            .snapshot
            .issuer_rows
            .iter()
            .find(|i| i.key_id == self.snapshot.issuer_id)
            .ok_or(SnapshotError::Invalid)?;
        let holder_row = self
            .snapshot
            .holder_rows
            .iter()
            .find(|h| h.key_id == key_id)
            .ok_or(SnapshotError::Invalid)?;
        let registry = hash(&projection(
            b"secs-service-registry-snapshot-v1\0",
            &json!({"generation":self.snapshot.generation,"owner_bundle_sha256":hex(&self.source.pin),"issuer":issuer_row,"holder":holder_row}),
        ));
        let result = PreparedOwnerBindings {
            evidence,
            input,
            opcode: descriptor.opcode,
            permission: hash(&self.snapshot.permission_preimage),
            registry,
            receiver: digest(prepared.policy_digest())?,
        };
        self.revalidate_prepared(&result, clock)?;
        Ok(result)
    }
    pub fn prepare_request(
        &self,
        raw: &[u8],
        subject: &str,
        key_id: &str,
        issued: u64,
        ttl: u64,
        clock: &dyn Clock,
    ) -> Result<PreparedOwnerBindings, SnapshotError> {
        self.prepare_original(raw, subject, key_id, issued, ttl, self.observed_at, clock)
    }
    pub fn revalidate_prepared(
        &self,
        prepared: &PreparedOwnerBindings,
        clock: &dyn Clock,
    ) -> Result<(), SnapshotError> {
        let now = self.revalidate(clock)?;
        if prepared.input.owner != self.source.pin {
            return Err(SnapshotError::Changed);
        }
        let d = self
            .snapshot
            .manifest
            .lookup(prepared.opcode)
            .map_err(|_| SnapshotError::Denied)?;
        service_evidence::revalidate_none(d, &prepared.input, &prepared.evidence, now)
            .map_err(|_| SnapshotError::Window)?;
        let final_now = self.source.observe(clock)?;
        if final_now >= prepared.input.end {
            return Err(SnapshotError::Window);
        }
        Ok(())
    }
    /// Strict cryptographic origin only. Not holder proof, evidence satisfaction,
    /// current Wallet custody/delegation or permission to execute/sign.
    pub fn verify_challenge_origin(
        &self,
        c: &UntrustedSignedServiceChallenge,
        clock: &dyn Clock,
    ) -> Result<[u8; 32], SnapshotError> {
        let now = self.revalidate(clock)?;
        let claims = &c.claims;
        let issuer = self.issuer()?;
        if claims.application != self.snapshot.app
            || claims.issuer_key_id != self.snapshot.issuer_id
            || claims.issuer_node_id != self.snapshot.issuer_node
            || claims.schema_bundle_sha256 != schema_bundle_digest(self.snapshot.app)
            || issuer.key.status != VerificationKeyStatus::Active
            || !issuer.key.production_authority
            || issuer.key.replaced_by.is_some()
        {
            return Err(SnapshotError::Denied);
        }
        Self::key_window(
            issuer.key.not_before,
            issuer.key.not_after,
            issuer.key.revoked_at,
            claims.issued_at,
            claims.expires_at,
            now,
        )?;
        if claims.issued_at < self.snapshot.start
            || claims.expires_at > self.snapshot.end
            || now < claims.issued_at
            || now >= claims.expires_at
        {
            return Err(SnapshotError::Window);
        }
        let bytes =
            challenge_transcript(claims, &c.request_bytes).map_err(|_| SnapshotError::Invalid)?;
        issuer
            .key
            .public_key
            .verify_strict(&bytes, &Signature::from_bytes(&c.issuer_signature))
            .map_err(|_| SnapshotError::InvalidSignature)?;
        let final_now = self.revalidate(clock)?;
        if final_now >= claims.expires_at {
            return Err(SnapshotError::Window);
        }
        Ok(hash(&bytes))
    }
    pub fn require_complete_authority(
        &self,
        c: &UntrustedSignedServiceChallenge,
        clock: &dyn Clock,
    ) -> Result<(), SnapshotError> {
        self.verify_challenge_origin(c, clock)?;
        let p = self.prepare_original(
            &c.request_bytes,
            &c.claims.holder_subject_id,
            &c.claims.holder_key_id,
            c.claims.issued_at,
            c.claims.ttl_seconds,
            c.claims.evidence.evidence_observed_at,
            clock,
        )?;
        if p.permission != c.claims.permission_policy_digest
            || p.registry != c.claims.registry_snapshot_digest
            || p.receiver != c.claims.receiver_policy_digest
            || p.evidence.bindings() != &c.claims.evidence
        {
            return Err(SnapshotError::Changed);
        }
        Err(SnapshotError::MissingQualifiedWalletAndContextIssuer)
    }
    /// Deliberately uninhabited production composition: a caller cannot turn a
    /// valid owner file, mode flag or public key metadata into missing Wallet or
    /// context-issuer qualification. Does not examine private key material.
    pub fn require_qualified_ports(&self, clock: &dyn Clock) -> Result<(), SnapshotError> {
        self.revalidate(clock)?;
        Err(SnapshotError::MissingQualifiedWalletAndContextIssuer)
    }
}
/// Adapter is always-denying until independent qualified ports exist. It can be
/// used to prove journal does not export on missing native owner boundaries.
pub struct DenyingOwnerGuard<'a, 's> {
    pub lease: &'a OwnerLease<'s>,
    pub clock: &'a dyn Clock,
}
impl AuthorityGuard for DenyingOwnerGuard<'_, '_> {
    fn revalidate(&mut self, input: GuardInput<'_>) -> Result<(), JournalError> {
        let _ = self
            .lease
            .require_complete_authority(input.challenge, self.clock);
        // No branch can turn validated input into the absent qualified ports.
        Err(JournalError::Rejected)
    }
}
#[cfg(test)]
#[path = "service_authority_snapshot_tests.rs"]
mod tests;
