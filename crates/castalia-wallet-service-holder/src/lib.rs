//! Wallet-owned service challenge validation and owner-private raw32 service custody.
//! Public inputs remain unqualified. A fixed holder-only source operation derives
//! configuration/time under retained actual custody; installed admission is separate.
//! Native protocol/policy/descriptor/oracle code is reused from pinned dependencies.
use ed25519_dalek::{Signature, VerifyingKey};
use libsec_core::service_holder_proof::{
    challenge_transcript, ServiceApplication, UntrustedSignedServiceChallenge, MAX_SAFE_TIME,
};
use secs_service_call_contract::{Application, ReceiverPolicy, ServiceIntent};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use server::{
    manifest::{
        OpcodeRange, OperationDescriptor, OperationName, OutputProfile, ReplayScope, TargetKind,
    },
    privacy::{DisclosurePermission, DisclosurePolicy},
    service_holder_proof::schema_bundle_digest,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Window,
    Denied,
    UnsupportedRequiredEvidence,
    InvalidSignature,
    Changed,
    MissingQualifiedCustody,
    Clock,
}
fn hash(v: &[u8]) -> [u8; 32] {
    Sha256::digest(v).into()
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn hex32(s: &str) -> Result<[u8; 32], Error> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid);
    }
    let mut out = [0; 32];
    for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| Error::Invalid)?, 16)
            .map_err(|_| Error::Invalid)?;
    }
    Ok(out)
}
fn ascii(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
fn object<'a>(v: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>, Error> {
    let m = v.as_object().ok_or(Error::Invalid)?;
    if m.len() != fields.len() || fields.iter().any(|k| !m.contains_key(*k)) {
        return Err(Error::Invalid);
    }
    Ok(m)
}
fn text(v: &Value, max: usize) -> Result<&str, Error> {
    let s = v.as_str().ok_or(Error::Invalid)?;
    if !ascii(s, max) {
        return Err(Error::Invalid);
    }
    Ok(s)
}
fn uint(v: &Value, min: u64, max: u64) -> Result<u64, Error> {
    let n = v.as_u64().ok_or(Error::Invalid)?;
    if n < min || n > max {
        return Err(Error::Invalid);
    }
    Ok(n)
}
fn array(v: &Value, max: usize) -> Result<&Vec<Value>, Error> {
    let a = v.as_array().ok_or(Error::Invalid)?;
    if a.len() > max {
        return Err(Error::Invalid);
    }
    Ok(a)
}
fn nullable_text(v: &Value, max: usize) -> Result<Option<String>, Error> {
    if v.is_null() {
        Ok(None)
    } else {
        Ok(Some(text(v, max)?.into()))
    }
}
fn nullable_time(v: &Value) -> Result<Option<u64>, Error> {
    if v.is_null() {
        Ok(None)
    } else {
        Ok(Some(uint(v, 0, MAX_SAFE_TIME)?))
    }
}
fn window(start: u64, end: u64) -> Result<(), Error> {
    if start >= end || end > MAX_SAFE_TIME {
        Err(Error::Window)
    } else {
        Ok(())
    }
}
fn strings(v: &Value) -> Result<Vec<String>, Error> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for x in array(v, 16)? {
        let s = text(x, 200)?.to_owned();
        if !seen.insert(s.clone()) {
            return Err(Error::Invalid);
        }
        out.push(s);
    }
    Ok(out)
}
struct JsonSeed(usize);
impl<'de> DeserializeSeed<'de> for JsonSeed {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        if self.0 > 16 {
            return Err(de::Error::custom("metadata depth"));
        }
        struct V(usize);
        impl<'de> Visitor<'de> for V {
            type Value = Value;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("closed bounded integer metadata")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
                Ok(Value::Bool(v))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
                if v > MAX_SAFE_TIME {
                    Err(E::custom("integer overflow"))
                } else {
                    Ok(Value::from(v))
                }
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
                if v.len() > 1024 {
                    Err(E::custom("metadata string"))
                } else {
                    Ok(Value::String(v.into()))
                }
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
                self.visit_str(&v)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = a.next_element_seed(JsonSeed(self.0 + 1))? {
                    if out.len() == 4096 {
                        return Err(de::Error::custom("container bound"));
                    }
                    out.push(v);
                }
                Ok(Value::Array(out))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
                let mut out = Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    // serde_json 1.0.150 arbitrary_precision numbers use this map token.
                    // It is never a valid field in the closed owner metadata profile.
                    if k == "$serde_json::private::Number" {
                        return Err(de::Error::custom("numeric metadata token"));
                    }
                    if k.len() > 256 || out.len() == 4096 || out.contains_key(&k) {
                        return Err(de::Error::custom("duplicate or bounded object"));
                    }
                    let v = a.next_value_seed(JsonSeed(self.0 + 1))?;
                    out.insert(k, v);
                }
                Ok(Value::Object(out))
            }
        }
        d.deserialize_any(V(self.0))
    }
}
fn strict_json(raw: &[u8]) -> Result<Value, Error> {
    if raw.len() > 262144 {
        return Err(Error::Invalid);
    }
    let mut d = serde_json::Deserializer::from_slice(raw);
    let v = JsonSeed(0)
        .deserialize(&mut d)
        .map_err(|_| Error::Invalid)?;
    d.end().map_err(|_| Error::Invalid)?;
    Ok(v)
}
fn canonical(v: &Value) -> Vec<u8> {
    match v {
        Value::Object(m) => {
            let mut out = vec![b'{'];
            for (i, (k, v)) in m.iter().collect::<BTreeMap<_, _>>().into_iter().enumerate() {
                if i > 0 {
                    out.push(b',')
                }
                out.extend(serde_json::to_vec(k).expect("string serialization"));
                out.push(b':');
                out.extend(canonical(v));
            }
            out.push(b'}');
            out
        }
        Value::Array(a) => {
            let mut out = vec![b'['];
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',')
                }
                out.extend(canonical(v));
            }
            out.push(b']');
            out
        }
        _ => serde_json::to_vec(v).expect("validated JSON"),
    }
}
struct Key {
    id: String,
    public: VerifyingKey,
    status: String,
    start: u64,
    end: u64,
    revoked: Option<u64>,
    replaced: Option<String>,
}
impl Key {
    fn parse(v: &Value) -> Result<Self, Error> {
        let public = VerifyingKey::from_bytes(&hex32(text(&v["public_key_hex"], 64)?)?)
            .map_err(|_| Error::Invalid)?;
        if public.is_weak() || text(&v["algorithm"], 32)? != "ed25519" {
            return Err(Error::Invalid);
        }
        let status = text(&v["status"], 32)?;
        if !["active", "revoked", "expired", "unknown", "not_yet_valid"].contains(&status) {
            return Err(Error::Invalid);
        }
        let start = uint(&v["not_before"], 0, MAX_SAFE_TIME)?;
        let end = uint(&v["not_after"], 1, MAX_SAFE_TIME)?;
        window(start, end)?;
        Ok(Self {
            id: text(&v["key_id"], 128)?.into(),
            public,
            status: status.into(),
            start,
            end,
            revoked: nullable_time(&v["revoked_at"])?,
            replaced: nullable_text(&v["replaced_by"], 128)?,
        })
    }
    fn contains(&self, issued: u64, end: u64, now: u64) -> Result<(), Error> {
        if self.status != "active" || self.replaced.is_some() {
            return Err(Error::Denied);
        }
        if self.start > issued
            || self.end < end
            || now < self.start
            || now >= self.end
            || self.revoked.is_some_and(|t| t < end || t <= now)
        {
            return Err(Error::Window);
        }
        Ok(())
    }
}
struct Issuer {
    node: String,
    key: Key,
}
struct Holder {
    subject: String,
    generation: u64,
    key: Key,
}
/// Validated PUBLIC configuration only. Does not prove privileged origin or custody.
pub struct ValidatedWalletOwnerInput {
    digest: [u8; 32],
    application: ServiceApplication,
    start: u64,
    end: u64,
    issuer: Issuer,
    holder: Holder,
    descriptors: BTreeMap<u8, OperationDescriptor>,
    policy: ReceiverPolicy,
}
fn native_descriptor(v: &Value) -> Result<OperationDescriptor, Error> {
    object(
        v,
        &[
            "opcode",
            "name",
            "payload_schema",
            "output_profile",
            "target_kind",
            "required_credentials",
            "required_capabilities",
            "accepted_evidence",
            "required_authority_mode",
            "replay_scope",
            "max_ttl_seconds",
            "handler_id",
            "dev_binding",
            "range",
            "disclosure_policy",
        ],
    )?;
    if v["target_kind"] != "receiver_production_handler"
        || v["replay_scope"] != "session_opcode_nonce"
        || v["range"] != "operator_defined"
        || v["dev_binding"] != false
    {
        return Err(Error::Invalid);
    }
    let output_profile = if v["output_profile"].is_null() {
        None
    } else {
        let o = &v["output_profile"];
        object(
            o,
            &[
                "schema_id",
                "max_output_bytes",
                "max_execution_response_bytes",
            ],
        )?;
        Some(OutputProfile {
            schema_id: text(&o["schema_id"], 256)?.into(),
            max_output_bytes: usize::try_from(uint(&o["max_output_bytes"], 1, MAX_SAFE_TIME)?)
                .map_err(|_| Error::Invalid)?,
            max_execution_response_bytes: usize::try_from(uint(
                &o["max_execution_response_bytes"],
                1,
                MAX_SAFE_TIME,
            )?)
            .map_err(|_| Error::Invalid)?,
        })
    };
    let d = &v["disclosure_policy"];
    object(d, &["policy_id", "policy_version", "permissions"])?;
    let mut permissions = Vec::new();
    let mut seen = BTreeSet::new();
    for rule in array(&d["permissions"], 64)? {
        object(rule, &["class", "surface", "representation"])?;
        if !seen.insert(canonical(rule)) {
            return Err(Error::Invalid);
        }
        permissions.push(
            serde_json::from_value::<DisclosurePermission>(rule.clone())
                .map_err(|_| Error::Invalid)?,
        );
    }
    let handler = text(&v["handler_id"], 256)?;
    if handler.starts_with("dev/") {
        return Err(Error::Invalid);
    }
    let out = OperationDescriptor {
        opcode: uint(&v["opcode"], 64, 255)? as u8,
        name: OperationName::new(text(&v["name"], 200)?),
        payload_schema: nullable_text(&v["payload_schema"], 256)?,
        output_profile,
        target_kind: TargetKind::ReceiverProductionHandler,
        required_credentials: strings(&v["required_credentials"])?,
        required_capabilities: strings(&v["required_capabilities"])?,
        accepted_evidence: strings(&v["accepted_evidence"])?,
        required_authority_mode: serde_json::from_value(v["required_authority_mode"].clone())
            .map_err(|_| Error::Invalid)?,
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: uint(&v["max_ttl_seconds"], 1, 60)?,
        handler_id: handler.into(),
        dev_binding: false,
        range: OpcodeRange::OperatorDefined,
        disclosure_policy: DisclosurePolicy {
            policy_id: text(&d["policy_id"], 128)?.into(),
            policy_version: uint(&d["policy_version"], 1, 65535)? as u16,
            permissions,
        },
    };
    out.validate().map_err(|_| Error::Invalid)?;
    Ok(out)
}
impl ValidatedWalletOwnerInput {
    pub fn holder_generation(&self) -> u64 {
        self.holder.generation
    }
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        let v = strict_json(raw)?;
        object(
            &v,
            &[
                "schema",
                "generation",
                "valid_not_before",
                "valid_until",
                "application",
                "issuer_node_id",
                "selected_issuer_key_id",
                "issuers",
                "holder",
                "descriptors",
                "delegation_policy",
            ],
        )?;
        if v["schema"] != "castalia.wallet-service-owner-input.v1" {
            return Err(Error::Invalid);
        }
        uint(&v["generation"], 1, MAX_SAFE_TIME)?;
        let start = uint(&v["valid_not_before"], 0, MAX_SAFE_TIME)?;
        let end = uint(&v["valid_until"], 1, MAX_SAFE_TIME)?;
        window(start, end)?;
        let application = match v["application"].as_str() {
            Some("runtime") => ServiceApplication::RuntimeV1,
            Some("service") => ServiceApplication::ServiceV1,
            _ => return Err(Error::Invalid),
        };
        let selected = text(&v["selected_issuer_key_id"], 128)?;
        let node = text(&v["issuer_node_id"], 128)?;
        let mut issuer = None;
        let mut ids = BTreeSet::new();
        let mut materials = BTreeSet::new();
        for i in array(&v["issuers"], 32)? {
            object(
                i,
                &[
                    "node_id",
                    "key_id",
                    "public_key_hex",
                    "algorithm",
                    "status",
                    "not_before",
                    "not_after",
                    "revoked_at",
                    "replaced_by",
                ],
            )?;
            let key = Key::parse(i)?;
            let inode = text(&i["node_id"], 128)?;
            if !ids.insert(key.id.clone()) || !materials.insert(key.public.to_bytes()) {
                return Err(Error::Invalid);
            }
            if key.id == selected {
                if inode != node {
                    return Err(Error::Invalid);
                }
                issuer = Some(Issuer {
                    node: inode.into(),
                    key,
                });
            }
        }
        let h = &v["holder"];
        object(
            h,
            &[
                "subject_id",
                "generation",
                "key_id",
                "public_key_hex",
                "algorithm",
                "status",
                "not_before",
                "not_after",
                "revoked_at",
                "replaced_by",
            ],
        )?;
        let key = Key::parse(h)?;
        if !ids.insert(key.id.clone()) || !materials.insert(key.public.to_bytes()) {
            return Err(Error::Invalid);
        }
        let holder = Holder {
            subject: text(&h["subject_id"], 128)?.into(),
            generation: uint(&h["generation"], 1, MAX_SAFE_TIME)?,
            key,
        };
        let mut descriptors = BTreeMap::new();
        let mut names = BTreeSet::new();
        for d in array(&v["descriptors"], 256)? {
            let d = native_descriptor(d)?;
            if descriptors.contains_key(&d.opcode) || !names.insert(d.name.as_str().to_owned()) {
                return Err(Error::Invalid);
            }
            descriptors.insert(d.opcode, d);
        }
        let p = &v["delegation_policy"];
        object(
            p,
            &[
                "schema",
                "application",
                "audience",
                "not_before",
                "not_after",
                "max_ttl_seconds",
                "principals",
                "descriptors",
                "rules",
            ],
        )?;
        if p["application"] != v["application"] || p["audience"] != application.audience() {
            return Err(Error::Invalid);
        }
        for x in array(&p["principals"], 32)? {
            object(
                x,
                &["subject_id", "key_id", "not_before", "not_after", "revoked"],
            )?;
        }
        let pd = array(&p["descriptors"], 256)?;
        if pd.len() != descriptors.len() {
            return Err(Error::Invalid);
        }
        for x in pd {
            object(
                x,
                &[
                    "operation",
                    "opcode",
                    "fingerprint",
                    "handler_id",
                    "max_ttl_seconds",
                ],
            )?;
            let d = descriptors
                .get(&(uint(&x["opcode"], 64, 255)? as u8))
                .ok_or(Error::Invalid)?;
            if x["operation"] != d.name.as_str()
                || x["handler_id"] != d.handler_id
                || x["fingerprint"]
                    != d.authorization_fingerprint()
                        .trim_start_matches("descriptor:sha256:")
                || uint(&x["max_ttl_seconds"], 1, 60)? != d.max_ttl_seconds
            {
                return Err(Error::Invalid);
            }
        }
        let mut rules = BTreeSet::new();
        for x in array(&p["rules"], 1024)? {
            object(
                x,
                &[
                    "subject_id",
                    "key_id",
                    "operation",
                    "resource",
                    "resource_match",
                    "effect",
                    "not_before",
                    "not_after",
                    "active",
                ],
            )?;
            text(&x["resource"], 1024)?;
            if !rules.insert(canonical(x)) {
                return Err(Error::Invalid);
            }
        }
        let policy = ReceiverPolicy::parse(&canonical(p)).map_err(|_| Error::Invalid)?;
        Ok(Self {
            digest: hash(raw),
            application,
            start,
            end,
            issuer: issuer.ok_or(Error::Invalid)?,
            holder,
            descriptors,
            policy,
        })
    }
}
/// Signature/binding validation only; no qualification, signing or replay admission.
pub struct ValidatedServiceChallenge {
    owner_digest: [u8; 32],
    wallet_policy_digest: [u8; 32],
    challenge: UntrustedSignedServiceChallenge,
}
impl ValidatedServiceChallenge {
    pub fn request_bytes(&self) -> &[u8] {
        &self.challenge.request_bytes
    }
    pub fn wallet_policy_digest(&self) -> [u8; 32] {
        self.wallet_policy_digest
    }
    pub fn owner_input_digest(&self) -> [u8; 32] {
        self.owner_digest
    }
}
pub fn validate_service_challenge(
    o: &ValidatedWalletOwnerInput,
    c: &UntrustedSignedServiceChallenge,
    now: u64,
) -> Result<ValidatedServiceChallenge, Error> {
    c.claims.validate().map_err(|_| Error::Invalid)?;
    let v = &c.claims;
    if now == 0 || now > MAX_SAFE_TIME {
        return Err(Error::Clock);
    }
    if now < v.issued_at || now >= v.expires_at || o.start > v.issued_at || o.end < v.expires_at {
        return Err(Error::Window);
    }
    if v.application != o.application
        || v.issuer_node_id != o.issuer.node
        || v.issuer_key_id != o.issuer.key.id
        || v.holder_subject_id != o.holder.subject
        || v.holder_key_id != o.holder.key.id
        || v.holder_public_key_fingerprint != hash(o.holder.key.public.as_bytes())
        || v.schema_bundle_sha256 != schema_bundle_digest(o.application)
    {
        return Err(Error::Denied);
    }
    o.issuer.key.contains(v.issued_at, v.expires_at, now)?;
    o.holder.key.contains(v.issued_at, v.expires_at, now)?;
    let transcript = challenge_transcript(v, &c.request_bytes).map_err(|_| Error::Invalid)?;
    o.issuer
        .key
        .public
        .verify_strict(&transcript, &Signature::from_bytes(&c.issuer_signature))
        .map_err(|_| Error::InvalidSignature)?;
    let app = match o.application {
        ServiceApplication::RuntimeV1 => Application::Runtime,
        ServiceApplication::ServiceV1 => Application::Service,
    };
    let intent = ServiceIntent::parse(app, &c.request_bytes).map_err(|_| Error::Invalid)?;
    let d = o.descriptors.get(&v.opcode).ok_or(Error::Denied)?;
    if intent.operation() != v.operation
        || intent.resource() != v.resource
        || d.name.as_str() != v.operation
        || d.handler_id != v.handler_id
        || d.authorization_fingerprint()
            != format!("descriptor:sha256:{}", hex(&v.descriptor_fingerprint))
        || v.ttl_seconds > d.max_ttl_seconds
    {
        return Err(Error::Denied);
    }
    if !d.required_credentials.is_empty()
        || !d.required_capabilities.is_empty()
        || !d.accepted_evidence.is_empty()
        || d.required_authority_mode.is_some()
    {
        return Err(Error::UnsupportedRequiredEvidence);
    }
    let prepared = o
        .policy
        .prepare(
            &intent,
            &o.holder.subject,
            &o.holder.key.id,
            v.issued_at,
            v.ttl_seconds,
        )
        .map_err(|_| Error::Denied)?;
    if prepared.expires_at() != v.expires_at
        || prepared.audience() != v.audience
        || prepared.opcode() != v.opcode
        || prepared.handler_id() != v.handler_id
        || prepared.descriptor_fingerprint() != hex(&v.descriptor_fingerprint)
    {
        return Err(Error::Window);
    }
    Ok(ValidatedServiceChallenge {
        owner_digest: o.digest,
        wallet_policy_digest: hex32(prepared.policy_digest())?,
        challenge: c.clone(),
    })
}
/// Opaque current native custody handle. Holder proof alone grants no execution authority.
pub struct ServiceIdentityHandle {
    custody: custody::HandleBinding,
}
/// Sealed single-use value; cannot be constructed from caller wire/public input.
pub struct PreparedServiceHolderProof {
    _private: (),
    #[cfg(test)]
    validated: ValidatedServiceChallenge,
}
impl ServiceIdentityHandle {
    /// Sign only the frozen service-holder transcript using actual CURRENT-bound
    /// custody/configuration and the native clock under one retained lease.
    /// This does not independently qualify Native evidence or issue a context.
    pub fn present_current_service_challenge(
        &self,
        c: &UntrustedSignedServiceChallenge,
    ) -> Result<Vec<u8>, Error> {
        self.custody.present_current_service_challenge(c)
    }
    pub fn prepare_service_challenge(
        &self,
        o: &ValidatedWalletOwnerInput,
        c: &UntrustedSignedServiceChallenge,
        now: u64,
    ) -> Result<PreparedServiceHolderProof, Error> {
        self.custody.validate().map_err(|_| Error::Changed)?;
        let _ = validate_service_challenge(o, c, now)?;
        Err(Error::MissingQualifiedCustody)
    }
    pub fn present_prepared_service_challenge(
        &self,
        _p: PreparedServiceHolderProof,
    ) -> Result<Vec<u8>, Error> {
        self.custody.validate().map_err(|_| Error::Changed)?;
        Err(Error::MissingQualifiedCustody)
    }
}
#[cfg(test)]
#[path = "tests.rs"]
pub(crate) mod tests;

// Native issuer/context composition remains test-only here. Fixed holder-only
// signing is confined to actual custody above, not to these synthetic ports.
#[cfg(test)]
use crate as wallet_holder;
#[cfg(test)]
pub(crate) use server::{
    caller, dregg_authority, identity, manifest, privacy, service_holder_proof,
};
#[cfg(test)]
mod native_issuer_fixture_tests;
#[cfg(test)]
#[path = "../vendor/secS-service-b/server/src/service_authority_snapshot.rs"]
mod service_authority_snapshot;
#[cfg(test)]
#[path = "../vendor/secS-service-b/server/src/service_challenge_store.rs"]
mod service_challenge_store;
#[cfg(test)]
#[path = "../vendor/secS-service-b/server/src/service_evidence.rs"]
mod service_evidence;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../vendor/secS-service-b/server/src/work_private_files.rs"]
mod work_private_files;

/// Native owner-only raw seed custody; this does not qualify proof authority.
pub mod custody;
/// Retained native custody administration; no signing authority is granted.
pub use custody::ServiceAdministrationSession;
#[cfg(test)]
mod custody_tests;
