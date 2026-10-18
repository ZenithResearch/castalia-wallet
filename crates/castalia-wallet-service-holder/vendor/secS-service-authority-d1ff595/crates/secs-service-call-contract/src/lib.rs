//! Immutable scope-checked service intents, not authenticated authority.
//!
//! This additive library has no signer, key custody, file/network API or replay store.
//! Operator startup supplies the receiver policy; the request cannot select it.
//! A later issuer must authenticate the caller independently and recheck current
//! policy/time before signing. Caller proof v1 does not bind receiver audience.
//!
//! Prepared values cannot be decoded or constructed by callers:
//! ```compile_fail
//! use secs_service_call_contract::PreparedServiceIntent;
//! let forged = PreparedServiceIntent { audience: "chosen".into() };
//! ```
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{value::RawValue, Value};
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
    ops::Index,
};

pub const MAX_REQUEST_BYTES: usize = 2_097_152;
const MAX_POLICY_BYTES: usize = 262_144;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
const MAX_TTL: u64 = 60;
const RUNTIME_SCHEMA: &str = include_str!("../schemas/runtime-v1.schema.json");
const SERVICE_COMMAND: &str = include_str!("../schemas/service.command.v1.schema.json");
const SERVICE_QUERY: &str = include_str!("../schemas/service.query.v1.schema.json");

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Application {
    Runtime,
    Service,
}
impl Application {
    fn audience(self) -> &'static str {
        match self {
            Self::Runtime => "runtime://receiver-local",
            Self::Service => "service-management",
        }
    }
    fn prefix(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Service => "service",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    MalformedRequest,
    UnsupportedContract,
    WrongResource,
    InvalidPolicy,
    WrongApplication,
    UnknownPrincipal,
    OutsideWindow,
    UnallocatedOperation,
    Denied,
    InvalidLifetime,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "service_intent_rejected:{self:?}")
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

// Retain number lexemes for validation; opaque values never pass through a
// floating-point reserializer. RawValue validates JSON grammar independently.
#[derive(Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}
impl Json {
    fn from_raw(raw: &str, depth: usize) -> Result<Self> {
        if depth > 64 {
            return Err(Error::MalformedRequest);
        }
        match raw.as_bytes().first().copied() {
            Some(b'{') => {
                struct ObjectVisitor(usize);
                impl<'de> Visitor<'de> for ObjectVisitor {
                    type Value = Json;
                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        f.write_str("unique bounded JSON object")
                    }
                    fn visit_map<A: MapAccess<'de>>(
                        self,
                        mut a: A,
                    ) -> std::result::Result<Json, A::Error> {
                        let mut object = BTreeMap::new();
                        while let Some(key) = a.next_key::<String>()? {
                            if object.contains_key(&key) || object.len() >= 65_536 {
                                return Err(de::Error::custom("invalid member"));
                            }
                            let raw = a.next_value::<Box<RawValue>>()?;
                            let value = Json::from_raw(raw.get(), self.0 + 1)
                                .map_err(|_| de::Error::custom("invalid JSON value"))?;
                            object.insert(key, value);
                        }
                        Ok(Json::Object(object))
                    }
                }
                let mut deserializer = serde_json::Deserializer::from_str(raw);
                deserializer
                    .deserialize_map(ObjectVisitor(depth))
                    .map_err(|_| Error::MalformedRequest)
            }
            Some(b'[') => {
                let values: Vec<Box<RawValue>> =
                    serde_json::from_str(raw).map_err(|_| Error::MalformedRequest)?;
                if values.len() > 65_536 {
                    return Err(Error::MalformedRequest);
                }
                Ok(Self::Array(
                    values
                        .iter()
                        .map(|v| Self::from_raw(v.get(), depth + 1))
                        .collect::<Result<_>>()?,
                ))
            }
            Some(b'"') => Ok(Self::String(
                serde_json::from_str(raw).map_err(|_| Error::MalformedRequest)?,
            )),
            Some(b't') => Ok(Self::Bool(true)),
            Some(b'f') => Ok(Self::Bool(false)),
            Some(b'n') => Ok(Self::Null),
            Some(b'-' | b'0'..=b'9') => {
                // Integer tokens remain arbitrary precision. Decimal/exponent
                // values must be finite in the existing Python public profile.
                if raw.contains(['.', 'e', 'E']) && !raw.parse::<f64>().is_ok_and(f64::is_finite) {
                    return Err(Error::MalformedRequest);
                }
                Ok(Self::Number(raw.into()))
            }
            _ => Err(Error::MalformedRequest),
        }
    }
    fn from_value(v: &Value) -> Self {
        match v {
            Value::Null => Self::Null,
            Value::Bool(v) => Self::Bool(*v),
            Value::Number(v) => Self::Number(v.to_string()),
            Value::String(v) => Self::String(v.clone()),
            Value::Array(v) => Self::Array(v.iter().map(Self::from_value).collect()),
            Value::Object(v) => Self::Object(
                v.iter()
                    .map(|(k, v)| (k.clone(), Self::from_value(v)))
                    .collect(),
            ),
        }
    }
    fn get(&self, k: &str) -> Option<&Self> {
        self.as_object()?.get(k)
    }
    fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }
    fn as_array(&self) -> Option<&Vec<Self>> {
        if let Self::Array(a) = self {
            Some(a)
        } else {
            None
        }
    }
    fn as_object(&self) -> Option<&BTreeMap<String, Self>> {
        if let Self::Object(o) = self {
            Some(o)
        } else {
            None
        }
    }
    fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
    fn is_boolean(&self) -> bool {
        matches!(self, Self::Bool(_))
    }
    fn is_number(&self) -> bool {
        matches!(self, Self::Number(_))
    }
    fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }
    fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }
    fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }
    fn is_integer(&self) -> bool {
        matches!(self,Self::Number(s) if !s.contains(['.','e','E']))
    }
    fn integer_cmp(&self, bound: i64) -> Option<Ordering> {
        let Self::Number(s) = self else { return None };
        if !self.is_integer() {
            return None;
        }
        Some(match s.parse::<i128>() {
            Ok(n) => n.cmp(&(bound as i128)),
            Err(_) => {
                if s.starts_with('-') {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
        })
    }
}
impl Index<&str> for Json {
    type Output = Json;
    fn index(&self, k: &str) -> &Json {
        static NULL: Json = Json::Null;
        self.get(k).unwrap_or(&NULL)
    }
}
fn parse(raw: &[u8], max: usize) -> Result<Json> {
    if raw.is_empty() || raw.len() > max {
        return Err(Error::MalformedRequest);
    }
    let value: Box<RawValue> = serde_json::from_slice(raw).map_err(|_| Error::MalformedRequest)?;
    let value = Json::from_raw(value.get(), 0)?;
    if !value.is_object() {
        return Err(Error::MalformedRequest);
    }
    Ok(value)
}
fn canonical(v: &Value) -> Vec<u8> {
    fn append(v: &Value, out: &mut Vec<u8>) {
        match v {
            Value::Object(o) => {
                out.push(b'{');
                let mut keys: Vec<_> = o.keys().collect();
                keys.sort();
                for (n, k) in keys.into_iter().enumerate() {
                    if n > 0 {
                        out.push(b',');
                    }
                    serde_json::to_writer(&mut *out, k).unwrap();
                    out.push(b':');
                    append(&o[k], out);
                }
                out.push(b'}');
            }
            Value::Array(a) => {
                out.push(b'[');
                for (n, v) in a.iter().enumerate() {
                    if n > 0 {
                        out.push(b',');
                    }
                    append(v, out);
                }
                out.push(b']');
            }
            _ => serde_json::to_writer(out, v).unwrap(),
        }
    }
    let mut out = Vec::new();
    append(v, &mut out);
    out
}
fn digest(v: &[u8]) -> String {
    Sha256::digest(v)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn id(s: &str, lower: bool) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && b[0].is_ascii_alphanumeric()
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"._:-".contains(c))
        && (!lower
            || b.iter()
                .all(|c| !c.is_ascii_uppercase() && !b":".contains(c)))
}
fn label(s: &str) -> bool {
    id(s, false)
}
// Python str.strip/re\S includes these separators in addition to the
// Unicode White_Space property used by Rust. Match the existing reader.
fn python_whitespace(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{001c}'..='\u{001f}')
}
fn service_plan_json(v: &Json, depth: usize) -> bool {
    if depth > 32 {
        return false;
    }
    match v {
        Json::String(s) => !s.contains('\0'),
        Json::Array(values) => values.iter().all(|v| service_plan_json(v, depth + 1)),
        Json::Object(values) => values
            .iter()
            .all(|(k, v)| depth < 32 && !k.contains('\0') && service_plan_json(v, depth + 1)),
        _ => true,
    }
}
fn service_command_static_profile(operation: &str, payload: &Json) -> bool {
    if matches!(operation, "case.plan.approve" | "case.plan.revise") {
        if !payload
            .get("reason")
            .and_then(Json::as_str)
            .is_some_and(|s| s.chars().any(|c| !python_whitespace(c)))
            || !service_plan_json(payload, 0)
        {
            return false;
        }
        let Some(inputs) = payload.get("inputs").and_then(Json::as_object) else {
            return false;
        };
        let Some(selections) = payload.get("carry_forward").and_then(Json::as_array) else {
            return false;
        };
        let mut targets = BTreeSet::new();
        for selection in selections {
            let Some(target) = selection.get("target_input").and_then(Json::as_str) else {
                return false;
            };
            if inputs.contains_key(target) || !targets.insert(target) {
                return false;
            }
        }
        // Approve's empty selection and every identifier/digest/field bound
        // are already enforced by the frozen public schema, before this step.
        return true;
    }
    // All other closed lifecycle command payload members are strings. Their
    // required/nonblank and length constraints are already frozen in schema.
    payload.as_object().is_some_and(|p| {
        p.values()
            .all(|v| v.as_str().is_some_and(|s| !s.contains('\0')))
    })
}
fn pattern(s: &str, p: &str) -> bool {
    match p {
        "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}(?![\\s\\S])"
        | "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" => id(s, false),
        "^[a-z0-9][a-z0-9._-]{0,127}$" => id(s, true),
        "^[a-f0-9]{64}(?![\\s\\S])" | "^[a-f0-9]{64}$" => {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        "\\S" => s.chars().any(|c| !python_whitespace(c)),
        _ => false,
    }
}
// Exact bounded subset required by the frozen public bundles, not a general
// user-configurable JSON Schema engine. Unknown keywords/patterns deny.
fn valid(v: &Json, s: &Value, root: &Value, n: usize) -> bool {
    if n > 128 || !s.is_object() {
        return false;
    }
    const KEYS: &[&str] = &[
        "$schema",
        "$id",
        "$defs",
        "$ref",
        "$comment",
        "title",
        "oneOf",
        "anyOf",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "enum",
        "const",
        "items",
        "uniqueItems",
        "minItems",
        "maxItems",
        "pattern",
        "propertyNames",
        "maxProperties",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
    ];
    if s.as_object()
        .unwrap()
        .keys()
        .any(|k| !KEYS.contains(&k.as_str()))
    {
        return false;
    }
    if let Some(r) = s.get("$ref").and_then(Value::as_str) {
        let Some(name) = r.strip_prefix("#/$defs/") else {
            return false;
        };
        let Some(target) = root.get("$defs").and_then(|d| d.get(name)) else {
            return false;
        };
        if !valid(v, target, root, n + 1) {
            return false;
        }
    }
    for (key, exact) in [("oneOf", true), ("anyOf", false)] {
        if let Some(a) = s.get(key).and_then(Value::as_array) {
            let count = a.iter().filter(|t| valid(v, t, root, n + 1)).count();
            if if exact { count != 1 } else { count == 0 } {
                return false;
            }
        }
    }
    if s.get("const").is_some_and(|c| Json::from_value(c) != *v)
        || s.get("enum")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.iter().any(|c| Json::from_value(c) == *v))
    {
        return false;
    }
    if let Some(t) = s.get("type") {
        let types: Vec<&str> = if let Some(t) = t.as_str() {
            vec![t]
        } else if let Some(a) = t.as_array() {
            a.iter().filter_map(Value::as_str).collect()
        } else {
            return false;
        };
        if !types.iter().any(|t| match *t {
            "null" => v.is_null(),
            "boolean" => v.is_boolean(),
            "object" => v.is_object(),
            "array" => v.is_array(),
            "string" => v.is_string(),
            "integer" => v.is_integer(),
            "number" => v.is_number(),
            _ => false,
        }) {
            return false;
        }
    }
    if s.get("minimum")
        .and_then(Value::as_i64)
        .is_some_and(|m| v.integer_cmp(m) == Some(Ordering::Less))
        || s.get("maximum")
            .and_then(Value::as_i64)
            .is_some_and(|m| v.integer_cmp(m) == Some(Ordering::Greater))
    {
        return false;
    }
    if let Some(x) = v.as_str() {
        let len = x.chars().count() as u64;
        if s.get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|m| len < m)
            || s.get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|m| len > m)
            || s.get("pattern")
                .and_then(Value::as_str)
                .is_some_and(|p| !pattern(x, p))
        {
            return false;
        }
    }
    if let Some(a) = v.as_array() {
        let len = a.len() as u64;
        if s.get("minItems")
            .and_then(Value::as_u64)
            .is_some_and(|m| len < m)
            || s.get("maxItems")
                .and_then(Value::as_u64)
                .is_some_and(|m| len > m)
        {
            return false;
        }
        if s.get("uniqueItems") == Some(&Value::Bool(true))
            && a.iter().enumerate().any(|(n, v)| a[..n].contains(v))
        {
            return false;
        }
        if let Some(t) = s.get("items") {
            if !a.iter().all(|v| valid(v, t, root, n + 1)) {
                return false;
            }
        }
    }
    if let Some(o) = v.as_object() {
        if s.get("maxProperties")
            .and_then(Value::as_u64)
            .is_some_and(|m| o.len() as u64 > m)
        {
            return false;
        }
        if s.get("required")
            .and_then(Value::as_array)
            .is_some_and(|a| {
                a.iter()
                    .any(|k| k.as_str().is_none_or(|k| !o.contains_key(k)))
            })
        {
            return false;
        }
        for (k, v) in o {
            if let Some(p) = s.get("propertyNames") {
                if !valid(&Json::String(k.clone()), p, root, n + 1) {
                    return false;
                }
            }
            if let Some(p) = s.get("properties").and_then(|p| p.get(k)) {
                if !valid(v, p, root, n + 1) {
                    return false;
                }
            } else if s.get("additionalProperties") == Some(&Value::Bool(false)) {
                return false;
            } else if let Some(p) = s.get("additionalProperties").filter(|p| p.is_object()) {
                if !valid(v, p, root, n + 1) {
                    return false;
                }
            }
        }
    }
    true
}
fn text<'a>(v: &'a Json, k: &str) -> Result<&'a str> {
    v.get(k)
        .and_then(Json::as_str)
        .ok_or(Error::MalformedRequest)
}
const RUNTIME_OPERATIONS: &[(&str, u8)] = &[
    ("process.draft.put", 0x40),
    ("process.publish", 0x41),
    ("run.create", 0x42),
    ("run.cancel", 0x43),
    ("run.retry", 0x44),
    ("artifact.put", 0x45),
    ("actor.register", 0x46),
    ("actor.advertise", 0x47),
    ("executor.claim", 0x48),
    ("executor.heartbeat", 0x49),
    ("executor.complete", 0x4a),
    ("executor.fail", 0x4b),
    ("executor.release", 0x4c),
    ("handoff.consume", 0x4d),
    ("executor.effect.intent", 0x4e),
    ("executor.effect.dispatch", 0x4f),
    ("executor.effect.observe", 0x50),
    ("effect.resolve", 0x51),
    ("process.get", 0x60),
    ("version.get", 0x61),
    ("run.get", 0x62),
    ("work.list", 0x63),
    ("events.list", 0x64),
    ("artifact.get", 0x65),
    ("receipt.get", 0x66),
    ("output.get", 0x67),
    ("effect.get", 0x68),
    ("attempt.get", 0x69),
];
const SERVICE_OPERATIONS: &[&str] = &[
    "request.create",
    "request.qualify",
    "request.accept",
    "request.reject",
    "request.convert",
    "case.plan",
    "case.close",
    "case.plan.approve",
    "case.plan.revise",
    "request.execution",
    "case.summary",
    "case.plan-history",
];
fn raw_operation(app: Application, operation: &str) -> Option<&str> {
    let raw = operation
        .strip_prefix(app.prefix())?
        .strip_prefix('.')?
        .strip_suffix(".v1")?;
    if match app {
        Application::Runtime => RUNTIME_OPERATIONS.iter().any(|(op, _)| *op == raw),
        Application::Service => SERVICE_OPERATIONS.contains(&raw),
    } {
        Some(raw)
    } else {
        None
    }
}
fn runtime_resource(op: &str, p: &Json) -> Result<String> {
    let t = |k| text(p, k);
    Ok(match op {
        "process.draft.put" => format!(
            "processes/{}",
            text(p.get("draft").ok_or(Error::MalformedRequest)?, "process_id")?
        ),
        "process.publish" | "process.get" => format!("processes/{}", t("process_id")?),
        "version.get" => format!("versions/{}", t("process_version")?),
        "run.create" | "run.cancel" | "run.retry" | "run.get" => format!("runs/{}", t("run_id")?),
        op if op.starts_with("executor.") => {
            format!("runs/{}/steps/{}", t("run_id")?, t("step_id")?)
        }
        "actor.register" | "actor.advertise" => format!("actors/{}", t("actor_id")?),
        "work.list" => format!("actors/{}/work", t("actor_id")?),
        "artifact.put" => format!(
            "artifacts/{}",
            text(
                p.get("artifact").ok_or(Error::MalformedRequest)?,
                "content_hash"
            )?
        ),
        "artifact.get" => format!("artifacts/{}", t("content_hash")?),
        "receipt.get" => format!("receipts/{}", t("receipt_id")?),
        "output.get" => format!(
            "runs/{}/steps/{}/attempts/{}/output",
            t("run_id")?,
            t("step_id")?,
            t("attempt_id")?
        ),
        "attempt.get" => format!(
            "runs/{}/steps/{}/attempts/{}",
            t("run_id")?,
            t("step_id")?,
            t("attempt_id")?
        ),
        "effect.resolve" | "effect.get" => format!("effects/{}", t("effect_id")?),
        "events.list" => {
            if p.get("run_id").is_some() {
                format!("runs/{}/events", t("run_id")?)
            } else {
                "events".into()
            }
        }
        "handoff.consume" => format!(
            "handoffs/{}",
            digest(&canonical(
                &serde_json::json!({"source":t("source")?,"event_id":t("event_id")?})
            ))
        ),
        _ => return Err(Error::UnsupportedContract),
    })
}
#[derive(Clone)]
pub struct ServiceIntent {
    application: Application,
    operation: String,
    resource: String,
    bytes: Vec<u8>,
    digest: String,
}
impl fmt::Debug for ServiceIntent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ServiceIntent")
            .field("application", &self.application)
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}
impl ServiceIntent {
    pub fn parse(application: Application, raw: &[u8]) -> Result<Self> {
        let v = parse(
            raw,
            if application == Application::Service {
                65_536
            } else {
                MAX_REQUEST_BYTES
            },
        )?;
        let schema = text(&v, "schema")?;
        let (bundle, reference) = match (application, schema) {
            (Application::Runtime, "runtime.command.v1") => (RUNTIME_SCHEMA, Some("command")),
            (Application::Runtime, "runtime.query.v1") => (RUNTIME_SCHEMA, Some("query")),
            (Application::Service, "service.command.v1") => (SERVICE_COMMAND, None),
            (Application::Service, "service.query.v1") => (SERVICE_QUERY, None),
            _ => return Err(Error::WrongApplication),
        };
        let root: Value = serde_json::from_str(bundle).map_err(|_| Error::UnsupportedContract)?;
        let selected = reference.map(|r| &root["$defs"][r]).unwrap_or(&root);
        if !valid(&v, selected, &root, 0) {
            return Err(Error::MalformedRequest);
        }
        let op = text(&v, "operation")?;
        if application == Application::Service
            && schema == "service.command.v1"
            && !service_command_static_profile(op, &v["payload"])
        {
            return Err(Error::MalformedRequest);
        }
        let operation = format!("{}.{}.v1", application.prefix(), op);
        if raw_operation(application, &operation).is_none() {
            return Err(Error::UnsupportedContract);
        }
        let resource = match application {
            Application::Runtime => runtime_resource(op, &v["payload"])?,
            Application::Service => format!(
                "{}/{}",
                if text(&v["resource"], "kind")? == "ServiceRequest" {
                    "requests"
                } else {
                    "cases"
                },
                text(&v["resource"], "id")?
            ),
        };
        if application == Application::Runtime
            && schema == "runtime.command.v1"
            && text(&v, "resource")? != resource
        {
            return Err(Error::WrongResource);
        }
        let bytes = raw.to_vec();
        let hash = digest(&bytes);
        Ok(Self {
            application,
            operation,
            resource,
            bytes,
            digest: hash,
        })
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn request_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn request_digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Principal {
    subject_id: String,
    key_id: String,
    not_before: u64,
    not_after: u64,
    revoked: bool,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    operation: String,
    opcode: u8,
    fingerprint: String,
    handler_id: String,
    max_ttl_seconds: u64,
}
#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Scope {
    Exact,
    Prefix,
}
#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Effect {
    Allow,
    Deny,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    subject_id: String,
    key_id: String,
    operation: String,
    resource: String,
    resource_match: Scope,
    effect: Effect,
    not_before: u64,
    not_after: u64,
    active: bool,
}
impl Rule {
    fn matches(&self, s: &str, k: &str, operation: &str, resource: &str) -> bool {
        self.active
            && self.subject_id == s
            && self.key_id == k
            && self.operation == operation
            && match self.resource_match {
                Scope::Exact => self.resource == resource,
                Scope::Prefix => resource.starts_with(&self.resource),
            }
    }
    fn current(&self, now: u64) -> bool {
        self.not_before <= now && now < self.not_after
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema: String,
    application: Application,
    audience: String,
    not_before: u64,
    not_after: u64,
    max_ttl_seconds: u64,
    principals: Vec<Principal>,
    descriptors: Vec<Descriptor>,
    rules: Vec<Rule>,
}
fn window(a: u64, b: u64) -> bool {
    a < b && b <= MAX_SAFE
}
fn resource_scope(app: Application, rule: &Rule) -> bool {
    let r = &rule.resource;
    if r.contains('*')
        || r.contains("//")
        || r.starts_with('/')
        || r.split('/').any(|s| s == "." || s == "..")
    {
        return false;
    }
    if rule.resource_match == Scope::Prefix && !r.ends_with('/') {
        return false;
    }
    let r = if rule.resource_match == Scope::Prefix {
        r.trim_end_matches('/')
    } else {
        r.as_str()
    };
    let mut parts = r.split('/');
    let first = parts.next().unwrap_or("");
    let allowed = match app {
        Application::Runtime => [
            "processes",
            "versions",
            "runs",
            "actors",
            "artifacts",
            "receipts",
            "effects",
            "handoffs",
            "events",
        ]
        .contains(&first),
        Application::Service => ["requests", "cases"].contains(&first),
    };
    allowed
        && parts.all(|s| id(s, false))
        && (r.contains('/') || rule.resource_match == Scope::Prefix || r == "events")
}
/// Trusted startup policy. Parsing does not authenticate its source; callers
/// must load it through native owner-controlled configuration, never request JSON.
#[derive(Clone)]
pub struct ReceiverPolicy(Policy);
impl ReceiverPolicy {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        parse(raw, MAX_POLICY_BYTES).map_err(|_| Error::InvalidPolicy)?;
        let p: Policy = serde_json::from_slice(raw).map_err(|_| Error::InvalidPolicy)?;
        if p.schema != "secs.service-receiver-policy.v1"
            || p.audience != p.application.audience()
            || !window(p.not_before, p.not_after)
            || !(1..=MAX_TTL).contains(&p.max_ttl_seconds)
            || p.principals.len() > 32
            || p.descriptors.len() > 256
            || p.rules.len() > 1024
        {
            return Err(Error::InvalidPolicy);
        }
        let mut keys = BTreeSet::new();
        for x in &p.principals {
            if !label(&x.subject_id)
                || !label(&x.key_id)
                || !window(x.not_before, x.not_after)
                || !keys.insert(&x.key_id)
            {
                return Err(Error::InvalidPolicy);
            }
        }
        let (mut operations, mut opcodes) = (BTreeSet::new(), BTreeSet::new());
        for d in &p.descriptors {
            let Some(raw) = raw_operation(p.application, &d.operation) else {
                return Err(Error::InvalidPolicy);
            };
            if !operations.insert(&d.operation)
                || !opcodes.insert(d.opcode)
                || d.opcode < 0x40
                || !pattern(&d.fingerprint, "^[a-f0-9]{64}$")
                || d.handler_id.is_empty()
                || d.handler_id.len() > 256
                || d.handler_id.starts_with("dev/")
                || d.handler_id.bytes().any(|b| !(0x21..=0x7e).contains(&b))
                || !(1..=MAX_TTL).contains(&d.max_ttl_seconds)
            {
                return Err(Error::InvalidPolicy);
            }
            if p.application == Application::Runtime
                && RUNTIME_OPERATIONS
                    .iter()
                    .find(|(op, _)| *op == raw)
                    .map(|(_, code)| *code)
                    != Some(d.opcode)
            {
                return Err(Error::InvalidPolicy);
            }
        }
        for x in &p.rules {
            if !label(&x.subject_id)
                || !label(&x.key_id)
                || raw_operation(p.application, &x.operation).is_none()
                || !window(x.not_before, x.not_after)
                || !resource_scope(p.application, x)
            {
                return Err(Error::InvalidPolicy);
            }
        }
        Ok(Self(p))
    }
    /// Scope/time preparation only. Subject/key selectors must come from a
    /// separately authenticated native caller registry, never caller claims.
    /// No nonce is consumed and no signature or qualification is issued.
    pub fn prepare(
        &self,
        intent: &ServiceIntent,
        subject_id: &str,
        key_id: &str,
        now: u64,
        requested_ttl: u64,
    ) -> Result<PreparedServiceIntent> {
        let p = &self.0;
        if intent.application != p.application {
            return Err(Error::WrongApplication);
        }
        if now == 0 || now < p.not_before || now >= p.not_after {
            return Err(Error::OutsideWindow);
        }
        if !(1..=MAX_TTL).contains(&requested_ttl) {
            return Err(Error::InvalidLifetime);
        }
        let principal = p
            .principals
            .iter()
            .find(|x| x.subject_id == subject_id && x.key_id == key_id)
            .ok_or(Error::UnknownPrincipal)?;
        if principal.revoked || now < principal.not_before || now >= principal.not_after {
            return Err(Error::OutsideWindow);
        }
        let descriptor = p
            .descriptors
            .iter()
            .find(|d| d.operation == intent.operation)
            .ok_or(Error::UnallocatedOperation)?;
        let matching: Vec<_> = p
            .rules
            .iter()
            .filter(|r| r.matches(subject_id, key_id, &intent.operation, &intent.resource))
            .collect();
        if matching
            .iter()
            .any(|r| r.effect == Effect::Deny && r.current(now))
        {
            return Err(Error::Denied);
        }
        let allow_end = matching
            .iter()
            .filter(|r| r.effect == Effect::Allow && r.current(now))
            .map(|r| r.not_after)
            .max()
            .ok_or(Error::Denied)?;
        let ttl = requested_ttl
            .min(p.max_ttl_seconds)
            .min(descriptor.max_ttl_seconds);
        let mut expires = now
            .checked_add(ttl)
            .ok_or(Error::InvalidLifetime)?
            .min(p.not_after)
            .min(principal.not_after)
            .min(allow_end);
        for deny in matching
            .iter()
            .filter(|r| r.effect == Effect::Deny && r.not_before > now)
        {
            expires = expires.min(deny.not_before);
        }
        if expires <= now {
            return Err(Error::OutsideWindow);
        }
        Ok(PreparedServiceIntent {
            intent: intent.clone(),
            audience: p.audience.clone(),
            subject_id: subject_id.into(),
            key_id: key_id.into(),
            opcode: descriptor.opcode,
            fingerprint: descriptor.fingerprint.clone(),
            handler_id: descriptor.handler_id.clone(),
            issued_at: now,
            expires_at: expires,
            policy_digest: digest(&canonical(
                &serde_json::json!({"schema":p.schema,"application":p.application.prefix(),"audience":p.audience,"not_before":p.not_before,"not_after":p.not_after,"max_ttl_seconds":p.max_ttl_seconds,"principals":p.principals.iter().map(|x|serde_json::json!({"subject_id":x.subject_id,"key_id":x.key_id,"not_before":x.not_before,"not_after":x.not_after,"revoked":x.revoked})).collect::<Vec<_>>(),"descriptors":p.descriptors.iter().map(|x|serde_json::json!({"operation":x.operation,"opcode":x.opcode,"fingerprint":x.fingerprint,"handler_id":x.handler_id,"max_ttl_seconds":x.max_ttl_seconds})).collect::<Vec<_>>(),"rules":p.rules.iter().map(|x|serde_json::json!({"subject_id":x.subject_id,"key_id":x.key_id,"operation":x.operation,"resource":x.resource,"resource_match":if x.resource_match==Scope::Exact{"exact"}else{"prefix"},"effect":if x.effect==Effect::Allow{"allow"}else{"deny"},"not_before":x.not_before,"not_after":x.not_after,"active":x.active})).collect::<Vec<_>>()}),
            )),
        })
    }
}
/// Sealed immutable preparation snapshot. It proves a local policy decision
/// only, not authenticated caller identity, a signature, replay or readiness.
#[derive(Clone)]
pub struct PreparedServiceIntent {
    intent: ServiceIntent,
    audience: String,
    subject_id: String,
    key_id: String,
    opcode: u8,
    fingerprint: String,
    handler_id: String,
    issued_at: u64,
    expires_at: u64,
    policy_digest: String,
}
impl fmt::Debug for PreparedServiceIntent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PreparedServiceIntent")
            .field("operation", &self.intent.operation)
            .field("audience", &self.audience)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
impl PreparedServiceIntent {
    pub fn operation(&self) -> &str {
        self.intent.operation()
    }
    pub fn resource(&self) -> &str {
        self.intent.resource()
    }
    pub fn request_bytes(&self) -> &[u8] {
        self.intent.request_bytes()
    }
    pub fn request_digest(&self) -> &str {
        self.intent.request_digest()
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn opcode(&self) -> u8 {
        self.opcode
    }
    pub fn descriptor_fingerprint(&self) -> &str {
        &self.fingerprint
    }
    pub fn handler_id(&self) -> &str {
        &self.handler_id
    }
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
}
