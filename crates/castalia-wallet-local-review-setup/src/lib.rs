//! Fixed create-only owner setup. No signing port or automatic recovery/reset.
use castalia_wallet_private_files::service_store::ServiceRoot;
use castalia_wallet_service_holder::custody::{
    Application, NewServiceIdentity, ServiceIdentityStore,
};
use libsec_core::service_holder_proof::ServiceApplication;
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize,
};
use serde_json::{json, Value};
use server::{
    manifest::{OpcodeRange, OperationDescriptor, OperationName, ReplayScope, TargetKind},
    privacy::DisclosurePolicy,
    service_owner_publication::OwnerPublicationSource,
    service_wallet_source::{
        OwnerSelectedWalletRoot, StartupWalletObservationPin, WalletCurrentSource,
    },
    ServiceAuthority,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const RUN: &str = "local-review-pilot-20261017-001";
pub const ACTOR: &str = "frank-local-review-pilot";
pub const INTEGRATION: &str = "local-review-pilot";
pub const ROUTE: &str = "operator-local-review";
pub const HOLDER: &str = "service:frank-local-review-pilot";
const NODE: &str = "node:local-review-command-issuer";
const COMMAND_KEY: &str = "issuer:local-review-command-v1";
const RESULT_SUBJECT: &str = "service:local-review-result-party";
const RESULT_KEY: &str = "issuer:local-review-result-v1";
const VERSION: &str = "personal-review-v1-911747b69cf2b2f5";
const HANDLER: &str = "frank.local-review.result-v1";
pub const OPERATIONS: [&str; 9] = [
    "review.load_review",
    "review.transcribe",
    "review.resolve_components",
    "review.annotate",
    "review.extract",
    "review.bind_source",
    "review.write_review",
    "review.write_status",
    "review.daily_note",
];
pub const LEGACY: [&str; 4] = [
    "transcribe-review-audio",
    "annotate-review-transcript",
    "extract-review-observations",
    "update_review_status",
];
pub const RESOURCES: [&str; 8] = [
    "review.record",
    "review.audio",
    "review.events",
    "review.workspace",
    "subject.codebase",
    "vault.notes",
    "review.status",
    "vault.daily-note",
];
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupError;
impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("pilot owner setup denied; partial state retained")
    }
}
impl std::error::Error for SetupError {}
type Result<T> = std::result::Result<T, SetupError>;
fn ok(b: bool) -> Result<()> {
    if b {
        Ok(())
    } else {
        Err(SetupError)
    }
}
fn hash(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn pin(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| SetupError)
}
fn canonical(v: &Value) -> Vec<u8> {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(m) => Value::Object(
                m.iter()
                    .map(|(k, v)| (k.clone(), sort(v)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_vec(&sort(v)).expect("JSON value")
}
// Closed metadata only. No application request/result bytes enter this parser.
// Reserve the pinned serde_json arbitrary-precision internal numeric map tag.
struct Closed;
impl<'de> Deserialize<'de> for ClosedValue {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        d.deserialize_any(Closed).map(Self)
    }
}
struct ClosedValue(Value);
impl<'de> Visitor<'de> for Closed {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("bounded unsigned JSON metadata")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(json!(v))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        if v.len() > 65536 || v.contains('\0') {
            Err(E::custom("text"))
        } else {
            Ok(json!(v))
        }
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
        self.visit_str(&v)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut rows = Vec::new();
        while let Some(v) = a.next_element::<ClosedValue>()? {
            if rows.len() >= 256 {
                return Err(de::Error::custom("array"));
            }
            rows.push(v.0);
        }
        Ok(Value::Array(rows))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut m = serde_json::Map::new();
        while let Some(k) = a.next_key::<String>()? {
            if m.len() >= 256 || k == "$serde_json::private::Number" || m.contains_key(&k) {
                return Err(de::Error::custom("duplicate/reserved"));
            }
            m.insert(k, a.next_value::<ClosedValue>()?.0);
        }
        Ok(Value::Object(m))
    }
}
fn parse<T: serde::de::DeserializeOwned>(raw: &[u8], maximum: usize) -> Result<T> {
    ok(!raw.is_empty() && raw.len() <= maximum)?;
    let mut d = serde_json::Deserializer::from_slice(raw);
    let v = ClosedValue::deserialize(&mut d).map_err(|_| SetupError)?.0;
    d.end().map_err(|_| SetupError)?;
    fn bounded(v: &Value, depth: usize, n: &mut usize) -> bool {
        *n += 1;
        if depth > 24 || *n > 10000 {
            return false;
        }
        match v {
            Value::Array(a) => a.iter().all(|v| bounded(v, depth + 1, n)),
            Value::Object(m) => m.values().all(|v| bounded(v, depth + 1, n)),
            _ => true,
        }
    }
    ok(bounded(&v, 0, &mut 0))?;
    serde_json::from_value(v).map_err(|_| SetupError)
}
fn canonical_path(p: &Path) -> Result<()> {
    ok(p.is_absolute()
        && p.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
        && p.as_os_str().as_bytes().len() <= 4096)?;
    for a in p.ancestors() {
        let m = fs::symlink_metadata(a).map_err(|_| SetupError)?;
        let sticky = m.uid() == 0 && m.mode() & 0o1000 != 0;
        ok(m.is_dir()
            && (m.uid() == 0 || m.uid() == unsafe { libc::geteuid() })
            && (m.mode() & 0o022 == 0 || sticky))?;
    }
    Ok(())
}
fn private_dir(p: &Path) -> Result<()> {
    canonical_path(p)?;
    let m = fs::symlink_metadata(p).map_err(|_| SetupError)?;
    ok(m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o7777 == 0o700)
}
fn read(p: &Path, max: u64, mode: u32) -> Result<Vec<u8>> {
    canonical_path(p.parent().ok_or(SetupError)?)?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)
        .map_err(|_| SetupError)?;
    let a = f.metadata().map_err(|_| SetupError)?;
    ok(a.is_file()
        && a.uid() == unsafe { libc::geteuid() }
        && a.nlink() == 1
        && a.mode() & 0o7777 == mode
        && a.len() <= max)?;
    let mut raw = Vec::new();
    (&mut f)
        .take(max + 1)
        .read_to_end(&mut raw)
        .map_err(|_| SetupError)?;
    let b = f.metadata().map_err(|_| SetupError)?;
    ok(raw.len() as u64 == a.len()
        && (
            a.dev(),
            a.ino(),
            a.len(),
            a.mode(),
            a.mtime(),
            a.mtime_nsec(),
            a.ctime(),
            a.ctime_nsec(),
        ) == (
            b.dev(),
            b.ino(),
            b.len(),
            b.mode(),
            b.mtime(),
            b.mtime_nsec(),
            b.ctime(),
            b.ctime_nsec(),
        ))?;
    Ok(raw)
}
fn create_dir(p: &Path) -> Result<()> {
    DirBuilder::new()
        .mode(0o700)
        .create(p)
        .map_err(|_| SetupError)?;
    private_dir(p)?;
    File::open(p.parent().ok_or(SetupError)?)
        .and_then(|f| f.sync_all())
        .map_err(|_| SetupError)
}
fn write(p: &Path, raw: &[u8]) -> Result<()> {
    ok(raw.len() <= 1048576)?;
    private_dir(p.parent().ok_or(SetupError)?)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)
        .map_err(|_| SetupError)?;
    f.write_all(raw)
        .and_then(|_| f.sync_all())
        .map_err(|_| SetupError)?;
    File::open(p.parent().ok_or(SetupError)?)
        .and_then(|f| f.sync_all())
        .map_err(|_| SetupError)?;
    ok(read(p, 1048576, 0o600)? == raw)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    pilot_root: PathBuf,
    not_before: String,
    not_after: String,
    result_opcode: String,
    composition_sha256: String,
    source_manifest_sha256: String,
    wallet_command_sha256: String,
    result_command_sha256: String,
    verifier_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    content_hash: String,
    byte_length: u64,
    media_type: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transcript {
    audio_sha256: String,
    artifact: Artifact,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    path: String,
    artifact: Artifact,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    actor_id: String,
    integration_id: String,
    route: String,
    capabilities: Vec<String>,
    resources: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Composition {
    schema: String,
    runtime_endpoint: String,
    journal: PathBuf,
    capture_root: PathBuf,
    actor: Actor,
    run_ids: Vec<String>,
    producer_artifact_sha256: String,
    normalizer_sha256: String,
    transcript: Transcript,
    snapshots: BTreeMap<String, Vec<Snapshot>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    sha256: String,
    byte_length: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    producer_artifact_sha256: String,
    normalizer_sha256: String,
    configuration_sha256: String,
    entries: Vec<Entry>,
}
fn seconds(s: &str) -> Result<u64> {
    ok(!s.is_empty()
        && s.len() <= 16
        && s.bytes().all(|b| b.is_ascii_digit())
        && (!s.starts_with('0') || s == "0"))?;
    s.parse().map_err(|_| SetupError)
}
fn identifier(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn final_window(start: u64, end: u64, floor: u64, at: u64) -> bool {
    start <= at && at < end && at >= floor
}
fn final_wallet(
    wallet: &WalletCurrentSource,
) -> Result<server::service_wallet_source::WalletCurrentLease<'_>> {
    let held = wallet.capture_shared().map_err(|_| SetupError)?;
    held.revalidate().map_err(|_| SetupError)?;
    Ok(held)
}
fn artifact(a: &Artifact) -> Result<()> {
    ok(pin(&a.content_hash)
        && a.byte_length <= 1048576
        && !a.media_type.is_empty()
        && a.media_type.len() <= 128)
}
fn exact_set(rows: &[String], expected: impl Iterator<Item = &'static str>) -> bool {
    rows.iter().collect::<BTreeSet<_>>().len() == rows.len()
        && rows.iter().map(String::as_str).collect::<BTreeSet<_>>() == expected.collect()
}
struct Input {
    p: Plan,
    c: Composition,
    start: u64,
    end: u64,
    observed_floor: u64,
}
fn preflight(raw: &[u8]) -> Result<Input> {
    let p: Plan = parse(raw, 16384)?;
    ok(p.schema == "castalia.wallet-local-review-setup.v1"
        && p.result_opcode == "e0"
        && p.pilot_root
            .file_name()
            .is_some_and(|s| s == "Process-Pilot"))?;
    private_dir(&p.pilot_root)?;
    private_dir(&p.pilot_root.join("config"))?;
    private_dir(&p.pilot_root.join("data"))?;
    ok(fs::symlink_metadata(p.pilot_root.join("authority"))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound))?;
    let start = seconds(&p.not_before)?;
    let end = seconds(&p.not_after)?;
    let n = now()?;
    ok(start > 0
        && start <= n
        && n < end
        && end <= n.checked_add(3600).ok_or(SetupError)?
        && end - start <= 3600
        && end <= 9_007_199_254_740_991)?;
    for v in [
        &p.composition_sha256,
        &p.source_manifest_sha256,
        &p.wallet_command_sha256,
        &p.result_command_sha256,
        &p.verifier_sha256,
    ] {
        ok(pin(v))?;
    }
    for (name, h) in [
        ("castalia-wallet-service", &p.wallet_command_sha256),
        ("secs-frank-result", &p.result_command_sha256),
        ("process-runtime-secs-check", &p.verifier_sha256),
    ] {
        ok(hash(&read(
            &p.pilot_root.join("native").join(name),
            67108864,
            0o500,
        )?) == *h)?;
    }
    let cr = read(
        &p.pilot_root.join("config/review-composition.json"),
        65536,
        0o600,
    )?;
    ok(hash(&cr) == p.composition_sha256)?;
    let c: Composition = parse(&cr, 65536)?;
    ok(c.schema == "frank.local-review.composition.v1"
        && c.runtime_endpoint == "http://127.0.0.1:8192"
        && c.journal == p.pilot_root.join("data/frank.db")
        && c.capture_root == p.pilot_root.join("data/capture")
        && c.actor.actor_id == ACTOR
        && c.actor.integration_id == INTEGRATION
        && c.actor.route == ROUTE
        && c.run_ids == [RUN]
        && exact_set(&c.actor.capabilities, OPERATIONS.into_iter().chain(LEGACY))
        && exact_set(&c.actor.resources, RESOURCES.into_iter())
        && pin(&c.producer_artifact_sha256)
        && pin(&c.normalizer_sha256)
        && pin(&c.transcript.audio_sha256)
        && c.snapshots.len() <= 64)?;
    artifact(&c.transcript.artifact)?;
    for (subject, rows) in &c.snapshots {
        ok(identifier(subject) && rows.len() <= 128)?;
        for s in rows {
            ok(!s.path.is_empty() && s.path.len() <= 4096)?;
            artifact(&s.artifact)?;
        }
    }
    // Public source preparation precedes authority; no unpublished Runtime state
    // or not-yet-issued command/result configuration hash is needed.
    ok(fs::symlink_metadata(&c.capture_root)
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        && fs::symlink_metadata(&c.journal)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound))?;
    private_dir(&p.pilot_root.join("inputs/source-blobs"))?;
    let mr = read(
        &p.pilot_root.join("config/review-source-manifest.json"),
        16384,
        0o600,
    )?;
    ok(hash(&mr) == p.source_manifest_sha256)?;
    let m: Manifest = parse(&mr, 16384)?;
    ok(m.schema == "frank.local-review.source-manifest.v1"
        && m.producer_artifact_sha256 == c.producer_artifact_sha256
        && m.normalizer_sha256 == c.normalizer_sha256
        && m.configuration_sha256 == p.composition_sha256
        && (3..=128).contains(&m.entries.len()))?;
    let mut seen = BTreeSet::new();
    for e in m.entries {
        ok(pin(&e.sha256) && seen.insert(e.sha256.clone()) && e.byte_length <= 1048576)?;
        let b = read(
            &p.pilot_root.join("inputs/source-blobs").join(&e.sha256),
            1048576,
            0o600,
        )?;
        ok(b.len() as u64 == e.byte_length && hash(&b) == e.sha256)?;
    }
    ok([
        &c.producer_artifact_sha256,
        &c.normalizer_sha256,
        &p.composition_sha256,
    ]
    .into_iter()
    .all(|h| seen.contains(h)))?;
    Ok(Input {
        p,
        c,
        start,
        end,
        observed_floor: n,
    })
}
#[derive(Clone)]
struct Rule {
    name: &'static str,
    opcode: u8,
    kind: &'static str,
    resource: String,
}
fn rules() -> Vec<Rule> {
    let mut r = Vec::new();
    let mut add = |name, opcode, kind, resource| {
        r.push(Rule {
            name,
            opcode,
            kind,
            resource,
        })
    };
    for (op, code, res) in [
        (
            "process.draft.put",
            0x40,
            "processes/personal-review-v1".into(),
        ),
        (
            "process.publish",
            0x41,
            "processes/personal-review-v1".into(),
        ),
        ("run.create", 0x42, format!("runs/{RUN}")),
        ("actor.register", 0x46, format!("actors/{ACTOR}")),
        ("work.list", 0x63, format!("actors/{ACTOR}/work")),
        ("events.list", 0x64, "events".into()),
        ("run.get", 0x62, format!("runs/{RUN}")),
        ("version.get", 0x61, format!("versions/{VERSION}")),
    ] {
        add(op, code, "exact", res);
    }
    for (op, code) in [("artifact.put", 0x45), ("artifact.get", 0x65)] {
        add(op, code, "prefix", "artifacts/".into());
    }
    add("receipt.get", 0x66, "prefix", "receipts/".into());
    for i in 1..=9 {
        for (op, code) in [
            ("executor.claim", 0x48),
            ("executor.heartbeat", 0x49),
            ("executor.complete", 0x4a),
            ("executor.fail", 0x4b),
            ("executor.release", 0x4c),
            ("executor.effect.intent", 0x4e),
            ("executor.effect.dispatch", 0x4f),
            ("executor.effect.observe", 0x50),
        ] {
            add(op, code, "exact", format!("runs/{RUN}/steps/step_{i}"));
        }
        for (op, code) in [("attempt.get", 0x69), ("output.get", 0x67)] {
            add(
                op,
                code,
                "prefix",
                format!("runs/{RUN}/steps/step_{i}/attempts/"),
            );
        }
    }
    r
}
fn descriptor(opcode: u8, name: &str, handler: &str, result: bool) -> Result<(Value, String)> {
    let (credential, capability, evidence) = if result {
        (
            vec!["frank.local-review.result-party-assignment.v1"],
            vec!["frank.result.attest.v1"],
            vec!["frank.local-review.capture.v1"],
        )
    } else {
        (vec![], vec![], vec![])
    };
    let policy = if result {
        "frank.result-receipt.v1"
    } else {
        "runtime.local-review-receipt.v1"
    };
    let payload = if result {
        "frank.native-result-payload.v1"
    } else {
        "application/json"
    };
    let d = OperationDescriptor {
        opcode,
        name: OperationName::new(name),
        payload_schema: Some(payload.into()),
        output_profile: None,
        target_kind: TargetKind::ReceiverProductionHandler,
        required_credentials: credential.iter().map(|s| (*s).into()).collect(),
        required_capabilities: capability.iter().map(|s| (*s).into()).collect(),
        accepted_evidence: evidence.iter().map(|s| (*s).into()).collect(),
        required_authority_mode: None,
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 60,
        handler_id: handler.into(),
        dev_binding: false,
        range: OpcodeRange::OperatorDefined,
        disclosure_policy: DisclosurePolicy::deny_by_default(policy, 1),
    };
    d.validate().map_err(|_| SetupError)?;
    let h = d
        .authorization_fingerprint()
        .strip_prefix("descriptor:sha256:")
        .ok_or(SetupError)?
        .to_owned();
    Ok((
        json!({"opcode":opcode,"name":name,"payload_schema":payload,"output_profile":null,
        "target_kind":"receiver_production_handler","required_credentials":credential,"required_capabilities":capability,
        "accepted_evidence":evidence,"required_authority_mode":null,"replay_scope":"session_opcode_nonce",
        "max_ttl_seconds":60,"handler_id":handler,"dev_binding":false,"range":"operator_defined",
        "disclosure_policy":{"policy_id":policy,"policy_version":1,"permissions":[]}}),
        h,
    ))
}
fn public_key(key: &str, material: &str, start: u64, end: u64) -> Value {
    json!({"key_id":key,"public_key_hex":material,"status":"active","production_authority":true,
        "not_before":start,"not_after":end,"revoked_at":null})
}
/// SAME actual bounded owner-plan bytes are pinned before closed parse or stores.
pub fn create_from_plan(path: &Path, expected_sha256: &str) -> Result<Value> {
    ok(pin(expected_sha256))?;
    let raw = read(path, 16384, 0o600)?;
    ok(hash(&raw) == expected_sha256)?;
    let input = preflight(&raw)?;
    create_selected(path, expected_sha256, input)
}
fn create_selected(path: &Path, expected_sha256: &str, input: Input) -> Result<Value> {
    let p = input.p;
    let c = input.c;
    let (start, end) = (input.start, input.end);
    let observed_floor = input.observed_floor;
    let base = p.pilot_root.join("authority");
    create_dir(&base)?;
    write(
        &base.join("SETUP-BEGIN.json"),
        &canonical(
            &json!({"schema":"castalia.wallet-local-review-setup-intent.v1",
        "plan_sha256":expected_sha256,"run_id":RUN,"started_at":now()?,"failure_policy":"retain; no automatic retry/rekey"}),
        ),
    )?;
    // Fixed public capture preparation, not reconstruction of an execution
    // observation. Every entry is copied by its manifest-pinned content hash.
    create_dir(&c.capture_root)?;
    create_dir(&c.capture_root.join("blobs"))?;
    let manifest_raw = read(
        &p.pilot_root.join("config/review-source-manifest.json"),
        16384,
        0o600,
    )?;
    ok(hash(&manifest_raw) == p.source_manifest_sha256)?;
    let manifest: Manifest = parse(&manifest_raw, 16384)?;
    for e in &manifest.entries {
        let raw = read(
            &p.pilot_root.join("inputs/source-blobs").join(&e.sha256),
            1048576,
            0o600,
        )?;
        ok(raw.len() as u64 == e.byte_length && hash(&raw) == e.sha256)?;
        write(&c.capture_root.join("blobs").join(&e.sha256), &raw)?;
    }
    write(&c.capture_root.join("source-manifest.json"), &manifest_raw)?;
    write(&c.capture_root.join("capture.lock"), b"")?;
    // Every key is generated by its native custody API; only public bytes return.
    for d in [
        "wallet",
        "command-issuer",
        "result-issuer",
        "native",
        "command-journal",
        "result-journal",
        "assignment",
        "config",
    ] {
        create_dir(&base.join(d))?;
    }
    write(&base.join("result-journal/journal.lock"), b"")?;
    let command_public = ServiceAuthority::create_issuer_key(&base.join("command-issuer"))
        .map_err(|_| SetupError)?;
    let result_public =
        ServiceAuthority::create_issuer_key(&base.join("result-issuer")).map_err(|_| SetupError)?;
    let store = ServiceIdentityStore::create(
        &base.join("wallet"),
        NewServiceIdentity {
            application: Application::Runtime,
            subject_id: HOLDER.into(),
            not_before: start,
            not_after: end,
        },
    )
    .map_err(|_| SetupError)?;
    let initial = store.public_identity().map_err(|_| SetupError)?;
    let mut descriptors = Vec::new();
    let mut receiver_descriptors = Vec::new();
    let mut unique = BTreeSet::new();
    let rr = rules();
    for r in &rr {
        if unique.insert(r.opcode) {
            let name = format!("runtime.{}.v1", r.name);
            let handler = format!("process-runtime.v1:{}", r.name);
            let (d, h) = descriptor(r.opcode, &name, &handler, false)?;
            descriptors.push(d);
            receiver_descriptors.push(json!({"operation":name,"opcode":r.opcode,"fingerprint":h,"handler_id":handler,"max_ttl_seconds":60}));
        }
    }
    ok(unique.len() == 21)?;
    let delegation_rules: Vec<_> = rr
        .iter()
        .map(|r| {
            json!({"subject_id":HOLDER,"key_id":initial.key_id,
        "operation":format!("runtime.{}.v1",r.name),"resource":r.resource,"resource_match":r.kind,
        "effect":"allow","active":true,"not_before":start,"not_after":end})
        })
        .collect();
    let receiver = json!({"schema":"secs.service-receiver-policy.v1","application":"runtime",
        "audience":ServiceApplication::RuntimeV1.audience(),"not_before":start,"not_after":end,"max_ttl_seconds":60,
        "principals":[{"subject_id":HOLDER,"key_id":initial.key_id,"not_before":start,"not_after":end,"revoked":false}],
        "descriptors":receiver_descriptors,"rules":delegation_rules});
    let mut issuer = json!({"node_id":NODE,"key_id":COMMAND_KEY,"public_key_hex":hex(&command_public),"algorithm":"ed25519",
        "status":"active","not_before":start,"not_after":end,"revoked_at":null,"replaced_by":null});
    let holder = json!({"subject_id":HOLDER,"key_id":initial.key_id,"public_key_hex":initial.public_key_hex,
        "generation":initial.key_generation,"algorithm":"ed25519","status":"active","not_before":start,"not_after":end,
        "revoked_at":null,"replaced_by":null});
    let owner = json!({"schema":"castalia.wallet-service-owner-input.v1","generation":initial.state_revision+1,
        "valid_not_before":start,"valid_until":end,"application":"runtime","issuer_node_id":NODE,"selected_issuer_key_id":COMMAND_KEY,
        "issuers":[issuer.clone()],"holder":holder,"descriptors":descriptors,"delegation_policy":receiver});
    let identity = store
        .configure(initial.expected(), &canonical(&owner))
        .map_err(|_| SetupError)?;
    store
        .cleanup_unreferenced(identity.expected())
        .map_err(|_| SetupError)?;
    // Derive only public reference DATA under the actual shared filesystem lease.
    let public_root = ServiceRoot::open(&base.join("wallet")).map_err(|_| SetupError)?;
    let observed = public_root.lock_public_shared().map_err(|_| SetupError)?;
    let metadata = observed.metadata();
    let state: Value = parse(metadata.state_bytes(), 4096)?;
    let actual_owner: Value = parse(metadata.owner_input_bytes().ok_or(SetupError)?, 262144)?;
    let mut reference = json!({"schema":"secs.wallet-current-reference.v2","current_sha256":hash(metadata.current_bytes()),
        "custody_state_sha256":hash(metadata.state_bytes()),"delegation_policy_sha256":hash(&canonical(&actual_owner["delegation_policy"]))});
    for name in [
        "store_id",
        "subject_id",
        "purpose",
        "application",
        "state_revision",
        "key_generation",
        "state",
        "key_id",
        "public_key_hex",
        "public_key_sha256",
        "not_before",
        "not_after",
        "revoked_at",
        "owner_input_sha256",
    ] {
        reference[name] = state[name].clone();
    }
    observed.revalidate().map_err(|_| SetupError)?;
    drop(observed);
    let startup = json!({"schema":"secs.wallet-current-startup-pin.v2","store_id":state["store_id"],
        "minimum_state_revision":state["state_revision"],"minimum_key_generation":state["key_generation"],
        "expected_wallet_reference_sha256":hash(&canonical(&reference))});
    let wallet = WalletCurrentSource::open(
        OwnerSelectedWalletRoot::open(&base.join("wallet")).map_err(|_| SetupError)?,
        StartupWalletObservationPin::parse_owner_configuration(&canonical(&startup))
            .map_err(|_| SetupError)?,
    )
    .map_err(|_| SetupError)?;
    issuer["production_authority"] = json!(true);
    let mut nholder = holder.clone();
    nholder
        .as_object_mut()
        .ok_or(SetupError)?
        .remove("generation");
    nholder
        .as_object_mut()
        .ok_or(SetupError)?
        .remove("replaced_by");
    let permissions:Vec<_>=rr.iter().map(|r|json!({"caller_id":HOLDER,"opcode":r.opcode,"operation":format!("runtime.{}.v1",r.name),
        "resource":if r.kind=="exact" {json!({"kind":"exact","value":r.resource})}else{json!({"kind":"prefix","prefix":r.resource})},
        "effect":"allow","not_before":start,"not_after":end,"status":"active","authority_source":"receiver_local"})).collect();
    let bundle = json!({"schema":"secs.service-owner-bundle.v2","generation":1,"wallet_current":reference,
        "valid_not_before":start,"valid_until":end,"application":"runtime","issuer_node_id":NODE,
        "selected_issuer_key_id":COMMAND_KEY,"issuers":[issuer],"holders":[nholder],
        "descriptors":descriptors,"permissions":permissions,"receiver_policy":receiver});
    let pin_native =
        OwnerPublicationSource::create_initial(&base.join("native"), &wallet, &canonical(&bundle))
            .map_err(|_| SetupError)?;
    let configs = base.join("config");
    let mut outputs = BTreeMap::<String, String>::new();
    let mut save = |name: &str, v: Value| -> Result<PathBuf> {
        let bytes = canonical(&v);
        let p = configs.join(name);
        write(&p, &bytes)?;
        outputs.insert(name.into(), hash(&bytes));
        Ok(p)
    };
    let command_config = save(
        "command-authority.json",
        json!({"schema":"secs.service-authority-configuration.v1",
        "wallet_root":base.join("wallet"),"wallet_observation_pin":startup,"native_root":base.join("native"),
        "native_generation":pin_native.generation(),"native_sha256":hex(&pin_native.sha256()),
        "issuer_root":base.join("command-issuer"),"issuer_node_id":NODE,"issuer_key_id":COMMAND_KEY,
        "issuer_public_key_hex":hex(&command_public),"journal_root":base.join("command-journal"),"maximum_ttl":30,
        "journal_capacity":"local_review_pilot_512"}),
    )?;
    let bind = identity.binding();
    let expect = identity.expected();
    let wallet_config = save(
        "wallet-command.json",
        json!({"schema":"castalia.wallet-service-command.v1",
        "native_configuration":command_config,"native_configuration_sha256":hash(&read(&command_config,65536,0o600)?),
        "wallet_root":base.join("wallet"),"application":"runtime",
        "store_binding":{"store_id":bind.store_id,"subject_id":bind.subject_id,"application":"runtime","purpose":bind.purpose,"minimum_revision":bind.minimum_revision},
        "expected_state":{"state_revision":expect.state_revision,"state_sha256":expect.state_sha256}}),
    )?;
    let runtime_descriptors:Vec<_>=receiver_descriptors.iter().map(|d|json!({"operation":d["operation"],"fingerprint":d["fingerprint"],"handler_id":d["handler_id"]})).collect();
    let runtime_rules:Vec<_>=rr.iter().map(|r|json!({"subject_id":HOLDER,"key_id":identity.key_id,"operation":format!("runtime.{}.v1",r.name),
        "resource":r.resource,"resource_match":r.kind,"effect":"allow","active":true,"not_before_ms":start*1000,"not_after_ms":end*1000})).collect();
    let runtime_policy = save(
        "runtime-policy.json",
        json!({"schema":"runtime.receiver-policy.v1","audience":ServiceApplication::RuntimeV1.audience(),
        "keys":[public_key(COMMAND_KEY,&hex(&command_public),start,end)],"descriptors":runtime_descriptors,"permissions":runtime_rules,"revoked_subject_keys":[]}),
    )?;
    save(
        "runtime-receiver.json",
        json!({"schema":"runtime.receiver-configuration.v1","audience":ServiceApplication::RuntimeV1.audience(),
        "native_verifier":{"executable":p.pilot_root.join("native/process-runtime-secs-check"),"sha256":p.verifier_sha256},"policy_file":runtime_policy}),
    )?;
    let assignment = json!({"schema":"frank.local-review.result-party-assignment.v1","assignment_id":RUN,"generation":1,"active":true,
        "subject_id":RESULT_SUBJECT,"key_id":RESULT_KEY,"issuer_public_key_hex":hex(&result_public),"actor_id":ACTOR,"integration_id":INTEGRATION,
        "route":ROUTE,"run_ids":[RUN],"operations":OPERATIONS,"producer_artifact_sha256":c.producer_artifact_sha256,
        "normalizer_sha256":c.normalizer_sha256,"configuration_sha256":p.composition_sha256,"source_manifest_sha256":p.source_manifest_sha256,
        "not_before":start,"not_after":end});
    write(&base.join("assignment/assignment.lock"), b"")?;
    let assignment_raw = canonical(&assignment);
    write(&base.join("assignment/assignment.json"), &assignment_raw)?;
    let (_, result_fingerprint) = descriptor(0xe0, "frank.result.attest.v1", HANDLER, true)?;
    let result_config = save(
        "result-authority.json",
        json!({"schema":"frank.result-authority-configuration.v1",
        "issuer_root":base.join("result-issuer"),"issuer_subject_id":RESULT_SUBJECT,"issuer_key_id":RESULT_KEY,
        "issuer_public_key_hex":hex(&result_public),"assignment_root":base.join("assignment"),"assignment_sha256":hash(&assignment_raw),
        "capture_root":c.capture_root,"journal_root":base.join("result-journal"),
        "descriptor":{"opcode":224,"handler_id":HANDLER,"fingerprint":result_fingerprint},"maximum_ttl":30}),
    )?;
    let result_rules:Vec<_>=(1..=9).map(|i|json!({"subject_id":RESULT_SUBJECT,"key_id":RESULT_KEY,
        "resource":format!("runs/{RUN}/steps/step_{i}/attempts/"),"resource_match":"prefix","effect":"allow","active":true,
        "not_before_ms":start*1000,"not_after_ms":end*1000})).collect();
    let result_policy = save(
        "result-policy.json",
        json!({"schema":"frank.result-receiver-policy.v1","audience":"frank://result-receiver",
        "operation":"frank.result.attest.v1","keys":[public_key(RESULT_KEY,&hex(&result_public),start,end)],
        "descriptor":{"opcode":224,"handler_id":HANDLER,"fingerprint":result_fingerprint},
        "subjects":[{"subject_id":RESULT_SUBJECT,"key_id":RESULT_KEY,"actor_id":ACTOR,"integration_id":INTEGRATION,"route":ROUTE}],
        "rules":result_rules,"revoked_subject_keys":[]}),
    )?;
    save(
        "frank-local-review.json",
        json!({"schema":"frank.local-review.config.v1",
        "composition":{"path":p.pilot_root.join("config/review-composition.json"),"sha256":p.composition_sha256},"source_manifest_sha256":p.source_manifest_sha256,
        "wallet":{"executable":p.pilot_root.join("native/castalia-wallet-service"),"executable_sha256":p.wallet_command_sha256,
            "configuration":wallet_config,"configuration_sha256":hash(&read(&wallet_config,65536,0o600)?)},
        "result":{"executable":p.pilot_root.join("native/secs-frank-result"),"executable_sha256":p.result_command_sha256,
            "configuration":result_config,"configuration_sha256":hash(&read(&result_config,65536,0o600)?)},
        "verifier":{"executable":p.pilot_root.join("native/process-runtime-secs-check"),"sha256":p.verifier_sha256,"policy":result_policy}}),
    )?;
    // Final exact input check does not recapture authority or renew any window.
    for (name, h) in [
        ("castalia-wallet-service", &p.wallet_command_sha256),
        ("secs-frank-result", &p.result_command_sha256),
        ("process-runtime-secs-check", &p.verifier_sha256),
    ] {
        ok(hash(&read(
            &p.pilot_root.join("native").join(name),
            67108864,
            0o500,
        )?) == *h)?;
    }
    ok(hash(&read(path, 16384, 0o600)?) == expected_sha256
        && hash(&read(
            &p.pilot_root.join("config/review-composition.json"),
            65536,
            0o600,
        )?) == p.composition_sha256
        && hash(&read(
            &p.pilot_root.join("config/review-source-manifest.json"),
            16384,
            0o600,
        )?) == p.source_manifest_sha256)?;
    // Fresh actual Wallet observation is held through the COMPLETE export.
    // Clock is sampled only after the final potentially blocking source checks.
    let final_wallet = final_wallet(&wallet)?;
    ok(final_window(start, end, observed_floor, now()?))?;
    let receipt = json!({"schema":"castalia.wallet-local-review-setup-complete.v1","plan_sha256":expected_sha256,
        "root":p.pilot_root,"run_id":RUN,"holder":identity,"native_generation":pin_native.generation(),"native_sha256":hex(&pin_native.sha256()),
        "command_issuer":{"node_id":NODE,"key_id":COMMAND_KEY,"public_key_hex":hex(&command_public)},
        "result_party":{"subject_id":RESULT_SUBJECT,"key_id":RESULT_KEY,"public_key_hex":hex(&result_public)},
        "configuration_hashes":outputs,"assignment_sha256":hash(&assignment_raw),"not_before":start,"not_after":end,
        "scope":"one isolated pilot store; events/artifacts/receipts are explicitly store scoped",
        "activation":false,"service_started":false,"run_created":false});
    write(&base.join("COMPLETE.json"), &canonical(&receipt))?;
    final_wallet.revalidate().map_err(|_| SetupError)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests;
