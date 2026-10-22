//! Create-only empty workspace authority. No process/run/result bootstrap or signing port.
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

pub const HOLDER: &str = "service:frank-workspace";
const NODE: &str = "node:workspace-command-issuer";
const COMMAND_KEY: &str = "issuer:workspace-command-v1";
const MAX_WINDOW: u64 = 3600;
const MAX_IDENTITY_LIFETIME: u64 = 31_536_000;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupError;
impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("workspace owner setup denied; partial state retained")
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
    workspace_root: PathBuf,
    not_before: String,
    not_after: String,
    identity_not_after: String,
    wallet_command_sha256: String,
    verifier_sha256: String,
}
struct Input {
    p: Plan,
    start: u64,
    end: u64,
    identity_end: u64,
    observed_floor: u64,
}
fn seconds(s: &str) -> Result<u64> {
    ok(!s.is_empty()
        && s.len() <= 16
        && s.bytes().all(|b| b.is_ascii_digit())
        && (!s.starts_with('0') || s == "0"))?;
    s.parse().map_err(|_| SetupError)
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
fn absent(p: &Path) -> Result<()> {
    ok(fs::symlink_metadata(p).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound))
}
fn empty_data(root: &Path) -> Result<()> {
    private_dir(&root.join("data"))?;
    // The actual Runtime owns schema creation. Never open/copy/edit its database.
    ok(fs::read_dir(root.join("data"))
        .map_err(|_| SetupError)?
        .next()
        .is_none())
}
fn binaries(p: &Plan) -> Result<()> {
    for (name, h) in [
        ("castalia-wallet-service", &p.wallet_command_sha256),
        ("process-runtime-secs-check", &p.verifier_sha256),
    ] {
        ok(hash(&read(
            &p.workspace_root.join("native").join(name),
            67108864,
            0o500,
        )?) == *h)?;
    }
    Ok(())
}
fn preflight(raw: &[u8]) -> Result<Input> {
    let p: Plan = parse(raw, 16384)?;
    ok(p.schema == "castalia.wallet-workspace-setup.v1")?;
    private_dir(&p.workspace_root)?;
    private_dir(&p.workspace_root.join("config"))?;
    private_dir(&p.workspace_root.join("native"))?;
    empty_data(&p.workspace_root)?;
    // The generated Wallet command source selection has an existing1024-byte path limit.
    ok(p.workspace_root
        .join("authority/config/command-authority.json")
        .as_os_str()
        .as_bytes()
        .len()
        <= 1024)?;
    absent(&p.workspace_root.join("authority"))?;
    let (start, end) = (seconds(&p.not_before)?, seconds(&p.not_after)?);
    let identity_end = seconds(&p.identity_not_after)?;
    let n = now()?;
    ok(start > 0
        && start <= n
        && n < end
        && end <= n.checked_add(MAX_WINDOW).ok_or(SetupError)?
        && end - start <= MAX_WINDOW
        && end <= identity_end
        && identity_end <= start.checked_add(MAX_IDENTITY_LIFETIME).ok_or(SetupError)?
        && identity_end <= 9_007_199_254_740_991
        && pin(&p.wallet_command_sha256)
        && pin(&p.verifier_sha256))?;
    binaries(&p)?;
    Ok(Input {
        p,
        start,
        end,
        identity_end,
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
    [
        ("process.draft.put", 0x40, "prefix", "processes/"),
        ("process.publish", 0x41, "prefix", "processes/"),
        ("process.get", 0x60, "prefix", "processes/"),
        ("version.get", 0x61, "prefix", "versions/"),
        // Honest isolated-store observation; no nonexistent process/run filter.
        ("events.list", 0x64, "exact", "events"),
    ]
    .into_iter()
    .map(|(name, opcode, kind, resource)| Rule {
        name,
        opcode,
        kind,
        resource: resource.into(),
    })
    .collect()
}
fn runtime_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}
/// The first live-provider profile preserves the authoring/catalog surface and
/// adds only one Actor and one Run. Step/Attempt resources remain descendants
/// of that exact Run. The isolated store's content-addressed artifact and
/// receipt namespaces are available because real workflow inputs, outputs and
/// verification receipts cannot be materialized without them.
fn live_provider_rules(actor_id: &str, run_id: &str) -> Result<Vec<Rule>> {
    ok(runtime_id(actor_id) && runtime_id(run_id))?;
    let mut result = rules();
    let actor = format!("actors/{actor_id}");
    let run = format!("runs/{run_id}");
    let steps = format!("{run}/steps/");
    for (name, opcode, kind, resource) in [
        ("run.create", 0x42, "exact", run.clone()),
        ("run.get", 0x62, "exact", run),
        ("actor.register", 0x46, "exact", actor.clone()),
        ("work.list", 0x63, "exact", format!("{actor}/work")),
        ("artifact.put", 0x45, "prefix", "artifacts/".into()),
        ("artifact.get", 0x65, "prefix", "artifacts/".into()),
        ("receipt.get", 0x66, "prefix", "receipts/".into()),
        ("executor.claim", 0x48, "prefix", steps.clone()),
        ("executor.heartbeat", 0x49, "prefix", steps.clone()),
        ("executor.complete", 0x4A, "prefix", steps.clone()),
        ("executor.fail", 0x4B, "prefix", steps.clone()),
        ("executor.release", 0x4C, "prefix", steps.clone()),
        ("executor.effect.intent", 0x4E, "prefix", steps.clone()),
        ("executor.effect.dispatch", 0x4F, "prefix", steps.clone()),
        ("executor.effect.observe", 0x50, "prefix", steps.clone()),
        ("output.get", 0x67, "prefix", steps.clone()),
        ("attempt.get", 0x69, "prefix", steps),
    ] {
        result.push(Rule {
            name,
            opcode,
            kind,
            resource,
        });
    }
    Ok(result)
}
fn descriptor(opcode: u8, name: &str, handler: &str) -> Result<(Value, String)> {
    let credential: Vec<&str> = vec![];
    let capability: Vec<&str> = vec![];
    let evidence: Vec<&str> = vec![];
    let policy = "runtime.workspace-receipt.v1";
    let payload = "application/json";
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
/// The SAME bounded private owner-plan read is pinned before parsing or custody.
/// All returned key material is public; partial state is never reset or rekeyed.
pub fn create_from_plan(path: &Path, expected_sha256: &str) -> Result<Value> {
    ok(pin(expected_sha256))?;
    let raw = read(path, 16384, 0o600)?;
    ok(hash(&raw) == expected_sha256)?;
    let input = preflight(&raw)?;
    create_selected(path, expected_sha256, input)
}
fn create_selected(path: &Path, expected_sha256: &str, input: Input) -> Result<Value> {
    let p = input.p;
    let (start, end, identity_end, observed_floor) = (
        input.start,
        input.end,
        input.identity_end,
        input.observed_floor,
    );
    let base = p.workspace_root.join("authority");
    create_dir(&base)?;
    write(
        &base.join("SETUP-BEGIN.json"),
        &canonical(&json!({
        "schema":"castalia.wallet-workspace-setup-intent.v1","plan_sha256":expected_sha256,
        "started_at":now()?,"failure_policy":"retain; no automatic retry/rekey"})),
    )?;
    for d in [
        "wallet",
        "command-issuer",
        "native",
        "command-journal",
        "config",
    ] {
        create_dir(&base.join(d))?;
    }
    let command_public = ServiceAuthority::create_issuer_key(&base.join("command-issuer"))
        .map_err(|_| SetupError)?;
    let store = ServiceIdentityStore::create(
        &base.join("wallet"),
        NewServiceIdentity {
            application: Application::Runtime,
            subject_id: HOLDER.into(),
            not_before: start,
            not_after: identity_end,
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
            let (d, h) = descriptor(r.opcode, &name, &handler)?;
            descriptors.push(d);
            receiver_descriptors.push(json!({"operation":name,"opcode":r.opcode,"fingerprint":h,"handler_id":handler,"max_ttl_seconds":60}));
        }
    }
    ok(unique.len() == 5)?;
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
        "generation":initial.key_generation,"algorithm":"ed25519","status":"active","not_before":start,"not_after":identity_end,
        "revoked_at":null,"replaced_by":null});
    let owner = json!({"schema":"castalia.wallet-service-owner-input.v1","generation":initial.state_revision+1,
        "valid_not_before":start,"valid_until":identity_end,"application":"runtime","issuer_node_id":NODE,"selected_issuer_key_id":COMMAND_KEY,
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
    save(
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
        "native_verifier":{"executable":p.workspace_root.join("native/process-runtime-secs-check"),"sha256":p.verifier_sha256},"policy_file":runtime_policy}),
    )?;
    // No process, actor, run, result issuer, assignment or capture exists here.
    // Recheck exact inputs and current Wallet after the last blocking input read.
    binaries(&p)?;
    ok(hash(&read(path, 16384, 0o600)?) == expected_sha256)?;
    empty_data(&p.workspace_root)?;
    let held = final_wallet(&wallet)?;
    ok(final_window(start, end, observed_floor, now()?))?;
    let receipt = json!({"schema":"castalia.wallet-workspace-setup-complete.v1",
        "plan_sha256":expected_sha256,"root":p.workspace_root,"holder":identity,
        "native_generation":pin_native.generation(),"native_sha256":hex(&pin_native.sha256()),
        "command_issuer":{"node_id":NODE,"key_id":COMMAND_KEY,"public_key_hex":hex(&command_public)},
        "configuration_hashes":outputs,"not_before":start,"not_after":end,"identity_not_after":identity_end,
        "journal_capacity":"local_review_pilot_512",
        "scope":"five authoring/catalog operations in one isolated Runtime store; events are store scoped",
        "activation":false,"service_started":false,"runtime_store_initialized":false,
        "process_created":false,"run_created":false});
    write(&base.join("COMPLETE.json"), &canonical(&receipt))?;
    held.revalidate().map_err(|_| SetupError)?;
    Ok(receipt)
}
mod renewal;
pub use renewal::{renew_from_plan, resume_renewal_from_plan, RenewalError};
#[cfg(test)]
mod tests;
