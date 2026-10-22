//! Fixed-scope owner renewal. No issuer key access, signing, grants selected by callers,
//! business database access, history deletion or automatic new window on recovery.
use super::*;
use castalia_wallet_service_holder::custody::{
    PublicServiceIdentity, ServiceAdministrationSession,
};
use serde::{Deserialize, Serialize};
use server::service_owner_publication::{
    OriginalPhysicalRootIdentities, OriginalTerminalDisposition, OriginalTransitionSelection,
    OwnerStartupPin, RecoveryRelation, WalletExpectedCurrent, WalletTransitionIntent,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalError {
    Denied,
    RecoveryRequired,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Previous {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewalPlan {
    schema: String,
    workspace_root: PathBuf,
    previous_complete: Previous,
    not_before: String,
    not_after: String,
    wallet_command_sha256: String,
    verifier_sha256: String,
    #[serde(default)]
    actor_id: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    handoff_id: Option<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Original {
    schema: String,
    plan_sha256: String,
    native_device: u64,
    native_inode: u64,
    wallet_device: u64,
    wallet_inode: u64,
    native: Value,
    owner_input: Value,
    wallet_state: Value,
    startup: Value,
    target_policy: Value,
    next_owner_input: Value,
}
struct Selected {
    plan: RenewalPlan,
    old: Value,
    holder: PublicServiceIdentity,
    configs: BTreeMap<String, Value>,
    start: u64,
    end: u64,
    floor: u64,
    generation: u64,
    attempt: PathBuf,
    old_rules: Vec<Rule>,
    target_rules: Vec<Rule>,
    target_scope: &'static str,
}
const AUTHORING_SCOPE: &str =
    "five authoring/catalog operations in one isolated Runtime store; events are store scoped";
pub(super) const LIVE_PROVIDER_SCOPE: &str =
    "finite Frank Hermes pilot for one exact handoff, derived Run and Actor; authoring/catalog retained";

fn plan_target(p: &RenewalPlan) -> Result<(Vec<Rule>, &'static str)> {
    match p.schema.as_str() {
        "castalia.wallet-workspace-renewal.v1" => {
            ok(p.actor_id.is_none() && p.run_id.is_none() && p.handoff_id.is_none())?;
            Ok((rules(), AUTHORING_SCOPE))
        }
        "castalia.wallet-workspace-live-provider-authority.v1" => {
            let actor = p.actor_id.as_deref().ok_or(SetupError)?;
            let run = p.run_id.as_deref().ok_or(SetupError)?;
            let handoff = p.handoff_id.as_deref().ok_or(SetupError)?;
            Ok((
                live_provider_rules(actor, run, handoff)?,
                LIVE_PROVIDER_SCOPE,
            ))
        }
        _ => Err(SetupError),
    }
}

fn receipt_rules(old: &Value, p: &RenewalPlan) -> Result<Vec<Rule>> {
    match old["scope"].as_str().ok_or(SetupError)? {
        AUTHORING_SCOPE => Ok(rules()),
        LIVE_PROVIDER_SCOPE => {
            let actor = old["actor_id"].as_str().ok_or(SetupError)?;
            let run = old["run_id"].as_str().ok_or(SetupError)?;
            let handoff = old["handoff_id"].as_str().ok_or(SetupError)?;
            if p.schema == "castalia.wallet-workspace-live-provider-authority.v1" {
                // The actor identity is stable across the live-provider pilot, while
                // each bounded execution receives a fresh exact Run authority. The
                // old Run remains useful only for reconstructing the predecessor
                // policy and is never carried into the successor rule set.
                ok(p.actor_id.as_deref() == Some(actor))?;
            }
            live_provider_rules(actor, run, handoff)
        }
        _ => Err(SetupError),
    }
}
fn closed(v: &Value, fields: &[&str]) -> Result<()> {
    let m = v.as_object().ok_or(SetupError)?;
    ok(m.len() == fields.len() && fields.iter().all(|k| m.contains_key(*k)))
}
fn previously_begun(path: &Path, expected: &str) -> bool {
    (|| -> Result<bool> {
        let raw = read(path, 16384, 0o600)?;
        ok(hash(&raw) == expected)?;
        let p: RenewalPlan = parse(&raw, 16384)?;
        private_dir(&p.workspace_root)?;
        let raw = read(&p.previous_complete.path, 65536, 0o600)?;
        ok(hash(&raw) == p.previous_complete.sha256)?;
        let old: Value = parse(&raw, 65536)?;
        ok(old["root"] == json!(p.workspace_root))?;
        let generation = old["native_generation"].as_u64().ok_or(SetupError)?;
        let authority = p.workspace_root.join("authority");
        ok(p.previous_complete.path == authority.join("COMPLETE.json")
            || p.previous_complete.path
                == authority
                    .join("renewals")
                    .join(generation.to_string())
                    .join("COMPLETE.json"))?;
        let next = generation.checked_add(1).ok_or(SetupError)?;
        Ok(fs::symlink_metadata(authority.join("renewals").join(next.to_string())).is_ok())
    })()
    .unwrap_or(false)
}
fn digest(v: &Value) -> Result<[u8; 32]> {
    let s = v.as_str().ok_or(SetupError)?;
    ok(pin(s))?;
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| SetupError)?;
    }
    Ok(out)
}
pub(super) fn configuration_names() -> [&'static str; 4] {
    [
        "command-authority.json",
        "wallet-command.json",
        "runtime-policy.json",
        "runtime-receiver.json",
    ]
}
fn current_inputs(p: &RenewalPlan) -> Result<()> {
    for (name, expected) in [
        ("castalia-wallet-service", &p.wallet_command_sha256),
        ("process-runtime-secs-check", &p.verifier_sha256),
    ] {
        ok(pin(expected)
            && hash(&read(
                &p.workspace_root.join("native").join(name),
                67108864,
                0o500,
            )?) == *expected)?;
    }
    Ok(())
}
fn select(path: &Path, expected: &str) -> Result<Selected> {
    ok(pin(expected))?;
    let raw = read(path, 16384, 0o600)?;
    ok(hash(&raw) == expected)?;
    let p: RenewalPlan = parse(&raw, 16384)?;
    let (target_rules, target_scope) = plan_target(&p)?;
    for name in ["", "config", "data", "native", "authority"] {
        private_dir(&p.workspace_root.join(name))?;
    }
    current_inputs(&p)?;
    ok(pin(&p.previous_complete.sha256))?;
    let old_raw = read(&p.previous_complete.path, 65536, 0o600)?;
    ok(hash(&old_raw) == p.previous_complete.sha256)?;
    let old: Value = parse(&old_raw, 65536)?;
    ok(old["root"] == json!(p.workspace_root))?;
    let old_g = old["native_generation"].as_u64().ok_or(SetupError)?;
    let authority = p.workspace_root.join("authority");
    let original = p.previous_complete.path == authority.join("COMPLETE.json");
    let prior = p.previous_complete.path
        == authority
            .join("renewals")
            .join(old_g.to_string())
            .join("COMPLETE.json");
    ok(
        (original && old["schema"] == "castalia.wallet-workspace-setup-complete.v1")
            || (prior && old["schema"] == "castalia.wallet-workspace-renewal-complete.v1"),
    )?;
    for flag in [
        "activation",
        "service_started",
        "runtime_store_initialized",
        "process_created",
        "run_created",
    ] {
        ok(old[flag] == false)?;
    }
    ok(old["journal_capacity"] == "local_review_pilot_512")?;
    let mut fields = vec![
        "schema",
        "plan_sha256",
        "root",
        "holder",
        "native_generation",
        "native_sha256",
        "command_issuer",
        "configuration_hashes",
        "not_before",
        "not_after",
        "identity_not_after",
        "journal_capacity",
        "scope",
        "activation",
        "service_started",
        "runtime_store_initialized",
        "process_created",
        "run_created",
    ];
    if prior {
        fields.push("previous_complete");
    }
    if old["scope"] == LIVE_PROVIDER_SCOPE {
        fields.extend(["actor_id", "run_id", "handoff_id"]);
    }
    closed(&old, &fields)?;
    let old_rules = receipt_rules(&old, &p)?;
    // Once execution authority exists, a generic authoring renewal cannot
    // silently remove it. The exact live-provider profile must be selected.
    ok(old["scope"] != LIVE_PROVIDER_SCOPE || target_scope == LIVE_PROVIDER_SCOPE)?;
    closed(
        &old["command_issuer"],
        &["node_id", "key_id", "public_key_hex"],
    )?;
    let holder: PublicServiceIdentity =
        serde_json::from_value(old["holder"].clone()).map_err(|_| SetupError)?;
    ok(holder.subject_id == HOLDER
        && holder.application == Application::Runtime
        && holder.state == castalia_wallet_service_holder::custody::IdentityState::Active
        && old["identity_not_after"] == holder.not_after)?;
    let start = seconds(&p.not_before)?;
    let end = seconds(&p.not_after)?;
    let floor = now()?;
    ok(start > 0
        && start < end
        && start >= old["not_before"].as_u64().ok_or(SetupError)?
        && end > old["not_after"].as_u64().ok_or(SetupError)?
        && end - start <= MAX_WINDOW
        && holder.not_before <= start
        && end <= holder.not_after)?;
    let generation = old_g
        .checked_add(1)
        .filter(|g| *g <= 9_007_199_254_740_991)
        .ok_or(SetupError)?;
    ok(authority
        .join("renewals")
        .join(generation.to_string())
        .join("config/command-authority.json")
        .as_os_str()
        .as_bytes()
        .len()
        <= 1024)?;
    let config_dir = p
        .previous_complete
        .path
        .parent()
        .ok_or(SetupError)?
        .join("config");
    let hashes = old["configuration_hashes"].as_object().ok_or(SetupError)?;
    ok(hashes.len() == 4)?;
    let mut configs = BTreeMap::new();
    for name in configuration_names() {
        let raw = read(&config_dir.join(name), 65536, 0o600)?;
        ok(hash(&raw) == hashes[name].as_str().ok_or(SetupError)?)?;
        configs.insert(name.into(), parse(&raw, 65536)?);
    }
    let c = &configs["command-authority.json"];
    closed(
        c,
        &[
            "schema",
            "wallet_root",
            "wallet_observation_pin",
            "native_root",
            "native_generation",
            "native_sha256",
            "issuer_root",
            "issuer_node_id",
            "issuer_key_id",
            "issuer_public_key_hex",
            "journal_root",
            "maximum_ttl",
            "journal_capacity",
        ],
    )?;
    ok(c["schema"] == "secs.service-authority-configuration.v1")?;
    for (field, leaf) in [
        ("wallet_root", "wallet"),
        ("native_root", "native"),
        ("issuer_root", "command-issuer"),
        ("journal_root", "command-journal"),
    ] {
        ok(c[field] == json!(authority.join(leaf)))?;
    }
    ok(c["native_generation"] == old_g
        && c["native_sha256"] == old["native_sha256"]
        && c["issuer_node_id"] == NODE
        && c["issuer_key_id"] == COMMAND_KEY
        && c["issuer_public_key_hex"] == old["command_issuer"]["public_key_hex"]
        && old["command_issuer"]["node_id"] == NODE
        && old["command_issuer"]["key_id"] == COMMAND_KEY
        && c["maximum_ttl"] == 30
        && c["journal_capacity"] == "local_review_pilot_512")?;
    let w = &configs["wallet-command.json"];
    closed(
        w,
        &[
            "schema",
            "native_configuration",
            "native_configuration_sha256",
            "wallet_root",
            "application",
            "store_binding",
            "expected_state",
        ],
    )?;
    ok(w["schema"] == "castalia.wallet-service-command.v1")?;
    closed(
        &w["store_binding"],
        &[
            "store_id",
            "subject_id",
            "application",
            "purpose",
            "minimum_revision",
        ],
    )?;
    closed(&w["expected_state"], &["state_revision", "state_sha256"])?;
    ok(w["store_binding"]
        == json!({"store_id":holder.store_id,"subject_id":holder.subject_id,"application":"runtime","purpose":holder.purpose,"minimum_revision":holder.state_revision}))?;
    ok(
        w["native_configuration"] == json!(config_dir.join("command-authority.json"))
            && w["native_configuration_sha256"] == hashes["command-authority.json"]
            && w["wallet_root"] == json!(authority.join("wallet"))
            && w["application"] == "runtime"
            && w["expected_state"]["state_revision"] == holder.state_revision
            && w["expected_state"]["state_sha256"] == holder.expected().state_sha256,
    )?;
    ok(configs["runtime-receiver.json"]["native_verifier"]["sha256"] == p.verifier_sha256)?;
    Ok(Selected {
        attempt: authority.join("renewals").join(generation.to_string()),
        plan: p,
        old,
        holder,
        configs,
        start,
        end,
        floor,
        generation,
        old_rules,
        target_rules,
        target_scope,
    })
}
fn old_pin(s: &Selected) -> Result<OwnerStartupPin> {
    OwnerStartupPin::new(s.generation - 1, digest(&s.old["native_sha256"])?).map_err(|_| SetupError)
}
fn wallet_source(s: &Selected) -> Result<WalletCurrentSource> {
    WalletCurrentSource::open(
        OwnerSelectedWalletRoot::open(&s.plan.workspace_root.join("authority/wallet"))
            .map_err(|_| SetupError)?,
        StartupWalletObservationPin::parse_owner_configuration(&canonical(
            &s.configs["command-authority.json"]["wallet_observation_pin"],
        ))
        .map_err(|_| SetupError)?,
    )
    .map_err(|_| SetupError)
}
struct RuleDocuments {
    descriptors: Vec<Value>,
    receiver_descriptors: Vec<Value>,
    receiver_rules: Vec<Value>,
    native_permissions: Vec<Value>,
    runtime_descriptors: Vec<Value>,
    runtime_permissions: Vec<Value>,
}
fn rule_documents(rr: &[Rule], key_id: &str, start: u64, end: u64) -> Result<RuleDocuments> {
    let mut descriptors = Vec::new();
    let mut receiver_descriptors = Vec::new();
    let mut receiver_rules = Vec::new();
    let mut native_permissions = Vec::new();
    let mut runtime_descriptors = Vec::new();
    let mut runtime_permissions = Vec::new();
    for r in rr {
        let operation = format!("runtime.{}.v1", r.name);
        let handler = format!("process-runtime.v1:{}", r.name);
        let (descriptor, fingerprint) = descriptor(r.opcode, &operation, &handler)?;
        descriptors.push(descriptor);
        receiver_descriptors.push(json!({"operation":operation,"opcode":r.opcode,
            "fingerprint":fingerprint,"handler_id":handler,"max_ttl_seconds":60}));
        receiver_rules.push(json!({"subject_id":HOLDER,"key_id":key_id,
            "operation":operation,"resource":r.resource.as_str(),"resource_match":r.kind,
            "effect":"allow","active":true,"not_before":start,"not_after":end}));
        native_permissions.push(json!({"caller_id":HOLDER,"opcode":r.opcode,
            "operation":operation,"resource":if r.kind=="exact"{
                json!({"kind":"exact","value":r.resource.as_str()})
            }else{
                json!({"kind":"prefix","prefix":r.resource.as_str()})
            },"effect":"allow","not_before":start,"not_after":end,
            "status":"active","authority_source":"receiver_local"}));
        runtime_descriptors.push(json!({"operation":operation,"fingerprint":fingerprint,
            "handler_id":handler}));
        runtime_permissions.push(json!({"subject_id":HOLDER,"key_id":key_id,
            "operation":operation,"resource":r.resource.as_str(),"resource_match":r.kind,
            "effect":"allow","active":true,"not_before_ms":start*1000,"not_after_ms":end*1000}));
    }
    Ok(RuleDocuments {
        descriptors,
        receiver_descriptors,
        receiver_rules,
        native_permissions,
        runtime_descriptors,
        runtime_permissions,
    })
}

/// Validate the exact predecessor and derive either a same-scope renewal or the
/// one-handoff/one-Actor/one-derived-Run live-provider expansion. Identity, custody, replay history,
/// issuer key and every unrelated Runtime resource remain fixed.
fn derive(s: &Selected, native: &Value, owner: &Value) -> Result<(Value, Value)> {
    ok(native["schema"] == "secs.service-owner-bundle.v2"
        && native["generation"] == s.generation - 1
        && hash(&canonical(native)) == s.old["native_sha256"]
        && owner["holder"]["subject_id"] == HOLDER
        && owner["holder"]["key_id"] == s.holder.key_id
        && owner["holder"]["public_key_hex"] == s.holder.public_key_hex
        && owner["holder"]["generation"] == s.holder.key_generation
        && owner["holder"]["not_before"] == s.holder.not_before
        && owner["holder"]["not_after"] == s.holder.not_after
        && owner["valid_not_before"] == s.holder.not_before
        && owner["valid_until"] == s.holder.not_after
        && owner["application"] == "runtime"
        && owner["issuer_node_id"] == NODE
        && owner["selected_issuer_key_id"] == COMMAND_KEY
        && owner["generation"] == s.holder.state_revision
        && hash(&canonical(owner)) == s.holder.owner_input_sha256.clone().ok_or(SetupError)?)?;
    let old_start = s.old["not_before"].as_u64().ok_or(SetupError)?;
    let old_end = s.old["not_after"].as_u64().ok_or(SetupError)?;
    let old_documents = rule_documents(&s.old_rules, &s.holder.key_id, old_start, old_end)?;
    let receiver = json!({"schema":"secs.service-receiver-policy.v1","application":"runtime","audience":ServiceApplication::RuntimeV1.audience(),"not_before":old_start,"not_after":old_end,"max_ttl_seconds":60,"principals":[{"subject_id":HOLDER,"key_id":s.holder.key_id,"not_before":old_start,"not_after":old_end,"revoked":false}],"descriptors":old_documents.receiver_descriptors,"rules":old_documents.receiver_rules});
    ok(owner["descriptors"] == json!(old_documents.descriptors)
        && native["descriptors"] == owner["descriptors"]
        && owner["delegation_policy"] == receiver
        && native["receiver_policy"] == receiver
        && native["permissions"] == json!(old_documents.native_permissions)
        && native["valid_not_before"] == old_start
        && native["valid_until"] == old_end
        && native["application"] == "runtime"
        && native["issuer_node_id"] == NODE
        && native["selected_issuer_key_id"] == COMMAND_KEY
        && owner["issuers"].as_array().is_some_and(|v| v.len() == 1)
        && native["issuers"].as_array().is_some_and(|v| v.len() == 1))?;
    let expected_issuer = json!({"node_id":NODE,"key_id":COMMAND_KEY,"public_key_hex":s.old["command_issuer"]["public_key_hex"],"algorithm":"ed25519","status":"active","not_before":old_start,"not_after":old_end,"revoked_at":null,"replaced_by":null});
    ok(owner["issuers"][0] == expected_issuer)?;
    let mut ni = expected_issuer;
    ni["production_authority"] = json!(true);
    ok(native["issuers"][0] == ni)?;
    let mut expected_holder = owner["holder"].clone();
    expected_holder
        .as_object_mut()
        .ok_or(SetupError)?
        .remove("generation");
    expected_holder
        .as_object_mut()
        .ok_or(SetupError)?
        .remove("replaced_by");
    ok(native["holders"] == json!([expected_holder]))?;
    let rp = &s.configs["runtime-policy.json"];
    ok(
        *rp == json!({"schema":"runtime.receiver-policy.v1","audience":ServiceApplication::RuntimeV1.audience(),"keys":[public_key(COMMAND_KEY,s.old["command_issuer"]["public_key_hex"].as_str().ok_or(SetupError)?,old_start,old_end)],"descriptors":old_documents.runtime_descriptors,"permissions":old_documents.runtime_permissions,"revoked_subject_keys":[]})
    )?;
    let rc = &s.configs["runtime-receiver.json"];
    closed(
        rc,
        &["schema", "audience", "native_verifier", "policy_file"],
    )?;
    closed(&rc["native_verifier"], &["executable", "sha256"])?;
    ok(rc["native_verifier"]["sha256"] == s.plan.verifier_sha256)?;
    ok(rc["schema"] == "runtime.receiver-configuration.v1"
        && rc["audience"] == ServiceApplication::RuntimeV1.audience()
        && rc["native_verifier"]["executable"]
            == json!(s
                .plan
                .workspace_root
                .join("native/process-runtime-secs-check")))?;
    let mut next = owner.clone();
    next["generation"] = json!(s.holder.state_revision.checked_add(1).ok_or(SetupError)?);
    next["issuers"][0]["not_before"] = json!(s.start);
    next["issuers"][0]["not_after"] = json!(s.end);
    let next_documents = rule_documents(&s.target_rules, &s.holder.key_id, s.start, s.end)?;
    next["descriptors"] = json!(next_documents.descriptors);
    next["delegation_policy"] = json!({"schema":"secs.service-receiver-policy.v1",
        "application":"runtime","audience":ServiceApplication::RuntimeV1.audience(),
        "not_before":s.start,"not_after":s.end,"max_ttl_seconds":60,
        "principals":[{"subject_id":HOLDER,"key_id":s.holder.key_id,
            "not_before":s.start,"not_after":s.end,"revoked":false}],
        "descriptors":next_documents.receiver_descriptors,"rules":next_documents.receiver_rules});
    let mut policy = native.clone();
    let m = policy.as_object_mut().ok_or(SetupError)?;
    m.remove("generation");
    m.remove("wallet_current");
    policy["schema"] = json!("secs.wallet-native-target-policy.v1");
    policy["native_bundle_profile"] = json!("secs.service-owner-bundle.v2");
    policy["valid_not_before"] = json!(s.start);
    policy["valid_until"] = json!(s.end);
    policy["issuers"][0]["not_before"] = json!(s.start);
    policy["issuers"][0]["not_after"] = json!(s.end);
    policy["descriptors"] = next["descriptors"].clone();
    policy["receiver_policy"] = next["delegation_policy"].clone();
    policy["permissions"] = json!(next_documents.native_permissions);
    Ok((policy, next))
}
fn selection(s: &Selected, o: &Original) -> Result<OriginalTransitionSelection> {
    ok(o.schema == "castalia.wallet-workspace-renewal-original.v1")?;
    let (policy, next) = derive(s, &o.native, &o.owner_input)?;
    ok(policy == o.target_policy
        && next == o.next_owner_input
        && o.startup == s.configs["command-authority.json"]["wallet_observation_pin"])?;
    OriginalTransitionSelection::new(
        OriginalPhysicalRootIdentities::from_owner_configuration(
            o.native_device,
            o.native_inode,
            o.wallet_device,
            o.wallet_inode,
        ),
        old_pin(s)?,
        canonical(&o.native),
        canonical(&o.startup),
        canonical(&o.native["wallet_current"]),
        canonical(&o.wallet_state),
        WalletTransitionIntent::Configure {
            owner_input: canonical(&next),
        },
        canonical(&policy),
    )
    .map_err(|_| SetupError)
}
pub(super) fn same_key(a: &PublicServiceIdentity, b: &PublicServiceIdentity) -> bool {
    a.store_id == b.store_id
        && a.subject_id == b.subject_id
        && a.application == b.application
        && a.purpose == b.purpose
        && a.key_generation == b.key_generation
        && a.key_id == b.key_id
        && a.public_key_hex == b.public_key_hex
        && a.public_key_sha256 == b.public_key_sha256
        && a.not_before == b.not_before
        && a.not_after == b.not_after
        && a.state == b.state
}
fn original(
    s: &Selected,
    admin: &ServiceAdministrationSession<'_>,
    expected: &str,
) -> Result<Original> {
    let actual = admin.public_identity().map_err(|_| SetupError)?;
    ok(actual == s.holder)?;
    let view = admin.public_observation().map_err(|_| SetupError)?;
    let md = view.metadata();
    let state: Value = parse(md.state_bytes(), 4096)?;
    let owner: Value = parse(md.owner_input_bytes().ok_or(SetupError)?, 262144)?;
    let native: Value = parse(
        &read(
            &s.plan
                .workspace_root
                .join("authority/native/owner-generation.json"),
            262144,
            0o600,
        )?,
        262144,
    )?;
    let (policy, next) = derive(s, &native, &owner)?;
    let nm = fs::symlink_metadata(s.plan.workspace_root.join("authority/native"))
        .map_err(|_| SetupError)?;
    let wm = fs::symlink_metadata(s.plan.workspace_root.join("authority/wallet"))
        .map_err(|_| SetupError)?;
    view.revalidate().map_err(|_| SetupError)?;
    let o = Original {
        schema: "castalia.wallet-workspace-renewal-original.v1".into(),
        plan_sha256: expected.into(),
        native_device: nm.dev(),
        native_inode: nm.ino(),
        wallet_device: wm.dev(),
        wallet_inode: wm.ino(),
        native,
        owner_input: owner,
        wallet_state: state,
        startup: s.configs["command-authority.json"]["wallet_observation_pin"].clone(),
        target_policy: policy,
        next_owner_input: next,
    };
    selection(s, &o)?;
    Ok(o)
}
fn ensure_attempt(s: &Selected, expected: &str, o: &Original) -> Result<()> {
    let parent = s.attempt.parent().ok_or(SetupError)?;
    if fs::symlink_metadata(parent).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        create_dir(parent)?;
    }
    private_dir(parent)?;
    let mut count = 0;
    for entry in fs::read_dir(parent).map_err(|_| SetupError)? {
        let e = entry.map_err(|_| SetupError)?;
        count += 1;
        ok(count <= 64)?;
        let name = e.file_name();
        let name = name.to_str().ok_or(SetupError)?;
        ok(seconds(name).is_ok_and(|v| v > 1)
            && !e.file_type().map_err(|_| SetupError)?.is_symlink()
            && e.file_type().map_err(|_| SetupError)?.is_dir())?;
    }
    ok(count < 64)?;
    create_dir(&s.attempt)?;
    write(
        &s.attempt.join("INTENT.json"),
        &canonical(
            &json!({"schema":"castalia.wallet-workspace-renewal-intent.v1","plan_sha256":expected,"previous_complete":s.plan.previous_complete,"generation":s.generation,"not_before":s.start,"not_after":s.end,"failure_policy":"retain; explicit exact-plan resume only"}),
        ),
    )?;
    write(
        &s.attempt.join("ORIGINAL.json"),
        &serde_json::to_vec(o).map_err(|_| SetupError)?,
    )?;
    create_dir(&s.attempt.join("config"))
}
fn identical_or_new(path: &Path, raw: &[u8]) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => ok(read(path, 1048576, 0o600)? == raw),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => write(path, raw),
        Err(_) => Err(SetupError),
    }
}
fn finish(
    s: &Selected,
    o: &Original,
    source: &OwnerPublicationSource,
    wallet: &WalletCurrentSource,
    admin: &ServiceAdministrationSession<'_>,
    path: &Path,
    expected: &str,
) -> Result<Value> {
    let actual = admin.public_identity().map_err(|_| SetupError)?;
    ok(same_key(&s.holder, &actual)
        && actual.state_revision == s.holder.state_revision + 1
        && actual.previous_state_sha256 == Some(s.holder.expected().state_sha256)
        && actual.owner_input_sha256 == Some(hash(&canonical(&o.next_owner_input))))?;
    let inspection = source
        .begin_original_transition_inspection(wallet, selection(s, o)?)
        .map_err(|_| SetupError)?;
    let terminal = inspection
        .into_terminal_observer_retaining(admin.public_observation().map_err(|_| SetupError)?)
        .map_err(|_| SetupError)?;
    let observed = terminal
        .observe(admin.public_observation().map_err(|_| SetupError)?)
        .map_err(|_| SetupError)?;
    ok(
        observed.disposition() == OriginalTerminalDisposition::DerivedNewSource
            && observed.native_generation() == s.generation,
    )?;
    let startup: Value = parse(observed.wallet_startup_pin_bytes(), 16384)?;
    let dir = s.attempt.join("config");
    let mut outputs = BTreeMap::<String, String>::new();
    let mut c = s.configs["command-authority.json"].clone();
    c["native_generation"] = json!(s.generation);
    c["native_sha256"] = json!(hex(&observed.native_sha256()));
    c["wallet_observation_pin"] = startup;
    let mut w = s.configs["wallet-command.json"].clone();
    w["native_configuration"] = json!(dir.join("command-authority.json"));
    w["native_configuration_sha256"] = json!(hash(&canonical(&c)));
    let binding = actual.binding();
    let state = actual.expected();
    w["store_binding"] = json!({"store_id":binding.store_id,"subject_id":binding.subject_id,"application":"runtime","purpose":binding.purpose,"minimum_revision":binding.minimum_revision});
    w["expected_state"] =
        json!({"state_revision":state.state_revision,"state_sha256":state.state_sha256});
    let target_documents = rule_documents(&s.target_rules, &actual.key_id, s.start, s.end)?;
    let rp = json!({"schema":"runtime.receiver-policy.v1",
        "audience":ServiceApplication::RuntimeV1.audience(),
        "keys":[public_key(COMMAND_KEY,
            s.old["command_issuer"]["public_key_hex"].as_str().ok_or(SetupError)?,
            s.start,s.end)],
        "descriptors":target_documents.runtime_descriptors,
        "permissions":target_documents.runtime_permissions,
        "revoked_subject_keys":[]});
    let mut receiver = s.configs["runtime-receiver.json"].clone();
    receiver["policy_file"] = json!(dir.join("runtime-policy.json"));
    receiver["native_verifier"]["sha256"] = json!(s.plan.verifier_sha256);
    for (name, v) in [
        ("command-authority.json", c),
        ("wallet-command.json", w),
        ("runtime-policy.json", rp),
        ("runtime-receiver.json", receiver),
    ] {
        let raw = canonical(&v);
        identical_or_new(&dir.join(name), &raw)?;
        outputs.insert(name.into(), hash(&raw));
    }
    current_inputs(&s.plan)?;
    ok(hash(&read(path, 16384, 0o600)?) == expected)?;
    ok(hash(&read(&s.plan.previous_complete.path, 65536, 0o600)?)
        == s.plan.previous_complete.sha256)?;
    ok(final_window(s.start, s.end, s.floor, now()?))?;
    let again = terminal
        .observe(admin.public_observation().map_err(|_| SetupError)?)
        .map_err(|_| SetupError)?;
    ok(again.native_sha256() == observed.native_sha256()
        && again.wallet_reference_bytes() == observed.wallet_reference_bytes())?;
    let mut receipt = json!({"schema":"castalia.wallet-workspace-renewal-complete.v1","plan_sha256":expected,"root":s.plan.workspace_root,"previous_complete":s.plan.previous_complete,"holder":actual,"native_generation":s.generation,"native_sha256":hex(&observed.native_sha256()),"command_issuer":s.old["command_issuer"],"configuration_hashes":outputs,"not_before":s.start,"not_after":s.end,"identity_not_after":s.holder.not_after,"journal_capacity":"local_review_pilot_512","scope":s.target_scope,"activation":false,"service_started":false,"runtime_store_initialized":false,"process_created":false,"run_created":false});
    if s.target_scope == LIVE_PROVIDER_SCOPE {
        receipt["actor_id"] = json!(s.plan.actor_id.as_deref().ok_or(SetupError)?);
        receipt["run_id"] = json!(s.plan.run_id.as_deref().ok_or(SetupError)?);
        receipt["handoff_id"] = json!(s.plan.handoff_id.as_deref().ok_or(SetupError)?);
    }
    identical_or_new(&s.attempt.join("COMPLETE.json"), &canonical(&receipt))?;
    terminal
        .observe(admin.public_observation().map_err(|_| SetupError)?)
        .map_err(|_| SetupError)?;
    Ok(receipt)
}
fn resume_transition(
    s: &Selected,
    o: &Original,
    source: &OwnerPublicationSource,
    wallet: &WalletCurrentSource,
    admin: &mut ServiceAdministrationSession<'_>,
) -> Result<()> {
    let inspection = source
        .begin_original_transition_inspection(wallet, selection(s, o)?)
        .map_err(|_| SetupError)?;
    if inspection
        .candidate_transition_id()
        .map_err(|_| SetupError)?
        .is_none()
    {
        return Ok(());
    }
    // Native permits reconciliation only, never replay of the original Configure.
    // A prepared+old-Wallet state therefore stays explicitly recovery_required.
    // Frozen Wallet cannot expose the held physical root while poisoned. Do
    // not mutate it using a path check or infer a same-root reconciliation fence.
    let actual = admin.public_identity().map_err(|_| SetupError)?;
    ok(actual.state_revision == s.holder.state_revision + 1 && same_key(&s.holder, &actual))?;
    match inspection
        .into_full_recovery_retaining(admin.public_observation().map_err(|_| SetupError)?)
    {
        Ok(mut session) => {
            session
                .record_outcome_and_target(
                    admin.public_observation().map_err(|_| SetupError)?,
                    RecoveryRelation::IntendedOutcome,
                )
                .map_err(|_| SetupError)?;
            session
                .publish_recorded_target(admin.public_observation().map_err(|_| SetupError)?)
                .map_err(|_| SetupError)?;
            session
                .finalize_recorded_transition(admin.public_observation().map_err(|_| SetupError)?)
                .map_err(|_| SetupError)?;
        }
        Err(retained) => {
            let (_, inspection) = *retained;
            let mut completed = inspection
                .into_completed_cleanup_retaining(
                    admin.public_observation().map_err(|_| SetupError)?,
                )
                .map_err(|_| SetupError)?;
            completed
                .cleanup(admin.public_observation().map_err(|_| SetupError)?)
                .map_err(|_| SetupError)?;
        }
    }
    Ok(())
}
/// Retire only duplicate custody revisions after all Native/public completion
/// succeeded. The caller has released every administration/Native lease first.
/// Public transition records, configuration receipts and the journal are untouched.
fn cleanup_completed(
    store: &ServiceIdentityStore,
    s: &Selected,
    receipt: Value,
) -> std::result::Result<Value, RenewalError> {
    (|| -> Result<Value> {
        let identity: PublicServiceIdentity =
            serde_json::from_value(receipt["holder"].clone()).map_err(|_| SetupError)?;
        checkpoint("before_cleanup")?;
        store
            .cleanup_unreferenced(identity.expected())
            .map_err(|_| SetupError)?;
        ok(store.public_identity().map_err(|_| SetupError)? == identity)?;
        ok(final_window(s.start, s.end, s.floor, now()?))?;
        Ok(receipt)
    })()
    .map_err(|_| RenewalError::RecoveryRequired)
}
fn run(path: &Path, expected: &str, resume: bool) -> std::result::Result<Value, RenewalError> {
    let early = if resume || previously_begun(path, expected) {
        RenewalError::RecoveryRequired
    } else {
        RenewalError::Denied
    };
    let s = select(path, expected).map_err(|_| early)?;
    let begun = fs::symlink_metadata(&s.attempt).is_ok();
    if !final_window(s.start, s.end, s.floor, now().map_err(|_| early)?)
        || s.end > s.floor.checked_add(MAX_WINDOW).ok_or(early)?
    {
        return Err(if begun || resume {
            RenewalError::RecoveryRequired
        } else {
            RenewalError::Denied
        });
    }
    let store = ServiceIdentityStore::open(
        &s.plan.workspace_root.join("authority/wallet"),
        s.holder.binding(),
    )
    .map_err(|_| early)?;
    let wallet = wallet_source(&s).map_err(|_| early)?;
    let source = OwnerPublicationSource::open_owner_selected_root(
        &s.plan.workspace_root.join("authority/native"),
    )
    .map_err(|_| early)?;
    let mut admin = store.begin_administration().map_err(|_| early)?;
    if resume {
        let receipt = (|| {
            private_dir(&s.attempt)?;
            let intent: Value = parse(&read(&s.attempt.join("INTENT.json"), 16384, 0o600)?, 16384)?;
            ok(intent["plan_sha256"] == expected && intent["generation"] == s.generation)?;
            let o: Original = parse(
                &read(&s.attempt.join("ORIGINAL.json"), 262144, 0o600)?,
                262144,
            )?;
            ok(o.plan_sha256 == expected)?;
            selection(&s, &o)?;
            resume_transition(&s, &o, &source, &wallet, &mut admin)?;
            finish(&s, &o, &source, &wallet, &admin, path, expected)
        })()
        .map_err(|_| RenewalError::RecoveryRequired)?;
        drop(admin);
        return cleanup_completed(&store, &s, receipt);
    }
    absent(&s.attempt).map_err(|_| RenewalError::RecoveryRequired)?;
    let o = original(&s, &admin, expected).map_err(|_| RenewalError::Denied)?;
    ensure_attempt(&s, expected, &o).map_err(|_| RenewalError::RecoveryRequired)?;
    let receipt = (|| {
        checkpoint("intent")?;
        let mut session = source
            .begin_administration(
                old_pin(&s)?,
                &wallet,
                admin.public_observation().map_err(|_| SetupError)?,
            )
            .map_err(|_| SetupError)?;
        let raw = canonical(&o.next_owner_input);
        {
            let guard = session
                .prepare_wallet_transition(
                    admin.public_observation().map_err(|_| SetupError)?,
                    WalletTransitionIntent::Configure {
                        owner_input: raw.clone(),
                    },
                    &canonical(&o.target_policy),
                )
                .map_err(|_| SetupError)?;
            checkpoint("prepared")?;
            let expected_state = s.holder.expected();
            guard
                .authorize_configure(
                    admin.public_observation().map_err(|_| SetupError)?,
                    &WalletExpectedCurrent {
                        state_revision: expected_state.state_revision,
                        state_sha256: digest(&json!(expected_state.state_sha256))?,
                    },
                    &raw,
                )
                .map_err(|_| SetupError)?;
            admin
                .configure(s.holder.expected(), &raw)
                .map_err(|_| SetupError)?;
        }
        checkpoint("configured")?;
        session
            .record_outcome_and_target(
                admin.public_observation().map_err(|_| SetupError)?,
                RecoveryRelation::IntendedOutcome,
            )
            .map_err(|_| SetupError)?;
        session
            .publish_recorded_target(admin.public_observation().map_err(|_| SetupError)?)
            .map_err(|_| SetupError)?;
        checkpoint("published")?;
        session
            .finalize_recorded_transition(admin.public_observation().map_err(|_| SetupError)?)
            .map_err(|_| SetupError)?;
        drop(session);
        finish(&s, &o, &source, &wallet, &admin, path, expected)
    })()
    .map_err(|_| RenewalError::RecoveryRequired)?;
    drop(admin);
    cleanup_completed(&store, &s, receipt)
}
/// Requires the controller's stopped-workspace owner decision; these real
/// leases protect publication, not an attestation that every process is stopped.
pub fn renew_from_plan(path: &Path, expected: &str) -> std::result::Result<Value, RenewalError> {
    run(path, expected, false)
}
/// Same original inputs/window only. Never reapplies a lost Configure guard.
pub fn resume_renewal_from_plan(
    path: &Path,
    expected: &str,
) -> std::result::Result<Value, RenewalError> {
    run(path, expected, true)
}
#[cfg(test)]
thread_local! { pub(super) static STOP:std::cell::RefCell<Option<&'static str>>=const{std::cell::RefCell::new(None)}; }
fn checkpoint(_name: &str) -> Result<()> {
    #[cfg(test)]
    if STOP.with(|v| v.borrow().is_some_and(|n| n == _name)) {
        return Err(SetupError);
    }
    Ok(())
}
