//! Disposable actual public custody/issuer APIs. Public binary layout fixtures
//! are pinned but NEVER executed and do not qualify an installed executable.
use super::*;
use libsec_core::service_holder_proof::UntrustedSignedServiceChallenge;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    plan: PathBuf,
    pin: String,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().canonicalize().unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("Process-Workspace");
        create_dir(&root).unwrap();
        for leaf in ["config", "data", "native"] {
            create_dir(&root.join(leaf)).unwrap();
        }
        let public = b"PUBLIC NONEXECUTABLE SOURCE TEST FIXTURE; NEVER EXECUTED";
        for leaf in ["castalia-wallet-service", "process-runtime-secs-check"] {
            let p = root.join("native").join(leaf);
            write(&p, public).unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o500)).unwrap();
        }
        let n = now().unwrap();
        let raw = canonical(
            &json!({"schema":"castalia.wallet-workspace-setup.v1","workspace_root":root,
            "not_before":(n-30).to_string(),"not_after":(n+1800).to_string(),
            "identity_not_after":(n+86400).to_string(),
            "wallet_command_sha256":hash(public),"verifier_sha256":hash(public)}),
        );
        let plan = parent.join("workspace-plan.json");
        write(&plan, &raw).unwrap();
        Self {
            _temp: temp,
            root,
            plan,
            pin: hash(&raw),
        }
    }
    fn value(&self) -> Value {
        parse(&read(&self.plan, 16384, 0o600).unwrap(), 16384).unwrap()
    }
    fn replace(&mut self, value: Value) {
        fs::remove_file(&self.plan).unwrap();
        let raw = canonical(&value);
        write(&self.plan, &raw).unwrap();
        self.pin = hash(&raw);
    }
    fn setup(&self) -> Value {
        create_from_plan(&self.plan, &self.pin).unwrap()
    }
    fn configuration(&self, name: &str) -> Value {
        parse(
            &read(&self.root.join("authority/config").join(name), 65536, 0o600).unwrap(),
            65536,
        )
        .unwrap()
    }
    fn store(&self, receipt: &Value) -> ServiceIdentityStore {
        let identity: castalia_wallet_service_holder::custody::PublicServiceIdentity =
            serde_json::from_value(receipt["holder"].clone()).unwrap();
        ServiceIdentityStore::open(&self.root.join("authority/wallet"), identity.binding()).unwrap()
    }
    fn no_authority(&self) {
        assert!(!self.root.join("authority").exists());
    }
}
fn request(op: &str) -> Vec<u8> {
    let query = match op {
        "process.get" => Some(json!({"process_id":"my-new-process"})),
        "version.get" => Some(json!({"process_version":"my-new-version"})),
        "events.list" => Some(json!({"after":0,"limit":10})),
        "work.list" => Some(json!({"actor_id":"actor","limit":1})),
        "effect.get" => Some(json!({"effect_id":"effect"})),
        _ => None,
    };
    if let Some(payload) = query {
        return canonical(&json!({"schema":"runtime.query.v1","operation":op,"payload":payload}));
    }
    let (payload, expected) = match op {
        "process.draft.put" => (
            json!({"draft":{"schema":"process.draft.v1","process_id":"my-new-process","inputs":{},
            "steps":[{"step_id":"hello","depends_on":[],"capabilities":["custom.hello"],"resources":[],"inputs":{},"bindings":{},"outputs":{},"max_attempts":1}]},
            "provenance":{"source_id":"my-editor","media_type":"application/json","content_hash":"00".repeat(32),"parser":"explicit-json-v1","uncertainties":[]}}),
            Value::Null,
        ),
        "process.publish" => (
            json!({"process_id":"my-new-process","draft_revision":1,"version_id":"my-new-version"}),
            json!(1),
        ),
        "run.create" => (
            json!({"run_id":"run","pin":{"process_id":"my-new-process","process_version":"my-new-version","compilation_hash":"00".repeat(32)},"inputs":{}}),
            Value::Null,
        ),
        "actor.register" => (
            json!({"actor_id":"actor","capabilities":[],"resources":[]}),
            Value::Null,
        ),
        _ => panic!("closed fixture"),
    };
    let resource = if op.starts_with("process.") {
        "processes/my-new-process"
    } else if op == "run.create" {
        "runs/run"
    } else {
        "actors/actor"
    };
    canonical(
        &json!({"schema":"runtime.command.v1","operation":op,"request_id":format!("request-{}",op.replace('.', "-")),
        "resource":resource,"expected_version":expected,"payload":payload}),
    )
}

#[test]
fn workspace_scope_is_five_fixed_authoring_and_catalog_operations() {
    let r = rules();
    assert_eq!(r.len(), 5);
    assert_eq!(
        r.iter()
            .map(|r| (r.name, r.opcode, r.kind, r.resource))
            .collect::<Vec<_>>(),
        vec![
            ("process.draft.put", 0x40, "prefix", "processes/"),
            ("process.publish", 0x41, "prefix", "processes/"),
            ("process.get", 0x60, "prefix", "processes/"),
            ("version.get", 0x61, "prefix", "versions/"),
            ("events.list", 0x64, "exact", "events")
        ]
    );
}
#[test]
fn create_emits_four_pinned_existing_dtos_and_no_business_or_workflow_state() {
    let f = Fixture::new();
    let receipt = f.setup();
    assert_eq!(
        receipt["schema"],
        "castalia.wallet-workspace-setup-complete.v1"
    );
    assert_eq!(receipt["holder"]["subject_id"], HOLDER);
    assert_eq!(receipt["holder"]["state"], "active");
    let hashes = receipt["configuration_hashes"].as_object().unwrap();
    assert_eq!(hashes.len(), 4);
    for name in [
        "command-authority.json",
        "wallet-command.json",
        "runtime-policy.json",
        "runtime-receiver.json",
    ] {
        assert_eq!(
            hashes[name],
            hash(&read(&f.root.join("authority/config").join(name), 65536, 0o600).unwrap())
        );
    }
    assert!(fs::read_dir(f.root.join("data")).unwrap().next().is_none());
    for leaf in ["result-issuer", "result-journal", "assignment", "capture"] {
        assert!(!f.root.join("authority").join(leaf).exists());
    }
    for flag in [
        "activation",
        "service_started",
        "runtime_store_initialized",
        "process_created",
        "run_created",
    ] {
        assert_eq!(receipt[flag], false);
    }
    let native = f.configuration("command-authority.json");
    assert_eq!(native["maximum_ttl"], 30);
    assert_eq!(native["journal_capacity"], "local_review_pilot_512");
    assert_eq!(receipt["journal_capacity"], "local_review_pilot_512");
    let runtime = f.configuration("runtime-policy.json");
    assert_eq!(runtime["audience"], "runtime://receiver-local");
    assert_eq!(runtime["descriptors"].as_array().unwrap().len(), 5);
    assert_eq!(runtime["permissions"].as_array().unwrap().len(), 5);
    assert_eq!(runtime["keys"].as_array().unwrap().len(), 1);
    let receiver = f.configuration("runtime-receiver.json");
    assert_eq!(
        receiver["native_verifier"]["executable"],
        f.root
            .join("native/process-runtime-secs-check")
            .to_str()
            .unwrap()
    );
    assert_eq!(
        f.configuration("wallet-command.json")["native_configuration_sha256"],
        hashes["command-authority.json"]
    );
}
#[tokio::test(flavor = "current_thread")]
async fn actual_custody_authorizes_all_five_and_process_readback_is_fresh() {
    let f = Fixture::new();
    let receipt = f.setup();
    let store = f.store(&receipt);
    let identity = store.public_identity().unwrap();
    let holder = store.open_identity(identity.expected()).unwrap();
    let config = f.root.join("authority/config/command-authority.json");
    let authority = ServiceAuthority::open_pinned_owner_configuration(
        &config,
        hex_digest(&receipt["configuration_hashes"]["command-authority.json"]),
    )
    .await
    .unwrap();
    for r in rules() {
        let raw = request(r.name);
        let query = r.name.ends_with(".get") || r.name == "events.list";
        let bytes = if query {
            authority.acquire_query(&raw).await.unwrap()
        } else {
            authority.issue(&raw).await.unwrap()
        };
        let challenge = UntrustedSignedServiceChallenge::decode_inner(&bytes).unwrap();
        assert_eq!(challenge.claims.operation, format!("runtime.{}.v1", r.name));
        assert_eq!(challenge.request_bytes, raw);
        let proof = holder
            .present_current_service_challenge(&challenge)
            .unwrap();
        let done = if query {
            authority.complete_query(&raw, &proof).await.unwrap()
        } else {
            authority.complete(&raw, &proof).await.unwrap()
        };
        let packet: libsec_core::ZenithPacket = bincode::deserialize(&done.packet).unwrap();
        assert_eq!(packet.encrypted_payload, raw);
        assert_eq!(packet.opcode, r.opcode);
        let signed: server::verifier::SignedVerifiedCallContext =
            bincode::deserialize(&done.signed_context).unwrap();
        let public = ed25519_dalek::VerifyingKey::from_bytes(&hex_digest(
            &receipt["command_issuer"]["public_key_hex"],
        ))
        .unwrap();
        public
            .verify_strict(
                &bincode::serialize(&signed.context).unwrap(),
                &ed25519_dalek::Signature::from_slice(&signed.signature).unwrap(),
            )
            .unwrap();
        assert_eq!(
            signed.context.packet_hash,
            hex_digest(&json!(hash(&done.packet)))
        );
        assert_eq!(signed.context.operation, format!("runtime.{}.v1", r.name));
        assert_eq!(
            (signed.context.issued_at, signed.context.expires_at),
            (challenge.claims.issued_at, challenge.claims.expires_at)
        );
        if r.name == "process.get" {
            let again = UntrustedSignedServiceChallenge::decode_inner(
                &authority.acquire_query(&raw).await.unwrap(),
            )
            .unwrap();
            assert_ne!(again.claims.challenge_id, challenge.claims.challenge_id);
            assert_ne!(again.claims.session_id, challenge.claims.session_id);
            assert_ne!(again.claims.nonce, challenge.claims.nonce);
            assert_eq!(authority.complete_query(&raw, &proof).await.unwrap(), done);
        }
    }
    assert_eq!(store.public_identity().unwrap().key_id, identity.key_id);
    assert_eq!(
        store.public_identity().unwrap().expected(),
        identity.expected()
    );
}
fn hex_digest(v: &Value) -> [u8; 32] {
    let s = v.as_str().unwrap();
    std::array::from_fn(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
}
#[tokio::test(flavor = "current_thread")]
async fn execution_other_reads_service_and_run_scoped_events_remain_denied() {
    let f = Fixture::new();
    f.setup();
    let a = ServiceAuthority::open_owner_configuration(
        &f.root.join("authority/config/command-authority.json"),
    )
    .await
    .unwrap();
    // Own valid acquisition proves the selected Native sources are usable.
    a.acquire_query(&request("process.get")).await.unwrap();
    for op in ["run.create", "actor.register", "work.list", "effect.get"] {
        let raw = request(op);
        assert!(a.issue(&raw).await.is_err());
        assert!(a.acquire_query(&raw).await.is_err());
    }
    let events = canonical(
        &json!({"schema":"runtime.query.v1","operation":"events.list","payload":{"after":0,"limit":1,"run_id":"run"}}),
    );
    assert!(a.acquire_query(&events).await.is_err());
    let service = canonical(
        &json!({"schema":"service.query.v1","request_id":"q1","operation":"case.summary","resource":{"kind":"Case","id":"case"},"payload":{}}),
    );
    assert!(a.acquire_query(&service).await.is_err());
}
#[test]
fn existing_authority_is_retained_and_never_silently_rekeyed() {
    let f = Fixture::new();
    let first = f.setup();
    let old = read(&f.root.join("authority/COMPLETE.json"), 65536, 0o600).unwrap();
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    assert_eq!(
        read(&f.root.join("authority/COMPLETE.json"), 65536, 0o600).unwrap(),
        old
    );
    assert_eq!(
        f.store(&first).public_identity().unwrap().key_id,
        first["holder"]["key_id"].as_str().unwrap()
    );
}
#[test]
fn partial_authority_blocks_creation_without_cleanup() {
    let f = Fixture::new();
    create_dir(&f.root.join("authority")).unwrap();
    write(&f.root.join("authority/partial"), b"retain").unwrap();
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    assert_eq!(
        read(&f.root.join("authority/partial"), 16, 0o600).unwrap(),
        b"retain"
    );
    assert!(!f.root.join("authority/COMPLETE.json").exists());
}
#[test]
fn nonempty_business_data_is_rejected_before_custody() {
    let f = Fixture::new();
    write(&f.root.join("data/existing-store"), b"public fixture").unwrap();
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
}
#[test]
fn wrong_consumed_plan_pin_is_rejected_before_custody() {
    let f = Fixture::new();
    preflight(&read(&f.plan, 16384, 0o600).unwrap()).unwrap();
    assert!(create_from_plan(&f.plan, &"00".repeat(32)).is_err());
    f.no_authority();
}
#[test]
fn unsafe_plan_and_binary_modes_are_rejected_before_custody() {
    for which in ["plan", "binary"] {
        let f = Fixture::new();
        let p = if which == "plan" {
            f.plan.clone()
        } else {
            f.root.join("native/castalia-wallet-service")
        };
        fs::set_permissions(p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(create_from_plan(&f.plan, &f.pin).is_err());
        f.no_authority();
    }
}
#[test]
fn missing_or_substituted_public_binary_is_rejected_before_custody() {
    for missing in [true, false] {
        let f = Fixture::new();
        let p = f.root.join("native/castalia-wallet-service");
        fs::remove_file(&p).unwrap();
        if !missing {
            write(&p, b"different public binary").unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o500)).unwrap();
        }
        assert!(create_from_plan(&f.plan, &f.pin).is_err());
        f.no_authority();
    }
}
#[test]
fn closed_plan_rejects_workflow_fields_and_unsupported_metadata_numbers() {
    let mut f = Fixture::new();
    let mut v = f.value();
    v["run_id"] = json!("must-not-bootstrap");
    f.replace(v);
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
    for raw in [
        br#"{"schema":"a","schema":"b"}"#.as_slice(),
        br#"{"x":-0}"#,
        br#"{"x":1.0}"#,
        br#"{"x":1e2}"#,
        br#"{"$serde_json::private::Number":"1"}"#,
    ] {
        assert!(parse::<Value>(raw, 16384).is_err());
    }
}
#[test]
fn finite_window_expired_future_or_over_one_hour_denies_before_custody() {
    for kind in ["expired", "future", "long", "leading-zero"] {
        let mut f = Fixture::new();
        let mut p = f.value();
        let n = now().unwrap();
        match kind {
            "expired" => {
                p["not_before"] = json!((n - 3600).to_string());
                p["not_after"] = json!((n - 1).to_string());
            }
            "future" => {
                p["not_before"] = json!((n + 600).to_string());
            }
            "long" => {
                p["not_before"] = json!((n - 30).to_string());
                p["not_after"] = json!((n + 3600).to_string());
            }
            _ => {
                p["not_before"] = json!(format!("0{}", n - 30));
            }
        }
        f.replace(p);
        assert!(create_from_plan(&f.plan, &f.pin).is_err());
        f.no_authority();
    }
}
#[test]
fn final_time_is_exclusive_and_cannot_roll_back_before_observed_floor() {
    assert!(final_window(10, 30, 15, 15));
    for n in [0, 9, 14, 30, 31] {
        assert!(!final_window(10, 30, 15, n));
    }
}
#[tokio::test(flavor = "current_thread")]
async fn current_custody_revocation_denies_cached_delivery_and_new_queries() {
    let f = Fixture::new();
    let receipt = f.setup();
    let store = f.store(&receipt);
    let id = store.public_identity().unwrap();
    let holder = store.open_identity(id.expected()).unwrap();
    let a = ServiceAuthority::open_owner_configuration(
        &f.root.join("authority/config/command-authority.json"),
    )
    .await
    .unwrap();
    let raw = request("process.get");
    let c = UntrustedSignedServiceChallenge::decode_inner(&a.acquire_query(&raw).await.unwrap())
        .unwrap();
    let p = holder.present_current_service_challenge(&c).unwrap();
    a.complete_query(&raw, &p).await.unwrap();
    store.revoke(id.expected()).unwrap();
    assert!(a.complete_query(&raw, &p).await.is_err());
    assert!(a.acquire_query(&raw).await.is_err());
}
#[test]
fn late_public_input_change_retains_partial_state_without_complete() {
    let f = Fixture::new();
    let input = preflight(&read(&f.plan, 16384, 0o600).unwrap()).unwrap();
    let p = f.root.join("native/process-runtime-secs-check");
    fs::remove_file(&p).unwrap();
    write(&p, b"substituted public binary").unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(create_selected(&f.plan, &f.pin, input).is_err());
    assert!(f.root.join("authority/SETUP-BEGIN.json").exists());
    assert!(!f.root.join("authority/COMPLETE.json").exists());
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
}
#[test]
fn symlink_plan_or_workspace_root_is_rejected_before_custody() {
    let f = Fixture::new();
    let alias = f.plan.with_file_name("alias-plan.json");
    std::os::unix::fs::symlink(&f.plan, &alias).unwrap();
    assert!(create_from_plan(&alias, &f.pin).is_err());
    f.no_authority();
    let mut f = Fixture::new();
    let alias = f.root.with_file_name("alias-root");
    std::os::unix::fs::symlink(&f.root, &alias).unwrap();
    let mut p = f.value();
    p["workspace_root"] = json!(alias);
    f.replace(p);
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
}

#[test]
fn identity_lifetime_is_separate_from_policy_window() {
    let f = Fixture::new();
    let selected = f.value();
    let identity_end: u64 = selected["identity_not_after"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let policy_end: u64 = selected["not_after"].as_str().unwrap().parse().unwrap();
    assert!(identity_end > policy_end);
    let receipt = f.setup();
    assert_eq!(receipt["identity_not_after"], identity_end);
    assert_eq!(receipt["not_after"], policy_end);
    assert_eq!(receipt["holder"]["not_after"], identity_end);
    let root = ServiceRoot::open(&f.root.join("authority/wallet")).unwrap();
    let view = root.lock_public_shared().unwrap();
    let owner: Value = parse(view.metadata().owner_input_bytes().unwrap(), 262144).unwrap();
    assert_eq!(owner["valid_until"], identity_end);
    assert_eq!(owner["holder"]["not_after"], identity_end);
    assert_eq!(owner["issuers"][0]["not_after"], policy_end);
    assert_eq!(owner["delegation_policy"]["not_after"], policy_end);
    for principal in owner["delegation_policy"]["principals"].as_array().unwrap() {
        assert_eq!(principal["not_after"], policy_end);
    }
    for rule in owner["delegation_policy"]["rules"].as_array().unwrap() {
        assert_eq!(rule["not_after"], policy_end);
    }
    view.revalidate().unwrap();
    drop(view);
    let bundle: Value = parse(
        &read(
            &f.root.join("authority/native/owner-generation.json"),
            262144,
            0o600,
        )
        .unwrap(),
        262144,
    )
    .unwrap();
    assert_eq!(bundle["wallet_current"]["not_after"], identity_end);
    assert_eq!(bundle["holders"][0]["not_after"], identity_end);
    assert_eq!(bundle["valid_until"], policy_end);
    assert_eq!(bundle["issuers"][0]["not_after"], policy_end);
    assert_eq!(bundle["receiver_policy"], owner["delegation_policy"]);
    for rule in bundle["permissions"].as_array().unwrap() {
        assert_eq!(rule["not_after"], policy_end);
    }
    let runtime = f.configuration("runtime-policy.json");
    assert_eq!(runtime["keys"][0]["not_after"], policy_end);
    for rule in runtime["permissions"].as_array().unwrap() {
        assert_eq!(rule["not_after_ms"], policy_end * 1000);
    }
}

#[test]
fn identity_plan_is_required_and_bounded_before_custody() {
    // Each case starts from an independently valid complete owner plan.
    for kind in [
        "missing",
        "number",
        "leading-zero",
        "too-short",
        "beyond-year",
        "unsafe-integer",
        "overflow",
    ] {
        let mut f = Fixture::new();
        let mut p = f.value();
        preflight(&canonical(&p)).unwrap();
        let start: u64 = p["not_before"].as_str().unwrap().parse().unwrap();
        let end: u64 = p["not_after"].as_str().unwrap().parse().unwrap();
        match kind {
            "missing" => {
                p.as_object_mut().unwrap().remove("identity_not_after");
            }
            "number" => p["identity_not_after"] = json!(end + 1),
            "leading-zero" => p["identity_not_after"] = json!(format!("0{}", end + 1)),
            "too-short" => p["identity_not_after"] = json!((end - 1).to_string()),
            "beyond-year" => p["identity_not_after"] = json!((start + 31_536_001).to_string()),
            "unsafe-integer" => p["identity_not_after"] = json!("9007199254740992"),
            _ => p["identity_not_after"] = json!("18446744073709551615"),
        }
        f.replace(p);
        assert_eq!(create_from_plan(&f.plan, &f.pin), Err(SetupError), "{kind}");
        f.no_authority();
    }
}

#[test]
fn identity_year_ceiling_and_policy_end_equality_are_explicitly_valid() {
    for at_year_ceiling in [true, false] {
        let mut f = Fixture::new();
        let mut p = f.value();
        let start: u64 = p["not_before"].as_str().unwrap().parse().unwrap();
        p["identity_not_after"] = if at_year_ceiling {
            json!((start + 31_536_000).to_string())
        } else {
            p["not_after"].clone()
        };
        f.replace(p);
        preflight(&read(&f.plan, 16384, 0o600).unwrap()).unwrap();
        f.no_authority();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn stable_identity_can_be_configured_after_policy_expiry_without_extending_grants() {
    let mut f = Fixture::new();
    let mut plan = f.value();
    let end = now().unwrap() + 30;
    plan["not_after"] = json!(end.to_string());
    f.replace(plan);
    let receipt = f.setup();
    let store = f.store(&receipt);
    let before = store.public_identity().unwrap();
    let holder = store.open_identity(before.expected()).unwrap();
    let a = ServiceAuthority::open_owner_configuration(
        &f.root.join("authority/config/command-authority.json"),
    )
    .await
    .unwrap();
    let raw = request("process.get");
    let challenge =
        UntrustedSignedServiceChallenge::decode_inner(&a.acquire_query(&raw).await.unwrap())
            .unwrap();
    let proof = holder
        .present_current_service_challenge(&challenge)
        .unwrap();
    a.complete_query(&raw, &proof).await.unwrap();
    assert!(challenge.claims.expires_at <= end);
    let public_root = ServiceRoot::open(&f.root.join("authority/wallet")).unwrap();
    let old_owner: Value = {
        let view = public_root.lock_public_shared().unwrap();
        parse(view.metadata().owner_input_bytes().unwrap(), 262144).unwrap()
    };
    let config = f.configuration("command-authority.json");
    let wallet = WalletCurrentSource::open(
        OwnerSelectedWalletRoot::open(&f.root.join("authority/wallet")).unwrap(),
        StartupWalletObservationPin::parse_owner_configuration(&canonical(
            &config["wallet_observation_pin"],
        ))
        .unwrap(),
    )
    .unwrap();
    // This waits only for a disposable short policy; no caller clock controls
    // production authorization. Deadline is finite and uses a monotonic timer.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(35);
    while now().unwrap() < end {
        assert!(
            std::time::Instant::now() < deadline,
            "OS clock did not reach policy expiry"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(now().unwrap() < before.not_after);
    assert_eq!(store.public_identity().unwrap(), before);
    store.open_identity(before.expected()).unwrap();
    assert!(a.acquire_query(&raw).await.is_err());
    assert!(a.complete_query(&raw, &proof).await.is_err());
    wallet.capture_shared().unwrap().revalidate().unwrap();
    // Expired grants do not prevent owner administration on the still-live
    // identity. Beginning administration alone publishes no new grant.
    let native =
        OwnerPublicationSource::open_owner_selected_root(&f.root.join("authority/native")).unwrap();
    {
        let administration = store.begin_administration().unwrap();
        let observed = administration.public_observation().unwrap();
        let session = native
            .begin_administration(
                server::service_owner_publication::OwnerStartupPin::new(
                    receipt["native_generation"].as_u64().unwrap(),
                    hex_digest(&receipt["native_sha256"]),
                )
                .unwrap(),
                &wallet,
                observed,
            )
            .unwrap();
        drop(session);
    }
    // Explicit configure keeps the SAME expired issuer/delegation windows.
    // It is a custody configuration test, not coupled policy renewal.
    let mut next_owner = old_owner.clone();
    next_owner["generation"] = json!(before.state_revision + 1);
    let after = store
        .configure(before.expected(), &canonical(&next_owner))
        .unwrap();
    assert_eq!(after.subject_id, before.subject_id);
    assert_eq!(after.key_id, before.key_id);
    assert_eq!(after.public_key_hex, before.public_key_hex);
    assert_eq!(after.key_generation, before.key_generation);
    assert_eq!(after.not_before, before.not_before);
    assert_eq!(after.not_after, before.not_after);
    assert_eq!(after.state_revision, before.state_revision + 1);
    let view = public_root.lock_public_shared().unwrap();
    let configured: Value = parse(view.metadata().owner_input_bytes().unwrap(), 262144).unwrap();
    assert_eq!(
        configured["delegation_policy"],
        old_owner["delegation_policy"]
    );
    assert_eq!(configured["issuers"], old_owner["issuers"]);
    assert_eq!(configured["holder"], old_owner["holder"]);
    view.revalidate().unwrap();
    drop(view);
    // Neither the old Native CAS nor expired evidence is silently renewed.
    assert!(a.acquire_query(&raw).await.is_err());
    assert!(a.complete_query(&raw, &proof).await.is_err());
}
