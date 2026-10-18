//! Disposable owner API controls; fake public executable bytes are NEVER run.
use super::*;
use castalia_wallet_service_holder::custody::ServiceIdentityStore;
use libsec_core::service_holder_proof::UntrustedSignedServiceChallenge;
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    plan: PathBuf,
    pin: String,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        fs::set_permissions(&base, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        private_dir(&base).unwrap();
        let root = base.join("Process-Pilot");
        create_dir(&root).unwrap();
        for d in ["config", "data", "native", "inputs"] {
            create_dir(&root.join(d)).unwrap();
        }
        create_dir(&root.join("inputs/source-blobs")).unwrap();
        let mut caps: Vec<_> = OPERATIONS.into_iter().chain(LEGACY).collect();
        caps.sort();
        let producer = b"public producer source fixture never executed";
        let normalizer = b"public normalizer source fixture never executed";
        let value = json!({"schema":"frank.local-review.composition.v1","runtime_endpoint":"http://127.0.0.1:8192",
            "journal":root.join("data/frank.db"),"capture_root":root.join("data/capture"),
            "actor":{"actor_id":ACTOR,"integration_id":INTEGRATION,"route":ROUTE,"capabilities":caps,"resources":RESOURCES},
            "run_ids":[RUN],"producer_artifact_sha256":hash(producer),"normalizer_sha256":hash(normalizer),
            "transcript":{"audio_sha256":hash(b"actual selected audio placeholder only"),
                "artifact":{"content_hash":hash(b"transcript"),"byte_length":10,"media_type":"application/json"}},
            "snapshots":{}});
        let cr = canonical(&value);
        write(&root.join("config/review-composition.json"), &cr).unwrap();
        let mut entries = Vec::new();
        for blob in [producer.as_slice(), normalizer.as_slice(), cr.as_slice()] {
            write(&root.join("inputs/source-blobs").join(hash(blob)), blob).unwrap();
            entries.push(json!({"sha256":hash(blob),"byte_length":blob.len()}));
        }
        let mr = canonical(
            &json!({"schema":"frank.local-review.source-manifest.v1","producer_artifact_sha256":hash(producer),
            "normalizer_sha256":hash(normalizer),"configuration_sha256":hash(&cr),"entries":entries}),
        );
        write(&root.join("config/review-source-manifest.json"), &mr).unwrap();
        let native_bytes = b"PUBLIC NONEXECUTABLE BINARY LAYOUT FIXTURE";
        for name in [
            "castalia-wallet-service",
            "secs-frank-result",
            "process-runtime-secs-check",
        ] {
            let target = root.join("native").join(name);
            write(&target, native_bytes).unwrap();
            fs::set_permissions(&target, std::os::unix::fs::PermissionsExt::from_mode(0o500))
                .unwrap();
        }
        let n = now().unwrap();
        let plan = base.join("owner-plan.json");
        let raw = canonical(
            &json!({"schema":"castalia.wallet-local-review-setup.v1","pilot_root":root,
            "not_before":(n-30).to_string(),"not_after":(n+1800).to_string(),"result_opcode":"e0",
            "composition_sha256":hash(&cr),"source_manifest_sha256":hash(&mr),"wallet_command_sha256":hash(native_bytes),
            "result_command_sha256":hash(native_bytes),"verifier_sha256":hash(native_bytes)}),
        );
        write(&plan, &raw).unwrap();
        Self {
            _temp: temp,
            root,
            plan,
            pin: hash(&raw),
        }
    }
    fn plan_value(&self) -> Value {
        parse(&read(&self.plan, 16384, 0o600).unwrap(), 16384).unwrap()
    }
    fn replace_plan(&mut self, v: Value) {
        fs::remove_file(&self.plan).unwrap();
        let raw = canonical(&v);
        write(&self.plan, &raw).unwrap();
        self.pin = hash(&raw);
    }
    fn replace_composition(&mut self, changed: Value) {
        let plan = self.plan_value();
        let old = read(
            &self.root.join("config/review-composition.json"),
            65536,
            0o600,
        )
        .unwrap();
        let old_hash = hash(&old);
        let raw = canonical(&changed);
        let h = hash(&raw);
        fs::remove_file(self.root.join("config/review-composition.json")).unwrap();
        write(&self.root.join("config/review-composition.json"), &raw).unwrap();
        write(&self.root.join("inputs/source-blobs").join(&h), &raw).unwrap();
        let mp = self.root.join("config/review-source-manifest.json");
        let mut m: Value = parse(&read(&mp, 16384, 0o600).unwrap(), 16384).unwrap();
        m["configuration_sha256"] = json!(h);
        let rows = m["entries"].as_array_mut().unwrap();
        let row = rows
            .iter_mut()
            .find(|row| row["sha256"] == old_hash)
            .unwrap();
        *row = json!({"sha256":h,"byte_length":raw.len()});
        fs::remove_file(&mp).unwrap();
        let mr = canonical(&m);
        write(&mp, &mr).unwrap();
        let mut plan = plan;
        plan["composition_sha256"] = json!(h);
        plan["source_manifest_sha256"] = json!(hash(&mr));
        self.replace_plan(plan);
    }
    fn valid(&self) {
        preflight(&read(&self.plan, 16384, 0o600).unwrap()).unwrap();
    }
    fn no_authority(&self) {
        assert!(!self.root.join("authority").exists());
    }
}
#[test]
fn closed_scope_has_only_21_runtime_ops_and_honest_global_store_events() {
    let rr = rules();
    assert_eq!(
        rr.iter().map(|r| r.opcode).collect::<BTreeSet<_>>().len(),
        21
    );
    assert_eq!(rr.len(), 101);
    assert!(rr
        .iter()
        .any(|r| r.name == "events.list" && r.resource == "events" && r.kind == "exact"));
    assert!(rr
        .iter()
        .filter(|r| r.kind == "prefix")
        .all(|r| r.resource == "artifacts/"
            || r.resource == "receipts/"
            || (r.resource.starts_with(&format!("runs/{RUN}/steps/"))
                && r.resource.ends_with("/attempts/"))));
    assert!(!rr
        .iter()
        .any(|r| ["process.get", "effect.get", "run.retry", "handoff.consume"].contains(&r.name)));
}
#[tokio::test]
async fn actual_owner_creation_and_wallet_native_query_roundtrip() {
    let f = Fixture::new();
    f.valid();
    let receipt = create_from_plan(&f.plan, &f.pin).unwrap();
    let a = f.root.join("authority");
    assert!(a.join("SETUP-BEGIN.json").is_file());
    assert!(a.join("COMPLETE.json").is_file());
    assert_ne!(
        receipt["command_issuer"]["public_key_hex"],
        receipt["result_party"]["public_key_hex"]
    );
    assert_ne!(
        receipt["holder"]["public_key_hex"],
        receipt["command_issuer"]["public_key_hex"]
    );
    assert_eq!(receipt["activation"], false);
    assert_eq!(receipt["run_created"], false);
    let configuration = a.join("config/command-authority.json");
    let cfg = read(&configuration, 65536, 0o600).unwrap();
    let bytes: [u8; 32] = Sha256::digest(&cfg).into();
    let authority = ServiceAuthority::open_pinned_owner_configuration(&configuration, bytes)
        .await
        .unwrap();
    let request = canonical(
        &json!({"schema":"runtime.query.v1","operation":"run.get","payload":{"run_id":RUN}}),
    );
    let challenge = authority.acquire_query(&request).await.unwrap();
    let challenge = UntrustedSignedServiceChallenge::decode_inner(&challenge).unwrap();
    let identity: castalia_wallet_service_holder::custody::PublicServiceIdentity =
        serde_json::from_value(receipt["holder"].clone()).unwrap();
    let store = ServiceIdentityStore::open(&a.join("wallet"), identity.binding()).unwrap();
    let holder = store.open_identity(identity.expected()).unwrap();
    let proof = holder
        .present_current_service_challenge(&challenge)
        .unwrap();
    let completed = authority.complete_query(&request, &proof).await.unwrap();
    assert!(!completed.packet.is_empty());
    assert!(!completed.signed_context.is_empty());
    let master: Value = parse(
        &read(&a.join("config/frank-local-review.json"), 65536, 0o600).unwrap(),
        65536,
    )
    .unwrap();
    assert_eq!(
        master["composition"]["sha256"],
        f.plan_value()["composition_sha256"]
    );
    assert_eq!(
        master["source_manifest_sha256"],
        f.plan_value()["source_manifest_sha256"]
    );
    assert!(f.root.join("data/capture/capture.lock").is_file());
}
#[test]
fn duplicate_create_preserves_exact_complete_and_public_identity() {
    let f = Fixture::new();
    let receipt = create_from_plan(&f.plan, &f.pin).unwrap();
    let file = f.root.join("authority/COMPLETE.json");
    let original = read(&file, 262144, 0o600).unwrap();
    assert_eq!(create_from_plan(&f.plan, &f.pin), Err(SetupError));
    assert_eq!(read(&file, 262144, 0o600).unwrap(), original);
    assert_eq!(parse::<Value>(&original, 262144).unwrap(), receipt);
}
#[test]
fn wrong_same_read_plan_pin_denies_before_store() {
    let f = Fixture::new();
    f.valid();
    assert_eq!(create_from_plan(&f.plan, &"0".repeat(64)), Err(SetupError));
    f.no_authority();
}
#[test]
fn unknown_duplicate_and_reserved_metadata_deny() {
    let mut f = Fixture::new();
    f.valid();
    let mut v = f.plan_value();
    v["qualified"] = json!(true);
    f.replace_plan(v);
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
    assert!(parse::<Value>(br#"{"a":1,"a":2}"#, 16384).is_err());
    assert!(parse::<Value>(br#"{"x":{"$serde_json::private::Number":"1"}}"#, 16384).is_err());
    assert!(parse::<Value>(br#"{"a":-0}"#, 16384).is_err());
    assert!(parse::<Value>(br#"{"a":1e1}"#, 16384).is_err());
}
#[test]
fn expired_and_unallocated_result_opcode_deny() {
    let mut f = Fixture::new();
    f.valid();
    let mut v = f.plan_value();
    v["not_after"] = json!((now().unwrap() - 1).to_string());
    f.replace_plan(v);
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
    let mut f = Fixture::new();
    f.valid();
    let mut v = f.plan_value();
    v["result_opcode"] = json!("e1");
    f.replace_plan(v);
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
}
#[test]
fn native_pin_mismatch_and_symlink_deny_before_store() {
    let mut f = Fixture::new();
    f.valid();
    let mut v = f.plan_value();
    v["wallet_command_sha256"] = json!("0".repeat(64));
    f.replace_plan(v);
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
    let f = Fixture::new();
    f.valid();
    let target = f.root.join("native/castalia-wallet-service");
    fs::remove_file(&target).unwrap();
    std::os::unix::fs::symlink(f.root.join("native/secs-frank-result"), target).unwrap();
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
}
#[test]
fn composition_change_and_public_blob_tamper_deny_before_store() {
    let f = Fixture::new();
    f.valid();
    let file = f.root.join("config/review-composition.json");
    fs::remove_file(&file).unwrap();
    write(&file, b"{}").unwrap();
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
    let f = Fixture::new();
    f.valid();
    let c: Composition = parse(
        &read(&f.root.join("config/review-composition.json"), 65536, 0o600).unwrap(),
        65536,
    )
    .unwrap();
    let file = f.root.join("inputs/source-blobs").join(c.normalizer_sha256);
    fs::remove_file(&file).unwrap();
    write(&file, b"changed").unwrap();
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
}
#[test]
fn partial_public_copy_failure_retained_and_never_rekeyed() {
    let f = Fixture::new();
    let raw = read(&f.plan, 16384, 0o600).unwrap();
    let input = preflight(&raw).unwrap();
    let file = f
        .root
        .join("inputs/source-blobs")
        .join(&input.c.normalizer_sha256);
    fs::remove_file(&file).unwrap();
    write(&file, b"changed after exact preflight").unwrap();
    assert!(create_selected(&f.plan, &f.pin, input).is_err());
    assert!(f.root.join("authority/SETUP-BEGIN.json").is_file());
    assert!(!f.root.join("authority/COMPLETE.json").exists());
    assert!(!f.root.join("authority/command-issuer").exists());
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    assert!(!f.root.join("authority/command-issuer").exists());
}

#[test]
fn consistently_pinned_other_run_or_extra_capability_still_denies() {
    let mut f = Fixture::new();
    f.valid();
    let mut c: Value = parse(
        &read(&f.root.join("config/review-composition.json"), 65536, 0o600).unwrap(),
        65536,
    )
    .unwrap();
    c["run_ids"] = json!(["other-run"]);
    f.replace_composition(c);
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
    let mut f = Fixture::new();
    f.valid();
    let mut c: Value = parse(
        &read(&f.root.join("config/review-composition.json"), 65536, 0o600).unwrap(),
        65536,
    )
    .unwrap();
    c["actor"]["capabilities"]
        .as_array_mut()
        .unwrap()
        .push(json!("arbitrary.execute"));
    f.replace_composition(c);
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
}

#[test]
fn valid_512k_source_blob_copies_and_binds_exactly() {
    let mut f = Fixture::new();
    f.valid();
    let blob = vec![b'p'; 512 * 1024];
    let mut c: Value = parse(
        &read(&f.root.join("config/review-composition.json"), 65536, 0o600).unwrap(),
        65536,
    )
    .unwrap();
    c["producer_artifact_sha256"] = json!(hash(&blob));
    f.replace_composition(c);
    let mp = f.root.join("config/review-source-manifest.json");
    let mut m: Value = parse(&read(&mp, 16384, 0o600).unwrap(), 16384).unwrap();
    let prior = m["producer_artifact_sha256"].as_str().unwrap().to_owned();
    m["producer_artifact_sha256"] = json!(hash(&blob));
    let row = m["entries"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|v| v["sha256"] == prior)
        .unwrap();
    *row = json!({"sha256":hash(&blob),"byte_length":blob.len()});
    // Fixture construction must not hit the production readback defect:
    // the negative is the later capture COPY inside create_from_plan.
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(f.root.join("inputs/source-blobs").join(hash(&blob)))
            .unwrap();
        file.write_all(&blob).unwrap();
        file.sync_all().unwrap();
    }
    fs::remove_file(&mp).unwrap();
    let raw = canonical(&m);
    write(&mp, &raw).unwrap();
    let mut plan = f.plan_value();
    plan["source_manifest_sha256"] = json!(hash(&raw));
    f.replace_plan(plan);
    f.valid();
    let receipt = create_from_plan(&f.plan, &f.pin).unwrap();
    assert_eq!(receipt["activation"], false);
    let copied = read(
        &f.root.join("data/capture/blobs").join(hash(&blob)),
        1048576,
        0o600,
    )
    .unwrap();
    assert_eq!(copied, blob);
}
#[test]
fn over_one_mib_source_entry_denies_before_creating_authority() {
    let mut f = Fixture::new();
    f.valid();
    let mp = f.root.join("config/review-source-manifest.json");
    let mut m: Value = parse(&read(&mp, 16384, 0o600).unwrap(), 16384).unwrap();
    m["entries"][0]["byte_length"] = json!(1048577u64);
    fs::remove_file(&mp).unwrap();
    let raw = canonical(&m);
    write(&mp, &raw).unwrap();
    let mut plan = f.plan_value();
    plan["source_manifest_sha256"] = json!(hash(&raw));
    f.replace_plan(plan);
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
}
#[test]
fn completed_setup_includes_empty_private_result_journal_lock() {
    let f = Fixture::new();
    f.valid();
    create_from_plan(&f.plan, &f.pin).unwrap();
    let p = f.root.join("authority/result-journal/journal.lock");
    assert_eq!(read(&p, 0, 0o600).unwrap(), b"");
}
#[test]
fn consistently_repinned_bad_snapshot_subject_denies_before_keys() {
    let mut f = Fixture::new();
    f.valid();
    let mut c: Value = parse(
        &read(&f.root.join("config/review-composition.json"), 65536, 0o600).unwrap(),
        65536,
    )
    .unwrap();
    c["snapshots"] = json!({"space subject":[]});
    f.replace_composition(c);
    assert!(create_from_plan(&f.plan, &f.pin).is_err());
    f.no_authority();
}
#[test]
fn valid_snapshot_subject_grammar_stays_supported() {
    let mut f = Fixture::new();
    f.valid();
    let mut c: Value = parse(
        &read(&f.root.join("config/review-composition.json"), 65536, 0o600).unwrap(),
        65536,
    )
    .unwrap();
    c["snapshots"] = json!({"Subject.foo:bar_baz-9":[]});
    f.replace_composition(c);
    f.valid();
    assert!(create_from_plan(&f.plan, &f.pin).is_ok());
}

#[test]
fn final_clock_requires_original_lower_and_observed_floor_with_exclusive_end() {
    assert!(final_window(100, 200, 120, 120));
    assert!(final_window(100, 200, 120, 199));
    assert!(!final_window(100, 200, 120, 119));
    assert!(!final_window(100, 200, 90, 99));
    assert!(!final_window(100, 200, 120, 200));
}
#[test]
fn final_public_wallet_check_denies_revoked_actual_current() {
    let f = Fixture::new();
    let receipt = create_from_plan(&f.plan, &f.pin).unwrap();
    let a = f.root.join("authority");
    let config: Value = parse(
        &read(&a.join("config/command-authority.json"), 65536, 0o600).unwrap(),
        65536,
    )
    .unwrap();
    let wallet = WalletCurrentSource::open(
        OwnerSelectedWalletRoot::open(&a.join("wallet")).unwrap(),
        StartupWalletObservationPin::parse_owner_configuration(&canonical(
            &config["wallet_observation_pin"],
        ))
        .unwrap(),
    )
    .unwrap();
    {
        let held = final_wallet(&wallet).unwrap();
        held.revalidate().unwrap();
    }
    let identity: castalia_wallet_service_holder::custody::PublicServiceIdentity =
        serde_json::from_value(receipt["holder"].clone()).unwrap();
    let store = ServiceIdentityStore::open(&a.join("wallet"), identity.binding()).unwrap();
    store.revoke(identity.expected()).unwrap();
    assert!(final_wallet(&wallet).is_err());
}

#[tokio::test]
async fn emitted_command_config_selects_finite_pilot_capacity_and_preserves_native_pin() {
    let f = Fixture::new();
    f.valid();
    let receipt = create_from_plan(&f.plan, &f.pin).unwrap();
    assert_eq!(receipt["activation"], false);
    assert_eq!(receipt["run_created"], false);
    let config = f.root.join("authority/config/command-authority.json");
    let raw = read(&config, 65536, 0o600).unwrap();
    let value: Value = parse(&raw, 65536).unwrap();
    assert_eq!(value["journal_capacity"], "local_review_pilot_512");
    assert_eq!(value["maximum_ttl"], 30);
    let wallet: Value = parse(
        &read(
            &f.root.join("authority/config/wallet-command.json"),
            65536,
            0o600,
        )
        .unwrap(),
        65536,
    )
    .unwrap();
    assert_eq!(wallet["native_configuration_sha256"], hash(&raw));
    let pin: [u8; 32] = Sha256::digest(&raw).into();
    assert!(
        ServiceAuthority::open_pinned_owner_configuration(&config, pin)
            .await
            .is_ok()
    );
    let result: Value = parse(
        &read(
            &f.root.join("authority/config/result-authority.json"),
            65536,
            0o600,
        )
        .unwrap(),
        65536,
    )
    .unwrap();
    assert!(result.get("journal_capacity").is_none());
}
