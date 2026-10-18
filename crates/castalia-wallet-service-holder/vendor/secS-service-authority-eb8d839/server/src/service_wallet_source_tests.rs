use super::*;
use castalia_wallet_private_files::service_store::{ServiceLease, StagingFile};
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    process::Command,
};
pub(crate) fn private_file(path: &Path, raw: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(raw).unwrap();
    f.sync_all().unwrap();
}
pub(crate) fn policy() -> Value {
    serde_json::from_str::<Value>(include_str!(
        "../tests/fixtures/service-wallet-contract-v3/transition-vectors.json"
    ))
    .unwrap()["vectors"][0]["target_policy"]
        .clone()
}
pub(crate) struct WalletFiles {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) state: Value,
}
impl WalletFiles {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir_in("/private/tmp").unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let p = policy();
        let h = &p["holders"][0];
        let state = json!({"schema":"castalia.wallet-service-custody-state.v1","store_id":"00112233445566778899aabbccddeeff","subject_id":h["subject_id"],"purpose":"secs-service-holder-proof.v1","application":"runtime","state_revision":1,"key_generation":1,"key_id":h["key_id"],"public_key_hex":h["public_key_hex"],"public_key_sha256":hex(&hash(&digest(h["public_key_hex"].as_str().unwrap()).unwrap())),"state":"unconfigured","created_at":80,"key_created_at":80,"published_at":90,"not_before":0,"not_after":180,"revoked_at":null,"previous_state_sha256":null,"owner_input_sha256":null});
        let out = Self { dir, state };
        let root = ServiceRoot::open(out.path()).unwrap();
        let mut lease = root.initialize().unwrap();
        out.publish(&mut lease, &out.state, None, false);
        out
    }
    pub(crate) fn path(&self) -> &Path {
        self.dir.path()
    }
    pub(crate) fn publish(
        &self,
        l: &mut ServiceLease<'_>,
        state: &Value,
        owner: Option<&[u8]>,
        replace: bool,
    ) {
        l.begin_staging().unwrap();
        if state["state"] != "revoked" {
            l.write_staging(StagingFile::Seed, &[0; 32]).unwrap();
        }
        l.write_staging(StagingFile::State, &canonical(state))
            .unwrap();
        if let Some(raw) = owner {
            l.write_staging(StagingFile::OwnerInput, raw).unwrap();
        }
        l.sync_staging().unwrap();
        l.publish_revision(state["state_revision"].as_u64().unwrap())
            .unwrap();
        let current = json!({"schema":"castalia.wallet-service-custody-current.v1","store_id":state["store_id"],"state_revision":state["state_revision"],"state_sha256":hex(&hash(&canonical(state)))});
        let clock = json!({"schema":"castalia.wallet-service-custody-clock.v1","store_id":state["store_id"],"observed_at":100});
        l.publish_clock(&canonical(&clock), replace).unwrap();
        l.publish_current(&canonical(&current), replace).unwrap();
        l.invalidate(false).unwrap();
    }
    pub(crate) fn observed(&self) -> ObservedWallet {
        let root = ServiceRoot::open(self.path()).unwrap();
        let l = root.lock_public_shared().unwrap();
        ObservedWallet::read(l.metadata()).unwrap()
    }
    pub(crate) fn source(&self) -> WalletCurrentSource {
        let o = self.observed();
        let pin = json!({"schema":"secs.wallet-current-startup-pin.v2","store_id":o.reference.value["store_id"],"minimum_state_revision":o.revision(),"minimum_key_generation":o.generation(),"expected_wallet_reference_sha256":hex(&o.reference.reference_digest())});
        WalletCurrentSource::open(
            OwnerSelectedWalletRoot::open(self.path()).unwrap(),
            StartupWalletObservationPin::parse_owner_configuration(&canonical(&pin)).unwrap(),
        )
        .unwrap()
    }
    pub(crate) fn owner_input(&self, revision: u64) -> Vec<u8> {
        let p = policy();
        let mut issuers = p["issuers"].clone();
        for i in issuers.as_array_mut().unwrap() {
            i.as_object_mut().unwrap().remove("production_authority");
        }
        let mut holder = p["holders"][0].clone();
        holder["generation"] = json!(1);
        holder["replaced_by"] = Value::Null;
        canonical(
            &json!({"schema":"castalia.wallet-service-owner-input.v1","generation":revision,"valid_not_before":0,"valid_until":185,"application":"runtime","issuer_node_id":p["issuer_node_id"],"selected_issuer_key_id":p["selected_issuer_key_id"],"issuers":issuers,"holder":holder,"descriptors":p["descriptors"],"delegation_policy":p["receiver_policy"]}),
        )
    }
    pub(crate) fn configure(&self) -> (Value, Vec<u8>) {
        let raw = self.owner_input(2);
        let mut s = self.state.clone();
        s["state_revision"] = json!(2);
        s["state"] = json!("active");
        s["published_at"] = json!(100);
        s["previous_state_sha256"] = json!(hex(&hash(&canonical(&self.state))));
        s["owner_input_sha256"] = json!(hex(&hash(&raw)));
        (s, raw)
    }
}
pub(crate) struct TestTime;
impl TestTime {
    pub(crate) fn set(n: u64) -> Self {
        TEST_NOW.with(|v| v.set(Some(n)));
        Self
    }
}
impl Drop for TestTime {
    fn drop(&mut self) {
        TEST_NOW.with(|v| v.set(None));
    }
}
#[test]
fn metadata_uses_actual_current_and_never_reads_seed() {
    let _time = TestTime::set(100);
    let f = WalletFiles::new();
    let source = f.source();
    let l = source.capture_shared().unwrap();
    assert_eq!(
        l.reference_sha256(),
        f.observed().reference.reference_digest()
    );
    assert_eq!(l.observed.reference.state(), WalletState::Unconfigured);
    assert_eq!(
        l.observed.active_window(100, 110),
        Err(SourceError::Inactive)
    );
    assert!(ServiceRoot::open(f.path())
        .unwrap()
        .lock_exclusive()
        .is_err());
    l.revalidate().unwrap();
}
#[test]
fn temporary_view_drops_before_mutable_clock_and_recaptures_same_exclusive() {
    let _time = TestTime::set(100);
    let f = WalletFiles::new();
    let source = f.source();
    let root = ServiceRoot::open(f.path()).unwrap();
    let mut session = root.lock_exclusive().unwrap();
    {
        let observation = source
            .capture_borrowed(session.public_observation().unwrap())
            .unwrap();
        observation.revalidate().unwrap();
        assert!(root.lock_shared().is_err());
    }
    let epoch = session.epoch().unwrap();
    session.invalidate(false).unwrap();
    assert!(session.epoch().unwrap() > epoch);
    let observation = source
        .capture_borrowed(session.public_observation().unwrap())
        .unwrap();
    observation.revalidate().unwrap();
}
#[test]
fn active_public_delegation_is_real_bounded_input_and_startup_drift_denies() {
    let _time = TestTime::set(100);
    let f = WalletFiles::new();
    let old_source = f.source();
    let (s, raw) = f.configure();
    let root = ServiceRoot::open(f.path()).unwrap();
    let mut l = root.lock_exclusive().unwrap();
    f.publish(&mut l, &s, Some(&raw), true);
    drop(l);
    assert!(matches!(
        old_source.capture_shared(),
        Err(SourceError::Changed)
    ));
    let source = f.source();
    let current = source.capture_shared().unwrap();
    current.observed.active_window(100, 110).unwrap();
    assert_eq!(
        current.observed.reference.value["delegation_policy_sha256"],
        hex(&hash(&canonical(&policy()["receiver_policy"])))
    );
}
#[test]
fn rollback_clock_and_changed_public_files_deny() {
    let _time = TestTime::set(100);
    let f = WalletFiles::new();
    let source = f.source();
    let l = source.capture_shared().unwrap();
    TEST_NOW.with(|v| v.set(Some(99)));
    assert_eq!(l.revalidate(), Err(SourceError::Clock));
    TEST_NOW.with(|v| v.set(Some(100)));
    fs::write(f.path().join("CLOCK"), b"{}").unwrap();
    assert!(l.revalidate().is_err());
}
#[test]
fn foreign_root_and_noncanonical_state_deny() {
    let _time = TestTime::set(100);
    let a = WalletFiles::new();
    let b = WalletFiles::new();
    let source = a.source();
    let root = ServiceRoot::open(b.path()).unwrap();
    let session = root.lock_exclusive().unwrap();
    assert!(matches!(
        source.capture_borrowed(session.public_observation().unwrap()),
        Err(SourceError::Changed)
    ));
    drop(session);
    let path = a.path().join("states/s0000000000000001/state.json");
    let mut raw = canonical(&a.state);
    raw.push(b' ');
    fs::write(path, raw).unwrap();
    assert!(source.capture_shared().is_err());
}
#[test]
fn current_lock_excludes_a_fresh_process() {
    let _time = TestTime::set(100);
    let f = WalletFiles::new();
    let source = f.source();
    let lease = source.capture_shared().unwrap();
    let output=Command::new("python3").arg("-c").arg("import fcntl,sys; f=open(sys.argv[1],'r+');\ntry: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(0)\nsys.exit(3)").arg(f.path().join("custody.lock")).output().unwrap();
    assert!(output.status.success());
    drop(lease);
}

#[test]
fn all_five_actual_current_states_and_inactive_nulls_are_derived_from_files() {
    let _time = TestTime::set(100);
    let f = WalletFiles::new();
    assert_eq!(f.observed().reference.state(), WalletState::Unconfigured);
    let root = ServiceRoot::open(f.path()).unwrap();
    let mut lease = root.lock_exclusive().unwrap();
    let (configured, first_input) = f.configure();
    f.publish(&mut lease, &configured, Some(&first_input), true);
    drop(lease);
    assert_eq!(f.observed().reference.state(), WalletState::Active);
    let mut lease = root.lock_exclusive().unwrap();
    let mut rotated = configured.clone();
    rotated["state_revision"] = json!(3);
    rotated["key_generation"] = json!(2);
    rotated["state"] = json!("unconfigured");
    rotated["owner_input_sha256"] = Value::Null;
    rotated["previous_state_sha256"] = json!(hex(&hash(&canonical(&configured))));
    rotated["key_created_at"] = json!(100);
    let public = ed25519_dalek::SigningKey::from_bytes(&[72; 32])
        .verifying_key()
        .to_bytes();
    rotated["public_key_hex"] = json!(hex(&public));
    rotated["public_key_sha256"] = json!(hex(&hash(&public)));
    rotated["key_id"] = json!(format!("service-ed25519:sha256:{}", hex(&hash(&public))));
    f.publish(&mut lease, &rotated, None, true);
    lease.remove_revision(1).unwrap();
    drop(lease);
    let actual = f.observed();
    assert_eq!(actual.reference.state(), WalletState::Unconfigured);
    assert!(actual.reference.value["owner_input_sha256"].is_null());
    assert!(actual.reference.value["delegation_policy_sha256"].is_null());
    assert_eq!(actual.active_window(100, 110), Err(SourceError::Inactive));
    let mut input = crate::service_authority_snapshot::strict_value(&f.owner_input(4)).unwrap();
    input["holder"]["generation"] = json!(2);
    for field in ["public_key_hex", "key_id"] {
        input["holder"][field] = rotated[field].clone();
    }
    for principal in input["delegation_policy"]["principals"]
        .as_array_mut()
        .unwrap()
    {
        principal["key_id"] = rotated["key_id"].clone();
    }
    for rule in input["delegation_policy"]["rules"].as_array_mut().unwrap() {
        rule["key_id"] = rotated["key_id"].clone();
    }
    let raw = canonical(&input);
    let mut configured_again = rotated.clone();
    configured_again["state_revision"] = json!(4);
    configured_again["state"] = json!("active");
    configured_again["previous_state_sha256"] = json!(hex(&hash(&canonical(&rotated))));
    configured_again["owner_input_sha256"] = json!(hex(&hash(&raw)));
    let mut lease = root.lock_exclusive().unwrap();
    f.publish(&mut lease, &configured_again, Some(&raw), true);
    lease.remove_revision(2).unwrap();
    drop(lease);
    f.observed().active_window(100, 110).unwrap();
    let mut revoked = configured_again.clone();
    revoked["state_revision"] = json!(5);
    revoked["state"] = json!("revoked");
    revoked["owner_input_sha256"] = Value::Null;
    revoked["revoked_at"] = json!(100);
    revoked["previous_state_sha256"] = json!(hex(&hash(&canonical(&configured_again))));
    let mut lease = root.lock_exclusive().unwrap();
    f.publish(&mut lease, &revoked, None, true);
    drop(lease);
    let actual = f.observed();
    assert_eq!(actual.reference.state(), WalletState::Revoked);
    assert_eq!(actual.active_window(100, 110), Err(SourceError::Inactive));
    assert!(actual.reference.value["owner_input_sha256"].is_null());
    assert!(actual.reference.value["delegation_policy_sha256"].is_null());
}

#[test]
fn retained_public_state_reuses_strict_closed_metadata_semantics_and_exact_bytes() {
    let _time = TestTime::set(100);
    let f = WalletFiles::new();
    let o = f.observed();
    assert!(retained_state(&canonical(&f.state), &o.reference).is_ok());
    let raw = canonical(&f.state);
    let mut cases = Vec::new();
    let mut extra = f.state.clone();
    extra["extra"] = json!(true);
    cases.push(canonical(&extra));
    for (field, value) in [
        ("created_at", json!(0)),
        ("key_created_at", json!(79)),
        ("published_at", json!(79)),
        ("subject_id", json!("foreign:subject")),
    ] {
        let mut bad = f.state.clone();
        bad[field] = value;
        cases.push(canonical(&bad));
    }
    let mut whitespace = raw.clone();
    whitespace.push(b' ');
    cases.push(whitespace);
    cases.push(
        String::from_utf8(raw.clone())
            .unwrap()
            .replace("\"created_at\":80", "\"created_at\":-0")
            .into_bytes(),
    );
    cases.push(
        String::from_utf8(raw)
            .unwrap()
            .replace("\"created_at\":80", "\"created_at\":80,\"created_at\":80")
            .into_bytes(),
    );
    cases.push(vec![b' '; 4097]);
    for raw in cases {
        let mut v = o.reference.value.clone();
        v["custody_state_sha256"] = json!(hex(&hash(&raw)));
        let reference = WalletReference::from_value(v).unwrap();
        assert!(retained_state(&raw, &reference).is_err());
    }
}

// Canonical Runtime/Service audience regression: real public files and OS time.
// Sentinel seed and metadata-only source; no Wallet private-custody qualification.
pub(crate) fn audience_request_fixture(
    application: libsec_core::service_holder_proof::ServiceApplication,
) -> (Value, Vec<u8>) {
    let (name, opcode, resource, app) = match application {
        libsec_core::service_holder_proof::ServiceApplication::RuntimeV1 => {
            ("runtime.run.create.v1", 0x42, "runs/run-1", "runtime")
        }
        libsec_core::service_holder_proof::ServiceApplication::ServiceV1 => (
            "service.request.create.v1",
            0x79,
            "requests/request-1",
            "service",
        ),
    };
    use crate::manifest::{
        OpcodeRange, OperationDescriptor, OperationName, ReplayScope, TargetKind,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut p = policy();
    let descriptor = OperationDescriptor {
        opcode,
        name: OperationName::new(name),
        payload_schema: Some("application/json".into()),
        output_profile: None,
        target_kind: TargetKind::ReceiverProductionHandler,
        required_credentials: vec![],
        required_capabilities: vec![],
        accepted_evidence: vec![],
        required_authority_mode: None,
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 60,
        handler_id: format!("fixture/{name}"),
        dev_binding: false,
        range: OpcodeRange::OperatorDefined,
        disclosure_policy: crate::privacy::DisclosurePolicy::deny_by_default("fixture", 1),
    };
    let fingerprint = descriptor
        .authorization_fingerprint()
        .trim_start_matches("descriptor:sha256:")
        .to_owned();
    p["application"] = json!(app);
    p["valid_not_before"] = json!(now - 600);
    p["valid_until"] = json!(now + 600);
    for kind in ["issuers", "holders", "permissions"] {
        for row in p[kind].as_array_mut().unwrap() {
            row["not_before"] = json!(now - 600);
            row["not_after"] = json!(now + 600);
        }
    }
    let d = &mut p["descriptors"][0];
    d["name"] = json!(descriptor.name.as_str());
    d["opcode"] = json!(descriptor.opcode);
    d["handler_id"] = json!(descriptor.handler_id);
    for r in p["permissions"].as_array_mut().unwrap() {
        r["opcode"] = json!(descriptor.opcode);
        r["operation"] = json!(descriptor.name.as_str());
        r["resource"] = json!({"kind":"exact","value":resource});
    }
    let policy = &mut p["receiver_policy"];
    policy["application"] = json!(app);
    policy["audience"] = json!(application.audience());
    policy["not_before"] = json!(now - 600);
    policy["not_after"] = json!(now + 600);
    for kind in ["principals", "rules"] {
        for r in policy[kind].as_array_mut().unwrap() {
            r["not_before"] = json!(now - 600);
            r["not_after"] = json!(now + 600);
        }
    }
    let pd = &mut policy["descriptors"][0];
    pd["operation"] = json!(descriptor.name.as_str());
    pd["opcode"] = json!(descriptor.opcode);
    pd["handler_id"] = json!(descriptor.handler_id);
    pd["fingerprint"] = json!(fingerprint);
    for r in policy["rules"].as_array_mut().unwrap() {
        r["operation"] = json!(descriptor.name.as_str());
        r["resource"] = json!(resource);
    }
    // This exact same object is Wallet's delegation_policy and Native's full
    // receiver_policy. It is not an alternate receiver namespace.
    secs_service_call_contract::ReceiverPolicy::parse(&canonical(&p["receiver_policy"])).unwrap();
    let mut issuers = p["issuers"].clone();
    for i in issuers.as_array_mut().unwrap() {
        i.as_object_mut().unwrap().remove("production_authority");
    }
    let mut holder = p["holders"][0].clone();
    holder["generation"] = json!(1);
    holder["replaced_by"] = Value::Null;
    let input = canonical(
        &json!({"schema":"castalia.wallet-service-owner-input.v1","generation":2,"valid_not_before":now-600,"valid_until":now+600,"application":p["application"],"issuer_node_id":p["issuer_node_id"],"selected_issuer_key_id":p["selected_issuer_key_id"],"issuers":issuers,"holder":holder,"descriptors":p["descriptors"],"delegation_policy":p["receiver_policy"]}),
    );
    (p, input)
}
fn audience_metadata_write(
    l: &mut castalia_wallet_private_files::service_store::ServiceLease<'_>,
    s: &Value,
    input: Option<&[u8]>,
    replace: bool,
) {
    use castalia_wallet_private_files::service_store::StagingFile;
    l.begin_staging().unwrap();
    l.write_staging(StagingFile::Seed, &[0; 32]).unwrap();
    l.write_staging(StagingFile::State, &canonical(s)).unwrap();
    if let Some(raw) = input {
        l.write_staging(StagingFile::OwnerInput, raw).unwrap();
    }
    l.sync_staging().unwrap();
    l.publish_revision(s["state_revision"].as_u64().unwrap())
        .unwrap();
    let pointer = json!({"schema":"castalia.wallet-service-custody-current.v1","store_id":s["store_id"],"state_revision":s["state_revision"],"state_sha256":hex(&hash(&canonical(s)))});
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    l.publish_clock(&canonical(&json!({"schema":"castalia.wallet-service-custody-clock.v1","store_id":s["store_id"],"observed_at":now})),replace).unwrap();
    l.publish_current(&canonical(&pointer), replace).unwrap();
    l.invalidate(false).unwrap();
}
pub(crate) fn audience_metadata_unconfigured(p: &Value) -> WalletFiles {
    let dir = tempfile::tempdir_in("/private/tmp").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let n = p["valid_not_before"].as_u64().unwrap();
    let end = p["valid_until"].as_u64().unwrap();
    let h = &p["holders"][0];
    let state = json!({"schema":"castalia.wallet-service-custody-state.v1","store_id":"102132435465768798a9bacbdcedfe0f","subject_id":h["subject_id"],"purpose":"secs-service-holder-proof.v1","application":p["application"],"state_revision":1,"key_generation":1,"key_id":h["key_id"],"public_key_hex":h["public_key_hex"],"public_key_sha256":hex(&hash(&digest(h["public_key_hex"].as_str().unwrap()).unwrap())),"state":"unconfigured","created_at":n,"key_created_at":n,"published_at":n,"not_before":n,"not_after":end,"revoked_at":null,"previous_state_sha256":null,"owner_input_sha256":null});
    let f = WalletFiles { dir, state };
    let root = ServiceRoot::open(f.path()).unwrap();
    let mut l = root.initialize().unwrap();
    audience_metadata_write(&mut l, &f.state, None, false);
    drop(l);
    f
}

fn audience_capture_active(p: &Value, raw: &[u8]) -> Result<()> {
    let f = audience_metadata_unconfigured(p);
    let declared: Value = serde_json::from_slice(raw).unwrap();
    let mut state = f.state.clone();
    state["state_revision"] = json!(2);
    state["state"] = json!("active");
    state["owner_input_sha256"] = json!(hex(&hash(raw)));
    state["previous_state_sha256"] = json!(hex(&hash(&canonical(&f.state))));
    state["published_at"] = json!(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs());
    let root = ServiceRoot::open(f.path()).unwrap();
    let mut l = root.lock_exclusive().unwrap();
    audience_metadata_write(&mut l, &state, Some(raw), true);
    drop(l);
    let pointer = json!({"schema":"castalia.wallet-service-custody-current.v1","store_id":state["store_id"],"state_revision":state["state_revision"],"state_sha256":hex(&hash(&canonical(&state)))});
    // Expected reference is independent fixture configuration data, never an
    // observed or qualified guard; actual capture below must read the real FS.
    let reference=WalletReference::from_value(json!({"schema":"secs.wallet-current-reference.v2","store_id":state["store_id"],"subject_id":state["subject_id"],"purpose":state["purpose"],"application":p["application"],"state_revision":2,"key_generation":1,"state":"active","current_sha256":hex(&hash(&canonical(&pointer))),"custody_state_sha256":hex(&hash(&canonical(&state))),"key_id":state["key_id"],"public_key_hex":state["public_key_hex"],"public_key_sha256":state["public_key_sha256"],"not_before":state["not_before"],"not_after":state["not_after"],"revoked_at":null,"owner_input_sha256":hex(&hash(raw)),"delegation_policy_sha256":hex(&hash(&canonical(&declared["delegation_policy"])))})).unwrap();
    let pin = canonical(
        &json!({"schema":"secs.wallet-current-startup-pin.v2","store_id":state["store_id"],"minimum_state_revision":2,"minimum_key_generation":1,"expected_wallet_reference_sha256":hex(&reference.reference_digest())}),
    );
    let source = WalletCurrentSource::open(
        OwnerSelectedWalletRoot::open(f.path()).unwrap(),
        StartupWalletObservationPin::parse_owner_configuration(&pin).unwrap(),
    )
    .unwrap();
    let result = source.capture_shared().map(|_| ());
    result
}

#[test]
fn accepted_service_delegation_passes_native_transition_input() {
    let (p, raw) =
        audience_request_fixture(libsec_core::service_holder_proof::ServiceApplication::ServiceV1);
    let f = audience_metadata_unconfigured(&p);
    let source = f.source();
    let current = source.capture_shared().unwrap();
    assert_eq!(p["receiver_policy"]["audience"], "service-management");
    // On unmodified ad8870 this exact positive expectation is expected to fail.
    validate_transition_request(&raw, &current.observed.reference).unwrap();
}
#[test]
fn accepted_service_delegation_passes_actual_native_current_capture() {
    let (p, raw) =
        audience_request_fixture(libsec_core::service_holder_proof::ServiceApplication::ServiceV1);
    audience_capture_active(&p, &raw).unwrap();
}
#[test]
fn existing_runtime_audience_keeps_input_and_actual_capture_compatibility() {
    let (p, raw) =
        audience_request_fixture(libsec_core::service_holder_proof::ServiceApplication::RuntimeV1);
    let f = audience_metadata_unconfigured(&p);
    let source = f.source();
    let current = source.capture_shared().unwrap();
    assert_eq!(p["receiver_policy"]["audience"], "runtime://receiver-local");
    validate_transition_request(&raw, &current.observed.reference).unwrap();
    audience_capture_active(&p, &raw).unwrap();
}
#[test]
fn service_uri_alias_is_denied_as_transition_input() {
    let (p, raw) =
        audience_request_fixture(libsec_core::service_holder_proof::ServiceApplication::ServiceV1);
    let f = audience_metadata_unconfigured(&p);
    let source = f.source();
    let current = source.capture_shared().unwrap();
    let mut v: Value = serde_json::from_slice(&raw).unwrap();
    v["delegation_policy"]["audience"] = json!("service://receiver-local");
    assert!(validate_transition_request(&canonical(&v), &current.observed.reference).is_err());
}
#[test]
fn service_uri_alias_is_denied_from_actual_current_metadata() {
    let (p, raw) =
        audience_request_fixture(libsec_core::service_holder_proof::ServiceApplication::ServiceV1);
    let mut v: Value = serde_json::from_slice(&raw).unwrap();
    v["delegation_policy"]["audience"] = json!("service://receiver-local");
    // The independent fixture pin hashes this wrong audience exactly: a denial
    // cannot be attributed merely to a deliberately mismatched expected digest.
    assert!(audience_capture_active(&p, &canonical(&v)).is_err());
}
