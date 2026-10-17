use super::*;
use serde_json::json;
#[test]
fn duplicate_fields_and_noninteger_metadata_deny() {
    for raw in [
        br#"{"x":1,"x":2}"#.as_slice(),
        br#"{"x":{"nested":1,"nested":2}}"#,
        br#"{"x":[{"nested":1,"nested":2}]}"#,
        br#"{"x":1.0}"#,
        br#"{"x":9007199254740992}"#,
    ] {
        assert!(strict_value(raw).is_err(), "accepted invalid metadata");
    }
}
#[test]
fn permission_projection_golden_and_array_order() {
    let row = json!({"caller_id":"holder:fixture","opcode":66,"operation":"runtime.run.create.v1","resource":{"kind":"exact","value":"runs/run-1"},"effect":"allow","not_before":90,"not_after":200,"status":"active","authority_source":"receiver_local"});
    let bytes = projection(
        b"secs-service-permission-snapshot-v1\0",
        &json!({"records":[row.clone()]}),
    );
    assert_eq!(
        hex(&hash(&bytes)),
        "e2acbd798e9e2535c5bb79be85ae1f2126f7363b908b598a76f386a267ab225d"
    );
    let two = json!([row,{"x":1}]);
    assert_ne!(canonical(&two), canonical(&json!([{"x":1},two[0]])));
    assert_eq!(
        canonical(&json!({"z":{"b":1,"a":2},"a":0})),
        br#"{"a":0,"z":{"a":2,"b":1}}"#
    );
}
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    sync::atomic::AtomicU64,
};
struct Now(AtomicU64);
impl Now {
    fn new(v: u64) -> Self {
        Self(AtomicU64::new(v))
    }
    fn set(&self, v: u64) {
        self.0.store(v, Ordering::SeqCst);
    }
}
impl Clock for Now {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
fn challenge() -> UntrustedSignedServiceChallenge {
    UntrustedSignedServiceChallenge::decode_inner(include_bytes!(
        "../tests/fixtures/service-holder-proof-v1/challenge.bin"
    ))
    .unwrap()
}
fn descriptor() -> Value {
    json!({"opcode":66,"name":"runtime.run.create.v1","payload_schema":"application/json","output_profile":null,"target_kind":"receiver_production_handler","required_credentials":[],"required_capabilities":[],"accepted_evidence":[],"required_authority_mode":null,"replay_scope":"session_opcode_nonce","max_ttl_seconds":60,"handler_id":"fixture/runtime.run.create.v1","dev_binding":false,"range":"operator_defined","disclosure_policy":{"policy_id":"fixture","policy_version":1,"permissions":[]}})
}
fn fixture() -> Value {
    let d = descriptor();
    let native: Descriptor = serde_json::from_value(d.clone()).unwrap();
    let fp = native
        .native()
        .unwrap()
        .authorization_fingerprint()
        .replace("descriptor:sha256:", "");
    let issuer = hex(include_bytes!(
        "../tests/fixtures/service-holder-proof-v1/issuer-public.bin"
    ));
    let holder = hex(include_bytes!(
        "../tests/fixtures/service-holder-proof-v1/holder-public.bin"
    ));
    json!({"schema":"secs.service-owner-bundle.v1","generation":1,"valid_not_before":90,"valid_until":200,"application":"runtime","issuer_node_id":"node:fixture","selected_issuer_key_id":"issuer:key","issuers":[{"node_id":"node:fixture","key_id":"issuer:key","public_key_hex":issuer,"algorithm":"ed25519","status":"active","not_before":90,"not_after":200,"revoked_at":null,"replaced_by":null,"production_authority":true}],"holders":[{"key_id":"holder:key","subject_id":"holder:fixture","public_key_hex":holder,"algorithm":"ed25519","status":"active","not_before":90,"not_after":200,"revoked_at":null}],"descriptors":[d],"permissions":[{"caller_id":"holder:fixture","opcode":66,"operation":"runtime.run.create.v1","resource":{"kind":"exact","value":"runs/run-1"},"effect":"allow","not_before":90,"not_after":200,"status":"active","authority_source":"receiver_local"}],"receiver_policy":{"schema":"secs.service-receiver-policy.v1","application":"runtime","audience":"runtime://receiver-local","not_before":90,"not_after":200,"max_ttl_seconds":60,"principals":[{"subject_id":"holder:fixture","key_id":"holder:key","not_before":90,"not_after":200,"revoked":false}],"descriptors":[{"operation":"runtime.run.create.v1","opcode":66,"fingerprint":fp,"handler_id":"fixture/runtime.run.create.v1","max_ttl_seconds":60}],"rules":[{"subject_id":"holder:fixture","key_id":"holder:key","operation":"runtime.run.create.v1","resource":"runs/run-1","resource_match":"exact","effect":"allow","not_before":90,"not_after":200,"active":true}]}})
}
struct Files {
    dir: tempfile::TempDir,
    raw: Vec<u8>,
}
impl Files {
    fn new(v: &Value) -> Self {
        let dir = tempfile::tempdir_in("/private/tmp").unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let raw = canonical(v);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.path().join(FILE))
            .unwrap();
        f.write_all(&raw).unwrap();
        Self { dir, raw }
    }
    fn source(&self) -> OwnerSource {
        OwnerSource::open(self.dir.path(), 1, hash(&self.raw)).unwrap()
    }
}
fn prepare(
    lease: &OwnerLease<'_>,
    clock: &dyn Clock,
) -> Result<PreparedOwnerBindings, SnapshotError> {
    lease.prepare_request(
        &challenge().request_bytes,
        "holder:fixture",
        "holder:key",
        100,
        60,
        clock,
    )
}
#[test]
fn real_owner_read_native_policy_and_explicit_missing_ports() {
    let files = Files::new(&fixture());
    let source = files.source();
    let clock = Now::new(100);
    let lease = source.lease(&clock).unwrap();
    let prepared = prepare(&lease, &clock).unwrap();
    assert_eq!(prepared.evidence().bindings().evidence_observed_at, 100);
    clock.set(120);
    lease.revalidate_prepared(&prepared, &clock).unwrap();
    assert_eq!(prepared.evidence().bindings().evidence_observed_at, 100);
    assert_eq!(
        lease.require_qualified_ports(&clock),
        Err(SnapshotError::MissingQualifiedWalletAndContextIssuer)
    );
    clock.set(160);
    assert_eq!(
        lease.revalidate_prepared(&prepared, &clock),
        Err(SnapshotError::Window)
    );
}
#[test]
fn retained_public_signature_is_verified_strictly_without_signing() {
    let files = Files::new(&fixture());
    let source = files.source();
    let clock = Now::new(100);
    let lease = source.lease(&clock).unwrap();
    let c = challenge();
    assert!(lease.verify_challenge_origin(&c, &clock).is_ok());
    let mut bad = c.clone();
    bad.issuer_signature[0] ^= 1;
    assert_eq!(
        lease.verify_challenge_origin(&bad, &clock),
        Err(SnapshotError::InvalidSignature)
    );
    let mut bad = c.clone();
    bad.request_bytes[0] ^= 1;
    assert!(lease.verify_challenge_origin(&bad, &clock).is_err());
    let mut bad = c;
    bad.claims.issuer_key_id = "other".into();
    assert_eq!(
        lease.verify_challenge_origin(&bad, &clock),
        Err(SnapshotError::Denied)
    );
    clock.set(160);
    assert!(lease.verify_challenge_origin(&challenge(), &clock).is_err());
}
#[test]
fn actual_fixture_obligations_cannot_become_empty() {
    let mut v = fixture();
    for field in [
        "required_credentials",
        "required_capabilities",
        "accepted_evidence",
    ] {
        v["descriptors"][0][field] = json!(["fixture.required"]);
        let native: Descriptor = serde_json::from_value(v["descriptors"][0].clone()).unwrap();
        v["receiver_policy"]["descriptors"][0]["fingerprint"] = json!(native
            .native()
            .unwrap()
            .authorization_fingerprint()
            .replace("descriptor:sha256:", ""));
        let files = Files::new(&v);
        let source = files.source();
        let clock = Now::new(100);
        let lease = source.lease(&clock).unwrap();
        assert!(matches!(
            prepare(&lease, &clock),
            Err(SnapshotError::UnsupportedRequiredEvidence)
        ));
        v = fixture();
    }
}
#[test]
fn unknown_fields_at_each_dto_nesting_deny() {
    for pointer in [
        "",
        "/issuers/0",
        "/holders/0",
        "/descriptors/0",
        "/descriptors/0/disclosure_policy",
        "/permissions/0",
        "/permissions/0/resource",
        "/receiver_policy",
        "/receiver_policy/principals/0",
        "/receiver_policy/descriptors/0",
        "/receiver_policy/rules/0",
    ] {
        let mut v = fixture();
        v.pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), json!(true));
        assert!(parse_bundle(&canonical(&v)).is_err(), "accepted {pointer}");
    }
}
#[test]
fn duplicates_aliases_weak_keys_and_missing_explicit_fields_deny() {
    for case in 0..8 {
        let mut v = fixture();
        match case {
            0 => {
                let x = v["issuers"][0].clone();
                v["issuers"].as_array_mut().unwrap().push(x);
            }
            1 => {
                let mut x = v["holders"][0].clone();
                x["key_id"] = json!("another");
                v["holders"].as_array_mut().unwrap().push(x);
            }
            2 => v["holders"][0]["public_key_hex"] = v["issuers"][0]["public_key_hex"].clone(),
            3 => {
                let x = v["descriptors"][0].clone();
                v["descriptors"].as_array_mut().unwrap().push(x);
            }
            4 => v["holders"][0]["public_key_hex"] = json!("00".repeat(32)),
            5 => {
                v["issuers"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("revoked_at");
            }
            6 => {
                v["descriptors"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("required_authority_mode");
            }
            _ => v["permissions"][0]["authority_source"] = json!("dregg_authority"),
        };
        assert!(parse_bundle(&canonical(&v)).is_err(), "accepted case{case}");
    }
}
#[test]
fn every_window_second_is_evaluated_and_future_denies_cap() {
    for case in 0..4 {
        let mut v = fixture();
        match case {
            0 => {
                let mut deny = v["permissions"][0].clone();
                deny["effect"] = json!("deny");
                deny["not_before"] = json!(155);
                v["permissions"].as_array_mut().unwrap().push(deny);
            }
            1 => v["permissions"][0]["not_after"] = json!(159),
            2 => {
                let mut deny = v["receiver_policy"]["rules"][0].clone();
                deny["effect"] = json!("deny");
                deny["not_before"] = json!(155);
                v["receiver_policy"]["rules"]
                    .as_array_mut()
                    .unwrap()
                    .push(deny);
            }
            _ => v["holders"][0]["revoked_at"] = json!(150),
        };
        let files = Files::new(&v);
        let source = files.source();
        let clock = Now::new(100);
        let lease = source.lease(&clock).unwrap();
        assert!(prepare(&lease, &clock).is_err(), "accepted case{case}");
    }
}
#[test]
fn replaced_or_revoked_key_metadata_cannot_pass() {
    for field in ["status", "replaced_by", "production_authority"] {
        let mut v = fixture();
        v["issuers"][0][field] = match field {
            "status" => json!("revoked"),
            "replaced_by" => json!("new-key"),
            _ => json!(false),
        };
        let files = Files::new(&v);
        let source = files.source();
        let clock = Now::new(100);
        let lease = source.lease(&clock).unwrap();
        assert!(prepare(&lease, &clock).is_err());
        assert!(lease.verify_challenge_origin(&challenge(), &clock).is_err());
    }
}
#[test]
fn exact_independent_pin_and_generation_are_required() {
    let files = Files::new(&fixture());
    let clock = Now::new(100);
    assert!(OwnerSource::open(files.dir.path(), 2, hash(&files.raw))
        .unwrap()
        .lease(&clock)
        .is_err());
    assert!(OwnerSource::open(files.dir.path(), 1, [1; 32])
        .unwrap()
        .lease(&clock)
        .is_err());
}
#[test]
fn content_or_inode_change_never_uses_last_good_snapshot() {
    for replace in [false, true] {
        let files = Files::new(&fixture());
        let source = files.source();
        let clock = Now::new(100);
        let lease = source.lease(&clock).unwrap();
        if replace {
            let path = files.dir.path().join("replacement");
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            f.write_all(&files.raw).unwrap();
            fs::rename(path, files.dir.path().join(FILE)).unwrap();
        } else {
            fs::write(files.dir.path().join(FILE), b"{}").unwrap();
        }
        assert!(lease.revalidate(&clock).is_err());
    }
}
#[test]
fn source_symlink_permissions_and_hardlinks_deny() {
    for case in 0..3 {
        let files = Files::new(&fixture());
        let path = files.dir.path().join(FILE);
        match case {
            0 => {
                let target = files.dir.path().join("real");
                fs::rename(&path, &target).unwrap();
                std::os::unix::fs::symlink(target, path).unwrap();
            }
            1 => fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap(),
            _ => fs::hard_link(path, files.dir.path().join("alias")).unwrap(),
        };
        assert!(files.source().lease(&Now::new(100)).is_err());
    }
}
#[test]
fn source_size_and_container_depth_limits_are_exact() {
    for count in [4096, 4097] {
        let raw = serde_json::to_vec(&vec![0; count]).unwrap();
        assert_eq!(strict_value(&raw).is_ok(), count == 4096);
        let obj: serde_json::Map<String, Value> =
            (0..count).map(|i| (format!("k{i}"), json!(0))).collect();
        assert_eq!(
            strict_value(&serde_json::to_vec(&obj).unwrap()).is_ok(),
            count == 4096
        );
    }
    for depth in [16, 17] {
        let raw = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        assert_eq!(strict_value(raw.as_bytes()).is_ok(), depth == 16);
    }
    assert!(strict_value(&vec![b' '; MAX_BUNDLE as usize + 1]).is_err());
}
#[test]
fn source_clock_rollback_and_post_read_expiry_deny() {
    let files = Files::new(&fixture());
    let source = files.source();
    let clock = Now::new(100);
    let lease = source.lease(&clock).unwrap();
    clock.set(120);
    lease.revalidate(&clock).unwrap();
    clock.set(119);
    assert_eq!(lease.revalidate(&clock), Err(SnapshotError::Clock));
    clock.set(200);
    assert_eq!(lease.revalidate(&clock), Err(SnapshotError::Window));
}
#[tokio::test]
async fn actual_journal_io_does_not_release_shared_owner_lease() {
    let files = Files::new(&fixture());
    let source = files.source();
    let clock = Now::new(100);
    let lease = source.lease(&clock).unwrap();
    assert!(private::lock(&files.dir.path().join(LOCK), true).is_err());
    let jdir = tempfile::tempdir_in("/private/tmp").unwrap();
    fs::set_permissions(jdir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal = crate::service_challenge_store::Journal::open(
        jdir.path(),
        crate::service_challenge_store::Limits::default(),
        &clock,
    )
    .await
    .unwrap();
    journal.stats(&clock).await.unwrap();
    lease.revalidate(&clock).unwrap();
    assert!(private::lock(&files.dir.path().join(LOCK), true).is_err());
    drop(lease);
    assert!(private::lock(&files.dir.path().join(LOCK), true).is_ok());
}
#[test]
fn registry_projection_golden() {
    let issuer = json!({"node_id":"node:fixture","key_id":"issuer:key","public_key_hex":"11".repeat(32),"algorithm":"ed25519","status":"active","not_before":90,"not_after":200,"revoked_at":null,"replaced_by":null,"production_authority":true});
    let holder = json!({"key_id":"holder:key","subject_id":"holder:fixture","public_key_hex":"22".repeat(32),"algorithm":"ed25519","status":"active","not_before":90,"not_after":200,"revoked_at":null});
    let bytes = projection(
        b"secs-service-registry-snapshot-v1\0",
        &json!({"generation":1,"owner_bundle_sha256":"bb".repeat(32),"issuer":issuer,"holder":holder}),
    );
    assert_eq!(
        hex(&hash(&bytes)),
        "30a1146ebf3a9857889062a05866311be918460ab3c3ecf0360616e1f21be0bd"
    );
}
#[test]
fn globally_aliased_key_id_is_rejected_even_with_distinct_material() {
    let mut v = fixture();
    v["holders"][0]["key_id"] = json!("issuer:key");
    assert!(parse_bundle(&canonical(&v)).is_err());
}
#[test]
fn full_public_request_bytes_are_preserved() {
    let files = Files::new(&fixture());
    let source = files.source();
    let clock = Now::new(100);
    let lease = source.lease(&clock).unwrap();
    let mut raw = challenge().request_bytes;
    raw.resize(2_097_152, b' ');
    let p = lease
        .prepare_request(&raw, "holder:fixture", "holder:key", 100, 60, &clock)
        .unwrap();
    assert_eq!(p.input.request, hash(&raw));
    raw.push(b' ');
    assert!(lease
        .prepare_request(&raw, "holder:fixture", "holder:key", 100, 60, &clock)
        .is_err());
}
#[test]
fn final_clock_is_sampled_after_reread_and_preimage_validation() {
    use std::sync::Mutex;
    struct Sequence(Mutex<std::collections::VecDeque<u64>>);
    impl Clock for Sequence {
        fn now(&self) -> u64 {
            self.0.lock().unwrap().pop_front().unwrap_or(160)
        }
    }
    let files = Files::new(&fixture());
    let source = files.source();
    let clock = Now::new(100);
    let lease = source.lease(&clock).unwrap();
    let delayed = Sequence(Mutex::new([100, 100, 160].into()));
    assert!(matches!(
        prepare(&lease, &delayed),
        Err(SnapshotError::Window)
    ));
}
#[tokio::test]
async fn missing_ports_never_export_or_leave_live_journal_rows() {
    let files = Files::new(&fixture());
    let source = files.source();
    let clock = Now::new(100);
    let lease = source.lease(&clock).unwrap();
    let dir = tempfile::tempdir_in("/private/tmp").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let journal = crate::service_challenge_store::Journal::open(
        dir.path(),
        crate::service_challenge_store::Limits::default(),
        &clock,
    )
    .await
    .unwrap();
    let mut guard = DenyingOwnerGuard {
        lease: &lease,
        clock: &clock,
    };
    assert!(journal
        .persist_pending(&challenge(), &[], &[], &mut guard, &clock)
        .await
        .is_err());
    assert_eq!(journal.stats(&clock).await.unwrap().pending, 0);
    assert_eq!(
        lease.require_qualified_ports(&clock),
        Err(SnapshotError::MissingQualifiedWalletAndContextIssuer)
    );
}
#[tokio::test]
async fn retained_lease_rechecks_clock_after_actual_sqlite_close() {
    use std::sync::Arc;
    // Explicit test-only storage seam: this does not stand in for qualified
    // Wallet/evidence/context authority. Production DenyingOwnerGuard never allows.
    struct SourceOnly<'a, 's> {
        lease: &'a OwnerLease<'s>,
        clock: &'a Now,
    }
    impl AuthorityGuard for SourceOnly<'_, '_> {
        fn revalidate(&mut self, _: GuardInput<'_>) -> Result<(), JournalError> {
            self.lease
                .revalidate(self.clock)
                .map(|_| ())
                .map_err(|_| JournalError::Rejected)
        }
    }
    let files = Files::new(&fixture());
    let source = files.source();
    let clock = Arc::new(Now::new(100));
    let lease = source.lease(clock.as_ref()).unwrap();
    let dir = tempfile::tempdir_in("/private/tmp").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut journal = crate::service_challenge_store::Journal::open(
        dir.path(),
        crate::service_challenge_store::Limits::default(),
        clock.as_ref(),
    )
    .await
    .unwrap();
    let later = clock.clone();
    journal.after_close_for_test(move || later.set(200));
    let mut guard = SourceOnly {
        lease: &lease,
        clock: clock.as_ref(),
    };
    assert!(journal
        .persist_pending(&challenge(), &[], &[], &mut guard, clock.as_ref())
        .await
        .is_err());
    assert!(private::lock(&files.dir.path().join(LOCK), true).is_err());
    assert_eq!(journal.stats(clock.as_ref()).await.unwrap().pending, 0);
}
#[test]
fn initial_capture_is_retained_when_challenge_issue_time_is_later() {
    let files = Files::new(&fixture());
    let source = files.source();
    let clock = Now::new(100);
    let lease = source.lease(&clock).unwrap();
    clock.set(101);
    let prepared = lease
        .prepare_request(
            &challenge().request_bytes,
            "holder:fixture",
            "holder:key",
            101,
            59,
            &clock,
        )
        .unwrap();
    assert_eq!(prepared.evidence().bindings().evidence_observed_at, 100);
    assert_eq!(prepared.evidence().bindings().evidence_valid_until, 160);
}
#[test]
fn public_origin_positive_does_not_satisfy_derived_owner_digests() {
    let files = Files::new(&fixture());
    let source = files.source();
    let clock = Now::new(100);
    let lease = source.lease(&clock).unwrap();
    let c = challenge();
    lease.verify_challenge_origin(&c, &clock).unwrap();
    assert_eq!(
        lease.require_complete_authority(&c, &clock),
        Err(SnapshotError::Changed)
    );
}
#[test]
fn optional_dto_objects_are_closed_too() {
    for case in 0..2 {
        let mut v = fixture();
        if case == 0 {
            v["descriptors"][0]["output_profile"] = json!({"schema_id":"fixture.output.v1","max_output_bytes":100,"max_execution_response_bytes":200,"unexpected":1});
        } else {
            v["descriptors"][0]["disclosure_policy"]["permissions"] = json!([{"class":"wallet_identity","surface":"log","representation":"redacted_digest","unexpected":1}]);
        }
        assert!(parse_bundle(&canonical(&v)).is_err());
    }
}
#[test]
fn actual_file_read_has_hard_bound_and_lock_replacement_denies() {
    let files = Files::new(&fixture());
    let source = files.source();
    let clock = Now::new(100);
    let lease = source.lease(&clock).unwrap();
    fs::write(
        files.dir.path().join(FILE),
        vec![b' '; MAX_BUNDLE as usize + 1],
    )
    .unwrap();
    assert!(lease.revalidate(&clock).is_err());
    let files = Files::new(&fixture());
    let source = files.source();
    let lease = source.lease(&clock).unwrap();
    fs::rename(
        files.dir.path().join(LOCK),
        files.dir.path().join("old-lock"),
    )
    .unwrap();
    let _new = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(files.dir.path().join(LOCK))
        .unwrap();
    assert!(matches!(
        lease.revalidate(&clock),
        Err(SnapshotError::Changed)
    ));
}

#[test]
fn epoch_zero_native_owner_windows_prepare_without_waiving_ports() {
    let mut v = fixture();
    v["valid_not_before"] = json!(0);
    v["issuers"][0]["not_before"] = json!(0);
    v["holders"][0]["not_before"] = json!(0);
    v["permissions"][0]["not_before"] = json!(0);
    v["receiver_policy"]["not_before"] = json!(0);
    v["receiver_policy"]["principals"][0]["not_before"] = json!(0);
    v["receiver_policy"]["rules"][0]["not_before"] = json!(0);
    let files = Files::new(&v);
    let source = files.source();
    let clock = Now::new(100);
    let lease = source.lease(&clock).unwrap();
    let prepared = prepare(&lease, &clock).unwrap();
    assert_eq!(prepared.evidence().bindings().evidence_valid_not_before, 0);
    assert_eq!(prepared.evidence().bindings().evidence_observed_at, 100);
    assert_eq!(
        lease.require_qualified_ports(&clock),
        Err(SnapshotError::MissingQualifiedWalletAndContextIssuer)
    );
}
#[test]
fn evidence_observed_before_key_validity_is_a_window_error() {
    let mut v = fixture();
    v["issuers"][0]["not_before"] = json!(95);
    let files = Files::new(&v);
    let source = files.source();
    let clock = Now::new(90);
    let lease = source.lease(&clock).unwrap();
    clock.set(100);
    assert!(matches!(
        prepare(&lease, &clock),
        Err(SnapshotError::Window)
    ));
}

#[test]
fn strict_metadata_number_profiles_do_not_depend_on_serde_features() {
    for raw in [
        b"0".as_slice(),
        b"9007199254740991",
        br#"{"n":0,"tag":"$serde_json::private::Number"}"#,
        br#"[0,9007199254740991,"prefix $serde_json::private::Number suffix"]"#,
    ] {
        assert!(strict_value(raw).is_ok(), "valid metadata: {:?}", raw);
    }
    let mut accepted = Vec::new();
    for value in [
        "1.0",
        "1e0",
        "1.000",
        "-0",
        "-0.0",
        "-1",
        "9007199254740992",
        "18446744073709551616",
    ] {
        for raw in [
            value.to_owned(),
            format!("{{\"n\":{value}}}"),
            format!("[{value}]"),
            format!("{{\"n\":[{{\"value\":{value}}}]}}"),
        ] {
            if strict_value(raw.as_bytes()).is_ok() {
                accepted.push(raw);
            }
        }
    }
    for raw in [
        br#"{"$serde_json::private::Number":"1.0"}"#.as_slice(),
        br#"{"nested":{"$serde_json::private::Number":"1"}}"#,
        br#"[{"$serde_json::private::Number":"1e0"}]"#,
        br#"{"\u0024serde_json::private::Number":"-0"}"#,
    ] {
        if strict_value(raw).is_ok() {
            accepted.push(String::from_utf8(raw.to_vec()).unwrap());
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted forbidden metadata: {accepted:?}"
    );
}

#[test]
fn public_owner_lower_bound_rejects_negative_zero_and_noninteger_lexemes() {
    let raw = String::from_utf8(canonical(&fixture())).unwrap();
    assert!(parse_bundle(raw.as_bytes()).is_ok());
    let zero = raw.replacen("\"valid_not_before\":90", "\"valid_not_before\":0", 1);
    assert_ne!(zero, raw);
    assert!(parse_bundle(zero.as_bytes()).is_ok());
    let mut accepted = Vec::new();
    for value in [
        "-0",
        "-0.0",
        "1.0",
        "1e0",
        "9007199254740992",
        "18446744073709551616",
    ] {
        let changed = raw.replacen(
            "\"valid_not_before\":90",
            &format!("\"valid_not_before\":{value}"),
            1,
        );
        assert_ne!(changed, raw);
        if parse_bundle(changed.as_bytes()).is_ok() {
            accepted.push(value);
        }
    }
    assert!(
        accepted.is_empty(),
        "accepted owner lower-bound lexemes: {accepted:?}"
    );
}

#[test]
fn pure_body_reuse_preserves_v1_outer_schema_generation_and_nonempty_holder_rule() {
    let value = fixture();
    let original = parse_bundle(&canonical(&value)).unwrap();
    assert_eq!(original.generation, 1);
    assert_eq!((original.start, original.end), (90, 200));
    let mut policy = value.clone();
    policy.as_object_mut().unwrap().remove("schema");
    policy.as_object_mut().unwrap().remove("generation");
    validate_unqualified_policy_body(policy.clone(), false).unwrap();
    policy["holders"] = json!([]);
    assert!(validate_unqualified_policy_body(policy.clone(), false).is_err());
    validate_unqualified_policy_body(policy, true).unwrap();
    let mut old = value.clone();
    old["holders"] = json!([]);
    assert!(parse_bundle(&canonical(&old)).is_err());
    for replacement in [
        json!("secs.service-owner-bundle.v2"),
        json!("secs.wallet-native-target-policy.v1"),
    ] {
        let mut invalid = value.clone();
        invalid["schema"] = replacement;
        assert!(parse_bundle(&canonical(&invalid)).is_err());
    }
    for generation in [json!(0), json!(MAX_SAFE_TIME + 1)] {
        let mut invalid = value.clone();
        invalid["generation"] = generation;
        assert!(parse_bundle(&canonical(&invalid)).is_err());
    }
    let mut invalid = value.clone();
    invalid["wallet_current"] = json!({});
    assert!(parse_bundle(&canonical(&invalid)).is_err());
    let mut missing = value;
    missing["holders"][0]
        .as_object_mut()
        .unwrap()
        .remove("revoked_at");
    assert!(parse_bundle(&canonical(&missing)).is_err());
}
