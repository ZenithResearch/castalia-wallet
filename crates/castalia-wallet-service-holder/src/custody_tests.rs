use super::custody::*;
use std::{fs, os::unix::fs::PermissionsExt, path::Path};
fn root() -> tempfile::TempDir {
    let d = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}
fn spec() -> NewServiceIdentity {
    NewServiceIdentity {
        application: Application::Runtime,
        subject_id: "service:disposable-test".into(),
        not_before: 0,
        not_after: 4_000_000_000,
    }
}
#[test]
fn real_create_restart_and_rotation_need_explicit_cleanup() {
    let d = root();
    let store = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    let a = store.public_identity().unwrap();
    assert_eq!(a.state, IdentityState::Unconfigured);
    assert_eq!(a.key_generation, 1);
    assert_eq!(
        fs::metadata(d.path().join("states/s0000000000000001/seed.raw"))
            .unwrap()
            .len(),
        32
    );
    let binding = store.binding();
    drop(store);
    let store = ServiceIdentityStore::open(d.path(), binding).unwrap();
    assert_eq!(store.public_identity().unwrap(), a);
    let b = store.rotate(a.expected(), 0, 4_000_000_000).unwrap();
    assert_eq!(b.subject_id, a.subject_id);
    assert_ne!(b.public_key_hex, a.public_key_hex);
    assert_eq!(b.key_generation, 2);
    assert_eq!(b.state_revision, 2);
    assert_eq!(
        store.rotate(b.expected(), 0, 4_000_000_000).unwrap_err(),
        CustodyError::Capacity
    );
    store.cleanup_unreferenced(b.expected()).unwrap();
    let c = store.revoke(b.expected()).unwrap();
    assert_eq!(c.state, IdentityState::Revoked);
    assert_eq!(
        store.rotate(c.expected(), 0, 4_000_000_000).unwrap_err(),
        CustodyError::Revoked
    );
    assert!(!d.path().join("states/s0000000000000003/seed.raw").exists());
}
#[test]
fn stale_cas_and_seed_mismatch_deny() {
    let d = root();
    let s = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    let a = s.public_identity().unwrap();
    s.rotate(a.expected(), 0, 4_000_000_000).unwrap();
    assert_eq!(s.revoke(a.expected()).unwrap_err(), CustodyError::Changed);
    fs::write(
        d.path().join("states/s0000000000000002/seed.raw"),
        [9u8; 32],
    )
    .unwrap();
    assert_eq!(s.public_identity().unwrap_err(), CustodyError::KeyMismatch);
}
#[test]
fn uncertain_initial_ack_recovers_without_saved_binding() {
    let d = root();
    let s = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    let a = s.public_identity().unwrap();
    drop(s);
    let recovered = ServiceIdentityStore::recover_initialization(d.path(), spec()).unwrap();
    assert_eq!(recovered.public_identity().unwrap(), a);
    assert!(ServiceIdentityStore::inspect_initialization(
        &OwnerConfiguredRoot::open(d.path()).unwrap(),
        spec()
    )
    .is_err());
}
fn owner_input(s: &PublicServiceIdentity) -> Vec<u8> {
    let mut v = crate::tests::input();
    v["generation"] = (s.state_revision + 1).into();
    v["holder"]["generation"] = s.key_generation.into();
    v["holder"]["key_id"] = s.key_id.clone().into();
    v["holder"]["subject_id"] = s.subject_id.clone().into();
    v["holder"]["public_key_hex"] = s.public_key_hex.clone().into();
    v["holder"]["not_before"] = s.not_before.into();
    v["holder"]["not_after"] = s.not_after.into();
    for k in ["principals", "rules"] {
        for entry in v["delegation_policy"][k].as_array_mut().unwrap() {
            entry["key_id"] = s.key_id.clone().into();
            entry["subject_id"] = s.subject_id.clone().into();
        }
    }
    crate::canonical(&v)
}
pub(crate) fn assert_legacy_ports_deny(p: crate::PreparedServiceHolderProof) {
    super::custody::TEST_NOW.with(|v| v.set(Some(100)));
    let d = root();
    let mut cfg = spec();
    cfg.not_after = 180;
    let s = ServiceIdentityStore::create(d.path(), cfg).unwrap();
    let a = s.public_identity().unwrap();
    let raw = owner_input(&a);
    let b = s.configure(a.expected(), &raw).unwrap();
    let h = s.open_identity(b.expected()).unwrap();
    let o = crate::ValidatedWalletOwnerInput::parse(&raw).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let mut c = crate::tests::challenge(&v);
    c.claims.holder_key_id = b.key_id;
    c.claims.holder_subject_id = b.subject_id;
    c.claims.holder_public_key_fingerprint = crate::hex32(&b.public_key_sha256).unwrap();
    crate::tests::resign(&mut c);
    assert!(matches!(
        h.prepare_service_challenge(&o, &c, 100),
        Err(crate::Error::MissingQualifiedCustody)
    ));
    assert!(matches!(
        h.present_prepared_service_challenge(p),
        Err(crate::Error::MissingQualifiedCustody)
    ));
    super::custody::TEST_NOW.with(|v| v.set(None));
}
struct Time;
impl Time {
    fn at(n: u64) -> Self {
        TEST_NOW.with(|v| v.set(Some(n)));
        Self
    }
}
impl Drop for Time {
    fn drop(&mut self) {
        TEST_NOW.with(|v| v.set(None));
        TEST_FAIL.with(|v| v.set(None));
        TEST_ACTION.with(|v| *v.borrow_mut() = None);
    }
}
#[test]
fn configure_exact_owner_binding_rotate_unconfigured_and_terminal_revoke() {
    let _t = Time::at(100);
    let d = root();
    let mut cfg = spec();
    cfg.not_after = 180;
    let s = ServiceIdentityStore::create(d.path(), cfg).unwrap();
    let a = s.public_identity().unwrap();
    assert!(matches!(
        s.open_identity(a.expected()),
        Err(CustodyError::Unconfigured)
    ));
    let raw = owner_input(&a);
    let b = s.configure(a.expected(), &raw).unwrap();
    let h = s.open_identity(b.expected()).unwrap();
    assert!(h.custody.validate().is_ok());
    s.cleanup_unreferenced(b.expected()).unwrap();
    assert_eq!(h.custody.validate(), Err(CustodyError::Changed));
    let h = s.open_identity(b.expected()).unwrap();
    let c = s.rotate(b.expected(), 0, 180).unwrap();
    assert_eq!(h.custody.validate(), Err(CustodyError::Changed));
    assert_eq!(s.configure(c.expected(), &raw), Err(CustodyError::Capacity));
    s.cleanup_unreferenced(c.expected()).unwrap();
    assert_eq!(
        s.configure(c.expected(), &raw),
        Err(CustodyError::KeyMismatch)
    );
    let d = s.configure(c.expected(), &owner_input(&c)).unwrap();
    s.cleanup_unreferenced(d.expected()).unwrap();
    let h = s.open_identity(d.expected()).unwrap();
    let e = s.revoke(d.expected()).unwrap();
    assert_eq!(h.custody.validate(), Err(CustodyError::Changed));
    assert_eq!(s.configure(e.expected(), &raw), Err(CustodyError::Revoked));
}
#[test]
fn same_current_reload_and_reconcile_invalidate_handles() {
    let _t = Time::at(100);
    let d = root();
    let mut cfg = spec();
    cfg.not_after = 180;
    let s = ServiceIdentityStore::create(d.path(), cfg).unwrap();
    let a = s.public_identity().unwrap();
    let b = s.configure(a.expected(), &owner_input(&a)).unwrap();
    let h = s.open_identity(b.expected()).unwrap();
    let second = ServiceIdentityStore::open(d.path(), s.binding()).unwrap();
    assert_eq!(h.custody.validate(), Err(CustodyError::Changed));
    let h = second.open_identity(b.expected()).unwrap();
    assert_eq!(s.reconcile_current().unwrap(), b);
    assert_eq!(h.custody.validate(), Err(CustodyError::Changed));
}
#[test]
fn all_initial_publication_faults_recover_or_require_explicit_abandon() {
    let _t = Time::at(100);
    for point in [
        "before_staging",
        "before_revision",
        "after_revision",
        "after_clock",
        "after_current",
        "final_clock",
    ] {
        let d = root();
        TEST_FAIL.with(|v| v.set(Some(point)));
        assert!(matches!(
            ServiceIdentityStore::create(d.path(), spec()),
            Err(CustodyError::PublicationUncertain)
        ));
        TEST_FAIL.with(|v| v.set(None));
        if d.path().join("CURRENT").exists() {
            let s = ServiceIdentityStore::recover_initialization(d.path(), spec()).unwrap();
            assert_eq!(s.public_identity().unwrap().state_revision, 1);
            assert!(ServiceIdentityStore::inspect_initialization(
                &OwnerConfiguredRoot::open(d.path()).unwrap(),
                spec()
            )
            .is_err());
        } else {
            assert!(ServiceIdentityStore::recover_initialization(d.path(), spec()).is_err());
            assert!(ServiceIdentityStore::create(d.path(), spec()).is_err());
            let root = OwnerConfiguredRoot::open(d.path()).unwrap();
            let inspection = ServiceIdentityStore::inspect_initialization(&root, spec()).unwrap();
            assert!(matches!(
                ServiceIdentityStore::inspect_initialization(&root, spec()),
                Err(CustodyError::Busy)
            ));
            inspection.abandon().unwrap();
            let s = ServiceIdentityStore::create(d.path(), spec()).unwrap();
            assert_eq!(s.public_identity().unwrap().state_revision, 1);
        }
    }
}
#[test]
fn mutation_uncertainty_selects_only_actual_current_and_blocks_until_reconciled() {
    let _t = Time::at(100);
    for point in [
        "before_staging",
        "before_revision",
        "after_revision",
        "after_clock",
        "after_current",
        "final_clock",
    ] {
        let d = root();
        let s = ServiceIdentityStore::create(d.path(), spec()).unwrap();
        let a = s.public_identity().unwrap();
        TEST_FAIL.with(|v| v.set(Some(point)));
        assert_eq!(
            s.rotate(a.expected(), 0, 4_000_000_000),
            Err(CustodyError::PublicationUncertain)
        );
        assert_eq!(s.public_identity(), Err(CustodyError::PublicationUncertain));
        TEST_FAIL.with(|v| v.set(None));
        let b = s.reconcile_current().unwrap();
        assert_eq!(
            b.state_revision,
            if ["after_current", "final_clock"].contains(&point) {
                2
            } else {
                1
            }
        );
        s.cleanup_unreferenced(b.expected()).unwrap();
        s.rotate(b.expected(), 0, 4_000_000_000).unwrap();
    }
}
#[test]
fn whole_clock_floor_and_exclusive_end_rechecked_after_io() {
    let _t = Time::at(100);
    let d = root();
    let mut cfg = spec();
    cfg.not_after = 180;
    let s = ServiceIdentityStore::create(d.path(), cfg).unwrap();
    let a = s.public_identity().unwrap();
    let b = s.configure(a.expected(), &owner_input(&a)).unwrap();
    let h = s.open_identity(b.expected()).unwrap();
    TEST_NOW.with(|v| v.set(Some(99)));
    assert_eq!(s.public_identity(), Err(CustodyError::Clock));
    TEST_NOW.with(|v| v.set(Some(100)));
    TEST_ACTION.with(|v| {
        *v.borrow_mut() = Some(Box::new(|step| {
            if step == "after_load" {
                TEST_NOW.with(|v| v.set(Some(180)))
            }
        }))
    });
    assert_eq!(h.custody.validate(), Err(CustodyError::Expired));
    TEST_ACTION.with(|v| *v.borrow_mut() = None);
    TEST_NOW.with(|v| v.set(Some(179)));
    assert_eq!(s.public_identity(), Err(CustodyError::Clock));
}
#[test]
fn invalid_metadata_and_exact_seed_lengths_deny_without_fallback() {
    let _t = Time::at(100);
    for len in [31, 33] {
        let d = root();
        let s = ServiceIdentityStore::create(d.path(), spec()).unwrap();
        fs::write(
            d.path().join("states/s0000000000000001/seed.raw"),
            vec![7u8; len],
        )
        .unwrap();
        assert!(s.public_identity().is_err());
    }
    let d = root();
    let s = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    let original = fs::read(d.path().join("CURRENT")).unwrap();
    for suffix in [b" ".as_slice(), b"\n", b"{}"] {
        let mut b = original.clone();
        b.extend(suffix);
        fs::write(d.path().join("CURRENT"), b).unwrap();
        assert_eq!(s.public_identity(), Err(CustodyError::Corrupt));
    }
}
#[test]
fn malformed_number_grammar_is_closed_under_hostile_serde_features() {
    for number in [
        "-0",
        "1.0",
        "1e0",
        "9007199254740992",
        "18446744073709551616",
        "{\"$serde_json::private::Number\":\"1\"}",
    ] {
        let _t = Time::at(100);
        let d = root();
        let s = ServiceIdentityStore::create(d.path(), spec()).unwrap();
        let p = d.path().join("CLOCK");
        let raw = fs::read_to_string(&p)
            .unwrap()
            .replace("\"observed_at\":100", &format!("\"observed_at\":{number}"));
        fs::write(p, raw).unwrap();
        assert!(s.public_identity().is_err(), "accepted {number}");
    }
}
#[test]
fn no_implicit_recreation_or_abandonment_of_corrupt_current() {
    let d = root();
    let s = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    fs::write(d.path().join("CURRENT"), b"broken").unwrap();
    assert!(s.reconcile_current().is_err());
    let root = OwnerConfiguredRoot::open(d.path()).unwrap();
    assert!(ServiceIdentityStore::inspect_initialization(&root, spec()).is_err());
    assert!(ServiceIdentityStore::recover_initialization(d.path(), spec()).is_err());
    assert!(ServiceIdentityStore::create(d.path(), spec()).is_err());
}
#[test]
fn unsupported_descriptor_obligations_and_owner_aliases_are_not_optional() {
    let _t = Time::at(100);
    let d = root();
    let mut cfg = spec();
    cfg.not_after = 180;
    let s = ServiceIdentityStore::create(d.path(), cfg).unwrap();
    let a = s.public_identity().unwrap();
    let raw = owner_input(&a);
    let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    v["generation"] = 1.into();
    assert_eq!(
        s.configure(a.expected(), &crate::canonical(&v)),
        Err(CustodyError::KeyMismatch)
    );
    let mut raw = String::from_utf8(raw).unwrap();
    raw.insert_str(1, "\"generation\":2,");
    assert_eq!(
        s.configure(a.expected(), raw.as_bytes()),
        Err(CustodyError::InvalidInput)
    );
}
#[test]
fn stale_startup_pin_and_metadata_key_substitution_are_rejected() {
    let d = root();
    let s = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    let mut binding = s.binding();
    binding.minimum_revision = 2;
    assert!(matches!(
        ServiceIdentityStore::open(d.path(), binding),
        Err(CustodyError::Changed)
    ));
    let d2 = root();
    let other = ServiceIdentityStore::create(d2.path(), spec()).unwrap();
    assert!(matches!(
        ServiceIdentityStore::open(d2.path(), s.binding()),
        Err(CustodyError::Changed)
    ));
    assert_ne!(
        s.public_identity().unwrap().public_key_hex,
        other.public_identity().unwrap().public_key_hex
    );
}
#[test]
fn administrative_reconcile_and_cleanup_publish_durable_clock_floor() {
    let _t = Time::at(100);
    let d = root();
    let s = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    TEST_NOW.with(|v| v.set(Some(105)));
    let a = s.reconcile_current().unwrap();
    let c: serde_json::Value =
        serde_json::from_slice(&fs::read(d.path().join("CLOCK")).unwrap()).unwrap();
    assert_eq!(c["observed_at"], 105);
    TEST_NOW.with(|v| v.set(Some(106)));
    s.cleanup_unreferenced(a.expected()).unwrap();
    let c: serde_json::Value =
        serde_json::from_slice(&fs::read(d.path().join("CLOCK")).unwrap()).unwrap();
    assert_eq!(c["observed_at"], 106);
}
#[test]
fn every_nonempty_descriptor_obligation_blocks_configuration() {
    let _t = Time::at(100);
    let d = root();
    let mut cfg = spec();
    cfg.not_after = 180;
    let s = ServiceIdentityStore::create(d.path(), cfg).unwrap();
    let a = s.public_identity().unwrap();
    for field in [
        "required_credentials",
        "required_capabilities",
        "accepted_evidence",
        "required_authority_mode",
    ] {
        let mut v: serde_json::Value = serde_json::from_slice(&owner_input(&a)).unwrap();
        v["descriptors"][0][field] = if field == "required_authority_mode" {
            serde_json::json!("signed_source")
        } else {
            serde_json::json!(["fixture.required"])
        };
        let descriptor = crate::native_descriptor(&v["descriptors"][0]).unwrap();
        v["delegation_policy"]["descriptors"][0]["fingerprint"] = descriptor
            .authorization_fingerprint()
            .trim_start_matches("descriptor:sha256:")
            .into();
        assert_eq!(
            s.configure(a.expected(), &crate::canonical(&v)),
            Err(CustodyError::UnsupportedRequiredEvidence)
        );
    }
}
#[test]
fn crash_child() {
    let Ok(path) = std::env::var("CUSTODY_DISPOSABLE_TEST_ROOT") else {
        return;
    };
    let point = std::env::var("CUSTODY_DISPOSABLE_CRASH_POINT").unwrap();
    let _t = Time::at(100);
    TEST_ACTION.with(|v| {
        *v.borrow_mut() = Some(Box::new(move |step| {
            if step == point {
                std::process::exit(86)
            }
        }))
    });
    let _ = ServiceIdentityStore::create(Path::new(&path), spec());
    panic!("test crash point not reached");
}
#[test]
fn process_exit_releases_lock_and_restart_never_activates_orphan() {
    for point in [
        "before_revision",
        "after_revision",
        "after_clock",
        "after_current",
    ] {
        let d = root();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "custody_tests::crash_child", "--nocapture"])
            .env("CUSTODY_DISPOSABLE_TEST_ROOT", d.path())
            .env("CUSTODY_DISPOSABLE_CRASH_POINT", point)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(86));
        if point == "after_current" {
            let s = ServiceIdentityStore::recover_initialization(d.path(), spec()).unwrap();
            assert_eq!(s.public_identity().unwrap().key_generation, 1);
        } else {
            assert!(ServiceIdentityStore::recover_initialization(d.path(), spec()).is_err());
            let root = OwnerConfiguredRoot::open(d.path()).unwrap();
            ServiceIdentityStore::inspect_initialization(&root, spec())
                .unwrap()
                .abandon()
                .unwrap();
            assert!(!d.path().join("CURRENT").exists());
        }
    }
}
#[test]
fn two_cooperative_writers_cannot_both_commit_same_cas() {
    let d = root();
    let s = std::sync::Arc::new(ServiceIdentityStore::create(d.path(), spec()).unwrap());
    let e = s.public_identity().unwrap().expected();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let jobs: Vec<_> = (0..2)
        .map(|_| {
            let s = s.clone();
            let e = e.clone();
            let b = barrier.clone();
            std::thread::spawn(move || {
                b.wait();
                s.rotate(e, 0, 4_000_000_000)
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(results
        .iter()
        .any(|r| matches!(r, Err(CustodyError::Busy | CustodyError::Changed))));
}
#[test]
fn final_publication_clock_failure_is_uncertain_and_invalidates_handles() {
    let _t = Time::at(100);
    let d = root();
    let mut cfg = spec();
    cfg.not_after = 180;
    TEST_ACTION.with(|v| {
        *v.borrow_mut() = Some(Box::new(|step| {
            if step == "final_clock" {
                TEST_NOW.with(|v| v.set(Some(180)))
            }
        }))
    });
    assert!(matches!(
        ServiceIdentityStore::create(d.path(), cfg.clone()),
        Err(CustodyError::PublicationUncertain)
    ));
    TEST_ACTION.with(|v| *v.borrow_mut() = None);
    let s = ServiceIdentityStore::recover_initialization(d.path(), cfg).unwrap();
    assert_eq!(s.public_identity().unwrap().not_after, 180);
    assert!(matches!(
        s.open_identity(s.public_identity().unwrap().expected()),
        Err(CustodyError::Unconfigured)
    ));
}
#[test]
fn retained_root_lock_and_conditional_file_layout_are_checked() {
    use std::os::unix::fs::symlink;
    let d = root();
    let s = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    let a = s.public_identity().unwrap();
    let p = d.path().join("states/s0000000000000001/owner-input.json");
    fs::write(&p, b"{}").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(s.public_identity(), Err(CustodyError::Corrupt));
    fs::remove_file(p).unwrap();
    let old = root();
    fs::rename(d.path().join("custody.lock"), old.path().join("old-lock")).unwrap();
    symlink(old.path().join("old-lock"), d.path().join("custody.lock")).unwrap();
    assert!(s.cleanup_unreferenced(a.expected()).is_err());
    assert!(d.path().join("CURRENT").exists());
}
#[test]
fn safe_lock_replacement_between_operations_invalidates_existing_store() {
    let d = root();
    let s = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    let away = root();
    fs::rename(d.path().join("custody.lock"), away.path().join("old")).unwrap();
    let lock = d.path().join("custody.lock");
    fs::write(&lock, []).unwrap();
    fs::set_permissions(lock, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(s.public_identity(), Err(CustodyError::UnsafeStorage));
    assert!(s.reconcile_current().is_err());
}
#[test]
fn current_is_rechecked_before_publication_without_overwriting_a_changed_pointer() {
    let _t = Time::at(100);
    let d = root();
    let s = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    let a = s.public_identity().unwrap();
    let path = d.path().join("CURRENT");
    let altered = path.clone();
    TEST_ACTION.with(|v| {
        *v.borrow_mut() = Some(Box::new(move |step| {
            if step == "before_revision" {
                fs::write(&altered, b"changed").unwrap()
            }
        }))
    });
    assert_eq!(
        s.rotate(a.expected(), 0, 4_000_000_000),
        Err(CustodyError::PublicationUncertain)
    );
    assert_eq!(fs::read(path).unwrap(), b"changed");
}
#[test]
fn accepted_public_state_vectors_preserve_exact_metadata_and_pointer_hashes() {
    for (raw, pointer) in [
        (
            include_bytes!("../tests/custody-vectors/state-1.json").as_slice(),
            include_bytes!("../tests/custody-vectors/current-1.json").as_slice(),
        ),
        (
            include_bytes!("../tests/custody-vectors/state-2.json").as_slice(),
            include_bytes!("../tests/custody-vectors/current-2.json").as_slice(),
        ),
        (
            include_bytes!("../tests/custody-vectors/state-3.json").as_slice(),
            include_bytes!("../tests/custody-vectors/current-3.json").as_slice(),
        ),
        (
            include_bytes!("../tests/custody-vectors/state-4.json").as_slice(),
            include_bytes!("../tests/custody-vectors/current-4.json").as_slice(),
        ),
        (
            include_bytes!("../tests/custody-vectors/state-5.json").as_slice(),
            include_bytes!("../tests/custody-vectors/current-5.json").as_slice(),
        ),
    ] {
        let expected = super::custody::check_public_state_vector(raw).unwrap();
        let p: serde_json::Value = serde_json::from_slice(pointer).unwrap();
        assert_eq!(
            expected.state_revision,
            p["state_revision"].as_u64().unwrap()
        );
        assert_eq!(expected.state_sha256, p["state_sha256"].as_str().unwrap());
        let mut v: serde_json::Value = serde_json::from_slice(raw).unwrap();
        v.as_object_mut().unwrap().remove("revoked_at");
        assert!(super::custody::check_public_state_vector(&crate::canonical(&v)).is_err());
    }
}
#[test]
fn native_clock_floor_survives_store_lifetime_and_does_not_reset_on_denial() {
    use std::sync::atomic::AtomicU64;
    let last = AtomicU64::new(0);
    assert_eq!(super::custody::monotonic_clock(&last, 100), Ok(100));
    assert_eq!(
        super::custody::monotonic_clock(&last, 0),
        Err(CustodyError::Clock)
    );
    assert_eq!(
        super::custody::monotonic_clock(&last, 99),
        Err(CustodyError::Clock)
    );
    assert_eq!(super::custody::monotonic_clock(&last, 100), Ok(100));
    assert_eq!(super::custody::monotonic_clock(&last, 101), Ok(101));
    assert_eq!(
        super::custody::monotonic_clock(&last, 100),
        Err(CustodyError::Clock)
    );
}

#[test]
fn administration_session_mutates_on_one_lease_and_retains_exclusion() {
    let _time = Time::at(100);
    let d = root();
    let mut cfg = spec();
    cfg.not_after = 180;
    let store = ServiceIdentityStore::create(d.path(), cfg).unwrap();
    let before = store.public_identity().unwrap();
    let mut session = store.begin_administration().unwrap();
    assert_eq!(store.public_identity(), Err(CustodyError::Busy));
    assert!(matches!(
        store.begin_administration(),
        Err(CustodyError::Busy)
    ));
    let lock = session
        .public_observation()
        .unwrap()
        .metadata()
        .lock_identity();
    let configured = session
        .configure(before.expected(), &owner_input(&before))
        .unwrap();
    assert_eq!(configured.state, IdentityState::Active);
    {
        let view = session.public_observation().unwrap();
        assert_eq!(view.metadata().state_revision(), configured.state_revision);
        assert_eq!(view.metadata().lock_identity(), lock);
        assert!(view.metadata().owner_input_bytes().is_some());
        view.revalidate().unwrap();
    }
    TEST_NOW.with(|v| v.set(Some(101)));
    assert_eq!(session.reconcile_current().unwrap(), configured);
    let view = session.public_observation().unwrap();
    let clock: serde_json::Value = serde_json::from_slice(view.metadata().clock_bytes()).unwrap();
    assert_eq!(clock["observed_at"], 101);
    drop(view);
    drop(session);
    assert_eq!(store.public_identity().unwrap(), configured);
}
#[test]
fn administration_session_reconcile_invalidates_handles_and_stale_cas() {
    let _time = Time::at(100);
    let d = root();
    let mut cfg = spec();
    cfg.not_after = 180;
    let store = ServiceIdentityStore::create(d.path(), cfg).unwrap();
    let a = store.public_identity().unwrap();
    let b = store.configure(a.expected(), &owner_input(&a)).unwrap();
    let handle = store.open_identity(b.expected()).unwrap();
    let mut session = store.begin_administration().unwrap();
    assert_eq!(session.revoke(a.expected()), Err(CustodyError::Changed));
    assert_eq!(session.reconcile_current().unwrap(), b);
    drop(session);
    assert_eq!(handle.custody.validate(), Err(CustodyError::Changed));
}
#[test]
fn retained_administration_recovers_actual_uncertain_current_without_relocking() {
    let _time = Time::at(100);
    for point in [
        "before_staging",
        "after_revision",
        "after_current",
        "final_clock",
    ] {
        let d = root();
        let store = ServiceIdentityStore::create(d.path(), spec()).unwrap();
        let old = store.public_identity().unwrap();
        let mut session = store.begin_administration().unwrap();
        TEST_FAIL.with(|v| v.set(Some(point)));
        assert_eq!(
            session.rotate(old.expected(), 0, 4_000_000_000),
            Err(CustodyError::PublicationUncertain)
        );
        assert_eq!(
            session.public_identity(),
            Err(CustodyError::PublicationUncertain)
        );
        assert!(session.public_observation().is_err());
        TEST_FAIL.with(|v| v.set(None));
        let actual = session.reconcile_current().unwrap();
        assert_eq!(
            actual.state_revision,
            if ["after_current", "final_clock"].contains(&point) {
                2
            } else {
                1
            }
        );
        drop(session);
        assert_eq!(store.public_identity().unwrap(), actual);
    }
}
#[test]
fn retained_administration_rejects_clock_rollback_and_current_drift() {
    let _time = Time::at(100);
    let d = root();
    let store = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    let mut session = store.begin_administration().unwrap();
    TEST_NOW.with(|v| v.set(Some(99)));
    assert_eq!(session.public_identity(), Err(CustodyError::Clock));
    TEST_NOW.with(|v| v.set(Some(100)));
    fs::write(d.path().join("CURRENT"), b"broken").unwrap();
    assert!(session.public_observation().is_err());
    assert!(session.reconcile_current().is_err());
}

#[test]
fn retained_administration_excludes_child_writer_at_actual_publication_steps() {
    let _time = Time::at(100);
    let d = root();
    let store = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    let expected = store.public_identity().unwrap().expected();
    let lock = d.path().join("custody.lock");
    let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let observations = seen.clone();
    TEST_ACTION.with(|slot| *slot.borrow_mut() = Some(Box::new(move |step| {
        if ["before_staging", "after_revision", "after_current", "final_clock"].contains(&step) {
            let status = std::process::Command::new("python3").arg("-c").arg(
                "import os,fcntl,sys\nf=os.open(sys.argv[1],os.O_RDWR)\ntry: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(87)\nsys.exit(0)"
            ).arg(&lock).status().unwrap();
            assert_eq!(status.code(), Some(87));
            observations.borrow_mut().push(step.to_owned());
        }
    })));
    let mut session = store.begin_administration().unwrap();
    let old_epoch = session.public_observation().unwrap().metadata().epoch();
    let rotated = session.rotate(expected, 0, 4_000_000_000).unwrap();
    assert!(session.public_observation().unwrap().metadata().epoch() > old_epoch);
    assert_eq!(rotated.state, IdentityState::Unconfigured);
    assert!(session
        .public_observation()
        .unwrap()
        .metadata()
        .owner_input_bytes()
        .is_none());
    TEST_ACTION.with(|slot| *slot.borrow_mut() = None);
    assert_eq!(
        &*seen.borrow(),
        &[
            "before_staging",
            "after_revision",
            "after_current",
            "final_clock"
        ]
    );
    drop(session);
    assert_eq!(store.public_identity().unwrap(), rotated);
}
#[test]
fn retained_administration_revoke_has_no_seed_or_owner_and_preserves_key() {
    let _time = Time::at(100);
    let d = root();
    let store = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    let old = store.public_identity().unwrap();
    let mut session = store.begin_administration().unwrap();
    let revoked = session.revoke(old.expected()).unwrap();
    assert_eq!(revoked.state, IdentityState::Revoked);
    assert_eq!(revoked.public_key_hex, old.public_key_hex);
    assert_eq!(revoked.key_generation, old.key_generation);
    assert_eq!(revoked.revoked_at, Some(100));
    let observation = session.public_observation().unwrap();
    assert!(observation.metadata().owner_input_bytes().is_none());
    assert!(!d.path().join("states/s0000000000000002/seed.raw").exists());
    drop(observation);
    assert_eq!(
        session.rotate(revoked.expected(), 0, 4_000_000_000),
        Err(CustodyError::Revoked)
    );
    assert_eq!(session.reconcile_current().unwrap(), revoked);
}

#[test]
fn retained_public_observation_never_reads_or_attests_seed_health() {
    let _time = Time::at(100);
    let d = root();
    let store = ServiceIdentityStore::create(d.path(), spec()).unwrap();
    let session = store.begin_administration().unwrap();
    let observation = session.public_observation().unwrap();
    fs::write(d.path().join("states/s0000000000000001/seed.raw"), [9; 32]).unwrap();
    observation.revalidate().unwrap();
    drop(observation);
    assert!(session.public_observation().is_ok());
    assert_eq!(session.public_identity(), Err(CustodyError::KeyMismatch));
}

#[path = "service_current_holder_tests.rs"]
mod current_holder_tests;
