use super::*;
use crate::service_wallet_source::tests::{policy, private_file, TestTime, WalletFiles};
use castalia_wallet_private_files::service_store::ServiceRoot;
use std::{fs, os::unix::fs::PermissionsExt, process::Command};
struct OwnerFiles {
    dir: tempfile::TempDir,
    pin: OwnerStartupPin,
}
impl OwnerFiles {
    fn new(w: &WalletFiles) -> Self {
        let dir = tempfile::tempdir_in("/private/tmp").unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut v = policy();
        v["schema"] = json!("secs.service-owner-bundle.v2");
        v.as_object_mut().unwrap().remove("native_bundle_profile");
        v["generation"] = json!(1);
        v["wallet_current"] = w.observed().reference.value;
        let raw = canonical(&v);
        TargetBundle::parse(&raw).unwrap();
        private_file(&dir.path().join(CURRENT), &raw);
        private_file(&dir.path().join(LOCK), b"");
        Self {
            dir,
            pin: OwnerStartupPin::new(1, hash(&raw)).unwrap(),
        }
    }
    fn source(&self) -> OwnerPublicationSource {
        OwnerPublicationSource::open_owner_selected_root(self.dir.path()).unwrap()
    }
}
#[test]
fn actual_first_configuration_and_native_publication_hold_both_leases() {
    let _time = TestTime::set(100);
    let w = WalletFiles::new();
    let wallet = w.source();
    let owner_files = OwnerFiles::new(&w);
    let owner = owner_files.source();
    let custody_root = ServiceRoot::open(w.path()).unwrap();
    let mut custody = custody_root.lock_exclusive().unwrap();
    let mut native = owner
        .begin_administration(
            owner_files.pin,
            &wallet,
            custody.public_observation().unwrap(),
        )
        .unwrap();
    let (next, input) = w.configure();
    {
        let guard = native
            .prepare_wallet_transition(
                custody.public_observation().unwrap(),
                WalletTransitionIntent::Configure {
                    owner_input: input.clone(),
                },
                &canonical(&policy()),
            )
            .unwrap();
        let expected = WalletExpectedCurrent {
            state_revision: 1,
            state_sha256: hash(&canonical(&w.state)),
        };
        guard
            .authorize_configure(custody.public_observation().unwrap(), &expected, &input)
            .unwrap();
        assert!(guard
            .authorize_rotate(custody.public_observation().unwrap(), &expected, 0, 180)
            .is_err());
        assert!(owner.lock(false).is_err());
        assert!(custody_root.lock_shared().is_err());
        // The guard remains borrowed from Native while the actual temporary
        // Wallet view is gone, so this mutable same-lease operation compiles.
        w.publish(&mut custody, &next, Some(&input), true);
        assert!(guard
            .authorize_configure(custody.public_observation().unwrap(), &expected, &input)
            .is_err());
    }
    let next_pin = native
        .record_outcome_and_target(
            custody.public_observation().unwrap(),
            RecoveryRelation::IntendedOutcome,
        )
        .unwrap();
    assert_eq!(next_pin.generation(), 2);
    assert!(wallet.capture_shared().is_err());
    assert_eq!(
        native
            .publish_recorded_target(custody.public_observation().unwrap())
            .unwrap(),
        next_pin
    );
    assert_eq!(
        native
            .finalize_recorded_transition(custody.public_observation().unwrap())
            .unwrap(),
        next_pin
    );
    assert_eq!(
        list(owner.files.root(), 5).unwrap(),
        vec![LOCK.to_owned(), CURRENT.to_owned()]
    );
    drop(native);
    drop(custody);
    let current_wallet = w.source();
    let current = current_wallet.capture_shared().unwrap();
    let native = owner.capture_shared(next_pin, &current).unwrap();
    current
        .require_active_for_challenge(100, 110, &native)
        .unwrap();
}
#[test]
fn immutable_policy_drift_and_foreign_expected_state_cannot_authorize_mutation() {
    let _time = TestTime::set(100);
    let w = WalletFiles::new();
    let wallet = w.source();
    let f = OwnerFiles::new(&w);
    let owner = f.source();
    let root = ServiceRoot::open(w.path()).unwrap();
    let custody = root.lock_exclusive().unwrap();
    let mut s = owner
        .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
        .unwrap();
    let guard = s
        .prepare_wallet_transition(
            custody.public_observation().unwrap(),
            WalletTransitionIntent::Revoke,
            &canonical(&policy()),
        )
        .unwrap();
    let wrong = WalletExpectedCurrent {
        state_revision: 2,
        state_sha256: hash(&canonical(&w.state)),
    };
    assert!(guard
        .authorize_revoke(custody.public_observation().unwrap(), &wrong)
        .is_err());
    fs::write(
        owner.files.path.join(RECORDS).join("TARGET-POLICY.json"),
        b"{}",
    )
    .unwrap();
    let correct = WalletExpectedCurrent {
        state_revision: 1,
        state_sha256: hash(&canonical(&w.state)),
    };
    assert!(guard
        .authorize_revoke(custody.public_observation().unwrap(), &correct)
        .is_err());
    assert!(owner.files.exists(MARKER, false).unwrap());
}
#[test]
fn same_current_reconcile_requires_actual_epoch_change_and_advances_native() {
    let _time = TestTime::set(100);
    let w = WalletFiles::new();
    let wallet = w.source();
    let f = OwnerFiles::new(&w);
    let owner = f.source();
    let root = ServiceRoot::open(w.path()).unwrap();
    let mut custody = root.lock_exclusive().unwrap();
    let mut s = owner
        .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
        .unwrap();
    {
        let guard = s
            .prepare_wallet_transition(
                custody.public_observation().unwrap(),
                WalletTransitionIntent::Reconcile,
                &canonical(&policy()),
            )
            .unwrap();
        guard
            .authorize_reconcile(
                custody.public_observation().unwrap(),
                &WalletExpectedCurrent {
                    state_revision: 1,
                    state_sha256: hash(&canonical(&w.state)),
                },
            )
            .unwrap();
    }
    assert!(s
        .record_outcome_and_target(
            custody.public_observation().unwrap(),
            RecoveryRelation::ReconciledUnchanged
        )
        .is_err());
    custody.invalidate(false).unwrap();
    let pin = s
        .record_outcome_and_target(
            custody.public_observation().unwrap(),
            RecoveryRelation::ReconciledUnchanged,
        )
        .unwrap();
    s.publish_recorded_target(custody.public_observation().unwrap())
        .unwrap();
    s.finalize_recorded_transition(custody.public_observation().unwrap())
        .unwrap();
    assert_eq!(pin.generation(), 2);
}
#[test]
fn recovery_reuses_recorded_policy_and_exact_bytes_after_native_replacement() {
    let _time = TestTime::set(100);
    let w = WalletFiles::new();
    let wallet = w.source();
    let f = OwnerFiles::new(&w);
    let owner = f.source();
    let root = ServiceRoot::open(w.path()).unwrap();
    let mut custody = root.lock_exclusive().unwrap();
    let mut s = owner
        .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
        .unwrap();
    {
        let _prepared = s
            .prepare_wallet_transition(
                custody.public_observation().unwrap(),
                WalletTransitionIntent::Reconcile,
                &canonical(&policy()),
            )
            .unwrap();
    }
    custody.invalidate(false).unwrap();
    let pin = s
        .record_outcome_and_target(
            custody.public_observation().unwrap(),
            RecoveryRelation::ReconciledUnchanged,
        )
        .unwrap();
    let id = s.transition_id().unwrap();
    FAULT.with(|v| *v.borrow_mut() = Some("native_replaced".into()));
    assert!(s
        .publish_recorded_target(custody.public_observation().unwrap())
        .is_err());
    FAULT.with(|v| *v.borrow_mut() = None);
    drop(s);
    drop(custody);
    drop(owner);
    let owner = f.source();
    let custody = root.lock_exclusive().unwrap();
    let mut resumed = owner
        .begin_recovery(f.pin, id, &wallet, custody.public_observation().unwrap())
        .unwrap();
    assert_eq!(
        resumed
            .publish_recorded_target(custody.public_observation().unwrap())
            .unwrap(),
        pin
    );
    assert_eq!(
        resumed
            .finalize_recorded_transition(custody.public_observation().unwrap())
            .unwrap(),
        pin
    );
}
#[test]
fn native_exclusive_lock_excludes_fresh_process_for_complete_interval() {
    let _time = TestTime::set(100);
    let w = WalletFiles::new();
    let wallet = w.source();
    let f = OwnerFiles::new(&w);
    let owner = f.source();
    let root = ServiceRoot::open(w.path()).unwrap();
    let custody = root.lock_exclusive().unwrap();
    let _session = owner
        .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
        .unwrap();
    let result=Command::new("python3").arg("-c").arg("import fcntl,sys;f=open(sys.argv[1],'r+');\ntry:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError:sys.exit(0)\nsys.exit(3)").arg(f.dir.path().join(LOCK)).status().unwrap();
    assert!(result.success());
}
#[test]
fn source_rejects_unsafe_extras_and_hardlinks() {
    let _time = TestTime::set(100);
    let w = WalletFiles::new();
    let f = OwnerFiles::new(&w);
    private_file(&f.dir.path().join("unknown"), b"x");
    assert!(f.source_result().is_err());
    fs::remove_file(f.dir.path().join("unknown")).unwrap();
    let file = f.dir.path().join(CURRENT);
    fs::hard_link(&file, f.dir.path().join("linked")).unwrap();
    assert!(f.source_result().is_err());
}
impl OwnerFiles {
    fn source_result(&self) -> Result<OwnerPublicationSource> {
        OwnerPublicationSource::open_owner_selected_root(self.dir.path())
    }
}

#[test]
fn retained_outcome_and_target_retry_reuses_exact_original_policy_after_lost_ack() {
    for point in [
        "outcome_durable",
        "target_durable",
        "outcome_recorded",
        "native_published",
    ] {
        let _time = TestTime::set(100);
        let w = WalletFiles::new();
        let wallet = w.source();
        let f = OwnerFiles::new(&w);
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let mut custody = root.lock_exclusive().unwrap();
        let mut s = owner
            .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
            .unwrap();
        {
            let _prepared = s
                .prepare_wallet_transition(
                    custody.public_observation().unwrap(),
                    WalletTransitionIntent::Reconcile,
                    &canonical(&policy()),
                )
                .unwrap();
        }
        let id = s.transition_id().unwrap();
        custody.sync_current().unwrap();
        custody.discard_temporary().unwrap();
        custody.invalidate(false).unwrap();
        FAULT.with(|v| *v.borrow_mut() = Some(point.into()));
        if point == "native_published" {
            s.record_outcome_and_target(
                custody.public_observation().unwrap(),
                RecoveryRelation::ReconciledUnchanged,
            )
            .unwrap();
            assert!(s
                .publish_recorded_target(custody.public_observation().unwrap())
                .is_err());
        } else {
            assert!(s
                .record_outcome_and_target(
                    custody.public_observation().unwrap(),
                    RecoveryRelation::ReconciledUnchanged
                )
                .is_err());
        }
        FAULT.with(|v| *v.borrow_mut() = None);
        let exact_policy = owner.files.read("TARGET-POLICY.json", true).unwrap();
        let exact_outcome = owner.files.read("OUTCOME.json", true).unwrap();
        drop(s);
        drop(custody);
        drop(owner);
        let owner = f.source();
        let mut custody = root.lock_exclusive().unwrap();
        let mut resumed = owner
            .begin_recovery(f.pin, id, &wallet, custody.public_observation().unwrap())
            .unwrap();
        if resumed.marker.as_ref().unwrap().value["stage"] == "prepared" {
            custody.sync_current().unwrap();
            custody.discard_temporary().unwrap();
            custody.invalidate(false).unwrap();
            resumed
                .record_outcome_and_target(
                    custody.public_observation().unwrap(),
                    RecoveryRelation::ReconciledUnchanged,
                )
                .unwrap();
        }
        assert_eq!(
            owner.files.read("TARGET-POLICY.json", true).unwrap(),
            exact_policy
        );
        assert_eq!(
            owner.files.read("OUTCOME.json", true).unwrap(),
            exact_outcome
        );
        resumed
            .publish_recorded_target(custody.public_observation().unwrap())
            .unwrap();
        let new_pin = resumed
            .finalize_recorded_transition(custody.public_observation().unwrap())
            .unwrap();
        assert_eq!(new_pin.generation(), 2);
    }
}

#[test]
fn active_metadata_with_revoked_selected_issuer_denies_whole_original_window() {
    let _time = TestTime::set(100);
    let w = WalletFiles::new();
    let (state, input) = w.configure();
    let root = ServiceRoot::open(w.path()).unwrap();
    let mut custody = root.lock_exclusive().unwrap();
    w.publish(&mut custody, &state, Some(&input), true);
    drop(custody);
    let wallet = w.source();
    let mut f = OwnerFiles::new(&w);
    let path = f.dir.path().join(CURRENT);
    let mut bundle =
        crate::service_authority_snapshot::strict_value(&fs::read(&path).unwrap()).unwrap();
    bundle["issuers"][0]["status"] = json!("revoked");
    bundle["issuers"][0]["revoked_at"] = json!(100);
    let raw = canonical(&bundle);
    fs::write(&path, &raw).unwrap();
    f.pin = OwnerStartupPin::new(1, hash(&raw)).unwrap();
    let owner = f.source();
    let current = wallet.capture_shared().unwrap();
    let native = owner.capture_shared(f.pin, &current).unwrap();
    assert_eq!(
        current.require_active_for_challenge(100, 110, &native),
        Err(SourceError::Window)
    );
}

#[test]
fn native_files_charge_allocated_extents_even_when_logical_bytes_stay_small() {
    let _time = TestTime::set(100);
    let w = WalletFiles::new();
    let f = OwnerFiles::new(&w);
    let file = fs::OpenOptions::new()
        .write(true)
        .open(f.dir.path().join(CURRENT))
        .unwrap();
    #[cfg(target_os = "macos")]
    let rc = {
        let mut allocation = libc::fstore_t {
            fst_flags: libc::F_ALLOCATEALL,
            fst_posmode: libc::F_PEOFPOSMODE,
            fst_offset: 0,
            fst_length: 1048576,
            fst_bytesalloc: 0,
        };
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &mut allocation) }
    };
    #[cfg(target_os = "linux")]
    let rc = unsafe { libc::fallocate(file.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, 0, 1048576) };
    assert_eq!(
        rc, 0,
        "fixture preallocation must execute on the declared local filesystem"
    );
    assert!(file.metadata().unwrap().len() < IMAGE);
    assert!(charged(&file).unwrap() > IMAGE + BLOCK);
    assert!(matches!(
        f.source_result(),
        Err(SourceError::UnsafeStorage) | Err(SourceError::Capacity)
    ));
}

fn completed_tombstone() -> (
    WalletFiles,
    WalletCurrentSource,
    WalletCurrentSource,
    OwnerFiles,
    OwnerStartupPin,
    [u8; 16],
) {
    let w = WalletFiles::new();
    let old_wallet = w.source();
    let f = OwnerFiles::new(&w);
    let owner = f.source();
    let root = ServiceRoot::open(w.path()).unwrap();
    let mut custody = root.lock_exclusive().unwrap();
    let mut session = owner
        .begin_administration(f.pin, &old_wallet, custody.public_observation().unwrap())
        .unwrap();
    let (next, input) = w.configure();
    {
        let _prepared = session
            .prepare_wallet_transition(
                custody.public_observation().unwrap(),
                WalletTransitionIntent::Configure {
                    owner_input: input.clone(),
                },
                &canonical(&policy()),
            )
            .unwrap();
    }
    let id = session.transition_id().unwrap();
    w.publish(&mut custody, &next, Some(&input), true);
    let target = session
        .record_outcome_and_target(
            custody.public_observation().unwrap(),
            RecoveryRelation::IntendedOutcome,
        )
        .unwrap();
    session
        .publish_recorded_target(custody.public_observation().unwrap())
        .unwrap();
    FAULT.with(|v| *v.borrow_mut() = Some("tombstone_renamed".into()));
    assert!(session
        .finalize_recorded_transition(custody.public_observation().unwrap())
        .is_err());
    FAULT.with(|v| *v.borrow_mut() = None);
    assert!(!owner.files.exists(MARKER, false).unwrap());
    assert!(owner.files.exists(TEMP, false).unwrap());
    assert_eq!(list(&owner.files.records().unwrap(), 6).unwrap().len(), 6);
    drop(session);
    drop(custody);
    drop(root);
    drop(owner);
    let new_wallet = w.source();
    (w, old_wallet, new_wallet, f, target, id)
}
#[test]
fn all_64_completed_record_presence_masks_require_distinct_new_pinned_cleanup() {
    let _time = TestTime::set(100);
    let names = [
        "OLD-NATIVE.json",
        "OLD-WALLET-STATE.json",
        "TARGET-POLICY.json",
        "REQUEST-OWNER-INPUT.json",
        "OUTCOME.json",
        "TARGET-NATIVE.json",
    ];
    for mask in 0u8..64 {
        let (w, old_wallet, new_wallet, f, target, id) = completed_tombstone();
        let owner = f.source();
        for (i, n) in names.iter().enumerate() {
            if mask & (1 << i) == 0 {
                fs::remove_file(f.dir.path().join(RECORDS).join(n)).unwrap();
            }
        }
        let root = ServiceRoot::open(w.path()).unwrap();
        let custody = root.lock_exclusive().unwrap();
        let ordinary = owner.begin_recovery(
            f.pin,
            id,
            &old_wallet,
            custody.public_observation().unwrap(),
        );
        assert_eq!(
            ordinary.is_ok(),
            mask == 63,
            "ordinary recovery admitted missing proof mask {mask}"
        );
        drop(ordinary);
        let result = owner
            .cleanup_completed_wallet_transition(
                target,
                id,
                &new_wallet,
                custody.public_observation().unwrap(),
            )
            .unwrap();
        assert_eq!(result.transition_id(), id);
        assert_eq!(result.removed_records(), mask.count_ones() as usize);
        assert_eq!(
            list(owner.files.root(), 5).unwrap(),
            vec![LOCK.to_string(), CURRENT.to_string()]
        );
        assert_eq!(
            check_bundle(&owner.files.read(CURRENT, false).unwrap(), target)
                .unwrap()
                .value["generation"],
            2
        );
    }
}
#[test]
fn completed_cleanup_rejects_bad_new_pins_ids_and_present_inconsistent_records() {
    let _time = TestTime::set(100);
    for corrupt in [
        "OLD-NATIVE.json",
        "OLD-WALLET-STATE.json",
        "TARGET-POLICY.json",
        "REQUEST-OWNER-INPUT.json",
        "OUTCOME.json",
        "TARGET-NATIVE.json",
    ] {
        let (w, _old, new_wallet, f, target, id) = completed_tombstone();
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let custody = root.lock_exclusive().unwrap();
        let wrong = OwnerStartupPin::new(target.generation() + 1, target.sha256()).unwrap();
        assert!(owner
            .cleanup_completed_wallet_transition(
                wrong,
                id,
                &new_wallet,
                custody.public_observation().unwrap()
            )
            .is_err());
        assert!(owner
            .cleanup_completed_wallet_transition(
                target,
                [91; 16],
                &new_wallet,
                custody.public_observation().unwrap()
            )
            .is_err());
        fs::write(f.dir.path().join(RECORDS).join(corrupt), b"{}").unwrap();
        assert!(owner
            .cleanup_completed_wallet_transition(
                target,
                id,
                &new_wallet,
                custody.public_observation().unwrap()
            )
            .is_err());
        assert_eq!(list(&owner.files.records().unwrap(), 6).unwrap().len(), 6);
        assert!(owner.files.exists(TEMP, false).unwrap());
    }
}
#[test]
fn every_completed_cleanup_unlink_boundary_returns_uncertainty_and_restarts_with_new_pins() {
    let _time = TestTime::set(100);
    let points = [
        "tombstone_root_synced",
        "unlinked_before_sync:OLD-NATIVE.json",
        "record_unlinked:OLD-WALLET-STATE.json",
        "record_unlinked:OUTCOME.json",
        "record_unlinked:REQUEST-OWNER-INPUT.json",
        "record_unlinked:TARGET-NATIVE.json",
        "record_unlinked:TARGET-POLICY.json",
        "records_synced",
        "records_closed",
        "records_removed",
        "before_tombstone_unlink",
        "unlinked_before_sync:.wallet-transition.tmp",
        "tombstone_removed",
    ];
    for point in points {
        let (w, _old, new_wallet, f, target, id) = completed_tombstone();
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let custody = root.lock_exclusive().unwrap();
        FAULT.with(|v| *v.borrow_mut() = Some(point.into()));
        assert!(
            owner
                .cleanup_completed_wallet_transition(
                    target,
                    id,
                    &new_wallet,
                    custody.public_observation().unwrap()
                )
                .is_err(),
            "{point}"
        );
        FAULT.with(|v| *v.borrow_mut() = None);
        if owner.files.exists(TEMP, false).unwrap() {
            owner
                .cleanup_completed_wallet_transition(
                    target,
                    id,
                    &new_wallet,
                    custody.public_observation().unwrap(),
                )
                .unwrap();
        } else {
            assert!(!list(owner.files.root(), 5)
                .unwrap()
                .iter()
                .any(|n| n == RECORDS || n == MARKER));
            // The failed cleanup did not report success. A separate decision
            // using the independently selected NEW pins can capture the already
            // durable coherent G+1. This is not proof of final-unlink durability.
            drop(custody);
            let actual_wallet = new_wallet.capture_shared().unwrap();
            let separately_pinned = owner.capture_shared(target, &actual_wallet).unwrap();
            separately_pinned.revalidate().unwrap();
        }
        assert_eq!(
            list(owner.files.root(), 5).unwrap(),
            vec![LOCK.to_string(), CURRENT.to_string()]
        );
    }
}
#[test]
fn predecessor_state_is_exact_and_required_for_changed_outcome_restart() {
    let _time = TestTime::set(100);
    for field in [
        "created_at",
        "key_created_at",
        "published_at",
        "previous_state_sha256",
    ] {
        let w = WalletFiles::new();
        let wallet = w.source();
        let f = OwnerFiles::new(&w);
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let mut custody = root.lock_exclusive().unwrap();
        let mut session = owner
            .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
            .unwrap();
        let (mut next, input) = w.configure();
        {
            let _prepared = session
                .prepare_wallet_transition(
                    custody.public_observation().unwrap(),
                    WalletTransitionIntent::Configure {
                        owner_input: input.clone(),
                    },
                    &canonical(&policy()),
                )
                .unwrap();
        }
        let id = session.transition_id().unwrap();
        assert_eq!(
            owner.files.read("OLD-WALLET-STATE.json", true).unwrap(),
            canonical(&w.state)
        );
        match field {
            "created_at" => next[field] = json!(79),
            "key_created_at" => next[field] = json!(81),
            "published_at" => next[field] = json!(89),
            _ => next[field] = json!("11".repeat(32)),
        }
        w.publish(&mut custody, &next, Some(&input), true);
        drop(session);
        assert!(
            owner
                .begin_recovery(f.pin, id, &wallet, custody.public_observation().unwrap())
                .is_err(),
            "{field}"
        );
        assert!(owner.files.exists(MARKER, false).unwrap());
    }
}
#[test]
fn s1_only_accepts_exact_source_temp_and_reverse_prefix_cleanup() {
    let _time = TestTime::set(100);
    for count in 0..=4 {
        for temp_kind in 0..3 {
            let w = WalletFiles::new();
            let wallet = w.source();
            let f = OwnerFiles::new(&w);
            let owner = f.source();
            owner.files.make_records().unwrap();
            let native = owner.files.read(CURRENT, false).unwrap();
            let state = canonical(&w.state);
            let policy = canonical(&policy());
            let input = w.owner_input(2);
            for (n, raw) in [
                "OLD-NATIVE.json",
                "OLD-WALLET-STATE.json",
                "TARGET-POLICY.json",
                "REQUEST-OWNER-INPUT.json",
            ]
            .into_iter()
            .zip([
                native.as_slice(),
                state.as_slice(),
                policy.as_slice(),
                input.as_slice(),
            ])
            .take(count)
            {
                owner.files.write(n, true, raw, false).unwrap();
            }
            if temp_kind > 0 {
                private_file(
                    &f.dir.path().join(TEMP),
                    if temp_kind == 1 { &native } else { &state },
                );
            }
            let root = ServiceRoot::open(w.path()).unwrap();
            let custody = root.lock_exclusive().unwrap();
            let receipt = owner
                .abort_unprepared_wallet_transition(
                    f.pin,
                    &wallet,
                    custody.public_observation().unwrap(),
                )
                .unwrap();
            assert_eq!(receipt.removed_records(), count);
            assert_eq!(owner.files.read(CURRENT, false).unwrap(), native);
            assert_eq!(
                list(owner.files.root(), 5).unwrap(),
                vec![LOCK.to_owned(), CURRENT.to_owned()]
            );
        }
    }
    for raw in [
        b"{".as_slice(),
        b"",
        b"{}",
        b"{\"stage\":\"native_published\"}",
    ] {
        let w = WalletFiles::new();
        let wallet = w.source();
        let f = OwnerFiles::new(&w);
        let owner = f.source();
        owner.files.make_records().unwrap();
        private_file(&f.dir.path().join(TEMP), raw);
        let root = ServiceRoot::open(w.path()).unwrap();
        let custody = root.lock_exclusive().unwrap();
        assert!(owner
            .abort_unprepared_wallet_transition(
                f.pin,
                &wallet,
                custody.public_observation().unwrap()
            )
            .is_err());
        assert_eq!(owner.files.read(TEMP, false).unwrap(), raw);
    }
}
#[test]
fn s2_proves_original_chain_then_discards_only_unselected_temp_and_reuses_outcome() {
    let _time = TestTime::set(100);
    for stage in 0..6 {
        let w = WalletFiles::new();
        let wallet = w.source();
        let f = OwnerFiles::new(&w);
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let mut custody = root.lock_exclusive().unwrap();
        let mut session = owner
            .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
            .unwrap();
        let (next, input) = w.configure();
        {
            let _prepared = session
                .prepare_wallet_transition(
                    custody.public_observation().unwrap(),
                    WalletTransitionIntent::Configure {
                        owner_input: input.clone(),
                    },
                    &canonical(&policy()),
                )
                .unwrap();
        }
        let id = session.transition_id().unwrap();
        w.publish(&mut custody, &next, Some(&input), true);
        if stage > 0 {
            let point = match stage {
                1 => "outcome_durable",
                2 => "target_durable",
                _ => "unused",
            };
            FAULT.with(|v| *v.borrow_mut() = Some(point.into()));
            let result = session.record_outcome_and_target(
                custody.public_observation().unwrap(),
                RecoveryRelation::IntendedOutcome,
            );
            FAULT.with(|v| *v.borrow_mut() = None);
            if stage <= 2 {
                assert!(result.is_err());
            } else {
                result.unwrap();
            }
        }
        if stage == 5 {
            FAULT.with(|v| *v.borrow_mut() = Some("native_replaced".into()));
            assert!(session
                .publish_recorded_target(custody.public_observation().unwrap())
                .is_err());
            FAULT.with(|v| *v.borrow_mut() = None);
        }
        if stage == 4 {
            session
                .publish_recorded_target(custody.public_observation().unwrap())
                .unwrap();
        }
        let marker = owner.files.read(MARKER, false).unwrap();
        let names = list(&owner.files.records().unwrap(), 6).unwrap();
        let images: Vec<_> = names
            .iter()
            .map(|n| (n.clone(), owner.files.read(n, true).unwrap()))
            .collect();
        drop(session);
        private_file(
            &f.dir.path().join(TEMP),
            b"arbitrary unselected partial bytes",
        );
        assert!(owner
            .begin_recovery(f.pin, id, &wallet, custody.public_observation().unwrap())
            .is_err());
        assert!(owner
            .discard_uncommitted_transition_temp(
                f.pin,
                [90; 16],
                &wallet,
                custody.public_observation().unwrap()
            )
            .is_err());
        assert!(owner.files.exists(TEMP, false).unwrap());
        owner
            .discard_uncommitted_transition_temp(
                f.pin,
                id,
                &wallet,
                custody.public_observation().unwrap(),
            )
            .unwrap();
        assert_eq!(owner.files.read(MARKER, false).unwrap(), marker);
        for (n, raw) in images {
            assert_eq!(owner.files.read(&n, true).unwrap(), raw);
        }
        let mut resumed = owner
            .begin_recovery(f.pin, id, &wallet, custody.public_observation().unwrap())
            .unwrap();
        if resumed.marker.as_ref().unwrap().value["stage"] == "prepared" {
            resumed
                .record_outcome_and_target(
                    custody.public_observation().unwrap(),
                    RecoveryRelation::IntendedOutcome,
                )
                .unwrap();
        }
        resumed
            .publish_recorded_target(custody.public_observation().unwrap())
            .unwrap();
        resumed
            .finalize_recorded_transition(custody.public_observation().unwrap())
            .unwrap();
    }
}

#[test]
fn native_lifecycle_configure_rotate_reconfigure_revoke_never_rekeys_policy_implicitly() {
    let _time = TestTime::set(100);
    let w = WalletFiles::new();
    let f = OwnerFiles::new(&w);
    let owner = f.source();
    let root = ServiceRoot::open(w.path()).unwrap();
    let mut pin = f.pin;
    let mut current = w.state.clone();
    let mut selected = policy();
    for step in 0..4 {
        let wallet = w.source();
        let mut custody = root.lock_exclusive().unwrap();
        if step >= 2 {
            custody.remove_revision(step - 1).unwrap();
        }
        let mut next = current.clone();
        next["state_revision"] = json!(current["state_revision"].as_u64().unwrap() + 1);
        next["previous_state_sha256"] = json!(hex(&hash(&canonical(&current))));
        next["published_at"] = json!(100);
        let intent;
        let owner_input;
        if step == 0 {
            let (s, input) = w.configure();
            next = s;
            owner_input = Some(input.clone());
            intent = WalletTransitionIntent::Configure { owner_input: input };
        } else if step == 1 {
            let key = ed25519_dalek::SigningKey::from_bytes(&[72; 32])
                .verifying_key()
                .to_bytes();
            next["key_generation"] = json!(2);
            next["key_created_at"] = json!(100);
            next["state"] = json!("unconfigured");
            next["owner_input_sha256"] = Value::Null;
            next["public_key_hex"] = json!(hex(&key));
            next["public_key_sha256"] = json!(hex(&hash(&key)));
            next["key_id"] = json!(format!("service-ed25519:sha256:{}", hex(&hash(&key))));
            owner_input = None;
            intent = WalletTransitionIntent::Rotate {
                not_before: 0,
                not_after: 180,
            };
        } else if step == 2 {
            for n in ["key_id", "public_key_hex"] {
                selected["holders"][0][n] = current[n].clone();
            }
            for p in selected["receiver_policy"]["principals"]
                .as_array_mut()
                .unwrap()
            {
                p["key_id"] = current["key_id"].clone();
            }
            for r in selected["receiver_policy"]["rules"].as_array_mut().unwrap() {
                r["key_id"] = current["key_id"].clone();
            }
            let mut input =
                crate::service_authority_snapshot::strict_value(&w.owner_input(4)).unwrap();
            input["holder"]["generation"] = json!(2);
            for n in ["key_id", "public_key_hex"] {
                input["holder"][n] = current[n].clone();
            }
            input["delegation_policy"] = selected["receiver_policy"].clone();
            let input = canonical(&input);
            next["state"] = json!("active");
            next["owner_input_sha256"] = json!(hex(&hash(&input)));
            owner_input = Some(input.clone());
            intent = WalletTransitionIntent::Configure { owner_input: input };
        } else {
            next["state"] = json!("revoked");
            next["revoked_at"] = json!(100);
            next["owner_input_sha256"] = Value::Null;
            owner_input = None;
            intent = WalletTransitionIntent::Revoke;
        }
        let mut native = owner
            .begin_administration(pin, &wallet, custody.public_observation().unwrap())
            .unwrap();
        {
            let guard = native
                .prepare_wallet_transition(
                    custody.public_observation().unwrap(),
                    intent,
                    &canonical(&selected),
                )
                .unwrap();
            let expected = WalletExpectedCurrent {
                state_revision: current["state_revision"].as_u64().unwrap(),
                state_sha256: hash(&canonical(&current)),
            };
            match step {
                0 | 2 => guard
                    .authorize_configure(
                        custody.public_observation().unwrap(),
                        &expected,
                        owner_input.as_ref().unwrap(),
                    )
                    .unwrap(),
                1 => guard
                    .authorize_rotate(custody.public_observation().unwrap(), &expected, 0, 180)
                    .unwrap(),
                _ => guard
                    .authorize_revoke(custody.public_observation().unwrap(), &expected)
                    .unwrap(),
            };
        }
        w.publish(&mut custody, &next, owner_input.as_deref(), true);
        pin = native
            .record_outcome_and_target(
                custody.public_observation().unwrap(),
                RecoveryRelation::IntendedOutcome,
            )
            .unwrap();
        native
            .publish_recorded_target(custody.public_observation().unwrap())
            .unwrap();
        native
            .finalize_recorded_transition(custody.public_observation().unwrap())
            .unwrap();
        drop(native);
        drop(custody);
        let actual = w.source();
        let current_wallet = actual.capture_shared().unwrap();
        let current_native = owner.capture_shared(pin, &current_wallet).unwrap();
        assert_eq!(pin.generation(), step + 2);
        if step == 0 || step == 2 {
            current_wallet
                .require_active_for_challenge(100, 110, &current_native)
                .unwrap();
        } else {
            assert_eq!(
                current_wallet.require_active_for_challenge(100, 110, &current_native),
                Err(SourceError::Inactive)
            );
        }
        let bundle = crate::service_authority_snapshot::strict_value(
            &owner.files.read(CURRENT, false).unwrap(),
        )
        .unwrap();
        assert_eq!(bundle["holders"], selected["holders"]);
        assert_eq!(bundle["receiver_policy"], selected["receiver_policy"]);
        if step == 1 {
            assert_ne!(
                bundle["holders"][0]["key_id"],
                bundle["wallet_current"]["key_id"]
            );
        }
        current = next;
    }
}

#[test]
fn completed_recovery_child_process() {
    let Ok(raw) = std::env::var("NI01_NATIVE_RECOVERY_FIXTURE") else {
        return;
    };
    let _time = TestTime::set(100);
    let v: Value = serde_json::from_str(&raw).unwrap();
    let owner = OwnerPublicationSource::open_owner_selected_root(Path::new(
        v["native_root"].as_str().unwrap(),
    ))
    .unwrap();
    let wallet = WalletCurrentSource::open(
        wallet::OwnerSelectedWalletRoot::open(Path::new(v["wallet_root"].as_str().unwrap()))
            .unwrap(),
        wallet::StartupWalletObservationPin::parse_owner_configuration(&canonical(
            &v["wallet_pin"],
        ))
        .unwrap(),
    )
    .unwrap();
    let root = ServiceRoot::open(Path::new(v["wallet_root"].as_str().unwrap())).unwrap();
    let custody = root.lock_exclusive().unwrap();
    let pin = OwnerStartupPin::new(
        v["native_pin"]["generation"].as_u64().unwrap(),
        wallet::digest(v["native_pin"]["bundle_sha256"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let text = v["id"].as_str().unwrap();
    let mut id = [0; 16];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
    }
    if v["mode"] == "original" {
        let mut session = owner
            .begin_recovery(pin, id, &wallet, custody.public_observation().unwrap())
            .unwrap();
        session
            .finalize_recorded_transition(custody.public_observation().unwrap())
            .unwrap();
    } else {
        owner
            .cleanup_completed_wallet_transition(
                pin,
                id,
                &wallet,
                custody.public_observation().unwrap(),
            )
            .unwrap();
    }
}
#[test]
fn fresh_process_original_and_partial_completed_cleanup_use_real_sources_and_locks() {
    let _time = TestTime::set(100);
    for partial in [false, true] {
        let (w, old_wallet, new_wallet, f, target, id) = completed_tombstone();
        let owner = f.source();
        if partial {
            fs::remove_file(f.dir.path().join(RECORDS).join("OLD-WALLET-STATE.json")).unwrap();
        }
        let source = if partial { &new_wallet } else { &old_wallet };
        let wallet_pin = source.test_startup_pin_bytes();
        let pin = if partial { target } else { f.pin };
        let config = json!({"native_root":f.dir.path(),"wallet_root":w.path(),"native_pin":pin.value(),"wallet_pin":serde_json::from_slice::<Value>(&wallet_pin).unwrap(),"id":hex(&id),"mode":if partial{"cleanup"}else{"original"}});
        let result = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("service_owner_publication::tests::completed_recovery_child_process")
            .arg("--test-threads=1")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env(
                "NI01_NATIVE_RECOVERY_FIXTURE",
                String::from_utf8(canonical(&config)).unwrap(),
            )
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
        assert_eq!(
            list(owner.files.root(), 5).unwrap(),
            vec![LOCK.to_owned(), CURRENT.to_owned()]
        );
    }
}

fn retained_transition_id(owner: &OwnerPublicationSource) -> [u8; 16] {
    let marker = TransitionMarker::parse(&owner.files.read(MARKER, false).unwrap()).unwrap();
    let encoded = marker.value["transition_id"].as_str().unwrap();
    let mut id = [0; 16];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[i * 2..i * 2 + 2], 16).unwrap();
    }
    id
}

#[test]
fn interrupted_prepared_writes_use_only_strict_s1_or_selected_marker_recovery() {
    let _time = TestTime::set(100);
    for destination in [
        "OLD-NATIVE.json",
        "OLD-WALLET-STATE.json",
        "TARGET-POLICY.json",
        "REQUEST-OWNER-INPUT.json",
        MARKER,
    ] {
        for boundary in [
            "temp_written",
            "temp_synced",
            "temp_closed",
            "renamed_before_sync",
        ] {
            let point = format!("{boundary}:{destination}");
            let w = WalletFiles::new();
            let wallet = w.source();
            let f = OwnerFiles::new(&w);
            let owner = f.source();
            let root = ServiceRoot::open(w.path()).unwrap();
            let mut custody = root.lock_exclusive().unwrap();
            let mut session = owner
                .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
                .unwrap();
            let (_, input) = w.configure();
            FAULT.with(|v| *v.borrow_mut() = Some(point.clone()));
            assert!(
                session
                    .prepare_wallet_transition(
                        custody.public_observation().unwrap(),
                        WalletTransitionIntent::Configure { owner_input: input },
                        &canonical(&policy())
                    )
                    .is_err(),
                "{point}"
            );
            FAULT.with(|v| *v.borrow_mut() = None);
            drop(session);
            if owner.files.exists(MARKER, false).unwrap() {
                let id = retained_transition_id(&owner);
                let mut resumed = owner
                    .begin_recovery(f.pin, id, &wallet, custody.public_observation().unwrap())
                    .unwrap();
                resumed
                    .recovery_reconciliation_guard()
                    .unwrap()
                    .authorize_reconcile(
                        custody.public_observation().unwrap(),
                        &WalletExpectedCurrent {
                            state_revision: 1,
                            state_sha256: hash(&canonical(&w.state)),
                        },
                    )
                    .unwrap();
                custody.invalidate(false).unwrap();
                resumed
                    .record_outcome_and_target(
                        custody.public_observation().unwrap(),
                        RecoveryRelation::ExplicitAbortUnchanged,
                    )
                    .unwrap();
                resumed
                    .publish_recorded_target(custody.public_observation().unwrap())
                    .unwrap();
                resumed
                    .finalize_recorded_transition(custody.public_observation().unwrap())
                    .unwrap();
            } else {
                let allowed = boundary == "renamed_before_sync"
                    || destination == "OLD-NATIVE.json"
                    || destination == "OLD-WALLET-STATE.json";
                let result = owner.abort_unprepared_wallet_transition(
                    f.pin,
                    &wallet,
                    custody.public_observation().unwrap(),
                );
                assert_eq!(result.is_ok(), allowed, "{point}");
                if !allowed {
                    assert!(owner.files.exists(TEMP, false).unwrap());
                    assert!(owner
                        .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
                        .is_err());
                    continue;
                }
                assert_eq!(
                    hash(&owner.files.read(CURRENT, false).unwrap()),
                    f.pin.sha256()
                );
            }
            assert_eq!(
                list(owner.files.root(), 5).unwrap(),
                vec![LOCK.to_owned(), CURRENT.to_owned()],
                "{point}"
            );
        }
    }
}

#[test]
fn interrupted_selected_writes_require_explicit_s2_and_reuse_retained_outcome() {
    let _time = TestTime::set(100);
    for stage in 0..5 {
        let destination = match stage {
            0 => "OUTCOME.json",
            1 => "TARGET-NATIVE.json",
            2 | 4 => MARKER,
            _ => CURRENT,
        };
        for boundary in [
            "temp_written",
            "temp_synced",
            "temp_closed",
            "renamed_before_sync",
        ] {
            let point = format!("{boundary}:{destination}");
            let w = WalletFiles::new();
            let wallet = w.source();
            let f = OwnerFiles::new(&w);
            let owner = f.source();
            let root = ServiceRoot::open(w.path()).unwrap();
            let mut custody = root.lock_exclusive().unwrap();
            let mut session = owner
                .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
                .unwrap();
            let (next, input) = w.configure();
            {
                let _prepared = session
                    .prepare_wallet_transition(
                        custody.public_observation().unwrap(),
                        WalletTransitionIntent::Configure {
                            owner_input: input.clone(),
                        },
                        &canonical(&policy()),
                    )
                    .unwrap();
            }
            let id = session.transition_id().unwrap();
            w.publish(&mut custody, &next, Some(&input), true);
            if stage >= 3 {
                session
                    .record_outcome_and_target(
                        custody.public_observation().unwrap(),
                        RecoveryRelation::IntendedOutcome,
                    )
                    .unwrap();
            }
            FAULT.with(|v| *v.borrow_mut() = Some(point.clone()));
            let result = if stage >= 3 {
                session.publish_recorded_target(custody.public_observation().unwrap())
            } else {
                session.record_outcome_and_target(
                    custody.public_observation().unwrap(),
                    RecoveryRelation::IntendedOutcome,
                )
            };
            assert!(result.is_err(), "stage{stage} {point}");
            FAULT.with(|v| *v.borrow_mut() = None);
            drop(session);
            let marker = owner.files.read(MARKER, false).unwrap();
            let names = list(&owner.files.records().unwrap(), 6).unwrap();
            let original: Vec<_> = names
                .iter()
                .map(|n| (n.clone(), owner.files.read(n, true).unwrap()))
                .collect();
            if owner.files.exists(TEMP, false).unwrap() {
                assert!(owner
                    .begin_recovery(f.pin, id, &wallet, custody.public_observation().unwrap())
                    .is_err());
                owner
                    .discard_uncommitted_transition_temp(
                        f.pin,
                        id,
                        &wallet,
                        custody.public_observation().unwrap(),
                    )
                    .unwrap();
                assert_eq!(owner.files.read(MARKER, false).unwrap(), marker);
                for (n, bytes) in &original {
                    assert_eq!(owner.files.read(n, true).unwrap(), *bytes);
                }
            }
            let mut resumed = owner
                .begin_recovery(f.pin, id, &wallet, custody.public_observation().unwrap())
                .unwrap();
            if resumed.marker.as_ref().unwrap().value["stage"] == "prepared" {
                resumed
                    .record_outcome_and_target(
                        custody.public_observation().unwrap(),
                        RecoveryRelation::IntendedOutcome,
                    )
                    .unwrap();
            }
            for (n, bytes) in &original {
                assert_eq!(
                    owner.files.read(n, true).unwrap(),
                    *bytes,
                    "stage{stage} {point} {n}"
                );
            }
            resumed
                .publish_recorded_target(custody.public_observation().unwrap())
                .unwrap();
            resumed
                .finalize_recorded_transition(custody.public_observation().unwrap())
                .unwrap();
            assert_eq!(
                list(owner.files.root(), 5).unwrap(),
                vec![LOCK.to_owned(), CURRENT.to_owned()]
            );
        }
    }
}

#[test]
fn interrupted_tombstone_rename_is_resynced_before_any_record_deletion() {
    let _time = TestTime::set(100);
    let w = WalletFiles::new();
    let wallet = w.source();
    let f = OwnerFiles::new(&w);
    let owner = f.source();
    let root = ServiceRoot::open(w.path()).unwrap();
    let mut custody = root.lock_exclusive().unwrap();
    let mut session = owner
        .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
        .unwrap();
    let (next, input) = w.configure();
    {
        let _prepared = session
            .prepare_wallet_transition(
                custody.public_observation().unwrap(),
                WalletTransitionIntent::Configure {
                    owner_input: input.clone(),
                },
                &canonical(&policy()),
            )
            .unwrap();
    }
    let id = session.transition_id().unwrap();
    w.publish(&mut custody, &next, Some(&input), true);
    session
        .record_outcome_and_target(
            custody.public_observation().unwrap(),
            RecoveryRelation::IntendedOutcome,
        )
        .unwrap();
    session
        .publish_recorded_target(custody.public_observation().unwrap())
        .unwrap();
    FAULT.with(|v| *v.borrow_mut() = Some(format!("renamed_before_sync:{TEMP}")));
    assert!(session
        .finalize_recorded_transition(custody.public_observation().unwrap())
        .is_err());
    FAULT.with(|v| *v.borrow_mut() = None);
    drop(session);
    assert_eq!(list(&owner.files.records().unwrap(), 6).unwrap().len(), 6);
    let mut resumed = owner
        .begin_recovery(f.pin, id, &wallet, custody.public_observation().unwrap())
        .unwrap();
    FAULT.with(|v| *v.borrow_mut() = Some("tombstone_root_synced".into()));
    assert!(resumed
        .finalize_recorded_transition(custody.public_observation().unwrap())
        .is_err());
    FAULT.with(|v| *v.borrow_mut() = None);
    assert_eq!(list(&owner.files.records().unwrap(), 6).unwrap().len(), 6);
    resumed
        .finalize_recorded_transition(custody.public_observation().unwrap())
        .unwrap();
    assert_eq!(
        list(owner.files.root(), 5).unwrap(),
        vec![LOCK.to_owned(), CURRENT.to_owned()]
    );
}

#[test]
fn poison_preflight_moves_same_native_file_then_requires_second_actual_epoch_advance() {
    let _time = TestTime::set(100);
    for changed in [false, true] {
        let w = WalletFiles::new();
        let wallet = w.source();
        let f = OwnerFiles::new(&w);
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let mut custody = root.lock_exclusive().unwrap();
        let held_custody_lock = custody.lock_identity();
        let mut session = owner
            .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
            .unwrap();
        let held_native_fd = session.lock.as_raw_fd();
        let (next, input) = w.configure();
        let intent = if changed {
            WalletTransitionIntent::Configure {
                owner_input: input.clone(),
            }
        } else {
            WalletTransitionIntent::Reconcile
        };
        {
            let _prepared = session
                .prepare_wallet_transition(
                    custody.public_observation().unwrap(),
                    intent,
                    &canonical(&policy()),
                )
                .unwrap();
        }
        let id = session.transition_id().unwrap();
        if changed {
            w.publish(&mut custody, &next, Some(&input), true);
        }
        // Native metadata tests deliberately use real FS poison and repair,
        // never pretend this sentinel-seed fixture is real custody validation.
        custody.invalidate(true).unwrap();
        assert!(custody.poisoned().unwrap());
        assert!(custody.public_observation().is_err());
        let preflight = session.into_wallet_recovery_preflight().unwrap();
        assert_eq!(preflight.lock.as_raw_fd(), held_native_fd);
        {
            let fence = preflight.reconciliation_fence().unwrap();
            assert_eq!(fence.transition_id(), id);
            assert_eq!(fence.old_wallet_state_bytes(), canonical(&w.state));
            assert_eq!(
                fence.selected_wallet_root_identity(),
                wallet.configured_root_identity()
            );
            assert_eq!(
                fence.old_wallet_startup_pin_bytes(),
                wallet.configured_startup_pin_bytes()
            );
            assert_eq!(
                fence.configure_owner_input_bytes(),
                changed.then_some(input.as_slice())
            );
            assert!(fence.requested_rotation_window().is_none());
            fence.revalidate().unwrap();
            assert!(owner.lock(false).is_err());
            assert!(root.lock_shared().is_err());
            assert!(custody.public_observation().is_err());
            custody.sync_current().unwrap();
            custody.discard_temporary().unwrap();
            custody.invalidate(false).unwrap();
            fence.revalidate().unwrap();
        }
        let mut recovered = preflight
            .resume_with_actual_wallet(custody.public_observation().unwrap())
            .unwrap();
        assert_eq!(recovered.lock.as_raw_fd(), held_native_fd);
        assert_eq!(custody.lock_identity(), held_custody_lock);
        assert!(owner.lock(false).is_err());
        assert!(root.lock_shared().is_err());
        if !changed {
            assert!(recovered
                .record_outcome_and_target(
                    custody.public_observation().unwrap(),
                    RecoveryRelation::ReconciledUnchanged
                )
                .is_err());
        }
        let current = if changed { &next } else { &w.state };
        {
            let guard = recovered.recovery_reconciliation_guard().unwrap();
            assert!(guard
                .authorize_reconcile(
                    custody.public_observation().unwrap(),
                    &WalletExpectedCurrent {
                        state_revision: 99,
                        state_sha256: hash(&canonical(current))
                    }
                )
                .is_err());
            guard
                .authorize_reconcile(
                    custody.public_observation().unwrap(),
                    &WalletExpectedCurrent {
                        state_revision: current["state_revision"].as_u64().unwrap(),
                        state_sha256: hash(&canonical(current)),
                    },
                )
                .unwrap();
        }
        custody.sync_current().unwrap();
        custody.discard_temporary().unwrap();
        custody.invalidate(false).unwrap();
        let pin = recovered
            .record_outcome_and_target(
                custody.public_observation().unwrap(),
                if changed {
                    RecoveryRelation::IntendedOutcome
                } else {
                    RecoveryRelation::ReconciledUnchanged
                },
            )
            .unwrap();
        assert_eq!(pin.generation(), 2);
        recovered
            .publish_recorded_target(custody.public_observation().unwrap())
            .unwrap();
        recovered
            .finalize_recorded_transition(custody.public_observation().unwrap())
            .unwrap();
        assert_eq!(custody.lock_identity(), held_custody_lock);
        assert_eq!(
            list(owner.files.root(), 5).unwrap(),
            vec![LOCK.to_owned(), CURRENT.to_owned()]
        );
    }
}

#[test]
fn poison_preflight_denies_nonprepared_incomplete_drift_and_clock_before_any_repair() {
    let _time = TestTime::set(100);
    for bad in [
        "id",
        "cas",
        "temp",
        "outcome",
        "target",
        "stage",
        "old_state",
        "policy",
        "request",
        "current",
        "lock",
        "clock",
    ] {
        let w = WalletFiles::new();
        let wallet = w.source();
        let f = OwnerFiles::new(&w);
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let mut custody = root.lock_exclusive().unwrap();
        let mut session = owner
            .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
            .unwrap();
        let (_, input) = w.configure();
        {
            let _prepared = session
                .prepare_wallet_transition(
                    custody.public_observation().unwrap(),
                    WalletTransitionIntent::Configure { owner_input: input },
                    &canonical(&policy()),
                )
                .unwrap();
        }
        let id = session.transition_id().unwrap();
        custody.invalidate(true).unwrap();
        let clock = fs::read(w.path().join("CLOCK")).unwrap();
        if bad == "lock" {
            fs::remove_file(f.dir.path().join(LOCK)).unwrap();
            private_file(&f.dir.path().join(LOCK), b"");
            assert!(session.into_wallet_recovery_preflight().is_err());
        } else {
            drop(session);
            match bad {
                "temp" => private_file(&f.dir.path().join(TEMP), b"partial"),
                "outcome" => private_file(&f.dir.path().join(RECORDS).join("OUTCOME.json"), b"{}"),
                "target" => private_file(
                    &f.dir.path().join(RECORDS).join("TARGET-NATIVE.json"),
                    b"{}",
                ),
                "stage" => {
                    let mut marker: Value =
                        serde_json::from_slice(&owner.files.read(MARKER, false).unwrap()).unwrap();
                    marker["stage"] = json!("outcome_recorded");
                    fs::write(f.dir.path().join(MARKER), canonical(&marker)).unwrap();
                }
                "old_state" => {
                    fs::remove_file(f.dir.path().join(RECORDS).join("OLD-WALLET-STATE.json"))
                        .unwrap();
                }
                "policy" => {
                    fs::write(f.dir.path().join(RECORDS).join("TARGET-POLICY.json"), b"{}").unwrap()
                }
                "request" => fs::write(
                    f.dir.path().join(RECORDS).join("REQUEST-OWNER-INPUT.json"),
                    b"{}",
                )
                .unwrap(),
                "current" => fs::write(f.dir.path().join(CURRENT), b"{}").unwrap(),
                "clock" => crate::service_wallet_source::TEST_NOW.with(|v| v.set(Some(99))),
                _ => {}
            }
            assert!(
                owner
                    .begin_wallet_recovery_preflight(
                        if bad == "cas" {
                            OwnerStartupPin::new(2, [7; 32]).unwrap()
                        } else {
                            f.pin
                        },
                        if bad == "id" { [9; 16] } else { id },
                        &wallet
                    )
                    .is_err(),
                "{bad}"
            );
            crate::service_wallet_source::TEST_NOW.with(|v| v.set(Some(100)));
        }
        assert!(custody.poisoned().unwrap(), "{bad}");
        assert!(custody.public_observation().is_err(), "{bad}");
        assert_eq!(fs::read(w.path().join("CLOCK")).unwrap(), clock, "{bad}");
        assert!(owner.files.exists(MARKER, false).unwrap());
    }
}

#[test]
fn poison_preflight_resume_rejects_actual_wrong_predecessor_and_root_without_relocking() {
    let _time = TestTime::set(100);
    for bad in ["previous", "created", "root"] {
        let w = WalletFiles::new();
        let wallet = w.source();
        let f = OwnerFiles::new(&w);
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let mut custody = root.lock_exclusive().unwrap();
        let mut session = owner
            .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
            .unwrap();
        let (mut next, input) = w.configure();
        {
            let _prepared = session
                .prepare_wallet_transition(
                    custody.public_observation().unwrap(),
                    WalletTransitionIntent::Configure {
                        owner_input: input.clone(),
                    },
                    &canonical(&policy()),
                )
                .unwrap();
        }
        if bad == "previous" {
            next["previous_state_sha256"] = json!("11".repeat(32));
        }
        if bad == "created" {
            next["created_at"] = json!(79);
        }
        w.publish(&mut custody, &next, Some(&input), true);
        custody.invalidate(true).unwrap();
        let preflight = session.into_wallet_recovery_preflight().unwrap();
        custody.sync_current().unwrap();
        custody.discard_temporary().unwrap();
        custody.invalidate(false).unwrap();
        if bad == "root" {
            let foreign = WalletFiles::new();
            let foreign_root = ServiceRoot::open(foreign.path()).unwrap();
            let foreign_lease = foreign_root.lock_exclusive().unwrap();
            assert!(preflight
                .resume_with_actual_wallet(foreign_lease.public_observation().unwrap())
                .is_err());
        } else {
            assert!(
                preflight
                    .resume_with_actual_wallet(custody.public_observation().unwrap())
                    .is_err(),
                "{bad}"
            );
        }
        assert!(owner.files.exists(MARKER, false).unwrap());
        assert!(!owner.files.exists("OUTCOME.json", true).unwrap());
        assert!(!custody.poisoned().unwrap());
    }
}

#[test]
fn poison_preflight_rejects_independent_old_wallet_pin_minima_and_reference_drift() {
    let _time = TestTime::set(100);
    for field in [
        "minimum_state_revision",
        "minimum_key_generation",
        "expected_wallet_reference_sha256",
        "store_id",
    ] {
        let w = WalletFiles::new();
        let wallet = w.source();
        let f = OwnerFiles::new(&w);
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let mut custody = root.lock_exclusive().unwrap();
        let mut session = owner
            .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
            .unwrap();
        {
            let _prepared = session
                .prepare_wallet_transition(
                    custody.public_observation().unwrap(),
                    WalletTransitionIntent::Reconcile,
                    &canonical(&policy()),
                )
                .unwrap();
        }
        let id = session.transition_id().unwrap();
        custody.invalidate(true).unwrap();
        drop(session);
        let mut pin: Value =
            serde_json::from_slice(&wallet.configured_startup_pin_bytes()).unwrap();
        pin[field] = match field {
            "store_id" => json!("11".repeat(16)),
            "expected_wallet_reference_sha256" => json!("11".repeat(32)),
            _ => json!(2),
        };
        let changed = WalletCurrentSource::open(
            crate::service_wallet_source::OwnerSelectedWalletRoot::open(w.path()).unwrap(),
            crate::service_wallet_source::StartupWalletObservationPin::parse_owner_configuration(
                &canonical(&pin),
            )
            .unwrap(),
        )
        .unwrap();
        let clock = fs::read(w.path().join("CLOCK")).unwrap();
        assert!(
            owner
                .begin_wallet_recovery_preflight(f.pin, id, &changed)
                .is_err(),
            "{field}"
        );
        assert!(custody.poisoned().unwrap());
        assert_eq!(fs::read(w.path().join("CLOCK")).unwrap(), clock);
    }
}

#[test]
fn real_completed_tombstone_denies_old_unqualified_owner_helper_until_new_pin_cleanup() {
    struct At100;
    impl crate::service_challenge_store::Clock for At100 {
        fn now(&self) -> u64 {
            100
        }
    }
    let _time = TestTime::set(100);
    let (w, _old, new_wallet, f, target, id) = completed_tombstone();
    let helper = crate::service_authority_snapshot::OwnerSource::open(
        f.dir.path(),
        target.generation(),
        target.sha256(),
    )
    .unwrap();
    assert!(helper.lease(&At100).is_err());
    let root = ServiceRoot::open(w.path()).unwrap();
    let custody = root.lock_exclusive().unwrap();
    f.source()
        .cleanup_completed_wallet_transition(
            target,
            id,
            &new_wallet,
            custody.public_observation().unwrap(),
        )
        .unwrap();
    drop(custody);
    drop(helper.lease(&At100).unwrap());
}

#[test]
fn changed_delegation_policy_supports_intended_outcome_but_incompatible_unchanged_stays_fenced() {
    let _time = TestTime::set(100);
    for intended in [false, true] {
        let w = WalletFiles::new();
        let (active, initial_input) = w.configure();
        let root = ServiceRoot::open(w.path()).unwrap();
        {
            let mut lease = root.lock_exclusive().unwrap();
            w.publish(&mut lease, &active, Some(&initial_input), true);
        }
        let wallet = w.source();
        let f = OwnerFiles::new(&w);
        let owner = f.source();
        let mut custody = root.lock_exclusive().unwrap();
        let mut session = owner
            .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
            .unwrap();
        let mut new_policy = policy();
        new_policy["receiver_policy"]["rules"][0]["resource"] = json!("runs/run-2");
        let mut input: Value = serde_json::from_slice(&w.owner_input(3)).unwrap();
        input["delegation_policy"] = new_policy["receiver_policy"].clone();
        let input = canonical(&input);
        let exact_policy = canonical(&new_policy);
        {
            let _prepared = session
                .prepare_wallet_transition(
                    custody.public_observation().unwrap(),
                    WalletTransitionIntent::Configure {
                        owner_input: input.clone(),
                    },
                    &exact_policy,
                )
                .unwrap();
        }
        let id = session.transition_id().unwrap();
        if intended {
            let mut next = active.clone();
            next["state_revision"] = json!(3);
            next["previous_state_sha256"] = json!(hex(&hash(&canonical(&active))));
            next["owner_input_sha256"] = json!(hex(&hash(&input)));
            w.publish(&mut custody, &next, Some(&input), true);
            session
                .record_outcome_and_target(
                    custody.public_observation().unwrap(),
                    RecoveryRelation::IntendedOutcome,
                )
                .unwrap();
            session
                .publish_recorded_target(custody.public_observation().unwrap())
                .unwrap();
            session
                .finalize_recorded_transition(custody.public_observation().unwrap())
                .unwrap();
        } else {
            drop(session);
            let mut resumed = owner
                .begin_recovery(f.pin, id, &wallet, custody.public_observation().unwrap())
                .unwrap();
            resumed
                .recovery_reconciliation_guard()
                .unwrap()
                .authorize_reconcile(
                    custody.public_observation().unwrap(),
                    &WalletExpectedCurrent {
                        state_revision: 2,
                        state_sha256: hash(&canonical(&active)),
                    },
                )
                .unwrap();
            custody.invalidate(false).unwrap();
            assert!(resumed
                .record_outcome_and_target(
                    custody.public_observation().unwrap(),
                    RecoveryRelation::ExplicitAbortUnchanged
                )
                .is_err());
            assert!(owner.files.exists(MARKER, false).unwrap());
            assert_eq!(
                owner.files.read("TARGET-POLICY.json", true).unwrap(),
                exact_policy
            );
            assert_eq!(
                hash(&owner.files.read(CURRENT, false).unwrap()),
                f.pin.sha256()
            );
            assert!(!owner.files.exists("OUTCOME.json", true).unwrap());
            assert!(!owner.files.exists("TARGET-NATIVE.json", true).unwrap());
        }
    }
}

// Fresh processes probe the real selected files, rather than Native's local
// source registry. Codes distinguish exclusion from an unexpected child error.
fn retaining_child_can_lock(path: &Path, shared: bool) -> bool {
    let status = Command::new("python3")
        .arg("-c")
        .arg("import fcntl,sys\nf=open(sys.argv[1],'r+')\ntry:fcntl.flock(f,(fcntl.LOCK_SH if sys.argv[2]=='shared' else fcntl.LOCK_EX)|fcntl.LOCK_NB)\nexcept BlockingIOError:sys.exit(87)\nsys.exit(0)")
        .arg(path)
        .arg(if shared { "shared" } else { "exclusive" })
        .status()
        .unwrap();
    match status.code() {
        Some(0) => true,
        Some(87) => false,
        code => panic!("unexpected lock probe status {code:?}"),
    }
}
fn retaining_native_images(owner: &OwnerPublicationSource) -> BTreeMap<String, Vec<u8>> {
    let mut images = BTreeMap::new();
    for name in list(owner.files.root(), 5).unwrap() {
        if name == RECORDS {
            for record in list(&owner.files.records().unwrap(), 6).unwrap() {
                images.insert(
                    format!("{RECORDS}/{record}"),
                    owner.files.read(&record, true).unwrap(),
                );
            }
        } else {
            images.insert(name.clone(), owner.files.read(&name, false).unwrap());
        }
    }
    images
}
#[test]
fn retaining_characterizes_compatible_consuming_error_wrappers_releasing_native_only() {
    let _time = TestTime::set(100);
    for after_move in [false, true] {
        let w = WalletFiles::new();
        let wallet = w.source();
        let f = OwnerFiles::new(&w);
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let mut custody = root.lock_exclusive().unwrap();
        let mut session = owner
            .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
            .unwrap();
        {
            let _prepared = session
                .prepare_wallet_transition(
                    custody.public_observation().unwrap(),
                    WalletTransitionIntent::Reconcile,
                    &canonical(&policy()),
                )
                .unwrap();
        }
        if after_move {
            let preflight = session.into_wallet_recovery_preflight().unwrap();
            let (next, input) = w.configure();
            w.publish(&mut custody, &next, Some(&input), true);
            let images = retaining_native_images(&owner);
            assert!(preflight
                .resume_with_actual_wallet(custody.public_observation().unwrap())
                .is_err());
            assert_eq!(retaining_native_images(&owner), images);
        } else {
            private_file(&f.dir.path().join(TEMP), b"partial");
            let images = retaining_native_images(&owner);
            assert!(session.into_wallet_recovery_preflight().is_err());
            assert_eq!(retaining_native_images(&owner), images);
        }
        // This records the original compatibility behavior, not a successful
        // retained recovery. Its durable marker continues to deny admission.
        assert!(retaining_child_can_lock(&f.dir.path().join(LOCK), false));
        assert!(!retaining_child_can_lock(
            &w.path().join("custody.lock"),
            false
        ));
        assert!(owner.files.exists(MARKER, false).unwrap());
        assert!(!owner.files.exists("OUTCOME.json", true).unwrap());
        assert!(!owner.files.exists("TARGET-NATIVE.json", true).unwrap());
    }
}

fn retaining_assert_both_locks_held(owner_path: &Path, wallet_path: &Path) {
    assert!(!retaining_child_can_lock(&owner_path.join(LOCK), false));
    assert!(!retaining_child_can_lock(&owner_path.join(LOCK), true));
    assert!(!retaining_child_can_lock(
        &wallet_path.join("custody.lock"),
        false
    ));
}
fn retaining_expect_success<T, O>(result: std::result::Result<T, Box<(SourceError, O)>>) -> T {
    match result {
        Ok(value) => value,
        Err(failure) => panic!("unexpected retaining failure: {:?}", failure.0),
    }
}
#[test]
fn retaining_conversion_returns_same_session_on_repeated_validation_errors() {
    let _time = TestTime::set(100);
    for bad in ["temp", "state", "policy", "marker", "clock"] {
        let w = WalletFiles::new();
        let wallet = w.source();
        let f = OwnerFiles::new(&w);
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let custody = root.lock_exclusive().unwrap();
        let mut session = owner
            .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
            .unwrap();
        {
            let _prepared = session
                .prepare_wallet_transition(
                    custody.public_observation().unwrap(),
                    WalletTransitionIntent::Reconcile,
                    &canonical(&policy()),
                )
                .unwrap();
        }
        let held_fd = session.lock.as_raw_fd();
        let held_identity = id(&session.lock).unwrap();
        let old_native = session.old_raw.clone();
        let old_wallet = session.old_wallet.state_raw.clone();
        let old_epoch = session.old_wallet.epoch;
        let old_marker = session.marker.as_ref().unwrap().canonical_bytes().to_vec();
        match bad {
            "temp" => private_file(&f.dir.path().join(TEMP), b"partial"),
            "state" => {
                fs::remove_file(f.dir.path().join(RECORDS).join("OLD-WALLET-STATE.json")).unwrap()
            }
            "policy" => {
                fs::write(f.dir.path().join(RECORDS).join("TARGET-POLICY.json"), b"{}").unwrap()
            }
            "marker" => fs::write(f.dir.path().join(MARKER), b"{}").unwrap(),
            "clock" => crate::service_wallet_source::TEST_NOW.with(|v| v.set(Some(99))),
            _ => unreachable!(),
        }
        let images = retaining_native_images(&owner);
        let clock = fs::read(w.path().join("CLOCK")).unwrap();
        for _ in 0..2 {
            session = match session.into_wallet_recovery_preflight_retaining() {
                Ok(_) => panic!("{bad} unexpectedly converted"),
                Err(failure) => {
                    let (_error, original_session) = *failure;
                    original_session
                }
            };
            assert_eq!(session.lock.as_raw_fd(), held_fd, "{bad}");
            assert_eq!(id(&session.lock).unwrap(), held_identity, "{bad}");
            assert_eq!(session.old_raw, old_native, "{bad}");
            assert_eq!(session.old_wallet.state_raw, old_wallet, "{bad}");
            assert_eq!(session.old_wallet.epoch, old_epoch, "{bad}");
            assert_eq!(
                session.marker.as_ref().unwrap().canonical_bytes(),
                old_marker,
                "{bad}"
            );
            assert_eq!(retaining_native_images(&owner), images, "{bad}");
            assert_eq!(fs::read(w.path().join("CLOCK")).unwrap(), clock, "{bad}");
            retaining_assert_both_locks_held(f.dir.path(), w.path());
            assert!(session.recovery_reconciliation_guard().is_err());
            assert!(!owner.files.exists("OUTCOME.json", true).unwrap());
            assert!(!owner.files.exists("TARGET-NATIVE.json", true).unwrap());
        }
        // Corrupt/missing originals and an ambiguous temp stay fenced. This
        // API does not repair them or clear a durable transition fence.
        drop(session);
        assert!(retaining_child_can_lock(&f.dir.path().join(LOCK), false));
        assert!(!retaining_child_can_lock(
            &w.path().join("custody.lock"),
            false
        ));
        crate::service_wallet_source::TEST_NOW.with(|v| v.set(Some(100)));
    }
}
#[test]
fn retaining_resume_preserves_original_preflight_before_and_after_file_move() {
    let _time = TestTime::set(100);
    for bad in ["temp", "relation"] {
        let w = WalletFiles::new();
        let wallet = w.source();
        let f = OwnerFiles::new(&w);
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let mut custody = root.lock_exclusive().unwrap();
        let mut session = owner
            .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
            .unwrap();
        {
            let _prepared = session
                .prepare_wallet_transition(
                    custody.public_observation().unwrap(),
                    WalletTransitionIntent::Reconcile,
                    &canonical(&policy()),
                )
                .unwrap();
        }
        let mut preflight =
            retaining_expect_success(session.into_wallet_recovery_preflight_retaining());
        let held_fd = preflight.lock.as_raw_fd();
        let held_identity = id(&preflight.lock).unwrap();
        let originals = (
            preflight.data.marker.canonical_bytes().to_vec(),
            preflight.data.old_raw.clone(),
            preflight.data.reference.canonical_bytes().to_vec(),
            preflight.data.state_raw.clone(),
            preflight.data.policy_raw.clone(),
            preflight.data.configure_raw.clone(),
        );
        if bad == "temp" {
            private_file(&f.dir.path().join(TEMP), b"partial");
        } else {
            // A real selected same-root current changed by an unrelated
            // configure cannot satisfy the original reconcile relation.
            let (next, input) = w.configure();
            w.publish(&mut custody, &next, Some(&input), true);
        }
        let images = retaining_native_images(&owner);
        let wallet_current = fs::read(w.path().join("CURRENT")).unwrap();
        let clock = fs::read(w.path().join("CLOCK")).unwrap();
        for _ in 0..2 {
            preflight = match preflight
                .resume_with_actual_wallet_retaining(custody.public_observation().unwrap())
            {
                Ok(_) => panic!("{bad} unexpectedly resumed"),
                Err(failure) => {
                    let (_error, original_preflight) = *failure;
                    original_preflight
                }
            };
            assert_eq!(preflight.lock.as_raw_fd(), held_fd, "{bad}");
            assert_eq!(id(&preflight.lock).unwrap(), held_identity, "{bad}");
            assert_eq!(
                preflight.data.marker.canonical_bytes(),
                originals.0,
                "{bad}"
            );
            assert_eq!(preflight.data.old_raw, originals.1, "{bad}");
            assert_eq!(
                preflight.data.reference.canonical_bytes(),
                originals.2,
                "{bad}"
            );
            assert_eq!(preflight.data.state_raw, originals.3, "{bad}");
            assert_eq!(preflight.data.policy_raw, originals.4, "{bad}");
            assert_eq!(preflight.data.configure_raw, originals.5, "{bad}");
            assert_eq!(retaining_native_images(&owner), images, "{bad}");
            assert_eq!(
                fs::read(w.path().join("CURRENT")).unwrap(),
                wallet_current,
                "{bad}"
            );
            assert_eq!(fs::read(w.path().join("CLOCK")).unwrap(), clock, "{bad}");
            retaining_assert_both_locks_held(f.dir.path(), w.path());
            assert!(!owner.files.exists("OUTCOME.json", true).unwrap());
            assert!(!owner.files.exists("TARGET-NATIVE.json", true).unwrap());
        }
        drop(preflight);
        assert!(retaining_child_can_lock(&f.dir.path().join(LOCK), false));
        assert!(!retaining_child_can_lock(
            &w.path().join("custody.lock"),
            false
        ));
    }
}
#[test]
fn retaining_resume_correct_view_or_readonly_checkpoint_retry_keeps_epoch_rule() {
    let _time = TestTime::set(100);
    for bad in ["foreign_root", "checkpoint"] {
        let w = WalletFiles::new();
        let wallet = w.source();
        let f = OwnerFiles::new(&w);
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let mut custody = root.lock_exclusive().unwrap();
        let held_custody = custody.lock_identity();
        let mut session = owner
            .begin_administration(f.pin, &wallet, custody.public_observation().unwrap())
            .unwrap();
        {
            let _prepared = session
                .prepare_wallet_transition(
                    custody.public_observation().unwrap(),
                    WalletTransitionIntent::Reconcile,
                    &canonical(&policy()),
                )
                .unwrap();
        }
        let held_fd = session.lock.as_raw_fd();
        let held_identity = id(&session.lock).unwrap();
        let preflight =
            retaining_expect_success(session.into_wallet_recovery_preflight_retaining());
        let images = retaining_native_images(&owner);
        let originals = (
            preflight.data.policy_raw.clone(),
            preflight.data.configure_raw.clone(),
        );
        let foreign = WalletFiles::new();
        let foreign_root = ServiceRoot::open(foreign.path()).unwrap();
        let foreign_custody = foreign_root.lock_exclusive().unwrap();
        if bad == "checkpoint" {
            FAULT.with(|v| *v.borrow_mut() = Some("recovery_first_actual_view".into()));
        }
        let result = preflight.resume_with_actual_wallet_retaining(if bad == "foreign_root" {
            foreign_custody.public_observation().unwrap()
        } else {
            custody.public_observation().unwrap()
        });
        FAULT.with(|v| *v.borrow_mut() = None);
        let preflight = match result {
            Ok(_) => panic!("{bad} unexpectedly resumed"),
            Err(failure) => {
                let (_error, original_preflight) = *failure;
                original_preflight
            }
        };
        assert_eq!(preflight.lock.as_raw_fd(), held_fd);
        assert_eq!(id(&preflight.lock).unwrap(), held_identity);
        assert_eq!(preflight.data.policy_raw, originals.0);
        assert_eq!(preflight.data.configure_raw, originals.1);
        assert_eq!(retaining_native_images(&owner), images);
        retaining_assert_both_locks_held(f.dir.path(), w.path());
        preflight
            .reconciliation_fence()
            .unwrap()
            .revalidate()
            .unwrap();
        let mut recovered = retaining_expect_success(
            preflight.resume_with_actual_wallet_retaining(custody.public_observation().unwrap()),
        );
        assert_eq!(recovered.lock.as_raw_fd(), held_fd);
        assert_eq!(id(&recovered.lock).unwrap(), held_identity);
        assert_eq!(custody.lock_identity(), held_custody);
        assert!(recovered
            .record_outcome_and_target(
                custody.public_observation().unwrap(),
                RecoveryRelation::ReconciledUnchanged
            )
            .is_err());
        assert_eq!(retaining_native_images(&owner), images);
        {
            let guard = recovered.recovery_reconciliation_guard().unwrap();
            guard
                .authorize_reconcile(
                    custody.public_observation().unwrap(),
                    &WalletExpectedCurrent {
                        state_revision: 1,
                        state_sha256: hash(&canonical(&w.state)),
                    },
                )
                .unwrap();
        }
        // Real FS epoch progress; this metadata-only fixture is not actual
        // Wallet private seed/CAS validation or joint crash qualification.
        custody.sync_current().unwrap();
        custody.discard_temporary().unwrap();
        custody.invalidate(false).unwrap();
        let pin = recovered
            .record_outcome_and_target(
                custody.public_observation().unwrap(),
                RecoveryRelation::ReconciledUnchanged,
            )
            .unwrap();
        recovered
            .publish_recorded_target(custody.public_observation().unwrap())
            .unwrap();
        recovered
            .finalize_recorded_transition(custody.public_observation().unwrap())
            .unwrap();
        assert_eq!(pin.generation(), 2);
        assert_eq!(recovered.lock.as_raw_fd(), held_fd);
        assert_eq!(id(&recovered.lock).unwrap(), held_identity);
        retaining_assert_both_locks_held(f.dir.path(), w.path());
        drop(recovered);
        assert!(retaining_child_can_lock(&f.dir.path().join(LOCK), false));
    }
}

#[path = "service_original_selection_tests.rs"]
mod original_selection;
