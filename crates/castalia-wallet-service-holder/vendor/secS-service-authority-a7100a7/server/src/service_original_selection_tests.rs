//! Native public-metadata fixtures only. Actual shared FS/OS locks/clock, with
//! fixed sentinel seed bytes; no real Wallet private custody/entropy claim.
use super::*;
use crate::service_wallet_source::tests::{
    audience_metadata_unconfigured, audience_request_fixture,
};
use castalia_wallet_private_files::service_store::{Identity, ServiceLease, StagingFile};
use libsec_core::service_holder_proof::ServiceApplication;
fn apps() -> [ServiceApplication; 2] {
    [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1]
}
fn current_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn owner_for(w: &WalletFiles, p: &Value) -> OwnerFiles {
    let dir = tempfile::tempdir_in("/private/tmp").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut v = p.clone();
    v["schema"] = json!("secs.service-owner-bundle.v2");
    v.as_object_mut().unwrap().remove("native_bundle_profile");
    v["generation"] = json!(1);
    v["wallet_current"] = w.observed().reference.value;
    let raw = canonical(&v);
    TargetBundle::parse(&raw).unwrap();
    private_file(&dir.path().join(CURRENT), &raw);
    private_file(&dir.path().join(LOCK), b"");
    OwnerFiles {
        dir,
        pin: OwnerStartupPin::new(1, hash(&raw)).unwrap(),
    }
}
struct OriginalBytes {
    roots: OriginalPhysicalRootIdentities,
    pin: OwnerStartupPin,
    native: Vec<u8>,
    startup: Vec<u8>,
    reference: Vec<u8>,
    state: Vec<u8>,
    policy: Vec<u8>,
}
impl OriginalBytes {
    fn before_call(
        owner: &OwnerPublicationSource,
        pin: OwnerStartupPin,
        wallet: &WalletCurrentSource,
        w: &WalletFiles,
        p: &Value,
    ) -> Self {
        let o = w.observed();
        Self {
            roots: OriginalPhysicalRootIdentities::from_owner_configuration(
                owner.files.identity.0,
                owner.files.identity.1,
                o.root.device,
                o.root.inode,
            ),
            pin,
            native: owner.files.read(CURRENT, false).unwrap(),
            startup: wallet.configured_startup_pin_bytes(),
            reference: o.reference.canonical_bytes().into(),
            state: o.state_raw,
            policy: canonical(p),
        }
    }
    fn selection(&self, intent: WalletTransitionIntent) -> OriginalTransitionSelection {
        OriginalTransitionSelection::new(
            self.roots,
            self.pin,
            self.native.clone(),
            self.startup.clone(),
            self.reference.clone(),
            self.state.clone(),
            intent,
            self.policy.clone(),
        )
        .unwrap()
    }
}
fn publish_metadata(w: &WalletFiles, l: &mut ServiceLease<'_>, next: &Value, input: Option<&[u8]>) {
    l.begin_staging().unwrap();
    if next["state"] != "revoked" {
        l.write_staging(StagingFile::Seed, &[0; 32]).unwrap();
    }
    l.write_staging(StagingFile::State, &canonical(next))
        .unwrap();
    if let Some(raw) = input {
        l.write_staging(StagingFile::OwnerInput, raw).unwrap();
    }
    l.sync_staging().unwrap();
    l.publish_revision(next["state_revision"].as_u64().unwrap())
        .unwrap();
    let pointer = json!({"schema":"castalia.wallet-service-custody-current.v1","store_id":next["store_id"],"state_revision":next["state_revision"],"state_sha256":hex(&hash(&canonical(next)))});
    l.publish_clock(&canonical(&json!({"schema":"castalia.wallet-service-custody-clock.v1","store_id":w.state["store_id"],"observed_at":current_time()})),true).unwrap();
    l.publish_current(&canonical(&pointer), true).unwrap();
    l.invalidate(false).unwrap();
}
fn configured_next(w: &WalletFiles, input: &[u8]) -> Value {
    let mut next = w.state.clone();
    next["state_revision"] = json!(2);
    next["state"] = json!("active");
    next["published_at"] = json!(current_time());
    next["owner_input_sha256"] = json!(hex(&hash(input)));
    next["previous_state_sha256"] = json!(hex(&hash(&canonical(&w.state))));
    next
}
fn identity(file: &File) -> (i32, u64, u64) {
    let m = file.metadata().unwrap();
    (file.as_raw_fd(), m.dev(), m.ino())
}
fn assert_inspection_held(
    i: &NativeOriginalTransitionInspection<'_, '_>,
    f: &OwnerFiles,
    w: &WalletFiles,
    before: (i32, u64, u64),
    saved: &OriginalBytes,
) {
    assert_eq!(identity(&i.lock), before);
    assert_eq!(
        i.original_wallet_data().old_wallet_startup_pin_bytes(),
        saved.startup
    );
    assert_eq!(
        i.original_wallet_data().old_wallet_state_bytes(),
        saved.state
    );
    assert_eq!(
        i.original_wallet_data().selected_wallet_root_identity(),
        saved.roots.wallet_identity()
    );
    retaining_assert_both_locks_held(f.dir.path(), w.path());
}
#[test]
fn original_root_getters_and_both_app_old_terminal_observation_are_data_only() {
    for app in apps() {
        let (p, _) = audience_request_fixture(app);
        let w = audience_metadata_unconfigured(&p);
        let wallet = w.source();
        let f = owner_for(&w, &p);
        let owner = f.source();
        let saved = OriginalBytes::before_call(&owner, f.pin, &wallet, &w, &p);
        assert_eq!(
            saved.roots.native_identity(),
            Identity {
                device: owner.files.identity.0,
                inode: owner.files.identity.1
            }
        );
        let root = ServiceRoot::open(w.path()).unwrap();
        let c = root.lock_exclusive().unwrap();
        let i = retaining_expect_success(owner.begin_original_transition_inspection(
            &wallet,
            saved.selection(WalletTransitionIntent::Reconcile),
        ));
        let fd = identity(&i.lock);
        let t = retaining_expect_success(
            i.into_terminal_observer_retaining(c.public_observation().unwrap()),
        );
        let data = t.observe(c.public_observation().unwrap()).unwrap();
        assert_eq!(
            data.disposition(),
            OriginalTerminalDisposition::OldSourceUnchanged
        );
        assert_eq!(data.wallet_startup_pin_bytes(), saved.startup);
        assert_eq!(identity(&t.inspection.lock), fd);
        retaining_assert_both_locks_held(f.dir.path(), w.path());
        assert!(list(owner.files.root(), 5)
            .unwrap()
            .iter()
            .all(|n| n == LOCK || n == CURRENT));
    }
}
#[test]
fn original_selection_rejects_wrong_original_images_minima_and_policy_application() {
    for app in apps() {
        let (p, _) = audience_request_fixture(app);
        let w = audience_metadata_unconfigured(&p);
        let wallet = w.source();
        let f = owner_for(&w, &p);
        let owner = f.source();
        let saved = OriginalBytes::before_call(&owner, f.pin, &wallet, &w, &p);
        for field in ["native", "reference", "state", "minima", "policy"] {
            let mut native = saved.native.clone();
            let mut reference = saved.reference.clone();
            let mut state = saved.state.clone();
            let mut startup = saved.startup.clone();
            let mut policy = saved.policy.clone();
            match field {
                "native" => native = b"{}".to_vec(),
                "reference" => reference = b"{}".to_vec(),
                "state" => state = b"{}".to_vec(),
                "policy" => {
                    let mut v: Value = serde_json::from_slice(&policy).unwrap();
                    v["application"] = json!("wrong");
                    policy = canonical(&v);
                }
                _ => {
                    let mut v: Value = serde_json::from_slice(&startup).unwrap();
                    v["minimum_state_revision"] = json!(2);
                    startup = canonical(&v);
                }
            }
            assert!(
                OriginalTransitionSelection::new(
                    saved.roots,
                    saved.pin,
                    native,
                    startup,
                    reference,
                    state,
                    WalletTransitionIntent::Reconcile,
                    policy
                )
                .is_err(),
                "{field}"
            );
        }
    }
}
#[test]
fn original_byte_identical_native_wallet_and_both_copied_roots_deny() {
    for app in apps() {
        let (p, _) = audience_request_fixture(app);
        let w = audience_metadata_unconfigured(&p);
        let wallet = w.source();
        let f = owner_for(&w, &p);
        let owner = f.source();
        let saved = OriginalBytes::before_call(&owner, f.pin, &wallet, &w, &p);
        // Recreate known public fixture images; never read/copy/hash seed bytes.
        let copied = audience_metadata_unconfigured(&p);
        fs::write(
            copied.path().join("CLOCK"),
            fs::read(w.path().join("CLOCK")).unwrap(),
        )
        .unwrap();
        let copied_wallet = copied.source();
        let nf = owner_for(&copied, &p);
        let no = nf.source();
        assert_eq!(
            owner.files.read(CURRENT, false).unwrap(),
            no.files.read(CURRENT, false).unwrap()
        );
        assert_eq!(
            w.observed().reference.canonical_bytes(),
            copied.observed().reference.canonical_bytes()
        );
        for (o, ws) in [
            (&no, &wallet),
            (&owner, &copied_wallet),
            (&no, &copied_wallet),
        ] {
            let images = retaining_native_images(o);
            assert!(o
                .begin_original_transition_inspection(
                    ws,
                    saved.selection(WalletTransitionIntent::Reconcile)
                )
                .is_err());
            assert_eq!(retaining_native_images(o), images);
        }
    }
}
#[test]
fn original_full_retaining_errors_before_and_after_move_preserve_exact_owners() {
    for app in apps() {
        for fault in ["original_full_before_move", "original_full_constructed"] {
            let (p, _) = audience_request_fixture(app);
            let w = audience_metadata_unconfigured(&p);
            let wallet = w.source();
            let f = owner_for(&w, &p);
            let owner = f.source();
            let saved = OriginalBytes::before_call(&owner, f.pin, &wallet, &w, &p);
            let root = ServiceRoot::open(w.path()).unwrap();
            let c = root.lock_exclusive().unwrap();
            let mut s = owner
                .begin_administration(f.pin, &wallet, c.public_observation().unwrap())
                .unwrap();
            s.prepare_wallet_transition(
                c.public_observation().unwrap(),
                WalletTransitionIntent::Reconcile,
                &saved.policy,
            )
            .unwrap();
            drop(s);
            let i = retaining_expect_success(owner.begin_original_transition_inspection(
                &wallet,
                saved.selection(WalletTransitionIntent::Reconcile),
            ));
            let fd = identity(&i.lock);
            let images = retaining_native_images(&owner);
            FAULT.with(|v| *v.borrow_mut() = Some(fault.into()));
            let failure = match i.into_full_recovery_retaining(c.public_observation().unwrap()) {
                Err(e) => e,
                Ok(_) => panic!("expected checked failure"),
            };
            FAULT.with(|v| *v.borrow_mut() = None);
            let (error, i) = *failure;
            assert_eq!(error, SourceError::PublicationUncertain);
            assert_inspection_held(&i, &f, &w, fd, &saved);
            assert_eq!(retaining_native_images(&owner), images);
            let s = retaining_expect_success(
                i.into_full_recovery_retaining(c.public_observation().unwrap()),
            );
            assert_eq!(identity(&s.lock), fd);
            assert_eq!(
                s.original_selection.as_ref().unwrap().startup_raw,
                saved.startup
            );
            retaining_assert_both_locks_held(f.dir.path(), w.path());
        }
    }
}
#[test]
fn original_prepared_poison_and_resume_keep_roots_and_require_second_epoch() {
    for app in apps() {
        let (p, _) = audience_request_fixture(app);
        let w = audience_metadata_unconfigured(&p);
        let wallet = w.source();
        let f = owner_for(&w, &p);
        let owner = f.source();
        let saved = OriginalBytes::before_call(&owner, f.pin, &wallet, &w, &p);
        let root = ServiceRoot::open(w.path()).unwrap();
        let mut c = root.lock_exclusive().unwrap();
        let mut s = owner
            .begin_administration(f.pin, &wallet, c.public_observation().unwrap())
            .unwrap();
        s.prepare_wallet_transition(
            c.public_observation().unwrap(),
            WalletTransitionIntent::Reconcile,
            &saved.policy,
        )
        .unwrap();
        drop(s);
        c.invalidate(true).unwrap();
        assert!(c.public_observation().is_err());
        let i = retaining_expect_success(owner.begin_original_transition_inspection(
            &wallet,
            saved.selection(WalletTransitionIntent::Reconcile),
        ));
        let fd = identity(&i.lock);
        let p = retaining_expect_success(i.into_prepared_recovery_preflight_retaining());
        {
            let fence = p.reconciliation_fence().unwrap();
            assert_eq!(
                fence.selected_wallet_root_identity(),
                saved.roots.wallet_identity()
            );
            assert_eq!(fence.old_wallet_startup_pin_bytes(), saved.startup);
        }
        // Real FS poison/epoch repair only; actual private Wallet repair is a separate coupled test obligation.
        c.invalidate(false).unwrap();
        let mut s = retaining_expect_success(
            p.resume_with_actual_wallet_retaining(c.public_observation().unwrap()),
        );
        assert_eq!(identity(&s.lock), fd);
        assert!(s
            .record_outcome_and_target(
                c.public_observation().unwrap(),
                RecoveryRelation::ReconciledUnchanged
            )
            .is_err());
        {
            let guard = s.recovery_reconciliation_guard().unwrap();
            guard
                .authorize_reconcile(
                    c.public_observation().unwrap(),
                    &WalletExpectedCurrent {
                        state_revision: 1,
                        state_sha256: hash(&saved.state),
                    },
                )
                .unwrap();
        }
        c.invalidate(false).unwrap();
        s.record_outcome_and_target(
            c.public_observation().unwrap(),
            RecoveryRelation::ReconciledUnchanged,
        )
        .unwrap();
        s.publish_recorded_target(c.public_observation().unwrap())
            .unwrap();
        s.finalize_recorded_transition(c.public_observation().unwrap())
            .unwrap();
        assert_eq!(s.original_selection.as_ref().unwrap().roots, saved.roots);
    }
}
#[test]
fn original_preflight_conversion_errors_return_same_file_without_any_observed_epoch() {
    for app in apps() {
        for fault in [
            "original_preflight_before_move",
            "original_preflight_constructed",
        ] {
            let (p, _) = audience_request_fixture(app);
            let w = audience_metadata_unconfigured(&p);
            let wallet = w.source();
            let f = owner_for(&w, &p);
            let owner = f.source();
            let saved = OriginalBytes::before_call(&owner, f.pin, &wallet, &w, &p);
            let root = ServiceRoot::open(w.path()).unwrap();
            let c = root.lock_exclusive().unwrap();
            let mut s = owner
                .begin_administration(f.pin, &wallet, c.public_observation().unwrap())
                .unwrap();
            s.prepare_wallet_transition(
                c.public_observation().unwrap(),
                WalletTransitionIntent::Reconcile,
                &saved.policy,
            )
            .unwrap();
            drop(s);
            let i = retaining_expect_success(owner.begin_original_transition_inspection(
                &wallet,
                saved.selection(WalletTransitionIntent::Reconcile),
            ));
            let fd = identity(&i.lock);
            let images = retaining_native_images(&owner);
            FAULT.with(|v| *v.borrow_mut() = Some(fault.into()));
            let failure = match i.into_prepared_recovery_preflight_retaining() {
                Err(e) => e,
                Ok(_) => panic!("expected retaining failure"),
            };
            FAULT.with(|v| *v.borrow_mut() = None);
            let (_, i) = *failure;
            assert_inspection_held(&i, &f, &w, fd, &saved);
            assert_eq!(retaining_native_images(&owner), images);
        }
    }
}
#[test]
fn original_s2_discard_retains_owners_and_requires_fresh_original_selector_interval() {
    for app in apps() {
        let (p, _) = audience_request_fixture(app);
        let w = audience_metadata_unconfigured(&p);
        let wallet = w.source();
        let f = owner_for(&w, &p);
        let owner = f.source();
        let saved = OriginalBytes::before_call(&owner, f.pin, &wallet, &w, &p);
        let root = ServiceRoot::open(w.path()).unwrap();
        let c = root.lock_exclusive().unwrap();
        let mut s = owner
            .begin_administration(f.pin, &wallet, c.public_observation().unwrap())
            .unwrap();
        s.prepare_wallet_transition(
            c.public_observation().unwrap(),
            WalletTransitionIntent::Reconcile,
            &saved.policy,
        )
        .unwrap();
        drop(s);
        private_file(&f.dir.path().join(TEMP), b"partial");
        let i = retaining_expect_success(owner.begin_original_transition_inspection(
            &wallet,
            saved.selection(WalletTransitionIntent::Reconcile),
        ));
        let fd = identity(&i.lock);
        let mut d = retaining_expect_success(
            i.into_temp_discard_retaining(c.public_observation().unwrap()),
        );
        let images = retaining_native_images(&owner);
        FAULT.with(|v| *v.borrow_mut() = Some("original_before_temp_unlink".into()));
        assert!(d.discard_temp(c.public_observation().unwrap()).is_err());
        FAULT.with(|v| *v.borrow_mut() = None);
        assert_eq!(identity(&d.inspection.lock), fd);
        assert_eq!(retaining_native_images(&owner), images);
        d.discard_temp(c.public_observation().unwrap()).unwrap();
        assert!(owner.files.exists(MARKER, false).unwrap());
        assert!(!owner.files.exists(TEMP, false).unwrap());
        retaining_assert_both_locks_held(f.dir.path(), w.path());
        drop(d);
        drop(c);
        let c = root.lock_exclusive().unwrap();
        let i = retaining_expect_success(owner.begin_original_transition_inspection(
            &wallet,
            saved.selection(WalletTransitionIntent::Reconcile),
        ));
        let _r = retaining_expect_success(
            i.into_full_recovery_retaining(c.public_observation().unwrap()),
        );
        retaining_assert_both_locks_held(f.dir.path(), w.path());
    }
}
fn completed_original(
    app: ServiceApplication,
) -> (
    WalletFiles,
    WalletCurrentSource,
    OwnerFiles,
    OriginalBytes,
    Vec<u8>,
    OwnerStartupPin,
) {
    let (p, input) = audience_request_fixture(app);
    let w = audience_metadata_unconfigured(&p);
    let wallet = w.source();
    let f = owner_for(&w, &p);
    let owner = f.source();
    let saved = OriginalBytes::before_call(&owner, f.pin, &wallet, &w, &p);
    let root = ServiceRoot::open(w.path()).unwrap();
    let mut c = root.lock_exclusive().unwrap();
    let mut s = owner
        .begin_administration(f.pin, &wallet, c.public_observation().unwrap())
        .unwrap();
    s.prepare_wallet_transition(
        c.public_observation().unwrap(),
        WalletTransitionIntent::Configure {
            owner_input: input.clone(),
        },
        &saved.policy,
    )
    .unwrap();
    let next = configured_next(&w, &input);
    publish_metadata(&w, &mut c, &next, Some(&input));
    let target = s
        .record_outcome_and_target(
            c.public_observation().unwrap(),
            RecoveryRelation::IntendedOutcome,
        )
        .unwrap();
    s.publish_recorded_target(c.public_observation().unwrap())
        .unwrap();
    FAULT.with(|v| *v.borrow_mut() = Some("tombstone_renamed".into()));
    assert!(s
        .finalize_recorded_transition(c.public_observation().unwrap())
        .is_err());
    FAULT.with(|v| *v.borrow_mut() = None);
    drop(s);
    drop(c);
    (w, wallet, f, saved, input, target)
}
#[test]
fn original_all64_completed_masks_both_apps_never_recreate_missing_history() {
    let names = [
        "OLD-NATIVE.json",
        "OLD-WALLET-STATE.json",
        "TARGET-POLICY.json",
        "REQUEST-OWNER-INPUT.json",
        "OUTCOME.json",
        "TARGET-NATIVE.json",
    ];
    for app in apps() {
        for mask in 0u8..64 {
            let (w, wallet, f, saved, input, target) = completed_original(app);
            let owner = f.source();
            for (i, n) in names.iter().enumerate() {
                if mask & (1 << i) == 0 {
                    fs::remove_file(f.dir.path().join(RECORDS).join(n)).unwrap();
                }
            }
            let root = ServiceRoot::open(w.path()).unwrap();
            let c = root.lock_exclusive().unwrap();
            let i = retaining_expect_success(owner.begin_original_transition_inspection(
                &wallet,
                saved.selection(WalletTransitionIntent::Configure { owner_input: input }),
            ));
            let fd = identity(&i.lock);
            let mut d = retaining_expect_success(
                i.into_completed_cleanup_retaining(c.public_observation().unwrap()),
            );
            let data = d.cleanup(c.public_observation().unwrap()).unwrap();
            assert_eq!(data.removed_records(), mask.count_ones() as usize);
            assert_eq!(identity(&d.inspection.lock), fd);
            let observed = d.observe_terminal(c.public_observation().unwrap()).unwrap();
            assert_eq!(
                observed.disposition(),
                OriginalTerminalDisposition::DerivedNewSource
            );
            assert_eq!(observed.native_generation(), target.generation());
            assert_eq!(observed.native_sha256(), target.sha256());
            assert!(!owner.files.exists(RECORDS, false).unwrap());
            assert!(!owner.files.exists(TEMP, false).unwrap());
            retaining_assert_both_locks_held(f.dir.path(), w.path());
        }
    }
}
#[test]
fn original_completed_present_mismatch_and_wrong_target_deny_without_erasing_evidence() {
    for app in apps() {
        for corrupt in ["P", "state", "outcome", "native"] {
            let (w, wallet, f, saved, input, _) = completed_original(app);
            let owner = f.source();
            let path = match corrupt {
                "P" => f.dir.path().join(RECORDS).join("TARGET-POLICY.json"),
                "state" => f.dir.path().join(RECORDS).join("OLD-WALLET-STATE.json"),
                "outcome" => f.dir.path().join(RECORDS).join("OUTCOME.json"),
                _ => f.dir.path().join(CURRENT),
            };
            fs::write(path, b"{}").unwrap();
            let root = ServiceRoot::open(w.path()).unwrap();
            let _c = root.lock_exclusive().unwrap();
            let images = retaining_native_images(&owner);
            assert!(owner
                .begin_original_transition_inspection(
                    &wallet,
                    saved.selection(WalletTransitionIntent::Configure { owner_input: input })
                )
                .is_err());
            assert_eq!(retaining_native_images(&owner), images);
        }
    }
}
#[test]
fn original_completed_uncertain_final_unlink_is_error_then_explicit_source_only_observation() {
    for app in apps() {
        let (w, wallet, f, saved, input, _) = completed_original(app);
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let c = root.lock_exclusive().unwrap();
        let i = retaining_expect_success(owner.begin_original_transition_inspection(
            &wallet,
            saved.selection(WalletTransitionIntent::Configure { owner_input: input }),
        ));
        let mut d = retaining_expect_success(
            i.into_completed_cleanup_retaining(c.public_observation().unwrap()),
        );
        let fd = identity(&d.inspection.lock);
        FAULT.with(|v| *v.borrow_mut() = Some(format!("unlinked_before_sync:{TEMP}")));
        assert!(d.cleanup(c.public_observation().unwrap()).is_err());
        FAULT.with(|v| *v.borrow_mut() = None);
        assert_eq!(identity(&d.inspection.lock), fd);
        assert!(!owner.files.exists(TEMP, false).unwrap());
        assert!(d.cleanup(c.public_observation().unwrap()).is_err());
        assert_eq!(
            d.observe_terminal(c.public_observation().unwrap())
                .unwrap()
                .disposition(),
            OriginalTerminalDisposition::DerivedNewSource
        );
        retaining_assert_both_locks_held(f.dir.path(), w.path());
    }
}

fn intent_for(kind: &str, input: &[u8], state: &Value) -> WalletTransitionIntent {
    match kind {
        "configure" => WalletTransitionIntent::Configure {
            owner_input: input.to_vec(),
        },
        "rotate" => WalletTransitionIntent::Rotate {
            not_before: state["not_before"].as_u64().unwrap(),
            not_after: state["not_after"].as_u64().unwrap(),
        },
        "revoke" => WalletTransitionIntent::Revoke,
        "reconcile" => WalletTransitionIntent::Reconcile,
        _ => panic!("closed test mutation"),
    }
}
// Actual durable Native checkpoints and public metadata only. No synthetic
// OutcomeRecord, observed time, private Wallet health or successful lease.
fn staged_original(
    app: ServiceApplication,
    kind: &str,
    stage: &str,
) -> (
    WalletFiles,
    WalletCurrentSource,
    OwnerFiles,
    OriginalBytes,
    Vec<u8>,
) {
    let (p, input) = audience_request_fixture(app);
    let w = audience_metadata_unconfigured(&p);
    let wallet = w.source();
    let f = owner_for(&w, &p);
    let owner = f.source();
    let saved = OriginalBytes::before_call(&owner, f.pin, &wallet, &w, &p);
    let root = ServiceRoot::open(w.path()).unwrap();
    let mut c = root.lock_exclusive().unwrap();
    let mut s = owner
        .begin_administration(f.pin, &wallet, c.public_observation().unwrap())
        .unwrap();
    s.prepare_wallet_transition(
        c.public_observation().unwrap(),
        intent_for(kind, &input, &w.state),
        &saved.policy,
    )
    .unwrap();
    if stage != "prepared_old" {
        if kind == "reconcile" {
            c.invalidate(false).unwrap();
        } else {
            let mut next = w.state.clone();
            next["state_revision"] = json!(2);
            next["previous_state_sha256"] = json!(hex(&hash(&saved.state)));
            next["published_at"] = json!(current_time());
            match kind {
                "configure" => next = configured_next(&w, &input),
                "rotate" => {
                    let key = ed25519_dalek::SigningKey::from_bytes(&[72; 32])
                        .verifying_key()
                        .to_bytes();
                    next["key_generation"] = json!(2);
                    next["key_created_at"] = next["published_at"].clone();
                    next["public_key_hex"] = json!(hex(&key));
                    next["public_key_sha256"] = json!(hex(&hash(&key)));
                    next["key_id"] = json!(format!("service-ed25519:sha256:{}", hex(&hash(&key))));
                }
                "revoke" => {
                    next["state"] = json!("revoked");
                    next["revoked_at"] = next["published_at"].clone();
                }
                _ => unreachable!(),
            }
            publish_metadata(
                &w,
                &mut c,
                &next,
                (kind == "configure").then_some(input.as_slice()),
            );
        }
        if stage != "prepared_current" {
            let relation = if kind == "reconcile" {
                RecoveryRelation::ReconciledUnchanged
            } else {
                RecoveryRelation::IntendedOutcome
            };
            if matches!(stage, "outcome_durable" | "target_durable") {
                FAULT.with(|v| *v.borrow_mut() = Some(stage.into()));
                assert!(s
                    .record_outcome_and_target(c.public_observation().unwrap(), relation)
                    .is_err());
                FAULT.with(|v| *v.borrow_mut() = None);
            } else {
                s.record_outcome_and_target(c.public_observation().unwrap(), relation)
                    .unwrap();
                if stage == "native_replaced" {
                    FAULT.with(|v| *v.borrow_mut() = Some(stage.into()));
                    assert!(s
                        .publish_recorded_target(c.public_observation().unwrap())
                        .is_err());
                    FAULT.with(|v| *v.borrow_mut() = None);
                } else if matches!(stage, "native_published" | "tombstone") {
                    s.publish_recorded_target(c.public_observation().unwrap())
                        .unwrap();
                    if stage == "tombstone" {
                        FAULT.with(|v| *v.borrow_mut() = Some("tombstone_renamed".into()));
                        assert!(s
                            .finalize_recorded_transition(c.public_observation().unwrap())
                            .is_err());
                        FAULT.with(|v| *v.borrow_mut() = None);
                    }
                }
            }
        }
    }
    drop(s);
    drop(c);
    (w, wallet, f, saved, input)
}
#[test]
fn original_all_mutations_admit_existing_full_and_s2_stage_current_output_matrix() {
    let stages = [
        "prepared_old",
        "prepared_current",
        "outcome_durable",
        "target_durable",
        "outcome_recorded",
        "native_replaced",
        "native_published",
    ];
    for app in apps() {
        for kind in ["configure", "rotate", "revoke", "reconcile"] {
            for stage in stages {
                for temp in [false, true] {
                    let (w, wallet, f, saved, input) = staged_original(app, kind, stage);
                    let owner = f.source();
                    if temp {
                        private_file(&f.dir.path().join(TEMP), b"uncommitted partial bytes");
                    }
                    let root = ServiceRoot::open(w.path()).unwrap();
                    let c = root.lock_exclusive().unwrap();
                    let i = retaining_expect_success(owner.begin_original_transition_inspection(
                        &wallet,
                        saved.selection(intent_for(kind, &input, &w.state)),
                    ));
                    let fd = identity(&i.lock);
                    let images = retaining_native_images(&owner);
                    if temp {
                        let d = retaining_expect_success(
                            i.into_temp_discard_retaining(c.public_observation().unwrap()),
                        );
                        assert_eq!(identity(&d.inspection.lock), fd);
                        assert_eq!(
                            d.original_wallet_data().old_wallet_startup_pin_bytes(),
                            saved.startup
                        );
                    } else {
                        let s = retaining_expect_success(
                            i.into_full_recovery_retaining(c.public_observation().unwrap()),
                        );
                        assert_eq!(identity(&s.lock), fd);
                        assert_eq!(s.original_selection.as_ref().unwrap().roots, saved.roots);
                    }
                    assert_eq!(
                        retaining_native_images(&owner),
                        images,
                        "{kind}/{stage}/{temp}"
                    );
                }
            }
        }
    }
}
#[test]
fn original_cleanup_temp_and_terminal_all_retaining_conversion_boundaries_keep_same_file() {
    for app in apps() {
        for branch in ["temp", "cleanup", "terminal"] {
            for boundary in ["before_move", "constructed"] {
                let (w, wallet, f, saved, input) = if branch == "cleanup" {
                    let (w, ws, f, s, i, _) = completed_original(app);
                    (w, ws, f, s, i)
                } else if branch == "temp" {
                    staged_original(app, "reconcile", "prepared_old")
                } else {
                    let (p, input) = audience_request_fixture(app);
                    let w = audience_metadata_unconfigured(&p);
                    let wallet = w.source();
                    let f = owner_for(&w, &p);
                    let owner = f.source();
                    let saved = OriginalBytes::before_call(&owner, f.pin, &wallet, &w, &p);
                    (w, wallet, f, saved, input)
                };
                let owner = f.source();
                if branch == "temp" {
                    private_file(&f.dir.path().join(TEMP), b"partial");
                }
                let root = ServiceRoot::open(w.path()).unwrap();
                let c = root.lock_exclusive().unwrap();
                let intent = if branch == "cleanup" {
                    WalletTransitionIntent::Configure { owner_input: input }
                } else {
                    WalletTransitionIntent::Reconcile
                };
                let i = retaining_expect_success(
                    owner.begin_original_transition_inspection(&wallet, saved.selection(intent)),
                );
                let fd = identity(&i.lock);
                let images = retaining_native_images(&owner);
                let fault = format!("original_{branch}_{boundary}");
                FAULT.with(|v| *v.borrow_mut() = Some(fault));
                let failure = match branch {
                    "temp" => {
                        match i.into_temp_discard_retaining(c.public_observation().unwrap()) {
                            Err(e) => e,
                            Ok(_) => panic!("expected retaining failure"),
                        }
                    }
                    "cleanup" => {
                        match i.into_completed_cleanup_retaining(c.public_observation().unwrap()) {
                            Err(e) => e,
                            Ok(_) => panic!("expected retaining failure"),
                        }
                    }
                    _ => {
                        match i.into_terminal_observer_retaining(c.public_observation().unwrap()) {
                            Err(e) => e,
                            Ok(_) => panic!("expected retaining failure"),
                        }
                    }
                };
                FAULT.with(|v| *v.borrow_mut() = None);
                let (error, i) = *failure;
                assert_eq!(error, SourceError::PublicationUncertain);
                assert_inspection_held(&i, &f, &w, fd, &saved);
                assert_eq!(retaining_native_images(&owner), images);
            }
        }
    }
}
#[test]
fn original_reconcile_all64_masks_deny_nonconfigure_request_and_accept_only_present_originals() {
    let names = [
        "OLD-NATIVE.json",
        "OLD-WALLET-STATE.json",
        "TARGET-POLICY.json",
        "REQUEST-OWNER-INPUT.json",
        "OUTCOME.json",
        "TARGET-NATIVE.json",
    ];
    for app in apps() {
        for mask in 0u8..64 {
            let (w, wallet, f, saved, input) = staged_original(app, "reconcile", "tombstone");
            let owner = f.source();
            let root = ServiceRoot::open(w.path()).unwrap();
            let c = root.lock_exclusive().unwrap();
            for (i, n) in names.iter().enumerate() {
                if *n == "REQUEST-OWNER-INPUT.json" {
                    if mask & (1 << i) != 0 {
                        private_file(&f.dir.path().join(RECORDS).join(n), &input);
                    }
                } else if mask & (1 << i) == 0 {
                    fs::remove_file(f.dir.path().join(RECORDS).join(n)).unwrap();
                }
            }
            let images = retaining_native_images(&owner);
            let selection = saved.selection(WalletTransitionIntent::Reconcile);
            let acquired = owner.begin_original_transition_inspection(&wallet, selection);
            if mask & 8 != 0 {
                assert!(acquired.is_err());
                assert_eq!(retaining_native_images(&owner), images);
            } else {
                let i = retaining_expect_success(acquired);
                let fd = identity(&i.lock);
                let mut d = retaining_expect_success(
                    i.into_completed_cleanup_retaining(c.public_observation().unwrap()),
                );
                assert_eq!(
                    d.cleanup(c.public_observation().unwrap())
                        .unwrap()
                        .removed_records(),
                    mask.count_ones() as usize
                );
                assert_eq!(identity(&d.inspection.lock), fd);
                assert_eq!(
                    d.observe_terminal(c.public_observation().unwrap())
                        .unwrap()
                        .disposition(),
                    OriginalTerminalDisposition::DerivedNewSource
                );
            }
        }
    }
}
#[test]
fn original_returned_owner_denies_foreign_view_and_root_replacement_then_allows_actual_restore() {
    for app in apps() {
        let (w, wallet, f, saved, _) = staged_original(app, "reconcile", "prepared_old");
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let c = root.lock_exclusive().unwrap();
        let i = retaining_expect_success(owner.begin_original_transition_inspection(
            &wallet,
            saved.selection(WalletTransitionIntent::Reconcile),
        ));
        let fd = identity(&i.lock);
        let images = retaining_native_images(&owner);
        let (p, _) = audience_request_fixture(app);
        let foreign = audience_metadata_unconfigured(&p);
        let foreign_root = ServiceRoot::open(foreign.path()).unwrap();
        let foreign_lease = foreign_root.lock_exclusive().unwrap();
        let failure =
            match i.into_full_recovery_retaining(foreign_lease.public_observation().unwrap()) {
                Err(e) => e,
                Ok(_) => panic!("foreign view accepted"),
            };
        let (_, i) = *failure;
        assert_inspection_held(&i, &f, &w, fd, &saved);
        assert_eq!(retaining_native_images(&owner), images);
        let moved = f.dir.path().with_extension("held-original");
        fs::rename(f.dir.path(), &moved).unwrap();
        fs::create_dir(f.dir.path()).unwrap();
        fs::set_permissions(f.dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(i.revalidate().is_err());
        assert_eq!(identity(&i.lock), fd);
        retaining_assert_both_locks_held(&moved, w.path());
        fs::remove_dir(f.dir.path()).unwrap();
        fs::rename(&moved, f.dir.path()).unwrap();
        i.revalidate().unwrap();
        let s = retaining_expect_success(
            i.into_full_recovery_retaining(c.public_observation().unwrap()),
        );
        assert_eq!(identity(&s.lock), fd);
    }
}
#[test]
fn original_preflight_resume_retaining_early_late_errors_keep_original_roots_minima_and_bytes() {
    for app in apps() {
        for bad in ["foreign", "previous", "checkpoint"] {
            let (p, input) = audience_request_fixture(app);
            let w = audience_metadata_unconfigured(&p);
            let wallet = w.source();
            let f = owner_for(&w, &p);
            let owner = f.source();
            let saved = OriginalBytes::before_call(&owner, f.pin, &wallet, &w, &p);
            let root = ServiceRoot::open(w.path()).unwrap();
            let mut c = root.lock_exclusive().unwrap();
            let mut s = owner
                .begin_administration(f.pin, &wallet, c.public_observation().unwrap())
                .unwrap();
            s.prepare_wallet_transition(
                c.public_observation().unwrap(),
                WalletTransitionIntent::Configure {
                    owner_input: input.clone(),
                },
                &saved.policy,
            )
            .unwrap();
            drop(s);
            let i = retaining_expect_success(owner.begin_original_transition_inspection(
                &wallet,
                saved.selection(WalletTransitionIntent::Configure {
                    owner_input: input.clone(),
                }),
            ));
            let fd = identity(&i.lock);
            let mut p = retaining_expect_success(i.into_prepared_recovery_preflight_retaining());
            let foreign = audience_metadata_unconfigured(
                &serde_json::from_slice::<Value>(&saved.policy).unwrap(),
            );
            let fr = ServiceRoot::open(foreign.path()).unwrap();
            let fl = fr.lock_exclusive().unwrap();
            if bad == "previous" {
                let mut next = configured_next(&w, &input);
                next["previous_state_sha256"] = json!("11".repeat(32));
                publish_metadata(&w, &mut c, &next, Some(&input));
            }
            let images = retaining_native_images(&owner);
            for _ in 0..2 {
                if bad == "checkpoint" {
                    FAULT.with(|v| *v.borrow_mut() = Some("recovery_first_actual_view".into()));
                }
                let view = if bad == "foreign" {
                    fl.public_observation().unwrap()
                } else {
                    c.public_observation().unwrap()
                };
                let failure = match p.resume_with_actual_wallet_retaining(view) {
                    Err(e) => e,
                    Ok(_) => panic!("expected retaining resume failure"),
                };
                FAULT.with(|v| *v.borrow_mut() = None);
                let (_, returned) = *failure;
                p = returned;
                assert_eq!(identity(&p.lock), fd);
                let original = p.original_selection.as_ref().unwrap();
                assert_eq!(original.roots, saved.roots);
                assert_eq!(original.startup_raw, saved.startup);
                assert_eq!(p.data.old_raw, saved.native);
                assert_eq!(p.data.state_raw, saved.state);
                assert_eq!(p.data.policy_raw, saved.policy);
                assert_eq!(
                    p.original_wallet_data().unwrap().old_wallet_state_bytes(),
                    saved.state
                );
                retaining_assert_both_locks_held(f.dir.path(), w.path());
                assert_eq!(retaining_native_images(&owner), images);
            }
        }
    }
}
#[test]
fn original_present_policy_window_minima_and_stage_drift_errors_retain_same_owner() {
    for app in apps() {
        for bad in ["minima", "P", "window", "stage", "current", "clock"] {
            let (w, wallet, f, saved, _) = staged_original(app, "rotate", "prepared_old");
            let owner = f.source();
            let root = ServiceRoot::open(w.path()).unwrap();
            let c = root.lock_exclusive().unwrap();
            let i = retaining_expect_success(owner.begin_original_transition_inspection(
                &wallet,
                saved.selection(intent_for("rotate", &[], &w.state)),
            ));
            let fd = identity(&i.lock);
            // Private fields are touched ONLY by this cfg(test) negative; callers
            // cannot replace immutable retained configuration through the public API.
            let mut i = i;
            match bad {
                "minima" => {
                    let mut v: Value = serde_json::from_slice(&i.original.startup_raw).unwrap();
                    v["minimum_state_revision"] = json!(2);
                    i.original.startup_raw = canonical(&v);
                }
                "P" => {
                    let mut v: Value = serde_json::from_slice(&saved.policy).unwrap();
                    v["valid_until"] = json!(v["valid_until"].as_u64().unwrap() - 1);
                    i.original = OriginalTransitionSelection::new(
                        saved.roots,
                        saved.pin,
                        saved.native.clone(),
                        saved.startup.clone(),
                        saved.reference.clone(),
                        saved.state.clone(),
                        intent_for("rotate", &[], &w.state),
                        canonical(&v),
                    )
                    .unwrap();
                }
                "window" => {
                    i.original = saved.selection(WalletTransitionIntent::Rotate {
                        not_before: w.state["not_before"].as_u64().unwrap(),
                        not_after: w.state["not_after"].as_u64().unwrap() - 1,
                    });
                }
                "stage" => {
                    let mut v: Value =
                        serde_json::from_slice(&owner.files.read(MARKER, false).unwrap()).unwrap();
                    v["stage"] = json!("native_published");
                    fs::write(f.dir.path().join(MARKER), canonical(&v)).unwrap();
                }
                "current" => {
                    fs::write(f.dir.path().join(CURRENT), b"{}").unwrap();
                }
                _ => {
                    crate::service_wallet_source::TEST_NOW.with(|v| v.set(Some(1)));
                }
            }
            let images = retaining_native_images(&owner);
            let failure = match i.into_full_recovery_retaining(c.public_observation().unwrap()) {
                Err(e) => e,
                Ok(_) => panic!("drift accepted"),
            };
            crate::service_wallet_source::TEST_NOW.with(|v| v.set(None));
            let (_, i) = *failure;
            assert_eq!(identity(&i.lock), fd);
            retaining_assert_both_locks_held(f.dir.path(), w.path());
            assert_eq!(retaining_native_images(&owner), images);
        }
    }
}
#[test]
fn original_empty_terminal_never_self_pins_changed_policy_or_accepts_empty_record_directory() {
    for app in apps() {
        for bad in ["empty-records", "different-policy"] {
            let (p, _) = audience_request_fixture(app);
            let w = audience_metadata_unconfigured(&p);
            let wallet = w.source();
            let f = owner_for(&w, &p);
            let owner = f.source();
            let saved = OriginalBytes::before_call(&owner, f.pin, &wallet, &w, &p);
            let root = ServiceRoot::open(w.path()).unwrap();
            let c = root.lock_exclusive().unwrap();
            let i = retaining_expect_success(owner.begin_original_transition_inspection(
                &wallet,
                saved.selection(WalletTransitionIntent::Reconcile),
            ));
            let fd = identity(&i.lock);
            if bad == "empty-records" {
                fs::create_dir(f.dir.path().join(RECORDS)).unwrap();
                fs::set_permissions(
                    f.dir.path().join(RECORDS),
                    fs::Permissions::from_mode(0o700),
                )
                .unwrap();
            } else {
                let mut other = p.clone();
                other["valid_until"] = json!(p["valid_until"].as_u64().unwrap() - 1);
                let policy = TargetPolicy::parse(&canonical(&other)).unwrap();
                let old = NativeCas::parse(&canonical(&f.pin.value())).unwrap();
                let reference = WalletReference::parse(&saved.reference).unwrap();
                let coherent_wrong = policy.derive_target(&old, &reference).unwrap();
                fs::write(f.dir.path().join(CURRENT), coherent_wrong.canonical_bytes()).unwrap();
            }
            let images = retaining_native_images(&owner);
            let failure = match i.into_terminal_observer_retaining(c.public_observation().unwrap())
            {
                Err(e) => e,
                Ok(_) => panic!("terminal accepted unsupported source"),
            };
            let (_, i) = *failure;
            assert_inspection_held(&i, &f, &w, fd, &saved);
            assert_eq!(retaining_native_images(&owner), images);
        }
    }
}

fn replace_selected_native_path(f: &OwnerFiles) -> std::path::PathBuf {
    let moved = f.dir.path().with_extension("same-held-native");
    fs::rename(f.dir.path(), &moved).unwrap();
    fs::create_dir(f.dir.path()).unwrap();
    fs::set_permissions(f.dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    moved
}
fn restore_selected_native_path(f: &OwnerFiles, moved: &Path) {
    fs::remove_dir(f.dir.path()).unwrap();
    fs::rename(moved, f.dir.path()).unwrap();
}
#[test]
fn original_every_returned_branch_rechecks_native_root_and_retains_file_on_replacement() {
    for app in apps() {
        for branch in ["full", "preflight", "temp", "cleanup", "terminal"] {
            let (w, wallet, f, saved, input) = match branch {
                "cleanup" => {
                    let (w, ws, f, s, i, _) = completed_original(app);
                    (w, ws, f, s, i)
                }
                "terminal" => {
                    let (p, input) = audience_request_fixture(app);
                    let w = audience_metadata_unconfigured(&p);
                    let ws = w.source();
                    let f = owner_for(&w, &p);
                    let o = f.source();
                    let saved = OriginalBytes::before_call(&o, f.pin, &ws, &w, &p);
                    (w, ws, f, saved, input)
                }
                _ => staged_original(app, "reconcile", "prepared_old"),
            };
            let owner = f.source();
            if branch == "temp" {
                private_file(&f.dir.path().join(TEMP), b"partial");
            }
            let root = ServiceRoot::open(w.path()).unwrap();
            let c = root.lock_exclusive().unwrap();
            let intent = if branch == "cleanup" {
                WalletTransitionIntent::Configure { owner_input: input }
            } else {
                WalletTransitionIntent::Reconcile
            };
            let i = retaining_expect_success(
                owner.begin_original_transition_inspection(&wallet, saved.selection(intent)),
            );
            let fd = identity(&i.lock);
            match branch {
                "full" => {
                    let mut s = retaining_expect_success(
                        i.into_full_recovery_retaining(c.public_observation().unwrap()),
                    );
                    let moved = replace_selected_native_path(&f);
                    assert!(s
                        .record_outcome_and_target(
                            c.public_observation().unwrap(),
                            RecoveryRelation::ReconciledUnchanged
                        )
                        .is_err());
                    assert_eq!(identity(&s.lock), fd);
                    assert_eq!(
                        s.original_wallet_data()
                            .unwrap()
                            .old_wallet_startup_pin_bytes(),
                        saved.startup
                    );
                    retaining_assert_both_locks_held(&moved, w.path());
                    restore_selected_native_path(&f, &moved);
                }
                "preflight" => {
                    let p =
                        retaining_expect_success(i.into_prepared_recovery_preflight_retaining());
                    let moved = replace_selected_native_path(&f);
                    assert!(p.revalidate().is_err());
                    assert_eq!(identity(&p.lock), fd);
                    assert_eq!(
                        p.original_wallet_data()
                            .unwrap()
                            .old_wallet_startup_pin_bytes(),
                        saved.startup
                    );
                    retaining_assert_both_locks_held(&moved, w.path());
                    restore_selected_native_path(&f, &moved);
                }
                "temp" => {
                    let mut d = retaining_expect_success(
                        i.into_temp_discard_retaining(c.public_observation().unwrap()),
                    );
                    let moved = replace_selected_native_path(&f);
                    assert!(d.discard_temp(c.public_observation().unwrap()).is_err());
                    assert_eq!(identity(&d.inspection.lock), fd);
                    retaining_assert_both_locks_held(&moved, w.path());
                    restore_selected_native_path(&f, &moved);
                }
                "cleanup" => {
                    let mut d = retaining_expect_success(
                        i.into_completed_cleanup_retaining(c.public_observation().unwrap()),
                    );
                    let moved = replace_selected_native_path(&f);
                    assert!(d.cleanup(c.public_observation().unwrap()).is_err());
                    assert_eq!(identity(&d.inspection.lock), fd);
                    retaining_assert_both_locks_held(&moved, w.path());
                    restore_selected_native_path(&f, &moved);
                }
                _ => {
                    let t = retaining_expect_success(
                        i.into_terminal_observer_retaining(c.public_observation().unwrap()),
                    );
                    let moved = replace_selected_native_path(&f);
                    assert!(t.observe(c.public_observation().unwrap()).is_err());
                    assert_eq!(identity(&t.inspection.lock), fd);
                    retaining_assert_both_locks_held(&moved, w.path());
                    restore_selected_native_path(&f, &moved);
                }
            }
        }
    }
}
#[test]
fn original_full_finalize_partial_error_retains_owner_then_explicit_new_cleanup_interval() {
    for app in apps() {
        let (w, wallet, f, saved, input) = staged_original(app, "configure", "native_published");
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let c = root.lock_exclusive().unwrap();
        let i = retaining_expect_success(owner.begin_original_transition_inspection(
            &wallet,
            saved.selection(WalletTransitionIntent::Configure {
                owner_input: input.clone(),
            }),
        ));
        let fd = identity(&i.lock);
        let mut s = retaining_expect_success(
            i.into_full_recovery_retaining(c.public_observation().unwrap()),
        );
        FAULT.with(|v| *v.borrow_mut() = Some("record_unlinked:OLD-NATIVE.json".into()));
        assert!(s
            .finalize_recorded_transition(c.public_observation().unwrap())
            .is_err());
        FAULT.with(|v| *v.borrow_mut() = None);
        assert_eq!(identity(&s.lock), fd);
        assert_eq!(
            s.original_wallet_data().unwrap().old_wallet_state_bytes(),
            saved.state
        );
        assert_eq!(
            s.original_wallet_data()
                .unwrap()
                .old_wallet_startup_pin_bytes(),
            saved.startup
        );
        retaining_assert_both_locks_held(f.dir.path(), w.path());
        assert!(owner.files.exists(TEMP, false).unwrap());
        assert!(!owner.files.exists("OLD-NATIVE.json", true).unwrap());
        let images = retaining_native_images(&owner);
        assert!(s
            .finalize_recorded_transition(c.public_observation().unwrap())
            .is_err());
        assert_eq!(retaining_native_images(&owner), images);
        // Explicitly end this interval; missing history cannot be repaired by
        // ordinary recovery or by laundering its candidate ID into strict-ID.
        drop(s);
        drop(c);
        let c = root.lock_exclusive().unwrap();
        let i = retaining_expect_success(owner.begin_original_transition_inspection(
            &wallet,
            saved.selection(WalletTransitionIntent::Configure { owner_input: input }),
        ));
        let mut d = retaining_expect_success(
            i.into_completed_cleanup_retaining(c.public_observation().unwrap()),
        );
        assert_eq!(
            d.cleanup(c.public_observation().unwrap())
                .unwrap()
                .removed_records(),
            5
        );
        assert_eq!(
            d.observe_terminal(c.public_observation().unwrap())
                .unwrap()
                .disposition(),
            OriginalTerminalDisposition::DerivedNewSource
        );
    }
}
#[test]
fn original_legacy_full_and_preflight_accessors_return_no_original_selection() {
    for app in apps() {
        let (p, _) = audience_request_fixture(app);
        let w = audience_metadata_unconfigured(&p);
        let wallet = w.source();
        let f = owner_for(&w, &p);
        let owner = f.source();
        let root = ServiceRoot::open(w.path()).unwrap();
        let c = root.lock_exclusive().unwrap();
        let mut s = owner
            .begin_administration(f.pin, &wallet, c.public_observation().unwrap())
            .unwrap();
        assert!(s.original_wallet_data().is_none());
        s.prepare_wallet_transition(
            c.public_observation().unwrap(),
            WalletTransitionIntent::Reconcile,
            &canonical(&p),
        )
        .unwrap();
        let p = retaining_expect_success(s.into_wallet_recovery_preflight_retaining());
        assert!(p.original_wallet_data().is_none());
    }
}
