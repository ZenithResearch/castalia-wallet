use super::*;
use std::os::unix::fs::PermissionsExt;
fn root() -> (tempfile::TempDir, ServiceRoot) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = ServiceRoot::open(&path).unwrap();
    (temp, root)
}
#[test]
fn independent_roots_share_readers_epoch_and_busy_writer() {
    let (temp, a) = root();
    let init = a.initialize().unwrap();
    drop(init);
    let b = ServiceRoot::open(&temp.path().canonicalize().unwrap()).unwrap();
    let x = a.lock_shared().unwrap();
    let y = b.lock_shared().unwrap();
    assert_eq!(
        a.lock_exclusive().err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(x);
    assert!(a.lock_exclusive().is_err());
    drop(y);
    let mut ex = a.lock_exclusive().unwrap();
    let old = ex.epoch().unwrap();
    ex.invalidate(false).unwrap();
    assert!(ex.epoch().unwrap() > old);
    drop(ex);
    assert!(b.lock_exclusive().is_ok());
}
#[test]
fn immutable_state_and_pointer_publication_are_bounded() {
    let (_t, r) = root();
    let mut l = r.initialize().unwrap();
    l.begin_staging().unwrap();
    l.write_staging(StagingFile::Seed, &[7; 32]).unwrap();
    l.write_staging(StagingFile::State, b"{}").unwrap();
    l.sync_staging().unwrap();
    l.publish_revision(1).unwrap();
    assert_eq!(&*l.read(ServiceFile::Seed(1)).unwrap(), &[7; 32]);
    l.publish_clock(b"{}", false).unwrap();
    l.publish_current(b"{}", false).unwrap();
    assert_eq!(&*l.read(ServiceFile::Current).unwrap(), b"{}");
    assert!(l.write_staging(StagingFile::Seed, &[1; 33]).is_err());
    assert!(l.publish_current(b"new", false).is_err());
    l.publish_current(b"new", true).unwrap();
    assert_eq!(&*l.read(ServiceFile::Current).unwrap(), b"new");
}
#[test]
fn root_lock_links_and_unknown_entries_deny() {
    let (t, r) = root();
    drop(r.initialize().unwrap());
    std::fs::write(t.path().join("unknown"), b"x").unwrap();
    assert!(r.lock_shared().is_err());
    std::fs::remove_file(t.path().join("unknown")).unwrap();
    std::fs::hard_link(t.path().join("custody.lock"), t.path().join("alias")).unwrap();
    assert!(r.lock_shared().is_err());
}
#[test]
fn missing_current_abandon_retains_lock_and_requires_separate_initialize() {
    let (_t, r) = root();
    let mut l = r.initialize().unwrap();
    let id = l.lock_identity();
    l.begin_staging().unwrap();
    l.write_staging(StagingFile::State, b"partial").unwrap();
    l.abandon_incomplete().unwrap();
    assert_eq!(id, l.lock_identity());
    drop(l);
    let new = r.initialize().unwrap();
    assert_eq!(id, new.lock_identity());
}

fn process_exclusive(path: &std::path::Path) -> i32 {
    std::process::Command::new("python3")
        .arg("-c")
        .arg(
            "import os,fcntl,sys
f=os.open(sys.argv[1],os.O_RDWR)
try: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError: sys.exit(87)
sys.exit(0)",
        )
        .arg(path.join("custody.lock"))
        .status()
        .unwrap()
        .code()
        .unwrap()
}
#[test]
fn dropping_one_independent_reader_does_not_unlock_other_for_child_process() {
    let (temp, a) = root();
    drop(a.initialize().unwrap());
    let b = ServiceRoot::open(&temp.path().canonicalize().unwrap()).unwrap();
    let first = a.lock_shared().unwrap();
    let second = b.lock_shared().unwrap();
    assert_eq!(process_exclusive(temp.path()), 87);
    drop(first);
    assert_eq!(process_exclusive(temp.path()), 87);
    drop(second);
    assert_eq!(process_exclusive(temp.path()), 0);
}
#[test]
fn lost_initial_ack_has_current_and_partial_init_never_implicitly_recreates() {
    for step in [
        "before_clock_rename",
        "after_clock_rename",
        "after_clock_sync",
        "before_current_rename",
        "after_current_rename",
        "after_current_sync",
    ] {
        let (_t, r) = root();
        let mut l = r.initialize().unwrap();
        l.begin_staging().unwrap();
        l.write_staging(StagingFile::Seed, &[4; 32]).unwrap();
        l.write_staging(StagingFile::State, b"partial").unwrap();
        l.publish_revision(1).unwrap();
        TEST_FAILURE.with(|v| *v.borrow_mut() = Some(step));
        let outcome = l
            .publish_clock(b"{}", false)
            .and_then(|_| l.publish_current(b"{}", false));
        assert!(outcome.is_err());
        TEST_FAILURE.with(|v| *v.borrow_mut() = None);
        let has_current = l
            .inspect_bounded()
            .unwrap()
            .root_entries
            .iter()
            .any(|s| s == "CURRENT");
        if has_current {
            assert!(l.read(ServiceFile::Clock).is_ok());
            assert!(l.abandon_incomplete().is_err());
            l.sync_current().unwrap();
        } else {
            assert!(r.initialize().is_err());
            l.abandon_incomplete().unwrap();
        }
        drop(l);
        if !has_current {
            assert!(r.initialize().is_ok());
        }
    }
}
#[test]
fn symlink_seed_and_replaced_lock_and_root_are_denied() {
    use std::os::unix::fs::symlink;
    let (temp, r) = root();
    let mut l = r.initialize().unwrap();
    l.begin_staging().unwrap();
    l.publish_revision(1).unwrap();
    symlink(
        "/dev/zero",
        temp.path().join("states/s0000000000000001/seed.raw"),
    )
    .unwrap();
    assert!(l.read(ServiceFile::Seed(1)).is_err());
    std::fs::remove_file(temp.path().join("states/s0000000000000001/seed.raw")).unwrap();
    std::fs::rename(temp.path().join("custody.lock"), temp.path().join("old")).unwrap();
    std::fs::write(temp.path().join("custody.lock"), []).unwrap();
    std::fs::set_permissions(
        temp.path().join("custody.lock"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(l.revalidate().is_err());
}
#[test]
fn registry_epoch_poison_is_shared_and_reconcile_invalidates_same_current() {
    let (temp, r) = root();
    let mut l = r.initialize().unwrap();
    let first = l.epoch().unwrap();
    l.invalidate(true).unwrap();
    assert!(l.poisoned().unwrap());
    drop(l);
    let other = ServiceRoot::open(&temp.path().canonicalize().unwrap()).unwrap();
    let mut l = other.lock_exclusive().unwrap();
    assert!(l.poisoned().unwrap());
    l.invalidate(false).unwrap();
    assert!(!l.poisoned().unwrap());
    assert!(l.epoch().unwrap() > first + 1);
}
#[cfg(target_os = "macos")]
#[test]
fn real_preallocated_empty_lock_is_not_unreserved_headroom() {
    let (temp, r) = root();
    drop(r.initialize().unwrap());
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(temp.path().join("custody.lock"))
        .unwrap();
    let mut req = libc::fstore_t {
        fst_flags: libc::F_ALLOCATEALL,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: 8 * 1024 * 1024,
        fst_bytesalloc: 0,
    };
    assert_eq!(
        unsafe { libc::fcntl(f.as_raw_fd(), libc::F_PREALLOCATE, &mut req) },
        0
    );
    assert_eq!(f.metadata().unwrap().len(), 0);
    assert!(f.metadata().unwrap().blocks() * 512 >= 8 * 1024 * 1024);
    assert!(r.lock_shared().is_err());
}

#[test]
fn initial_clock_is_mandatory_and_absent_lock_does_not_implicitly_recreate() {
    let (temp, r) = root();
    let mut l = r.initialize().unwrap();
    assert!(l.publish_current(b"{}", false).is_err());
    drop(l);
    std::fs::remove_file(temp.path().join("custody.lock")).unwrap();
    assert!(r.lock_shared().is_err());
    assert!(!temp.path().join("custody.lock").exists());
}
#[test]
fn partial_files_cleanup_is_bounded_and_committed_pointer_is_never_abandoned() {
    let (_t, r) = root();
    let mut l = r.initialize().unwrap();
    l.begin_staging().unwrap();
    l.write_staging(StagingFile::Seed, &[1; 7]).unwrap();
    l.write_staging(StagingFile::State, b"{").unwrap();
    l.publish_revision(1).unwrap();
    l.abandon_incomplete().unwrap();
    drop(l);
    let mut l = r.initialize().unwrap();
    l.publish_clock(b"{}", false).unwrap();
    l.publish_current(b"invalid", false).unwrap();
    assert!(l.abandon_incomplete().is_err());
}
#[test]
fn changes_to_ancestor_permissions_and_root_binding_deny_retained_leases() {
    let temp = tempfile::tempdir().unwrap();
    let p = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    let private = p.join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let r = ServiceRoot::open(&private).unwrap();
    let l = r.initialize().unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(l.revalidate().is_err());
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::rename(&private, p.join("old")).unwrap();
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(l.revalidate().is_err());
}

#[test]
fn atomic_seed_replacement_during_read_is_detected_even_when_old_inode_survives() {
    let (temp, r) = root();
    let outside = tempfile::tempdir().unwrap();
    let mut l = r.initialize().unwrap();
    l.begin_staging().unwrap();
    l.write_staging(StagingFile::Seed, &[2; 32]).unwrap();
    l.publish_revision(1).unwrap();
    let path = temp.path().join("states/s0000000000000001/seed.raw");
    let retained = outside.path().join("retained");
    TEST_ACTION.with(|v| {
        *v.borrow_mut() = Some(Box::new(move |step| {
            if step == "after_read" {
                std::fs::rename(&path, &retained).unwrap();
                std::fs::write(&path, [3; 32]).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }))
    });
    let result = l.read(ServiceFile::Seed(1));
    TEST_ACTION.with(|v| *v.borrow_mut() = None);
    assert!(result.is_err());
}

fn replace_safe_lock(path: &std::path::Path, outside: &std::path::Path) {
    std::fs::rename(path.join("custody.lock"), outside.join("old-lock")).unwrap();
    std::fs::write(path.join("custody.lock"), []).unwrap();
    std::fs::set_permissions(
        path.join("custody.lock"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}
#[test]
fn replaced_lock_denies_temporary_cleanup_before_any_delete() {
    let (temp, root) = root();
    let outside = tempfile::tempdir().unwrap();
    let mut lease = root.initialize().unwrap();
    let pending = temp.path().join(".CURRENT.tmp");
    std::fs::write(&pending, b"pending-other-publication").unwrap();
    std::fs::set_permissions(&pending, std::fs::Permissions::from_mode(0o600)).unwrap();
    replace_safe_lock(temp.path(), outside.path());
    assert!(lease.discard_temporary().is_err());
    assert_eq!(
        std::fs::read(&pending).unwrap(),
        b"pending-other-publication"
    );
}
#[test]
fn replaced_lock_denies_initial_abandon_before_any_delete() {
    let (temp, root) = root();
    let outside = tempfile::tempdir().unwrap();
    let mut lease = root.initialize().unwrap();
    lease.publish_clock(b"partial-clock", false).unwrap();
    replace_safe_lock(temp.path(), outside.path());
    assert!(lease.abandon_incomplete().is_err());
    assert_eq!(
        std::fs::read(temp.path().join("CLOCK")).unwrap(),
        b"partial-clock"
    );
    assert!(!temp.path().join("RESET").exists());
}

fn public_pointer(rev: u64) -> Vec<u8> {
    format!("{{\"schema\":\"castalia.wallet-service-custody-current.v1\",\"state_revision\":{rev},\"state_sha256\":\"{}\",\"store_id\":\"{}\"}}", "0".repeat(64), "1".repeat(32)).into_bytes()
}
fn seed_public_fixture(root: &ServiceRoot) {
    let mut lease = root.initialize().unwrap();
    lease.begin_staging().unwrap();
    lease.write_staging(StagingFile::Seed, &[7; 32]).unwrap();
    lease
        .write_staging(StagingFile::State, b"state-one")
        .unwrap();
    lease.publish_revision(1).unwrap();
    lease.publish_clock(b"clock-one", false).unwrap();
    lease.publish_current(&public_pointer(1), false).unwrap();
}
#[test]
fn public_metadata_selects_current_and_reader_lifetime_excludes_writers() {
    let (temp, root) = root();
    seed_public_fixture(&root);
    let first = root.lock_public_shared().unwrap();
    let second = root.lock_public_shared().unwrap();
    assert_eq!(first.metadata().state_revision(), 1);
    assert_eq!(first.metadata().state_bytes(), b"state-one");
    assert_eq!(first.metadata().clock_bytes(), b"clock-one");
    assert!(first.metadata().owner_input_bytes().is_none());
    assert_eq!(first.metadata().current_bytes(), public_pointer(1));
    assert_eq!(process_exclusive(temp.path()), 87);
    drop(first);
    assert_eq!(process_exclusive(temp.path()), 87);
    second.revalidate().unwrap();
    drop(second);
    assert_eq!(process_exclusive(temp.path()), 0);
}
#[test]
fn exclusive_public_view_drops_before_clock_write_without_unlocking() {
    let (temp, root) = root();
    seed_public_fixture(&root);
    let mut lease = root.lock_exclusive().unwrap();
    let identity = lease.lock_identity();
    {
        let view = lease.public_observation().unwrap();
        assert_eq!(view.metadata().lock_identity(), identity);
        assert_eq!(view.metadata().clock_bytes(), b"clock-one");
        view.revalidate().unwrap();
        assert_eq!(process_exclusive(temp.path()), 87);
    }
    lease.publish_clock(b"clock-two", true).unwrap();
    let view = lease.public_observation().unwrap();
    assert_eq!(view.metadata().clock_bytes(), b"clock-two");
    assert_eq!(view.metadata().lock_identity(), identity);
    assert_eq!(process_exclusive(temp.path()), 87);
    drop(view);
    drop(lease);
    let shared = root.lock_shared().unwrap();
    assert!(shared.public_observation().is_err());
}
#[test]
fn public_selection_rejects_noncanonical_numbers_and_missing_selected_state() {
    let (temp, root) = root();
    seed_public_fixture(&root);
    let good = String::from_utf8(public_pointer(1)).unwrap();
    for bad in [
        "0",
        "-0",
        "01",
        "1.0",
        "1e0",
        "9007199254740992",
        "18446744073709551616",
    ] {
        std::fs::write(
            temp.path().join("CURRENT"),
            good.replace("\"state_revision\":1", &format!("\"state_revision\":{bad}")),
        )
        .unwrap();
        assert!(root.lock_public_shared().is_err(), "accepted {bad}");
    }
    for bad in [
        format!("{good}\n"),
        good.replacen('{', "{\"extra\":0,", 1),
        good.replacen('{', "{\"state_revision\":1,", 1),
    ] {
        std::fs::write(temp.path().join("CURRENT"), bad).unwrap();
        assert!(root.lock_public_shared().is_err());
    }
    std::fs::write(temp.path().join("CURRENT"), public_pointer(2)).unwrap();
    assert!(root.lock_public_shared().is_err());
}
#[test]
fn public_view_pins_file_identity_and_safe_absence_without_reading_seed() {
    let (temp, root) = root();
    seed_public_fixture(&root);
    let view = root.lock_public_shared().unwrap();
    // Public metadata does not verify secret contents. Custody does that itself.
    std::fs::write(
        temp.path().join("states/s0000000000000001/seed.raw"),
        [9; 32],
    )
    .unwrap();
    view.revalidate().unwrap();
    let owner = temp
        .path()
        .join("states/s0000000000000001/owner-input.json");
    std::fs::write(&owner, b"{}").unwrap();
    std::fs::set_permissions(&owner, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(view.revalidate().is_err());
    drop(view);
    let view = root.lock_public_shared().unwrap();
    assert_eq!(view.metadata().owner_input_bytes(), Some(b"{}".as_slice()));
    let replacement = temp.path().join(".CLOCK.tmp");
    std::fs::write(&replacement, b"clock-one").unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::rename(&replacement, temp.path().join("CLOCK")).unwrap();
    assert!(view.revalidate().is_err());
    drop(view);
    std::fs::write(owner, vec![b'x'; 262145]).unwrap();
    assert!(root.lock_public_shared().is_err());
}

#[test]
fn public_capture_detects_actual_pointer_replacement_during_anchored_read() {
    let (temp, root) = root();
    seed_public_fixture(&root);
    let path = temp.path().to_owned();
    let mut first = true;
    TEST_ACTION.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |step| {
            if step == "after_read" && first {
                first = false;
                let replacement = path.join(".CURRENT.tmp");
                std::fs::write(&replacement, public_pointer(1)).unwrap();
                std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
                std::fs::rename(replacement, path.join("CURRENT")).unwrap();
            }
        }))
    });
    assert!(root.lock_public_shared().is_err());
    TEST_ACTION.with(|slot| *slot.borrow_mut() = None);
    assert!(root.lock_public_shared().is_ok());
}
#[test]
fn public_observation_rejects_shared_poison_and_changed_epoch() {
    let (_temp, root) = root();
    seed_public_fixture(&root);
    let view = root.lock_public_shared().unwrap();
    let prior = view.metadata().epoch();
    // Fault injection in the actual shared registry, not a caller assertion.
    root.shared.state.lock().unwrap().epoch += 1;
    assert!(view.revalidate().is_err());
    drop(view);
    let view = root.lock_public_shared().unwrap();
    assert!(view.metadata().epoch() > prior);
    root.shared.state.lock().unwrap().poisoned = true;
    assert!(view.revalidate().is_err());
    drop(view);
    assert!(root.lock_public_shared().is_err());
}
