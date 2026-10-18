// Included only by the isolated test harness; no server root export is assumed.
use service_challenge_journal_isolated::service_challenge_store::*;

#[test]
fn accepted_limits_only_tighten() {
    assert_eq!(completion_reservation(2_097_152), Ok(2_220_101));
    assert_eq!(
        completion_reservation(2_097_153),
        Err(JournalError::Invalid)
    );
    assert_eq!(
        Limits {
            rows_global: 257,
            ..Limits::default()
        }
        .validate(),
        Err(JournalError::Invalid)
    );
}

// Acceptance first: requires real SQLite persistence and restart, not a map.
#[tokio::test]
async fn pending_reservation_is_durable_before_export() {
    let directory = private_dir();
    let clock = TestClock::new(100);
    let mut guard = MockGuard::allow();
    let journal = Journal::open(directory.path(), Limits::default(), &clock)
        .await
        .unwrap();
    let challenge = test_challenge(1, "holder", 128);
    journal
        .persist_pending(&challenge, b"evidence", b"lineage", &mut guard, &clock)
        .await
        .unwrap();
    drop(journal);
    let reopened = Journal::open(directory.path(), Limits::default(), &clock)
        .await
        .unwrap();
    let stats = reopened.stats(&clock).await.unwrap();
    assert_eq!(stats.pending, 1);
    assert_eq!(stats.accounted_bytes, 128 + COMPLETION_OVERHEAD);
}

use libsec_core::{service_holder_proof::*, ZenithPacket};
use sha2::{Digest, Sha256};
use sqlx::Connection;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);
impl TestClock {
    fn new(n: u64) -> Self {
        Self(Arc::new(AtomicU64::new(n)))
    }
    fn set(&self, n: u64) {
        self.0.store(n, Ordering::SeqCst);
    }
}
impl Clock for TestClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct MockGuard {
    deny: bool,
    delay: Option<(TestClock, u64)>,
    calls: u64,
    stop_on: u64,
}
impl MockGuard {
    fn allow() -> Self {
        Self {
            deny: false,
            delay: None,
            calls: 0,
            stop_on: 0,
        }
    }
}
impl AuthorityGuard for MockGuard {
    fn revalidate(&mut self, input: GuardInput<'_>) -> Result<(), JournalError> {
        assert!(!input.evidence.is_empty());
        self.calls += 1;
        if self.stop_on == 0 || self.calls == self.stop_on {
            if let Some((t, n)) = &self.delay {
                t.set(*n);
            }
            if self.deny {
                return Err(JournalError::Rejected);
            }
        }
        Ok(())
    }
}
fn test_challenge(n: u8, holder: &str, size: usize) -> UntrustedSignedServiceChallenge {
    let request = vec![b' '; size.max(1)];
    let digest = Sha256::digest(&request).into();
    UntrustedSignedServiceChallenge {
        claims: ServiceChallengeClaims {
            application: ServiceApplication::RuntimeV1,
            issuer_node_id: "test-issuer".into(),
            issuer_key_id: "test-issuer-key".into(),
            audience: "runtime://receiver-local".into(),
            operation: "runtime.run.create.v1".into(),
            resource: "runs/test".into(),
            opcode: 0x42,
            request_length: request.len() as u64,
            request_sha256: digest,
            schema_bundle_sha256: [1; 32],
            descriptor_fingerprint: [2; 32],
            handler_id: "runtime".into(),
            holder_subject_id: holder.into(),
            holder_key_id: "test-holder-key".into(),
            holder_public_key_fingerprint: [3; 32],
            receiver_policy_digest: [4; 32],
            permission_policy_digest: [5; 32],
            registry_snapshot_digest: [6; 32],
            challenge_id: [n; 32],
            session_id: [n; 16],
            nonce: [n; 12],
            ttl_seconds: 60,
            issued_at: 100,
            expires_at: 160,
            evidence: ServiceEvidenceBindings {
                required_evidence_digest: [7; 32],
                evidence_snapshot_digest: [8; 32],
                evidence_observations_digest: [9; 32],
                evidence_adapter_profiles_digest: [10; 32],
                evidence_source_epoch_digest: [11; 32],
                evidence_valid_not_before: 90,
                evidence_valid_until: 160,
                evidence_observed_at: 99,
                evidence_revocation_checked_at: 99,
                evidence_revocation_fresh_until: 160,
            },
        },
        request_bytes: request,
        issuer_signature: [0; 64],
    }
}
fn packet(c: &UntrustedSignedServiceChallenge) -> (Vec<u8>, Vec<u8>) {
    let proof = UntrustedServiceHolderProof {
        claims: c.claims.clone(),
        issuer_signature: c.issuer_signature,
        holder_policy_digest: [12; 32],
        holder_signature: [0; 64],
    }
    .encode()
    .unwrap();
    let p = ZenithPacket {
        session_id: c.claims.session_id,
        nonce: c.claims.nonce,
        opcode: c.claims.opcode,
        proof: proof.clone(),
        claim_ttl: c.claims.ttl_seconds,
        encrypted_payload: c.request_bytes.clone(),
        mac: [0; 16],
    };
    (bincode::serialize(&p).unwrap(), proof)
}
async fn setup(limits: Limits) -> (tempfile::TempDir, TestClock, Journal) {
    let d = private_dir();
    let t = TestClock::new(100);
    let j = Journal::open(d.path(), limits, &t).await.unwrap();
    (d, t, j)
}
async fn pending(j: &Journal, t: &TestClock, c: &UntrustedSignedServiceChallenge) {
    j.persist_pending(c, b"evidence", b"lineage", &mut MockGuard::allow(), t)
        .await
        .unwrap();
}

#[tokio::test]
async fn completed_exact_cache_restart_conflict_and_current_revocation() {
    let (d, t, j) = setup(Limits::default()).await;
    let c = test_challenge(1, "holder", 12);
    let (p, proof) = packet(&c);
    pending(&j, &t, &c).await;
    let out = j
        .complete(
            c.claims.challenge_id,
            &p,
            b"context",
            IssuanceTimes {
                holder_verified_at: 100,
                context_signed_at: 100,
            },
            &mut MockGuard::allow(),
            &t,
        )
        .await
        .unwrap();
    drop(j);
    let j = Journal::open(d.path(), Limits::default(), &t)
        .await
        .unwrap();
    assert_eq!(
        out,
        j.cached(
            c.claims.challenge_id,
            &proof,
            &c.request_bytes,
            &mut MockGuard::allow(),
            &t
        )
        .await
        .unwrap()
    );
    assert_eq!(
        j.complete(
            c.claims.challenge_id,
            &p,
            b"new context",
            IssuanceTimes {
                holder_verified_at: 100,
                context_signed_at: 100
            },
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Conflict)
    );
    let mut bad = proof.clone();
    bad[3] ^= 1;
    assert_eq!(
        j.cached(
            c.claims.challenge_id,
            &bad,
            &c.request_bytes,
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Conflict)
    );
    let mut g = MockGuard::allow();
    g.deny = true;
    assert_eq!(
        j.cached(c.claims.challenge_id, &proof, &c.request_bytes, &mut g, &t)
            .await
            .err(),
        Some(JournalError::Rejected)
    );
    assert_eq!(j.stats(&t).await.unwrap().tombstones, 1);
    assert_eq!(
        j.cached(
            c.claims.challenge_id,
            &proof,
            &c.request_bytes,
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Rejected)
    );
}
#[tokio::test]
async fn pending_limit_and_all_state_rows_cannot_be_evaded() {
    let (_d, t, j) = setup(Limits {
        pending_per_holder: 1,
        rows_per_holder: 2,
        ..Limits::default()
    })
    .await;
    let c = test_challenge(1, "holder", 1);
    pending(&j, &t, &c).await;
    assert_eq!(
        j.persist_pending(
            &test_challenge(2, "holder", 1),
            b"e",
            b"l",
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Capacity)
    );
    j.reject(c.claims.challenge_id, &t).await.unwrap();
    pending(&j, &t, &test_challenge(2, "holder", 1)).await;
    j.reject([2; 32], &t).await.unwrap();
    assert_eq!(
        j.persist_pending(
            &test_challenge(3, "holder", 1),
            b"e",
            b"l",
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Capacity)
    );
    let s = j.stats(&t).await.unwrap();
    assert_eq!(s.rows, 2);
    assert_eq!(s.tombstones, 2);
    assert!(s.accounted_bytes <= 2 * TOMBSTONE_LIMIT);
}
#[tokio::test]
async fn completed_rows_count_after_pending_slots_are_released() {
    let (_d, t, j) = setup(Limits {
        rows_global: 2,
        pending_global: 1,
        ..Limits::default()
    })
    .await;
    for n in 1..=2 {
        let c = test_challenge(n, &format!("holder-{n}"), 1);
        pending(&j, &t, &c).await;
        j.complete(
            c.claims.challenge_id,
            &packet(&c).0,
            b"context",
            IssuanceTimes {
                holder_verified_at: 100,
                context_signed_at: 100,
            },
            &mut MockGuard::allow(),
            &t,
        )
        .await
        .unwrap();
    }
    assert_eq!(
        j.persist_pending(
            &test_challenge(3, "another", 1),
            b"e",
            b"l",
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Capacity)
    );
    assert_eq!(j.stats(&t).await.unwrap().completed, 2);
}
#[tokio::test]
async fn reservations_raw_bytes_and_holder_rotation_are_bounded() {
    let (_d, t, j) = setup(Limits {
        bytes_per_holder: COMPLETION_OVERHEAD + 100,
        ..Limits::default()
    })
    .await;
    pending(&j, &t, &test_challenge(1, "stable-holder", 100)).await;
    let mut rotated = test_challenge(2, "stable-holder", 1);
    rotated.claims.holder_key_id = "rotated-key".into();
    assert_eq!(
        j.persist_pending(&rotated, b"e", b"l", &mut MockGuard::allow(), &t)
            .await
            .err(),
        Some(JournalError::Capacity)
    );
    let (_d, t, j) = setup(Limits {
        request_bytes_global: 10,
        ..Limits::default()
    })
    .await;
    pending(&j, &t, &test_challenge(1, "a", 10)).await;
    assert_eq!(
        j.persist_pending(
            &test_challenge(2, "b", 1),
            b"e",
            b"l",
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Capacity)
    );
}
#[tokio::test]
async fn exact_nonce_and_session_collisions_fail_without_extra_rows() {
    let (_d, t, j) = setup(Limits::default()).await;
    let c = test_challenge(1, "holder", 1);
    pending(&j, &t, &c).await;
    for same_session in [true, false] {
        let mut other = test_challenge(2, "holder", 1);
        if same_session {
            other.claims.session_id = c.claims.session_id;
        } else {
            other.claims.nonce = c.claims.nonce;
        }
        assert_eq!(
            j.persist_pending(&other, b"e", b"l", &mut MockGuard::allow(), &t)
                .await
                .err(),
            Some(JournalError::Conflict)
        );
    }
    assert_eq!(j.stats(&t).await.unwrap().rows, 1);
}
#[tokio::test]
async fn delayed_guard_and_postcommit_guard_respect_exclusive_expiry() {
    for stop_on in [1, 2] {
        let (_d, t, j) = setup(Limits::default()).await;
        let mut g = MockGuard::allow();
        g.delay = Some((t.clone(), 160));
        g.stop_on = stop_on;
        assert_eq!(
            j.persist_pending(&test_challenge(1, "holder", 1), b"e", b"l", &mut g, &t)
                .await
                .err(),
            Some(JournalError::Expired)
        );
        t.set(159);
        assert_eq!(j.stats(&t).await.err(), Some(JournalError::ClockRollback));
    }
}
#[tokio::test]
async fn prune_at_exclusive_deadline_then_restart_rejects_clock_rollback() {
    let (d, t, j) = setup(Limits::default()).await;
    pending(&j, &t, &test_challenge(1, "holder", 1)).await;
    t.set(159);
    assert_eq!(j.stats(&t).await.unwrap().rows, 1);
    t.set(160);
    assert_eq!(j.stats(&t).await.unwrap().rows, 0);
    drop(j);
    t.set(159);
    assert!(matches!(
        Journal::open(d.path(), Limits::default(), &t).await,
        Err(JournalError::ClockRollback)
    ));
}
#[tokio::test]
async fn full_public_payload_fits_and_invalid_completion_preserves_pending() {
    let (_d, t, j) = setup(Limits::default()).await;
    let c = test_challenge(1, "holder", 2_097_152);
    pending(&j, &t, &c).await;
    assert_eq!(j.stats(&t).await.unwrap().accounted_bytes, 2_220_101);
    let (p, _) = packet(&c);
    let mut altered: ZenithPacket = bincode::deserialize(&p).unwrap();
    altered.mac[0] = 1;
    assert_eq!(
        j.complete(
            c.claims.challenge_id,
            &bincode::serialize(&altered).unwrap(),
            b"context",
            IssuanceTimes {
                holder_verified_at: 100,
                context_signed_at: 100
            },
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Conflict)
    );
    assert_eq!(j.stats(&t).await.unwrap().pending, 1);
    j.complete(
        c.claims.challenge_id,
        &p,
        &vec![0; 65536],
        IssuanceTimes {
            holder_verified_at: 100,
            context_signed_at: 100,
        },
        &mut MockGuard::allow(),
        &t,
    )
    .await
    .unwrap();
    assert_eq!(j.stats(&t).await.unwrap().completed, 1);
}
#[tokio::test]
async fn restart_detects_accounting_and_blob_corruption() {
    for sql in [
        "UPDATE service_challenges_v1 SET accounted=1",
        "UPDATE service_challenges_v1 SET record=x'0102'",
    ] {
        let (d, t, j) = setup(Limits::default()).await;
        pending(&j, &t, &test_challenge(1, "holder", 1)).await;
        drop(j);
        let mut db = sqlx::SqliteConnection::connect(&format!(
            "sqlite://{}",
            d.path().join("service-challenges.sqlite3").display()
        ))
        .await
        .unwrap();
        sqlx::query(sql).execute(&mut db).await.unwrap();
        db.close().await.unwrap();
        assert!(matches!(
            Journal::open(d.path(), Limits::default(), &t).await,
            Err(JournalError::Corrupt)
        ));
    }
}

fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reservations_and_completions_never_exceed_limits() {
    let (_d, t, j) = setup(Limits {
        rows_global: 2,
        pending_global: 2,
        ..Limits::default()
    })
    .await;
    let j = Arc::new(j);
    let mut jobs = Vec::new();
    for n in 1..=12 {
        let j = j.clone();
        let t = t.clone();
        jobs.push(tokio::spawn(async move {
            j.persist_pending(
                &test_challenge(n, "holder", 1),
                b"e",
                b"l",
                &mut MockGuard::allow(),
                &t,
            )
            .await
            .map(|_| n)
        }));
    }
    let mut admitted = Vec::new();
    for job in jobs {
        match job.await.unwrap() {
            Ok(n) => admitted.push(n),
            Err(JournalError::Busy | JournalError::Capacity) => (),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert!(!admitted.is_empty());
    assert!(admitted.len() <= 2);
    assert_eq!(j.stats(&t).await.unwrap().rows, admitted.len() as u64);
    let n = admitted[0];
    let c = test_challenge(n, "holder", 1);
    let (p, proof) = packet(&c);
    let mut ga = MockGuard::allow();
    let mut gb = MockGuard::allow();
    let (a, b) = tokio::join!(
        j.complete(
            c.claims.challenge_id,
            &p,
            b"context",
            IssuanceTimes {
                holder_verified_at: 100,
                context_signed_at: 100
            },
            &mut ga,
            &t
        ),
        j.complete(
            c.claims.challenge_id,
            &p,
            b"context",
            IssuanceTimes {
                holder_verified_at: 100,
                context_signed_at: 100
            },
            &mut gb,
            &t
        )
    );
    assert!(a.is_ok() || b.is_ok());
    for x in [&a, &b] {
        assert!(x.is_ok() || matches!(x, Err(JournalError::Busy)));
    }
    let cached = j
        .cached(
            c.claims.challenge_id,
            &proof,
            &c.request_bytes,
            &mut MockGuard::allow(),
            &t,
        )
        .await
        .unwrap();
    assert_eq!(cached.packet, p);
}
#[tokio::test]
async fn completion_events_are_separate_immutable_and_inside_authorized_window() {
    let (_d, t, j) = setup(Limits::default()).await;
    let c = test_challenge(1, "holder", 1);
    pending(&j, &t, &c).await;
    let (p, proof) = packet(&c);
    t.set(120);
    let times = IssuanceTimes {
        holder_verified_at: 105,
        context_signed_at: 110,
    };
    let result = j
        .complete(
            c.claims.challenge_id,
            &p,
            b"context",
            times,
            &mut MockGuard::allow(),
            &t,
        )
        .await
        .unwrap();
    assert_eq!(result.holder_verified_at, 105);
    assert_eq!(result.signed_at, 110);
    t.set(125);
    assert_eq!(
        result,
        j.cached(
            c.claims.challenge_id,
            &proof,
            &c.request_bytes,
            &mut MockGuard::allow(),
            &t
        )
        .await
        .unwrap()
    );
    assert_eq!(
        j.complete(
            c.claims.challenge_id,
            &p,
            b"context",
            IssuanceTimes {
                holder_verified_at: 105,
                context_signed_at: 120
            },
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Conflict)
    );
}
#[tokio::test]
async fn failed_checkpoint_exports_nothing_then_exact_restart_delivery_recovers() {
    let (d, t, j) = setup(Limits::default()).await;
    let c = test_challenge(1, "holder", 1);
    pending(&j, &t, &c).await;
    let (p, proof) = packet(&c);
    let mut reader = sqlx::SqliteConnection::connect(&format!(
        "sqlite://{}",
        d.path().join("service-challenges.sqlite3").display()
    ))
    .await
    .unwrap();
    sqlx::query("BEGIN").execute(&mut reader).await.unwrap();
    let _: i64 = sqlx::query_scalar("SELECT count(*) FROM service_challenges_v1")
        .fetch_one(&mut reader)
        .await
        .unwrap();
    assert_eq!(
        j.complete(
            c.claims.challenge_id,
            &p,
            b"context",
            IssuanceTimes {
                holder_verified_at: 100,
                context_signed_at: 100
            },
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Busy)
    );
    sqlx::query("ROLLBACK").execute(&mut reader).await.unwrap();
    reader.close().await.unwrap();
    drop(j);
    let j = Journal::open(d.path(), Limits::default(), &t)
        .await
        .unwrap();
    assert_eq!(
        j.cached(
            c.claims.challenge_id,
            &proof,
            &c.request_bytes,
            &mut MockGuard::allow(),
            &t
        )
        .await
        .unwrap()
        .packet,
        p
    );
}
#[tokio::test]
async fn physical_cap_blocks_before_growth_and_checks_wal() {
    let (d, t, j) = setup(Limits {
        physical_bytes: 1024 * 1024,
        ..Limits::default()
    })
    .await;
    // The physical page reservation tightens admission but retains the public 2MiB
    // payload contract: this low operator limit denies storage, never truncates it.
    assert!(matches!(
        j.persist_pending(
            &test_challenge(1, "holder", 2_097_152),
            b"e",
            b"l",
            &mut MockGuard::allow(),
            &t
        )
        .await,
        Err(JournalError::Storage | JournalError::Capacity)
    ));
    let total: u64 = std::fs::read_dir(d.path())
        .unwrap()
        .map(|e| e.unwrap().metadata().unwrap().len())
        .sum();
    assert!(total <= 1024 * 1024);
    let wal = d.path().join("service-challenges.sqlite3-wal");
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(wal)
        .unwrap();
    file.set_len(1024 * 1024 + 1).unwrap();
    assert_eq!(j.stats(&t).await.err(), Some(JournalError::Capacity));
}
#[tokio::test]
async fn directory_and_database_aliases_are_not_accepted() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let d = private_dir();
    let t = TestClock::new(100);
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        Journal::open(d.path(), Limits::default(), &t).await,
        Err(JournalError::Invalid)
    ));
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let other = private_dir();
    let target = other.path().join("alias");
    std::fs::write(&target, []).unwrap();
    symlink(&target, d.path().join("service-challenges.sqlite3")).unwrap();
    assert!(matches!(
        Journal::open(d.path(), Limits::default(), &t).await,
        Err(JournalError::Invalid)
    ));
}

// This subprocess test entry never signs and uses only explicit mock authority.
#[tokio::test]
async fn crash_worker() {
    let Ok(directory) = std::env::var("JOURNAL_CRASH_DIR") else {
        return;
    };
    let phase = std::env::var("JOURNAL_CRASH_PHASE").unwrap();
    let marker = std::env::var("JOURNAL_CRASH_MARKER").unwrap();
    let t = TestClock::new(100);
    let j = Journal::open(std::path::Path::new(&directory), Limits::default(), &t)
        .await
        .unwrap();
    let c = test_challenge(1, "holder", 10);
    struct CrashGuard {
        count: u64,
        stop: u64,
        marker: String,
    }
    impl AuthorityGuard for CrashGuard {
        fn revalidate(&mut self, _: GuardInput<'_>) -> Result<(), JournalError> {
            self.count += 1;
            if self.count == self.stop {
                std::fs::write(&self.marker, b"at-boundary").unwrap();
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
            Ok(())
        }
    }
    let mut g = CrashGuard {
        count: 0,
        stop: if phase.ends_with("after") { 2 } else { 1 },
        marker,
    };
    if phase.starts_with("complete") {
        pending(&j, &t, &c).await;
        j.complete(
            c.claims.challenge_id,
            &packet(&c).0,
            b"context",
            IssuanceTimes {
                holder_verified_at: 100,
                context_signed_at: 100,
            },
            &mut g,
            &t,
        )
        .await
        .unwrap();
    } else {
        j.persist_pending(&c, b"evidence", b"lineage", &mut g, &t)
            .await
            .unwrap();
    }
    panic!("crash hook not reached");
}
#[tokio::test]
async fn killed_process_before_and_after_commits_preserves_exact_recovery() {
    use std::os::unix::fs::PermissionsExt;
    for phase in [
        "pending-before",
        "pending-after",
        "complete-before",
        "complete-after",
    ] {
        let outer = private_dir();
        let dir = outer.path().join("journal");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let marker = outer.path().join("marker");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "tests::crash_worker", "--nocapture"])
            .env("JOURNAL_CRASH_DIR", &dir)
            .env("JOURNAL_CRASH_MARKER", &marker)
            .env("JOURNAL_CRASH_PHASE", phase)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        while !marker.exists() && start.elapsed() < std::time::Duration::from_secs(10) {
            assert!(
                child.try_wait().unwrap().is_none(),
                "worker exited early: {phase}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let reached = marker.exists();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(reached, "boundary not reached: {phase}");
        let t = TestClock::new(100);
        let j = Journal::open(&dir, Limits::default(), &t).await.unwrap();
        let stats = j.stats(&t).await.unwrap();
        match phase {
            "pending-before" => assert_eq!(stats.rows, 0),
            "pending-after" | "complete-before" => assert_eq!(stats.pending, 1),
            "complete-after" => {
                assert_eq!(stats.completed, 1);
                let c = test_challenge(1, "holder", 10);
                let (p, proof) = packet(&c);
                let output = j
                    .cached(
                        c.claims.challenge_id,
                        &proof,
                        &c.request_bytes,
                        &mut MockGuard::allow(),
                        &t,
                    )
                    .await
                    .unwrap();
                assert_eq!(output.packet, p);
                assert_eq!(output.context, b"context");
            }
            _ => unreachable!(),
        }
    }
}

#[tokio::test]
async fn unknown_storage_schema_is_not_silently_accepted() {
    let (d, t, j) = setup(Limits::default()).await;
    pending(&j, &t, &test_challenge(1, "holder", 1)).await;
    drop(j);
    let mut db = sqlx::SqliteConnection::connect(&format!(
        "sqlite://{}",
        d.path().join("service-challenges.sqlite3").display()
    ))
    .await
    .unwrap();
    sqlx::query("ALTER TABLE service_challenges_v1 ADD COLUMN uncharged BLOB")
        .execute(&mut db)
        .await
        .unwrap();
    db.close().await.unwrap();
    assert!(matches!(
        Journal::open(d.path(), Limits::default(), &t).await,
        Err(JournalError::Corrupt)
    ));
}

#[tokio::test]
async fn altered_sqlite_page_size_cannot_weaken_physical_reservation() {
    let (d, t, j) = setup(Limits::default()).await;
    pending(&j, &t, &test_challenge(1, "holder", 1)).await;
    drop(j);
    let mut db = sqlx::SqliteConnection::connect(&format!(
        "sqlite://{}",
        d.path().join("service-challenges.sqlite3").display()
    ))
    .await
    .unwrap();
    for sql in [
        "PRAGMA journal_mode=DELETE",
        "PRAGMA page_size=8192",
        "VACUUM",
    ] {
        sqlx::query(sql).execute(&mut db).await.unwrap();
    }
    db.close().await.unwrap();
    assert!(matches!(
        Journal::open(d.path(), Limits::default(), &t).await,
        Err(JournalError::Corrupt)
    ));
}

#[tokio::test]
async fn delayed_actual_sqlite_close_cannot_export_after_exclusive_expiry() {
    let (_d, t, mut j) = setup(Limits::default()).await;
    let delayed = t.clone();
    j.after_close_for_test(move || {
        std::thread::sleep(std::time::Duration::from_millis(5));
        delayed.set(160);
    });
    assert_eq!(
        j.persist_pending(
            &test_challenge(1, "holder", 1),
            b"e",
            b"l",
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Expired)
    );
}

#[tokio::test]
async fn post_close_revocation_blocks_completion_and_cached_delivery() {
    use std::sync::atomic::AtomicBool;
    struct Current(Arc<AtomicBool>);
    impl AuthorityGuard for Current {
        fn revalidate(&mut self, _: GuardInput<'_>) -> Result<(), JournalError> {
            if self.0.load(Ordering::SeqCst) {
                Err(JournalError::Rejected)
            } else {
                Ok(())
            }
        }
    }
    for cached in [false, true] {
        let (_d, t, mut j) = setup(Limits::default()).await;
        let c = test_challenge(1, "holder", 10);
        pending(&j, &t, &c).await;
        let (p, proof) = packet(&c);
        if cached {
            j.complete(
                c.claims.challenge_id,
                &p,
                b"context",
                IssuanceTimes {
                    holder_verified_at: 100,
                    context_signed_at: 100,
                },
                &mut MockGuard::allow(),
                &t,
            )
            .await
            .unwrap();
        }
        let revoked = Arc::new(AtomicBool::new(false));
        let next = revoked.clone();
        j.after_close_for_test(move || {
            next.store(true, Ordering::SeqCst);
        });
        let mut guard = Current(revoked);
        let result = if cached {
            j.cached(
                c.claims.challenge_id,
                &proof,
                &c.request_bytes,
                &mut guard,
                &t,
            )
            .await
        } else {
            j.complete(
                c.claims.challenge_id,
                &p,
                b"context",
                IssuanceTimes {
                    holder_verified_at: 100,
                    context_signed_at: 100,
                },
                &mut guard,
                &t,
            )
            .await
        };
        assert_eq!(result.err(), Some(JournalError::Rejected));
        assert_eq!(j.stats(&t).await.unwrap().tombstones, 1);
    }
}
#[tokio::test]
async fn post_close_clock_advance_is_durable_before_export() {
    let (d, t, mut j) = setup(Limits::default()).await;
    let delayed = t.clone();
    j.after_close_for_test(move || {
        delayed.set(101);
    });
    pending(&j, &t, &test_challenge(1, "holder", 1)).await;
    drop(j);
    t.set(100);
    assert!(matches!(
        Journal::open(d.path(), Limits::default(), &t).await,
        Err(JournalError::ClockRollback)
    ));
}
#[tokio::test]
async fn all_default_holder_rows_count_even_when_rejected() {
    let (_d, t, j) = setup(Limits::default()).await;
    for n in 1..=32 {
        let c = test_challenge(n, "holder", 1);
        pending(&j, &t, &c).await;
        j.reject(c.claims.challenge_id, &t).await.unwrap();
    }
    assert_eq!(j.stats(&t).await.unwrap().tombstones, 32);
    assert_eq!(
        j.persist_pending(
            &test_challenge(33, "holder", 1),
            b"e",
            b"l",
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Capacity)
    );
}
#[tokio::test]
async fn global_reservations_and_metadata_boundaries_are_enforced() {
    let (_d, t, j) = setup(Limits {
        bytes_global: 2 * (COMPLETION_OVERHEAD + 1),
        ..Limits::default()
    })
    .await;
    pending(&j, &t, &test_challenge(1, "a", 1)).await;
    pending(&j, &t, &test_challenge(2, "b", 1)).await;
    assert_eq!(
        j.persist_pending(
            &test_challenge(3, "c", 1),
            b"e",
            b"l",
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Capacity)
    );
    let (_d, t, j) = setup(Limits::default()).await;
    let c = test_challenge(1, "holder", 1);
    assert_eq!(
        j.persist_pending(
            &c,
            &vec![0; METADATA_LIMIT + 1],
            b"l",
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Invalid)
    );
    assert_eq!(
        j.persist_pending(&c, b"e", &vec![0; 4097], &mut MockGuard::allow(), &t)
            .await
            .err(),
        Some(JournalError::Invalid)
    );
    j.persist_pending(
        &c,
        &vec![0; METADATA_LIMIT],
        &vec![0; 4096],
        &mut MockGuard::allow(),
        &t,
    )
    .await
    .unwrap();
    let (p, _) = packet(&c);
    assert_eq!(
        j.complete(
            c.claims.challenge_id,
            &p,
            &vec![0; CONTEXT_LIMIT + 1],
            IssuanceTimes {
                holder_verified_at: 100,
                context_signed_at: 100
            },
            &mut MockGuard::allow(),
            &t
        )
        .await
        .err(),
        Some(JournalError::Invalid)
    );
    assert_eq!(j.stats(&t).await.unwrap().pending, 1);
}
#[tokio::test]
async fn existing_sidecars_cannot_consume_the_physical_safety_margin() {
    use std::os::unix::fs::OpenOptionsExt;
    for name in ["journal.lock", "service-challenges.sqlite3-shm"] {
        let (d, t, j) = setup(Limits::default()).await;
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(d.path().join(name))
            .unwrap();
        f.set_len(128 * 1024 + 1).unwrap();
        assert_eq!(j.stats(&t).await.err(), Some(JournalError::Capacity));
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn native_preallocation_past_lock_eof_cannot_consume_reserved_space() {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
    let (d, t, j) = setup(Limits::default()).await;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(d.path().join("journal.lock"))
        .unwrap();
    let mut allocation = libc::fstore_t {
        fst_flags: libc::F_ALLOCATEALL,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: 8 * 1024 * 1024,
        fst_bytesalloc: 0,
    };
    assert_eq!(
        unsafe { libc::fcntl(lock.as_raw_fd(), libc::F_PREALLOCATE, &mut allocation) },
        0,
        "native disposable preallocation must be exercised"
    );
    let metadata = lock.metadata().unwrap();
    assert_eq!(metadata.len(), 0);
    assert!(metadata.blocks() * 512 >= 8 * 1024 * 1024);
    assert_eq!(j.stats(&t).await.err(), Some(JournalError::Capacity));
}
