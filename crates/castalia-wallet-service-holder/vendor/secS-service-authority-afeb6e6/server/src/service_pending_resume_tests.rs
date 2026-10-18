//! Recovery from actual disposable journal files with freshly reopened owners.
//! Public metadata fixtures only; not private Wallet or installed admission.
use super::*;

pub(super) async fn first_challenge(
    f: &Fixture,
    dir: &std::path::Path,
    app: ServiceApplication,
) -> UntrustedSignedServiceChallenge {
    let wallet = f.wallet.source();
    let native = f.owner_source();
    let key = f.key_source();
    let clock = PendingClock::new(f.now);
    let journal = Journal::open(dir, Limits::default(), &clock).await.unwrap();
    PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &journal, 60)
        .unwrap()
        .issue_pending_challenge(&request(app))
        .await
        .unwrap()
        .challenge
}

#[tokio::test(flavor = "current_thread")]
async fn reopened_owners_recover_exact_pending_without_reset_or_extra_quota() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let dir = journal_directory();
        let original = first_challenge(&f, dir.path(), app).await;
        let original_bytes = original.encode_inner().unwrap();
        // All original sources, the issuer and the Journal have been dropped.
        crate::service_wallet_source::TEST_NOW.with(|t| t.set(Some(f.now + 2)));
        let wallet = f.wallet.source();
        let native = f.owner_source();
        let key = f.key_source();
        let clock = PendingClock::new(f.now + 2);
        let limits = Limits {
            pending_global: 1,
            pending_per_holder: 1,
            ..Limits::default()
        };
        let journal = Journal::open(dir.path(), limits, &clock).await.unwrap();
        let issuer =
            PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &journal, 60).unwrap();
        let before = journal.stats(&clock).await.unwrap();
        for _ in 0..2 {
            let recovered = issuer
                .resume_pending_challenge(&request(app), original.claims.challenge_id)
                .await
                .unwrap();
            assert_eq!(recovered.challenge.encode_inner().unwrap(), original_bytes);
            assert_eq!(recovered.challenge.claims.issued_at, f.now);
            assert_eq!(recovered.challenge.claims.expires_at, f.now + 60);
            assert_eq!(
                recovered.challenge.claims.evidence.evidence_observed_at,
                f.now
            );
            assert_eq!(
                recovered
                    .challenge
                    .claims
                    .evidence
                    .evidence_revocation_checked_at,
                f.now
            );
        }
        assert_eq!(journal.stats(&clock).await.unwrap(), before);
        assert_eq!(
            (
                before.rows,
                before.pending,
                before.completed,
                before.tombstones
            ),
            (1, 1, 0, 0)
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_request_missing_identity_and_tightened_cap_do_not_export_or_replace_pending() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let dir = journal_directory();
        let original = first_challenge(&f, dir.path(), app).await;
        crate::service_wallet_source::TEST_NOW.with(|t| t.set(Some(f.now + 1)));
        let wallet = f.wallet.source();
        let native = f.owner_source();
        let key = f.key_source();
        let clock = PendingClock::new(f.now + 1);
        let journal = Journal::open(dir.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let issuer =
            PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &journal, 60).unwrap();
        let mut changed = request(app);
        changed.push(b' ');
        assert_eq!(
            issuer
                .resume_pending_challenge(&changed, original.claims.challenge_id)
                .await
                .unwrap_err(),
            PendingError::Invalid
        );
        assert_eq!(
            issuer
                .resume_pending_challenge(&request(app), [0; 32])
                .await
                .unwrap_err(),
            PendingError::Invalid
        );
        let mut absent = original.claims.challenge_id;
        absent[0] ^= 1;
        assert_eq!(
            issuer
                .resume_pending_challenge(&request(app), absent)
                .await
                .unwrap_err(),
            PendingError::Journal(JournalError::Missing)
        );
        let tighter =
            PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &journal, 59).unwrap();
        assert_eq!(
            tighter
                .resume_pending_challenge(&request(app), original.claims.challenge_id)
                .await
                .unwrap_err(),
            PendingError::Invalid
        );
        assert_eq!(
            issuer
                .resume_pending_challenge(&request(app), original.claims.challenge_id)
                .await
                .unwrap()
                .challenge,
            original
        );
        assert_eq!(journal.stats(&clock).await.unwrap().rows, 1);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn changed_current_native_or_actual_key_denies_recovered_challenge() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        for change in ["native", "key"] {
            let f = Fixture::new(app, |_, _| {});
            let _time = TestTime::set(f.now);
            let dir = journal_directory();
            let original = first_challenge(&f, dir.path(), app).await;
            crate::service_wallet_source::TEST_NOW.with(|t| t.set(Some(f.now + 1)));
            if change == "native" {
                let path = f.owner.path().join("owner-generation.json");
                let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                value["generation"] = json!(8);
                fs::write(path, canonical(&value)).unwrap();
            } else {
                fs::write(f.key.path().join("issuer.seed.hex"), hex(&[82; 32])).unwrap();
            }
            let wallet = f.wallet.source();
            let native = f.owner_source();
            let key = f.key_source();
            let clock = PendingClock::new(f.now + 1);
            let journal = Journal::open(dir.path(), Limits::default(), &clock)
                .await
                .unwrap();
            let issuer =
                PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &journal, 60).unwrap();
            let error = issuer
                .resume_pending_challenge(&request(app), original.claims.challenge_id)
                .await
                .unwrap_err();
            // An initial-request retry cannot evade the same current-owner
            // denial by choosing a fresh issue time or challenge identity.
            assert_eq!(
                issuer
                    .issue_pending_challenge(&request(app))
                    .await
                    .unwrap_err(),
                error
            );
            if change == "key" {
                assert_eq!(
                    error,
                    PendingError::Issuer(crate::service_context_issuer::IssuerError::Selection)
                );
            } else {
                assert_eq!(
                    error,
                    PendingError::Source(crate::service_wallet_source::SourceError::Changed)
                );
            }
        }
    }
}

// Deliberately accepts STORAGE fixtures, never used by the actual issuer. The
// journal authenticates storage structure, so its digest alone is not authority.
pub(super) struct UnauthenticatedStorageFixture;
impl AuthorityGuard for UnauthenticatedStorageFixture {
    fn revalidate(&mut self, _: GuardInput<'_>) -> Result<(), JournalError> {
        Ok(())
    }
}
#[tokio::test(flavor = "current_thread")]
async fn structurally_valid_journal_with_forged_signature_is_not_authority() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let original_dir = journal_directory();
        let mut forged = first_challenge(&f, original_dir.path(), app).await;
        forged.issuer_signature[0] ^= 1;
        let wallet_source = f.wallet.source();
        let native_source = f.owner_source();
        let wallet = wallet_source.capture_shared().unwrap();
        let native = native_source.capture_shared(f.pin, &wallet).unwrap();
        let policy = native.policy().unwrap();
        let (subject, holder_key, _) = holder(&wallet).unwrap();
        let window = OriginalServiceWindow::new(f.now, f.now + 60).unwrap();
        let prepared = policy
            .prepare_original(&request(app), subject, holder_key, window)
            .unwrap();
        let lineage = wallet.observed.reference.lineage_preimage();
        let fake_dir = journal_directory();
        let clock = PendingClock::new(f.now);
        let journal = Journal::open(fake_dir.path(), Limits::default(), &clock)
            .await
            .unwrap();
        journal
            .persist_pending(
                &forged,
                prepared.evidence().bytes(),
                &lineage,
                &mut UnauthenticatedStorageFixture,
                &clock,
            )
            .await
            .unwrap();
        drop(policy);
        drop(native);
        drop(wallet);
        let key = f.key_source();
        let issuer =
            PendingIssuer::from_startup(&wallet_source, &native_source, f.pin, &key, &journal, 60)
                .unwrap();
        assert_eq!(
            issuer
                .resume_pending_challenge(&request(app), forged.claims.challenge_id)
                .await
                .unwrap_err(),
            PendingError::Invalid
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn recovery_retains_real_owners_through_final_close_and_denies_late_expiry() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let dir = journal_directory();
        let original = first_challenge(&f, dir.path(), app).await;
        crate::service_wallet_source::TEST_NOW.with(|t| t.set(Some(f.now + 1)));
        let wallet = f.wallet.source();
        let native = f.owner_source();
        let key = f.key_source();
        let clock = PendingClock::new(f.now + 1);
        let mut journal = Journal::open(dir.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let reached = Arc::clone(&calls);
        let wallet_path = f.wallet.path().to_path_buf();
        let owner_lock = f.owner.path().join(".service-owner.lock");
        let key_lock = f.key.path().join(".service-issuer.lock");
        let deadline = f.now + 60;
        journal.after_close_for_test(move || {
            // The first close is an UNTRUSTED inspection before owner acquisition.
            // Only the second close is guarded Pending export/admission.
            if reached.fetch_add(1, Ordering::SeqCst) == 0 {
                return;
            }
            match ServiceRoot::open(&wallet_path).unwrap().lock_exclusive() {
                Ok(_) => panic!("recovery released Wallet before final admission"),
                Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
            };
            for path in [&owner_lock, &key_lock] {
                let file = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .unwrap();
                assert_eq!(
                    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                    -1
                );
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::WouldBlock
                );
            }
            crate::service_wallet_source::TEST_NOW.with(|t| t.set(Some(deadline)));
        });
        let issuer =
            PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &journal, 60).unwrap();
        assert_eq!(
            issuer
                .resume_pending_challenge(&request(app), original.claims.challenge_id)
                .await
                .unwrap_err(),
            PendingError::Journal(JournalError::Expired)
        );
        assert!(calls.load(Ordering::SeqCst) >= 2);
        use sqlx::{sqlite::SqliteConnectOptions, Connection, SqliteConnection};
        let options = SqliteConnectOptions::new()
            .filename(dir.path().join("service-challenges.sqlite3"))
            .read_only(true)
            .create_if_missing(false);
        let mut db = SqliteConnection::connect_with(&options).await.unwrap();
        let rows: Vec<(i64, i64)> =
            sqlx::query_as("SELECT state,expires FROM service_challenges_v1")
                .fetch_all(&mut db)
                .await
                .unwrap();
        assert_eq!(rows, vec![(2, deadline as i64)]);
        db.close().await.unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn durable_clock_rollback_after_reopen_denies_instead_of_reissuing() {
    let app = ServiceApplication::RuntimeV1;
    let f = Fixture::new(app, |_, _| {});
    let _time = TestTime::set(f.now);
    let dir = journal_directory();
    let original = first_challenge(&f, dir.path(), app).await;
    let clock = PendingClock::new(f.now);
    let journal = Journal::open(dir.path(), Limits::default(), &clock)
        .await
        .unwrap();
    crate::service_wallet_source::TEST_NOW.with(|t| t.set(Some(f.now + 3)));
    journal.stats(&clock).await.unwrap();
    crate::service_wallet_source::TEST_NOW.with(|t| t.set(Some(f.now + 1)));
    let wallet = f.wallet.source();
    let native = f.owner_source();
    let key = f.key_source();
    let issuer = PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &journal, 60).unwrap();
    assert_eq!(
        issuer
            .resume_pending_challenge(&request(app), original.claims.challenge_id)
            .await
            .unwrap_err(),
        PendingError::Journal(JournalError::ClockRollback)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn exact_pending_survives_a_fresh_process() {
    const CHILD_ENV: &str = "SECS_PENDING_RECOVERY_PUBLIC_FIXTURE";
    if let Some(path) = std::env::var_os(CHILD_ENV) {
        let cfg: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let _time = TestTime::set(cfg["now"].as_u64().unwrap());
        use crate::service_wallet_source::{
            OwnerSelectedWalletRoot, StartupWalletObservationPin, WalletCurrentSource,
        };
        let wallet = WalletCurrentSource::open(
            OwnerSelectedWalletRoot::open(std::path::Path::new(
                cfg["wallet_root"].as_str().unwrap(),
            ))
            .unwrap(),
            StartupWalletObservationPin::parse_owner_configuration(
                cfg["wallet_pin"].as_str().unwrap().as_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
        let native = OwnerPublicationSource::open_owner_selected_root(std::path::Path::new(
            cfg["native_root"].as_str().unwrap(),
        ))
        .unwrap();
        let pin = OwnerStartupPin::new(
            cfg["native_generation"].as_u64().unwrap(),
            serde_json::from_value(cfg["native_digest"].clone()).unwrap(),
        )
        .unwrap();
        let key = IssuerKeySource::open_selected(
            std::path::Path::new(cfg["key_root"].as_str().unwrap()),
            IssuerSelection::new(
                "node:ni03:public-fixture",
                "issuer:ni03:public-fixture",
                SigningKey::from_bytes(&PUBLIC_SEED)
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
        let clock = PendingClock::new(cfg["now"].as_u64().unwrap());
        let journal = Journal::open(
            std::path::Path::new(cfg["journal_root"].as_str().unwrap()),
            Limits::default(),
            &clock,
        )
        .await
        .unwrap();
        let issuer =
            PendingIssuer::from_startup(&wallet, &native, pin, &key, &journal, 60).unwrap();
        let raw: Vec<u8> = serde_json::from_value(cfg["request"].clone()).unwrap();
        let id = serde_json::from_value(cfg["challenge_id"].clone()).unwrap();
        // Lost first response: retry with ONLY exact raw bytes, no challenge ID.
        let recovered = issuer.issue_pending_challenge(&raw).await.unwrap();
        assert_eq!(
            issuer
                .resume_pending_challenge(&raw, id)
                .await
                .unwrap()
                .challenge,
            recovered.challenge
        );
        assert_eq!(journal.stats(&clock).await.unwrap().pending, 1);
        fs::write(
            cfg["result"].as_str().unwrap(),
            recovered.challenge.encode_inner().unwrap(),
        )
        .unwrap();
        return;
    }
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let dir = journal_directory();
        let original = first_challenge(&f, dir.path(), app).await;
        let helper = journal_directory();
        let cfg_path = helper.path().join("public-fixture.json");
        let result_path = helper.path().join("recovered-challenge.bin");
        let wallet_pin = String::from_utf8(f.wallet.source().test_startup_pin_bytes()).unwrap();
        fs::write(&cfg_path, canonical(&json!({
            "now": f.now+2, "wallet_root":f.wallet.path(), "wallet_pin":wallet_pin,
            "native_root":f.owner.path(), "native_generation":f.pin.generation(), "native_digest":f.pin.sha256(),
            "key_root":f.key.path(), "journal_root":dir.path(), "request":request(app),
            "challenge_id":original.claims.challenge_id, "result":result_path,
        }))).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "service_authority::pending_tests::resume_tests::exact_pending_survives_a_fresh_process", "--test-threads=1"])
            .env(CHILD_ENV, &cfg_path).stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("owned recovery fixture child timed out");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.len() + output.stderr.len() < 65_536);
        assert_eq!(
            fs::read(result_path).unwrap(),
            original.encode_inner().unwrap()
        );
    }
}
