//! Source-proposal tests only; not executed by the author. Both applications use
//! disposable public Native fixtures/test time, never installed Wallet custody.
use super::*;
use crate::{ServiceAuthorityError, ServiceResume};

fn configured_authority(
    f: &Fixture,
    journal: &std::path::Path,
) -> (tempfile::TempDir, std::path::PathBuf) {
    let cfg = journal_directory();
    let path = cfg.path().join("authority.json");
    private_file(&path, &canonical(&configuration(f, journal)));
    (cfg, path)
}
async fn stats(journal: &std::path::Path, at: u64) -> crate::service_challenge_store::Stats {
    let clock = PendingClock::new(at);
    Journal::open(journal, Limits::default(), &clock)
        .await
        .unwrap()
        .stats(&clock)
        .await
        .unwrap()
}
fn pending(result: ServiceResume) -> Vec<u8> {
    match result {
        ServiceResume::PendingChallenge(bytes) => bytes,
        ServiceResume::Completed(_) => panic!("unexpected Completed result"),
    }
}
fn completed(result: ServiceResume) -> crate::ServiceCompletion {
    match result {
        ServiceResume::Completed(value) => value,
        ServiceResume::PendingChallenge(_) => panic!("unexpected Pending result"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_resume_recovers_pending_after_reopen_without_new_window_or_quota() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let d = journal_directory();
        let (_cfg, path) = configured_authority(&f, d.path());
        let authority = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        let raw = request(app);
        assert_eq!(
            authority.resume(&raw).await.unwrap_err(),
            ServiceAuthorityError
        );
        assert_eq!(stats(d.path(), f.now).await.rows, 0);
        let original = authority.issue(&raw).await.unwrap();
        let claims = UntrustedSignedServiceChallenge::decode_inner(&original)
            .unwrap()
            .claims;
        drop(authority);
        crate::service_wallet_source::TEST_NOW.with(|v| v.set(Some(f.now + 2)));
        let authority = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        let before = stats(d.path(), f.now + 2).await;
        for _ in 0..2 {
            assert_eq!(pending(authority.resume(&raw).await.unwrap()), original);
        }
        assert_eq!(stats(d.path(), f.now + 2).await, before);
        assert_eq!((claims.issued_at, claims.expires_at), (f.now, f.now + 60));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_resume_recovers_completed_after_lost_output_without_caller_proof() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let d = journal_directory();
        let (_cfg, path) = configured_authority(&f, d.path());
        let authority = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        let raw = request(app);
        let challenge =
            UntrustedSignedServiceChallenge::decode_inner(&authority.issue(&raw).await.unwrap())
                .unwrap();
        let p = proof(&f, &challenge);
        let original = authority.complete(&raw, &p).await.unwrap();
        let original_proof = p.clone();
        drop(p);
        drop(authority);
        crate::service_wallet_source::TEST_NOW.with(|v| v.set(Some(f.now + 2)));
        let authority = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        let before = stats(d.path(), f.now + 2).await;
        for _ in 0..2 {
            let recovered = completed(authority.resume(&raw).await.unwrap());
            assert_eq!(recovered, original);
            let packet: libsec_core::ZenithPacket =
                bincode::deserialize(&recovered.packet).unwrap();
            assert_eq!(packet.proof, original_proof);
            let signed: SignedVerifiedCallContext =
                bincode::deserialize(&recovered.signed_context).unwrap();
            assert_eq!(
                (signed.context.issued_at, signed.context.expires_at),
                (challenge.claims.issued_at, challenge.claims.expires_at)
            );
        }
        assert_eq!(stats(d.path(), f.now + 2).await, before);
        // Existing issue semantics stay Pending-only, even when resume succeeds.
        assert_eq!(
            authority.issue(&raw).await.unwrap_err(),
            ServiceAuthorityError
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_resume_wrong_request_and_original_expiry_never_create_or_renew() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        for cached in [false, true] {
            let f = Fixture::new(app, |_, _| {});
            let _time = TestTime::set(f.now);
            let d = journal_directory();
            let (_cfg, path) = configured_authority(&f, d.path());
            let authority = ServiceAuthority::open_owner_configuration(&path)
                .await
                .unwrap();
            let raw = request(app);
            let challenge = UntrustedSignedServiceChallenge::decode_inner(
                &authority.issue(&raw).await.unwrap(),
            )
            .unwrap();
            if cached {
                authority
                    .complete(&raw, &proof(&f, &challenge))
                    .await
                    .unwrap();
            }
            let before = stats(d.path(), f.now).await;
            let mut changed = raw.clone();
            changed.push(b' ');
            assert_eq!(
                authority.resume(&changed).await.unwrap_err(),
                ServiceAuthorityError
            );
            assert_eq!(stats(d.path(), f.now).await, before);
            assert!(
                authority.resume(&raw).await.is_ok(),
                "own exact-request control"
            );
            crate::service_wallet_source::TEST_NOW
                .with(|v| v.set(Some(challenge.claims.expires_at)));
            assert_eq!(
                authority.resume(&raw).await.unwrap_err(),
                ServiceAuthorityError
            );
            assert_eq!(stats(d.path(), challenge.claims.expires_at).await.rows, 0);
            drop(authority);
            crate::service_wallet_source::TEST_NOW
                .with(|v| v.set(Some(challenge.claims.expires_at + 1)));
            let authority = ServiceAuthority::open_owner_configuration(&path)
                .await
                .unwrap();
            assert_eq!(
                authority.resume(&raw).await.unwrap_err(),
                ServiceAuthorityError
            );
            assert_eq!(
                stats(d.path(), challenge.claims.expires_at + 1).await.rows,
                0
            );
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_resume_denies_current_policy_issuer_and_wallet_inactive_or_revoked_changes() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        for cached in [false, true] {
            for change in [
                "native_policy",
                "issuer",
                "wallet_inactive",
                "wallet_revoked",
            ] {
                let f = Fixture::new(app, |_, _| {});
                let _time = TestTime::set(f.now);
                let d = journal_directory();
                let (_cfg, path) = configured_authority(&f, d.path());
                let authority = ServiceAuthority::open_owner_configuration(&path)
                    .await
                    .unwrap();
                let raw = request(app);
                let challenge = UntrustedSignedServiceChallenge::decode_inner(
                    &authority.issue(&raw).await.unwrap(),
                )
                .unwrap();
                if cached {
                    authority
                        .complete(&raw, &proof(&f, &challenge))
                        .await
                        .unwrap();
                }
                assert!(
                    authority.resume(&raw).await.is_ok(),
                    "own current-owner control"
                );
                match change {
                    "native_policy" => {
                        let path = f.owner.path().join("owner-generation.json");
                        let mut value: Value =
                            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                        assert_ne!(
                            value["receiver_policy"]["rules"][0]["effect"],
                            json!("deny")
                        );
                        value["receiver_policy"]["rules"][0]["effect"] = json!("deny");
                        private_rewrite(&path, &canonical(&value));
                    }
                    "issuer" => private_rewrite(
                        &f.key.path().join("issuer.seed.hex"),
                        hex(&[82; 32]).as_bytes(),
                    ),
                    _ => {
                        let old = f.wallet.observed();
                        let mut state: Value = serde_json::from_slice(&old.state_raw).unwrap();
                        state["state_revision"] = json!(3);
                        state["state"] = json!(if change == "wallet_revoked" {
                            "revoked"
                        } else {
                            "unconfigured"
                        });
                        state["published_at"] = json!(f.now);
                        state["previous_state_sha256"] = json!(hex(&hash(&old.state_raw)));
                        state["owner_input_sha256"] = Value::Null;
                        if change == "wallet_revoked" {
                            state["revoked_at"] = json!(f.now);
                        }
                        let root = ServiceRoot::open(f.wallet.path()).unwrap();
                        let mut lease = root.lock_exclusive().unwrap();
                        f.wallet.publish(&mut lease, &state, None, true);
                        lease.publish_clock(&canonical(&json!({"schema":"castalia.wallet-service-custody-clock.v1", "store_id":state["store_id"], "observed_at":f.now})), true).unwrap();
                    }
                }
                assert_eq!(
                    authority.resume(&raw).await.unwrap_err(),
                    ServiceAuthorityError,
                    "accepted {change}"
                );
                assert_eq!(
                    authority.resume(&raw).await.unwrap_err(),
                    ServiceAuthorityError
                );
                assert_eq!(stats(d.path(), f.now).await.rows, 1, "no replacement row");
            }
        }
    }
}
fn private_rewrite(path: &std::path::Path, bytes: &[u8]) {
    // Existing owned disposable file: preserve its0600 mode and selected inode.
    fs::write(path, bytes).unwrap();
    assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_resume_rejects_tombstones_and_ambiguous_requests_without_reissue() {
    use super::super::super::resume_tests::UnauthenticatedStorageFixture;
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        for cached in [false, true] {
            for ambiguous in [false, true] {
                let f = Fixture::new(app, |_, _| {});
                let _time = TestTime::set(f.now);
                let d = journal_directory();
                let (_cfg, path) = configured_authority(&f, d.path());
                let authority = ServiceAuthority::open_owner_configuration(&path)
                    .await
                    .unwrap();
                let raw = request(app);
                let challenge = UntrustedSignedServiceChallenge::decode_inner(
                    &authority.issue(&raw).await.unwrap(),
                )
                .unwrap();
                if cached {
                    authority
                        .complete(&raw, &proof(&f, &challenge))
                        .await
                        .unwrap();
                }
                assert!(
                    authority.resume(&raw).await.is_ok(),
                    "own valid retained-row control"
                );
                let clock = PendingClock::new(f.now);
                let journal = Journal::open(d.path(), Limits::default(), &clock)
                    .await
                    .unwrap();
                if ambiguous {
                    let basis = journal
                        .retained_completion_basis(challenge.claims.challenge_id, &clock)
                        .await
                        .unwrap();
                    let mut other = challenge.clone();
                    other.claims.challenge_id[0] ^= 1;
                    other.claims.session_id[0] ^= 1;
                    other.claims.nonce[0] ^= 1;
                    // Generic storage-only legacy duplicate; never authority.
                    journal
                        .persist_pending(
                            &other,
                            &basis.evidence,
                            &basis.lineage,
                            &mut UnauthenticatedStorageFixture,
                            &clock,
                        )
                        .await
                        .unwrap();
                } else {
                    journal
                        .reject(challenge.claims.challenge_id, &clock)
                        .await
                        .unwrap();
                }
                let before = journal.stats(&clock).await.unwrap();
                assert_eq!(
                    authority.resume(&raw).await.unwrap_err(),
                    ServiceAuthorityError
                );
                assert_eq!(
                    authority.issue(&raw).await.unwrap_err(),
                    ServiceAuthorityError
                );
                assert_eq!(journal.stats(&clock).await.unwrap(), before);
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_resume_retains_current_owners_and_original_expiry_after_final_close() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        for cached in [false, true] {
            let f = Fixture::new(app, |_, _| {});
            let _time = TestTime::set(f.now);
            let w = f.wallet.source();
            let n = f.owner_source();
            let k = f.key_source();
            let d = journal_directory();
            let clock = PendingClock::new(f.now);
            let mut journal = Journal::open(d.path(), Limits::default(), &clock)
                .await
                .unwrap();
            let challenge = {
                let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &journal, 60).unwrap();
                let c = issuer
                    .issue_pending_challenge(&request(app))
                    .await
                    .unwrap()
                    .challenge;
                if cached {
                    issuer
                        .complete_service_challenge(&request(app), &proof(&f, &c))
                        .await
                        .unwrap();
                }
                assert!(
                    issuer.resume_service_challenge(&request(app)).await.is_ok(),
                    "own final-export control"
                );
                c
            };
            let reached = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&reached);
            let wallet_path = f.wallet.path().to_path_buf();
            let native_lock = f.owner.path().join(".service-owner.lock");
            let key_lock = f.key.path().join(".service-issuer.lock");
            let deadline = challenge.claims.expires_at;
            journal.after_close_for_test(move || {
                let root = ServiceRoot::open(&wallet_path).unwrap();
                match root.lock_exclusive() {
                    Ok(_) => return, // Untrusted inspection: no authority owners.
                    Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
                }
                observed.fetch_add(1, Ordering::SeqCst);
                for path in [&native_lock, &key_lock] {
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
                crate::service_wallet_source::TEST_NOW.with(|v| v.set(Some(deadline)));
            });
            let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &journal, 60).unwrap();
            assert!(issuer
                .resume_service_challenge(&request(app))
                .await
                .is_err());
            assert!(
                reached.load(Ordering::SeqCst) >= 1,
                "guarded final close not reached"
            );
            // Before normal expiry pruning, the final guard persisted rejection.
            let mut conn = sqlx::SqliteConnection::connect(&format!(
                "sqlite://{}",
                d.path().join("service-challenges.sqlite3").display()
            ))
            .await
            .unwrap();
            let state: i64 = sqlx::query_scalar("SELECT state FROM service_challenges_v1")
                .fetch_one(&mut conn)
                .await
                .unwrap();
            assert_eq!(state, 2);
            conn.close().await.unwrap();
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_resume_bounds_raw_input_and_does_not_log_transport_bytes() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let d = journal_directory();
        let (_cfg, path) = configured_authority(&f, d.path());
        let authority = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        for bad in [Vec::new(), vec![b'x'; 2_097_153], b"{invalid".to_vec()] {
            assert_eq!(
                authority.resume(&bad).await.unwrap_err(),
                ServiceAuthorityError
            );
        }
        assert_eq!(stats(d.path(), f.now).await.rows, 0);
        let raw = request(app);
        let original = authority.issue(&raw).await.unwrap();
        let resumed = authority.resume(&raw).await.unwrap();
        assert_eq!(
            format!("{resumed:?}"),
            format!(
                "PendingChallenge {{ challenge_bytes: {}, .. }}",
                original.len()
            )
        );
        assert_eq!(pending(resumed), original);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn pinned_owner_startup_accepts_exact_bytes_and_legacy_open_remains_compatible() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let d = journal_directory();
        let (_cfg, path) = configured_authority(&f, d.path());
        let selected = fs::read(&path).unwrap();
        let pinned = ServiceAuthority::open_pinned_owner_configuration(&path, hash(&selected))
            .await
            .unwrap();
        let raw = request(app);
        let original = pinned.issue(&raw).await.unwrap();
        drop(pinned);
        let legacy = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        assert_eq!(legacy.issue(&raw).await.unwrap(), original);
        assert_eq!(pending(legacy.resume(&raw).await.unwrap()), original);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn pinned_owner_startup_changed_pin_or_bytes_denies_before_journal_creation() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        for change in ["digest", "bytes"] {
            let f = Fixture::new(app, |_, _| {});
            let _time = TestTime::set(f.now);
            // Independent exact-pin positive establishes ordinary valid startup.
            let control = journal_directory();
            let (_control_cfg, control_path) = configured_authority(&f, control.path());
            ServiceAuthority::open_pinned_owner_configuration(
                &control_path,
                hash(&fs::read(&control_path).unwrap()),
            )
            .await
            .unwrap();
            let d = journal_directory();
            let (_cfg, path) = configured_authority(&f, d.path());
            let selected = fs::read(&path).unwrap();
            let mut expected = hash(&selected);
            if change == "digest" {
                expected[0] ^= 1;
            } else {
                let mut value: Value = serde_json::from_slice(&selected).unwrap();
                value["maximum_ttl"] = json!(59);
                private_rewrite(&path, &canonical(&value));
            }
            assert!(matches!(
                ServiceAuthority::open_pinned_owner_configuration(&path, expected).await,
                Err(ServiceAuthorityError)
            ));
            assert_eq!(
                fs::read_dir(d.path()).unwrap().count(),
                0,
                "mismatch opened journal"
            );
            // The same actual current bytes remain a valid owner configuration;
            // the negative above is the digest fence, not invalid source shape.
            let legacy = ServiceAuthority::open_owner_configuration(&path)
                .await
                .unwrap();
            legacy.issue(&request(app)).await.unwrap();
        }
    }
}

// All direct SQL below is a disposable storage-only race fixture. The candidate
// production source has no row mutation or callback hook added for this test.
async fn retained_resume_race_rows(directory: &std::path::Path) -> Vec<Vec<u8>> {
    use sqlx::Row;
    let mut conn = sqlx::SqliteConnection::connect(&format!(
        "sqlite://{}",
        directory.join("service-challenges.sqlite3").display()
    ))
    .await
    .unwrap();
    let rows = sqlx::query("SELECT id,holder,session,nonce,expires,state,accounted,request_bytes,record,digest FROM service_challenges_v1 ORDER BY id")
        .fetch_all(&mut conn)
        .await
        .unwrap();
    let bytes = rows
        .iter()
        .map(|row| {
            bincode::serialize(&(
                row.get::<Vec<u8>, _>("id"),
                row.get::<String, _>("holder"),
                row.get::<Vec<u8>, _>("session"),
                row.get::<Vec<u8>, _>("nonce"),
                row.get::<i64, _>("expires"),
                row.get::<i64, _>("state"),
                row.get::<i64, _>("accounted"),
                row.get::<i64, _>("request_bytes"),
                row.get::<Vec<u8>, _>("record"),
                row.get::<Vec<u8>, _>("digest"),
            ))
            .unwrap()
        })
        .collect();
    conn.close().await.unwrap();
    bytes
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_resume_captured_completed_basis_denies_late_pending_or_ambiguity_without_rewriting_rows(
) {
    use super::super::super::resume_tests::UnauthenticatedStorageFixture;
    use ed25519_dalek::Signer;
    use sqlx::Row;
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        for ambiguous in [false, true] {
            let f = Fixture::new(app, |_, _| {});
            let _time = TestTime::set(f.now);
            let w = f.wallet.source();
            let n = f.owner_source();
            let k = f.key_source();
            let d = journal_directory();
            let clock = PendingClock::new(f.now);
            let journal = Journal::open(d.path(), Limits::default(), &clock)
                .await
                .unwrap();
            let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &journal, 60).unwrap();
            let raw = request(app);
            let challenge = issuer
                .issue_pending_challenge(&raw)
                .await
                .unwrap()
                .challenge;
            let p = proof(&f, &challenge);
            let original = issuer.complete_service_challenge(&raw, &p).await.unwrap();
            // Immutable Completed input is captured BEFORE either late mutation.
            let retained = journal
                .retained_completion_basis(challenge.claims.challenge_id, &clock)
                .await
                .unwrap();
            assert_eq!(retained.completion.as_ref().unwrap(), &original);
            let window =
                OriginalServiceWindow::new(challenge.claims.issued_at, challenge.claims.expires_at)
                    .unwrap();
            let control_entered = std::cell::Cell::new(false);
            let control = issuer
                .complete_retained_service_challenge(
                    &raw,
                    &p,
                    &retained,
                    window,
                    &clock,
                    &control_entered,
                )
                .await
                .unwrap();
            assert_eq!(control, original);
            assert!(
                control_entered.get(),
                "own cached final-export positive did not reach journal"
            );

            if ambiguous {
                let mut other = challenge.clone();
                other.claims.challenge_id[0] ^= 1;
                other.claims.session_id[0] ^= 1;
                other.claims.nonce[0] ^= 1;
                // Valid disposable PUBLIC issuer signature, not a forged codec
                // failure. Generic storage allows this legacy same-request row;
                // the Native producer must reject its resulting ambiguity.
                other.issuer_signature = SigningKey::from_bytes(&PUBLIC_SEED)
                    .sign(
                        &libsec_core::service_holder_proof::challenge_transcript(
                            &other.claims,
                            &raw,
                        )
                        .unwrap(),
                    )
                    .to_bytes();
                journal
                    .persist_pending(
                        &other,
                        &retained.evidence,
                        &retained.lineage,
                        &mut UnauthenticatedStorageFixture,
                        &clock,
                    )
                    .await
                    .unwrap();
            } else {
                // Produce a genuine, internally consistent Pending record using
                // the unchanged journal codec, reservation and digest accounting.
                // Only then copy its complete mutable columns into this row.
                let pending_dir = journal_directory();
                let pending_journal = Journal::open(pending_dir.path(), Limits::default(), &clock)
                    .await
                    .unwrap();
                pending_journal
                    .persist_pending(
                        &challenge,
                        &retained.evidence,
                        &retained.lineage,
                        &mut UnauthenticatedStorageFixture,
                        &clock,
                    )
                    .await
                    .unwrap();
                let mut source = sqlx::SqliteConnection::connect(&format!(
                    "sqlite://{}",
                    pending_dir
                        .path()
                        .join("service-challenges.sqlite3")
                        .display()
                ))
                .await
                .unwrap();
                let row = sqlx::query("SELECT state,accounted,request_bytes,record,digest FROM service_challenges_v1 WHERE id=?")
                    .bind(challenge.claims.challenge_id.as_slice()).fetch_one(&mut source).await.unwrap();
                assert_eq!(row.get::<i64, _>("state"), 0);
                let state = row.get::<i64, _>("state");
                let accounted = row.get::<i64, _>("accounted");
                let request_bytes = row.get::<i64, _>("request_bytes");
                let record = row.get::<Vec<u8>, _>("record");
                let digest = row.get::<Vec<u8>, _>("digest");
                source.close().await.unwrap();
                let mut destination = sqlx::SqliteConnection::connect(&format!(
                    "sqlite://{}",
                    d.path().join("service-challenges.sqlite3").display()
                ))
                .await
                .unwrap();
                let changed = sqlx::query("UPDATE service_challenges_v1 SET state=?,accounted=?,request_bytes=?,record=?,digest=? WHERE id=? AND state=1")
                    .bind(state).bind(accounted).bind(request_bytes).bind(record).bind(digest)
                    .bind(challenge.claims.challenge_id.as_slice()).execute(&mut destination).await.unwrap();
                assert_eq!(changed.rows_affected(), 1);
                destination.close().await.unwrap();
                // The strict journal audit and Pending decoder both succeed;
                // a corrupt SQL-only state edit cannot satisfy this precondition.
                let current = journal
                    .retained_pending(challenge.claims.challenge_id, &clock)
                    .await
                    .unwrap();
                assert_eq!(current.challenge, challenge);
                assert_eq!(current.evidence, retained.evidence);
                assert_eq!(current.lineage, retained.lineage);
            }
            let before_stats = journal.stats(&clock).await.unwrap();
            assert_eq!(before_stats.rows, if ambiguous { 2 } else { 1 });
            assert_eq!(before_stats.pending, 1);
            assert_eq!(before_stats.completed, u64::from(ambiguous));
            assert_eq!(before_stats.tombstones, 0);
            let before_rows = retained_resume_race_rows(d.path()).await;
            let entered = std::cell::Cell::new(false);
            let error = issuer
                .complete_retained_service_challenge(&raw, &p, &retained, window, &clock, &entered)
                .await
                .unwrap_err();
            assert!(
                entered.get(),
                "race did not reach guarded cached journal export"
            );
            assert_eq!(
                error,
                PendingError::Journal(if ambiguous {
                    JournalError::Conflict
                } else {
                    JournalError::Rejected
                })
            );
            assert_eq!(
                retained_resume_race_rows(d.path()).await,
                before_rows,
                "cached denial rewrote or recreated retained rows/context"
            );
            assert_eq!(journal.stats(&clock).await.unwrap(), before_stats);
            assert_eq!(retained.completion.as_ref().unwrap(), &original);
        }
    }
}
