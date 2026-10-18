//! Ordinary source tests using disposable public holder/issuer material.
//! No installed Wallet key, live authority, VM or qualification claim.
use super::*;
use crate::verifier::SignedVerifiedCallContext;
use ed25519_dalek::Signer;
use libsec_core::{
    service_holder_proof::{holder_transcript, UntrustedServiceHolderProof},
    ZenithPacket,
};
use sqlx::Connection;
fn proof(f: &Fixture, c: &UntrustedSignedServiceChallenge) -> Vec<u8> {
    let v: Value = serde_json::from_slice(&f.owner_input).unwrap();
    let mut p = UntrustedServiceHolderProof {
        claims: c.claims.clone(),
        issuer_signature: c.issuer_signature,
        holder_policy_digest: hash(&canonical(&v["delegation_policy"])),
        holder_signature: [0; 64],
    };
    let k = SigningKey::from_bytes(&[42; 32]);
    assert_eq!(
        hex(k.verifying_key().as_bytes()),
        v["holder"]["public_key_hex"].as_str().unwrap()
    );
    p.holder_signature = k
        .sign(&holder_transcript(&p, &c.request_bytes).unwrap())
        .to_bytes();
    p.encode().unwrap()
}
#[tokio::test]
async fn completes_original_and_returns_exact_cache_for_both_applications() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let w = f.wallet.source();
        let n = f.owner_source();
        let k = f.key_source();
        let d = journal_directory();
        let clock = PendingClock::new(f.now);
        let j = Journal::open(d.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &j, 60).unwrap();
        let raw = request(app);
        let c = issuer
            .issue_pending_challenge(&raw)
            .await
            .unwrap()
            .challenge;
        let p = proof(&f, &c);
        let out = issuer.complete_service_challenge(&raw, &p).await.unwrap();
        let packet: ZenithPacket = bincode::deserialize(&out.packet).unwrap();
        let signed: SignedVerifiedCallContext = bincode::deserialize(&out.context).unwrap();
        assert_eq!(packet.proof, p);
        assert_eq!(packet.encrypted_payload, raw);
        assert_eq!(signed.context.schema_version, 4);
        assert_eq!(signed.context.issued_at, c.claims.issued_at);
        assert_eq!(signed.context.expires_at, c.claims.expires_at);
        assert_eq!(signed.context.replay_scope, "session:opcode:nonce");
        assert_eq!(
            signed.context.resource.as_deref(),
            Some(c.claims.resource.as_str())
        );
        assert_eq!(
            signed.context.subject.subject_id,
            c.claims.holder_subject_id
        );
        assert_eq!(signed.context.packet_hash, hash(&out.packet));
        SigningKey::from_bytes(&PUBLIC_SEED)
            .verifying_key()
            .verify_strict(
                &bincode::serialize(&signed.context).unwrap(),
                &ed25519_dalek::Signature::from_slice(&signed.signature).unwrap(),
            )
            .unwrap();
        assert_eq!(j.stats(&clock).await.unwrap().completed, 1);
        drop(j);
        let j = Journal::open(d.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &j, 60).unwrap();
        assert_eq!(
            issuer.complete_service_challenge(&raw, &p).await.unwrap(),
            out
        );
    }
}

#[tokio::test]
async fn altered_holder_proofs_and_requests_never_complete_or_burn_valid_cache() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let w = f.wallet.source();
        let n = f.owner_source();
        let k = f.key_source();
        let d = journal_directory();
        let clock = PendingClock::new(f.now);
        let j = Journal::open(d.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &j, 60).unwrap();
        let raw = request(app);
        let c = issuer
            .issue_pending_challenge(&raw)
            .await
            .unwrap()
            .challenge;
        let p = proof(&f, &c);
        for i in 0..6 {
            let mut bad = UntrustedServiceHolderProof::decode(&p).unwrap();
            match i {
                0 => bad.holder_signature[0] ^= 1,
                1 => bad.holder_policy_digest[0] ^= 1,
                2 => bad.issuer_signature[0] ^= 1,
                3 => bad.claims.nonce[0] ^= 1,
                4 => bad.claims.challenge_id[0] ^= 1,
                _ => bad.claims.request_sha256[0] ^= 1,
            }
            assert!(issuer
                .complete_service_challenge(&raw, &bad.encode().unwrap())
                .await
                .is_err());
            assert_eq!(j.stats(&clock).await.unwrap().pending, 1);
        }
        let mut other = raw.clone();
        other.push(b' ');
        assert!(issuer.complete_service_challenge(&other, &p).await.is_err());
        let out = issuer.complete_service_challenge(&raw, &p).await.unwrap();
        let mut bad = UntrustedServiceHolderProof::decode(&p).unwrap();
        bad.holder_signature[0] ^= 1;
        assert!(issuer
            .complete_service_challenge(&raw, &bad.encode().unwrap())
            .await
            .is_err());
        assert_eq!(j.stats(&clock).await.unwrap().completed, 1);
        assert_eq!(
            issuer.complete_service_challenge(&raw, &p).await.unwrap(),
            out
        );
    }
}

#[tokio::test]
async fn cached_actual_key_or_owner_change_tombstones_exact_retained_completion() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        for key_change in [false, true] {
            let f = Fixture::new(app, |_, _| {});
            let _time = TestTime::set(f.now);
            let w = f.wallet.source();
            let n = f.owner_source();
            let k = f.key_source();
            let d = journal_directory();
            let clock = PendingClock::new(f.now);
            let j = Journal::open(d.path(), Limits::default(), &clock)
                .await
                .unwrap();
            let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &j, 60).unwrap();
            let raw = request(app);
            let c = issuer
                .issue_pending_challenge(&raw)
                .await
                .unwrap()
                .challenge;
            let p = proof(&f, &c);
            issuer.complete_service_challenge(&raw, &p).await.unwrap();
            let changed = if key_change {
                f.key.path().join("issuer.seed.hex")
            } else {
                f.owner.path().join("owner-generation.json")
            };
            let original = fs::read(&changed).unwrap();
            fs::write(
                &changed,
                if key_change {
                    hex(&[82; 32]).into_bytes()
                } else {
                    b"{}".to_vec()
                },
            )
            .unwrap();
            assert!(issuer.complete_service_challenge(&raw, &p).await.is_err());
            let stats = j.stats(&clock).await.unwrap();
            assert_eq!(stats.completed, 0);
            assert_eq!(stats.tombstones, 1);
            fs::write(&changed, original).unwrap();
            assert!(issuer.complete_service_challenge(&raw, &p).await.is_err());
        }
    }
}

#[tokio::test]
async fn completion_and_cache_retain_actual_locks_through_final_close_and_expiry() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        for cached in [false, true] {
            let f = Fixture::new(app, |_, _| {});
            let _time = TestTime::set(f.now);
            let w = f.wallet.source();
            let n = f.owner_source();
            let k = f.key_source();
            let d = journal_directory();
            let clock = PendingClock::new(f.now);
            let mut j = Journal::open(d.path(), Limits::default(), &clock)
                .await
                .unwrap();
            let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &j, 60).unwrap();
            let raw = request(app);
            let c = issuer
                .issue_pending_challenge(&raw)
                .await
                .unwrap()
                .challenge;
            let p = proof(&f, &c);
            if cached {
                issuer.complete_service_challenge(&raw, &p).await.unwrap();
            }
            let calls = Arc::new(AtomicUsize::new(0));
            let reached = Arc::clone(&calls);
            let wallet_path = f.wallet.path().to_path_buf();
            let native_lock = f.owner.path().join(".service-owner.lock");
            let key_lock = f.key.path().join(".service-issuer.lock");
            let deadline = c.claims.expires_at;
            j.after_close_for_test(move || {
                if reached.fetch_add(1,Ordering::SeqCst)==0 {return;}// untrusted inspection only
                let root=ServiceRoot::open(&wallet_path).unwrap();
                assert!(matches!(root.lock_exclusive(),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock));
                for path in [&native_lock,&key_lock] {
                    let file=fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
                    assert_eq!(unsafe{libc::flock(file.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)},-1);
                    assert_eq!(std::io::Error::last_os_error().kind(),std::io::ErrorKind::WouldBlock);
                }
                crate::service_wallet_source::TEST_NOW.with(|v|v.set(Some(deadline)));
            });
            let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &j, 60).unwrap();
            assert!(issuer.complete_service_challenge(&raw, &p).await.is_err());
            assert!(calls.load(Ordering::SeqCst) >= 2);
            // Read before stats prunes expired rows. The actual stored row must
            // already be rejected by the post-close guard under the OS lock.
            let mut connection = sqlx::SqliteConnection::connect(&format!(
                "sqlite://{}",
                d.path().join("service-challenges.sqlite3").display()
            ))
            .await
            .unwrap();
            let state: i64 = sqlx::query_scalar("SELECT state FROM service_challenges_v1")
                .fetch_one(&mut connection)
                .await
                .unwrap();
            assert_eq!(state, 2);
            connection.close().await.unwrap();
        }
    }
}

#[tokio::test]
async fn forged_completed_context_is_rejected_despite_valid_storage_checksums() {
    use super::resume_tests::UnauthenticatedStorageFixture;
    use crate::service_challenge_store::IssuanceTimes;
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let w = f.wallet.source();
        let n = f.owner_source();
        let k = f.key_source();
        let d = journal_directory();
        let clock = PendingClock::new(f.now);
        let j = Journal::open(d.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &j, 60).unwrap();
        let raw = request(app);
        let c = issuer
            .issue_pending_challenge(&raw)
            .await
            .unwrap()
            .challenge;
        let p = proof(&f, &c);
        let good = issuer.complete_service_challenge(&raw, &p).await.unwrap();
        let basis = j
            .retained_completion_basis(c.claims.challenge_id, &clock)
            .await
            .unwrap();
        for change in 0..4 {
            let mut bad: SignedVerifiedCallContext = bincode::deserialize(&good.context).unwrap();
            match change {
                0 => bad.signature[0] ^= 1,
                1 => bad.signer_key_id = "unknown".into(),
                2 => bad.context.subject.subject_id = "other-holder".into(),
                _ => bad.context.replay_scope = "session_opcode_nonce".into(),
            }
            if change >= 2 {
                bad.signature = SigningKey::from_bytes(&PUBLIC_SEED)
                    .sign(&bincode::serialize(&bad.context).unwrap())
                    .to_bytes()
                    .to_vec();
            }
            let bad = bincode::serialize(&bad).unwrap();
            let fake = journal_directory();
            let fake_j = Journal::open(fake.path(), Limits::default(), &clock)
                .await
                .unwrap();
            fake_j
                .persist_pending(
                    &c,
                    &basis.evidence,
                    &basis.lineage,
                    &mut UnauthenticatedStorageFixture,
                    &clock,
                )
                .await
                .unwrap();
            fake_j
                .complete(
                    c.claims.challenge_id,
                    &good.packet,
                    &bad,
                    IssuanceTimes {
                        holder_verified_at: good.holder_verified_at,
                        context_signed_at: good.signed_at,
                    },
                    &mut UnauthenticatedStorageFixture,
                    &clock,
                )
                .await
                .unwrap();
            let fake_issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &fake_j, 60).unwrap();
            assert!(fake_issuer
                .complete_service_challenge(&raw, &p)
                .await
                .is_err());
            assert_eq!(fake_j.stats(&clock).await.unwrap().tombstones, 1);
        }
    }
}

#[tokio::test]
async fn tightened_startup_window_rejects_and_retains_cache_tombstone() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let w = f.wallet.source();
        let n = f.owner_source();
        let k = f.key_source();
        let d = journal_directory();
        let clock = PendingClock::new(f.now);
        let j = Journal::open(d.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &j, 60).unwrap();
        let raw = request(app);
        let c = issuer
            .issue_pending_challenge(&raw)
            .await
            .unwrap()
            .challenge;
        let p = proof(&f, &c);
        issuer.complete_service_challenge(&raw, &p).await.unwrap();
        let strict = PendingIssuer::from_startup(&w, &n, f.pin, &k, &j, 1).unwrap();
        assert_eq!(
            strict
                .complete_service_challenge(&raw, &p)
                .await
                .unwrap_err(),
            PendingError::Invalid
        );
        assert_eq!(j.stats(&clock).await.unwrap().tombstones, 1);
        assert!(issuer.complete_service_challenge(&raw, &p).await.is_err());
    }
}

#[tokio::test]
async fn ambiguous_retained_requests_deny_completion_and_cached_delivery() {
    use super::resume_tests::UnauthenticatedStorageFixture;
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        for cached in [false, true] {
            let f = Fixture::new(app, |_, _| {});
            let _time = TestTime::set(f.now);
            let w = f.wallet.source();
            let n = f.owner_source();
            let k = f.key_source();
            let d = journal_directory();
            let clock = PendingClock::new(f.now);
            let j = Journal::open(d.path(), Limits::default(), &clock)
                .await
                .unwrap();
            let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &j, 60).unwrap();
            let raw = request(app);
            let c = issuer
                .issue_pending_challenge(&raw)
                .await
                .unwrap()
                .challenge;
            let p = proof(&f, &c);
            if cached {
                issuer.complete_service_challenge(&raw, &p).await.unwrap();
            }
            let basis = j
                .retained_completion_basis(c.claims.challenge_id, &clock)
                .await
                .unwrap();
            let mut duplicate = c.clone();
            duplicate.claims.challenge_id[0] ^= 1;
            duplicate.claims.session_id[0] ^= 1;
            duplicate.claims.nonce[0] ^= 1;
            j.persist_pending(
                &duplicate,
                &basis.evidence,
                &basis.lineage,
                &mut UnauthenticatedStorageFixture,
                &clock,
            )
            .await
            .unwrap();
            let before = j.stats(&clock).await.unwrap();
            assert_eq!(
                issuer
                    .complete_service_challenge(&raw, &p)
                    .await
                    .unwrap_err(),
                PendingError::Journal(JournalError::Conflict)
            );
            assert_eq!(j.stats(&clock).await.unwrap(), before);
        }
    }
}

#[tokio::test]
async fn cached_delivery_reopen_cannot_erase_durable_clock_rollback() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let w = f.wallet.source();
        let n = f.owner_source();
        let k = f.key_source();
        let d = journal_directory();
        let clock = PendingClock::new(f.now);
        let j = Journal::open(d.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &j, 60).unwrap();
        let raw = request(app);
        let c = issuer
            .issue_pending_challenge(&raw)
            .await
            .unwrap()
            .challenge;
        let p = proof(&f, &c);
        let out = issuer.complete_service_challenge(&raw, &p).await.unwrap();
        crate::service_wallet_source::TEST_NOW.with(|v| v.set(Some(f.now + 2)));
        assert_eq!(
            issuer.complete_service_challenge(&raw, &p).await.unwrap(),
            out
        );
        drop(j);
        drop(w);
        drop(n);
        drop(k);
        crate::service_wallet_source::TEST_NOW.with(|v| v.set(Some(f.now + 1)));
        assert!(matches!(
            Journal::open(d.path(), Limits::default(), &PendingClock::new(0)).await,
            Err(JournalError::ClockRollback)
        ));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn exact_completed_delivery_survives_a_fresh_process() {
    const CHILD_ENV: &str = "SECS_COMPLETED_RECOVERY_PUBLIC_FIXTURE";
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
        let p: Vec<u8> = serde_json::from_value(cfg["proof"].clone()).unwrap();
        let completed = issuer.complete_service_challenge(&raw, &p).await.unwrap();
        assert_eq!(journal.stats(&clock).await.unwrap().completed, 1);
        let result = std::path::Path::new(cfg["result"].as_str().unwrap());
        fs::write(result.with_extension("packet"), completed.packet).unwrap();
        fs::write(result.with_extension("context"), completed.context).unwrap();
        return;
    }
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let dir = journal_directory();
        let w = f.wallet.source();
        let n = f.owner_source();
        let k = f.key_source();
        let clock = PendingClock::new(f.now);
        let j = Journal::open(dir.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &j, 60).unwrap();
        let raw = request(app);
        let c = issuer
            .issue_pending_challenge(&raw)
            .await
            .unwrap()
            .challenge;
        let p = proof(&f, &c);
        let original = issuer.complete_service_challenge(&raw, &p).await.unwrap();
        drop(j);
        drop(w);
        drop(n);
        drop(k);
        let helper = journal_directory();
        let cfg_path = helper.path().join("public-fixture.json");
        let result_path = helper.path().join("recovered-completion");
        let wallet_pin = String::from_utf8(f.wallet.source().test_startup_pin_bytes()).unwrap();
        fs::write(&cfg_path, canonical(&json!({
            "now": f.now+2, "wallet_root":f.wallet.path(), "wallet_pin":wallet_pin,
            "native_root":f.owner.path(), "native_generation":f.pin.generation(), "native_digest":f.pin.sha256(),
            "key_root":f.key.path(), "journal_root":dir.path(), "request":request(app),
            "proof":p, "result":result_path,
        }))).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "service_authority::pending_tests::completion_tests::exact_completed_delivery_survives_a_fresh_process", "--test-threads=1"])
            .env(CHILD_ENV, &cfg_path).stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("owned completed-delivery fixture child timed out");
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
            fs::read(result_path.with_extension("packet")).unwrap(),
            original.packet
        );
        assert_eq!(
            fs::read(result_path.with_extension("context")).unwrap(),
            original.context
        );
    }
}

#[path = "service_startup_tests.rs"]
mod startup_tests;
