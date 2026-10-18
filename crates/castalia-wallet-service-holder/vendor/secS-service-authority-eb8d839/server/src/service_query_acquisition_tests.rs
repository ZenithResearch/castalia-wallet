//! Unexecuted test-first proposal. Disposable Native public fixtures/test clocks;
//! no receiver/actual Wallet/private-custody/installed qualification claim.
use super::*;
const READS: [&str; 8] = [
    "work.list",
    "events.list",
    "attempt.get",
    "output.get",
    "run.get",
    "artifact.get",
    "version.get",
    "receipt.get",
];
fn read_request(op: &str) -> Vec<u8> {
    let payload = match op {
        "work.list" => json!({"actor_id":"actor-1","limit":1}),
        "events.list" => json!({"after":0,"limit":1}),
        "attempt.get" | "output.get" => {
            json!({"run_id":"run-1","step_id":"step-1","attempt_id":"attempt-1"})
        }
        "run.get" => json!({"run_id":"run-1"}),
        "artifact.get" => json!({"content_hash":"00".repeat(32)}),
        "version.get" => json!({"process_version":"version-1"}),
        "receipt.get" => json!({"receipt_id":"receipt-1"}),
        "process.get" => json!({"process_id":"process-1"}),
        "effect.get" => json!({"effect_id":"effect-1"}),
        _ => panic!("unsupported test operation"),
    };
    canonical(&json!({"schema":"runtime.query.v1","operation":op,"payload":payload}))
}
fn query_fixture(op: &str) -> (Fixture, Vec<u8>) {
    let raw = read_request(op);
    let intent = secs_service_call_contract::ServiceIntent::parse(
        secs_service_call_contract::Application::Runtime,
        &raw,
    )
    .unwrap();
    let operation = intent.operation().to_owned();
    let resource = intent.resource().to_owned();
    let opcode = match op {
        "work.list" => 0x63,
        "events.list" => 0x64,
        "attempt.get" => 0x69,
        "output.get" => 0x67,
        "run.get" => 0x62,
        "artifact.get" => 0x65,
        "version.get" => 0x61,
        "receipt.get" => 0x66,
        _ => panic!("not a selected fixture"),
    };
    let f = Fixture::new(ServiceApplication::RuntimeV1, |p, _| {
        let mut descriptor = public_descriptor(ServiceApplication::RuntimeV1);
        descriptor.name = OperationName::new(&operation);
        descriptor.opcode = opcode;
        descriptor.handler_id = format!("fixture/{operation}");
        let fingerprint = descriptor
            .authorization_fingerprint()
            .trim_start_matches("descriptor:sha256:")
            .to_owned();
        p["descriptors"][0]["name"] = json!(operation);
        p["descriptors"][0]["opcode"] = json!(opcode);
        p["descriptors"][0]["handler_id"] = json!(descriptor.handler_id);
        for row in p["permissions"].as_array_mut().unwrap() {
            row["opcode"] = json!(opcode);
            row["operation"] = json!(operation);
            row["resource"] = json!({"kind":"exact","value":resource});
        }
        let d = &mut p["receiver_policy"]["descriptors"][0];
        d["operation"] = json!(operation);
        d["opcode"] = json!(opcode);
        d["handler_id"] = json!(descriptor.handler_id);
        d["fingerprint"] = json!(fingerprint);
        for row in p["receiver_policy"]["rules"].as_array_mut().unwrap() {
            row["operation"] = json!(operation);
            row["resource"] = json!(resource);
        }
    });
    (f, raw)
}

#[tokio::test(flavor = "current_thread")]
async fn query_acquisition_all_eight_identical_concurrent_and_sequential_reads_are_fresh() {
    for op in READS {
        let (f, raw) = query_fixture(op);
        let _time = TestTime::set(f.now);
        let d = journal_directory();
        let (_cfg, path) = configured_authority(&f, d.path());
        let authority = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        let first = UntrustedSignedServiceChallenge::decode_inner(
            &authority.acquire_query(&raw).await.unwrap(),
        )
        .unwrap();
        let second = UntrustedSignedServiceChallenge::decode_inner(
            &authority.acquire_query(&raw).await.unwrap(),
        )
        .unwrap();
        assert_ne!(first.claims.challenge_id, second.claims.challenge_id);
        assert_ne!(first.claims.session_id, second.claims.session_id);
        assert_ne!(first.claims.nonce, second.claims.nonce);
        assert_eq!(first.request_bytes, raw);
        assert_eq!(second.request_bytes, raw);
        let p = proof(&f, &first);
        let p2 = proof(&f, &second);
        let original = authority.complete_query(&raw, &p).await.unwrap();
        let out2 = authority.complete_query(&raw, &p2).await.unwrap();
        assert_eq!(authority.complete_query(&raw, &p).await.unwrap(), original);
        assert_ne!(original.packet, out2.packet);
        let signed: SignedVerifiedCallContext =
            bincode::deserialize(&original.signed_context).unwrap();
        SigningKey::from_bytes(&PUBLIC_SEED)
            .verifying_key()
            .verify_strict(
                &bincode::serialize(&signed.context).unwrap(),
                &ed25519_dalek::Signature::from_slice(&signed.signature).unwrap(),
            )
            .unwrap();
        assert_eq!(signed.context.packet_hash, hash(&original.packet));
        assert_eq!(
            signed.context.audience,
            ServiceApplication::RuntimeV1.audience()
        );
        assert_eq!(
            (signed.context.issued_at, signed.context.expires_at),
            (first.claims.issued_at, first.claims.expires_at)
        );
        drop(authority);
        let authority = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        assert_eq!(authority.complete_query(&raw, &p).await.unwrap(), original);
        let third = UntrustedSignedServiceChallenge::decode_inner(
            &authority.acquire_query(&raw).await.unwrap(),
        )
        .unwrap();
        assert_ne!(third.claims.challenge_id, first.claims.challenge_id);
        assert_ne!(third.claims.challenge_id, second.claims.challenge_id);
        assert_ne!(third.claims.session_id, first.claims.session_id);
        assert_ne!(third.claims.nonce, first.claims.nonce);
        authority
            .complete_query(&raw, &proof(&f, &third))
            .await
            .unwrap();
        let s = stats(d.path(), f.now).await;
        assert_eq!((s.rows, s.completed), (3, 3));
        // Request-only old APIs still reject ambiguous retained requests.
        assert_eq!(
            authority.issue(&raw).await.unwrap_err(),
            ServiceAuthorityError
        );
        assert_eq!(
            authority.resume(&raw).await.unwrap_err(),
            ServiceAuthorityError
        );
        assert_eq!(
            authority.complete(&raw, &p).await.unwrap_err(),
            ServiceAuthorityError
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn query_acquisition_denies_omitted_reads_commands_service_and_unbounded_input() {
    let (f, raw) = query_fixture("work.list");
    let _time = TestTime::set(f.now);
    let d = journal_directory();
    let (_cfg, path) = configured_authority(&f, d.path());
    let authority = ServiceAuthority::open_owner_configuration(&path)
        .await
        .unwrap();
    let c = UntrustedSignedServiceChallenge::decode_inner(
        &authority.acquire_query(&raw).await.unwrap(),
    )
    .unwrap();
    let p = proof(&f, &c);
    authority.complete_query(&raw, &p).await.unwrap();
    let service = canonical(
        &json!({"schema":"service.query.v1","request_id":"query-1","operation":"case.summary","resource":{"kind":"Case","id":"case-1"},"payload":{}}),
    );
    secs_service_call_contract::ServiceIntent::parse(
        secs_service_call_contract::Application::Service,
        &service,
    )
    .unwrap();
    for bad in [
        read_request("process.get"),
        read_request("effect.get"),
        request(ServiceApplication::RuntimeV1),
        request(ServiceApplication::ServiceV1),
        service,
        Vec::new(),
        vec![b'x'; 2_097_153],
        b"{invalid".to_vec(),
    ] {
        let before = stats(d.path(), f.now).await;
        assert_eq!(
            authority.acquire_query(&bad).await.unwrap_err(),
            ServiceAuthorityError
        );
        assert_eq!(
            authority.complete_query(&bad, &p).await.unwrap_err(),
            ServiceAuthorityError
        );
        assert_eq!(stats(d.path(), f.now).await, before);
    }
    assert!(authority.complete_query(&raw, &p).await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn query_acquisition_denies_runtime_read_on_actual_service_policy() {
    let f = Fixture::new(ServiceApplication::ServiceV1, |_, _| {});
    let _time = TestTime::set(f.now);
    let d = journal_directory();
    let (_cfg, path) = configured_authority(&f, d.path());
    let authority = ServiceAuthority::open_owner_configuration(&path)
        .await
        .unwrap();
    let own = request(ServiceApplication::ServiceV1);
    authority.issue(&own).await.unwrap();
    let before = stats(d.path(), f.now).await;
    assert_eq!(
        authority
            .acquire_query(&read_request("work.list"))
            .await
            .unwrap_err(),
        ServiceAuthorityError
    );
    assert_eq!(stats(d.path(), f.now).await, before);
    assert!(authority.resume(&own).await.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn query_completion_binds_exact_request_proof_and_challenge_id() {
    use libsec_core::service_holder_proof::UntrustedServiceHolderProof;
    for cached in [false, true] {
        let (f, raw) = query_fixture("events.list");
        let _time = TestTime::set(f.now);
        let d = journal_directory();
        let (_cfg, path) = configured_authority(&f, d.path());
        let authority = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        let c = UntrustedSignedServiceChallenge::decode_inner(
            &authority.acquire_query(&raw).await.unwrap(),
        )
        .unwrap();
        let p = proof(&f, &c);
        if cached {
            authority.complete_query(&raw, &p).await.unwrap();
        }
        for change in 0..6 {
            let mut bad = UntrustedServiceHolderProof::decode(&p).unwrap();
            let mut changed = raw.clone();
            match change {
                0 => bad.holder_signature[0] ^= 1,
                1 => bad.holder_policy_digest[0] ^= 1,
                2 => bad.issuer_signature[0] ^= 1,
                3 => bad.claims.challenge_id[0] ^= 1,
                4 => bad.claims.nonce[0] ^= 1,
                _ => changed.push(b' '),
            };
            let before = stats(d.path(), f.now).await;
            assert_eq!(
                authority
                    .complete_query(&changed, &bad.encode().unwrap())
                    .await
                    .unwrap_err(),
                ServiceAuthorityError
            );
            assert_eq!(stats(d.path(), f.now).await, before);
        }
        assert!(authority.complete_query(&raw, &p).await.is_ok());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn query_completion_and_new_acquisition_deny_changed_current_owners_or_revocation() {
    for cached in [false, true] {
        for change in ["native", "issuer", "revoked"] {
            let (f, raw) = query_fixture("work.list");
            let _time = TestTime::set(f.now);
            let d = journal_directory();
            let (_cfg, path) = configured_authority(&f, d.path());
            let authority = ServiceAuthority::open_owner_configuration(&path)
                .await
                .unwrap();
            let c = UntrustedSignedServiceChallenge::decode_inner(
                &authority.acquire_query(&raw).await.unwrap(),
            )
            .unwrap();
            let p = proof(&f, &c);
            if cached {
                authority.complete_query(&raw, &p).await.unwrap();
            }
            match change {
                "native" => private_rewrite(&f.owner.path().join("owner-generation.json"), b"{}"),
                "issuer" => private_rewrite(
                    &f.key.path().join("issuer.seed.hex"),
                    hex(&[82; 32]).as_bytes(),
                ),
                _ => {
                    let old = f.wallet.observed();
                    let mut state: Value = serde_json::from_slice(&old.state_raw).unwrap();
                    state["state_revision"] = json!(3);
                    state["state"] = json!("revoked");
                    state["published_at"] = json!(f.now);
                    state["revoked_at"] = json!(f.now);
                    state["owner_input_sha256"] = Value::Null;
                    state["previous_state_sha256"] = json!(hex(&hash(&old.state_raw)));
                    let root = ServiceRoot::open(f.wallet.path()).unwrap();
                    let mut lease = root.lock_exclusive().unwrap();
                    f.wallet.publish(&mut lease, &state, None, true);
                    lease.publish_clock(&canonical(&json!({"schema":"castalia.wallet-service-custody-clock.v1","store_id":state["store_id"],"observed_at":f.now})),true).unwrap();
                }
            }
            assert_eq!(
                authority.complete_query(&raw, &p).await.unwrap_err(),
                ServiceAuthorityError
            );
            assert_eq!(
                authority.acquire_query(&raw).await.unwrap_err(),
                ServiceAuthorityError
            );
            assert_eq!(stats(d.path(), f.now).await.rows, 1);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn query_completion_original_expiry_does_not_implicitly_acquire_again() {
    for cached in [false, true] {
        let (f, raw) = query_fixture("events.list");
        let _time = TestTime::set(f.now);
        let d = journal_directory();
        let (_cfg, path) = configured_authority(&f, d.path());
        let authority = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        let c = UntrustedSignedServiceChallenge::decode_inner(
            &authority.acquire_query(&raw).await.unwrap(),
        )
        .unwrap();
        let p = proof(&f, &c);
        if cached {
            authority.complete_query(&raw, &p).await.unwrap();
        }
        crate::service_wallet_source::TEST_NOW.with(|v| v.set(Some(c.claims.expires_at)));
        assert_eq!(
            authority.complete_query(&raw, &p).await.unwrap_err(),
            ServiceAuthorityError
        );
        assert_eq!(
            authority.resume(&raw).await.unwrap_err(),
            ServiceAuthorityError
        );
        assert_eq!(stats(d.path(), c.claims.expires_at).await.rows, 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn query_acquisition_capacity_denies_without_recovering_existing_read() {
    let (f, raw) = query_fixture("work.list");
    let _time = TestTime::set(f.now);
    let w = f.wallet.source();
    let n = f.owner_source();
    let k = f.key_source();
    let d = journal_directory();
    let clock = PendingClock::new(f.now);
    let journal = Journal::open(
        d.path(),
        Limits {
            pending_per_holder: 1,
            ..Limits::default()
        },
        &clock,
    )
    .await
    .unwrap();
    let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &journal, 60).unwrap();
    let first = issuer
        .acquire_query_challenge(&raw)
        .await
        .unwrap()
        .challenge;
    let before = journal.stats(&clock).await.unwrap();
    let retained = journal
        .retained_pending(first.claims.challenge_id, &clock)
        .await
        .unwrap();
    assert_eq!(
        journal
            .persist_pending_fresh(
                &first,
                &retained.evidence,
                &retained.lineage,
                &mut super::super::super::super::resume_tests::UnauthenticatedStorageFixture,
                &clock
            )
            .await
            .unwrap_err(),
        JournalError::Conflict
    );
    assert_eq!(
        issuer.acquire_query_challenge(&raw).await.unwrap_err(),
        PendingError::Journal(JournalError::Capacity)
    );
    assert_eq!(journal.stats(&clock).await.unwrap(), before);
    assert_eq!(
        issuer
            .issue_pending_challenge(&raw)
            .await
            .unwrap()
            .challenge,
        first
    );
}

#[tokio::test(flavor = "current_thread")]
async fn query_cached_final_stage_allows_other_read_ids_but_denies_pending_or_rejected_target() {
    use super::super::super::super::resume_tests::UnauthenticatedStorageFixture;
    use sqlx::Row;
    for race in ["other_query", "pending_target", "tombstone_target"] {
        let (f, raw) = query_fixture("work.list");
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
        let c = issuer
            .acquire_query_challenge(&raw)
            .await
            .unwrap()
            .challenge;
        let p = proof(&f, &c);
        let original = issuer.complete_query_challenge(&raw, &p).await.unwrap();
        let basis = journal
            .retained_completion_basis_by_id(c.claims.challenge_id, &clock)
            .await
            .unwrap();
        let window = OriginalServiceWindow::new(c.claims.issued_at, c.claims.expires_at).unwrap();
        let entered = std::cell::Cell::new(false);
        assert_eq!(
            issuer
                .complete_retained_scoped_challenge(
                    &raw,
                    &p,
                    &basis,
                    window,
                    CompletionAdmission {
                        scope: ExchangeScope::RuntimeRead,
                        clock: &clock,
                        journal_entered: &entered
                    }
                )
                .await
                .unwrap(),
            original
        );
        assert!(entered.get());
        match race {
            "other_query" => {
                let other = issuer.acquire_query_challenge(&raw).await.unwrap();
                assert_ne!(other.challenge.claims.challenge_id, c.claims.challenge_id);
            }
            "tombstone_target" => journal.reject(c.claims.challenge_id, &clock).await.unwrap(),
            _ => {
                let pd = journal_directory();
                let pj = Journal::open(pd.path(), Limits::default(), &clock)
                    .await
                    .unwrap();
                pj.persist_pending(
                    &c,
                    &basis.evidence,
                    &basis.lineage,
                    &mut UnauthenticatedStorageFixture,
                    &clock,
                )
                .await
                .unwrap();
                let mut source = sqlx::SqliteConnection::connect(&format!(
                    "sqlite://{}",
                    pd.path().join("service-challenges.sqlite3").display()
                ))
                .await
                .unwrap();
                let row=sqlx::query("SELECT state,accounted,request_bytes,record,digest FROM service_challenges_v1 WHERE id=?").bind(c.claims.challenge_id.as_slice()).fetch_one(&mut source).await.unwrap();
                assert_eq!(row.get::<i64, _>("state"), 0);
                let values = (
                    row.get::<i64, _>("state"),
                    row.get::<i64, _>("accounted"),
                    row.get::<i64, _>("request_bytes"),
                    row.get::<Vec<u8>, _>("record"),
                    row.get::<Vec<u8>, _>("digest"),
                );
                source.close().await.unwrap();
                let mut target = sqlx::SqliteConnection::connect(&format!(
                    "sqlite://{}",
                    d.path().join("service-challenges.sqlite3").display()
                ))
                .await
                .unwrap();
                assert_eq!(sqlx::query("UPDATE service_challenges_v1 SET state=?,accounted=?,request_bytes=?,record=?,digest=? WHERE id=? AND state=1").bind(values.0).bind(values.1).bind(values.2).bind(values.3).bind(values.4).bind(c.claims.challenge_id.as_slice()).execute(&mut target).await.unwrap().rows_affected(),1);
                target.close().await.unwrap();
                assert_eq!(
                    journal
                        .retained_pending(c.claims.challenge_id, &clock)
                        .await
                        .unwrap()
                        .challenge,
                    c
                );
            }
        }
        let rows = retained_resume_race_rows(d.path()).await;
        let before = journal.stats(&clock).await.unwrap();
        let entered = std::cell::Cell::new(false);
        let result = issuer
            .complete_retained_scoped_challenge(
                &raw,
                &p,
                &basis,
                window,
                CompletionAdmission {
                    scope: ExchangeScope::RuntimeRead,
                    clock: &clock,
                    journal_entered: &entered,
                },
            )
            .await;
        assert!(entered.get());
        if race == "other_query" {
            assert_eq!(result.unwrap(), original);
        } else {
            assert_eq!(
                result.unwrap_err(),
                PendingError::Journal(JournalError::Rejected)
            );
        }
        assert_eq!(retained_resume_race_rows(d.path()).await, rows);
        assert_eq!(journal.stats(&clock).await.unwrap(), before);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn query_completion_accepts_eligible_old_issue_rows_but_never_weakens_old_ambiguity_guards() {
    for op in READS {
        let (f, raw) = query_fixture(op);
        let _time = TestTime::set(f.now);
        let d = journal_directory();
        let (_cfg, path) = configured_authority(&f, d.path());
        let authority = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        let legacy = authority.issue(&raw).await.unwrap();
        assert_eq!(pending(authority.resume(&raw).await.unwrap()), legacy);
        let c = UntrustedSignedServiceChallenge::decode_inner(&legacy).unwrap();
        let p = proof(&f, &c);
        let original = authority.complete_query(&raw, &p).await.unwrap();
        assert_eq!(authority.complete(&raw, &p).await.unwrap(), original);
        assert_eq!(completed(authority.resume(&raw).await.unwrap()), original);
        let other = UntrustedSignedServiceChallenge::decode_inner(
            &authority.acquire_query(&raw).await.unwrap(),
        )
        .unwrap();
        assert_ne!(other.claims.challenge_id, c.claims.challenge_id);
        assert_eq!(
            authority.issue(&raw).await.unwrap_err(),
            ServiceAuthorityError
        );
        assert_eq!(
            authority.complete(&raw, &p).await.unwrap_err(),
            ServiceAuthorityError
        );
        assert_eq!(
            authority.resume(&raw).await.unwrap_err(),
            ServiceAuthorityError
        );
        assert_eq!(authority.complete_query(&raw, &p).await.unwrap(), original);
        authority
            .complete_query(&raw, &proof(&f, &other))
            .await
            .unwrap();
        let count = stats(d.path(), f.now).await;
        assert_eq!((count.rows, count.completed), (2, 2));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn query_completion_final_close_rechecks_current_owners_and_exclusive_expiry() {
    for cached in [false, true] {
        let (f, raw) = query_fixture("work.list");
        let _time = TestTime::set(f.now);
        let w = f.wallet.source();
        let n = f.owner_source();
        let k = f.key_source();
        let d = journal_directory();
        let clock = PendingClock::new(f.now);
        let mut journal = Journal::open(d.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let c = {
            let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &journal, 60).unwrap();
            let c = issuer
                .acquire_query_challenge(&raw)
                .await
                .unwrap()
                .challenge;
            if cached {
                issuer
                    .complete_query_challenge(&raw, &proof(&f, &c))
                    .await
                    .unwrap();
            }
            c
        };
        let reached = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&reached);
        let wallet = f.wallet.path().to_path_buf();
        let native = f.owner.path().join(".service-owner.lock");
        let key = f.key.path().join(".service-issuer.lock");
        let deadline = c.claims.expires_at;
        journal.after_close_for_test(move || {
            let root = ServiceRoot::open(&wallet).unwrap();
            match root.lock_exclusive() {
                Ok(_) => return,
                Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
            }
            observed.fetch_add(1, Ordering::SeqCst);
            for path in [&native, &key] {
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
            .complete_query_challenge(&raw, &proof(&f, &c))
            .await
            .is_err());
        assert!(reached.load(Ordering::SeqCst) >= 1);
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
