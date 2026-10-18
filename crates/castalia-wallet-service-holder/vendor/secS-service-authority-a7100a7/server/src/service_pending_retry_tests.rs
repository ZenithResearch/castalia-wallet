//! Exact-request retry uses real Native owners and disposable journal files.
//! Synthetic storage-only mutations below are never accepted as authority.
use super::resume_tests::{first_challenge, UnauthenticatedStorageFixture};
use super::*;
use crate::service_challenge_store::{IssuanceTimes, PendingInsertError};

#[tokio::test(flavor = "current_thread")]
async fn lost_response_retry_reopens_exact_challenge_without_new_quota() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let dir = journal_directory();
        let original = first_challenge(&f, dir.path(), app).await;
        crate::service_wallet_source::TEST_NOW.with(|t| t.set(Some(f.now + 2)));
        let wallet = f.wallet.source();
        let native = f.owner_source();
        let key = f.key_source();
        let clock = PendingClock::new(f.now + 2);
        let journal = Journal::open(
            dir.path(),
            Limits {
                pending_global: 1,
                pending_per_holder: 1,
                ..Limits::default()
            },
            &clock,
        )
        .await
        .unwrap();
        let issuer =
            PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &journal, 60).unwrap();
        let before = journal.stats(&clock).await.unwrap();
        for _ in 0..2 {
            let retried = issuer.issue_pending_challenge(&request(app)).await.unwrap();
            assert_eq!(
                retried.challenge.encode_inner().unwrap(),
                original.encode_inner().unwrap()
            );
        }
        assert_eq!(journal.stats(&clock).await.unwrap(), before);
        let mut distinct = request(app);
        distinct.push(b' ');
        assert_eq!(
            issuer.issue_pending_challenge(&distinct).await.unwrap_err(),
            PendingError::Journal(JournalError::Capacity)
        );
        assert_eq!(journal.stats(&clock).await.unwrap(), before);
    }
}

fn fixture_packet(c: &UntrustedSignedServiceChallenge) -> Vec<u8> {
    let proof = libsec_core::service_holder_proof::UntrustedServiceHolderProof {
        claims: c.claims.clone(),
        issuer_signature: c.issuer_signature,
        holder_policy_digest: [15; 32],
        holder_signature: [0; 64],
    }
    .encode()
    .unwrap();
    bincode::serialize(&libsec_core::ZenithPacket {
        session_id: c.claims.session_id,
        nonce: c.claims.nonce,
        opcode: c.claims.opcode,
        proof,
        claim_ttl: c.claims.ttl_seconds,
        encrypted_payload: c.request_bytes.clone(),
        mac: [0; 16],
    })
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn completed_rejected_and_ambiguous_retained_requests_never_reissue() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        for state in ["completed", "rejected", "ambiguous"] {
            let f = Fixture::new(app, |_, _| {});
            let _time = TestTime::set(f.now);
            let dir = journal_directory();
            let original = first_challenge(&f, dir.path(), app).await;
            let clock = PendingClock::new(f.now);
            let journal = Journal::open(dir.path(), Limits::default(), &clock)
                .await
                .unwrap();
            if state == "completed" {
                journal
                    .complete(
                        original.claims.challenge_id,
                        &fixture_packet(&original),
                        b"UNAUTHENTICATED storage fixture",
                        IssuanceTimes {
                            holder_verified_at: f.now,
                            context_signed_at: f.now,
                        },
                        &mut UnauthenticatedStorageFixture,
                        &clock,
                    )
                    .await
                    .unwrap();
            } else if state == "rejected" {
                journal
                    .reject(original.claims.challenge_id, &clock)
                    .await
                    .unwrap();
            } else {
                let retained = journal
                    .retained_pending(original.claims.challenge_id, &clock)
                    .await
                    .unwrap();
                let mut other = original.clone();
                other.claims.challenge_id[0] ^= 1;
                other.claims.session_id[0] ^= 1;
                other.claims.nonce[0] ^= 1;
                // Simulate two legacy retained rows: the old generic storage port
                // intentionally still permits this. Native must not pick either.
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
            }
            let before = journal.stats(&clock).await.unwrap();
            let wallet = f.wallet.source();
            let native = f.owner_source();
            let key = f.key_source();
            let issuer =
                PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &journal, 60).unwrap();
            assert_eq!(
                issuer
                    .issue_pending_challenge(&request(app))
                    .await
                    .unwrap_err(),
                PendingError::Journal(if state == "ambiguous" {
                    JournalError::Conflict
                } else {
                    JournalError::Rejected
                })
            );
            assert_eq!(journal.stats(&clock).await.unwrap(), before);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn atomic_same_request_conflict_is_distinct_from_random_identity_collision() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let dir = journal_directory();
        let original = first_challenge(&f, dir.path(), app).await;
        let clock = PendingClock::new(f.now);
        let journal = Journal::open(dir.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let retained = journal
            .retained_pending(original.claims.challenge_id, &clock)
            .await
            .unwrap();
        let mut second = original.clone();
        second.claims.challenge_id[0] ^= 1;
        second.claims.session_id[0] ^= 1;
        second.claims.nonce[0] ^= 1;
        assert_eq!(
            journal
                .persist_pending_once(
                    &second,
                    &retained.evidence,
                    &retained.lineage,
                    &mut UnauthenticatedStorageFixture,
                    &clock
                )
                .await
                .unwrap_err(),
            PendingInsertError::RetainedRequest
        );
        // Same session/nonce, different exact request: generic conflict cannot
        // authorize fallback to an unrelated retained challenge.
        let mut collision = second;
        collision.claims.session_id = original.claims.session_id;
        collision.request_bytes.push(b' ');
        collision.claims.request_length = collision.request_bytes.len() as u64;
        collision.claims.request_sha256 = hash(&collision.request_bytes);
        assert_eq!(
            journal
                .persist_pending_once(
                    &collision,
                    &retained.evidence,
                    &retained.lineage,
                    &mut UnauthenticatedStorageFixture,
                    &clock
                )
                .await
                .unwrap_err(),
            PendingInsertError::Journal(JournalError::Conflict)
        );
        let stats = journal.stats(&clock).await.unwrap();
        assert_eq!((stats.rows, stats.pending), (1, 1));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn two_no_match_issuers_keep_one_atomic_winner_then_resume_exact_bytes() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let dir = journal_directory();
        let clock = PendingClock::new(f.now);
        let journal = Journal::open(dir.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let wallet = f.wallet.source();
        let native = f.owner_source();
        let key = f.key_source();
        let first =
            PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &journal, 60).unwrap();
        let second =
            PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &journal, 60).unwrap();
        let raw = request(app);
        // Deterministically interleave two outstanding operations: both finish
        // the no-match lookup before either starts its issuance transaction.
        assert!(first.retained_request_id(&raw).await.unwrap().is_none());
        assert!(second.retained_request_id(&raw).await.unwrap().is_none());
        let winner = first.issue_new_pending_challenge(&raw).await.unwrap();
        let loser = second.issue_new_pending_challenge(&raw).await.unwrap_err();
        assert_eq!(loser, PendingError::RetainedRequest);
        let recovered = second.resume_matching_request(&raw).await.unwrap();
        assert_eq!(
            winner.challenge.encode_inner().unwrap(),
            recovered.challenge.encode_inner().unwrap()
        );
        assert_eq!(journal.stats(&clock).await.unwrap().rows, 1);
        // A lookup ID is not a reservation. Legacy writes can introduce another
        // same-request row; the final locked recovery must then reject it too.
        let retained = journal
            .retained_pending(winner.challenge.claims.challenge_id, &clock)
            .await
            .unwrap();
        let mut other = winner.challenge.clone();
        other.claims.challenge_id[0] ^= 1;
        other.claims.session_id[0] ^= 1;
        other.claims.nonce[0] ^= 1;
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
        assert_eq!(
            second
                .resume_pending_challenge(&raw, winner.challenge.claims.challenge_id)
                .await
                .unwrap_err(),
            PendingError::Journal(JournalError::Conflict)
        );
        assert_eq!(journal.stats(&clock).await.unwrap().rows, 2);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn expired_retention_allows_new_invitation_but_rollback_never_does() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let dir = journal_directory();
        let original = first_challenge(&f, dir.path(), app).await;
        let wallet = f.wallet.source();
        let native = f.owner_source();
        let key = f.key_source();
        let clock = PendingClock::new(f.now);
        let journal = Journal::open(dir.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let issuer =
            PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &journal, 60).unwrap();
        crate::service_wallet_source::TEST_NOW.with(|t| t.set(Some(f.now + 60)));
        let next = issuer.issue_pending_challenge(&request(app)).await.unwrap();
        assert_eq!(next.challenge.claims.issued_at, f.now + 60);
        assert_eq!(next.challenge.claims.expires_at, f.now + 120);
        assert_ne!(
            next.challenge.claims.challenge_id,
            original.claims.challenge_id
        );
        assert_eq!(journal.stats(&clock).await.unwrap().rows, 1);
        crate::service_wallet_source::TEST_NOW.with(|t| t.set(Some(f.now + 59)));
        assert_eq!(
            issuer
                .issue_pending_challenge(&request(app))
                .await
                .unwrap_err(),
            // The already-observed current source catches this rollback before
            // another journal lookup can begin.
            PendingError::Source(crate::service_wallet_source::SourceError::Clock)
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rollback_at_conflict_close_cannot_select_fresh_clock_recovery() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let dir = journal_directory();
        let original = first_challenge(&f, dir.path(), app).await;
        let clock = PendingClock::new(f.now);
        let mut journal = Journal::open(dir.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let reached = Arc::clone(&calls);
        let rollback = f.now - 1;
        journal.after_close_for_test(move || {
            reached.fetch_add(1, Ordering::SeqCst);
            crate::service_wallet_source::TEST_NOW.with(|t| t.set(Some(rollback)));
        });
        let wallet = f.wallet.source();
        let native = f.owner_source();
        let key = f.key_source();
        let issuer =
            PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &journal, 60).unwrap();
        // Deterministic second no-match issuer reaches atomic conflict after the
        // winner has committed. The ordinary close hook rolls back the OS-clock
        // fixture before a recoverable marker could select another phase.
        assert_eq!(
            issuer
                .issue_new_pending_challenge(&request(app))
                .await
                .unwrap_err(),
            PendingError::Journal(JournalError::Invalid)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        crate::service_wallet_source::TEST_NOW.with(|t| t.set(Some(f.now)));
        assert_eq!(journal.stats(&clock).await.unwrap().rows, 1);
        // A later separate call may retry normally with newly sampled sources.
        let clean = Journal::open(dir.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let retry = PendingIssuer::from_startup(&wallet, &native, f.pin, &key, &clean, 60).unwrap();
        assert_eq!(
            retry
                .issue_pending_challenge(&request(app))
                .await
                .unwrap()
                .challenge,
            original
        );
    }
}
