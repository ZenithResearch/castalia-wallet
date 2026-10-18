//! Real SQLite accounting controls with codec-valid untrusted tombstone rows.
//! These rows prove storage/replay retention, not issuer authentication.
use super::*;
struct At(u64);
impl Clock for At {
    fn now(&self) -> u64 {
        self.0
    }
}
fn directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}
fn row(n: u64) -> Record {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&n.to_be_bytes());
    let mut session = [0u8; 16];
    session[..8].copy_from_slice(&n.to_be_bytes());
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&n.to_be_bytes());
    let lineage = b"retained-public-storage-fixture".to_vec();
    Record {
        version: 1,
        state: TOMBSTONE,
        id,
        holder: "stable-holder".into(),
        session,
        nonce,
        issued: 100,
        expires: 160,
        request_length: 1,
        signed_at: 100,
        holder_verified_at: 100,
        request_digest: hash(b"x"),
        challenge_digest: [2; 32],
        metadata_digest: [0; 32],
        evidence_digest: [0; 32],
        lineage_digest: hash(&lineage),
        packet_digest: [0; 32],
        proof_digest: [0; 32],
        context_digest: [0; 32],
        metadata: vec![],
        body: vec![],
        context: vec![],
        evidence: vec![],
        lineage,
    }
}
#[test]
fn row_profile_opt_in_preserves_defaults_bytes_pending_and_absolute_512_hard_ceiling() {
    let legacy = Limits::default();
    assert_eq!((legacy.rows_per_holder, legacy.rows_global), (32, 256));
    assert_eq!(
        Limits {
            rows_per_holder: 33,
            ..Limits::default()
        }
        .validate(),
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
    let pilot = Limits::for_owner_capacity(RowCapacity::LocalReviewPilot512);
    assert_eq!((pilot.rows_per_holder, pilot.rows_global), (512, 512));
    assert_eq!(pilot.validate(), Ok(()));
    assert_eq!((pilot.pending_per_holder, pilot.pending_global), (8, 64));
    assert_eq!(
        (
            pilot.bytes_per_holder,
            pilot.bytes_global,
            pilot.request_bytes_global,
            pilot.physical_bytes
        ),
        (8 << 20, 32 << 20, 16 << 20, 64 << 20)
    );
    assert_eq!(
        Limits {
            rows_per_holder: 513,
            ..pilot.clone()
        }
        .validate(),
        Err(JournalError::Invalid)
    );
    assert_eq!(
        Limits {
            rows_global: 513,
            ..pilot.clone()
        }
        .validate(),
        Err(JournalError::Invalid)
    );
    assert_eq!(
        Limits {
            bytes_per_holder: (8 << 20) + 1,
            ..pilot.clone()
        }
        .validate(),
        Err(JournalError::Invalid)
    );
    assert_eq!(
        Limits {
            pending_per_holder: 9,
            ..pilot.clone()
        }
        .validate(),
        Err(JournalError::Invalid)
    );
    assert_eq!(
        Limits {
            rows_per_holder: 17,
            rows_global: 23,
            ..pilot
        }
        .validate(),
        Ok(())
    );
}
#[tokio::test(flavor = "current_thread")]
async fn pilot_all_state_row_512_is_durable_513_denies_and_tightened_reopen_never_evicts() {
    let d = directory();
    let clock = At(100);
    let limits = Limits::for_owner_capacity(RowCapacity::LocalReviewPilot512);
    let j = Journal::open(d.path(), limits.clone(), &clock)
        .await
        .unwrap();
    let mut s = j.session(&clock).await.unwrap();
    // One real transaction; avoid512 process launches/crypto fixture calls.
    // Each capacity check audits CURRENT actual rows, not assumed counters.
    for n in 1..=512 {
        let r = row(n);
        r.validate().unwrap();
        s.capacity(&r).await.unwrap();
        s.put(&r).await.unwrap();
    }
    assert_eq!(s.capacity(&row(513)).await, Err(JournalError::Capacity));
    s.commit().await.unwrap();
    s.finish_error(&Ok::<(), JournalError>(()), &clock)
        .await
        .unwrap();
    assert_eq!(j.stats(&clock).await.unwrap().rows, 512);
    assert_eq!(j.stats(&clock).await.unwrap().tombstones, 512);
    assert_eq!(
        j.retained_resumable_request_id("stable-holder", b"x", &clock)
            .await
            .err(),
        Some(JournalError::Conflict)
    );
    // Rejected replay identities are all retained, including the last admitted row.
    assert_eq!(
        j.retained_completion_basis_by_id(row(512).id, &clock)
            .await
            .err(),
        Some(JournalError::Rejected)
    );
    drop(j);
    let j = Journal::open(d.path(), limits.clone(), &clock)
        .await
        .unwrap();
    assert_eq!(j.stats(&clock).await.unwrap().rows, 512);
    drop(j);
    assert!(Journal::open(d.path(), Limits::default(), &clock)
        .await
        .is_err());
    let tight = Limits {
        rows_per_holder: 511,
        ..limits.clone()
    };
    assert!(Journal::open(d.path(), tight, &clock).await.is_err());
    let j = Journal::open(d.path(), limits, &clock).await.unwrap();
    assert_eq!(j.stats(&clock).await.unwrap().rows, 512);
    // Normal exclusive expiry pruning remains unchanged; no unexpired eviction.
    assert_eq!(j.stats(&At(160)).await.unwrap().rows, 0);
    assert_eq!(
        j.stats(&At(159)).await.err(),
        Some(JournalError::ClockRollback)
    );
}
