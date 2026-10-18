//! Capacity is owner startup policy, not request authority or installed proof.
use super::*;
async fn raw_rows(path: &std::path::Path) -> i64 {
    let mut db = sqlx::SqliteConnection::connect(&format!(
        "sqlite://{}",
        path.join("service-challenges.sqlite3").display()
    ))
    .await
    .unwrap();
    let count = sqlx::query_scalar("SELECT count(*) FROM service_challenges_v1")
        .fetch_one(&mut db)
        .await
        .unwrap();
    db.close().await.unwrap();
    count
}

fn capacity_configuration(
    f: &Fixture,
    journal: &std::path::Path,
    pilot: bool,
) -> (tempfile::TempDir, std::path::PathBuf) {
    let cfg = journal_directory();
    let path = cfg.path().join("authority.json");
    let mut v = configuration(f, journal);
    if pilot {
        v["journal_capacity"] = json!("local_review_pilot_512");
    }
    private_file(&path, &canonical(&v));
    (cfg, path)
}
async fn fill_completed(
    authority: &ServiceAuthority,
    f: &Fixture,
    raw: &[u8],
    count: usize,
) -> (Vec<u8>, crate::ServiceCompletion) {
    let mut first = None;
    for _ in 0..count {
        let c = UntrustedSignedServiceChallenge::decode_inner(
            &authority.acquire_query(raw).await.unwrap(),
        )
        .unwrap();
        let p = proof(f, &c);
        let out = authority.complete_query(raw, &p).await.unwrap();
        if first.is_none() {
            first = Some((p, out));
        }
    }
    first.unwrap()
}
#[tokio::test(flavor = "current_thread")]
async fn journal_capacity_legacy_default_still_denies_query_33_without_evicting_rows() {
    let (f, raw) = query_fixture("run.get");
    let _time = TestTime::set(f.now);
    let d = journal_directory();
    let (_cfg, path) = capacity_configuration(&f, d.path(), false);
    let authority = ServiceAuthority::open_owner_configuration(&path)
        .await
        .unwrap();
    let (proof, first) = fill_completed(&authority, &f, &raw, 32).await;
    assert_eq!(stats(d.path(), f.now).await.rows, 32);
    assert_eq!(
        authority.acquire_query(&raw).await.unwrap_err(),
        ServiceAuthorityError
    );
    assert_eq!(stats(d.path(), f.now).await.rows, 32);
    assert_eq!(authority.complete_query(&raw, &proof).await.unwrap(), first);
}
#[tokio::test(flavor = "current_thread")]
async fn journal_capacity_explicit_pilot_survives_33_reopen_exact_retry_and_legacy_ambiguity() {
    let (f, raw) = query_fixture("run.get");
    let _time = TestTime::set(f.now);
    let d = journal_directory();
    let (_cfg, path) = capacity_configuration(&f, d.path(), true);
    let authority = ServiceAuthority::open_owner_configuration(&path)
        .await
        .unwrap();
    let (proof, first) = fill_completed(&authority, &f, &raw, 33).await;
    assert_eq!(raw_rows(d.path()).await, 33);
    drop(authority);
    let authority = ServiceAuthority::open_owner_configuration(&path)
        .await
        .unwrap();
    assert_eq!(authority.complete_query(&raw, &proof).await.unwrap(), first);
    // No request-unique API is widened after duplicate query acquisitions.
    assert_eq!(
        authority.issue(&raw).await.unwrap_err(),
        ServiceAuthorityError
    );
    assert_eq!(
        authority.resume(&raw).await.unwrap_err(),
        ServiceAuthorityError
    );
    assert_eq!(
        authority.complete(&raw, &proof).await.unwrap_err(),
        ServiceAuthorityError
    );
    let signed: SignedVerifiedCallContext = bincode::deserialize(&first.signed_context).unwrap();
    assert_eq!(signed.context.issued_at, f.now);
    assert_eq!(signed.context.expires_at, f.now + 60);
    // A separate legacy config selecting this same retained journal must deny;
    // it must not evict the unexpired opt-in rows to fit its tighter policy.
    let (_legacy_cfg, legacy_path) = capacity_configuration(&f, d.path(), false);
    assert!(ServiceAuthority::open_owner_configuration(&legacy_path)
        .await
        .is_err());
    assert_eq!(raw_rows(d.path()).await, 33);
    assert_eq!(authority.complete_query(&raw, &proof).await.unwrap(), first);
}
#[tokio::test(flavor = "current_thread")]
async fn journal_capacity_unknown_null_and_duplicate_profiles_deny_before_journal_creation() {
    let (f, _) = query_fixture("run.get");
    let _time = TestTime::set(f.now);
    for mode in ["unknown", "null", "duplicate"] {
        let d = journal_directory();
        let cfg = journal_directory();
        let path = cfg.path().join("authority.json");
        let mut v = configuration(&f, d.path());
        v["journal_capacity"] = if mode == "null" {
            Value::Null
        } else {
            json!("unbounded")
        };
        let mut raw = canonical(&v);
        if mode == "duplicate" {
            raw.pop();
            raw.extend_from_slice(b",\"journal_capacity\":\"local_review_pilot_512\"}");
        }
        private_file(&path, &raw);
        assert!(ServiceAuthority::open_owner_configuration(&path)
            .await
            .is_err());
        assert!(!d.path().join("service-challenges.sqlite3").exists());
    }
}
