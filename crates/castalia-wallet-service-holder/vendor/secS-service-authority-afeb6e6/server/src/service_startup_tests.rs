//! Public startup facade controls over disposable actual owner roots.
//! Public fixture keys only; no live identity or installed admission.
use super::*;
use crate::ServiceAuthority;
use std::os::unix::fs::MetadataExt;
fn configuration(f: &Fixture, journal: &std::path::Path) -> Value {
    json!({"schema":"secs.service-authority-configuration.v1",
        "wallet_root":f.wallet.path(),"wallet_observation_pin":serde_json::from_slice::<Value>(&f.wallet.source().test_startup_pin_bytes()).unwrap(),
        "native_root":f.owner.path(),"native_generation":f.pin.generation(),"native_sha256":hex(&f.pin.sha256()),
        "issuer_root":f.key.path(),"issuer_node_id":"node:ni03:public-fixture","issuer_key_id":"issuer:ni03:public-fixture",
        "issuer_public_key_hex":hex(SigningKey::from_bytes(&PUBLIC_SEED).verifying_key().as_bytes()),
        "journal_root":journal,"maximum_ttl":60})
}
#[tokio::test(flavor = "current_thread")]
async fn public_owner_startup_issues_and_completes_both_application_requests() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::new(app, |_, _| {});
        let _time = TestTime::set(f.now);
        let d = journal_directory();
        let cfg = journal_directory();
        let path = cfg.path().join("authority.json");
        private_file(&path, &canonical(&configuration(&f, d.path())));
        let authority = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        let raw = request(app);
        let challenge =
            UntrustedSignedServiceChallenge::decode_inner(&authority.issue(&raw).await.unwrap())
                .unwrap();
        let p = proof(&f, &challenge);
        let completed = authority.complete(&raw, &p).await.unwrap();
        let signed: SignedVerifiedCallContext =
            bincode::deserialize(&completed.signed_context).unwrap();
        assert_eq!(signed.context.packet_hash, hash(&completed.packet));
        assert_eq!(signed.context.audience, app.audience());
        assert_eq!(signed.context.issued_at, challenge.claims.issued_at);
        assert_eq!(signed.context.expires_at, challenge.claims.expires_at);
        drop(authority);
        let authority = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        assert_eq!(authority.complete(&raw, &p).await.unwrap(), completed);
        let mut changed = raw;
        changed.push(b' ');
        assert!(authority.complete(&changed, &p).await.is_err());
    }
}
#[tokio::test(flavor = "current_thread")]
async fn startup_rejects_shared_duplicate_unknown_and_caller_clock_configuration() {
    let f = Fixture::new(ServiceApplication::RuntimeV1, |_, _| {});
    let _time = TestTime::set(f.now);
    let d = journal_directory();
    for change in [
        "shared",
        "unknown",
        "clock",
        "key_bytes",
        "ttl",
        "duplicate",
    ] {
        let cfg = journal_directory();
        let path = cfg.path().join("authority.json");
        let mut v = configuration(&f, d.path());
        match change {
            "unknown" => v["qualified"] = json!(true),
            "clock" => v["now_seconds"] = json!(f.now),
            "key_bytes" => v["seed"] = json!("not-a-key"),
            "ttl" => v["maximum_ttl"] = json!(61),
            _ => {}
        }
        let mut raw = canonical(&v);
        if change == "duplicate" {
            raw.pop();
            raw.extend_from_slice(b",\"schema\":\"secs.service-authority-configuration.v1\"}");
        }
        private_file(&path, &raw);
        if change == "shared" {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(
            ServiceAuthority::open_owner_configuration(&path)
                .await
                .is_err(),
            "accepted {change}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn journal_rejects_replaced_selected_root_before_call() {
    let f = Fixture::new(ServiceApplication::RuntimeV1, |_, _| {});
    let _time = TestTime::set(f.now);
    let base = journal_directory();
    let path = base.path().join("selected");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let clock = PendingClock::new(f.now);
    let journal = Journal::open(&path, Limits::default(), &clock)
        .await
        .unwrap();
    fs::rename(&path, base.path().join("retained")).unwrap();
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(journal.stats(&clock).await.is_err());
    assert_eq!(
        fs::read_dir(&path).unwrap().count(),
        0,
        "replacement root touched"
    );
}
#[tokio::test(flavor = "current_thread")]
async fn journal_rejects_root_or_lock_replacement_after_sqlite_close() {
    for replace_root in [true, false] {
        let f = Fixture::new(ServiceApplication::RuntimeV1, |_, _| {});
        let _time = TestTime::set(f.now);
        let base = journal_directory();
        let path = base.path().join("selected");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let clock = PendingClock::new(f.now);
        let mut journal = Journal::open(&path, Limits::default(), &clock)
            .await
            .unwrap();
        let w = f.wallet.source();
        let n = f.owner_source();
        let k = f.key_source();
        let c = PendingIssuer::from_startup(&w, &n, f.pin, &k, &journal, 60)
            .unwrap()
            .issue_pending_challenge(&request(ServiceApplication::RuntimeV1))
            .await
            .unwrap()
            .challenge;
        let p = proof(&f, &c);
        let selected = path.clone();
        let retained = base.path().join("retained");
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        journal.after_close_for_test(move || {
            if observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                if replace_root {
                    fs::rename(&selected, &retained).unwrap();
                    fs::create_dir(&selected).unwrap();
                    fs::set_permissions(&selected, fs::Permissions::from_mode(0o700)).unwrap();
                } else {
                    fs::rename(selected.join("journal.lock"), retained.clone()).unwrap();
                    private_file(&selected.join("journal.lock"), b"");
                }
            }
        });
        let issuer = PendingIssuer::from_startup(&w, &n, f.pin, &k, &journal, 60).unwrap();
        assert!(
            issuer
                .complete_service_challenge(&c.request_bytes, &p)
                .await
                .is_err(),
            "exported with replaced binding"
        );
        assert!(
            calls.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "final completion close not reached"
        );
        if replace_root {
            assert_eq!(
                fs::read_dir(&path).unwrap().count(),
                0,
                "replacement root touched"
            );
        }
    }
}
#[tokio::test(flavor = "current_thread")]
async fn journal_rejects_symlink_ancestor_before_creating_files() {
    let base = journal_directory();
    let target = base.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
    let child = target.join("child");
    fs::create_dir(&child).unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    let link = base.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(Journal::open(
        &link.join("child"),
        Limits::default(),
        &PendingClock::new(1)
    )
    .await
    .is_err());
    assert_eq!(fs::read_dir(&child).unwrap().count(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn startup_canonicalizes_unordered_nested_wallet_pin_without_feature_drift() {
    let f = Fixture::new(ServiceApplication::RuntimeV1, |_, _| {});
    let _time = TestTime::set(f.now);
    let d = journal_directory();
    let cfg = journal_directory();
    let v = configuration(&f, d.path());
    let original = String::from_utf8(canonical(&v["wallet_observation_pin"])).unwrap();
    let pairs = v["wallet_observation_pin"]
        .as_object()
        .unwrap()
        .iter()
        .rev()
        .map(|(k, v)| {
            format!(
                "{}:{}",
                serde_json::to_string(k).unwrap(),
                serde_json::to_string(v).unwrap()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let reordered = format!("{{{pairs}}}");
    assert_ne!(reordered, original);
    let raw = String::from_utf8(canonical(&v))
        .unwrap()
        .replace(&original, &reordered);
    let path = cfg.path().join("authority.json");
    private_file(&path, raw.as_bytes());
    let a = ServiceAuthority::open_owner_configuration(&path)
        .await
        .unwrap();
    a.issue(&request(ServiceApplication::RuntimeV1))
        .await
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn create_only_native_bootstrap_supplies_public_pins_and_real_issuer() {
    for app in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let key = journal_directory();
        let public = ServiceAuthority::create_issuer_key(key.path()).unwrap();
        let f = Fixture::new(app, |v, _| {
            v["issuers"][0]["public_key_hex"] = json!(hex(&public))
        });
        let _time = TestTime::set(f.now);
        let original_key = fs::read(key.path().join("issuer.seed.hex")).unwrap();
        assert!(ServiceAuthority::create_issuer_key(key.path()).is_err());
        assert!(fs::read(key.path().join("issuer.seed.hex")).unwrap() == original_key);
        let native = journal_directory();
        let wallet = f.wallet.source();
        let mut bundle: Value = serde_json::from_slice(
            &fs::read(f.owner.path().join("owner-generation.json")).unwrap(),
        )
        .unwrap();
        bundle["generation"] = json!(1);
        let raw = canonical(&bundle);
        let pin = OwnerPublicationSource::create_initial(native.path(), &wallet, &raw).unwrap();
        assert_eq!(pin.sha256(), hash(&raw));
        assert_eq!(pin.generation(), 1);
        assert!(OwnerPublicationSource::create_initial(native.path(), &wallet, &raw).is_err());
        assert_eq!(
            fs::read(native.path().join("owner-generation.json")).unwrap(),
            raw
        );
        let d = journal_directory();
        let cfg = journal_directory();
        let path = cfg.path().join("authority.json");
        let mut c = configuration(&f, d.path());
        c["native_generation"] = json!(pin.generation());
        c["native_sha256"] = json!(hex(&pin.sha256()));
        c["native_root"] = json!(native.path());
        c["issuer_root"] = json!(key.path());
        c["issuer_public_key_hex"] = json!(hex(&public));
        private_file(&path, &canonical(&c));
        let a = ServiceAuthority::open_owner_configuration(&path)
            .await
            .unwrap();
        let raw = request(app);
        let challenge =
            UntrustedSignedServiceChallenge::decode_inner(&a.issue(&raw).await.unwrap()).unwrap();
        a.complete(&raw, &proof(&f, &challenge)).await.unwrap();
        for name in ["issuer.seed.hex", ".service-issuer.lock"] {
            let m = fs::symlink_metadata(key.path().join(name)).unwrap();
            assert_eq!(m.mode() & 0o777, 0o600);
            assert_eq!(m.nlink(), 1);
        }
    }
}
#[test]
fn native_bootstrap_rejects_other_wallet_generation_or_window_without_publication() {
    let f = Fixture::new(ServiceApplication::RuntimeV1, |_, _| {});
    let _time = TestTime::set(f.now);
    let wallet = f.wallet.source();
    let mut bundle: Value =
        serde_json::from_slice(&fs::read(f.owner.path().join("owner-generation.json")).unwrap())
            .unwrap();
    bundle["generation"] = json!(1);
    let raw = canonical(&bundle);
    for change in ["wallet", "generation", "expired"] {
        let d = journal_directory();
        let mut v: Value = serde_json::from_slice(&raw).unwrap();
        match change {
            "wallet" => v["wallet_current"]["state_revision"] = json!(999),
            "generation" => v["generation"] = json!(2),
            _ => v["valid_until"] = json!(f.now),
        }
        assert!(OwnerPublicationSource::create_initial(d.path(), &wallet, &canonical(&v)).is_err());
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
    }
}
