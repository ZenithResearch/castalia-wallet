//! Actual disposable public owner APIs; public binary fixtures are never executed.
use super::*;
use crate::renewal;
use crate::{renew_from_plan, resume_renewal_from_plan, RenewalError};

struct RenewalFixture {
    f: Fixture,
    old: Value,
    path: PathBuf,
    pin: String,
}
impl RenewalFixture {
    fn new() -> Self {
        let f = Fixture::new();
        let old = f.setup();
        Self::from_previous(f, old, None)
    }
    fn from_previous(f: Fixture, old: Value, previous: Option<PathBuf>) -> Self {
        let previous = previous.unwrap_or_else(|| f.root.join("authority/COMPLETE.json"));
        let n = now().unwrap();
        let public = f.value();
        let raw = canonical(
            &json!({"schema":"castalia.wallet-workspace-renewal.v1","workspace_root":f.root,
            "previous_complete":{"path":previous,"sha256":hash(&read(&previous,65536,0o600).unwrap())},
            "not_before":(n-1).max(old["not_before"].as_u64().unwrap()).to_string(),"not_after":(n+2400).max(old["not_after"].as_u64().unwrap()+1).to_string(),
            "wallet_command_sha256":public["wallet_command_sha256"],"verifier_sha256":public["verifier_sha256"]}),
        );
        let path = f.root.join("config").join(format!(
            "renew-{}.json",
            old["native_generation"].as_u64().unwrap() + 1
        ));
        write(&path, &raw).unwrap();
        Self {
            f,
            old,
            path,
            pin: hash(&raw),
        }
    }
    fn value(&self) -> Value {
        parse(&read(&self.path, 16384, 0o600).unwrap(), 16384).unwrap()
    }
    fn replace(&mut self, v: Value) {
        fs::remove_file(&self.path).unwrap();
        let raw = canonical(&v);
        write(&self.path, &raw).unwrap();
        self.pin = hash(&raw);
    }
    fn live_provider(mut self, actor_id: &str, run_id: &str) -> Self {
        let mut value = self.value();
        value["schema"] = json!("castalia.wallet-workspace-live-provider-authority.v1");
        value["actor_id"] = json!(actor_id);
        value["run_id"] = json!(run_id);
        self.replace(value);
        self
    }
    fn attempt(&self) -> PathBuf {
        self.f
            .root
            .join("authority/renewals")
            .join((self.old["native_generation"].as_u64().unwrap() + 1).to_string())
    }
    fn apply(&self) -> Value {
        renew_from_plan(&self.path, &self.pin).unwrap()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn live_provider_expansion_retains_identity_and_limits_actor_and_run() {
    let x = RenewalFixture::new().live_provider("actor", "run");
    let store = x.f.store(&x.old);
    let old_identity = store.public_identity().unwrap();
    let result = x.apply();
    assert_eq!(result["scope"], renewal::LIVE_PROVIDER_SCOPE);
    assert_eq!(result["actor_id"], "actor");
    assert_eq!(result["run_id"], "run");
    assert!(renewal::same_key(
        &old_identity,
        &store.public_identity().unwrap()
    ));

    let config = x.attempt().join("config");
    let policy: Value = parse(
        &read(&config.join("runtime-policy.json"), 65536, 0o600).unwrap(),
        65536,
    )
    .unwrap();
    assert_eq!(policy["permissions"].as_array().unwrap().len(), 22);
    assert_eq!(policy["descriptors"].as_array().unwrap().len(), 22);
    let permissions = policy["permissions"].as_array().unwrap();
    assert!(permissions
        .iter()
        .any(|row| row["operation"] == "runtime.actor.register.v1"
            && row["resource"] == "actors/actor"
            && row["resource_match"] == "exact"));
    assert!(permissions
        .iter()
        .any(|row| row["operation"] == "runtime.run.create.v1"
            && row["resource"] == "runs/run"
            && row["resource_match"] == "exact"));
    assert!(permissions
        .iter()
        .any(|row| row["operation"] == "runtime.executor.complete.v1"
            && row["resource"] == "runs/run/steps/"
            && row["resource_match"] == "prefix"));

    let authority = ServiceAuthority::open_pinned_owner_configuration(
        &config.join("command-authority.json"),
        hex_digest(&result["configuration_hashes"]["command-authority.json"]),
    )
    .await
    .unwrap();
    for operation in ["actor.register", "run.create"] {
        authority.issue(&request(operation)).await.unwrap();
    }
    authority
        .acquire_query(&request("work.list"))
        .await
        .unwrap();

    let mut other: Value = parse(&request("actor.register"), 65536).unwrap();
    other["request_id"] = json!("request-actor-register-other");
    other["resource"] = json!("actors/other");
    other["payload"]["actor_id"] = json!("other");
    assert!(authority.issue(&canonical(&other)).await.is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn live_provider_renewal_replaces_only_the_exact_run() {
    let first = RenewalFixture::new().live_provider("actor", "run-one");
    let first_result = first.apply();
    let selected = first.attempt().join("COMPLETE.json");
    let second = RenewalFixture::from_previous(first.f, first_result, Some(selected))
        .live_provider("actor", "run-two");
    let second_result = second.apply();
    assert_eq!(second_result["actor_id"], "actor");
    assert_eq!(second_result["run_id"], "run-two");

    let config = second.attempt().join("config");
    let authority = ServiceAuthority::open_pinned_owner_configuration(
        &config.join("command-authority.json"),
        hex_digest(&second_result["configuration_hashes"]["command-authority.json"]),
    )
    .await
    .unwrap();
    let mut old_run: Value = parse(&request("run.create"), 65536).unwrap();
    old_run["request_id"] = json!("request-run-create-old");
    old_run["resource"] = json!("runs/run-one");
    old_run["payload"]["run_id"] = json!("run-one");
    assert!(authority.issue(&canonical(&old_run)).await.is_err());

    let mut new_run: Value = parse(&request("run.create"), 65536).unwrap();
    new_run["request_id"] = json!("request-run-create-new");
    new_run["resource"] = json!("runs/run-two");
    new_run["payload"]["run_id"] = json!("run-two");
    authority.issue(&canonical(&new_run)).await.unwrap();
}

#[test]
fn live_provider_renewal_cannot_replace_the_actor() {
    let first = RenewalFixture::new().live_provider("actor-one", "run-one");
    let first_result = first.apply();
    let selected = first.attempt().join("COMPLETE.json");
    let second = RenewalFixture::from_previous(first.f, first_result, Some(selected))
        .live_provider("actor-two", "run-two");
    assert_eq!(
        renew_from_plan(&second.path, &second.pin),
        Err(RenewalError::Denied)
    );
    assert!(!second.attempt().exists());
}
struct Stop;
impl Drop for Stop {
    fn drop(&mut self) {
        renewal::STOP.with(|v| *v.borrow_mut() = None)
    }
}
fn stop(at: &'static str) -> Stop {
    renewal::STOP.with(|v| *v.borrow_mut() = Some(at));
    Stop
}
async fn rows(root: &Path) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    use sqlx::Connection;
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(root.join("authority/command-journal/service-challenges.sqlite3"))
        .read_only(true);
    let mut c = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    let rows = sqlx::query_as("SELECT id,record,digest FROM service_challenges_v1 ORDER BY id")
        .fetch_all(&mut c)
        .await
        .unwrap();
    c.close().await.unwrap();
    rows
}
#[tokio::test(flavor = "current_thread")]
async fn renewal_retains_keys_journal_and_five_real_operations() {
    let x = RenewalFixture::new();
    let original = read(&x.f.root.join("authority/COMPLETE.json"), 65536, 0o600).unwrap();
    let old_configs: Vec<_> = renewal::configuration_names()
        .into_iter()
        .map(|n| {
            (
                n,
                read(&x.f.root.join("authority/config").join(n), 65536, 0o600).unwrap(),
            )
        })
        .collect();
    let store = x.f.store(&x.old);
    let old_id = store.public_identity().unwrap();
    let a = ServiceAuthority::open_owner_configuration(
        &x.f.root.join("authority/config/command-authority.json"),
    )
    .await
    .unwrap();
    let raw = request("process.get");
    let c = UntrustedSignedServiceChallenge::decode_inner(&a.acquire_query(&raw).await.unwrap())
        .unwrap();
    let proof = store
        .open_identity(old_id.expected())
        .unwrap()
        .present_current_service_challenge(&c)
        .unwrap();
    a.complete_query(&raw, &proof).await.unwrap();
    let before = rows(&x.f.root).await;
    assert_eq!(before.len(), 1);
    let result = x.apply();
    assert_eq!(rows(&x.f.root).await, before);
    assert_eq!(
        read(&x.f.root.join("authority/COMPLETE.json"), 65536, 0o600).unwrap(),
        original
    );
    for (n, b) in old_configs {
        assert_eq!(
            read(&x.f.root.join("authority/config").join(n), 65536, 0o600).unwrap(),
            b
        );
    }
    assert_eq!(
        result["schema"],
        "castalia.wallet-workspace-renewal-complete.v1"
    );
    assert_eq!(result["native_generation"], 2);
    assert_eq!(result["command_issuer"], x.old["command_issuer"]);
    assert_eq!(
        result["holder"]["key_generation"],
        x.old["holder"]["key_generation"]
    );
    assert_eq!(
        result["holder"]["public_key_hex"],
        x.old["holder"]["public_key_hex"]
    );
    let actual = store.public_identity().unwrap();
    assert_eq!(actual.state_revision, old_id.state_revision + 1);
    assert!(renewal::same_key(&old_id, &actual));
    assert!(a.complete_query(&raw, &proof).await.is_err());
    assert!(a.acquire_query(&raw).await.is_err());
    let a = ServiceAuthority::open_pinned_owner_configuration(
        &x.attempt().join("config/command-authority.json"),
        hex_digest(&result["configuration_hashes"]["command-authority.json"]),
    )
    .await
    .unwrap();
    let h = store.open_identity(actual.expected()).unwrap();
    for r in rules() {
        let raw = request(r.name);
        let query = r.name.ends_with(".get") || r.name == "events.list";
        let bytes = if query {
            a.acquire_query(&raw).await.unwrap()
        } else {
            a.issue(&raw).await.unwrap()
        };
        let c = UntrustedSignedServiceChallenge::decode_inner(&bytes).unwrap();
        assert_eq!(c.request_bytes, raw);
        assert!(c.claims.expires_at <= result["not_after"].as_u64().unwrap());
        let p = h.present_current_service_challenge(&c).unwrap();
        let done = if query {
            a.complete_query(&raw, &p).await.unwrap()
        } else {
            a.complete(&raw, &p).await.unwrap()
        };
        let packet: libsec_core::ZenithPacket = bincode::deserialize(&done.packet).unwrap();
        assert_eq!(packet.opcode, r.opcode);
        assert_eq!(packet.encrypted_payload, raw);
        let signed: server::verifier::SignedVerifiedCallContext =
            bincode::deserialize(&done.signed_context).unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&hex_digest(
            &result["command_issuer"]["public_key_hex"],
        ))
        .unwrap()
        .verify_strict(
            &bincode::serialize(&signed.context).unwrap(),
            &ed25519_dalek::Signature::from_slice(&signed.signature).unwrap(),
        )
        .unwrap();
    }
    for denied in ["run.create", "actor.register", "work.list", "effect.get"] {
        assert!(a.issue(&request(denied)).await.is_err());
        assert!(a.acquire_query(&request(denied)).await.is_err());
    }
    assert_eq!(resume_renewal_from_plan(&x.path, &x.pin).unwrap(), result);
    assert_eq!(
        renew_from_plan(&x.path, &x.pin),
        Err(RenewalError::RecoveryRequired)
    );
}
#[test]
fn renewal_is_sequential_and_original_receipts_remain_immutable() {
    let x = RenewalFixture::new();
    let first = x.apply();
    {
        let root = ServiceRoot::open(&x.f.root.join("authority/wallet")).unwrap();
        let lease = root.lock_exclusive().unwrap();
        assert_eq!(
            lease.inspect_bounded().unwrap().revisions,
            vec![first["holder"]["state_revision"].as_u64().unwrap()]
        );
    }
    let selected = x.attempt().join("COMPLETE.json");
    let bytes = read(&selected, 65536, 0o600).unwrap();
    let next = RenewalFixture::from_previous(x.f, first, Some(selected.clone()));
    let second = next.apply();
    assert_eq!(second["native_generation"], 3);
    assert_eq!(read(&selected, 65536, 0o600).unwrap(), bytes);
    assert_eq!(
        second["holder"]["key_generation"],
        next.old["holder"]["key_generation"]
    );
}
#[test]
fn renewal_plan_pin_window_and_previous_receipt_fail_before_mutation() {
    for kind in [
        "plan-pin",
        "previous-pin",
        "expired",
        "future",
        "long",
        "identity-end",
        "backdated",
        "shortened",
        "unknown",
    ] {
        let mut x = RenewalFixture::new();
        let before = x.f.store(&x.old).public_identity().unwrap();
        let mut p = x.value();
        let n = now().unwrap();
        match kind {
            "plan-pin" => {}
            "previous-pin" => p["previous_complete"]["sha256"] = json!("00".repeat(32)),
            "expired" => {
                p["not_before"] = json!((n - 10).to_string());
                p["not_after"] = json!((n - 1).to_string());
            }
            "future" => {
                p["not_before"] = json!((n + 100).to_string());
                p["not_after"] = json!((n + 300).to_string());
            }
            "backdated" => {
                p["not_before"] = json!((x.old["not_before"].as_u64().unwrap() - 1).to_string())
            }
            "shortened" => p["not_after"] = json!(x.old["not_after"].as_u64().unwrap().to_string()),
            "long" => p["not_after"] = json!((n + 7200).to_string()),
            "identity-end" => p["not_after"] = json!((before.not_after + 1).to_string()),
            _ => p["permissions"] = json!([]),
        }
        x.replace(p);
        let expected = if kind == "plan-pin" {
            "00".repeat(32)
        } else {
            x.pin.clone()
        };
        assert_eq!(
            renew_from_plan(&x.path, &expected),
            Err(RenewalError::Denied),
            "{kind}"
        );
        assert!(!x.attempt().exists());
        assert_eq!(x.f.store(&x.old).public_identity().unwrap(), before);
    }
}
#[test]
fn revoked_or_stale_wallet_denies_renewal_without_rekey_or_intent() {
    for revoke in [true, false] {
        let x = RenewalFixture::new();
        let store = x.f.store(&x.old);
        let before = store.public_identity().unwrap();
        if revoke {
            store.revoke(before.expected()).unwrap();
        } else {
            let root = ServiceRoot::open(&x.f.root.join("authority/wallet")).unwrap();
            let mut owner: Value = {
                let v = root.lock_public_shared().unwrap();
                parse(v.metadata().owner_input_bytes().unwrap(), 262144).unwrap()
            };
            owner["generation"] = json!(before.state_revision + 1);
            store
                .configure(before.expected(), &canonical(&owner))
                .unwrap();
        }
        let current = store.public_identity().unwrap();
        assert_eq!(renew_from_plan(&x.path, &x.pin), Err(RenewalError::Denied));
        assert_eq!(store.public_identity().unwrap(), current);
        assert!(!x.attempt().exists());
    }
}
#[test]
fn renewal_intent_or_prepared_before_configure_is_retained_and_never_replayed() {
    for at in ["intent", "prepared"] {
        let x = RenewalFixture::new();
        let before = x.f.store(&x.old).public_identity().unwrap();
        {
            let _stop = stop(at);
            assert_eq!(
                renew_from_plan(&x.path, &x.pin),
                Err(RenewalError::RecoveryRequired)
            );
        }
        let marker_path = x.f.root.join("authority/native/wallet-transition.json");
        let marker = if at == "prepared" {
            Some(read(&marker_path, 16384, 0o600).unwrap())
        } else {
            assert!(!marker_path.exists());
            None
        };
        assert_eq!(x.f.store(&x.old).public_identity().unwrap(), before);
        assert_eq!(
            resume_renewal_from_plan(&x.path, &x.pin),
            Err(RenewalError::RecoveryRequired)
        );
        if let Some(marker) = marker {
            assert_eq!(read(&marker_path, 16384, 0o600).unwrap(), marker);
        } else {
            assert!(!marker_path.exists());
        }
        assert_eq!(x.f.store(&x.old).public_identity().unwrap(), before);
        assert!(!x.attempt().join("COMPLETE.json").exists());
        assert!(x.attempt().join("INTENT.json").exists());
        assert!(x.attempt().join("ORIGINAL.json").exists());
    }
}

#[test]
fn renewal_resumes_actual_configure_publish_or_completed_cleanup_once_under_original_inputs() {
    for at in ["configured", "published", "before_cleanup"] {
        let x = RenewalFixture::new();
        {
            let _stop = stop(at);
            assert_eq!(
                renew_from_plan(&x.path, &x.pin),
                Err(RenewalError::RecoveryRequired)
            );
        }
        let actual = x.f.store(&x.old).public_identity().unwrap();
        assert_eq!(
            actual.state_revision,
            x.old["holder"]["state_revision"].as_u64().unwrap() + 1
        );
        let completed = if at == "before_cleanup" {
            assert!(!x
                .f
                .root
                .join("authority/native/wallet-transition.json")
                .exists());
            let root = ServiceRoot::open(&x.f.root.join("authority/wallet")).unwrap();
            let lease = root.lock_exclusive().unwrap();
            assert_eq!(
                lease.inspect_bounded().unwrap().revisions,
                vec![actual.state_revision - 1, actual.state_revision]
            );
            Some(read(&x.attempt().join("COMPLETE.json"), 65536, 0o600).unwrap())
        } else {
            None
        };
        let result = resume_renewal_from_plan(&x.path, &x.pin).unwrap();
        if let Some(completed) = completed {
            assert_eq!(
                read(&x.attempt().join("COMPLETE.json"), 65536, 0o600).unwrap(),
                completed
            );
        }
        {
            let root = ServiceRoot::open(&x.f.root.join("authority/wallet")).unwrap();
            let lease = root.lock_exclusive().unwrap();
            assert_eq!(
                lease.inspect_bounded().unwrap().revisions,
                vec![actual.state_revision]
            );
        }
        assert_eq!(
            result["not_after"].as_u64().unwrap().to_string(),
            x.value()["not_after"].as_str().unwrap()
        );
        assert_eq!(x.f.store(&x.old).public_identity().unwrap(), actual);
        assert_eq!(resume_renewal_from_plan(&x.path, &x.pin).unwrap(), result);
        assert!(!x
            .f
            .root
            .join("authority/native/wallet-transition.json")
            .exists());
    }
}
#[test]
fn renewal_original_tamper_or_changed_recovery_window_cannot_complete() {
    for change_plan in [false, true] {
        let mut x = RenewalFixture::new();
        {
            let _stop = stop("configured");
            assert_eq!(
                renew_from_plan(&x.path, &x.pin),
                Err(RenewalError::RecoveryRequired)
            );
        }
        let actual = x.f.store(&x.old).public_identity().unwrap();
        if change_plan {
            let mut p = x.value();
            let end = p["not_after"].as_str().unwrap().parse::<u64>().unwrap();
            p["not_after"] = json!((end + 1).to_string());
            x.replace(p);
        } else {
            let p = x.attempt().join("ORIGINAL.json");
            let mut o: Value = parse(&read(&p, 262144, 0o600).unwrap(), 262144).unwrap();
            o["target_policy"]["permissions"][0]["resource"] =
                json!({"kind":"prefix","prefix":"runs/"});
            fs::remove_file(&p).unwrap();
            write(&p, &canonical(&o)).unwrap();
        }
        assert_eq!(
            resume_renewal_from_plan(&x.path, &x.pin),
            Err(RenewalError::RecoveryRequired)
        );
        assert_eq!(x.f.store(&x.old).public_identity().unwrap(), actual);
        assert!(!x.attempt().join("COMPLETE.json").exists());
    }
}
#[tokio::test(flavor = "current_thread")]
async fn renewal_after_old_policy_expiry_preserves_the_live_identity() {
    let mut f = Fixture::new();
    let mut p = f.value();
    let end = now().unwrap() + 10;
    p["not_after"] = json!(end.to_string());
    f.replace(p);
    let old = f.setup();
    let x = RenewalFixture::from_previous(f, old, None);
    let store = x.f.store(&x.old);
    let before = store.public_identity().unwrap();
    let a = ServiceAuthority::open_owner_configuration(
        &x.f.root.join("authority/config/command-authority.json"),
    )
    .await
    .unwrap();
    a.acquire_query(&request("process.get")).await.unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while now().unwrap() < end {
        assert!(std::time::Instant::now() < deadline);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(a.acquire_query(&request("process.get")).await.is_err());
    let renewed = x.apply();
    let after = store.public_identity().unwrap();
    assert!(renewal::same_key(&before, &after));
    let a = ServiceAuthority::open_pinned_owner_configuration(
        &x.attempt().join("config/command-authority.json"),
        hex_digest(&renewed["configuration_hashes"]["command-authority.json"]),
    )
    .await
    .unwrap();
    let raw = request("process.get");
    let c = UntrustedSignedServiceChallenge::decode_inner(&a.acquire_query(&raw).await.unwrap())
        .unwrap();
    let proof = store
        .open_identity(after.expected())
        .unwrap()
        .present_current_service_challenge(&c)
        .unwrap();
    a.complete_query(&raw, &proof).await.unwrap();
}

#[test]
fn renewal_begun_attempt_public_input_or_lock_failure_remains_recovery_required() {
    for public_config in [true, false] {
        let x = RenewalFixture::new();
        {
            let _stop = stop("configured");
            assert_eq!(
                renew_from_plan(&x.path, &x.pin),
                Err(RenewalError::RecoveryRequired)
            );
        }
        let target = if public_config {
            x.f.root.join("authority/config/command-authority.json")
        } else {
            x.f.root.join("authority/native/.service-owner.lock")
        };
        let old = fs::metadata(&target).unwrap().permissions();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            renew_from_plan(&x.path, &x.pin),
            Err(RenewalError::RecoveryRequired)
        );
        assert_eq!(
            resume_renewal_from_plan(&x.path, &x.pin),
            Err(RenewalError::RecoveryRequired)
        );
        assert!(x.attempt().join("INTENT.json").exists());
        assert!(x.attempt().join("ORIGINAL.json").exists());
        assert!(!x.attempt().join("COMPLETE.json").exists());
        fs::set_permissions(&target, old).unwrap();
        resume_renewal_from_plan(&x.path, &x.pin).unwrap();
    }
}

#[test]
fn renewal_rejects_changed_verifier_selection_before_mutation() {
    for change in [false, true] {
        let mut x = RenewalFixture::new();
        if !change {
            x.apply();
            continue;
        }
        let before = x.f.store(&x.old).public_identity().unwrap();
        let verifier = x.f.root.join("native/process-runtime-secs-check");
        let new_public = b"PUBLIC NEW VERIFIER SOURCE FIXTURE NEVER EXECUTED";
        fs::remove_file(&verifier).unwrap();
        write(&verifier, new_public).unwrap();
        fs::set_permissions(&verifier, fs::Permissions::from_mode(0o500)).unwrap();
        let mut plan = x.value();
        plan["verifier_sha256"] = json!(hash(new_public));
        x.replace(plan);
        // The replacement matches its newly selected exact bytes and mode;
        // predecessor receiver pin remains different, so this is not a bad-pin test.
        assert_eq!(
            hash(&read(&verifier, 67108864, 0o500).unwrap()),
            x.value()["verifier_sha256"]
        );
        assert_eq!(renew_from_plan(&x.path, &x.pin), Err(RenewalError::Denied));
        assert_eq!(x.f.store(&x.old).public_identity().unwrap(), before);
        assert!(!x.attempt().exists());
    }
}
#[test]
fn renewal_poisoned_custody_stays_held_without_reconciliation() {
    let x = RenewalFixture::new();
    {
        let _stop = stop("configured");
        assert_eq!(
            renew_from_plan(&x.path, &x.pin),
            Err(RenewalError::RecoveryRequired)
        );
    }
    let store = x.f.store(&x.old);
    let configured = store.public_identity().unwrap();
    assert_eq!(
        configured.state_revision,
        x.old["holder"]["state_revision"].as_u64().unwrap() + 1
    );
    let marker = x.f.root.join("authority/native/wallet-transition.json");
    let before = read(&marker, 16384, 0o600).unwrap();
    let root = ServiceRoot::open(&x.f.root.join("authority/wallet")).unwrap();
    {
        let mut lease = root.lock_exclusive().unwrap();
        assert!(!lease.poisoned().unwrap());
        lease.invalidate(true).unwrap();
        assert!(lease.poisoned().unwrap());
    }
    assert_eq!(
        store.public_identity(),
        Err(castalia_wallet_service_holder::custody::CustodyError::PublicationUncertain)
    );
    assert_eq!(
        resume_renewal_from_plan(&x.path, &x.pin),
        Err(RenewalError::RecoveryRequired)
    );
    {
        let lease = root.lock_exclusive().unwrap();
        assert!(lease.poisoned().unwrap());
    }
    assert_eq!(read(&marker, 16384, 0o600).unwrap(), before);
    assert!(!x.attempt().join("COMPLETE.json").exists());
}
