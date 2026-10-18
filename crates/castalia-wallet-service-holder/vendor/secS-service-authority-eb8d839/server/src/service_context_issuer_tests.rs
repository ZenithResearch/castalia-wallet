use super::*;
use crate::{
    service_authority,
    service_authority_snapshot::canonical,
    service_owner_publication::{OwnerPublicationSource, OwnerStartupPin},
    service_wallet_source::{
        hash, hex,
        tests::{
            audience_metadata_unconfigured, audience_request_fixture, private_file, WalletFiles,
        },
        SourceError,
    },
};
use castalia_wallet_private_files::service_store::ServiceRoot;
use libsec_core::service_holder_proof::ServiceApplication;
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

// Disposable PUBLIC test seed, unrelated to any configured operator identity.
const SEED: [u8; 32] = [81; 32];
struct Fixture {
    wallet: WalletFiles,
    owner: tempfile::TempDir,
    key: tempfile::TempDir,
    pin: OwnerStartupPin,
    policy: Value,
}
impl Fixture {
    fn new() -> Self {
        Self::with_policy(|_| {})
    }
    fn with_policy(edit: impl FnOnce(&mut Value)) -> Self {
        Self::with_state(edit, true)
    }
    fn with_state(edit: impl FnOnce(&mut Value), configured: bool) -> Self {
        Self::with_application_state(ServiceApplication::RuntimeV1, edit, configured, 7)
    }
    fn for_application(application: ServiceApplication) -> Self {
        Self::with_application_state(application, |_| {}, true, 7)
    }
    fn with_application_state(
        application: ServiceApplication,
        edit: impl FnOnce(&mut Value),
        configured: bool,
        generation: u64,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (mut p, _) = audience_request_fixture(application);
        p["issuer_node_id"] = json!("node:ni02:fixture");
        p["selected_issuer_key_id"] = json!("issuer:ni02:fixture");
        p["issuers"][0]["node_id"] = p["issuer_node_id"].clone();
        p["issuers"][0]["key_id"] = p["selected_issuer_key_id"].clone();
        p["issuers"][0]["public_key_hex"] = json!(hex(SigningKey::from_bytes(&SEED)
            .verifying_key()
            .as_bytes()));
        p["valid_not_before"] = json!(now - 600);
        p["valid_until"] = json!(now + 600);
        for group in ["issuers", "holders", "permissions"] {
            for row in p[group].as_array_mut().unwrap() {
                row["not_before"] = json!(now - 600);
                row["not_after"] = json!(now + 600);
            }
        }
        p["receiver_policy"]["not_before"] = json!(now - 600);
        p["receiver_policy"]["not_after"] = json!(now + 600);
        for group in ["principals", "rules"] {
            for row in p["receiver_policy"][group].as_array_mut().unwrap() {
                row["not_before"] = json!(now - 600);
                row["not_after"] = json!(now + 600);
            }
        }
        // Retain the real deny rule, outside these disposable <=60s positive
        // windows. Expanding it over the allow window would mask preparation.
        for row in p["receiver_policy"]["rules"].as_array_mut().unwrap() {
            if row["effect"] == "deny" {
                row["not_before"] = json!(now + 300);
            }
        }
        edit(&mut p);
        let w = audience_metadata_unconfigured(&p);
        let mut issuers = p["issuers"].clone();
        for i in issuers.as_array_mut().unwrap() {
            i.as_object_mut().unwrap().remove("production_authority");
        }
        let mut holder = p["holders"][0].clone();
        holder["generation"] = json!(1);
        holder["replaced_by"] = Value::Null;
        let input = canonical(
            &json!({"schema":"castalia.wallet-service-owner-input.v1","generation":2,"valid_not_before":now-600,"valid_until":now+600,"application":p["application"],"issuer_node_id":p["issuer_node_id"],"selected_issuer_key_id":p["selected_issuer_key_id"],"issuers":issuers,"holder":holder,"descriptors":p["descriptors"],"delegation_policy":p["receiver_policy"]}),
        );
        let mut state = w.state.clone();
        state["state_revision"] = json!(2);
        state["state"] = json!(if configured { "active" } else { "unconfigured" });
        state["published_at"] = json!(now);
        state["not_before"] = json!(now - 600);
        state["not_after"] = json!(now + 600);
        state["previous_state_sha256"] = json!(hex(&hash(&canonical(&w.state))));
        state["owner_input_sha256"] = if configured {
            json!(hex(&hash(&input)))
        } else {
            Value::Null
        };
        let root = ServiceRoot::open(w.path()).unwrap();
        let mut custody = root.lock_exclusive().unwrap();
        w.publish(
            &mut custody,
            &state,
            if configured { Some(&input) } else { None },
            true,
        );
        custody.publish_clock(&canonical(&json!({"schema":"castalia.wallet-service-custody-clock.v1","store_id":state["store_id"],"observed_at":now})),true).unwrap();
        drop(custody);
        let owner = tempfile::tempdir_in("/private/tmp").unwrap();
        fs::set_permissions(owner.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut bundle = p.clone();
        bundle["schema"] = json!("secs.service-owner-bundle.v2");
        bundle
            .as_object_mut()
            .unwrap()
            .remove("native_bundle_profile");
        bundle["generation"] = json!(generation);
        bundle["wallet_current"] = w.observed().reference.value;
        let raw = canonical(&bundle);
        private_file(&owner.path().join("owner-generation.json"), &raw);
        private_file(&owner.path().join(".service-owner.lock"), b"");
        let key = tempfile::tempdir_in("/private/tmp").unwrap();
        fs::set_permissions(key.path(), fs::Permissions::from_mode(0o700)).unwrap();
        private_file(&key.path().join(KEY_LOCK), b"");
        private_file(&key.path().join(KEY_FILE), hex(&SEED).as_bytes());
        Self {
            wallet: w,
            owner,
            key,
            pin: OwnerStartupPin::new(generation, hash(&raw)).unwrap(),
            policy: p,
        }
    }
    fn owner_source(&self) -> OwnerPublicationSource {
        OwnerPublicationSource::open_owner_selected_root(self.owner.path()).unwrap()
    }
    fn selection(&self) -> IssuerSelection {
        IssuerSelection::new(
            "node:ni02:fixture",
            "issuer:ni02:fixture",
            SigningKey::from_bytes(&SEED).verifying_key().to_bytes(),
        )
        .unwrap()
    }
    fn key_source(&self) -> IssuerKeySource {
        IssuerKeySource::open_selected(self.key.path(), self.selection()).unwrap()
    }
}
fn child_lock(path: &std::path::Path, exclusive: bool, excluded: bool) {
    let output = Command::new("python3").arg("-c").arg("import fcntl,sys\nf=open(sys.argv[1],'r+')\ntry: fcntl.flock(f, (fcntl.LOCK_EX if sys.argv[2]=='1' else fcntl.LOCK_SH)|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(87)\nsys.exit(0)").arg(path).arg(if exclusive {"1"} else {"0"}).output().unwrap();
    assert_eq!(output.status.code(), Some(if excluded { 87 } else { 0 }));
}
fn window() -> OriginalServiceWindow {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    OriginalServiceWindow::new(n, n + 30).unwrap()
}
#[test]
fn actual_key_and_native_shared_files_remain_held_through_typed_signatures() {
    for application in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::for_application(application);
        let ws = f.wallet.source();
        let w = ws.capture_shared().unwrap();
        let os = f.owner_source();
        let native = os.capture_shared(f.pin, &w).unwrap();
        let policy = native.policy().unwrap();
        assert_eq!(policy.application(), application);
        let original = window();
        let (preimage, claims, raw) =
            service_authority::tests::challenge_codec_fixture(&policy, original);
        let (operation, resource, opcode) = match application {
            ServiceApplication::RuntimeV1 => ("runtime.run.create.v1", "runs/run-1", 0x42),
            ServiceApplication::ServiceV1 => {
                ("service.request.create.v1", "requests/request-1", 0x79)
            }
        };
        assert_eq!(claims.application, application);
        assert_eq!(claims.audience, application.audience());
        assert_eq!(claims.operation, operation);
        assert_eq!(claims.resource, resource);
        assert_eq!(claims.opcode, opcode);
        // Actual held Native full-policy preparation parses the matching
        // public request. The codec input itself remains unqualified test data.
        let subject = f.policy["holders"][0]["subject_id"].as_str().unwrap();
        let holder = f.policy["holders"][0]["key_id"].as_str().unwrap();
        let bindings = policy
            .prepare_original(&raw, subject, holder, original)
            .unwrap();
        assert_eq!(
            bindings.evidence().bindings().evidence_observed_at,
            policy.lineage().observed_at()
        );
        assert_eq!(
            bindings.evidence().bindings().evidence_valid_until,
            original.expires_at()
        );
        let source = f.key_source();
        let key = source.lease(&policy, original).unwrap();
        child_lock(&f.key.path().join(KEY_LOCK), true, true);
        child_lock(&f.key.path().join(KEY_LOCK), false, false);
        child_lock(&f.owner.path().join(".service-owner.lock"), true, true);
        let signature = key.sign_challenge(&preimage).unwrap();
        let bytes = libsec_core::service_holder_proof::challenge_transcript(&claims, &raw).unwrap();
        SigningKey::from_bytes(&SEED)
            .verifying_key()
            .verify_strict(&bytes, &ed25519_dalek::Signature::from_bytes(&signature))
            .unwrap();
        let prepared = service_authority::tests::context_codec_fixture(&policy, original);
        let signed = key.sign_context(prepared).unwrap();
        assert_eq!(
            signed.context.schema_version,
            crate::verifier::VERIFIED_CALL_CONTEXT_SCHEMA_VERSION
        );
        assert_eq!(signed.context.audience, application.audience());
        assert_eq!(signed.context.operation, operation);
        assert_eq!(signed.context.resource.as_deref(), Some(resource));
        assert_eq!(signed.context.opcode, opcode);
        assert_eq!(signed.context.issued_at, original.issued_at());
        assert_eq!(signed.context.expires_at, original.expires_at());
        signed
            .verify_ed25519_with_key(
                &SigningKey::from_bytes(&SEED).verifying_key(),
                application.audience(),
                original.issued_at(),
            )
            .unwrap();
        let other_audience = match application {
            ServiceApplication::RuntimeV1 => ServiceApplication::ServiceV1.audience(),
            ServiceApplication::ServiceV1 => ServiceApplication::RuntimeV1.audience(),
        };
        assert!(signed
            .verify_ed25519_with_key(
                &SigningKey::from_bytes(&SEED).verifying_key(),
                other_audience,
                original.issued_at(),
            )
            .is_err());
        assert!(SigningKey::from_bytes(&SEED)
            .verifying_key()
            .verify_strict(
                &bytes,
                &ed25519_dalek::Signature::from_slice(&signed.signature).unwrap()
            )
            .is_err());
        let context_bytes = bincode::serialize(&signed.context).unwrap();
        assert!(SigningKey::from_bytes(&SEED)
            .verifying_key()
            .verify_strict(
                &context_bytes,
                &ed25519_dalek::Signature::from_bytes(&signature)
            )
            .is_err());
        key.revalidate().unwrap();
        drop(key);
        child_lock(&f.key.path().join(KEY_LOCK), true, false);
    }
}
#[test]
fn missing_existing_lock_is_not_created_and_bad_format_is_closed() {
    let f = Fixture::new();
    fs::remove_file(f.key.path().join(KEY_LOCK)).unwrap();
    assert!(IssuerKeySource::open_selected(f.key.path(), f.selection()).is_err());
    assert!(!f.key.path().join(KEY_LOCK).exists());
    for raw in [
        vec![81; 32],
        vec![b'A'; 64],
        format!("{}\n", hex(&SEED)).into_bytes(),
        vec![b'0'; 63],
        vec![b'0'; 65],
    ] {
        let f = Fixture::new();
        fs::write(f.key.path().join(KEY_FILE), raw).unwrap();
        let ws = f.wallet.source();
        let w = ws.capture_shared().unwrap();
        let os = f.owner_source();
        let n = os.capture_shared(f.pin, &w).unwrap();
        let p = n.policy().unwrap();
        if let Ok(s) = IssuerKeySource::open_selected(f.key.path(), f.selection()) {
            assert!(s.lease(&p, window()).is_err());
        }
    }
}
#[test]
fn exact_root_inventory_modes_links_and_nonblocking_special_files_deny() {
    for mode in [0o644, 0o700, 0o1600, 0o660] {
        let f = Fixture::new();
        fs::set_permissions(
            f.key.path().join(KEY_FILE),
            fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert!(IssuerKeySource::open_selected(f.key.path(), f.selection()).is_err());
    }
    let f = Fixture::new();
    private_file(&f.key.path().join("unknown.tmp"), b"");
    assert!(IssuerKeySource::open_selected(f.key.path(), f.selection()).is_err());
    let f = Fixture::new();
    let outside = tempfile::tempdir_in("/private/tmp").unwrap();
    fs::hard_link(f.key.path().join(KEY_FILE), outside.path().join("alias")).unwrap();
    assert!(IssuerKeySource::open_selected(f.key.path(), f.selection()).is_err());
    let f = Fixture::new();
    let key = f.key.path().join(KEY_FILE);
    fs::remove_file(&key).unwrap();
    symlink("/dev/null", &key).unwrap();
    assert!(IssuerKeySource::open_selected(f.key.path(), f.selection()).is_err());
    let f = Fixture::new();
    let key = f.key.path().join(KEY_FILE);
    fs::remove_file(&key).unwrap();
    let name = std::ffi::CString::new(key.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    // O_NONBLOCK must return a denial without a writer or blocking read.
    assert!(IssuerKeySource::open_selected(f.key.path(), f.selection()).is_err());
}
#[test]
fn held_key_revalidation_detects_in_place_and_selected_identity_drift() {
    for changed in ["contents", "key", "lock", "root"] {
        let f = Fixture::new();
        let ws = f.wallet.source();
        let w = ws.capture_shared().unwrap();
        let os = f.owner_source();
        let n = os.capture_shared(f.pin, &w).unwrap();
        let p = n.policy().unwrap();
        let s = f.key_source();
        let original = window();
        let k = s.lease(&p, original).unwrap();
        let (preimage, _, _) = service_authority::tests::challenge_codec_fixture(&p, original);
        k.revalidate().unwrap();
        k.sign_challenge(&preimage).unwrap();
        // Displaced entries must not add a third name to the selected root.
        // The old descriptor stays held; the selected replacement is valid.
        let outside = tempfile::tempdir_in("/private/tmp").unwrap();
        fs::set_permissions(outside.path(), fs::Permissions::from_mode(0o700)).unwrap();
        match changed {
            "contents" => fs::write(f.key.path().join(KEY_FILE), hex(&[82; 32])).unwrap(),
            "key" => {
                fs::rename(f.key.path().join(KEY_FILE), outside.path().join("old-key")).unwrap();
                private_file(&f.key.path().join(KEY_FILE), hex(&SEED).as_bytes());
            }
            "lock" => {
                fs::rename(f.key.path().join(KEY_LOCK), outside.path().join("old-lock")).unwrap();
                private_file(&f.key.path().join(KEY_LOCK), b"");
            }
            "root" => {
                fs::rename(f.key.path(), outside.path().join("old-root")).unwrap();
                fs::create_dir(f.key.path()).unwrap();
                fs::set_permissions(f.key.path(), fs::Permissions::from_mode(0o700)).unwrap();
                private_file(&f.key.path().join(KEY_LOCK), b"");
                private_file(&f.key.path().join(KEY_FILE), hex(&SEED).as_bytes());
            }
            _ => unreachable!(),
        }
        let mut names: Vec<_> = fs::read_dir(f.key.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, vec![KEY_LOCK.to_owned(), KEY_FILE.to_owned()]);
        if changed != "contents" {
            assert_eq!(
                fs::read(f.key.path().join(KEY_FILE)).unwrap().as_slice(),
                hex(&SEED).as_bytes()
            );
            assert_eq!(
                fs::metadata(f.key.path()).unwrap().permissions().mode() & 0o7777,
                0o700
            );
            for leaf in [KEY_LOCK, KEY_FILE] {
                assert_eq!(
                    fs::metadata(f.key.path().join(leaf))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o7777,
                    0o600
                );
            }
            // Native/Wallet were acquired before either key; their source
            // leases are not reacquired after the old key lock is held.
            let fresh_source = f.key_source();
            let fresh = fresh_source.lease(&p, original).unwrap();
            fresh.revalidate().unwrap();
            fresh.sign_challenge(&preimage).unwrap();
        }
        let expected = if changed == "contents" {
            IssuerError::Selection
        } else {
            IssuerError::UnsafeSource
        };
        assert_eq!(k.revalidate(), Err(expected), "{changed}");
        assert_eq!(k.sign_challenge(&preimage), Err(expected), "{changed}");
    }
}
#[test]
fn selected_full_policy_lineage_and_original_window_cannot_be_substituted() {
    let f = Fixture::new();
    let ws = f.wallet.source();
    let w = ws.capture_shared().unwrap();
    let os = f.owner_source();
    let n = os.capture_shared(f.pin, &w).unwrap();
    let p = n.policy().unwrap();
    assert_eq!(p.lineage().generation(), 7);
    assert_eq!(p.lineage().owner_digest(), f.pin.sha256());
    let s = f.key_source();
    let original = window();
    let k = s.lease(&p, original).unwrap();
    let other =
        OriginalServiceWindow::new(original.issued_at(), original.expires_at() - 1).unwrap();
    let (preimage, _, _) = service_authority::tests::challenge_codec_fixture(&p, other);
    assert_eq!(k.sign_challenge(&preimage), Err(IssuerError::Binding));
    let raw = include_bytes!("../tests/fixtures/service-holder-proof-v1/challenge.bin");
    let request =
        libsec_core::service_holder_proof::UntrustedSignedServiceChallenge::decode_inner(raw)
            .unwrap()
            .request_bytes;
    let subject = f.policy["holders"][0]["subject_id"].as_str().unwrap();
    let holder = f.policy["holders"][0]["key_id"].as_str().unwrap();
    let bindings = p
        .prepare_original(&request, subject, holder, original)
        .unwrap();
    assert_eq!(
        bindings.evidence().bindings().evidence_observed_at,
        p.lineage().observed_at()
    );
    let marker = f.owner.path().join("wallet-transition.json");
    // Minimal owner-private marker-presence fence only. This is not a complete
    // valid transition record, recovery result or acknowledgment fixture.
    private_file(&marker, b"{}");
    assert_eq!(
        fs::metadata(&marker).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert_eq!(p.revalidate(), Err(SourceError::TransitionPending));
    assert_eq!(
        k.sign_challenge(&preimage),
        Err(IssuerError::Policy(HeldPolicyError::Source(
            SourceError::TransitionPending
        )))
    );
}
#[test]
fn unsafe_native_marker_mode_precedes_pending_fence_for_both_applications() {
    for application in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let f = Fixture::for_application(application);
        let ws = f.wallet.source();
        let w = ws.capture_shared().unwrap();
        let os = f.owner_source();
        let n = os.capture_shared(f.pin, &w).unwrap();
        let p = n.policy().unwrap();
        let source = f.key_source();
        let original = window();
        let key = source.lease(&p, original).unwrap();
        let (preimage, _, _) = service_authority::tests::challenge_codec_fixture(&p, original);
        // Own-source positives and the unchanged original input precede the
        // unsafe marker. A wrong window/input must not cause these denials.
        p.revalidate().unwrap();
        key.revalidate().unwrap();
        key.sign_challenge(&preimage).unwrap();
        let marker = f.owner.path().join("wallet-transition.json");
        private_file(&marker, b"{}");
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            fs::metadata(&marker).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        // Current storage inspection precedes the marker-presence fence. The
        // marker body is not a valid transition/recovery acknowledgment here.
        assert_eq!(p.revalidate(), Err(SourceError::UnsafeStorage));
        let expected = IssuerError::Policy(HeldPolicyError::Source(SourceError::UnsafeStorage));
        assert_eq!(key.revalidate(), Err(expected));
        assert_eq!(key.sign_challenge(&preimage), Err(expected));
    }
}
#[test]
fn same_window_two_actual_policy_lineages_require_exact_input_binding() {
    for application in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let first = Fixture::for_application(application);
        let second = Fixture::with_application_state(application, |_| {}, true, 8);
        // Acquire every actual Wallet lease, then both actual Native leases,
        // before acquiring either key. Pure policy data cannot replace them.
        let first_wallet_source = first.wallet.source();
        let second_wallet_source = second.wallet.source();
        let first_wallet = first_wallet_source.capture_shared().unwrap();
        let second_wallet = second_wallet_source.capture_shared().unwrap();
        let first_owner = first.owner_source();
        let second_owner = second.owner_source();
        let first_native = first_owner
            .capture_shared(first.pin, &first_wallet)
            .unwrap();
        let second_native = second_owner
            .capture_shared(second.pin, &second_wallet)
            .unwrap();
        let first_policy = first_native.policy().unwrap();
        let second_policy = second_native.policy().unwrap();
        let original = window();
        assert_eq!(first_policy.application(), second_policy.application());
        assert_eq!(first_policy.lineage().generation(), 7);
        assert_eq!(second_policy.lineage().generation(), 8);
        assert_ne!(
            first_policy.lineage().owner_digest(),
            second_policy.lineage().owner_digest()
        );
        assert!(first_policy.lineage() != second_policy.lineage());
        let first_issuer = first_policy.selected_issuer(original).unwrap();
        let second_issuer = second_policy.selected_issuer(original).unwrap();
        assert_eq!(first_issuer.node_id, second_issuer.node_id);
        assert_eq!(first_issuer.key.key_id, second_issuer.key.key_id);
        assert_eq!(
            first_issuer.key.public_key.to_bytes(),
            second_issuer.key.public_key.to_bytes()
        );
        let first_source = first.key_source();
        let second_source = second.key_source();
        let first_key = first_source.lease(&first_policy, original).unwrap();
        let second_key = second_source.lease(&second_policy, original).unwrap();
        assert_eq!(
            first_key.original_window().issued_at(),
            second_key.original_window().issued_at()
        );
        assert_eq!(
            first_key.original_window().expires_at(),
            second_key.original_window().expires_at()
        );
        let (first_input, _, _) =
            service_authority::tests::challenge_codec_fixture(&first_policy, original);
        let (second_input, _, _) =
            service_authority::tests::challenge_codec_fixture(&second_policy, original);
        // Both genuine held sources sign their own unqualified codec inputs.
        first_key.sign_challenge(&first_input).unwrap();
        second_key.sign_challenge(&second_input).unwrap();
        first_key
            .sign_context(service_authority::tests::context_codec_fixture(
                &first_policy,
                original,
            ))
            .unwrap();
        second_key
            .sign_context(service_authority::tests::context_codec_fixture(
                &second_policy,
                original,
            ))
            .unwrap();
        // Same app, issuer material and exact window: only complete lineage
        // differs, so cross-input errors must be exactly Binding.
        assert_eq!(
            first_key.sign_challenge(&second_input),
            Err(IssuerError::Binding)
        );
        assert_eq!(
            second_key.sign_challenge(&first_input),
            Err(IssuerError::Binding)
        );
        assert_eq!(
            first_key.sign_context(service_authority::tests::context_codec_fixture(
                &second_policy,
                original
            )),
            Err(IssuerError::Binding)
        );
        assert_eq!(
            second_key.sign_context(service_authority::tests::context_codec_fixture(
                &first_policy,
                original
            )),
            Err(IssuerError::Binding)
        );
    }
}
#[test]
fn unsafe_owned_ancestor_denies_but_actual_sticky_root_fixture_is_supported() {
    let f = Fixture::new();
    let parent = tempfile::tempdir_in("/private/tmp").unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o777)).unwrap();
    let root = parent.path().join("key");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    private_file(&root.join(KEY_LOCK), b"");
    private_file(&root.join(KEY_FILE), hex(&SEED).as_bytes());
    assert!(IssuerKeySource::open_selected(&root, f.selection()).is_err());
    // The healthy fixture lives below actual root-owned sticky /private/tmp.
    assert!(IssuerKeySource::open_selected(f.key.path(), f.selection()).is_ok());
}

#[test]
fn independently_selected_public_node_and_id_must_match_the_actual_native_issuer() {
    let f = Fixture::new();
    let ws = f.wallet.source();
    let w = ws.capture_shared().unwrap();
    let os = f.owner_source();
    let n = os.capture_shared(f.pin, &w).unwrap();
    let p = n.policy().unwrap();
    let other = SigningKey::from_bytes(&[82; 32]).verifying_key().to_bytes();
    for selection in [
        IssuerSelection::new(
            "other-node",
            "issuer:ni02:fixture",
            SigningKey::from_bytes(&SEED).verifying_key().to_bytes(),
        )
        .unwrap(),
        IssuerSelection::new(
            "node:ni02:fixture",
            "other-key",
            SigningKey::from_bytes(&SEED).verifying_key().to_bytes(),
        )
        .unwrap(),
        IssuerSelection::new("node:ni02:fixture", "issuer:ni02:fixture", other).unwrap(),
    ] {
        let source = IssuerKeySource::open_selected(f.key.path(), selection).unwrap();
        assert!(matches!(
            source.lease(&p, window()),
            Err(IssuerError::Selection)
        ));
    }
}
#[test]
fn actual_selected_issuer_status_and_entire_original_window_are_checked() {
    for case in [
        "inactive",
        "not-production",
        "replaced",
        "future",
        "expired",
        "revocation-before-end",
        "revocation-at-end",
    ] {
        let f = Fixture::with_policy(|p| {
            let issued = p["valid_not_before"].as_u64().unwrap() + 600;
            match case {
                "inactive" => p["issuers"][0]["status"] = json!("revoked"),
                "not-production" => p["issuers"][0]["production_authority"] = json!(false),
                "replaced" => p["issuers"][0]["replaced_by"] = json!("replacement:fixture"),
                "future" => p["issuers"][0]["not_before"] = json!(issued + 60),
                "expired" => p["issuers"][0]["not_after"] = json!(issued - 1),
                "revocation-before-end" => p["issuers"][0]["revoked_at"] = json!(issued + 29),
                "revocation-at-end" => p["issuers"][0]["revoked_at"] = json!(issued + 30),
                _ => unreachable!(),
            }
        });
        let issued = f.policy["valid_not_before"].as_u64().unwrap() + 600;
        let original = OriginalServiceWindow::new(issued, issued + 30).unwrap();
        let ws = f.wallet.source();
        let w = ws.capture_shared().unwrap();
        let os = f.owner_source();
        let n = os.capture_shared(f.pin, &w).unwrap();
        let p = n.policy().unwrap();
        let s = f.key_source();
        assert_eq!(
            s.lease(&p, original).is_ok(),
            case == "revocation-at-end",
            "{case}"
        );
    }
}
#[test]
fn actual_os_expiry_denies_a_held_key_and_returns_no_late_signature() {
    let f = Fixture::new();
    let ws = f.wallet.source();
    let w = ws.capture_shared().unwrap();
    let os = f.owner_source();
    let n = os.capture_shared(f.pin, &w).unwrap();
    let p = n.policy().unwrap();
    let s = f.key_source();
    let issued = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let original = OriginalServiceWindow::new(issued, issued + 3).unwrap();
    let key = s.lease(&p, original).unwrap();
    let (preimage, _, _) = service_authority::tests::challenge_codec_fixture(&p, original);
    while SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        < original.expires_at()
    {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(key.revalidate().is_err());
    assert!(key.sign_challenge(&preimage).is_err());
}

#[test]
fn actual_exclusive_key_writer_excludes_a_new_issuer_lease() {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let f = Fixture::new();
    let ws = f.wallet.source();
    let w = ws.capture_shared().unwrap();
    let os = f.owner_source();
    let n = os.capture_shared(f.pin, &w).unwrap();
    let p = n.policy().unwrap();
    let s = f.key_source();
    let mut child=Command::new("python3").arg("-c").arg("import fcntl,sys; f=open(sys.argv[1],'r+'); fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB); print('held',flush=True); sys.stdin.read()").arg(f.key.path().join(KEY_LOCK)).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "held\n");
    assert!(matches!(s.lease(&p, window()), Err(IssuerError::Busy)));
    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
    assert!(s.lease(&p, window()).is_ok());
}
#[test]
fn native_fence_is_checked_before_malformed_seed_can_be_consumed() {
    let f = Fixture::new();
    let ws = f.wallet.source();
    let w = ws.capture_shared().unwrap();
    let os = f.owner_source();
    let n = os.capture_shared(f.pin, &w).unwrap();
    let p = n.policy().unwrap();
    let s = f.key_source();
    fs::write(f.key.path().join(KEY_FILE), [b'A'; 64]).unwrap();
    private_file(&f.owner.path().join("wallet-transition.json"), b"{}");
    let error = match s.lease(&p, window()) {
        Err(e) => e,
        Ok(_) => panic!("unexpected issuer lease"),
    };
    assert_eq!(
        error,
        IssuerError::Policy(HeldPolicyError::Source(SourceError::TransitionPending))
    );
    assert!(!format!("{error:?}").contains(&"A".repeat(64)));
}
#[cfg(target_os = "macos")]
#[test]
fn actual_key_acl_denies() {
    let f = Fixture::new();
    let output = Command::new("/bin/chmod")
        .args(["+a", "everyone allow read"])
        .arg(f.key.path().join(KEY_FILE))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(IssuerKeySource::open_selected(f.key.path(), f.selection()).is_err());
}

#[test]
fn inactive_actual_wallet_reference_cannot_select_an_issuer() {
    let f = Fixture::with_state(|_| {}, false);
    let ws = f.wallet.source();
    let w = ws.capture_shared().unwrap();
    let os = f.owner_source();
    let n = os.capture_shared(f.pin, &w).unwrap();
    let p = n.policy().unwrap();
    let s = f.key_source();
    assert!(s.lease(&p, window()).is_err());
}
#[test]
fn exact_read_only_key_mode_is_supported_without_creating_or_rewriting_files() {
    let f = Fixture::new();
    fs::set_permissions(
        f.key.path().join(KEY_FILE),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    let ws = f.wallet.source();
    let w = ws.capture_shared().unwrap();
    let os = f.owner_source();
    let n = os.capture_shared(f.pin, &w).unwrap();
    let p = n.policy().unwrap();
    let s = f.key_source();
    let key = s.lease(&p, window()).unwrap();
    key.revalidate().unwrap();
    assert_eq!(
        fs::metadata(f.key.path().join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o400
    );
}
