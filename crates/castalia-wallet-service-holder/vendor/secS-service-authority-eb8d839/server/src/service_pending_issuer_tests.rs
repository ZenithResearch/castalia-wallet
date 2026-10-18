//! Ordinary disposable PUBLIC fixture regressions for the private Pending path.
//! Source only until separately released. No configured identity, live issuer,
//! completion/context issuance, private fault backend or installed qualification.
use super::*;
use crate::{
    manifest::{OpcodeRange, OperationDescriptor, OperationName, ReplayScope, TargetKind},
    service_authority_snapshot::canonical,
    service_challenge_store::{
        AuthorityGuard, ExportStage, GuardInput, Journal, JournalError, Limits,
    },
    service_context_issuer::{IssuerKeySource, IssuerSelection},
    service_owner_publication::{OwnerPublicationSource, OwnerStartupPin},
    service_wallet_source::{
        hash, hex,
        tests::{
            audience_metadata_unconfigured, audience_request_fixture, private_file, TestTime,
            WalletFiles,
        },
    },
};
use castalia_wallet_private_files::service_store::ServiceRoot;
use ed25519_dalek::SigningKey;
use libsec_core::service_holder_proof::{challenge_transcript, UntrustedSignedServiceChallenge};
use serde_json::{json, Value};
use std::{
    fs,
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

// Disposable PUBLIC test material; not a configured or selected operator key.
const PUBLIC_SEED: [u8; 32] = [81; 32];
struct Fixture {
    wallet: WalletFiles,
    owner: tempfile::TempDir,
    key: tempfile::TempDir,
    pin: OwnerStartupPin,
    now: u64,
    // Original public configuration DATA retained for negative transition tests.
    owner_input: Vec<u8>,
}
impl Fixture {
    fn new(application: ServiceApplication, edit: impl FnOnce(&mut Value, u64)) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (mut policy, _) = audience_request_fixture(application);
        policy["issuer_node_id"] = json!("node:ni03:public-fixture");
        policy["selected_issuer_key_id"] = json!("issuer:ni03:public-fixture");
        policy["issuers"][0]["node_id"] = policy["issuer_node_id"].clone();
        policy["issuers"][0]["key_id"] = policy["selected_issuer_key_id"].clone();
        policy["issuers"][0]["public_key_hex"] = json!(hex(SigningKey::from_bytes(&PUBLIC_SEED)
            .verifying_key()
            .as_bytes()));
        policy["valid_not_before"] = json!(now - 600);
        policy["valid_until"] = json!(now + 600);
        for group in ["issuers", "holders", "permissions"] {
            for row in policy[group].as_array_mut().unwrap() {
                row["not_before"] = json!(now - 600);
                row["not_after"] = json!(now + 600);
            }
        }
        policy["receiver_policy"]["not_before"] = json!(now - 600);
        policy["receiver_policy"]["not_after"] = json!(now + 600);
        for group in ["principals", "rules"] {
            for row in policy["receiver_policy"][group].as_array_mut().unwrap() {
                row["not_before"] = json!(now - 600);
                row["not_after"] = json!(now + 600);
                // Keep the existing deny rule, outside ordinary <=60s windows.
                if row["effect"] == "deny" {
                    row["not_before"] = json!(now + 300);
                }
            }
        }
        edit(&mut policy, now);
        let wallet = audience_metadata_unconfigured(&policy);
        let mut issuers = policy["issuers"].clone();
        for issuer in issuers.as_array_mut().unwrap() {
            issuer
                .as_object_mut()
                .unwrap()
                .remove("production_authority");
        }
        let mut holder = policy["holders"][0].clone();
        holder["generation"] = json!(1);
        holder["replaced_by"] = Value::Null;
        let owner_input = canonical(&json!({
            "schema":"castalia.wallet-service-owner-input.v1", "generation":2,
            "valid_not_before":policy["valid_not_before"], "valid_until":policy["valid_until"],
            "application":policy["application"], "issuer_node_id":policy["issuer_node_id"],
            "selected_issuer_key_id":policy["selected_issuer_key_id"], "issuers":issuers,
            "holder":holder, "descriptors":policy["descriptors"], "delegation_policy":policy["receiver_policy"]
        }));
        let mut state = wallet.state.clone();
        state["state_revision"] = json!(2);
        state["state"] = json!("active");
        state["published_at"] = json!(now);
        state["previous_state_sha256"] = json!(hex(&hash(&canonical(&wallet.state))));
        state["owner_input_sha256"] = json!(hex(&hash(&owner_input)));
        let root = ServiceRoot::open(wallet.path()).unwrap();
        let mut custody = root.lock_exclusive().unwrap();
        wallet.publish(&mut custody, &state, Some(&owner_input), true);
        custody.publish_clock(&canonical(&json!({
            "schema":"castalia.wallet-service-custody-clock.v1", "store_id":state["store_id"], "observed_at":now
        })), true).unwrap();
        drop(custody);
        let owner = tempfile::tempdir_in("/private/tmp").unwrap();
        fs::set_permissions(owner.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut bundle = policy.clone();
        bundle["schema"] = json!("secs.service-owner-bundle.v2");
        bundle
            .as_object_mut()
            .unwrap()
            .remove("native_bundle_profile");
        bundle["generation"] = json!(7);
        bundle["wallet_current"] = wallet.observed().reference.value;
        let raw = canonical(&bundle);
        private_file(&owner.path().join("owner-generation.json"), &raw);
        private_file(&owner.path().join(".service-owner.lock"), b"");
        let key = tempfile::tempdir_in("/private/tmp").unwrap();
        fs::set_permissions(key.path(), fs::Permissions::from_mode(0o700)).unwrap();
        private_file(&key.path().join(".service-issuer.lock"), b"");
        private_file(
            &key.path().join("issuer.seed.hex"),
            hex(&PUBLIC_SEED).as_bytes(),
        );
        Self {
            wallet,
            owner,
            key,
            pin: OwnerStartupPin::new(7, hash(&raw)).unwrap(),
            now,
            owner_input,
        }
    }
    fn owner_source(&self) -> OwnerPublicationSource {
        OwnerPublicationSource::open_owner_selected_root(self.owner.path()).unwrap()
    }
    fn key_source(&self) -> IssuerKeySource {
        IssuerKeySource::open_selected(
            self.key.path(),
            IssuerSelection::new(
                "node:ni03:public-fixture",
                "issuer:ni03:public-fixture",
                SigningKey::from_bytes(&PUBLIC_SEED)
                    .verifying_key()
                    .to_bytes(),
            )
            .unwrap(),
        )
        .unwrap()
    }
}
fn request(application: ServiceApplication) -> Vec<u8> {
    let bytes: &[u8] = match application {
        ServiceApplication::RuntimeV1 => {
            include_bytes!("../tests/fixtures/service-holder-proof-v1/challenge.bin")
        }
        ServiceApplication::ServiceV1 => {
            include_bytes!("../tests/fixtures/service-holder-proof-v1/service/challenge.bin")
        }
    };
    UntrustedSignedServiceChallenge::decode_inner(bytes)
        .unwrap()
        .request_bytes
}
fn journal_directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir_in("/private/tmp").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}
fn input<'a>(
    challenge: &'a UntrustedSignedServiceChallenge,
    evidence: &'a [u8],
    lineage: &'a [u8],
) -> GuardInput<'a> {
    GuardInput {
        stage: ExportStage::Pending,
        challenge,
        evidence,
        lineage,
        packet: &[],
        context: &[],
        signed_at: 0,
        holder_verified_at: 0,
    }
}
fn public_descriptor(application: ServiceApplication) -> OperationDescriptor {
    let (name, opcode) = match application {
        ServiceApplication::RuntimeV1 => ("runtime.run.create.v1", 0x42),
        ServiceApplication::ServiceV1 => ("service.request.create.v1", 0x79),
    };
    OperationDescriptor {
        opcode,
        name: OperationName::new(name),
        payload_schema: Some("application/json".into()),
        output_profile: None,
        target_kind: TargetKind::ReceiverProductionHandler,
        required_credentials: vec![],
        required_capabilities: vec![],
        accepted_evidence: vec![],
        required_authority_mode: None,
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 60,
        handler_id: format!("fixture/{name}"),
        dev_binding: false,
        range: OpcodeRange::OperatorDefined,
        disclosure_policy: crate::privacy::DisclosurePolicy::deny_by_default("fixture", 1),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn both_profiles_sign_exact_original_claims_and_retain_durable_pending() {
    for application in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let fixture = Fixture::new(application, |_, _| {});
        let _time = TestTime::set(fixture.now);
        let wallet_source = fixture.wallet.source();
        let native_source = fixture.owner_source();
        let key_source = fixture.key_source();
        let directory = journal_directory();
        let clock = PendingClock::new(fixture.now);
        let mut journal = Journal::open(directory.path(), Limits::default(), &clock)
            .await
            .unwrap();
        // Observe the ORIGINAL issuance call after SQLite closes and before its
        // final admission returns. These are ordinary disposable public files.
        let retained_checks = Arc::new(AtomicUsize::new(0));
        let reached = Arc::clone(&retained_checks);
        let wallet_path = fixture.wallet.path().to_path_buf();
        let native_lock = fixture.owner.path().join(".service-owner.lock");
        let issuer_lock = fixture.key.path().join(".service-issuer.lock");
        journal.after_close_for_test(move || {
            // Initial untrusted exact-request lookup precedes authority owners.
            if reached.fetch_add(1, Ordering::SeqCst) == 0 {
                return;
            }
            let root = ServiceRoot::open(&wallet_path).unwrap();
            match root.lock_exclusive() {
                Ok(_) => panic!("original Wallet shared lease was not retained"),
                Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
            };
            for path in [&native_lock, &issuer_lock] {
                let lock = fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .unwrap();
                let result =
                    unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                let error = std::io::Error::last_os_error();
                assert_eq!(result, -1);
                assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
                assert!(matches!(error.raw_os_error(), Some(code)
                    if code == libc::EWOULDBLOCK || code == libc::EAGAIN));
            }
        });
        let issuer = PendingIssuer::from_startup(
            &wallet_source,
            &native_source,
            fixture.pin,
            &key_source,
            &journal,
            60,
        )
        .unwrap();
        let raw = request(application);
        let stored = issuer.issue_pending_challenge(&raw).await.unwrap();
        assert!(retained_checks.load(Ordering::SeqCst) >= 2);
        let c = &stored.challenge;
        let expected_descriptor = public_descriptor(application);
        let expected_resource = match application {
            ServiceApplication::RuntimeV1 => "runs/run-1",
            ServiceApplication::ServiceV1 => "requests/request-1",
        };
        let observed_wallet = fixture.wallet.observed();
        assert_eq!(c.claims.operation, expected_descriptor.name.as_str());
        assert_eq!(c.claims.resource, expected_resource);
        assert_eq!(c.claims.opcode, expected_descriptor.opcode);
        assert_eq!(c.claims.handler_id, expected_descriptor.handler_id);
        assert_eq!(
            hex(&c.claims.descriptor_fingerprint),
            expected_descriptor
                .authorization_fingerprint()
                .trim_start_matches("descriptor:sha256:")
        );
        assert_eq!(
            c.claims.schema_bundle_sha256,
            crate::service_holder_proof::schema_bundle_digest(application)
        );
        assert_eq!(
            hex(&c.claims.holder_public_key_fingerprint),
            observed_wallet.reference.value["public_key_sha256"]
                .as_str()
                .unwrap()
        );
        // Independent fixture horizons; no expectation is copied from the
        // producer's freshly recomputed pending_claims result.
        assert_eq!(
            c.claims.evidence.evidence_valid_not_before,
            fixture.now - 600
        );
        assert_eq!(c.claims.evidence.evidence_valid_until, fixture.now + 60);
        assert_eq!(c.claims.evidence.evidence_observed_at, fixture.now);
        assert_eq!(
            c.claims.evidence.evidence_revocation_checked_at,
            fixture.now
        );
        assert_eq!(
            c.claims.evidence.evidence_revocation_fresh_until,
            fixture.now + 60
        );
        assert_eq!(c.request_bytes, raw);
        assert_eq!(c.claims.application, application);
        assert_eq!(c.claims.audience, application.audience());
        assert_eq!(c.claims.issuer_node_id, "node:ni03:public-fixture");
        assert_eq!(c.claims.issuer_key_id, "issuer:ni03:public-fixture");
        assert_eq!(c.claims.issued_at, fixture.now);
        assert_eq!(c.claims.expires_at, fixture.now + 60);
        assert_eq!(c.claims.ttl_seconds, 60);
        assert_eq!(c.claims.request_length, raw.len() as u64);
        assert_eq!(c.claims.request_sha256, hash(&raw));
        assert_ne!(c.claims.challenge_id, [0; 32]);
        assert_ne!(c.claims.session_id, [0; 16]);
        assert_ne!(c.claims.nonce, [0; 12]);
        SigningKey::from_bytes(&PUBLIC_SEED)
            .verifying_key()
            .verify_strict(
                &challenge_transcript(&c.claims, &raw).unwrap(),
                &ed25519_dalek::Signature::from_bytes(&c.issuer_signature),
            )
            .unwrap();
        // Reopen actual journal storage and read through a fresh concrete guard.
        // This same-current fixture is not a claim of restart/rebinding support.
        let reopened = Journal::open(directory.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let stats = reopened.stats(&clock).await.unwrap();
        assert_eq!(
            (stats.rows, stats.pending, stats.completed, stats.tombstones),
            (1, 1, 0, 0)
        );
        let wallet = wallet_source.capture_shared().unwrap();
        let native = native_source.capture_shared(fixture.pin, &wallet).unwrap();
        let policy = native.policy().unwrap();
        let window = OriginalServiceWindow::new(c.claims.issued_at, c.claims.expires_at).unwrap();
        let (subject, key_id, _) = holder(&wallet).unwrap();
        let prepared = policy
            .prepare_original(&raw, subject, key_id, window)
            .unwrap();
        assert_eq!(
            c.claims.permission_policy_digest,
            prepared.permission_digest()
        );
        assert_eq!(
            c.claims.registry_snapshot_digest,
            prepared.registry_digest()
        );
        assert_eq!(c.claims.receiver_policy_digest, prepared.receiver_digest());
        assert_eq!(c.claims.evidence, *prepared.evidence().bindings());
        assert_eq!(c.claims.holder_subject_id, subject);
        assert_eq!(c.claims.holder_key_id, key_id);
        assert_eq!(prepared.intent().request_bytes(), raw);
        let key = key_source.lease(&policy, window).unwrap();
        let selected = policy.selected_issuer(window).unwrap();
        let preimage = ServiceChallengeSignaturePreimage {
            binding: SigningBinding {
                lineage: policy.lineage(),
                application,
                node: selected.node_id.clone(),
                key: selected.key.key_id.clone(),
                public: selected.key.public_key.to_bytes(),
                window,
            },
            transcript: challenge_transcript(&c.claims, &raw).unwrap(),
        };
        let lineage = wallet.observed.reference.lineage_preimage();
        let randomness = PendingRandomness {
            challenge: c.claims.challenge_id,
            session: c.claims.session_id,
            nonce: c.claims.nonce,
        };
        let mut guard = PendingGuard {
            wallet: &wallet,
            native: &native,
            policy: &policy,
            key: &key,
            prepared: &prepared,
            preimage: &preimage,
            challenge: c,
            lineage: &lineage,
            raw: &raw,
            window,
            randomness,
            clock: &clock,
        };
        let loaded = reopened
            .pending(c.claims.challenge_id, &mut guard, &clock)
            .await
            .unwrap();
        assert_eq!(loaded.challenge, *c);
        assert!(ServiceRoot::open(fixture.wallet.path())
            .unwrap()
            .lock_exclusive()
            .is_err());
        // Actual Native/key shared flocks remain held by the guard's owners.
        for path in [
            fixture.owner.path().join(".service-owner.lock"),
            fixture.key.path().join(".service-issuer.lock"),
        ] {
            let lock = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap();
            assert_ne!(
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                0
            );
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn all_four_external_obligations_deny_wallet_configuration_and_none_preparation() {
    for application in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let fixture = Fixture::new(application, |_, _| {});
        let _time = TestTime::set(fixture.now);
        let source = fixture.wallet.source();
        let current = source.capture_shared().unwrap();
        let reference = &current.observed.reference;
        let mut next: Value = serde_json::from_slice(&fixture.owner_input).unwrap();
        next["generation"] = json!(reference.value["state_revision"].as_u64().unwrap() + 1);
        // Positive control: the exact real current reference accepts the
        // unchanged next configuration before each isolated obligation edit.
        crate::service_wallet_source::validate_transition_request(&canonical(&next), reference)
            .unwrap();
        for obligation in 0..4 {
            let mut candidate = next.clone();
            let mut descriptor = public_descriptor(application);
            assert_eq!(
                candidate["delegation_policy"]["descriptors"][0]["fingerprint"],
                descriptor
                    .authorization_fingerprint()
                    .trim_start_matches("descriptor:sha256:")
            );
            match obligation {
                0 => {
                    descriptor.required_credentials = vec!["public.credential".into()];
                    candidate["descriptors"][0]["required_credentials"] =
                        json!(["public.credential"]);
                }
                1 => {
                    descriptor.required_capabilities = vec!["public.capability".into()];
                    candidate["descriptors"][0]["required_capabilities"] =
                        json!(["public.capability"]);
                }
                2 => {
                    descriptor.accepted_evidence = vec!["public.evidence".into()];
                    candidate["descriptors"][0]["accepted_evidence"] = json!(["public.evidence"]);
                }
                _ => {
                    descriptor.required_authority_mode =
                        Some(crate::dregg_authority::AuthorityMode::LocalFixture);
                    candidate["descriptors"][0]["required_authority_mode"] = json!("local_fixture");
                }
            }
            let fingerprint = descriptor.authorization_fingerprint();
            let digest = fingerprint.trim_start_matches("descriptor:sha256:");
            candidate["delegation_policy"]["descriptors"][0]["fingerprint"] = json!(digest);
            assert_eq!(
                crate::service_wallet_source::validate_transition_request(
                    &canonical(&candidate),
                    reference
                ),
                Err(crate::service_wallet_source::SourceError::Invalid),
                "Wallet obligation {obligation}"
            );
            // Separate pure preparation control. No unsupported Wallet current
            // is fabricated, and this does not claim PendingIssuer was reached.
            let raw = request(application);
            let input = crate::service_evidence::EvidenceInput {
                owner: hash(&fs::read(fixture.owner.path().join("owner-generation.json")).unwrap()),
                descriptor: pending_digest(digest).unwrap(),
                subject: reference.value["subject_id"].as_str().unwrap().into(),
                audience: application.audience().into(),
                operation: descriptor.name.as_str().into(),
                resource: match application {
                    ServiceApplication::RuntimeV1 => "runs/run-1",
                    ServiceApplication::ServiceV1 => "requests/request-1",
                }
                .into(),
                request: hash(&raw),
                start: fixture.now - 600,
                end: fixture.now + 60,
                observed: fixture.now,
            };
            assert!(
                matches!(
                    crate::service_evidence::prepare_none(&descriptor, &input),
                    Err(crate::service_evidence::EvidenceError::UnsupportedRequiredEvidence)
                ),
                "none obligation {obligation}"
            );
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn largest_original_window_is_capped_before_signing_by_all_current_bounds() {
    for application in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        for bound in 0..8 {
            let fixture = Fixture::new(application, |policy, now| {
                match bound {
                    0 => {} // Trusted startup cap, not an incoming selector.
                    1 => {
                        policy["valid_until"] = json!(now + 11);
                        policy["holders"][0]["not_after"] = json!(now + 11);
                    }
                    2 => {
                        policy["issuers"][0]["not_after"] = json!(now + 12);
                    }
                    3 => {
                        policy["holders"][0]["not_after"] = json!(now + 13);
                        policy["valid_until"] = json!(now + 13);
                    }
                    4 => {
                        for row in policy["permissions"].as_array_mut().unwrap() {
                            if row["effect"] == "allow" {
                                row["not_after"] = json!(now + 14);
                            }
                        }
                    }
                    5 => {
                        policy["receiver_policy"]["max_ttl_seconds"] = json!(7);
                    }
                    6 => {
                        for row in policy["receiver_policy"]["rules"].as_array_mut().unwrap() {
                            if row["effect"] == "deny" {
                                row["not_before"] = json!(now + 9);
                            }
                        }
                    }
                    _ => {
                        policy["receiver_policy"]["principals"][0]["not_after"] = json!(now + 15);
                        policy["valid_until"] = json!(now + 15);
                        policy["holders"][0]["not_after"] = json!(now + 15);
                    }
                }
            });
            let _time = TestTime::set(fixture.now);
            let wallet = fixture.wallet.source();
            let native = fixture.owner_source();
            let key = fixture.key_source();
            let directory = journal_directory();
            let clock = PendingClock::new(fixture.now);
            let journal = Journal::open(directory.path(), Limits::default(), &clock)
                .await
                .unwrap();
            let cap = if bound == 0 { 17 } else { 60 };
            let issuer =
                PendingIssuer::from_startup(&wallet, &native, fixture.pin, &key, &journal, cap)
                    .unwrap();
            let stored = issuer
                .issue_pending_challenge(&request(application))
                .await
                .unwrap();
            let expected = [17, 11, 12, 13, 14, 7, 9, 15][bound];
            assert_eq!(stored.challenge.claims.issued_at, fixture.now);
            assert_eq!(stored.challenge.claims.ttl_seconds, expected);
            assert_eq!(stored.challenge.claims.expires_at, fixture.now + expected);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn concrete_guard_rejects_substitutions_completion_fields_and_changed_source() {
    let application = ServiceApplication::RuntimeV1;
    let fixture = Fixture::new(application, |_, _| {});
    let _time = TestTime::set(fixture.now);
    let wallet_source = fixture.wallet.source();
    let native_source = fixture.owner_source();
    let key_source = fixture.key_source();
    let directory = journal_directory();
    let clock = PendingClock::new(fixture.now);
    let journal = Journal::open(directory.path(), Limits::default(), &clock)
        .await
        .unwrap();
    let issuer = PendingIssuer::from_startup(
        &wallet_source,
        &native_source,
        fixture.pin,
        &key_source,
        &journal,
        60,
    )
    .unwrap();
    let raw = request(application);
    let stored = issuer.issue_pending_challenge(&raw).await.unwrap();
    let challenge = &stored.challenge;
    let wallet = wallet_source.capture_shared().unwrap();
    let native = native_source.capture_shared(fixture.pin, &wallet).unwrap();
    let policy = native.policy().unwrap();
    let window =
        OriginalServiceWindow::new(challenge.claims.issued_at, challenge.claims.expires_at)
            .unwrap();
    let (subject, key_id, _) = holder(&wallet).unwrap();
    let prepared = policy
        .prepare_original(&raw, subject, key_id, window)
        .unwrap();
    let key = key_source.lease(&policy, window).unwrap();
    let selected = policy.selected_issuer(window).unwrap();
    let preimage = ServiceChallengeSignaturePreimage {
        binding: SigningBinding {
            lineage: policy.lineage(),
            application,
            node: selected.node_id.clone(),
            key: selected.key.key_id.clone(),
            public: selected.key.public_key.to_bytes(),
            window,
        },
        transcript: challenge_transcript(&challenge.claims, &raw).unwrap(),
    };
    let lineage = wallet.observed.reference.lineage_preimage();
    let randomness = PendingRandomness {
        challenge: challenge.claims.challenge_id,
        session: challenge.claims.session_id,
        nonce: challenge.claims.nonce,
    };
    let mut guard = PendingGuard {
        wallet: &wallet,
        native: &native,
        policy: &policy,
        key: &key,
        prepared: &prepared,
        preimage: &preimage,
        challenge,
        lineage: &lineage,
        raw: &raw,
        window,
        randomness,
        clock: &clock,
    };
    guard
        .revalidate(input(challenge, prepared.evidence().bytes(), &lineage))
        .unwrap();
    for index in 0..28 {
        let mut different = challenge.clone();
        match index {
            0 => different.claims.application = ServiceApplication::ServiceV1,
            1 => different.claims.audience.push('x'),
            2 => different.claims.operation.push('x'),
            3 => different.claims.resource.push('x'),
            4 => different.claims.opcode ^= 1,
            5 => different.claims.request_length += 1,
            6 => different.claims.request_sha256[0] ^= 1,
            7 => different.claims.schema_bundle_sha256[0] ^= 1,
            8 => different.claims.descriptor_fingerprint[0] ^= 1,
            9 => different.claims.handler_id.push('x'),
            10 => different.claims.holder_subject_id.push('x'),
            11 => different.claims.holder_key_id.push('x'),
            12 => different.claims.holder_public_key_fingerprint[0] ^= 1,
            13 => different.claims.receiver_policy_digest[0] ^= 1,
            14 => different.claims.permission_policy_digest[0] ^= 1,
            15 => different.claims.registry_snapshot_digest[0] ^= 1,
            16 => different.claims.challenge_id[0] ^= 1,
            17 => different.claims.session_id[0] ^= 1,
            18 => different.claims.nonce[0] ^= 1,
            19 => different.claims.ttl_seconds -= 1,
            20 => different.claims.issued_at -= 1,
            21 => different.claims.expires_at -= 1,
            22 => different.claims.issuer_node_id.push('x'),
            23 => different.claims.issuer_key_id.push('x'),
            24 => different.claims.evidence.evidence_source_epoch_digest[0] ^= 1,
            25 => different.claims.evidence.evidence_observed_at -= 1,
            26 => different.request_bytes.push(b' '),
            _ => different.issuer_signature[0] ^= 1,
        }
        assert_eq!(
            guard.revalidate(input(&different, prepared.evidence().bytes(), &lineage)),
            Err(JournalError::Rejected),
            "substitution {index}"
        );
    }
    for stage in [ExportStage::Complete, ExportStage::Cached] {
        let mut different = input(challenge, prepared.evidence().bytes(), &lineage);
        different.stage = stage;
        assert_eq!(guard.revalidate(different), Err(JournalError::Rejected));
    }
    for field in 0..4 {
        let mut different = input(challenge, prepared.evidence().bytes(), &lineage);
        match field {
            0 => different.packet = b"packet",
            1 => different.context = b"context",
            2 => different.signed_at = fixture.now,
            _ => different.holder_verified_at = fixture.now,
        }
        assert_eq!(guard.revalidate(different), Err(JournalError::Rejected));
    }
    let mut evidence = prepared.evidence().bytes().to_vec();
    evidence[0] ^= 1;
    assert_eq!(
        guard.revalidate(input(challenge, &evidence, &lineage)),
        Err(JournalError::Rejected)
    );
    let mut wrong_lineage = lineage.clone();
    wrong_lineage[0] ^= 1;
    assert_eq!(
        guard.revalidate(input(
            challenge,
            prepared.evidence().bytes(),
            &wrong_lineage
        )),
        Err(JournalError::Rejected)
    );
    // Public fixture publishes a different owner epoch; the retained old
    // snapshot must reject changed current metadata rather than refresh it.
    let owner_file = fixture.owner.path().join("owner-generation.json");
    let replacement = fixture.owner.path().join("replacement-public-bundle");
    let mut changed: Value = serde_json::from_slice(&fs::read(&owner_file).unwrap()).unwrap();
    changed["generation"] = json!(8);
    private_file(&replacement, &canonical(&changed));
    fs::rename(replacement, owner_file).unwrap();
    assert_eq!(
        guard.revalidate(input(challenge, prepared.evidence().bytes(), &lineage)),
        Err(JournalError::Rejected)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn startup_mismatch_lock_and_quota_denials_return_no_new_signed_output() {
    let fixture = Fixture::new(ServiceApplication::RuntimeV1, |_, _| {});
    let _time = TestTime::set(fixture.now);
    let wallet = fixture.wallet.source();
    let native = fixture.owner_source();
    let key = fixture.key_source();
    let directory = journal_directory();
    let clock = PendingClock::new(fixture.now);
    let limits = Limits {
        pending_global: 1,
        pending_per_holder: 1,
        ..Limits::default()
    };
    let journal = Journal::open(directory.path(), limits, &clock)
        .await
        .unwrap();
    let bad_pin = OwnerStartupPin::new(fixture.pin.generation(), [43; 32]).unwrap();
    let denied =
        PendingIssuer::from_startup(&wallet, &native, bad_pin, &key, &journal, 60).unwrap();
    assert!(denied
        .issue_pending_challenge(&request(ServiceApplication::RuntimeV1))
        .await
        .is_err());
    assert_eq!(journal.stats(&clock).await.unwrap().rows, 0);
    for cap in [0, 61] {
        assert!(
            PendingIssuer::from_startup(&wallet, &native, fixture.pin, &key, &journal, cap)
                .is_err()
        );
    }
    let issuer =
        PendingIssuer::from_startup(&wallet, &native, fixture.pin, &key, &journal, 60).unwrap();
    let wallet_root = ServiceRoot::open(fixture.wallet.path()).unwrap();
    let exclusive = wallet_root.lock_exclusive().unwrap();
    assert!(issuer
        .issue_pending_challenge(&request(ServiceApplication::RuntimeV1))
        .await
        .is_err());
    drop(exclusive);
    let first = issuer
        .issue_pending_challenge(&request(ServiceApplication::RuntimeV1))
        .await
        .unwrap();
    // A byte-distinct valid request tests quota, rather than an exact retry.
    let mut distinct = request(ServiceApplication::RuntimeV1);
    distinct.push(b' ');
    assert_eq!(
        issuer.issue_pending_challenge(&distinct).await.unwrap_err(),
        PendingError::Journal(JournalError::Capacity)
    );
    let stats = journal.stats(&clock).await.unwrap();
    assert_eq!((stats.rows, stats.pending, stats.completed), (1, 1, 0));
    assert_eq!(first.challenge.claims.issued_at, fixture.now);
}

#[tokio::test(flavor = "current_thread")]
async fn final_postclose_deadline_denies_and_tombstones_without_export() {
    let fixture = Fixture::new(ServiceApplication::RuntimeV1, |_, _| {});
    let _time = TestTime::set(fixture.now);
    let wallet = fixture.wallet.source();
    let native = fixture.owner_source();
    let key = fixture.key_source();
    let directory = journal_directory();
    let clock = PendingClock::new(fixture.now);
    let mut journal = Journal::open(directory.path(), Limits::default(), &clock)
        .await
        .unwrap();
    let deadline = fixture.now + 60;
    // Existing ordinary test-only final-close hook advances only the public
    // Native clock fixture. No private backend/fault/interposer path is used.
    let reached = Arc::new(AtomicUsize::new(0));
    let hook_reached = Arc::clone(&reached);
    journal.after_close_for_test(move || {
        // Skip only the initial untrusted request lookup; advance time at the
        // actual guarded issuance close so this still proves tombstoning.
        if hook_reached.fetch_add(1, Ordering::SeqCst) == 0 {
            return;
        }
        crate::service_wallet_source::TEST_NOW.with(|value| value.set(Some(deadline)));
    });
    let issuer =
        PendingIssuer::from_startup(&wallet, &native, fixture.pin, &key, &journal, 60).unwrap();
    assert_eq!(
        issuer
            .issue_pending_challenge(&request(ServiceApplication::RuntimeV1))
            .await
            .unwrap_err(),
        PendingError::Journal(JournalError::Expired)
    );
    assert!(reached.load(Ordering::SeqCst) >= 2);
    // Read the actual disposable database BEFORE stats opens a journal session,
    // since every session prunes rows at the exclusive expiry boundary.
    use sqlx::{sqlite::SqliteConnectOptions, Connection, SqliteConnection};
    let options = SqliteConnectOptions::new()
        .filename(directory.path().join("service-challenges.sqlite3"))
        .read_only(true)
        .create_if_missing(false);
    let mut db = SqliteConnection::connect_with(&options).await.unwrap();
    let rows: Vec<(i64, i64)> = sqlx::query_as("SELECT state,expires FROM service_challenges_v1")
        .fetch_all(&mut db)
        .await
        .unwrap();
    assert_eq!(rows, vec![(2, deadline as i64)]);
    let high_water: i64 =
        sqlx::query_scalar("SELECT high_water FROM service_challenge_meta_v1 WHERE id=1")
            .fetch_one(&mut db)
            .await
            .unwrap();
    assert_eq!(high_water, deadline as i64);
    db.close().await.unwrap();
    let stats = journal.stats(&clock).await.unwrap();
    assert_eq!(
        (stats.rows, stats.pending, stats.completed, stats.tombstones),
        (0, 0, 0, 0)
    );
}

#[test]
fn native_clock_rollback_and_failure_are_sticky_without_a_caller_clock_port() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let _time = TestTime::set(now);
    let clock = PendingClock::new(now);
    assert_eq!(clock.sample(), Ok(now));
    crate::service_wallet_source::TEST_NOW.with(|value| value.set(Some(now - 1)));
    assert_eq!(clock.sample(), Err(JournalError::ClockRollback));
    crate::service_wallet_source::TEST_NOW.with(|value| value.set(Some(now + 1)));
    assert_eq!(clock.sample(), Err(JournalError::ClockRollback));
    let failed = PendingClock::new(now);
    crate::service_wallet_source::TEST_NOW.with(|value| value.set(Some(0)));
    assert_eq!(failed.sample(), Err(JournalError::Invalid));
    crate::service_wallet_source::TEST_NOW.with(|value| value.set(Some(now + 1)));
    assert_eq!(failed.sample(), Err(JournalError::ClockRollback));
}

#[tokio::test(flavor = "current_thread")]
async fn current_revocation_malformed_request_and_wallet_reference_changes_deny() {
    for application in [ServiceApplication::RuntimeV1, ServiceApplication::ServiceV1] {
        let revoked = Fixture::new(application, |policy, now| {
            policy["issuers"][0]["revoked_at"] = json!(now);
        });
        let _time = TestTime::set(revoked.now);
        let wallet = revoked.wallet.source();
        let native = revoked.owner_source();
        let key = revoked.key_source();
        let directory = journal_directory();
        let clock = PendingClock::new(revoked.now);
        let journal = Journal::open(directory.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let issuer =
            PendingIssuer::from_startup(&wallet, &native, revoked.pin, &key, &journal, 60).unwrap();
        assert!(issuer
            .issue_pending_challenge(&request(application))
            .await
            .is_err());
        assert_eq!(journal.stats(&clock).await.unwrap().rows, 0);
        drop(_time);

        let fixture = Fixture::new(application, |_, _| {});
        let _time = TestTime::set(fixture.now);
        let wallet = fixture.wallet.source();
        let native = fixture.owner_source();
        let key = fixture.key_source();
        let directory = journal_directory();
        let clock = PendingClock::new(fixture.now);
        let journal = Journal::open(directory.path(), Limits::default(), &clock)
            .await
            .unwrap();
        let issuer =
            PendingIssuer::from_startup(&wallet, &native, fixture.pin, &key, &journal, 60).unwrap();
        assert!(issuer
            .issue_pending_challenge(b"{bad request}")
            .await
            .is_err());
        assert_eq!(journal.stats(&clock).await.unwrap().rows, 0);
        // Supported ordinary metadata-fixture publication: active -> unconfigured
        // at a new state revision. The original startup/Native binding cannot
        // silently accept the new current reference or refresh its old lineage.
        let previous = fixture.wallet.observed();
        let mut state: Value = serde_json::from_slice(&previous.state_raw).unwrap();
        state["state_revision"] = json!(3);
        state["state"] = json!("unconfigured");
        state["published_at"] = json!(fixture.now);
        state["previous_state_sha256"] = json!(hex(&hash(&previous.state_raw)));
        state["owner_input_sha256"] = Value::Null;
        let root = ServiceRoot::open(fixture.wallet.path()).unwrap();
        let mut custody = root.lock_exclusive().unwrap();
        fixture.wallet.publish(&mut custody, &state, None, true);
        custody.publish_clock(&canonical(&json!({"schema":"castalia.wallet-service-custody-clock.v1", "store_id":state["store_id"], "observed_at":fixture.now})), true).unwrap();
        drop(custody);
        assert!(issuer
            .issue_pending_challenge(&request(application))
            .await
            .is_err());
        assert_eq!(journal.stats(&clock).await.unwrap().rows, 0);
    }
}

#[path = "service_pending_resume_tests.rs"]
mod resume_tests;

#[path = "service_pending_retry_tests.rs"]
mod retry_tests;

#[path = "service_completion_tests.rs"]
mod completion_tests;
