//! Disposable actual Wallet custody tests for the fixed service-holder transcript.
//! These create fresh temporary identities, never load an installed identity.
use super::*;
use crate::{canonical, hash, hex32, validate_service_challenge, Error, ValidatedWalletOwnerInput};
use ed25519_dalek::{Signature, VerifyingKey};
use libsec_core::service_holder_proof::{
    holder_transcript, ServiceApplication, UntrustedServiceHolderProof,
    UntrustedSignedServiceChallenge,
};
use serde_json::{json, Value};

fn configured(
    app: Application,
) -> (
    tempfile::TempDir,
    ServiceIdentityStore,
    UntrustedSignedServiceChallenge,
    Vec<u8>,
) {
    let dir = root();
    let mut cfg = spec();
    cfg.application = app;
    cfg.not_after = 180;
    let store = ServiceIdentityStore::create(dir.path(), cfg).unwrap();
    let state = store.public_identity().unwrap();
    let mut v: Value = serde_json::from_slice(&owner_input(&state)).unwrap();
    let mut c=UntrustedSignedServiceChallenge::decode_inner(match app {
        Application::Runtime=>include_bytes!("../vendor/secS-service-b/server/tests/fixtures/service-holder-proof-v1/challenge.bin"),
        Application::Service=>include_bytes!("../vendor/secS-service-b/server/tests/fixtures/service-holder-proof-v1/service/challenge.bin"),
    }).unwrap();
    let app_name = if app == Application::Runtime {
        "runtime"
    } else {
        "service"
    };
    v["application"] = json!(app_name);
    v["delegation_policy"]["application"] = json!(app_name);
    v["delegation_policy"]["audience"] = json!(c.claims.application.audience());
    v["descriptors"][0]["name"] = json!(c.claims.operation);
    v["descriptors"][0]["opcode"] = json!(c.claims.opcode);
    v["descriptors"][0]["handler_id"] = json!(format!("fixture/{}", c.claims.operation));
    let descriptor = crate::tests::descriptor(&v["descriptors"][0]);
    let fp = descriptor
        .authorization_fingerprint()
        .trim_start_matches("descriptor:sha256:")
        .to_owned();
    let d = &mut v["delegation_policy"]["descriptors"][0];
    d["fingerprint"] = json!(fp);
    d["handler_id"] = json!(descriptor.handler_id);
    d["opcode"] = json!(c.claims.opcode);
    d["operation"] = json!(c.claims.operation);
    for rule in v["delegation_policy"]["rules"].as_array_mut().unwrap() {
        rule["operation"] = json!(c.claims.operation);
        rule["resource"] = json!(c.claims.resource);
    }
    c.claims.descriptor_fingerprint = hex32(&fp).unwrap();
    c.claims.handler_id = descriptor.handler_id;
    c.claims.holder_subject_id = state.subject_id.clone();
    c.claims.holder_key_id = state.key_id.clone();
    c.claims.holder_public_key_fingerprint = hex32(&state.public_key_sha256).unwrap();
    crate::tests::resign(&mut c);
    let raw = canonical(&v);
    store.configure(state.expected(), &raw).unwrap();
    (dir, store, c, raw)
}

#[test]
fn current_custody_signs_exact_original_challenge_for_both_applications() {
    for app in [Application::Runtime, Application::Service] {
        let _time = Time::at(100);
        let (_dir, store, c, raw) = configured(app);
        let state = store.public_identity().unwrap();
        let handle = store.open_identity(state.expected()).unwrap();
        let first = handle.present_current_service_challenge(&c).unwrap();
        let proof = UntrustedServiceHolderProof::decode(&first).unwrap();
        assert_eq!(proof.claims, c.claims);
        assert_eq!(proof.issuer_signature, c.issuer_signature);
        assert_eq!(
            proof.holder_policy_digest,
            validate_service_challenge(&ValidatedWalletOwnerInput::parse(&raw).unwrap(), &c, 100)
                .unwrap()
                .wallet_policy_digest()
        );
        let public = VerifyingKey::from_bytes(&hex32(&state.public_key_hex).unwrap()).unwrap();
        let transcript = holder_transcript(&proof, &c.request_bytes).unwrap();
        public
            .verify_strict(&transcript, &Signature::from_bytes(&proof.holder_signature))
            .unwrap();
        assert!(first.len() <= 16_384);
        TEST_NOW.with(|v| v.set(Some(101)));
        assert_eq!(handle.present_current_service_challenge(&c).unwrap(), first);
        assert_eq!(
            (proof.claims.issued_at, proof.claims.expires_at),
            (100, 160)
        );
        // Altering the exact request changes the frozen holder transcript.
        let mut changed = c.request_bytes.clone();
        changed.push(b' ');
        let changed_transcript = holder_transcript(&proof, &changed);
        assert!(
            changed_transcript.is_err()
                || public
                    .verify_strict(
                        &changed_transcript.unwrap(),
                        &Signature::from_bytes(&proof.holder_signature)
                    )
                    .is_err()
        );
    }
}

#[test]
fn signed_substitution_and_expired_or_wrong_application_challenges_deny() {
    for app in [Application::Runtime, Application::Service] {
        let _time = Time::at(100);
        let (_dir, store, c, _) = configured(app);
        let handle = store
            .open_identity(store.public_identity().unwrap().expected())
            .unwrap();
        let mut forged = c.clone();
        forged.issuer_signature[0] ^= 1;
        assert_eq!(
            handle
                .present_current_service_challenge(&forged)
                .unwrap_err(),
            Error::InvalidSignature
        );
        for field in ["holder", "application", "request"] {
            let mut changed = c.clone();
            if field == "holder" {
                changed.claims.holder_subject_id = "service:other".into();
            } else if field == "application" {
                // A fully valid opposite-application transcript reaches the
                // actual custody application check; an impossible opcode/app
                // pairing would fail inside this fixture's signer instead.
                changed=UntrustedSignedServiceChallenge::decode_inner(if c.claims.application==ServiceApplication::RuntimeV1 {
                    include_bytes!("../vendor/secS-service-b/server/tests/fixtures/service-holder-proof-v1/service/challenge.bin")
                } else {
                    include_bytes!("../vendor/secS-service-b/server/tests/fixtures/service-holder-proof-v1/challenge.bin")
                }).unwrap();
                changed.claims.holder_subject_id = c.claims.holder_subject_id.clone();
                changed.claims.holder_key_id = c.claims.holder_key_id.clone();
                changed.claims.holder_public_key_fingerprint =
                    c.claims.holder_public_key_fingerprint;
            } else {
                changed.request_bytes.push(b' ');
                changed.claims.request_length = changed.request_bytes.len() as u64;
                changed.claims.request_sha256 = hash(&changed.request_bytes);
                changed.claims.resource = "other/resource".into();
            }
            crate::tests::resign(&mut changed);
            assert_eq!(
                handle
                    .present_current_service_challenge(&changed)
                    .unwrap_err(),
                Error::Denied,
                "{field}"
            );
        }
        TEST_NOW.with(|v| v.set(Some(160)));
        assert_eq!(
            handle.present_current_service_challenge(&c).unwrap_err(),
            Error::Window
        );
    }
}

#[test]
fn stale_handle_after_reconciliation_rotation_or_revocation_cannot_sign() {
    for action in ["reconcile", "rotate", "revoke"] {
        let _time = Time::at(100);
        let (_dir, store, c, _) = configured(Application::Runtime);
        let state = store.public_identity().unwrap();
        store.cleanup_unreferenced(state.expected()).unwrap();
        let handle = store.open_identity(state.expected()).unwrap();
        match action {
            "reconcile" => {
                store.reconcile_current().unwrap();
            }
            "rotate" => {
                store.rotate(state.expected(), 0, 180).unwrap();
            }
            "revoke" => {
                store.revoke(state.expected()).unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            handle.present_current_service_challenge(&c).unwrap_err(),
            Error::Changed
        );
    }
}

#[test]
fn retained_custody_lock_and_final_clock_deny_postsign_expiry_and_rollback() {
    use castalia_wallet_private_files::service_store::ServiceRoot;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    for app in [Application::Runtime, Application::Service] {
        for final_time in [99, 160] {
            let _time = Time::at(100);
            let (dir, store, c, _) = configured(app);
            let handle = store
                .open_identity(store.public_identity().unwrap().expected())
                .unwrap();
            let path = dir.path().to_path_buf();
            let reached = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&reached);
            TEST_ACTION.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move |label| {
                    if label == "service_holder_before_final_clock" {
                        match ServiceRoot::open(&path).unwrap().lock_exclusive() {
                            Ok(_) => {
                                panic!("holder released real custody lease before final export")
                            }
                            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
                        };
                        counter.fetch_add(1, Ordering::SeqCst);
                        TEST_NOW.with(|v| v.set(Some(final_time)));
                    }
                }))
            });
            assert_eq!(
                handle.present_current_service_challenge(&c).unwrap_err(),
                if final_time == 99 {
                    Error::Clock
                } else {
                    Error::Window
                }
            );
            assert_eq!(reached.load(Ordering::SeqCst), 1);
            TEST_ACTION.with(|hook| *hook.borrow_mut() = None);
            // Every denial releases its owned lease; no dead handle/lock escape.
            let root = ServiceRoot::open(dir.path()).unwrap();
            let exclusive = root.lock_exclusive().unwrap();
            drop(exclusive);
        }
    }
}

#[test]
fn post_sign_owner_file_substitution_is_reloaded_and_denied() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    for app in [Application::Runtime, Application::Service] {
        let _time = Time::at(100);
        let (dir, store, c, _) = configured(app);
        let state = store.public_identity().unwrap();
        let handle = store.open_identity(state.expected()).unwrap();
        let path = dir.path().join(format!(
            "states/s{:016}/owner-input.json",
            state.state_revision
        ));
        // Public policy only; no test reads or returns the temporary raw seed.
        let reached = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reached);
        TEST_ACTION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |label| {
                if label == "service_holder_before_final_reload" {
                    let mut bytes = fs::read(&path).unwrap();
                    bytes.push(b' ');
                    fs::write(&path, bytes).unwrap();
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            }))
        });
        assert_eq!(
            handle.present_current_service_challenge(&c).unwrap_err(),
            Error::Changed
        );
        assert_eq!(reached.load(Ordering::SeqCst), 1);
    }
}
