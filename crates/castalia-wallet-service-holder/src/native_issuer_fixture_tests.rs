//! Strictly cfg(test), synthetic custody/issuer composition. No installed authority,
//! provider, handler dispatch, native key loading or production success adapter.
#![cfg(test)]
use crate::{
    service_authority_snapshot::{OwnerLease, OwnerSource, PreparedOwnerBindings},
    service_challenge_store::*,
    wallet_holder::{
        self,
        tests::{challenge, input, owner, resign, SyntheticHandle},
    },
};
use bincode::Options;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use libsec_core::{service_holder_proof::*, ZenithPacket};
use secs_permissions::{
    AuthoritySource, PermissionEffect, PermissionPolicy, PermissionRecord, PermissionStatus,
    ResourceScope,
};
use secs_service_call_contract::ReceiverPolicy;
use serde_json::{json, Value};
use server::{
    caller::CallerKey,
    identity::{explicit_test_fixture_identity, PublicVerifierKey},
    manifest::ReceiverManifest,
    receipt::AuthenticatorKind,
    service_holder_proof::{
        verify_service_holder_proof_v1, CurrentServiceProofState, ServiceHolderKeyRegistry,
        ServiceIssuerKey, ServiceIssuerKeyRegistry, ValidityWindow,
    },
    verifier::{SignedVerifiedCallContext, VerifiedCallContext, VerifiedSubject},
};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    sync::atomic::{AtomicU64, Ordering},
};
fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
struct Now(AtomicU64);
impl Now {
    fn set(&self, n: u64) {
        self.0.store(n, Ordering::SeqCst)
    }
}
impl Clock for Now {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Fixture {
    wallet: RefCell<Value>,
    dir: tempfile::TempDir,
    source: OwnerSource,
    receiver: ReceiverPolicy,
    issuers: ServiceIssuerKeyRegistry,
    holders: ServiceHolderKeyRegistry,
    manifest: ReceiverManifest,
    permissions: PermissionPolicy,
    issuer_public: VerifyingKey,
    context_signatures: Cell<u64>,
}
impl Fixture {
    fn new() -> Self {
        let wallet = input();
        let mut issuer = wallet["issuers"][0].clone();
        issuer["production_authority"] = json!(true);
        let mut holder = wallet["holder"].clone();
        holder.as_object_mut().unwrap().remove("generation");
        holder.as_object_mut().unwrap().remove("replaced_by");
        let vectors: Value =
            serde_json::from_str(include_str!("../tests/fixtures/delegation-goldens.json"))
                .unwrap();
        let receiver = vectors["vectors"][1]["policy"].clone();
        let permissions = json!([{"caller_id":"holder:fixture","opcode":66,"operation":"runtime.run.create.v1","resource":{"kind":"exact","value":"runs/run-1"},"effect":"allow","not_before":0,"not_after":200,"status":"active","authority_source":"receiver_local"}]);
        let bundle = json!({"schema":"secs.service-owner-bundle.v1","generation":1,"valid_not_before":0,"valid_until":200,"application":"runtime","issuer_node_id":"node:fixture","selected_issuer_key_id":"issuer:key","issuers":[issuer],"holders":[holder],"descriptors":wallet["descriptors"],"permissions":permissions,"receiver_policy":receiver});
        let dir = tempfile::tempdir_in("/private/tmp").unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let raw = serde_json::to_vec(&bundle).unwrap();
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.path().join("owner-generation.json"))
            .unwrap();
        file.write_all(&raw).unwrap();
        drop(file);
        let source = OwnerSource::open(dir.path(), 1, hash(&raw)).unwrap();
        let issuer_public = SigningKey::from_bytes(&[41; 32]).verifying_key();
        let holder_public = SigningKey::from_bytes(&[42; 32]).verifying_key();
        let issuers = ServiceIssuerKeyRegistry::from_keys([ServiceIssuerKey {
            node_id: "node:fixture".into(),
            key: PublicVerifierKey::configured_production_authority(
                "issuer:key",
                "ed25519",
                issuer_public,
            )
            .with_validity_window(Some(0), Some(200)),
        }])
        .unwrap();
        let holders = ServiceHolderKeyRegistry::from_keys([CallerKey::active(
            "holder:key",
            "holder:fixture",
            holder_public,
        )
        .with_validity_window(Some(0), Some(180))])
        .unwrap();
        let manifest =
            ReceiverManifest::new([wallet_holder::tests::descriptor(&wallet["descriptors"][0])]);
        let permissions = PermissionPolicy::new(vec![PermissionRecord {
            caller_id: "holder:fixture".into(),
            opcode: 66,
            operation: "runtime.run.create.v1".into(),
            resource: ResourceScope::Exact {
                value: "runs/run-1".into(),
            },
            effect: PermissionEffect::Allow,
            not_before: 0,
            not_after: 200,
            status: PermissionStatus::Active,
            authority_source: AuthoritySource::ReceiverLocal,
        }])
        .unwrap();
        Self {
            wallet: RefCell::new(wallet),
            dir,
            source,
            receiver: ReceiverPolicy::parse(&serde_json::to_vec(&receiver).unwrap()).unwrap(),
            issuers,
            holders,
            manifest,
            permissions,
            issuer_public,
            context_signatures: Cell::new(0),
        }
    }
    fn challenge(
        &self,
        lease: &OwnerLease<'_>,
        clock: &Now,
    ) -> (UntrustedSignedServiceChallenge, PreparedOwnerBindings) {
        let mut c = challenge(&self.wallet.borrow());
        let prepared = lease
            .prepare_request(
                &c.request_bytes,
                "holder:fixture",
                "holder:key",
                100,
                60,
                clock,
            )
            .unwrap();
        assert_eq!(
            prepared.permission_digest(),
            hash(lease.permission_preimage())
        );
        c.claims.permission_policy_digest = prepared.permission_digest();
        c.claims.registry_snapshot_digest = prepared.registry_digest();
        c.claims.receiver_policy_digest = prepared.receiver_digest();
        c.claims.evidence = prepared.evidence().bindings().clone();
        resign(&mut c);
        (c, prepared)
    }
    fn expected_context(&self, packet: &ZenithPacket) -> VerifiedCallContext {
        let proof = UntrustedServiceHolderProof::decode(&packet.proof).unwrap();
        let c = &proof.claims;
        VerifiedCallContext {
            schema_version: 4,
            context_id: format!("fixture:{}", hex(&c.challenge_id)),
            packet_hash: hash(&bincode::serialize(packet).unwrap()),
            session_id: c.session_id,
            nonce: c.nonce,
            opcode: c.opcode,
            operation: c.operation.clone(),
            resource: Some(c.resource.clone()),
            subject: VerifiedSubject {
                subject_id: c.holder_subject_id.clone(),
                key_id: c.holder_key_id.clone(),
            },
            audience: c.audience.clone(),
            evidence_summary: vec!["synthetic:no-required-evidence".into()],
            proof_metadata: None,
            capability_result: "synthetic:not-qualified".into(),
            credential_result: "synthetic:not-qualified".into(),
            issued_at: c.issued_at,
            expires_at: c.expires_at,
            descriptor_fingerprint: format!("descriptor:sha256:{}", hex(&c.descriptor_fingerprint)),
            replay_scope: "session:opcode:nonce".into(),
            handler_id: Some(c.handler_id.clone()),
        }
    }
    fn signed_context(&self, packet: &ZenithPacket) -> Vec<u8> {
        self.context_signatures
            .set(self.context_signatures.get() + 1);
        let context = self.expected_context(packet);
        // Existing explicit test identity marks the result LocalDevUntrusted. It is
        // deliberately not an artifact that a production receiver should accept.
        bincode::serialize(
            &explicit_test_fixture_identity("issuer:key", [41; 32])
                .sign_context(context)
                .unwrap(),
        )
        .unwrap()
    }
}
struct SyntheticGuard<'a, 's> {
    fixture: &'a Fixture,
    lease: &'a OwnerLease<'s>,
    prepared: &'a PreparedOwnerBindings,
    challenge: &'a UntrustedSignedServiceChallenge,
    clock: &'a Now,
    wallet_digest: [u8; 32],
}
impl AuthorityGuard for SyntheticGuard<'_, '_> {
    fn revalidate(&mut self, input: GuardInput<'_>) -> Result<(), JournalError> {
        fn reject<E>(_: E) -> JournalError {
            JournalError::Rejected
        }
        self.lease
            .revalidate_prepared(self.prepared, self.clock)
            .map_err(reject)?;
        self.lease
            .verify_challenge_origin(input.challenge, self.clock)
            .map_err(reject)?;
        if input.challenge != self.challenge
            || input.evidence != self.prepared.evidence().bytes()
            || input.lineage != self.prepared.registry_digest()
        {
            return Err(JournalError::Rejected);
        }
        let wallet = owner(&self.fixture.wallet.borrow());
        let current =
            wallet_holder::validate_service_challenge(&wallet, input.challenge, self.clock.now())
                .map_err(reject)?;
        if current.wallet_policy_digest() != self.wallet_digest {
            return Err(JournalError::Rejected);
        }
        if input.stage != ExportStage::Pending {
            let packet: ZenithPacket = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(2_113_605)
                .reject_trailing_bytes()
                .deserialize(input.packet)
                .map_err(reject)?;
            let state = CurrentServiceProofState {
                application: ServiceApplication::RuntimeV1,
                issuer_node_id: "node:fixture",
                issuer_keys: &self.fixture.issuers,
                holder_keys: &self.fixture.holders,
                manifest: &self.fixture.manifest,
                receiver_policy: &self.fixture.receiver,
                permissions: &self.fixture.permissions,
                permission_policy_digest: self.prepared.permission_digest(),
                registry_snapshot_digest: self.prepared.registry_digest(),
                evidence: self.prepared.evidence().bindings(),
                wallet_policy_digest: self.wallet_digest,
                wallet_validity: ValidityWindow {
                    not_before: 0,
                    not_after: 180,
                },
                recorded_challenge_digest: hash(
                    &challenge_transcript(&self.challenge.claims, &self.challenge.request_bytes)
                        .map_err(reject)?,
                ),
            };
            let verified = verify_service_holder_proof_v1(&packet, &state, self.clock.now())
                .map_err(reject)?;
            let signed: SignedVerifiedCallContext = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(65536)
                .reject_trailing_bytes()
                .deserialize(input.context)
                .map_err(reject)?;
            let ctx = &signed.context;
            let c = verified.claims();
            // Match the complete expected fixture context, including its unqualified marker.
            if signed.context != self.fixture.expected_context(&packet)
                || signed.signer_key_id != "issuer:key"
                || signed.authenticator_kind != AuthenticatorKind::LocalDevUntrusted
                || ctx.packet_hash != verified.packet_sha256()
                || ctx.issued_at != c.issued_at
                || ctx.expires_at != c.expires_at
                || input.signed_at < ctx.issued_at
                || input.holder_verified_at > input.signed_at
            {
                return Err(JournalError::Rejected);
            }
            self.fixture
                .issuer_public
                .verify_strict(
                    &bincode::serialize(ctx).map_err(reject)?,
                    &Signature::from_slice(&signed.signature).map_err(reject)?,
                )
                .map_err(reject)?;
        }
        self.lease
            .revalidate_prepared(self.prepared, self.clock)
            .map_err(reject)?;
        wallet_holder::validate_service_challenge(&wallet, input.challenge, self.clock.now())
            .map_err(reject)?;
        Ok(())
    }
}
fn packet(c: &UntrustedSignedServiceChallenge, proof: Vec<u8>) -> ZenithPacket {
    ZenithPacket {
        session_id: c.claims.session_id,
        nonce: c.claims.nonce,
        opcode: c.claims.opcode,
        proof,
        claim_ttl: c.claims.ttl_seconds,
        encrypted_payload: c.request_bytes.clone(),
        mac: [0; 16],
    }
}
fn private_dir() -> tempfile::TempDir {
    let d = tempfile::tempdir_in("/private/tmp").unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}
#[tokio::test]
async fn synthetic_crypto_chain_commits_once_restarts_and_cached_current_denial_tombstones() {
    let f = Fixture::new();
    let clock = Now(AtomicU64::new(100));
    let lease = f.source.lease(&clock).unwrap();
    let (c, prepared) = f.challenge(&lease, &clock);
    let wallet = owner(&f.wallet.borrow());
    let digest = wallet_holder::validate_service_challenge(&wallet, &c, 100)
        .unwrap()
        .wallet_policy_digest();
    let mut guard = SyntheticGuard {
        fixture: &f,
        lease: &lease,
        prepared: &prepared,
        challenge: &c,
        clock: &clock,
        wallet_digest: digest,
    };
    let dir = private_dir();
    let journal = Journal::open(dir.path(), Limits::default(), &clock)
        .await
        .unwrap();
    let limited_dir = private_dir();
    let limited = Journal::open(
        limited_dir.path(),
        Limits {
            rows_global: 1,
            rows_per_holder: 1,
            pending_global: 1,
            pending_per_holder: 1,
            ..Limits::default()
        },
        &clock,
    )
    .await
    .unwrap();
    limited
        .persist_pending(
            &c,
            prepared.evidence().bytes(),
            &prepared.registry_digest(),
            &mut guard,
            &clock,
        )
        .await
        .unwrap();
    let mut second_challenge = c.clone();
    second_challenge.claims.challenge_id = [77; 32];
    second_challenge.claims.session_id = [77; 16];
    second_challenge.claims.nonce = [77; 12];
    resign(&mut second_challenge);
    assert!(matches!(
        limited
            .persist_pending(
                &second_challenge,
                prepared.evidence().bytes(),
                &prepared.registry_digest(),
                &mut guard,
                &clock
            )
            .await,
        Err(JournalError::Capacity)
    ));
    assert_eq!(limited.stats(&clock).await.unwrap().rows, 1);
    limited.reject(c.claims.challenge_id, &clock).await.unwrap();
    let rejected = limited.stats(&clock).await.unwrap();
    assert_eq!(rejected.rows, 1);
    assert_eq!(rejected.tombstones, 1);
    assert!(limited
        .pending(c.claims.challenge_id, &mut guard, &clock)
        .await
        .is_err());
    let exported = journal
        .persist_pending(
            &c,
            prepared.evidence().bytes(),
            &prepared.registry_digest(),
            &mut guard,
            &clock,
        )
        .await
        .unwrap();
    assert_eq!(
        exported.challenge.claims.challenge_id,
        c.claims.challenge_id
    );
    assert_eq!(journal.stats(&clock).await.unwrap().pending, 1);
    let reloaded = journal
        .pending(c.claims.challenge_id, &mut guard, &clock)
        .await
        .unwrap();
    assert_eq!(reloaded.challenge, exported.challenge);
    let mut holder = SyntheticHandle::new();
    let p = holder.prepare(&wallet, &exported.challenge, 100).unwrap();
    let proof = holder.present(&wallet, p, || 101).unwrap();
    let packet = packet(&c, proof.clone());
    let raw = bincode::serialize(&packet).unwrap();
    let context = f.signed_context(&packet);
    clock.set(102);
    let times = IssuanceTimes {
        holder_verified_at: 101,
        context_signed_at: 102,
    };
    let mut racing_guard = SyntheticGuard {
        fixture: &f,
        lease: &lease,
        prepared: &prepared,
        challenge: &c,
        clock: &clock,
        wallet_digest: digest,
    };
    let (first, second) = tokio::join!(
        journal.complete(
            c.claims.challenge_id,
            &raw,
            &context,
            times,
            &mut guard,
            &clock
        ),
        journal.complete(
            c.claims.challenge_id,
            &raw,
            &context,
            times,
            &mut racing_guard,
            &clock
        )
    );
    assert!(first.is_ok() || second.is_ok());
    if let (Ok(a), Ok(b)) = (&first, &second) {
        assert_eq!(a, b);
    }
    let done = first.or(second).unwrap();
    assert_eq!(done.context, context);
    assert_eq!(journal.stats(&clock).await.unwrap().completed, 1);
    let duplicate = journal
        .complete(
            c.claims.challenge_id,
            &raw,
            &context,
            times,
            &mut guard,
            &clock,
        )
        .await
        .unwrap();
    assert_eq!(duplicate, done);
    drop(journal);
    let journal = Journal::open(dir.path(), Limits::default(), &clock)
        .await
        .unwrap();
    let cached = journal
        .cached(
            c.claims.challenge_id,
            &proof,
            &c.request_bytes,
            &mut guard,
            &clock,
        )
        .await
        .unwrap();
    assert_eq!(cached, done);
    assert_eq!(f.context_signatures.get(), 1);
    f.wallet.borrow_mut()["delegation_policy"]["rules"][0]["effect"] = json!("deny");
    assert!(journal
        .cached(
            c.claims.challenge_id,
            &proof,
            &c.request_bytes,
            &mut guard,
            &clock
        )
        .await
        .is_err());
    assert_eq!(journal.stats(&clock).await.unwrap().tombstones, 1);
    f.wallet.borrow_mut()["delegation_policy"]["rules"][0]["effect"] = json!("allow");
    assert!(journal
        .cached(
            c.claims.challenge_id,
            &proof,
            &c.request_bytes,
            &mut guard,
            &clock
        )
        .await
        .is_err());
    // Seed custody was never opened. Owner bundle contains public fixtures only.
    assert!(f.dir.path().join("owner-generation.json").exists());
}
#[tokio::test]
async fn synthetic_corrupt_completion_never_exports_and_post_close_expiry_denies() {
    let f = Fixture::new();
    let clock = std::sync::Arc::new(Now(AtomicU64::new(100)));
    let lease = f.source.lease(clock.as_ref()).unwrap();
    let (c, prepared) = f.challenge(&lease, &clock);
    let wallet = owner(&f.wallet.borrow());
    let mut holder = SyntheticHandle::new();
    let p = holder.prepare(&wallet, &c, 100).unwrap();
    let proof = holder.present(&wallet, p, || 101).unwrap();
    let packet = packet(&c, proof);
    let raw = bincode::serialize(&packet).unwrap();
    let mut context = f.signed_context(&packet);
    let mut guard = SyntheticGuard {
        fixture: &f,
        lease: &lease,
        prepared: &prepared,
        challenge: &c,
        clock: &clock,
        wallet_digest: wallet_holder::validate_service_challenge(&wallet, &c, 100)
            .unwrap()
            .wallet_policy_digest(),
    };
    let dir = private_dir();
    let journal = Journal::open(dir.path(), Limits::default(), clock.as_ref())
        .await
        .unwrap();
    journal
        .persist_pending(
            &c,
            prepared.evidence().bytes(),
            &prepared.registry_digest(),
            &mut guard,
            clock.as_ref(),
        )
        .await
        .unwrap();
    clock.set(102);
    *context.last_mut().unwrap() ^= 1;
    assert!(journal
        .complete(
            c.claims.challenge_id,
            &raw,
            &context,
            IssuanceTimes {
                holder_verified_at: 101,
                context_signed_at: 102
            },
            &mut guard,
            clock.as_ref()
        )
        .await
        .is_err());
    assert_eq!(journal.stats(clock.as_ref()).await.unwrap().completed, 0);
    let dir = private_dir();
    clock.set(102);
    let mut journal = Journal::open(dir.path(), Limits::default(), clock.as_ref())
        .await
        .unwrap();
    let later = clock.clone();
    journal.after_close_for_test(move || later.set(160));
    assert!(journal
        .persist_pending(
            &c,
            prepared.evidence().bytes(),
            &prepared.registry_digest(),
            &mut guard,
            clock.as_ref()
        )
        .await
        .is_err());
    assert_eq!(journal.stats(clock.as_ref()).await.unwrap().pending, 0);
}
