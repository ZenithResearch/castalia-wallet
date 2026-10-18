//! Ordinary-library macOS control: actual Native issuer + actual Wallet custody.
//! All stores/keys are disposable, generated through public APIs. No test clocks,
//! copied issuer claims, private Native modules, receiver admission or live grant.
use castalia_wallet_private_files::service_store::ServiceRoot;
use castalia_wallet_service_holder::{
    custody::{Application, ExpectedState, NewServiceIdentity, ServiceIdentityStore},
    ServiceIdentityHandle,
};
use ed25519_dalek::{Signature, VerifyingKey};
use libsec_core::{
    service_holder_proof::{
        challenge_transcript, holder_transcript, ServiceApplication, UntrustedServiceHolderProof,
        UntrustedSignedServiceChallenge,
    },
    ZenithPacket,
};
use serde_json::{json, Value};
use server::{
    manifest::{OpcodeRange, OperationDescriptor, OperationName, ReplayScope, TargetKind},
    privacy::DisclosurePolicy,
    receipt::AuthenticatorKind,
    service_owner_publication::OwnerPublicationSource,
    service_wallet_source::{
        OwnerSelectedWalletRoot, StartupWalletObservationPin, WalletCurrentSource,
    },
    verifier::SignedVerifiedCallContext,
    ServiceAuthority,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(raw: &str) -> [u8; 32] {
    assert_eq!(raw.len(), 64);
    std::array::from_fn(|i| u8::from_str_radix(&raw[2 * i..2 * i + 2], 16).unwrap())
}
fn canonical(v: &Value) -> Vec<u8> {
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(m) => Value::Object(
                m.iter()
                    .map(|(k, v)| (k.clone(), sorted(v)))
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_vec(&sorted(v)).unwrap()
}
fn directory(base: &Path, name: &str) -> PathBuf {
    let path = base.join(name);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}
fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
struct Fixture {
    _root: tempfile::TempDir,
    store: ServiceIdentityStore,
    expected: ExpectedState,
    holder: ServiceIdentityHandle,
    issuer_public: [u8; 32],
    holder_public: [u8; 32],
    app: ServiceApplication,
    request: Vec<u8>,
    configuration: PathBuf,
    command_configuration: PathBuf,
    owner_input: Vec<u8>,
    descriptor: OperationDescriptor,
    holder_policy_digest: [u8; 32],
}
impl Fixture {
    fn new(application: Application, maximum_ttl: u64) -> Self {
        Self::with_selected_request(application, maximum_ttl, None)
    }
    fn with_selected_request(
        application: Application,
        maximum_ttl: u64,
        selected_request: Option<(Vec<u8>, u8)>,
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let wallet_root = directory(&base, "wallet");
        let issuer_root = directory(&base, "issuer");
        let native_root = directory(&base, "native");
        let journal_root = directory(&base, "journal");
        let issuer_public = ServiceAuthority::create_issuer_key(&issuer_root).unwrap();
        assert!(ServiceAuthority::create_issuer_key(&issuer_root).is_err());
        let start = now() - 300;
        let end = now() + 3600;
        let store = ServiceIdentityStore::create(
            &wallet_root,
            NewServiceIdentity {
                application,
                subject_id: "service:disposable-current-chain".into(),
                not_before: start,
                not_after: end,
            },
        )
        .unwrap();
        let identity = store.public_identity().unwrap();
        let (app, app_name, fixture):(_,_,&[u8])=match application {
            Application::Runtime=>(ServiceApplication::RuntimeV1,"runtime",include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/vendor/secS-service-authority-d1ff595/server/tests/fixtures/service-holder-proof-v1/challenge.bin"))),
            Application::Service=>(ServiceApplication::ServiceV1,"service",include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"),"/vendor/secS-service-authority-d1ff595/server/tests/fixtures/service-holder-proof-v1/service/challenge.bin"))),
        };
        // The public fixture supplies only an application request, never issuer claims.
        let default_request = UntrustedSignedServiceChallenge::decode_inner(fixture)
            .unwrap()
            .request_bytes;
        let (request, opcode) = selected_request.unwrap_or({
            (
                default_request,
                match application {
                    Application::Runtime => 0x42,
                    Application::Service => 0x79,
                },
            )
        });
        let intent = secs_service_call_contract::ServiceIntent::parse(
            match application {
                Application::Runtime => secs_service_call_contract::Application::Runtime,
                Application::Service => secs_service_call_contract::Application::Service,
            },
            &request,
        )
        .unwrap();
        let operation = intent.operation();
        let resource = intent.resource();
        let handler = format!("fixture/{operation}");
        let descriptor = OperationDescriptor {
            opcode,
            name: OperationName::new(operation),
            payload_schema: Some("application/json".into()),
            output_profile: None,
            target_kind: TargetKind::ReceiverProductionHandler,
            required_credentials: vec![],
            required_capabilities: vec![],
            accepted_evidence: vec![],
            required_authority_mode: None,
            replay_scope: ReplayScope::SessionOpcodeNonce,
            max_ttl_seconds: 60,
            handler_id: handler.clone(),
            dev_binding: false,
            range: OpcodeRange::OperatorDefined,
            disclosure_policy: DisclosurePolicy::deny_by_default("fixture", 1),
        };
        let fingerprint = descriptor.authorization_fingerprint();
        let fingerprint = fingerprint.strip_prefix("descriptor:sha256:").unwrap();
        let mut native:Value=serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),"/vendor/secS-service-authority-d1ff595/server/tests/fixtures/service-wallet-contract-v3/transition-vectors.json"))).unwrap();
        native = native["vectors"][0]["target_policy"].clone();
        native["application"] = json!(app_name);
        native["valid_not_before"] = json!(start);
        native["valid_until"] = json!(end);
        native["issuer_node_id"] = json!("node:disposable-current-chain");
        native["selected_issuer_key_id"] = json!("issuer:disposable-current-chain");
        native["issuers"] = json!([{"node_id":native["issuer_node_id"],"key_id":native["selected_issuer_key_id"],
            "public_key_hex":hex(&issuer_public),"algorithm":"ed25519","status":"active","not_before":start,"not_after":end,
            "revoked_at":null,"replaced_by":null,"production_authority":true}]);
        native["holders"] = json!([{"subject_id":identity.subject_id,"key_id":identity.key_id,"public_key_hex":identity.public_key_hex,
            "algorithm":"ed25519","status":"active","not_before":start,"not_after":end,"revoked_at":null}]);
        native["descriptors"] = json!([{"opcode":opcode,"name":operation,"payload_schema":"application/json","output_profile":null,
            "target_kind":"receiver_production_handler","required_credentials":[],"required_capabilities":[],"accepted_evidence":[],
            "required_authority_mode":null,"replay_scope":"session_opcode_nonce","max_ttl_seconds":60,"handler_id":handler,
            "dev_binding":false,"range":"operator_defined","disclosure_policy":{"policy_id":"fixture","policy_version":1,"permissions":[]}}]);
        native["permissions"] = json!([{"caller_id":identity.subject_id,"opcode":opcode,"operation":operation,
            "resource":{"kind":"exact","value":resource},"effect":"allow","not_before":start,"not_after":end,"status":"active","authority_source":"receiver_local"}]);
        native["receiver_policy"] = json!({"schema":"secs.service-receiver-policy.v1","application":app_name,"audience":app.audience(),
            "not_before":start,"not_after":end,"max_ttl_seconds":60,
            "principals":[{"subject_id":identity.subject_id,"key_id":identity.key_id,"not_before":start,"not_after":end,"revoked":false}],
            "descriptors":[{"operation":operation,"opcode":opcode,"fingerprint":fingerprint,"handler_id":handler,"max_ttl_seconds":60}],
            "rules":[{"subject_id":identity.subject_id,"key_id":identity.key_id,"operation":operation,"resource":resource,
                "resource_match":"exact","effect":"allow","active":true,"not_before":start,"not_after":end}]});
        let mut issuers = native["issuers"].clone();
        issuers[0]
            .as_object_mut()
            .unwrap()
            .remove("production_authority");
        let mut holder = native["holders"][0].clone();
        holder["generation"] = json!(identity.key_generation);
        holder["replaced_by"] = Value::Null;
        let owner = canonical(
            &json!({"schema":"castalia.wallet-service-owner-input.v1","generation":identity.state_revision+1,
            "valid_not_before":start,"valid_until":end,"application":app_name,"issuer_node_id":native["issuer_node_id"],
            "selected_issuer_key_id":native["selected_issuer_key_id"],"issuers":issuers,"holder":holder,
            "descriptors":native["descriptors"],"delegation_policy":native["receiver_policy"]}),
        );
        let identity = store.configure(identity.expected(), &owner).unwrap();
        // Owner administration explicitly retires the prior revision before
        // opening a signing handle or pinning the current public state.
        store.cleanup_unreferenced(identity.expected()).unwrap();
        let holder = store.open_identity(identity.expected()).unwrap();
        // Independently build startup DATA from actual public files under a real
        // shared observation. Native recaptures and validates it independently.
        let public_root = ServiceRoot::open(&wallet_root).unwrap();
        let observation = public_root.lock_public_shared().unwrap();
        let metadata = observation.metadata();
        let state: Value = serde_json::from_slice(metadata.state_bytes()).unwrap();
        let actual_owner: Value =
            serde_json::from_slice(metadata.owner_input_bytes().unwrap()).unwrap();
        let mut reference = json!({"schema":"secs.wallet-current-reference.v2","current_sha256":hex(&hash(metadata.current_bytes())),
            "custody_state_sha256":hex(&hash(metadata.state_bytes())),"delegation_policy_sha256":hex(&hash(&canonical(&actual_owner["delegation_policy"])))});
        for name in [
            "store_id",
            "subject_id",
            "purpose",
            "application",
            "state_revision",
            "key_generation",
            "state",
            "key_id",
            "public_key_hex",
            "public_key_sha256",
            "not_before",
            "not_after",
            "revoked_at",
            "owner_input_sha256",
        ] {
            reference[name] = state[name].clone();
        }
        observation.revalidate().unwrap();
        drop(observation);
        let startup = json!({"schema":"secs.wallet-current-startup-pin.v2","store_id":state["store_id"],
            "minimum_state_revision":state["state_revision"],"minimum_key_generation":state["key_generation"],
            "expected_wallet_reference_sha256":hex(&hash(&canonical(&reference)))});
        let wallet = WalletCurrentSource::open(
            OwnerSelectedWalletRoot::open(&wallet_root).unwrap(),
            StartupWalletObservationPin::parse_owner_configuration(&canonical(&startup)).unwrap(),
        )
        .unwrap();
        let observed = wallet.capture_shared().unwrap();
        assert_eq!(observed.reference_bytes(), canonical(&reference));
        drop(observed);
        native
            .as_object_mut()
            .unwrap()
            .remove("native_bundle_profile");
        native["schema"] = json!("secs.service-owner-bundle.v2");
        native["generation"] = json!(1);
        native["wallet_current"] = reference;
        let pin =
            OwnerPublicationSource::create_initial(&native_root, &wallet, &canonical(&native))
                .unwrap();
        let configuration = base.join("authority.json");
        private_file(
            &configuration,
            &canonical(&json!({
            "schema":"secs.service-authority-configuration.v1","wallet_root":wallet_root,"wallet_observation_pin":startup,
            "native_root":native_root,"native_generation":pin.generation(),"native_sha256":hex(&pin.sha256()),"issuer_root":issuer_root,
            "issuer_node_id":native["issuer_node_id"],"issuer_key_id":native["selected_issuer_key_id"],"issuer_public_key_hex":hex(&issuer_public),
            "journal_root":journal_root,"maximum_ttl":maximum_ttl})),
        );
        let command_configuration = base.join("command.json");
        let binding = identity.binding();
        let expected = identity.expected();
        private_file(
            &command_configuration,
            &canonical(&json!({
                "schema":"castalia.wallet-service-command.v1",
                "native_configuration":configuration,
                "native_configuration_sha256":hex(&hash(&fs::read(&configuration).unwrap())),
                "wallet_root":wallet_root,
                "application":app_name,
                "store_binding":{
                    "store_id":binding.store_id,"subject_id":binding.subject_id,
                    "application":app_name,"purpose":binding.purpose,
                    "minimum_revision":binding.minimum_revision
                },
                "expected_state":{
                    "state_revision":expected.state_revision,"state_sha256":expected.state_sha256
                }
            })),
        );
        Self {
            _root: root,
            store,
            expected: identity.expected(),
            holder,
            issuer_public,
            holder_public: unhex(&identity.public_key_hex),
            app,
            request,
            configuration,
            command_configuration,
            owner_input: canonical(&actual_owner),
            descriptor,
            holder_policy_digest: hash(&canonical(&actual_owner["delegation_policy"])),
        }
    }
    async fn authority(&self) -> ServiceAuthority {
        ServiceAuthority::open_owner_configuration(&self.configuration)
            .await
            .unwrap()
    }
    async fn prepare(
        &self,
        authority: &ServiceAuthority,
    ) -> (UntrustedSignedServiceChallenge, Vec<u8>) {
        let raw = authority.issue(&self.request).await.unwrap();
        assert_eq!(
            authority.issue(&self.request).await.unwrap(),
            raw,
            "lost-response retry renewed challenge"
        );
        let challenge = UntrustedSignedServiceChallenge::decode_inner(&raw).unwrap();
        VerifyingKey::from_bytes(&self.issuer_public)
            .unwrap()
            .verify_strict(
                &challenge_transcript(&challenge.claims, &self.request).unwrap(),
                &Signature::from_bytes(&challenge.issuer_signature),
            )
            .unwrap();
        let proof = self
            .holder
            .present_current_service_challenge(&challenge)
            .unwrap();
        let decoded = UntrustedServiceHolderProof::decode(&proof).unwrap();
        assert_eq!(decoded.claims, challenge.claims);
        assert_eq!(decoded.issuer_signature, challenge.issuer_signature);
        assert_eq!(decoded.holder_policy_digest, self.holder_policy_digest);
        VerifyingKey::from_bytes(&self.holder_public)
            .unwrap()
            .verify_strict(
                &holder_transcript(&decoded, &self.request).unwrap(),
                &Signature::from_bytes(&decoded.holder_signature),
            )
            .unwrap();
        (challenge, proof)
    }
    async fn exchange(
        &self,
        authority: &ServiceAuthority,
    ) -> (
        UntrustedSignedServiceChallenge,
        Vec<u8>,
        server::ServiceCompletion,
    ) {
        let (challenge, proof) = self.prepare(authority).await;
        let completed = authority.complete(&self.request, &proof).await.unwrap();
        (challenge, proof, completed)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn actual_native_wallet_exchange_preserves_original_context_and_reopened_cache() {
    for application in [Application::Runtime, Application::Service] {
        let f = Fixture::new(application, 60);
        let authority = f.authority().await;
        let (challenge, proof, completed) = f.exchange(&authority).await;
        let signed: SignedVerifiedCallContext =
            bincode::deserialize(&completed.signed_context).unwrap();
        signed
            .verify_ed25519_with_key(
                &VerifyingKey::from_bytes(&f.issuer_public).unwrap(),
                f.app.audience(),
                now(),
            )
            .unwrap();
        VerifyingKey::from_bytes(&f.issuer_public)
            .unwrap()
            .verify_strict(
                &bincode::serialize(&signed.context).unwrap(),
                &Signature::from_slice(&signed.signature).unwrap(),
            )
            .unwrap();
        let identity = f.store.public_identity().unwrap();
        let intent = secs_service_call_contract::ServiceIntent::parse(
            match application {
                Application::Runtime => secs_service_call_contract::Application::Runtime,
                Application::Service => secs_service_call_contract::Application::Service,
            },
            &f.request,
        )
        .unwrap();
        assert_eq!(signed.signer_key_id, "issuer:disposable-current-chain");
        assert_eq!(
            signed.authenticator_kind,
            AuthenticatorKind::Ed25519NodeAndVerifier
        );
        assert_eq!(signed.context.schema_version, 4);
        assert_eq!(signed.context.subject.subject_id, identity.subject_id);
        assert_eq!(signed.context.subject.key_id, identity.key_id);
        assert_eq!(signed.context.operation, intent.operation());
        assert_eq!(signed.context.resource.as_deref(), Some(intent.resource()));
        assert_eq!(signed.context.audience, f.app.audience());
        assert_eq!(signed.context.session_id, challenge.claims.session_id);
        assert_eq!(signed.context.nonce, challenge.claims.nonce);
        assert_eq!(signed.context.opcode, f.descriptor.opcode);
        assert_eq!(
            signed.context.descriptor_fingerprint,
            f.descriptor.authorization_fingerprint()
        );
        assert_eq!(
            signed.context.handler_id.as_deref(),
            Some(f.descriptor.handler_id.as_str())
        );
        assert_eq!(signed.context.replay_scope, "session:opcode:nonce");
        assert!(signed.context.evidence_summary.is_empty());
        assert!(signed.context.proof_metadata.is_none());
        assert!(signed.context.capability_result.is_empty());
        assert!(signed.context.credential_result.is_empty());
        assert_eq!(signed.context.packet_hash, hash(&completed.packet));
        assert_eq!(signed.context.issued_at, challenge.claims.issued_at);
        assert_eq!(signed.context.expires_at, challenge.claims.expires_at);
        assert!(signed.context.issued_at <= now() && now() < signed.context.expires_at);
        let packet: ZenithPacket = bincode::deserialize(&completed.packet).unwrap();
        assert_eq!(packet.session_id, challenge.claims.session_id);
        assert_eq!(packet.nonce, challenge.claims.nonce);
        assert_eq!(packet.proof, proof);
        assert_eq!(packet.claim_ttl, challenge.claims.ttl_seconds);
        assert_eq!(packet.opcode, challenge.claims.opcode);
        assert_eq!(packet.encrypted_payload, f.request);
        assert_eq!(
            authority.complete(&f.request, &proof).await.unwrap(),
            completed
        );
        drop(authority);
        let reopened = f.authority().await;
        assert_eq!(
            reopened.complete(&f.request, &proof).await.unwrap(),
            completed
        );
        assert_eq!(
            f.holder
                .present_current_service_challenge(&challenge)
                .unwrap(),
            proof
        );
    }
}
#[tokio::test(flavor = "current_thread")]
async fn actual_exchange_denies_changed_request_or_holder_signature() {
    for application in [Application::Runtime, Application::Service] {
        for cached in [false, true] {
            for bad_proof in [false, true] {
                let f = Fixture::new(application, 60);
                let authority = f.authority().await;
                let (_, proof) = f.prepare(&authority).await;
                let baseline = if cached {
                    Some(authority.complete(&f.request, &proof).await.unwrap())
                } else {
                    None
                };
                let mut request = f.request.clone();
                let mut supplied = proof.clone();
                if bad_proof {
                    let index = supplied.len() - 1;
                    supplied[index] ^= 1;
                } else {
                    request.push(b' ');
                }
                assert!(authority.complete(&request, &supplied).await.is_err());
                // Failed input must neither substitute nor destroy the valid
                // original Pending/Cached exchange.
                let valid = authority.complete(&f.request, &proof).await.unwrap();
                if let Some(baseline) = baseline {
                    assert_eq!(valid, baseline);
                }
            }
        }
    }
}
#[tokio::test(flavor = "current_thread")]
async fn actual_wallet_revocation_denies_existing_cached_completion() {
    for application in [Application::Runtime, Application::Service] {
        let f = Fixture::new(application, 60);
        let authority = f.authority().await;
        let (challenge, proof, _) = f.exchange(&authority).await;
        f.store.revoke(f.expected.clone()).unwrap();
        assert!(f
            .holder
            .present_current_service_challenge(&challenge)
            .is_err());
        assert!(authority.complete(&f.request, &proof).await.is_err());
    }
}
#[tokio::test(flavor = "current_thread")]
async fn actual_original_window_expiry_denies_wallet_and_native_completion() {
    for application in [Application::Runtime, Application::Service] {
        let f = Fixture::new(application, 5);
        let authority = f.authority().await;
        let raw = authority.issue(&f.request).await.unwrap();
        let challenge = UntrustedSignedServiceChallenge::decode_inner(&raw).unwrap();
        let proof = f
            .holder
            .present_current_service_challenge(&challenge)
            .unwrap();
        while now() < challenge.claims.expires_at {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(f
            .holder
            .present_current_service_challenge(&challenge)
            .is_err());
        assert!(authority.complete(&f.request, &proof).await.is_err());
    }
}

// Command controls use a normal Cargo binary, never the library's cfg(test)
// backend. The retained test-first patch used an optional lookup to assert the
// missing target at runtime. The implemented target is now required at compile time.
fn service_binary() -> &'static str {
    env!("CARGO_BIN_EXE_castalia-wallet-service")
}
fn command_output(
    f: &Fixture,
    mode: &str,
    config: &Path,
    request: &[u8],
    extra: &[&str],
) -> std::process::Output {
    use std::process::{Command, Stdio};
    let mut child = Command::new(service_binary())
        .arg(mode)
        .arg("--config")
        .arg(config)
        .args(extra)
        .env_clear()
        .current_dir(f._root.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let sent = child.stdin.take().unwrap().write_all(request);
    if let Err(error) = sent {
        // A rejected oversize/argument input may close stdin before its sender.
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    child.wait_with_output().unwrap()
}
fn denied(output: std::process::Output) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"castalia wallet service command denied\n");
}
fn decode_hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    assert!(s
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn command_completion(f: &Fixture, output: &std::process::Output) -> server::ServiceCompletion {
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let map = value.as_object().unwrap();
    assert_eq!(map.len(), 3);
    let schema = match f.app {
        ServiceApplication::RuntimeV1 => "runtime.secs-envelope.v1",
        ServiceApplication::ServiceV1 => "service.secs-envelope.v1",
    };
    assert_eq!(map["schema"], schema);
    let result = server::ServiceCompletion {
        packet: decode_hex(map["packet_hex"].as_str().unwrap()),
        signed_context: decode_hex(map["signed_context_hex"].as_str().unwrap()),
    };
    let packet: ZenithPacket = bincode::deserialize(&result.packet).unwrap();
    let proof = UntrustedServiceHolderProof::decode(&packet.proof).unwrap();
    assert_eq!(packet.encrypted_payload, f.request);
    assert_eq!(proof.claims.application, f.app);
    assert_eq!(packet.session_id, proof.claims.session_id);
    assert_eq!(packet.nonce, proof.claims.nonce);
    assert_eq!(packet.claim_ttl, proof.claims.ttl_seconds);
    assert_eq!(packet.opcode, proof.claims.opcode);
    VerifyingKey::from_bytes(&f.issuer_public)
        .unwrap()
        .verify_strict(
            &challenge_transcript(&proof.claims, &f.request).unwrap(),
            &Signature::from_bytes(&proof.issuer_signature),
        )
        .unwrap();
    VerifyingKey::from_bytes(&f.holder_public)
        .unwrap()
        .verify_strict(
            &holder_transcript(&proof, &f.request).unwrap(),
            &Signature::from_bytes(&proof.holder_signature),
        )
        .unwrap();
    let signed: SignedVerifiedCallContext = bincode::deserialize(&result.signed_context).unwrap();
    signed
        .verify_ed25519_with_key(
            &VerifyingKey::from_bytes(&f.issuer_public).unwrap(),
            f.app.audience(),
            now(),
        )
        .unwrap();
    let identity = f.store.public_identity().unwrap();
    let intent = secs_service_call_contract::ServiceIntent::parse(
        match f.app {
            ServiceApplication::RuntimeV1 => secs_service_call_contract::Application::Runtime,
            ServiceApplication::ServiceV1 => secs_service_call_contract::Application::Service,
        },
        &f.request,
    )
    .unwrap();
    assert_eq!(signed.context.subject.subject_id, identity.subject_id);
    assert_eq!(signed.context.subject.key_id, identity.key_id);
    assert_eq!(signed.context.operation, intent.operation());
    assert_eq!(signed.context.resource.as_deref(), Some(intent.resource()));
    assert_eq!(signed.context.packet_hash, hash(&result.packet));
    assert_eq!(signed.context.session_id, proof.claims.session_id);
    assert_eq!(signed.context.nonce, proof.claims.nonce);
    assert_eq!(signed.context.opcode, f.descriptor.opcode);
    assert_eq!(
        signed.context.descriptor_fingerprint,
        f.descriptor.authorization_fingerprint()
    );
    assert_eq!(signed.context.issued_at, proof.claims.issued_at);
    assert_eq!(signed.context.expires_at, proof.claims.expires_at);
    assert!(signed.context.evidence_summary.is_empty());
    assert!(signed.context.proof_metadata.is_none());
    result
}
fn command_configuration(f: &Fixture) -> Value {
    serde_json::from_slice(&fs::read(&f.command_configuration).unwrap()).unwrap()
}
fn altered_configuration(f: &Fixture, name: &str, value: &Value) -> PathBuf {
    let path = f._root.path().canonicalize().unwrap().join(name);
    private_file(&path, &canonical(value));
    path
}

#[test]
fn service_command_binary_issue_and_exact_resume_both_applications() {
    service_binary();
    for app in [Application::Runtime, Application::Service] {
        let f = Fixture::new(app, 60);
        let first = command_output(&f, "issue", &f.command_configuration, &f.request, &[]);
        let result = command_completion(&f, &first);
        let repeated = command_output(&f, "resume", &f.command_configuration, &f.request, &[]);
        assert_eq!(command_completion(&f, &repeated), result);
        assert_eq!(first.stdout, repeated.stdout);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn service_command_resume_lost_issue_holder_and_completion_delivery() {
    service_binary();
    for app in [Application::Runtime, Application::Service] {
        for boundary in ["issue", "holder", "completion"] {
            let f = Fixture::new(app, 60);
            let authority = f.authority().await;
            let raw = authority.issue(&f.request).await.unwrap();
            let challenge = UntrustedSignedServiceChallenge::decode_inner(&raw).unwrap();
            let proof = if boundary == "issue" {
                None
            } else {
                Some(
                    f.holder
                        .present_current_service_challenge(&challenge)
                        .unwrap(),
                )
            };
            let completed = if boundary == "completion" {
                Some(
                    authority
                        .complete(&f.request, proof.as_ref().unwrap())
                        .await
                        .unwrap(),
                )
            } else {
                None
            };
            drop(authority);
            // Drop each producer at its public boundary; no private fault backend
            // and no claim of an actual process kill at these three boundaries.
            let resumed = command_output(&f, "resume", &f.command_configuration, &f.request, &[]);
            let actual = command_completion(&f, &resumed);
            let packet: ZenithPacket = bincode::deserialize(&actual.packet).unwrap();
            let decoded = UntrustedServiceHolderProof::decode(&packet.proof).unwrap();
            assert_eq!(decoded.claims, challenge.claims);
            assert_eq!(decoded.issuer_signature, challenge.issuer_signature);
            if let Some(proof) = proof {
                assert_eq!(packet.proof, proof);
            }
            if let Some(completed) = completed {
                assert_eq!(actual, completed);
            }
            let again = command_output(&f, "resume", &f.command_configuration, &f.request, &[]);
            assert_eq!(resumed.stdout, again.stdout);
            assert_eq!(command_completion(&f, &again), actual);
        }
    }
}

#[test]
fn service_command_resume_missing_and_wrong_exact_request_never_issues() {
    service_binary();
    for app in [Application::Runtime, Application::Service] {
        let f = Fixture::new(app, 60);
        denied(command_output(
            &f,
            "resume",
            &f.command_configuration,
            &f.request,
            &[],
        ));
        let first = command_output(&f, "issue", &f.command_configuration, &f.request, &[]);
        command_completion(&f, &first);
        let mut changed = f.request.clone();
        changed.push(b' '); // valid JSON, distinct exact intent bytes
        denied(command_output(
            &f,
            "resume",
            &f.command_configuration,
            &changed,
            &[],
        ));
        let exact = command_output(&f, "resume", &f.command_configuration, &f.request, &[]);
        assert_eq!(first.stdout, exact.stdout);
        command_completion(&f, &exact);
    }
}

#[test]
fn service_command_completed_output_may_be_discarded_then_explicitly_resumed() {
    use std::process::{Command, Stdio};
    service_binary();
    for app in [Application::Runtime, Application::Service] {
        let f = Fixture::new(app, 60);
        let mut child = Command::new(service_binary())
            .arg("issue")
            .arg("--config")
            .arg(&f.command_configuration)
            .env_clear()
            .current_dir(f._root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&f.request).unwrap();
        let lost = child.wait_with_output().unwrap();
        assert!(lost.status.success());
        assert!(lost.stderr.is_empty());
        let resumed = command_output(&f, "resume", &f.command_configuration, &f.request, &[]);
        command_completion(&f, &resumed);
        let again = command_output(&f, "resume", &f.command_configuration, &f.request, &[]);
        assert_eq!(resumed.stdout, again.stdout);
        command_completion(&f, &again);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn service_command_pending_and_completed_reject_revocation_and_changed_owner() {
    service_binary();
    for app in [Application::Runtime, Application::Service] {
        for cached in [false, true] {
            for change_owner in [false, true] {
                let f = Fixture::new(app, 60);
                let authority = f.authority().await;
                let (_, proof) = f.prepare(&authority).await;
                if cached {
                    authority.complete(&f.request, &proof).await.unwrap();
                }
                drop(authority);
                if change_owner {
                    let mut owner: Value = serde_json::from_slice(&f.owner_input).unwrap();
                    owner["generation"] = json!(f.expected.state_revision + 1);
                    f.store
                        .configure(f.expected.clone(), &canonical(&owner))
                        .unwrap();
                } else {
                    f.store.revoke(f.expected.clone()).unwrap();
                }
                denied(command_output(
                    &f,
                    "resume",
                    &f.command_configuration,
                    &f.request,
                    &[],
                ));
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn service_command_resume_original_expiry_never_renews() {
    service_binary();
    for app in [Application::Runtime, Application::Service] {
        for cached in [false, true] {
            let f = Fixture::new(app, 5);
            let authority = f.authority().await;
            let (challenge, proof) = f.prepare(&authority).await;
            if cached {
                authority.complete(&f.request, &proof).await.unwrap();
            }
            drop(authority);
            while now() < challenge.claims.expires_at {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            denied(command_output(
                &f,
                "resume",
                &f.command_configuration,
                &f.request,
                &[],
            ));
        }
    }
}

#[test]
fn service_command_closed_configuration_and_exact_identity_selection() {
    service_binary();
    let f = Fixture::new(Application::Runtime, 60);
    for case in 0..12 {
        let mut value = command_configuration(&f);
        match case {
            0 => value["unknown"] = json!(true),
            1 => value["store_binding"]["unknown"] = json!(true),
            2 => value["expected_state"]["unknown"] = json!(true),
            3 => value["application"] = json!("service"),
            4 => value["store_binding"]["application"] = json!("service"),
            5 => value["store_binding"]["subject_id"] = json!("service:other"),
            6 => value["store_binding"]["store_id"] = json!("0".repeat(32)),
            7 => value["store_binding"]["purpose"] = json!("generic-signing"),
            8 => value["store_binding"]["minimum_revision"] = json!(f.expected.state_revision + 1),
            9 => value["expected_state"]["state_sha256"] = json!("0".repeat(64)),
            10 => value["expected_state"]["state_revision"] = json!(f.expected.state_revision + 1),
            11 => value["native_configuration_sha256"] = json!("0".repeat(64)),
            _ => unreachable!(),
        }
        let config = altered_configuration(&f, &format!("invalid-{case}.json"), &value);
        denied(command_output(&f, "issue", &config, &f.request, &[]));
    }
    let raw = fs::read_to_string(&f.command_configuration).unwrap();
    for (i, duplicate) in [
        raw.replacen(
            '{',
            "{\"schema\":\"castalia.wallet-service-command.v1\",",
            1,
        ),
        raw.replace(
            "\"store_binding\":{",
            "\"store_binding\":{\"minimum_revision\":1,",
        ),
        raw.replace(
            "\"expected_state\":{",
            "\"expected_state\":{\"state_revision\":1,",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        assert_ne!(duplicate, raw);
        let path = f
            ._root
            .path()
            .canonicalize()
            .unwrap()
            .join(format!("duplicate-{i}.json"));
        private_file(&path, duplicate.as_bytes());
        denied(command_output(&f, "issue", &path, &f.request, &[]));
    }
    let other = Fixture::new(Application::Runtime, 60);
    let other_selection = command_configuration(&other);
    let mut wrong_root = command_configuration(&f);
    assert_eq!(wrong_root["application"], other_selection["application"]);
    // Every Wallet field now validly selects the second real identity. Only the
    // retained first Native configuration/root selection is inconsistent.
    for field in [
        "wallet_root",
        "application",
        "store_binding",
        "expected_state",
    ] {
        wrong_root[field] = other_selection[field].clone();
    }
    let config = altered_configuration(&f, "wrong-native-wallet.json", &wrong_root);
    denied(command_output(&f, "issue", &config, &f.request, &[]));
    // Without the root-equality guard, issue could create first-root Pending
    // before the later holder-key mismatch denies. Observe that side effect.
    // Every denied issue above must leave the first exact request Missing.
    denied(command_output(
        &f,
        "resume",
        &f.command_configuration,
        &f.request,
        &[],
    ));

    let valid = command_output(&f, "issue", &f.command_configuration, &f.request, &[]);
    let completed = command_completion(&f, &valid);
    // Completed has no pending-challenge holder-key check: without root equality
    // it could forward the first Wallet's cached bytes under the second profile.
    denied(command_output(&f, "resume", &config, &f.request, &[]));
    let retained = command_output(&f, "resume", &f.command_configuration, &f.request, &[]);
    assert_eq!(command_completion(&f, &retained), completed);
    assert_eq!(retained.stdout, valid.stdout);
    // The second selection is valid with its own Native root as well; denial is
    // not an invalid StoreBinding, expected state, application or unsafe store.
    let other_valid = command_output(
        &other,
        "issue",
        &other.command_configuration,
        &other.request,
        &[],
    );
    command_completion(&other, &other_valid);
}

#[test]
fn service_command_native_pin_and_closed_native_parser_are_both_required() {
    service_binary();
    let f = Fixture::new(Application::Runtime, 60);
    let original = fs::read(&f.configuration).unwrap();
    let mut changed = original.clone();
    changed.push(b' ');
    fs::write(&f.configuration, &changed).unwrap();
    denied(command_output(
        &f,
        "issue",
        &f.command_configuration,
        &f.request,
        &[],
    ));
    let mut native: Value = serde_json::from_slice(&original).unwrap();
    native["unknown"] = json!(true);
    let native_path = f
        ._root
        .path()
        .canonicalize()
        .unwrap()
        .join("unknown-native.json");
    private_file(&native_path, &canonical(&native));
    let mut config = command_configuration(&f);
    config["native_configuration"] = json!(native_path);
    config["native_configuration_sha256"] = json!(hex(&hash(&canonical(&native))));
    let selected = altered_configuration(&f, "selected-unknown-native.json", &config);
    denied(command_output(&f, "issue", &selected, &f.request, &[]));
    fs::write(&f.configuration, original).unwrap();
    denied(command_output(
        &f,
        "resume",
        &f.command_configuration,
        &f.request,
        &[],
    ));
}

#[test]
fn service_command_unsafe_configuration_storage_denies() {
    use std::os::unix::fs::symlink;
    service_binary();
    let f = Fixture::new(Application::Runtime, 60);
    fs::set_permissions(&f.command_configuration, fs::Permissions::from_mode(0o640)).unwrap();
    denied(command_output(
        &f,
        "issue",
        &f.command_configuration,
        &f.request,
        &[],
    ));
    fs::set_permissions(&f.command_configuration, fs::Permissions::from_mode(0o600)).unwrap();
    let base = f._root.path().canonicalize().unwrap();
    let link = base.join("config-link.json");
    symlink(&f.command_configuration, &link).unwrap();
    denied(command_output(&f, "issue", &link, &f.request, &[]));
    let hard = base.join("config-hardlink.json");
    fs::hard_link(&f.command_configuration, &hard).unwrap();
    denied(command_output(
        &f,
        "issue",
        &f.command_configuration,
        &f.request,
        &[],
    ));
    fs::remove_file(hard).unwrap();
    let unsafe_parent = directory(&base, "unsafe");
    let unsafe_path = unsafe_parent.join("config.json");
    private_file(&unsafe_path, &fs::read(&f.command_configuration).unwrap());
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
    denied(command_output(&f, "issue", &unsafe_path, &f.request, &[]));
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o700)).unwrap();
    denied(command_output(
        &f,
        "resume",
        &f.command_configuration,
        &f.request,
        &[],
    ));
}

#[test]
fn service_command_exact_stdin_bounds_and_closed_cli_deny_without_pending() {
    service_binary();
    for app in [Application::Runtime, Application::Service] {
        let f = Fixture::new(app, 60);
        for invalid in [
            Vec::new(),
            vec![b' '; f.app.max_request_bytes() + 1],
            b"{}".to_vec(),
        ] {
            denied(command_output(
                &f,
                "issue",
                &f.command_configuration,
                &invalid,
                &[],
            ));
        }
        let other = Fixture::new(
            match app {
                Application::Runtime => Application::Service,
                Application::Service => Application::Runtime,
            },
            60,
        );
        denied(command_output(
            &f,
            "issue",
            &f.command_configuration,
            &other.request,
            &[],
        ));
        for flag in [
            "--clock",
            "--key",
            "--policy",
            "--journal",
            "--output",
            "--ttl",
        ] {
            denied(command_output(
                &f,
                "issue",
                &f.command_configuration,
                &f.request,
                &[flag, "1"],
            ));
        }
        denied(command_output(
            &f,
            "automatic",
            &f.command_configuration,
            &f.request,
            &[],
        ));
        denied(command_output(
            &f,
            "resume",
            &f.command_configuration,
            &f.request,
            &[],
        ));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn service_command_pinned_library_hashes_the_consumed_configuration() {
    use castalia_wallet_service_holder::service_command::{exchange_pinned, Mode};
    for app in [Application::Runtime, Application::Service] {
        let f = Fixture::new(app, 60);
        let expected = hash(&fs::read(&f.command_configuration).unwrap());
        let mut wrong = expected;
        wrong[0] ^= 1;
        assert!(
            exchange_pinned(&f.command_configuration, Mode::Issue, wrong, &f.request)
                .await
                .is_err()
        );
        assert!(f.authority().await.resume(&f.request).await.is_err());
        let first = exchange_pinned(&f.command_configuration, Mode::Issue, expected, &f.request)
            .await
            .unwrap();
        let repeated =
            exchange_pinned(&f.command_configuration, Mode::Resume, expected, &f.request)
                .await
                .unwrap();
        assert_eq!(first, repeated);
        let legacy = command_output(&f, "resume", &f.command_configuration, &f.request, &[]);
        command_completion(&f, &legacy);
        assert_eq!(legacy.stdout, first);
    }
}

#[test]
fn service_command_binary_exact_configuration_pin_preserves_legacy_forms() {
    for app in [Application::Runtime, Application::Service] {
        let f = Fixture::new(app, 60);
        let expected = hex(&hash(&fs::read(&f.command_configuration).unwrap()));
        let suffix = ["--config-sha256", expected.as_str()];
        let first = command_output(&f, "issue", &f.command_configuration, &f.request, &suffix);
        let completion = command_completion(&f, &first);
        let repeated = command_output(&f, "resume", &f.command_configuration, &f.request, &suffix);
        assert_eq!(command_completion(&f, &repeated), completion);
        assert_eq!(first.stdout, repeated.stdout);
        let legacy = command_output(&f, "resume", &f.command_configuration, &f.request, &[]);
        assert_eq!(command_completion(&f, &legacy), completion);
        assert_eq!(legacy.stdout, first.stdout);
        // The old issue form remains an actual creation path on a fresh root.
        let old = Fixture::new(app, 60);
        let issued = command_output(&old, "issue", &old.command_configuration, &old.request, &[]);
        command_completion(&old, &issued);
    }
}

#[test]
fn service_command_binary_wrong_and_malformed_configuration_pins_deny_before_issue() {
    for app in [Application::Runtime, Application::Service] {
        let f = Fixture::new(app, 60);
        let expected = hash(&fs::read(&f.command_configuration).unwrap());
        let mut wrong = expected;
        wrong[0] ^= 1;
        let wrong = hex(&wrong);
        let short = "a".repeat(63);
        let long = "a".repeat(65);
        let upper = "A".repeat(64);
        let invalid = "g".repeat(64);
        let valid = hex(&expected);
        for suffix in [
            vec!["--config-sha256", wrong.as_str()],
            vec!["--config-sha256"],
            vec!["--config-sha256", ""],
            vec!["--config-sha256", short.as_str()],
            vec!["--config-sha256", long.as_str()],
            vec!["--config-sha256", upper.as_str()],
            vec!["--config-sha256", invalid.as_str()],
            vec!["--config-sha256", valid.as_str(), "extra"],
            vec![
                "--config-sha256",
                valid.as_str(),
                "--config-sha256",
                valid.as_str(),
            ],
            vec!["--config-sha256=ignored"],
        ] {
            denied(command_output(
                &f,
                "issue",
                &f.command_configuration,
                &f.request,
                &suffix,
            ));
        }
        // Every denial above precedes issuance of this otherwise valid request.
        denied(command_output(
            &f,
            "resume",
            &f.command_configuration,
            &f.request,
            &[],
        ));
        let suffix = ["--config-sha256", valid.as_str()];
        let first = command_output(&f, "issue", &f.command_configuration, &f.request, &suffix);
        let completion = command_completion(&f, &first);
        // Incorrect pins also cannot expose an already Completed cache entry.
        denied(command_output(
            &f,
            "resume",
            &f.command_configuration,
            &f.request,
            &["--config-sha256", wrong.as_str()],
        ));
        let exact = command_output(&f, "resume", &f.command_configuration, &f.request, &suffix);
        assert_eq!(command_completion(&f, &exact), completion);
        assert_eq!(exact.stdout, first.stdout);
    }
}

#[test]
fn service_command_substituted_safe_configuration_cannot_use_the_original_pin() {
    for app in [Application::Runtime, Application::Service] {
        let first = Fixture::new(app, 60);
        let other = Fixture::new(app, 60);
        assert_eq!(first.request, other.request);
        let original = fs::read(&first.command_configuration).unwrap();
        let selected = fs::read(&other.command_configuration).unwrap();
        let expected = hex(&hash(&original));
        let selected_pin = hex(&hash(&selected));
        assert_ne!(expected, selected_pin);
        // Replace only content at the same safe owner-private path. Every field
        // in the substituted configuration validly selects the second real root.
        fs::write(&first.command_configuration, &selected).unwrap();
        denied(command_output(
            &first,
            "issue",
            &first.command_configuration,
            &first.request,
            &["--config-sha256", expected.as_str()],
        ));
        denied(command_output(
            &other,
            "resume",
            &other.command_configuration,
            &other.request,
            &[],
        ));
        fs::write(&first.command_configuration, &original).unwrap();
        denied(command_output(
            &first,
            "resume",
            &first.command_configuration,
            &first.request,
            &[],
        ));
        // The safe substitute is not malformed: with its own digest it succeeds.
        fs::write(&first.command_configuration, &selected).unwrap();
        let accepted = command_output(
            &first,
            "issue",
            &first.command_configuration,
            &first.request,
            &["--config-sha256", selected_pin.as_str()],
        );
        command_completion(&other, &accepted);
        fs::write(&first.command_configuration, &original).unwrap();
        let original_ok = command_output(
            &first,
            "issue",
            &first.command_configuration,
            &first.request,
            &["--config-sha256", expected.as_str()],
        );
        command_completion(&first, &original_ok);
    }
}

// Exact existing Runtime reader requests and opcode table only. The fixture
// generates actual disposable Wallet/issuer keys through public native APIs.
fn service_query_fixture(operation: &str, maximum_ttl: u64) -> Fixture {
    let (payload, opcode) = match operation {
        "work.list" => (json!({"actor_id":"actor-1","limit":1}), 0x63),
        "events.list" => (json!({"after":0,"limit":1}), 0x64),
        "attempt.get" => (
            json!({"run_id":"run-1","step_id":"step-1","attempt_id":"attempt-1"}),
            0x69,
        ),
        "output.get" => (
            json!({"run_id":"run-1","step_id":"step-1","attempt_id":"attempt-1"}),
            0x67,
        ),
        "run.get" => (json!({"run_id":"run-1"}), 0x62),
        "artifact.get" => (json!({"content_hash":"00".repeat(32)}), 0x65),
        "version.get" => (json!({"process_version":"version-1"}), 0x61),
        "receipt.get" => (json!({"receipt_id":"receipt-1"}), 0x66),
        "process.get" => (json!({"process_id":"process-1"}), 0x60),
        "effect.get" => (json!({"effect_id":"effect-1"}), 0x68),
        _ => panic!("unlisted fixture operation"),
    };
    let request =
        canonical(&json!({"schema":"runtime.query.v1","operation":operation,"payload":payload}));
    secs_service_call_contract::ServiceIntent::parse(
        secs_service_call_contract::Application::Runtime,
        &request,
    )
    .unwrap();
    Fixture::with_selected_request(Application::Runtime, maximum_ttl, Some((request, opcode)))
}
fn service_query_packet(
    completed: &server::ServiceCompletion,
) -> (ZenithPacket, UntrustedServiceHolderProof) {
    let packet: ZenithPacket = bincode::deserialize(&completed.packet).unwrap();
    let proof = UntrustedServiceHolderProof::decode(&packet.proof).unwrap();
    (packet, proof)
}

#[test]
fn service_query_binary_all_nine_reads_get_distinct_valid_native_replay_identity() {
    for op in [
        "work.list",
        "events.list",
        "attempt.get",
        "output.get",
        "run.get",
        "artifact.get",
        "version.get",
        "receipt.get",
        "process.get",
    ] {
        let f = service_query_fixture(op, 60);
        let digest = hex(&hash(&fs::read(&f.command_configuration).unwrap()));
        let suffix = ["--config-sha256", digest.as_str()];
        let first = command_output(&f, "query", &f.command_configuration, &f.request, &suffix);
        let a = command_completion(&f, &first);
        let second = command_output(&f, "query", &f.command_configuration, &f.request, &suffix);
        let b = command_completion(&f, &second);
        let (pa, ha) = service_query_packet(&a);
        let (pb, hb) = service_query_packet(&b);
        assert_eq!(pa.encrypted_payload, f.request);
        assert_eq!(pb.encrypted_payload, f.request);
        assert_eq!(ha.claims.operation, format!("runtime.{op}.v1"));
        assert_ne!(ha.claims.challenge_id, hb.claims.challenge_id);
        assert_ne!(pa.session_id, pb.session_id);
        assert_ne!(pa.nonce, pb.nonce);
        assert_ne!(a.packet, b.packet);
        assert_ne!(a.signed_context, b.signed_context);
        // Unpinned syntax remains an explicit, compatible fresh-read form;
        // Frank's trusted launcher must select the pinned form above.
        let third = command_output(&f, "query", &f.command_configuration, &f.request, &[]);
        let c = command_completion(&f, &third);
        let (pc, hc) = service_query_packet(&c);
        assert_ne!(hc.claims.challenge_id, ha.claims.challenge_id);
        assert_ne!(hc.claims.challenge_id, hb.claims.challenge_id);
        assert_ne!(pc.session_id, pa.session_id);
        assert_ne!(pc.nonce, pa.nonce);
        assert_eq!(pc.encrypted_payload, f.request);
    }
}

#[test]
fn service_query_binary_lost_stdout_only_permits_an_explicit_new_read() {
    let f = service_query_fixture("events.list", 60);
    let digest = hex(&hash(&fs::read(&f.command_configuration).unwrap()));
    let suffix = ["--config-sha256", digest.as_str()];
    let discarded = command_output(&f, "query", &f.command_configuration, &f.request, &suffix);
    // The test keeps public output as an oracle, then discards the caller
    // response. This is an ordinary boundary control, not process fault injection.
    let original = command_completion(&f, &discarded);
    let (_, h1) = service_query_packet(&original);
    drop(discarded);
    let next = command_output(&f, "query", &f.command_configuration, &f.request, &suffix);
    let current = command_completion(&f, &next);
    let (_, h2) = service_query_packet(&current);
    assert_ne!(h1.claims.challenge_id, h2.claims.challenge_id);
    assert_eq!(h1.claims.request_sha256, h2.claims.request_sha256);
    assert_eq!(h1.claims.request_length, h2.claims.request_length);
    // Two eligible retained read identities cannot be resolved by raw bytes.
    // No old recovery mode is silently widened into a fresh-poll fallback.
    denied(command_output(
        &f,
        "resume",
        &f.command_configuration,
        &f.request,
        &suffix,
    ));
    denied(command_output(
        &f,
        "issue",
        &f.command_configuration,
        &f.request,
        &suffix,
    ));
    assert_eq!(
        serde_json::from_slice::<Value>(&f.request).unwrap()["payload"]["after"],
        0
    );
}

#[test]
fn service_query_binary_denies_commands_service_and_the_unselected_effect_read() {
    {
        let op = "effect.get";
        let f = service_query_fixture(op, 60);
        let digest = hex(&hash(&fs::read(&f.command_configuration).unwrap()));
        let suffix = ["--config-sha256", digest.as_str()];
        // Explicit normal issue is a valid own-policy positive for the omitted
        // query; its Query denial cannot be credited to a missing descriptor.
        let issued = command_output(&f, "issue", &f.command_configuration, &f.request, &suffix);
        command_completion(&f, &issued);
        denied(command_output(
            &f,
            "query",
            &f.command_configuration,
            &f.request,
            &suffix,
        ));
        let exact = command_output(&f, "resume", &f.command_configuration, &f.request, &suffix);
        assert_eq!(
            command_completion(&f, &exact),
            command_completion(&f, &issued)
        );
    }
    for app in [Application::Runtime, Application::Service] {
        let f = Fixture::new(app, 60);
        let digest = hex(&hash(&fs::read(&f.command_configuration).unwrap()));
        let suffix = ["--config-sha256", digest.as_str()];
        let own = command_output(&f, "issue", &f.command_configuration, &f.request, &suffix);
        command_completion(&f, &own);
        denied(command_output(
            &f,
            "query",
            &f.command_configuration,
            &f.request,
            &suffix,
        ));
        let exact = command_output(&f, "resume", &f.command_configuration, &f.request, &suffix);
        assert_eq!(exact.stdout, own.stdout);
    }
}

#[test]
fn service_query_binary_pin_mismatch_never_acquires_or_exposes_a_read() {
    let f = service_query_fixture("work.list", 60);
    let digest = hash(&fs::read(&f.command_configuration).unwrap());
    let mut wrong = digest;
    wrong[0] ^= 1;
    let wrong = hex(&wrong);
    let digest = hex(&digest);
    let suffix = ["--config-sha256", digest.as_str()];
    denied(command_output(
        &f,
        "query",
        &f.command_configuration,
        &f.request,
        &["--config-sha256", wrong.as_str()],
    ));
    denied(command_output(
        &f,
        "resume",
        &f.command_configuration,
        &f.request,
        &suffix,
    ));
    let first = command_output(&f, "query", &f.command_configuration, &f.request, &suffix);
    command_completion(&f, &first);
    denied(command_output(
        &f,
        "query",
        &f.command_configuration,
        &f.request,
        &["--config-sha256", wrong.as_str()],
    ));
    // Still exactly one identity: a failed pin did not create a second read.
    let cached = command_output(&f, "resume", &f.command_configuration, &f.request, &suffix);
    assert_eq!(
        command_completion(&f, &cached),
        command_completion(&f, &first)
    );
    assert_eq!(cached.stdout, first.stdout);
}

#[test]
fn service_query_binary_revocation_and_expiry_never_turn_resume_into_acquisition() {
    let revoked = service_query_fixture("work.list", 60);
    let digest = hex(&hash(&fs::read(&revoked.command_configuration).unwrap()));
    let suffix = ["--config-sha256", digest.as_str()];
    let first = command_output(
        &revoked,
        "query",
        &revoked.command_configuration,
        &revoked.request,
        &suffix,
    );
    command_completion(&revoked, &first);
    revoked.store.revoke(revoked.expected.clone()).unwrap();
    denied(command_output(
        &revoked,
        "query",
        &revoked.command_configuration,
        &revoked.request,
        &suffix,
    ));
    denied(command_output(
        &revoked,
        "resume",
        &revoked.command_configuration,
        &revoked.request,
        &suffix,
    ));

    let expired = service_query_fixture("events.list", 5);
    let digest = hex(&hash(&fs::read(&expired.command_configuration).unwrap()));
    let suffix = ["--config-sha256", digest.as_str()];
    let first = command_output(
        &expired,
        "query",
        &expired.command_configuration,
        &expired.request,
        &suffix,
    );
    let completed = command_completion(&expired, &first);
    let (_, original) = service_query_packet(&completed);
    while now() < original.claims.expires_at {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    denied(command_output(
        &expired,
        "resume",
        &expired.command_configuration,
        &expired.request,
        &suffix,
    ));
    // Only this explicitly different Query invocation may choose a new window.
    let fresh = command_output(
        &expired,
        "query",
        &expired.command_configuration,
        &expired.request,
        &suffix,
    );
    let next = command_completion(&expired, &fresh);
    let (_, current) = service_query_packet(&next);
    assert_ne!(original.claims.challenge_id, current.claims.challenge_id);
    assert_eq!(
        original.claims.request_sha256,
        current.claims.request_sha256
    );
    assert!(current.claims.issued_at >= original.claims.expires_at);
}
