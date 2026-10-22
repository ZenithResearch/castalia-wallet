//! Create-only finite Service Management authority for the local provider.
//!
//! This is deliberately separate from the stable Frank Runtime identity. Each
//! reviewed generation creates one finite Service application identity and a
//! closed receiver policy. Old generations and their journals remain retained.
use super::*;

const SERVICE_HOLDER: &str = "service:service-management-provider";
const SERVICE_NODE: &str = "node:service-management-provider";
const SERVICE_COMMAND_KEY: &str = "issuer:service-management-provider-v1";
const SERVICE_SCOPE: &str =
    "finite local provider lifecycle authority in one isolated Service Management store";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServicePlan {
    schema: String,
    workspace_root: PathBuf,
    generation: String,
    not_before: String,
    not_after: String,
    wallet_command_sha256: String,
    verifier_sha256: String,
}

fn service_rules() -> Vec<Rule> {
    [
        ("request.create", 0x70, "requests/"),
        ("request.qualify", 0x71, "requests/"),
        ("request.accept", 0x72, "requests/"),
        ("request.reject", 0x73, "requests/"),
        ("request.convert", 0x74, "requests/"),
        ("case.plan", 0x75, "cases/"),
        ("case.plan.approve", 0x76, "cases/"),
        ("case.plan.revise", 0x77, "cases/"),
        ("case.close", 0x78, "cases/"),
        ("request.execution", 0x80, "requests/"),
        ("case.summary", 0x81, "cases/"),
        ("case.plan-history", 0x82, "cases/"),
    ]
    .into_iter()
    .map(|(name, opcode, resource)| Rule {
        name,
        opcode,
        kind: "prefix",
        resource: resource.into(),
    })
    .collect()
}

fn service_descriptor(opcode: u8, operation: &str) -> Result<(Value, String)> {
    let name = format!("service.{operation}.v1");
    let handler = format!("service-management.v1:{operation}");
    let d = OperationDescriptor {
        opcode,
        name: OperationName::new(&name),
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
        disclosure_policy: DisclosurePolicy::deny_by_default("service.provider-command.v1", 1),
    };
    d.validate().map_err(|_| SetupError)?;
    let fingerprint = d
        .authorization_fingerprint()
        .strip_prefix("descriptor:sha256:")
        .ok_or(SetupError)?
        .to_owned();
    Ok((
        json!({"opcode":opcode,"name":name,"payload_schema":"application/json","output_profile":null,
        "target_kind":"receiver_production_handler","required_credentials":[],"required_capabilities":[],
        "accepted_evidence":[],"required_authority_mode":null,"replay_scope":"session_opcode_nonce",
        "max_ttl_seconds":60,"handler_id":handler,"dev_binding":false,"range":"operator_defined",
        "disclosure_policy":{"policy_id":"service.provider-command.v1","policy_version":1,"permissions":[]}}),
        fingerprint,
    ))
}

fn generation_parent(root: &Path) -> Result<PathBuf> {
    let parent = root.join("authority/provider-service");
    match fs::symlink_metadata(&parent) {
        Ok(_) => private_dir(&parent)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => create_dir(&parent)?,
        Err(_) => return Err(SetupError),
    }
    Ok(parent)
}

fn service_preflight(raw: &[u8]) -> Result<(ServicePlan, u64, u64, u64)> {
    let p: ServicePlan = parse(raw, 16384)?;
    ok(p.schema == "castalia.wallet-provider-service-authority.v1")?;
    private_dir(&p.workspace_root)?;
    for leaf in ["config", "data", "native", "authority"] {
        private_dir(&p.workspace_root.join(leaf))?;
    }
    let generation = seconds(&p.generation)?;
    let (start, end, observed) = (seconds(&p.not_before)?, seconds(&p.not_after)?, now()?);
    ok(generation > 0
        && generation <= 64
        && start > 0
        && start <= observed
        && observed < end
        && end <= observed.checked_add(MAX_WINDOW).ok_or(SetupError)?
        && end - start <= MAX_WINDOW
        && end <= 9_007_199_254_740_991
        && pin(&p.wallet_command_sha256)
        && pin(&p.verifier_sha256))?;
    binaries(&Plan {
        schema: "castalia.wallet-workspace-setup.v1".into(),
        workspace_root: p.workspace_root.clone(),
        not_before: p.not_before.clone(),
        not_after: p.not_after.clone(),
        identity_not_after: p.not_after.clone(),
        wallet_command_sha256: p.wallet_command_sha256.clone(),
        verifier_sha256: p.verifier_sha256.clone(),
    })?;
    ok(p.workspace_root
        .join(format!(
            "authority/provider-service/{generation}/config/command-authority.json"
        ))
        .as_os_str()
        .as_bytes()
        .len()
        <= 1024)?;
    Ok((p, generation, start, end))
}

/// Create one reviewed finite Service identity and closed receiver policy.
/// The plan contains no commands, resources, keys or caller-selected policy.
pub fn create_provider_service_from_plan(path: &Path, expected_sha256: &str) -> Result<Value> {
    ok(pin(expected_sha256))?;
    let raw = read(path, 16384, 0o600)?;
    ok(hash(&raw) == expected_sha256)?;
    let (p, generation, start, end) = service_preflight(&raw)?;
    let parent = generation_parent(&p.workspace_root)?;
    let mut count = 0;
    for entry in fs::read_dir(&parent).map_err(|_| SetupError)? {
        let entry = entry.map_err(|_| SetupError)?;
        count += 1;
        let name = entry.file_name();
        let name = name.to_str().ok_or(SetupError)?;
        ok(count <= 64
            && seconds(name).is_ok_and(|value| value > 0)
            && !entry.file_type().map_err(|_| SetupError)?.is_symlink()
            && entry.file_type().map_err(|_| SetupError)?.is_dir())?;
    }
    ok(count < 64)?;
    let base = parent.join(generation.to_string());
    absent(&base)?;
    create_dir(&base)?;
    write(
        &base.join("SETUP-BEGIN.json"),
        &canonical(
            &json!({"schema":"castalia.wallet-provider-service-authority-intent.v1",
            "plan_sha256":expected_sha256,"generation":generation,"started_at":now()?,
            "failure_policy":"retain; owner selects a new generation after reconciliation"}),
        ),
    )?;
    for leaf in [
        "wallet",
        "command-issuer",
        "native",
        "command-journal",
        "config",
    ] {
        create_dir(&base.join(leaf))?;
    }

    let command_public = ServiceAuthority::create_issuer_key(&base.join("command-issuer"))
        .map_err(|_| SetupError)?;
    let store = ServiceIdentityStore::create(
        &base.join("wallet"),
        NewServiceIdentity {
            application: Application::Service,
            subject_id: SERVICE_HOLDER.into(),
            not_before: start,
            not_after: end,
        },
    )
    .map_err(|_| SetupError)?;
    let initial = store.public_identity().map_err(|_| SetupError)?;
    let rules = service_rules();
    let mut descriptors = Vec::new();
    let mut receiver_descriptors = Vec::new();
    let mut seen = BTreeSet::new();
    for rule in &rules {
        ok(seen.insert(rule.opcode))?;
        let (descriptor, fingerprint) = service_descriptor(rule.opcode, rule.name)?;
        let operation = format!("service.{}.v1", rule.name);
        let handler = format!("service-management.v1:{}", rule.name);
        descriptors.push(descriptor);
        receiver_descriptors.push(json!({"operation":operation,"opcode":rule.opcode,
            "fingerprint":fingerprint,"handler_id":handler,"max_ttl_seconds":60}));
    }
    ok(seen.len() == 12)?;
    let delegation_rules: Vec<_> = rules
        .iter()
        .map(|rule| {
            json!({"subject_id":SERVICE_HOLDER,"key_id":initial.key_id,
            "operation":format!("service.{}.v1",rule.name),"resource":rule.resource,
            "resource_match":"prefix","effect":"allow","active":true,
            "not_before":start,"not_after":end})
        })
        .collect();
    let receiver = json!({"schema":"secs.service-receiver-policy.v1","application":"service",
        "audience":ServiceApplication::ServiceV1.audience(),"not_before":start,"not_after":end,
        "max_ttl_seconds":60,"principals":[{"subject_id":SERVICE_HOLDER,"key_id":initial.key_id,
        "not_before":start,"not_after":end,"revoked":false}],"descriptors":receiver_descriptors,
        "rules":delegation_rules});
    let mut issuer = json!({"node_id":SERVICE_NODE,"key_id":SERVICE_COMMAND_KEY,
        "public_key_hex":hex(&command_public),"algorithm":"ed25519","status":"active",
        "not_before":start,"not_after":end,"revoked_at":null,"replaced_by":null});
    let holder = json!({"subject_id":SERVICE_HOLDER,"key_id":initial.key_id,
        "public_key_hex":initial.public_key_hex,"generation":initial.key_generation,"algorithm":"ed25519",
        "status":"active","not_before":start,"not_after":end,"revoked_at":null,"replaced_by":null});
    let owner = json!({"schema":"castalia.wallet-service-owner-input.v1",
        "generation":initial.state_revision+1,"valid_not_before":start,"valid_until":end,
        "application":"service","issuer_node_id":SERVICE_NODE,"selected_issuer_key_id":SERVICE_COMMAND_KEY,
        "issuers":[issuer.clone()],"holder":holder,"descriptors":descriptors,"delegation_policy":receiver});
    let identity = store
        .configure(initial.expected(), &canonical(&owner))
        .map_err(|_| SetupError)?;
    store
        .cleanup_unreferenced(identity.expected())
        .map_err(|_| SetupError)?;

    let public_root = ServiceRoot::open(&base.join("wallet")).map_err(|_| SetupError)?;
    let observed = public_root.lock_public_shared().map_err(|_| SetupError)?;
    let metadata = observed.metadata();
    let state: Value = parse(metadata.state_bytes(), 4096)?;
    let actual_owner: Value = parse(metadata.owner_input_bytes().ok_or(SetupError)?, 262144)?;
    let mut reference = json!({"schema":"secs.wallet-current-reference.v2",
        "current_sha256":hash(metadata.current_bytes()),"custody_state_sha256":hash(metadata.state_bytes()),
        "delegation_policy_sha256":hash(&canonical(&actual_owner["delegation_policy"]))});
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
    observed.revalidate().map_err(|_| SetupError)?;
    drop(observed);
    let startup = json!({"schema":"secs.wallet-current-startup-pin.v2","store_id":state["store_id"],
        "minimum_state_revision":state["state_revision"],"minimum_key_generation":state["key_generation"],
        "expected_wallet_reference_sha256":hash(&canonical(&reference))});
    let wallet = WalletCurrentSource::open(
        OwnerSelectedWalletRoot::open(&base.join("wallet")).map_err(|_| SetupError)?,
        StartupWalletObservationPin::parse_owner_configuration(&canonical(&startup))
            .map_err(|_| SetupError)?,
    )
    .map_err(|_| SetupError)?;
    issuer["production_authority"] = json!(true);
    let mut native_holder = holder.clone();
    native_holder
        .as_object_mut()
        .ok_or(SetupError)?
        .remove("generation");
    native_holder
        .as_object_mut()
        .ok_or(SetupError)?
        .remove("replaced_by");
    let native_permissions: Vec<_> = rules
        .iter()
        .map(|rule| {
            json!({"caller_id":SERVICE_HOLDER,
        "opcode":rule.opcode,"operation":format!("service.{}.v1",rule.name),
        "resource":{"kind":"prefix","prefix":rule.resource},"effect":"allow",
        "not_before":start,"not_after":end,"status":"active","authority_source":"receiver_local"})
        })
        .collect();
    let bundle = json!({"schema":"secs.service-owner-bundle.v2","generation":1,
        "wallet_current":reference,"valid_not_before":start,"valid_until":end,"application":"service",
        "issuer_node_id":SERVICE_NODE,"selected_issuer_key_id":SERVICE_COMMAND_KEY,
        "issuers":[issuer],"holders":[native_holder],"descriptors":descriptors,
        "permissions":native_permissions,"receiver_policy":receiver});
    let native_pin =
        OwnerPublicationSource::create_initial(&base.join("native"), &wallet, &canonical(&bundle))
            .map_err(|_| SetupError)?;

    let configs = base.join("config");
    let mut outputs = BTreeMap::<String, String>::new();
    let mut save = |name: &str, value: Value| -> Result<PathBuf> {
        let bytes = canonical(&value);
        let file = configs.join(name);
        write(&file, &bytes)?;
        outputs.insert(name.into(), hash(&bytes));
        Ok(file)
    };
    let command_configuration = save(
        "command-authority.json",
        json!({
        "schema":"secs.service-authority-configuration.v1","wallet_root":base.join("wallet"),
        "wallet_observation_pin":startup,"native_root":base.join("native"),
        "native_generation":native_pin.generation(),"native_sha256":hex(&native_pin.sha256()),
        "issuer_root":base.join("command-issuer"),"issuer_node_id":SERVICE_NODE,
        "issuer_key_id":SERVICE_COMMAND_KEY,"issuer_public_key_hex":hex(&command_public),
        "journal_root":base.join("command-journal"),"maximum_ttl":30,
        "journal_capacity":"local_review_pilot_512"}),
    )?;
    let binding = identity.binding();
    let expected = identity.expected();
    save(
        "wallet-command.json",
        json!({"schema":"castalia.wallet-service-command.v1",
        "native_configuration":command_configuration,"native_configuration_sha256":hash(&read(&command_configuration,65536,0o600)?),
        "wallet_root":base.join("wallet"),"application":"service",
        "store_binding":{"store_id":binding.store_id,"subject_id":binding.subject_id,"application":"service",
            "purpose":binding.purpose,"minimum_revision":binding.minimum_revision},
        "expected_state":{"state_revision":expected.state_revision,"state_sha256":expected.state_sha256}}),
    )?;
    let service_descriptors: Vec<_> = receiver_descriptors
        .iter()
        .map(|row| {
            json!({
        "operation":row["operation"],"opcode":row["opcode"],"fingerprint":row["fingerprint"],
        "handler_id":row["handler_id"]})
        })
        .collect();
    let service_permissions: Vec<_> = rules
        .iter()
        .map(|rule| {
            json!({
        "subject_id":SERVICE_HOLDER,"key_id":identity.key_id,
        "operation":format!("service.{}.v1",rule.name),"resource":rule.resource,
        "effect":"allow","not_before_ms":start*1000,"not_after_ms":end*1000,
        "resource_match":"prefix","active":true})
        })
        .collect();
    save(
        "service-receiver.json",
        json!({"schema":"service.receiver-policy.v1",
        "audience":ServiceApplication::ServiceV1.audience(),
        "keys":[public_key(SERVICE_COMMAND_KEY,&hex(&command_public),start,end)],
        "descriptors":service_descriptors,"rules":service_permissions,"revoked_subject_keys":[]}),
    )?;

    binaries(&Plan {
        schema: "castalia.wallet-workspace-setup.v1".into(),
        workspace_root: p.workspace_root.clone(),
        not_before: p.not_before.clone(),
        not_after: p.not_after.clone(),
        identity_not_after: p.not_after.clone(),
        wallet_command_sha256: p.wallet_command_sha256.clone(),
        verifier_sha256: p.verifier_sha256.clone(),
    })?;
    ok(hash(&read(path, 16384, 0o600)?) == expected_sha256)?;
    let held = final_wallet(&wallet)?;
    ok(final_window(start, end, start, now()?))?;
    let receipt = json!({"schema":"castalia.wallet-provider-service-authority-complete.v1",
        "plan_sha256":expected_sha256,"root":p.workspace_root,"generation":generation,
        "holder":identity,"native_generation":native_pin.generation(),"native_sha256":hex(&native_pin.sha256()),
        "command_issuer":{"node_id":SERVICE_NODE,"key_id":SERVICE_COMMAND_KEY,
            "public_key_hex":hex(&command_public)},"configuration_hashes":outputs,
        "not_before":start,"not_after":end,"journal_capacity":"local_review_pilot_512",
        "scope":SERVICE_SCOPE,"activation":false,"service_started":false});
    write(&base.join("COMPLETE.json"), &canonical(&receipt))?;
    held.revalidate().map_err(|_| SetupError)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use castalia_wallet_service_holder::service_command::{exchange_pinned, Mode};
    use std::os::unix::fs::PermissionsExt;

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        plan: PathBuf,
        digest: String,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let parent = temp.path().canonicalize().unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
            let root = parent.join("Process-Workspace");
            create_dir(&root).unwrap();
            for leaf in ["config", "data", "native", "authority"] {
                create_dir(&root.join(leaf)).unwrap();
            }
            let binary = b"PUBLIC NONEXECUTABLE PROVIDER SERVICE TEST FIXTURE";
            for name in ["castalia-wallet-service", "process-runtime-secs-check"] {
                let path = root.join("native").join(name);
                write(&path, binary).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o500)).unwrap();
            }
            let current = now().unwrap();
            let value = json!({"schema":"castalia.wallet-provider-service-authority.v1",
                "workspace_root":root,"generation":"1","not_before":(current-30).to_string(),
                "not_after":(current+1800).to_string(),"wallet_command_sha256":hash(binary),
                "verifier_sha256":hash(binary)});
            let raw = canonical(&value);
            let plan = parent.join("provider-service-plan.json");
            write(&plan, &raw).unwrap();
            Self {
                _temp: temp,
                root,
                plan,
                digest: hash(&raw),
            }
        }

        fn setup(&self) -> Value {
            create_provider_service_from_plan(&self.plan, &self.digest).unwrap()
        }

        fn config(&self, name: &str) -> Value {
            parse(
                &read(
                    &self
                        .root
                        .join("authority/provider-service/1/config")
                        .join(name),
                    262144,
                    0o600,
                )
                .unwrap(),
                262144,
            )
            .unwrap()
        }
    }

    #[tokio::test]
    async fn service_authority_issues_exact_request_and_emits_closed_receiver_policy() {
        let fixture = Fixture::new();
        let receipt = fixture.setup();
        assert_eq!(
            receipt["schema"],
            "castalia.wallet-provider-service-authority-complete.v1"
        );
        assert_eq!(receipt["holder"]["application"], "service");
        assert_eq!(receipt["holder"]["subject_id"], SERVICE_HOLDER);
        let policy = fixture.config("service-receiver.json");
        assert_eq!(policy["schema"], "service.receiver-policy.v1");
        assert_eq!(policy["audience"], ServiceApplication::ServiceV1.audience());
        assert_eq!(policy["descriptors"].as_array().unwrap().len(), 12);
        assert_eq!(policy["rules"].as_array().unwrap().len(), 12);
        assert!(policy["rules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|rule| rule["resource_match"] == "prefix"
                && matches!(rule["resource"].as_str(), Some("requests/" | "cases/"))));

        let command = canonical(
            &json!({"schema":"service.command.v1","operation":"request.create",
            "request_id":"create-1","resource":{"kind":"ServiceRequest","id":"request-1"},
            "expected_version":null,"payload":{"summary":"Test intake"}}),
        );
        let path = fixture
            .root
            .join("authority/provider-service/1/config/wallet-command.json");
        let digest = hash(&read(&path, 65536, 0o600).unwrap());
        let mut pin = [0u8; 32];
        for (index, chunk) in digest.as_bytes().chunks_exact(2).enumerate() {
            pin[index] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        let envelope = exchange_pinned(&path, Mode::Issue, pin, &command)
            .await
            .unwrap();
        let value: Value = parse(&envelope, 1048576).unwrap();
        assert_eq!(value["schema"], "service.secs-envelope.v1");
    }

    #[test]
    fn generation_is_create_only_and_changed_or_unbounded_plans_fail_closed() {
        let fixture = Fixture::new();
        fixture.setup();
        assert!(create_provider_service_from_plan(&fixture.plan, &fixture.digest).is_err());

        let mut value: Value = parse(&read(&fixture.plan, 16384, 0o600).unwrap(), 16384).unwrap();
        value["operation"] = json!("request.create");
        let changed = canonical(&value);
        fs::remove_file(&fixture.plan).unwrap();
        write(&fixture.plan, &changed).unwrap();
        assert!(create_provider_service_from_plan(&fixture.plan, &hash(&changed)).is_err());
    }
}
