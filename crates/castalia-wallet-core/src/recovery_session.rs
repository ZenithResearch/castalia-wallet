//! Platform-neutral custody session. The host owns persistence; a candidate is
//! installed only after the host's atomic compare-and-swap has completed.
use crate::{
    OpenedWallet, create_wallet, import_wallet,
    portable::{self, Trust},
};
use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAX: usize = 1_048_576;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
type Result<T> = std::result::Result<T, &'static str>;
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    State {},
    Observe {
        snapshot: String,
    },
    // Host-only migration of an existing encrypted installation. The host must
    // read legacy confirmation from its prior record, not from page input.
    PrepareExisting {
        file: String,
        password: String,
        legacy_confirmed: bool,
        expected_revision: u64,
    },
    Identity {},
    PrepareCreate {
        password: String,
        created_at: u64,
        expected_revision: u64,
    },
    PrepareRestore {
        file: String,
        file_password: String,
        password: String,
        expected_revision: u64,
        data_file: Option<String>,
        data_password: Option<String>,
    },
    PrepareLegacy {
        key: String,
        password: String,
        created_at: u64,
        expected_revision: u64,
    },
    PrepareData {
        file: String,
        password: String,
        previous_contents: Option<Value>,
    },
    ExportData {
        password: String,
        exported_at: u64,
    },
    PrepareTrust {
        trust: Trust,
    },
    ApproveRestoreTrust {
        trust: Trust,
    },
    ActivateMembership {
        proof: Value,
        scoped: bool,
    },
    DataSummary {},
    WalletIdentities {},
    ChainAccounts {},
    PrepareWalletIdentities {
        identities: Value,
        expected_revision: u64,
    },
    // Host-only, explicitly approved runtime policy. Never installed by discovery
    // or serialized into a recovery file/local snapshot.
    ApprovePresentationTrust {
        config: Value,
    },
    PresentationIdentity {},
    PrepareCredentialPresentation {
        request: String,
        now: u64,
    },
    ApproveCredentialPresentation {
        token: String,
        now: u64,
    },
    CancelCredentialPresentation {},
    // Opt-in native graph protocol v2. Historical membership-gated methods stay unchanged.
    GraphAccessIdentityV2 {},
    PrepareResourceOwnerV1 {
        challenge: String,
        binding: crate::resource_owner::Binding,
        now: u64,
    },
    ApproveResourceOwnerV1 {
        token: String,
        now: u64,
    },
    PrepareOperatorAccessV1 {
        challenge: String,
        pin: crate::read_access::IssuerPin,
        now: u64,
    },
    ApproveOperatorAccessV1 {
        token: String,
        now: u64,
    },
    PrepareGraphAccessRequestV2 {
        challenge: String,
        pin: crate::read_access::IssuerPin,
        now: u64,
    },
    ApproveGraphAccessRequestV2 {
        token: String,
        now: u64,
    },
    ApproveGraphReadCredentialV2 {
        challenge: String,
        pin: crate::read_access::IssuerPin,
        now: u64,
    },
    GraphReadCredentialV2 {
        receiver: String,
        now: u64,
    },
    SignGraphReadCallV2 {
        receiver: String,
        call: castalia_wallet_presentation::read_authority::Call,
        now: u64,
    },
    ReviewHolderGrant {
        pin: secs_grant_contract::IssuerPin,
        grant: Box<secs_grant_contract::Grant>,
        now: u64,
    },
    PrepareHolderGrant {
        pin: secs_grant_contract::IssuerPin,
        grant: Box<secs_grant_contract::Grant>,
        now: u64,
    },
    HolderGrants {},
    HolderGrant {
        service: String,
        now: u64,
    },
    DeriveHolderCredential {
        service: String,
        permissions: Option<Vec<secs_grant_contract::Permission>>,
        expires_at: u64,
        now: u64,
    },
    PresentHolderCredential {
        service: String,
        credential: Box<secs_grant_contract::Credential>,
        call: Value,
        now: u64,
    },
    ForgetHolderGrant {
        service: String,
    },
    ExportHolderGrantBackup {},
    PrepareHolderGrantBackup {
        file: String,
    },
    ReadAccessIdentity {},
    PrepareAccessRequest {
        challenge: String,
        pin: crate::read_access::IssuerPin,
        now: u64,
    },
    ApproveAccessRequest {
        token: String,
        now: u64,
    },
    ApproveReadCredential {
        challenge: String,
        pin: crate::read_access::IssuerPin,
        now: u64,
    },
    StoreReadCredential {
        request_id: String,
        credential: castalia_wallet_presentation::read_authority::Credential,
        now: u64,
    },
    ReadCredential {
        receiver: String,
        now: u64,
    },
    SignReadCall {
        receiver: String,
        call: castalia_wallet_presentation::read_authority::Call,
        now: u64,
    },
    ApproveReadAccess {
        challenge: String,
        receiver: String,
        now: u64,
    },
    StoreReadAccess {
        request_id: String,
        secret: String,
        expires_at: u64,
        metadata: Value,
        now: u64,
    },
    ReadAccess {
        receiver: String,
        now: u64,
    },
    ForgetReadAccess {
        receiver: String,
    },
    Unlock {
        snapshot: String,
        password: String,
    },
    ExportRecovery {
        password: String,
    },
    VerifyBackup {
        file: String,
        password: String,
    },
    CommitCandidate {
        token: String,
        expected_revision: u64,
    },
    ConfirmCommit {
        token: String,
        snapshot: String,
    },
    MembershipRequest {
        scope_id: Option<String>,
    },
    Cancel {},
    Lock {},
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: String,
    revision: u64,
    custody: String,
    local: SealedState,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedState {
    schema: String,
    owner: String,
    revision: u64,
    nonce: String,
    ciphertext: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalState {
    backup_verified: bool,
    #[serde(default)]
    legacy_confirmed: bool,
    #[serde(default)]
    contents: Option<Value>,
    #[serde(default)]
    trust: Trust,
    #[serde(default)]
    active_membership: Option<Value>,
    #[serde(default = "installation_id")]
    installation_id: String,
    #[serde(default)]
    access: std::collections::BTreeMap<String, crate::read_access::StoredAccess>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    read_credentials: std::collections::BTreeMap<String, crate::read_access::SignedAccess>,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    holder_grants: std::collections::BTreeMap<String, crate::holder_grants::StoredGrant>,
}
struct Pending {
    token: String,
    expected_revision: u64,
    snapshot: String,
    wallet: Option<OpenedWallet>,
    local: LocalState,
    started: bool,
}
struct SessionPresentation {
    token: String,
    revision: u64,
    prepared: castalia_wallet_presentation::PreparedRequest,
}
#[derive(Default)]
pub struct RecoverySession {
    wallet: Option<OpenedWallet>,
    custody: Option<String>,
    revision: u64,
    local: LocalState,
    pending: Option<Pending>,
    restore_trust: Trust,
    presentation_trust: Option<castalia_wallet_presentation::TrustConfig>,
    presentation: Option<SessionPresentation>,
    access_request: Option<(String, crate::access_request::PreparedAccessRequest)>,
    graph_access_request: Option<(String, crate::access_request::PreparedAccessRequest)>,
    operator_access: Option<(String, crate::access_request::PreparedAccessRequest)>,
    resource_owner: Option<(String, crate::resource_owner::PreparedOwnerClaim)>,
    read_approval: Option<crate::read_access::Challenge>,
    credential_approval: Option<(
        crate::read_access::Challenge,
        castalia_wallet_presentation::read_authority::Policy,
    )>,
}

impl RecoverySession {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn invoke(&mut self, raw: &str) -> Result<Value> {
        if raw.is_empty() || raw.len() > MAX * 3 {
            self.presentation = None;
            return Err("request_too_large");
        }
        // A malformed invocation cannot leave an earlier signing preview live.
        let command: Command = match portable::parse_unique(raw)
            .map_err(|_| "invalid_request")
            .and_then(|_| serde_json::from_str(raw).map_err(|_| "invalid_request"))
        {
            Ok(command) => command,
            Err(error) => {
                self.presentation = None;
                return Err(error);
            }
        };
        if !matches!(
            &command,
            Command::State {}
                | Command::Identity {}
                | Command::ReadAccessIdentity {}
                | Command::ApproveAccessRequest { .. }
        ) {
            self.access_request = None;
        }
        // A new preparation attempt invalidates any older preview, including
        // when its validation subsequently fails.
        if matches!(
            &command,
            Command::PrepareExisting { .. }
                | Command::PrepareHolderGrant { .. }
                | Command::PrepareHolderGrantBackup { .. }
                | Command::ForgetHolderGrant { .. }
                | Command::PrepareCreate { .. }
                | Command::PrepareRestore { .. }
                | Command::PrepareLegacy { .. }
                | Command::PrepareData { .. }
                | Command::PrepareWalletIdentities { .. }
                | Command::PrepareTrust { .. }
                | Command::VerifyBackup { .. }
                | Command::ActivateMembership { .. }
                | Command::StoreReadAccess { .. }
                | Command::StoreReadCredential { .. }
                | Command::ForgetReadAccess { .. }
        ) {
            self.pending = None;
        }
        if !matches!(
            &command,
            Command::State {}
                | Command::GraphAccessIdentityV2 {}
                | Command::ApproveGraphAccessRequestV2 { .. }
        ) {
            self.graph_access_request = None;
        }
        if !matches!(
            &command,
            Command::State {}
                | Command::GraphAccessIdentityV2 {}
                | Command::ApproveOperatorAccessV1 { .. }
        ) {
            self.operator_access = None;
        }
        // Only state inspection and final consent retain a first-owner review.
        // Another operation, including a failed new prepare, invalidates it.
        if !matches!(
            &command,
            Command::State {} | Command::ApproveResourceOwnerV1 { .. }
        ) {
            self.resource_owner = None;
        }
        // Passive reads cannot transfer consent. Every other operation invalidates
        // a pending presentation, even an unsuccessful mutation or new preparation.
        if !matches!(
            &command,
            Command::State {}
                | Command::Identity {}
                | Command::DataSummary {}
                | Command::PresentationIdentity {}
                | Command::ApproveCredentialPresentation { .. }
        ) {
            self.presentation = None;
        }
        match command {
            Command::ReviewHolderGrant { pin, grant, now } => {
                let stored = crate::holder_grants::StoredGrant::review(
                    self.graph_wallet_v2()?,
                    pin,
                    *grant,
                    &self.local.installation_id,
                    now,
                )?;
                Ok(stored.summary())
            }
            Command::PrepareHolderGrant { pin, grant, now } => {
                let stored = crate::holder_grants::StoredGrant::review(
                    self.graph_wallet_v2()?,
                    pin,
                    *grant,
                    &self.local.installation_id,
                    now,
                )?;
                let mut local = self.local.clone();
                if !local.holder_grants.contains_key(&stored.pin.service)
                    && local.holder_grants.len() >= 128
                {
                    return Err("grant_capacity");
                }
                local
                    .holder_grants
                    .insert(stored.pin.service.clone(), stored);
                crate::holder_grants::validate_capacity(&local.holder_grants)?;
                self.prepare(None, self.custody.clone().ok_or("wallet_locked")?, local)
            }
            Command::HolderGrants {} => {
                self.open_wallet()?;
                Ok(
                    json!({"schema":"castalia.holder-grant-list.v1","grants":self.local.holder_grants.values().map(|g|g.summary()).collect::<Vec<_>>()}),
                )
            }
            Command::HolderGrant { service, now } => {
                self.graph_wallet_v2()?;
                let g = self
                    .local
                    .holder_grants
                    .get(&service)
                    .ok_or("grant_not_saved")?;
                secs_grant_contract::verify_grant(&g.pin, &g.grant, now)?;
                serde_json::to_value(g).map_err(|_| "encoding_failed")
            }
            Command::DeriveHolderCredential {
                service,
                permissions,
                expires_at,
                now,
            } => {
                let wallet = self.graph_wallet_v2()?;
                let g = self
                    .local
                    .holder_grants
                    .get(&service)
                    .ok_or("grant_not_saved")?;
                serde_json::to_value(g.derive(
                    wallet,
                    permissions,
                    &self.local.installation_id,
                    now,
                    expires_at,
                )?)
                .map_err(|_| "encoding_failed")
            }
            Command::PresentHolderCredential {
                service,
                credential,
                call,
                now,
            } => {
                let wallet = self.graph_wallet_v2()?;
                let g = self
                    .local
                    .holder_grants
                    .get(&service)
                    .ok_or("grant_not_saved")?;
                g.present(wallet, &credential, &call, now)
            }
            Command::ForgetHolderGrant { service } => {
                self.open_wallet()?;
                let mut local = self.local.clone();
                local.holder_grants.remove(&service);
                self.prepare(None, self.custody.clone().ok_or("wallet_locked")?, local)
            }
            Command::ExportHolderGrantBackup {} => {
                let wallet = self.graph_wallet_v2()?;
                let contents = json!({"schema":"castalia.holder-grant-backup.v1","owner_public_key":wallet.public_key_hex(),"grants":self.local.holder_grants});
                let file = wallet
                    .seal_identity_section(&contents.to_string())
                    .map_err(|_| "encoding_failed")?;
                Ok(json!({"file":file.as_str()}))
            }
            Command::PrepareHolderGrantBackup { file } => {
                let wallet = self.graph_wallet_v2()?;
                let opened = wallet
                    .open_identity_section(file.as_bytes())
                    .map_err(|_| "invalid_grant_backup")?;
                let grants = crate::holder_grants::parse_backup(wallet, &opened)?;
                let mut local = self.local.clone();
                for (service, g) in grants {
                    if let Some(old) = local.holder_grants.get(&service)
                        && secs_grant_contract::digest(old)? != secs_grant_contract::digest(&g)?
                    {
                        return Err("grant_backup_conflict");
                    }
                    local.holder_grants.insert(service, g);
                }
                crate::holder_grants::validate_capacity(&local.holder_grants)?;
                self.prepare(None, self.custody.clone().ok_or("wallet_locked")?, local)
            }
            Command::PrepareResourceOwnerV1 {
                challenge,
                binding,
                now,
            } => {
                let wallet = self.graph_wallet_v2()?;
                let prepared = crate::resource_owner::PreparedOwnerClaim::prepare(
                    &challenge,
                    &binding,
                    &wallet.public_key_hex(),
                    now,
                )?;
                let token = installation_id();
                let summary = prepared.summary();
                self.resource_owner = Some((token.clone(), prepared));
                Ok(json!({"token":token,"summary":summary}))
            }
            Command::ApproveResourceOwnerV1 { token, now } => {
                let (expected, prepared) = self
                    .resource_owner
                    .take()
                    .ok_or("owner_approval_unavailable")?;
                if token != expected {
                    return Err("owner_context_changed");
                }
                prepared.approve(self.graph_wallet_v2()?, now)
            }
            Command::PrepareOperatorAccessV1 {
                challenge,
                pin,
                now,
            } => {
                let wallet = self.graph_wallet_v2()?;
                let prepared =
                    crate::access_request::PreparedAccessRequest::prepare_native_operator(
                        &challenge,
                        &wallet.public_key_hex(),
                        &self.local.installation_id,
                        &pin,
                        now,
                    )?;
                let token = installation_id();
                let mut summary = prepared.summary();
                summary["kind"] = json!("operator_access");
                summary["native_protocol"] = json!("castalia.operator-access.v1");
                self.operator_access = Some((token.clone(), prepared));
                Ok(json!({"token":token,"summary":summary}))
            }
            Command::ApproveOperatorAccessV1 { token, now } => {
                let (expected, prepared) = self
                    .operator_access
                    .take()
                    .ok_or("access_approval_unavailable")?;
                if token != expected {
                    return Err("access_context_changed");
                }
                prepared.approve(self.graph_wallet_v2()?, now)
            }
            Command::GraphAccessIdentityV2 {} => {
                let wallet = self.graph_wallet_v2()?;
                Ok(
                    json!({"protocol":"castalia.graph-access.v2","subject_public_key":wallet.public_key_hex(),"installation_id":self.local.installation_id}),
                )
            }
            Command::PrepareGraphAccessRequestV2 {
                challenge,
                pin,
                now,
            } => {
                let wallet = self.graph_wallet_v2()?;
                let prepared = crate::access_request::PreparedAccessRequest::prepare_native(
                    &challenge,
                    &wallet.public_key_hex(),
                    &self.local.installation_id,
                    &pin,
                    now,
                )?;
                let token = installation_id();
                let mut summary = prepared.summary();
                summary["native_protocol"] = json!("castalia.graph-access.v2");
                self.graph_access_request = Some((token.clone(), prepared));
                Ok(json!({"token":token,"summary":summary}))
            }
            Command::ApproveGraphAccessRequestV2 { token, now } => {
                let (expected, prepared) = self
                    .graph_access_request
                    .take()
                    .ok_or("access_approval_unavailable")?;
                if token != expected {
                    return Err("access_context_changed");
                }
                let mut approved = prepared.approve(self.graph_wallet_v2()?, now)?;
                approved["proof"] = self
                    .local
                    .active_membership
                    .clone()
                    .unwrap_or_else(|| json!({}));
                Ok(approved)
            }
            Command::ApproveGraphReadCredentialV2 {
                challenge,
                pin,
                now,
            } => {
                self.credential_approval = None;
                let wallet = self.graph_wallet_v2()?;
                let parsed = crate::read_access::Challenge::parse(
                    &challenge,
                    &wallet.public_key_hex(),
                    &self.local.installation_id,
                    &pin.receiver,
                    now,
                )?;
                let policy: castalia_wallet_presentation::read_authority::Policy =
                    serde_json::from_value(
                        parsed
                            .details
                            .get("authority_policy")
                            .ok_or("invalid_request")?
                            .clone(),
                    )
                    .map_err(|_| "invalid_request")?;
                pin.check(&policy)?;
                if policy.issuer != parsed.issuer
                    || policy.receiver != parsed.receiver
                    || parsed.credential_expires_at - parsed.issued_at > policy.max_lifetime_seconds
                {
                    return Err("invalid_request");
                }
                let signature = wallet
                    .sign(&parsed.transcript()?)
                    .map_err(|_| "signing_failed")?;
                let result = json!({"challenge":parsed,"proof":self.local.active_membership.clone().unwrap_or_else(|| json!({})),"signature":URL_SAFE_NO_PAD.encode(signature)});
                self.credential_approval = Some((parsed, policy));
                Ok(result)
            }
            Command::GraphReadCredentialV2 { receiver, now } => {
                self.graph_wallet_v2()?;
                let access = self
                    .local
                    .read_credentials
                    .get(&receiver)
                    .ok_or("access_setup_required")?;
                castalia_wallet_presentation::read_authority::verify_credential(
                    &access.policy,
                    &access.credential,
                    now,
                )?;
                serde_json::to_value(access).map_err(|_| "encoding_failed")
            }
            Command::SignGraphReadCallV2 {
                receiver,
                call,
                now,
            } => {
                let wallet = self.graph_wallet_v2()?;
                let access = self
                    .local
                    .read_credentials
                    .get(&receiver)
                    .ok_or("access_setup_required")?;
                let mut proof = access.unsigned_call(
                    &call,
                    installation_id(),
                    &wallet.public_key_hex(),
                    &self.local.installation_id,
                    now,
                )?;
                proof.signature = hex::encode(
                    wallet
                        .sign(&proof.transcript()?)
                        .map_err(|_| "signing_failed")?,
                );
                Ok(json!({"credential":access.credential,"call":call,"proof":proof}))
            }
            Command::State {} => Ok(self.state()),
            Command::Identity {} => {
                let wallet = self.open_wallet()?;
                Ok(json!({"ownerPublicKey":wallet.public_key_hex(),
                    "mlDsa65PublicKey":wallet.ml_dsa_public_key_base64url(),
                    "mlDsa65PublicKeyCommitment":wallet.ml_dsa_public_key_commitment_hex()}))
            }
            Command::PrepareExisting {
                file,
                password,
                legacy_confirmed,
                expected_revision,
            } => {
                self.require_empty(expected_revision)?;
                let password = Zeroizing::new(password);
                let wallet =
                    import_wallet(file.as_bytes(), &password).map_err(|_| "unlock_failed")?;
                let local = LocalState {
                    legacy_confirmed,
                    ..LocalState::default()
                };
                self.prepare(Some(wallet), file, local)
            }
            Command::Observe { snapshot } => {
                if self.wallet.is_some() || self.pending.is_some() {
                    return Err("session_busy");
                }
                let value = parse_snapshot(&snapshot)?;
                self.revision = value.revision;
                self.custody = Some(value.custody);
                Ok(self.state())
            }
            Command::PrepareCreate {
                password,
                created_at,
                expected_revision,
            } => {
                let password = Zeroizing::new(password);
                new_password(&password)?;
                self.require_empty(expected_revision)?;
                if created_at > MAX_SAFE {
                    return Err("invalid_time");
                }
                let (wallet, custody) =
                    create_wallet(&password, created_at).map_err(|_| "creation_failed")?;
                self.prepare(Some(wallet), custody.to_string(), LocalState::default())
            }
            Command::PrepareRestore {
                file,
                file_password,
                password,
                expected_revision,
                data_file,
                data_password,
            } => {
                let file_password = Zeroizing::new(file_password);
                let password = Zeroizing::new(password);
                self.require_empty(expected_revision)?;
                new_password(&password)?;
                if portable::parse_unique(&file)?["schema"] == "castalia.castaway.v1" {
                    return Err("data_file_requires_recovery");
                }
                let wallet = import_wallet(file.as_bytes(), &file_password)
                    .map_err(|_| "recovery_file_invalid")?;
                let custody = wallet
                    .export_randomized(&password)
                    .map_err(|_| "recovery_failed")?;
                let contents = match (data_file, data_password) {
                    (Some(file), Some(secret)) => Some(portable::import(
                        &wallet,
                        &file,
                        &Zeroizing::new(secret),
                        &self.restore_trust,
                    )?),
                    (None, None) => None,
                    _ => return Err("data_password_required"),
                };
                let local = LocalState {
                    backup_verified: true,
                    legacy_confirmed: false,
                    contents,
                    trust: self.restore_trust.clone(),
                    active_membership: None,
                    installation_id: installation_id(),
                    access: Default::default(),
                    read_credentials: Default::default(),
                    holder_grants: Default::default(),
                };
                self.prepare(Some(wallet), custody.to_string(), local)
            }
            Command::PrepareLegacy {
                key,
                password,
                created_at,
                expected_revision,
            } => {
                self.require_empty(expected_revision)?;
                new_password(&password)?;
                if created_at > MAX_SAFE {
                    return Err("invalid_time");
                }
                let key = Zeroizing::new(key);
                let password = Zeroizing::new(password);
                let parts: Vec<_> = key.split('.').collect();
                if parts.len() != 3 || parts[0] != "castalia-recovery-key-v1" {
                    return Err("legacy_key_invalid");
                }
                let seed = Zeroizing::new(
                    crate::decode_exact::<32>(parts[1]).map_err(|_| "legacy_key_invalid")?,
                );
                let checksum =
                    crate::decode_exact::<4>(parts[2]).map_err(|_| "legacy_key_invalid")?;
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"castalia/recovery-key/v1\0");
                hasher.update(seed.as_ref());
                if !bool::from(checksum.ct_eq(&hasher.finalize().as_bytes()[..4])) {
                    return Err("legacy_key_invalid");
                }
                let wallet = OpenedWallet::from_signing_key(
                    ed25519_dalek::SigningKey::from_bytes(&seed),
                    created_at,
                );
                let custody = wallet
                    .export_randomized(&password)
                    .map_err(|_| "recovery_failed")?;
                self.prepare(Some(wallet), custody.to_string(), LocalState::default())
            }
            Command::ChainAccounts {} => serde_json::from_str(
                &self
                    .open_wallet()?
                    .chain_accounts()
                    .map_err(|_| "account_validation_failed")?,
            )
            .map_err(|_| "account_validation_failed"),
            Command::WalletIdentities {} => {
                let owner = self.open_wallet()?.public_key_hex();
                let records = self
                    .local
                    .contents
                    .as_ref()
                    .and_then(|v| v["sections"].get("walletIdentities"))
                    .cloned()
                    .unwrap_or_else(|| crate::wallet_identities::empty(&owner));
                crate::wallet_identities::validate(&records, &owner)
            }
            Command::PrepareWalletIdentities {
                identities,
                expected_revision,
            } => {
                if expected_revision != self.revision {
                    return Err("preview_stale");
                }
                let wallet = self.open_wallet()?;
                let old = self
                    .local
                    .contents
                    .clone()
                    .unwrap_or(portable::empty_contents(wallet, 0)?);
                let next =
                    portable::with_wallet_identities(&old, &identities, &wallet.public_key_hex())?;
                portable::validate(wallet, &next, &self.local.trust)?;
                let mut local = self.local.clone();
                local.contents = Some(next);
                self.prepare(None, self.custody.clone().ok_or("wallet_locked")?, local)
            }
            Command::PrepareData {
                file,
                password,
                previous_contents,
            } => {
                let password = Zeroizing::new(password);
                let wallet = self.open_wallet()?;
                let incoming = portable::import(wallet, &file, &password, &self.local.trust)?;
                let old = previous_contents
                    .or_else(|| self.local.contents.clone())
                    .unwrap_or(portable::empty_contents(wallet, 0)?);
                portable::validate(wallet, &old, &self.local.trust)?;
                let mut next = old.clone();
                next["sections"]["identity"] = incoming["sections"]["identity"].clone();
                for field in ["memberships", "scopedMemberships"] {
                    if let Some(incoming) = incoming["sections"].get(field) {
                        let mut merged = old["sections"][field]
                            .as_array()
                            .cloned()
                            .unwrap_or_default();
                        for p in incoming.as_array().ok_or("invalid_contents")? {
                            if let Some(index) = merged
                                .iter()
                                .position(|old| old["membershipId"] == p["membershipId"])
                            {
                                merged[index] = p.clone()
                            } else {
                                merged.push(p.clone())
                            }
                        }
                        next["sections"][field] = json!(merged);
                    }
                }
                if let Some(a) = incoming["sections"].get("chainAccounts") {
                    next["sections"]["chainAccounts"] = a.clone();
                }
                // Preserve committed identities even if a host supplies an older profile snapshot.
                let owner = wallet.public_key_hex();
                let committed = self
                    .local
                    .contents
                    .as_ref()
                    .and_then(|v| v["sections"].get("walletIdentities"));
                let previous = old["sections"].get("walletIdentities");
                let incoming_ids = incoming["sections"].get("walletIdentities");
                if committed.is_some() || previous.is_some() || incoming_ids.is_some() {
                    let mut identities = crate::wallet_identities::empty(&owner);
                    for section in [committed, previous, incoming_ids].into_iter().flatten() {
                        identities = crate::wallet_identities::merge(&identities, section, &owner)?;
                    }
                    next = portable::with_wallet_identities(&next, &identities, &owner)?;
                }
                portable::validate(wallet, &next, &self.local.trust)?;
                let mut local = self.local.clone();
                local.contents = Some(next);
                let mut preview =
                    self.prepare(None, self.custody.clone().ok_or("wallet_locked")?, local)?;
                preview["imported_wallet_identities"] = json!(
                    incoming["sections"]["walletIdentities"]["accounts"]
                        .as_array()
                        .map_or(0, Vec::len)
                );
                preview["replaces_profile"] =
                    json!(old["sections"]["identity"] != incoming["sections"]["identity"]);
                preview["replaced_proofs"] = json!(
                    ["memberships", "scopedMemberships"]
                        .iter()
                        .flat_map(|f| incoming["sections"][*f]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter(|p| old["sections"][*f]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .any(|v| v["membershipId"] == p["membershipId"] && v != *p))
                            .map(|p| p["membershipId"].clone()))
                        .collect::<Vec<_>>()
                );
                Ok(preview)
            }
            Command::ExportData {
                password,
                exported_at,
            } => {
                let password = Zeroizing::new(password);
                new_password(&password)?;
                let wallet = self.open_wallet()?;
                let contents = self
                    .local
                    .contents
                    .clone()
                    .unwrap_or(portable::empty_contents(wallet, exported_at)?);
                Ok(
                    json!({"file":portable::export(wallet,&contents,&password,exported_at,&self.local.trust)?.as_str(),"extension":"castaway"}),
                )
            }
            Command::ApproveRestoreTrust { trust } => {
                self.require_empty(0)?;
                trust.validate()?;
                self.pending = None;
                self.restore_trust = trust;
                Ok(self.state())
            }
            Command::PrepareTrust { trust } => {
                self.open_wallet()?;
                trust.validate()?;
                let mut local = self.local.clone();
                // Re-approving an identical configuration does not revoke the
                // person's existing activation or read connection.
                if serde_json::to_value(&local.trust).map_err(|_| "invalid_trust")?
                    != serde_json::to_value(&trust).map_err(|_| "invalid_trust")?
                {
                    local.active_membership = None;
                    local.access.clear();
                    local.read_credentials.clear();
                    self.read_approval = None;
                    self.credential_approval = None;
                }
                local.trust = trust;
                self.prepare(None, self.custody.clone().ok_or("wallet_locked")?, local)
            }
            Command::ActivateMembership { proof, scoped } => {
                if !self.local.backup_verified && !self.local.legacy_confirmed {
                    return Err("backup_verification_required");
                }
                portable::verify_proof(
                    &proof,
                    &self.open_wallet()?.public_key_hex(),
                    &self.local.trust,
                    scoped,
                )?;
                let mut local = self.local.clone();
                let mut contents = local
                    .contents
                    .clone()
                    .unwrap_or(portable::empty_contents(self.open_wallet()?, 0)?);
                let field = if scoped {
                    "scopedMemberships"
                } else {
                    "memberships"
                };
                let mut proofs = contents["sections"][field]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                proofs.retain(|p| p["membershipId"] != proof["membershipId"]);
                proofs.push(proof.clone());
                contents["sections"][field] = json!(proofs);
                portable::validate(self.open_wallet()?, &contents, &local.trust)?;
                local.contents = Some(contents);
                local.active_membership = Some(proof);
                self.prepare(None, self.custody.clone().ok_or("wallet_locked")?, local)
            }
            Command::PrepareAccessRequest {
                challenge,
                pin,
                now,
            } => {
                let wallet = self.open_wallet()?;
                if (!self.local.backup_verified && !self.local.legacy_confirmed)
                    || self.local.active_membership.is_none()
                {
                    return Err("membership_required");
                }
                let prepared = crate::access_request::PreparedAccessRequest::prepare_native(
                    &challenge,
                    &wallet.public_key_hex(),
                    &self.local.installation_id,
                    &pin,
                    now,
                )?;
                let token = installation_id();
                let summary = prepared.summary();
                self.access_request = Some((token.clone(), prepared));
                Ok(json!({"token":token,"summary":summary}))
            }
            Command::ApproveAccessRequest { token, now } => {
                let (expected, prepared) = self
                    .access_request
                    .take()
                    .ok_or("access_approval_unavailable")?;
                if token != expected {
                    return Err("access_context_changed");
                }
                let wallet = self.open_wallet()?;
                if self.local.active_membership.is_none() {
                    return Err("membership_required");
                }
                let mut approved = prepared.approve(wallet, now)?;
                approved["proof"] = self
                    .local
                    .active_membership
                    .clone()
                    .ok_or("membership_required")?;
                Ok(approved)
            }
            Command::ReadAccessIdentity {} => {
                let wallet = self.open_wallet()?;
                if (!self.local.backup_verified && !self.local.legacy_confirmed)
                    || self.local.active_membership.is_none()
                {
                    return Err("membership_required");
                }
                Ok(
                    json!({"subject_public_key":wallet.public_key_hex(),"installation_id":self.local.installation_id}),
                )
            }
            Command::ApproveReadCredential {
                challenge,
                pin,
                now,
            } => {
                self.credential_approval = None;
                let wallet = self.open_wallet()?;
                if (!self.local.backup_verified && !self.local.legacy_confirmed)
                    || self.local.active_membership.is_none()
                {
                    return Err("membership_required");
                }
                let parsed = crate::read_access::Challenge::parse(
                    &challenge,
                    &wallet.public_key_hex(),
                    &self.local.installation_id,
                    &pin.receiver,
                    now,
                )?;
                let policy: castalia_wallet_presentation::read_authority::Policy =
                    serde_json::from_value(
                        parsed
                            .details
                            .get("authority_policy")
                            .ok_or("invalid_request")?
                            .clone(),
                    )
                    .map_err(|_| "invalid_request")?;
                pin.check(&policy)?;
                if policy.issuer != parsed.issuer
                    || policy.receiver != parsed.receiver
                    || parsed.credential_expires_at - parsed.issued_at > policy.max_lifetime_seconds
                {
                    return Err("invalid_request");
                }
                let sig = wallet
                    .sign(&parsed.transcript()?)
                    .map_err(|_| "signing_failed")?;
                let result = json!({"challenge":parsed,"proof":self.local.active_membership,"signature":URL_SAFE_NO_PAD.encode(sig)});
                self.credential_approval = Some((parsed, policy));
                Ok(result)
            }
            Command::StoreReadCredential {
                request_id,
                credential,
                now,
            } => {
                self.open_wallet()?;
                let (approved, policy) =
                    self.credential_approval.take().ok_or("preview_expired")?;
                if request_id != approved.request_id {
                    return Err("invalid_credential");
                }
                let access =
                    crate::read_access::SignedAccess::accept(&approved, policy, credential, now)?;
                let mut local = self.local.clone();
                local.access.remove(&approved.receiver);
                local.read_credentials.insert(approved.receiver, access);
                self.prepare(None, self.custody.clone().ok_or("wallet_locked")?, local)
            }
            Command::ReadCredential { receiver, now } => {
                self.open_wallet()?;
                if self.local.active_membership.is_none() {
                    return Err("membership_required");
                }
                let access = self
                    .local
                    .read_credentials
                    .get(&receiver)
                    .ok_or("access_setup_required")?;
                castalia_wallet_presentation::read_authority::verify_credential(
                    &access.policy,
                    &access.credential,
                    now,
                )?;
                serde_json::to_value(access).map_err(|_| "encoding_failed")
            }
            Command::SignReadCall {
                receiver,
                call,
                now,
            } => {
                let wallet = self.open_wallet()?;
                if (!self.local.backup_verified && !self.local.legacy_confirmed)
                    || self.local.active_membership.is_none()
                {
                    return Err("membership_required");
                }
                let access = self
                    .local
                    .read_credentials
                    .get(&receiver)
                    .ok_or("access_setup_required")?;
                let mut proof = access.unsigned_call(
                    &call,
                    installation_id(),
                    &wallet.public_key_hex(),
                    &self.local.installation_id,
                    now,
                )?;
                proof.signature = hex::encode(
                    wallet
                        .sign(&proof.transcript()?)
                        .map_err(|_| "signing_failed")?,
                );
                Ok(json!({"credential":access.credential,"call":call,"proof":proof}))
            }
            Command::ApproveReadAccess {
                challenge,
                receiver,
                now,
            } => {
                let wallet = self.open_wallet()?;
                if (!self.local.backup_verified && !self.local.legacy_confirmed)
                    || self.local.active_membership.is_none()
                {
                    return Err("membership_required");
                }
                let parsed = crate::read_access::Challenge::parse(
                    &challenge,
                    &wallet.public_key_hex(),
                    &self.local.installation_id,
                    &receiver,
                    now,
                )?;
                let sig = wallet
                    .sign(&parsed.transcript()?)
                    .map_err(|_| "signing_failed")?;
                let result = json!({"challenge":parsed,"proof":self.local.active_membership,"signature":URL_SAFE_NO_PAD.encode(sig)});
                self.read_approval = Some(parsed);
                Ok(result)
            }
            Command::StoreReadAccess {
                request_id,
                secret,
                expires_at,
                metadata,
                now,
            } => {
                self.open_wallet()?;
                let approved = self.read_approval.take().ok_or("preview_expired")?;
                if approved.request_id != request_id
                    || now >= approved.expires_at
                    || expires_at <= now
                    || expires_at > approved.credential_expires_at
                    || secret.is_empty()
                    || secret.len() > 8192
                    || serde_json::to_vec(&metadata)
                        .map_err(|_| "invalid_request")?
                        .len()
                        > 32768
                {
                    return Err("invalid_credential");
                }
                let mut local = self.local.clone();
                local.access.insert(
                    approved.receiver.clone(),
                    crate::read_access::StoredAccess {
                        issuer: approved.issuer,
                        receiver: approved.receiver,
                        secret,
                        expires_at,
                        metadata,
                    },
                );
                self.prepare(None, self.custody.clone().ok_or("wallet_locked")?, local)
            }
            Command::ReadAccess { receiver, now } => {
                self.open_wallet()?;
                if self.local.active_membership.is_none() {
                    return Err("membership_required");
                }
                let access = self
                    .local
                    .access
                    .get(&receiver)
                    .ok_or("access_setup_required")?;
                if now >= access.expires_at {
                    return Err("access_expired");
                }
                serde_json::to_value(access).map_err(|_| "encoding_failed")
            }
            Command::ForgetReadAccess { receiver } => {
                self.open_wallet()?;
                let mut local = self.local.clone();
                local.access.remove(&receiver);
                local.read_credentials.remove(&receiver);
                self.prepare(None, self.custody.clone().ok_or("wallet_locked")?, local)
            }
            Command::ApprovePresentationTrust { config } => {
                self.presentation_trust = None;
                self.presentation_identity()?;
                let raw = serde_json::to_vec(&config).map_err(|_| "invalid_trust")?;
                let config = castalia_wallet_presentation::TrustConfig::parse(&raw)?;
                // The approved caller must actually occur in the pinned policy.
                if !config
                    .pins
                    .iter()
                    .all(|pin| pin.callers.contains(&config.caller))
                {
                    return Err("invalid_trust");
                }
                self.presentation_trust = Some(config);
                Ok(self.state())
            }
            Command::PresentationIdentity {} => self.presentation_identity(),
            Command::PrepareCredentialPresentation { request, now } => {
                self.presentation_identity()?;
                if self.pending.is_some() {
                    return Err("session_busy");
                }
                let config = self
                    .presentation_trust
                    .as_ref()
                    .ok_or("trust_setup_required")?;
                let prepared = self.open_wallet()?.prepare_credential_presentation(
                    request.as_bytes(),
                    &config.pins,
                    &config.caller,
                    now,
                )?;
                let summary: Value =
                    serde_json::from_slice(&prepared.summary()?).map_err(|_| "encoding_failed")?;
                let mut nonce = [0; 16];
                OsRng
                    .try_fill_bytes(&mut nonce)
                    .map_err(|_| "randomness_unavailable")?;
                let token = hex::encode(nonce);
                self.presentation = Some(SessionPresentation {
                    token: token.clone(),
                    revision: self.revision,
                    prepared,
                });
                Ok(json!({"token":token,"summary":summary}))
            }
            Command::ApproveCredentialPresentation { token, now } => {
                // Consume before validation, including wrong token, stale state or clock.
                let pending = self.presentation.take().ok_or("preview_expired")?;
                self.presentation_identity()?;
                if pending.token != token
                    || pending.revision != self.revision
                    || self.pending.is_some()
                {
                    return Err("preview_stale");
                }
                self.presentation_trust
                    .as_ref()
                    .ok_or("trust_setup_required")?;
                let mut nonce = [0; 16];
                OsRng
                    .try_fill_bytes(&mut nonce)
                    .map_err(|_| "randomness_unavailable")?;
                let bytes = self.open_wallet()?.approve_credential_presentation(
                    pending.prepared,
                    now,
                    &nonce,
                )?;
                let presentation = String::from_utf8(bytes).map_err(|_| "encoding_failed")?;
                Ok(json!({"presentation":presentation}))
            }
            Command::CancelCredentialPresentation {} => Ok(self.state()),
            Command::DataSummary {} => {
                self.open_wallet()?;
                Ok(
                    json!({"contents":self.local.contents,"active_membership":self.local.active_membership,"trust":self.local.trust}),
                )
            }
            Command::Unlock { snapshot, password } => {
                let password = Zeroizing::new(password);
                self.lock();
                let stored = parse_snapshot(&snapshot)?;
                let wallet = import_wallet(stored.custody.as_bytes(), &password)
                    .map_err(|_| "unlock_failed")?;
                let local = open(&wallet, &stored.local, stored.revision)?;
                self.custody = Some(stored.custody);
                self.revision = stored.revision;
                self.local = local;
                self.wallet = Some(wallet);
                Ok(self.state())
            }
            Command::ExportRecovery { password } => {
                let password = Zeroizing::new(password);
                new_password(&password)?;
                let file = self
                    .open_wallet()?
                    .export_randomized(&password)
                    .map_err(|_| "export_failed")?;
                Ok(json!({"file":file.as_str(),"extension":"castalia-recovery"}))
            }
            Command::VerifyBackup { file, password } => {
                let password = Zeroizing::new(password);
                let restored = import_wallet(file.as_bytes(), &password)
                    .map_err(|_| "recovery_file_invalid")?;
                let wallet = self.open_wallet()?;
                if wallet.public_key_hex() != restored.public_key_hex()
                    || wallet.ml_dsa_public_key_base64url()
                        != restored.ml_dsa_public_key_base64url()
                    || wallet
                        .chain_accounts()
                        .map_err(|_| "account_validation_failed")?
                        != restored
                            .chain_accounts()
                            .map_err(|_| "account_validation_failed")?
                {
                    return Err("backup_identity_mismatch");
                }
                let mut local = self.local.clone();
                local.backup_verified = true;
                self.prepare(None, self.custody.clone().ok_or("wallet_locked")?, local)
            }
            Command::CommitCandidate {
                token,
                expected_revision,
            } => {
                let pending = self.pending.as_mut().ok_or("preview_expired")?;
                if pending.token != token
                    || pending.expected_revision != expected_revision
                    || self.revision != expected_revision
                {
                    return Err("preview_stale");
                }
                pending.started = true;
                Ok(json!({"snapshot":pending.snapshot,"expected_revision":expected_revision}))
            }
            Command::ConfirmCommit { token, snapshot } => {
                let pending = self.pending.as_ref().ok_or("preview_expired")?;
                if !pending.started
                    || pending.token != token
                    || pending.snapshot != snapshot
                    || self.revision != pending.expected_revision
                {
                    return Err("commit_mismatch");
                }
                let stored = parse_snapshot(&snapshot)?;
                let pending = self.pending.take().ok_or("preview_expired")?;
                if let Some(wallet) = pending.wallet {
                    self.wallet = Some(wallet);
                }
                self.custody = Some(stored.custody);
                self.revision = stored.revision;
                self.local = pending.local;
                Ok(self.state())
            }
            Command::MembershipRequest { scope_id } => {
                if !self.local.backup_verified && !self.local.legacy_confirmed {
                    return Err("backup_verification_required");
                }
                if scope_id.is_none() && self.local.trust.v3.is_none() {
                    return Err("trust_setup_required");
                }
                let wallet = self.open_wallet()?;
                let mut message = if scope_id.is_some() {
                    b"castalia/scoped-membership-join/v4\0".to_vec()
                } else {
                    b"castalia/zenith-membership-join/v3\0".to_vec()
                };
                message.extend_from_slice(
                    &hex::decode(wallet.public_key_hex()).map_err(|_| "invalid_identity")?,
                );
                if let Some(scope) = &scope_id {
                    let policy = self.local.trust.v4.as_ref().ok_or("trust_setup_required")?;
                    if !policy["scopes"]
                        .as_array()
                        .ok_or("trust_setup_required")?
                        .iter()
                        .any(|s| s["scopeId"].as_str() == Some(scope))
                    {
                        return Err("trust_setup_required");
                    }
                    message.extend_from_slice(
                        &crate::decode_hex_32(scope).map_err(|_| "invalid_scope")?,
                    );
                }
                let signature = wallet.sign(&message).map_err(|_| "signing_failed")?;
                if let Some(scope) = scope_id {
                    return Ok(
                        json!({"schema":"castalia.scoped-membership-issuance-request.v4","version":4,"scopeType":"community","scopeId":scope,"ownerPublicKey":wallet.public_key_hex(),"signatureSuite":"Ed25519","signature":URL_SAFE_NO_PAD.encode(signature)}),
                    );
                }
                Ok(
                    json!({"schema":"castalia.zenith-membership-issuance-request.v3","version":3,"ownerPublicKey":wallet.public_key_hex(),"signatureSuite":"Ed25519","signature":URL_SAFE_NO_PAD.encode(signature)}),
                )
            }
            Command::Cancel {} => {
                self.read_approval = None;
                self.credential_approval = None;
                self.pending = None;
                Ok(self.state())
            }
            Command::Lock {} => {
                self.lock();
                Ok(self.state())
            }
        }
    }
    fn graph_wallet_v2(&self) -> Result<&OpenedWallet> {
        let wallet = self.open_wallet()?;
        if !self.local.backup_verified && !self.local.legacy_confirmed {
            return Err("backup_verification_required");
        }
        Ok(wallet)
    }
    fn presentation_identity(&self) -> Result<Value> {
        let wallet = self.open_wallet()?;
        if !self.local.backup_verified && !self.local.legacy_confirmed {
            return Err("backup_verification_required");
        }
        let proof = self
            .local
            .active_membership
            .as_ref()
            .ok_or("membership_required")?;
        let scoped = proof["schema"] == "castalia.scoped-membership-credential.v4";
        portable::verify_proof(proof, &wallet.public_key_hex(), &self.local.trust, scoped)?;
        Ok(json!({"public_key":wallet.public_key_hex(),"membership":proof}))
    }
    fn open_wallet(&self) -> Result<&OpenedWallet> {
        self.wallet.as_ref().ok_or("wallet_locked")
    }
    fn require_empty(&self, expected_revision: u64) -> Result<()> {
        if self.custody.is_some() || self.wallet.is_some() {
            return Err("wallet_already_exists");
        }
        if self.revision != expected_revision {
            return Err("preview_stale");
        }
        Ok(())
    }
    fn state(&self) -> Value {
        json!({"configured":self.custody.is_some(),"unlocked":self.wallet.is_some(),"revision":self.revision,
            "public_key":self.wallet.as_ref().map(OpenedWallet::public_key_hex),
            "backup_verified":self.wallet.is_some() && self.local.backup_verified,
            "holder_grant_protocol":"secs.holder-grant.v1", "resource_owner_protocol":"zenith.resource-owner.v1", "operator_access_protocol":"castalia.operator-access.v1", "graph_access_protocol":"castalia.graph-access.v2", "backup_eligible":self.wallet.is_some() && (self.local.backup_verified || self.local.legacy_confirmed), "membership_active":self.wallet.is_some() && self.local.active_membership.is_some()})
    }
    fn lock(&mut self) {
        self.presentation = None;
        self.presentation_trust = None;
        self.resource_owner = None;
        self.operator_access = None;
        self.graph_access_request = None;
        self.access_request = None;
        self.wallet = None;
        self.pending = None;
        self.local = LocalState::default();
        self.restore_trust = Trust::default();
        self.read_approval = None;
        self.credential_approval = None;
    }
    fn prepare(
        &mut self,
        new_wallet: Option<OpenedWallet>,
        custody: String,
        local: LocalState,
    ) -> Result<Value> {
        let mut local = local;
        if local.installation_id.is_empty() {
            local.installation_id = installation_id();
        }
        let wallet = new_wallet
            .as_ref()
            .or(self.wallet.as_ref())
            .ok_or("wallet_locked")?;
        let revision = self
            .revision
            .checked_add(1)
            .filter(|n| *n <= MAX_SAFE)
            .ok_or("revision_exhausted")?;
        let sealed = seal(wallet, &local, revision)?;
        let snapshot = serde_json::to_string(&Snapshot {
            schema: "castalia.wallet-local.v1".into(),
            revision,
            custody,
            local: sealed,
        })
        .map_err(|_| "encoding_failed")?;
        let mut nonce = [0; 16];
        OsRng.fill_bytes(&mut nonce);
        let token = hex::encode(nonce);
        let result = json!({"holder_grants":local.holder_grants.values().map(|g|g.summary()).collect::<Vec<_>>(),"token":token,"expected_revision":self.revision,"public_key":wallet.public_key_hex(),
            "ml_dsa_commitment":wallet.ml_dsa_public_key_commitment_hex(),"chain_accounts":serde_json::from_str::<Value>(&wallet.chain_accounts().map_err(|_| "account_validation_failed")?).map_err(|_| "account_validation_failed")?,"backup_verified":local.backup_verified,"profile":local.contents.as_ref().map(|c|c["sections"]["identity"].clone()),"memberships":local.contents.as_ref().map(|c|c["sections"].clone()),"wallet_identities":local.contents.as_ref().and_then(|c|c["sections"].get("walletIdentities")).cloned().unwrap_or_else(||crate::wallet_identities::empty(&wallet.public_key_hex())),"trust":local.trust});
        self.pending = Some(Pending {
            token,
            expected_revision: self.revision,
            snapshot,
            wallet: new_wallet,
            local,
            started: false,
        });
        Ok(result)
    }
}
fn new_password(value: &str) -> Result<()> {
    if value.chars().count() < 12 || value.len() > 4096 {
        Err("password_minimum_12")
    } else {
        Ok(())
    }
}
fn parse_snapshot(raw: &str) -> Result<Snapshot> {
    if raw.len() > MAX * 2 {
        return Err("invalid_snapshot");
    }
    let snapshot: Snapshot = serde_json::from_str(raw).map_err(|_| "invalid_snapshot")?;
    if snapshot.schema != "castalia.wallet-local.v1"
        || snapshot.revision == 0
        || snapshot.revision > MAX_SAFE
    {
        return Err("invalid_snapshot");
    }
    Ok(snapshot)
}
fn key(wallet: &OpenedWallet) -> Zeroizing<[u8; 32]> {
    let seed = Zeroizing::new(wallet.signing_key.to_bytes());
    Zeroizing::new(blake3::derive_key(
        "castalia/wallet-local-state/v1",
        seed.as_ref(),
    ))
}
fn aad(owner: &str, revision: u64) -> Vec<u8> {
    format!("castalia.wallet-local-state.v1\0{owner}\0{revision}").into_bytes()
}
fn seal(wallet: &OpenedWallet, local: &LocalState, revision: u64) -> Result<SealedState> {
    let owner = wallet.public_key_hex();
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut nonce);
    let plaintext = Zeroizing::new(serde_json::to_vec(local).map_err(|_| "encoding_failed")?);
    let cipher =
        Aes256Gcm::new_from_slice(key(wallet).as_ref()).map_err(|_| "encryption_failed")?;
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &plaintext,
                aad: &aad(&owner, revision),
            },
        )
        .map_err(|_| "encryption_failed")?;
    Ok(SealedState {
        schema: "castalia.wallet-local-state.v1".into(),
        owner,
        revision,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}
fn open(wallet: &OpenedWallet, sealed: &SealedState, revision: u64) -> Result<LocalState> {
    if sealed.schema != "castalia.wallet-local-state.v1"
        || sealed.owner != wallet.public_key_hex()
        || sealed.revision != revision
    {
        return Err("invalid_snapshot");
    }
    let nonce = crate::decode_exact::<12>(&sealed.nonce).map_err(|_| "invalid_snapshot")?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&sealed.ciphertext)
        .map_err(|_| "invalid_snapshot")?;
    let cipher = Aes256Gcm::new_from_slice(key(wallet).as_ref()).map_err(|_| "invalid_snapshot")?;
    let bytes = Zeroizing::new(
        cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &ciphertext,
                    aad: &aad(&sealed.owner, revision),
                },
            )
            .map_err(|_| "invalid_snapshot")?,
    );
    serde_json::from_slice(&bytes).map_err(|_| "invalid_snapshot")
}

fn installation_id() -> String {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
