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
    ReadAccessIdentity {},
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
}
struct Pending {
    token: String,
    expected_revision: u64,
    snapshot: String,
    wallet: Option<OpenedWallet>,
    local: LocalState,
    started: bool,
}
#[derive(Default)]
pub struct RecoverySession {
    wallet: Option<OpenedWallet>,
    custody: Option<String>,
    revision: u64,
    local: LocalState,
    pending: Option<Pending>,
    restore_trust: Trust,
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
            return Err("request_too_large");
        }
        portable::parse_unique(raw).map_err(|_| "invalid_request")?;
        let command: Command = serde_json::from_str(raw).map_err(|_| "invalid_request")?;
        // A new preparation attempt invalidates any older preview, including
        // when its validation subsequently fails.
        if matches!(
            &command,
            Command::PrepareExisting { .. }
                | Command::PrepareCreate { .. }
                | Command::PrepareRestore { .. }
                | Command::PrepareLegacy { .. }
                | Command::PrepareData { .. }
                | Command::PrepareTrust { .. }
                | Command::VerifyBackup { .. }
                | Command::ActivateMembership { .. }
                | Command::StoreReadAccess { .. }
                | Command::StoreReadCredential { .. }
                | Command::ForgetReadAccess { .. }
        ) {
            self.pending = None;
        }
        match command {
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
                portable::validate(wallet, &next, &self.local.trust)?;
                let mut local = self.local.clone();
                local.contents = Some(next);
                let mut preview =
                    self.prepare(None, self.custody.clone().ok_or("wallet_locked")?, local)?;
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
            "backup_eligible":self.wallet.is_some() && (self.local.backup_verified || self.local.legacy_confirmed), "membership_active":self.wallet.is_some() && self.local.active_membership.is_some()})
    }
    fn lock(&mut self) {
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
        let result = json!({"token":token,"expected_revision":self.revision,"public_key":wallet.public_key_hex(),
            "ml_dsa_commitment":wallet.ml_dsa_public_key_commitment_hex(),"chain_accounts":serde_json::from_str::<Value>(&wallet.chain_accounts().map_err(|_| "account_validation_failed")?).map_err(|_| "account_validation_failed")?,"backup_verified":local.backup_verified,"profile":local.contents.as_ref().map(|c|c["sections"]["identity"].clone()),"memberships":local.contents.as_ref().map(|c|c["sections"].clone()),"trust":local.trust});
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
