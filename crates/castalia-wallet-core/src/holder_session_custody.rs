//! Portable temporary-key custody; same closed protocol as the private helper.
//! No root Wallet, import/export, persistence, generic signing or OS isolation claim.
use crate::session_signer::HolderSessionKey;
use secs_grant_contract::{self as c, IssuerPin, holder_sessions as s};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, &'static str>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema: String,
    provider: IssuerPin,
    context: s::Context,
    maximum_session_seconds: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    request_id: String,
    body: Command,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    CreateSession {
        expires_at: u64,
    },
    ProvePossession {
        session_handle: String,
        challenge: Box<s::Challenge>,
    },
    InstallCredential {
        session_handle: String,
        credential: Box<s::Credential>,
        reviewed_challenge: Box<s::Challenge>,
    },
    PresentCall {
        session_handle: String,
        call: Value,
    },
    StatusProof {
        session_handle: String,
        challenge: Box<s::Challenge>,
    },
    CloseSession {
        session_handle: String,
    },
}
pub struct HolderSessionCustody {
    profile: Profile,
    sessions: HashMap<String, HolderSessionKey>,
    outcomes: HashMap<String, (Vec<u8>, Value)>,
}
fn identifier(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn random() -> Result<String> {
    let mut bytes = [0; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| "randomness_unavailable")?;
    Ok(hex::encode(bytes))
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| "invalid_clock")
}
impl HolderSessionCustody {
    /// Bounded JSON input/output. Errors never include caller bytes or private material.
    pub fn invoke(&mut self, raw: &[u8]) -> Value {
        let request_id = c::parse::<Value>(raw).ok().and_then(|v| {
            v.get("request_id")
                .and_then(Value::as_str)
                .filter(|s| identifier(s))
                .map(str::to_owned)
        });
        match now().and_then(|current| self.handle(raw, current)) {
            Ok(value) => value,
            Err(code) => json!({"schema":"castalia.holder-session-agent-result.v1",
                "request_id":request_id,"ok":false,"error":code}),
        }
    }

    pub fn new(raw: &[u8]) -> Result<Self> {
        if raw.len() > 65536 {
            return Err("invalid_holder_session_profile");
        }
        let profile: Profile = c::parse(raw)?;
        let text = |s: &str| {
            !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_graphic() && b != b'*')
        };
        let public: [u8; 32] = hex::decode(&profile.provider.public_key)
            .map_err(|_| "invalid_holder_session_profile")?
            .try_into()
            .map_err(|_| "invalid_holder_session_profile")?;
        let issuer = ed25519_dalek::VerifyingKey::from_bytes(&public)
            .map_err(|_| "invalid_holder_session_profile")?;
        if profile.schema != "castalia.holder-session-agent-profile.v1"
            || !(1..=3600).contains(&profile.maximum_session_seconds)
            || issuer.is_weak()
            || hex::encode(public) != profile.provider.public_key
            || [
                &profile.provider.issuer,
                &profile.provider.key_id,
                &profile.provider.service,
                &profile.context.origin,
                &profile.context.audience,
            ]
            .iter()
            .any(|s| !text(s))
        {
            return Err("invalid_holder_session_profile");
        }
        Ok(Self {
            profile,
            sessions: HashMap::new(),
            outcomes: HashMap::new(),
        })
    }
    fn handle(&mut self, raw: &[u8], current: u64) -> Result<Value> {
        let v: Value = c::parse(raw)?;
        let request: Request =
            serde_json::from_value(v.clone()).map_err(|_| "invalid_holder_session_command")?;
        if request.schema != "castalia.holder-session-agent-command.v1"
            || !identifier(&request.request_id)
        {
            return Err("invalid_holder_session_command");
        }
        let digest = Sha256::digest(c::canonical(&v)?).to_vec();
        if let Some((original, result)) = self.outcomes.get(&request.request_id) {
            return if original == &digest {
                Ok(result.clone())
            } else {
                Err("session_command_conflict")
            };
        }
        if self.outcomes.len() >= 256 {
            return Err("session_command_capacity");
        }
        let value = self.execute(request.body, current)?;
        let result = json!({"schema":"castalia.holder-session-agent-result.v1","request_id":request.request_id,"ok":true,"value":value});
        self.outcomes
            .insert(request.request_id, (digest, result.clone()));
        Ok(result)
    }
    fn execute(&mut self, command: Command, now: u64) -> Result<Value> {
        match command {
            Command::CreateSession { expires_at } => {
                if self.sessions.len() >= 8
                    || expires_at <= now
                    || expires_at - now > self.profile.maximum_session_seconds
                {
                    return Err("invalid_session_lifetime_or_capacity");
                }
                let handle = random()?;
                let installation = random()?;
                let key = HolderSessionKey::create(
                    self.profile.provider.clone(),
                    self.profile.context.clone(),
                    installation.clone(),
                    now,
                    expires_at,
                )?;
                let value = json!({"session_handle":handle,"session_public_key":key.public_key(),"session_installation_id":installation,"maximum_expires_at":expires_at,"service":self.profile.provider.service});
                self.sessions.insert(handle, key);
                Ok(value)
            }
            Command::ProvePossession {
                session_handle,
                challenge,
            } => {
                let signature = self
                    .sessions
                    .get_mut(&session_handle)
                    .ok_or("session_unavailable")?
                    .prove_possession(&challenge, now)?;
                Ok(json!({"session_signature":signature,"challenge_digest":c::digest(&challenge)?}))
            }
            Command::InstallCredential {
                session_handle,
                credential,
                reviewed_challenge,
            } => {
                self.sessions
                    .get_mut(&session_handle)
                    .ok_or("session_unavailable")?
                    .install_credential(*credential, &reviewed_challenge, now)?;
                Ok(json!({"installed":true,"expires_at":reviewed_challenge.expires_at}))
            }
            Command::PresentCall {
                session_handle,
                call,
            } => self
                .sessions
                .get(&session_handle)
                .ok_or("session_unavailable")?
                .present_call(&call, now),
            Command::StatusProof {
                session_handle,
                challenge,
            } => {
                let proof = self
                    .sessions
                    .get(&session_handle)
                    .ok_or("session_unavailable")?
                    .status_proof(&challenge, now)?;
                serde_json::to_value(proof).map_err(|_| "encoding_failed")
            }
            Command::CloseSession { session_handle } => {
                self.sessions
                    .remove(&session_handle)
                    .ok_or("session_unavailable")?
                    .close();
                Ok(json!({"closed":true,"server_revocation_confirmed":false}))
            }
        }
    }
}
