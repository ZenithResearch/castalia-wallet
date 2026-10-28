//! Private inherited stdio for a local broker. Never connect this wire directly
//! to MCP: internal results can contain public-but-sensitive grant/proof data.
use castalia_wallet_core::{read_access, session_signer::SessionKey};
use secs_grant_contract::{IssuerPin, scoped_grants as c};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{self, BufRead, Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
type Result<T> = std::result::Result<T, &'static str>;
const MAX: usize = 131072;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema: String,
    provider: IssuerPin,
    receiver: read_access::IssuerPin,
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
    ApproveMemberRequest {
        session_handle: String,
        challenge: Value,
    },
    ApproveEnrollment {
        session_handle: String,
        challenge: Value,
    },
    InstallGrant {
        session_handle: String,
        grant: c::Grant,
        reviewed_expiry: u64,
        reviewed_permissions: Vec<c::Permission>,
    },
    PresentCall {
        session_handle: String,
        call: Value,
    },
    CloseSession {
        session_handle: String,
    },
}
struct Agent {
    profile: Profile,
    sessions: HashMap<String, SessionKey>,
    outcomes: HashMap<String, (Vec<u8>, Value)>,
}
fn identifier(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn random_id() -> Result<String> {
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
impl Agent {
    fn new(profile: Profile) -> Result<Self> {
        if profile.schema != "castalia.session-agent-profile.v1"
            || !(60..=86400).contains(&profile.maximum_session_seconds)
            || profile.provider.issuer != profile.receiver.issuer
            || profile.provider.key_id != profile.receiver.key_id
            || profile.provider.public_key != profile.receiver.public_key
        {
            return Err("invalid_session_profile");
        }
        Ok(Self {
            profile,
            sessions: HashMap::new(),
            outcomes: HashMap::new(),
        })
    }
    fn handle(&mut self, raw: &[u8]) -> Result<Value> {
        if raw.len() > MAX {
            return Err("request_too_large");
        }
        let value: Value = secs_grant_contract::parse(raw)?;
        let request: Request =
            serde_json::from_value(value.clone()).map_err(|_| "invalid_session_command")?;
        if request.schema != "castalia.session-agent-command.v1" || !identifier(&request.request_id)
        {
            return Err("invalid_session_command");
        }
        let digest = Sha256::digest(secs_grant_contract::canonical(&value)?).to_vec();
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
        let current = now()?;
        let value = self.execute(request.body, current)?;
        let result = json!({"schema":"castalia.session-agent-result.v1","request_id":request.request_id,
                         "ok":true,"value":value});
        self.outcomes
            .insert(request.request_id, (digest, result.clone()));
        Ok(result)
    }
    fn execute(&mut self, command: Command, current: u64) -> Result<Value> {
        match command {
            Command::CreateSession { expires_at } => {
                if self.sessions.len() >= 8
                    || expires_at <= current
                    || expires_at - current > self.profile.maximum_session_seconds
                {
                    return Err("invalid_session_lifetime_or_capacity");
                }
                let handle = random_id()?;
                let installation = random_id()?;
                let key = SessionKey::create(
                    self.profile.provider.clone(),
                    installation.clone(),
                    current,
                    expires_at,
                )?;
                let value = json!({"session_handle":handle,"holder_public_key":key.public_key(),
                    "installation_id":installation,"maximum_expires_at":expires_at,
                    "service":self.profile.provider.service});
                self.sessions.insert(handle, key);
                Ok(value)
            }
            Command::ApproveMemberRequest {
                session_handle,
                challenge,
            } => self
                .sessions
                .get(&session_handle)
                .ok_or("session_unavailable")?
                .approve_member_request(
                    &String::from_utf8(secs_grant_contract::canonical(&challenge)?)
                        .map_err(|_| "invalid_challenge")?,
                    &self.profile.receiver,
                    current,
                ),
            Command::ApproveEnrollment {
                session_handle,
                challenge,
            } => self
                .sessions
                .get(&session_handle)
                .ok_or("session_unavailable")?
                .approve_enrollment(
                    &String::from_utf8(secs_grant_contract::canonical(&challenge)?)
                        .map_err(|_| "invalid_challenge")?,
                    &self.profile.receiver,
                    current,
                ),
            Command::InstallGrant {
                session_handle,
                grant,
                reviewed_expiry,
                reviewed_permissions,
            } => {
                self.sessions
                    .get_mut(&session_handle)
                    .ok_or("session_unavailable")?
                    .install_grant(grant, reviewed_expiry, &reviewed_permissions, current)?;
                Ok(json!({"installed":true,"expires_at":reviewed_expiry}))
            }
            Command::PresentCall {
                session_handle,
                call,
            } => self
                .sessions
                .get(&session_handle)
                .ok_or("session_unavailable")?
                .present_call(&call, current),
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
fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--profile-file")) {
        return Err("profile_required");
    }
    let path = PathBuf::from(args.next().ok_or("profile_required")?);
    if args.next().is_some() {
        return Err("invalid_arguments");
    }
    let raw = castalia_wallet_private_files::read(&path, 65536).map_err(|_| "unsafe_profile")?;
    let profile: Profile = secs_grant_contract::parse(&raw)?;
    let mut agent = Agent::new(profile)?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    loop {
        let mut frame = Vec::new();
        let count = input
            .by_ref()
            .take((MAX + 1) as u64)
            .read_until(b'\n', &mut frame)
            .map_err(|_| "session_input_failed")?;
        if count == 0 {
            return Ok(());
        }
        if count > MAX || frame.last() != Some(&b'\n') {
            return Err("invalid_session_frame");
        }
        let result = agent.handle(&frame).unwrap_or_else(
            |code| json!({"schema":"castalia.session-agent-result.v1","ok":false,"error":code}),
        );
        let bytes = secs_grant_contract::canonical(&result)?;
        output
            .write_all(&bytes)
            .and_then(|_| output.write_all(b"\n"))
            .and_then(|_| output.flush())
            .map_err(|_| "session_output_failed")?;
    }
}
fn main() {
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}
