//! Separate private finite-holder-session helper. No owner bootstrap, member key,
//! reusable grant input, key import/export, HTTP listener or arbitrary signer.
use castalia_wallet_core::session_signer::HolderSessionKey;
use secs_grant_contract::{self as c, IssuerPin, holder_sessions as s};
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
struct Agent {
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
impl Agent {
    fn new(profile: Profile) -> Result<Self> {
        if profile.schema != "castalia.holder-session-agent-profile.v1"
            || !(1..=3600).contains(&profile.maximum_session_seconds)
        {
            return Err("invalid_holder_session_profile");
        }
        Ok(Self {
            profile,
            sessions: HashMap::new(),
            outcomes: HashMap::new(),
        })
    }
    fn handle(&mut self, raw: &[u8]) -> Result<Value> {
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
        let value = self.execute(request.body, now()?)?;
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
    let mut agent = Agent::new(c::parse(&raw)?)?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    loop {
        let mut frame = Vec::new();
        let count = (&mut input)
            .take((MAX + 1) as u64)
            .read_until(b'\n', &mut frame)
            .map_err(|_| "invalid_session_input")?;
        if count == 0 {
            return Ok(());
        }
        if frame.len() > MAX || !frame.ends_with(b"\n") {
            return Err("invalid_session_frame");
        }
        let request_id = c::parse::<Value>(&frame).ok().and_then(|v| {
            v.get("request_id")
                .and_then(Value::as_str)
                .filter(|s| identifier(s))
                .map(str::to_owned)
        });
        let result = match agent.handle(&frame) {
            Ok(value) => value,
            Err(code) => {
                json!({"schema":"castalia.holder-session-agent-result.v1","request_id":request_id,"ok":false,"error":code})
            }
        };
        let bytes = c::canonical(&result)?;
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
