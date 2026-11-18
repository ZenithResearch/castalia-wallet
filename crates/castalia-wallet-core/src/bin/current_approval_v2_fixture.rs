//! Local, default-off disposable fixture. A trusted launcher supplies the observer's public key.
use castalia_wallet_core::funding_fixture::current_approval_v2::{
    ApprovalSession, Intent, ProfileStatement, Release, ReviewContext, Role, Signed,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{self, BufRead, Read, Write};

const FRAME: usize = 196_608;
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "camelCase", deny_unknown_fields)]
enum Command {
    Open {},
    Install {
        receipt: Signed<ProfileStatement>,
    },
    Inspect {
        original: String,
        context: ReviewContext,
    },
    Prepare {
        original: String,
        context: ReviewContext,
        intent: Signed<Intent>,
    },
    Release {
        receipt: Signed<Release>,
    },
    Cancel {
        handle: String,
    },
    Lock {},
}
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 5 || args[1] != "--observer-key" || args[3] != "--role" {
        eprintln!("Expected --observer-key PUBLIC_HEX --role ROLE");
        std::process::exit(2);
    }
    if args[2].len() != 64
        || !args[2]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        std::process::exit(2);
    }
    let key = hex::decode(&args[2])
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok());
    let role = match args[4].as_str() {
        "controller" => Some(Role::Controller),
        "author" => Some(Role::Author),
        "recovery" => Some(Role::Recovery),
        "feePayer" => Some(Role::FeePayer),
        _ => None,
    };
    let (Some(key), Some(role)) = (key, role) else {
        std::process::exit(2)
    };
    let Ok(mut session) = ApprovalSession::fresh(key, role) else {
        std::process::exit(2)
    };
    let (reader, writer) = (io::stdin(), io::stdout());
    let mut reader = reader.lock();
    let mut writer = writer.lock();
    let mut opened = false;
    loop {
        let mut line = Vec::new();
        let Ok(n) = (&mut reader)
            .take((FRAME + 1) as u64)
            .read_until(b'\n', &mut line)
        else {
            break;
        };
        if n == 0 {
            break;
        }
        if n > FRAME || line.last() != Some(&b'\n') {
            let _ = writeln!(
                writer,
                "{}",
                json!({"ok":false,"error":"invalid bounded input framing"})
            );
            let _ = writer.flush();
            break;
        }
        let result = (|| -> Result<Value, String> {
            let cmd: Command =
                serde_json::from_slice(&line).map_err(|_| "invalid closed fixture command")?;
            match cmd {
                Command::Open {} if !opened => {
                    opened = true;
                    session.info()
                }
                _ if !opened => return Err("session not open".into()),
                Command::Open {} => return Err("session already open".into()),
                Command::Install { receipt } => {
                    session.install(&receipt).map(|_| json!({"installed":true}))
                }
                Command::Inspect { original, context } => session.inspect(&original, &context),
                Command::Prepare {
                    original,
                    context,
                    intent,
                } => session.prepare(&original, &context, &intent),
                Command::Release { receipt } => session.release(&receipt).map(|w| json!(w)),
                Command::Cancel { handle } => Ok(json!({"cancelled":session.cancel(&handle)})),
                Command::Lock {} => {
                    session.lock();
                    Ok(json!({"locked":true}))
                }
            }
            .map_err(|e| e.to_string())
        })();
        let response = match result {
            Ok(r) => json!({"ok":true,"result":r}),
            Err(e) => json!({"ok":false,"error":e}),
        };
        if writeln!(writer, "{response}").is_err() || writer.flush().is_err() {
            break;
        }
    }
    session.lock();
}
