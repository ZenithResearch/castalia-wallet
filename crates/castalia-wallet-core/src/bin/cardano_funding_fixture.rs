//! Opt-in local fixture process: no listener, key import, vault access or production consent.
use castalia_wallet_core::{
    CardanoFundingNetworkV1,
    funding_fixture::{FixtureProfile, FundingFixtureSession},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{self, BufRead, Read, Write};
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "camelCase", deny_unknown_fields)]
enum Command {
    Open {
        #[serde(rename = "networkJson")]
        network_json: String,
    },
    SetProfile {
        profile: FixtureProfile,
        #[serde(rename = "ownerSignature")]
        owner_signature: String,
    },
    SetContext {
        generation: u64,
        digest: String,
        #[serde(rename = "ownerSignature")]
        owner_signature: String,
    },
    Inspect {
        #[serde(rename = "transactionHex")]
        transaction_hex: String,
    },
    Prepare {
        #[serde(rename = "transactionHex")]
        transaction_hex: String,
        #[serde(rename = "ownerSignature")]
        owner_signature: String,
    },
    Approve {
        handle: String,
    },
    Cancel {
        handle: String,
    },
    Invalidate,
    Close,
}
fn execute(
    command: Command,
    session: &mut Option<FundingFixtureSession>,
    owner: [u8; 32],
) -> Result<Value, String> {
    if let Command::Open { network_json } = command {
        if session.is_some() {
            return Err("session already created".into());
        }
        let network = CardanoFundingNetworkV1::from_json(network_json.as_bytes())
            .map_err(|_| "invalid network profile")?;
        let s = FundingFixtureSession::fresh(owner, network).map_err(|e| e.to_string())?;
        let info = serde_json::to_value(s.info()).map_err(|_| "cannot encode public info")?;
        *session = Some(s);
        return Ok(info);
    }
    let s = session.as_mut().ok_or("session not created")?;
    match command {
        Command::SetProfile {
            profile,
            owner_signature,
        } => Ok(
            json!({"profileDigest":s.set_profile(profile,&owner_signature).map_err(|e|e.to_string())?}),
        ),
        Command::SetContext {
            generation,
            digest,
            owner_signature,
        } => {
            s.set_context(generation, &digest, &owner_signature)
                .map_err(|e| e.to_string())?;
            Ok(json!({"updated":true}))
        }
        Command::Inspect { transaction_hex } => {
            serde_json::to_value(s.inspect(&transaction_hex).map_err(|e| e.to_string())?)
                .map_err(|_| "cannot encode inspection".into())
        }
        Command::Prepare {
            transaction_hex,
            owner_signature,
        } => serde_json::to_value(
            s.prepare(&transaction_hex, &owner_signature)
                .map_err(|e| e.to_string())?,
        )
        .map_err(|_| "cannot encode preparation".into()),
        Command::Approve { handle } => {
            serde_json::to_value(s.approve(&handle).map_err(|e| e.to_string())?)
                .map_err(|_| "cannot encode witness".into())
        }
        Command::Cancel { handle } => Ok(json!({"cancelled":s.cancel(&handle)})),
        Command::Invalidate => {
            s.invalidate().map_err(|e| e.to_string())?;
            Ok(json!({"invalidated":true,"epoch":s.info().epoch}))
        }
        Command::Close => {
            s.close();
            Ok(json!({"closed":true}))
        }
        Command::Open { .. } => Err("session already created".into()),
    }
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 || args[1] != "--owner-verification-key" {
        eprintln!("Requires one explicit fixture-owner PUBLIC verification key.");
        std::process::exit(2);
    }
    let owner = hex::decode(&args[2])
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok());
    let Some(owner) = owner else {
        eprintln!("Invalid fixture-owner PUBLIC verification key.");
        std::process::exit(2)
    };
    let mut session = None;
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    loop {
        let mut line = Vec::new();
        let read = (&mut reader).take(131073).read_until(b'\n', &mut line);
        let Ok(count) = read else { break };
        if count == 0 {
            break;
        }
        if count > 131072 || line.last() != Some(&b'\n') {
            let _ = writeln!(
                writer,
                "{}",
                json!({"ok":false,"error":"invalid bounded input framing"})
            );
            let _ = writer.flush();
            break;
        }
        let command: Result<Command, _> = serde_json::from_slice(&line);
        let response = match command {
            Ok(command) => match execute(command, &mut session, owner) {
                Ok(result) => json!({"ok":true,"result":result}),
                Err(error) => json!({"ok":false,"error":error}),
            },
            Err(_) => json!({"ok":false,"error":"invalid closed fixture command"}),
        };
        if writeln!(writer, "{response}").is_err() || writer.flush().is_err() {
            break;
        }
    }
    if let Some(s) = session.as_mut() {
        s.close();
    }
}
