use castalia_wallet_workspace_setup::{
    create_from_plan, renew_from_plan, resume_renewal_from_plan, RenewalError,
};
use std::path::Path;
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 6 || args[2] != "--plan" || args[4] != "--plan-sha256" {
        eprintln!("{{\"error\":\"workspace_owner_action_denied\"}}");
        std::process::exit(2);
    }
    let Some(pin) = args[5].to_str() else {
        std::process::exit(2)
    };
    let path = Path::new(&args[3]);
    if args[1] == "create" {
        match create_from_plan(path, pin) {
            Ok(receipt) => println!(
                "{}",
                serde_json::json!({"schema":"castalia.wallet-workspace-setup-output.v1","status":"configured_not_activated","authority_root":receipt["root"].as_str().map(|p|format!("{p}/authority"))})
            ),
            Err(_) => {
                eprintln!("{{\"error\":\"workspace_owner_setup_denied_partial_state_retained\"}}");
                std::process::exit(2);
            }
        }
        return;
    }
    let result = if args[1] == "renew" {
        renew_from_plan(path, pin)
    } else if args[1] == "resume-renewal" {
        resume_renewal_from_plan(path, pin)
    } else {
        Err(RenewalError::Denied)
    };
    match result {
        Ok(receipt) => {
            let generation = receipt["native_generation"]
                .as_u64()
                .expect("closed renewal receipt");
            let root = receipt["root"].as_str().expect("closed renewal root");
            let complete = Path::new(root)
                .join("authority/renewals")
                .join(generation.to_string())
                .join("COMPLETE.json");
            // Hash exactly the same canonical receipt bytes the owner published.
            use sha2::Digest;
            fn sorted(v: &serde_json::Value) -> serde_json::Value {
                match v {
                    serde_json::Value::Object(m) => serde_json::Value::Object(
                        m.iter()
                            .map(|(k, v)| (k.clone(), sorted(v)))
                            .collect::<std::collections::BTreeMap<_, _>>()
                            .into_iter()
                            .collect(),
                    ),
                    serde_json::Value::Array(a) => {
                        serde_json::Value::Array(a.iter().map(sorted).collect())
                    }
                    _ => v.clone(),
                }
            }
            let raw = serde_json::to_vec(&sorted(&receipt)).expect("public receipt");
            let sha: String = sha2::Sha256::digest(&raw)
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect();
            println!(
                "{}",
                serde_json::json!({"schema":"castalia.wallet-workspace-renewal-output.v1","status":"configured_not_activated","complete":{"path":complete,"sha256":sha}})
            );
        }
        Err(e) => {
            eprintln!(
                "{}",
                serde_json::json!({"error":if e==RenewalError::RecoveryRequired{"workspace_owner_renewal_recovery_required_partial_state_retained"}else{"workspace_owner_renewal_denied"}})
            );
            std::process::exit(if e == RenewalError::RecoveryRequired {
                4
            } else {
                2
            });
        }
    }
}
