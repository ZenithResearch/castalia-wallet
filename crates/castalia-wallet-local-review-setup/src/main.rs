use std::path::Path;
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    let result = (|| {
        if args.len() != 6
            || args[1] != "create"
            || args[2] != "--plan"
            || args[4] != "--plan-sha256"
        {
            return Err(());
        }
        let pin = args[5].to_str().ok_or(())?;
        castalia_wallet_local_review_setup::create_from_plan(Path::new(&args[3]), pin)
            .map_err(|_| ())
    })();
    match result {
        Ok(receipt) => println!(
            "{}",
            serde_json::json!({"schema":"castalia.wallet-local-review-setup-output.v1",
            "status":"configured_not_activated","run_id":receipt["run_id"],"authority_root":receipt["root"].as_str().map(|p|format!("{p}/authority"))})
        ),
        Err(()) => {
            eprintln!("{{\"error\":\"pilot_owner_setup_denied_partial_state_retained\"}}");
            std::process::exit(2);
        }
    }
}
