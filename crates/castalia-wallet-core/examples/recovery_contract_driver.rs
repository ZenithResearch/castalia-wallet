//! Test harness only: stdin/stdout JSON lines, no persistence, network, or host keys.
//! Use disposable identities. This is not an application/provider signing API.
use castalia_wallet_core::recovery_session::RecoverySession;
use std::io::{self, BufRead, Write};
fn main() {
    let mut session = RecoverySession::new();
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut output = io::stdout().lock();
    loop {
        let mut bytes = Vec::new();
        let mut limited = (&mut input).take(3_145_730);
        use std::io::Read;
        match limited.read_until(b'\n', &mut bytes) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if bytes.len() > 3_145_728 {
            break;
        }
        let result = match std::str::from_utf8(&bytes) {
            Ok(raw) => session.invoke(raw.trim_end()),
            Err(_) => Err("invalid_request"),
        };
        let response = match result {
            Ok(value) => serde_json::json!({"ok":true,"value":value}),
            Err(error) => serde_json::json!({"ok":false,"error":error}),
        };
        if writeln!(output, "{response}").is_err() || output.flush().is_err() {
            break;
        }
    }
}
