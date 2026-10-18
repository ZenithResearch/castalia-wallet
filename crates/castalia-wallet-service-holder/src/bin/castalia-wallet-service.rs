//! Explicit owner startup plus exact bounded stdin; no caller authority flags.
use castalia_wallet_service_holder::service_command::{
    exchange, exchange_pinned, Denied, Mode, MAX_STDIN_BYTES,
};
use std::{
    io::{Read, Write},
    path::PathBuf,
};

fn configuration_digest(value: &std::ffi::OsStr) -> Result<[u8; 32], Denied> {
    let value = value.to_str().ok_or(Denied)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Denied);
    }
    let mut digest = [0; 32];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[i] = u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| Denied)?, 16)
            .map_err(|_| Denied)?;
    }
    Ok(digest)
}

async fn run() -> Result<(), Denied> {
    let mut args = std::env::args_os().skip(1);
    let mode = match args.next().as_deref().and_then(|s| s.to_str()) {
        Some("issue") => Mode::Issue,
        Some("resume") => Mode::Resume,
        Some("query") => Mode::Query,
        _ => return Err(Denied),
    };
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--config")) {
        return Err(Denied);
    }
    let configuration = PathBuf::from(args.next().ok_or(Denied)?);
    let expected_sha256 = match args.next() {
        None => None,
        Some(flag) if flag == std::ffi::OsStr::new("--config-sha256") => {
            Some(configuration_digest(&args.next().ok_or(Denied)?)?)
        }
        _ => return Err(Denied),
    };
    if args.next().is_some() || !configuration.is_absolute() {
        return Err(Denied);
    }
    let mut request = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_STDIN_BYTES as u64 + 1)
        .read_to_end(&mut request)
        .map_err(|_| Denied)?;
    if request.len() > MAX_STDIN_BYTES {
        return Err(Denied);
    }
    let output = match expected_sha256 {
        Some(expected) => exchange_pinned(&configuration, mode, expected, &request).await?,
        None => exchange(&configuration, mode, &request).await?,
    };
    std::io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|_| Denied)
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if run().await.is_err() {
        let _ = std::io::stderr()
            .lock()
            .write_all(b"castalia wallet service command denied\n");
        std::process::exit(2);
    }
}
