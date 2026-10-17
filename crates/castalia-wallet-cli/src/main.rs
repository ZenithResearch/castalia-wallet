//! Explicit terminal approval for a credential-bound generic presentation.
use castalia_wallet_presentation::{
    MAX_ENVELOPE_BYTES, TrustConfig, complete, decode_hex, prepare_request,
};
use castalia_wallet_private_files as private_files;
use ed25519_dalek::{Signer as _, SigningKey};
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, IsTerminal, Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, &'static str>;
struct Arguments {
    request: PathBuf,
    trust: PathBuf,
    output: PathBuf,
}
fn arguments() -> Result<Arguments> {
    let mut request = None;
    let mut trust = None;
    let mut output = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(flag) = args.next() {
        let slot = match flag.to_str() {
            Some("--request-file") => &mut request,
            Some("--trust-config-file") => &mut trust,
            Some("--presentation-output") => &mut output,
            _ => return Err("invalid_arguments"),
        };
        if slot.is_some() {
            return Err("invalid_arguments");
        }
        *slot = Some(PathBuf::from(args.next().ok_or("invalid_arguments")?));
    }
    Ok(Arguments {
        request: request.ok_or("invalid_arguments")?,
        trust: trust.ok_or("invalid_arguments")?,
        output: output.ok_or("invalid_arguments")?,
    })
}
fn clock() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| "invalid_clock")
}
fn confirm(summary: &[u8]) -> Result<()> {
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "approval_required")?;
    if !tty.is_terminal() {
        return Err("approval_required");
    }
    // The validator rejects terminal control/bidi characters in every disclosure.
    // JSON escaping makes literal punctuation unambiguous without executing it.
    let value: serde_json::Value =
        serde_json::from_slice(summary).map_err(|_| "invalid_summary")?;
    let text = serde_json::to_string_pretty(&value).map_err(|_| "invalid_summary")?;
    write!(
        tty,
        "Castalia Wallet credential presentation\n{text}\nType APPROVE to sign this request: "
    )
    .map_err(|_| "approval_required")?;
    tty.flush().map_err(|_| "approval_required")?;
    let mut answer = String::new();
    BufReader::new((&mut tty).take(16))
        .read_line(&mut answer)
        .map_err(|_| "approval_required")?;
    if answer != "APPROVE\n" && answer != "APPROVE\r\n" {
        return Err("user_denied");
    }
    Ok(())
}
fn run() -> Result<()> {
    let args = arguments()?;
    let raw = private_files::read(&args.request, MAX_ENVELOPE_BYTES as u64)
        .map_err(|_| "unsafe_request_file")?;
    let trust_raw = private_files::read(&args.trust, MAX_ENVELOPE_BYTES as u64)
        .map_err(|_| "unsafe_trust_config")?;
    let trust = TrustConfig::parse(&trust_raw)?;
    if trust.caller.kind != "terminal" {
        return Err("invalid_terminal_caller");
    }
    let key_path = PathBuf::from(
        std::env::var_os("CASTALIA_SIGNING_KEY_FILE").ok_or("signing_key_reference_required")?,
    );
    let public =
        std::env::var("CASTALIA_SIGNING_PUBLIC_KEY").map_err(|_| "expected_public_key_required")?;
    decode_hex::<32>(&public)?;
    let output = private_files::Output::prepare(&args.output).map_err(|_| "unsafe_output")?;
    let prepared = prepare_request(&raw, &trust.pins, &trust.caller, &public, clock()?)?;
    confirm(&prepared.summary()?)?;
    // A privileged trust change during human approval invalidates that approval.
    let current_trust = private_files::read(&args.trust, MAX_ENVELOPE_BYTES as u64)
        .map_err(|_| "unsafe_trust_config")?;
    if current_trust != trust_raw {
        return Err("trust_configuration_changed");
    }
    // Only the explicit current raw32 profile is accepted, never a recovery container.
    let raw_seed =
        Zeroizing::new(private_files::read(&key_path, 32).map_err(|_| "unsafe_signing_key_file")?);
    let seed: &[u8; 32] = raw_seed
        .as_slice()
        .try_into()
        .map_err(|_| "invalid_signing_key_file")?;
    let signer = SigningKey::from_bytes(seed);
    if hex::encode(signer.verifying_key().as_bytes()) != public {
        return Err("signing_identity_mismatch");
    }
    let mut nonce = [0; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| "randomness_unavailable")?;
    let prepared = prepared.prepare_presentation(clock()?, &nonce)?;
    let signature = signer.sign(prepared.signature_transcript()).to_bytes();
    let presentation = complete(prepared, &signature)?.canonical()?;
    drop(signer);
    drop(raw_seed);
    output.write(&presentation).map_err(|_| "output_failed")?;
    Ok(())
}
fn main() {
    if std::env::args_os()
        .skip(1)
        .eq([std::ffi::OsString::from("--help")])
    {
        println!(
            "castalia-wallet-present-credential-v2 --request-file FILE --trust-config-file FILE --presentation-output FILE\nRequires explicit /dev/tty approval on every request. Environment: CASTALIA_SIGNING_KEY_FILE (existing raw 32-byte seed), CASTALIA_SIGNING_PUBLIC_KEY (64 lowercase hex). All files must be absolute and owner-private; output is create-only. No .env loading, automatic approval or application operations."
        );
        return;
    }
    match run() {
        Ok(()) => println!(
            "{{\"ok\":true,\"schema\":\"castalia.credential-presentation.v2\",\"output_written\":true}}"
        ),
        Err(code) => {
            eprintln!("{{\"error\":\"{code}\"}}");
            std::process::exit(2);
        }
    }
}
