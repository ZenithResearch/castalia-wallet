//! Private process adapter over the portable finite holder-session custody engine.
use castalia_wallet_core::holder_session_custody::HolderSessionCustody;
use secs_grant_contract as c;
use std::{
    io::{self, BufRead, Read, Write},
    path::PathBuf,
};
type Result<T> = std::result::Result<T, &'static str>;
const MAX: usize = 131072;
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
    let mut agent = HolderSessionCustody::new(&raw)?;
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
        let result = agent.invoke(&frame);
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
