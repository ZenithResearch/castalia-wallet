use castalia_wallet_presentation::{
    CREDENTIAL_DOMAIN, Caller, TrustConfig, canonical_json, verify_presentation,
};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::Value;
use std::{
    fs::{self},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::PathBuf,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    raw: Vec<u8>,
    trust: TrustConfig,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let vector: Value = serde_json::from_str(include_str!(
            "../../../docs/vectors/credential-presentation-v2.json"
        ))
        .unwrap();
        let mut request = vector["request"].clone();
        let now = clock();
        request["credential"]["claims"]["issued_at"] = now.into();
        request["credential"]["claims"]["expires_at"] = (now + 120).into();
        let mut transcript = CREDENTIAL_DOMAIN.to_vec();
        transcript.extend(canonical_json(&request["credential"]["claims"]).unwrap());
        request["credential"]["signature"] = hex::encode(
            SigningKey::from_bytes(&[11; 32])
                .sign(&transcript)
                .to_bytes(),
        )
        .into();
        let raw = canonical_json(&request).unwrap();
        let trust_raw = canonical_json(&vector["trust_config"]).unwrap();
        for (name, bytes) in [
            ("request.json", raw.as_slice()),
            ("trust.json", trust_raw.as_slice()),
            ("key", &[22; 32]),
        ] {
            let path = root.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self {
            _temp: temp,
            root,
            raw,
            trust: TrustConfig::parse(&trust_raw).unwrap(),
        }
    }
    fn command(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_castalia-wallet-present-credential-v2"));
        c.env_clear()
            .env("CASTALIA_SIGNING_KEY_FILE", self.root.join("key"))
            .env(
                "CASTALIA_SIGNING_PUBLIC_KEY",
                hex::encode(SigningKey::from_bytes(&[22; 32]).verifying_key().as_bytes()),
            )
            .arg("--request-file")
            .arg(self.root.join("request.json"))
            .arg("--trust-config-file")
            .arg(self.root.join("trust.json"))
            .arg("--presentation-output")
            .arg(self.root.join("output.json"));
        c
    }
}
fn clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn detached(c: &mut Command) {
    // SAFETY: setsid is async-signal-safe and no parent process state is mutated.
    unsafe {
        c.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
#[test]
fn no_terminal_fails_without_output_even_with_piped_approval() {
    let f = Fixture::new();
    let mut cmd = f.command();
    detached(&mut cmd);
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(b"APPROVE\n");
    let result = child.wait_with_output().unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("approval_required"));
    assert!(!f.root.join("output.json").exists());
    assert_eq!(fs::read(f.root.join("key")).unwrap(), [22; 32]);
}
fn terminal_run(
    f: &Fixture,
    answer: &[u8],
    mut after_prompt: impl FnMut(),
) -> (std::process::ExitStatus, String) {
    let command = f.command();
    let mut cmd = Command::new("/usr/bin/script");
    cmd.env_clear();
    for (key, value) in command.get_envs() {
        if let Some(value) = value {
            cmd.env(key, value);
        }
    }
    #[cfg(target_os = "macos")]
    {
        cmd.arg("-q")
            .arg("/dev/null")
            .arg(command.get_program())
            .args(command.get_args());
    }
    #[cfg(not(target_os = "macos"))]
    {
        fn quote(value: &std::ffi::OsStr) -> String {
            format!("'{}'", value.to_string_lossy().replace('\'', "'\\''"))
        }
        let shell = std::iter::once(command.get_program())
            .chain(command.get_args())
            .map(quote)
            .collect::<Vec<_>>()
            .join(" ");
        cmd.args(["-q", "-e", "-c"]).arg(shell).arg("/dev/null");
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut text = String::new();
    while !text.contains("Type APPROVE to sign this request:") {
        let mut poll = libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 10_000) } <= 0 {
            let _ = child.kill();
            let _ = child.wait();
            panic!("terminal prompt timeout: {text}");
        }
        let mut bytes = [0; 4096];
        let n = stdout.read(&mut bytes).unwrap();
        if n == 0 {
            let _ = child.kill();
            let _ = child.wait();
            panic!("terminal exited before prompt: {text}");
        }
        text.push_str(&String::from_utf8_lossy(&bytes[..n]));
    }
    after_prompt();
    child.stdin.as_mut().unwrap().write_all(answer).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("terminal completion timeout");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    (status, text)
}

#[test]
fn explicit_terminal_approval_signs_fresh_bounded_presentation() {
    let f = Fixture::new();
    let (status, text) = terminal_run(&f, b"APPROVE\n", || {});
    assert!(status.success());
    assert!(text.contains("Fixture request"));
    assert!(text.contains("fixture-issuer"));
    let presentation = fs::read(f.root.join("output.json")).unwrap();
    verify_presentation(
        &f.raw,
        &presentation,
        &f.trust.pins,
        &f.trust.caller,
        clock(),
    )
    .unwrap();
    assert_eq!(
        fs::metadata(f.root.join("output.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(fs::read(f.root.join("key")).unwrap(), [22; 32]);
}
#[test]
fn terminal_denial_and_trust_change_never_publish() {
    let f = Fixture::new();
    assert!(!terminal_run(&f, b"NO\n", || {}).0.success());
    assert!(!f.root.join("output.json").exists());
    let f = Fixture::new();
    let trust = f.root.join("trust.json");
    assert!(
        !terminal_run(&f, b"APPROVE\n", || {
            let mut config = f.trust.clone();
            config.caller = Caller {
                kind: "terminal".into(),
                id: "changed".into(),
            };
            fs::write(&trust, canonical_json(&config).unwrap()).unwrap();
        })
        .0
        .success()
    );
    assert!(!f.root.join("output.json").exists());
}
