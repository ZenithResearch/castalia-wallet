//! Actual subprocess and secS cryptography, all identities/state disposable.
use ed25519_dalek::SigningKey;
use secs_grant_contract::{IssuerPin, Validity, scoped_grants as c};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
struct Harness {
    _directory: tempfile::TempDir,
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    sequence: u64,
}
fn clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn issuer() -> (SigningKey, IssuerPin) {
    let key = SigningKey::from_bytes(&[78; 32]);
    let pin = IssuerPin {
        issuer: "fixture-provider".into(),
        key_id: "fixture-key".into(),
        service: "service:fixture".into(),
        public_key: hex::encode(key.verifying_key().as_bytes()),
    };
    (key, pin)
}
fn permission() -> c::Permission {
    serde_json::from_value(
        json!({"operation":"fixture.read","resource":"fixture:objects",
        "roles":[{"role":"target","selector":{"schema":"secs.resource-selector.v1",
        "service":"service:fixture","kinds":["Object"],"selection":{"mode":"objects",
        "refs":[{"kind":"Object","id":"one"}]}}}],"constraints":{}}),
    )
    .unwrap()
}
impl Harness {
    fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.json");
        let (_, pin) = issuer();
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({"schema":"castalia.session-agent-profile.v1",
            "provider":pin,"receiver":{"issuer":pin.issuer,"key_id":pin.key_id,
            "public_key":pin.public_key,"receiver":"https://fixture.invalid","audience":"fixture"},
            "maximum_session_seconds":3600}))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_castalia-session-agent"))
            .arg("--profile-file")
            .arg(path.canonicalize().unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            _directory: directory,
            child,
            input,
            output,
            sequence: 0,
        }
    }
    fn raw(&mut self, value: &Value) -> Value {
        writeln!(self.input, "{}", serde_json::to_string(value).unwrap()).unwrap();
        self.input.flush().unwrap();
        let mut line = String::new();
        assert!(
            self.output.read_line(&mut line).unwrap() > 0,
            "native helper terminated"
        );
        serde_json::from_str(&line).unwrap()
    }
    fn request(&mut self, body: Value) -> Value {
        self.sequence += 1;
        self.raw(&json!({"schema":"castalia.session-agent-command.v1",
                        "request_id":format!("{:032x}",self.sequence),"body":body}))
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn process_creation_is_explicit_idempotent_and_has_no_key_export() {
    let mut h = Harness::start();
    let end = clock() + 300;
    let request = json!({"schema":"castalia.session-agent-command.v1","request_id":"aa".repeat(16),
                      "body":{"operation":"create_session","expires_at":end}});
    let first = h.raw(&request);
    assert_eq!(first["ok"], true);
    assert_eq!(first, h.raw(&request));
    assert_eq!(first["value"].as_object().unwrap().len(), 5);
    assert!(first["value"]["holder_public_key"].as_str().unwrap().len() == 64);
    let mut changed = request;
    changed["body"]["expires_at"] = (end - 1).into();
    assert_eq!(h.raw(&changed)["error"], "session_command_conflict");
    assert_eq!(h.request(json!({"operation":"export_seed"}))["ok"], false);
    assert_eq!(
        h.request(json!({"operation":"create_session","expires_at":end,"seed":"untrusted"}))["ok"],
        false
    );
}

#[test]
fn process_installs_exact_new_holder_root_and_presents_real_secs_proof() {
    let mut h = Harness::start();
    let now = clock();
    let end = now + 300;
    let created = h.request(json!({"operation":"create_session","expires_at":end}));
    let session = &created["value"];
    let handle = session["session_handle"].clone();
    let call =
        json!({"operation":"fixture.read","resource":"fixture:objects","parameters":{"id":"one"}});
    assert_eq!(
        h.request(json!({"operation":"present_call","session_handle":handle,"call":call}))["ok"],
        false
    );
    let (key, pin) = issuer();
    let root = c::issue_grant(
        &pin,
        c::GrantClaims {
            schema: c::GRANT.into(),
            grant_id: "11".repeat(16),
            revision: "22".repeat(32),
            issuer: pin.issuer.clone(),
            key_id: pin.key_id.clone(),
            service: pin.service.clone(),
            holder_public_key: session["holder_public_key"].as_str().unwrap().into(),
            installation_id: Some(session["installation_id"].as_str().unwrap().into()),
            validity: Validity::Dated {
                not_before: now - 1,
                not_after: end,
            },
            max_credential_lifetime_seconds: 60,
            onward_delegation: false,
            permissions: vec![permission()],
        },
        &key,
        now,
    )
    .unwrap();
    let bad = h.request(
        json!({"operation":"install_grant","session_handle":handle,"grant":root,
        "reviewed_expiry":end-1,"reviewed_permissions":[permission()]}),
    );
    assert_eq!(bad["ok"], false);
    let installed = h.request(
        json!({"operation":"install_grant","session_handle":handle,"grant":root,
        "reviewed_expiry":end,"reviewed_permissions":[permission()]}),
    );
    assert_eq!(installed["value"]["installed"], true);
    let presented =
        h.request(json!({"operation":"present_call","session_handle":handle,"call":call}));
    assert_eq!(presented["ok"], true);
    let envelope = &presented["value"];
    let credential: c::Credential = serde_json::from_value(envelope["credential"].clone()).unwrap();
    let proof = serde_json::from_value(envelope["proof"].clone()).unwrap();
    c::verify_presentation(&pin, &credential, &call, &proof, clock()).unwrap();
    assert_eq!(
        credential.claims.holder_public_key,
        session["holder_public_key"]
    );
    assert!(credential.claims.expires_at <= end);
    assert_eq!(
        h.request(json!({"operation":"close_session","session_handle":handle}))["value"]["server_revocation_confirmed"],
        false
    );
    assert_eq!(
        h.request(json!({"operation":"present_call","session_handle":handle,"call":call}))["ok"],
        false
    );
}
