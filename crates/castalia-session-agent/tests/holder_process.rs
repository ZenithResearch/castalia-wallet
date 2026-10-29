use ed25519_dalek::SigningKey;
use secs_grant_contract::{self as c, holder_sessions as s};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
struct Harness {
    _dir: tempfile::TempDir,
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    n: u64,
}
fn clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../vendor/secs-grant-contract/tests/fixtures/holder-session-v1.json"
    ))
    .unwrap()
}
impl Harness {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        let v = vector();
        std::fs::write(&path,serde_json::to_vec(&json!({"schema":"castalia.holder-session-agent-profile.v1","provider":v["pin"],"context":v["context"],"maximum_session_seconds":600})).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_castalia-holder-session-agent"))
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
            _dir: dir,
            child,
            input,
            output,
            n: 0,
        }
    }
    fn raw(&mut self, v: Value) -> Value {
        writeln!(self.input, "{v}").unwrap();
        self.input.flush().unwrap();
        let mut line = String::new();
        assert!(self.output.read_line(&mut line).unwrap() > 0);
        serde_json::from_str(&line).unwrap()
    }
    fn call(&mut self, body: Value) -> Value {
        self.n += 1;
        self.raw(json!({"schema":"castalia.holder-session-agent-command.v1","request_id":format!("{:032x}",self.n),"body":body}))
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn native_holder_helper_issues_no_grant_but_presents_finite_token_without_wallet() {
    let mut h = Harness::start();
    let now = clock();
    let v = vector();
    let identity = h.call(json!({"operation":"create_session","expires_at":now+500}));
    assert_eq!(identity["ok"], true);
    // The helper creates its key using its own clock. A challenge cannot predate
    // creation if process startup crosses a second boundary.
    let now = clock();
    let value = &identity["value"];
    assert!(value.get("holder_public_key").is_none());
    let handle = value["session_handle"].clone();
    let issuer = SigningKey::from_bytes(&[61; 32]);
    let holder = SigningKey::from_bytes(&[62; 32]);
    let pin = serde_json::from_value(v["pin"].clone()).unwrap();
    let context = serde_json::from_value(v["context"].clone()).unwrap();
    let mut parent: c::scoped_grants::Grant =
        serde_json::from_value(v["parent_grant"].clone()).unwrap();
    parent.claims.validity = c::Validity::Dated {
        not_before: now - 1,
        not_after: now + 1000,
    };
    parent = c::scoped_grants::issue_grant(&pin, parent.claims, &issuer, now).unwrap();
    let mut challenge: s::Challenge = serde_json::from_value(v["challenge"].clone()).unwrap();
    challenge.parent_grant_digest = c::digest(&parent).unwrap();
    challenge.session_public_key = value["session_public_key"].as_str().unwrap().into();
    challenge.session_installation_id = value["session_installation_id"].as_str().unwrap().into();
    challenge.issued_at = now;
    challenge.review_deadline = now + 120;
    challenge.expires_at = now + 300;
    let pop = h.call(
        json!({"operation":"prove_possession","session_handle":handle,"challenge":challenge}),
    );
    assert_eq!(pop["ok"], true, "{pop}");
    let authorization = s::authorize(
        &pin,
        parent.clone(),
        challenge.clone(),
        pop["value"]["session_signature"].as_str().unwrap().into(),
        &context,
        &holder,
        now,
    )
    .unwrap();
    let token = s::issue(
        &pin,
        &authorization,
        "88".repeat(16),
        &context,
        &issuer,
        now,
    )
    .unwrap();
    let installed=h.call(json!({"operation":"install_credential","session_handle":handle,"credential":token,"reviewed_challenge":challenge}));
    assert_eq!(installed["ok"], true);
    let proof =
        h.call(json!({"operation":"present_call","session_handle":handle,"call":v["call"]}));
    assert_eq!(proof["ok"], true);
    s::verify_presentation(
        &pin,
        &parent,
        &serde_json::from_value(proof["value"]["credential"].clone()).unwrap(),
        &v["call"],
        &serde_json::from_value(proof["value"]["proof"].clone()).unwrap(),
        &context,
        clock(),
    )
    .unwrap();
    let status =
        h.call(json!({"operation":"status_proof","session_handle":handle,"challenge":challenge}));
    assert_eq!(status["ok"], true);
    s::verify_status(
        &challenge,
        &serde_json::from_value(status["value"].clone()).unwrap(),
        &context,
        clock(),
    )
    .unwrap();
    assert_eq!(
        h.call(
            json!({"operation":"prove_possession","session_handle":handle,"challenge":challenge})
        )["ok"],
        false
    );
    assert_eq!(
        h.call(json!({"operation":"close_session","session_handle":handle}))["value"]["server_revocation_confirmed"],
        false
    );
    assert_eq!(
        h.call(json!({"operation":"present_call","session_handle":handle,"call":v["call"]}))["ok"],
        false
    );
}

#[test]
fn holder_agent_rejects_owner_wire_seed_import_and_conflicting_identity_retries() {
    let mut h = Harness::start();
    let now = clock();
    let command = json!({"schema":"castalia.holder-session-agent-command.v1","request_id":"aa".repeat(16),"body":{"operation":"create_session","expires_at":now+300}});
    let one = h.raw(command.clone());
    let two = h.raw(command.clone());
    assert_eq!(one, two);
    let mut changed = command.clone();
    changed["body"]["expires_at"] = json!(now + 301);
    assert_eq!(h.raw(changed)["ok"], false);
    let mut old = command;
    old["schema"] = json!("castalia.session-agent-command.v1");
    assert_eq!(h.raw(old)["ok"], false);
    for op in [
        "install_grant",
        "approve_enrollment",
        "approve_member_request",
        "import_seed",
        "sign",
    ] {
        assert_eq!(h.call(json!({"operation":op}))["ok"], false);
    }
}
