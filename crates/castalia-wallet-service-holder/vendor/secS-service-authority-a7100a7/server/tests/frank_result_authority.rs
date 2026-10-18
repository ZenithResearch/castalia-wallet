//! Ordinary-library disposable owner/capture controls. No live role or signer.
use serde_json::{json, Value};
use server::manifest::{OpcodeRange, OperationDescriptor, OperationName, ReplayScope, TargetKind};
use server::privacy::DisclosurePolicy;
use server::{FrankResultAuthority, FrankResultMode, ServiceAuthority};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn write(p: &Path, b: &[u8]) {
    fs::write(p, b).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
}
fn directory(p: &Path) {
    fs::create_dir(p).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
}
fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn descriptor() -> OperationDescriptor {
    OperationDescriptor {
        opcode: 231,
        name: OperationName::new("frank.result.attest.v1"),
        payload_schema: Some("frank.native-result-payload.v1".into()),
        output_profile: None,
        target_kind: TargetKind::ReceiverProductionHandler,
        required_credentials: vec!["frank.local-review.result-party-assignment.v1".into()],
        required_capabilities: vec!["frank.result.attest.v1".into()],
        accepted_evidence: vec!["frank.local-review.capture.v1".into()],
        required_authority_mode: None,
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 60,
        handler_id: "fixture-result-receiver".into(),
        dev_binding: false,
        range: OpcodeRange::OperatorDefined,
        disclosure_policy: DisclosurePolicy::deny_by_default("frank.result-receipt.v1", 1),
    }
}
struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    config: PathBuf,
    pin: [u8; 32],
    selector: Vec<u8>,
    capture: PathBuf,
    payload: Vec<u8>,
    public: [u8; 32],
}
impl Fixture {
    fn new(outcome: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for n in ["issuer", "assignment", "captures", "journal"] {
            directory(&root.join(n));
        }
        for n in [
            "assignment/assignment.lock",
            "captures/capture.lock",
            "journal/journal.lock",
        ] {
            write(&root.join(n), b"");
        }
        directory(&root.join("captures/blobs"));
        let public = ServiceAuthority::create_issuer_key(&root.join("issuer")).unwrap();
        let producer = sha(b"disposable actual local fixture producer");
        let normalizer = sha(b"fixture normalization");
        let config_hash = sha(b"effect-disabled fixture configuration");
        let mut entries = Vec::new();
        for b in [
            b"disposable actual local fixture producer".as_slice(),
            b"fixture normalization",
            b"effect-disabled fixture configuration",
        ] {
            write(&root.join("captures/blobs").join(sha(b)), b);
            entries.push(json!({"sha256":sha(b),"byte_length":b.len()}));
        }
        let manifest = bytes(
            &json!({"schema":"frank.local-review.source-manifest.v1","producer_artifact_sha256":producer,"normalizer_sha256":normalizer,"configuration_sha256":config_hash,"entries":entries}),
        );
        write(&root.join("captures/source-manifest.json"), &manifest);
        let annotation = bytes(
            &json!({"schema":"review.transcript-annotation.v1","transcript":"","words":[],"audio_offset_ms":0,"events":[],"component_names":[],"review_id":"review-1","speech_policy":"verbatim; target evidence is separate","uncertainties":["Normalized events retain no raw gesture geometry; inspect the root events artifact."]}),
        );
        let annotation_ref = json!({"content_hash":sha(&annotation),"byte_length":annotation.len(),"media_type":"application/json"});
        let annotation_ref_bytes = bytes(&annotation_ref);
        for body in [&annotation, &annotation_ref_bytes] {
            write(&root.join("captures/blobs").join(sha(body)), body);
        }
        let work = bytes(
            &json!({"schema":"frank.work.v1","binding":{"run_id":"run-1","step_id":"step-1","attempt_id":"attempt-1","fence":1},"actor_id":"actor-1","integration_id":"local-review","route":"review-route","effect_id":"effect-1","operation":"review.annotate","scope":"review-1","inputs":{"transcript":"","words":[],"audio_offset_ms":0,"events":[],"component_names":[],"review_id":"review-1"},"output_types":{}}),
        );
        let result = json!({"schema":"frank.result.v1","event_id":"event-1","binding":{"run_id":"run-1","step_id":"step-1","attempt_id":"attempt-1","fence":1},"actor_id":"actor-1","integration_id":"local-review","route":"review-route","effect_id":"effect-1","provider_reference":"local-review:reservation-1","outcome":outcome,"outputs":if outcome=="succeeded" {json!({"resolved_transcript":"","transcript_note":annotation_ref})}else{json!({})}});
        let payload = bytes(
            &json!({"schema":"frank.native-result-payload.v1","work_sha256":sha(&work),"result":result}),
        );
        let claim = b"retained public-client claim observation in a disposable fixture";
        write(&root.join("captures/blobs").join(sha(claim)), claim);
        let mut observations = Vec::new();
        if outcome == "succeeded" {
            observations.push(json!({"kind":"artifact-write","input_sha256":sha(&annotation),"output_sha256":sha(&bytes(&annotation_ref)),"byte_length":bytes(&annotation_ref).len(),"reference":sha(&bytes(&annotation_ref))}));
        }
        observations.push(json!({"kind":"claim-check","input_sha256":sha(&work),"output_sha256":sha(claim),"byte_length":claim.len(),"reference":sha(claim)}));
        let receipt = bytes(
            &json!({"schema":"frank.local-review.capture.v1","reservation_id":"reservation-1","work_sha256":sha(&work),"payload_sha256":sha(&payload),"unsigned_result_sha256":sha(&bytes(&result)),"producer_artifact_sha256":producer,"normalizer_sha256":normalizer,"configuration_sha256":config_hash,"source_manifest_sha256":sha(&manifest),"operation":"review.annotate","outcome":outcome,"completion_kind":if outcome=="succeeded" {"computed"} else {"malformed_packet"},"observations":observations}),
        );
        let reservation = bytes(
            &json!({"schema":"frank.local-review.reservation.v1","reservation_id":"reservation-1","work_sha256":sha(&work),"configuration_sha256":config_hash}),
        );
        let id = sha(&reservation);
        let capture = root.join("captures").join(&id);
        directory(&capture);
        write(&capture.join("work.json"), &work);
        write(&capture.join("payload.json"), &payload);
        write(&capture.join("receipt.json"), &receipt);
        write(&capture.join("reservation.json"), &reservation);
        let t = now();
        let assignment = bytes(
            &json!({"schema":"frank.local-review.result-party-assignment.v1","assignment_id":"fixture-assignment","generation":1,"active":true,"subject_id":"fixture-result-party","key_id":"fixture-result-key","issuer_public_key_hex":public.iter().map(|b|format!("{b:02x}")).collect::<String>(),"actor_id":"actor-1","integration_id":"local-review","route":"review-route","run_ids":["run-1"],"operations":["review.annotate"],"producer_artifact_sha256":producer,"normalizer_sha256":normalizer,"configuration_sha256":config_hash,"source_manifest_sha256":sha(&manifest),"not_before":t-1,"not_after":t+600}),
        );
        write(&root.join("assignment/assignment.json"), &assignment);
        let config = root.join("authority.json");
        let raw = bytes(
            &json!({"schema":"frank.result-authority-configuration.v1","issuer_root":root.join("issuer"),"issuer_subject_id":"fixture-result-party","issuer_key_id":"fixture-result-key","issuer_public_key_hex":public.iter().map(|b|format!("{b:02x}")).collect::<String>(),"assignment_root":root.join("assignment"),"assignment_sha256":sha(&assignment),"capture_root":root.join("captures"),"journal_root":root.join("journal"),"descriptor":{"opcode":231,"handler_id":"fixture-result-receiver","fingerprint":descriptor().authorization_fingerprint().strip_prefix("descriptor:sha256:").unwrap()},"maximum_ttl":60}),
        );
        write(&config, &raw);
        let pin = hash(&raw);
        Self {
            _temp: temp,
            root,
            config,
            pin,
            selector: bytes(
                &json!({"schema":"frank.result-capture-selector.v1","capture_id":id,"renewal_of":null}),
            ),
            capture,
            payload,
            public,
        }
    }
    async fn authority(&self) -> FrankResultAuthority {
        FrankResultAuthority::open_pinned_owner_configuration(&self.config, self.pin)
            .await
            .unwrap()
    }
    fn repin(&mut self, change: impl FnOnce(&mut Value)) {
        let mut v: Value = serde_json::from_slice(&fs::read(&self.config).unwrap()).unwrap();
        change(&mut v);
        let b = bytes(&v);
        write(&self.config, &b);
        self.pin = hash(&b);
    }
}
fn native(
    raw: &[u8],
) -> (
    libsec_core::ZenithPacket,
    server::verifier::SignedVerifiedCallContext,
) {
    let value: Value = serde_json::from_slice(raw).unwrap();
    fn unhex(v: &str) -> Vec<u8> {
        (0..v.len())
            .step_by(2)
            .map(|n| u8::from_str_radix(&v[n..n + 2], 16).unwrap())
            .collect()
    }
    assert_eq!(value.as_object().unwrap().len(), 3);
    assert_eq!(value["schema"], "frank.secs-result-envelope.v1");
    (
        bincode::deserialize(&unhex(value["packet_hex"].as_str().unwrap())).unwrap(),
        bincode::deserialize(&unhex(value["signed_context_hex"].as_str().unwrap())).unwrap(),
    )
}

#[tokio::test]
async fn actual_key_clock_success_failure_and_exact_no_create_resume() {
    for outcome in ["succeeded", "failed"] {
        let f = Fixture::new(outcome);
        let a = f.authority().await;
        assert!(a
            .execute(FrankResultMode::Resume, &f.selector)
            .await
            .is_err());
        assert!(!f.root.join("journal/results.sqlite3").exists());
        let raw = a
            .execute(FrankResultMode::Attest, &f.selector)
            .await
            .unwrap();
        let (p, c) = native(&raw);
        assert_eq!(p.encrypted_payload, f.payload);
        assert_eq!(
            c.context.packet_hash,
            hash(&bincode::serialize(&p).unwrap())
        );
        assert_eq!(c.context.audience, "frank://result-receiver");
        assert_eq!(c.context.operation, "frank.result.attest.v1");
        assert_eq!(
            c.context.descriptor_fingerprint,
            descriptor().authorization_fingerprint()[18..]
        );
        assert!(c.context.issued_at <= now() && now() < c.context.expires_at);
        assert!(c.context.expires_at - c.context.issued_at <= 60);
        use ed25519_dalek::Verifier;
        ed25519_dalek::VerifyingKey::from_bytes(&f.public)
            .unwrap()
            .verify(
                &bincode::serialize(&c.context).unwrap(),
                &ed25519_dalek::Signature::from_slice(&c.signature).unwrap(),
            )
            .unwrap();
        let receipt: Value = serde_json::from_slice(&p.proof).unwrap();
        assert_eq!(receipt["claim"], "accountable-local-computation");
        assert!(c.context.credential_result.contains("fixture-assignment"));
        assert!(!c.context.evidence_summary.is_empty());
        assert!(a
            .execute(FrankResultMode::Attest, &f.selector)
            .await
            .is_err());
        drop(a);
        assert_eq!(
            f.authority()
                .await
                .execute(FrankResultMode::Resume, &f.selector)
                .await
                .unwrap(),
            raw
        );
        let mut changed = f.selector.clone();
        changed.push(b' ');
        assert!(f
            .authority()
            .await
            .execute(FrankResultMode::Resume, &changed)
            .await
            .is_err());
    }
}
#[tokio::test]
async fn explicit_renewal_is_one_edge_and_keeps_payload_and_original_bytes() {
    let f = Fixture::new("succeeded");
    let a = f.authority().await;
    let first = a
        .execute(FrankResultMode::Attest, &f.selector)
        .await
        .unwrap();
    let mut selector: Value = serde_json::from_slice(&f.selector).unwrap();
    selector["renewal_of"] = json!(sha(&first));
    let renewal = bytes(&selector);
    let second = a.execute(FrankResultMode::Renew, &renewal).await.unwrap();
    let (p1, c1) = native(&first);
    let (p2, c2) = native(&second);
    assert_eq!(p1.encrypted_payload, p2.encrypted_payload);
    assert_ne!(p1.nonce, p2.nonce);
    assert_ne!(c1.context.context_id, c2.context.context_id);
    assert_eq!(
        a.execute(FrankResultMode::Resume, &renewal).await.unwrap(),
        second
    );
    assert_eq!(
        a.execute(FrankResultMode::Resume, &f.selector)
            .await
            .unwrap(),
        first
    );
    assert!(a.execute(FrankResultMode::Renew, &renewal).await.is_err());
}
#[tokio::test]
async fn config_role_key_capture_and_provenance_changes_deny() {
    for change in [
        "config",
        "assignment",
        "work",
        "payload",
        "receipt",
        "reservation",
        "manifest",
        "key",
        "lock",
        "root",
    ] {
        let f = Fixture::new("succeeded");
        let a = f.authority().await;
        let raw = a
            .execute(FrankResultMode::Attest, &f.selector)
            .await
            .unwrap();
        let path = match change {
            "config" => f.config.clone(),
            "assignment" => f.root.join("assignment/assignment.json"),
            "work" => f.capture.join("work.json"),
            "payload" => f.capture.join("payload.json"),
            "receipt" => f.capture.join("receipt.json"),
            "reservation" => f.capture.join("reservation.json"),
            "manifest" => f.root.join("captures/source-manifest.json"),
            "key" => f.root.join("issuer/issuer.seed.hex"),
            "lock" => f.root.join("journal/journal.lock"),
            _ => f.root.join("journal"),
        };
        if change == "root" {
            fs::rename(&path, f.root.join("displaced")).unwrap();
            directory(&path);
            write(&path.join("journal.lock"), b"");
        } else if change == "lock" {
            fs::rename(&path, f.root.join("old-lock")).unwrap();
            write(&path, b"");
        } else {
            let mut b = fs::read(&path).unwrap();
            b.push(b' ');
            write(&path, &b);
        }
        assert!(
            a.execute(FrankResultMode::Resume, &f.selector)
                .await
                .is_err(),
            "accepted {change}"
        );
        assert!(!raw.is_empty());
    }
}
#[tokio::test]
async fn wrong_pins_scope_and_closed_selectors_deny() {
    for change in ["pin", "opcode", "fingerprint", "key", "ttl", "extra"] {
        let mut f = Fixture::new("succeeded");
        if change == "pin" {
            f.pin = [0; 32];
        } else {
            f.repin(|v| match change {
                "opcode" => v["descriptor"]["opcode"] = json!(1),
                "fingerprint" => v["descriptor"]["fingerprint"] = json!("descriptor:sha256:wrong"),
                "key" => v["issuer_key_id"] = json!("other"),
                "ttl" => v["maximum_ttl"] = json!(61),
                _ => v["clock"] = json!(1),
            });
        }
        let opened = FrankResultAuthority::open_pinned_owner_configuration(&f.config, f.pin).await;
        if let Ok(a) = opened {
            assert!(
                a.execute(FrankResultMode::Attest, &f.selector)
                    .await
                    .is_err(),
                "accepted {change}"
            );
        }
    }
    let f = Fixture::new("succeeded");
    let a = f.authority().await;
    for raw in [
        b"{}".as_slice(),
        b"{\"schema\":\"x\",\"schema\":\"y\"}",
        b"{\"capture_id\":\"../../key\"}",
    ] {
        assert!(a.execute(FrankResultMode::Attest, raw).await.is_err());
    }
}
#[tokio::test]
async fn normal_binary_uses_pinned_config_and_exact_stdout_envelope() {
    let f = Fixture::new("succeeded");
    let binary = env!("CARGO_BIN_EXE_secs-frank-result");
    use std::io::Write;
    let mut c = std::process::Command::new(binary)
        .args([
            "attest",
            "--config",
            f.config.to_str().unwrap(),
            "--config-sha256",
            &sha(&fs::read(&f.config).unwrap()),
        ])
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(&f.selector).unwrap();
    let out = c.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    native(&out.stdout);
}

impl Fixture {
    // Rebind a disposable fixture with exact raw JSON; no numeric round-trip.
    fn replace_raw(&mut self, work: Vec<u8>, result: Vec<u8>) {
        let payload=format!("{{\"schema\":\"frank.native-result-payload.v1\",\"work_sha256\":\"{}\",\"result\":{}}}",sha(&work),std::str::from_utf8(&result).unwrap()).into_bytes();
        let mut receipt: Value =
            serde_json::from_slice(&fs::read(self.capture.join("receipt.json")).unwrap()).unwrap();
        receipt["work_sha256"] = json!(sha(&work));
        receipt["payload_sha256"] = json!(sha(&payload));
        receipt["unsigned_result_sha256"] = json!(sha(&result));
        receipt["observations"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap()["input_sha256"] = json!(sha(&work));
        let mut reservation: Value =
            serde_json::from_slice(&fs::read(self.capture.join("reservation.json")).unwrap())
                .unwrap();
        reservation["work_sha256"] = json!(sha(&work));
        let raw = bytes(&reservation);
        let id = sha(&raw);
        let dest = self.root.join("captures").join(&id);
        if dest != self.capture {
            directory(&dest);
        }
        for (name, b) in [
            ("reservation.json", raw),
            ("receipt.json", bytes(&receipt)),
            ("work.json", work),
            ("payload.json", payload.clone()),
        ] {
            write(&dest.join(name), &b);
        }
        self.capture = dest;
        self.payload = payload;
        self.selector = bytes(
            &json!({"schema":"frank.result-capture-selector.v1","capture_id":id,"renewal_of":null}),
        );
    }
    fn raw_result(&self) -> Vec<u8> {
        #[derive(serde::Deserialize)]
        struct P {
            result: Box<serde_json::value::RawValue>,
        }
        serde_json::from_slice::<P>(&self.payload)
            .unwrap()
            .result
            .get()
            .as_bytes()
            .to_vec()
    }
}
#[tokio::test]
async fn original_numeric_unicode_payload_bytes_survive_and_duplicate_or_nonfinite_denies() {
    for value in [
        "-0.0",
        "1.234e-12",
        "184467440737095516160000000000",
        "\"é😀\\u007f\"",
        "[true,null,false]",
    ] {
        let mut f = Fixture::new("succeeded");
        let work = String::from_utf8(fs::read(f.capture.join("work.json")).unwrap())
            .unwrap()
            .replacen(
                "\"inputs\":{",
                &format!("\"inputs\":{{\"probe\":{value},"),
                1,
            );
        let result = f.raw_result();
        f.replace_raw(work.into_bytes(), result);
        let out = f
            .authority()
            .await
            .execute(FrankResultMode::Attest, &f.selector)
            .await
            .unwrap();
        assert_eq!(native(&out).0.encrypted_payload, f.payload);
    }
    for value in [
        "NaN",
        "1e999",
        "01",
        "{\"same\":1,\"same\":2}",
        "\"\\ud800\"",
    ] {
        let mut f = Fixture::new("succeeded");
        let work = String::from_utf8(fs::read(f.capture.join("work.json")).unwrap())
            .unwrap()
            .replacen(
                "\"inputs\":{",
                &format!("\"inputs\":{{\"probe\":{value},"),
                1,
            );
        let result = f.raw_result();
        f.replace_raw(work.into_bytes(), result);
        assert!(f
            .authority()
            .await
            .execute(FrankResultMode::Attest, &f.selector)
            .await
            .is_err());
    }
}
#[tokio::test]
async fn mismatched_body_claim_or_undeclared_evidence_denies() {
    for field in ["actor_id", "route", "effect_id", "attempt_id"] {
        let mut f = Fixture::new("succeeded");
        let work = fs::read(f.capture.join("work.json")).unwrap();
        let mut result: Value = serde_json::from_slice(&f.raw_result()).unwrap();
        if field == "attempt_id" {
            result["binding"][field] = json!("other");
        } else {
            result[field] = json!("other");
        }
        f.replace_raw(work, bytes(&result));
        assert!(f
            .authority()
            .await
            .execute(FrankResultMode::Attest, &f.selector)
            .await
            .is_err());
    }
    for mutation in [
        "empty",
        "not-final-claim",
        "missing-blob",
        "unknown-kind",
        "wrong-length",
    ] {
        let f = Fixture::new("succeeded");
        let p = f.capture.join("receipt.json");
        let mut r: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        match mutation {
            "empty" => r["observations"] = json!([]),
            "not-final-claim" => {
                r["observations"]
                    .as_array_mut()
                    .unwrap()
                    .last_mut()
                    .unwrap()["kind"] = json!("artifact-read")
            }
            "missing-blob" => r["observations"][0]["output_sha256"] = json!("0".repeat(64)),
            "unknown-kind" => r["observations"][0]["kind"] = json!("work-input"),
            _ => r["observations"][0]["byte_length"] = json!(0),
        }
        write(&p, &bytes(&r));
        assert!(
            f.authority()
                .await
                .execute(FrankResultMode::Attest, &f.selector)
                .await
                .is_err(),
            "accepted {mutation}"
        );
    }
}
#[tokio::test]
async fn all_state_deleted_relations_changed_records_and_lowered_floor_deny() {
    use sqlx::Connection;
    for sql in [
        "DELETE FROM captures",
        "DELETE FROM attestations",
        "UPDATE meta SET high_water=0",
        "UPDATE captures SET original=x'00'",
        "UPDATE attestations SET record=x'00'",
        "UPDATE attestations SET parent='orphan'",
        "UPDATE attestations SET replay='changed'",
    ] {
        let f = Fixture::new("succeeded");
        let a = f.authority().await;
        let _ = a
            .execute(FrankResultMode::Attest, &f.selector)
            .await
            .unwrap();
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(f.root.join("journal/results.sqlite3"))
            .create_if_missing(false);
        let mut db = sqlx::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        sqlx::query(sql).execute(&mut db).await.unwrap();
        db.close().await.unwrap();
        drop(a);
        let a = f.authority().await;
        assert!(
            a.execute(FrankResultMode::Resume, &f.selector)
                .await
                .is_err(),
            "accepted {sql}"
        );
        assert!(
            a.execute(FrankResultMode::Attest, &f.selector)
                .await
                .is_err(),
            "reissued after {sql}"
        );
    }
}
#[tokio::test]
async fn expired_resume_denies_but_explicit_same_body_renewal_works_and_is_bounded() {
    let mut f = Fixture::new("succeeded");
    f.repin(|v| v["maximum_ttl"] = json!(8));
    let a = f.authority().await;
    let first = a
        .execute(FrankResultMode::Attest, &f.selector)
        .await
        .unwrap();
    let expiry = native(&first).1.context.expires_at;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while now() < expiry {
        assert!(
            std::time::Instant::now() < deadline,
            "fixture expiry clock did not advance"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(now() >= expiry);
    assert!(a
        .execute(FrankResultMode::Resume, &f.selector)
        .await
        .is_err());
    let mut s: Value = serde_json::from_slice(&f.selector).unwrap();
    s["renewal_of"] = json!(sha(&first));
    let next = a.execute(FrankResultMode::Renew, &bytes(&s)).await.unwrap();
    assert_eq!(
        native(&next).0.encrypted_payload,
        native(&first).0.encrypted_payload
    );
    // Separate ordinary window avoids sleep/race assumptions in the finite-chain bound.
    let f = Fixture::new("succeeded");
    let a = f.authority().await;
    let mut previous = a
        .execute(FrankResultMode::Attest, &f.selector)
        .await
        .unwrap();
    let original = previous.clone();
    let mut s: Value = serde_json::from_slice(&f.selector).unwrap();
    for _ in 1..16 {
        s["renewal_of"] = json!(sha(&previous));
        previous = a.execute(FrankResultMode::Renew, &bytes(&s)).await.unwrap();
    }
    s["renewal_of"] = json!(sha(&previous));
    assert!(a.execute(FrankResultMode::Renew, &bytes(&s)).await.is_err());
    assert_eq!(
        a.execute(FrankResultMode::Resume, &f.selector)
            .await
            .unwrap(),
        original
    );
}
#[tokio::test]
async fn simultaneous_instances_create_only_one_initial_record() {
    let f = Fixture::new("succeeded");
    let a = f.authority().await;
    let b = f.authority().await;
    let (x, y) = tokio::join!(
        a.execute(FrankResultMode::Attest, &f.selector),
        b.execute(FrankResultMode::Attest, &f.selector)
    );
    assert_eq!(usize::from(x.is_ok()) + usize::from(y.is_ok()), 1);
    let result = x.or(y).unwrap();
    assert_eq!(
        f.authority()
            .await
            .execute(FrankResultMode::Resume, &f.selector)
            .await
            .unwrap(),
        result
    );
}

impl Fixture {
    fn operation_case(operation: &str) -> Self {
        let mut f = Self::new("succeeded");
        let artifact = |raw: &[u8], media: &str| json!({"content_hash":sha(raw),"byte_length":raw.len(),"media_type":media});
        let audio = b"fixture audio".to_vec();
        let events = b"[]".to_vec();
        let packet = b"{}".to_vec();
        let note = b"# fixture note".to_vec();
        let audio_ref = artifact(&audio, "audio/wav");
        let events_ref = artifact(&events, "application/json");
        let packet_ref = artifact(&packet, "application/json");
        let note_ref = artifact(&note, "text/markdown");
        let binding =
            json!({"run_id":"run-1","step_id":"step-1","attempt_id":"attempt-1","fence":1});
        let mut trace: Vec<(&str, Vec<u8>, Vec<u8>)> = Vec::new();
        let (inputs, outputs) = match operation {
            "review.load_review" => {
                trace.push(("artifact-read", bytes(&json!([audio_ref])), audio));
                trace.push(("artifact-read", bytes(&json!([events_ref])), events));
                (
                    json!({"review_id":"review-1","audio_asset":audio_ref,"events_asset":events_ref}),
                    json!({"review_id_short":"review-1","audio_asset":audio_ref,"events":[]}),
                )
            }
            "review.transcribe" => {
                let response = json!({"transcript":"","audio_offset_ms":0,"words":[]});
                trace.push(("artifact-read", bytes(&json!([audio_ref])), audio.clone()));
                trace.push(("provider-response", audio, bytes(&response)));
                (json!({"audio_asset":audio_ref}), response)
            }
            "review.resolve_components" => {
                trace.push((
                    "component-snapshot-read",
                    bytes(&json!(["subject-1", []])),
                    b"[]".to_vec(),
                ));
                (
                    json!({"subject_id":"subject-1","events":[]}),
                    json!({"component_names":[]}),
                )
            }
            "review.annotate" => {
                return f;
            }
            "review.extract" => {
                trace.push(("artifact-write", packet, bytes(&packet_ref)));
                (
                    json!({"resolved_transcript":"","words":[],"events":[],"component_names":[]}),
                    json!({"review_packet":packet_ref}),
                )
            }
            "review.bind_source" => {
                trace.push((
                    "source-snapshot-read",
                    bytes(&json!(["subject-1", ["#a"]])),
                    b"[]".to_vec(),
                ));
                (
                    json!({"subject_id":"subject-1","observations":[{"selectors":["#a"]}]}),
                    json!({"codebase_context":[{}]}),
                )
            }
            "review.write_review" => {
                trace.push(("artifact-read", bytes(&json!([packet_ref])), packet.clone()));
                trace.push(("artifact-write", packet, bytes(&packet_ref)));
                trace.push(("artifact-write", note, bytes(&note_ref)));
                (
                    json!({"review_packet":packet_ref}),
                    json!({"review_packet":packet_ref,"review_note":note_ref}),
                )
            }
            "review.write_status" => {
                trace.push(("artifact-read", bytes(&json!([packet_ref])), packet));
                trace.push(("artifact-read", bytes(&json!([note_ref])), note));
                trace.push(("simulated-intent",bytes(&json!([binding,"review.status",{"review_id":"review-1","decision":"processed","review_packet":packet_ref}])),bytes(&json!({"recorded":true,"simulation":true}))));
                (
                    json!({"review_id":"review-1","review_packet":packet_ref,"review_note":note_ref}),
                    json!({"review_status_updated":{"review_id":"review-1","review_note":note_ref,"status":"simulated_processed"}}),
                )
            }
            "review.daily_note" => {
                trace.push(("artifact-read", bytes(&json!([note_ref])), note.clone()));
                trace.push(("artifact-read", bytes(&json!([note_ref])), note));
                trace.push(("simulated-intent",bytes(&json!([binding,"vault.daily-note",{"review_id":"review-1","subject_id":"subject-1","line":"Simulated review review-1: 0 speech-derived feedback item(s).","review_note":note_ref}])),bytes(&json!({"recorded":true,"simulation":true}))));
                (
                    json!({"review_id":"review-1","review_id_short":"review-1","subject_id":"subject-1","transcript_note":note_ref,"review_note":note_ref,"observations":[]}),
                    json!({}),
                )
            }
            _ => panic!("fixture operation"),
        };
        f.install_operation(operation, inputs, outputs, trace);
        f
    }
    fn install_operation(
        &mut self,
        operation: &str,
        inputs: Value,
        outputs: Value,
        trace: Vec<(&str, Vec<u8>, Vec<u8>)>,
    ) {
        let mut work: Value =
            serde_json::from_slice(&fs::read(self.capture.join("work.json")).unwrap()).unwrap();
        work["operation"] = json!(operation);
        work["inputs"] = inputs;
        let mut result: Value = serde_json::from_slice(&self.raw_result()).unwrap();
        result["outputs"] = outputs;
        self.replace_raw(bytes(&work), bytes(&result));
        let path = self.capture.join("receipt.json");
        let mut receipt: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        receipt["operation"] = json!(operation);
        let claim = receipt["observations"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .clone();
        let mut observations = Vec::new();
        for (kind, input, output) in trace {
            for body in [&input, &output] {
                write(&self.root.join("captures/blobs").join(sha(body)), body);
            }
            observations.push(json!({"kind":kind,"input_sha256":sha(&input),"output_sha256":sha(&output),"byte_length":output.len(),"reference":sha(&output)}));
        }
        observations.push(claim);
        receipt["observations"] = json!(observations);
        write(&path, &bytes(&receipt));
        let path = self.root.join("assignment/assignment.json");
        let mut assignment: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assignment["operations"] = json!([operation]);
        let raw = bytes(&assignment);
        write(&path, &raw);
        self.repin(|config| config["assignment_sha256"] = json!(sha(&raw)));
    }
}
#[tokio::test]
async fn successful_operations_require_correlated_actual_port_traces() {
    for operation in [
        "review.load_review",
        "review.transcribe",
        "review.resolve_components",
        "review.annotate",
        "review.extract",
        "review.bind_source",
        "review.write_review",
        "review.write_status",
        "review.daily_note",
    ] {
        for mutation in ["valid", "missing-port", "wrong-input"] {
            let f = Fixture::operation_case(operation);
            if mutation != "valid" {
                let path = f.capture.join("receipt.json");
                let mut receipt: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                if mutation == "missing-port" {
                    receipt["observations"].as_array_mut().unwrap().remove(0);
                } else {
                    receipt["observations"][0]["input_sha256"] = receipt["work_sha256"].clone();
                }
                write(&path, &bytes(&receipt));
            }
            let result = f
                .authority()
                .await
                .execute(FrankResultMode::Attest, &f.selector)
                .await;
            assert_eq!(
                result.is_ok(),
                mutation == "valid",
                "{operation} {mutation}"
            );
        }
    }
    for operation in ["review.annotate", "review.extract", "review.write_review"] {
        let mut f = Fixture::operation_case(operation);
        let work = fs::read(f.capture.join("work.json")).unwrap();
        let mut result: Value = serde_json::from_slice(&f.raw_result()).unwrap();
        let key = if operation == "review.annotate" {
            "transcript_note"
        } else {
            "review_packet"
        };
        result["outputs"][key]["content_hash"] = json!("0".repeat(64));
        f.replace_raw(work, bytes(&result));
        assert!(
            f.authority()
                .await
                .execute(FrankResultMode::Attest, &f.selector)
                .await
                .is_err(),
            "accepted unrelated artifact output: {operation}"
        );
    }
    let mut f = Fixture::new("succeeded");
    f.install_operation(
        "review.bind_source",
        json!({"subject_id":"subject-1","observations":[]}),
        json!({"codebase_context":[]}),
        Vec::new(),
    );
    assert!(
        f.authority()
            .await
            .execute(FrankResultMode::Attest, &f.selector)
            .await
            .is_ok(),
        "zero-observation pure computation fabricated a port obligation"
    );
    // A known failure is a valid prefix: no later write/provider is invented.
    let f = Fixture::new("failed");
    assert!(f
        .authority()
        .await
        .execute(FrankResultMode::Attest, &f.selector)
        .await
        .is_ok());
}

#[tokio::test]
async fn failed_artifact_integrity_capture_keeps_actual_return_without_later_provider() {
    let mut f = Fixture::operation_case("review.transcribe");
    let work = fs::read(f.capture.join("work.json")).unwrap();
    let mut result: Value = serde_json::from_slice(&f.raw_result()).unwrap();
    result["outcome"] = json!("failed");
    result["outputs"] = json!({});
    f.replace_raw(work, bytes(&result));
    let returned = b"actual mismatching artifact return";
    write(&f.root.join("captures/blobs").join(sha(returned)), returned);
    let path = f.capture.join("receipt.json");
    let mut receipt: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    receipt["outcome"] = json!("failed");
    receipt["completion_kind"] = json!("artifact_integrity_mismatch");
    let rows = receipt["observations"].as_array_mut().unwrap();
    rows.remove(1); // The failed read prevents the provider call.
    rows[0]["output_sha256"] = json!(sha(returned));
    rows[0]["reference"] = json!(sha(returned));
    rows[0]["byte_length"] = json!(returned.len());
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1]["kind"], "claim-check");
    write(&path, &bytes(&receipt));
    assert!(f
        .authority()
        .await
        .execute(FrankResultMode::Attest, &f.selector)
        .await
        .is_ok());
}

#[tokio::test]
async fn raw_result_output_numeric_unicode_lexemes_survive_and_invalid_values_deny() {
    for value in [
        "-0.0",
        "1.234e-12",
        "184467440737095516160000000000",
        "\"é😀\\u007f\"",
        "[true,null,false]",
    ] {
        let mut f = Fixture::new("succeeded");
        let work = fs::read(f.capture.join("work.json")).unwrap();
        let original = String::from_utf8(f.raw_result()).unwrap();
        assert_eq!(original.matches("\"outputs\":{").count(), 1);
        // Insert raw lexemes alongside the required valid annotation outputs.
        // No serde Value conversion touches the result or its probe.
        let result = original
            .replacen(
                "\"outputs\":{",
                &format!("\"outputs\":{{\"probe\":{value},"),
                1,
            )
            .into_bytes();
        f.replace_raw(work, result.clone());
        assert_eq!(f.raw_result(), result);
        let expected_payload = f.payload.clone();
        let out = f
            .authority()
            .await
            .execute(FrankResultMode::Attest, &f.selector)
            .await
            .unwrap();
        assert_eq!(native(&out).0.encrypted_payload, expected_payload);
    }
    for value in [
        "NaN",
        "1e999",
        "01",
        "{\"same\":1,\"same\":2}",
        "\"\\ud800\"",
    ] {
        let mut f = Fixture::new("succeeded");
        let work = fs::read(f.capture.join("work.json")).unwrap();
        let original = String::from_utf8(f.raw_result()).unwrap();
        assert_eq!(original.matches("\"outputs\":{").count(), 1);
        let result = original
            .replacen(
                "\"outputs\":{",
                &format!("\"outputs\":{{\"probe\":{value},"),
                1,
            )
            .into_bytes();
        f.replace_raw(work, result);
        assert!(f
            .authority()
            .await
            .execute(FrankResultMode::Attest, &f.selector)
            .await
            .is_err());
    }
}
