//! Fixed accountable local-review attestation. No generic signer or live setup.
use crate::{
    frank_result_contract as contract,
    frank_result_store::{HeldFile, Root, Store},
    receipt::AuthenticatorKind,
    verifier::{SignedVerifiedCallContext, VerifiedCallContext, VerifiedSubject},
    work_private_files::{HeldIssuerFiles, IssuerDirectory},
};
use bincode::Options;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrankResultError;
impl std::fmt::Display for FrankResultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native result authority denied")
    }
}
impl std::error::Error for FrankResultError {}
pub(crate) use FrankResultError as Error;
pub(super) type Result<T> = std::result::Result<T, Error>;
pub(super) fn hash(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
pub(super) fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn sha(b: &[u8]) -> String {
    hex(&hash(b))
}
// Only newly constructed metadata uses this serializer. Raw work/result/payload
// never enter it. Sorted keys are stable under hostile serde_json map features.
fn json<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    fn emit(v: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
        match v {
            serde_json::Value::Object(map) => {
                out.push(b'{');
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                for (i, (key, value)) in entries.into_iter().enumerate() {
                    if i != 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(key).map_err(|_| Error)?);
                    out.push(b':');
                    emit(value, out)?;
                }
                out.push(b'}');
            }
            serde_json::Value::Array(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i != 0 {
                        out.push(b',');
                    }
                    emit(item, out)?;
                }
                out.push(b']');
            }
            _ => out.extend(serde_json::to_vec(v).map_err(|_| Error)?),
        }
        Ok(())
    }
    let value = serde_json::to_value(v).map_err(|_| Error)?;
    let mut out = Vec::new();
    emit(&value, &mut out)?;
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FrankResultMode {
    Attest,
    Resume,
    Renew,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    issuer_root: PathBuf,
    issuer_subject_id: String,
    issuer_key_id: String,
    issuer_public_key_hex: String,
    assignment_root: PathBuf,
    assignment_sha256: String,
    capture_root: PathBuf,
    journal_root: PathBuf,
    descriptor: Descriptor,
    maximum_ttl: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    opcode: u8,
    handler_id: String,
    fingerprint: String,
}
impl Descriptor {
    fn validate(&self) -> Result<()> {
        use crate::manifest::*;
        if self.opcode < 64 || !contract::identifier(&self.handler_id) {
            return Err(Error);
        }
        contract::digest(&self.fingerprint)?;
        let d = OperationDescriptor {
            opcode: self.opcode,
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
            handler_id: self.handler_id.clone(),
            dev_binding: false,
            range: OpcodeRange::OperatorDefined,
            disclosure_policy: crate::privacy::DisclosurePolicy::deny_by_default(
                "frank.result-receipt.v1",
                1,
            ),
        };
        if d.authorization_fingerprint() != format!("descriptor:sha256:{}", self.fingerprint) {
            return Err(Error);
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    schema: String,
    assignment_id: String,
    generation: u64,
    active: bool,
    subject_id: String,
    key_id: String,
    issuer_public_key_hex: String,
    actor_id: String,
    integration_id: String,
    route: String,
    run_ids: Vec<String>,
    operations: Vec<String>,
    producer_artifact_sha256: String,
    normalizer_sha256: String,
    configuration_sha256: String,
    source_manifest_sha256: String,
    not_before: u64,
    not_after: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selector {
    schema: String,
    capture_id: String,
    #[serde(deserialize_with = "contract::nullable")]
    renewal_of: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    schema: String,
    reservation_id: String,
    work_sha256: String,
    configuration_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    reservation_id: String,
    work_sha256: String,
    payload_sha256: String,
    unsigned_result_sha256: String,
    producer_artifact_sha256: String,
    normalizer_sha256: String,
    configuration_sha256: String,
    source_manifest_sha256: String,
    operation: String,
    outcome: String,
    completion_kind: String,
    observations: Vec<Observation>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    kind: String,
    #[serde(deserialize_with = "contract::nullable")]
    input_sha256: Option<String>,
    #[serde(deserialize_with = "contract::nullable")]
    output_sha256: Option<String>,
    byte_length: u64,
    reference: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    producer_artifact_sha256: String,
    normalizer_sha256: String,
    configuration_sha256: String,
    entries: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    sha256: String,
    byte_length: u64,
}

pub(super) struct Capture {
    pub id: String,
    pub effect: String,
    pub original: Vec<u8>,
    work: contract::Work,
    payload: Vec<u8>,
    receipt: Receipt,
    receipt_hash: String,
    root: Root,
    blobs: Root,
    files: Vec<HeldFile>,
    observations: BTreeMap<String, u64>,
}
impl Capture {
    fn check(&self) -> Result<()> {
        self.root.check()?;
        self.blobs.check()?;
        for f in &self.files {
            f.check()?;
        }
        Ok(())
    }
    fn load(root: &Root, id: &str, a: &Assignment) -> Result<Self> {
        contract::digest(id)?;
        root.check()?;
        let capture = Root::open(&root.path.join(id))?;
        let blobs = Root::open(&root.path.join("blobs"))?;
        let mut files = Vec::new();
        for (name, limit) in [
            ("work.json", 1_048_576),
            ("payload.json", 262_144),
            ("receipt.json", 16_384),
            ("reservation.json", 16_384),
        ] {
            files.push(capture.file(name, limit)?);
        }
        files.push(root.file("source-manifest.json", 16_384)?);
        let (work, result, payload) = contract::work_and_result(&files[0].bytes, &files[1].bytes)?;
        let receipt: Receipt = contract::metadata(&files[2].bytes, 16_384)?;
        let reservation: Reservation = contract::metadata(&files[3].bytes, 16_384)?;
        let manifest: Manifest = contract::metadata(&files[4].bytes, 16_384)?;
        if id != sha(&files[3].bytes)
            || reservation.schema != "frank.local-review.reservation.v1"
            || !contract::identifier(&reservation.reservation_id)
            || reservation.work_sha256 != sha(&files[0].bytes)
            || reservation.configuration_sha256 != a.configuration_sha256
            || receipt.schema != "frank.local-review.capture.v1"
            || receipt.reservation_id != reservation.reservation_id
            || receipt.work_sha256 != reservation.work_sha256
            || receipt.payload_sha256 != sha(&files[1].bytes)
            || receipt.unsigned_result_sha256 != sha(payload.result.get().as_bytes())
            || receipt.source_manifest_sha256 != sha(&files[4].bytes)
            || receipt.source_manifest_sha256 != a.source_manifest_sha256
            || receipt.operation != work.operation
            || receipt.outcome != result.outcome
            || result.provider_reference != format!("local-review:{}", reservation.reservation_id)
        {
            return Err(Error);
        }
        for (actual, expected) in [
            (
                &receipt.producer_artifact_sha256,
                &a.producer_artifact_sha256,
            ),
            (&receipt.normalizer_sha256, &a.normalizer_sha256),
            (&receipt.configuration_sha256, &a.configuration_sha256),
            (
                &manifest.producer_artifact_sha256,
                &a.producer_artifact_sha256,
            ),
            (&manifest.normalizer_sha256, &a.normalizer_sha256),
            (&manifest.configuration_sha256, &a.configuration_sha256),
        ] {
            contract::digest(actual)?;
            if actual != expected {
                return Err(Error);
            }
        }
        if manifest.schema != "frank.local-review.source-manifest.v1"
            || manifest.entries.is_empty()
            || manifest.entries.len() > 128
            || receipt.observations.is_empty()
            || receipt.observations.len() > 128
        {
            return Err(Error);
        }
        let mut available = BTreeMap::new();
        let mut total = 0u64;
        fn blob(
            blobs: &Root,
            available: &mut BTreeMap<String, (u64, usize)>,
            files: &mut Vec<HeldFile>,
            total: &mut u64,
            h: &str,
        ) -> Result<u64> {
            contract::digest(h)?;
            if let Some((n, _)) = available.get(h) {
                return Ok(*n);
            }
            let f = blobs.file(h, 1024 * 1024)?;
            let n = f.bytes.len() as u64;
            *total = total.checked_add(n).ok_or(Error)?;
            if *total > 132 * 1024 * 1024 || sha(&f.bytes) != h {
                return Err(Error);
            }
            available.insert(h.to_owned(), (n, files.len()));
            files.push(f);
            Ok(n)
        }
        let mut manifest_names = BTreeSet::new();
        for e in &manifest.entries {
            if !manifest_names.insert(&e.sha256)
                || blob(&blobs, &mut available, &mut files, &mut total, &e.sha256)? != e.byte_length
            {
                return Err(Error);
            }
        }
        for h in [
            &a.producer_artifact_sha256,
            &a.normalizer_sha256,
            &a.configuration_sha256,
        ] {
            if !manifest_names.contains(h) {
                return Err(Error);
            }
        }
        let work_hash = sha(&files[0].bytes);
        let work_length = files[0].bytes.len() as u64;
        let mut observations = BTreeMap::new();
        let mut trace_bytes = 0u64;
        for o in &receipt.observations {
            if ![
                "artifact-read",
                "artifact-write",
                "provider-response",
                "source-snapshot-read",
                "component-snapshot-read",
                "claim-check",
                "simulated-intent",
            ]
            .contains(&o.kind.as_str())
            {
                return Err(Error);
            }
            let reference = o
                .output_sha256
                .as_ref()
                .or(o.input_sha256.as_ref())
                .ok_or(Error)?;
            if reference != &o.reference {
                return Err(Error);
            }
            for h in [&o.input_sha256, &o.output_sha256].into_iter().flatten() {
                let len = if h == &work_hash {
                    work_length
                } else {
                    blob(&blobs, &mut available, &mut files, &mut total, h)?
                };
                trace_bytes = trace_bytes.checked_add(len).ok_or(Error)?;
                if trace_bytes > 4 * 1024 * 1024 || (h == reference && len != o.byte_length) {
                    return Err(Error);
                }
            }
            if o.kind == "claim-check"
                && (o.input_sha256.as_deref() != Some(work_hash.as_str())
                    || o.output_sha256.is_none())
            {
                return Err(Error);
            }
            *observations.entry(o.kind.clone()).or_insert(0) += 1;
        }
        let claim = receipt.observations.last().ok_or(Error)?;
        if claim.kind != "claim-check"
            || claim.input_sha256.as_deref() != Some(work_hash.as_str())
            || claim.output_sha256.is_none()
        {
            return Err(Error);
        }
        const FAILURES: [&str; 14] = [
            "artifact_unavailable",
            "malformed_artifact",
            "artifact_integrity_mismatch",
            "artifact_write_integrity_mismatch",
            "malformed_review_events",
            "unresolved_event_timing",
            "malformed_transcription",
            "malformed_transcription_timing",
            "malformed_component_evidence",
            "malformed_source_evidence",
            "malformed_packet",
            "packet_input_mismatch",
            "review_packet_degraded",
            "status_simulation_unconfirmed",
        ];
        if (result.outcome == "succeeded" && receipt.completion_kind != "computed")
            || (result.outcome == "failed"
                && !FAILURES.contains(&receipt.completion_kind.as_str())
                && receipt.completion_kind != "daily_note_simulation_unconfirmed"
                && receipt.completion_kind != "status_intent_required")
        {
            return Err(Error);
        }
        if result.outcome == "succeeded" {
            Self::success_evidence(&work, &result, &receipt, |h| {
                if h == work_hash {
                    return Ok(files[0].bytes.as_slice());
                }
                let (_, index) = available.get(h).ok_or(Error)?;
                Ok(files[*index].bytes.as_slice())
            })?;
        }
        let effect = sha(&json(&[
            work.binding.run_id.as_str(),
            work.binding.step_id.as_str(),
            work.binding.attempt_id.as_str(),
            work.binding.fence.get(),
            &work.actor_id,
            &work.integration_id,
            &work.route,
            &work.effect_id,
        ])?);
        let original = bincode::serialize(
            &files[..5]
                .iter()
                .map(|f| f.bytes.as_slice())
                .collect::<Vec<_>>(),
        )
        .map_err(|_| Error)?;
        let payload = files[1].bytes.clone();
        let receipt_hash = sha(&files[2].bytes);
        let value = Self {
            id: id.to_owned(),
            effect,
            original,
            work,
            payload,
            receipt,
            receipt_hash,
            root: capture,
            blobs,
            files,
            observations,
        };
        value.check()?;
        Ok(value)
    }
    // Check accountable successful port relationships, not a replay of speech,
    // normalization or source semantics. Known failures keep honest prefixes.
    fn success_evidence<'a>(
        work: &contract::Work,
        result: &contract::Terminal,
        receipt: &Receipt,
        lookup: impl Fn(&str) -> Result<&'a [u8]>,
    ) -> Result<()> {
        use serde_json::value::RawValue;
        type Object = BTreeMap<String, Box<RawValue>>;
        fn object(raw: &[u8]) -> Result<Object> {
            contract::raw_json(raw, 1_048_576)?;
            serde_json::from_slice(raw).map_err(|_| Error)
        }
        fn array(raw: &[u8]) -> Result<Vec<Box<RawValue>>> {
            contract::raw_json(raw, 1_048_576)?;
            serde_json::from_slice(raw).map_err(|_| Error)
        }
        fn field<'a>(value: &'a Object, key: &str) -> Result<&'a RawValue> {
            value.get(key).map(Box::as_ref).ok_or(Error)
        }
        fn text(raw: &RawValue) -> Result<String> {
            serde_json::from_str(raw.get()).map_err(|_| Error)
        }
        fn same(a: &RawValue, b: &RawValue) -> Result<()> {
            if a.get() != b.get() {
                return Err(Error);
            }
            Ok(())
        }
        #[derive(Deserialize, PartialEq, Eq)]
        #[serde(deny_unknown_fields)]
        struct Artifact {
            content_hash: String,
            byte_length: u64,
            media_type: String,
        }
        fn artifact(raw: &[u8]) -> Result<Artifact> {
            let value: Artifact = contract::metadata(raw, 65_536)?;
            contract::digest(&value.content_hash)?;
            if value.byte_length > 1_048_576 || value.media_type.is_empty() {
                return Err(Error);
            }
            Ok(value)
        }
        fn take<'a>(
            rows: &[&Observation],
            at: &mut usize,
            kind: &str,
            lookup: &impl Fn(&str) -> Result<&'a [u8]>,
        ) -> Result<(&'a [u8], &'a [u8])> {
            let row = rows.get(*at).ok_or(Error)?;
            if row.kind != kind {
                return Err(Error);
            }
            *at += 1;
            Ok((
                lookup(row.input_sha256.as_deref().ok_or(Error)?)?,
                lookup(row.output_sha256.as_deref().ok_or(Error)?)?,
            ))
        }
        fn read<'a>(
            rows: &[&Observation],
            at: &mut usize,
            expected: &RawValue,
            lookup: &impl Fn(&str) -> Result<&'a [u8]>,
        ) -> Result<&'a [u8]> {
            let (input, output) = take(rows, at, "artifact-read", lookup)?;
            let args = array(input)?;
            if args.len() != 1 {
                return Err(Error);
            }
            let reference = artifact(args[0].get().as_bytes())?;
            if reference != artifact(expected.get().as_bytes())?
                || reference.content_hash != sha(output)
                || reference.byte_length != output.len() as u64
            {
                return Err(Error);
            }
            Ok(output)
        }
        fn write<'a>(
            rows: &[&Observation],
            at: &mut usize,
            expected: &RawValue,
            media: &str,
            lookup: &impl Fn(&str) -> Result<&'a [u8]>,
        ) -> Result<()> {
            let (input, output) = take(rows, at, "artifact-write", lookup)?;
            let reference = artifact(output)?;
            if reference != artifact(expected.get().as_bytes())?
                || reference.content_hash != sha(input)
                || reference.byte_length != input.len() as u64
                || reference.media_type != media
            {
                return Err(Error);
            }
            Ok(())
        }
        fn query<'a>(
            rows: &[&Observation],
            at: &mut usize,
            kind: &str,
            first: &RawValue,
            second: &RawValue,
            lookup: &impl Fn(&str) -> Result<&'a [u8]>,
        ) -> Result<()> {
            let (input, output) = take(rows, at, kind, lookup)?;
            let args = array(input)?;
            if args.len() != 2 {
                return Err(Error);
            }
            same(&args[0], first)?;
            same(&args[1], second)?;
            array(output)?;
            Ok(())
        }
        fn intent<'a>(
            rows: &[&Observation],
            at: &mut usize,
            work: &contract::Work,
            operation: &str,
            lookup: &impl Fn(&str) -> Result<&'a [u8]>,
        ) -> Result<Object> {
            let (input, output) = take(rows, at, "simulated-intent", lookup)?;
            let args = array(input)?;
            if args.len() != 3 || text(&args[1])? != operation {
                return Err(Error);
            }
            let binding: contract::Binding =
                serde_json::from_str(args[0].get()).map_err(|_| Error)?;
            if !work.binding.same(&binding) {
                return Err(Error);
            }
            let response = object(output)?;
            if field(&response, "simulation")?.get() != "true"
                || field(&response, "recorded")?.get() != "true"
            {
                return Err(Error);
            }
            object(args[2].get().as_bytes())
        }
        let inputs = object(work.inputs.get().as_bytes())?;
        let outputs = object(result.outputs.get().as_bytes())?;
        let rows: Vec<_> = receipt
            .observations
            .iter()
            .filter(|row| row.kind != "claim-check")
            .collect();
        let mut at = 0;
        match work.operation.as_str() {
            "review.load_review" => {
                read(&rows, &mut at, field(&inputs, "audio_asset")?, &lookup)?;
                read(&rows, &mut at, field(&inputs, "events_asset")?, &lookup)?;
                if artifact(field(&outputs, "audio_asset")?.get().as_bytes())?
                    != artifact(field(&inputs, "audio_asset")?.get().as_bytes())?
                    || text(field(&outputs, "review_id_short")?)?
                        != text(field(&inputs, "review_id")?)?
                            .chars()
                            .take(8)
                            .collect::<String>()
                {
                    return Err(Error);
                }
                array(field(&outputs, "events")?.get().as_bytes())?;
            }
            "review.transcribe" => {
                let audio = read(&rows, &mut at, field(&inputs, "audio_asset")?, &lookup)?;
                let (input, output) = take(&rows, &mut at, "provider-response", &lookup)?;
                if input != audio {
                    return Err(Error);
                }
                let response = object(output)?;
                if text(field(&response, "transcript")?)? != text(field(&outputs, "transcript")?)? {
                    return Err(Error);
                }
                array(field(&response, "words")?.get().as_bytes())?;
                array(field(&outputs, "words")?.get().as_bytes())?;
            }
            "review.resolve_components" => {
                query(
                    &rows,
                    &mut at,
                    "component-snapshot-read",
                    field(&inputs, "subject_id")?,
                    field(&inputs, "events")?,
                    &lookup,
                )?;
                array(field(&outputs, "component_names")?.get().as_bytes())?;
            }
            "review.annotate" => {
                if text(field(&outputs, "resolved_transcript")?)?
                    != text(field(&inputs, "transcript")?)?
                {
                    return Err(Error);
                }
                write(
                    &rows,
                    &mut at,
                    field(&outputs, "transcript_note")?,
                    "application/json",
                    &lookup,
                )?;
            }
            "review.extract" => write(
                &rows,
                &mut at,
                field(&outputs, "review_packet")?,
                "application/json",
                &lookup,
            )?,
            "review.bind_source" => {
                let observations = array(field(&inputs, "observations")?.get().as_bytes())?;
                for observation in &observations {
                    let value = object(observation.get().as_bytes())?;
                    query(
                        &rows,
                        &mut at,
                        "source-snapshot-read",
                        field(&inputs, "subject_id")?,
                        field(&value, "selectors")?,
                        &lookup,
                    )?;
                }
                if array(field(&outputs, "codebase_context")?.get().as_bytes())?.len()
                    != observations.len()
                {
                    return Err(Error);
                }
            }
            "review.write_review" => {
                read(&rows, &mut at, field(&inputs, "review_packet")?, &lookup)?;
                write(
                    &rows,
                    &mut at,
                    field(&outputs, "review_packet")?,
                    "application/json",
                    &lookup,
                )?;
                write(
                    &rows,
                    &mut at,
                    field(&outputs, "review_note")?,
                    "text/markdown",
                    &lookup,
                )?;
            }
            "review.write_status" => {
                read(&rows, &mut at, field(&inputs, "review_packet")?, &lookup)?;
                read(&rows, &mut at, field(&inputs, "review_note")?, &lookup)?;
                let payload = intent(&rows, &mut at, work, "review.status", &lookup)?;
                if payload.len() != 3 || text(field(&payload, "decision")?)? != "processed" {
                    return Err(Error);
                }
                same(field(&payload, "review_id")?, field(&inputs, "review_id")?)?;
                same(
                    field(&payload, "review_packet")?,
                    field(&inputs, "review_packet")?,
                )?;
                let status = object(field(&outputs, "review_status_updated")?.get().as_bytes())?;
                if status.len() != 3 || text(field(&status, "status")?)? != "simulated_processed" {
                    return Err(Error);
                }
                same(field(&status, "review_id")?, field(&inputs, "review_id")?)?;
                same(
                    field(&status, "review_note")?,
                    field(&inputs, "review_note")?,
                )?;
            }
            "review.daily_note" => {
                read(&rows, &mut at, field(&inputs, "transcript_note")?, &lookup)?;
                read(&rows, &mut at, field(&inputs, "review_note")?, &lookup)?;
                let payload = intent(&rows, &mut at, work, "vault.daily-note", &lookup)?;
                let count = array(field(&inputs, "observations")?.get().as_bytes())?.len();
                let line = format!(
                    "Simulated review {}: {} speech-derived feedback item(s).",
                    text(field(&inputs, "review_id_short")?)?,
                    count
                );
                if payload.len() != 4
                    || text(field(&payload, "line")?)? != line
                    || !outputs.is_empty()
                {
                    return Err(Error);
                }
                for key in ["review_id", "subject_id", "review_note"] {
                    same(field(&payload, key)?, field(&inputs, key)?)?;
                }
            }
            _ => return Err(Error),
        }
        if at != rows.len() {
            return Err(Error);
        }
        Ok(())
    }
    fn resource(&self) -> String {
        format!(
            "runs/{}/steps/{}/attempts/{}/effects/{}",
            self.work.binding.run_id,
            self.work.binding.step_id,
            self.work.binding.attempt_id,
            self.work.effect_id
        )
    }
}
#[derive(Serialize, Deserialize)]
pub(super) struct Output {
    pub envelope: Vec<u8>,
    packet: Vec<u8>,
    context: Vec<u8>,
    issued: u64,
    expires: u64,
}
impl Output {
    pub fn encode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|_| Error)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() > 2 * 1024 * 1024 {
            return Err(Error);
        }
        let o: Self = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(2 * 1024 * 1024)
            .reject_trailing_bytes()
            .deserialize(b)
            .map_err(|_| Error)?;
        if o.encode()? != b {
            return Err(Error);
        }
        Ok(o)
    }
    pub fn envelope_hash(&self) -> String {
        sha(&self.envelope)
    }
    pub fn window(&self, n: u64) -> Result<()> {
        if self.issued == 0
            || self.expires <= self.issued
            || n < self.issued
            || n >= self.expires
            || self.expires - self.issued > 60
        {
            return Err(Error);
        }
        Ok(())
    }
    pub fn issued(&self) -> u64 {
        self.issued
    }
    pub fn ledger_check(
        &self,
        id: &str,
        effect: &str,
        original: &[u8],
        public: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        if original.len() > 2 * 1024 * 1024 {
            return Err(Error);
        }
        let raw: Vec<Vec<u8>> = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(2 * 1024 * 1024)
            .reject_trailing_bytes()
            .deserialize(original)
            .map_err(|_| Error)?;
        if raw.len() != 5 || bincode::serialize(&raw).map_err(|_| Error)? != original {
            return Err(Error);
        }
        let (w, r, payload) = contract::work_and_result(&raw[0], &raw[1])?;
        let receipt: Receipt = contract::metadata(&raw[2], 16_384)?;
        let reservation: Reservation = contract::metadata(&raw[3], 16_384)?;
        let manifest: Manifest = contract::metadata(&raw[4], 16_384)?;
        let identity = sha(&json(&[
            w.binding.run_id.as_str(),
            w.binding.step_id.as_str(),
            w.binding.attempt_id.as_str(),
            w.binding.fence.get(),
            &w.actor_id,
            &w.integration_id,
            &w.route,
            &w.effect_id,
        ])?);
        if id != sha(&raw[3])
            || effect != identity
            || reservation.schema != "frank.local-review.reservation.v1"
            || receipt.schema != "frank.local-review.capture.v1"
            || manifest.schema != "frank.local-review.source-manifest.v1"
            || receipt.reservation_id != reservation.reservation_id
            || receipt.work_sha256 != sha(&raw[0])
            || reservation.work_sha256 != receipt.work_sha256
            || receipt.payload_sha256 != sha(&raw[1])
            || receipt.unsigned_result_sha256 != sha(payload.result.get().as_bytes())
            || receipt.source_manifest_sha256 != sha(&raw[4])
            || receipt.operation != w.operation
            || receipt.outcome != r.outcome
            || r.provider_reference != format!("local-review:{}", reservation.reservation_id)
        {
            return Err(Error);
        }
        if self.packet.len() > 262_144 + 16_384 + 69
            || self.context.len() > 65_536
            || self.envelope.len() > 1_048_576
            || self.issued == 0
            || self.expires <= self.issued
            || self.expires - self.issued > 60
        {
            return Err(Error);
        }
        let p: libsec_core::ZenithPacket = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit((262_144 + 16_384 + 69) as u64)
            .reject_trailing_bytes()
            .deserialize(&self.packet)
            .map_err(|_| Error)?;
        let s: SignedVerifiedCallContext = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(65_536)
            .reject_trailing_bytes()
            .deserialize(&self.context)
            .map_err(|_| Error)?;
        if bincode::serialize(&p).map_err(|_| Error)? != self.packet
            || bincode::serialize(&s).map_err(|_| Error)? != self.context
            || p.session_id == [0; 16]
            || p.nonce == [0; 12]
            || p.mac != [0; 16]
            || p.encrypted_payload != raw[1]
            || p.claim_ttl != self.expires - self.issued
            || s.context.schema_version != 4
            || s.context.packet_hash != hash(&self.packet)
            || s.context.session_id != p.session_id
            || s.context.nonce != p.nonce
            || s.context.opcode != p.opcode
            || s.context.operation != "frank.result.attest.v1"
            || s.context.audience != "frank://result-receiver"
            || s.context.resource.as_deref()
                != Some(
                    format!(
                        "runs/{}/steps/{}/attempts/{}/effects/{}",
                        w.binding.run_id, w.binding.step_id, w.binding.attempt_id, w.effect_id
                    )
                    .as_str(),
                )
            || s.context.issued_at != self.issued
            || s.context.expires_at != self.expires
            || s.context.replay_scope != "session:opcode:nonce"
            || s.authenticator_kind != AuthenticatorKind::Ed25519NodeAndVerifier
        {
            return Err(Error);
        }
        public
            .verify_strict(
                &bincode::serialize(&s.context).map_err(|_| Error)?,
                &ed25519_dalek::Signature::from_slice(&s.signature).map_err(|_| Error)?,
            )
            .map_err(|_| Error)?;
        if self.envelope
            != json(
                &serde_json::json!({"schema":"frank.secs-result-envelope.v1","packet_hex":hex(&self.packet),"signed_context_hex":hex(&self.context)}),
            )?
        {
            return Err(Error);
        }
        Ok(())
    }
    pub fn replay(&self) -> Result<String> {
        let c: SignedVerifiedCallContext =
            bincode::deserialize(&self.context).map_err(|_| Error)?;
        Ok(sha(&bincode::serialize(&(
            c.context.subject.subject_id,
            c.context.session_id,
            c.context.opcode,
            c.context.nonce,
        ))
        .map_err(|_| Error)?))
    }
}

/// Owner-selected fixed local result authority. No provisioning, raw signer,
/// caller clock or arbitrary result/context input is exposed.
pub struct FrankResultAuthority {
    configuration: Configuration,
    config_parent: Root,
    config: HeldFile,
    assignment_root: Root,
    assignment_lock_source: HeldFile,
    assignment_file: HeldFile,
    assignment: Assignment,
    captures: Root,
    capture_lock_source: HeldFile,
    issuer: IssuerDirectory,
    store: Store,
}
impl FrankResultAuthority {
    pub async fn open_pinned_owner_configuration(
        path: &Path,
        expected_sha256: [u8; 32],
    ) -> Result<Self> {
        let config_parent = Root::open(path.parent().ok_or(Error)?)?;
        let config = HeldFile::open(path, 65_536)?;
        if hash(&config.bytes) != expected_sha256 {
            return Err(Error);
        }
        let c: Configuration = contract::metadata(&config.bytes, 65_536)?;
        if c.schema != "frank.result-authority-configuration.v1"
            || !(1..=60).contains(&c.maximum_ttl)
            || !contract::identifier(&c.issuer_subject_id)
            || !contract::identifier(&c.issuer_key_id)
        {
            return Err(Error);
        }
        c.descriptor.validate()?;
        let public =
            ed25519_dalek::VerifyingKey::from_bytes(&contract::digest(&c.issuer_public_key_hex)?)
                .map_err(|_| Error)?;
        if public.is_weak() {
            return Err(Error);
        }
        let assignment_root = Root::open(&c.assignment_root)?;
        let assignment_lock_source = assignment_root.file("assignment.lock", 0)?;
        let lock = assignment_root.lock("assignment.lock", false)?;
        let assignment_file = assignment_root.file("assignment.json", 65_536)?;
        if sha(&assignment_file.bytes) != c.assignment_sha256 {
            return Err(Error);
        }
        let a: Assignment = contract::metadata(&assignment_file.bytes, 65_536)?;
        if a.schema != "frank.local-review.result-party-assignment.v1"
            || !a.active
            || a.generation == 0
            || a.subject_id != c.issuer_subject_id
            || a.key_id != c.issuer_key_id
            || a.issuer_public_key_hex != c.issuer_public_key_hex
            || a.not_before == 0
            || a.not_before >= a.not_after
            || a.not_after > 9_007_199_254_740_991
            || a.run_ids.is_empty()
            || a.run_ids.len() > 64
            || a.operations.is_empty()
            || a.operations.len() > 9
        {
            return Err(Error);
        }
        for s in [
            &a.assignment_id,
            &a.subject_id,
            &a.key_id,
            &a.actor_id,
            &a.integration_id,
            &a.route,
        ]
        .into_iter()
        .chain(a.run_ids.iter())
        {
            if !contract::identifier(s) {
                return Err(Error);
            }
        }
        for h in [
            &a.producer_artifact_sha256,
            &a.normalizer_sha256,
            &a.configuration_sha256,
            &a.source_manifest_sha256,
        ] {
            contract::digest(h)?;
        }
        if a.run_ids.iter().collect::<BTreeSet<_>>().len() != a.run_ids.len()
            || a.operations.iter().collect::<BTreeSet<_>>().len() != a.operations.len()
            || a.operations
                .iter()
                .any(|s| !contract::OPERATIONS.contains(&s.as_str()))
        {
            return Err(Error);
        }
        let captures = Root::open(&c.capture_root)?;
        let capture_lock_source = captures.file("capture.lock", 0)?;
        let issuer = IssuerDirectory::open(&c.issuer_root).map_err(|_| Error)?;
        let store = Store::open(&c.journal_root)?;
        lock.check()?;
        assignment_file.check()?;
        config.check()?;
        config_parent.check()?;
        Ok(Self {
            configuration: c,
            config_parent,
            config,
            assignment_root,
            assignment_lock_source,
            assignment_file,
            assignment: a,
            captures,
            capture_lock_source,
            issuer,
            store,
        })
    }
    fn current(
        &self,
        capture: &Capture,
        assignment_lock: &HeldFile,
        capture_lock: &HeldFile,
        key: &HeldIssuerFiles<'_>,
        signing: &SigningKey,
    ) -> Result<()> {
        self.config_parent.check()?;
        self.config.check()?;
        self.assignment_root.check()?;
        self.assignment_lock_source.check()?;
        assignment_lock.check()?;
        self.assignment_file.check()?;
        self.captures.check()?;
        self.capture_lock_source.check()?;
        capture_lock.check()?;
        capture.check()?;
        key.revalidate().map_err(|_| Error)?;
        if key.read_seed().map_err(|_| Error)?.as_ref() != signing.as_bytes()
            || hex(signing.verifying_key().as_bytes()) != self.configuration.issuer_public_key_hex
        {
            return Err(Error);
        }
        Ok(())
    }
    fn time(&self, n: u64) -> Result<()> {
        if n < self.assignment.not_before || n >= self.assignment.not_after {
            return Err(Error);
        }
        Ok(())
    }
    fn receipt(&self, c: &Capture, n: u64) -> Result<Vec<u8>> {
        let b = json(
            &serde_json::json!({"schema":"frank.local-review.attestation-receipt.v1","capture_id":c.id,"capture_receipt_sha256":c.receipt_hash,"assignment_id":self.assignment.assignment_id,"assignment_sha256":self.configuration.assignment_sha256,"work_sha256":c.receipt.work_sha256,"payload_sha256":c.receipt.payload_sha256,"source_manifest_sha256":c.receipt.source_manifest_sha256,"producer_artifact_sha256":c.receipt.producer_artifact_sha256,"normalizer_sha256":c.receipt.normalizer_sha256,"observation_kind_counts":c.observations,"checked_at":n,"claim":"accountable-local-computation"}),
        )?;
        if b.len() > 16_384 {
            return Err(Error);
        }
        Ok(b)
    }
    fn context(
        &self,
        c: &Capture,
        p: &libsec_core::ZenithPacket,
        packet: &[u8],
        n: u64,
    ) -> Result<VerifiedCallContext> {
        self.time(n)?;
        let expires = n
            .checked_add(self.configuration.maximum_ttl)
            .ok_or(Error)?
            .min(self.assignment.not_after);
        if expires <= n {
            return Err(Error);
        }
        Ok(VerifiedCallContext {
            schema_version: 4,
            context_id: format!(
                "result-{}",
                &sha(&[p.session_id.as_slice(), p.nonce.as_slice()].concat())[..48]
            ),
            packet_hash: hash(packet),
            session_id: p.session_id,
            nonce: p.nonce,
            opcode: p.opcode,
            operation: "frank.result.attest.v1".into(),
            resource: Some(c.resource()),
            subject: VerifiedSubject {
                subject_id: self.assignment.subject_id.clone(),
                key_id: self.assignment.key_id.clone(),
            },
            audience: "frank://result-receiver".into(),
            evidence_summary: vec![
                format!("capture-receipt-sha256:{}", c.receipt_hash),
                format!("work-sha256:{}", c.receipt.work_sha256),
                format!("payload-sha256:{}", c.receipt.payload_sha256),
                format!(
                    "source-manifest-sha256:{}",
                    c.receipt.source_manifest_sha256
                ),
                format!(
                    "observation-kinds:{}",
                    String::from_utf8(json(&c.observations)?).map_err(|_| Error)?
                ),
                "external-effects:disabled".into(),
            ],
            proof_metadata: None,
            capability_result: format!(
                "allow:frank.result.attest.v1;assignment:{};scope-sha256:{}",
                self.assignment.assignment_id,
                sha(c.resource().as_bytes())
            ),
            credential_result: format!(
                "owner-assignment:{};generation:{};sha256:{};role:local-review-result-party",
                self.assignment.assignment_id,
                self.assignment.generation,
                self.configuration.assignment_sha256
            ),
            issued_at: n,
            expires_at: expires,
            descriptor_fingerprint: self.configuration.descriptor.fingerprint.clone(),
            replay_scope: "session:opcode:nonce".into(),
            handler_id: Some(self.configuration.descriptor.handler_id.clone()),
        })
    }
    fn make(&self, c: &Capture, key: &SigningKey, floor: u64) -> Result<Output> {
        use rand::RngCore;
        let mut random = [0u8; 28];
        let mut found = false;
        for _ in 0..4 {
            rand::rngs::OsRng
                .try_fill_bytes(&mut random)
                .map_err(|_| Error)?;
            if random[..16] != [0; 16] && random[16..] != [0; 12] {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error);
        }
        let n = crate::clock::failclosed_unix_seconds();
        if n < floor || n == 0 || n > 9_007_199_254_740_991 {
            return Err(Error);
        }
        self.time(n)?;
        let expires = n
            .checked_add(self.configuration.maximum_ttl)
            .ok_or(Error)?
            .min(self.assignment.not_after);
        let packet = libsec_core::ZenithPacket {
            session_id: random[..16].try_into().map_err(|_| Error)?,
            nonce: random[16..].try_into().map_err(|_| Error)?,
            opcode: self.configuration.descriptor.opcode,
            proof: self.receipt(c, n)?,
            claim_ttl: expires - n,
            encrypted_payload: c.payload.clone(),
            mac: [0; 16],
        };
        let packet_bytes = bincode::serialize(&packet).map_err(|_| Error)?;
        let context = self.context(c, &packet, &packet_bytes, n)?;
        let signature = key
            .sign(&bincode::serialize(&context).map_err(|_| Error)?)
            .to_bytes()
            .to_vec();
        let signed = SignedVerifiedCallContext {
            context,
            signer_key_id: self.configuration.issuer_key_id.clone(),
            authenticator_kind: AuthenticatorKind::Ed25519NodeAndVerifier,
            signature,
        };
        let context_bytes = bincode::serialize(&signed).map_err(|_| Error)?;
        if context_bytes.len() > 65_536 || packet_bytes.len() > 262_144 + 16_384 + 69 {
            return Err(Error);
        }
        let envelope = json(
            &serde_json::json!({"schema":"frank.secs-result-envelope.v1","packet_hex":hex(&packet_bytes),"signed_context_hex":hex(&context_bytes)}),
        )?;
        if envelope.len() > 1_048_576 {
            return Err(Error);
        }
        Ok(Output {
            envelope,
            packet: packet_bytes,
            context: context_bytes,
            issued: n,
            expires,
        })
    }
    fn authenticate(&self, c: &Capture, out: &Output, key: &SigningKey) -> Result<()> {
        if out.packet.len() > 262_144 + 16_384 + 69
            || out.context.len() > 65_536
            || out.envelope.len() > 1_048_576
        {
            return Err(Error);
        }
        let p: libsec_core::ZenithPacket = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit((262_144 + 16_384 + 69) as u64)
            .reject_trailing_bytes()
            .deserialize(&out.packet)
            .map_err(|_| Error)?;
        let s: SignedVerifiedCallContext = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(65_536)
            .reject_trailing_bytes()
            .deserialize(&out.context)
            .map_err(|_| Error)?;
        if bincode::serialize(&p).map_err(|_| Error)? != out.packet
            || bincode::serialize(&s).map_err(|_| Error)? != out.context
            || p.session_id == [0; 16]
            || p.nonce == [0; 12]
            || p.opcode != self.configuration.descriptor.opcode
            || p.mac != [0; 16]
            || p.encrypted_payload != c.payload
            || p.proof != self.receipt(c, out.issued)?
            || out.expires <= out.issued
            || p.claim_ttl != out.expires - out.issued
            || s.context != self.context(c, &p, &out.packet, out.issued)?
            || s.context.expires_at != out.expires
            || s.signer_key_id != self.configuration.issuer_key_id
            || s.authenticator_kind != AuthenticatorKind::Ed25519NodeAndVerifier
        {
            return Err(Error);
        }
        key.verifying_key()
            .verify_strict(
                &bincode::serialize(&s.context).map_err(|_| Error)?,
                &ed25519_dalek::Signature::from_slice(&s.signature).map_err(|_| Error)?,
            )
            .map_err(|_| Error)?;
        if out.envelope
            != json(
                &serde_json::json!({"schema":"frank.secs-result-envelope.v1","packet_hex":hex(&out.packet),"signed_context_hex":hex(&out.context)}),
            )?
        {
            return Err(Error);
        }
        Ok(())
    }
    pub async fn execute(&self, mode: FrankResultMode, exact_selector: &[u8]) -> Result<Vec<u8>> {
        let selector: Selector = contract::metadata(exact_selector, 1024)?;
        if selector.schema != "frank.result-capture-selector.v1" {
            return Err(Error);
        }
        contract::digest(&selector.capture_id)?;
        if let Some(p) = &selector.renewal_of {
            contract::digest(p)?;
        }
        if (mode == FrankResultMode::Attest && selector.renewal_of.is_some())
            || (mode == FrankResultMode::Renew && selector.renewal_of.is_none())
        {
            return Err(Error);
        }
        self.config_parent.check()?;
        self.config.check()?;
        self.assignment_lock_source.check()?;
        self.capture_lock_source.check()?;
        let assignment_lock = self.assignment_root.lock("assignment.lock", false)?;
        self.assignment_file.check()?;
        let capture_lock = self.captures.lock("capture.lock", false)?;
        let capture = Capture::load(&self.captures, &selector.capture_id, &self.assignment)?;
        let w = &capture.work;
        if w.actor_id != self.assignment.actor_id
            || w.integration_id != self.assignment.integration_id
            || w.route != self.assignment.route
            || !self.assignment.run_ids.contains(&w.binding.run_id)
            || !self.assignment.operations.contains(&w.operation)
        {
            return Err(Error);
        }
        let files = self.issuer.lease().map_err(|_| Error)?;
        let seed = files.read_seed().map_err(|_| Error)?;
        let signing = SigningKey::from_bytes(&seed);
        let current = || self.current(&capture, &assignment_lock, &capture_lock, &files, &signing);
        current()?;
        self.store
            .exchange(
                mode,
                exact_selector,
                &capture,
                selector.renewal_of.as_deref().unwrap_or(""),
                &signing,
                &hash(&self.config.bytes),
                |n| {
                    current()?;
                    self.make(&capture, &signing, n)
                },
                |output| {
                    current()?;
                    self.authenticate(&capture, output, &signing)
                },
            )
            .await
    }
}

#[cfg(test)]
mod metadata_golden_tests {
    use super::*;
    #[test]
    fn internal_metadata_is_feature_stable_without_touching_raw_payloads() {
        let envelope = serde_json::json!({"signed_context_hex":"abcd","schema":"frank.secs-result-envelope.v1","packet_hex":"0123"});
        assert_eq!(json(&envelope).unwrap(),b"{\"packet_hex\":\"0123\",\"schema\":\"frank.secs-result-envelope.v1\",\"signed_context_hex\":\"abcd\"}");
        let nested = serde_json::json!({"z":{"β":[{"z":true,"a":null},1]},"a":"é😀"});
        assert_eq!(
            json(&nested).unwrap(),
            "{\"a\":\"é😀\",\"z\":{\"β\":[{\"a\":null,\"z\":true},1]}}".as_bytes()
        );
    }
}
