//! Opt-in owner-configured Native exchange. No request-selected authority inputs.
//! The command reuses Native's journal; it does not add a Wallet exchange journal.
use crate::{
    canonical,
    custody::{Application, ExpectedState, ServiceIdentityStore, StoreBinding},
    hash, hex, hex32, object, strict_json, text, uint, MAX_SAFE_TIME,
};
use libsec_core::service_holder_proof::{
    ServiceApplication, UntrustedSignedServiceChallenge, MAX_PROOF_BYTES, MAX_RUNTIME_REQUEST_BYTES,
};
use serde_json::{json, Value};
use server::{ServiceAuthority, ServiceCompletion, ServiceResume};
use std::path::{Component, Path, PathBuf};

const CONFIGURATION_LIMIT: u64 = 65_536;
const CONTEXT_LIMIT: usize = 65_536;
const PACKET_OVERHEAD: usize = 69;
/// Transport admission only; the selected application's public reader enforces
/// its own lower limit and exact schema before Native can create Pending state.
pub const MAX_STDIN_BYTES: usize = MAX_RUNTIME_REQUEST_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Issue,
    Resume,
    Query,
}
/// Deliberately carries no path, request, secret or internal failure detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denied;
type Result<T> = std::result::Result<T, Denied>;

struct Configuration {
    native_configuration: PathBuf,
    native_configuration_sha256: [u8; 32],
    wallet_root: PathBuf,
    application: Application,
    binding: StoreBinding,
    expected: ExpectedState,
}
fn application(v: &Value) -> Result<Application> {
    match v.as_str() {
        Some("runtime") => Ok(Application::Runtime),
        Some("service") => Ok(Application::Service),
        _ => Err(Denied),
    }
}
fn absolute_path(v: &Value) -> Result<PathBuf> {
    let s = v.as_str().ok_or(Denied)?;
    let p = PathBuf::from(s);
    if s.is_empty()
        || s.len() > 1024
        || s.contains('\0')
        || !p.is_absolute()
        || p.components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(Denied);
    }
    Ok(p)
}
fn load(path: &Path, expected_sha256: Option<[u8; 32]>) -> Result<Configuration> {
    let raw = castalia_wallet_private_files::read(path, CONFIGURATION_LIMIT).map_err(|_| Denied)?;
    // Bind the exact bounded bytes consumed below, before parsing or opening any
    // configuration-selected source. The compatibility entrypoint has no pin.
    if expected_sha256.is_some_and(|expected| hash(&raw) != expected) {
        return Err(Denied);
    }
    let value = strict_json(&raw).map_err(|_| Denied)?;
    let c = object(
        &value,
        &[
            "schema",
            "native_configuration",
            "native_configuration_sha256",
            "wallet_root",
            "application",
            "store_binding",
            "expected_state",
        ],
    )
    .map_err(|_| Denied)?;
    if c["schema"] != "castalia.wallet-service-command.v1" {
        return Err(Denied);
    }
    let selected = application(&c["application"])?;
    let b = object(
        &c["store_binding"],
        &[
            "store_id",
            "subject_id",
            "application",
            "purpose",
            "minimum_revision",
        ],
    )
    .map_err(|_| Denied)?;
    let store_id = text(&b["store_id"], 32).map_err(|_| Denied)?;
    if store_id.len() != 32
        || !store_id
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        || application(&b["application"])? != selected
        || b["purpose"] != "secs-service-holder-proof.v1"
    {
        return Err(Denied);
    }
    let e =
        object(&c["expected_state"], &["state_revision", "state_sha256"]).map_err(|_| Denied)?;
    let state_sha256 = text(&e["state_sha256"], 64).map_err(|_| Denied)?;
    hex32(state_sha256).map_err(|_| Denied)?;
    let configuration = Configuration {
        native_configuration: absolute_path(&c["native_configuration"])?,
        native_configuration_sha256: hex32(
            text(&c["native_configuration_sha256"], 64).map_err(|_| Denied)?,
        )
        .map_err(|_| Denied)?,
        wallet_root: absolute_path(&c["wallet_root"])?,
        application: selected,
        binding: StoreBinding {
            store_id: store_id.into(),
            subject_id: text(&b["subject_id"], 128).map_err(|_| Denied)?.into(),
            application: selected,
            purpose: "secs-service-holder-proof.v1".into(),
            minimum_revision: uint(&b["minimum_revision"], 1, MAX_SAFE_TIME).map_err(|_| Denied)?,
        },
        expected: ExpectedState {
            state_revision: uint(&e["state_revision"], 1, MAX_SAFE_TIME).map_err(|_| Denied)?,
            state_sha256: state_sha256.into(),
        },
    };
    // Bind the two public source selections using exact pinned bytes. Native's
    // pinned opener independently checks the SAME bytes it consumes; a pre/post
    // path read alone would not close replacement between reads.
    let native = castalia_wallet_private_files::read(
        &configuration.native_configuration,
        CONFIGURATION_LIMIT,
    )
    .map_err(|_| Denied)?;
    if hash(&native) != configuration.native_configuration_sha256 {
        return Err(Denied);
    }
    let native_value = strict_json(&native).map_err(|_| Denied)?;
    if absolute_path(native_value.get("wallet_root").ok_or(Denied)?)? != configuration.wallet_root {
        return Err(Denied);
    }
    // Native owns its complete closed configuration parser and owner checks.
    Ok(configuration)
}
fn envelope(application: ServiceApplication, completion: ServiceCompletion) -> Result<Vec<u8>> {
    if completion.packet.is_empty()
        || completion.packet.len()
            > application.max_request_bytes() + MAX_PROOF_BYTES + PACKET_OVERHEAD
        || completion.signed_context.is_empty()
        || completion.signed_context.len() > CONTEXT_LIMIT
    {
        return Err(Denied);
    }
    Ok(canonical(&json!({
        "schema": match application {
            ServiceApplication::RuntimeV1 => "runtime.secs-envelope.v1",
            ServiceApplication::ServiceV1 => "service.secs-envelope.v1",
        },
        "packet_hex": hex(&completion.packet),
        "signed_context_hex": hex(&completion.signed_context),
    })))
}
/// `configuration` is a trusted startup selection, not a field in the request.
/// Returns the existing Native envelope only after successful current checks.
/// Errors never fall back from resume to issue, re-create or renew a challenge.
pub async fn exchange(configuration: &Path, mode: Mode, exact_request: &[u8]) -> Result<Vec<u8>> {
    exchange_selected(configuration, mode, None, exact_request).await
}
/// Pin the exact command-configuration read before its closed parse or source
/// opening. The digest is owner-selected startup consistency data, not authority.
/// Native's separate same-read configuration pin remains mandatory.
pub async fn exchange_pinned(
    configuration: &Path,
    mode: Mode,
    expected_sha256: [u8; 32],
    exact_request: &[u8],
) -> Result<Vec<u8>> {
    exchange_selected(configuration, mode, Some(expected_sha256), exact_request).await
}
async fn exchange_selected(
    configuration: &Path,
    mode: Mode,
    expected_sha256: Option<[u8; 32]>,
    exact_request: &[u8],
) -> Result<Vec<u8>> {
    let c = load(configuration, expected_sha256)?;
    let (application, contract) = match c.application {
        Application::Runtime => (
            ServiceApplication::RuntimeV1,
            secs_service_call_contract::Application::Runtime,
        ),
        Application::Service => (
            ServiceApplication::ServiceV1,
            secs_service_call_contract::Application::Service,
        ),
    };
    let intent = secs_service_call_contract::ServiceIntent::parse(contract, exact_request)
        .map_err(|_| Denied)?;
    if mode == Mode::Query
        && (c.application != Application::Runtime
            || !matches!(
                intent.operation(),
                "runtime.work.list.v1"
                    | "runtime.events.list.v1"
                    | "runtime.attempt.get.v1"
                    | "runtime.output.get.v1"
                    | "runtime.run.get.v1"
                    | "runtime.artifact.get.v1"
                    | "runtime.process.get.v1"
                    | "runtime.version.get.v1"
                    | "runtime.receipt.get.v1"
            ))
    {
        return Err(Denied);
    }
    let store = ServiceIdentityStore::open(&c.wallet_root, c.binding).map_err(|_| Denied)?;
    let identity = store.public_identity().map_err(|_| Denied)?;
    if identity.application != c.application || identity.expected() != c.expected {
        return Err(Denied);
    }
    let holder = store.open_identity(c.expected).map_err(|_| Denied)?;
    let authority = ServiceAuthority::open_pinned_owner_configuration(
        &c.native_configuration,
        c.native_configuration_sha256,
    )
    .await
    .map_err(|_| Denied)?;
    let resumed = match mode {
        Mode::Issue => ServiceResume::PendingChallenge(
            authority.issue(exact_request).await.map_err(|_| Denied)?,
        ),
        Mode::Resume => authority.resume(exact_request).await.map_err(|_| Denied)?,
        Mode::Query => ServiceResume::PendingChallenge(
            authority
                .acquire_query(exact_request)
                .await
                .map_err(|_| Denied)?,
        ),
    };
    let completed = match resumed {
        ServiceResume::Completed(completed) => completed,
        ServiceResume::PendingChallenge(raw) => {
            let challenge =
                UntrustedSignedServiceChallenge::decode_inner(&raw).map_err(|_| Denied)?;
            if challenge.claims.application != application
                || challenge.request_bytes != exact_request
                || challenge.claims.holder_subject_id != identity.subject_id
                || challenge.claims.holder_key_id != identity.key_id
            {
                return Err(Denied);
            }
            let proof = holder
                .present_current_service_challenge(&challenge)
                .map_err(|_| Denied)?;
            match mode {
                Mode::Query => authority
                    .complete_query(exact_request, &proof)
                    .await
                    .map_err(|_| Denied)?,
                Mode::Issue | Mode::Resume => authority
                    .complete(exact_request, &proof)
                    .await
                    .map_err(|_| Denied)?,
            }
        }
    };
    envelope(application, completed)
}
