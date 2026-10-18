pub mod caller;
pub mod clock;
pub mod config;
pub mod credential_presentation;
pub mod devgraph_authority;
pub mod devgraph_issue_create_cli;
pub mod devgraph_issue_create_wallet_cli;
pub mod devgraph_work_admin;
pub mod devgraph_work_authority;
pub mod devgraph_work_cli;
pub mod devgraph_work_request;
pub mod devgraph_work_v2;
pub mod devgraph_work_v2_cli;
pub mod dregg_authority;
pub mod dregg_live_source;
pub mod evidence;
pub mod file_write;
pub mod gateway;
pub mod identity;
pub mod ingress;
pub mod ledger;
pub mod manifest;
pub mod membership;
pub mod node_registration;
pub mod nullifier;
pub mod ontology;
pub mod payload;
pub mod permctl;
pub mod permissions;
pub mod privacy;
pub mod proof_keys;
pub mod public_audit;
pub mod public_audit_cli;
pub mod receipt;
pub mod runtime_mode;
pub mod schema;
pub mod service_holder_proof;
pub mod session;
pub mod verification_context;
pub mod verifier;
mod work_private_files;

mod devgraph_work_progress;

// Isolated, unqualified private service metadata mechanisms. No public authority API.
#[allow(dead_code)]
mod service_authority_snapshot;
#[allow(dead_code)]
mod service_challenge_store;
#[allow(dead_code)]
mod service_evidence;
#[allow(dead_code)]
mod service_wallet_contract;

/// Bounded owner publication and retained transition recovery.
pub mod service_owner_publication;
/// Actual metadata-only Wallet source; no issuer/signing/admission authority.
pub mod service_wallet_source;

// Private NI03/NI05 issuance, recovery and exact completion/cache composition;
// owner-selected startup facade; installed NI01/NI02/NI03 admission remains separate.
#[allow(dead_code)]
mod service_authority;
#[allow(dead_code)]
mod service_context_issuer;

pub use service_authority::{
    ServiceAuthority, ServiceAuthorityError, ServiceCompletion, ServiceResume,
};
