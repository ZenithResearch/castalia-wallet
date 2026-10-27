//! Shared public selection review; no custody operation, signature or grant import.
//! These selectors are not supported inside existing v1 permissions/backups.
//! Receiver adapters must resolve current hierarchy and compound effects.
pub use secs_grant_contract::resource_selector::{
    Hierarchy, ResourceRef, ResourceSelector, Selection,
};
use secs_grant_contract::{Result, resource_selector::parse_selector};

/// Bind an unsigned selection to the already-verified canonical service. A route
/// URL, application profile or organizational membership is not that authority.
pub fn review(raw: &str, verified_service: &str) -> Result<ResourceSelector> {
    parse_selector(raw.as_bytes(), verified_service)
}

/// Conservative structural narrowing. No network/ancestry lookup, signing,
/// revocation decision or key export occurs; false means reject the derivation.
pub fn can_narrow(child: &str, parent: &str, verified_service: &str) -> Result<bool> {
    review(child, verified_service)?.within(&review(parent, verified_service)?)
}
