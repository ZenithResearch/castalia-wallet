//! Private service issuer used by the source-tested retained-owner composition.
//! Fixed challenge/context signing only; no public signer or installed admission.
//! The exact64 lowercase hex profile is proposed source behavior only; selecting
//! any live Native key role, finite lifecycle and public pin is separate approval.
use crate::{
    receipt::AuthenticatorKind,
    service_authority::{
        OriginalServiceWindow, PreparedServiceContext, ServiceChallengeSignaturePreimage,
    },
    service_owner_publication::{HeldNativePolicy, HeldPolicyError},
    verifier::SignedVerifiedCallContext,
    work_private_files::{HeldIssuerFiles, IssuerDirectory},
};
use ed25519_dalek::{Signer, SigningKey};
use std::path::Path;
#[cfg(test)]
const KEY_FILE: &str = "issuer.seed.hex";
#[cfg(test)]
const KEY_LOCK: &str = ".service-issuer.lock";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IssuerError {
    UnsafeSource,
    Busy,
    Selection,
    Binding,
    Policy(HeldPolicyError),
}
impl From<HeldPolicyError> for IssuerError {
    fn from(e: HeldPolicyError) -> Self {
        Self::Policy(e)
    }
}
fn storage(e: std::io::Error) -> IssuerError {
    if e.kind() == std::io::ErrorKind::WouldBlock {
        IssuerError::Busy
    } else {
        IssuerError::UnsafeSource
    }
}
/// Independently declared source selection, not a registry observation, key
/// allocation or successful authority assertion. No secret or role inference.
pub(crate) struct IssuerSelection {
    node: String,
    key: String,
    public: [u8; 32],
}
impl IssuerSelection {
    pub(crate) fn new(node: &str, key: &str, public: [u8; 32]) -> Option<Self> {
        fn label(s: &str) -> bool {
            !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
        }
        if !label(node) || !label(key) {
            return None;
        }
        let parsed = ed25519_dalek::VerifyingKey::from_bytes(&public).ok()?;
        if parsed.is_weak() {
            return None;
        }
        Some(Self {
            node: node.into(),
            key: key.into(),
            public,
        })
    }
}
pub(crate) struct IssuerKeySource {
    files: IssuerDirectory,
    selection: IssuerSelection,
}
impl IssuerKeySource {
    pub(crate) fn open_selected(
        root: &Path,
        selection: IssuerSelection,
    ) -> Result<Self, IssuerError> {
        Ok(Self {
            files: IssuerDirectory::open(root).map_err(storage)?,
            selection,
        })
    }
    pub(crate) fn lease<'a, 'n, 's>(
        &'a self,
        policy: &'a HeldNativePolicy<'n, 's>,
        original: OriginalServiceWindow,
    ) -> Result<IssuerKeyLease<'a, 'n, 's>, IssuerError> {
        // Native is acquired/revalidated before the key lock or any seed read.
        let issuer = policy.selected_issuer(original)?;
        if issuer.node_id != self.selection.node
            || issuer.key.key_id != self.selection.key
            || issuer.key.algorithm != "ed25519"
            || issuer.key.public_key.to_bytes() != self.selection.public
        {
            return Err(IssuerError::Selection);
        }
        let files = self.files.lease().map_err(storage)?;
        let seed = files.read_seed().map_err(storage)?;
        let signing = SigningKey::from_bytes(&seed);
        if signing.verifying_key().to_bytes() != self.selection.public {
            return Err(IssuerError::Selection);
        }
        let lease = IssuerKeyLease {
            source: self,
            policy,
            files,
            signing,
            original,
        };
        lease.revalidate()?;
        Ok(lease)
    }
}
/// Owns one actual stable shared key lock and the same checked key descriptor;
/// borrows the whole held Native policy and retained ancestor chain. No Clone,
/// Debug, Deserialize, secret getter, generic identity or Signer implementation.
pub(crate) struct IssuerKeyLease<'a, 'n, 's> {
    source: &'a IssuerKeySource,
    policy: &'a HeldNativePolicy<'n, 's>,
    files: HeldIssuerFiles<'a>,
    signing: SigningKey,
    original: OriginalServiceWindow,
}
impl IssuerKeyLease<'_, '_, '_> {
    pub(crate) fn original_window(&self) -> OriginalServiceWindow {
        self.original
    }
    pub(crate) fn revalidate(&self) -> Result<(), IssuerError> {
        let issuer = self.policy.selected_issuer(self.original)?;
        if issuer.node_id != self.source.selection.node
            || issuer.key.key_id != self.source.selection.key
            || issuer.key.public_key.to_bytes() != self.source.selection.public
        {
            return Err(IssuerError::Selection);
        }
        let seed = self.files.read_seed().map_err(storage)?;
        if seed[..] != self.signing.as_bytes()[..] {
            return Err(IssuerError::Selection);
        }
        self.policy.selected_issuer(self.original)?;
        Ok(())
    }
    pub(crate) fn sign_challenge(
        &self,
        input: &ServiceChallengeSignaturePreimage,
    ) -> Result<[u8; 64], IssuerError> {
        self.revalidate()?;
        let bytes = input
            .for_held_key(self.policy, self.original)
            .ok_or(IssuerError::Binding)?;
        let signature = self.signing.sign(bytes).to_bytes();
        self.revalidate()?;
        Ok(signature)
    }
    pub(crate) fn sign_context(
        &self,
        input: PreparedServiceContext,
    ) -> Result<SignedVerifiedCallContext, IssuerError> {
        self.revalidate()?;
        let bytes = input
            .bytes_for_held_key(self.policy, self.original)
            .ok_or(IssuerError::Binding)?;
        let signature = self.signing.sign(&bytes).to_bytes();
        let signed = SignedVerifiedCallContext {
            context: input.into_context(),
            signer_key_id: self.source.selection.key.clone(),
            authenticator_kind: AuthenticatorKind::Ed25519NodeAndVerifier,
            signature: signature.to_vec(),
        };
        self.revalidate()?;
        Ok(signed)
    }
}
#[cfg(test)]
#[path = "service_context_issuer_tests.rs"]
mod tests;
