//! Owner-selected startup only. Parsed configuration is not current authority.
use super::{PendingClock, PendingError, PendingIssuer};
use crate::{
    service_challenge_store::{Journal, Limits},
    service_context_issuer::{IssuerKeySource, IssuerSelection},
    service_owner_publication::{OwnerPublicationSource, OwnerStartupPin},
    service_wallet_source::{
        OwnerSelectedWalletRoot, StartupWalletObservationPin, WalletCurrentSource,
    },
};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Opaque fail-closed startup/call error; never contains keys, request or proof bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceAuthorityError;
impl std::fmt::Display for ServiceAuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native service authority denied")
    }
}
impl std::error::Error for ServiceAuthorityError {}
impl From<PendingError> for ServiceAuthorityError {
    fn from(_: PendingError) -> Self {
        Self
    }
}
/// Exact durable transport bytes, not a verified receiver admission token.
#[derive(PartialEq, Eq)]
pub struct ServiceCompletion {
    pub packet: Vec<u8>,
    pub signed_context: Vec<u8>,
}
impl std::fmt::Debug for ServiceCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceCompletion")
            .field("packet_bytes", &self.packet.len())
            .field("signed_context_bytes", &self.signed_context.len())
            .finish_non_exhaustive()
    }
}
/// Exact transport data recovered under the original window, not receiver
/// admission. Completed output has passed the unchanged current-owner cached
/// delivery guard. There is no standalone unvalidated-proof recovery result;
/// the completed Packet retains its existing validated holder-proof field.
#[derive(PartialEq, Eq)]
pub enum ServiceResume {
    PendingChallenge(Vec<u8>),
    Completed(ServiceCompletion),
}
impl std::fmt::Debug for ServiceResume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PendingChallenge(bytes) => f
                .debug_struct("PendingChallenge")
                .field("challenge_bytes", &bytes.len())
                .finish_non_exhaustive(),
            Self::Completed(completed) => f.debug_tuple("Completed").field(completed).finish(),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema: String,
    wallet_root: PathBuf,
    wallet_observation_pin: serde_json::Value,
    native_root: PathBuf,
    native_generation: u64,
    native_sha256: String,
    issuer_root: PathBuf,
    issuer_node_id: String,
    issuer_key_id: String,
    issuer_public_key_hex: String,
    journal_root: PathBuf,
    maximum_ttl: u64,
}
/// Owns fixed actual sources and journal. No clock, claims, signer, qualification,
/// policy selectors or arbitrary context are accepted at the request boundary.
/// Does not provision custody, select live roles or install a receiver.
pub struct ServiceAuthority {
    wallet: WalletCurrentSource,
    native: OwnerPublicationSource,
    pin: OwnerStartupPin,
    issuer: IssuerKeySource,
    journal: Journal,
    maximum_ttl: u64,
}
impl ServiceAuthority {
    /// Explicit create-only Native issuer-key provisioning. OS entropy stays in
    /// Native; only the public key is returned. This does not select a live role,
    /// grant policy, qualify the installation or replace existing material.
    /// A partial/uncertain root is retained and a second creation is denied.
    pub fn create_issuer_key(root: &Path) -> Result<[u8; 32], ServiceAuthorityError> {
        use rand::RngCore;
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| ServiceAuthorityError)?;
        let public = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        crate::work_private_files::IssuerDirectory::create_new(root, &seed)
            .map_err(|_| ServiceAuthorityError)?;
        Ok(public)
    }
    pub async fn open_owner_configuration(path: &Path) -> Result<Self, ServiceAuthorityError> {
        let raw =
            crate::work_private_files::read(path, 65_536).map_err(|_| ServiceAuthorityError)?;
        Self::open_read_owner_configuration(&raw).await
    }
    /// Bind the exact bounded private read consumed by this Native startup.
    /// The owner-selected digest is a consistency pin, not authority approval.
    /// Mismatch denies before parsing or opening any selected source/journal.
    pub async fn open_pinned_owner_configuration(
        path: &Path,
        expected_sha256: [u8; 32],
    ) -> Result<Self, ServiceAuthorityError> {
        let raw =
            crate::work_private_files::read(path, 65_536).map_err(|_| ServiceAuthorityError)?;
        if crate::service_wallet_source::hash(&raw) != expected_sha256 {
            return Err(ServiceAuthorityError);
        }
        Self::open_read_owner_configuration(&raw).await
    }
    async fn open_read_owner_configuration(raw: &[u8]) -> Result<Self, ServiceAuthorityError> {
        // Check duplicates recursively before serde's closed shape conversion.
        let value = crate::service_authority_snapshot::strict_value(raw)
            .map_err(|_| ServiceAuthorityError)?;
        let c: Configuration = serde_json::from_value(value).map_err(|_| ServiceAuthorityError)?;
        if c.schema != "secs.service-authority-configuration.v1"
            || !(1..=60).contains(&c.maximum_ttl)
        {
            return Err(ServiceAuthorityError);
        }
        let pin_raw = crate::service_authority_snapshot::canonical(&c.wallet_observation_pin);
        let wallet = WalletCurrentSource::open(
            OwnerSelectedWalletRoot::open(&c.wallet_root).map_err(|_| ServiceAuthorityError)?,
            StartupWalletObservationPin::parse_owner_configuration(&pin_raw)
                .map_err(|_| ServiceAuthorityError)?,
        )
        .map_err(|_| ServiceAuthorityError)?;
        let native = OwnerPublicationSource::open_owner_selected_root(&c.native_root)
            .map_err(|_| ServiceAuthorityError)?;
        let pin = OwnerStartupPin::new(
            c.native_generation,
            super::pending_digest(&c.native_sha256)?,
        )
        .map_err(|_| ServiceAuthorityError)?;
        let selection = IssuerSelection::new(
            &c.issuer_node_id,
            &c.issuer_key_id,
            super::pending_digest(&c.issuer_public_key_hex)?,
        )
        .ok_or(ServiceAuthorityError)?;
        let issuer = IssuerKeySource::open_selected(&c.issuer_root, selection)
            .map_err(|_| ServiceAuthorityError)?;
        let journal = Journal::open(&c.journal_root, Limits::default(), &PendingClock::new(0))
            .await
            .map_err(|_| ServiceAuthorityError)?;
        Ok(Self {
            wallet,
            native,
            pin,
            issuer,
            journal,
            maximum_ttl: c.maximum_ttl,
        })
    }
    fn pending(&self) -> Result<PendingIssuer<'_>, PendingError> {
        PendingIssuer::from_startup(
            &self.wallet,
            &self.native,
            self.pin,
            &self.issuer,
            &self.journal,
            self.maximum_ttl,
        )
    }
    /// Returns the original retained signed challenge; no new window on retries.
    pub async fn issue(&self, exact_request: &[u8]) -> Result<Vec<u8>, ServiceAuthorityError> {
        let stored = self
            .pending()?
            .issue_pending_challenge(exact_request)
            .await?;
        stored
            .challenge
            .encode_inner()
            .map_err(|_| ServiceAuthorityError)
    }
    /// Resume an existing exact request only. Missing/expired/pruned/rejected
    /// rows deny; this method never calls issue or renews the original window.
    /// Pending returns its original guarded challenge; Completed uses the exact
    /// retained proof internally through the existing guarded cached delivery.
    pub async fn resume(
        &self,
        exact_request: &[u8],
    ) -> Result<ServiceResume, ServiceAuthorityError> {
        Ok(self
            .pending()?
            .resume_service_challenge(exact_request)
            .await?)
    }
    /// Exact request + Wallet compact proof only. Cached delivery revalidates all
    /// current owners and the original window; it never re-signs or renews.
    pub async fn complete(
        &self,
        exact_request: &[u8],
        holder_proof: &[u8],
    ) -> Result<ServiceCompletion, ServiceAuthorityError> {
        let stored = self
            .pending()?
            .complete_service_challenge(exact_request, holder_proof)
            .await?;
        Ok(ServiceCompletion {
            packet: stored.packet,
            signed_context: stored.context,
        })
    }
}
