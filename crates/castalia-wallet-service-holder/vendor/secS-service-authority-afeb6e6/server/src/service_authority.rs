//! Private retained-owner NI03/NI05 issuance, recovery and completion source.
//! Not an installed admission or Wallet presenter. Exact request/proof retries
//! and cached delivery require all actual current owners and original window.
//! A codec, parsed claim, pure policy or loaded key alone cannot create authority.
use crate::{
    service_authority_snapshot::NativePolicyLineage,
    service_owner_publication::HeldNativePolicy,
    verifier::{VerifiedCallContext, VERIFIED_CALL_CONTEXT_SCHEMA_VERSION},
};
use libsec_core::service_holder_proof::{ServiceApplication, MAX_SAFE_TIME};

/// Unqualified immutable original time data. Not an OS clock or approval.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct OriginalServiceWindow {
    issued: u64,
    expires: u64,
}
impl OriginalServiceWindow {
    pub(crate) fn new(issued: u64, expires: u64) -> Option<Self> {
        (issued > 0 && issued < expires && expires <= MAX_SAFE_TIME && expires - issued <= 60)
            .then_some(Self { issued, expires })
    }
    pub(crate) fn issued_at(self) -> u64 {
        self.issued
    }
    pub(crate) fn expires_at(self) -> u64 {
        self.expires
    }
}
struct SigningBinding {
    lineage: NativePolicyLineage,
    application: ServiceApplication,
    node: String,
    key: String,
    public: [u8; 32],
    window: OriginalServiceWindow,
}
impl SigningBinding {
    fn matches(&self, policy: &HeldNativePolicy<'_, '_>, window: OriginalServiceWindow) -> bool {
        if self.lineage != policy.lineage()
            || self.application != policy.application()
            || self.window != window
        {
            return false;
        }
        let Ok(issuer) = policy.selected_issuer(window) else {
            return false;
        };
        self.node == issuer.node_id
            && self.key == issuer.key.key_id
            && self.public == issuer.key.public_key.to_bytes()
    }
}
/// Constructed only by the private retained-owner Pending path below.
/// No raw-byte/public-claims constructor is present.
pub(crate) struct ServiceChallengeSignaturePreimage {
    binding: SigningBinding,
    transcript: Vec<u8>,
}
impl ServiceChallengeSignaturePreimage {
    pub(crate) fn for_held_key(
        &self,
        policy: &HeldNativePolicy<'_, '_>,
        window: OriginalServiceWindow,
    ) -> Option<&[u8]> {
        self.binding
            .matches(policy, window)
            .then_some(self.transcript.as_slice())
    }
}
/// Constructed only by NI05's retained-original/strict-holder/current-state path. An ordinary caller-built context is not accepted.
pub(crate) struct PreparedServiceContext {
    binding: SigningBinding,
    context: VerifiedCallContext,
}
impl PreparedServiceContext {
    pub(crate) fn bytes_for_held_key(
        &self,
        policy: &HeldNativePolicy<'_, '_>,
        window: OriginalServiceWindow,
    ) -> Option<Vec<u8>> {
        if !self.binding.matches(policy, window)
            || self.context.schema_version != VERIFIED_CALL_CONTEXT_SCHEMA_VERSION
            || self.context.issued_at != window.issued_at()
            || self.context.expires_at != window.expires_at()
        {
            return None;
        }
        // Exactly the existing schema4 context signature preimage: no new
        // prefix, reset TTL, alternate serialization or caller context port.
        bincode::serialize(&self.context).ok()
    }
    pub(crate) fn into_context(self) -> VerifiedCallContext {
        self.context
    }
}

// Startup-selected owners only. The incoming method below accepts exact request
// bytes, never claims, key/subject/audience selectors, clock or validity window.
struct PendingIssuer<'s> {
    wallet: &'s crate::service_wallet_source::WalletCurrentSource,
    native: &'s crate::service_owner_publication::OwnerPublicationSource,
    pin: crate::service_owner_publication::OwnerStartupPin,
    issuer: &'s crate::service_context_issuer::IssuerKeySource,
    journal: &'s crate::service_challenge_store::Journal,
    maximum_ttl: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingError {
    Invalid,
    Entropy,
    RetainedRequest,
    Source(crate::service_wallet_source::SourceError),
    Policy(crate::service_owner_publication::HeldPolicyError),
    Issuer(crate::service_context_issuer::IssuerError),
    Journal(crate::service_challenge_store::JournalError),
}
impl From<crate::service_wallet_source::SourceError> for PendingError {
    fn from(error: crate::service_wallet_source::SourceError) -> Self {
        Self::Source(error)
    }
}
impl From<crate::service_owner_publication::HeldPolicyError> for PendingError {
    fn from(error: crate::service_owner_publication::HeldPolicyError) -> Self {
        Self::Policy(error)
    }
}
impl From<crate::service_context_issuer::IssuerError> for PendingError {
    fn from(error: crate::service_context_issuer::IssuerError) -> Self {
        Self::Issuer(error)
    }
}
impl From<crate::service_challenge_store::JournalError> for PendingError {
    fn from(error: crate::service_challenge_store::JournalError) -> Self {
        Self::Journal(error)
    }
}
impl From<crate::service_challenge_store::PendingInsertError> for PendingError {
    fn from(error: crate::service_challenge_store::PendingInsertError) -> Self {
        match error {
            crate::service_challenge_store::PendingInsertError::RetainedRequest => {
                Self::RetainedRequest
            }
            crate::service_challenge_store::PendingInsertError::Journal(error) => {
                Self::Journal(error)
            }
        }
    }
}
// Native's existing monotonic OS-clock boundary, never a caller-provided Clock.
// Clock's infallible legacy trait returns0 on sticky failure, which the unchanged
// journal rejects. No later successful sample can erase an earlier clock error.
struct PendingClock {
    floor: std::cell::Cell<u64>,
    failed: std::cell::Cell<bool>,
}
impl PendingClock {
    fn new(floor: u64) -> Self {
        Self {
            floor: std::cell::Cell::new(floor),
            failed: std::cell::Cell::new(false),
        }
    }
    fn sample(&self) -> Result<u64, crate::service_challenge_store::JournalError> {
        use crate::service_challenge_store::JournalError;
        if self.failed.get() {
            return Err(JournalError::ClockRollback);
        }
        let sampled = crate::service_wallet_source::now();
        let Ok(now) = sampled else {
            self.failed.set(true);
            return Err(JournalError::Invalid);
        };
        if now == 0 || now > MAX_SAFE_TIME || now < self.floor.get() {
            self.failed.set(true);
            return Err(JournalError::ClockRollback);
        }
        self.floor.set(now);
        Ok(now)
    }
}
impl crate::service_challenge_store::Clock for PendingClock {
    fn now(&self) -> u64 {
        self.sample().unwrap_or(0)
    }
}
#[derive(Clone, Copy)]
struct PendingRandomness {
    challenge: [u8; 32],
    session: [u8; 16],
    nonce: [u8; 12],
}
impl PendingRandomness {
    fn fresh() -> Result<Self, PendingError> {
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        for _ in 0..4 {
            let mut bytes = [0; 60];
            rng.try_fill_bytes(&mut bytes)
                .map_err(|_| PendingError::Entropy)?;
            let result = Self {
                challenge: bytes[..32].try_into().map_err(|_| PendingError::Entropy)?,
                session: bytes[32..48]
                    .try_into()
                    .map_err(|_| PendingError::Entropy)?,
                nonce: bytes[48..].try_into().map_err(|_| PendingError::Entropy)?,
            };
            if result.challenge != [0; 32] && result.session != [0; 16] && result.nonce != [0; 12] {
                return Ok(result);
            }
        }
        Err(PendingError::Entropy)
    }
}
fn pending_digest(value: &str) -> Result<[u8; 32], PendingError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(PendingError::Invalid);
    }
    let mut result = [0; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| PendingError::Invalid)?;
    }
    Ok(result)
}
fn holder<'a>(
    wallet: &'a crate::service_wallet_source::WalletCurrentLease<'_>,
) -> Result<(&'a str, &'a str, [u8; 32]), PendingError> {
    let value = &wallet.observed.reference.value;
    Ok((
        value["subject_id"].as_str().ok_or(PendingError::Invalid)?,
        value["key_id"].as_str().ok_or(PendingError::Invalid)?,
        pending_digest(
            value["public_key_sha256"]
                .as_str()
                .ok_or(PendingError::Invalid)?,
        )?,
    ))
}
fn pending_claims(
    wallet: &crate::service_wallet_source::WalletCurrentLease<'_>,
    policy: &HeldNativePolicy<'_, '_>,
    prepared: &crate::service_authority_snapshot::PreparedOwnerBindings,
    window: OriginalServiceWindow,
    randomness: PendingRandomness,
) -> Result<libsec_core::service_holder_proof::ServiceChallengeClaims, PendingError> {
    use libsec_core::service_holder_proof::ServiceChallengeClaims;
    let intent = prepared.intent();
    let (subject, holder_key, public) = holder(wallet)?;
    let issuer = policy.selected_issuer(window)?;
    if intent.subject_id() != subject
        || intent.key_id() != holder_key
        || intent.issued_at() != window.issued_at()
        || intent.expires_at() != window.expires_at()
        || intent.audience() != policy.application().audience()
    {
        return Err(PendingError::Invalid);
    }
    let claims = ServiceChallengeClaims {
        application: policy.application(),
        issuer_node_id: issuer.node_id.clone(),
        issuer_key_id: issuer.key.key_id.clone(),
        audience: intent.audience().into(),
        operation: intent.operation().into(),
        resource: intent.resource().into(),
        opcode: intent.opcode(),
        request_length: intent.request_bytes().len() as u64,
        request_sha256: crate::service_wallet_source::hash(intent.request_bytes()),
        schema_bundle_sha256: crate::service_holder_proof::schema_bundle_digest(
            policy.application(),
        ),
        descriptor_fingerprint: pending_digest(intent.descriptor_fingerprint())?,
        handler_id: intent.handler_id().into(),
        holder_subject_id: subject.into(),
        holder_key_id: holder_key.into(),
        holder_public_key_fingerprint: public,
        receiver_policy_digest: prepared.receiver_digest(),
        permission_policy_digest: prepared.permission_digest(),
        registry_snapshot_digest: prepared.registry_digest(),
        challenge_id: randomness.challenge,
        session_id: randomness.session,
        nonce: randomness.nonce,
        ttl_seconds: window.expires_at() - window.issued_at(),
        issued_at: window.issued_at(),
        expires_at: window.expires_at(),
        evidence: prepared.evidence().bindings().clone(),
    };
    claims.validate().map_err(|_| PendingError::Invalid)?;
    Ok(claims)
}
// The guard explicitly borrows Wallet: Native capture_shared alone does not.
// All owners are lexical locals in issue_pending_challenge, not a self-reference.
struct PendingGuard<'g, 'w, 'a, 'n, 's> {
    wallet: &'g crate::service_wallet_source::WalletCurrentLease<'w>,
    native: &'g crate::service_owner_publication::NativeOwnerCurrentLease<'s>,
    policy: &'g HeldNativePolicy<'n, 's>,
    key: &'g crate::service_context_issuer::IssuerKeyLease<'a, 'n, 's>,
    prepared: &'g crate::service_authority_snapshot::PreparedOwnerBindings,
    preimage: &'g ServiceChallengeSignaturePreimage,
    challenge: &'g libsec_core::service_holder_proof::UntrustedSignedServiceChallenge,
    lineage: &'g [u8],
    raw: &'g [u8],
    window: OriginalServiceWindow,
    randomness: PendingRandomness,
    clock: &'g PendingClock,
}
impl PendingGuard<'_, '_, '_, '_, '_> {
    fn check(
        &self,
        input: crate::service_challenge_store::GuardInput<'_>,
    ) -> Result<(), PendingError> {
        use libsec_core::service_holder_proof::challenge_transcript;
        if input.stage != crate::service_challenge_store::ExportStage::Pending
            || !input.packet.is_empty()
            || !input.context.is_empty()
            || input.signed_at != 0
            || input.holder_verified_at != 0
            || input.challenge != self.challenge
            || input.evidence != self.prepared.evidence().bytes()
            || input.lineage != self.lineage
            || self.wallet.observed.reference.lineage_preimage().as_slice() != self.lineage
            || self.prepared.intent().request_bytes() != self.raw
            || self.challenge.request_bytes.as_slice() != self.raw
            || self.key.original_window() != self.window
            || !self.preimage.binding.matches(self.policy, self.window)
        {
            return Err(PendingError::Invalid);
        }
        self.wallet.require_active_for_challenge(
            self.window.issued_at(),
            self.window.expires_at(),
            self.native,
        )?;
        self.policy.revalidate()?;
        self.key.revalidate()?;
        let (subject, key_id, _) = holder(self.wallet)?;
        let current = self.policy.prepare_recorded_original(
            self.raw,
            subject,
            key_id,
            self.window,
            self.prepared.evidence().bindings().evidence_observed_at,
        )?;
        if current.permission_digest() != self.prepared.permission_digest()
            || current.registry_digest() != self.prepared.registry_digest()
            || current.receiver_digest() != self.prepared.receiver_digest()
            || current.evidence().bytes() != self.prepared.evidence().bytes()
            || pending_claims(
                self.wallet,
                self.policy,
                &current,
                self.window,
                self.randomness,
            )? != self.challenge.claims
        {
            return Err(PendingError::Invalid);
        }
        let transcript = challenge_transcript(&self.challenge.claims, self.raw)
            .map_err(|_| PendingError::Invalid)?;
        if transcript.as_slice() != self.preimage.transcript.as_slice() {
            return Err(PendingError::Invalid);
        }
        self.policy
            .selected_issuer(self.window)?
            .key
            .public_key
            .verify_strict(
                &transcript,
                &ed25519_dalek::Signature::from_bytes(&self.challenge.issuer_signature),
            )
            .map_err(|_| PendingError::Invalid)?;
        self.key.revalidate()?;
        self.wallet.require_active_for_challenge(
            self.window.issued_at(),
            self.window.expires_at(),
            self.native,
        )?;
        let now = self.clock.sample()?;
        if now < self.window.issued_at() || now >= self.window.expires_at() {
            return Err(PendingError::Invalid);
        }
        Ok(())
    }
}
impl crate::service_challenge_store::AuthorityGuard for PendingGuard<'_, '_, '_, '_, '_> {
    fn revalidate(
        &mut self,
        input: crate::service_challenge_store::GuardInput<'_>,
    ) -> Result<(), crate::service_challenge_store::JournalError> {
        self.check(input)
            .map_err(|_| crate::service_challenge_store::JournalError::Rejected)
    }
}
// Fields are derived only after exact retained-challenge and current-owner
// holder verification. Keep the original window, including on a cached retry.
fn completion_context(
    holder: &crate::service_holder_proof::AuthenticatedServiceHolder,
) -> VerifiedCallContext {
    let c = holder.claims();
    let packet_hash = holder.packet_sha256();
    VerifiedCallContext {
        schema_version: VERIFIED_CALL_CONTEXT_SCHEMA_VERSION,
        context_id: format!(
            "ctx-v1-{}-{:02x}-{}",
            c.issued_at,
            c.opcode,
            crate::service_wallet_source::hex(&packet_hash[..8])
        ),
        packet_hash,
        session_id: c.session_id,
        nonce: c.nonce,
        opcode: c.opcode,
        operation: c.operation.clone(),
        resource: Some(c.resource.clone()),
        subject: crate::verifier::VerifiedSubject {
            subject_id: c.holder_subject_id.clone(),
            key_id: c.holder_key_id.clone(),
        },
        audience: c.audience.clone(),
        evidence_summary: vec![],
        proof_metadata: None,
        // The actual prepared no-required-evidence path rejects every nonempty
        // obligation. These empty summaries do not attest external evidence.
        capability_result: String::new(),
        credential_result: String::new(),
        issued_at: c.issued_at,
        expires_at: c.expires_at,
        descriptor_fingerprint: format!(
            "descriptor:sha256:{}",
            crate::service_wallet_source::hex(&c.descriptor_fingerprint)
        ),
        replay_scope: "session:opcode:nonce".into(),
        handler_id: Some(c.handler_id.clone()),
    }
}
struct CompletionGuard<'g, 'w, 'a, 'n, 's> {
    pending: PendingGuard<'g, 'w, 'a, 'n, 's>,
    packet: &'g libsec_core::ZenithPacket,
    packet_bytes: &'g [u8],
    context_bytes: &'g [u8],
    signed: &'g crate::verifier::SignedVerifiedCallContext,
    times: crate::service_challenge_store::IssuanceTimes,
}
impl CompletionGuard<'_, '_, '_, '_, '_> {
    fn check(
        &self,
        input: crate::service_challenge_store::GuardInput<'_>,
    ) -> Result<(), PendingError> {
        use crate::service_challenge_store::{ExportStage, GuardInput};
        if !matches!(input.stage, ExportStage::Complete | ExportStage::Cached)
            || input.packet != self.packet_bytes
            || input.context != self.context_bytes
            || input.holder_verified_at != self.times.holder_verified_at
            || input.signed_at != self.times.context_signed_at
            || input.holder_verified_at < self.pending.window.issued_at()
            || input.signed_at < input.holder_verified_at
            || input.signed_at >= self.pending.window.expires_at()
        {
            return Err(PendingError::Invalid);
        }
        // Reuse all exact retained-claims/evidence/lineage and current owner/key
        // checks. A completed storage stage is never accepted as Pending data.
        self.pending.check(GuardInput {
            stage: ExportStage::Pending,
            challenge: input.challenge,
            evidence: input.evidence,
            lineage: input.lineage,
            packet: &[],
            context: &[],
            signed_at: 0,
            holder_verified_at: 0,
        })?;
        let holder = self.pending.policy.verify_holder(
            self.pending.wallet,
            self.packet,
            self.pending.prepared,
            self.pending.window,
            crate::service_wallet_source::hash(&self.pending.preimage.transcript),
        )?;
        let issuer = self.pending.policy.selected_issuer(self.pending.window)?;
        if self.signed.context != completion_context(&holder)
            || self.signed.signer_key_id != issuer.key.key_id
            || self.signed.authenticator_kind
                != crate::receipt::AuthenticatorKind::Ed25519NodeAndVerifier
            || bincode::serialize(self.signed).map_err(|_| PendingError::Invalid)?
                != self.context_bytes
            || bincode::serialize(self.packet).map_err(|_| PendingError::Invalid)?
                != self.packet_bytes
        {
            return Err(PendingError::Invalid);
        }
        issuer
            .key
            .public_key
            .verify_strict(
                &bincode::serialize(&self.signed.context).map_err(|_| PendingError::Invalid)?,
                &ed25519_dalek::Signature::from_slice(&self.signed.signature)
                    .map_err(|_| PendingError::Invalid)?,
            )
            .map_err(|_| PendingError::Invalid)?;
        self.pending.key.revalidate()?;
        self.pending.wallet.require_active_for_challenge(
            self.pending.window.issued_at(),
            self.pending.window.expires_at(),
            self.pending.native,
        )?;
        let now = self.pending.clock.sample()?;
        if now < input.signed_at
            || now < self.pending.window.issued_at()
            || now >= self.pending.window.expires_at()
        {
            return Err(PendingError::Invalid);
        }
        Ok(())
    }
}
impl crate::service_challenge_store::AuthorityGuard for CompletionGuard<'_, '_, '_, '_, '_> {
    fn revalidate(
        &mut self,
        input: crate::service_challenge_store::GuardInput<'_>,
    ) -> Result<(), crate::service_challenge_store::JournalError> {
        self.check(input)
            .map_err(|_| crate::service_challenge_store::JournalError::Rejected)
    }
}
impl<'s> PendingIssuer<'s> {
    fn from_startup(
        wallet: &'s crate::service_wallet_source::WalletCurrentSource,
        native: &'s crate::service_owner_publication::OwnerPublicationSource,
        pin: crate::service_owner_publication::OwnerStartupPin,
        issuer: &'s crate::service_context_issuer::IssuerKeySource,
        journal: &'s crate::service_challenge_store::Journal,
        maximum_ttl: u64,
    ) -> Result<Self, PendingError> {
        if !(1..=60).contains(&maximum_ttl) {
            return Err(PendingError::Invalid);
        }
        Ok(Self {
            wallet,
            native,
            pin,
            issuer,
            journal,
            maximum_ttl,
        })
    }
    /// Only exact request and compact holder-proof bytes are caller inputs.
    /// Untrusted inspection precedes Wallet -> Native -> key -> journal locks.
    /// No Packet, context, owner, clock, policy, target or key selectors accepted.
    async fn complete_service_challenge(
        &self,
        raw: &[u8],
        proof_bytes: &[u8],
    ) -> Result<crate::service_challenge_store::StoredCompletion, PendingError> {
        use libsec_core::{service_holder_proof::UntrustedServiceHolderProof, ZenithPacket};
        if raw.is_empty() || raw.len() > 2_097_152 {
            return Err(PendingError::Invalid);
        }
        let proof =
            UntrustedServiceHolderProof::decode(proof_bytes).map_err(|_| PendingError::Invalid)?;
        let clock = PendingClock::new(0);
        clock.sample()?;
        let retained = self
            .journal
            .retained_completion_basis(proof.claims.challenge_id, &clock)
            .await?;
        clock.sample()?;
        let challenge = &retained.challenge;
        if challenge.request_bytes != raw
            || proof.claims != challenge.claims
            || proof.issuer_signature != challenge.issuer_signature
        {
            return Err(PendingError::Invalid);
        }
        let window =
            OriginalServiceWindow::new(challenge.claims.issued_at, challenge.claims.expires_at)
                .ok_or(PendingError::Invalid)?;
        if let Some(cached) = &retained.completion {
            let packet = ZenithPacket {
                session_id: challenge.claims.session_id,
                nonce: challenge.claims.nonce,
                opcode: challenge.claims.opcode,
                proof: proof_bytes.to_vec(),
                claim_ttl: challenge.claims.ttl_seconds,
                encrypted_payload: raw.to_vec(),
                mac: [0; 16],
            };
            if bincode::serialize(&packet).map_err(|_| PendingError::Invalid)? != cached.packet {
                return Err(PendingError::Invalid);
            }
        }
        let journal_entered = std::cell::Cell::new(false);
        let result = self
            .complete_retained_service_challenge(
                raw,
                proof_bytes,
                &retained,
                window,
                &clock,
                &journal_entered,
            )
            .await;
        if result.is_err() && !journal_entered.get() {
            if let Some(cached) = &retained.completion {
                // The inner future has returned, dropping partial/current owners
                // before journal cleanup. Reuse the SAME sticky clock; no retry
                // with refreshed state/time can convert a denial into success.
                // Cleanup uncertainty must not obscure the original denial or
                // create a positive fallback. A sticky clock failure may itself
                // prevent this negative persistence; future export still checks
                // all actual owners and the original window.
                let _cleanup = self
                    .journal
                    .reject_cached_exact(challenge.claims.challenge_id, cached, &clock)
                    .await;
            }
        }
        result
    }
    async fn complete_retained_service_challenge(
        &self,
        raw: &[u8],
        proof_bytes: &[u8],
        retained: &crate::service_challenge_store::RetainedCompletionBasis,
        window: OriginalServiceWindow,
        clock: &PendingClock,
        journal_entered: &std::cell::Cell<bool>,
    ) -> Result<crate::service_challenge_store::StoredCompletion, PendingError> {
        use crate::service_challenge_store::{ExportStage, GuardInput, IssuanceTimes};
        use bincode::Options;
        use libsec_core::{service_holder_proof::challenge_transcript, ZenithPacket};
        let challenge = &retained.challenge;
        if challenge.claims.ttl_seconds > self.maximum_ttl {
            return Err(PendingError::Invalid);
        }
        let wallet = self.wallet.capture_shared()?;
        let native = self.native.capture_shared(self.pin, &wallet)?;
        let policy = native.policy()?;
        wallet.require_active_for_challenge(window.issued_at(), window.expires_at(), &native)?;
        let (subject, holder_key, _) = holder(&wallet)?;
        let prepared = policy.prepare_recorded_original(
            raw,
            subject,
            holder_key,
            window,
            challenge.claims.evidence.evidence_observed_at,
        )?;
        let randomness = PendingRandomness {
            challenge: challenge.claims.challenge_id,
            session: challenge.claims.session_id,
            nonce: challenge.claims.nonce,
        };
        let lineage = wallet.observed.reference.lineage_preimage();
        if retained.evidence != prepared.evidence().bytes()
            || retained.lineage != lineage
            || challenge.claims != pending_claims(&wallet, &policy, &prepared, window, randomness)?
        {
            return Err(PendingError::Invalid);
        }
        let transcript =
            challenge_transcript(&challenge.claims, raw).map_err(|_| PendingError::Invalid)?;
        let selected = policy.selected_issuer(window)?;
        let preimage = ServiceChallengeSignaturePreimage {
            binding: SigningBinding {
                lineage: policy.lineage(),
                application: policy.application(),
                node: selected.node_id.clone(),
                key: selected.key.key_id.clone(),
                public: selected.key.public_key.to_bytes(),
                window,
            },
            transcript,
        };
        let packet = ZenithPacket {
            session_id: challenge.claims.session_id,
            nonce: challenge.claims.nonce,
            opcode: challenge.claims.opcode,
            proof: proof_bytes.to_vec(),
            claim_ttl: challenge.claims.ttl_seconds,
            encrypted_payload: raw.to_vec(),
            mac: [0; 16],
        };
        let authenticated = policy.verify_holder(
            &wallet,
            &packet,
            &prepared,
            window,
            crate::service_wallet_source::hash(&preimage.transcript),
        )?;
        let key = self.issuer.lease(&policy, window)?;
        let pending = PendingGuard {
            wallet: &wallet,
            native: &native,
            policy: &policy,
            key: &key,
            prepared: &prepared,
            preimage: &preimage,
            challenge,
            lineage: &lineage,
            raw,
            window,
            randomness,
            clock,
        };
        pending.check(GuardInput {
            stage: ExportStage::Pending,
            challenge,
            evidence: &retained.evidence,
            lineage: &retained.lineage,
            packet: &[],
            context: &[],
            signed_at: 0,
            holder_verified_at: 0,
        })?;
        let context = completion_context(&authenticated);
        let verified_at = clock.sample()?;
        let is_cached = retained.completion.is_some();
        let (signed, times) = if let Some(cached) = &retained.completion {
            let signed: crate::verifier::SignedVerifiedCallContext = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .with_limit(crate::service_challenge_store::CONTEXT_LIMIT as u64)
                .reject_trailing_bytes()
                .deserialize(&cached.context)
                .map_err(|_| PendingError::Invalid)?;
            if signed.context != context {
                return Err(PendingError::Invalid);
            }
            (
                signed,
                IssuanceTimes {
                    holder_verified_at: cached.holder_verified_at,
                    context_signed_at: cached.signed_at,
                },
            )
        } else {
            let selected = policy.selected_issuer(window)?;
            let prepared_context = PreparedServiceContext {
                binding: SigningBinding {
                    lineage: policy.lineage(),
                    application: policy.application(),
                    node: selected.node_id.clone(),
                    key: selected.key.key_id.clone(),
                    public: selected.key.public_key.to_bytes(),
                    window,
                },
                context,
            };
            let signed = key.sign_context(prepared_context)?;
            (
                signed,
                IssuanceTimes {
                    holder_verified_at: verified_at,
                    context_signed_at: clock.sample()?,
                },
            )
        };
        let packet_bytes = bincode::serialize(&packet).map_err(|_| PendingError::Invalid)?;
        let context_bytes = bincode::serialize(&signed).map_err(|_| PendingError::Invalid)?;
        if let Some(cached) = &retained.completion {
            if cached.packet != packet_bytes || cached.context != context_bytes {
                return Err(PendingError::Invalid);
            }
        }
        let mut guard = CompletionGuard {
            pending,
            packet: &packet,
            packet_bytes: &packet_bytes,
            context_bytes: &context_bytes,
            signed: &signed,
            times,
        };
        journal_entered.set(true);
        if is_cached {
            Ok(self
                .journal
                .cached_unique(
                    challenge.claims.challenge_id,
                    proof_bytes,
                    raw,
                    &mut guard,
                    clock,
                )
                .await?)
        } else {
            Ok(self
                .journal
                .complete_unique(
                    challenge.claims.challenge_id,
                    &packet_bytes,
                    &context_bytes,
                    times,
                    &mut guard,
                    clock,
                )
                .await?)
        }
    }
    /// Lookup identity is untrusted and selects only a row, never an authority
    /// source or claim. Recover exact original bytes; no entropy, signing or TTL
    /// renewal occurs. A changed row is checked again under the final journal lock.
    async fn resume_pending_challenge(
        &self,
        raw: &[u8],
        challenge_id: [u8; 32],
    ) -> Result<crate::service_challenge_store::StoredChallenge, PendingError> {
        use libsec_core::service_holder_proof::challenge_transcript;
        if raw.is_empty() || raw.len() > 2_097_152 || challenge_id == [0; 32] {
            return Err(PendingError::Invalid);
        }
        let clock = PendingClock::new(0);
        clock.sample()?;
        // No authority owners are held while this bounded UNTRUSTED inspection
        // takes the journal lock. It cannot export from the producer.
        let retained = self.journal.retained_pending(challenge_id, &clock).await?;
        let challenge = &retained.challenge;
        if challenge.request_bytes != raw
            || challenge.claims.challenge_id != challenge_id
            || challenge.claims.ttl_seconds > self.maximum_ttl
        {
            return Err(PendingError::Invalid);
        }
        let window =
            OriginalServiceWindow::new(challenge.claims.issued_at, challenge.claims.expires_at)
                .ok_or(PendingError::Invalid)?;
        let wallet = self.wallet.capture_shared()?;
        let native = self.native.capture_shared(self.pin, &wallet)?;
        let policy = native.policy()?;
        wallet.require_active_for_challenge(window.issued_at(), window.expires_at(), &native)?;
        let (subject, holder_key, _) = holder(&wallet)?;
        let prepared = policy.prepare_recorded_original(
            raw,
            subject,
            holder_key,
            window,
            challenge.claims.evidence.evidence_observed_at,
        )?;
        let randomness = PendingRandomness {
            challenge: challenge_id,
            session: challenge.claims.session_id,
            nonce: challenge.claims.nonce,
        };
        let lineage = wallet.observed.reference.lineage_preimage();
        if retained.lineage != lineage
            || retained.evidence != prepared.evidence().bytes()
            || challenge.claims != pending_claims(&wallet, &policy, &prepared, window, randomness)?
        {
            return Err(PendingError::Invalid);
        }
        let transcript =
            challenge_transcript(&challenge.claims, raw).map_err(|_| PendingError::Invalid)?;
        let selected = policy.selected_issuer(window)?;
        selected
            .key
            .public_key
            .verify_strict(
                &transcript,
                &ed25519_dalek::Signature::from_bytes(&challenge.issuer_signature),
            )
            .map_err(|_| PendingError::Invalid)?;
        // Actual private key source selection/revalidation follows policy and
        // signature validation and precedes reacquiring the journal lock.
        let key = self.issuer.lease(&policy, window)?;
        let preimage = ServiceChallengeSignaturePreimage {
            binding: SigningBinding {
                lineage: policy.lineage(),
                application: policy.application(),
                node: selected.node_id.clone(),
                key: selected.key.key_id.clone(),
                public: selected.key.public_key.to_bytes(),
                window,
            },
            transcript,
        };
        let mut guard = PendingGuard {
            wallet: &wallet,
            native: &native,
            policy: &policy,
            key: &key,
            prepared: &prepared,
            preimage: &preimage,
            challenge,
            lineage: &lineage,
            raw,
            window,
            randomness,
            clock: &clock,
        };
        Ok(self
            .journal
            .pending_unique(challenge_id, &mut guard, &clock)
            .await?)
    }
    async fn retained_request_id(&self, raw: &[u8]) -> Result<Option<[u8; 32]>, PendingError> {
        if raw.is_empty() || raw.len() > 2_097_152 {
            return Err(PendingError::Invalid);
        }
        // Preliminary Wallet capture supplies only a stable lookup identity. It
        // drops BEFORE the journal lock; recovery reacquires every actual owner.
        let subject = {
            let wallet = self.wallet.capture_shared()?;
            holder(&wallet)?.0.to_owned()
        };
        let clock = PendingClock::new(0);
        clock.sample()?;
        Ok(self
            .journal
            .retained_request_id(&subject, raw, &clock)
            .await?)
    }
    async fn resume_matching_request(
        &self,
        raw: &[u8],
    ) -> Result<crate::service_challenge_store::StoredChallenge, PendingError> {
        let id = self
            .retained_request_id(raw)
            .await?
            .ok_or(PendingError::Journal(
                crate::service_challenge_store::JournalError::Missing,
            ))?;
        self.resume_pending_challenge(raw, id).await
    }
    async fn issue_pending_challenge(
        &self,
        raw: &[u8],
    ) -> Result<crate::service_challenge_store::StoredChallenge, PendingError> {
        if let Some(id) = self.retained_request_id(raw).await? {
            return self.resume_pending_challenge(raw, id).await;
        }
        // All issuance owners have dropped when this future returns. Only this
        // typed atomic request conflict allows ONE new lookup/recovery attempt.
        // Busy, capacity, random identity collisions and storage failures deny.
        match self.issue_new_pending_challenge(raw).await {
            Err(PendingError::RetainedRequest) => self.resume_matching_request(raw).await,
            result => result,
        }
    }
    async fn issue_new_pending_challenge(
        &self,
        raw: &[u8],
    ) -> Result<crate::service_challenge_store::StoredChallenge, PendingError> {
        use crate::service_authority_snapshot::SnapshotError;
        use crate::service_owner_publication::HeldPolicyError;
        use libsec_core::service_holder_proof::{
            challenge_transcript, UntrustedSignedServiceChallenge,
        };
        let wallet = self.wallet.capture_shared()?;
        let native = self.native.capture_shared(self.pin, &wallet)?;
        let policy = native.policy()?;
        let clock = PendingClock::new(policy.lineage().observed_at());
        let issued = clock.sample()?;
        let (subject, holder_key, _) = holder(&wallet)?;
        // At most60 complete-window validations, largest first. An inadmissible
        // longer candidate is never signed, stored or reused as an old window.
        let mut selected = None;
        for ttl in (1..=self.maximum_ttl).rev() {
            let Some(expires) = issued.checked_add(ttl) else {
                return Err(PendingError::Invalid);
            };
            let Some(window) = OriginalServiceWindow::new(issued, expires) else {
                continue;
            };
            let prepared = match policy.prepare_original(raw, subject, holder_key, window) {
                Ok(value) => value,
                Err(HeldPolicyError::Policy(SnapshotError::Window | SnapshotError::Denied)) => {
                    continue
                }
                Err(error) => return Err(error.into()),
            };
            match wallet.require_active_for_challenge(issued, expires, &native) {
                Ok(()) => {
                    selected = Some((window, prepared));
                    break;
                }
                Err(crate::service_wallet_source::SourceError::Window) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let (window, prepared) = selected.ok_or(PendingError::Invalid)?;
        // No private key access until the real descriptor's explicit empty-
        // obligation evidence and exact whole-window request policy pass above.
        let randomness = PendingRandomness::fresh()?;
        let key = self.issuer.lease(&policy, window)?;
        let claims = pending_claims(&wallet, &policy, &prepared, window, randomness)?;
        let issuer = policy.selected_issuer(window)?;
        let preimage = ServiceChallengeSignaturePreimage {
            binding: SigningBinding {
                lineage: policy.lineage(),
                application: policy.application(),
                node: issuer.node_id.clone(),
                key: issuer.key.key_id.clone(),
                public: issuer.key.public_key.to_bytes(),
                window,
            },
            transcript: challenge_transcript(&claims, raw).map_err(|_| PendingError::Invalid)?,
        };
        let challenge = UntrustedSignedServiceChallenge {
            claims,
            request_bytes: raw.to_vec(),
            issuer_signature: key.sign_challenge(&preimage)?,
        };
        let lineage = wallet.observed.reference.lineage_preimage();
        let mut guard = PendingGuard {
            wallet: &wallet,
            native: &native,
            policy: &policy,
            key: &key,
            prepared: &prepared,
            preimage: &preimage,
            challenge: &challenge,
            lineage: &lineage,
            raw,
            window,
            randomness,
            clock: &clock,
        };
        // Nothing signed escapes until durable Pending, connection close and the
        // journal's final full guard/clock-floor admission have returned success.
        let stored = self
            .journal
            .persist_pending_once(
                &challenge,
                prepared.evidence().bytes(),
                &lineage,
                &mut guard,
                &clock,
            )
            .await?;
        Ok(stored)
    }
}
#[cfg(test)]
#[path = "service_pending_issuer_tests.rs"]
mod pending_tests;

#[cfg(test)]
#[path = "service_authority_tests.rs"]
pub(crate) mod tests;

#[path = "service_authority_startup.rs"]
mod startup;
pub use startup::{ServiceAuthority, ServiceAuthorityError, ServiceCompletion};
