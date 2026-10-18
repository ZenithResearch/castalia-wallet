//! Privileged original-input administrative selection. All configured/returned
//! bytes are DATA. Only actual held sources authorize bounded bookkeeping;
//! these owners expose no issuer, current lease or historical-success receipt.
use super::*;
use crate::service_wallet_contract::{verify_original_reference_relation, StartupPin};
use castalia_wallet_private_files::service_store::Identity;

/// Independently retained BEFORE the opaque call. DATA, not source provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OriginalPhysicalRootIdentities {
    native_device: u64,
    native_inode: u64,
    wallet_device: u64,
    wallet_inode: u64,
}
impl OriginalPhysicalRootIdentities {
    pub fn from_owner_configuration(
        native_device: u64,
        native_inode: u64,
        wallet_device: u64,
        wallet_inode: u64,
    ) -> Self {
        Self {
            native_device,
            native_inode,
            wallet_device,
            wallet_inode,
        }
    }
    pub fn native_identity(&self) -> Identity {
        Identity {
            device: self.native_device,
            inode: self.native_inode,
        }
    }
    pub fn wallet_identity(&self) -> Identity {
        Identity {
            device: self.wallet_device,
            inode: self.wallet_inode,
        }
    }
}
/// Bounded original public configuration. Parsing does not authenticate when or
/// where the operator selected it, and cannot create an observation or owner.
pub struct OriginalTransitionSelection {
    pub(super) roots: OriginalPhysicalRootIdentities,
    old_pin: OwnerStartupPin,
    old_raw: Vec<u8>,
    pub(super) startup_raw: Vec<u8>,
    old_reference: WalletReference,
    old_state: wallet::StateRecord,
    old_state_raw: Vec<u8>,
    intent: WalletTransitionIntent,
    policy: TargetPolicy,
    request: Value,
}
impl OriginalTransitionSelection {
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep the independently retained original anchors explicit in the reviewed constructor contract."
    )]
    pub fn new(
        roots: OriginalPhysicalRootIdentities,
        old_native: OwnerStartupPin,
        exact_old_native_bytes: Vec<u8>,
        exact_old_wallet_startup_pin_bytes: Vec<u8>,
        exact_old_wallet_reference_bytes: Vec<u8>,
        exact_old_wallet_state_bytes: Vec<u8>,
        original_intent: WalletTransitionIntent,
        exact_original_target_policy_bytes: Vec<u8>,
    ) -> Result<Self> {
        let configure_size = match &original_intent {
            WalletTransitionIntent::Configure { owner_input } => owner_input.len(),
            _ => 0,
        };
        let sizes = [
            exact_old_native_bytes.len(),
            exact_old_wallet_startup_pin_bytes.len(),
            exact_old_wallet_reference_bytes.len(),
            exact_old_wallet_state_bytes.len(),
            exact_original_target_policy_bytes.len(),
            configure_size,
        ];
        if sizes[0] > IMAGE as usize
            || sizes[3] > 4096
            || configure_size > IMAGE as usize
            || sizes[4]
                .checked_add(4096 + 64)
                .is_none_or(|n| n > IMAGE as usize)
            || sizes
                .into_iter()
                .try_fold(0usize, |a, n| a.checked_add(n))
                .is_none_or(|n| n > LOGICAL as usize)
        {
            return Err(SourceError::Capacity);
        }
        old_native
            .generation
            .checked_add(1)
            .filter(|g| *g <= MAX_SAFE_TIME)
            .ok_or(SourceError::Capacity)?;
        let old_bundle = check_bundle(&exact_old_native_bytes, old_native)?;
        let old_reference =
            WalletReference::parse(&exact_old_wallet_reference_bytes).map_err(invalid)?;
        let pin = StartupPin::parse(&exact_old_wallet_startup_pin_bytes).map_err(invalid)?;
        pin.compare_reference(&old_reference).map_err(invalid)?;
        let old_state = wallet::retained_state(&exact_old_wallet_state_bytes, &old_reference)?;
        let policy = TargetPolicy::parse(&exact_original_target_policy_bytes).map_err(invalid)?;
        if canonical(&old_bundle.value["wallet_current"]) != old_reference.canonical_bytes()
            || policy.value["application"] != old_reference.value["application"]
        {
            return Err(SourceError::Changed);
        }
        if old_reference.state() == WalletState::Revoked && original_intent.kind() != "reconcile" {
            return Err(SourceError::Inactive);
        }
        let mut request = json!({"owner_input_sha256":null,"requested_not_before":null,"requested_not_after":null,"target_policy_sha256":hex(&policy.digest())});
        match &original_intent {
            WalletTransitionIntent::Configure { owner_input } => {
                wallet::validate_transition_request(owner_input, &old_reference)?;
                request["owner_input_sha256"] = json!(hex(&hash(owner_input)));
            }
            WalletTransitionIntent::Rotate {
                not_before,
                not_after,
            } => {
                if not_before >= not_after || *not_after > MAX_SAFE_TIME {
                    return Err(SourceError::Window);
                }
                request["requested_not_before"] = json!(not_before);
                request["requested_not_after"] = json!(not_after);
            }
            _ => {}
        }
        verify_original_reference_relation(
            &old_reference,
            &old_reference,
            original_intent.kind(),
            &request,
        )
        .map_err(invalid)?;
        Ok(Self {
            roots,
            old_pin: old_native,
            old_raw: exact_old_native_bytes,
            startup_raw: exact_old_wallet_startup_pin_bytes,
            old_reference,
            old_state,
            old_state_raw: exact_old_wallet_state_bytes,
            intent: original_intent,
            policy,
            request,
        })
    }
    pub fn original_physical_roots(&self) -> &OriginalPhysicalRootIdentities {
        &self.roots
    }
    pub(super) fn wallet_data(&self) -> OriginalWalletSelectionData<'_> {
        OriginalWalletSelectionData { selection: self }
    }
    pub(super) fn validate_source(
        &self,
        source: &OwnerPublicationSource,
        wallet: &WalletCurrentSource,
        lock: &File,
        lock_id: (u64, u64),
    ) -> Result<()> {
        source.files.inspect()?;
        source.files.validate_root()?;
        safe(lock, 0)?;
        let expected = self.roots.native_identity();
        if source.files.identity != (expected.device, expected.inode)
            || id(source.files.root())? != (expected.device, expected.inode)
            || id(lock)? != lock_id
            || wallet.configured_root_identity() != self.roots.wallet_identity()
            || wallet.configured_startup_pin_bytes() != self.startup_raw
        {
            return Err(SourceError::Changed);
        }
        let fresh = open_at(source.files.root(), LOCK, libc::O_RDONLY)?;
        safe(&fresh, 0)?;
        if id(&fresh)? != lock_id {
            return Err(SourceError::Changed);
        }
        close(fresh)?;
        source.time(self.old_state.published_at)?;
        Ok(())
    }
    fn match_marker(&self, m: &TransitionMarker) -> Result<()> {
        if m.value["old_native_cas"] != self.old_pin.value()
            || m.value["old_native_image_sha256"] != hex(&self.old_pin.sha256)
            || canonical(&m.value["old_wallet_reference"]) != self.old_reference.canonical_bytes()
            || m.value["mutation"] != self.intent.kind()
            || m.value["request"] != self.request
            || m.value["started_at"]
                .as_u64()
                .is_none_or(|n| n < self.old_state.published_at)
        {
            return Err(SourceError::Changed);
        }
        m.binding_preimage(&self.policy).map_err(invalid)?;
        Ok(())
    }
    pub(super) fn validate_full_records(
        &self,
        source: &OwnerPublicationSource,
        m: &TransitionMarker,
    ) -> Result<()> {
        self.match_marker(m)?;
        if source.files.read("OLD-NATIVE.json", true)? != self.old_raw
            || source.files.read("OLD-WALLET-STATE.json", true)? != self.old_state_raw
            || source.files.read("TARGET-POLICY.json", true)? != self.policy.canonical_bytes()
        {
            return Err(SourceError::Changed);
        }
        match &self.intent {
            WalletTransitionIntent::Configure { owner_input } => {
                if source.files.read("REQUEST-OWNER-INPUT.json", true)? != *owner_input {
                    return Err(SourceError::Changed);
                }
            }
            _ => {
                if source.files.exists("REQUEST-OWNER-INPUT.json", true)? {
                    return Err(SourceError::Changed);
                }
            }
        }
        let outcome = source.files.exists("OUTCOME.json", true)?;
        let target = source.files.exists("TARGET-NATIVE.json", true)?;
        if outcome && target {
            let o =
                OutcomeRecord::parse(&source.files.read("OUTCOME.json", true)?).map_err(invalid)?;
            verify_retained_transition(
                m,
                &self.policy,
                &self.old_raw,
                Some(&o),
                Some(&source.files.read("TARGET-NATIVE.json", true)?),
            )
            .map_err(invalid)?;
        } else {
            if m.value["stage"] != "prepared" || target {
                return Err(SourceError::Changed);
            }
            verify_retained_transition(m, &self.policy, &self.old_raw, None, None)
                .map_err(invalid)?;
            if outcome {
                OutcomeRecord::parse(&source.files.read("OUTCOME.json", true)?)
                    .map_err(invalid)?
                    .verify(m, &self.policy)
                    .map_err(invalid)?;
            }
        }
        let now = source.time(m.value["started_at"].as_u64().ok_or(SourceError::Invalid)?)?;
        if outcome {
            let o =
                OutcomeRecord::parse(&source.files.read("OUTCOME.json", true)?).map_err(invalid)?;
            if o.value["observed_at"].as_u64().is_none_or(|n| n > now) {
                return Err(SourceError::Clock);
            }
        }
        Ok(())
    }
    fn verify_actual(&self, current: &ObservedWallet) -> Result<()> {
        if current.root != self.roots.wallet_identity() {
            return Err(SourceError::Changed);
        }
        verify_original_reference_relation(
            &self.old_reference,
            &current.reference,
            self.intent.kind(),
            &self.request,
        )
        .map_err(invalid)?;
        compare_predecessor(
            &self.old_reference,
            &self.old_state,
            &self.old_state_raw,
            current,
            self.intent.kind(),
        )
    }
    fn validate_present_records(
        &self,
        source: &OwnerPublicationSource,
        m: &TransitionMarker,
        current: &[u8],
    ) -> Result<Vec<String>> {
        self.match_marker(m)?;
        if !list(source.files.root(), 5)?.iter().any(|n| n == RECORDS) {
            return Ok(Vec::new());
        }
        let now = source.time(m.value["started_at"].as_u64().ok_or(SourceError::Invalid)?)?;
        let d = source.files.records()?;
        let names = list(&d, 6)?;
        close(d)?;
        for n in &names {
            bound(n, true)?;
            let raw = source.files.read(n, true)?;
            match n.as_str() {
                "OLD-NATIVE.json" => {
                    if raw != self.old_raw {
                        return Err(SourceError::Changed);
                    }
                }
                "OLD-WALLET-STATE.json" => {
                    if raw != self.old_state_raw {
                        return Err(SourceError::Changed);
                    }
                }
                "TARGET-POLICY.json" => {
                    if raw != self.policy.canonical_bytes() {
                        return Err(SourceError::Changed);
                    }
                }
                "REQUEST-OWNER-INPUT.json" => match &self.intent {
                    WalletTransitionIntent::Configure { owner_input } if raw == *owner_input => {}
                    _ => return Err(SourceError::Changed),
                },
                "OUTCOME.json" => {
                    let o = OutcomeRecord::parse(&raw).map_err(invalid)?;
                    o.verify(m, &self.policy).map_err(invalid)?;
                    if o.value["observed_at"].as_u64().is_none_or(|n| n > now) {
                        return Err(SourceError::Clock);
                    }
                }
                "TARGET-NATIVE.json" => {
                    if raw != current {
                        return Err(SourceError::Changed);
                    }
                }
                _ => return Err(SourceError::UnsafeStorage),
            }
        }
        Ok(names)
    }
}
/// Borrowed independent comparison DATA for Wallet's actual private validator.
pub struct OriginalWalletSelectionData<'a> {
    selection: &'a OriginalTransitionSelection,
}
impl OriginalWalletSelectionData<'_> {
    pub fn selected_wallet_root_identity(&self) -> Identity {
        self.selection.roots.wallet_identity()
    }
    pub fn old_wallet_startup_pin_bytes(&self) -> &[u8] {
        &self.selection.startup_raw
    }
    pub fn old_wallet_reference_bytes(&self) -> &[u8] {
        self.selection.old_reference.canonical_bytes()
    }
    pub fn old_wallet_state_bytes(&self) -> &[u8] {
        &self.selection.old_state_raw
    }
    pub fn mutation_kind(&self) -> WalletMutationKind {
        match self.selection.intent {
            WalletTransitionIntent::Configure { .. } => WalletMutationKind::Configure,
            WalletTransitionIntent::Rotate { .. } => WalletMutationKind::Rotate,
            WalletTransitionIntent::Revoke => WalletMutationKind::Revoke,
            WalletTransitionIntent::Reconcile => WalletMutationKind::Reconcile,
        }
    }
    pub fn configure_owner_input_bytes(&self) -> Option<&[u8]> {
        match &self.selection.intent {
            WalletTransitionIntent::Configure { owner_input } => Some(owner_input),
            _ => None,
        }
    }
    pub fn requested_rotation_window(&self) -> Option<(u64, u64)> {
        match self.selection.intent {
            WalletTransitionIntent::Rotate {
                not_before,
                not_after,
            } => Some((not_before, not_after)),
            _ => None,
        }
    }
}
/// Actual exclusive Native descriptor and immutable original configuration.
/// No Clone/Deserialize/Debug, raw File or current/issuer lease is exposed.
pub struct NativeOriginalTransitionInspection<'s, 'w> {
    pub(super) source: &'s OwnerPublicationSource,
    pub(super) wallet: &'w WalletCurrentSource,
    pub(super) lock: File,
    pub(super) lock_id: (u64, u64),
    pub(super) original: OriginalTransitionSelection,
}
enum Layout {
    Empty,
    Ordinary {
        marker: TransitionMarker,
        exact: Vec<u8>,
        temp: bool,
    },
    Completed {
        marker: TransitionMarker,
        exact: Vec<u8>,
    },
}
fn transition_id(m: &TransitionMarker) -> Result<[u8; 16]> {
    let s = m.value["transition_id"]
        .as_str()
        .ok_or(SourceError::Invalid)?;
    let mut out = [0; 16];
    for (i, n) in out.iter_mut().enumerate() {
        *n = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(invalid)?;
    }
    Ok(out)
}
struct HeldOriginal<'a> {
    source: &'a OwnerPublicationSource,
    wallet: &'a WalletCurrentSource,
    lock: &'a File,
    lock_id: (u64, u64),
    original: &'a OriginalTransitionSelection,
}
impl HeldOriginal<'_> {
    fn roots(&self) -> Result<()> {
        self.original
            .validate_source(self.source, self.wallet, self.lock, self.lock_id)
    }
    fn layout(&self) -> Result<Layout> {
        self.roots()?;
        let s = self.source;
        let o = self.original;
        let marker = s.files.exists(MARKER, false)?;
        let temp = s.files.exists(TEMP, false)?;
        let current = s.files.read(CURRENT, false)?;
        if marker {
            let exact = s.files.read(MARKER, false)?;
            let m = TransitionMarker::parse(&exact).map_err(invalid)?;
            o.validate_full_records(s, &m)?;
            self.native_stage(&m, &current)?;
            return Ok(Layout::Ordinary {
                marker: m,
                exact,
                temp,
            });
        }
        if temp {
            let exact = s.files.read(TEMP, false)?;
            let m = TransitionMarker::parse(&exact).map_err(invalid)?;
            if m.value["stage"] != "native_published" {
                return Err(SourceError::TransitionPending);
            }
            o.match_marker(&m)?;
            self.native_stage(&m, &current)?;
            o.validate_present_records(s, &m, &current)?;
            return Ok(Layout::Completed { marker: m, exact });
        }
        if list(s.files.root(), 5)?.iter().any(|n| n == RECORDS) {
            return Err(SourceError::TransitionPending);
        }
        if current != o.old_raw {
            let b = TargetBundle::parse(&current).map_err(invalid)?;
            if b.value["generation"] != o.old_pin.generation + 1 {
                return Err(SourceError::Changed);
            }
        }
        self.roots()?;
        Ok(Layout::Empty)
    }
    fn native_stage(&self, m: &TransitionMarker, current: &[u8]) -> Result<()> {
        let o = self.original;
        let s = self.source;
        if m.value["stage"] == "native_published"
            && (m.value["target_native"]["native_cas"]["bundle_sha256"] != hex(&hash(current))
                || m.value["target_native"]["native_cas"]["generation"] != o.old_pin.generation + 1)
        {
            return Err(SourceError::Changed);
        }
        if current != o.old_raw || m.value["stage"] == "native_published" {
            if m.value["stage"] == "prepared" {
                return Err(SourceError::Changed);
            }
            let recorded = WalletReference::parse(&canonical(
                &m.value["observed_outcome"]["wallet_reference"],
            ))
            .map_err(invalid)?;
            let cas = NativeCas::parse(&canonical(&o.old_pin.value())).map_err(invalid)?;
            if o.policy
                .derive_target(&cas, &recorded)
                .map_err(invalid)?
                .canonical_bytes()
                != current
            {
                return Err(SourceError::Changed);
            }
        }
        s.time(m.value["started_at"].as_u64().ok_or(SourceError::Invalid)?)?;
        Ok(())
    }
    fn actual(&self, view: &BorrowedPublicServiceObservation<'_, '_>) -> Result<ObservedWallet> {
        self.roots()?;
        let actual = self.wallet.inspect_transition(view)?;
        self.original.verify_actual(&actual)?;
        let n = self.source.time(actual.durable)?;
        if actual.state.published_at > n {
            return Err(SourceError::Clock);
        }
        if actual.reference.canonical_bytes() != self.original.old_reference.canonical_bytes() {
            if let WalletTransitionIntent::Configure { owner_input } = &self.original.intent {
                if view.metadata().owner_input_bytes() != Some(owner_input.as_slice()) {
                    return Err(SourceError::Changed);
                }
            }
        }
        Ok(actual)
    }
    fn full(
        &self,
        view: &BorrowedPublicServiceObservation<'_, '_>,
        require_temp: bool,
    ) -> Result<(TransitionMarker, ObservedWallet, Vec<u8>)> {
        let Layout::Ordinary {
            marker,
            exact,
            temp,
        } = self.layout()?
        else {
            return Err(SourceError::TransitionPending);
        };
        if temp != require_temp {
            return Err(SourceError::TransitionPending);
        }
        let actual = self.actual(view)?;
        if self.source.files.exists("OUTCOME.json", true)? {
            let o = OutcomeRecord::parse(&self.source.files.read("OUTCOME.json", true)?)
                .map_err(invalid)?;
            o.verify(&marker, &self.original.policy).map_err(invalid)?;
            if o.reference().canonical_bytes() != actual.reference.canonical_bytes() {
                return Err(SourceError::Changed);
            }
        }
        self.roots()?;
        self.wallet.inspect_transition(view)?.equal(&actual)?;
        Ok((marker, actual, exact))
    }
    fn expected_target(&self, actual: &ObservedWallet) -> Result<(Vec<u8>, OwnerStartupPin)> {
        let cas = NativeCas::parse(&canonical(&self.original.old_pin.value())).map_err(invalid)?;
        let target = self
            .original
            .policy
            .derive_target(&cas, &actual.reference)
            .map_err(invalid)?;
        let raw = target.canonical_bytes().to_vec();
        if self.source.files.read(CURRENT, false)? != raw {
            return Err(SourceError::Changed);
        }
        // No digest of observed CURRENT is fed back as its expected pin.
        let pin = OwnerStartupPin::new(self.original.old_pin.generation + 1, target.digest())?;
        Ok((raw, pin))
    }
    fn completed(
        &self,
        view: &BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<(TransitionMarker, Vec<u8>, ObservedWallet, OwnerStartupPin)> {
        let Layout::Completed { marker, exact } = self.layout()? else {
            return Err(SourceError::TransitionPending);
        };
        let actual = self.actual(view)?;
        if canonical(&marker.value["observed_outcome"]["wallet_reference"])
            != actual.reference.canonical_bytes()
        {
            return Err(SourceError::Changed);
        }
        let (raw, pin) = self.expected_target(&actual)?;
        if marker.value["target_native"]["native_cas"] != pin.value() {
            return Err(SourceError::Changed);
        }
        self.original
            .validate_present_records(self.source, &marker, &raw)?;
        self.source
            .remaining_completed_records(&marker, &raw, &actual)?;
        self.roots()?;
        self.wallet.inspect_transition(view)?.equal(&actual)?;
        Ok((marker, exact, actual, pin))
    }
    fn terminal(
        &self,
        view: &BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<OriginalTerminalSourceData> {
        if !matches!(self.layout()?, Layout::Empty) {
            return Err(SourceError::TransitionPending);
        }
        let actual = self.actual(view)?;
        let raw = self.source.files.read(CURRENT, false)?;
        let (disposition, pin, startup) = if raw == self.original.old_raw {
            if actual.reference.canonical_bytes() != self.original.old_reference.canonical_bytes()
                || actual.state_raw != self.original.old_state_raw
            {
                return Err(SourceError::Changed);
            }
            (
                OriginalTerminalDisposition::OldSourceUnchanged,
                self.original.old_pin,
                self.original.startup_raw.clone(),
            )
        } else {
            let (_, pin) = self.expected_target(&actual)?;
            let startup = canonical(
                &json!({"schema":"secs.wallet-current-startup-pin.v2","store_id":actual.reference.value["store_id"],"minimum_state_revision":actual.revision(),"minimum_key_generation":actual.generation(),"expected_wallet_reference_sha256":hex(&actual.reference.reference_digest())}),
            );
            StartupPin::parse(&startup)
                .map_err(invalid)?
                .compare_reference(&actual.reference)
                .map_err(invalid)?;
            (OriginalTerminalDisposition::DerivedNewSource, pin, startup)
        };
        self.roots()?;
        if self.source.files.read(CURRENT, false)? != raw
            || !matches!(self.layout()?, Layout::Empty)
        {
            return Err(SourceError::Changed);
        }
        self.wallet.inspect_transition(view)?.equal(&actual)?;
        self.source.time(actual.durable)?;
        Ok(OriginalTerminalSourceData {
            disposition,
            native_generation: pin.generation,
            native_sha256: pin.sha256,
            wallet_reference: actual.reference.canonical_bytes().into(),
            wallet_startup: startup,
        })
    }
}
impl OwnerPublicationSource {
    pub fn begin_original_transition_inspection<'s, 'w>(
        &'s self,
        wallet: &'w WalletCurrentSource,
        original: OriginalTransitionSelection,
    ) -> std::result::Result<
        NativeOriginalTransitionInspection<'s, 'w>,
        Box<(SourceError, OriginalTransitionSelection)>,
    > {
        let lock = match self.lock(true) {
            Ok(lock) => lock,
            Err(error) => return Err(Box::new((error, original))),
        };
        let lock_id = match id(&lock) {
            Ok(id) => id,
            Err(error) => return Err(Box::new((error, original))),
        };
        let inspection = NativeOriginalTransitionInspection {
            source: self,
            wallet,
            lock,
            lock_id,
            original,
        };
        if let Err(error) = inspection.revalidate() {
            return Err(Box::new((error, inspection.original)));
        }
        Ok(inspection)
    }
}
impl<'s, 'w> NativeOriginalTransitionInspection<'s, 'w> {
    fn held(&self) -> HeldOriginal<'_> {
        HeldOriginal {
            source: self.source,
            wallet: self.wallet,
            lock: &self.lock,
            lock_id: self.lock_id,
            original: &self.original,
        }
    }
    pub fn revalidate(&self) -> Result<()> {
        self.held().layout().map(|_| ())
    }
    pub fn candidate_transition_id(&self) -> Result<Option<[u8; 16]>> {
        match self.held().layout()? {
            Layout::Empty => Ok(None),
            Layout::Ordinary { marker, .. } | Layout::Completed { marker, .. } => {
                transition_id(&marker).map(Some)
            }
        }
    }
    pub fn original_wallet_data(&self) -> OriginalWalletSelectionData<'_> {
        OriginalWalletSelectionData {
            selection: &self.original,
        }
    }
    pub fn into_full_recovery_retaining(
        self,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> std::result::Result<NativeOwnerAdministrationSession<'s, 'w>, Box<(SourceError, Self)>>
    {
        let checked = (|| {
            let (marker, actual, _) = self.held().full(&view, false)?;
            checkpoint("original_full_before_move")?;
            let reference = WalletReference::parse(self.original.old_reference.canonical_bytes())
                .map_err(invalid)?;
            let state = wallet::retained_state(&self.original.old_state_raw, &reference)?;
            Ok((marker, actual, reference, state))
        })();
        let (marker, actual, reference, state) = match checked {
            Ok(v) => v,
            Err(error) => return Err(Box::new((error, self))),
        };
        let Self {
            source,
            wallet,
            lock,
            lock_id,
            original,
        } = self;
        let session = NativeOwnerAdministrationSession {
            source,
            wallet,
            lock,
            lock_id,
            pin: original.old_pin,
            old_raw: original.old_raw.clone(),
            old_wallet: RetainedWalletBasis {
                reference,
                state,
                state_raw: original.old_state_raw.clone(),
                root: actual.root,
                lock: actual.lock,
                epoch: actual.epoch,
            },
            marker: Some(marker),
            tombstone: false,
            recovering: true,
            original_selection: Some(original),
        };
        let checked = (|| {
            checkpoint("original_full_constructed")?;
            session.revalidate()?;
            session.validate_records()?;
            session.verify_current_transition(&actual)?;
            session.actual(&view)?.equal(&actual)
        })();
        if let Err(error) = checked {
            let NativeOwnerAdministrationSession {
                source,
                wallet,
                lock,
                lock_id,
                original_selection,
                ..
            } = session;
            let original = original_selection
                .expect("original-only local construction retains immutable selection");
            return Err(Box::new((
                error,
                Self {
                    source,
                    wallet,
                    lock,
                    lock_id,
                    original,
                },
            )));
        }
        Ok(session)
    }
    pub fn into_prepared_recovery_preflight_retaining(
        self,
    ) -> std::result::Result<NativeWalletRecoveryPreflight<'s, 'w>, Box<(SourceError, Self)>> {
        let checked = (|| {
            self.revalidate()?;
            let Layout::Ordinary {
                marker,
                temp: false,
                ..
            } = self.held().layout()?
            else {
                return Err(SourceError::TransitionPending);
            };
            let id = transition_id(&marker)?;
            let data = self.source.prepared_recovery_data(
                self.original.old_pin,
                id,
                self.wallet,
                &self.lock,
                self.lock_id,
            )?;
            checkpoint("original_preflight_before_move")?;
            Ok((id, data))
        })();
        let (transition_id, data) = match checked {
            Ok(v) => v,
            Err(error) => return Err(Box::new((error, self))),
        };
        let Self {
            source,
            wallet,
            lock,
            lock_id,
            original,
        } = self;
        let p = NativeWalletRecoveryPreflight {
            source,
            wallet,
            lock,
            lock_id,
            pin: original.old_pin,
            transition_id,
            data,
            original_selection: Some(original),
        };
        let checked = (|| {
            checkpoint("original_preflight_constructed")?;
            p.revalidate()
        })();
        if let Err(error) = checked {
            let NativeWalletRecoveryPreflight {
                source,
                wallet,
                lock,
                lock_id,
                original_selection,
                ..
            } = p;
            let original = original_selection
                .expect("original-only local construction retains immutable selection");
            return Err(Box::new((
                error,
                Self {
                    source,
                    wallet,
                    lock,
                    lock_id,
                    original,
                },
            )));
        }
        Ok(p)
    }
    pub fn into_temp_discard_retaining(
        self,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> std::result::Result<NativeOriginalTempDiscardSession<'s, 'w>, Box<(SourceError, Self)>>
    {
        if let Err(error) = (|| {
            self.held().full(&view, true)?;
            checkpoint("original_temp_before_move")
        })() {
            return Err(Box::new((error, self)));
        }
        let owner = NativeOriginalTempDiscardSession { inspection: self };
        if let Err(error) = (|| {
            checkpoint("original_temp_constructed")?;
            owner.inspection.held().full(&view, true).map(|_| ())
        })() {
            return Err(Box::new((error, owner.inspection)));
        }
        Ok(owner)
    }
    pub fn into_completed_cleanup_retaining(
        self,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> std::result::Result<NativeOriginalCompletedCleanupSession<'s, 'w>, Box<(SourceError, Self)>>
    {
        if let Err(error) = (|| {
            self.held().completed(&view)?;
            checkpoint("original_cleanup_before_move")
        })() {
            return Err(Box::new((error, self)));
        }
        let owner = NativeOriginalCompletedCleanupSession { inspection: self };
        if let Err(error) = (|| {
            checkpoint("original_cleanup_constructed")?;
            owner.inspection.held().completed(&view).map(|_| ())
        })() {
            return Err(Box::new((error, owner.inspection)));
        }
        Ok(owner)
    }
    pub fn into_terminal_observer_retaining(
        self,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> std::result::Result<NativeOriginalTerminalSession<'s, 'w>, Box<(SourceError, Self)>> {
        if let Err(error) = (|| {
            self.held().terminal(&view)?;
            checkpoint("original_terminal_before_move")
        })() {
            return Err(Box::new((error, self)));
        }
        let owner = NativeOriginalTerminalSession { inspection: self };
        if let Err(error) = (|| {
            checkpoint("original_terminal_constructed")?;
            owner.inspection.held().terminal(&view).map(|_| ())
        })() {
            return Err(Box::new((error, owner.inspection)));
        }
        Ok(owner)
    }
}
/// Only fixed-temp deletion; an explicit later interval must re-enter ORIGINAL
/// selection. Its candidate ID is never a predeclared strict-ID receipt.
pub struct NativeOriginalTempDiscardSession<'s, 'w> {
    pub(super) inspection: NativeOriginalTransitionInspection<'s, 'w>,
}
impl NativeOriginalTempDiscardSession<'_, '_> {
    pub fn original_wallet_data(&self) -> OriginalWalletSelectionData<'_> {
        self.inspection.original_wallet_data()
    }
    pub fn discard_temp(
        &mut self,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<UncommittedTransitionTempDiscard> {
        let h = self.inspection.held();
        let (marker, actual, exact) = h.full(&view, true)?;
        let temp = open_at(h.source.files.root(), TEMP, libc::O_RDONLY)?;
        safe(&temp, IMAGE)?;
        let temp_id = identity_metadata(&temp.metadata().map_err(io_error)?);
        let marker_file = open_at(h.source.files.root(), MARKER, libc::O_RDONLY)?;
        safe(&marker_file, RECORD)?;
        let marker_id = identity_metadata(&marker_file.metadata().map_err(io_error)?);
        h.full(&view, true)?;
        h.wallet.inspect_transition(&view)?.equal(&actual)?;
        let fresh = open_at(h.source.files.root(), TEMP, libc::O_RDONLY)?;
        safe(&fresh, IMAGE)?;
        let marker_fresh = open_at(h.source.files.root(), MARKER, libc::O_RDONLY)?;
        safe(&marker_fresh, RECORD)?;
        if identity_metadata(&fresh.metadata().map_err(io_error)?) != temp_id
            || identity_metadata(&marker_fresh.metadata().map_err(io_error)?) != marker_id
            || h.source.files.read(MARKER, false)? != exact
        {
            return Err(SourceError::Changed);
        }
        close(fresh)?;
        close(marker_fresh)?;
        close(marker_file)?;
        close(temp)?;
        h.roots()?;
        checkpoint("original_before_temp_unlink")?;
        unlink(h.source.files.root(), TEMP, false)?;
        let (_, after, after_exact) = h.full(&view, false)?;
        after.equal(&actual)?;
        if after_exact != exact {
            return Err(SourceError::Changed);
        }
        Ok(UncommittedTransitionTempDiscard {
            transition_id: transition_id(&marker)?,
        })
    }
}
/// Only completed bookkeeping cleanup/terminal observation; no reconciliation.
pub struct NativeOriginalCompletedCleanupSession<'s, 'w> {
    pub(super) inspection: NativeOriginalTransitionInspection<'s, 'w>,
}
impl NativeOriginalCompletedCleanupSession<'_, '_> {
    pub fn original_wallet_data(&self) -> OriginalWalletSelectionData<'_> {
        self.inspection.original_wallet_data()
    }
    pub fn cleanup(
        &mut self,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<CompletedWalletTransitionCleanup> {
        cleanup_original_held(
            self.inspection.source,
            self.inspection.wallet,
            &self.inspection.lock,
            self.inspection.lock_id,
            &self.inspection.original,
            &view,
        )
    }
    pub fn observe_terminal(
        &self,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<OriginalTerminalSourceData> {
        self.inspection.held().terminal(&view)
    }
}
pub(super) fn cleanup_original_held(
    source: &OwnerPublicationSource,
    wallet: &WalletCurrentSource,
    lock: &File,
    lock_id: (u64, u64),
    original: &OriginalTransitionSelection,
    view: &BorrowedPublicServiceObservation<'_, '_>,
) -> Result<CompletedWalletTransitionCleanup> {
    let h = HeldOriginal {
        source,
        wallet,
        lock,
        lock_id,
        original,
    };
    let (marker, exact, current, pin) = h.completed(view)?;
    let witness = source.confirm_tombstone(&exact, lock)?;
    let names = source.remaining_completed_records(
        &marker,
        &source.files.read(CURRENT, false)?,
        &current,
    )?;
    if list(source.files.root(), 5)?.iter().any(|n| n == RECORDS) {
        let d = source.files.records()?;
        for n in &names {
            source.revalidate_tombstone(&exact, &witness)?;
            h.completed(view)?;
            wallet.inspect_transition(view)?.equal(&current)?;
            checkpoint(&format!("before_record_unlink:{n}"))?;
            unlink(&d, n, false)?;
            checkpoint(&format!("record_unlinked:{n}"))?;
            h.completed(view)?;
        }
        source.revalidate_tombstone(&exact, &witness)?;
        h.completed(view)?;
        sync(&d)?;
        checkpoint("records_synced")?;
        h.completed(view)?;
        close(d)?;
        checkpoint("records_closed")?;
        h.completed(view)?;
        source.revalidate_tombstone(&exact, &witness)?;
        unlink(source.files.root(), RECORDS, true)?;
        checkpoint("records_removed")?;
        h.completed(view)?;
    }
    source.revalidate_tombstone(&exact, &witness)?;
    h.completed(view)?;
    wallet.inspect_transition(view)?.equal(&current)?;
    source.finish_tombstone(&exact, &witness, pin, &current, wallet, view)?;
    let terminal = h.terminal(view)?;
    if terminal.disposition != OriginalTerminalDisposition::DerivedNewSource
        || terminal.native_sha256 != pin.sha256
    {
        return Err(SourceError::Changed);
    }
    Ok(CompletedWalletTransitionCleanup {
        transition_id: transition_id(&marker)?,
        removed_records: names.len(),
    })
}
/// Read-only terminal source observation. No ID or acknowledged success exists.
pub struct NativeOriginalTerminalSession<'s, 'w> {
    pub(super) inspection: NativeOriginalTransitionInspection<'s, 'w>,
}
impl NativeOriginalTerminalSession<'_, '_> {
    pub fn original_wallet_data(&self) -> OriginalWalletSelectionData<'_> {
        self.inspection.original_wallet_data()
    }
    pub fn observe(
        &self,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<OriginalTerminalSourceData> {
        self.inspection.held().terminal(&view)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginalTerminalDisposition {
    OldSourceUnchanged,
    DerivedNewSource,
}
/// Bookkeeping DATA only. It is not a live pin update or an authority lease.
pub struct OriginalTerminalSourceData {
    disposition: OriginalTerminalDisposition,
    native_generation: u64,
    native_sha256: [u8; 32],
    wallet_reference: Vec<u8>,
    wallet_startup: Vec<u8>,
}
impl OriginalTerminalSourceData {
    pub fn disposition(&self) -> OriginalTerminalDisposition {
        self.disposition
    }
    pub fn native_generation(&self) -> u64 {
        self.native_generation
    }
    pub fn native_sha256(&self) -> [u8; 32] {
        self.native_sha256
    }
    pub fn wallet_reference_bytes(&self) -> &[u8] {
        &self.wallet_reference
    }
    pub fn wallet_startup_pin_bytes(&self) -> &[u8] {
        &self.wallet_startup
    }
}
