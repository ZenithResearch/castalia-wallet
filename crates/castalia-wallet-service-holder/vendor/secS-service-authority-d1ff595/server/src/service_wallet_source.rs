//! Actual metadata-only Wallet observation under the immutable shared filesystem
//! package's OS lease. Public metadata establishes source provenance, never
//! secret health, caller authentication, signing authority or installed admission.
use crate::service_authority_snapshot::{
    canonical, strict_value, validate_unqualified_policy_body,
};
use crate::service_wallet_contract::{StartupPin, WalletReference, WalletState};
use castalia_wallet_private_files::service_store::{
    BorrowedPublicServiceObservation, Identity, PublicServiceMetadata,
    PublicServiceObservationLease, ServiceRoot,
};
use libsec_core::service_holder_proof::{ServiceApplication, MAX_SAFE_TIME};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    Invalid,
    UnsafeStorage,
    Busy,
    Changed,
    Clock,
    Inactive,
    Window,
    TransitionPending,
    Capacity,
    PublicationUncertain,
    NoUnpreparedTransition,
}
pub(crate) type Result<T> = std::result::Result<T, SourceError>;
pub(crate) fn io_error(e: io::Error) -> SourceError {
    if e.kind() == io::ErrorKind::WouldBlock {
        SourceError::Busy
    } else {
        SourceError::UnsafeStorage
    }
}
pub(crate) fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
pub(crate) fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
#[cfg(test)]
pub(crate) fn digest(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SourceError::Invalid);
    }
    let mut out = [0; 32];
    for (i, v) in out.iter_mut().enumerate() {
        *v = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| SourceError::Invalid)?;
    }
    Ok(out)
}
fn closed(v: &Value, names: &[&str]) -> Result<()> {
    let m = v.as_object().ok_or(SourceError::Invalid)?;
    if m.len() != names.len() || names.iter().any(|n| !m.contains_key(*n)) {
        return Err(SourceError::Invalid);
    }
    Ok(())
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T> {
    let v = strict_value(raw).map_err(|_| SourceError::Invalid)?;
    if canonical(&v) != raw {
        return Err(SourceError::Invalid);
    }
    let t: T = serde_json::from_value(v).map_err(|_| SourceError::Invalid)?;
    if canonical(&serde_json::to_value(&t).map_err(|_| SourceError::Invalid)?) != raw {
        return Err(SourceError::Invalid);
    }
    Ok(t)
}
fn lower(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Owner-selected safe root; selection belongs to startup configuration.
/// It cannot be deserialized from a request or proof.
pub struct OwnerSelectedWalletRoot {
    root: ServiceRoot,
    identity: Identity,
}
impl OwnerSelectedWalletRoot {
    pub fn open(path: &Path) -> Result<Self> {
        let root = ServiceRoot::open(path).map_err(io_error)?;
        let m = std::fs::symlink_metadata(path).map_err(io_error)?;
        Ok(Self {
            root,
            identity: Identity {
                device: m.dev(),
                inode: m.ino(),
            },
        })
    }
}
/// Independent exact startup reference and minimum anchors. Parsed pins are
/// configuration data; only a capture of the selected real source makes a lease.
pub struct StartupWalletObservationPin {
    pin: StartupPin,
}
impl StartupWalletObservationPin {
    pub fn parse_owner_configuration(raw: &[u8]) -> Result<Self> {
        Ok(Self {
            pin: StartupPin::parse(raw).map_err(|_| SourceError::Invalid)?,
        })
    }
}
type Floor = Arc<Mutex<u64>>;
type Floors = Mutex<BTreeMap<(u64, u64), Weak<Mutex<u64>>>>;
fn floor_for(i: Identity) -> Result<Floor> {
    static F: OnceLock<Floors> = OnceLock::new();
    let mut all = F
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| SourceError::Clock)?;
    all.retain(|_, v| v.strong_count() > 0);
    let k = (i.device, i.inode);
    if let Some(v) = all.get(&k).and_then(Weak::upgrade) {
        return Ok(v);
    }
    if all.len() >= 128 {
        return Err(SourceError::UnsafeStorage);
    }
    let f = Arc::new(Mutex::new(0));
    all.insert(k, Arc::downgrade(&f));
    Ok(f)
}
pub(crate) fn now() -> Result<u64> {
    #[cfg(test)]
    if let Some(n) = TEST_NOW.with(|v| v.get()) {
        return if n > 0 && n <= MAX_SAFE_TIME {
            Ok(n)
        } else {
            Err(SourceError::Clock)
        };
    }
    static LAST: AtomicU64 = AtomicU64::new(0);
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SourceError::Clock)?
        .as_secs();
    if n == 0 || n > MAX_SAFE_TIME {
        return Err(SourceError::Clock);
    }
    LAST.fetch_update(Ordering::AcqRel, Ordering::Acquire, |p| {
        (n >= p).then_some(n)
    })
    .map_err(|_| SourceError::Clock)?;
    Ok(n)
}
pub(crate) fn observe(f: &Mutex<u64>, durable: u64) -> Result<u64> {
    let n = now()?;
    let mut prior = f.lock().map_err(|_| SourceError::Clock)?;
    if n < durable || n < *prior {
        return Err(SourceError::Clock);
    }
    *prior = n;
    Ok(n)
}
#[cfg(test)]
thread_local! {pub(crate) static TEST_NOW:std::cell::Cell<Option<u64>>=const{std::cell::Cell::new(None)};}

/// Safe source bound to independently selected root and exact startup pin.
pub struct WalletCurrentSource {
    root: OwnerSelectedWalletRoot,
    pin: StartupPin,
    floor: Floor,
}
impl WalletCurrentSource {
    pub fn open(root: OwnerSelectedWalletRoot, pin: StartupWalletObservationPin) -> Result<Self> {
        let floor = floor_for(root.identity)?;
        Ok(Self {
            root,
            pin: pin.pin,
            floor,
        })
    }
    #[cfg(test)]
    pub(crate) fn test_startup_pin_bytes(&self) -> Vec<u8> {
        canonical(&self.pin.value)
    }
    // Configuration facts only; these do not capture a current observation.
    pub(crate) fn configured_root_identity(&self) -> Identity {
        self.root.identity
    }
    pub(crate) fn configured_startup_pin_bytes(&self) -> Vec<u8> {
        canonical(&self.pin.value)
    }
    pub(crate) fn pin_reference(&self, r: &WalletReference) -> Result<()> {
        self.pin
            .compare_reference(r)
            .map_err(|_| SourceError::Changed)
    }
    fn inspect(&self, m: &PublicServiceMetadata, exact: bool) -> Result<ObservedWallet> {
        if m.root_identity() != self.root.identity {
            return Err(SourceError::Changed);
        }
        let o = ObservedWallet::read(m)?;
        if exact {
            self.pin
                .compare_reference(&o.reference)
                .map_err(|_| SourceError::Changed)?;
        } else {
            if self.pin.value["store_id"] != o.reference.value["store_id"]
                || o.revision()
                    < self.pin.value["minimum_state_revision"]
                        .as_u64()
                        .ok_or(SourceError::Invalid)?
                || o.generation()
                    < self.pin.value["minimum_key_generation"]
                        .as_u64()
                        .ok_or(SourceError::Invalid)?
            {
                return Err(SourceError::Changed);
            }
        }
        observe(&self.floor, o.durable)?;
        Ok(o)
    }
    pub fn capture_shared(&self) -> Result<WalletCurrentLease<'_>> {
        let lease = self.root.root.lock_public_shared().map_err(io_error)?;
        let observed = self.inspect(lease.metadata(), true)?;
        lease.revalidate().map_err(io_error)?;
        observe(&self.floor, observed.durable)?;
        Ok(WalletCurrentLease {
            source: self,
            lease,
            observed,
        })
    }
    /// Consumes the actual temporary view. Dropping this returned lease ends
    /// the immutable custody borrow, allowing mutation on the still-held session.
    pub fn capture_borrowed<'s, 'l, 'r>(
        &'s self,
        view: BorrowedPublicServiceObservation<'l, 'r>,
    ) -> Result<WalletBorrowedLease<'s, 'l, 'r>> {
        let observed = self.inspect(view.metadata(), true)?;
        view.revalidate().map_err(io_error)?;
        Ok(WalletBorrowedLease {
            source: self,
            view,
            observed,
        })
    }
    pub(crate) fn inspect_initial(
        &self,
        view: &BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<ObservedWallet> {
        view.revalidate().map_err(io_error)?;
        let o = self.inspect(view.metadata(), true)?;
        view.revalidate().map_err(io_error)?;
        Ok(o)
    }
    pub(crate) fn inspect_transition(
        &self,
        view: &BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<ObservedWallet> {
        view.revalidate().map_err(io_error)?;
        let o = self.inspect(view.metadata(), false)?;
        view.revalidate().map_err(io_error)?;
        observe(&self.floor, o.durable)?;
        Ok(o)
    }
}
/// Holds a real shared custody lock. No Clone, Deserialize or public constructor.
pub struct WalletCurrentLease<'s> {
    source: &'s WalletCurrentSource,
    lease: PublicServiceObservationLease<'s>,
    pub(crate) observed: ObservedWallet,
}
impl WalletCurrentLease<'_> {
    pub fn reference_bytes(&self) -> &[u8] {
        self.observed.reference.canonical_bytes()
    }
    pub fn reference_sha256(&self) -> [u8; 32] {
        self.observed.reference.reference_digest()
    }
    pub fn revalidate(&self) -> Result<()> {
        self.lease.revalidate().map_err(io_error)?;
        let o = self.source.inspect(self.lease.metadata(), true)?;
        self.observed.equal(&o)?;
        Ok(())
    }
    pub fn require_active_for_challenge(
        &self,
        issued_at: u64,
        expires_at: u64,
        owner: &crate::service_owner_publication::NativeOwnerCurrentLease<'_>,
    ) -> Result<()> {
        self.revalidate()?;
        self.observed.active_window(issued_at, expires_at)?;
        owner.require_wallet_window(&self.observed, issued_at, expires_at)?;
        self.revalidate()
    }
}
/// Temporary same-exclusive observation. It cannot outlive the real custody
/// session or overlap its mutable CLOCK/publication operations.
pub struct WalletBorrowedLease<'s, 'l, 'r> {
    source: &'s WalletCurrentSource,
    view: BorrowedPublicServiceObservation<'l, 'r>,
    pub(crate) observed: ObservedWallet,
}
impl WalletBorrowedLease<'_, '_, '_> {
    pub fn reference_bytes(&self) -> &[u8] {
        self.observed.reference.canonical_bytes()
    }
    pub fn revalidate(&self) -> Result<()> {
        self.view.revalidate().map_err(io_error)?;
        let o = self.source.inspect(self.view.metadata(), true)?;
        self.observed.equal(&o)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pointer {
    schema: String,
    store_id: String,
    state_revision: u64,
    state_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClockRecord {
    schema: String,
    store_id: String,
    observed_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateRecord {
    schema: String,
    pub(crate) store_id: String,
    pub(crate) subject_id: String,
    purpose: String,
    application: String,
    state_revision: u64,
    key_generation: u64,
    key_id: String,
    public_key_hex: String,
    public_key_sha256: String,
    state: String,
    pub(crate) created_at: u64,
    pub(crate) key_created_at: u64,
    pub(crate) published_at: u64,
    not_before: u64,
    not_after: u64,
    revoked_at: Option<u64>,
    pub(crate) previous_state_sha256: Option<String>,
    owner_input_sha256: Option<String>,
}
/// Internally derived only from an actual filesystem view. Retaining this value
/// alone does not retain a lock and is not execution authority.
pub(crate) struct ObservedWallet {
    pub(crate) reference: WalletReference,
    pub(crate) state: StateRecord,
    pub(crate) state_raw: Vec<u8>,
    pub(crate) durable: u64,
    pub(crate) root: Identity,
    pub(crate) lock: Identity,
    pub(crate) epoch: u64,
}
impl ObservedWallet {
    fn read(m: &PublicServiceMetadata) -> Result<Self> {
        let p: Pointer = decode(m.current_bytes())?;
        let s: StateRecord = decode(m.state_bytes())?;
        let c: ClockRecord = decode(m.clock_bytes())?;
        valid_state(&s)?;
        if p.schema != "castalia.wallet-service-custody-current.v1"
            || p.store_id != s.store_id
            || p.state_revision != s.state_revision
            || m.state_revision() != s.state_revision
            || p.state_sha256 != hex(&hash(m.state_bytes()))
            || c.schema != "castalia.wallet-service-custody-clock.v1"
            || c.store_id != s.store_id
            || c.observed_at < s.published_at
            || c.observed_at > MAX_SAFE_TIME
        {
            return Err(SourceError::Invalid);
        }
        let delegation = match (s.state.as_str(), m.owner_input_bytes()) {
            ("active", Some(raw)) => {
                if s.owner_input_sha256.as_deref() != Some(hex(&hash(raw)).as_str()) {
                    return Err(SourceError::Changed);
                }
                Some(validate_owner_input(raw, &s)?)
            }
            ("unconfigured" | "revoked", None) => None,
            _ => return Err(SourceError::Invalid),
        };
        let reference=WalletReference::from_value(json!({"schema":"secs.wallet-current-reference.v2","store_id":s.store_id,"subject_id":s.subject_id,"purpose":s.purpose,"application":s.application,"state_revision":s.state_revision,"key_generation":s.key_generation,"state":s.state,"current_sha256":hex(&hash(m.current_bytes())),"custody_state_sha256":hex(&hash(m.state_bytes())),"key_id":s.key_id,"public_key_hex":s.public_key_hex,"public_key_sha256":s.public_key_sha256,"not_before":s.not_before,"not_after":s.not_after,"revoked_at":s.revoked_at,"owner_input_sha256":s.owner_input_sha256,"delegation_policy_sha256":delegation.map(|h|hex(&h))})).map_err(|_|SourceError::Invalid)?;
        Ok(Self {
            reference,
            state: s,
            state_raw: m.state_bytes().to_vec(),
            durable: c.observed_at,
            root: m.root_identity(),
            lock: m.lock_identity(),
            epoch: m.epoch(),
        })
    }
    pub(crate) fn equal(&self, other: &Self) -> Result<()> {
        if self.reference.canonical_bytes() != other.reference.canonical_bytes()
            || self.root != other.root
            || self.lock != other.lock
            || self.epoch != other.epoch
        {
            return Err(SourceError::Changed);
        }
        Ok(())
    }
    pub(crate) fn configuration(&self, raw: &[u8]) -> Result<()> {
        if self.reference.state() == WalletState::Revoked {
            return Err(SourceError::Inactive);
        }
        let mut next = self.state.clone();
        next.state_revision = next
            .state_revision
            .checked_add(1)
            .filter(|n| *n <= MAX_SAFE_TIME)
            .ok_or(SourceError::Capacity)?;
        validate_owner_input(raw, &next).map(|_| ())
    }
    pub(crate) fn revision(&self) -> u64 {
        self.state.state_revision
    }
    pub(crate) fn generation(&self) -> u64 {
        self.state.key_generation
    }
    pub(crate) fn active_window(&self, issued: u64, expires: u64) -> Result<()> {
        if self.reference.state() != WalletState::Active {
            return Err(SourceError::Inactive);
        }
        let n = now()?;
        if issued == 0
            || issued >= expires
            || expires > MAX_SAFE_TIME
            || issued < self.state.not_before
            || expires > self.state.not_after
            || issued > n
            || n >= expires
            || n < self.durable
        {
            return Err(SourceError::Window);
        }
        Ok(())
    }
}

fn valid_state(s: &StateRecord) -> Result<()> {
    if s.schema != "castalia.wallet-service-custody-state.v1"
        || s.purpose != "secs-service-holder-proof.v1"
        || !lower(&s.store_id, 32)
        || !(1..=MAX_SAFE_TIME).contains(&s.state_revision)
        || !(1..=s.state_revision).contains(&s.key_generation)
        || s.created_at == 0
        || s.created_at > s.key_created_at
        || s.key_created_at > s.published_at
        || s.published_at > MAX_SAFE_TIME
        || (s.state_revision == 1) != s.previous_state_sha256.is_none()
        || s.previous_state_sha256
            .as_ref()
            .is_some_and(|v| !lower(v, 64))
        || s.owner_input_sha256.as_ref().is_some_and(|v| !lower(v, 64))
        || (s.state == "active") != s.owner_input_sha256.is_some()
        || (s.state == "revoked") != s.revoked_at.is_some()
        || s.revoked_at.is_some_and(|v| v != s.published_at)
    {
        return Err(SourceError::Invalid);
    }
    Ok(())
}
/// Strict retained data only. This creates no current-source/lease capability.
pub(crate) fn retained_state(raw: &[u8], reference: &WalletReference) -> Result<StateRecord> {
    if raw.is_empty()
        || raw.len() > 4096
        || reference.value["custody_state_sha256"] != hex(&hash(raw))
    {
        return Err(SourceError::Changed);
    }
    let s: StateRecord = decode(raw)?;
    valid_state(&s)?;
    let value = serde_json::to_value(&s).map_err(|_| SourceError::Invalid)?;
    for n in [
        "store_id",
        "subject_id",
        "purpose",
        "application",
        "state_revision",
        "key_generation",
        "state",
        "key_id",
        "public_key_hex",
        "public_key_sha256",
        "not_before",
        "not_after",
        "revoked_at",
        "owner_input_sha256",
    ] {
        if value[n] != reference.value[n] {
            return Err(SourceError::Changed);
        }
    }
    Ok(s)
}
// Validate the actual public Wallet input using the same full native registry,
// descriptor, permission and receiver constructors. The transformation below is
// only parser reuse; it creates no native publication, grants or provenance.
pub(crate) fn validate_owner_input(raw: &[u8], s: &StateRecord) -> Result<[u8; 32]> {
    validate_bound_owner_input(
        raw,
        OwnerInputBinding {
            application: &s.application,
            subject_id: &s.subject_id,
            key_id: &s.key_id,
            public_key_hex: &s.public_key_hex,
            state_revision: s.state_revision,
            key_generation: s.key_generation,
            not_before: s.not_before,
            not_after: s.not_after,
        },
    )
}
// Pure expected input facts; no source/lease or qualification is constructed.
struct OwnerInputBinding<'a> {
    application: &'a str,
    subject_id: &'a str,
    key_id: &'a str,
    public_key_hex: &'a str,
    state_revision: u64,
    key_generation: u64,
    not_before: u64,
    not_after: u64,
}
pub(crate) fn validate_transition_request(raw: &[u8], old: &WalletReference) -> Result<[u8; 32]> {
    let v = &old.value;
    let text = |n: &str| v[n].as_str().ok_or(SourceError::Invalid);
    let uint = |n: &str| v[n].as_u64().ok_or(SourceError::Invalid);
    validate_bound_owner_input(
        raw,
        OwnerInputBinding {
            application: text("application")?,
            subject_id: text("subject_id")?,
            key_id: text("key_id")?,
            public_key_hex: text("public_key_hex")?,
            state_revision: uint("state_revision")?
                .checked_add(1)
                .filter(|n| *n <= MAX_SAFE_TIME)
                .ok_or(SourceError::Capacity)?,
            key_generation: uint("key_generation")?,
            not_before: uint("not_before")?,
            not_after: uint("not_after")?,
        },
    )
}
fn validate_bound_owner_input(raw: &[u8], s: OwnerInputBinding<'_>) -> Result<[u8; 32]> {
    let v = strict_value(raw).map_err(|_| SourceError::Invalid)?;
    fn strings(v: &Value) -> bool {
        match v {
            Value::String(s) => s.len() <= 1024,
            Value::Array(a) => a.iter().all(strings),
            Value::Object(m) => m.values().all(strings),
            _ => true,
        }
    }
    if !strings(&v) {
        return Err(SourceError::Invalid);
    }
    closed(
        &v,
        &[
            "schema",
            "generation",
            "valid_not_before",
            "valid_until",
            "application",
            "issuer_node_id",
            "selected_issuer_key_id",
            "issuers",
            "holder",
            "descriptors",
            "delegation_policy",
        ],
    )?;
    if v["schema"] != "castalia.wallet-service-owner-input.v1"
        || v["generation"] != s.state_revision
        || v["application"] != s.application
        || v["valid_not_before"]
            .as_u64()
            .is_none_or(|n| n > s.not_before)
        || v["valid_until"].as_u64().is_none_or(|n| n < s.not_after)
    {
        return Err(SourceError::Changed);
    }
    let h = &v["holder"];
    closed(
        h,
        &[
            "subject_id",
            "generation",
            "key_id",
            "public_key_hex",
            "algorithm",
            "status",
            "not_before",
            "not_after",
            "revoked_at",
            "replaced_by",
        ],
    )?;
    if h["subject_id"] != s.subject_id
        || h["generation"] != s.key_generation
        || h["key_id"] != s.key_id
        || h["public_key_hex"] != s.public_key_hex
        || h["not_before"] != s.not_before
        || h["not_after"] != s.not_after
        || h["status"] != "active"
        || !h["revoked_at"].is_null()
        || !h["replaced_by"].is_null()
    {
        return Err(SourceError::Changed);
    }
    let mut body = serde_json::Map::new();
    for n in [
        "valid_not_before",
        "valid_until",
        "application",
        "issuer_node_id",
        "selected_issuer_key_id",
        "descriptors",
    ] {
        body.insert(n.into(), v[n].clone());
    }
    let mut issuers = v["issuers"].as_array().ok_or(SourceError::Invalid)?.clone();
    for i in &mut issuers {
        closed(
            i,
            &[
                "node_id",
                "key_id",
                "public_key_hex",
                "algorithm",
                "status",
                "not_before",
                "not_after",
                "revoked_at",
                "replaced_by",
            ],
        )?;
        i.as_object_mut()
            .ok_or(SourceError::Invalid)?
            .insert("production_authority".into(), json!(false));
    }
    let mut holder = h.clone();
    let hm = holder.as_object_mut().ok_or(SourceError::Invalid)?;
    hm.remove("generation");
    hm.remove("replaced_by");
    body.insert("issuers".into(), json!(issuers));
    body.insert("holders".into(), json!([holder]));
    body.insert("permissions".into(), json!([]));
    body.insert("receiver_policy".into(), v["delegation_policy"].clone());
    validate_unqualified_policy_body(Value::Object(body), false)
        .map_err(|_| SourceError::Invalid)?;
    let policy = &v["delegation_policy"];
    let application = match s.application {
        "runtime" => ServiceApplication::RuntimeV1,
        "service" => ServiceApplication::ServiceV1,
        _ => return Err(SourceError::Invalid),
    };
    if policy["application"] != s.application || policy["audience"] != application.audience() {
        return Err(SourceError::Invalid);
    }
    let descriptors = v["descriptors"].as_array().ok_or(SourceError::Invalid)?;
    let pd = policy["descriptors"]
        .as_array()
        .ok_or(SourceError::Invalid)?;
    if descriptors.len() != pd.len() {
        return Err(SourceError::Invalid);
    }
    for d in descriptors {
        if [
            "required_credentials",
            "required_capabilities",
            "accepted_evidence",
        ]
        .iter()
        .any(|n| d[*n].as_array().is_none_or(|a| !a.is_empty()))
            || !d["required_authority_mode"].is_null()
        {
            return Err(SourceError::Invalid);
        }
        crate::service_authority_snapshot::validate_descriptor_binding(d, pd)
            .map_err(|_| SourceError::Invalid)?;
    }
    Ok(hash(&canonical(policy)))
}
#[cfg(test)]
#[path = "service_wallet_source_tests.rs"]
pub(crate) mod tests;
