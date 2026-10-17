//! Owner-only service custody, separate from Member Key/encrypted recovery custody.
//! Private files and advisory locks coordinate cooperative owner processes. This is
//! not protection against the owning UID, restored backups, or a qualified issuer.
use crate::{
    ascii, canonical, hash, hex, hex32, strict_json, ValidatedWalletOwnerInput, MAX_SAFE_TIME,
};
use castalia_wallet_private_files::service_store::{
    BorrowedPublicServiceObservation, Identity, PublicServiceMetadata, ServiceFile, ServiceLease,
    ServiceRoot, StagingFile,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
const PURPOSE: &str = "secs-service-holder-proof.v1";
const STATE: &str = "castalia.wallet-service-custody-state.v1";
const CURRENT: &str = "castalia.wallet-service-custody-current.v1";
const CLOCK: &str = "castalia.wallet-service-custody-clock.v1";
type Result<T> = std::result::Result<T, CustodyError>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyError {
    InvalidInput,
    UnsafeStorage,
    MissingStore,
    AlreadyExists,
    Busy,
    Unconfigured,
    Revoked,
    Expired,
    Changed,
    KeyMismatch,
    Corrupt,
    Clock,
    Capacity,
    PublicationUncertain,
    UnsupportedRequiredEvidence,
}
impl From<io::Error> for CustodyError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::NotFound => Self::MissingStore,
            io::ErrorKind::AlreadyExists => Self::AlreadyExists,
            io::ErrorKind::WouldBlock => Self::Busy,
            _ => Self::UnsafeStorage,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Application {
    Runtime,
    Service,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityState {
    Unconfigured,
    Active,
    Revoked,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewServiceIdentity {
    pub application: Application,
    pub subject_id: String,
    pub not_before: u64,
    pub not_after: u64,
}
impl NewServiceIdentity {
    fn validate(&self) -> Result<()> {
        if !ascii(&self.subject_id, 128)
            || self.not_before >= self.not_after
            || self.not_after > MAX_SAFE_TIME
        {
            return Err(CustodyError::InvalidInput);
        }
        Ok(())
    }
}
/// Public startup pin, never an authority attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreBinding {
    pub store_id: String,
    pub subject_id: String,
    pub application: Application,
    pub purpose: String,
    pub minimum_revision: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedState {
    pub state_revision: u64,
    pub state_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicServiceIdentity {
    pub schema: String,
    pub store_id: String,
    pub subject_id: String,
    pub purpose: String,
    pub application: Application,
    pub state_revision: u64,
    pub key_generation: u64,
    pub key_id: String,
    pub public_key_hex: String,
    pub public_key_sha256: String,
    pub state: IdentityState,
    pub created_at: u64,
    pub key_created_at: u64,
    pub published_at: u64,
    pub not_before: u64,
    pub not_after: u64,
    pub revoked_at: Option<u64>,
    pub previous_state_sha256: Option<String>,
    pub owner_input_sha256: Option<String>,
}
impl PublicServiceIdentity {
    pub fn expected(&self) -> ExpectedState {
        ExpectedState {
            state_revision: self.state_revision,
            state_sha256: hex(&hash(&encode(self))),
        }
    }
    pub fn binding(&self) -> StoreBinding {
        StoreBinding {
            store_id: self.store_id.clone(),
            subject_id: self.subject_id.clone(),
            application: self.application,
            purpose: self.purpose.clone(),
            minimum_revision: self.state_revision,
        }
    }
    fn valid(&self) -> Result<()> {
        if self.schema != STATE
            || self.purpose != PURPOSE
            || !lower_hex(&self.store_id, 32)
            || !ascii(&self.subject_id, 128)
            || !(1..=MAX_SAFE_TIME).contains(&self.state_revision)
            || !(1..=self.state_revision).contains(&self.key_generation)
            || self.not_before >= self.not_after
            || self.not_after > MAX_SAFE_TIME
            || self.created_at == 0
            || self.created_at > self.key_created_at
            || self.key_created_at > self.published_at
            || self.published_at > MAX_SAFE_TIME
            || (self.state_revision == 1) != self.previous_state_sha256.is_none()
            || self
                .previous_state_sha256
                .as_ref()
                .is_some_and(|s| !lower_hex(s, 64))
            || self
                .owner_input_sha256
                .as_ref()
                .is_some_and(|s| !lower_hex(s, 64))
            || (self.state == IdentityState::Active) != self.owner_input_sha256.is_some()
            || (self.state == IdentityState::Revoked) != self.revoked_at.is_some()
            || self.revoked_at.is_some_and(|v| v != self.published_at)
        {
            return Err(CustodyError::Corrupt);
        }
        let key = VerifyingKey::from_bytes(
            &hex32(&self.public_key_hex).map_err(|_| CustodyError::Corrupt)?,
        )
        .map_err(|_| CustodyError::Corrupt)?;
        if key.is_weak()
            || self.public_key_sha256 != hex(&hash(key.as_bytes()))
            || self.key_id != format!("service-ed25519:sha256:{}", self.public_key_sha256)
        {
            return Err(CustodyError::KeyMismatch);
        }
        Ok(())
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
struct Clock {
    schema: String,
    store_id: String,
    observed_at: u64,
}
fn lower_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    canonical(&serde_json::to_value(v).expect("closed public metadata"))
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(raw: &[u8]) -> Result<T> {
    let v = strict_json(raw).map_err(|_| CustodyError::Corrupt)?;
    if canonical(&v) != raw {
        return Err(CustodyError::Corrupt);
    }
    let parsed: T = serde_json::from_value(v).map_err(|_| CustodyError::Corrupt)?;
    // Also rejects omitted nullable fields accepted by serde's Option default.
    if encode(&parsed) != raw {
        return Err(CustodyError::Corrupt);
    }
    Ok(parsed)
}
type Floor = Arc<Mutex<u64>>;
type Floors = Mutex<BTreeMap<(u64, u64), Weak<Mutex<u64>>>>;
fn floor_for(i: Identity) -> Result<Floor> {
    static FLOORS: OnceLock<Floors> = OnceLock::new();
    let mut all = FLOORS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| CustodyError::Clock)?;
    all.retain(|_, v| v.strong_count() > 0);
    let k = (i.device, i.inode);
    if let Some(v) = all.get(&k).and_then(Weak::upgrade) {
        return Ok(v);
    }
    if all.len() >= 128 {
        return Err(CustodyError::Capacity);
    }
    let f = Arc::new(Mutex::new(0));
    all.insert(k, Arc::downgrade(&f));
    Ok(f)
}
pub(super) fn monotonic_clock(last: &AtomicU64, n: u64) -> Result<u64> {
    if n == 0 || n > MAX_SAFE_TIME {
        return Err(CustodyError::Clock);
    }
    last.fetch_update(Ordering::AcqRel, Ordering::Acquire, |prior| {
        (n >= prior).then_some(n)
    })
    .map_err(|_| CustodyError::Clock)?;
    Ok(n)
}
fn now() -> Result<u64> {
    #[cfg(test)]
    if let Some(n) = TEST_NOW.with(|v| v.get()) {
        return if n > 0 && n <= MAX_SAFE_TIME {
            Ok(n)
        } else {
            Err(CustodyError::Clock)
        };
    }
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CustodyError::Clock)?
        .as_secs();
    // Retain actual native observations even after the last store handle closes.
    static NATIVE_OBSERVED: AtomicU64 = AtomicU64::new(0);
    monotonic_clock(&NATIVE_OBSERVED, n)
}
fn observe(f: &Floor, durable: u64) -> Result<u64> {
    let n = now()?;
    let mut prior = f.lock().map_err(|_| CustodyError::Clock)?;
    if n < durable || n < *prior {
        return Err(CustodyError::Clock);
    }
    *prior = n;
    Ok(n)
}
fn live(s: &PublicServiceIdentity, n: u64) -> Result<()> {
    if s.state == IdentityState::Revoked {
        return Err(CustodyError::Revoked);
    }
    if n < s.not_before || n >= s.not_after {
        return Err(CustodyError::Expired);
    }
    Ok(())
}
fn seed() -> Result<Zeroizing<[u8; 32]>> {
    let mut s = Zeroizing::new([0; 32]);
    getrandom::getrandom(s.as_mut()).map_err(|_| CustodyError::UnsafeStorage)?;
    Ok(s)
}
fn set_key(s: &mut PublicServiceIdentity, raw: &[u8; 32]) {
    let key = SigningKey::from_bytes(raw);
    s.public_key_hex = hex(key.verifying_key().as_bytes());
    s.public_key_sha256 = hex(&hash(key.verifying_key().as_bytes()));
    s.key_id = format!("service-ed25519:sha256:{}", s.public_key_sha256);
}
fn owner_matches(raw: &[u8], s: &PublicServiceIdentity) -> Result<()> {
    let o = ValidatedWalletOwnerInput::parse(raw).map_err(|_| CustodyError::InvalidInput)?;
    let v = strict_json(raw).map_err(|_| CustodyError::InvalidInput)?;
    let app = match s.application {
        Application::Runtime => libsec_core::service_holder_proof::ServiceApplication::RuntimeV1,
        Application::Service => libsec_core::service_holder_proof::ServiceApplication::ServiceV1,
    };
    if o.application != app
        || v["generation"].as_u64() != Some(s.state_revision)
        || o.holder.subject != s.subject_id
        || o.holder.generation != s.key_generation
        || o.holder.key.id != s.key_id
        || hex(o.holder.key.public.as_bytes()) != s.public_key_hex
        || o.holder.key.start != s.not_before
        || o.holder.key.end != s.not_after
        || o.holder.key.status != "active"
        || o.holder.key.revoked.is_some()
        || o.holder.key.replaced.is_some()
    {
        return Err(CustodyError::KeyMismatch);
    }
    // Obligation presence is never inferred from the receiver's reduced policy.
    if o.descriptors.values().any(|d| {
        !d.required_credentials.is_empty()
            || !d.required_capabilities.is_empty()
            || !d.accepted_evidence.is_empty()
            || d.required_authority_mode.is_some()
    }) {
        return Err(CustodyError::UnsupportedRequiredEvidence);
    }
    if o.start > s.not_before || o.end < s.not_after {
        return Err(CustodyError::InvalidInput);
    }
    Ok(())
}
struct Loaded {
    state: PublicServiceIdentity,
    seed: Option<Zeroizing<[u8; 32]>>,
    _owner: Option<Zeroizing<Vec<u8>>>,
    durable: u64,
}
fn absent(l: &ServiceLease<'_>, f: ServiceFile) -> Result<()> {
    match l.read(f) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(CustodyError::Corrupt),
    }
}
fn load(l: &ServiceLease<'_>, binding: Option<&StoreBinding>) -> Result<Loaded> {
    let raw = l.read(ServiceFile::Current)?;
    let p: Pointer = decode(&raw)?;
    if p.schema != CURRENT
        || !lower_hex(&p.store_id, 32)
        || !(1..=MAX_SAFE_TIME).contains(&p.state_revision)
        || !lower_hex(&p.state_sha256, 64)
    {
        return Err(CustodyError::Corrupt);
    }
    let state_raw = l.read(ServiceFile::State(p.state_revision))?;
    if hex(&hash(&state_raw)) != p.state_sha256 {
        return Err(CustodyError::Corrupt);
    }
    let state: PublicServiceIdentity = decode(&state_raw)?;
    state.valid()?;
    if state.store_id != p.store_id || state.state_revision != p.state_revision {
        return Err(CustodyError::Corrupt);
    }
    if let Some(b) = binding {
        if b.store_id != state.store_id
            || b.subject_id != state.subject_id
            || b.purpose != state.purpose
            || b.application != state.application
            || b.minimum_revision == 0
            || b.minimum_revision > state.state_revision
        {
            return Err(CustodyError::Changed);
        }
    }
    let c: Clock = decode(&l.read(ServiceFile::Clock)?)?;
    if c.schema != CLOCK
        || c.store_id != state.store_id
        || c.observed_at < state.published_at
        || c.observed_at > MAX_SAFE_TIME
    {
        return Err(CustodyError::Clock);
    }
    let seed = if state.state == IdentityState::Revoked {
        absent(l, ServiceFile::Seed(p.state_revision))?;
        None
    } else {
        let raw = l.read(ServiceFile::Seed(p.state_revision))?;
        let mut s = Zeroizing::new([0; 32]);
        if raw.len() != 32 {
            return Err(CustodyError::KeyMismatch);
        }
        s.copy_from_slice(&raw);
        if hex(SigningKey::from_bytes(&s).verifying_key().as_bytes()) != state.public_key_hex {
            return Err(CustodyError::KeyMismatch);
        }
        Some(s)
    };
    let owner = if state.state == IdentityState::Active {
        let raw = l.read(ServiceFile::OwnerInput(p.state_revision))?;
        if Some(hex(&hash(&raw))) != state.owner_input_sha256 {
            return Err(CustodyError::Corrupt);
        }
        owner_matches(&raw, &state)?;
        Some(raw)
    } else {
        absent(l, ServiceFile::OwnerInput(p.state_revision))?;
        None
    };
    l.revalidate()?;
    checkpoint("after_load")?;
    Ok(Loaded {
        state,
        seed,
        _owner: owner,
        durable: c.observed_at,
    })
}
// Validate only the actual public observation. Never open/read seed material
// through a metadata view; ordinary custody load/presentation checks it itself.
fn observed_public_state(
    m: &PublicServiceMetadata,
    b: &StoreBinding,
) -> Result<(PublicServiceIdentity, u64)> {
    let p: Pointer = decode(m.current_bytes())?;
    let s: PublicServiceIdentity = decode(m.state_bytes())?;
    s.valid()?;
    if p.schema != CURRENT
        || p.store_id != s.store_id
        || p.state_revision != s.state_revision
        || m.state_revision() != s.state_revision
        || p.state_sha256 != hex(&hash(m.state_bytes()))
    {
        return Err(CustodyError::Corrupt);
    }
    if b.store_id != s.store_id
        || b.subject_id != s.subject_id
        || b.purpose != s.purpose
        || b.application != s.application
        || b.minimum_revision == 0
        || b.minimum_revision > s.state_revision
    {
        return Err(CustodyError::Changed);
    }
    let c: Clock = decode(m.clock_bytes())?;
    if c.schema != CLOCK
        || c.store_id != s.store_id
        || c.observed_at < s.published_at
        || c.observed_at > MAX_SAFE_TIME
    {
        return Err(CustodyError::Clock);
    }
    match (s.state, m.owner_input_bytes()) {
        (IdentityState::Active, Some(raw)) => {
            if s.owner_input_sha256 != Some(hex(&hash(raw))) {
                return Err(CustodyError::Corrupt);
            }
            owner_matches(raw, &s)?;
        }
        (IdentityState::Unconfigured | IdentityState::Revoked, None) => {}
        _ => return Err(CustodyError::Corrupt),
    }
    Ok((s, c.observed_at))
}
fn cas(s: &PublicServiceIdentity, e: &ExpectedState) -> Result<()> {
    if &s.expected() != e {
        return Err(CustodyError::Changed);
    }
    Ok(())
}
fn clean_for_write(l: &ServiceLease<'_>, r: u64) -> Result<()> {
    let i = l.inspect_bounded()?;
    if i.staging
        || i.revisions != [r]
        || i.root_entries
            .iter()
            .any(|s| s == ".CURRENT.tmp" || s == ".CLOCK.tmp" || s == "RESET")
    {
        return Err(CustodyError::Capacity);
    }
    Ok(())
}
fn check_prior(l: &ServiceLease<'_>, s: &PublicServiceIdentity, create: bool) -> Result<()> {
    if create {
        return absent(l, ServiceFile::Current);
    }
    let prior = load(l, None)?;
    cas(
        &prior.state,
        &ExpectedState {
            state_revision: s.state_revision - 1,
            state_sha256: s
                .previous_state_sha256
                .clone()
                .ok_or(CustodyError::Corrupt)?,
        },
    )
}
fn publish(
    l: &mut ServiceLease<'_>,
    f: &Floor,
    s: &PublicServiceIdentity,
    seed: Option<&[u8; 32]>,
    owner: Option<&[u8]>,
    create: bool,
) -> Result<()> {
    let result: Result<()> = (|| {
        l.invalidate(true)?;
        checkpoint("before_staging")?;
        l.begin_staging()?;
        if let Some(raw) = seed {
            l.write_staging(StagingFile::Seed, raw)?
        }
        if let Some(raw) = owner {
            l.write_staging(StagingFile::OwnerInput, raw)?
        }
        l.write_staging(StagingFile::State, &encode(s))?;
        l.sync_staging()?;
        checkpoint("before_revision")?;
        l.publish_revision(s.state_revision)?;
        checkpoint("after_revision")?;
        check_prior(l, s, create)?;
        let n = observe(f, s.published_at)?;
        l.publish_clock(
            &encode(&Clock {
                schema: CLOCK.into(),
                store_id: s.store_id.clone(),
                observed_at: n,
            }),
            !create,
        )?;
        checkpoint("after_clock")?;
        check_prior(l, s, create)?;
        let e = s.expected();
        l.publish_current(
            &encode(&Pointer {
                schema: CURRENT.into(),
                store_id: s.store_id.clone(),
                state_revision: s.state_revision,
                state_sha256: e.state_sha256.clone(),
            }),
            !create,
        )?;
        checkpoint("after_current")?;
        let reread = load(l, None)?;
        cas(&reread.state, &e)?;
        drop(reread);
        l.revalidate()?;
        checkpoint("final_clock")?;
        let n = observe(f, s.published_at)?;
        if s.state != IdentityState::Revoked {
            live(s, n)?
        }
        l.invalidate(false)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = l.invalidate(true);
        return Err(CustodyError::PublicationUncertain);
    }
    Ok(())
}
fn advance_clock(
    l: &mut ServiceLease<'_>,
    f: &Floor,
    s: &PublicServiceIdentity,
    durable: u64,
) -> Result<()> {
    let n = observe(f, durable)?;
    l.publish_clock(
        &encode(&Clock {
            schema: CLOCK.into(),
            store_id: s.store_id.clone(),
            observed_at: n,
        }),
        true,
    )?;
    let c: Clock = decode(&l.read(ServiceFile::Clock)?)?;
    if c.schema != CLOCK || c.store_id != s.store_id || c.observed_at != n {
        return Err(CustodyError::Clock);
    }
    l.revalidate()?;
    observe(f, n)?;
    Ok(())
}
struct StoreInner {
    root: ServiceRoot,
    binding: StoreBinding,
    floor: Floor,
    lock_identity: Identity,
}
impl StoreInner {
    fn lease(&self, write: bool) -> Result<ServiceLease<'_>> {
        let l = if write {
            self.root.lock_exclusive()?
        } else {
            self.root.lock_shared()?
        };
        if l.lock_identity() != self.lock_identity {
            return Err(CustodyError::UnsafeStorage);
        }
        Ok(l)
    }
}
pub struct ServiceIdentityStore {
    inner: Arc<StoreInner>,
}
/// Selected by owner startup code, not by challenge/request wire.
pub struct OwnerConfiguredRoot {
    root: ServiceRoot,
}
impl OwnerConfiguredRoot {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            root: ServiceRoot::open(path)?,
        })
    }
}
/// Retains the exclusive lease between inspection and explicit abandon. Non-Clone.
pub struct IncompleteInitialization<'a> {
    lease: ServiceLease<'a>,
}
impl IncompleteInitialization<'_> {
    pub fn abandon(mut self) -> Result<()> {
        self.lease.abandon_incomplete()?;
        Ok(())
    }
}
impl ServiceIdentityStore {
    pub fn create(path: &Path, spec: NewServiceIdentity) -> Result<Self> {
        spec.validate()?;
        let root = ServiceRoot::open(path)?;
        let mut l = root.initialize()?;
        let f = floor_for(l.lock_identity())?;
        let n = observe(&f, 0)?;
        if n < spec.not_before || n >= spec.not_after {
            return Err(CustodyError::Expired);
        }
        let raw = seed()?;
        let mut id = [0u8; 16];
        getrandom::getrandom(&mut id).map_err(|_| CustodyError::UnsafeStorage)?;
        let mut s = PublicServiceIdentity {
            schema: STATE.into(),
            store_id: hex(&id),
            subject_id: spec.subject_id,
            purpose: PURPOSE.into(),
            application: spec.application,
            state_revision: 1,
            key_generation: 1,
            key_id: String::new(),
            public_key_hex: String::new(),
            public_key_sha256: String::new(),
            state: IdentityState::Unconfigured,
            created_at: n,
            key_created_at: n,
            published_at: n,
            not_before: spec.not_before,
            not_after: spec.not_after,
            revoked_at: None,
            previous_state_sha256: None,
            owner_input_sha256: None,
        };
        set_key(&mut s, &raw);
        s.valid()?;
        publish(&mut l, &f, &s, Some(&raw), None, true)?;
        drop(raw);
        let lock_identity = l.lock_identity();
        drop(l);
        Ok(Self {
            inner: Arc::new(StoreInner {
                root,
                binding: s.binding(),
                floor: f,
                lock_identity,
            }),
        })
    }
    pub fn open(path: &Path, binding: StoreBinding) -> Result<Self> {
        let root = ServiceRoot::open(path)?;
        let mut l = root.lock_exclusive()?;
        if l.poisoned()? {
            return Err(CustodyError::PublicationUncertain);
        }
        let f = floor_for(l.lock_identity())?;
        let a = load(&l, Some(&binding))?;
        let durable = a.durable;
        drop(a);
        l.revalidate()?;
        observe(&f, durable)?;
        l.invalidate(false)?;
        let lock_identity = l.lock_identity();
        drop(l);
        Ok(Self {
            inner: Arc::new(StoreInner {
                root,
                binding,
                floor: f,
                lock_identity,
            }),
        })
    }
    pub fn binding(&self) -> StoreBinding {
        self.inner.binding.clone()
    }
    pub fn public_identity(&self) -> Result<PublicServiceIdentity> {
        let l = self.inner.lease(false)?;
        if l.poisoned()? {
            return Err(CustodyError::PublicationUncertain);
        }
        let a = load(&l, Some(&self.inner.binding))?;
        let s = a.state.clone();
        let durable = a.durable;
        drop(a);
        l.revalidate()?;
        observe(&self.inner.floor, durable)?;
        Ok(s)
    }
    pub fn open_identity(&self, e: ExpectedState) -> Result<crate::ServiceIdentityHandle> {
        let l = self.inner.lease(false)?;
        if l.poisoned()? {
            return Err(CustodyError::PublicationUncertain);
        }
        let a = load(&l, Some(&self.inner.binding))?;
        cas(&a.state, &e)?;
        if a.state.state == IdentityState::Unconfigured {
            return Err(CustodyError::Unconfigured);
        }
        let s = a.state.clone();
        let durable = a.durable;
        drop(a);
        l.revalidate()?;
        live(&s, observe(&self.inner.floor, durable)?)?;
        Ok(crate::ServiceIdentityHandle {
            custody: HandleBinding {
                inner: self.inner.clone(),
                expected: e,
                epoch: l.epoch()?,
            },
        })
    }
    pub fn configure(&self, e: ExpectedState, raw: &[u8]) -> Result<PublicServiceIdentity> {
        self.begin_administration()?.configure(e, raw)
    }
    pub fn rotate(&self, e: ExpectedState, start: u64, end: u64) -> Result<PublicServiceIdentity> {
        if start >= end || end > MAX_SAFE_TIME {
            return Err(CustodyError::InvalidInput);
        }
        self.begin_administration()?.rotate(e, start, end)
    }
    pub fn revoke(&self, e: ExpectedState) -> Result<PublicServiceIdentity> {
        self.begin_administration()?.revoke(e)
    }
    /// Acquire exactly one StoreInner-bound exclusive custody lease. A poisoned
    /// store may be inspected only through explicit reconciliation; normal
    /// session reads and mutations continue to deny uncertainty.
    pub fn begin_administration(&self) -> Result<ServiceAdministrationSession<'_>> {
        Ok(ServiceAdministrationSession {
            inner: &self.inner,
            lease: self.inner.lease(true)?,
        })
    }
    pub fn reconcile_current(&self) -> Result<PublicServiceIdentity> {
        self.begin_administration()?.reconcile_current()
    }
    pub fn cleanup_unreferenced(&self, e: ExpectedState) -> Result<usize> {
        let mut l = self.inner.lease(true)?;
        if l.poisoned()? {
            return Err(CustodyError::PublicationUncertain);
        }
        let a = load(&l, Some(&self.inner.binding))?;
        cas(&a.state, &e)?;
        let state = a.state.clone();
        let durable = a.durable;
        drop(a);
        observe(&self.inner.floor, durable)?;
        l.invalidate(true)?;
        let result: Result<usize> = (|| {
            let i = l.inspect_bounded()?;
            let mut count = 0;
            for r in i.revisions {
                if r != e.state_revision {
                    l.remove_revision(r)?;
                    count += 1
                }
            }
            if i.staging {
                l.remove_staging()?;
                count += 1
            }
            l.discard_temporary()?;
            advance_clock(&mut l, &self.inner.floor, &state, durable)?;
            let a = load(&l, Some(&self.inner.binding))?;
            cas(&a.state, &e)?;
            drop(a);
            l.revalidate()?;
            observe(&self.inner.floor, durable)?;
            l.invalidate(false)?;
            Ok(count)
        })();
        result.map_err(|_| CustodyError::PublicationUncertain)
    }
    pub fn inspect_initialization<'a>(
        root: &'a OwnerConfiguredRoot,
        spec: NewServiceIdentity,
    ) -> Result<IncompleteInitialization<'a>> {
        spec.validate()?;
        let l = root.root.lock_exclusive()?;
        let i = l.inspect_bounded()?;
        if i.root_entries.iter().any(|s| s == "CURRENT") || i.revisions.iter().any(|r| *r != 1) {
            return Err(CustodyError::AlreadyExists);
        }
        l.revalidate()?;
        now()?;
        Ok(IncompleteInitialization { lease: l })
    }
    pub fn recover_initialization(path: &Path, spec: NewServiceIdentity) -> Result<Self> {
        spec.validate()?;
        let root = ServiceRoot::open(path)?;
        let mut l = root.lock_exclusive()?;
        let f = floor_for(l.lock_identity())?;
        l.invalidate(true)?;
        let a = load(&l, None)?;
        let s = a.state.clone();
        let durable = a.durable;
        drop(a);
        if s.state_revision != 1
            || s.key_generation != 1
            || s.state != IdentityState::Unconfigured
            || s.subject_id != spec.subject_id
            || s.application != spec.application
            || s.not_before != spec.not_before
            || s.not_after != spec.not_after
        {
            return Err(CustodyError::Changed);
        }
        l.sync_current()?;
        l.discard_temporary()?;
        advance_clock(&mut l, &f, &s, durable)?;
        let b = load(&l, None)?;
        cas(&b.state, &s.expected())?;
        drop(b);
        l.revalidate()?;
        observe(&f, durable)?;
        l.invalidate(false)?;
        let lock_identity = l.lock_identity();
        drop(l);
        Ok(Self {
            inner: Arc::new(StoreInner {
                root,
                binding: s.binding(),
                floor: f,
                lock_identity,
            }),
        })
    }
}
/// Opaque, non-Clone owner administration session. Its lifetime is tied to
/// the real store; no raw lease, callback, assertion token or unlock/relock is
/// exposed. This implements custody mechanics, not coupled native publication.
pub struct ServiceAdministrationSession<'store> {
    inner: &'store StoreInner,
    lease: ServiceLease<'store>,
}
impl<'store> ServiceAdministrationSession<'store> {
    pub fn public_identity(&self) -> Result<PublicServiceIdentity> {
        let l = &self.lease;
        if l.poisoned()? {
            return Err(CustodyError::PublicationUncertain);
        }
        let a = load(l, Some(&self.inner.binding))?;
        let s = a.state.clone();
        let durable = a.durable;
        drop(a);
        l.revalidate()?;
        observe(&self.inner.floor, durable)?;
        Ok(s)
    }
    /// A temporary public view from this same exclusive lease. Its immutable
    /// borrow must end before any mutable session operation.
    pub fn public_observation(&self) -> Result<BorrowedPublicServiceObservation<'_, 'store>> {
        if self.lease.poisoned()? {
            return Err(CustodyError::PublicationUncertain);
        }
        let observation = self.lease.public_observation()?;
        let (_, durable) = observed_public_state(observation.metadata(), &self.inner.binding)?;
        observation.revalidate()?;
        observe(&self.inner.floor, durable)?;
        Ok(observation)
    }
    pub fn configure(&mut self, e: ExpectedState, raw: &[u8]) -> Result<PublicServiceIdentity> {
        self.change_under_lease(e, Change::Configure(raw))
    }
    pub fn rotate(
        &mut self,
        e: ExpectedState,
        start: u64,
        end: u64,
    ) -> Result<PublicServiceIdentity> {
        if start >= end || end > MAX_SAFE_TIME {
            return Err(CustodyError::InvalidInput);
        }
        self.change_under_lease(e, Change::Rotate(start, end))
    }
    pub fn revoke(&mut self, e: ExpectedState) -> Result<PublicServiceIdentity> {
        self.change_under_lease(e, Change::Revoke)
    }
    pub fn reconcile_current(&mut self) -> Result<PublicServiceIdentity> {
        self.reconcile_under_lease()
    }
    fn change_under_lease(
        &mut self,
        e: ExpectedState,
        change: Change<'_>,
    ) -> Result<PublicServiceIdentity> {
        let l = &mut self.lease;
        if l.poisoned()? {
            return Err(CustodyError::PublicationUncertain);
        }
        let mut a = load(l, Some(&self.inner.binding))?;
        cas(&a.state, &e)?;
        if a.state.state == IdentityState::Revoked {
            return Err(CustodyError::Revoked);
        }
        clean_for_write(l, a.state.state_revision)?;
        let n = observe(&self.inner.floor, a.durable)?;
        let mut s = a.state.clone();
        s.state_revision = s
            .state_revision
            .checked_add(1)
            .filter(|n| *n <= MAX_SAFE_TIME)
            .ok_or(CustodyError::Capacity)?;
        s.previous_state_sha256 = Some(e.state_sha256);
        s.published_at = n;
        let mut owner = None;
        match change {
            Change::Configure(raw) => {
                live(&s, n)?;
                owner_matches(raw, &s)?;
                s.state = IdentityState::Active;
                s.owner_input_sha256 = Some(hex(&hash(raw)));
                owner = Some(raw);
            }
            Change::Rotate(start, end) => {
                if n < start || n >= end {
                    return Err(CustodyError::Expired);
                }
                s.key_generation = s
                    .key_generation
                    .checked_add(1)
                    .filter(|n| *n <= MAX_SAFE_TIME)
                    .ok_or(CustodyError::Capacity)?;
                s.key_created_at = n;
                s.not_before = start;
                s.not_after = end;
                s.state = IdentityState::Unconfigured;
                s.owner_input_sha256 = None;
                a.seed = Some(seed()?);
                set_key(&mut s, a.seed.as_ref().unwrap());
            }
            Change::Revoke => {
                s.state = IdentityState::Revoked;
                s.revoked_at = Some(n);
                s.owner_input_sha256 = None;
                a.seed = None;
            }
        }
        s.valid()?;
        publish(l, &self.inner.floor, &s, a.seed.as_deref(), owner, false)?;
        Ok(s)
    }
    fn reconcile_under_lease(&mut self) -> Result<PublicServiceIdentity> {
        let l = &mut self.lease;
        l.invalidate(true)?;
        let a = load(l, Some(&self.inner.binding))?;
        let s = a.state.clone();
        let durable = a.durable;
        drop(a);
        l.sync_current()?;
        l.discard_temporary()?;
        advance_clock(l, &self.inner.floor, &s, durable)?;
        let b = load(l, Some(&self.inner.binding))?;
        cas(&b.state, &s.expected())?;
        drop(b);
        l.revalidate()?;
        observe(&self.inner.floor, durable)?;
        l.invalidate(false)?;
        Ok(s)
    }
}
enum Change<'a> {
    Configure(&'a [u8]),
    Rotate(u64, u64),
    Revoke,
}
pub(crate) struct HandleBinding {
    inner: Arc<StoreInner>,
    expected: ExpectedState,
    epoch: u64,
}
fn service_holder_error(error: CustodyError) -> crate::Error {
    match error {
        CustodyError::Clock => crate::Error::Clock,
        CustodyError::Expired => crate::Error::Window,
        CustodyError::UnsupportedRequiredEvidence => crate::Error::UnsupportedRequiredEvidence,
        _ => crate::Error::Changed,
    }
}
impl HandleBinding {
    /// One fixed holder-proof operation, wholly inside actual Wallet custody.
    /// Parsed public owner inputs/clock/keys never enter from the caller.
    pub(crate) fn present_current_service_challenge(
        &self,
        c: &libsec_core::service_holder_proof::UntrustedSignedServiceChallenge,
    ) -> std::result::Result<Vec<u8>, crate::Error> {
        use crate::{validate_service_challenge, Error};
        use ed25519_dalek::{Signature, Signer};
        use libsec_core::service_holder_proof::{
            challenge_transcript, holder_transcript, UntrustedServiceHolderProof,
        };
        // Bounded framing/exact raw digest validation before custody acquisition.
        challenge_transcript(&c.claims, &c.request_bytes).map_err(|_| Error::Invalid)?;
        let lease = self.inner.lease(false).map_err(service_holder_error)?;
        let current = || -> Result<Loaded> {
            if lease.poisoned()? || lease.epoch()? != self.epoch {
                return Err(CustodyError::Changed);
            }
            let loaded = load(&lease, Some(&self.inner.binding))?;
            cas(&loaded.state, &self.expected)?;
            if loaded.state.state != IdentityState::Active {
                return Err(CustodyError::Changed);
            }
            Ok(loaded)
        };
        let loaded = current().map_err(service_holder_error)?;
        let owner_raw = loaded._owner.as_ref().ok_or(Error::Changed)?;
        let owner = ValidatedWalletOwnerInput::parse(owner_raw).map_err(|_| Error::Changed)?;
        let observed = observe(&self.inner.floor, loaded.durable).map_err(service_holder_error)?;
        live(&loaded.state, observed).map_err(service_holder_error)?;
        let validated = validate_service_challenge(&owner, c, observed)?;
        let seed = loaded.seed.as_ref().ok_or(Error::Changed)?;
        let signing = SigningKey::from_bytes(seed);
        let mut proof = UntrustedServiceHolderProof {
            claims: c.claims.clone(),
            issuer_signature: c.issuer_signature,
            holder_policy_digest: validated.wallet_policy_digest,
            holder_signature: [0; 64],
        };
        // Evidence/Native policy digests are issuer-authenticated opaque bindings
        // here; this signature does NOT qualify current Native evidence/context.
        let transcript = holder_transcript(&proof, &c.request_bytes).map_err(|_| Error::Invalid)?;
        proof.holder_signature = signing.sign(&transcript).to_bytes();
        signing
            .verifying_key()
            .verify_strict(&transcript, &Signature::from_bytes(&proof.holder_signature))
            .map_err(|_| Error::InvalidSignature)?;
        let encoded = proof.encode().map_err(|_| Error::Invalid)?;
        checkpoint("service_holder_before_final_reload").map_err(service_holder_error)?;
        // Same retained shared lease; no validation-then-reacquire gap, lock
        // upgrade, clock publication or externally callable signer callback.
        let reloaded = current().map_err(service_holder_error)?;
        if reloaded.state != loaded.state
            || reloaded.durable != loaded.durable
            || reloaded._owner.as_ref().map(|b| b.as_slice()) != Some(owner_raw.as_slice())
        {
            return Err(Error::Changed);
        }
        let reloaded_owner =
            ValidatedWalletOwnerInput::parse(reloaded._owner.as_ref().ok_or(Error::Changed)?)
                .map_err(|_| Error::Changed)?;
        let checked = observe(&self.inner.floor, reloaded.durable).map_err(service_holder_error)?;
        let revalidated = validate_service_challenge(&reloaded_owner, c, checked)?;
        if revalidated.owner_digest != validated.owner_digest
            || revalidated.wallet_policy_digest != validated.wallet_policy_digest
        {
            return Err(Error::Changed);
        }
        lease
            .revalidate()
            .map_err(CustodyError::from)
            .map_err(service_holder_error)?;
        if lease
            .poisoned()
            .map_err(CustodyError::from)
            .map_err(service_holder_error)?
            || lease
                .epoch()
                .map_err(CustodyError::from)
                .map_err(service_holder_error)?
                != self.epoch
        {
            return Err(Error::Changed);
        }
        let (durable, not_before, not_after) = (
            reloaded.durable,
            reloaded.state.not_before,
            reloaded.state.not_after,
        );
        // Zeroizing secret buffers and signing state are gone before the final
        // clock. Only the real lease and public output/bounds remain retained.
        drop(signing);
        drop(loaded);
        drop(reloaded);
        drop(owner);
        drop(reloaded_owner);
        drop(validated);
        drop(revalidated);
        checkpoint("service_holder_before_final_clock").map_err(service_holder_error)?;
        // Acquire the shared floor BEFORE sampling: no filesystem/parsing/crypto
        // work or blocking floor acquisition follows this last OS observation.
        let mut floor = self.inner.floor.lock().map_err(|_| Error::Clock)?;
        let final_now = now().map_err(service_holder_error)?;
        if final_now < durable || final_now < *floor {
            return Err(Error::Clock);
        }
        *floor = final_now;
        if final_now < c.claims.issued_at
            || final_now >= c.claims.expires_at
            || final_now < not_before
            || final_now >= not_after
        {
            return Err(Error::Window);
        }
        Ok(encoded)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        let l = self.inner.lease(false)?;
        if l.poisoned()? || l.epoch()? != self.epoch {
            return Err(CustodyError::Changed);
        }
        let a = load(&l, Some(&self.inner.binding))?;
        cas(&a.state, &self.expected)?;
        if a.state.state != IdentityState::Active {
            return Err(CustodyError::Changed);
        }
        let s = a.state.clone();
        let durable = a.durable;
        drop(a);
        l.revalidate()?;
        live(&s, observe(&self.inner.floor, durable)?)
    }
}
#[cfg(test)]
type TestAction = Option<Box<dyn FnMut(&str)>>;
#[cfg(test)]
thread_local! { pub(super) static TEST_NOW:std::cell::Cell<Option<u64>>=const {std::cell::Cell::new(None)}; pub(super) static TEST_ACTION:std::cell::RefCell<TestAction>=const {std::cell::RefCell::new(None)}; pub(super) static TEST_FAIL:std::cell::Cell<Option<&'static str>>=const {std::cell::Cell::new(None)}; }
fn checkpoint(_name: &str) -> Result<()> {
    #[cfg(test)]
    TEST_ACTION.with(|v| {
        if let Some(f) = v.borrow_mut().as_mut() {
            f(_name)
        }
    });
    #[cfg(test)]
    if TEST_FAIL.with(|v| v.get()) == Some(_name) {
        return Err(CustodyError::UnsafeStorage);
    }
    Ok(())
}
#[cfg(test)]
pub(super) fn check_public_state_vector(raw: &[u8]) -> Result<ExpectedState> {
    let s: PublicServiceIdentity = decode(raw)?;
    s.valid()?;
    Ok(s.expected())
}
