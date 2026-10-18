//! Isolated native service journal internals, not exported or qualified authority.
//!
//! This module owns no keys, signs nothing, and grants no execution authority.
//! Integration with an owner-held coherent authority/evidence guard is required.
//! The hard limits below come from the accepted service-holder-proof-v1 contract.
use std::path::PathBuf;

pub const COMPLETION_OVERHEAD: u64 = 122_949;
pub const ROW_LIMIT: u64 = 3 * 1024 * 1024;
pub const TOMBSTONE_LIMIT: u64 = 8192;
pub const METADATA_LIMIT: usize = 16_384;
pub const CONTEXT_LIMIT: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    Invalid,
    Capacity,
    Expired,
    ClockRollback,
    Rejected,
    Conflict,
    Missing,
    Corrupt,
    Storage,
    Busy,
}

/// Only an atomic exact-request match may select Native's bounded recovery.
/// Ordinary conflicts/capacity/storage errors never select that fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PendingInsertError {
    Journal(JournalError),
    RetainedRequest,
}
impl From<JournalError> for PendingInsertError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

/// Operator tightening only: raising any accepted ceiling fails closed.
#[derive(Clone, Debug)]
pub struct Limits {
    pub rows_per_holder: u64,
    pub rows_global: u64,
    pub pending_per_holder: u64,
    pub pending_global: u64,
    pub bytes_per_holder: u64,
    pub bytes_global: u64,
    pub request_bytes_global: u64,
    pub physical_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            rows_per_holder: 32,
            rows_global: 256,
            pending_per_holder: 8,
            pending_global: 64,
            bytes_per_holder: 8 << 20,
            bytes_global: 32 << 20,
            request_bytes_global: 16 << 20,
            physical_bytes: 64 << 20,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<(), JournalError> {
        let hard = Self::default();
        for (value, max) in [
            (self.rows_per_holder, hard.rows_per_holder),
            (self.rows_global, hard.rows_global),
            (self.pending_per_holder, hard.pending_per_holder),
            (self.pending_global, hard.pending_global),
            (self.bytes_per_holder, hard.bytes_per_holder),
            (self.bytes_global, hard.bytes_global),
            (self.request_bytes_global, hard.request_bytes_global),
            (self.physical_bytes, hard.physical_bytes),
        ] {
            if value == 0 || value > max {
                return Err(JournalError::Invalid);
            }
        }
        if self.physical_bytes < 1024 * 1024 {
            return Err(JournalError::Invalid);
        }
        Ok(())
    }
}

/// Total Pending accounted size, not an extra uncharged future allocation.
/// The retained Pending representation consumes part of this reservation.
pub fn completion_reservation(request_length: u64) -> Result<u64, JournalError> {
    if request_length == 0 || request_length > 2_097_152 {
        return Err(JournalError::Invalid);
    }
    request_length
        .checked_add(COMPLETION_OVERHEAD)
        .filter(|size| *size <= ROW_LIMIT)
        .ok_or(JournalError::Capacity)
}

/// One dedicated owner-controlled directory; never a shared application DB.
/// Secure directory/custody provisioning and owner qualification are external.
pub struct Journal {
    directory: PathBuf,
    selected: crate::work_private_files::Directory,
    identity: (u64, u64),
    limits: Limits,
    #[cfg(test)]
    after_close: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

use bincode::Options;
use libsec_core::{
    service_holder_proof::{
        UntrustedServiceHolderProof, UntrustedSignedServiceChallenge, MAX_SAFE_TIME,
    },
    ZenithPacket,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous},
    Connection, Row, SqliteConnection,
};
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::Path,
    time::Duration,
};

pub trait Clock {
    fn now(&self) -> u64;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportStage {
    Pending,
    Complete,
    Cached,
}

/// TRUSTED OWNER PORT, NOT a qualification token. The adapter must hold a coherent
/// authority-generation/evidence guard until this journal call returns, validate
/// the entire original window and exact evidence lineage, and authenticate any
/// signatures/context here. The journal checks storage/codec binding only.
/// The generic port itself supplies no publicly constructible authority approval.
pub trait AuthorityGuard {
    fn revalidate(&mut self, input: GuardInput<'_>) -> Result<(), JournalError>;
}
pub struct GuardInput<'a> {
    pub stage: ExportStage,
    pub challenge: &'a UntrustedSignedServiceChallenge,
    pub evidence: &'a [u8],
    pub lineage: &'a [u8],
    pub packet: &'a [u8],
    pub context: &'a [u8],
    pub signed_at: u64,
    pub holder_verified_at: u64,
}
/// Durably retained untrusted wire bytes. Never an execution capability.
#[derive(Debug)]
pub struct StoredChallenge {
    pub challenge: UntrustedSignedServiceChallenge,
}
/// Storage inspection only, not an authenticated challenge or export approval.
/// Crate-private so a request-only producer cannot return it as native authority.
pub(crate) struct RetainedCompletionBasis {
    pub(crate) challenge: UntrustedSignedServiceChallenge,
    pub(crate) evidence: Vec<u8>,
    pub(crate) lineage: Vec<u8>,
    pub(crate) completion: Option<StoredCompletion>,
}
pub(crate) struct RetainedPending {
    pub(crate) challenge: UntrustedSignedServiceChallenge,
    pub(crate) evidence: Vec<u8>,
    pub(crate) lineage: Vec<u8>,
}
#[derive(PartialEq, Eq)]
pub struct StoredCompletion {
    pub packet: Vec<u8>,
    pub context: Vec<u8>,
    pub holder_verified_at: u64,
    pub signed_at: u64,
}
impl std::fmt::Debug for StoredCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredCompletion")
            .field("packet_bytes", &self.packet.len())
            .field("context_bytes", &self.context.len())
            .finish_non_exhaustive()
    }
}
/// Owner-reported actual events, checked against the immutable challenge window
/// and final admission clock. Their authenticity remains the guard's obligation.
#[derive(Clone, Copy, Debug)]
pub struct IssuanceTimes {
    pub holder_verified_at: u64,
    pub context_signed_at: u64,
}
#[derive(Default, Debug, PartialEq, Eq)]
pub struct Stats {
    pub rows: u64,
    pub pending: u64,
    pub completed: u64,
    pub tombstones: u64,
    pub accounted_bytes: u64,
    pub request_bytes: u64,
}

const DB: &str = "service-challenges.sqlite3";
const SCHEMA: &str = "CREATE TABLE service_challenge_meta_v1 (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL CHECK(version=1), high_water INTEGER NOT NULL CHECK(high_water>0)); CREATE TABLE service_challenges_v1 (id BLOB PRIMARY KEY CHECK(length(id)=32), holder TEXT NOT NULL, session BLOB NOT NULL UNIQUE CHECK(length(session)=16), nonce BLOB NOT NULL UNIQUE CHECK(length(nonce)=12), expires INTEGER NOT NULL, state INTEGER NOT NULL CHECK(state IN (0,1,2)), accounted INTEGER NOT NULL CHECK(accounted>0), request_bytes INTEGER NOT NULL CHECK(request_bytes>=0), record BLOB NOT NULL, digest BLOB NOT NULL CHECK(length(digest)=32)) WITHOUT ROWID;";
const SIGNATURE_FIELD: usize = 2 + "issuer_signature".len() + 4 + 64;
const PENDING: u8 = 0;
const COMPLETED: u8 = 1;
const TOMBSTONE: u8 = 2;

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn directory_error(e: std::io::Error) -> JournalError {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput => {
            JournalError::Invalid
        }
        _ => JournalError::Storage,
    }
}
fn storage(_: impl std::fmt::Debug) -> JournalError {
    JournalError::Storage
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], limit: u64) -> Result<T, JournalError> {
    if bytes.len() as u64 > limit {
        return Err(JournalError::Invalid);
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|_| JournalError::Corrupt)
}
fn now(clock: &impl Clock, floor: u64) -> Result<u64, JournalError> {
    let value = clock.now();
    if value == 0 || value > MAX_SAFE_TIME {
        return Err(JournalError::Invalid);
    }
    if value < floor {
        return Err(JournalError::ClockRollback);
    }
    Ok(value)
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    version: u8,
    state: u8,
    id: [u8; 32],
    holder: String,
    session: [u8; 16],
    nonce: [u8; 12],
    issued: u64,
    expires: u64,
    request_length: u64,
    signed_at: u64,
    holder_verified_at: u64,
    request_digest: [u8; 32],
    challenge_digest: [u8; 32],
    metadata_digest: [u8; 32],
    evidence_digest: [u8; 32],
    lineage_digest: [u8; 32],
    packet_digest: [u8; 32],
    proof_digest: [u8; 32],
    context_digest: [u8; 32],
    metadata: Vec<u8>,
    body: Vec<u8>,
    context: Vec<u8>,
    evidence: Vec<u8>,
    lineage: Vec<u8>,
}
impl Record {
    fn pending(
        c: &UntrustedSignedServiceChallenge,
        evidence: &[u8],
        lineage: &[u8],
    ) -> Result<Self, JournalError> {
        if evidence.len() > METADATA_LIMIT || lineage.len() > 4096 {
            return Err(JournalError::Invalid);
        }
        let raw = c.encode_inner().map_err(|_| JournalError::Invalid)?;
        let cut = raw
            .len()
            .checked_sub(SIGNATURE_FIELD + c.request_bytes.len())
            .ok_or(JournalError::Invalid)?;
        let mut metadata = raw[..cut].to_vec();
        metadata.extend_from_slice(&raw[cut + c.request_bytes.len()..]);
        let claims = &c.claims;
        let r = Self {
            version: 1,
            state: PENDING,
            id: claims.challenge_id,
            holder: claims.holder_subject_id.clone(),
            session: claims.session_id,
            nonce: claims.nonce,
            issued: claims.issued_at,
            expires: claims.expires_at,
            request_length: claims.request_length,
            signed_at: 0,
            holder_verified_at: 0,
            request_digest: claims.request_sha256,
            challenge_digest: hash(&raw),
            metadata_digest: hash(&metadata),
            evidence_digest: hash(evidence),
            lineage_digest: hash(lineage),
            packet_digest: [0; 32],
            proof_digest: [0; 32],
            context_digest: [0; 32],
            metadata,
            body: c.request_bytes.clone(),
            context: vec![],
            evidence: evidence.to_vec(),
            lineage: lineage.to_vec(),
        };
        r.validate()?;
        Ok(r)
    }
    fn bytes(&self) -> Result<Vec<u8>, JournalError> {
        bincode::serialize(self).map_err(storage)
    }
    fn retained(&self) -> Result<u64, JournalError> {
        // Every copy in the row + lookup/indexed columns is charged. SQLite B-tree
        // and WAL overhead are bounded independently by the physical page budget.
        Ok(530
            + 2 * self.holder.len() as u64
            + self.metadata.len() as u64
            + self.body.len() as u64
            + self.context.len() as u64
            + self.evidence.len() as u64
            + self.lineage.len() as u64)
    }
    fn accounted(&self) -> Result<u64, JournalError> {
        let retained = self.retained()?;
        if self.state == PENDING {
            Ok(retained.max(completion_reservation(self.request_length)?))
        } else {
            Ok(retained)
        }
    }
    fn request_bytes(&self) -> u64 {
        if self.state == TOMBSTONE {
            0
        } else {
            self.request_length
        }
    }
    fn packet(&self) -> Result<ZenithPacket, JournalError> {
        decode(&self.body, 2_097_152 + 16_384 + 69)
    }
    fn challenge(&self) -> Result<UntrustedSignedServiceChallenge, JournalError> {
        if self.state == TOMBSTONE {
            return Err(JournalError::Rejected);
        }
        let request = if self.state == PENDING {
            self.body.clone()
        } else {
            self.packet()?.encrypted_payload
        };
        let cut = self
            .metadata
            .len()
            .checked_sub(SIGNATURE_FIELD)
            .ok_or(JournalError::Corrupt)?;
        let mut raw = self.metadata[..cut].to_vec();
        raw.extend_from_slice(&request);
        raw.extend_from_slice(&self.metadata[cut..]);
        if hash(&raw) != self.challenge_digest {
            return Err(JournalError::Corrupt);
        }
        UntrustedSignedServiceChallenge::decode_inner(&raw).map_err(|_| JournalError::Corrupt)
    }
    fn validate(&self) -> Result<(), JournalError> {
        if self.version != 1
            || self.state > 2
            || self.id == [0; 32]
            || self.session == [0; 16]
            || self.nonce == [0; 12]
            || self.issued == 0
            || self.expires > MAX_SAFE_TIME
            || self.expires <= self.issued
            || self.expires - self.issued > 60
            || self.holder.is_empty()
            || self.holder.len() > 128
            || !self.holder.bytes().all(|b| (0x21..=0x7e).contains(&b))
            || self.request_length == 0
            || self.request_length > 2_097_152
            || self.lineage.len() > 4096
            || hash(&self.lineage) != self.lineage_digest
            || self.metadata.len() > METADATA_LIMIT
            || self.evidence.len() > METADATA_LIMIT
            || self.context.len() > CONTEXT_LIMIT
        {
            return Err(JournalError::Corrupt);
        }
        let limit = if self.state == TOMBSTONE {
            TOMBSTONE_LIMIT
        } else {
            ROW_LIMIT
        };
        if self.retained()? > limit || self.accounted()? > limit {
            return Err(JournalError::Corrupt);
        }
        let variable =
            self.metadata.len() + self.body.len() + self.context.len() + self.evidence.len();
        if self.retained()?.saturating_sub(variable as u64) > 8192 {
            return Err(JournalError::Corrupt);
        }
        if self.state == TOMBSTONE {
            if !self.metadata.is_empty()
                || !self.body.is_empty()
                || !self.context.is_empty()
                || !self.evidence.is_empty()
            {
                return Err(JournalError::Corrupt);
            }
            return Ok(());
        }
        if hash(&self.metadata) != self.metadata_digest
            || hash(&self.evidence) != self.evidence_digest
        {
            return Err(JournalError::Corrupt);
        }
        let c = self.challenge()?;
        let v = &c.claims;
        if v.challenge_id != self.id
            || v.holder_subject_id != self.holder
            || v.session_id != self.session
            || v.nonce != self.nonce
            || v.issued_at != self.issued
            || v.expires_at != self.expires
            || v.request_length != self.request_length
            || v.request_sha256 != self.request_digest
        {
            return Err(JournalError::Corrupt);
        }
        if self.state == PENDING {
            if self.signed_at != 0
                || self.holder_verified_at != 0
                || !self.context.is_empty()
                || self.packet_digest != [0; 32]
                || self.proof_digest != [0; 32]
                || self.context_digest != [0; 32]
            {
                return Err(JournalError::Corrupt);
            }
        } else {
            let p = self.packet()?;
            let proof =
                UntrustedServiceHolderProof::decode(&p.proof).map_err(|_| JournalError::Corrupt)?;
            if p.session_id != v.session_id
                || p.nonce != v.nonce
                || p.opcode != v.opcode
                || p.claim_ttl != v.ttl_seconds
                || p.mac != [0; 16]
                || proof.claims != *v
                || proof.issuer_signature != c.issuer_signature
                || p.encrypted_payload != c.request_bytes
                || self.holder_verified_at < self.issued
                || self.holder_verified_at > self.signed_at
                || self.signed_at >= self.expires
                || self.context.is_empty()
                || hash(&self.body) != self.packet_digest
                || hash(&p.proof) != self.proof_digest
                || hash(&self.context) != self.context_digest
            {
                return Err(JournalError::Corrupt);
            }
        }
        Ok(())
    }
    // Stable holder identity survives key rotation and rejected-row compaction.
    // This selects untrusted data only; full raw bytes/current authority are
    // independently checked before any Native export.
    fn matches_request(&self, holder: &str, length: u64, digest: [u8; 32]) -> bool {
        self.holder == holder && self.request_length == length && self.request_digest == digest
    }
    fn reject(&mut self) {
        self.state = TOMBSTONE;
        self.metadata.clear();
        self.body.clear();
        self.context.clear();
        self.evidence.clear();
    }
    fn completion(&self) -> StoredCompletion {
        StoredCompletion {
            packet: self.body.clone(),
            context: self.context.clone(),
            signed_at: self.signed_at,
            holder_verified_at: self.holder_verified_at,
        }
    }
}

struct Lock(File);
impl Lock {
    fn validate(&self, journal: &Journal) -> Result<(), JournalError> {
        journal.validate_root()?;
        let current = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(journal.directory.join("journal.lock"))
            .map_err(storage)?;
        let held = self.0.metadata().map_err(storage)?;
        let fresh = current.metadata().map_err(storage)?;
        if !fresh.is_file()
            || fresh.nlink() != 1
            || fresh.uid() != unsafe { libc::geteuid() }
            || fresh.mode() & 0o077 != 0
            || (held.dev(), held.ino()) != (fresh.dev(), fresh.ino())
        {
            return Err(JournalError::Invalid);
        }
        if fresh.len() != 0 || fresh.blocks() != 0 {
            return Err(JournalError::Capacity);
        }
        crate::work_private_files::access(&current, false).map_err(storage)?;
        journal.validate_root()
    }
    fn acquire(directory: &Path) -> Result<Self, JournalError> {
        let m = fs::symlink_metadata(directory).map_err(storage)?;
        if !directory.is_absolute()
            || !m.is_dir()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
        {
            return Err(JournalError::Invalid);
        }
        let path = directory.join("journal.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(storage)?;
        let m = file.metadata().map_err(storage)?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
        {
            return Err(JournalError::Invalid);
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(JournalError::Busy);
        }
        Ok(Self(file))
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl Journal {
    fn validate_root(&self) -> Result<(), JournalError> {
        let fresh =
            crate::work_private_files::Directory::open(&self.directory).map_err(directory_error)?;
        let current = fresh.descriptor().metadata().map_err(storage)?;
        let held = self.selected.descriptor().metadata().map_err(storage)?;
        if (current.dev(), current.ino()) != self.identity
            || (held.dev(), held.ino()) != self.identity
        {
            return Err(JournalError::Invalid);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn after_close_for_test(&mut self, hook: impl Fn() + Send + Sync + 'static) {
        self.after_close = Some(std::sync::Arc::new(hook));
    }
    fn physical(&self) -> Result<u64, JournalError> {
        self.validate_root()?;
        let mut total = 0u64;
        for entry in fs::read_dir(&self.directory).map_err(storage)? {
            let entry = entry.map_err(storage)?;
            let name = entry.file_name();
            if ![
                DB.as_bytes(),
                b"service-challenges.sqlite3-wal",
                b"service-challenges.sqlite3-shm",
                b"journal.lock",
            ]
            .contains(&name.as_bytes())
            {
                return Err(JournalError::Invalid);
            }
            let m = fs::symlink_metadata(entry.path()).map_err(storage)?;
            if !m.is_file()
                || m.nlink() != 1
                || m.uid() != unsafe { libc::geteuid() }
                || m.mode() & 0o077 != 0
            {
                return Err(JournalError::Invalid);
            }
            let bound = match name.as_bytes() {
                b"journal.lock" => 0,
                b"service-challenges.sqlite3" => self.page_limit() * 4096,
                b"service-challenges.sqlite3-wal" => (self.page_limit() + 32) * 4120 + 32,
                b"service-challenges.sqlite3-shm" => 128 * 1024,
                _ => return Err(JournalError::Invalid),
            };
            let allocated = m.blocks().checked_mul(512).ok_or(JournalError::Capacity)?;
            let charged = m.len().max(allocated);
            // Preallocation beyond EOF consumes the same per-file reservation.
            // In particular an empty lock has no reserved data extents.
            if charged > bound {
                return Err(JournalError::Capacity);
            }
            total = total.checked_add(charged).ok_or(JournalError::Capacity)?;
        }
        if total > self.limits.physical_bytes {
            return Err(JournalError::Capacity);
        }
        Ok(total)
    }
    fn page_limit(&self) -> u64 {
        // Disallow spill and disk temp; checkpoint before/after each commit.
        // Reserve one full main DB plus a full dirty-page WAL, SHM and 512 KiB
        // margin, under 64 MiB. Tightens physical storage without lowering any
        // public request limit. SQLite max_page_count bounds growth *before* I/O.
        ((self.limits.physical_bytes - 512 * 1024) / (4096 + 4120)).min(7168)
    }
    async fn connect(&self, lock: &Lock) -> Result<SqliteConnection, JournalError> {
        lock.validate(self)?;
        self.physical()?;
        let length = fs::metadata(self.directory.join(DB))
            .map_err(storage)?
            .len();
        if length > self.page_limit() * 4096 {
            return Err(JournalError::Capacity);
        }
        if length > 0 {
            use std::io::Read;
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(self.directory.join(DB))
                .map_err(storage)?;
            let mut header = [0; 18];
            file.read_exact(&mut header)
                .map_err(|_| JournalError::Corrupt)?;
            if &header[..16] != b"SQLite format 3\0"
                || u16::from_be_bytes([header[16], header[17]]) != 4096
            {
                return Err(JournalError::Corrupt);
            }
        }
        let options = SqliteConnectOptions::new()
            .filename(self.directory.join(DB))
            .create_if_missing(false)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_millis(250));
        let mut conn = SqliteConnection::connect_with(&options)
            .await
            .map_err(storage)?;
        let configured = async {
            lock.validate(self)?;
            for sql in [
                "PRAGMA temp_store=MEMORY".to_owned(),
                "PRAGMA cache_spill=OFF".to_owned(),
                "PRAGMA secure_delete=ON".to_owned(),
                "PRAGMA wal_autocheckpoint=0".to_owned(),
                format!("PRAGMA max_page_count={}", self.page_limit()),
                format!("PRAGMA cache_size={}", self.page_limit() + 32),
            ] {
                sqlx::query(&sql)
                    .execute(&mut conn)
                    .await
                    .map_err(storage)?;
            }
            for (pragma, expected) in [
                ("page_size", 4096),
                ("max_page_count", self.page_limit() as i64),
                ("temp_store", 2),
                ("cache_spill", 0),
                ("secure_delete", 1),
                ("synchronous", 2),
                ("wal_autocheckpoint", 0),
                ("auto_vacuum", 0),
            ] {
                let value: i64 = sqlx::query_scalar(&format!("PRAGMA {pragma}"))
                    .fetch_one(&mut conn)
                    .await
                    .map_err(storage)?;
                if value != expected {
                    return Err(JournalError::Corrupt);
                }
            }
            let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
                .fetch_one(&mut conn)
                .await
                .map_err(storage)?;
            if mode != "wal" {
                return Err(JournalError::Corrupt);
            }
            self.checkpoint(&mut conn).await?;
            let check: String = sqlx::query_scalar("PRAGMA quick_check(1)")
                .fetch_one(&mut conn)
                .await
                .map_err(|_| JournalError::Corrupt)?;
            if check != "ok" {
                return Err(JournalError::Corrupt);
            }
            Ok(())
        }
        .await;
        if let Err(error) = configured {
            let _ = conn.close().await;
            return Err(error);
        }
        Ok(conn)
    }
    async fn checkpoint(&self, conn: &mut SqliteConnection) -> Result<(), JournalError> {
        let row = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_one(&mut *conn)
            .await
            .map_err(storage)?;
        if row.get::<i64, _>(0) != 0 {
            return Err(JournalError::Busy);
        }
        self.physical()?;
        Ok(())
    }
    pub async fn open(
        directory: &Path,
        limits: Limits,
        clock: &impl Clock,
    ) -> Result<Self, JournalError> {
        limits.validate()?;
        let selected =
            crate::work_private_files::Directory::open(directory).map_err(directory_error)?;
        let meta = selected.descriptor().metadata().map_err(storage)?;
        let j = Self {
            directory: directory.to_path_buf(),
            selected,
            identity: (meta.dev(), meta.ino()),
            limits,
            #[cfg(test)]
            after_close: None,
        };
        j.validate_root()?;
        let _lock = Lock::acquire(directory)?;
        _lock.validate(&j)?;
        j.physical()?;
        let created = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(DB))
        {
            Ok(f) => {
                f.sync_all().map_err(storage)?;
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(e) => return Err(storage(e)),
        };
        if !created && fs::metadata(directory.join(DB)).map_err(storage)?.len() == 0 {
            return Err(JournalError::Corrupt);
        }
        let mut conn = j.connect(&_lock).await?;
        if created {
            let time = now(clock, 0)?;
            sqlx::query("BEGIN IMMEDIATE")
                .execute(&mut conn)
                .await
                .map_err(storage)?;
            sqlx::raw_sql(SCHEMA)
                .execute(&mut conn)
                .await
                .map_err(storage)?;
            sqlx::query("INSERT INTO service_challenge_meta_v1 VALUES (1,1,?)")
                .bind(time as i64)
                .execute(&mut conn)
                .await
                .map_err(storage)?;
            sqlx::query("PRAGMA user_version=1")
                .execute(&mut conn)
                .await
                .map_err(storage)?;
            sqlx::query("COMMIT")
                .execute(&mut conn)
                .await
                .map_err(storage)?;
            j.checkpoint(&mut conn).await?;
            File::open(directory)
                .and_then(|f| f.sync_all())
                .map_err(storage)?;
        }
        conn.close().await.map_err(storage)?;
        drop(_lock);
        j.stats(clock).await?;
        Ok(j)
    }
    async fn session(&self, clock: &impl Clock) -> Result<Session<'_>, JournalError> {
        self.validate_root()?;
        let lock = Lock::acquire(&self.directory)?;
        lock.validate(self)?;
        let conn = self.connect(&lock).await?;
        let mut session = Session {
            journal: self,
            conn,
            _lock: lock,
            high_water: 0,
            exported: None,
        };
        let admission = async {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut session.conn)
                .await
                .map_err(|_| JournalError::Corrupt)?;
            if version != 1 {
                return Err(JournalError::Corrupt);
            }
            let mut observed: Vec<String> = sqlx::query_scalar(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY sql",
            )
            .fetch_all(&mut session.conn)
            .await
            .map_err(|_| JournalError::Corrupt)?;
            let mut expected: Vec<String> = SCHEMA
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            observed.sort();
            expected.sort();
            if observed != expected {
                return Err(JournalError::Corrupt);
            }
            session.begin().await?;
            let floor: i64 = sqlx::query_scalar(
                "SELECT high_water FROM service_challenge_meta_v1 WHERE id=1 AND version=1",
            )
            .fetch_one(&mut session.conn)
            .await
            .map_err(|_| JournalError::Corrupt)?;
            if floor <= 0 {
                return Err(JournalError::Corrupt);
            }
            session.high_water = now(clock, floor as u64)?;
            session.audit().await?;
            // The observed time and exclusive pruning commit together before any
            // new admission. A failed/tighter capacity check cannot undo time.
            sqlx::query("DELETE FROM service_challenges_v1 WHERE expires<=?")
                .bind(session.high_water as i64)
                .execute(&mut session.conn)
                .await
                .map_err(storage)?;
            session.commit().await?;
            session.begin().await?;
            let rows = session.audit().await?;
            session.check_limits(&rows, &self.limits)?;
            Ok(())
        }
        .await;
        if let Err(error) = admission {
            let _ = sqlx::query("ROLLBACK").execute(&mut session.conn).await;
            let _ = session.conn.close().await;
            return Err(error);
        }
        Ok(session)
    }
    async fn persist_after_close(
        &self,
        _held_lock: &Lock,
        row: Option<&Record>,
        floor: u64,
    ) -> Result<(), JournalError> {
        _held_lock.validate(self)?;
        let conn = self.connect(_held_lock).await?;
        // The borrowed Lock proves serialization remains held. This temporary
        // session never owns or releases that lock and never exports authority.
        let mut conn = conn;
        let result=async {
            sqlx::query("BEGIN IMMEDIATE").execute(&mut conn).await.map_err(storage)?;
            let old:i64=sqlx::query_scalar("SELECT high_water FROM service_challenge_meta_v1 WHERE id=1 AND version=1").fetch_one(&mut conn).await.map_err(|_|JournalError::Corrupt)?;
            if old<=0 || old as u64>floor {return Err(JournalError::ClockRollback);}
            if let Some(row)=row {
                row.validate()?;let bytes=row.bytes()?;
                let affected=sqlx::query("UPDATE service_challenges_v1 SET state=2,accounted=?,request_bytes=0,record=?,digest=? WHERE id=?")
                    .bind(row.accounted()? as i64).bind(&bytes).bind(hash(&bytes).as_slice()).bind(row.id.as_slice()).execute(&mut conn).await.map_err(storage)?.rows_affected();
                if affected!=1 {return Err(JournalError::Corrupt);}
            }
            sqlx::query("UPDATE service_challenge_meta_v1 SET high_water=? WHERE id=1").bind(floor as i64).execute(&mut conn).await.map_err(storage)?;
            sqlx::query("COMMIT").execute(&mut conn).await.map_err(storage)?;
            self.checkpoint(&mut conn).await
        }.await;
        let closed = conn.close().await.map_err(storage);
        result.and(closed)
    }
    pub async fn stats(&self, clock: &impl Clock) -> Result<Stats, JournalError> {
        let mut s = self.session(clock).await?;
        let rows = s.audit().await?;
        let stats = totals(&rows, None)?;
        s.clock(clock)?;
        s.commit().await?;
        s.conn.close().await.map_err(storage)?;
        Ok(stats)
    }
    pub async fn persist_pending(
        &self,
        c: &UntrustedSignedServiceChallenge,
        evidence: &[u8],
        lineage: &[u8],
        guard: &mut impl AuthorityGuard,
        clock: &impl Clock,
    ) -> Result<StoredChallenge, JournalError> {
        let row = Record::pending(c, evidence, lineage)?;
        let mut s = self.session(clock).await?;
        let result = async {
            if let Some(old) = s.get(row.id).await? {
                if old.state == TOMBSTONE {
                    return Err(JournalError::Rejected);
                }
                if old.state != PENDING || old.bytes()? != row.bytes()? {
                    return Err(JournalError::Conflict);
                }
            } else {
                s.capacity(&row).await?;
                s.put(&row).await?;
            }
            s.export(row.clone(), ExportStage::Pending, guard, clock)
                .await?;
            Ok(StoredChallenge {
                challenge: c.clone(),
            })
        }
        .await;
        s.finish_export(&result, guard, clock).await?;
        result
    }
    /// Native-only insertion. The identity check and insertion share the same
    /// OS lock/transaction, so two no-match issuers cannot both retain a row.
    pub(crate) async fn persist_pending_once(
        &self,
        c: &UntrustedSignedServiceChallenge,
        evidence: &[u8],
        lineage: &[u8],
        guard: &mut impl AuthorityGuard,
        clock: &impl Clock,
    ) -> Result<StoredChallenge, PendingInsertError> {
        let row = Record::pending(c, evidence, lineage)?;
        let mut session = self.session(clock).await?;
        let rows = match session.audit().await {
            Ok(rows) => rows,
            Err(error) => {
                let denied: Result<(), JournalError> = Err(error);
                session.finish_error(&denied, clock).await?;
                return Err(PendingInsertError::Journal(error));
            }
        };
        if rows
            .iter()
            .any(|old| old.matches_request(&row.holder, row.request_length, row.request_digest))
        {
            let denied: Result<(), JournalError> = Err(JournalError::Conflict);
            let floor = session.high_water;
            session.finish_error(&denied, clock).await?;
            // Error cleanup may observe a failed/rolled-back clock. Native's
            // adapter is sticky: do not replace that failure with a recoverable
            // marker and then silently start a fresh clock during fallback.
            now(clock, floor)?;
            return Err(PendingInsertError::RetainedRequest);
        }
        let result = async {
            // Random challenge/session/nonce collisions remain generic errors.
            if session.get(row.id).await?.is_some() {
                return Err(JournalError::Conflict);
            }
            session.capacity(&row).await?;
            session.put(&row).await?;
            session
                .export(row, ExportStage::Pending, guard, clock)
                .await?;
            Ok(StoredChallenge {
                challenge: c.clone(),
            })
        }
        .await;
        session.finish_export(&result, guard, clock).await?;
        result.map_err(PendingInsertError::Journal)
    }
    /// No authority owners may be held here. Every retained state participates;
    /// only one exact Pending match can be returned as an UNTRUSTED lookup ID.
    /// Pruning at original expiry bounds deduplication to retained rows.
    pub(crate) async fn retained_request_id(
        &self,
        holder: &str,
        raw: &[u8],
        clock: &impl Clock,
    ) -> Result<Option<[u8; 32]>, JournalError> {
        if holder.is_empty() || holder.len() > 128 || raw.is_empty() || raw.len() > 2_097_152 {
            return Err(JournalError::Invalid);
        }
        let mut session = self.session(clock).await?;
        let result = async {
            let rows = session.audit().await?;
            let digest = hash(raw);
            let mut matching = rows
                .iter()
                .filter(|row| row.matches_request(holder, raw.len() as u64, digest));
            let first = matching.next();
            if matching.next().is_some() {
                return Err(JournalError::Conflict);
            }
            let id = if let Some(row) = first {
                if row.state != PENDING {
                    return Err(JournalError::Rejected);
                }
                if row.body != raw {
                    return Err(JournalError::Conflict);
                }
                Some(row.id)
            } else {
                None
            };
            session.clock(clock)?;
            session.commit().await?;
            Ok(id)
        }
        .await;
        session.finish_error(&result, clock).await?;
        result
    }
    /// No authority owners may be held during this bounded untrusted lookup.
    /// Unlike issue's Pending-only lookup, explicit resume accepts exactly one
    /// Pending or Completed row. Missing, tombstoned and ambiguous matches deny;
    /// it never inserts a row or selects fresh randomness/window/authority.
    pub(crate) async fn retained_resumable_request_id(
        &self,
        holder: &str,
        raw: &[u8],
        clock: &impl Clock,
    ) -> Result<[u8; 32], JournalError> {
        if holder.is_empty() || holder.len() > 128 || raw.is_empty() || raw.len() > 2_097_152 {
            return Err(JournalError::Invalid);
        }
        let mut session = self.session(clock).await?;
        let result = async {
            let rows = session.audit().await?;
            let digest = hash(raw);
            let mut matching = rows
                .iter()
                .filter(|row| row.matches_request(holder, raw.len() as u64, digest));
            let row = matching.next().ok_or(JournalError::Missing)?;
            if matching.next().is_some() {
                return Err(JournalError::Conflict);
            }
            if row.state == TOMBSTONE {
                return Err(JournalError::Rejected);
            }
            if row.challenge()?.request_bytes != raw {
                return Err(JournalError::Conflict);
            }
            let id = row.id;
            session.clock(clock)?;
            session.commit().await?;
            Ok(id)
        }
        .await;
        session.finish_error(&result, clock).await?;
        result
    }
    /// Final Native recovery rechecks request uniqueness after acquiring all
    /// actual owners and the journal lock. An earlier lookup cannot pin a winner
    /// if a legacy writer has introduced an ambiguous retained request.
    pub(crate) async fn pending_unique(
        &self,
        id: [u8; 32],
        guard: &mut impl AuthorityGuard,
        clock: &impl Clock,
    ) -> Result<StoredChallenge, JournalError> {
        let mut session = self.session(clock).await?;
        let result = async {
            let row = session.get(id).await?.ok_or(JournalError::Missing)?;
            if row.state != PENDING {
                return Err(JournalError::Rejected);
            }
            let rows = session.audit().await?;
            if rows
                .iter()
                .filter(|other| {
                    other.matches_request(&row.holder, row.request_length, row.request_digest)
                })
                .count()
                != 1
            {
                return Err(JournalError::Conflict);
            }
            let challenge = row.challenge()?;
            session
                .export(row, ExportStage::Pending, guard, clock)
                .await?;
            Ok(StoredChallenge { challenge })
        }
        .await;
        session.finish_export(&result, guard, clock).await?;
        result
    }
    /// Inspect before acquiring the authority owners. This returns untrusted
    /// data only and closes storage/releases the journal lock. Recovery must
    /// reacquire Wallet -> Native -> key -> journal, authenticate all fields,
    /// and repeat exact row/current-state checks through `pending` before export.
    pub(crate) async fn retained_pending(
        &self,
        id: [u8; 32],
        clock: &impl Clock,
    ) -> Result<RetainedPending, JournalError> {
        let mut session = self.session(clock).await?;
        let result = async {
            let row = session.get(id).await?.ok_or(JournalError::Missing)?;
            if row.state != PENDING {
                return Err(JournalError::Rejected);
            }
            let retained = RetainedPending {
                challenge: row.challenge()?,
                evidence: row.evidence,
                lineage: row.lineage,
            };
            session.clock(clock)?;
            session.commit().await?;
            Ok(retained)
        }
        .await;
        session.finish_error(&result, clock).await?;
        result
    }
    pub async fn pending(
        &self,
        id: [u8; 32],
        guard: &mut impl AuthorityGuard,
        clock: &impl Clock,
    ) -> Result<StoredChallenge, JournalError> {
        let mut s = self.session(clock).await?;
        let result = async {
            let row = s.get(id).await?.ok_or(JournalError::Missing)?;
            if row.state != PENDING {
                return Err(JournalError::Rejected);
            }
            let challenge = row.challenge()?;
            s.export(row, ExportStage::Pending, guard, clock).await?;
            Ok(StoredChallenge { challenge })
        }
        .await;
        s.finish_export(&result, guard, clock).await?;
        result
    }
    // Private producer inspection. No authority is conferred by this data; the
    // selected row and uniqueness are checked again under the final export lock.
    pub(crate) async fn retained_completion_basis(
        &self,
        id: [u8; 32],
        clock: &impl Clock,
    ) -> Result<RetainedCompletionBasis, JournalError> {
        let mut s = self.session(clock).await?;
        let result = async {
            let row = s.get(id).await?.ok_or(JournalError::Missing)?;
            if row.state == TOMBSTONE {
                return Err(JournalError::Rejected);
            }
            s.require_unique_request(&row).await?;
            let completion = (row.state == COMPLETED).then(|| row.completion());
            let basis = RetainedCompletionBasis {
                challenge: row.challenge()?,
                evidence: row.evidence,
                lineage: row.lineage,
                completion,
            };
            s.clock(clock)?;
            s.commit().await?;
            Ok(basis)
        }
        .await;
        s.finish_error(&result, clock).await?;
        result
    }
    pub(crate) async fn complete_unique(
        &self,
        id: [u8; 32],
        packet: &[u8],
        context: &[u8],
        times: IssuanceTimes,
        guard: &mut impl AuthorityGuard,
        clock: &impl Clock,
    ) -> Result<StoredCompletion, JournalError> {
        self.complete_inner(id, packet, context, times, guard, clock, true)
            .await
    }
    pub async fn complete(
        &self,
        id: [u8; 32],
        packet: &[u8],
        context: &[u8],
        times: IssuanceTimes,
        guard: &mut impl AuthorityGuard,
        clock: &impl Clock,
    ) -> Result<StoredCompletion, JournalError> {
        self.complete_inner(id, packet, context, times, guard, clock, false)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn complete_inner(
        &self,
        id: [u8; 32],
        packet: &[u8],
        context: &[u8],
        times: IssuanceTimes,
        guard: &mut impl AuthorityGuard,
        clock: &impl Clock,
        unique: bool,
    ) -> Result<StoredCompletion, JournalError> {
        if packet.len() > 2_097_152 + 16_384 + 69
            || context.is_empty()
            || context.len() > CONTEXT_LIMIT
        {
            return Err(JournalError::Invalid);
        }
        let mut s = self.session(clock).await?;
        let result = async {
            let mut row = s.get(id).await?.ok_or(JournalError::Missing)?;
            if unique {
                s.require_unique_request(&row).await?;
            }
            if row.state == TOMBSTONE {
                return Err(JournalError::Rejected);
            }
            if row.state == COMPLETED {
                if row.body != packet
                    || row.context != context
                    || row.signed_at != times.context_signed_at
                    || row.holder_verified_at != times.holder_verified_at
                {
                    return Err(JournalError::Conflict);
                }
            } else {
                let p: ZenithPacket = decode(packet, 2_097_152 + 16_384 + 69)?;
                row.state = COMPLETED;
                row.body = packet.to_vec();
                row.context = context.to_vec();
                row.signed_at = times.context_signed_at;
                row.holder_verified_at = times.holder_verified_at;
                if row.signed_at > s.clock(clock)? {
                    return Err(JournalError::Invalid);
                }
                row.packet_digest = hash(packet);
                row.proof_digest = hash(&p.proof);
                row.context_digest = hash(context);
                row.validate().map_err(|_| JournalError::Conflict)?;
                s.capacity(&row).await?;
                s.put(&row).await?;
            }
            let output = row.completion();
            s.export(row, ExportStage::Complete, guard, clock).await?;
            Ok(output)
        }
        .await;
        s.finish_export(&result, guard, clock).await?;
        result
    }
    pub(crate) async fn cached_unique(
        &self,
        id: [u8; 32],
        proof: &[u8],
        request: &[u8],
        guard: &mut impl AuthorityGuard,
        clock: &impl Clock,
    ) -> Result<StoredCompletion, JournalError> {
        self.cached_inner(id, proof, request, guard, clock, true)
            .await
    }
    pub async fn cached(
        &self,
        id: [u8; 32],
        proof: &[u8],
        request: &[u8],
        guard: &mut impl AuthorityGuard,
        clock: &impl Clock,
    ) -> Result<StoredCompletion, JournalError> {
        self.cached_inner(id, proof, request, guard, clock, false)
            .await
    }
    async fn cached_inner(
        &self,
        id: [u8; 32],
        proof: &[u8],
        request: &[u8],
        guard: &mut impl AuthorityGuard,
        clock: &impl Clock,
        unique: bool,
    ) -> Result<StoredCompletion, JournalError> {
        if proof.len() > METADATA_LIMIT || request.len() > 2_097_152 {
            return Err(JournalError::Invalid);
        }
        let mut s = self.session(clock).await?;
        let result = async {
            let row = s.get(id).await?.ok_or(JournalError::Missing)?;
            if unique {
                s.require_unique_request(&row).await?;
            }
            if row.state != COMPLETED {
                return Err(JournalError::Rejected);
            }
            let p = row.packet()?;
            if p.proof != proof || p.encrypted_payload != request {
                return Err(JournalError::Conflict);
            }
            let output = row.completion();
            s.export(row, ExportStage::Cached, guard, clock).await?;
            Ok(output)
        }
        .await;
        s.finish_export(&result, guard, clock).await?;
        result
    }
    /// Negative-only cleanup after actual authority acquisition/checks fail.
    /// Never reject a different concurrent row or turn a conflict into export.
    pub(crate) async fn reject_cached_exact(
        &self,
        id: [u8; 32],
        expected: &StoredCompletion,
        clock: &impl Clock,
    ) -> Result<(), JournalError> {
        let mut s = self.session(clock).await?;
        let result = async {
            let mut row = s.get(id).await?.ok_or(JournalError::Missing)?;
            if row.state == TOMBSTONE
                && row.packet_digest == hash(&expected.packet)
                && row.context_digest == hash(&expected.context)
                && row.signed_at == expected.signed_at
                && row.holder_verified_at == expected.holder_verified_at
            {
                s.clock(clock)?;
                return s.commit().await;
            }
            if row.state != COMPLETED || row.completion() != *expected {
                return Err(JournalError::Conflict);
            }
            row.reject();
            s.put(&row).await?;
            s.clock(clock)?;
            s.commit().await
        }
        .await;
        s.finish_error(&result, clock).await?;
        result
    }
    pub async fn reject(&self, id: [u8; 32], clock: &impl Clock) -> Result<(), JournalError> {
        let mut s = self.session(clock).await?;
        let result = async {
            let mut row = s.get(id).await?.ok_or(JournalError::Missing)?;
            row.reject();
            s.put(&row).await?;
            s.clock(clock)?;
            s.commit().await
        }
        .await;
        s.finish_error(&result, clock).await?;
        result
    }
}

fn totals(rows: &[Record], holder: Option<&str>) -> Result<Stats, JournalError> {
    let mut stats = Stats::default();
    for row in rows
        .iter()
        .filter(|r| holder.is_none_or(|id| r.holder == id))
    {
        stats.rows += 1;
        stats.pending += u64::from(row.state == PENDING);
        stats.completed += u64::from(row.state == COMPLETED);
        stats.tombstones += u64::from(row.state == TOMBSTONE);
        stats.accounted_bytes = stats
            .accounted_bytes
            .checked_add(row.accounted()?)
            .ok_or(JournalError::Corrupt)?;
        stats.request_bytes = stats
            .request_bytes
            .checked_add(row.request_bytes())
            .ok_or(JournalError::Corrupt)?;
    }
    Ok(stats)
}
struct Session<'a> {
    journal: &'a Journal,
    conn: SqliteConnection,
    _lock: Lock,
    high_water: u64,
    exported: Option<(Record, ExportStage)>,
}
impl Session<'_> {
    fn clock(&mut self, clock: &impl Clock) -> Result<u64, JournalError> {
        self.high_water = now(clock, self.high_water)?;
        Ok(self.high_water)
    }
    async fn begin(&mut self) -> Result<(), JournalError> {
        self._lock.validate(self.journal)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut self.conn)
            .await
            .map_err(storage)?;
        Ok(())
    }
    async fn commit(&mut self) -> Result<(), JournalError> {
        self._lock.validate(self.journal)?;
        sqlx::query("UPDATE service_challenge_meta_v1 SET high_water=? WHERE id=1")
            .bind(self.high_water as i64)
            .execute(&mut self.conn)
            .await
            .map_err(storage)?;
        sqlx::query("COMMIT")
            .execute(&mut self.conn)
            .await
            .map_err(storage)?;
        self.journal.checkpoint(&mut self.conn).await
    }
    async fn audit(&mut self) -> Result<Vec<Record>, JournalError> {
        // Aggregate bounds are checked before loading any potentially corrupt blob.
        let q=sqlx::query("SELECT count(*),coalesce(sum(length(record)),0),coalesce(max(length(record)),0),coalesce(max(length(holder)),0) FROM service_challenges_v1").fetch_one(&mut self.conn).await.map_err(|_|JournalError::Corrupt)?;
        if q.get::<i64, _>(0) > 256
            || q.get::<i64, _>(1) > 32 << 20
            || q.get::<i64, _>(2) > ROW_LIMIT as i64
            || q.get::<i64, _>(3) > 128
        {
            return Err(JournalError::Corrupt);
        }
        let sql=sqlx::query("SELECT id,holder,session,nonce,expires,state,accounted,request_bytes,record,digest FROM service_challenges_v1").fetch_all(&mut self.conn).await.map_err(|_|JournalError::Corrupt)?;
        let mut records = Vec::with_capacity(sql.len());
        for row in sql {
            let bytes: Vec<u8> = row.try_get("record").map_err(|_| JournalError::Corrupt)?;
            let digest: Vec<u8> = row.try_get("digest").map_err(|_| JournalError::Corrupt)?;
            if hash(&bytes).as_slice() != digest {
                return Err(JournalError::Corrupt);
            }
            let r: Record = decode(&bytes, ROW_LIMIT)?;
            r.validate()?;
            if r.retained()? != bytes.len() as u64 + 124 + r.holder.len() as u64 {
                return Err(JournalError::Corrupt);
            }
            if row
                .try_get::<Vec<u8>, _>("id")
                .map_err(|_| JournalError::Corrupt)?
                != r.id
                || row
                    .try_get::<String, _>("holder")
                    .map_err(|_| JournalError::Corrupt)?
                    != r.holder
                || row
                    .try_get::<Vec<u8>, _>("session")
                    .map_err(|_| JournalError::Corrupt)?
                    != r.session
                || row
                    .try_get::<Vec<u8>, _>("nonce")
                    .map_err(|_| JournalError::Corrupt)?
                    != r.nonce
                || row
                    .try_get::<i64, _>("expires")
                    .map_err(|_| JournalError::Corrupt)?
                    != r.expires as i64
                || row
                    .try_get::<i64, _>("state")
                    .map_err(|_| JournalError::Corrupt)?
                    != r.state as i64
                || row
                    .try_get::<i64, _>("accounted")
                    .map_err(|_| JournalError::Corrupt)?
                    != r.accounted()? as i64
                || row
                    .try_get::<i64, _>("request_bytes")
                    .map_err(|_| JournalError::Corrupt)?
                    != r.request_bytes() as i64
            {
                return Err(JournalError::Corrupt);
            }
            records.push(r);
        }
        self.check_limits(&records, &Limits::default())?;
        Ok(records)
    }
    fn check_limits(&self, rows: &[Record], limits: &Limits) -> Result<(), JournalError> {
        let global = totals(rows, None)?;
        if global.rows > limits.rows_global
            || global.pending > limits.pending_global
            || global.accounted_bytes > limits.bytes_global
            || global.request_bytes > limits.request_bytes_global
        {
            return Err(JournalError::Capacity);
        }
        let mut holders = std::collections::BTreeMap::<&str, (u64, u64, u64)>::new();
        for row in rows {
            let h = holders.entry(&row.holder).or_default();
            h.0 += 1;
            h.1 += u64::from(row.state == PENDING);
            h.2 += row.accounted()?;
            if h.0 > limits.rows_per_holder
                || h.1 > limits.pending_per_holder
                || h.2 > limits.bytes_per_holder
            {
                return Err(JournalError::Capacity);
            }
        }
        Ok(())
    }
    async fn capacity(&mut self, row: &Record) -> Result<(), JournalError> {
        let mut records = self.audit().await?;
        records.retain(|old| old.id != row.id);
        records.push(row.clone());
        self.check_limits(&records, &self.journal.limits)
    }
    async fn require_unique_request(&mut self, row: &Record) -> Result<(), JournalError> {
        if self
            .audit()
            .await?
            .iter()
            .filter(|r| r.matches_request(&row.holder, row.request_length, row.request_digest))
            .count()
            != 1
        {
            return Err(JournalError::Conflict);
        }
        Ok(())
    }
    async fn get(&mut self, id: [u8; 32]) -> Result<Option<Record>, JournalError> {
        Ok(self.audit().await?.into_iter().find(|r| r.id == id))
    }
    async fn put(&mut self, row: &Record) -> Result<(), JournalError> {
        row.validate()?;
        let bytes = row.bytes()?;
        let digest = hash(&bytes);
        if row.retained()? != bytes.len() as u64 + 124 + row.holder.len() as u64 {
            return Err(JournalError::Corrupt);
        }
        sqlx::query("INSERT INTO service_challenges_v1(id,holder,session,nonce,expires,state,accounted,request_bytes,record,digest) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,accounted=excluded.accounted,request_bytes=excluded.request_bytes,record=excluded.record,digest=excluded.digest")
            .bind(row.id.as_slice()).bind(&row.holder).bind(row.session.as_slice()).bind(row.nonce.as_slice()).bind(row.expires as i64).bind(row.state as i64).bind(row.accounted()? as i64).bind(row.request_bytes() as i64).bind(bytes).bind(digest.as_slice()).execute(&mut self.conn).await.map_err(|e|if e.as_database_error().is_some_and(|e|e.is_unique_violation()){JournalError::Conflict}else{JournalError::Storage})?;
        Ok(())
    }
    fn guard(
        &mut self,
        row: &Record,
        stage: ExportStage,
        guard: &mut impl AuthorityGuard,
        clock: &impl Clock,
    ) -> Result<(), JournalError> {
        self._lock.validate(self.journal)?;
        current_guard(row, stage, guard, clock, &mut self.high_water)
    }
    async fn export(
        &mut self,
        mut row: Record,
        stage: ExportStage,
        guard: &mut impl AuthorityGuard,
        clock: &impl Clock,
    ) -> Result<(), JournalError> {
        if let Err(error) = self.guard(&row, stage, guard, clock) {
            row.reject();
            self.put(&row).await?;
            self.commit().await?;
            return Err(error);
        }
        self.commit().await?; // Exact bytes/reservation durable before any export.
                              // A guard may block and COMMIT/checkpoint may cross the deadline. Repeat
                              // the full current guard after durability; persist every observed clock.
                              // Export only at a clock equal to the durable floor. Continuously moving
                              // clocks deny after three attempts instead of spinning or extending TTL.
        for _ in 0..3 {
            self.begin().await?;
            if let Err(error) = self.guard(&row, stage, guard, clock) {
                row.reject();
                self.put(&row).await?;
                self.commit().await?;
                return Err(error);
            }
            self.commit().await?;
            let sampled = now(clock, self.high_water)?;
            if sampled == self.high_water {
                self.exported = Some((row, stage));
                return Ok(());
            }
            self.high_water = sampled;
            if sampled >= row.expires {
                self.begin().await?;
                row.reject();
                self.put(&row).await?;
                self.commit().await?;
                return Err(JournalError::Expired);
            }
        }
        self.begin().await?;
        row.reject();
        self.put(&row).await?;
        self.commit().await?;
        Err(JournalError::Busy)
    }
    async fn finish_export<T>(
        mut self,
        result: &Result<T, JournalError>,
        guard: &mut impl AuthorityGuard,
        clock: &impl Clock,
    ) -> Result<(), JournalError> {
        if result.is_err() {
            return self.finish_error(result, clock).await;
        }
        let (mut row, stage) = self.exported.take().ok_or(JournalError::Corrupt)?;
        let journal = self.journal;
        let mut floor = self.high_water;
        self.conn.close().await.map_err(storage)?;
        // Keep the OS file lock until the final admission returns. This code
        // performs binding checks before each full owner guard and final clock;
        // no filesystem work follows successful final admission.
        let held_lock = self._lock;
        #[cfg(test)]
        if let Some(hook) = &journal.after_close {
            hook();
        }
        for attempt in 0..3 {
            let mut observed = floor;
            let current = held_lock
                .validate(journal)
                .and_then(|()| current_guard(&row, stage, guard, clock, &mut observed));
            if current.is_ok() && observed == floor {
                return Ok(());
            }
            let denial = current
                .err()
                .or_else(|| (attempt == 2).then_some(JournalError::Busy));
            floor = observed;
            if let Some(error) = denial {
                row.reject();
                // Never replace the original denial with cleanup uncertainty.
                // A changed root/lock also prevents cleanup from touching it.
                let _cleanup = journal
                    .persist_after_close(&held_lock, Some(&row), floor)
                    .await;
                return Err(error);
            }
            // Time advanced across close/current validation. Durably record it,
            // close again, then repeat the whole current guard before export.
            journal.persist_after_close(&held_lock, None, floor).await?;
            #[cfg(test)]
            if let Some(hook) = &journal.after_close {
                hook();
            }
        }
        Err(JournalError::Busy)
    }
    async fn finish_error<T>(
        mut self,
        result: &Result<T, JournalError>,
        clock: &impl Clock,
    ) -> Result<(), JournalError> {
        let cleanup = async {
            if result.is_err() {
                // Roll back partial admission. Persist the greatest observed time in
                // a separate transaction even when a semantic error denies output.
                let _ = sqlx::query("ROLLBACK").execute(&mut self.conn).await;
                let sample = now(clock, self.high_water);
                if let Ok(value) = sample {
                    self.high_water = value;
                }
                self.begin().await?;
                self.commit().await?;
            }
            Ok(())
        }
        .await;
        // SQLite worker shutdown/checkpoint completes while the OS lock is held.
        let closed = self.conn.close().await.map_err(storage);
        #[cfg(test)]
        if let Some(hook) = &self.journal.after_close {
            hook();
        }
        cleanup.and(closed)
    }
}

// No storage work is permitted after this guard succeeds at a durable floor.
fn current_guard(
    row: &Record,
    stage: ExportStage,
    guard: &mut impl AuthorityGuard,
    clock: &impl Clock,
    floor: &mut u64,
) -> Result<(), JournalError> {
    let challenge = row.challenge()?;
    let result = guard.revalidate(GuardInput {
        stage,
        challenge: &challenge,
        evidence: &row.evidence,
        lineage: &row.lineage,
        packet: if row.state == COMPLETED {
            &row.body
        } else {
            &[]
        },
        context: &row.context,
        signed_at: row.signed_at,
        holder_verified_at: row.holder_verified_at,
    });
    *floor = now(clock, *floor)?;
    if *floor < row.issued || *floor >= row.expires {
        return Err(JournalError::Expired);
    }
    result
}
