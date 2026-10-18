//! Bounded owner-private publication under one retained native exclusive OS
//! lease. The opaque transition guard proves a durable administrative fence;
//! it grants no issuer signing, execution authority or installed admission.
use crate::{
    service_authority_snapshot::canonical,
    service_wallet_contract::{
        verify_retained_transition, NativeCas, OutcomeRecord, TargetBundle, TargetPolicy,
        TransitionMarker, WalletReference, WalletState,
    },
    service_wallet_source::{
        self as wallet, hash, hex, io_error, ObservedWallet, SourceError, WalletCurrentLease,
        WalletCurrentSource,
    },
    work_private_files as private,
};
use castalia_wallet_private_files::service_store::BorrowedPublicServiceObservation;
use libsec_core::service_holder_proof::MAX_SAFE_TIME;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};
#[path = "service_original_selection.rs"]
mod original_selection;
pub use original_selection::{
    NativeOriginalCompletedCleanupSession, NativeOriginalTempDiscardSession,
    NativeOriginalTerminalSession, NativeOriginalTransitionInspection,
    OriginalPhysicalRootIdentities, OriginalTerminalDisposition, OriginalTerminalSourceData,
    OriginalTransitionSelection, OriginalWalletSelectionData,
};
type Result<T> = std::result::Result<T, SourceError>;
const CURRENT: &str = "owner-generation.json";
const LOCK: &str = ".service-owner.lock";
const MARKER: &str = "wallet-transition.json";
const RECORDS: &str = "wallet-transition";
const TEMP: &str = ".wallet-transition.tmp";
const IMAGE: u64 = 262144;
const RECORD: u64 = 16384;
const BLOCK: u64 = 65536;
const LOGICAL: u64 = 2097152;
const ALLOCATED: u64 = 4194304;
fn invalid<T>(_: T) -> SourceError {
    SourceError::Invalid
}
fn name(s: &str) -> CString {
    CString::new(s).expect("fixed closed filename")
}
fn id(f: &File) -> Result<(u64, u64)> {
    let m = f.metadata().map_err(io_error)?;
    Ok((m.dev(), m.ino()))
}
fn charged(f: &File) -> Result<u64> {
    let m = f.metadata().map_err(io_error)?;
    m.blocks()
        .checked_mul(512)
        .map(|n| n.max(m.len()))
        .ok_or(SourceError::Capacity)
}
fn open_at(d: &File, n: &str, flags: i32) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            d.as_raw_fd(),
            name(n).as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn sync(f: &File) -> Result<()> {
    f.sync_all()
        .map_err(|_| SourceError::PublicationUncertain)?;
    #[cfg(target_os = "macos")]
    if f.metadata().map_err(io_error)?.is_file() && unsafe { libc::fcntl(f.as_raw_fd(), 51) } != 0 {
        return Err(SourceError::PublicationUncertain);
    }
    Ok(())
}
fn close(f: File) -> Result<()> {
    if unsafe { libc::close(f.into_raw_fd()) } != 0 {
        return Err(SourceError::PublicationUncertain);
    }
    Ok(())
}
fn safe(f: &File, max: u64) -> Result<()> {
    let m = f.metadata().map_err(io_error)?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || m.len() > max
        || charged(f)? > if max == 0 { 0 } else { max + BLOCK }
    {
        return Err(SourceError::UnsafeStorage);
    }
    private::access(f, false).map_err(io_error)
}
fn list(d: &File, max: usize) -> Result<Vec<String>> {
    let f = open_at(d, ".", libc::O_RDONLY | libc::O_DIRECTORY)?;
    let fd = f.into_raw_fd();
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        unsafe { libc::close(fd) };
        return Err(SourceError::UnsafeStorage);
    }
    let result = (|| {
        let mut out = Vec::new();
        loop {
            #[cfg(target_os = "macos")]
            unsafe {
                *libc::__error() = 0;
            }
            #[cfg(target_os = "linux")]
            unsafe {
                *libc::__errno_location() = 0;
            }
            let ent = unsafe { libc::readdir(dir) };
            if ent.is_null() {
                if std::io::Error::last_os_error().raw_os_error() != Some(0) {
                    return Err(SourceError::UnsafeStorage);
                }
                break;
            }
            let s = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }
                .to_str()
                .map_err(invalid)?;
            if s == "." || s == ".." {
                continue;
            }
            if out.len() >= max {
                return Err(SourceError::Capacity);
            }
            out.push(s.to_owned());
        }
        out.sort();
        Ok(out)
    })();
    if unsafe { libc::closedir(dir) } != 0 {
        return Err(SourceError::PublicationUncertain);
    }
    result
}
fn local_filesystem(d: &File) -> Result<()> {
    #[cfg(target_os = "macos")]
    unsafe {
        let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if libc::fstatfs(d.as_raw_fd(), info.as_mut_ptr()) != 0
            || info.assume_init().f_flags & 0x1000 == 0
        {
            return Err(SourceError::UnsafeStorage);
        }
    }
    #[cfg(target_os = "linux")]
    unsafe {
        let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if libc::fstatfs(d.as_raw_fd(), info.as_mut_ptr()) != 0
            || !matches!(
                info.assume_init().f_type as u64,
                0xef53 | 0x58465342 | 0x9123683e | 0x01021994
            )
        {
            return Err(SourceError::UnsafeStorage);
        }
    }
    Ok(())
}
fn directory(d: &File) -> Result<()> {
    let m = d.metadata().map_err(io_error)?;
    if !m.is_dir()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != 0o700
        || charged(d)? > BLOCK
    {
        return Err(SourceError::UnsafeStorage);
    }
    local_filesystem(d)?;
    private::access(d, true).map_err(io_error)
}
fn unlink(d: &File, n: &str, dir: bool) -> Result<()> {
    if unsafe {
        libc::unlinkat(
            d.as_raw_fd(),
            name(n).as_ptr(),
            if dir { libc::AT_REMOVEDIR } else { 0 },
        )
    } != 0
    {
        return Err(SourceError::PublicationUncertain);
    }
    checkpoint(&format!("unlinked_before_sync:{n}"))?;
    sync(d)?;
    checkpoint(&format!("unlinked_synced:{n}"))?;
    Ok(())
}
fn rename(from: &File, n: &str, to: &File, target: &str, replace: bool) -> Result<()> {
    #[cfg(target_os = "macos")]
    let rc = unsafe {
        unsafe extern "C" {
            fn renameatx_np(
                a: i32,
                b: *const libc::c_char,
                c: i32,
                d: *const libc::c_char,
                flags: libc::c_uint,
            ) -> i32;
        }
        renameatx_np(
            from.as_raw_fd(),
            name(n).as_ptr(),
            to.as_raw_fd(),
            name(target).as_ptr(),
            if replace { 0 } else { 4 },
        )
    };
    #[cfg(target_os = "linux")]
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            from.as_raw_fd(),
            name(n).as_ptr(),
            to.as_raw_fd(),
            name(target).as_ptr(),
            if replace { 0 } else { 1 },
        )
    };
    if rc != 0 {
        return Err(SourceError::PublicationUncertain);
    }
    checkpoint(&format!("renamed_before_sync:{target}"))?;
    sync(from)?;
    checkpoint(&format!("renamed_root_synced:{target}"))?;
    sync(to)
}
fn bound(n: &str, records: bool) -> Result<u64> {
    match (records, n) {
        (false, CURRENT | TEMP) => Ok(IMAGE),
        (false, LOCK) => Ok(0),
        (false, MARKER) => Ok(RECORD),
        (
            true,
            "OLD-NATIVE.json"
            | "TARGET-POLICY.json"
            | "REQUEST-OWNER-INPUT.json"
            | "TARGET-NATIVE.json",
        ) => Ok(IMAGE),
        (true, "OUTCOME.json") => Ok(RECORD),
        (true, "OLD-WALLET-STATE.json") => Ok(4096),
        _ => Err(SourceError::UnsafeStorage),
    }
}
struct NativeFiles {
    path: PathBuf,
    directory: private::Directory,
    identity: (u64, u64),
}
impl NativeFiles {
    fn open(path: &Path) -> Result<Self> {
        let directory = private::Directory::open(path).map_err(io_error)?;
        directory_check(&directory)?;
        let identity = id(directory.descriptor())?;
        Ok(Self {
            path: path.into(),
            directory,
            identity,
        })
    }
    fn root(&self) -> &File {
        self.directory.descriptor()
    }
    fn validate_root(&self) -> Result<()> {
        let fresh = private::Directory::open(&self.path).map_err(io_error)?;
        directory_check(&fresh)?;
        if id(fresh.descriptor())? != self.identity {
            return Err(SourceError::Changed);
        }
        Ok(())
    }
    fn records(&self) -> Result<File> {
        let f = open_at(self.root(), RECORDS, libc::O_RDONLY | libc::O_DIRECTORY)?;
        directory(&f)?;
        Ok(f)
    }
    fn inspect(&self) -> Result<(u64, u64)> {
        self.validate_root()?;
        let (mut logical, mut allocation) = (0, charged(self.root())?);
        for n in list(self.root(), 5)? {
            if n == RECORDS {
                let d = self.records()?;
                allocation = allocation
                    .checked_add(charged(&d)?)
                    .ok_or(SourceError::Capacity)?;
                for n in list(&d, 6)? {
                    let f = open_at(&d, &n, libc::O_RDONLY)?;
                    safe(&f, bound(&n, true)?)?;
                    logical += f.metadata().map_err(io_error)?.len();
                    allocation += charged(&f)?;
                }
            } else {
                let f = open_at(self.root(), &n, libc::O_RDONLY)?;
                safe(&f, bound(&n, false)?)?;
                logical += f.metadata().map_err(io_error)?.len();
                allocation += charged(&f)?;
            }
        }
        if logical > LOGICAL || allocation > ALLOCATED {
            return Err(SourceError::Capacity);
        }
        Ok((logical, allocation))
    }
    fn read(&self, n: &str, records: bool) -> Result<Vec<u8>> {
        self.validate_root()?;
        let parent = if records { Some(self.records()?) } else { None };
        let d = parent.as_ref().unwrap_or(self.root());
        let mut f = open_at(d, n, libc::O_RDONLY)?;
        let max = bound(n, records)?;
        safe(&f, max)?;
        let before = f.metadata().map_err(io_error)?;
        let mut bytes = Vec::with_capacity(before.len() as usize);
        (&mut f)
            .take(max + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        let after = f.metadata().map_err(io_error)?;
        let fresh = open_at(d, n, libc::O_RDONLY)?;
        safe(&fresh, max)?;
        if identity_metadata(&before) != identity_metadata(&after)
            || identity_metadata(&after) != identity_metadata(&fresh.metadata().map_err(io_error)?)
            || bytes.len() as u64 != before.len()
        {
            return Err(SourceError::Changed);
        }
        close(f)?;
        close(fresh)?;
        self.validate_root()?;
        Ok(bytes)
    }
    fn exists(&self, n: &str, records: bool) -> Result<bool> {
        let parent = if records { Some(self.records()?) } else { None };
        let d = parent.as_ref().unwrap_or(self.root());
        match open_at(d, n, libc::O_RDONLY) {
            Ok(f) => {
                safe(&f, bound(n, records)?)?;
                Ok(true)
            }
            Err(SourceError::UnsafeStorage) => {
                let mut s = std::mem::MaybeUninit::<libc::stat>::uninit();
                let rc = unsafe {
                    libc::fstatat(
                        d.as_raw_fd(),
                        name(n).as_ptr(),
                        s.as_mut_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if rc != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                    Ok(false)
                } else {
                    Err(SourceError::UnsafeStorage)
                }
            }
            Err(e) => Err(e),
        }
    }
    fn make_records(&self) -> Result<()> {
        if unsafe { libc::mkdirat(self.root().as_raw_fd(), name(RECORDS).as_ptr(), 0o700) } != 0 {
            return Err(SourceError::TransitionPending);
        }
        sync(self.root())?;
        directory(&self.records()?)
    }
    fn write(&self, n: &str, records: bool, bytes: &[u8], replace: bool) -> Result<()> {
        if bytes.len() as u64 > bound(n, records)? {
            return Err(SourceError::Capacity);
        }
        if !replace && self.exists(n, records)? {
            if self.read(n, records)? == bytes {
                let parent = if records { Some(self.records()?) } else { None };
                let d = parent.as_ref().unwrap_or(self.root());
                let f = open_at(d, n, libc::O_RDONLY)?;
                safe(&f, bound(n, records)?)?;
                sync(&f)?;
                close(f)?;
                sync(d)?;
                sync(self.root())?;
                if self.read(n, records)? != bytes {
                    return Err(SourceError::Changed);
                }
                return Ok(());
            }
            return Err(SourceError::Changed);
        }
        let (logical, allocated) = self.inspect()?;
        if logical + bytes.len() as u64 > LOGICAL
            || allocated + bytes.len() as u64 + BLOCK > ALLOCATED
        {
            return Err(SourceError::Capacity);
        }
        let mut f = open_at(
            self.root(),
            TEMP,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        safe(&f, IMAGE)?;
        f.write_all(bytes)
            .map_err(|_| SourceError::PublicationUncertain)?;
        checkpoint("temp_written")?;
        checkpoint(&format!("temp_written:{n}"))?;
        sync(&f)?;
        checkpoint("temp_synced")?;
        checkpoint(&format!("temp_synced:{n}"))?;
        safe(&f, IMAGE)?;
        close(f)?;
        checkpoint("temp_closed")?;
        checkpoint(&format!("temp_closed:{n}"))?;
        self.inspect()?;
        let parent = if records { Some(self.records()?) } else { None };
        rename(
            self.root(),
            TEMP,
            parent.as_ref().unwrap_or(self.root()),
            n,
            replace,
        )?;
        checkpoint(n)?;
        if self.read(n, records)? != bytes {
            return Err(SourceError::Changed);
        }
        self.inspect()?;
        Ok(())
    }
}
fn directory_check(d: &private::Directory) -> Result<()> {
    directory(d.descriptor())
}
fn identity_metadata(m: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
type Floors = Mutex<BTreeMap<(u64, u64), Weak<Mutex<u64>>>>;
fn floor(root: (u64, u64)) -> Result<Arc<Mutex<u64>>> {
    static F: OnceLock<Floors> = OnceLock::new();
    let mut all = F
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| SourceError::Clock)?;
    all.retain(|_, v| v.strong_count() > 0);
    if let Some(v) = all.get(&root).and_then(Weak::upgrade) {
        return Ok(v);
    }
    if all.len() >= 128 {
        return Err(SourceError::Capacity);
    }
    let f = Arc::new(Mutex::new(0));
    all.insert(root, Arc::downgrade(&f));
    Ok(f)
}

/// Independent native startup CAS. It is never selected by transition records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerStartupPin {
    generation: u64,
    sha256: [u8; 32],
}
impl OwnerStartupPin {
    pub fn new(generation: u64, sha256: [u8; 32]) -> Result<Self> {
        if generation == 0 || generation > MAX_SAFE_TIME || sha256 == [0; 32] {
            return Err(SourceError::Invalid);
        }
        Ok(Self { generation, sha256 })
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    fn value(&self) -> Value {
        json!({"generation":self.generation,"bundle_sha256":hex(&self.sha256)})
    }
}
/// A privileged selected Native owner root. No key/issuer loading occurs here.
pub struct OwnerPublicationSource {
    files: NativeFiles,
    floor: Arc<Mutex<u64>>,
}
impl OwnerPublicationSource {
    /// Explicit first publication into an empty owner-selected root. The bundle
    /// must be canonical generation1, finite/current and tied to the actual
    /// independently selected Wallet observation. No current file is replaced;
    /// partial publication is preserved for explicit diagnosis, never reset.
    /// The returned public pin is startup configuration data, not authority.
    pub fn create_initial(
        root: &Path,
        wallet: &WalletCurrentSource,
        raw: &[u8],
    ) -> Result<OwnerStartupPin> {
        let held_wallet = wallet.capture_shared()?;
        let bundle = TargetBundle::parse(raw).map_err(invalid)?;
        if bundle.value["generation"] != 1
            || canonical(&bundle.value["wallet_current"]) != held_wallet.reference_bytes()
        {
            return Err(SourceError::Changed);
        }
        let pin = OwnerStartupPin::new(1, bundle.digest())?;
        let now = wallet::now()?;
        if bundle.value["valid_not_before"]
            .as_u64()
            .is_none_or(|n| now < n)
            || bundle.value["valid_until"]
                .as_u64()
                .is_none_or(|n| now >= n)
        {
            return Err(SourceError::Window);
        }
        crate::service_authority_snapshot::ValidatedNativePolicy::parse(raw, pin.sha256, now)
            .map_err(invalid)?;
        let files = NativeFiles::open(root)?;
        if !list(files.root(), 1)?.is_empty() {
            return Err(SourceError::Changed);
        }
        let lock = open_at(
            files.root(),
            LOCK,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        )?;
        safe(&lock, 0)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        held_wallet.revalidate()?;
        files.inspect()?;
        if list(files.root(), 2)? != [LOCK] {
            return Err(SourceError::Changed);
        }
        sync(&lock)?;
        sync(files.root())?;
        files.write(CURRENT, false, raw, false)?;
        if files.read(CURRENT, false)? != raw
            || id(&lock)? != id(&open_at(files.root(), LOCK, libc::O_RDWR)?)?
        {
            return Err(SourceError::Changed);
        }
        held_wallet.revalidate()?;
        files.validate_root()?;
        let fresh = wallet::now()?;
        if fresh < now
            || bundle.value["valid_until"]
                .as_u64()
                .is_none_or(|end| fresh >= end)
        {
            return Err(SourceError::Window);
        }
        Ok(pin)
    }
    pub fn open_owner_selected_root(root: &Path) -> Result<Self> {
        let files = NativeFiles::open(root)?;
        let floor = floor(files.identity)?;
        files.inspect()?;
        Ok(Self { files, floor })
    }
    fn lock(&self, exclusive: bool) -> Result<File> {
        self.files.validate_root()?;
        let f = open_at(self.files.root(), LOCK, libc::O_RDWR)?;
        safe(&f, 0)?;
        if unsafe {
            libc::flock(
                f.as_raw_fd(),
                libc::LOCK_NB
                    | if exclusive {
                        libc::LOCK_EX
                    } else {
                        libc::LOCK_SH
                    },
            )
        } != 0
        {
            return Err(io_error(std::io::Error::last_os_error()));
        }
        self.files.inspect()?;
        Ok(f)
    }
    fn time(&self, durable: u64) -> Result<u64> {
        wallet::observe(&self.floor, durable)
    }
    pub fn capture_shared<'a>(
        &'a self,
        pin: OwnerStartupPin,
        wallet: &WalletCurrentLease<'_>,
    ) -> Result<NativeOwnerCurrentLease<'a>> {
        wallet.revalidate()?;
        let lock = self.lock(false)?;
        if self.files.exists(MARKER, false)?
            || list(self.files.root(), 5)?
                .iter()
                .any(|n| n == RECORDS || n == TEMP)
        {
            return Err(SourceError::TransitionPending);
        }
        let raw = self.files.read(CURRENT, false)?;
        let bundle = check_bundle(&raw, pin)?;
        if canonical(&bundle.value["wallet_current"]) != wallet.reference_bytes() {
            return Err(SourceError::Changed);
        }
        let n = self.time(wallet.observed.durable)?;
        if bundle.value["valid_not_before"]
            .as_u64()
            .is_none_or(|s| n < s)
            || bundle.value["valid_until"].as_u64().is_none_or(|e| n >= e)
        {
            return Err(SourceError::Window);
        }
        let lease = NativeOwnerCurrentLease {
            source: self,
            lock_id: id(&lock)?,
            lock,
            pin,
            bundle,
        };
        lease.revalidate()?;
        wallet.revalidate()?;
        Ok(lease)
    }
    /// Call only after custody exclusive acquisition. The concrete borrowed view
    /// proves that acquisition; it is dropped before this method returns.
    pub fn begin_administration<'s, 'w>(
        &'s self,
        pin: OwnerStartupPin,
        wallet: &'w WalletCurrentSource,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<NativeOwnerAdministrationSession<'s, 'w>> {
        let old_wallet = wallet.inspect_initial(&view)?;
        let lock = self.lock(true)?;
        if list(self.files.root(), 5)?
            .iter()
            .any(|n| n == MARKER || n == RECORDS || n == TEMP)
        {
            return Err(SourceError::TransitionPending);
        }
        let old_raw = self.files.read(CURRENT, false)?;
        let bundle = check_bundle(&old_raw, pin)?;
        if canonical(&bundle.value["wallet_current"]) != old_wallet.reference.canonical_bytes() {
            return Err(SourceError::Changed);
        }
        view.revalidate().map_err(io_error)?;
        self.time(old_wallet.durable)?;
        Ok(NativeOwnerAdministrationSession {
            source: self,
            lock_id: id(&lock)?,
            lock,
            pin,
            old_raw,
            wallet,
            old_wallet: RetainedWalletBasis::from_actual(old_wallet),
            marker: None,
            tombstone: false,
            recovering: false,
            original_selection: None,
        })
    }
    /// Recovery trusts the independent old CAS via OLD-NATIVE, then accepts the
    /// real current file only when it equals that old image or the exact retained
    /// deterministic target. No old startup digest is reopened as current.
    pub fn begin_recovery<'s, 'w>(
        &'s self,
        pin: OwnerStartupPin,
        transition_id: [u8; 16],
        wallet: &'w WalletCurrentSource,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<NativeOwnerAdministrationSession<'s, 'w>> {
        let observed = wallet.inspect_transition(&view)?;
        let lock = self.lock(true)?;
        let ordinary = self.files.exists(MARKER, false)?;
        let tombstone = self.files.exists(TEMP, false)?;
        if ordinary == tombstone {
            return Err(SourceError::TransitionPending);
        }
        let marker = TransitionMarker::parse(
            &self
                .files
                .read(if ordinary { MARKER } else { TEMP }, false)?,
        )
        .map_err(invalid)?;
        if tombstone && marker.value["stage"] != "native_published" {
            return Err(SourceError::Changed);
        }
        if marker.value["transition_id"] != hex(&transition_id)
            || marker.value["old_native_cas"] != pin.value()
        {
            return Err(SourceError::Changed);
        }
        let old_raw = self.files.read("OLD-NATIVE.json", true)?;
        check_bundle(&old_raw, pin)?;
        let old_reference =
            WalletReference::parse(&canonical(&marker.value["old_wallet_reference"]))
                .map_err(invalid)?;
        // The independently configured Wallet pin remains the trusted old anchor.
        wallet.pin_reference(&old_reference)?;
        let old_state_raw = self.files.read("OLD-WALLET-STATE.json", true)?;
        let old_state = wallet::retained_state(&old_state_raw, &old_reference)?;
        let old_wallet = RetainedWalletBasis {
            reference: old_reference,
            state: old_state,
            state_raw: old_state_raw,
            root: observed.root,
            lock: observed.lock,
            epoch: observed.epoch,
        };
        let session = NativeOwnerAdministrationSession {
            source: self,
            lock_id: id(&lock)?,
            lock,
            pin,
            old_raw,
            wallet,
            old_wallet,
            marker: Some(marker),
            tombstone,
            recovering: true,
            original_selection: None,
        };
        session.validate_records()?;
        session.revalidate()?;
        let actual = session.actual(&view)?;
        session.verify_current_transition(&actual)?;
        view.revalidate().map_err(io_error)?;
        self.time(session.started()?)?;
        Ok(session)
    }
}
// Validated retained public data only, with no observed Wallet root/lock/epoch.
struct PreparedRecoveryData {
    marker: TransitionMarker,
    old_raw: Vec<u8>,
    reference: WalletReference,
    state_raw: Vec<u8>,
    state: wallet::StateRecord,
    policy_raw: Vec<u8>,
    configure_raw: Option<Vec<u8>>,
}
impl OwnerPublicationSource {
    fn reserve_transition_capacity(&self) -> Result<()> {
        let (logical, allocated) = self.files.inspect()?;
        // Accepted complete worst-case layout, less the already selected image
        // and root directory; also reserved on restart before any new write.
        if logical
            .checked_add(1_609_728 - IMAGE)
            .is_none_or(|n| n > LOGICAL)
            || allocated
                .checked_add(2_330_624 - (IMAGE + BLOCK) - BLOCK)
                .is_none_or(|n| n > ALLOCATED)
        {
            return Err(SourceError::Capacity);
        }
        Ok(())
    }
    fn prepared_recovery_data(
        &self,
        pin: OwnerStartupPin,
        transition_id: [u8; 16],
        wallet: &WalletCurrentSource,
        lock: &File,
        lock_id: (u64, u64),
    ) -> Result<PreparedRecoveryData> {
        self.files.inspect()?;
        safe(lock, 0)?;
        let fresh = open_at(self.files.root(), LOCK, libc::O_RDONLY)?;
        safe(&fresh, 0)?;
        if id(lock)? != lock_id || id(&fresh)? != lock_id {
            return Err(SourceError::Changed);
        }
        close(fresh)?;
        if !self.files.exists(MARKER, false)? || self.files.exists(TEMP, false)? {
            return Err(SourceError::TransitionPending);
        }
        let marker = TransitionMarker::parse(&self.files.read(MARKER, false)?).map_err(invalid)?;
        if marker.value["stage"] != "prepared"
            || marker.value["transition_id"] != hex(&transition_id)
            || marker.value["old_native_cas"] != pin.value()
            || self.files.exists("OUTCOME.json", true)?
            || self.files.exists("TARGET-NATIVE.json", true)?
        {
            return Err(SourceError::Changed);
        }
        let old_raw = self.files.read("OLD-NATIVE.json", true)?;
        check_bundle(&old_raw, pin)?;
        if self.files.read(CURRENT, false)? != old_raw {
            return Err(SourceError::Changed);
        }
        let reference = WalletReference::parse(&canonical(&marker.value["old_wallet_reference"]))
            .map_err(invalid)?;
        wallet.pin_reference(&reference)?;
        let state_raw = self.files.read("OLD-WALLET-STATE.json", true)?;
        let state = wallet::retained_state(&state_raw, &reference)?;
        if marker.value["started_at"]
            .as_u64()
            .is_none_or(|n| n < state.published_at)
        {
            return Err(SourceError::Clock);
        }
        let policy_raw = self.files.read("TARGET-POLICY.json", true)?;
        let policy = TargetPolicy::parse(&policy_raw).map_err(invalid)?;
        if policy_raw.len() + 4096 + 64 > IMAGE as usize {
            return Err(SourceError::Capacity);
        }
        verify_retained_transition(&marker, &policy, &old_raw, None, None).map_err(invalid)?;
        let configure_raw = if marker.value["mutation"] == "configure" {
            let request = self.files.read("REQUEST-OWNER-INPUT.json", true)?;
            wallet::validate_transition_request(&request, &reference)?;
            if marker.value["request"]["owner_input_sha256"] != hex(&hash(&request)) {
                return Err(SourceError::Changed);
            }
            Some(request)
        } else {
            if self.files.exists("REQUEST-OWNER-INPUT.json", true)? {
                return Err(SourceError::Changed);
            }
            None
        };
        // Retained original slots are already charged. Reserve only the
        // remaining OUTCOME, TARGET and sole atomic replacement temp here.
        let (logical, allocated) = self.files.inspect()?;
        let remaining = RECORD + IMAGE + IMAGE;
        if logical.checked_add(remaining).is_none_or(|n| n > LOGICAL)
            || allocated
                .checked_add(remaining + 3 * BLOCK)
                .is_none_or(|n| n > ALLOCATED)
        {
            return Err(SourceError::Capacity);
        }
        self.time(
            marker.value["started_at"]
                .as_u64()
                .ok_or(SourceError::Invalid)?,
        )?;
        self.files.validate_root()?;
        Ok(PreparedRecoveryData {
            marker,
            old_raw,
            reference,
            state_raw,
            state,
            policy_raw,
            configure_raw,
        })
    }
    /// Native-only administration preflight. The supported Wallet coordinator
    /// already owns custody exclusive before calling this. No Wallet current
    /// observation or execution authority is claimed while poison prevents one.
    pub fn begin_wallet_recovery_preflight<'s, 'w>(
        &'s self,
        pin: OwnerStartupPin,
        transition_id: [u8; 16],
        wallet: &'w WalletCurrentSource,
    ) -> Result<NativeWalletRecoveryPreflight<'s, 'w>> {
        let lock = self.lock(true)?;
        let lock_id = id(&lock)?;
        let data = self.prepared_recovery_data(pin, transition_id, wallet, &lock, lock_id)?;
        Ok(NativeWalletRecoveryPreflight {
            source: self,
            lock,
            lock_id,
            pin,
            transition_id,
            wallet,
            data,
            original_selection: None,
        })
    }
}
/// Owns the actual Native exclusive descriptor, retaining only original Native
/// records and independent Wallet configuration until a real view is available.
pub struct NativeWalletRecoveryPreflight<'s, 'w> {
    source: &'s OwnerPublicationSource,
    lock: File,
    lock_id: (u64, u64),
    pin: OwnerStartupPin,
    transition_id: [u8; 16],
    wallet: &'w WalletCurrentSource,
    data: PreparedRecoveryData,
    original_selection: Option<OriginalTransitionSelection>,
}
impl<'s, 'w> NativeWalletRecoveryPreflight<'s, 'w> {
    /// Unqualified immutable original comparison DATA, including on an error
    /// retry. Legacy strict-ID entry points have no original-selection payload.
    pub fn original_wallet_data(&self) -> Option<OriginalWalletSelectionData<'_>> {
        self.original_selection
            .as_ref()
            .map(OriginalTransitionSelection::wallet_data)
    }
    pub fn reconciliation_fence(&self) -> Result<NativeCustodyReconciliationFence<'_, 's, 'w>> {
        self.revalidate()?;
        Ok(NativeCustodyReconciliationFence { preflight: self })
    }
    pub fn revalidate(&self) -> Result<()> {
        if let Some(original) = &self.original_selection {
            original.validate_source(self.source, self.wallet, &self.lock, self.lock_id)?;
            original.validate_full_records(self.source, &self.data.marker)?;
        }
        let data = self.source.prepared_recovery_data(
            self.pin,
            self.transition_id,
            self.wallet,
            &self.lock,
            self.lock_id,
        )?;
        if data.marker.canonical_bytes() != self.data.marker.canonical_bytes()
            || data.old_raw != self.data.old_raw
            || data.state_raw != self.data.state_raw
            || data.policy_raw != self.data.policy_raw
            || data.configure_raw != self.data.configure_raw
        {
            return Err(SourceError::Changed);
        }
        Ok(())
    }
    /// Compatibility conversion: an error consumes this object and releases its
    /// Native descriptor. Coordinators retaining a recovery interval must use
    /// [`Self::resume_with_actual_wallet_retaining`] instead.
    pub fn resume_with_actual_wallet(
        self,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<NativeOwnerAdministrationSession<'s, 'w>> {
        self.resume_with_actual_wallet_retaining(view)
            .map_err(|failure| {
                let (error, _retained) = *failure;
                error
            })
    }
    /// Move the held descriptor into full recovery only after checking an
    /// actual view. EVERY error returns this same Native-only owning preflight;
    /// it does not attest to current Wallet state or make a failed session
    /// available. Unpack an error with `let (error, preflight) = *failure`.
    /// Its fence and subsequent retries still revalidate all inputs.
    pub fn resume_with_actual_wallet_retaining(
        self,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> std::result::Result<NativeOwnerAdministrationSession<'s, 'w>, Box<(SourceError, Self)>>
    {
        if let Err(error) = self.revalidate() {
            return Err(Box::new((error, self)));
        }
        let observed = match self.wallet.inspect_transition(&view) {
            Ok(observed) => observed,
            Err(error) => return Err(Box::new((error, self))),
        };
        let Self {
            source,
            lock,
            lock_id,
            pin,
            transition_id,
            wallet,
            original_selection,
            data:
                PreparedRecoveryData {
                    marker,
                    old_raw,
                    reference,
                    state_raw,
                    state,
                    policy_raw,
                    configure_raw,
                },
        } = self;
        let session = NativeOwnerAdministrationSession {
            source,
            lock,
            lock_id,
            pin,
            old_raw,
            wallet,
            old_wallet: RetainedWalletBasis {
                reference,
                state,
                state_raw,
                root: observed.root,
                lock: observed.lock,
                epoch: observed.epoch,
            },
            marker: Some(marker),
            tombstone: false,
            recovering: true,
            original_selection,
        };
        // Every operation here borrows read-only: no record, owning File or
        // original input can be replaced before an error is reassembled below.
        let validation = (|| {
            session.revalidate()?;
            session.validate_records()?;
            session.verify_current_transition(&observed)?;
            session.actual(&view)?.equal(&observed)?;
            checkpoint("recovery_first_actual_view")
        })();
        if let Err(error) = validation {
            let NativeOwnerAdministrationSession {
                source,
                lock,
                lock_id,
                pin,
                old_raw,
                wallet,
                old_wallet,
                marker,
                original_selection,
                ..
            } = session;
            let marker = marker.expect("read-only validation preserves constructed marker");
            // Only original records/configuration and the SAME File return.
            // Discard the failed actual-view root/lock/epoch basis entirely.
            let retained = Self {
                source,
                lock,
                lock_id,
                pin,
                transition_id,
                wallet,
                original_selection,
                data: PreparedRecoveryData {
                    marker,
                    old_raw,
                    reference: old_wallet.reference,
                    state: old_wallet.state,
                    state_raw: old_wallet.state_raw,
                    policy_raw,
                    configure_raw,
                },
            };
            return Err(Box::new((error, retained)));
        }
        Ok(session)
    }
}
/// Borrowed opaque Native administration fence. All getters are unqualified
/// original-record/configuration comparison data for Wallet's real private
/// checks. They never attest to current Wallet provenance or key/seed health.
pub struct NativeCustodyReconciliationFence<'a, 's, 'w> {
    preflight: &'a NativeWalletRecoveryPreflight<'s, 'w>,
}
impl NativeCustodyReconciliationFence<'_, '_, '_> {
    pub fn revalidate(&self) -> Result<()> {
        self.preflight.revalidate()
    }
    pub fn transition_id(&self) -> [u8; 16] {
        self.preflight.transition_id
    }
    pub fn selected_wallet_root_identity(
        &self,
    ) -> castalia_wallet_private_files::service_store::Identity {
        self.preflight.original_selection.as_ref().map_or_else(
            || self.preflight.wallet.configured_root_identity(),
            |original| original.original_physical_roots().wallet_identity(),
        )
    }
    pub fn old_wallet_startup_pin_bytes(&self) -> Vec<u8> {
        self.preflight.original_selection.as_ref().map_or_else(
            || self.preflight.wallet.configured_startup_pin_bytes(),
            |original| original.startup_raw.clone(),
        )
    }
    pub fn old_wallet_reference_bytes(&self) -> &[u8] {
        self.preflight.data.reference.canonical_bytes()
    }
    pub fn old_wallet_state_bytes(&self) -> &[u8] {
        &self.preflight.data.state_raw
    }
    pub fn configure_owner_input_bytes(&self) -> Option<&[u8]> {
        self.preflight.data.configure_raw.as_deref()
    }
    pub fn mutation_kind(&self) -> WalletMutationKind {
        match self.preflight.data.marker.value["mutation"].as_str() {
            Some("configure") => WalletMutationKind::Configure,
            Some("rotate") => WalletMutationKind::Rotate,
            Some("revoke") => WalletMutationKind::Revoke,
            Some("reconcile") => WalletMutationKind::Reconcile,
            _ => unreachable!("closed validated marker mutation"),
        }
    }
    pub fn requested_rotation_window(&self) -> Option<(u64, u64)> {
        let request = &self.preflight.data.marker.value["request"];
        Some((
            request["requested_not_before"].as_u64()?,
            request["requested_not_after"].as_u64()?,
        ))
    }
}
impl<'s, 'w> NativeOwnerAdministrationSession<'s, 'w> {
    /// Compatibility conversion: an error consumes this session and releases
    /// its Native descriptor. A retained coordinator must instead use
    /// [`Self::into_wallet_recovery_preflight_retaining`].
    pub fn into_wallet_recovery_preflight(self) -> Result<NativeWalletRecoveryPreflight<'s, 'w>> {
        self.into_wallet_recovery_preflight_retaining()
            .map_err(|failure| {
                let (error, _retained) = *failure;
                error
            })
    }
    /// Move the SAME descriptor into prepared-only preflight. Every validation
    /// error returns the original session, with no Native or Wallet writes.
    /// Unpack an error with `let (error, session) = *failure`. Returning ownership
    /// makes no claim that damaged inputs are recoverable.
    pub fn into_wallet_recovery_preflight_retaining(
        self,
    ) -> std::result::Result<NativeWalletRecoveryPreflight<'s, 'w>, Box<(SourceError, Self)>> {
        let checked = (|| {
            self.revalidate()?;
            if self.tombstone {
                return Err(SourceError::TransitionPending);
            }
            let transition_id = self.transition_id()?;
            let data = self.source.prepared_recovery_data(
                self.pin,
                transition_id,
                self.wallet,
                &self.lock,
                self.lock_id,
            )?;
            Ok((transition_id, data))
        })();
        let (transition_id, data) = match checked {
            Ok(checked) => checked,
            Err(error) => return Err(Box::new((error, self))),
        };
        Ok(NativeWalletRecoveryPreflight {
            source: self.source,
            lock: self.lock,
            lock_id: self.lock_id,
            pin: self.pin,
            transition_id,
            wallet: self.wallet,
            data,
            original_selection: self.original_selection,
        })
    }
}
fn check_bundle(raw: &[u8], pin: OwnerStartupPin) -> Result<TargetBundle> {
    let b = TargetBundle::parse(raw).map_err(invalid)?;
    if b.digest() != pin.sha256 || b.value["generation"] != pin.generation {
        return Err(SourceError::Changed);
    }
    Ok(b)
}
// A retained descriptor and exact identity for the completed fixed-temp fence.
struct TombstoneWitness<'a> {
    lock: &'a File,
    lock_identity: (u64, u64),
    file: File,
    identity: (u64, u64, u64, i64, i64, i64, i64),
}
/// Acknowledges only removal of completed transition bookkeeping. No guard,
/// source lease, issuer key, grant or policy publication is returned.
pub struct CompletedWalletTransitionCleanup {
    transition_id: [u8; 16],
    removed_records: usize,
}
impl CompletedWalletTransitionCleanup {
    pub fn transition_id(&self) -> [u8; 16] {
        self.transition_id
    }
    pub fn removed_records(&self) -> usize {
        self.removed_records
    }
}
impl OwnerPublicationSource {
    fn confirm_tombstone<'a>(&self, exact: &[u8], lock: &'a File) -> Result<TombstoneWitness<'a>> {
        if self.files.exists(MARKER, false)? || self.files.read(TEMP, false)? != exact {
            return Err(SourceError::Changed);
        }
        let file = open_at(self.files.root(), TEMP, libc::O_RDONLY)?;
        safe(&file, RECORD)?;
        let witness = TombstoneWitness {
            lock,
            lock_identity: id(lock)?,
            identity: identity_metadata(&file.metadata().map_err(io_error)?),
            file,
        };
        self.revalidate_tombstone(exact, &witness)?;
        Ok(witness)
    }
    // Required on every path, including a tombstone inherited after restart,
    // before any retained record is deleted. No atomic writer can reuse TEMP.
    fn revalidate_tombstone(&self, exact: &[u8], w: &TombstoneWitness<'_>) -> Result<()> {
        self.files.inspect()?;
        safe(w.lock, 0)?;
        let held = open_at(self.files.root(), LOCK, libc::O_RDONLY)?;
        safe(&held, 0)?;
        if id(w.lock)? != w.lock_identity || id(&held)? != w.lock_identity {
            return Err(SourceError::Changed);
        }
        close(held)?;
        safe(&w.file, RECORD)?;
        sync(&w.file)?;
        sync(self.files.root())?;
        checkpoint("tombstone_root_synced")?;
        self.files.validate_root()?;
        if self.files.exists(MARKER, false)? || self.files.read(TEMP, false)? != exact {
            return Err(SourceError::Changed);
        }
        let fresh = open_at(self.files.root(), TEMP, libc::O_RDONLY)?;
        safe(&fresh, RECORD)?;
        if identity_metadata(&fresh.metadata().map_err(io_error)?) != w.identity
            || identity_metadata(&w.file.metadata().map_err(io_error)?) != w.identity
        {
            return Err(SourceError::Changed);
        }
        close(fresh)?;
        self.time(0)?;
        Ok(())
    }
    fn remaining_completed_records(
        &self,
        marker: &TransitionMarker,
        current: &[u8],
        actual_wallet: &ObservedWallet,
    ) -> Result<Vec<String>> {
        self.files.inspect()?;
        if !list(self.files.root(), 5)?.iter().any(|n| n == RECORDS) {
            return Ok(Vec::new());
        }
        let d = self.files.records()?;
        let names = list(&d, 6)?;
        close(d)?;
        for n in &names {
            bound(n, true)?;
        }
        let old_reference =
            WalletReference::parse(&canonical(&marker.value["old_wallet_reference"]))
                .map_err(invalid)?;
        if names.iter().any(|n| n == "OLD-NATIVE.json") {
            let raw = self.files.read("OLD-NATIVE.json", true)?;
            let b = TargetBundle::parse(&raw).map_err(invalid)?;
            if b.value["generation"] != marker.value["old_native_cas"]["generation"]
                || hex(&b.digest()) != marker.value["old_native_cas"]["bundle_sha256"]
                || b.value["wallet_current"] != marker.value["old_wallet_reference"]
            {
                return Err(SourceError::Changed);
            }
        }
        if names.iter().any(|n| n == "OLD-WALLET-STATE.json") {
            let raw = self.files.read("OLD-WALLET-STATE.json", true)?;
            let state = wallet::retained_state(&raw, &old_reference)?;
            compare_predecessor(
                &old_reference,
                &state,
                &raw,
                actual_wallet,
                marker.value["mutation"]
                    .as_str()
                    .ok_or(SourceError::Invalid)?,
            )?;
        }
        let policy = if names.iter().any(|n| n == "TARGET-POLICY.json") {
            let p = TargetPolicy::parse(&self.files.read("TARGET-POLICY.json", true)?)
                .map_err(invalid)?;
            marker.binding_preimage(&p).map_err(invalid)?;
            Some(p)
        } else {
            None
        };
        if names.iter().any(|n| n == "REQUEST-OWNER-INPUT.json") {
            if marker.value["mutation"] != "configure" {
                return Err(SourceError::Invalid);
            }
            let raw = self.files.read("REQUEST-OWNER-INPUT.json", true)?;
            if marker.value["request"]["owner_input_sha256"] != hex(&hash(&raw)) {
                return Err(SourceError::Changed);
            }
            wallet::validate_transition_request(&raw, &old_reference)?;
        }
        if names.iter().any(|n| n == "OUTCOME.json") {
            let raw = self.files.read("OUTCOME.json", true)?;
            let outcome = OutcomeRecord::parse(&raw).map_err(invalid)?;
            outcome.verify_marker(marker).map_err(invalid)?;
            if outcome.value["observed_at"].as_u64().is_none_or(|n| {
                n > self
                    .time(marker.value["started_at"].as_u64().unwrap_or(MAX_SAFE_TIME))
                    .unwrap_or(0)
            }) {
                return Err(SourceError::Clock);
            }
        }
        if names.iter().any(|n| n == "TARGET-NATIVE.json")
            && self.files.read("TARGET-NATIVE.json", true)? != current
        {
            return Err(SourceError::Changed);
        }
        if let Some(p) = policy {
            let cas =
                NativeCas::parse(&canonical(&marker.value["old_native_cas"])).map_err(invalid)?;
            let outcome_reference = WalletReference::parse(&canonical(
                &marker.value["observed_outcome"]["wallet_reference"],
            ))
            .map_err(invalid)?;
            if p.derive_target(&cas, &outcome_reference)
                .map_err(invalid)?
                .canonical_bytes()
                != current
            {
                return Err(SourceError::Changed);
            }
        }
        Ok(names)
    }
    fn delete_completed_records(
        &self,
        exact: &[u8],
        w: &TombstoneWitness<'_>,
        wallet: &WalletCurrentSource,
        view: &BorrowedPublicServiceObservation<'_, '_>,
        current_wallet: &ObservedWallet,
    ) -> Result<usize> {
        self.revalidate_tombstone(exact, w)?;
        let marker = TransitionMarker::parse(exact).map_err(invalid)?;
        if marker.value["stage"] != "native_published" {
            return Err(SourceError::Changed);
        }
        let current = self.files.read(CURRENT, false)?;
        let names = self.remaining_completed_records(&marker, &current, current_wallet)?;
        if list(self.files.root(), 5)?.iter().any(|n| n == RECORDS) {
            let d = self.files.records()?;
            for n in &names {
                self.revalidate_tombstone(exact, w)?;
                self.remaining_completed_records(&marker, &current, current_wallet)?;
                wallet.inspect_transition(view)?.equal(current_wallet)?;
                checkpoint(&format!("before_record_unlink:{n}"))?;
                unlink(&d, n, false)?;
                checkpoint(&format!("record_unlinked:{n}"))?;
            }
            sync(&d)?;
            checkpoint("records_synced")?;
            close(d)?;
            checkpoint("records_closed")?;
            unlink(self.files.root(), RECORDS, true)?;
            checkpoint("records_removed")?;
        }
        self.revalidate_tombstone(exact, w)?;
        Ok(names.len())
    }
    fn finish_tombstone(
        &self,
        exact: &[u8],
        w: &TombstoneWitness<'_>,
        pin: OwnerStartupPin,
        current: &ObservedWallet,
        wallet: &WalletCurrentSource,
        view: &BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<()> {
        self.files.inspect()?;
        if list(self.files.root(), 5)?
            .iter()
            .any(|n| n == RECORDS || n == MARKER)
        {
            return Err(SourceError::TransitionPending);
        }
        let actual = check_bundle(&self.files.read(CURRENT, false)?, pin)?;
        if canonical(&actual.value["wallet_current"]) != current.reference.canonical_bytes() {
            return Err(SourceError::Changed);
        }
        self.time(current.durable)?;
        self.revalidate_tombstone(exact, w)?;
        wallet.inspect_transition(view)?.equal(current)?;
        checkpoint("before_tombstone_unlink")?;
        unlink(self.files.root(), TEMP, false)?;
        checkpoint("tombstone_removed")?;
        self.files.inspect()?;
        self.time(current.durable)?;
        Ok(())
    }
    /// A NEW privileged owner cleanup decision using independently selected NEW
    /// native and full Wallet startup pins. Missing original inputs are allowed
    /// only here. Original-input transition recovery is not performed by this
    /// API. It changes no Wallet/native state, policy or generation and returns
    /// only a cleanup acknowledgment. Custody exclusive must already be held.
    pub fn cleanup_completed_wallet_transition(
        &self,
        target: OwnerStartupPin,
        expected_transition_id: [u8; 16],
        wallet: &WalletCurrentSource,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<CompletedWalletTransitionCleanup> {
        let current = wallet.inspect_initial(&view)?;
        let lock = self.lock(true)?;
        let lock_identity = id(&lock)?;
        if self.files.exists(MARKER, false)? {
            return Err(SourceError::TransitionPending);
        }
        let raw = self.files.read(CURRENT, false)?;
        let native = check_bundle(&raw, target)?;
        if canonical(&native.value["wallet_current"]) != current.reference.canonical_bytes() {
            return Err(SourceError::Changed);
        }
        let exact = self.files.read(TEMP, false)?;
        let marker = TransitionMarker::parse(&exact).map_err(invalid)?;
        if marker.value["stage"] != "native_published"
            || marker.value["transition_id"] != hex(&expected_transition_id)
            || marker.value["target_native"]["native_cas"] != target.value()
            || marker.value["target_native"]["target_image_sha256"] != hex(&target.sha256)
            || canonical(&marker.value["observed_outcome"]["wallet_reference"])
                != current.reference.canonical_bytes()
        {
            return Err(SourceError::Changed);
        }
        self.time(
            current.durable.max(
                marker.value["started_at"]
                    .as_u64()
                    .ok_or(SourceError::Invalid)?,
            ),
        )?;
        self.remaining_completed_records(&marker, &raw, &current)?;
        let witness = self.confirm_tombstone(&exact, &lock)?;
        wallet.inspect_initial(&view)?.equal(&current)?;
        let removed_records =
            self.delete_completed_records(&exact, &witness, wallet, &view, &current)?;
        wallet.inspect_initial(&view)?.equal(&current)?;
        let fresh = open_at(self.files.root(), LOCK, libc::O_RDONLY)?;
        safe(&fresh, 0)?;
        if id(&fresh)? != lock_identity || id(&lock)? != lock_identity {
            return Err(SourceError::Changed);
        }
        close(fresh)?;
        self.finish_tombstone(&exact, &witness, target, &current, wallet, &view)?;
        wallet.inspect_initial(&view)?.equal(&current)?;
        Ok(CompletedWalletTransitionCleanup {
            transition_id: expected_transition_id,
            removed_records,
        })
    }
}

/// Cleanup-only acknowledgment. This never claims an original transition or G+1.
pub struct UnpreparedWalletTransitionAbort {
    removed_records: usize,
}
impl UnpreparedWalletTransitionAbort {
    pub fn removed_records(&self) -> usize {
        self.removed_records
    }
}
/// Cleanup-only acknowledgment; all original marker and records remain fenced.
pub struct UncommittedTransitionTempDiscard {
    transition_id: [u8; 16],
}
impl UncommittedTransitionTempDiscard {
    pub fn transition_id(&self) -> [u8; 16] {
        self.transition_id
    }
}
impl OwnerPublicationSource {
    fn validate_unchanged_cleanup(
        &self,
        pin: OwnerStartupPin,
        wallet: &WalletCurrentSource,
        view: &BorrowedPublicServiceObservation<'_, '_>,
        current: &ObservedWallet,
        lock: &File,
        lock_id: (u64, u64),
    ) -> Result<()> {
        self.files.inspect()?;
        let fresh = open_at(self.files.root(), LOCK, libc::O_RDONLY)?;
        safe(&fresh, 0)?;
        if id(lock)? != lock_id || id(&fresh)? != lock_id {
            return Err(SourceError::Changed);
        }
        close(fresh)?;
        let native = check_bundle(&self.files.read(CURRENT, false)?, pin)?;
        if canonical(&native.value["wallet_current"]) != current.reference.canonical_bytes() {
            return Err(SourceError::Changed);
        }
        wallet.inspect_initial(view)?.equal(current)?;
        self.time(current.durable)?;
        Ok(())
    }
    fn unprepared_records(&self, current: &ObservedWallet, old: &[u8]) -> Result<Vec<String>> {
        if self.files.exists(MARKER, false)? {
            return Err(SourceError::TransitionPending);
        }
        if !list(self.files.root(), 5)?.iter().any(|n| n == RECORDS) {
            return Err(SourceError::NoUnpreparedTransition);
        }
        let directory = self.files.records()?;
        let names = list(&directory, 6)?;
        close(directory)?;
        let order = [
            "OLD-NATIVE.json",
            "OLD-WALLET-STATE.json",
            "TARGET-POLICY.json",
            "REQUEST-OWNER-INPUT.json",
        ];
        if names.len() > order.len()
            || names
                .iter()
                .any(|n| !order[..names.len()].contains(&n.as_str()))
        {
            return Err(SourceError::Changed);
        }
        if names.iter().any(|n| n == order[0]) && self.files.read(order[0], true)? != old {
            return Err(SourceError::Changed);
        }
        if names.iter().any(|n| n == order[1]) {
            let raw = self.files.read(order[1], true)?;
            wallet::retained_state(&raw, &current.reference)?;
            if raw != current.state_raw {
                return Err(SourceError::Changed);
            }
        }
        if names.iter().any(|n| n == order[2]) {
            let p = TargetPolicy::parse(&self.files.read(order[2], true)?).map_err(invalid)?;
            if p.value["application"] != current.reference.value["application"] {
                return Err(SourceError::Changed);
            }
        }
        if names.iter().any(|n| n == order[3]) {
            current.configuration(&self.files.read(order[3], true)?)?;
        }
        Ok(order[..names.len()].iter().map(|n| n.to_string()).collect())
    }
    /// A separate privileged owner decision to discard only a validated prefix
    /// of unprepared bookkeeping under independent unchanged OLD pins. Partial,
    /// unknown, P/request/marker-profile temps remain fenced for investigation.
    pub fn abort_unprepared_wallet_transition(
        &self,
        old: OwnerStartupPin,
        wallet: &WalletCurrentSource,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<UnpreparedWalletTransitionAbort> {
        let current = wallet.inspect_initial(&view)?;
        let lock = self.lock(true)?;
        let lock_id = id(&lock)?;
        self.validate_unchanged_cleanup(old, wallet, &view, &current, &lock, lock_id)?;
        let native = self.files.read(CURRENT, false)?;
        let names = self.unprepared_records(&current, &native)?;
        if self.files.exists(TEMP, false)? {
            let temp = self.files.read(TEMP, false)?;
            if temp != native && temp != current.state_raw {
                return Err(SourceError::TransitionPending);
            }
            // Full equality binds to independently checked exact source bytes.
            self.validate_unchanged_cleanup(old, wallet, &view, &current, &lock, lock_id)?;
            checkpoint("before_unprepared_temp_unlink")?;
            unlink(self.files.root(), TEMP, false)?;
            self.validate_unchanged_cleanup(old, wallet, &view, &current, &lock, lock_id)?;
        }
        let directory = self.files.records()?;
        for name in names.iter().rev() {
            self.validate_unchanged_cleanup(old, wallet, &view, &current, &lock, lock_id)?;
            self.unprepared_records(&current, &native)?;
            checkpoint(&format!("before_unprepared_unlink:{name}"))?;
            unlink(&directory, name, false)?;
            checkpoint(&format!("unprepared_unlinked:{name}"))?;
            self.validate_unchanged_cleanup(old, wallet, &view, &current, &lock, lock_id)?;
        }
        sync(&directory)?;
        close(directory)?;
        unlink(self.files.root(), RECORDS, true)?;
        self.validate_unchanged_cleanup(old, wallet, &view, &current, &lock, lock_id)?;
        Ok(UnpreparedWalletTransitionAbort {
            removed_records: names.len(),
        })
    }
    /// A distinct explicit recovery-only decision. Ordinary marker+temp capture
    /// remains denied. Proves the full original chain and exact admitted stage/
    /// current matrix without interpreting TEMP, then removes ONLY that temp.
    pub fn discard_uncommitted_transition_temp(
        &self,
        old: OwnerStartupPin,
        expected_transition_id: [u8; 16],
        wallet: &WalletCurrentSource,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<UncommittedTransitionTempDiscard> {
        let observed = wallet.inspect_transition(&view)?;
        let lock = self.lock(true)?;
        if !self.files.exists(MARKER, false)? || !self.files.exists(TEMP, false)? {
            return Err(SourceError::TransitionPending);
        }
        let exact = self.files.read(MARKER, false)?;
        let marker = TransitionMarker::parse(&exact).map_err(invalid)?;
        if marker.value["transition_id"] != hex(&expected_transition_id)
            || marker.value["old_native_cas"] != old.value()
        {
            return Err(SourceError::Changed);
        }
        let old_raw = self.files.read("OLD-NATIVE.json", true)?;
        check_bundle(&old_raw, old)?;
        let reference = WalletReference::parse(&canonical(&marker.value["old_wallet_reference"]))
            .map_err(invalid)?;
        wallet.pin_reference(&reference)?;
        let state_raw = self.files.read("OLD-WALLET-STATE.json", true)?;
        let state = wallet::retained_state(&state_raw, &reference)?;
        let basis = RetainedWalletBasis {
            reference,
            state,
            state_raw,
            root: observed.root,
            lock: observed.lock,
            epoch: observed.epoch,
        };
        let session = NativeOwnerAdministrationSession {
            source: self,
            lock_id: id(&lock)?,
            lock,
            pin: old,
            old_raw,
            wallet,
            old_wallet: basis,
            marker: Some(marker),
            tombstone: false,
            recovering: true,
            original_selection: None,
        };
        session.revalidate()?;
        session.validate_records()?;
        session.verify_current_transition(&observed)?;
        if self.files.exists("OUTCOME.json", true)? {
            let outcome =
                OutcomeRecord::parse(&self.files.read("OUTCOME.json", true)?).map_err(invalid)?;
            if outcome.reference().canonical_bytes() != observed.reference.canonical_bytes() {
                return Err(SourceError::Changed);
            }
        }
        let temp = open_at(self.files.root(), TEMP, libc::O_RDONLY)?;
        safe(&temp, IMAGE)?;
        let identity = identity_metadata(&temp.metadata().map_err(io_error)?);
        let marker_file = open_at(self.files.root(), MARKER, libc::O_RDONLY)?;
        safe(&marker_file, RECORD)?;
        let marker_identity = identity_metadata(&marker_file.metadata().map_err(io_error)?);
        session.revalidate()?;
        session.validate_records()?;
        session.actual(&view)?.equal(&observed)?;
        session.verify_current_transition(&observed)?;
        let fresh = open_at(self.files.root(), TEMP, libc::O_RDONLY)?;
        safe(&fresh, IMAGE)?;
        let marker_fresh = open_at(self.files.root(), MARKER, libc::O_RDONLY)?;
        safe(&marker_fresh, RECORD)?;
        if identity_metadata(&fresh.metadata().map_err(io_error)?) != identity
            || identity_metadata(&marker_fresh.metadata().map_err(io_error)?) != marker_identity
            || self.files.read(MARKER, false)? != exact
        {
            return Err(SourceError::Changed);
        }
        close(fresh)?;
        close(marker_fresh)?;
        close(marker_file)?;
        close(temp)?;
        checkpoint("before_uncommitted_temp_unlink")?;
        unlink(self.files.root(), TEMP, false)?;
        session.revalidate()?;
        session.validate_records()?;
        session.actual(&view)?.equal(&observed)?;
        if self.files.read(MARKER, false)? != exact {
            return Err(SourceError::Changed);
        }
        Ok(UncommittedTransitionTempDiscard {
            transition_id: expected_transition_id,
        })
    }
}
impl NativeOwnerAdministrationSession<'_, '_> {
    // Full relation check independent of whether this caller requests a new
    // outcome record, a recovery-only reconcile, or the explicit S2 cleanup.
    fn verify_current_transition(&self, current: &ObservedWallet) -> Result<()> {
        let marker = self.marker.as_ref().ok_or(SourceError::Invalid)?;
        if self.source.files.exists("OUTCOME.json", true)? {
            let original = OutcomeRecord::parse(&self.source.files.read("OUTCOME.json", true)?)
                .map_err(invalid)?;
            original.verify(marker, &self.policy()?).map_err(invalid)?;
            if original.reference().canonical_bytes() != current.reference.canonical_bytes() {
                return Err(SourceError::Changed);
            }
        }
        let kind = marker.value["mutation"]
            .as_str()
            .ok_or(SourceError::Invalid)?;
        compare_predecessor(
            &self.old_wallet.reference,
            &self.old_wallet.state,
            &self.old_wallet.state_raw,
            current,
            kind,
        )?;
        if current.reference.canonical_bytes() == self.old_wallet.reference.canonical_bytes() {
            return Ok(());
        }
        let relation = match kind {
            "configure" => "configured",
            "rotate" => "rotated_unconfigured",
            "revoke" => "revoked",
            _ => return Err(SourceError::Changed),
        };
        let policy = self.policy()?;
        let now = self.source.time(current.durable)?;
        let value = json!({"schema":"secs.wallet-current-outcome.v3","transition_id":marker.value["transition_id"],"old_wallet_reference_sha256":hex(&self.old_wallet.reference.reference_digest()),"old_native_cas":self.pin.value(),"mutation":kind,"request_sha256":hex(&hash(&canonical(&marker.value["request"]))),"wallet_reference":current.reference.value,"relation":relation,"observed_at":now,"target_policy_sha256":hex(&policy.digest())});
        let candidate = OutcomeRecord::parse(&canonical(&value)).map_err(invalid)?;
        if marker.value["stage"] == "prepared" {
            candidate.verify(marker, &policy).map_err(invalid)?;
        } else {
            let original = OutcomeRecord::parse(&self.source.files.read("OUTCOME.json", true)?)
                .map_err(invalid)?;
            original.verify(marker, &policy).map_err(invalid)?;
            if original.reference().canonical_bytes() != current.reference.canonical_bytes() {
                return Err(SourceError::Changed);
            }
        }
        Ok(())
    }
    pub fn recovery_reconciliation_guard(&self) -> Result<NativeWalletRecoveryGuard<'_, '_, '_>> {
        if !self.recovering || self.tombstone || self.source.files.exists(TEMP, false)? {
            return Err(SourceError::TransitionPending);
        }
        self.revalidate()?;
        self.validate_records()?;
        Ok(NativeWalletRecoveryGuard { session: self })
    }
}
/// Concrete recovery handle permits only custody reconciliation of the actual
/// checked current state. It cannot authorize replay of the original mutation.
pub struct NativeWalletRecoveryGuard<'a, 's, 'w> {
    session: &'a NativeOwnerAdministrationSession<'s, 'w>,
}
impl NativeWalletRecoveryGuard<'_, '_, '_> {
    pub fn authorize_reconcile(
        &self,
        view: BorrowedPublicServiceObservation<'_, '_>,
        expected: &WalletExpectedCurrent,
    ) -> Result<()> {
        self.session.revalidate()?;
        self.session.validate_records()?;
        let current = self.session.actual(&view)?;
        self.session.verify_current_transition(&current)?;
        if current.revision() != expected.state_revision
            || current.reference.value["custody_state_sha256"] != hex(&expected.state_sha256)
        {
            return Err(SourceError::Changed);
        }
        self.session.source.time(current.durable)?;
        view.revalidate().map_err(io_error)
    }
}

/// Holds actual Native shared lock. Later issuers must also hold the matching
/// actual Wallet and key/journal sources; this type alone cannot sign or admit.
pub struct NativeOwnerCurrentLease<'s> {
    source: &'s OwnerPublicationSource,
    lock: File,
    lock_id: (u64, u64),
    pin: OwnerStartupPin,
    bundle: TargetBundle,
}
impl NativeOwnerCurrentLease<'_> {
    pub fn revalidate(&self) -> Result<()> {
        self.source.files.inspect()?;
        if self.source.files.exists(MARKER, false)?
            || list(self.source.files.root(), 5)?
                .iter()
                .any(|n| n == RECORDS || n == TEMP)
        {
            return Err(SourceError::TransitionPending);
        }
        let lock = open_at(self.source.files.root(), LOCK, libc::O_RDONLY)?;
        safe(&lock, 0)?;
        if id(&lock)? != self.lock_id
            || id(&self.lock)? != self.lock_id
            || self.source.files.read(CURRENT, false)? != self.bundle.canonical_bytes()
        {
            return Err(SourceError::Changed);
        }
        self.source.time(0)?;
        Ok(())
    }
    pub fn startup_pin(&self) -> OwnerStartupPin {
        self.pin
    }
    /// Native-only full policy view from this exact held bundle. It does not
    /// extend the lifetime of Wallet custody or qualify evidence/admission.
    pub(crate) fn policy(&self) -> std::result::Result<HeldNativePolicy<'_, '_>, HeldPolicyError> {
        self.revalidate()?;
        let observed = self.source.time(0)?;
        let policy = crate::service_authority_snapshot::ValidatedNativePolicy::parse(
            self.bundle.canonical_bytes(),
            self.pin.sha256,
            observed,
        )?;
        self.revalidate()?;
        Ok(HeldNativePolicy {
            lease: self,
            policy,
        })
    }

    pub(crate) fn require_wallet_window(
        &self,
        w: &ObservedWallet,
        issued: u64,
        expires: u64,
    ) -> Result<()> {
        self.revalidate()?;
        if canonical(&self.bundle.value["wallet_current"]) != w.reference.canonical_bytes() {
            return Err(SourceError::Changed);
        }
        if w.reference.state() != WalletState::Active {
            return Err(SourceError::Inactive);
        }
        let n = self.source.time(w.durable)?;
        let issuer = self.bundle.value["issuers"]
            .as_array()
            .ok_or(SourceError::Invalid)?
            .iter()
            .find(|i| i["key_id"] == self.bundle.value["selected_issuer_key_id"])
            .ok_or(SourceError::Invalid)?;
        if issuer["status"] != "active"
            || issuer["production_authority"] != true
            || !issuer["replaced_by"].is_null()
            || issuer["not_before"]
                .as_u64()
                .is_none_or(|s| issued < s || n < s)
            || issuer["not_after"]
                .as_u64()
                .is_none_or(|e| expires > e || n >= e)
            || issuer["revoked_at"]
                .as_u64()
                .is_some_and(|r| r < expires || r <= n)
        {
            return Err(SourceError::Window);
        }
        if self.bundle.value["valid_not_before"]
            .as_u64()
            .is_none_or(|s| issued < s)
            || self.bundle.value["valid_until"]
                .as_u64()
                .is_none_or(|e| expires > e)
            || issued > n
            || n >= expires
        {
            return Err(SourceError::Window);
        }
        Ok(())
    }
}
/// These errors contain no issuer private material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeldPolicyError {
    Source(SourceError),
    Policy(crate::service_authority_snapshot::SnapshotError),
}
impl From<SourceError> for HeldPolicyError {
    fn from(e: SourceError) -> Self {
        Self::Source(e)
    }
}
impl From<crate::service_authority_snapshot::SnapshotError> for HeldPolicyError {
    fn from(e: crate::service_authority_snapshot::SnapshotError) -> Self {
        Self::Policy(e)
    }
}
/// Construction is confined to NativeOwnerCurrentLease::policy above. Sibling
/// modules cannot attach arbitrary parsed policy to a real lease. This borrow
/// retains the actual Native File, not a Wallet lease or an admission guard.
pub(crate) struct HeldNativePolicy<'a, 's> {
    lease: &'a NativeOwnerCurrentLease<'s>,
    policy: crate::service_authority_snapshot::ValidatedNativePolicy,
}
impl HeldNativePolicy<'_, '_> {
    pub(crate) fn lineage(&self) -> crate::service_authority_snapshot::NativePolicyLineage {
        self.policy.lineage()
    }
    pub(crate) fn application(&self) -> libsec_core::service_holder_proof::ServiceApplication {
        self.policy.application()
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        self.lease.revalidate()
    }
    pub(crate) fn selected_issuer(
        &self,
        window: crate::service_authority::OriginalServiceWindow,
    ) -> std::result::Result<&crate::service_holder_proof::ServiceIssuerKey, HeldPolicyError> {
        self.lease.revalidate()?;
        let now = self.lease.source.time(0)?;
        let key = self
            .policy
            .selected_issuer(window.issued_at(), window.expires_at(), now)?;
        self.lease.revalidate()?;
        Ok(key)
    }
    pub(crate) fn verify_holder(
        &self,
        wallet: &WalletCurrentLease<'_>,
        packet: &libsec_core::ZenithPacket,
        prepared: &crate::service_authority_snapshot::PreparedOwnerBindings,
        window: crate::service_authority::OriginalServiceWindow,
        recorded_challenge_digest: [u8; 32],
    ) -> std::result::Result<crate::service_holder_proof::AuthenticatedServiceHolder, HeldPolicyError>
    {
        wallet.require_active_for_challenge(window.issued_at(), window.expires_at(), self.lease)?;
        self.selected_issuer(window)?;
        let reference = &wallet.observed.reference.value;
        let policy_digest = wallet
            .observed
            .reference
            .delegation_policy_digest()
            .map_err(|_| SourceError::Invalid)?;
        let validity = crate::service_holder_proof::ValidityWindow {
            not_before: reference["not_before"]
                .as_u64()
                .ok_or(SourceError::Invalid)?,
            not_after: reference["not_after"]
                .as_u64()
                .ok_or(SourceError::Invalid)?,
        };
        let now = self.lease.source.time(0)?;
        let result = self.policy.verify_holder(
            packet,
            prepared,
            policy_digest,
            validity,
            recorded_challenge_digest,
            now,
        )?;
        wallet.require_active_for_challenge(window.issued_at(), window.expires_at(), self.lease)?;
        self.selected_issuer(window)?;
        Ok(result)
    }
    pub(crate) fn prepare_original(
        &self,
        raw: &[u8],
        subject: &str,
        key_id: &str,
        window: crate::service_authority::OriginalServiceWindow,
    ) -> std::result::Result<
        crate::service_authority_snapshot::PreparedOwnerBindings,
        HeldPolicyError,
    > {
        self.prepare_recorded_original(raw, subject, key_id, window, self.lineage().observed_at())
    }
    // Uses this exact held current policy; the original observation is bounded
    // data, not a caller-selected clock or a substitute for signature validation.
    pub(crate) fn prepare_recorded_original(
        &self,
        raw: &[u8],
        subject: &str,
        key_id: &str,
        window: crate::service_authority::OriginalServiceWindow,
        original_observed: u64,
    ) -> std::result::Result<
        crate::service_authority_snapshot::PreparedOwnerBindings,
        HeldPolicyError,
    > {
        self.selected_issuer(window)?;
        let now = self.lease.source.time(0)?;
        let prepared = self.policy.prepare_recorded_original(
            raw,
            subject,
            key_id,
            window.issued_at(),
            window.expires_at(),
            now,
            original_observed,
        )?;
        self.lease.revalidate()?;
        self.policy
            .revalidate_prepared(&prepared, self.lease.source.time(0)?)?;
        Ok(prepared)
    }
}

/// Typed owner request. Configure retains the exact full Wallet input bytes.
/// No caller-supplied current digest, source path, clock or qualification flag.
pub enum WalletTransitionIntent {
    Configure { owner_input: Vec<u8> },
    Rotate { not_before: u64, not_after: u64 },
    Revoke,
    Reconcile,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletMutationKind {
    Configure,
    Rotate,
    Revoke,
    Reconcile,
}
impl WalletTransitionIntent {
    fn kind(&self) -> &'static str {
        match self {
            Self::Configure { .. } => "configure",
            Self::Rotate { .. } => "rotate",
            Self::Revoke => "revoke",
            Self::Reconcile => "reconcile",
        }
    }
}
/// Exact expected custody CAS additionally checked by the actual Wallet mutator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletExpectedCurrent {
    pub state_revision: u64,
    pub state_sha256: [u8; 32],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryRelation {
    IntendedOutcome,
    ExplicitAbortUnchanged,
    ReconciledUnchanged,
}
fn compare_predecessor(
    old: &WalletReference,
    state: &wallet::StateRecord,
    raw: &[u8],
    current: &ObservedWallet,
    kind: &str,
) -> Result<()> {
    if current.reference.canonical_bytes() == old.canonical_bytes() {
        if current.state_raw != raw {
            return Err(SourceError::Changed);
        }
        return Ok(());
    }
    if current.state.previous_state_sha256.as_deref() != old.value["custody_state_sha256"].as_str()
        || current.state.created_at != state.created_at
        || current.state.published_at < state.published_at
        || (kind != "rotate" && current.state.key_created_at != state.key_created_at)
        || (kind == "rotate" && current.state.key_created_at != current.state.published_at)
    {
        return Err(SourceError::Changed);
    }
    Ok(())
}
// This is retained public predecessor data, not a current observation lease.
struct RetainedWalletBasis {
    reference: WalletReference,
    state: wallet::StateRecord,
    state_raw: Vec<u8>,
    root: castalia_wallet_private_files::service_store::Identity,
    lock: castalia_wallet_private_files::service_store::Identity,
    epoch: u64,
}
impl RetainedWalletBasis {
    fn from_actual(o: ObservedWallet) -> Self {
        Self {
            reference: o.reference,
            state: o.state,
            state_raw: o.state_raw,
            root: o.root,
            lock: o.lock,
            epoch: o.epoch,
        }
    }
    fn equal_current(&self, o: &ObservedWallet) -> Result<()> {
        if self.reference.canonical_bytes() != o.reference.canonical_bytes()
            || self.state_raw != o.state_raw
            || self.root != o.root
            || self.lock != o.lock
            || self.epoch != o.epoch
        {
            return Err(SourceError::Changed);
        }
        Ok(())
    }
}
/// One held exclusive native lock. All methods operate through its selected root
/// and descriptor; none call the old shared OwnerSource::lease helper.
pub struct NativeOwnerAdministrationSession<'s, 'w> {
    source: &'s OwnerPublicationSource,
    lock: File,
    lock_id: (u64, u64),
    pin: OwnerStartupPin,
    old_raw: Vec<u8>,
    wallet: &'w WalletCurrentSource,
    old_wallet: RetainedWalletBasis,
    marker: Option<TransitionMarker>,
    tombstone: bool,
    recovering: bool,
    original_selection: Option<OriginalTransitionSelection>,
}
impl NativeOwnerAdministrationSession<'_, '_> {
    /// Exact original comparison DATA for original-selector sessions. This
    /// accessor neither revalidates sources nor creates an authority receipt.
    /// Legacy entry points return None and retain their existing behavior.
    pub fn original_wallet_data(&self) -> Option<OriginalWalletSelectionData<'_>> {
        self.original_selection
            .as_ref()
            .map(OriginalTransitionSelection::wallet_data)
    }
    fn started(&self) -> Result<u64> {
        self.marker.as_ref().map_or(Ok(0), |m| {
            m.value["started_at"].as_u64().ok_or(SourceError::Invalid)
        })
    }
    fn revalidate(&self) -> Result<()> {
        if let Some(original) = &self.original_selection {
            original.validate_source(self.source, self.wallet, &self.lock, self.lock_id)?;
            if let Some(marker) = &self.marker {
                original.validate_full_records(self.source, marker)?;
            }
        }
        self.source.files.inspect()?;
        let lock = open_at(self.source.files.root(), LOCK, libc::O_RDONLY)?;
        safe(&lock, 0)?;
        if id(&self.lock)? != self.lock_id || id(&lock)? != self.lock_id {
            return Err(SourceError::Changed);
        }
        let current = self.source.files.read(CURRENT, false)?;
        if self
            .marker
            .as_ref()
            .is_some_and(|m| m.value["stage"] == "native_published")
            && current != self.source.files.read("TARGET-NATIVE.json", true)?
        {
            return Err(SourceError::Changed);
        }
        if current != self.old_raw {
            let marker = self.marker.as_ref().ok_or(SourceError::Changed)?;
            if marker.value["stage"] == "prepared"
                || current != self.source.files.read("TARGET-NATIVE.json", true)?
            {
                return Err(SourceError::Changed);
            }
        }
        self.source.time(self.started()?)?;
        Ok(())
    }
    fn actual(&self, view: &BorrowedPublicServiceObservation<'_, '_>) -> Result<ObservedWallet> {
        if let Some(original) = &self.original_selection {
            original.validate_source(self.source, self.wallet, &self.lock, self.lock_id)?;
        }
        let o = self.wallet.inspect_transition(view)?;
        if o.root != self.old_wallet.root || o.lock != self.old_wallet.lock {
            return Err(SourceError::Changed);
        }
        Ok(o)
    }
    fn old_actual(
        &self,
        view: &BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<ObservedWallet> {
        let o = self.actual(view)?;
        self.old_wallet.equal_current(&o)?;
        Ok(o)
    }
    pub fn prepare_wallet_transition(
        &mut self,
        view: BorrowedPublicServiceObservation<'_, '_>,
        intent: WalletTransitionIntent,
        exact_target_policy: &[u8],
    ) -> Result<NativeWalletTransitionGuard<'_, '_, '_>> {
        self.revalidate()?;
        if self.marker.is_some() || self.tombstone || self.recovering {
            return Err(SourceError::TransitionPending);
        }
        let old = self.old_actual(&view)?;
        let policy = TargetPolicy::parse(exact_target_policy).map_err(invalid)?;
        if policy.value["application"] != old.reference.value["application"]
            || exact_target_policy.len() + 4096 + 64 > IMAGE as usize
        {
            return Err(SourceError::Capacity);
        }
        self.pin
            .generation
            .checked_add(1)
            .filter(|n| *n <= MAX_SAFE_TIME)
            .ok_or(SourceError::Capacity)?;
        let n = self.source.time(old.durable)?;
        let mut request = json!({"owner_input_sha256":null,"requested_not_before":null,"requested_not_after":null,"target_policy_sha256":hex(&policy.digest())});
        match &intent {
            WalletTransitionIntent::Configure { owner_input } => {
                old.configuration(owner_input)?;
                if old.reference.value["not_before"]
                    .as_u64()
                    .is_none_or(|start| n < start)
                    || old.reference.value["not_after"]
                        .as_u64()
                        .is_none_or(|end| n >= end)
                {
                    return Err(SourceError::Window);
                }
                if owner_input.len() > IMAGE as usize {
                    return Err(SourceError::Capacity);
                }
                request["owner_input_sha256"] = json!(hex(&hash(owner_input)));
            }
            WalletTransitionIntent::Rotate {
                not_before,
                not_after,
            } => {
                if *not_before >= *not_after
                    || *not_after > MAX_SAFE_TIME
                    || n < *not_before
                    || n >= *not_after
                {
                    return Err(SourceError::Window);
                }
                request["requested_not_before"] = json!(not_before);
                request["requested_not_after"] = json!(not_after);
            }
            _ => {}
        }
        let mut transition_id = [0u8; 16];
        rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut transition_id)
            .map_err(|_| SourceError::UnsafeStorage)?;
        let value = json!({"schema":"secs.wallet-current-transition.v3","transition_id":hex(&transition_id),"stage":"prepared","mutation":intent.kind(),"old_wallet_reference":old.reference.value,"old_native_cas":self.pin.value(),"old_native_image_sha256":hex(&self.pin.sha256),"request":request,"started_at":n,"observed_outcome":null,"target_native":null,"target_policy":{"profile":"secs.wallet-native-target-policy.v1","sha256":hex(&policy.digest()),"bytes":exact_target_policy.len()}});
        let marker = TransitionMarker::parse(&canonical(&value)).map_err(invalid)?;
        marker.binding_preimage(&policy).map_err(invalid)?;
        self.source.reserve_transition_capacity()?;
        self.source.files.make_records()?;
        self.source
            .files
            .write("OLD-NATIVE.json", true, &self.old_raw, false)?;
        checkpoint("old_native_durable")?;
        wallet::retained_state(&self.old_wallet.state_raw, &self.old_wallet.reference)?;
        self.source.files.write(
            "OLD-WALLET-STATE.json",
            true,
            &self.old_wallet.state_raw,
            false,
        )?;
        checkpoint("old_wallet_state_durable")?;
        self.old_actual(&view)?;
        self.source
            .files
            .write("TARGET-POLICY.json", true, exact_target_policy, false)?;
        checkpoint("target_policy_durable")?;
        if let WalletTransitionIntent::Configure { owner_input } = &intent {
            self.source
                .files
                .write("REQUEST-OWNER-INPUT.json", true, owner_input, false)?;
            checkpoint("request_durable")?;
        }
        self.old_actual(&view)?;
        self.revalidate()?;
        self.source
            .files
            .write(MARKER, false, marker.canonical_bytes(), false)?;
        self.marker = Some(marker);
        checkpoint("prepared")?;
        self.old_actual(&view)?;
        self.validate_records()?;
        self.revalidate()?;
        Ok(NativeWalletTransitionGuard { session: self })
    }
    pub fn transition_id(&self) -> Result<[u8; 16]> {
        let s = self.marker.as_ref().ok_or(SourceError::Invalid)?.value["transition_id"]
            .as_str()
            .ok_or(SourceError::Invalid)?;
        let mut out = [0; 16];
        for (i, v) in out.iter_mut().enumerate() {
            *v = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(invalid)?;
        }
        Ok(out)
    }
    fn policy(&self) -> Result<TargetPolicy> {
        TargetPolicy::parse(&self.source.files.read("TARGET-POLICY.json", true)?).map_err(invalid)
    }
    fn validate_records(&self) -> Result<()> {
        let marker = self.marker.as_ref().ok_or(SourceError::Invalid)?;
        if self
            .source
            .files
            .read(if self.tombstone { TEMP } else { MARKER }, false)?
            != marker.canonical_bytes()
        {
            return Err(SourceError::Changed);
        }
        let policy = self.policy()?;
        let old = self.source.files.read("OLD-NATIVE.json", true)?;
        let old_state = self.source.files.read("OLD-WALLET-STATE.json", true)?;
        wallet::retained_state(&old_state, &self.old_wallet.reference)?;
        if old_state != self.old_wallet.state_raw {
            return Err(SourceError::Changed);
        }
        if marker.value["mutation"] == "configure" {
            let request = self.source.files.read("REQUEST-OWNER-INPUT.json", true)?;
            if marker.value["request"]["owner_input_sha256"] != hex(&hash(&request)) {
                return Err(SourceError::Changed);
            }
            wallet::validate_transition_request(&request, &self.old_wallet.reference)?;
        } else if self.source.files.exists("REQUEST-OWNER-INPUT.json", true)? {
            return Err(SourceError::Invalid);
        }
        let has_outcome = self.source.files.exists("OUTCOME.json", true)?;
        let has_target = self.source.files.exists("TARGET-NATIVE.json", true)?;
        if has_outcome && has_target {
            let outcome = OutcomeRecord::parse(&self.source.files.read("OUTCOME.json", true)?)
                .map_err(invalid)?;
            let target = self.source.files.read("TARGET-NATIVE.json", true)?;
            verify_retained_transition(marker, &policy, &old, Some(&outcome), Some(&target))
                .map_err(invalid)?;
        } else if marker.value["stage"] != "prepared" {
            return Err(SourceError::Changed);
        } else {
            verify_retained_transition(marker, &policy, &old, None, None).map_err(invalid)?;
            if has_outcome {
                OutcomeRecord::parse(&self.source.files.read("OUTCOME.json", true)?)
                    .map_err(invalid)?
                    .verify(marker, &policy)
                    .map_err(invalid)?;
            }
            if has_target {
                return Err(SourceError::Changed);
            }
        }
        Ok(())
    }
    /// Derives the exact G+1 target only from retained policy and actual current
    /// metadata. There is deliberately no replacement policy or time argument.
    pub fn record_outcome_and_target(
        &mut self,
        view: BorrowedPublicServiceObservation<'_, '_>,
        relation: RecoveryRelation,
    ) -> Result<OwnerStartupPin> {
        self.revalidate()?;
        self.validate_records()?;
        if self.tombstone {
            return Err(SourceError::TransitionPending);
        }
        let current = self.actual(&view)?;
        self.verify_current_transition(&current)?;
        let m = self.marker.as_ref().ok_or(SourceError::Invalid)?;
        let kind = m.value["mutation"].as_str().ok_or(SourceError::Invalid)?;
        let relation = match relation {
            RecoveryRelation::IntendedOutcome => match kind {
                "configure" => "configured",
                "rotate" => "rotated_unconfigured",
                "revoke" => "revoked",
                "reconcile" => "reconciled_unchanged",
                _ => return Err(SourceError::Invalid),
            },
            RecoveryRelation::ExplicitAbortUnchanged => "explicit_abort_unchanged",
            RecoveryRelation::ReconciledUnchanged => "reconciled_unchanged",
        };
        let same =
            current.reference.canonical_bytes() == self.old_wallet.reference.canonical_bytes();
        if (same || !self.recovering) && current.epoch <= self.old_wallet.epoch {
            return Err(SourceError::Changed);
        }
        let observed_at = self.source.time(current.durable)?;
        if current.state.published_at > observed_at {
            return Err(SourceError::Clock);
        }
        let policy = self.policy()?;
        let outcome_value = json!({"schema":"secs.wallet-current-outcome.v3","transition_id":m.value["transition_id"],"old_wallet_reference_sha256":hex(&self.old_wallet.reference.reference_digest()),"old_native_cas":self.pin.value(),"mutation":kind,"request_sha256":hex(&hash(&canonical(&m.value["request"]))),"wallet_reference":current.reference.value,"relation":relation,"observed_at":observed_at,"target_policy_sha256":hex(&policy.digest())});
        let outcome = if self.source.files.exists("OUTCOME.json", true)? {
            let retained = OutcomeRecord::parse(&self.source.files.read("OUTCOME.json", true)?)
                .map_err(invalid)?;
            if retained.value["wallet_reference"] != outcome_value["wallet_reference"]
                || retained.value["relation"] != outcome_value["relation"]
            {
                return Err(SourceError::Changed);
            }
            retained
        } else {
            OutcomeRecord::parse(&canonical(&outcome_value)).map_err(invalid)?
        };
        outcome.verify(m, &policy).map_err(invalid)?;
        let cas = NativeCas::parse(&canonical(&self.pin.value())).map_err(invalid)?;
        let target = policy
            .derive_target(&cas, &current.reference)
            .map_err(invalid)?;
        self.source
            .files
            .write("OUTCOME.json", true, outcome.canonical_bytes(), false)?;
        checkpoint("outcome_durable")?;
        self.source
            .files
            .write("TARGET-NATIVE.json", true, target.canonical_bytes(), false)?;
        checkpoint("target_durable")?;
        let mut v = m.value.clone();
        v["stage"] = json!("outcome_recorded");
        v["observed_outcome"] = json!({"wallet_reference":current.reference.value,"relation":relation,"outcome_sha256":hex(&hash(outcome.canonical_bytes())),"target_policy_sha256":hex(&policy.digest())});
        let pin = OwnerStartupPin::new(self.pin.generation + 1, target.digest())?;
        v["target_native"] = json!({"native_cas":pin.value(),"target_image_sha256":hex(&target.digest()),"target_policy_sha256":hex(&policy.digest())});
        let marker = TransitionMarker::parse(&canonical(&v)).map_err(invalid)?;
        self.actual(&view)?.equal(&current)?;
        self.source
            .files
            .write(MARKER, false, marker.canonical_bytes(), true)?;
        self.marker = Some(marker);
        checkpoint("outcome_recorded")?;
        self.validate_records()?;
        self.revalidate()?;
        Ok(pin)
    }
    pub fn publish_recorded_target(
        &mut self,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<OwnerStartupPin> {
        self.revalidate()?;
        self.validate_records()?;
        if self.tombstone {
            return Err(SourceError::TransitionPending);
        }
        let current = self.actual(&view)?;
        self.verify_current_transition(&current)?;
        let m = self.marker.as_ref().ok_or(SourceError::Invalid)?;
        if m.value["stage"] == "prepared"
            || canonical(&m.value["observed_outcome"]["wallet_reference"])
                != current.reference.canonical_bytes()
        {
            return Err(SourceError::Changed);
        }
        let raw = self.source.files.read("TARGET-NATIVE.json", true)?;
        let target = TargetBundle::parse(&raw).map_err(invalid)?;
        let pin = OwnerStartupPin::new(self.pin.generation + 1, target.digest())?;
        if self.source.files.read(CURRENT, false)? != raw {
            self.source.files.write(CURRENT, false, &raw, true)?;
            checkpoint("native_replaced")?;
        }
        let mut v = m.value.clone();
        v["stage"] = json!("native_published");
        let marker = TransitionMarker::parse(&canonical(&v)).map_err(invalid)?;
        self.actual(&view)?.equal(&current)?;
        self.source
            .files
            .write(MARKER, false, marker.canonical_bytes(), true)?;
        self.marker = Some(marker);
        checkpoint("native_published")?;
        self.revalidate()?;
        self.validate_records()?;
        Ok(pin)
    }
    pub fn finalize_recorded_transition(
        &mut self,
        view: BorrowedPublicServiceObservation<'_, '_>,
    ) -> Result<OwnerStartupPin> {
        self.revalidate()?;
        self.validate_records()?;
        let current = self.actual(&view)?;
        self.verify_current_transition(&current)?;
        let marker = self.marker.as_ref().ok_or(SourceError::Invalid)?;
        if marker.value["stage"] != "native_published"
            || canonical(&marker.value["observed_outcome"]["wallet_reference"])
                != current.reference.canonical_bytes()
        {
            return Err(SourceError::Changed);
        }
        let target = self.source.files.read("TARGET-NATIVE.json", true)?;
        if self.source.files.read(CURRENT, false)? != target {
            return Err(SourceError::Changed);
        }
        let pin = OwnerStartupPin::new(self.pin.generation + 1, hash(&target))?;
        self.source.time(current.durable)?;
        self.actual(&view)?.equal(&current)?;
        let exact = marker.canonical_bytes().to_vec();
        if !self.tombstone {
            if self.source.files.exists(TEMP, false)? {
                return Err(SourceError::TransitionPending);
            }
            checkpoint("before_tombstone_rename")?;
            rename(
                self.source.files.root(),
                MARKER,
                self.source.files.root(),
                TEMP,
                false,
            )?;
            self.tombstone = true;
            checkpoint("tombstone_renamed")?;
        }
        let tombstone = self.source.confirm_tombstone(&exact, &self.lock)?;
        self.validate_records()?;
        if let Some(original) = &self.original_selection {
            original_selection::cleanup_original_held(
                self.source,
                self.wallet,
                &self.lock,
                self.lock_id,
                original,
                &view,
            )?;
        } else {
            self.source.delete_completed_records(
                &exact,
                &tombstone,
                self.wallet,
                &view,
                &current,
            )?;
            self.actual(&view)?.equal(&current)?;
            self.source.time(current.durable)?;
            self.source
                .finish_tombstone(&exact, &tombstone, pin, &current, self.wallet, &view)?;
        }
        self.marker = None;
        self.tombstone = false;
        self.pin = pin;
        self.old_raw = target;
        self.old_wallet = RetainedWalletBasis::from_actual(current);
        self.revalidate()?;
        Ok(pin)
    }
}
/// Borrowed durable administrative handle. Its only constructors follow actual
/// old/current/CAS checks and durable retained-input/marker publication.
pub struct NativeWalletTransitionGuard<'a, 's, 'w> {
    session: &'a NativeOwnerAdministrationSession<'s, 'w>,
}
impl NativeWalletTransitionGuard<'_, '_, '_> {
    pub fn transition_id(&self) -> Result<[u8; 16]> {
        self.session.transition_id()
    }
    pub fn mutation_kind(&self) -> Result<WalletMutationKind> {
        Ok(
            match self
                .session
                .marker
                .as_ref()
                .ok_or(SourceError::Invalid)?
                .value["mutation"]
                .as_str()
            {
                Some("configure") => WalletMutationKind::Configure,
                Some("rotate") => WalletMutationKind::Rotate,
                Some("revoke") => WalletMutationKind::Revoke,
                Some("reconcile") => WalletMutationKind::Reconcile,
                _ => return Err(SourceError::Invalid),
            },
        )
    }
    fn authorize(
        &self,
        view: BorrowedPublicServiceObservation<'_, '_>,
        expected: &WalletExpectedCurrent,
        kind: WalletMutationKind,
    ) -> Result<()> {
        self.session.revalidate()?;
        self.session.validate_records()?;
        let m = self.session.marker.as_ref().ok_or(SourceError::Invalid)?;
        if m.value["stage"] != "prepared" || self.mutation_kind()? != kind {
            return Err(SourceError::Changed);
        }
        let old = self.session.old_actual(&view)?;
        if old.revision() != expected.state_revision
            || old.reference.value["custody_state_sha256"] != hex(&expected.state_sha256)
        {
            return Err(SourceError::Changed);
        }
        self.session.source.time(old.durable)?;
        view.revalidate().map_err(io_error)
    }
    pub fn authorize_configure(
        &self,
        view: BorrowedPublicServiceObservation<'_, '_>,
        expected: &WalletExpectedCurrent,
        exact_owner_input: &[u8],
    ) -> Result<()> {
        self.authorize(view, expected, WalletMutationKind::Configure)?;
        if self
            .session
            .source
            .files
            .read("REQUEST-OWNER-INPUT.json", true)?
            != exact_owner_input
        {
            return Err(SourceError::Changed);
        }
        Ok(())
    }
    pub fn authorize_rotate(
        &self,
        view: BorrowedPublicServiceObservation<'_, '_>,
        expected: &WalletExpectedCurrent,
        not_before: u64,
        not_after: u64,
    ) -> Result<()> {
        self.authorize(view, expected, WalletMutationKind::Rotate)?;
        let r = &self
            .session
            .marker
            .as_ref()
            .ok_or(SourceError::Invalid)?
            .value["request"];
        if r["requested_not_before"] != not_before || r["requested_not_after"] != not_after {
            return Err(SourceError::Changed);
        }
        Ok(())
    }
    pub fn authorize_revoke(
        &self,
        view: BorrowedPublicServiceObservation<'_, '_>,
        expected: &WalletExpectedCurrent,
    ) -> Result<()> {
        self.authorize(view, expected, WalletMutationKind::Revoke)
    }
    pub fn authorize_reconcile(
        &self,
        view: BorrowedPublicServiceObservation<'_, '_>,
        expected: &WalletExpectedCurrent,
    ) -> Result<()> {
        self.authorize(view, expected, WalletMutationKind::Reconcile)
    }
}
#[cfg(test)]
thread_local! {static FAULT:std::cell::RefCell<Option<String>>=const{std::cell::RefCell::new(None)};}
fn checkpoint(_name: &str) -> Result<()> {
    #[cfg(test)]
    if FAULT.with(|f| f.borrow().as_deref() == Some(_name)) {
        return Err(SourceError::PublicationUncertain);
    }
    Ok(())
}
#[cfg(test)]
#[path = "service_owner_publication_tests.rs"]
mod tests;
