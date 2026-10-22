//! Fixed-name native service custody files. This module interprets no authority.
use super::{Entry, access, directory, open_at};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::File,
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Component, Path},
    sync::{Arc, Mutex, OnceLock, Weak},
};
use zeroize::Zeroizing;
type Result<T> = io::Result<T>;
const BLOCK: u64 = 65_536;
const TOTAL: u64 = 4 * 1024 * 1024;
fn deny() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}
fn busy() -> io::Error {
    io::ErrorKind::WouldBlock.into()
}
fn name(s: &str) -> CString {
    CString::new(s).expect("fixed safe name")
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub device: u64,
    pub inode: u64,
}
fn id(f: &File) -> Result<Identity> {
    let m = f.metadata()?;
    Ok(Identity {
        device: m.dev(),
        inode: m.ino(),
    })
}
#[derive(Default)]
struct State {
    readers: usize,
    writer: bool,
    epoch: u64,
    poisoned: bool,
}
#[derive(Default)]
struct Shared {
    state: Mutex<State>,
}
type Registry = Mutex<BTreeMap<(u64, u64), Weak<Shared>>>;
fn registry() -> &'static Registry {
    static R: OnceLock<Registry> = OnceLock::new();
    R.get_or_init(Default::default)
}
fn shared(i: Identity) -> Result<Arc<Shared>> {
    let mut r = registry().lock().map_err(|_| deny())?;
    r.retain(|_, v| v.strong_count() > 0);
    if let Some(s) = r.get(&(i.device, i.inode)).and_then(Weak::upgrade) {
        return Ok(s);
    }
    if r.len() >= 128 {
        return Err(busy());
    }
    let s = Arc::new(Shared::default());
    r.insert((i.device, i.inode), Arc::downgrade(&s));
    Ok(s)
}
struct Permit {
    shared: Arc<Shared>,
    exclusive: bool,
}
impl Permit {
    fn get(s: &Arc<Shared>, exclusive: bool) -> Result<Self> {
        let mut x = s.state.lock().map_err(|_| deny())?;
        if x.writer || (exclusive && x.readers != 0) {
            return Err(busy());
        }
        if exclusive {
            x.writer = true
        } else {
            x.readers = x.readers.checked_add(1).ok_or_else(deny)?
        }
        Ok(Self {
            shared: s.clone(),
            exclusive,
        })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut s) = self.shared.state.lock() {
            if self.exclusive {
                s.writer = false
            } else {
                s.readers = s.readers.saturating_sub(1)
            }
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum StagingFile {
    Seed,
    State,
    OwnerInput,
}
impl StagingFile {
    fn spec(self) -> (&'static str, u64, u64) {
        match self {
            Self::Seed => ("seed.raw", 32, BLOCK),
            Self::State => ("state.json", 4096, BLOCK),
            Self::OwnerInput => ("owner-input.json", 262144, 5 * BLOCK),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum ServiceFile {
    Current,
    Clock,
    State(u64),
    OwnerInput(u64),
    Seed(u64),
}
fn revision(v: u64) -> Result<String> {
    if v == 0 || v > 9_007_199_254_740_991 {
        return Err(deny());
    }
    Ok(format!("s{v:016}"))
}
fn parse_revision(s: &str) -> Result<u64> {
    if s.len() != 17 || !s.starts_with('s') || !s.as_bytes()[1..].iter().all(u8::is_ascii_digit) {
        return Err(deny());
    }
    let v = s[1..].parse().map_err(|_| deny())?;
    if revision(v)? != s {
        return Err(deny());
    }
    Ok(v)
}
fn charged(f: &File) -> Result<u64> {
    let m = f.metadata()?;
    m.blocks()
        .checked_mul(512)
        .map(|n| n.max(m.len()))
        .ok_or_else(deny)
}
fn file_safe(f: &File, logical: u64, allocated: u64) -> Result<()> {
    let m = f.metadata()?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
        || m.len() > logical
        || charged(f)? > allocated
    {
        return Err(deny());
    }
    access(f, false)
}
fn dir_safe(f: &File) -> Result<()> {
    directory(f, true)?;
    if f.metadata()?.mode() & 0o7777 != 0o700 || charged(f)? > BLOCK {
        return Err(deny());
    }
    Ok(())
}
fn child_dir(parent: &File, s: &str) -> Result<File> {
    let f = open_at(parent, &name(s), libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    dir_safe(&f)?;
    Ok(f)
}
fn open_file(parent: &File, s: &str, l: u64, a: u64) -> Result<File> {
    let f = open_at(parent, &name(s), libc::O_RDONLY, 0)?;
    file_safe(&f, l, a)?;
    Ok(f)
}
fn list(f: &File, max: usize) -> Result<Vec<String>> {
    let dup = open_at(f, &name("."), libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    use std::os::fd::IntoRawFd;
    let fd = dup.into_raw_fd();
    let d = unsafe { libc::fdopendir(fd) };
    if d.is_null() {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
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
            let e = unsafe { libc::readdir(d) };
            if e.is_null() {
                if io::Error::last_os_error().raw_os_error() != Some(0) {
                    return Err(io::Error::last_os_error());
                }
                break;
            }
            let s = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) }
                .to_str()
                .map_err(|_| deny())?;
            if s == "." || s == ".." {
                continue;
            }
            if out.len() >= max {
                return Err(deny());
            }
            out.push(s.to_owned())
        }
        out.sort();
        Ok(out)
    })();
    unsafe { libc::closedir(d) };
    result
}
fn sync(f: &File) -> Result<()> {
    f.sync_all()?;
    #[cfg(target_os = "macos")]
    if f.metadata()?.is_file() && unsafe { libc::fcntl(f.as_raw_fd(), 51) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn unlink(parent: &File, s: &str, dir: bool) -> Result<()> {
    if unsafe {
        libc::unlinkat(
            parent.as_raw_fd(),
            name(s).as_ptr(),
            if dir { libc::AT_REMOVEDIR } else { 0 },
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn rename(parent: &File, from: &str, to: &str, replace: bool) -> Result<()> {
    #[cfg(target_os = "macos")]
    let r = unsafe {
        unsafe extern "C" {
            fn renameatx_np(
                a: i32,
                b: *const libc::c_char,
                c: i32,
                d: *const libc::c_char,
                flags: u32,
            ) -> i32;
        }
        renameatx_np(
            parent.as_raw_fd(),
            name(from).as_ptr(),
            parent.as_raw_fd(),
            name(to).as_ptr(),
            if replace { 0 } else { 4 },
        )
    };
    #[cfg(target_os = "linux")]
    let r = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            name(from).as_ptr(),
            parent.as_raw_fd(),
            name(to).as_ptr(),
            if replace { 0 } else { 1 },
        ) as i32
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let r = -1;
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
#[derive(Debug)]
pub struct Inventory {
    pub root_entries: Vec<String>,
    pub revisions: Vec<u64>,
    pub staging: bool,
    pub charge: u64,
}
pub struct ServiceRoot {
    entry: Entry,
    chain: Vec<Identity>,
    components: Vec<CString>,
    shared: Arc<Shared>,
}
impl ServiceRoot {
    pub fn open(path: &Path) -> Result<Self> {
        let entry = Entry::open(&path.join(".service-validation"), true)?;
        dir_safe(entry.parent())?;
        #[cfg(target_os = "macos")]
        unsafe {
            let mut s = std::mem::MaybeUninit::<libc::statfs>::uninit();
            if libc::fstatfs(entry.parent().as_raw_fd(), s.as_mut_ptr()) != 0
                || s.assume_init().f_flags & 0x1000 == 0
            {
                return Err(deny());
            }
        }
        #[cfg(target_os = "linux")]
        unsafe {
            let mut s = std::mem::MaybeUninit::<libc::statfs>::uninit();
            if libc::fstatfs(entry.parent().as_raw_fd(), s.as_mut_ptr()) != 0 {
                return Err(deny());
            }
            if !matches!(
                s.assume_init().f_type as u64,
                0xef53 | 0x58465342 | 0x9123683e | 0x01021994
            ) {
                return Err(deny());
            }
        }
        let chain = entry
            .directories
            .iter()
            .map(id)
            .collect::<Result<Vec<_>>>()?;
        let components = path
            .components()
            .filter_map(|c| {
                if let Component::Normal(n) = c {
                    use std::os::unix::ffi::OsStrExt;
                    Some(CString::new(n.as_bytes()).map_err(|_| deny()))
                } else {
                    None
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let shared = shared(*chain.last().ok_or_else(deny)?)?;
        let s = Self {
            entry,
            chain,
            components,
            shared,
        };
        s.revalidate()?;
        Ok(s)
    }
    fn root(&self) -> &File {
        self.entry.parent()
    }
    fn revalidate(&self) -> Result<()> {
        for (i, f) in self.entry.directories.iter().enumerate() {
            directory(f, i + 1 == self.chain.len())?;
            if id(f)? != self.chain[i] {
                return Err(deny());
            }
            if i > 0 {
                let current = open_at(
                    &self.entry.directories[i - 1],
                    &self.components[i - 1],
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?;
                if id(&current)? != self.chain[i] {
                    return Err(deny());
                }
            }
        }
        dir_safe(self.root())
    }
    fn lease(&self, exclusive: bool, create: bool) -> Result<ServiceLease<'_>> {
        let permit = Permit::get(&self.shared, exclusive)?;
        self.revalidate()?;
        let flags = libc::O_RDWR
            | if create {
                libc::O_CREAT | libc::O_EXCL
            } else {
                0
            };
        // Each lease opens a distinct OFD. Never dup/try_clone a lock descriptor.
        let file = open_at(self.root(), &name("custody.lock"), flags, 0o600)?;
        file_safe(&file, 0, 0)?;
        if unsafe {
            libc::flock(
                file.as_raw_fd(),
                libc::LOCK_NB
                    | if exclusive {
                        libc::LOCK_EX
                    } else {
                        libc::LOCK_SH
                    },
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let identity = id(&file)?;
        let lease = ServiceLease {
            root: self,
            lock: Some(file),
            lock_id: identity,
            permit: Some(permit),
            exclusive,
        };
        lease.revalidate()?;
        Ok(lease)
    }
    pub fn initialize(&self) -> Result<ServiceLease<'_>> {
        self.revalidate()?;
        let entries = list(self.root(), 8)?;
        let fresh = entries.is_empty();
        if !fresh && entries != ["RESET", "custody.lock", "states"] {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let mut lease = self.lease(true, fresh)?;
        if fresh {
            if unsafe { libc::mkdirat(self.root().as_raw_fd(), name("states").as_ptr(), 0o700) }
                != 0
            {
                return Err(io::Error::last_os_error());
            }
        } else {
            let reset = open_file(self.root(), "RESET", 0, 0)?;
            drop(reset);
            let states = child_dir(self.root(), "states")?;
            if !list(&states, 4)?.is_empty() {
                return Err(deny());
            }
            unlink(self.root(), "RESET", false)?;
            lease.invalidate(false)?;
        }
        sync(self.root())?;
        lease.revalidate()?;
        Ok(lease)
    }
    pub fn lock_shared(&self) -> Result<ServiceLease<'_>> {
        self.lease(false, false)
    }
    pub fn lock_exclusive(&self) -> Result<ServiceLease<'_>> {
        self.lease(true, false)
    }
    /// Retains the actual shared custody lock and exposes current public files only.
    pub fn lock_public_shared(&self) -> Result<PublicServiceObservationLease<'_>> {
        let lease = self.lease(false, false)?;
        let metadata = lease.capture_public()?;
        let observation = PublicServiceObservationLease { lease, metadata };
        observation.revalidate()?;
        Ok(observation)
    }
}
/// A bounded snapshot selected by the actual canonical CURRENT pointer.
/// This is public metadata, not an authority or a statement about secret health.
#[derive(Debug, PartialEq, Eq)]
pub struct PublicServiceMetadata {
    root_identity: Identity,
    lock_identity: Identity,
    state_directory_identity: Identity,
    epoch: u64,
    state_revision: u64,
    current: PublicFileRecord,
    clock: PublicFileRecord,
    state: PublicFileRecord,
    owner_input: Option<PublicFileRecord>,
}
#[derive(Debug, PartialEq, Eq)]
struct PublicFileRecord {
    bytes: Vec<u8>,
    identity: Identity,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl PublicServiceMetadata {
    pub fn root_identity(&self) -> Identity {
        self.root_identity
    }
    pub fn lock_identity(&self) -> Identity {
        self.lock_identity
    }
    pub fn state_directory_identity(&self) -> Identity {
        self.state_directory_identity
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn state_revision(&self) -> u64 {
        self.state_revision
    }
    pub fn current_bytes(&self) -> &[u8] {
        &self.current.bytes
    }
    pub fn clock_bytes(&self) -> &[u8] {
        &self.clock.bytes
    }
    pub fn state_bytes(&self) -> &[u8] {
        &self.state.bytes
    }
    pub fn owner_input_bytes(&self) -> Option<&[u8]> {
        self.owner_input.as_ref().map(|v| v.bytes.as_slice())
    }
    pub fn current_identity(&self) -> Identity {
        self.current.identity
    }
    pub fn clock_identity(&self) -> Identity {
        self.clock.identity
    }
    pub fn state_identity(&self) -> Identity {
        self.state.identity
    }
    pub fn owner_input_identity(&self) -> Option<Identity> {
        self.owner_input.as_ref().map(|v| v.identity)
    }
}
/// Non-Clone metadata capability retaining one actual shared OS lease.
pub struct PublicServiceObservationLease<'root> {
    lease: ServiceLease<'root>,
    metadata: PublicServiceMetadata,
}
impl PublicServiceObservationLease<'_> {
    pub fn metadata(&self) -> &PublicServiceMetadata {
        &self.metadata
    }
    pub fn revalidate(&self) -> Result<()> {
        if self.lease.capture_public()? != self.metadata {
            return Err(deny());
        }
        Ok(())
    }
}
/// A temporary immutable view of the same exclusive lease. Drop it before
/// mutable CLOCK/publication operations, then recapture without unlocking.
pub struct BorrowedPublicServiceObservation<'lease, 'root> {
    lease: &'lease ServiceLease<'root>,
    metadata: PublicServiceMetadata,
}
impl BorrowedPublicServiceObservation<'_, '_> {
    pub fn metadata(&self) -> &PublicServiceMetadata {
        &self.metadata
    }
    pub fn revalidate(&self) -> Result<()> {
        if self.lease.capture_public()? != self.metadata {
            return Err(deny());
        }
        Ok(())
    }
}
fn selected_public_revision(raw: &[u8]) -> Result<u64> {
    // The filesystem owns only this closed locator. Domain/hash/state/clock
    // validation remains in custody and the native public contract decoder.
    let text = std::str::from_utf8(raw).map_err(|_| deny())?;
    let prefix = "{\"schema\":\"castalia.wallet-service-custody-current.v1\",\"state_revision\":";
    let rest = text.strip_prefix(prefix).ok_or_else(deny)?;
    let (number, rest) = rest.split_once(",\"state_sha256\":\"").ok_or_else(deny)?;
    if number.is_empty() || number.starts_with('0') || !number.bytes().all(|v| v.is_ascii_digit()) {
        return Err(deny());
    }
    let revision = number.parse::<u64>().map_err(|_| deny())?;
    if !(1..=9_007_199_254_740_991).contains(&revision) {
        return Err(deny());
    }
    let (digest, rest) = rest.split_once("\",\"store_id\":\"").ok_or_else(deny)?;
    let store = rest.strip_suffix("\"}").ok_or_else(deny)?;
    let hex = |s: &str, len| {
        s.len() == len
            && s.bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    };
    if !hex(digest, 64) || !hex(store, 32) {
        return Err(deny());
    }
    Ok(revision)
}
pub struct ServiceLease<'a> {
    root: &'a ServiceRoot,
    lock: Option<File>,
    lock_id: Identity,
    permit: Option<Permit>,
    exclusive: bool,
}
impl Drop for ServiceLease<'_> {
    fn drop(&mut self) {
        drop(self.lock.take());
        drop(self.permit.take());
    }
}
impl<'root> ServiceLease<'root> {
    fn writeable(&self) -> Result<()> {
        if self.exclusive { Ok(()) } else { Err(deny()) }
    }
    pub fn epoch(&self) -> Result<u64> {
        Ok(self.root.shared.state.lock().map_err(|_| deny())?.epoch)
    }
    pub fn poisoned(&self) -> Result<bool> {
        Ok(self.root.shared.state.lock().map_err(|_| deny())?.poisoned)
    }
    pub fn invalidate(&mut self, poison: bool) -> Result<u64> {
        self.writeable()?;
        let mut s = self.root.shared.state.lock().map_err(|_| deny())?;
        s.epoch = s.epoch.checked_add(1).ok_or_else(deny)?;
        s.poisoned = poison;
        Ok(s.epoch)
    }
    pub fn lock_identity(&self) -> Identity {
        self.lock_id
    }
    pub fn revalidate(&self) -> Result<()> {
        self.root.revalidate()?;
        let current = open_file(self.root.root(), "custody.lock", 0, 0)?;
        if id(&current)? != self.lock_id {
            return Err(deny());
        }
        self.inspect_bounded()?;
        Ok(())
    }
    pub fn inspect_bounded(&self) -> Result<Inventory> {
        self.root.revalidate()?;
        let root = self.root.root();
        let entries = list(root, 8)?;
        let mut charge = charged(root)?;
        let mut revisions = Vec::new();
        let mut staging = false;
        for s in &entries {
            if s == "states" {
                let states = child_dir(root, s)?;
                charge += charged(&states)?;
                let names = list(&states, 3)?;
                for rev in names {
                    if rev == ".staging" {
                        staging = true
                    } else {
                        revisions.push(parse_revision(&rev)?)
                    }
                    let dir = child_dir(&states, &rev)?;
                    charge += charged(&dir)?;
                    for f in list(&dir, 3)? {
                        let (l, a) = match f.as_str() {
                            "seed.raw" => (32, BLOCK),
                            "state.json" => (4096, BLOCK),
                            "owner-input.json" => (262144, 5 * BLOCK),
                            _ => return Err(deny()),
                        };
                        charge += charged(&open_file(&dir, &f, l, a)?)?;
                    }
                }
            } else {
                let (l, a) = match s.as_str() {
                    "custody.lock" | "RESET" => (0, 0),
                    "CURRENT" | ".CURRENT.tmp" => (512, BLOCK),
                    "CLOCK" | ".CLOCK.tmp" => (256, BLOCK),
                    _ => return Err(deny()),
                };
                charge += charged(&open_file(root, s, l, a)?)?;
            }
        }
        if charge > TOTAL {
            return Err(deny());
        }
        Ok(Inventory {
            root_entries: entries,
            revisions,
            staging,
            charge,
        })
    }
    fn growth(&self) -> Result<()> {
        self.writeable()?;
        self.revalidate()?;
        if self.inspect_bounded()?.charge > TOTAL - 1024 * 1024 {
            return Err(deny());
        }
        Ok(())
    }
    fn state_dir(&self, r: u64) -> Result<File> {
        let states = child_dir(self.root.root(), "states")?;
        child_dir(&states, &revision(r)?)
    }
    fn staging(&self) -> Result<File> {
        let states = child_dir(self.root.root(), "states")?;
        child_dir(&states, ".staging")
    }
    pub fn read(&self, what: ServiceFile) -> Result<Zeroizing<Vec<u8>>> {
        self.read_record(what).map(|v| v.0)
    }
    fn read_record(&self, what: ServiceFile) -> Result<(Zeroizing<Vec<u8>>, PublicFileRecord)> {
        self.revalidate()?;
        let (parent, s, l, a) = match what {
            ServiceFile::Current => (None, "CURRENT", 512, BLOCK),
            ServiceFile::Clock => (None, "CLOCK", 256, BLOCK),
            ServiceFile::State(r) => (Some(self.state_dir(r)?), "state.json", 4096, BLOCK),
            ServiceFile::OwnerInput(r) => (
                Some(self.state_dir(r)?),
                "owner-input.json",
                262144,
                5 * BLOCK,
            ),
            ServiceFile::Seed(r) => (Some(self.state_dir(r)?), "seed.raw", 32, BLOCK),
        };
        let mut f = open_file(parent.as_ref().unwrap_or(self.root.root()), s, l, a)?;
        let before = f.metadata()?;
        let mut bytes = Zeroizing::new(Vec::with_capacity((l + 1) as usize));
        (&mut f).take(l + 1).read_to_end(&mut bytes)?;
        #[cfg(test)]
        fault("after_read")?;
        let after = f.metadata()?;
        if bytes.len() as u64 != before.len()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(deny());
        }
        file_safe(&f, l, a)?;
        let fresh_parent = match what {
            ServiceFile::Current | ServiceFile::Clock => None,
            ServiceFile::State(r) | ServiceFile::OwnerInput(r) | ServiceFile::Seed(r) => {
                Some(self.state_dir(r)?)
            }
        };
        if let (Some(old), Some(new)) = (&parent, &fresh_parent) {
            if id(old)? != id(new)? {
                return Err(deny());
            }
        }
        let fresh = open_file(fresh_parent.as_ref().unwrap_or(self.root.root()), s, l, a)?;
        let m = fresh.metadata()?;
        if id(&f)? != id(&fresh)?
            || m.len() != after.len()
            || m.mtime() != after.mtime()
            || m.mtime_nsec() != after.mtime_nsec()
            || m.ctime() != after.ctime()
            || m.ctime_nsec() != after.ctime_nsec()
        {
            return Err(deny());
        }
        let identity = id(&fresh)?;
        drop(fresh);
        drop(fresh_parent);
        drop(f);
        drop(parent);
        self.revalidate()?;
        Ok((
            bytes,
            PublicFileRecord {
                bytes: Vec::new(),
                identity,
                modified: (after.mtime(), after.mtime_nsec()),
                changed: (after.ctime(), after.ctime_nsec()),
            },
        ))
    }
    fn public_file(&self, file: ServiceFile) -> Result<PublicFileRecord> {
        let (bytes, mut record) = self.read_record(file)?;
        record.bytes = bytes.to_vec();
        Ok(record)
    }
    fn capture_public(&self) -> Result<PublicServiceMetadata> {
        self.revalidate()?;
        if self.poisoned()? {
            return Err(deny());
        }
        let epoch = self.epoch()?;
        let current = self.public_file(ServiceFile::Current)?;
        let state_revision = selected_public_revision(&current.bytes)?;
        let directory = self.state_dir(state_revision)?;
        let state_directory_identity = id(&directory)?;
        let state = self.public_file(ServiceFile::State(state_revision))?;
        let clock = self.public_file(ServiceFile::Clock)?;
        let owner_input = match self.public_file(ServiceFile::OwnerInput(state_revision)) {
            Ok(v) => Some(v),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        self.revalidate()?;
        if self.poisoned()?
            || self.epoch()? != epoch
            || id(&self.state_dir(state_revision)?)? != state_directory_identity
        {
            return Err(deny());
        }
        Ok(PublicServiceMetadata {
            root_identity: id(self.root.root())?,
            lock_identity: self.lock_id,
            state_directory_identity,
            epoch,
            state_revision,
            current,
            clock,
            state,
            owner_input,
        })
    }
    /// Available only on an exclusive lease, with no second permit or flock.
    pub fn public_observation(&self) -> Result<BorrowedPublicServiceObservation<'_, 'root>> {
        self.writeable()?;
        let observation = BorrowedPublicServiceObservation {
            lease: self,
            metadata: self.capture_public()?,
        };
        observation.revalidate()?;
        Ok(observation)
    }
    pub fn begin_staging(&mut self) -> Result<()> {
        self.growth()?;
        let inv = self.inspect_bounded()?;
        if inv.staging || inv.revisions.len() >= 3 {
            return Err(deny());
        }
        let states = child_dir(self.root.root(), "states")?;
        if unsafe { libc::mkdirat(states.as_raw_fd(), name(".staging").as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        sync(&states)?;
        self.revalidate()
    }
    fn write_new(&self, parent: &File, s: &str, bytes: &[u8], l: u64, a: u64) -> Result<()> {
        self.growth()?;
        if bytes.len() as u64 > l {
            return Err(deny());
        }
        let mut f = open_at(
            parent,
            &name(s),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        access(&f, false)?;
        f.write_all(bytes)?;
        sync(&f)?;
        file_safe(&f, l, a)?;
        drop(f);
        sync(parent)?;
        self.revalidate()
    }
    pub fn write_staging(&mut self, what: StagingFile, bytes: &[u8]) -> Result<()> {
        let (s, l, a) = what.spec();
        let dir = self.staging()?;
        let identity = id(&dir)?;
        self.write_new(&dir, s, bytes, l, a)?;
        if id(&self.staging()?)? != identity {
            return Err(deny());
        }
        self.revalidate()
    }
    pub fn sync_staging(&self) -> Result<()> {
        self.writeable()?;
        sync(&self.staging()?)?;
        self.revalidate()
    }
    pub fn publish_revision(&mut self, r: u64) -> Result<()> {
        self.growth()?;
        let states = child_dir(self.root.root(), "states")?;
        let staged = self.staging()?;
        let identity = id(&staged)?;
        rename(&states, ".staging", &revision(r)?, false)?;
        if id(&self.state_dir(r)?)? != identity {
            return Err(deny());
        }
        drop(staged);
        sync(&states)?;
        #[cfg(test)]
        fault("after_revision_sync")?;
        self.revalidate()
    }
    fn pointer(&mut self, bytes: &[u8], clock: bool, replace: bool) -> Result<()> {
        self.growth()?;
        let (active, tmp, max) = if clock {
            ("CLOCK", ".CLOCK.tmp", 256)
        } else {
            ("CURRENT", ".CURRENT.tmp", 512)
        };
        if replace {
            drop(open_file(self.root.root(), active, max, BLOCK)?)
        } else if self
            .inspect_bounded()?
            .root_entries
            .iter()
            .any(|s| s == active)
        {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        if !clock {
            drop(open_file(self.root.root(), "CLOCK", 256, BLOCK)?)
        }
        self.write_new(self.root.root(), tmp, bytes, max, BLOCK)?;
        #[cfg(test)]
        fault(if clock {
            "before_clock_rename"
        } else {
            "before_current_rename"
        })?;
        rename(self.root.root(), tmp, active, replace)?;
        #[cfg(test)]
        fault(if clock {
            "after_clock_rename"
        } else {
            "after_current_rename"
        })?;
        sync(self.root.root())?;
        #[cfg(test)]
        fault(if clock {
            "after_clock_sync"
        } else {
            "after_current_sync"
        })?;
        self.revalidate()
    }
    pub fn publish_current(&mut self, bytes: &[u8], replace: bool) -> Result<()> {
        self.pointer(bytes, false, replace)
    }
    pub fn publish_clock(&mut self, bytes: &[u8], replace: bool) -> Result<()> {
        self.pointer(bytes, true, replace)
    }
    pub fn sync_current(&self) -> Result<()> {
        self.writeable()?;
        for (s, l) in [("CURRENT", 512), ("CLOCK", 256)] {
            sync(&open_file(self.root.root(), s, l, BLOCK)?)?
        }
        sync(self.root.root())?;
        self.revalidate()
    }
    fn remove_dir(&mut self, s: &str) -> Result<()> {
        self.writeable()?;
        self.revalidate()?;
        let states = child_dir(self.root.root(), "states")?;
        let dir = child_dir(&states, s)?;
        for f in list(&dir, 3)? {
            if !matches!(f.as_str(), "state.json" | "seed.raw" | "owner-input.json") {
                return Err(deny());
            }
            unlink(&dir, &f, false)?;
        }
        sync(&dir)?;
        drop(dir);
        unlink(&states, s, true)?;
        sync(&states)?;
        self.revalidate()
    }
    pub fn remove_revision(&mut self, r: u64) -> Result<()> {
        self.remove_dir(&revision(r)?)
    }
    pub fn remove_staging(&mut self) -> Result<()> {
        self.remove_dir(".staging")
    }
    /// Caller must have validated the selected CURRENT before abandoning
    /// unreferenced temporary pointer/clock writes. Never changes CURRENT/CLOCK.
    pub fn discard_temporary(&mut self) -> Result<()> {
        self.writeable()?;
        self.revalidate()?;
        let inv = self.inspect_bounded()?;
        for s in [".CLOCK.tmp", ".CURRENT.tmp"] {
            if inv.root_entries.iter().any(|v| v == s) {
                unlink(self.root.root(), s, false)?;
            }
        }
        sync(self.root.root())?;
        self.revalidate()
    }
    pub fn abandon_incomplete(&mut self) -> Result<()> {
        self.writeable()?;
        self.revalidate()?;
        let inv = self.inspect_bounded()?;
        if inv.root_entries.iter().any(|s| s == "CURRENT") || inv.revisions.iter().any(|r| *r != 1)
        {
            return Err(deny());
        }
        for r in inv.revisions {
            self.remove_revision(r)?
        }
        if inv.staging {
            self.remove_staging()?
        }
        for s in ["CLOCK", ".CLOCK.tmp", ".CURRENT.tmp"] {
            if inv.root_entries.iter().any(|v| v == s) {
                unlink(self.root.root(), s, false)?
            }
        }
        if !inv.root_entries.iter().any(|s| s == "states")
            && unsafe {
                libc::mkdirat(self.root.root().as_raw_fd(), name("states").as_ptr(), 0o700)
            } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if !inv.root_entries.iter().any(|s| s == "RESET") {
            self.write_new(self.root.root(), "RESET", &[], 0, 0)?
        }
        sync(self.root.root())?;
        self.invalidate(false)?;
        self.revalidate()
    }
}
#[cfg(test)]
type TestAction = Option<Box<dyn FnMut(&str)>>;
#[cfg(test)]
thread_local! {
 static TEST_FAILURE: std::cell::RefCell<Option<&'static str>> = const { std::cell::RefCell::new(None) };
 static TEST_ACTION: std::cell::RefCell<TestAction> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn fault(step: &'static str) -> Result<()> {
    TEST_ACTION.with(|v| {
        if let Some(f) = v.borrow_mut().as_mut() {
            f(step);
        }
    });
    TEST_FAILURE.with(|v| {
        if *v.borrow() == Some(step) {
            Err(io::ErrorKind::Other.into())
        } else {
            Ok(())
        }
    })
}
#[cfg(test)]
#[path = "service_store_tests.rs"]
mod tests;
