//! Prepare the app's ciphertext directory before accepting any exports.
//! Startup only removes bounded, recognized files from this private directory.
use super::{
    native_policy::NativePolicyStore,
    private_exports::{ExportError, StageDirectory},
    wire,
};
use std::{
    ffi::{CStr, CString},
    fs::{File, Metadata},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    sync::Arc,
};

const DIRECTORY: &CStr = c"private-exports-v1";
const SESSION: &CStr = c"session.v1";
const FORMAT: &[u8] = b"Morse encrypted export staging v1\n";
const MAX_ORPHANS: usize = 64;
const MAX_ENCODED: u64 = 536_870_912 + 8192 * 24;

fn unavailable<T>(_: T) -> ExportError {
    ExportError::Unavailable
}
fn owned_directory(m: &Metadata) -> bool {
    m.is_dir() && m.uid() == unsafe { libc::geteuid() } && m.mode() & 0o777 == 0o700
}
fn owned_file(m: &Metadata) -> bool {
    m.is_file()
        && m.uid() == unsafe { libc::geteuid() }
        && m.nlink() == 1
        && m.mode() & 0o777 == 0o600
}
fn named_matches(parent: &File, name: &CStr, held: &Metadata) -> bool {
    let mut named: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut named,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    }) == 0
        && named.st_dev as u64 == held.dev()
        && named.st_ino as u64 == held.ino()
        && (named.st_mode & libc::S_IFMT) as u32 == (held.mode() & libc::S_IFMT as u32)
}

/// Retained by StageDirectory, including every in-flight EncryptedExport Arc.
/// Native policy supplies the actual held directory and process-owner proof.
pub(super) struct StageOwner {
    policy: Arc<NativePolicyStore>,
    app_data: File,
    session: File,
}
impl StageOwner {
    pub(super) fn check(&self, directory: &File) -> Result<(), ExportError> {
        self.check_identity(directory)?;
        if self.session.metadata().map_err(unavailable)?.len() != FORMAT.len() as u64 {
            return Err(ExportError::Unavailable);
        }
        Ok(())
    }
    fn check_identity(&self, directory: &File) -> Result<(), ExportError> {
        if !self.policy.current() {
            return Err(ExportError::Unavailable);
        }
        let parent = self.app_data.metadata().map_err(unavailable)?;
        let folder = directory.metadata().map_err(unavailable)?;
        let session = self.session.metadata().map_err(unavailable)?;
        if !owned_directory(&parent)
            || !owned_directory(&folder)
            || !named_matches(&self.app_data, DIRECTORY, &folder)
            || !owned_file(&session)
            || session.len() > FORMAT.len() as u64
            || !named_matches(directory, SESSION, &session)
            || !self.policy.current()
        {
            return Err(ExportError::Unavailable);
        }
        Ok(())
    }
}

struct DirectoryStream(*mut libc::DIR);
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}
fn names(directory: &File) -> Result<Vec<CString>, ExportError> {
    let fd = directory.try_clone().map_err(unavailable)?.into_raw_fd();
    let raw = unsafe { libc::fdopendir(fd) };
    if raw.is_null() {
        unsafe {
            libc::close(fd);
        }
        return Err(ExportError::Unavailable);
    }
    let stream = DirectoryStream(raw);
    // dup shares the descriptor position. Each bounded inventory starts at
    // the beginning, including a second inventory after marker recovery.
    unsafe {
        libc::rewinddir(stream.0);
    }
    let mut names = Vec::new();
    loop {
        // This module is compiled only by the protected macOS desktop target.
        unsafe {
            *libc::__error() = 0;
        }
        let row = unsafe { libc::readdir(stream.0) };
        if row.is_null() {
            if unsafe { *libc::__error() } != 0 {
                return Err(ExportError::Unavailable);
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*row).d_name.as_ptr()) };
        if name == c"." || name == c".." {
            continue;
        }
        if names.len() >= MAX_ORPHANS + 1 {
            return Err(ExportError::Unavailable);
        }
        names.push(name.to_owned());
    }
    Ok(names)
}
fn inventory(directory: &File, owner: &StageOwner) -> Result<Vec<(CString, File)>, ExportError> {
    owner.check(directory)?;
    let mut files = Vec::new();
    for name in names(directory)? {
        if name.as_c_str() == SESSION {
            continue;
        }
        if files.len() >= MAX_ORPHANS {
            return Err(ExportError::Unavailable);
        }
        let text = name.to_str().map_err(unavailable)?;
        let uuid = text
            .strip_suffix(".stage")
            .ok_or(ExportError::Unavailable)?;
        if wire::parse_uuid(uuid).is_none() {
            return Err(ExportError::Unavailable);
        }
        owner.check(directory)?;
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(ExportError::Unavailable);
        }
        let file = unsafe { File::from_raw_fd(raw) };
        let metadata = file.metadata().map_err(unavailable)?;
        if !owned_file(&metadata)
            || metadata.len() > MAX_ENCODED
            || !named_matches(directory, &name, &metadata)
        {
            return Err(ExportError::Unavailable);
        }
        files.push((name, file));
    }
    owner.check(directory)?;
    Ok(files)
}

/// This is the only production StageDirectory constructor. No caller path,
/// policy flag, JavaScript token or latest-window lookup authorizes cleanup.
pub(crate) fn prepare(policy: Arc<NativePolicyStore>) -> Result<Arc<StageDirectory>, ExportError> {
    if !policy.current() {
        return Err(ExportError::Unavailable);
    }
    let app_data=policy.owned_directory()?;
    if !owned_directory(&app_data.metadata().map_err(unavailable)?) || !policy.current() {
        return Err(ExportError::Unavailable);
    }
    let created = unsafe { libc::mkdirat(app_data.as_raw_fd(), DIRECTORY.as_ptr(), 0o700) } == 0;
    if !created && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
        return Err(ExportError::Unavailable);
    }
    let raw = unsafe {
        libc::openat(
            app_data.as_raw_fd(),
            DIRECTORY.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(ExportError::Unavailable);
    }
    let directory = unsafe { File::from_raw_fd(raw) };
    if !owned_directory(&directory.metadata().map_err(unavailable)?) || !policy.current() {
        return Err(ExportError::Unavailable);
    }
    let flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    let open_session = |create_flags| unsafe {
        libc::openat(
            directory.as_raw_fd(),
            SESSION.as_ptr(),
            flags | create_flags,
            0o600,
        )
    };
    let mut raw = open_session(0);
    if raw < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        // Process ownership, an empty private directory and exclusive marker
        // creation make mkdir-before-marker interruption recoverable. Never
        // add a marker to an unrecognized nonempty directory.
        if !names(&directory)?.is_empty()
            || !policy.current()
            || !named_matches(
                &app_data,
                DIRECTORY,
                &directory.metadata().map_err(unavailable)?,
            )
        {
            return Err(ExportError::Unavailable);
        }
        raw = open_session(libc::O_CREAT | libc::O_EXCL);
        if raw < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST) {
            raw = open_session(0);
        }
    }
    if raw < 0 {
        return Err(ExportError::Unavailable);
    }
    let session = unsafe { File::from_raw_fd(raw) };
    let metadata = session.metadata().map_err(unavailable)?;
    if !owned_file(&metadata)
        || metadata.len() > FORMAT.len() as u64
        || unsafe { libc::flock(session.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err(ExportError::Unavailable);
    }
    let owner = StageOwner {
        policy,
        app_data,
        session,
    };
    owner.check_identity(&directory)?;
    let length = owner.session.metadata().map_err(unavailable)?.len() as usize;
    let mut format = [0u8; FORMAT.len()];
    let prefix = format.get_mut(..length).ok_or(ExportError::Unavailable)?;
    owner
        .session
        .read_exact_at(prefix, 0)
        .map_err(unavailable)?;
    if prefix != &FORMAT[..length] {
        return Err(ExportError::Unavailable);
    }
    if length != FORMAT.len() {
        // Complete only an exact prefix of this public marker, with no other
        // directory entries. No old ciphertext is erased under a partial marker.
        let entries = names(&directory)?;
        if entries.len() != 1 || entries[0].as_c_str() != SESSION {
            return Err(ExportError::Unavailable);
        }
        owner.check_identity(&directory)?;
        owner
            .session
            .write_all_at(&FORMAT[length..], length as u64)
            .map_err(unavailable)?;
        owner.session.sync_all().map_err(unavailable)?;
        directory.sync_all().map_err(unavailable)?;
        owner.app_data.sync_all().map_err(unavailable)?;
    }
    // Validate every entry before mutating any. Held FDs keep identities alive;
    // no recursive directory removal and no traversal of unknown entries.
    let files = inventory(&directory, &owner)?;
    for (name, file) in files {
        owner.check(&directory)?;
        let held = file.metadata().map_err(unavailable)?;
        if !owned_file(&held) || !named_matches(&directory, &name, &held) {
            return Err(ExportError::Unavailable);
        }
        if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(ExportError::Unavailable);
        }
    }
    directory.sync_all().map_err(unavailable)?;
    owner.check(&directory)?;
    StageDirectory::from_startup(directory, owner)
}
