//! A native save choice retains filesystem identity without changing user data.
use super::{private_exports::{ExportContext, ExportError}, receiver_scope::{fresh_uuid, ChoiceAnchor, PrivateScope}, wire};
use std::{
    ffi::CString,
    fs::{File, Metadata, OpenOptions},
    os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt}}},
    path::Path,
    sync::{Arc,Mutex},
    time::{Duration, Instant},
};

#[derive(PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DestinationId([u8; 16]);
impl DestinationId {
    pub(crate) fn wire(self) -> String { wire::uuid(self.0) }
    fn parse(value: &str) -> Result<Self, ExportError> {
        wire::parse_uuid(value).map(Self).ok_or(ExportError::Invalid)
    }
}
struct Pending {
    id: DestinationId,
    anchor: ChoiceAnchor,
    expires: Instant,
    context: ExportContext,
    destination: ChosenDestination,
}
struct Choices {
    closed: bool,
    pending: Vec<Pending>,
}
pub(crate) struct DestinationChoices(Mutex<Choices>);
pub(crate) struct SelectedExport {
    destination: ChosenDestination,
    context: ExportContext,
    anchor: ChoiceAnchor,
}
impl SelectedExport {
    pub(super) fn from_choice(anchor:ChoiceAnchor,destination:ChosenDestination,context:ExportContext)->Self {
        Self { anchor,destination,context }
    }
    pub(super) fn bind(self, scope: &PrivateScope) -> Result<(ChosenDestination, ExportContext), ExportError> {
        self.anchor.matches(scope)?;
        Ok((self.destination, self.context))
    }
}
impl DestinationChoices {
    pub(crate) fn new() -> Self {
        Self(Mutex::new(Choices { closed: false, pending: Vec::new() }))
    }
    pub(crate) fn remember(&self, anchor: ChoiceAnchor, context: ExportContext,
        destination: ChosenDestination, now: Instant) -> Result<DestinationId, ExportError> {
        anchor.current()?;
        self.expire(now);
        let id = DestinationId(fresh_uuid()?);
        {
            let mut choices = self.0.lock().map_err(|_| ExportError::Unavailable)?;
            if choices.closed || choices.pending.len() >= 4 { return Err(ExportError::Unavailable); }
            choices.pending.push(Pending { id, anchor: anchor.clone(), context, destination,
                expires: now + Duration::from_secs(120) });
        }
        if let Err(error) = anchor.current() { self.remove(id); return Err(error.into()); }
        if !self.0.lock().map_err(|_| ExportError::Unavailable)?.pending.iter().any(|p| p.id == id) {
            return Err(ExportError::Unavailable);
        }
        Ok(id)
    }
    fn remove(&self, id: DestinationId) -> Option<Pending> {
        let mut choices = self.0.lock().unwrap_or_else(|e| e.into_inner());
        choices.pending.iter().position(|p| p.id == id).map(|i| choices.pending.remove(i))
    }
    /// Native timer and accesses supply monotonic time, never a caller clock.
    pub(crate) fn expire(&self, now: Instant) {
        let snapshot = self.0.lock().unwrap_or_else(|e| e.into_inner()).pending.iter()
            .map(|p| (p.id, p.expires, p.anchor.clone())).collect::<Vec<_>>();
        for (id, expires, anchor) in snapshot {
            if now >= expires || anchor.current().is_err() { drop(self.remove(id)); }
        }
    }
    pub(crate) fn pending(&self, scope: &PrivateScope, context: &ExportContext, now: Instant)
        -> Result<Option<DestinationId>, ExportError> {
        scope.check()?;
        self.expire(now);
        let found = self.0.lock().map_err(|_| ExportError::Unavailable)?.pending.iter().rev()
            .find(|p| p.context == *context).map(|p| (p.id, p.anchor.clone()));
        if let Some((id, anchor)) = found { anchor.matches(scope)?; Ok(Some(id)) }
        else { scope.check()?; Ok(None) }
    }
    pub(crate) fn claim(&self, scope: &PrivateScope, id: &str, context: &ExportContext, now: Instant)
        -> Result<SelectedExport, ExportError> {
        scope.check()?;
        let id = DestinationId::parse(id)?;
        // A valid opaque choice is consumed once, including validation failure.
        let pending = self.remove(id).ok_or(ExportError::Unavailable)?;
        if now >= pending.expires || pending.context != *context { return Err(ExportError::Unavailable); }
        pending.anchor.matches(scope)?;
        Ok(SelectedExport { destination: pending.destination, context: pending.context, anchor: pending.anchor })
    }
    pub(crate) fn close(&self) {
        let retired = {
            let mut choices = self.0.lock().unwrap_or_else(|e| e.into_inner());
            choices.closed = true;
            std::mem::take(&mut choices.pending)
        };
        drop(retired);
    }
}
impl Drop for DestinationChoices { fn drop(&mut self) { self.close(); } }
impl Identity {
    fn read(metadata: Metadata) -> Result<Self, ExportError> {
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(ExportError::Invalid);
        }
        Ok(Self {
            device: metadata.dev(), inode: metadata.ino(), size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

enum Target {
    Absent,
    Existing { file: File, identity: Identity },
}

pub(crate) struct ChosenDestination {
    parent: File,
    name: CString,
    target: Target,
    access: Option<Arc<dyn super::private_files::NativeFileAccess>>,
}
/// Keeps the native URL access grant alive through the final write and sync.
pub(crate) struct DestinationFile {
    file: File,
    _access: Option<Arc<dyn super::private_files::NativeFileAccess>>,
}
impl DestinationFile {
    pub(super) fn sync_all(&self)->std::io::Result<()> { self.file.sync_all() }
    #[cfg(test)]
    pub(super) fn unscoped(file:File)->Self { Self { file,_access:None } }
}
impl std::io::Write for DestinationFile {
    fn write(&mut self,bytes:&[u8])->std::io::Result<usize> { std::io::Write::write(&mut self.file,bytes) }
    fn flush(&mut self)->std::io::Result<()> { std::io::Write::flush(&mut self.file) }
}
impl ChosenDestination {
    /// Called only for a URL returned by the native save panel. The panel's
    /// security-scoped URL owner must outlive this descriptor when applicable.
    pub(crate) fn capture_selected(native_path:&Path,access:Arc<dyn super::private_files::NativeFileAccess>)->Result<Self,ExportError> {
        Self::capture_with_access(native_path,Some(access))
    }
    #[cfg(test)]
    pub(crate) fn capture(native_path:&Path)->Result<Self,ExportError> { Self::capture_with_access(native_path,None) }
    fn capture_with_access(native_path: &Path,access:Option<Arc<dyn super::private_files::NativeFileAccess>>) -> Result<Self, ExportError> {
        if !native_path.is_absolute() { return Err(ExportError::Invalid); }
        let parent_path = native_path.parent().ok_or(ExportError::Invalid)?;
        let name = native_path.file_name().ok_or(ExportError::Invalid)?.as_bytes();
        if name.is_empty() || name.len() > 255 { return Err(ExportError::Invalid); }
        let name = CString::new(name).map_err(|_| ExportError::Invalid)?;
        let parent = OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent_path).map_err(|_| ExportError::Unavailable)?;
        let raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(),
            libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        let target = if raw >= 0 {
            let file = unsafe { File::from_raw_fd(raw) };
            let identity = Identity::read(file.metadata().map_err(|_| ExportError::Unavailable)?)?;
            Target::Existing { file, identity }
        } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Target::Absent
        } else {
            return Err(ExportError::Unavailable);
        };
        Ok(Self { parent, name, target, access })
    }

    pub(crate) fn open(self, scope: &PrivateScope) -> Result<DestinationFile, ExportError> {
        scope.check()?;
        let file = self.open_selected()?;
        scope.check()?;
        Ok(file)
    }

    fn open_selected(self) -> Result<DestinationFile, ExportError> {
        let file=match self.target {
            Target::Absent => {
                let raw = unsafe { libc::openat(self.parent.as_raw_fd(), self.name.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600) };
                if raw < 0 { return Err(ExportError::Unavailable); }
                unsafe { File::from_raw_fd(raw) }
            }
            Target::Existing { file, identity } => {
                if Identity::read(file.metadata().map_err(|_| ExportError::Unavailable)?)? != identity {
                    return Err(ExportError::Unavailable);
                }
                let mut named: libc::stat = unsafe { std::mem::zeroed() };
                let found = unsafe { libc::fstatat(self.parent.as_raw_fd(), self.name.as_ptr(),
                    &mut named, libc::AT_SYMLINK_NOFOLLOW) };
                if found != 0 || named.st_dev as u64 != identity.device || named.st_ino as u64 != identity.inode
                    || named.st_mode & libc::S_IFMT != libc::S_IFREG {
                    return Err(ExportError::Unavailable);
                }
                // The retained descriptor prevents a pathname swap from
                // redirecting truncation or plaintext to a replacement file.
                file.set_len(0).map_err(|_| ExportError::Unavailable)?;
                file
            }
        };
        Ok(DestinationFile { file,_access:self.access })
    }
}


#[cfg(all(test, feature = "native-boundary-tests"))]
#[path = "tests/destination_tests.rs"]
#[allow(dead_code)]
mod tests;
