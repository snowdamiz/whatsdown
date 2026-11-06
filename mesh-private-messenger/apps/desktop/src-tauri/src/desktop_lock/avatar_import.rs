//! Worker-only import from a consumed native choice. Source and output buffers
//! remain owned through all original-scope completion fences.
use super::{
    native_job::{native_scope, NativeScope},
    private_files::{ChosenSource, FileError, FileHandle, PrivateFiles, Role},
    receiver_scope::PrivateScope,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    ffi::c_void,
    ptr::NonNull,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use zeroize::Zeroizing;
unsafe extern "C" {
    fn MDNativeAvatarEncode(scope: NativeScope, bytes: *const u8, length: u64) -> *mut c_void;
    fn MDNativeAvatarBytes(encoded: *mut c_void, length: *mut u64) -> *const u8;
    fn MDNativeAvatarRelease(encoded: *mut c_void);
}
static IMPORTS: AtomicUsize = AtomicUsize::new(0);
struct ImportSlot;
impl ImportSlot {
    fn reserve() -> Result<Self, FileError> {
        IMPORTS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 4).then_some(count + 1)
            })
            .map(|_| Self)
            .map_err(|_| FileError::Limit)
    }
}
impl Drop for ImportSlot {
    fn drop(&mut self) {
        IMPORTS.fetch_sub(1, Ordering::AcqRel);
    }
}
struct Encoded(NonNull<c_void>);
impl Drop for Encoded {
    fn drop(&mut self) {
        unsafe {
            MDNativeAvatarRelease(self.0.as_ptr());
        }
    }
}
struct SourceHold {
    files: Arc<PrivateFiles>,
    scope: PrivateScope,
    handle: FileHandle,
}
impl Drop for SourceHold {
    fn drop(&mut self) {
        self.files.cleanup(
            self.scope.owner(),
            self.scope.epoch(),
            Role::Source,
            self.handle,
        );
    }
}
pub(crate) fn import(
    files: Arc<PrivateFiles>,
    scope: PrivateScope,
    source: ChosenSource,
) -> Result<Zeroizing<String>, FileError> {
    scope.check()?;
    let _slot = ImportSlot::reserve()?;
    let size = source.size();
    if size == 0 || size > 20 * 1024 * 1024 {
        return Err(FileError::Limit);
    }
    let handle = files.claim_source(&scope, source, size)?;
    let _source = SourceHold {
        files: files.clone(),
        scope: scope.clone(),
        handle,
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(size as usize));
    let mut offset = 0;
    while offset < size {
        let chunk = files.read_source(
            &scope,
            handle,
            offset,
            std::cmp::min(65_536, (size - offset) as usize),
        )?;
        bytes.extend_from_slice(&chunk);
        offset += chunk.len() as u64;
    }
    scope.check()?;
    let scope = Arc::new(scope);
    let encoded = NonNull::new(unsafe {
        MDNativeAvatarEncode(native_scope(&scope), bytes.as_ptr(), bytes.len() as u64)
    })
    .map(Encoded);
    // Take raw returned ownership before the final fence can refuse it.
    scope.check()?;
    let encoded = encoded.ok_or(FileError::Invalid)?;
    let mut length = 0;
    let raw = unsafe { MDNativeAvatarBytes(encoded.0.as_ptr(), &mut length) };
    if raw.is_null() || length == 0 || length > 9198 {
        return Err(FileError::Invalid);
    }
    let jpeg = Zeroizing::new(unsafe { std::slice::from_raw_parts(raw, length as usize) }.to_vec());
    scope.check()?;
    let base64 = Zeroizing::new(STANDARD.encode(jpeg.as_slice()));
    let avatar = Zeroizing::new(format!("data:image/jpeg;base64,{}", base64.as_str()));
    if avatar.len() > 12_288 {
        return Err(FileError::Limit);
    }
    scope.check()?;
    Ok(avatar)
}
