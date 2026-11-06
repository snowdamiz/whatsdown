//! Native installation policy context, including the app-lifetime OS owner.
//! `open` must run on the worker before constructing Core/the controller.
use crate::desktop_lock::controller::{Policy, PolicyStore, Record, Refusal};
use std::ffi::{c_char, c_void, CString};
use std::{fs::File,os::fd::FromRawFd,path::Path};
use std::ptr::NonNull;

unsafe extern "C" {
    fn MDNativePolicyOpen(bundle: *const c_char, directory: *const c_char, failure: *mut i32) -> *mut c_void;
    fn MDNativePolicyCurrent(context: *mut c_void) -> bool;
    fn MDNativePolicyDuplicateOwnedDirectory(context:*mut c_void)->i32;
    fn MDNativePolicyRead(context: *mut c_void, install: *mut u8, sequence: *mut u64, policy: *mut u32) -> i32;
    fn MDNativePolicyTransition(context: *mut c_void, previous_install: *const u8, previous_sequence: u64,
        previous_policy: u32, desired: u32, install: *mut u8, sequence: *mut u64, policy: *mut u32) -> i32;
    fn MDNativePolicyRelease(context: *mut c_void);
}

pub struct NativePolicyStore {
    context: NonNull<c_void>,
    directory:File,
}
// The actual context serializes canonical policy IO; owner identity checks and
// close are locked native operations. No UI or callbacks occur through this ABI.
unsafe impl Send for NativePolicyStore {}
unsafe impl Sync for NativePolicyStore {}
impl NativePolicyStore {
    pub fn open(bundle: &str, app_data: &Path) -> Result<Self, Refusal> {
        let bundle = CString::new(bundle).map_err(|_| Refusal::PolicyUnreadable)?;
        let directory = app_data.to_str().ok_or(Refusal::PolicyUnreadable)?;
        let directory = CString::new(directory).map_err(|_| Refusal::PolicyUnreadable)?;
        let mut failure = 1;
        let context = unsafe { MDNativePolicyOpen(bundle.as_ptr(), directory.as_ptr(), &mut failure) };
        if failure != 0 {
            if !context.is_null() { unsafe { MDNativePolicyRelease(context) }; }
            return Err(Refusal::PolicyUnreadable);
        }
        Self::from_native_context(context)
    }
    fn from_native_context(context:*mut c_void)->Result<Self,Refusal> {
        let context=NonNull::new(context).ok_or(Refusal::PolicyUnreadable)?;
        let raw=unsafe { MDNativePolicyDuplicateOwnedDirectory(context.as_ptr()) };
        if raw<0 {
            unsafe { MDNativePolicyRelease(context.as_ptr()); }
            return Err(Refusal::PolicyUnreadable);
        }
        Ok(Self { context,directory:unsafe { File::from_raw_fd(raw) } })
    }
    pub(super) fn owned_directory(&self)->Result<File,Refusal> {
        if !self.current() { return Err(Refusal::PolicyUnreadable); }
        let directory=self.directory.try_clone().map_err(|_|Refusal::PolicyUnreadable)?;
        if !self.current() { return Err(Refusal::PolicyUnreadable); }
        Ok(directory)
    }
    pub fn current(&self) -> bool { unsafe { MDNativePolicyCurrent(self.context.as_ptr()) } }
    fn record(&self, operation: impl FnOnce(*mut u8, *mut u64, *mut u32) -> i32) -> Result<Record, Refusal> {
        if !self.current() { return Err(Refusal::PolicyUnreadable); }
        let mut install = [0;16]; let mut sequence = 0; let mut state = 0;
        let status = operation(install.as_mut_ptr(), &mut sequence, &mut state);
        if !self.current() { install.fill(0); return Err(Refusal::PolicyUnreadable); }
        match status {
            0 => Ok(Record { install, sequence, policy: match state {
                0 => Policy::Disabled, 1 => Policy::EnablePending, 2 => Policy::Enabled, 3 => Policy::DisablePending,
                _ => return Err(Refusal::PolicyUnreadable),
            }}),
            2 => Err(Refusal::PolicyChanged),
            _ => Err(Refusal::PolicyUnreadable),
        }
    }
    #[cfg(test)]
    pub(crate) unsafe fn from_test_context(context: *mut c_void) -> Result<Self, Refusal> {
        Self::from_native_context(context)
    }
}
fn native_policy(policy: Policy) -> u32 {
    match policy { Policy::Disabled => 0, Policy::EnablePending => 1, Policy::Enabled => 2, Policy::DisablePending => 3 }
}
impl PolicyStore for NativePolicyStore {
    fn read(&self) -> Result<Record, Refusal> {
        self.record(|install,sequence,policy| unsafe { MDNativePolicyRead(self.context.as_ptr(),install,sequence,policy) })
    }
    fn compare_write(&self, previous: Record, desired: Policy) -> Result<Record, Refusal> {
        self.record(|install,sequence,policy| unsafe {
            MDNativePolicyTransition(self.context.as_ptr(),previous.install.as_ptr(),previous.sequence,
                native_policy(previous.policy),native_policy(desired),install,sequence,policy)
        })
    }
}
impl Drop for NativePolicyStore {
    fn drop(&mut self) { unsafe { MDNativePolicyRelease(self.context.as_ptr()) }; }
}
