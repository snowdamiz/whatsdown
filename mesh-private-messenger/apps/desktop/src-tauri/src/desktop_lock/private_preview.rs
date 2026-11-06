//! Creation-time native WK scheme handler. The actual WK receiver chooses no
//! epoch: each preview entry retains its original scope through publication.
use super::{native_protection::NativeProtection,private_files::{FileHandle,PrivateFiles,PreviewReply},receiver_scope::MainThread};
use objc2::rc::Retained;
use objc2_web_kit::WKWebViewConfiguration;
use std::{ffi::c_void,sync::Arc};

#[repr(C)]
struct Payload {
    context:*mut c_void,
    release:Option<extern "C" fn(*mut c_void)>,
    current:Option<extern "C" fn(*mut c_void,*mut c_void)->bool>,
    bytes:*const u8,length:u64,mime:*const u8,mime_length:u64,
}
impl Payload {
    fn refused()->Self { Self { context:std::ptr::null_mut(),release:None,current:None,bytes:std::ptr::null(),length:0,mime:std::ptr::null(),mime_length:0 } }
}
type Complete=extern "C" fn(*mut c_void,Payload);
#[repr(C)]
struct Provider {
    context:*const c_void,retain:extern "C" fn(*const c_void),release:extern "C" fn(*const c_void),
    start:extern "C" fn(*const c_void,*mut c_void,*const u8,u64,*mut c_void,Complete),
}
unsafe extern "C" { fn MDPrivatePreviewConfiguration(provider:Provider)->*mut WKWebViewConfiguration; }
struct State { native:Arc<NativeProtection>,files:Arc<PrivateFiles> }
struct Held { native:Arc<NativeProtection>,reply:PreviewReply }
fn boundary<T>(work:impl FnOnce()->T)->T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)) { Ok(value)=>value,Err(_)=>std::process::abort() }
}
extern "C" fn retain(raw:*const c_void) { unsafe { Arc::increment_strong_count(raw.cast::<State>()) }; }
extern "C" fn release(raw:*const c_void) { unsafe { Arc::decrement_strong_count(raw.cast::<State>()) }; }
extern "C" fn release_payload(raw:*mut c_void) { boundary(||unsafe { drop(Box::from_raw(raw.cast::<Held>())) }); }
extern "C" fn current(raw:*mut c_void,actual_view:*mut c_void)->bool {
    boundary(|| {
        let held=unsafe { &*raw.cast::<Held>() };
        let Ok(owner)=(unsafe { held.native.private_receiver_on_main(actual_view) }) else { return false; };
        if held.reply.check(owner).is_err() { return false; }
        // Policy admission may synchronously revoke/rebind native presentation.
        unsafe { held.native.private_receiver_on_main(actual_view) }.is_ok_and(|after|after==owner)
    })
}
extern "C" fn start(raw:*const c_void,actual_view:*mut c_void,bytes:*const u8,length:u64,job:*mut c_void,complete:Complete) {
    boundary(|| {
        let state=unsafe { &*raw.cast::<State>() };
        let prepared=(|| {
            MainThread::current().ok()?;
            if bytes.is_null() || length!=36 { return None; }
            let text=std::str::from_utf8(unsafe { std::slice::from_raw_parts(bytes,length as usize) }).ok()?;
            let handle=FileHandle::parse(text).ok()?;
            let owner=unsafe { state.native.private_receiver_on_main(actual_view) }.ok()?;
            Some((handle,owner))
        })();
        let Some((handle,owner))=prepared else { complete(job,Payload::refused());return; };
        let files=state.files.clone();let native=state.native.clone();let job=job as usize;
        // The native handler reserves one of four process-wide slots *before*
        // spawning. Cancellation retains that reservation until this drains.
        let launched=std::thread::Builder::new().name("private-preview".into()).spawn(move ||boundary(|| {
            let payload=match files.preview_for_receiver(owner,handle) {
                Ok(reply)=>{
                    let held=Box::new(Held { native,reply });
                    let bytes=held.reply.bytes();let mime=held.reply.mime().as_bytes();
                    let bytes_ptr=bytes.as_ptr();let length=bytes.len() as u64;let mime_ptr=mime.as_ptr();let mime_length=mime.len() as u64;
                    Payload { context:Box::into_raw(held).cast(),release:Some(release_payload),current:Some(current),bytes:bytes_ptr,length,mime:mime_ptr,mime_length }
                },
                Err(_)=>Payload::refused(),
            };
            complete(job as *mut c_void,payload);
        }));
        if launched.is_err() { complete(job as *mut c_void,Payload::refused()); }
    });
}
pub(crate) fn configuration(native:Arc<NativeProtection>,files:Arc<PrivateFiles>)->Result<Retained<WKWebViewConfiguration>,&'static str> {
    MainThread::current().map_err(|_|"app_lock_unavailable")?;
    let state=Arc::new(State { native,files });
    let provider=Provider { context:Arc::as_ptr(&state).cast(),retain,release,start };
    // Native factory returns exactly +1 typed configuration. Default data store
    // and preinstalled handler survive Wry's remaining protocol registration.
    unsafe { Retained::from_raw(MDPrivatePreviewConfiguration(provider)) }.ok_or("app_lock_unavailable")
}
