//! App-lifetime native broker. Raw ownership stays paired to its original protection.
use super::{controller::Refusal,notification_actions::{native_authorization_scope,NativeAuthorizationScope,NotificationAction},receiver_scope::MainThread};
use std::{ffi::c_void,ptr::NonNull,sync::Arc};
use zeroize::{Zeroize,Zeroizing};
struct WakeSink(Box<dyn Fn()+Send+Sync>);
#[repr(C)]
struct Wake {context:*const c_void,retain:extern "C" fn(*const c_void),release:extern "C" fn(*const c_void),wake:extern "C" fn(*const c_void)}
#[repr(C)]
struct RawIntent {kind:u32,length:usize,scope:[u8;71]}
impl Default for RawIntent {fn default()->Self{Self{kind:0,length:0,scope:[0;71]}}}
impl Drop for RawIntent {fn drop(&mut self){self.kind.zeroize();self.length.zeroize();self.scope.zeroize();}}
unsafe extern "C" {
 fn MDNativeNoticeBrokerCreate(protection:*mut c_void,wake:Wake)->*mut c_void;
 fn MDNativeNoticeBrokerPublish(protection:*mut c_void,broker:*mut c_void,action:NativeAuthorizationScope,account:u64,
  title:*const u8,title_length:u64,body:*const u8,body_length:u64,scope:*const u8,scope_length:u64)->bool;
 fn MDNativeNoticeBrokerConsume(protection:*mut c_void,broker:*mut c_void,action:NativeAuthorizationScope,account:u64,output:*mut RawIntent)->bool;
 fn MDNativeNoticeBrokerRetireInvalid(broker:*mut c_void);
 fn MDNativeNoticeBrokerClose(broker:*mut c_void);
 fn MDNativeNoticeBrokerRelease(broker:*mut c_void);
}
extern "C" fn hold(raw:*const c_void){unsafe{Arc::increment_strong_count(raw.cast::<WakeSink>())};}
extern "C" fn drop_wake(raw:*const c_void){unsafe{Arc::decrement_strong_count(raw.cast::<WakeSink>())};}
extern "C" fn wake(raw:*const c_void){if std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{let sink=unsafe{&*raw.cast::<WakeSink>()};(sink.0)();})).is_err(){std::process::abort();}}
pub(crate) enum NativeNoticeIntent {None,Inbox,Scope(Zeroizing<String>)}
pub(crate) struct NativeNoticePort {protection:NonNull<c_void>,broker:NonNull<c_void>}
// SDK dereferences happen only on Main. Close is a short native latch and final
// Release moves ownership to Main; callers retain the original NativeProtection.
unsafe impl Send for NativeNoticePort {} unsafe impl Sync for NativeNoticePort {}
impl NativeNoticePort {
 pub(crate) fn new_on_main(protection:*mut c_void,callback:Box<dyn Fn()+Send+Sync>)->Result<Option<Self>,Refusal>{
  MainThread::current()?;let protection=NonNull::new(protection).ok_or(Refusal::PolicyUnreadable)?;
  let sink=Arc::new(WakeSink(callback));let raw=Arc::as_ptr(&sink).cast();
  let broker=unsafe{MDNativeNoticeBrokerCreate(protection.as_ptr(),Wake{context:raw,retain:hold,release:drop_wake,wake})};
  Ok(NonNull::new(broker).map(|broker|Self{protection,broker}))
 }
 pub(crate) fn publish_on_main(&self,action:&Arc<NotificationAction>,account:u64,title:&str,body:&str,scope:&str)->Result<bool,Refusal>{
  MainThread::current()?;action.check()?;
  let accepted=unsafe{MDNativeNoticeBrokerPublish(self.protection.as_ptr(),self.broker.as_ptr(),native_authorization_scope(action),account,
   title.as_ptr(),title.len() as u64,body.as_ptr(),body.len() as u64,scope.as_ptr(),scope.len() as u64)};
  action.check()?;Ok(accepted)
 }
 pub(crate) fn consume_on_main(&self,action:&Arc<NotificationAction>,account:u64)->Result<NativeNoticeIntent,Refusal>{
  MainThread::current()?;action.check()?;let mut output=RawIntent::default();
  let accepted=unsafe{MDNativeNoticeBrokerConsume(self.protection.as_ptr(),self.broker.as_ptr(),native_authorization_scope(action),account,&mut output)};
  action.check()?;if !accepted{return Err(Refusal::Cancelled);}
  match output.kind {
   0 if output.length==0=>Ok(NativeNoticeIntent::None),1 if output.length==0=>Ok(NativeNoticeIntent::Inbox),
   2=>{let bytes=output.scope.get(..output.length).ok_or(Refusal::Cancelled)?;
    let prefix=if bytes.len()==37 && bytes.starts_with(b"chat/"){5}else if bytes.len()==70&&bytes.starts_with(b"group/"){6}else{return Err(Refusal::Cancelled)};
    if !bytes[prefix..].iter().all(u8::is_ascii_hexdigit)||bytes[prefix..].iter().any(u8::is_ascii_uppercase){return Err(Refusal::Cancelled);}
    let scope=std::str::from_utf8(bytes).map_err(|_|Refusal::Cancelled)?;Ok(NativeNoticeIntent::Scope(Zeroizing::new(scope.to_owned())))
   },_=>Err(Refusal::Cancelled),
  }
 }
 pub(crate) fn retire_invalid_on_main(&self)->Result<(),Refusal>{MainThread::current()?;unsafe{MDNativeNoticeBrokerRetireInvalid(self.broker.as_ptr())};Ok(())}
 pub(crate) fn close(&self){unsafe{MDNativeNoticeBrokerClose(self.broker.as_ptr())};}
}
impl Drop for NativeNoticePort {fn drop(&mut self){unsafe{MDNativeNoticeBrokerRelease(self.broker.as_ptr())};}}
