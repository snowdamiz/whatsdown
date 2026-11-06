//! Avatar import is a separate native choice domain. Selection survives an
//! ordinary lock, while decode/crop/encode requires a fresh original scope.
use super::{private_choices::SelectedSource,private_files::{ChosenSource,FileError},receiver_scope::{fresh_uuid,ChoiceAnchor,PrivateScope},wire};
use std::{sync::{Arc,Mutex,TryLockError,atomic::{AtomicBool,Ordering}},time::{Instant,Duration}};
const MAX_AVATAR_SOURCE:u64=20*1024*1024;
#[derive(Clone,Copy,PartialEq,Eq)]
pub(crate) struct AvatarChoiceId([u8;16]);
impl AvatarChoiceId {pub(crate) fn wire(self)->String {wire::uuid(self.0)}}
struct Choice {id:AvatarChoiceId,anchor:ChoiceAnchor,deadline:Instant,live:AtomicBool,source:Mutex<Option<SelectedSource>>}
impl Choice {
    fn close(&self) {
        self.live.store(false,Ordering::Release);
        let removed=match self.source.try_lock() {Ok(mut source)=>source.take(),Err(TryLockError::WouldBlock)=>None,Err(TryLockError::Poisoned(error))=>error.into_inner().take()};drop(removed);
    }
    fn current(&self,now:Instant)->Result<(),FileError> {
        self.anchor.current()?;if !self.live.load(Ordering::Acquire) || now>=self.deadline {return Err(FileError::Unavailable);}Ok(())
    }
}
struct Choices {closed:bool,entries:Vec<Arc<Choice>>}
pub(crate) struct AvatarChoices(Mutex<Choices>);
impl AvatarChoices {
    pub(crate) fn new()->Self {Self(Mutex::new(Choices {closed:false,entries:Vec::new()}))}
    pub(crate) fn remember(&self,anchor:ChoiceAnchor,source:SelectedSource,now:Instant)->Result<AvatarChoiceId,FileError> {
        anchor.current()?;let metadata=source.metadata();if metadata.size>MAX_AVATAR_SOURCE || !metadata.mime.starts_with("image/") {return Err(FileError::Invalid);}
        self.expire(now);let id=AvatarChoiceId(fresh_uuid()?);let choice=Arc::new(Choice {id,anchor,deadline:now+Duration::from_secs(120),live:AtomicBool::new(true),source:Mutex::new(Some(source))});
        {let mut state=self.0.lock().map_err(|_|FileError::Unavailable)?;if state.closed || state.entries.len()>=4 {return Err(FileError::Limit);}state.entries.push(choice.clone());}
        if let Err(error)=choice.current(now) {self.remove(id);return Err(error);}Ok(id)
    }
    fn remove(&self,id:AvatarChoiceId) {
        let removed={let mut state=self.0.lock().unwrap_or_else(|e|e.into_inner());state.entries.iter().position(|v|v.id==id).map(|i|state.entries.remove(i))};if let Some(choice)=removed {choice.close();}
    }
    pub(crate) fn expire(&self,now:Instant) {
        let entries=self.0.lock().unwrap_or_else(|e|e.into_inner()).entries.clone();for choice in entries {if choice.current(now).is_err(){self.remove(choice.id);}}
    }
    pub(crate) fn pending(&self,scope:&PrivateScope,now:Instant)->Result<Option<AvatarChoiceId>,FileError> {
        scope.check()?;self.expire(now);let entries=self.0.lock().map_err(|_|FileError::Unavailable)?.entries.clone();
        for choice in entries.iter().rev() {
            if choice.anchor.matches(scope).is_err() {continue;}
            choice.current(now)?;choice.anchor.matches(scope)?;return Ok(Some(choice.id));
        }scope.check()?;Ok(None)
    }
    pub(crate) fn claim(&self,scope:&PrivateScope,id:&str,now:Instant)->Result<ChosenSource,FileError> {
        scope.check()?;self.expire(now);let id=AvatarChoiceId(wire::parse_uuid(id).ok_or(FileError::Invalid)?);
        let choice=self.0.lock().map_err(|_|FileError::Unavailable)?.entries.iter().find(|v|v.id==id).cloned().ok_or(FileError::Unavailable)?;
        choice.anchor.matches(scope)?;choice.current(now)?;
        let source={let mut held=choice.source.lock().map_err(|_|FileError::Unavailable)?;if !choice.live.load(Ordering::Acquire){return Err(FileError::Unavailable);}held.take().ok_or(FileError::Unavailable)?};
        let current=choice.current(now).and_then(|_|choice.anchor.matches(scope).map_err(FileError::from));self.remove(id);current?;
        let metadata=source.metadata();source.take(&metadata.selection,metadata.size)
    }
    pub(crate) fn close(&self) {
        let entries={let mut state=self.0.lock().unwrap_or_else(|e|e.into_inner());state.closed=true;std::mem::take(&mut state.entries)};for choice in entries {choice.close();}
    }
}
impl Drop for AvatarChoices {fn drop(&mut self){self.close();}}

#[cfg(all(test, feature = "native-boundary-tests"))]
#[path = "tests/avatar_choice_tests.rs"]
#[allow(dead_code)]
mod tests;
