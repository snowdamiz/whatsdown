//! Native attachment selections can survive picker inactivity, but grant no
//! private admission. Only a fresh scope for the same page/account can claim.
use super::{private_files::{ChosenSource,FileError},receiver_scope::{fresh_uuid,ChoiceAnchor,PrivateScope},wire};
use std::{sync::{Arc,Mutex,TryLockError,atomic::{AtomicBool,Ordering}},time::{Instant,Duration}};
use zeroize::Zeroizing;
#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub(crate) struct ChoiceId([u8;16]);
impl ChoiceId {
    pub(crate) fn wire(self)->String { wire::uuid(self.0) }
    fn parse(value:&str)->Result<Self,FileError> { wire::parse_uuid(value).map(Self).ok_or(FileError::Invalid) }
}
pub(crate) struct SelectedSource { id:ChoiceId,name:Zeroizing<String>,mime:Zeroizing<String>,source:ChosenSource }
impl SelectedSource {
    pub(super) fn metadata(&self)->SelectionMetadata {
        SelectionMetadata { selection:self.id.wire(),filename:Zeroizing::new(self.name.to_string()),mime:Zeroizing::new(self.mime.to_string()),size:self.source.size() }
    }
    pub(super) fn take(self,selection:&str,size:u64)->Result<ChosenSource,FileError> {
        if self.id!=ChoiceId::parse(selection)? || self.source.size()!=size { return Err(FileError::Changed); }
        Ok(self.source)
    }
    pub(crate) fn new(native_name:&str,native_mime:&str,source:ChosenSource)->Result<Self,FileError> {
        if native_name.is_empty() || native_name.len()>255 || matches!(native_name,"."|"..") ||
            native_name.chars().any(|c|c.is_control() || c=='/' || c=='\\') { return Err(FileError::Invalid); }
        let valid_token=|part:&str|part.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric) &&
            part.bytes().all(|byte|byte.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&byte));
        if native_mime.len()>127 || !native_mime.split_once('/').is_some_and(|(kind,subtype)|valid_token(kind) && valid_token(subtype)) {
            return Err(FileError::Invalid);
        }
        Ok(Self { id:ChoiceId(fresh_uuid()?),name:Zeroizing::new(native_name.to_owned()),mime:Zeroizing::new(native_mime.to_owned()),source })
    }
}
pub(crate) struct SelectionMetadata { pub(crate) selection:String,pub(crate) filename:Zeroizing<String>,pub(crate) mime:Zeroizing<String>,pub(crate) size:u64 }
pub(crate) struct ChoiceMetadata { pub(crate) choice:String,pub(crate) files:Vec<SelectionMetadata> }
struct Choice { id:ChoiceId,anchor:ChoiceAnchor,expires:Instant,live:AtomicBool,selections:Mutex<Vec<SelectedSource>> }
impl Choice {
    fn close(&self) {
        self.live.store(false,Ordering::Release);
        let retired=match self.selections.try_lock() { Ok(mut held)=>std::mem::take(&mut *held),Err(TryLockError::WouldBlock)=>Vec::new(),Err(TryLockError::Poisoned(error))=>std::mem::take(&mut *error.into_inner()) };
        drop(retired);
    }
    fn admission(&self,scope:&PrivateScope,now:Instant)->Result<(),FileError> {
        self.anchor.matches(scope)?;
        if !self.live.load(Ordering::Acquire) || now>=self.expires { return Err(FileError::Unavailable); }Ok(())
    }
}
struct State { closed:bool,choices:Vec<Arc<Choice>> }
pub(crate) struct AttachmentChoices { state:Mutex<State> }
impl AttachmentChoices {
    pub(crate) fn new()->Self { Self { state:Mutex::new(State { closed:false,choices:Vec::new() }) } }
    pub(crate) fn remember(&self,anchor:ChoiceAnchor,selections:Vec<SelectedSource>,now:Instant)->Result<ChoiceId,FileError> {
        anchor.current()?;
        if selections.is_empty() || selections.len()>10 { return Err(FileError::Invalid); }
        self.expire(now);let id=ChoiceId(fresh_uuid()?);
        let choice=Arc::new(Choice { id,anchor,expires:now+Duration::from_secs(120),live:AtomicBool::new(true),selections:Mutex::new(selections) });
        {
            let mut state=self.state.lock().map_err(|_|FileError::Unavailable)?;
            if state.closed || state.choices.len()>=4 { return Err(FileError::Limit); }
            state.choices.push(choice.clone());
        }
        if let Err(error)=choice.anchor.current() { self.remove(id);return Err(error.into()); }
        if !choice.live.load(Ordering::Acquire) { return Err(FileError::Unavailable); }Ok(id)
    }
    fn remove(&self,id:ChoiceId) {
        let removed={let mut state=self.state.lock().unwrap_or_else(|e|e.into_inner());state.choices.iter().position(|choice|choice.id==id).map(|index|state.choices.remove(index))};
        if let Some(choice)=removed { choice.close(); }
    }
    // Called by a native timer as well as on access; no caller-provided time or
    // account identity may enter this boundary. Release native holds outside it.
    pub(crate) fn expire(&self,now:Instant) {
        let snapshot=self.state.lock().unwrap_or_else(|e|e.into_inner()).choices.clone();
        for choice in snapshot { if now>=choice.expires || choice.anchor.current().is_err() { self.remove(choice.id); } }
    }
    pub(crate) fn pending(&self,scope:&PrivateScope,now:Instant)->Result<Option<ChoiceMetadata>,FileError> {
        scope.check()?;self.expire(now);
        let snapshot=self.state.lock().map_err(|_|FileError::Unavailable)?.choices.clone();
        for choice in snapshot.into_iter().rev() {
            if choice.admission(scope,now).is_err() { continue; }
            let files={let held=choice.selections.lock().map_err(|_|FileError::Unavailable)?;
                held.iter().map(SelectedSource::metadata).collect::<Vec<_>>()};
            choice.admission(scope,now)?;
            if !files.is_empty() { return Ok(Some(ChoiceMetadata { choice:choice.id.wire(),files })); }
        }
        scope.check()?;Ok(None)
    }
    // Automatic intake resolves only the exact native queued choice. It must
    // never fall back to the most recent picker/drop from another composer.
    pub(crate) fn selection(&self,scope:&PrivateScope,id:ChoiceId,now:Instant)->Result<Option<ChoiceMetadata>,FileError> {
        scope.check()?;self.expire(now);
        let choice=self.state.lock().map_err(|_|FileError::Unavailable)?.choices.iter().find(|value|value.id==id).cloned();
        let Some(choice)=choice else { scope.check()?;return Ok(None); };
        choice.admission(scope,now)?;
        let files={ let held=choice.selections.lock().map_err(|_|FileError::Unavailable)?;
            held.iter().map(SelectedSource::metadata).collect::<Vec<_>>() };
        choice.admission(scope,now)?;
        if files.is_empty() { Ok(None) } else { Ok(Some(ChoiceMetadata { choice:choice.id.wire(),files })) }
    }
    pub(crate) fn claim(&self,scope:&PrivateScope,id:&str,selection:&str,size:u64,now:Instant)->Result<ChosenSource,FileError> {
        scope.check()?;let id=ChoiceId::parse(id)?;let selection=ChoiceId::parse(selection)?;self.expire(now);
        let choice=self.state.lock().map_err(|_|FileError::Unavailable)?.choices.iter().find(|value|value.id==id).cloned().ok_or(FileError::Unavailable)?;
        choice.admission(scope,now)?;
        let (selected,empty)={
            let mut held=choice.selections.lock().map_err(|_|FileError::Unavailable)?;
            if !choice.live.load(Ordering::Acquire) { return Err(FileError::Unavailable); }
            let index=held.iter().position(|value|value.id==selection).ok_or(FileError::Unavailable)?;
            let selected=held.remove(index);(selected,held.is_empty())
        };
        // Selection is consumed before any filesystem work, including failure.
        let accepted=choice.admission(scope,now);
        if empty { self.remove(id); }
        accepted?;
        if selected.source.size()!=size { return Err(FileError::Changed); }Ok(selected.source)
    }
    pub(crate) fn close(&self) {
        let removed={let mut state=self.state.lock().unwrap_or_else(|e|e.into_inner());state.closed=true;std::mem::take(&mut state.choices)};
        for choice in removed { choice.close(); }
    }
}
impl Drop for AttachmentChoices { fn drop(&mut self) { self.close(); } }

#[cfg(all(test, feature = "native-boundary-tests"))]
#[path = "tests/choice_tests.rs"]
#[allow(dead_code)]
mod tests;
