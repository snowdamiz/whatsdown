//! Backup requests precede the chooser and the final archive size. They are
//! separate from attachment choices and carry no private publication authority.
use super::{private_choices::{SelectedSource,SelectionMetadata},private_destinations::{ChosenDestination,SelectedExport},private_exports::ExportContext,private_files::{ChosenSource,FileError},receiver_scope::{fresh_uuid,ChoiceAnchor,PrivateScope},wire};
use std::{sync::{Arc,Mutex,TryLockError,atomic::{AtomicBool,Ordering}},time::{Duration,Instant}};
const MAX_BACKUP:u64=16_796_864;
#[derive(Clone,Copy,PartialEq,Eq)]
pub(crate) enum BackupPurpose { Source,Export }
#[derive(Clone,Copy,PartialEq,Eq)]
pub(crate) struct BackupRequestId([u8;16]);
impl BackupRequestId { pub(crate) fn wire(self)->String {wire::uuid(self.0)} }
#[derive(Clone,Copy,PartialEq,Eq)]
pub(crate) struct BackupChoiceId([u8;16]);
impl BackupChoiceId { pub(crate) fn wire(self)->String {wire::uuid(self.0)} }
pub(crate) enum BackupMetadata {
    Source { request:String,choice:String,file:SelectionMetadata },
    Destination { request:String,choice:String },
}
pub(crate) enum DiscardBackup { Request(String),Choice(String) }
enum Selection { Source(SelectedSource),Destination(ChosenDestination) }
enum Phase { Waiting,Choosing,Selected(Selection),Closed }
type Cancel=Box<dyn FnOnce()+Send>;
struct Request {
    id:BackupRequestId,choice:BackupChoiceId,purpose:BackupPurpose,anchor:ChoiceAnchor,deadline:Instant,
    live:AtomicBool,phase:Mutex<Phase>,cancel:Mutex<Option<Cancel>>,
}
impl Request {
    fn metadata(&self,scope:&PrivateScope,now:Instant)->Result<Option<BackupMetadata>,FileError> {
        self.anchor.matches(scope)?;self.check(now)?;
        let metadata={let phase=self.phase.lock().map_err(|_|FileError::Unavailable)?;match &*phase {
            Phase::Selected(Selection::Source(source))=>Some(BackupMetadata::Source {request:self.id.wire(),choice:self.choice.wire(),file:source.metadata()}),
            Phase::Selected(Selection::Destination(_))=>Some(BackupMetadata::Destination {request:self.id.wire(),choice:self.choice.wire()}),_=>None,
        }};
        self.check(now)?;self.anchor.matches(scope)?;Ok(metadata)
    }
    fn check(&self,now:Instant)->Result<(),FileError> {
        self.anchor.current()?;
        if !self.live.load(Ordering::Acquire) || now>=self.deadline {return Err(FileError::Unavailable);}Ok(())
    }
    fn retire(&self) {
        self.live.store(false,Ordering::Release);
        let cancel=self.cancel.lock().unwrap_or_else(|e|e.into_inner()).take();
        let removed=match self.phase.try_lock() {
            Ok(mut phase)=>Some(std::mem::replace(&mut *phase,Phase::Closed)),
            Err(TryLockError::WouldBlock)=>None,
            Err(TryLockError::Poisoned(e))=>Some(std::mem::replace(&mut *e.into_inner(),Phase::Closed)),
        };
        drop(removed);if let Some(cancel)=cancel {cancel();}
    }
    fn on_cancel(&self,cancel:Cancel)->Result<(),FileError> {
        let mut callback=Some(cancel);
        let accepted={let mut slot=self.cancel.lock().map_err(|_|FileError::Unavailable)?;
            if self.live.load(Ordering::Acquire) && slot.is_none() {*slot=callback.take();true}else{false}};
        if let Some(cancel)=callback {cancel();}
        if accepted {Ok(())}else{Err(FileError::Unavailable)}
    }
    fn finish(&self,selection:Selection,now:Instant)->Result<BackupChoiceId,FileError> {
        self.check(now)?;
        {
            let mut phase=self.phase.lock().map_err(|_|FileError::Unavailable)?;
            if !self.live.load(Ordering::Acquire) || !matches!(*phase,Phase::Choosing) {return Err(FileError::Unavailable);}
            *phase=Phase::Selected(selection);
        }
        let callback=self.cancel.lock().unwrap_or_else(|e|e.into_inner()).take();drop(callback);
        if let Err(error)=self.check(now) {self.retire();return Err(error);}Ok(self.choice)
    }
}
struct Ticket(Option<Arc<Request>>);
impl Ticket {
    fn current(&self,scope:&PrivateScope,now:Instant)->Result<(),FileError> {
        let request=self.0.as_ref().ok_or(FileError::Unavailable)?;
        request.anchor.matches(scope)?;request.check(now)?;
        let choosing=matches!(*request.phase.lock().map_err(|_|FileError::Unavailable)?,Phase::Choosing);
        if !choosing {return Err(FileError::Unavailable);}request.check(now)?;request.anchor.matches(scope).map_err(FileError::from)
    }
    fn finish(mut self,selection:Selection,now:Instant)->Result<BackupChoiceId,FileError> {
        let request=self.0.take().ok_or(FileError::Unavailable)?;
        match request.finish(selection,now) {Ok(value)=>Ok(value),Err(error)=>{request.retire();Err(error)}}
    }
    fn on_cancel(&self,cancel:Cancel)->Result<(),FileError> {self.0.as_ref().ok_or(FileError::Unavailable)?.on_cancel(cancel)}
}
impl Drop for Ticket {fn drop(&mut self) {if let Some(request)=self.0.take(){request.retire();}}}
pub(crate) struct BackupSourceTicket(Ticket);
impl BackupSourceTicket {
    pub(crate) fn current(&self,scope:&PrivateScope,now:Instant)->Result<(),FileError> {self.0.current(scope,now)}
    pub(crate) fn on_cancel(&self,cancel:Cancel)->Result<(),FileError> {self.0.on_cancel(cancel)}
    pub(crate) fn complete(self,source:SelectedSource,now:Instant)->Result<BackupChoiceId,FileError> {
        if source.metadata().size>MAX_BACKUP {return Err(FileError::Limit);}
        self.0.finish(Selection::Source(source),now)
    }
}
pub(crate) struct BackupDestinationTicket(Ticket);
impl BackupDestinationTicket {
    pub(crate) fn current(&self,scope:&PrivateScope,now:Instant)->Result<(),FileError> {self.0.current(scope,now)}
    pub(crate) fn on_cancel(&self,cancel:Cancel)->Result<(),FileError> {self.0.on_cancel(cancel)}
    pub(crate) fn complete(self,destination:ChosenDestination,now:Instant)->Result<BackupChoiceId,FileError> {self.0.finish(Selection::Destination(destination),now)}
}
struct Requests { closed:bool,entries:Vec<Arc<Request>> }
pub(crate) struct BackupChoices(Mutex<Requests>);
impl BackupChoices {
    pub(crate) fn new()->Self {Self(Mutex::new(Requests {closed:false,entries:Vec::new()}))}
    pub(crate) fn begin(&self,scope:&PrivateScope,purpose:BackupPurpose,now:Instant)->Result<BackupRequestId,FileError> {
        let anchor=scope.choice_anchor()?;self.expire(now);
        let request=Arc::new(Request {id:BackupRequestId(fresh_uuid()?),choice:BackupChoiceId(fresh_uuid()?),purpose,anchor,deadline:now+Duration::from_secs(120),live:AtomicBool::new(true),phase:Mutex::new(Phase::Waiting),cancel:Mutex::new(None)});
        {let mut state=self.0.lock().map_err(|_|FileError::Unavailable)?;if state.closed || state.entries.len()>=4 {return Err(FileError::Limit);}state.entries.push(request.clone());}
        if let Err(error)=request.anchor.matches(scope) {self.remove(request.id);return Err(error.into());}
        request.check(now)?;Ok(request.id)
    }
    fn remove(&self,id:BackupRequestId) {
        let removed={let mut state=self.0.lock().unwrap_or_else(|e|e.into_inner());state.entries.iter().position(|r|r.id==id).map(|index|state.entries.remove(index))};
        if let Some(request)=removed {request.retire();}
    }
    pub(crate) fn expire(&self,now:Instant) {
        let entries=self.0.lock().unwrap_or_else(|e|e.into_inner()).entries.clone();
        for request in entries {if request.check(now).is_err(){self.remove(request.id);}}
    }
    fn start(&self,scope:&PrivateScope,id:&str,purpose:BackupPurpose,now:Instant)->Result<Ticket,FileError> {
        scope.check()?;self.expire(now);let id=BackupRequestId(wire::parse_uuid(id).ok_or(FileError::Invalid)?);
        let request=self.0.lock().map_err(|_|FileError::Unavailable)?.entries.iter().find(|r|r.id==id && r.purpose==purpose).cloned().ok_or(FileError::Unavailable)?;
        request.anchor.matches(scope)?;request.check(now)?;
        {let mut phase=request.phase.lock().map_err(|_|FileError::Unavailable)?;if !request.live.load(Ordering::Acquire) || !matches!(*phase,Phase::Waiting){return Err(FileError::Unavailable);}*phase=Phase::Choosing;}
        let ticket=Ticket(Some(request));ticket.current(scope,now)?;Ok(ticket)
    }
    pub(crate) fn start_source(&self,scope:&PrivateScope,id:&str,now:Instant)->Result<BackupSourceTicket,FileError> {self.start(scope,id,BackupPurpose::Source,now).map(BackupSourceTicket)}
    pub(crate) fn start_destination(&self,scope:&PrivateScope,id:&str,now:Instant)->Result<BackupDestinationTicket,FileError> {self.start(scope,id,BackupPurpose::Export,now).map(BackupDestinationTicket)}
    pub(crate) fn pending(&self,scope:&PrivateScope,purpose:BackupPurpose,now:Instant)->Result<Option<BackupMetadata>,FileError> {
        scope.check()?;self.expire(now);let entries=self.0.lock().map_err(|_|FileError::Unavailable)?.entries.clone();
        for request in entries.iter().rev().filter(|r|r.purpose==purpose) {
            if request.anchor.matches(scope).is_err() {continue;}
            let metadata=request.metadata(scope,now)?;if metadata.is_some(){return Ok(metadata);}
        }scope.check()?;Ok(None)
    }
    /// A chooser completion looks up its exact request and choice. Only the
    /// explicit pending-choice command may ask for the latest recoverable row.
    pub(crate) fn selection(&self,scope:&PrivateScope,purpose:BackupPurpose,request:&str,choice:&str,now:Instant)->Result<BackupMetadata,FileError> {
        scope.check()?;self.expire(now);
        let id=BackupRequestId(wire::parse_uuid(request).ok_or(FileError::Invalid)?);
        let choice=BackupChoiceId(wire::parse_uuid(choice).ok_or(FileError::Invalid)?);
        let request=self.0.lock().map_err(|_|FileError::Unavailable)?.entries.iter().find(|r|r.id==id && r.choice==choice && r.purpose==purpose).cloned().ok_or(FileError::Unavailable)?;
        request.metadata(scope,now)?.ok_or(FileError::Unavailable)
    }
    fn take(&self,scope:&PrivateScope,choice:&str,purpose:BackupPurpose,now:Instant)->Result<(ChoiceAnchor,Selection),FileError> {
        scope.check()?;self.expire(now);let id=BackupChoiceId(wire::parse_uuid(choice).ok_or(FileError::Invalid)?);
        let request=self.0.lock().map_err(|_|FileError::Unavailable)?.entries.iter().find(|r|r.choice==id && r.purpose==purpose).cloned().ok_or(FileError::Unavailable)?;
        request.anchor.matches(scope)?;request.check(now)?;
        let selected={let mut phase=request.phase.lock().map_err(|_|FileError::Unavailable)?;std::mem::replace(&mut *phase,Phase::Closed)};
        let current=request.check(now).and_then(|_|request.anchor.matches(scope).map_err(FileError::from));self.remove(request.id);current?;
        match selected {Phase::Selected(selection)=>Ok((request.anchor.clone(),selection)),_=>Err(FileError::Unavailable)}
    }
    pub(crate) fn claim_source(&self,scope:&PrivateScope,choice:&str,selection:&str,size:u64,now:Instant)->Result<ChosenSource,FileError> {
        let (_,selected)=self.take(scope,choice,BackupPurpose::Source,now)?;
        match selected {Selection::Source(source) if size<=MAX_BACKUP=>source.take(selection,size),_=>Err(FileError::Invalid)}
    }
    pub(crate) fn claim_export(&self,scope:&PrivateScope,choice:&str,source:&str,size:u64,now:Instant)->Result<SelectedExport,FileError> {
        let (anchor,selected)=self.take(scope,choice,BackupPurpose::Export,now)?;
        let prefix=format!("backup-export/{}/",wire::epoch(scope.epoch()));let counter=source.strip_prefix(&prefix).ok_or(FileError::Invalid)?;
        if counter.starts_with('0') || !counter.bytes().all(|b|b.is_ascii_digit()) || counter.parse::<u64>().ok().filter(|n|*n>0 && *n<=9_007_199_254_740_991).is_none() || size==0 || size>MAX_BACKUP {return Err(FileError::Invalid);}
        let context=ExportContext::new(source,"morse-backup.morsebackup","application/octet-stream",size).map_err(|_|FileError::Invalid)?;
        match selected {Selection::Destination(destination)=>Ok(SelectedExport::from_choice(anchor,destination,context)),_=>Err(FileError::Invalid)}
    }
    pub(crate) fn discard(&self,scope:&PrivateScope,purpose:BackupPurpose,target:DiscardBackup)->Result<(),FileError> {
        scope.check()?;let value=match &target {DiscardBackup::Request(value)|DiscardBackup::Choice(value)=>wire::parse_uuid(value).ok_or(FileError::Invalid)?};
        let request=self.0.lock().map_err(|_|FileError::Unavailable)?.entries.iter().find(|r|r.purpose==purpose && match target {DiscardBackup::Request(_)=>r.id.0==value,DiscardBackup::Choice(_)=>r.choice.0==value}).cloned();
        if let Some(request)=request {request.anchor.matches(scope)?;self.remove(request.id);}scope.check()?;Ok(())
    }
    pub(crate) fn close(&self) {
        let entries={let mut state=self.0.lock().unwrap_or_else(|e|e.into_inner());state.closed=true;std::mem::take(&mut state.entries)};
        for request in entries {request.retire();}
    }
}
impl Drop for BackupChoices {fn drop(&mut self){self.close();}}

#[cfg(all(test, feature = "native-boundary-tests"))]
#[path = "tests/backup_choice_tests.rs"]
#[allow(dead_code)]
mod tests;
