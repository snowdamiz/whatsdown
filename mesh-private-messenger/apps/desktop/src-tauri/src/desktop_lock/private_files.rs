//! Files are native resources, never reusable paths or caller-selected authority.
use super::{controller::{Epoch,Owner,Refusal},receiver_scope::{fresh_uuid,PrivateScope},resources::Resources,wire};
use std::{fs::{File,Metadata,OpenOptions},io,os::unix::fs::{FileExt,MetadataExt,OpenOptionsExt},path::Path,sync::{Arc,Mutex,TryLockError,atomic::{AtomicBool,Ordering}}};
use zeroize::Zeroizing;

pub(crate) const MAX_CHUNK:usize=65_536;
const MAX_SOURCE:u64=536_870_912;
const MAX_PREVIEW:usize=16_777_216;
#[derive(Debug,PartialEq,Eq)]
pub(crate) enum FileError { Admission(Refusal),Unavailable,Range,Changed,Limit,Invalid }
impl From<Refusal> for FileError { fn from(error:Refusal)->Self { Self::Admission(error) } }
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) struct FileHandle([u8;16]);
impl FileHandle {
    pub(crate) fn parse(value:&str)->Result<Self,FileError> { wire::parse_uuid(value).map(Self).ok_or(FileError::Invalid) }
    pub(crate) fn wire(self)->String { wire::uuid(self.0) }
    pub(crate) fn preview_uri(self)->String { format!("morse-private://preview/{}",self.wire()) }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum Role { Source,Preview,Export }
impl Role {
    fn tag(self,handle:FileHandle)->Vec<u8> {
        let mut tag=vec![match self { Self::Source=>1,Self::Preview=>2,Self::Export=>3 }];tag.extend_from_slice(&handle.0);tag
    }
}
#[derive(Clone,Copy,PartialEq,Eq)]
struct Identity { device:u64,inode:u64,size:u64,modified:i64,modified_ns:i64 }
impl Identity {
    fn read(metadata:Metadata)->Result<Self,FileError> {
        if !metadata.is_file() || metadata.len()==0 || metadata.len()>MAX_SOURCE { return Err(FileError::Invalid); }
        Ok(Self { device:metadata.dev(),inode:metadata.ino(),size:metadata.len(),modified:metadata.mtime(),modified_ns:metadata.mtime_nsec() })
    }
}
/// Created only at a native chooser boundary. This move-only value holds the
/// selected descriptor and its original identity; claim consumes the choice.
/// The native adapter holds the original security-scoped URL and releases it
/// on its required native queue only after the last descriptor operation ends.
pub(crate) trait NativeFileAccess:Send+Sync {}
pub(crate) struct ChosenSource { file:File,identity:Identity,_access:Option<Arc<dyn NativeFileAccess>> }
impl ChosenSource {
    pub(crate) fn open_selected(native_path:&Path,access:Arc<dyn NativeFileAccess>)->Result<Self,FileError> {
        Self::capture(native_path,Some(access))
    }
    #[cfg(test)]
    pub(crate) fn open(native_path:&Path)->Result<Self,FileError> {
        Self::capture(native_path,None)
    }
    fn capture(native_path:&Path,access:Option<Arc<dyn NativeFileAccess>>)->Result<Self,FileError> {
        let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK)
            .open(native_path).map_err(|_|FileError::Unavailable)?;
        let identity=Identity::read(file.metadata().map_err(|_|FileError::Unavailable)?)?;
        Ok(Self { file,identity,_access:access })
    }
    pub(crate) fn size(&self)->u64 { self.identity.size }
    fn unchanged(&self)->Result<(),FileError> {
        if Identity::read(self.file.metadata().map_err(|_|FileError::Unavailable)?)?!=self.identity { return Err(FileError::Changed); }Ok(())
    }
    fn read(&self,offset:u64,length:usize)->Result<Zeroizing<Vec<u8>>,FileError> {
        if length==0 || length>MAX_CHUNK || offset.checked_add(length as u64).is_none_or(|end|end>self.identity.size) { return Err(FileError::Range); }
        self.unchanged()?;let mut bytes=Zeroizing::new(vec![0;length]);let mut filled=0;
        while filled<length {
            match self.file.read_at(&mut bytes[filled..],offset+filled as u64) {
                Ok(0)=>return Err(FileError::Changed),Ok(n)=>filled+=n,
                Err(error) if error.kind()==io::ErrorKind::Interrupted=>continue,
                Err(_)=>return Err(FileError::Unavailable),
            }
        }
        self.unchanged()?;Ok(bytes)
    }
}
struct OwnedExport {
    staging:super::private_exports::EncryptedExport,
    destination:super::private_destinations::ChosenDestination,
}
enum Payload { Source(ChosenSource),Export(Option<OwnedExport>),Preview { mime:&'static str,bytes:Zeroizing<Vec<u8>> } }
struct Item { scope:PrivateScope,live:AtomicBool,data:Mutex<Option<Payload>> }
impl Item {
    fn retire(&self) {
        self.live.store(false,Ordering::Release);
        // Retirement never waits for IO. The operation holding data owns the
        // deferred wipe/close and cannot publish a result after this flag.
        let held=match self.data.try_lock() { Ok(mut data)=>data.take(),Err(TryLockError::WouldBlock)=>None,Err(TryLockError::Poisoned(error))=>error.into_inner().take() };
        drop(held);
    }
    fn with_data<T>(&self,scope:&PrivateScope,operation:impl FnOnce(&mut Payload)->Result<T,FileError>)->Result<T,FileError> {
        scope.check()?;
        let mut data=self.data.lock().map_err(|_|FileError::Unavailable)?;
        let result=(|| {
            scope.check()?;
            if !self.live.load(Ordering::Acquire) { return Err(FileError::Unavailable); }
            operation(data.as_mut().ok_or(FileError::Unavailable)?)
        })();
        let retired=if !self.live.load(Ordering::Acquire) { data.take() } else { None };
        drop(data);drop(retired);
        // PrivateScope may retire resources while consulting native policy;
        // neither the registry mutex nor the IO mutex is held for this fence.
        scope.check()?;
        if !self.live.load(Ordering::Acquire) { self.retire();return Err(FileError::Unavailable); }
        result
    }
}
/// Owns the original resource and private response bytes until native scheme
/// completion. The bridge checks this receipt again immediately before publish.
pub(crate) struct PreviewReply { item:Arc<Item>,mime:&'static str,bytes:Zeroizing<Vec<u8>> }
impl PreviewReply {
    pub(crate) fn owner(&self)->Owner { self.item.scope.owner() }
    pub(crate) fn check(&self,actual:Owner)->Result<(),FileError> {
        if actual!=self.owner() { return Err(FileError::Unavailable); }
        self.item.scope.check()?;
        if !self.item.live.load(Ordering::Acquire) { return Err(FileError::Unavailable); }Ok(())
    }
    pub(crate) fn mime(&self)->&'static str { self.mime }
    pub(crate) fn bytes(&self)->&[u8] { &self.bytes }
}
struct Entry { owner:Owner,epoch:Epoch,role:Role,handle:FileHandle,item:Arc<Item> }
pub(crate) struct PrivateFiles { resources:Arc<Resources>,state:Mutex<Vec<Entry>> }
impl PrivateFiles {
    pub(crate) fn new(resources:Arc<Resources>)->Arc<Self> { Arc::new(Self { resources,state:Mutex::new(Vec::new()) }) }
    fn remember(self:&Arc<Self>,scope:&PrivateScope,role:Role,payload:Payload)->Result<FileHandle,FileError> {
        scope.check()?;let handle=FileHandle(fresh_uuid()?);let owner=scope.owner();let epoch=scope.epoch();
        let item=Arc::new(Item { scope:scope.clone(),live:AtomicBool::new(true),data:Mutex::new(Some(payload)) });
        {
            let mut state=self.state.lock().map_err(|_|FileError::Unavailable)?;
            if state.iter().filter(|entry|entry.role==role).count()>=4 { return Err(FileError::Limit); }
            state.push(Entry { owner,epoch,role,handle,item:item.clone() });
        }
        let weak=Arc::downgrade(self);let cancel_item=item.clone();
        self.resources.register(owner,epoch,role.tag(handle),Box::new(move || {
            if let Some(files)=weak.upgrade() { files.remove(owner,epoch,role,handle); }
            cancel_item.retire();
        }))?;
        if let Err(error)=scope.check() { self.cleanup(owner,epoch,role,handle);return Err(error.into()); }
        if !item.live.load(Ordering::Acquire) { self.cleanup(owner,epoch,role,handle);return Err(FileError::Unavailable); }
        Ok(handle)
    }
    fn remove(&self,owner:Owner,epoch:Epoch,role:Role,handle:FileHandle) {
        let held={
            let mut state=self.state.lock().unwrap_or_else(|error|error.into_inner());
            state.iter().position(|entry|entry.owner==owner && entry.epoch==epoch && entry.role==role && entry.handle==handle).map(|index|state.swap_remove(index))
        };
        if let Some(entry)=held { entry.item.retire(); }
    }
    fn lookup(&self,scope:&PrivateScope,role:Role,handle:FileHandle)->Result<Arc<Item>,FileError> {
        scope.check()?;
        let state=self.state.lock().map_err(|_|FileError::Unavailable)?;
        state.iter().find(|entry|entry.owner==scope.owner() && entry.epoch==scope.epoch() && entry.role==role && entry.handle==handle)
            .map(|entry|entry.item.clone()).ok_or(FileError::Unavailable)
    }
    pub(crate) fn cleanup(&self,original_owner:Owner,original_epoch:Epoch,role:Role,handle:FileHandle) {
        // Receiving code authenticates original page headers with cleanup_epoch;
        // cleanup itself never asks for new private admission or a latest owner.
        self.resources.cancel_one(original_owner,original_epoch,&role.tag(handle));
    }
    pub(crate) fn claim_source(self:&Arc<Self>,scope:&PrivateScope,source:ChosenSource,expected_size:u64)->Result<FileHandle,FileError> {
        scope.check()?;source.unchanged()?;
        if source.size()!=expected_size { return Err(FileError::Changed); }
        self.remember(scope,Role::Source,Payload::Source(source))
    }
    pub(crate) fn read_source(&self,scope:&PrivateScope,handle:FileHandle,offset:u64,length:usize)->Result<Zeroizing<Vec<u8>>,FileError> {
        self.lookup(scope,Role::Source,handle)?.with_data(scope,|payload|match payload {
            Payload::Source(source)=>source.read(offset,length),_=>Err(FileError::Invalid),
        })
    }
    pub(crate) fn write_preview(self:&Arc<Self>,scope:&PrivateScope,mime:&str,bytes:Zeroizing<Vec<u8>>)->Result<FileHandle,FileError> {
        scope.check()?;
        let mime=match mime { "image/jpeg"=>"image/jpeg","image/png"=>"image/png","image/webp"=>"image/webp","image/gif"=>"image/gif","image/avif"=>"image/avif","image/heic"=>"image/heic","image/heif"=>"image/heif",_=>return Err(FileError::Invalid) };
        if bytes.is_empty() || bytes.len()>MAX_PREVIEW { return Err(FileError::Range); }
        self.remember(scope,Role::Preview,Payload::Preview { mime,bytes })
    }
    pub(crate) fn begin_export(self:&Arc<Self>,scope:&PrivateScope,directory:Arc<super::private_exports::StageDirectory>,selected:super::private_destinations::SelectedExport)->Result<FileHandle,FileError> {
        let (destination,context)=selected.bind(scope).map_err(export_error)?;
        let staging=super::private_exports::EncryptedExport::new(directory,scope,context).map_err(export_error)?;
        self.remember(scope,Role::Export,Payload::Export(Some(OwnedExport { staging,destination })))
    }
    pub(crate) fn write_export(&self,scope:&PrivateScope,handle:FileHandle,offset:u64,bytes:&[u8])->Result<(),FileError> {
        self.lookup(scope,Role::Export,handle)?.with_data(scope,|payload|match payload {
            Payload::Export(Some(export))=>export.staging.write(offset,bytes).map_err(export_error),_=>Err(FileError::Unavailable),
        })
    }
    pub(crate) fn commit_export(&self,scope:&PrivateScope,handle:FileHandle,
        mut publication:impl FnMut()->Result<(),super::private_exports::ExportError>)->Result<(),FileError> {
        use super::private_exports::ExportError;
        let item=self.lookup(scope,Role::Export,handle)?;
        let result=item.with_data(scope,|payload| {
            let Payload::Export(value)=payload else { return Err(FileError::Invalid); };
            let OwnedExport { staging,destination }=value.take().ok_or(FileError::Unavailable)?;
            staging.commit(|| {
                if !item.live.load(Ordering::Acquire) { return Err(ExportError::Unavailable); }
                publication()?;
                if !item.live.load(Ordering::Acquire) { return Err(ExportError::Unavailable); }Ok(())
            },||destination.open(scope)).map_err(export_error)
        });
        self.cleanup(scope.owner(),scope.epoch(),Role::Export,handle);result
    }
    pub(crate) fn preview_for_receiver(&self,actual:Owner,handle:FileHandle)->Result<PreviewReply,FileError> {
        let item={
            let state=self.state.lock().map_err(|_|FileError::Unavailable)?;
            state.iter().find(|entry|entry.role==Role::Preview && entry.owner==actual && entry.handle==handle)
                .map(|entry|entry.item.clone()).ok_or(FileError::Unavailable)?
        };
        let (mime,bytes)=item.with_data(&item.scope,|payload|match payload {
            Payload::Preview { mime,bytes }=>Ok((*mime,Zeroizing::new(bytes.to_vec()))),_=>Err(FileError::Invalid),
        })?;
        let reply=PreviewReply { item,mime,bytes };reply.check(actual)?;Ok(reply)
    }
    // The scheme handler must capture a scope from the actual requesting WK.
    // A URI alone, a webview label, or a latest-owner lookup is not authority.
    pub(crate) fn preview(&self,scope:&PrivateScope,handle:FileHandle)->Result<(&'static str,Zeroizing<Vec<u8>>),FileError> {
        self.lookup(scope,Role::Preview,handle)?.with_data(scope,|payload|match payload {
            Payload::Preview { mime,bytes }=>Ok((*mime,Zeroizing::new(bytes.to_vec()))),_=>Err(FileError::Invalid),
        })
    }
}
fn export_error(value:super::private_exports::ExportError)->FileError {
    use super::private_exports::ExportError;
    match value { ExportError::Admission(error)=>FileError::Admission(error),ExportError::Invalid=>FileError::Invalid,
        ExportError::Unavailable=>FileError::Unavailable,ExportError::Integrity=>FileError::Changed }
}
impl Drop for PrivateFiles {
    fn drop(&mut self) {
        let held=std::mem::take(self.state.get_mut().unwrap_or_else(|error|error.into_inner()));
        for entry in held { self.resources.cancel_one(entry.owner,entry.epoch,&entry.role.tag(entry.handle));entry.item.retire(); }
    }
}

#[cfg(all(test, feature = "native-boundary-tests"))]
#[path = "tests/file_tests.rs"]
#[allow(dead_code)]
mod tests;
