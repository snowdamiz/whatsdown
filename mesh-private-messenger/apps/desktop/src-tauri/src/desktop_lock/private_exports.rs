//! Encrypted, ephemeral export staging. Only commit's native destination callback
//! may create plaintext; private app storage never receives plaintext chunks.
use super::{controller::Refusal,receiver_scope::{fill_random,fresh_uuid,PrivateScope},wire};
use chacha20poly1305::{aead::{AeadInPlace,KeyInit},XChaCha20Poly1305,XNonce};
use std::{ffi::CString,fs::File,io::Write,os::{fd::{AsRawFd,FromRawFd},unix::fs::{FileExt,MetadataExt}},sync::Arc};
#[cfg(test)]
use std::{fs::OpenOptions,os::unix::fs::OpenOptionsExt,path::Path};
use zeroize::Zeroizing;
const MAX_SIZE:u64=536_870_912;
const CHUNK:usize=65_536;
const MAX_CHUNKS:u32=8192;
#[derive(Debug,PartialEq,Eq)]
pub(crate) enum ExportError { Admission(Refusal),Invalid,Unavailable,Integrity }
impl From<Refusal> for ExportError { fn from(value:Refusal)->Self { Self::Admission(value) } }
#[derive(PartialEq,Eq)]
pub(crate) struct ExportContext { source:Zeroizing<String>,name:Zeroizing<String>,mime:Zeroizing<String>,size:u64 }
impl ExportContext {
    pub(crate) fn new(source:&str,name:&str,mime:&str,size:u64)->Result<Self,ExportError> {
        let valid=|v:&str,max:usize|!v.is_empty() && v.len()<=max && !v.chars().any(char::is_control);
        let mut parts=mime.split('/');let token=|v:&str|!v.is_empty() && v.bytes().all(|b|b.is_ascii_alphanumeric() || b"-.+".contains(&b));
        if !valid(source,4096) || !valid(name,255) || matches!(name,"."|"..") || name.contains(['/', '\\']) ||
            !valid(mime,255) || !parts.next().is_some_and(token) || !parts.next().is_some_and(token) || parts.next().is_some() || size==0 || size>MAX_SIZE { return Err(ExportError::Invalid); }
        Ok(Self { source:Zeroizing::new(source.to_owned()),name:Zeroizing::new(name.to_owned()),mime:Zeroizing::new(mime.to_owned()),size })
    }
}
pub(crate) struct StageDirectory {
    directory:File,
    // Only component tests construct a directory without native startup ownership.
    owner:Option<super::stage_startup::StageOwner>,
}
impl StageDirectory {
    #[cfg(test)]
    pub(crate) fn open(native_path:&Path)->Result<Arc<Self>,ExportError> {
        let file=OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(native_path).map_err(|_|ExportError::Unavailable)?;
        let result=Self { directory:file,owner:None };result.check()?;Ok(Arc::new(result))
    }
    pub(super) fn from_startup(directory:File,owner:super::stage_startup::StageOwner)->Result<Arc<Self>,ExportError> {
        let result=Self { directory,owner:Some(owner) };result.check()?;Ok(Arc::new(result))
    }
    fn check(&self)->Result<(),ExportError> {
        if let Some(owner)=&self.owner { owner.check(&self.directory)?; }
        let m=self.directory.metadata().map_err(|_|ExportError::Unavailable)?;
        if !m.is_dir() || m.uid()!=unsafe { libc::getuid() } || m.mode()&0o777!=0o700 { return Err(ExportError::Unavailable); }Ok(())
    }
    fn create(&self,name:&CString)->Result<File,ExportError> {
        self.check()?;
        let raw=unsafe { libc::openat(self.directory.as_raw_fd(),name.as_ptr(),libc::O_RDWR|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o600) };
        if raw<0 { return Err(ExportError::Unavailable); }Ok(unsafe { File::from_raw_fd(raw) })
    }
}
pub(crate) struct EncryptedExport {
    directory:Arc<StageDirectory>,name:CString,file:File,scope:PrivateScope,cipher:XChaCha20Poly1305,
    prefix:[u8;16],binding:Zeroizing<Vec<u8>>,expected:u64,written:u64,count:u32,encoded:u64,failed:bool,
}
impl EncryptedExport {
    pub(crate) fn new(directory:Arc<StageDirectory>,scope:&PrivateScope,context:ExportContext)->Result<Self,ExportError> {
        scope.check()?;let id=fresh_uuid()?;let name=CString::new(format!("{}.stage",wire::uuid(id))).map_err(|_|ExportError::Invalid)?;
        let mut secret=Zeroizing::new([0u8;32]);fill_random(&mut *secret)?;let mut prefix=[0;16];fill_random(&mut prefix)?;
        let cipher=XChaCha20Poly1305::new_from_slice(&secret[..]).map_err(|_|ExportError::Unavailable)?;
        let mut binding=Zeroizing::new(Vec::with_capacity(8192));binding.extend_from_slice(b"Morse-private-export-v1\0");
        binding.extend_from_slice(&scope.owner().window.to_be_bytes());binding.extend_from_slice(&scope.owner().webview.to_be_bytes());
        binding.extend_from_slice(&scope.epoch().boot);binding.extend_from_slice(&scope.epoch().generation.to_be_bytes());binding.extend_from_slice(&id);binding.extend_from_slice(&context.size.to_be_bytes());
        for value in [&context.source,&context.name,&context.mime] { binding.extend_from_slice(&(value.len() as u32).to_be_bytes());binding.extend_from_slice(value.as_bytes()); }
        scope.check()?;let file=directory.create(&name)?;
        let result=Self { directory,name,file,scope:scope.clone(),cipher,prefix,binding,expected:context.size,written:0,count:0,encoded:0,failed:false };
        scope.check()?;Ok(result)
    }
    fn nonce(&self,index:u32)->[u8;24] {
        let mut value=[0;24];value[..16].copy_from_slice(&self.prefix);value[16..].copy_from_slice(&(u64::from(index)).to_be_bytes());value
    }
    fn aad(&self,index:u32,length:u32)->Zeroizing<Vec<u8>> {
        let mut value=Zeroizing::new(Vec::with_capacity(self.binding.len()+8));value.extend_from_slice(&self.binding);
        value.extend_from_slice(&index.to_be_bytes());value.extend_from_slice(&length.to_be_bytes());value
    }
    pub(crate) fn write(&mut self,offset:u64,bytes:&[u8])->Result<(),ExportError> {
        self.scope.check()?;self.directory.check()?;
        if self.failed || self.count>=MAX_CHUNKS || offset!=self.written || bytes.is_empty() || bytes.len()>CHUNK || offset.checked_add(bytes.len() as u64).is_none_or(|end|end>self.expected) { return Err(ExportError::Invalid); }
        self.failed=true;
        let length=bytes.len() as u32;let nonce=self.nonce(self.count);let aad=self.aad(self.count,length);
        let mut ciphertext=Zeroizing::new(Vec::with_capacity(bytes.len()+16));ciphertext.extend_from_slice(bytes);
        self.cipher.encrypt_in_place(XNonce::from_slice(&nonce),&aad,&mut *ciphertext).map_err(|_|ExportError::Integrity)?;
        self.scope.check()?;
        let metadata=self.file.metadata().map_err(|_|ExportError::Unavailable)?;
        if !metadata.is_file() || metadata.len()!=self.encoded { return Err(ExportError::Integrity); }
        self.file.write_all(&self.count.to_be_bytes()).and_then(|_|self.file.write_all(&length.to_be_bytes()))
            .and_then(|_|self.file.write_all(&ciphertext)).map_err(|_|ExportError::Unavailable)?;
        self.scope.check()?;self.written+=u64::from(length);self.encoded+=ciphertext.len() as u64+8;self.count+=1;self.failed=false;Ok(())
    }
    fn scan(&self,mut consume:impl FnMut(&[u8])->Result<(),ExportError>)->Result<(),ExportError> {
        self.scope.check()?;self.directory.check()?;
        let metadata=self.file.metadata().map_err(|_|ExportError::Unavailable)?;
        if self.failed || self.written!=self.expected || !metadata.is_file() || metadata.len()!=self.encoded { return Err(ExportError::Integrity); }
        let mut offset=0;let mut total=0u64;
        for index in 0..self.count {
            self.scope.check()?;self.directory.check()?;let mut header=[0;8];self.file.read_exact_at(&mut header,offset).map_err(|_|ExportError::Integrity)?;
            let actual=u32::from_be_bytes(header[..4].try_into().unwrap());let length=u32::from_be_bytes(header[4..].try_into().unwrap());
            if actual!=index || length==0 || length as usize>CHUNK || total+u64::from(length)>self.expected { return Err(ExportError::Integrity); }
            let mut plaintext=Zeroizing::new(vec![0;length as usize+16]);self.file.read_exact_at(&mut plaintext,offset+8).map_err(|_|ExportError::Integrity)?;
            let nonce=self.nonce(index);let aad=self.aad(index,length);
            self.cipher.decrypt_in_place(XNonce::from_slice(&nonce),&aad,&mut *plaintext).map_err(|_|ExportError::Integrity)?;
            if plaintext.len()!=length as usize { return Err(ExportError::Integrity); }
            self.scope.check()?;consume(&plaintext)?;self.scope.check()?;
            offset+=8+u64::from(length)+16;total+=u64::from(length);
        }
        if offset!=self.encoded || total!=self.expected || self.file.metadata().map_err(|_|ExportError::Unavailable)?.len()!=offset { return Err(ExportError::Integrity); }Ok(())
    }
    /// The native dialog/choice adapter opens only its retained selected target.
    /// Preflight authenticates every chunk before that callback can truncate or
    /// create plaintext. Revocation can leave already-exported bytes at that
    /// explicitly selected destination, but cannot publish subsequent chunks.
    pub(crate) fn commit(self,mut publication:impl FnMut()->Result<(),ExportError>,open_destination:impl FnOnce()->Result<super::private_destinations::DestinationFile,ExportError>)->Result<(),ExportError> {
        self.scope.check()?;
        if self.failed || self.written!=self.expected { return Err(ExportError::Integrity); }
        self.file.sync_all().map_err(|_|ExportError::Unavailable)?;self.scan(|_|Ok(()))?;
        self.scope.check()?;publication()?;self.scope.check()?;let mut destination=open_destination()?;
        self.scope.check()?;
        self.scan(|bytes| { publication()?;self.scope.check()?;destination.write_all(bytes).map_err(|_|ExportError::Unavailable)?;self.scope.check()?;Ok(()) })?;
        self.scope.check()?;destination.sync_all().map_err(|_|ExportError::Unavailable)?;self.scope.check()?;Ok(())
    }
}
impl Drop for EncryptedExport {
    fn drop(&mut self) {
        // Preserve a replacement at the old name. Unknown identity or IO
        // failure leaves only encrypted staging for later native cleanup.
        let Ok(held)=self.file.metadata() else { return; };
        let mut named:libc::stat=unsafe { std::mem::zeroed() };
        let found=unsafe { libc::fstatat(self.directory.directory.as_raw_fd(),self.name.as_ptr(),&mut named,libc::AT_SYMLINK_NOFOLLOW) };
        if found==0 && named.st_dev as u64==held.dev() && named.st_ino as u64==held.ino() && named.st_mode & libc::S_IFMT==libc::S_IFREG {
            unsafe { libc::unlinkat(self.directory.directory.as_raw_fd(),self.name.as_ptr(),0); }
        }
    }
}

#[cfg(all(test, feature = "native-boundary-tests"))]
#[path = "tests/export_tests.rs"]
#[allow(dead_code)]
mod tests;
