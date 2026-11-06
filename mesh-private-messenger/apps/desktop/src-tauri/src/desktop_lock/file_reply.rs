//! Reply ownership retained until the original receiving completion is published.
use super::{private_files::{FileHandle,PrivateFiles,Role},receiver_scope::PrivateScope};
use std::sync::Arc;
use serde_json::Value;
use tauri::ipc::Response;
use zeroize::{Zeroize,Zeroizing};
use super::incoming_files::{IncomingFiles,IncomingHandle};

struct Cleanup {
    files: Arc<PrivateFiles>,
    scope: PrivateScope,
    role: Role,
    handle: Option<FileHandle>,
}
impl Cleanup {
    fn disarm(&mut self) { let _ = self.handle.take(); }
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.files.cleanup(self.scope.owner(), self.scope.epoch(), self.role, handle);
        }
    }
}
struct IncomingCleanup { incoming:Arc<IncomingFiles>,scope:PrivateScope,handle:Option<IncomingHandle> }
impl Drop for IncomingCleanup {
    fn drop(&mut self) { if let Some(handle)=self.handle.take() { self.incoming.unsubscribe(self.scope.owner(),self.scope.epoch(),handle); } }
}
enum ReplyCleanup { File(Cleanup),Incoming(IncomingCleanup) }
impl ReplyCleanup {
    fn disarm(&mut self) { match self { Self::File(value)=>value.disarm(),Self::Incoming(value)=>{let _=value.handle.take();} } }
}
pub(super) struct FileReply {
    bytes: Zeroizing<Vec<u8>>,
    json: bool,
    cleanup: Option<ReplyCleanup>,
}
impl FileReply {
    pub(super) fn json(value: Value) -> Self {
        Self {
            bytes: Zeroizing::new(serde_json::to_vec(&value).expect("closed JSON value")),
            json: true,
            cleanup: None,
        }
    }
    pub(super) fn bytes(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            bytes,
            json: false,
            cleanup: None,
        }
    }
    pub(super) fn handle(
        files: Arc<PrivateFiles>,
        scope: PrivateScope,
        role: Role,
        handle: FileHandle,
        value: Value,
    ) -> Self {
        let cleanup = Some(ReplyCleanup::File(Cleanup {
            files,
            scope,
            role,
            handle: Some(handle),
        }));
        let mut reply = Self::json(value);
        reply.cleanup = cleanup;
        reply
    }
    pub(super) fn incoming(incoming:Arc<IncomingFiles>,scope:PrivateScope,handle:IncomingHandle,value:Value)->Self {
        let mut reply=Self::json(value);
        reply.cleanup=Some(ReplyCleanup::Incoming(IncomingCleanup { incoming,scope,handle:Some(handle) }));reply
    }
    pub(super) fn publish(mut self) -> Result<Response, &'static str> {
        let bytes = std::mem::take(&mut *self.bytes);
        let response = if self.json {
            match String::from_utf8(bytes) {
                Ok(value) => Response::new(value),
                Err(error) => {
                    let mut bytes = error.into_bytes();
                    bytes.zeroize();
                    return Err("invalid_file_response");
                }
            }
        } else {
            Response::new(bytes)
        };
        if let Some(cleanup) = self.cleanup.as_mut() { cleanup.disarm(); }
        Ok(response)
    }
}

#[cfg(all(test, feature = "native-boundary-tests"))]
#[path = "tests/file_reply_tests.rs"]
mod tests;
