//! A document grant is issued by native page load, independently of React owners.
//! A delayed bind must keep the document it arrived from across worker/main hops.
use super::{controller::Refusal, receiver_scope::fresh_uuid, wire};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

struct Grant { token: String, open: AtomicBool }
#[derive(Clone)]
pub(crate) struct DocumentPermit(Arc<Grant>);
impl DocumentPermit {
    pub(crate) fn check(&self) -> Result<(), Refusal> {
        if self.0.open.load(Ordering::Acquire) { Ok(()) } else { Err(Refusal::StaleOwner) }
    }
}
#[derive(Default)]
pub(crate) struct Documents(Mutex<Option<Arc<Grant>>>);
impl Documents {
    pub(crate) fn issue(&self) -> Result<String, Refusal> {
        let mut slot = self.0.lock().map_err(|_| Refusal::StaleOwner)?;
        if let Some(grant) = slot.as_ref() { return Ok(grant.token.clone()); }
        let token = wire::uuid(fresh_uuid()?);
        *slot = Some(Arc::new(Grant { token: token.clone(), open: AtomicBool::new(true) }));
        Ok(token)
    }
    pub(crate) fn capture(&self, token: &str) -> Result<DocumentPermit, Refusal> {
        let slot = self.0.lock().map_err(|_| Refusal::StaleOwner)?;
        let grant = slot.as_ref().filter(|grant| grant.token == token).ok_or(Refusal::StaleOwner)?;
        let permit = DocumentPermit(grant.clone()); permit.check()?; Ok(permit)
    }
    pub(crate) fn retire(&self) {
        if let Some(grant) = self.0.lock().unwrap().take() { grant.open.store(false, Ordering::Release); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    #[test]
    fn queued_bind_cannot_capture_the_replacement_document() {
        let docs = Documents::default();
        let old = docs.issue().unwrap();
        let permit = docs.capture(&old).unwrap();
        let (entered_tx, entered) = mpsc::channel(); let (resume, resume_rx) = mpsc::channel();
        let queued = std::thread::spawn(move || { entered_tx.send(()).unwrap(); resume_rx.recv().unwrap(); permit.check() });
        entered.recv().unwrap(); docs.retire(); let fresh = docs.issue().unwrap();
        resume.send(()).unwrap();
        assert_eq!(queued.join().unwrap(), Err(Refusal::StaleOwner));
        assert!(docs.capture(&old).is_err());
        assert!(docs.capture(&fresh).is_ok());
    }
    #[test]
    fn repeated_finished_callbacks_preserve_one_native_document_grant() {
        let docs = Documents::default(); let first = docs.issue().unwrap();
        assert_eq!(docs.issue().unwrap(), first);
        assert!(docs.capture("javascript-nominated-document").is_err());
    }
}
