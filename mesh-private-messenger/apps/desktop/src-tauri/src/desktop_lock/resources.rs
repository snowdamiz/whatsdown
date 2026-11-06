//! Native owned-job retirement. Cancels never wait for Core, policy or UI.
use super::controller::{Epoch, Owner, Refusal};
use std::sync::Mutex;
use zeroize::Zeroizing;

type Cancel = Box<dyn FnOnce() + Send>;
struct Entry { owner: Owner, epoch: Epoch, tag: Zeroizing<Vec<u8>>, cancel: Cancel }
struct State { retired: u64, closed: bool, entries: Vec<Entry> }
pub(crate) struct Resources { boot: [u8; 16], state: Mutex<State> }
impl Resources {
    pub(crate) fn new(boot: [u8; 16]) -> Self {
        Self { boot, state: Mutex::new(State { retired: 0, closed: false, entries: Vec::new() }) }
    }
    // Register a minted native resource BEFORE the final completion fence.
    // On refusal the original finite cleanup still runs, outside this lock.
    pub(crate) fn register(&self, owner: Owner, epoch: Epoch, tag: Vec<u8>, cancel: Cancel) -> Result<(), Refusal> {
        let tag=Zeroizing::new(tag);
        let mut state = self.state.lock().unwrap();
        if state.closed || epoch.boot != self.boot || epoch.generation <= state.retired || state.entries.len() >= 64 {
            drop(state);cancel();return Err(Refusal::StaleEpoch);
        }
        if state.entries.iter().any(|entry| entry.owner == owner && entry.epoch == epoch && entry.tag.as_slice() == tag.as_slice()) {
            drop(state);cancel();return Err(Refusal::Busy);
        }
        state.entries.push(Entry { owner, epoch, tag, cancel });Ok(())
    }
    pub(crate) fn owns(&self, owner: Owner, epoch: Epoch, tag: &[u8]) -> bool {
        let state = self.state.lock().unwrap();
        !state.closed && epoch.boot == self.boot && epoch.generation > state.retired &&
            state.entries.iter().any(|entry| entry.owner == owner && entry.epoch == epoch && entry.tag.as_slice() == tag)
    }
    pub(crate) fn forget(&self, owner: Owner, epoch: Epoch, tag: &[u8]) {
        let mut state = self.state.lock().unwrap();
        if let Some(index) = state.entries.iter().position(|entry| entry.owner == owner && entry.epoch == epoch && entry.tag.as_slice() == tag) {
            let entry = state.entries.swap_remove(index);drop(state);drop(entry);
        }
    }
    pub(crate) fn cancel_one(&self, owner: Owner, epoch: Epoch, tag: &[u8]) {
        let entry={
            let mut state=self.state.lock().unwrap();
            state.entries.iter().position(|entry|entry.owner==owner && entry.epoch==epoch && entry.tag.as_slice()==tag)
                .map(|index|state.entries.swap_remove(index))
        };
        if let Some(entry)=entry { (entry.cancel)(); }
    }
    pub(crate) fn retire(&self, epoch: Epoch) {
        if epoch.boot != self.boot { return; }
        let retired = {
            let mut state = self.state.lock().unwrap();state.retired = state.retired.max(epoch.generation);
            let (retired, held) = std::mem::take(&mut state.entries).into_iter().partition::<Vec<_>, _>(|entry| entry.epoch.generation <= state.retired);
            state.entries = held;retired
        };
        for entry in retired { (entry.cancel)(); }
    }
    pub(crate) fn close(&self) {
        let retired = { let mut state = self.state.lock().unwrap();state.closed = true;std::mem::take(&mut state.entries) };
        for entry in retired { (entry.cancel)(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    fn owner() -> Owner { Owner { window:1, webview:1 } }
    fn epoch(generation: u64) -> Epoch { Epoch { boot: [3; 16], generation } }
    fn cancel(counter: Arc<AtomicUsize>) -> Cancel { Box::new(move || { counter.fetch_add(1, Ordering::AcqRel); }) }
    #[test]
    fn a_minted_late_handle_is_retired_even_before_registration() {
        let jobs = Resources::new([3; 16]);let count = Arc::new(AtomicUsize::new(0));
        jobs.retire(epoch(4));
        assert_eq!(jobs.register(owner(),epoch(4), vec![9], cancel(count.clone())), Err(Refusal::StaleEpoch));
        assert_eq!(count.load(Ordering::Acquire), 1);
    }
    #[test]
    fn retirement_cleans_exact_old_resources_without_affecting_successor() {
        let jobs = Resources::new([3; 16]);let old = Arc::new(AtomicUsize::new(0));let next = Arc::new(AtomicUsize::new(0));
        jobs.register(owner(),epoch(4), vec![9], cancel(old.clone())).unwrap();jobs.register(owner(),epoch(5), vec![9], cancel(next.clone())).unwrap();
        jobs.retire(epoch(4));jobs.retire(epoch(4));jobs.forget(owner(),epoch(4), &[9]);
        assert_eq!(old.load(Ordering::Acquire), 1);assert_eq!(next.load(Ordering::Acquire), 0);
        jobs.forget(owner(),epoch(5), &[9]);jobs.close();assert_eq!(next.load(Ordering::Acquire), 0);
    }
    #[test]
    fn cancellation_can_reenter_without_deadlock_or_restoring_retired_resource() {
        let jobs = Arc::new(Resources::new([3; 16]));let count = Arc::new(AtomicUsize::new(0));
        let callback = jobs.clone();let retired = count.clone();
        jobs.register(owner(),epoch(4), vec![9], Box::new(move || {
            assert_eq!(callback.register(owner(),epoch(4), vec![8], cancel(retired)), Err(Refusal::StaleEpoch));
        })).unwrap();
        jobs.retire(epoch(4));assert_eq!(count.load(Ordering::Acquire), 1);
    }
    #[test]
    fn a_full_or_closed_registry_retires_new_native_ownership() {
        let jobs = Resources::new([3; 16]);let count = Arc::new(AtomicUsize::new(0));
        for n in 0..64 { jobs.register(owner(),epoch(4), vec![n], Box::new(|| {})).unwrap(); }
        assert_eq!(jobs.register(owner(),epoch(4), vec![64], cancel(count.clone())), Err(Refusal::StaleEpoch));
        jobs.close();assert_eq!(jobs.register(owner(),epoch(5), vec![65], cancel(count.clone())), Err(Refusal::StaleEpoch));
        assert_eq!(count.load(Ordering::Acquire), 2);
    }
    #[test]
    fn finite_cleanup_matches_original_owner_epoch_and_ticket_only() {
        let jobs=Resources::new([3;16]);let count=Arc::new(AtomicUsize::new(0));
        jobs.register(owner(),epoch(4),vec![9],cancel(count.clone())).unwrap();
        jobs.cancel_one(Owner { window:1,webview:2 },epoch(4),&[9]);
        jobs.cancel_one(owner(),epoch(5),&[9]);jobs.cancel_one(owner(),epoch(4),&[8]);
        assert_eq!(count.load(Ordering::Acquire),0);
        jobs.cancel_one(owner(),epoch(4),&[9]);jobs.cancel_one(owner(),epoch(4),&[9]);
        assert_eq!(count.load(Ordering::Acquire),1);
    }
}
