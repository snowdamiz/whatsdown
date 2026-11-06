//! Native attachment intake owns exact subscriptions; it never adopts a newer
//! private lease. A retired intake may leave a custody-only choice for a fresh
//! explicit picker action, but cannot deliver automatically after unlock.
use super::{
    controller::{Epoch, Owner, Refusal},
    private_choices::{AttachmentChoices, ChoiceId, ChoiceMetadata, SelectedSource},
    private_files::FileError,
    receiver_scope::{fresh_uuid, ChoiceAnchor, PrivateScope},
    resources::Resources,
    wire,
};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
    time::Instant,
};
static CAPTURES: AtomicUsize = AtomicUsize::new(0);
pub(crate) struct IncomingCapture {
    ticket: IncomingTicket,
}
impl Drop for IncomingCapture {
    fn drop(&mut self) {
        CAPTURES.fetch_sub(1, Ordering::AcqRel);
    }
}
impl IncomingCapture {
    pub(crate) fn ticket(&self) -> &IncomingTicket {
        &self.ticket
    }
    pub(crate) fn complete(
        &self,
        selected: Vec<SelectedSource>,
        now: Instant,
    ) -> Result<bool, FileError> {
        self.ticket.complete(selected, now)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IncomingHandle([u8; 16]);
impl IncomingHandle {
    pub(crate) fn wire(self) -> String {
        wire::uuid(self.0)
    }
    pub(crate) fn parse(value: &str) -> Result<Self, FileError> {
        wire::parse_uuid(value).map(Self).ok_or(FileError::Invalid)
    }
    fn tag(self) -> Vec<u8> {
        let mut value = vec![4];
        value.extend_from_slice(&self.0);
        value
    }
}
type Cancel = Box<dyn FnOnce() + Send>;
struct Subscription {
    id: IncomingHandle,
    scope: PrivateScope,
    anchor: ChoiceAnchor,
    live: AtomicBool,
    pending: Mutex<VecDeque<ChoiceId>>,
    native: Mutex<Option<Cancel>>,
    dragging: AtomicBool,
}
impl Subscription {
    fn check(&self) -> Result<(), FileError> {
        if !self.live.load(Ordering::Acquire) {
            return Err(FileError::Unavailable);
        }
        self.scope.check()?;
        if !self.live.load(Ordering::Acquire) {
            return Err(FileError::Unavailable);
        }
        Ok(())
    }
    fn close(&self) {
        self.live.store(false, Ordering::Release);
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let cancel = self.native.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(cancel) = cancel {
            cancel();
        }
    }
}
impl Drop for Subscription {
    fn drop(&mut self) {
        self.close();
    }
}
struct State {
    closed: bool,
    subscriptions: Vec<Arc<Subscription>>,
}
pub(crate) struct IncomingFiles {
    state: Mutex<State>,
    resources: Arc<Resources>,
    choices: Arc<AttachmentChoices>,
}

// A native event captures this ticket before dispatching any metadata/FD work.
// The ticket retains the original scope/anchor even after its subscription ends.
#[derive(Clone)]
pub(crate) struct IncomingTicket {
    subscription: Arc<Subscription>,
    registry: Weak<IncomingFiles>,
}
impl IncomingTicket {
    pub(crate) fn handle(&self) -> IncomingHandle {
        self.subscription.id
    }
    pub(crate) fn scope(&self) -> PrivateScope {
        self.subscription.scope.clone()
    }
    pub(crate) fn current(&self) -> bool {
        self.subscription.check().is_ok()
    }
    pub(crate) fn capture(&self) -> Result<IncomingCapture, FileError> {
        self.subscription.check()?;
        CAPTURES
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 4).then_some(count + 1)
            })
            .map_err(|_| FileError::Limit)?;
        let held = IncomingCapture {
            ticket: self.clone(),
        };
        self.subscription.check()?;
        Ok(held)
    }
    pub(crate) fn dragging_changed(&self, value: bool) -> bool {
        self.current()
            && self.subscription.dragging.swap(value, Ordering::AcqRel) != value
            && self.current()
    }
    pub(crate) fn install_native(&self, cancel: Cancel) -> Result<(), FileError> {
        let mut cancel = Some(cancel);
        {
            let mut slot = self
                .subscription
                .native
                .lock()
                .map_err(|_| FileError::Unavailable)?;
            if self.subscription.live.load(Ordering::Acquire) && slot.is_none() {
                *slot = cancel.take();
            }
        }
        if let Some(cancel) = cancel {
            cancel();
            return Err(FileError::Unavailable);
        }
        self.subscription.check()
    }
    pub(crate) fn complete(
        &self,
        selected: Vec<SelectedSource>,
        now: Instant,
    ) -> Result<bool, FileError> {
        let registry = self.registry.upgrade().ok_or(FileError::Unavailable)?;
        // Choice custody has its own page/account fence and bounded lifetime.
        // Ordinary lock can preserve it; no private metadata is published here.
        let id = registry
            .choices
            .remember(self.subscription.anchor.clone(), selected, now)?;
        if self.subscription.check().is_err() {
            return Ok(false);
        }
        {
            let mut queue = self
                .subscription
                .pending
                .lock()
                .map_err(|_| FileError::Unavailable)?;
            if !self.subscription.live.load(Ordering::Acquire) {
                return Ok(false);
            }
            if queue.len() >= 4 {
                return Err(FileError::Limit);
            }
            queue.push_back(id);
        }
        Ok(self.subscription.check().is_ok())
    }
}
impl IncomingFiles {
    pub(crate) fn new(resources: Arc<Resources>, choices: Arc<AttachmentChoices>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                closed: false,
                subscriptions: Vec::new(),
            }),
            resources,
            choices,
        })
    }
    pub(crate) fn subscribe(
        self: &Arc<Self>,
        scope: PrivateScope,
    ) -> Result<IncomingTicket, FileError> {
        scope.check()?;
        let anchor = scope.choice_anchor()?;
        let id = IncomingHandle(fresh_uuid()?);
        let entry = Arc::new(Subscription {
            id,
            scope,
            anchor,
            live: AtomicBool::new(true),
            pending: Mutex::new(VecDeque::new()),
            native: Mutex::new(None),
            dragging: AtomicBool::new(false),
        });
        {
            let mut state = self.state.lock().map_err(|_| FileError::Unavailable)?;
            state
                .subscriptions
                .retain(|entry| entry.live.load(Ordering::Acquire));
            if state.closed || state.subscriptions.len() >= 4 {
                return Err(FileError::Limit);
            }
            state.subscriptions.push(entry.clone());
        }
        let weak = Arc::downgrade(self);
        let held = entry.clone();
        self.resources.register(
            entry.scope.owner(),
            entry.scope.epoch(),
            id.tag(),
            Box::new(move || {
                held.close();
                if let Some(registry) = weak.upgrade() {
                    registry.remove(id);
                }
            }),
        )?;
        if let Err(error) = entry.check() {
            self.unsubscribe(entry.scope.owner(), entry.scope.epoch(), id);
            return Err(error);
        }
        Ok(IncomingTicket {
            subscription: entry,
            registry: Arc::downgrade(self),
        })
    }
    fn remove(&self, id: IncomingHandle) {
        let removed = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state
                .subscriptions
                .iter()
                .position(|entry| entry.id == id)
                .map(|index| state.subscriptions.remove(index))
        };
        if let Some(entry) = removed {
            entry.close();
        }
    }
    pub(crate) fn unsubscribe(&self, owner: Owner, epoch: Epoch, id: IncomingHandle) {
        self.resources.cancel_one(owner, epoch, &id.tag());
    }
    pub(crate) fn for_receiver(self: &Arc<Self>, actual: Owner) -> Option<IncomingTicket> {
        let entries = self.state.lock().ok()?.subscriptions.clone();
        for entry in entries.into_iter().rev() {
            if entry.scope.owner() == actual && entry.check().is_ok() {
                return Some(IncomingTicket {
                    subscription: entry,
                    registry: Arc::downgrade(self),
                });
            }
        }
        None
    }
    pub(crate) fn take(
        self: &Arc<Self>,
        scope: &PrivateScope,
        id: IncomingHandle,
        now: Instant,
    ) -> Result<(Option<ChoiceMetadata>, Option<IncomingTicket>), FileError> {
        scope.check()?;
        let entry = self
            .state
            .lock()
            .map_err(|_| FileError::Unavailable)?
            .subscriptions
            .iter()
            .find(|entry| entry.id == id)
            .cloned()
            .ok_or(FileError::Unavailable)?;
        if entry.scope.owner() != scope.owner() || entry.scope.epoch() != scope.epoch() {
            return Err(FileError::Admission(Refusal::StaleEpoch));
        }
        entry.check()?;
        let result = loop {
            let selected = entry
                .pending
                .lock()
                .map_err(|_| FileError::Unavailable)?
                .pop_front();
            let Some(id) = selected else {
                break None;
            };
            if let Some(choice) = self.choices.selection(scope, id, now)? {
                break Some(choice);
            }
        };
        let more = !entry
            .pending
            .lock()
            .map_err(|_| FileError::Unavailable)?
            .is_empty();
        entry.check()?;
        scope.check()?;
        let hint = more.then(|| IncomingTicket {
            subscription: entry,
            registry: Arc::downgrade(self),
        });
        Ok((result, hint))
    }
    pub(crate) fn close(&self) {
        let held = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.closed = true;
            std::mem::take(&mut state.subscriptions)
        };
        for entry in held {
            self.resources
                .cancel_one(entry.scope.owner(), entry.scope.epoch(), &entry.id.tag());
            entry.close();
        }
    }
}
impl Drop for IncomingFiles {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(all(test, feature = "native-boundary-tests"))]
#[path = "tests/incoming_tests.rs"]
mod tests;
