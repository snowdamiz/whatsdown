use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Owner {
    pub window: u64,
    pub webview: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Epoch {
    pub boot: [u8; 16],
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestId {
    boot: [u8; 16],
    sequence: u64,
}
impl RequestId {
    pub(crate) fn boot(self) -> [u8; 16] { self.boot }
    pub(crate) fn sequence(self) -> u64 { self.sequence }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Policy {
    Disabled,
    EnablePending,
    Enabled,
    DisablePending,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    pub install: [u8; 16],
    pub sequence: u64,
    pub policy: Policy,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    Booting,
    Locked,
    StaleOwner,
    StaleEpoch,
    Cancelled,
    TimedOut,
    PolicyUnreadable,
    PolicyChanged,
    Busy,
    Exhausted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Intent {
    Unlock,
    Enable,
    Disable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthReply {
    Approved,
    Cancelled,
    Failed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Booting,
    Disabled,
    Locked,
    Authenticating,
    AwaitingActivation,
    Activated,
    Error,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    Inactive,
    Active,
    Hidden,
    Minimized,
    SessionLocked,
    Destroyed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lease {
    epoch: Epoch,
    owner: Owner,
    account: u64,
    policy_sequence: u64,
}
impl Lease {
    // Native-only captured identity, never a latest-state repair or IPC value.
    pub(crate) fn account_generation(self) -> u64 { self.account }
}
#[derive(Clone, Copy, Debug)]
pub struct Presentation {
    pub revision: u64,
    pub owner: Option<Owner>,
    pub epoch: Epoch,
    pub phase: Phase,
    pub policy: Option<Policy>,
    // Native-only projection; never serialized by the DesktopEnvelope.
    pub(crate) account_generation: u64,
    pub(crate) notice_private_allowed: bool,
    pub foreground: bool,
    pub request: Option<RequestId>,
    pub uncover: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct AuthRequest {
    pub id: RequestId,
    pub owner: Owner,
    pub intent: Intent,
}

pub type Work = Box<dyn FnOnce() + Send>;
pub trait Executor: Send + Sync {
    fn post(&self, work: Work);
}
pub trait Clock: Send + Sync {
    fn milliseconds(&self) -> u64;
}
pub trait PolicyStore: Send + Sync {
    fn read(&self) -> Result<Record, Refusal>;
    fn compare_write(&self, previous: Record, desired: Policy) -> Result<Record, Refusal>;
}
// The native registry must retain cancelled request IDs: cancellation before
// context insertion must also prevent a later begin from presenting a prompt.
pub trait Authentication: Send + Sync {
    fn begin(
        &self,
        request: AuthRequest,
        reply: Box<dyn Fn(AuthReply) + Send + Sync>,
    ) -> Result<(), Refusal>;
    fn cancel(&self, request: RequestId);
}
// The native main-thread presenter must ignore a revision older than the latest
// received one. This prevents a delayed old uncover from overriding revocation.
// It must not block or reenter controller state while applying a presentation.
pub trait Cover: Send + Sync {
    fn apply(&self, presentation: Presentation);
    fn retire_private_resources(&self, epoch: Epoch);
}

#[derive(Clone, Copy)]
struct Challenge {
    request: AuthRequest,
    account: u64,
    original: Record,
    current: Record,
    deadline: u64,
    approved: bool,
    finalizing: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyAuthority {
    Unavailable,
    Verified(Record),
    Pending {
        request: RequestId,
        last_verified: Record,
    },
}
impl PolicyAuthority {
    fn verified(self) -> Option<Record> {
        match self {
            Self::Verified(record) => Some(record),
            _ => None,
        }
    }
    fn permits_private(self) -> bool {
        self.verified()
            .is_some_and(|r| matches!(r.policy, Policy::Disabled | Policy::Enabled))
    }
    fn matches(self, request: RequestId, record: Record) -> bool {
        match self {
            Self::Verified(actual) => actual == record,
            Self::Pending {
                request: actual,
                last_verified,
            } => actual == request && last_verified == record,
            Self::Unavailable => false,
        }
    }
    fn display(self) -> Option<Policy> {
        match self {
            Self::Verified(r)
            | Self::Pending {
                last_verified: r, ..
            } => Some(r.policy),
            Self::Unavailable => None,
        }
    }
}
struct State {
    owner: Option<Owner>,
    active: bool,
    epoch: Epoch,
    account: u64,
    authority: PolicyAuthority,
    phase: Phase,
    ready: bool,
    request: Option<Challenge>,
    next_request: u64,
    revision: u64,
    exhausted: bool,
}
pub struct Controller {
    state: Mutex<State>,
    policy_io: Mutex<()>,
    store: Arc<dyn PolicyStore>,
    auth: Arc<dyn Authentication>,
    clock: Arc<dyn Clock>,
    cover: Arc<dyn Cover>,
    executor: Arc<dyn Executor>,
}
impl Controller {
    pub fn new(
        boot: [u8; 16],
        owner: Owner,
        store: Arc<dyn PolicyStore>,
        auth: Arc<dyn Authentication>,
        clock: Arc<dyn Clock>,
        cover: Arc<dyn Cover>,
        executor: Arc<dyn Executor>,
    ) -> Arc<Self> {
        let this = Arc::new(Self {
            state: Mutex::new(State {
                owner: Some(owner),
                active: true,
                epoch: Epoch {
                    boot,
                    generation: 0,
                },
                account: 0,
                authority: PolicyAuthority::Unavailable,
                phase: Phase::Booting,
                ready: false,
                request: None,
                next_request: 0,
                revision: 0,
                exhausted: false,
            }),
            policy_io: Mutex::new(()),
            store,
            auth,
            clock,
            cover,
            executor,
        });
        this.publish();
        let weak = Arc::downgrade(&this);
        this.executor.post(Box::new(move || {
            if let Some(this) = weak.upgrade() {
                this.bootstrap();
            }
        }));
        this
    }
    fn bootstrap(&self) {
        let _io = self.policy_io.lock().unwrap();
        let loaded = self.store.read();
        {
            let mut s = self.state.lock().unwrap();
            match loaded {
                Ok(record) => {
                    s.authority = PolicyAuthority::Verified(record);
                    if s.phase == Phase::Booting {
                        s.phase = if record.policy == Policy::Disabled {
                            Phase::Disabled
                        } else {
                            Phase::Locked
                        };
                    }
                }
                Err(_) => {
                    s.authority = PolicyAuthority::Unavailable;
                    s.phase = Phase::Error;
                    s.ready = false;
                }
            }
        }
        self.publish();
    }
    fn publish(&self) {
        let p = {
            let mut s = self.state.lock().unwrap();
            s.revision = s.revision.saturating_add(1);
            Presentation {
                revision: s.revision,
                owner: s.owner,
                epoch: s.epoch,
                phase: s.phase,
                policy: s.authority.display(),
                account_generation: s.account,
                notice_private_allowed: !s.exhausted && s.owner.is_some() && s.request.is_none()
                    && s.authority.verified().is_some_and(|record|record.policy==Policy::Disabled),
                foreground: s.active,
                request: s.request.map(|challenge| challenge.request.id),
                uncover: s.owner.is_some()
                    && s.active
                    && s.ready
                    && s.phase == Phase::Activated
                    && !s.exhausted
                    && s.authority.permits_private(),
            }
        };
        self.cover.apply(p);
    }
    fn rotate(s: &mut State) -> Result<Epoch, Refusal> {
        let old = s.epoch;
        s.ready = false;
        match s.epoch.generation.checked_add(1) {
            Some(next) => s.epoch.generation = next,
            None => {
                s.exhausted = true;
                s.phase = Phase::Error;
                return Err(Refusal::Exhausted);
            }
        }
        Ok(old)
    }
    fn retire(&self, old: Epoch, cancel: Option<RequestId>) {
        self.publish();
        self.cover.retire_private_resources(old);
        if let Some(id) = cancel {
            self.auth.cancel(id);
        }
    }
    pub fn refresh_policy(self: &Arc<Self>) {
        let retired = {
            let mut s = self.state.lock().unwrap();
            let old = Self::rotate(&mut s).unwrap_or(s.epoch);
            let cancel = s.request.take().map(|c| c.request.id);
            s.authority = PolicyAuthority::Unavailable;
            s.phase = Phase::Booting;
            (old, cancel)
        };
        self.retire(retired.0, retired.1);
        let weak = Arc::downgrade(self);
        self.executor.post(Box::new(move || {
            if let Some(this) = weak.upgrade() {
                this.bootstrap()
            }
        }));
    }
    pub fn epoch(&self) -> Epoch {
        self.state.lock().unwrap().epoch
    }
    pub fn phase(&self) -> Phase {
        self.state.lock().unwrap().phase
    }
    pub fn policy(&self) -> Option<Policy> {
        self.state.lock().unwrap().authority.display()
    }
    pub fn activate(&self, owner: Owner, epoch: Epoch) -> Result<(), Refusal> {
        {
            let mut s = self.state.lock().unwrap();
            if s.exhausted {
                return Err(Refusal::Exhausted);
            }
            if s.owner != Some(owner) {
                return Err(Refusal::StaleOwner);
            }
            if s.epoch != epoch {
                return Err(Refusal::StaleEpoch);
            }
            if !s.active
                || !s.authority.permits_private()
                || !matches!(
                    s.phase,
                    Phase::Disabled | Phase::AwaitingActivation | Phase::Activated
                )
            {
                return Err(Refusal::Locked);
            }
            s.ready = true;
            s.phase = Phase::Activated;
        }
        self.publish();
        Ok(())
    }
    pub fn capture(&self, owner: Owner, epoch: Epoch) -> Result<Lease, Refusal> {
        let s = self.state.lock().unwrap();
        if s.exhausted {
            return Err(Refusal::Exhausted);
        }
        if s.owner != Some(owner) {
            return Err(Refusal::StaleOwner);
        }
        if s.epoch != epoch {
            return Err(Refusal::StaleEpoch);
        }
        let record = s.authority.verified().ok_or(Refusal::Locked)?;
        if s.phase != Phase::Activated
            || !s.authority.permits_private()
            || !s.ready
            || (record.policy != Policy::Disabled && !s.active)
        {
            return Err(Refusal::Locked);
        }
        Ok(Lease {
            epoch,
            owner,
            account: s.account,
            policy_sequence: record.sequence,
        })
    }
    pub(crate) fn choice_is_current(&self, lease: Lease) -> bool {
        let state = self.state.lock().unwrap();
        !state.exhausted && state.owner == Some(lease.owner) && state.account == lease.account
    }
    pub fn check(&self, lease: Lease) -> Result<(), Refusal> {
        let current = self.capture(lease.owner, lease.epoch)?;
        if current != lease {
            return Err(Refusal::StaleEpoch);
        }
        Ok(())
    }
    fn retired_phase(s: &State) -> Phase {
        if s.exhausted {
            return Phase::Error;
        }
        match s.authority {
            PolicyAuthority::Verified(record) if record.policy == Policy::Disabled => {
                Phase::Disabled
            }
            PolicyAuthority::Verified(_) | PolicyAuthority::Pending { .. } => Phase::Locked,
            PolicyAuthority::Unavailable if s.phase == Phase::Booting => Phase::Booting,
            PolicyAuthority::Unavailable => Phase::Error,
        }
    }
    pub fn lifecycle(self: &Arc<Self>, owner: Owner, event: Event) {
        if event == Event::Active {
            let pending = {
                let mut s = self.state.lock().unwrap();
                if s.owner != Some(owner) {
                    return;
                }
                s.active = true;
                s.request
                    .filter(|c| c.approved && !c.finalizing)
                    .map(|c| c.request.id)
            };
            self.publish();
            if let Some(id) = pending {
                self.schedule_finish(id);
            }
            return;
        }
        let retired = {
            let mut s = self.state.lock().unwrap();
            if s.owner != Some(owner) {
                return;
            }
            s.active = false;
            // Preserve existing disabled desktop background synchronization.
            if matches!(event, Event::Inactive | Event::Hidden | Event::Minimized)
                && s.request.is_none()
                && s.phase == Phase::Activated
                && s.authority.verified().map(|r| r.policy) == Some(Policy::Disabled)
            {
                drop(s);
                self.publish();
                return;
            }
            let old = match Self::rotate(&mut s) {
                Ok(old) => old,
                Err(_) => {
                    drop(s);
                    self.publish();
                    return;
                }
            };
            let cancel = if event == Event::Inactive {
                None
            } else {
                s.request.take().map(|c| c.request.id)
            };
            if event == Event::Destroyed {
                s.owner = None;
            }
            s.phase = if s.request.is_some() {
                Phase::Authenticating
            } else {
                Self::retired_phase(&s)
            };
            (old, cancel)
        };
        self.retire(retired.0, retired.1);
    }
    pub fn replace_owner(&self, owner: Owner) {
        let retired = {
            let mut s = self.state.lock().unwrap();
            let old = Self::rotate(&mut s).unwrap_or(s.epoch);
            let cancel = s.request.take().map(|c| c.request.id);
            s.owner = Some(owner);
            s.active = true;
            s.phase = Self::retired_phase(&s);
            (old, cancel)
        };
        self.retire(retired.0, retired.1);
    }
    pub fn account_changed(&self) {
        let retired = {
            let mut s = self.state.lock().unwrap();
            let old = Self::rotate(&mut s).unwrap_or(s.epoch);
            s.account = s.account.saturating_add(1);
            let cancel = s.request.take().map(|c| c.request.id);
            s.phase = Self::retired_phase(&s);
            (old, cancel)
        };
        self.retire(retired.0, retired.1);
    }
    // Native binding/attachment refusal is restrictive until a genuine policy
    // reload succeeds. A cached Disabled record cannot recover the failed owner.
    pub fn unavailable(&self, owner: Owner) {
        let retired = {
            let mut s = self.state.lock().unwrap();
            if s.owner != Some(owner) { return; }
            let old = Self::rotate(&mut s).unwrap_or(s.epoch);
            let cancel = s.request.take().map(|c| c.request.id);
            s.authority = PolicyAuthority::Unavailable;
            s.phase = Phase::Error;
            (old, cancel)
        };
        self.retire(retired.0, retired.1);
    }
    // IPC narrowing is checked inside the same native state lock as mutation.
    // A stale admitted caller cannot lock or retire a successor owner/epoch.
    pub fn lock_for(&self, owner: Owner, expected: Epoch) -> Result<(), Refusal> {
        let retired = {
            let mut s = self.state.lock().unwrap();
            if s.exhausted { return Err(Refusal::Exhausted); }
            if s.owner != Some(owner) { return Err(Refusal::StaleOwner); }
            if s.epoch != expected { return Err(Refusal::StaleEpoch); }
            if s.authority.verified().map(|record|record.policy) != Some(Policy::Enabled) {
                return Err(Refusal::PolicyChanged);
            }
            let old = Self::rotate(&mut s)?;
            let cancel = s.request.take().map(|c| c.request.id);
            s.phase = Phase::Locked;
            (old, cancel)
        };
        self.retire(retired.0, retired.1);
        Ok(())
    }
    pub fn lock_now(&self) {
        let retired = {
            let mut s = self.state.lock().unwrap();
            let old = Self::rotate(&mut s).unwrap_or(s.epoch);
            let cancel = s.request.take().map(|c| c.request.id);
            s.phase = Phase::Locked;
            (old, cancel)
        };
        self.retire(retired.0, retired.1);
    }
    pub fn request(
        self: &Arc<Self>,
        owner: Owner,
        epoch: Epoch,
        intent: Intent,
    ) -> Result<RequestId, Refusal> {
        let (challenge, old) = {
            let mut s = self.state.lock().unwrap();
            if s.exhausted {
                return Err(Refusal::Exhausted);
            }
            if s.owner != Some(owner) {
                return Err(Refusal::StaleOwner);
            }
            if s.epoch != epoch {
                return Err(Refusal::StaleEpoch);
            }
            if !s.active {
                return Err(Refusal::Locked);
            }
            if s.request.is_some() {
                return Err(Refusal::Busy);
            }
            let record = s.authority.verified().ok_or(Refusal::PolicyUnreadable)?;
            if s.phase == Phase::Error {
                return Err(Refusal::PolicyUnreadable);
            }
            if intent == Intent::Unlock && record.policy != Policy::Enabled {
                return Err(Refusal::PolicyChanged);
            }
            s.next_request = s.next_request.checked_add(1).ok_or(Refusal::Exhausted)?;
            let id = RequestId {
                boot: s.epoch.boot,
                sequence: s.next_request,
            };
            let c = Challenge {
                request: AuthRequest { id, owner, intent },
                account: s.account,
                original: record,
                current: record,
                deadline: self
                    .clock
                    .milliseconds()
                    .checked_add(120_000)
                    .ok_or(Refusal::Exhausted)?,
                approved: false,
                finalizing: false,
            };
            let old = Self::rotate(&mut s)?;
            s.request = Some(c);
            s.phase = Phase::Authenticating;
            (c, old)
        };
        self.retire(old, None);
        let weak = Arc::downgrade(self);
        self.executor.post(Box::new(move || {
            if let Some(this) = weak.upgrade() {
                this.begin_checked(challenge)
            }
        }));
        Ok(challenge.request.id)
    }
    fn valid(s: &State, c: Challenge, now: u64, foreground: bool) -> Result<(), Refusal> {
        let current = s.request.ok_or(Refusal::Cancelled)?;
        if current.request.id != c.request.id
            || s.owner != Some(c.request.owner)
            || s.account != c.account
        {
            return Err(Refusal::Cancelled);
        }
        if now > c.deadline {
            return Err(Refusal::TimedOut);
        }
        if !s.authority.matches(c.request.id, c.current) {
            return Err(Refusal::PolicyChanged);
        }
        if foreground && !s.active {
            return Err(Refusal::Cancelled);
        }
        Ok(())
    }
    fn begin_checked(self: &Arc<Self>, c: Challenge) {
        let checked = (|| {
            let _io = self.policy_io.lock().unwrap();
            {
                let mut s = self.state.lock().unwrap();
                Self::valid(&s, c, self.clock.milliseconds(), true)?;
                s.authority = PolicyAuthority::Pending {
                    request: c.request.id,
                    last_verified: c.current,
                };
            }
            if self.store.read()? != c.original {
                return Err(Refusal::PolicyChanged);
            }
            self.settle_policy(c.request.id, Some(c.original));
            Ok(())
        })();
        if let Err(error) = checked {
            self.settle_policy(c.request.id, None);
            self.fail(c.request.id, error, false);
            return;
        }
        {
            let s = self.state.lock().unwrap();
            if let Err(error) = Self::valid(&s, c, self.clock.milliseconds(), true) {
                drop(s);
                self.fail(c.request.id, error, false);
                return;
            }
        }
        let weak = Arc::downgrade(self);
        let id = c.request.id;
        if let Err(error) = self.auth.begin(
            c.request,
            Box::new(move |reply| {
                if let Some(this) = weak.upgrade() {
                    this.reply(id, reply)
                }
            }),
        ) {
            self.fail(id, error, false)
        }
    }
    fn reply(self: &Arc<Self>, id: RequestId, reply: AuthReply) {
        let action = {
            let mut s = self.state.lock().unwrap();
            let Some(c) = s.request else { return };
            if c.request.id != id || c.approved {
                return;
            }
            if let Err(error) = Self::valid(&s, c, self.clock.milliseconds(), false) {
                drop(s);
                self.fail(id, error, false);
                return;
            }
            match reply {
                AuthReply::Approved => {
                    s.request.as_mut().unwrap().approved = true;
                    s.active
                }
                AuthReply::Cancelled => {
                    drop(s);
                    self.fail(id, Refusal::Cancelled, true);
                    return;
                }
                AuthReply::Failed => {
                    drop(s);
                    self.fail(id, Refusal::Cancelled, false);
                    return;
                }
            }
        };
        if action {
            self.schedule_finish(id)
        }
    }
    fn schedule_finish(self: &Arc<Self>, id: RequestId) {
        {
            let mut s = self.state.lock().unwrap();
            let Some(c) = s.request.as_mut() else { return };
            if c.request.id != id || !c.approved || c.finalizing {
                return;
            }
            c.finalizing = true;
        }
        let weak = Arc::downgrade(self);
        self.executor.post(Box::new(move || {
            if let Some(this) = weak.upgrade() {
                this.finish(id)
            }
        }));
    }
    fn settle_policy(&self, id: RequestId, known: Option<Record>) {
        {
            let mut s = self.state.lock().unwrap();
            if !matches!(s.authority, PolicyAuthority::Pending { request, .. } if request == id) {
                return;
            }
            s.authority = known
                .map(PolicyAuthority::Verified)
                .unwrap_or(PolicyAuthority::Unavailable);
            // Settling old IO can update policy truth, never owner readiness.
            if known.is_none() {
                s.ready = false;
                s.phase = Phase::Error;
            }
        }
        self.publish();
    }
    fn finish(&self, id: RequestId) {
        let mut known = None;
        let result = (|| {
            let _io = self.policy_io.lock().unwrap();
            let mut c = {
                let mut s = self.state.lock().unwrap();
                let c = s.request.ok_or(Refusal::Cancelled)?;
                if c.request.id != id || !c.approved {
                    return Err(Refusal::Cancelled);
                }
                Self::valid(&s, c, self.clock.milliseconds(), true)?;
                // Admit policy IO under the short state lock before it can
                // settle outside that lock. Retirement cannot trust old bytes.
                s.authority = PolicyAuthority::Pending {
                    request: id,
                    last_verified: c.current,
                };
                c
            };
            if self.store.read()? != c.current {
                return Err(Refusal::PolicyChanged);
            }
            known = Some(c.current);
            let final_policy = match c.request.intent {
                Intent::Unlock | Intent::Enable => Policy::Enabled,
                Intent::Disable => Policy::Disabled,
            };
            let pending = match c.request.intent {
                Intent::Enable => Some(Policy::EnablePending),
                Intent::Disable => Some(Policy::DisablePending),
                Intent::Unlock => None,
            };
            let mut transitions = Vec::new();
            if let Some(p) = pending {
                if c.current.policy != final_policy {
                    if c.current.policy != p {
                        transitions.push(p);
                    }
                    transitions.push(final_policy);
                }
            }
            for desired in transitions {
                {
                    let s = self.state.lock().unwrap();
                    Self::valid(&s, c, self.clock.milliseconds(), true)?;
                }
                let expected = Record {
                    install: c.current.install,
                    sequence: c
                        .current
                        .sequence
                        .checked_add(1)
                        .ok_or(Refusal::Exhausted)?,
                    policy: desired,
                };
                known = None; // A failed write/readback has unknown durable outcome.
                let written = self.store.compare_write(c.current, desired)?;
                if written != expected || self.store.read()? != written {
                    return Err(Refusal::PolicyChanged);
                }
                known = Some(written);
                {
                    let mut s = self.state.lock().unwrap();
                    if !matches!(s.authority, PolicyAuthority::Pending { request, .. } if request == id)
                    {
                        return Err(Refusal::Cancelled);
                    }
                    s.authority = PolicyAuthority::Pending {
                        request: id,
                        last_verified: written,
                    };
                    if let Some(current) = s.request.as_mut() {
                        if current.request.id == id {
                            current.current = written;
                        }
                    }
                }
                c.current = written;
            }
            let old = {
                let mut s = self.state.lock().unwrap();
                Self::valid(&s, c, self.clock.milliseconds(), true)?;
                let old = Self::rotate(&mut s)?;
                s.authority = PolicyAuthority::Verified(c.current);
                s.request = None;
                s.phase = Phase::AwaitingActivation;
                old
            };
            self.retire(old, Some(id));
            Ok(())
        })();
        if let Err(error) = result {
            self.settle_policy(id, known);
            self.fail(id, error, false);
        }
    }
    fn fail(&self, id: RequestId, error: Refusal, allow_restore_disabled: bool) {
        let retired = {
            let mut s = self.state.lock().unwrap();
            let Some(c) = s.request else { return };
            if c.request.id != id {
                return;
            }
            let old = Self::rotate(&mut s).unwrap_or(s.epoch);
            s.request = None;
            if matches!(error, Refusal::PolicyChanged | Refusal::PolicyUnreadable) {
                s.authority = PolicyAuthority::Unavailable;
            }
            let restore = allow_restore_disabled
                && c.request.intent == Intent::Enable
                && c.original.policy == Policy::Disabled
                && !c.approved
                && s.authority == PolicyAuthority::Verified(c.original)
                && s.owner == Some(c.request.owner)
                && s.account == c.account;
            s.phase = if restore {
                Phase::Disabled
            } else if matches!(error, Refusal::PolicyChanged | Refusal::PolicyUnreadable) {
                Phase::Error
            } else {
                Phase::Locked
            };
            (old, Some(id))
        };
        self.retire(retired.0, retired.1);
    }
    pub fn cancel(&self, owner: Owner, id: RequestId) {
        let matches = {
            let s = self.state.lock().unwrap();
            s.owner == Some(owner) && s.request.map(|c| c.request.id) == Some(id)
        };
        if matches {
            self.fail(id, Refusal::Cancelled, true)
        }
    }
    pub fn expire(&self) {
        let expired = {
            let s = self.state.lock().unwrap();
            s.request
                .filter(|c| self.clock.milliseconds() > c.deadline)
                .map(|c| c.request.id)
        };
        if let Some(id) = expired {
            self.fail(id, Refusal::TimedOut, false)
        }
    }
}
