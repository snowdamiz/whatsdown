//! The actual startup gate used by bind and the native initialization worker.
use std::sync::{Arc, Mutex};
use tauri::async_runtime::{channel, Sender};

type Outcome<T> = Result<Arc<T>, &'static str>;
enum State<T> {
    Loading(Vec<Sender<Outcome<T>>>),
    Ready(Arc<T>),
    Failed,
    Closed,
}
pub(super) struct Startup<T>(Mutex<State<T>>);
impl<T> Startup<T> {
    pub(super) fn new() -> Self { Self(Mutex::new(State::Loading(Vec::new()))) }
    pub(super) fn is_closed(&self) -> bool { matches!(*self.0.lock().unwrap(), State::Closed) }
    pub(super) fn current(&self) -> Outcome<T> {
        match &*self.0.lock().unwrap() {
            State::Ready(ready) => Ok(ready.clone()),
            State::Loading(_) => Err("app_lock_booting"),
            _ => Err("app_lock_unavailable"),
        }
    }
    pub(super) async fn ready(&self) -> Outcome<T> {
        let mut receive = {
            let mut state = self.0.lock().unwrap();
            match &mut *state {
                State::Ready(ready) => return Ok(ready.clone()),
                State::Loading(waiters) => {
                    waiters.retain(|sender| !sender.is_closed());
                    if waiters.len() >= 32 { return Err("app_lock_busy"); }
                    let (send, receive) = channel(1); waiters.push(send); receive
                }
                _ => return Err("app_lock_unavailable"),
            }
        };
        let result = receive.recv().await.unwrap_or(Err("app_lock_unavailable"));
        // A queued success cannot authorize a caller after close/failure.
        self.current()?;
        result
    }
    pub(super) fn settle(&self, outcome: Outcome<T>) {
        let (previous, outcome) = {
            let mut state = self.0.lock().unwrap();
            match &*state {
                State::Loading(_) => {}
                State::Ready(_) if outcome.is_err() => {}
                _ => return,
            }
            let next = match &outcome { Ok(ready) => State::Ready(ready.clone()), Err(_) => State::Failed };
            (std::mem::replace(&mut *state, next), outcome)
        };
        if let State::Loading(waiters) = previous {
            for waiter in waiters { let _ = waiter.try_send(outcome.clone()); }
        }
    }
    pub(super) fn close(&self) {
        let previous = std::mem::replace(&mut *self.0.lock().unwrap(), State::Closed);
        if let State::Loading(waiters) = previous {
            for waiter in waiters { let _ = waiter.try_send(Err("app_lock_unavailable")); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, pin::pin, sync::atomic::{AtomicBool, Ordering}, task::{Context, Poll, Wake, Waker}};
    struct Signal(AtomicBool);
    impl Wake for Signal { fn wake(self: Arc<Self>) { self.0.store(true, Ordering::Release); } }
    fn context(signal: &Arc<Signal>) -> Waker { Waker::from(signal.clone()) }
    #[test]
    fn bind_waits_for_worker_and_receives_the_same_held_runtime() {
        let gate = Startup::new(); let signal = Arc::new(Signal(AtomicBool::new(false)));
        let waker = context(&signal); let mut cx = Context::from_waker(&waker);
        let mut waiting = pin!(gate.ready()); assert!(waiting.as_mut().poll(&mut cx).is_pending());
        let runtime = Arc::new(7); gate.settle(Ok(runtime.clone()));
        assert!(signal.0.load(Ordering::Acquire));
        let Poll::Ready(Ok(received)) = waiting.as_mut().poll(&mut cx) else { panic!("runtime not delivered") };
        assert!(Arc::ptr_eq(&runtime, &received));
    }
    #[test]
    fn shutdown_between_queued_success_and_bind_continuation_refuses() {
        let gate = Startup::new(); let signal = Arc::new(Signal(AtomicBool::new(false)));
        let waker = context(&signal); let mut cx = Context::from_waker(&waker);
        let mut waiting = pin!(gate.ready()); assert!(waiting.as_mut().poll(&mut cx).is_pending());
        gate.settle(Ok(Arc::new(7))); gate.close();
        assert!(matches!(waiting.as_mut().poll(&mut cx), Poll::Ready(Err("app_lock_unavailable"))));
        gate.settle(Ok(Arc::new(9))); assert_eq!(gate.current(), Err("app_lock_unavailable"));
    }
    #[test]
    fn initialization_failure_wakes_existing_and_later_binds_without_core() {
        let gate = Startup::<u8>::new(); let signal = Arc::new(Signal(AtomicBool::new(false)));
        let waker = context(&signal); let mut cx = Context::from_waker(&waker);
        let mut waiting = pin!(gate.ready()); assert!(waiting.as_mut().poll(&mut cx).is_pending());
        gate.settle(Err("native_initialization_failed"));
        assert!(matches!(waiting.as_mut().poll(&mut cx), Poll::Ready(Err("app_lock_unavailable"))));
        assert_eq!(gate.current(), Err("app_lock_unavailable"));
    }
    #[test]
    fn shutdown_wakes_unresolved_binds_and_drops_late_runtime() {
        let gate = Startup::new(); let signal = Arc::new(Signal(AtomicBool::new(false)));
        let waker = context(&signal); let mut cx = Context::from_waker(&waker);
        let mut waiting = pin!(gate.ready()); assert!(waiting.as_mut().poll(&mut cx).is_pending());
        gate.close(); let runtime = Arc::new(7); gate.settle(Ok(runtime.clone()));
        assert_eq!(Arc::strong_count(&runtime), 1);
        assert!(matches!(waiting.as_mut().poll(&mut cx), Poll::Ready(Err("app_lock_unavailable"))));
    }
}
