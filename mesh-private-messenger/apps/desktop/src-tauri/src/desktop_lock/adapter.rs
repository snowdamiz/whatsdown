use crate::desktop_lock::controller::{Controller, Epoch, Lease, Owner, Refusal};
use std::sync::Arc;
use zeroize::Zeroize;

#[derive(Debug, Eq, PartialEq)]
pub enum CommandError {
    Admission(Refusal),
    Operation(String),
}
impl From<Refusal> for CommandError {
    fn from(error: Refusal) -> Self {
        Self::Admission(error)
    }
}
pub struct ScopedCommands {
    controller: Arc<Controller>,
}
pub struct Queued {
    controller: Arc<Controller>,
    lease: Lease,
}
pub struct InFlight {
    controller: Arc<Controller>,
    lease: Lease,
}
impl ScopedCommands {
    pub fn new(controller: Arc<Controller>) -> Self {
        Self { controller }
    }
    // Owner comes from the receiving native webview, never a JS header.
    pub fn queue(&self, owner: Owner, expected: Epoch) -> Result<Queued, Refusal> {
        let lease = self.controller.capture(owner, expected)?;
        Ok(Queued {
            controller: Arc::clone(&self.controller),
            lease,
        })
    }
}
impl Queued {
    // Call this after the actual worker/Core lock has been acquired. Enqueue
    // admission alone never authorizes a body that was waiting behind work.
    pub fn execute(
        self,
        operation: impl FnOnce() -> Result<Vec<u8>, String>,
    ) -> Result<Vec<u8>, CommandError> {
        self.controller.check(self.lease)?;
        let flight = InFlight {
            controller: self.controller,
            lease: self.lease,
        };
        flight.complete_result(operation())
    }
    #[cfg(test)]
    pub(crate) fn start(self, body: impl FnOnce()) -> Result<InFlight, Refusal> {
        self.controller.check(self.lease)?;
        body();
        Ok(InFlight {
            controller: self.controller,
            lease: self.lease,
        })
    }
}
impl InFlight {
    fn complete_result(self, mut result: Result<Vec<u8>, String>) -> Result<Vec<u8>, CommandError> {
        if let Err(error) = self.controller.check(self.lease) {
            match &mut result {
                Ok(bytes) => bytes.zeroize(),
                Err(message) => message.zeroize(),
            }
            return Err(CommandError::Admission(error));
        }
        result.map_err(CommandError::Operation)
    }
    #[cfg(test)]
    pub(crate) fn complete(self, private_bytes: Vec<u8>) -> Result<Vec<u8>, Refusal> {
        self.complete_result(Ok(private_bytes))
            .map_err(|error| match error {
                CommandError::Admission(error) => error,
                CommandError::Operation(_) => unreachable!(),
            })
    }
}
