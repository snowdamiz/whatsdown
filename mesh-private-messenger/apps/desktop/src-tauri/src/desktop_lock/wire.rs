//! Desktop wire projection. All mutable controller fields come from one
//! immutable Presentation, captured under the controller's state lock.
use crate::desktop_lock::controller::{Epoch, Phase, Policy, Presentation, Refusal, RequestId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    Unknown,
    Unavailable,
    Available,
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct DesktopState {
    pub epoch: String,
    pub policy: &'static str,
    pub phase: &'static str,
    pub capability: &'static str,
    pub foreground: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct DesktopEnvelope {
    pub version: u8,
    pub owner: String,
    pub revision: String,
    pub state: DesktopState,
}
fn hex(byte: u8) -> char {
    b"0123456789abcdef"[usize::from(byte)] as char
}
pub fn uuid(bytes: [u8; 16]) -> String {
    let mut value = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        value.push(hex(byte >> 4));
        value.push(hex(byte & 15));
    }
    value
}
fn unhex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
pub fn parse_uuid(value: &str) -> Option<[u8; 16]> {
    if value.len() != 36 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut result = [0; 16];
    let mut index = 0;
    for (slot, item) in result.iter_mut().enumerate() {
        if matches!(slot, 4 | 6 | 8 | 10) {
            if bytes[index] != b'-' {
                return None;
            }
            index += 1;
        }
        *item = unhex(bytes[index])? * 16 + unhex(bytes[index + 1])?;
        index += 2;
    }
    Some(result)
}
pub fn epoch(value: Epoch) -> String {
    format!("{}/{}", uuid(value.boot), value.generation)
}
pub fn request(value: RequestId) -> String {
    format!("{}/{}", uuid(value.boot()), value.sequence())
}
pub fn parse_epoch(value: &str) -> Result<Epoch, Refusal> {
    let (boot, generation) = value.split_once('/').ok_or(Refusal::StaleEpoch)?;
    let boot = parse_uuid(boot).ok_or(Refusal::StaleEpoch)?;
    let parsed = generation.parse::<u64>().map_err(|_| Refusal::StaleEpoch)?;
    if parsed.to_string() != generation {
        return Err(Refusal::StaleEpoch);
    }
    Ok(Epoch {
        boot,
        generation: parsed,
    })
}
impl DesktopState {
    pub fn from_presentation(value: Presentation, capability: Capability) -> Self {
        Self {
            epoch: epoch(value.epoch),
            policy: match value.policy {
                None => "unknown",
                Some(Policy::Disabled) => "disabled",
                Some(Policy::EnablePending) => "enable_pending",
                Some(Policy::Enabled) => "enabled",
                Some(Policy::DisablePending) => "disable_pending",
            },
            phase: match value.phase {
                Phase::Booting => "booting",
                Phase::Disabled => "disabled",
                Phase::Locked => "locked",
                Phase::Authenticating => "authenticating",
                Phase::AwaitingActivation => "awaiting_activation",
                Phase::Activated => "activated",
                Phase::Error => "error",
            },
            capability: match capability {
                Capability::Unknown => "unknown",
                Capability::Unavailable => "unavailable",
                Capability::Available => "available",
            },
            foreground: value.foreground,
            request: value.request.map(request),
        }
    }
}
impl DesktopEnvelope {
    pub fn new(
        owner: [u8; 16],
        revision: u64,
        presentation: Presentation,
        capability: Capability,
    ) -> Self {
        Self {
            version: 1,
            owner: uuid(owner),
            revision: revision.to_string(),
            state: DesktopState::from_presentation(presentation, capability),
        }
    }
}
