##! Release-owned policy for new pairwise sessions, independent of suite history.
from Mobile.Platform import decode_native_security_config

# This ordinary record is a captured source, not a caller authority token. No
# decoded minimum is cached: callers derive it again from the canonical frame.
pub struct NativeSessionPolicy do
  frame :: Bytes
end

fn native_frame() -> Bytes!String do
  case Host.push_get_token(Bytes.from_utf8("messenger/config/v1")) do
    Err(_) -> Err("messenger_configuration_required")
    Ok(value)
  end
end

pub fn capture_native_session_policy() -> NativeSessionPolicy!String do
  let frame = native_frame()?
  decode_native_security_config(frame)?
  Ok(NativeSessionPolicy { frame: frame })
end

# This helper opens no database transaction and performs no network operation.
# Final writers call it after acquiring their existing writer lock, alongside
# the original AccountBasis/ReceiveSources, before publishing any new session.
pub fn require_current_session_policy(policy :: NativeSessionPolicy) -> Unit!String do
  decode_native_security_config(policy.frame)?
  if !Bytes.secure_equals(policy.frame, native_frame()?) do
    Err("account_state_changed")
  else
    Ok(nil)
  end
end

pub fn native_session_minimum(policy :: NativeSessionPolicy) -> Int!String do
  require_current_session_policy(policy)?
  Ok(decode_native_security_config(policy.frame)?.minimum_session_suite)
end
