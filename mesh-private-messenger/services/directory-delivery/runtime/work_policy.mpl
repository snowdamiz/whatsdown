# Raising signup work must not silently raise unrelated anonymous operations.
# Fall back to the existing deployment setting until the dedicated policy is set.
pub fn configured_signup_difficulty() -> Int do
  Env.get_int("MESSENGER_SIGNUP_DIFFICULTY", Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16))
end
