import RuntimeJobs

# Absent configuration preserves mixed-version rollout compatibility. Only
# explicit activation after draining old writers permits physical retirement.
pub fn prekey_retention_enabled() -> Bool!String do
  case Env.get("MESSENGER_PREKEY_RETENTION", "off") do
    "off" -> Ok(false)
    "on" -> Ok(true)
    _ -> Err("invalid prekey retention configuration")
  end
end

pub fn notify_prekey_retention(conn :: borrow PgConn) -> Result<(), String> do
  if prekey_retention_enabled()? do
    RuntimeJobs.notify(conn, "directory")
  else
    Ok(nil)
  end
end
