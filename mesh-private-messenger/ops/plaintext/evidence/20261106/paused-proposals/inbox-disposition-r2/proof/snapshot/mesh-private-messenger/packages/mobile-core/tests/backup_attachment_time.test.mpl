from Mobile.BackupAttachmentReader import (
  backup_attachment_read_completion, require_backup_attachment_read_time
)

fn clock_completion(captured :: String,
  fresh :: String,
  expires :: String,
  before :: String,
  now :: String) -> Bool!String do
  backup_attachment_read_completion(U64.parse(captured)?, U64.parse(fresh)?,
    U64.parse(expires)?, U64.parse(before)?, U64.parse(now)?)
end

test("read completion rejects observed rollback for live and already-expired attachments") do
  assert(clock_completion("100", "200", "300", "140", "130") == Err("backup_clock_rollback"))
  assert(clock_completion("100", "200", "120", "140", "130") == Err("backup_clock_rollback"))
  assert(clock_completion("100", "200", "80", "140", "99") == Err("backup_clock_rollback"))
end

test("read completion accepts equal and forward samples with strict attachment expiry") do
  assert(clock_completion("100", "200", "300", "140", "140") == Ok(true))
  assert(clock_completion("100", "200", "300", "140", "150") == Ok(true))
  assert(clock_completion("100", "200", "180", "140", "179") == Ok(true))
  assert(clock_completion("100", "200", "180", "140", "180") == Ok(false))
  assert(clock_completion("100", "200", "120", "140", "140") == Ok(false))
  assert(clock_completion("100", "200", "300", "200", "200") == Ok(true))
end

test("read completion refuses stale authority before classifying expiry including after expired shortcut") do
  assert(clock_completion("100", "200", "300", "99", "140") == Err("backup_clock_rollback"))
  assert(clock_completion("100", "200", "120", "140", "201") == Err("backup_authority_expired"))
  assert(clock_completion("100", "200", "300", "140", "201") == Err("backup_authority_expired"))
  assert(clock_completion("100", "200", "120", "201", "190") == Err("backup_authority_expired"))
end

fn clock_single_time_proof() -> Bool!String do
  let captured = U64.parse("100")?
  let fresh = U64.parse("200")?
  let expires = U64.parse("180")?
  assert(Result.is_ok(require_backup_attachment_read_time(captured, fresh, expires, U64.parse("179")?)))
  assert(require_backup_attachment_read_time(captured, fresh, expires, expires) == Err("backup_attachment_expired"))
  assert(require_backup_attachment_read_time(captured, fresh, expires, U64.parse("99")?) == Err("backup_clock_rollback"))
  assert(require_backup_attachment_read_time(captured, fresh, expires, U64.parse("201")?) == Err("backup_authority_expired"))
  Ok(true)
end

test("single-time attachment guard delegates to the same completion policy and retains refusal classes") do
  case clock_single_time_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
