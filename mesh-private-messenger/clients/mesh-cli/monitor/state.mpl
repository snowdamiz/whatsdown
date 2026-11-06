from Transparency.AnchorRing import decode_anchor_entry
from Transparency.Wire import decode_checkpoint, encode_checkpoint
from Transparency.Fork import decode_fork, encode_fork
from Transparency.Merkle import checkpoint_hash
from Monitor.Policy import monitor_successors
from Transparency.AnchorContext import decode_anchor_context

pub struct MonitorState do
  revision :: U64
  context_slot :: U64
  ring_index :: Int
  entry :: Bytes
  checkpoint :: Bytes
  registry :: String
  report :: String
  proof :: Bytes
  pending_index :: Int
  pending_entry :: Bytes
  proof_context :: Bytes
  probe_index :: Int
end

pub struct MonitorAttendance do
  ring_index :: Int
  entry :: Bytes
end

pub struct MonitorAttendanceCounts do
  pending :: Int
  met :: Int
  missed :: Int
  lost :: Int
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(value) -> Ok(value)
    _ -> Err("invalid_monitor_state")
  end
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(value) -> Ok(value)
    _ -> Err("invalid_monitor_state")
  end
end

fn open(path :: String) -> SqliteConn!String do
  let db = Sqlite.open(path)?
  let configured = configure(db)
  case configured do
    Err(error) -> do
      Sqlite.close(db)
      Err(error)
    end
    Ok(_) -> Ok(db)
  end
end

fn configure(db :: SqliteConn) -> Result<(), String> do
  Sqlite.execute(db, "PRAGMA busy_timeout = 1000", [])?
  Sqlite.query(db, "PRAGMA journal_mode = WAL", [])?
  Sqlite.execute(db, "PRAGMA synchronous = FULL", [])?
  Sqlite.execute(db,
    "CREATE TABLE IF NOT EXISTS monitor_state (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), identity TEXT NOT NULL, revision TEXT NOT NULL, context_slot TEXT NOT NULL, ring_index TEXT NOT NULL, entry BLOB NOT NULL, checkpoint BLOB NOT NULL, registry TEXT NOT NULL, report TEXT NOT NULL, proof BLOB NOT NULL)",
    [])?
  Sqlite.execute(db,
    "CREATE TABLE IF NOT EXISTS monitor_history (checkpoint_hash TEXT NOT NULL, posted_slot TEXT NOT NULL, entry BLOB NOT NULL, checkpoint BLOB NOT NULL, PRIMARY KEY(checkpoint_hash, posted_slot))",
    [])?
  Sqlite.execute(db,
    "CREATE TABLE IF NOT EXISTS monitor_attendance (checkpoint_hash TEXT NOT NULL, posted_slot TEXT NOT NULL, ring_index TEXT NOT NULL, entry BLOB NOT NULL, phase TEXT NOT NULL DEFAULT 'pending', PRIMARY KEY(checkpoint_hash, posted_slot))",
    [])?
  Sqlite.execute(db,
    "CREATE INDEX IF NOT EXISTS monitor_attendance_phase ON monitor_attendance(phase)",
    [])?
  let attendance_columns = Sqlite.query(db, "PRAGMA table_info(monitor_attendance)", [])?
  if !List.any(attendance_columns, fn(row) do Map.get(row, "name") == "attempt_order" end) do
    Sqlite.execute(db,
      "ALTER TABLE monitor_attendance ADD COLUMN attempt_order INTEGER NOT NULL DEFAULT 0",
      [])?
    nil
  end
  Sqlite.execute(db,
    "CREATE INDEX IF NOT EXISTS monitor_attendance_order ON monitor_attendance(phase, attempt_order)",
    [])?
  let columns = Sqlite.query(db, "PRAGMA table_info(monitor_state)", [])?
  if !List.any(columns, fn(row) do Map.get(row, "name") == "pending_entry" end) do
    Sqlite.execute(db,
      "ALTER TABLE monitor_state ADD COLUMN pending_entry BLOB NOT NULL DEFAULT X''",
      [])?
    nil
  end
  if !List.any(columns, fn(row) do Map.get(row, "name") == "pending_index" end) do
    Sqlite.execute(db,
      "ALTER TABLE monitor_state ADD COLUMN pending_index TEXT NOT NULL DEFAULT '-1'",
      [])?
    nil
  end
  if !List.any(columns, fn(row) do Map.get(row, "name") == "proof_context" end) do
    Sqlite.execute(db,
      "ALTER TABLE monitor_state ADD COLUMN proof_context BLOB NOT NULL DEFAULT X''",
      [])?
    nil
  end
  if !List.any(columns, fn(row) do Map.get(row, "name") == "probe_index" end) do
    Sqlite.execute(db,
      "ALTER TABLE monitor_state ADD COLUMN probe_index TEXT NOT NULL DEFAULT '0'",
      [])?
    nil
  end
  Ok(nil)
end

fn load(db :: SqliteConn, identity :: Bytes) -> MonitorState!String do
  if Bytes.length(identity) != 32 do
    return Err("invalid_monitor_identity")
  end
  Sqlite.execute_values(db,
    "INSERT OR IGNORE INTO monitor_state (singleton, identity, revision, context_slot, ring_index, entry, checkpoint, registry, report, proof) VALUES (1, ?, '0', '0', '-1', ?, ?, '', '{}', ?)",
    [
      Text(Bytes.to_hex(identity)),
      Binary(Bytes.empty()),
      Binary(Bytes.empty()),
      Binary(Bytes.empty())
    ])?
  existing(db, identity)
end

fn existing(db :: SqliteConn, identity :: Bytes) -> MonitorState!String do
  let rows = Sqlite.query_values(db, "SELECT * FROM monitor_state WHERE singleton = 1", [])?
  if List.length(rows) != 1 do
    return Err("monitor_not_initialized")
  end
  let row = List.head(rows)
  if text(Map.get(row, "identity"))? != Bytes.to_hex(identity) do
    return Err("monitor_identity_changed")
  end
  Ok(MonitorState {
    revision: U64.parse(text(Map.get(row, "revision"))?)?,
    context_slot: U64.parse(text(Map.get(row, "context_slot"))?)?,
    ring_index: case String.to_int(text(Map.get(row, "ring_index"))?) do
      None -> return Err("invalid_monitor_state")
      Some(index) -> index
    end,
    entry: binary(Map.get(row, "entry"))?,
    checkpoint: binary(Map.get(row, "checkpoint"))?,
    registry: text(Map.get(row, "registry"))?,
    report: text(Map.get(row, "report"))?,
    proof: binary(Map.get(row, "proof"))?,
    pending_index: number(text(Map.get(row, "pending_index"))?)?,
    pending_entry: binary(Map.get(row, "pending_entry"))?,
    proof_context: binary(Map.get(row, "proof_context"))?,
    probe_index: number(text(Map.get(row, "probe_index"))?)?
  })
end

pub fn load_monitor_state(path :: String, identity :: Bytes) -> MonitorState!String do
  let db = open(path)?
  let result = load(db, identity)
  Sqlite.close(db)
  result
end

# Status requests only read an existing cache; they never initialize a monitor
# or cross a network boundary.
pub fn read_monitor_state(path :: String, identity :: Bytes) -> MonitorState!String do
  if !File.exists(path) do
    return Err("monitor_not_initialized")
  end
  let db = Sqlite.open(path)?
  let result = existing(db, identity)
  Sqlite.close(db)
  result
end

fn save(db :: SqliteConn,
  identity :: Bytes,
  expected :: U64,
  value :: MonitorState) -> Result<(), String> do
  let old = load(db, identity)?
  if U64.compare(expected, old.revision) != 0 do
    return Err("monitor_state_changed")
  end
  if U64.compare(value.context_slot, old.context_slot) < 0 do
    return Err("monitor_context_regressed")
  end
  if String.length(value.report) > 16384
    || String.length(value.registry) > 524288
    || Bytes.length(value.proof) > 8192
    || Bytes.length(value.proof_context) > 19433
    || value.probe_index < 0
    || value.probe_index > 4294967295 do
    return Err("invalid_monitor_state")
  end
  if (Bytes.length(value.entry) == 0 && value.ring_index != -1)
    || (Bytes.length(value.entry) > 0 && (value.ring_index < 0 || value.ring_index >= 4096)) do
    return Err("invalid_monitor_cursor")
  end
  if (Bytes.length(value.pending_entry) == 0 && value.pending_index != -1)
    || (Bytes.length(value.pending_entry) > 0
      && (value.pending_index < 0 || value.pending_index >= 4096)) do
    return Err("invalid_monitor_cursor")
  end
  if Bytes.length(value.pending_entry) > 0 do
    decode_anchor_entry(value.pending_entry)?
  end
  if Bytes.length(old.pending_entry) > 0 do
    let retained = if Bytes.length(value.pending_entry) > 0 do
      value.pending_entry
    else
      value.entry
    end
    let index = if Bytes.length(value.pending_entry) > 0 do
      value.pending_index
    else
      value.ring_index
    end
    if Bytes.length(retained) == 0 || index != old.pending_index do
      return Err("monitor_pending_comparison_lost")
    end
    case monitor_successors([decode_anchor_entry(retained)?],
      Some(decode_anchor_entry(old.pending_entry)?)) do
      Err(_) -> return Err("monitor_pending_comparison_lost")
      Ok(_) -> nil
    end
  end
  Json.parse(value.report)?
  if String.length(value.registry) > 0 do
    Json.parse(value.registry)?
  end
  if Bytes.length(value.entry) > 0 do
    let entry = decode_anchor_entry(value.entry)?
    let checkpoint = decode_checkpoint(value.checkpoint)?
    if !Bytes.secure_equals(checkpoint_hash(checkpoint)?, entry.checkpoint_hash)
      || checkpoint.version != entry.log_version
      || U64.compare(checkpoint.sequence, entry.sequence) != 0
      || U64.compare(checkpoint.tree_size, entry.tree_size) != 0
      || !Bytes.secure_equals(checkpoint.tree_root, entry.tree_root)
      || U64.compare(checkpoint.timestamp, entry.timestamp) != 0 do
      return Err("monitor_checkpoint_mismatch")
    end
    Sqlite.execute_values(db,
      "INSERT OR IGNORE INTO monitor_history VALUES (?, ?, ?, ?)",
      [
        Text(Bytes.to_hex(entry.checkpoint_hash)),
        Text(U64.to_string(entry.slot)),
        Binary(value.entry),
        Binary(encode_checkpoint(checkpoint)?)
      ])?
    Sqlite.execute_values(db,
      "INSERT OR IGNORE INTO monitor_attendance (checkpoint_hash, posted_slot, ring_index, entry) VALUES (?, ?, ?, ?)",
      [
        Text(Bytes.to_hex(entry.checkpoint_hash)),
        Text(U64.to_string(entry.slot)),
        Text(Int.to_string(value.ring_index)),
        Binary(value.entry)
      ])?
    nil
  else if Bytes.length(value.checkpoint) > 0 || Bytes.length(old.entry) > 0 do
    return Err("monitor_cursor_reset")
  end
  let proof = if Bytes.length(old.proof) > 0 do
    old.proof
  else if Bytes.length(value.proof) > 0 do
    encode_fork(decode_fork(value.proof)?)?
  else
    Bytes.empty()
  end
  let proof_context = if Bytes.length(old.proof) > 0 do
    old.proof_context
  else
    value.proof_context
  end
  if Bytes.length(proof_context) > 0 do
    let context = decode_anchor_context(proof_context)?
    if !Bytes.secure_equals(context.identity, identity)
      || !Bytes.secure_equals(context.fork, proof) do
      return Err("monitor_evidence_context_mismatch")
    end
  end
  Sqlite.execute_values(db,
    "UPDATE monitor_state SET revision = ?, context_slot = ?, ring_index = ?, entry = ?, checkpoint = ?, registry = ?, report = ?, proof = ?, pending_index = ?, pending_entry = ?, proof_context = ?, probe_index = ? WHERE singleton = 1",
    [
      Text(U64.to_string(U64.add(old.revision, U64.parse("1")?)?)),
      Text(U64.to_string(value.context_slot)),
      Text(Int.to_string(value.ring_index)),
      Binary(value.entry),
      Binary(value.checkpoint),
      Text(value.registry),
      Text(value.report),
      Binary(proof),
      Text(Int.to_string(value.pending_index)),
      Binary(value.pending_entry),
      Binary(proof_context),
      Text(Int.to_string(value.probe_index))
    ])?
  Ok(nil)
end

fn pending(db :: SqliteConn, identity :: Bytes) -> List<MonitorAttendance>!String do
  existing(db, identity)?
  let rows = Sqlite.query_values(db,
    "SELECT ring_index, entry FROM monitor_attendance WHERE phase = 'pending' ORDER BY rowid LIMIT 32",
    [])?
  Ok(for row in rows do
    MonitorAttendance {
      ring_index: number(text(Map.get(row, "ring_index"))?)?,
      entry: binary(Map.get(row, "entry"))?
    }
  end)
end

fn number(value :: String) -> Int!String do
  case String.to_int(value) do
    None -> Err("invalid_monitor_state")
    Some(value) -> Ok(value)
  end
end

pub fn pending_monitor_attendance(path :: String,
  identity :: Bytes) -> List<MonitorAttendance>!String do
  let db = open(path)?
  let result = pending(db, identity)
  Sqlite.close(db)
  result
end

fn claim_attendance(db :: SqliteConn, identity :: Bytes) -> List<MonitorAttendance>!String do
  existing(db, identity)?
  # Selection and moving the batch to the back of the pending queue are one
  # atomic SQLite statement. Nothing is completed before an authenticated read.
  let rows = Sqlite.query_values(db,
    "UPDATE monitor_attendance SET attempt_order = (SELECT COALESCE(MAX(attempt_order), 0) + 1 FROM monitor_attendance WHERE phase = 'pending') WHERE rowid IN (SELECT rowid FROM monitor_attendance WHERE phase = 'pending' ORDER BY attempt_order, rowid LIMIT 32) RETURNING ring_index, entry",
    [])?
  Ok(for row in rows do
    MonitorAttendance {
      ring_index: number(text(Map.get(row, "ring_index"))?)?,
      entry: binary(Map.get(row, "entry"))?
    }
  end)
end

pub fn claim_monitor_attendance(path :: String,
  identity :: Bytes) -> List<MonitorAttendance>!String do
  let db = open(path)?
  let result = claim_attendance(db, identity)
  Sqlite.close(db)
  result
end

fn finish_attendance(db :: SqliteConn,
  identity :: Bytes,
  value :: MonitorAttendance,
  phase :: String) -> Result<(), String> do
  existing(db, identity)?
  if phase != "met" && phase != "missed" && phase != "lost" do
    return Err("invalid_monitor_attendance")
  end
  let entry = decode_anchor_entry(value.entry)?
  Sqlite.execute_values(db,
    "UPDATE monitor_attendance SET phase = ? WHERE checkpoint_hash = ? AND posted_slot = ? AND ring_index = ? AND entry = ? AND phase = 'pending'",
    [
      Text(phase),
      Text(Bytes.to_hex(entry.checkpoint_hash)),
      Text(U64.to_string(entry.slot)),
      Text(Int.to_string(value.ring_index)),
      Binary(value.entry)
    ])?
  Ok(nil)
end

pub fn finish_monitor_attendance(path :: String,
  identity :: Bytes,
  value :: MonitorAttendance,
  phase :: String) -> Result<(), String> do
  let db = open(path)?
  let result = finish_attendance(db, identity, value, phase)
  Sqlite.close(db)
  result
end

fn count_phase(db :: SqliteConn, phase :: String) -> Int!String do
  let row = List.head(Sqlite.query(db,
    "SELECT count(*) AS total FROM monitor_attendance WHERE phase = ?",
    [phase])?)
  number(Map.get(row, "total"))
end

fn counts(db :: SqliteConn, identity :: Bytes) -> MonitorAttendanceCounts!String do
  existing(db, identity)?
  Ok(MonitorAttendanceCounts {
    pending: count_phase(db, "pending")?,
    met: count_phase(db, "met")?,
    missed: count_phase(db, "missed")?,
    lost: count_phase(db, "lost")?
  })
end

pub fn monitor_attendance_counts(path :: String,
  identity :: Bytes) -> MonitorAttendanceCounts!String do
  let db = open(path)?
  let result = counts(db, identity)
  Sqlite.close(db)
  result
end

pub fn save_monitor_state(path :: String,
  identity :: Bytes,
  expected :: U64,
  value :: MonitorState) -> Result<(), String> do
  let db = open(path)?
  let result = case Sqlite.execute(db, "BEGIN IMMEDIATE", []) do
    Err(error)
    Ok(_) -> case save(db, identity, expected, value) do
      Err(error) -> do
        Sqlite.rollback(db)
        Err(error)
      end
      Ok(_) -> Sqlite.commit(db)
    end
  end
  Sqlite.close(db)
  result
end
