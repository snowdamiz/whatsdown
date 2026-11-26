##! The monitor's state: one SQLite file. Every step commits in a transaction,
##! so a crash leaves the state as it was after the last whole step (SQLite's
##! rollback journal with synchronous=FULL). The release Mesh compiler has no
##! File.rename or File.sync, so a plain state file could not be replaced
##! atomically; SQLite is the atomic primitive it does have.

pub struct Finding do
  key :: String
  found_at :: Int
  severity :: String
  kind :: String
  detail :: String
  evidence :: String
  frk :: Bytes
  proof_hash :: String
end

pub struct Filing do
  proof_hash :: String
  relay :: String
  status :: Int
  attempts :: Int
end

pub struct StoredEntry do
  position :: Int
  entry :: Bytes
  ring_index :: Int
  bitmap_known :: Bool
  cosign :: String
end

fn schema() -> List<String> do
  [
    "PRAGMA synchronous = FULL",
    "PRAGMA busy_timeout = 5000",
    "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS entries (position INTEGER PRIMARY KEY AUTOINCREMENT, ring_index INTEGER NOT NULL, entry BLOB NOT NULL, bitmap_known INTEGER NOT NULL, pair TEXT NOT NULL, cosign TEXT NOT NULL, epoch INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS findings (key TEXT PRIMARY KEY, found_at INTEGER NOT NULL, severity TEXT NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL, evidence TEXT NOT NULL, frk BLOB NOT NULL, proof_hash TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS filings (proof_hash TEXT NOT NULL, relay TEXT NOT NULL, status INTEGER NOT NULL, attempts INTEGER NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (proof_hash, relay))",
    "CREATE TABLE IF NOT EXISTS observed (hash TEXT PRIMARY KEY, sequence INTEGER NOT NULL, checkpoint BLOB NOT NULL, attestations BLOB NOT NULL, seen_at INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS leaf_chunks (chunk INTEGER PRIMARY KEY, hashes BLOB NOT NULL)"
  ]
end

fn run_all(db :: SqliteConn, statements :: List<String>) -> Result<(), String> do
  case statements do
    [] -> Ok(nil)
    statement :: rest -> do
      Sqlite.execute(db, statement, [])?
      run_all(db, rest)
    end
  end
end

pub fn monitor_store_open(path :: String) -> SqliteConn!String do
  let db = Sqlite.open(path)?
  case run_all(db, schema()) do
    Ok(_) -> Ok(db)
    Err(error) -> do
      Sqlite.close(db)
      Err(error)
    end
  end
end

# Runs work atomically: all of it lands, or none of it. Savepoints nest, so a
# batch of steps can commit together (the outermost one is the transaction).

pub fn monitor_store_atomic<T>(db :: SqliteConn, work :: Fun() -> T!String) -> T!String do
  Sqlite.execute(db, "SAVEPOINT monitor_step", [])?
  case work() do
    Ok(value) -> do
      Sqlite.execute(db, "RELEASE monitor_step", [])?
      Ok(value)
    end
    Err(error) -> do
      Sqlite.execute(db, "ROLLBACK TO monitor_step", [])
      Sqlite.execute(db, "RELEASE monitor_step", [])
      Err(error)
    end
  end
end

fn text(row :: Map<String, DbValue>, key :: String) -> String do
  case Map.get(row, key) do
    Text(value) -> value
    Binary(_) -> ""
    Null -> ""
  end
end

fn integer(row :: Map<String, DbValue>, key :: String) -> Int do
  case String.to_int(text(row, key)) do
    None -> 0
    Some(value) -> value
  end
end

fn binary(row :: Map<String, DbValue>, key :: String) -> Bytes do
  case Map.get(row, key) do
    Binary(value) -> value
    Text(_) -> Bytes.empty()
    Null -> Bytes.empty()
  end
end

pub fn monitor_kv_get(db :: SqliteConn, key :: String) -> String!String do
  let rows = Sqlite.query_values(db, "SELECT value FROM kv WHERE key = ?", [Text(key)])?
  case rows do
    [row] -> Ok(text(row, "value"))
    _ -> Ok("")
  end
end

pub fn monitor_kv_int(db :: SqliteConn, key :: String) -> Int!String do
  case String.to_int(monitor_kv_get(db, key)?) do
    None -> Ok(0)
    Some(value) -> Ok(value)
  end
end

pub fn monitor_kv_put(db :: SqliteConn, key :: String, value :: String) -> Result<(), String> do
  Sqlite.execute_values(db,
    "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    [Text(key), Text(value)])?
  Ok(nil)
end

pub fn monitor_entry_add(db :: SqliteConn,
  ring_index :: Int,
  entry :: Bytes,
  bitmap_known :: Bool,
  epoch :: Int) -> Result<(), String> do
  Sqlite.execute_values(db,
    "INSERT INTO entries (ring_index, entry, bitmap_known, pair, cosign, epoch) VALUES (?, ?, ?, 'pending', 'open', ?)",
    [
      Text(Int.to_string(ring_index)),
      Binary(entry),
      Text(if bitmap_known do
        "1"
      else
        "0"
      end),
      Text(Int.to_string(epoch))
    ])?
  Ok(nil)
end

fn stored_entry(row :: Map<String, DbValue>) -> StoredEntry do
  StoredEntry {
    position: integer(row, "position"),
    entry: binary(row, "entry"),
    ring_index: integer(row, "ring_index"),
    bitmap_known: integer(row, "bitmap_known") == 1,
    cosign: text(row, "cosign")
  }
end

fn entries_where(db :: SqliteConn, condition :: String, limit :: Int) -> List<StoredEntry>!String do
  let rows = Sqlite.query_values(db,
    "SELECT position, ring_index, entry, bitmap_known, cosign FROM entries WHERE #{condition} ORDER BY position LIMIT ?",
    [Text(Int.to_string(limit))])?
  Ok(List.map(rows, stored_entry))
end

pub fn monitor_entries_pending(db :: SqliteConn, limit :: Int) -> List<StoredEntry>!String do
  entries_where(db, "pair = 'pending'", limit)
end

pub fn monitor_entries_open(db :: SqliteConn, limit :: Int) -> List<StoredEntry>!String do
  entries_where(db, "cosign = 'open'", limit)
end

pub fn monitor_entries_counted(db :: SqliteConn, epoch :: Int) -> List<StoredEntry>!String do
  let rows = Sqlite.query_values(db,
    "SELECT position, ring_index, entry, bitmap_known, cosign FROM entries WHERE epoch = ? AND cosign IN ('met', 'below') ORDER BY position",
    [Text(Int.to_string(epoch))])?
  Ok(List.map(rows, stored_entry))
end

pub fn monitor_entries_count(db :: SqliteConn, condition :: String) -> Int!String do
  let rows = Sqlite.query_values(db, "SELECT count(*) AS n FROM entries WHERE #{condition}", [])?
  case rows do
    [row] -> Ok(integer(row, "n"))
    _ -> Ok(0)
  end
end

pub fn monitor_entry_pair(db :: SqliteConn,
  position :: Int,
  state :: String) -> Result<(), String> do
  Sqlite.execute_values(db,
    "UPDATE entries SET pair = ? WHERE position = ?",
    [Text(state), Text(Int.to_string(position))])?
  Ok(nil)
end

pub fn monitor_entry_cosign(db :: SqliteConn,
  position :: Int,
  entry :: Bytes,
  state :: String) -> Result<(), String> do
  Sqlite.execute_values(db,
    "UPDATE entries SET cosign = ?, entry = ?, bitmap_known = 1 WHERE position = ?",
    [Text(state), Binary(entry), Text(Int.to_string(position))])?
  Ok(nil)
end

# Keeps two epochs of finished entries for the attendance counts.

pub fn monitor_entries_prune(db :: SqliteConn, epoch :: Int) -> Result<(), String> do
  Sqlite.execute_values(db,
    "DELETE FROM entries WHERE pair <> 'pending' AND cosign <> 'open' AND epoch < ?",
    [Text(Int.to_string(epoch - 1))])?
  Ok(nil)
end

# Records a finding once per key. Returns true when it is new.

pub fn monitor_finding_add(db :: SqliteConn, value :: Finding) -> Bool!String do
  let changed = Sqlite.execute_values(db,
    "INSERT OR IGNORE INTO findings (key, found_at, severity, kind, detail, evidence, frk, proof_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [
      Text(value.key),
      Text(Int.to_string(value.found_at)),
      Text(value.severity),
      Text(value.kind),
      Text(value.detail),
      Text(value.evidence),
      Binary(value.frk),
      Text(value.proof_hash)
    ])?
  Ok(changed > 0)
end

fn finding(row :: Map<String, DbValue>) -> Finding do
  Finding {
    key: text(row, "key"),
    found_at: integer(row, "found_at"),
    severity: text(row, "severity"),
    kind: text(row, "kind"),
    detail: text(row, "detail"),
    evidence: text(row, "evidence"),
    frk: binary(row, "frk"),
    proof_hash: text(row, "proof_hash")
  }
end

pub fn monitor_findings(db :: SqliteConn) -> List<Finding>!String do
  let rows = Sqlite.query_values(db,
    "SELECT key, found_at, severity, kind, detail, evidence, frk, proof_hash FROM findings ORDER BY found_at DESC, key LIMIT 200",
    [])?
  Ok(List.map(rows, finding))
end

pub fn monitor_findings_with_proof(db :: SqliteConn) -> List<Finding>!String do
  let rows = Sqlite.query_values(db,
    "SELECT key, found_at, severity, kind, detail, evidence, frk, proof_hash FROM findings WHERE length(frk) > 0 ORDER BY found_at",
    [])?
  Ok(List.map(rows, finding))
end

pub fn monitor_filings(db :: SqliteConn, proof_hash :: String) -> List<Filing>!String do
  let rows = Sqlite.query_values(db,
    "SELECT proof_hash, relay, status, attempts FROM filings WHERE proof_hash = ? ORDER BY relay",
    [Text(proof_hash)])?
  Ok(List.map(rows,
    fn row -> Filing {
      proof_hash: text(row, "proof_hash"),
      relay: text(row, "relay"),
      status: integer(row, "status"),
      attempts: integer(row, "attempts")
    } end))
end

pub fn monitor_filing_put(db :: SqliteConn, value :: Filing, now_ms :: Int) -> Result<(), String> do
  Sqlite.execute_values(db,
    "INSERT INTO filings (proof_hash, relay, status, attempts, at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (proof_hash, relay) DO UPDATE SET status = excluded.status, attempts = excluded.attempts, at = excluded.at",
    [
      Text(value.proof_hash),
      Text(value.relay),
      Text(Int.to_string(value.status)),
      Text(Int.to_string(value.attempts)),
      Text(Int.to_string(now_ms))
    ])?
  Ok(nil)
end

# A checkpoint the directory served, with the Morse attestations it held
# for it (KTW v1 bytes).

pub fn monitor_observed_put(db :: SqliteConn,
  hash :: Bytes,
  sequence :: Int,
  checkpoint :: Bytes,
  attestations :: Bytes,
  now_ms :: Int) -> Result<(), String> do
  Sqlite.execute_values(db,
    "INSERT INTO observed (hash, sequence, checkpoint, attestations, seen_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (hash) DO UPDATE SET attestations = excluded.attestations, seen_at = excluded.seen_at",
    [
      Text(Bytes.to_hex(hash)),
      Text(Int.to_string(sequence)),
      Binary(checkpoint),
      Binary(attestations),
      Text(Int.to_string(now_ms))
    ])?
  Ok(nil)
end

# (checkpoint bytes, attestation bytes) for a checkpoint hash.

pub fn monitor_observed_get(db :: SqliteConn, hash :: Bytes) -> Option<(Bytes, Bytes)>!String do
  let rows = Sqlite.query_values(db,
    "SELECT checkpoint, attestations FROM observed WHERE hash = ?",
    [Text(Bytes.to_hex(hash))])?
  case rows do
    [row] -> Ok(Some((binary(row, "checkpoint"), binary(row, "attestations"))))
    _ -> Ok(None)
  end
end

# Fork proofs must be filed within 28 days of the older checkpoint.

pub fn monitor_observed_prune(db :: SqliteConn, now_ms :: Int) -> Result<(), String> do
  Sqlite.execute_values(db,
    "DELETE FROM observed WHERE seen_at < ?",
    [Text(Int.to_string(now_ms - 2_419_200_000))])?
  Ok(nil)
end

pub fn monitor_chunk_get(db :: SqliteConn, chunk :: Int) -> Bytes!String do
  let rows = Sqlite.query_values(db,
    "SELECT hashes FROM leaf_chunks WHERE chunk = ?",
    [Text(Int.to_string(chunk))])?
  case rows do
    [row] -> Ok(binary(row, "hashes"))
    _ -> Ok(Bytes.empty())
  end
end

pub fn monitor_chunk_put(db :: SqliteConn, chunk :: Int, hashes :: Bytes) -> Result<(), String> do
  Sqlite.execute_values(db,
    "INSERT INTO leaf_chunks (chunk, hashes) VALUES (?, ?) ON CONFLICT (chunk) DO UPDATE SET hashes = excluded.hashes",
    [Text(Int.to_string(chunk)), Binary(hashes)])?
  Ok(nil)
end

pub fn monitor_chunks_clear(db :: SqliteConn) -> Result<(), String> do
  Sqlite.execute(db, "DELETE FROM leaf_chunks", [])?
  Ok(nil)
end
