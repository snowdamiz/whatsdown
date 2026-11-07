from Storage.Blobs import blob_record_hash, load_blob, ensure_schema
from Storage.Records import with_record_transaction, put_blobs

fn current(database :: SqliteConn, label :: String) -> Bytes!String do
  let rows = Sqlite.query_values(database,
    "SELECT ciphertext FROM encrypted_blobs WHERE record_hash = ?",
    [Text(blob_record_hash(database, label)?)])?
  if List.length(rows) == 0 do
    return Ok(Bytes.empty())
  end
  if List.length(rows) != 1 do
    return Err("invalid_bounty_transfer_snapshot")
  end
  case Map.get(List.head(rows), "ciphertext") do
    Binary(value) -> Ok(value)
    _ -> Err("invalid_bounty_transfer_snapshot")
  end
end

fn expect(database :: SqliteConn, label :: String, previous :: Bytes) -> Result<(), String> do
  if !Bytes.secure_equals(current(database, label)?, previous) do
    Err("local_state_changed")
  else
    Ok(nil)
  end
end

pub fn bounty_transfer_row_label(claim :: String, asset :: Int) -> String!String do
  if String.length(claim) != 64 || asset < 0 || asset > 2 do
    return Err("invalid_bounty_transfer_route")
  end
  let decoded = Bytes.from_hex(claim)?
  if Bytes.to_hex(decoded) != claim do
    return Err("invalid_bounty_transfer_route")
  end
  Ok("bounty-transfer/v2/" <> claim <> "/" <> List.get(["legacy", "usdc", "morse"], asset))
end

fn history(database :: SqliteConn,
  label :: String,
  previous :: Bytes,
  next :: Bytes) -> Result<(), String> do
  if label == "" do
    if Bytes.length(previous) != 0 || Bytes.length(next) != 0 do
      return Err("invalid_bounty_transfer_snapshot")
    end
    return Ok(nil)
  end
  if Bytes.length(next) == 0 do
    return Err("invalid_bounty_transfer_snapshot")
  end
  expect(database, label, previous)?
  if Bytes.length(previous) != 0 && !Bytes.secure_equals(previous, next) do
    return Err("bounty_transfer_history_conflict")
  end
  put_blobs(database, [label], [next], 0)
end

# Legacy callers cannot overwrite a forwarding marker or append over history.
# State captures profile before preparation
# this compatibility helper captures
# it for old callers and still fences the authoritative old key and custody.
pub fn store_bounty_transfer_snapshot(path :: String,
  labels :: List<String>,
  blobs :: List<Bytes>,
  previous :: Bytes,
  selected :: Bytes) -> Result<(), String> do
  let profile = load_blob(path, "profile/v1")?
  store_bounty_transfer_legacy_snapshot(path, labels, blobs, previous, selected, profile)
end

pub fn store_bounty_transfer_legacy_snapshot(path :: String,
  labels :: List<String>,
  blobs :: List<Bytes>,
  previous :: Bytes,
  selected :: Bytes,
  profile :: Bytes) -> Result<(), String> do
  if List.length(labels) < 1
    || List.length(labels) > 2
    || List.length(labels) != List.length(blobs)
    || List.head(labels) != "bounty-transfer/v1"
    || Bytes.length(selected) == 0
    || Bytes.length(profile) == 0 do
    return Err("invalid_bounty_transfer_snapshot")
  end
  with_record_transaction(path,
    fn(database) do
      expect(database, "bounty-authority/v2", Bytes.empty())?
      expect(database, "bounty-transfer/v1", previous)?
      expect(database, "fork-bounty/v1", selected)?
      expect(database, "profile/v1", profile)?
      if List.length(labels) == 2 do
        let archived = List.get(labels, 1)
        if !String.starts_with(archived, "bounty-transfer/v1/history/") do
          return Err("invalid_bounty_transfer_snapshot")
        end
        # Existing authenticated identical history is reused by state. The old
        # API has no authenticated comparison, so only identical ciphertext wins.
        let existing = current(database, archived)?
        history(database, archived, existing, List.get(blobs, 1))?
      end
      put_blobs(database, [List.head(labels)], [List.head(blobs)], 0)
    end)
end

# Fixed bounded admission: every target is absent, even a proposed zero leg.
pub fn initialize_bounty_transfer_root(path :: String,
  claim :: String,
  root :: Bytes,
  marker :: Bytes,
  previous :: Bytes,
  custody :: Bytes,
  profile :: Bytes,
  legacy :: Bytes,
  usdc :: Bytes,
  morse :: Bytes) -> Result<(), String> do
  if Bytes.length(root) == 0
    || Bytes.length(marker) == 0
    || Bytes.length(custody) == 0
    || Bytes.length(profile) == 0 do
    return Err("invalid_bounty_transfer_snapshot")
  end
  let labels = [
    bounty_transfer_row_label(claim, 0)?,
    bounty_transfer_row_label(claim, 1)?,
    bounty_transfer_row_label(claim, 2)?
  ]
  let archive = bounty_transfer_row_label(claim, 0)? <> "/archive/v1"
  with_record_transaction(path,
    fn(database) do
      expect(database, "bounty-authority/v2", Bytes.empty())?
      expect(database, "bounty-transfer/v1", previous)?
      expect(database, "fork-bounty/v1", custody)?
      expect(database, "profile/v1", profile)?
      for target in labels do
        expect(database, target, Bytes.empty())?
      end
      expect(database, archive, Bytes.empty())?
      # All predicates precede all writes. Any write/commit failure rolls back.
      put_blobs(database, ["bounty-authority/v2", "bounty-transfer/v1"], [root, marker], 0)?
      let values = [legacy, usdc, morse]
      for index in 0..3 do
        if Bytes.length(List.get(values, index)) > 0 do
          put_blobs(database, [List.get(labels, index)], [List.get(values, index)], 0)?
        end
      end
      if Bytes.length(previous) > 0 do
        put_blobs(database, [archive], [previous], 0)?
      end
      Ok(nil)
    end)
end

pub fn store_bounty_transfer_route_snapshot(path :: String,
  claim :: String,
  asset :: Int,
  root :: Bytes,
  marker :: Bytes,
  previous :: Bytes,
  custody :: Bytes,
  profile :: Bytes,
  next :: Bytes,
  history_label :: String,
  history_previous :: Bytes,
  history_next :: Bytes) -> Result<(), String> do
  if Bytes.length(root) == 0
    || Bytes.length(marker) == 0
    || Bytes.length(previous) == 0
    || Bytes.length(custody) == 0
    || Bytes.length(profile) == 0
    || Bytes.length(next) == 0 do
    return Err("invalid_bounty_transfer_snapshot")
  end
  let target = bounty_transfer_row_label(claim, asset)?
  if history_label != "" && !String.starts_with(history_label, target <> "/history/") do
    return Err("invalid_bounty_transfer_snapshot")
  end
  with_record_transaction(path,
    fn(database) do
      expect(database, "bounty-authority/v2", root)?
      expect(database, "bounty-transfer/v1", marker)?
      expect(database, "fork-bounty/v1", custody)?
      expect(database, "profile/v1", profile)?
      expect(database, target, previous)?
      history(database, history_label, history_previous, history_next)?
      put_blobs(database, [target], [next], 0)
    end)
end

fn read_rows(database :: SqliteConn, claim :: String) -> List<Bytes>!String do
  let shared = [
    current(database, "bounty-authority/v2")?,
    current(database, "bounty-transfer/v1")?,
    current(database, "fork-bounty/v1")?,
    current(database, "profile/v1")?
  ]
  if claim == "" do
    return Ok(shared ++ [Bytes.empty(), Bytes.empty(), Bytes.empty()])
  end
  Ok(shared
    ++ [
      current(database, bounty_transfer_row_label(claim, 0)?)?,
      current(database, bounty_transfer_row_label(claim, 1)?)?,
      current(database, bounty_transfer_row_label(claim, 2)?)?
    ])
end

# One SQLite read transaction observes the entire aggregate. A preliminary root
# lookup only selects the bounded labels
# state checks it against this snapshot.
pub fn read_bounty_transfer_rows(path :: String, claim :: String) -> List<Bytes>!String do
  ensure_schema(path)?
  let database = Sqlite.open(path)?
  let result = case Sqlite.execute(database, "BEGIN", []) do
    Err(error)
    Ok(_) -> case read_rows(database, claim) do
      Err(error)
      Ok(rows) -> case Sqlite.commit(database) do
        Err(error)
        Ok(_) -> Ok(rows)
      end
    end
  end
  case result do
    Err(_) -> do
      Sqlite.rollback(database)
      nil
    end
    Ok(_) -> nil
  end
  Sqlite.close(database)
  result
end
