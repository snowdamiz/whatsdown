##! Sealed per-message availability and durable local consumption.
from Storage.FanoutCommit import FanoutSnapshot
from Storage.AccountGuard import require_account_basis_bounded_with_key
from Storage.Blobs import put_blob_with_key, blob_record_hash_with_key
from Binary.Reader import BinaryReader
from Mobile.Codec import (
  mobile_join,
  mobile_byte,
  mobile_vector,
  mobile_write_u16,
  mobile_write_u64,
  mobile_reader,
  take_fixed,
  take_vector_error,
  mobile_finish,
  mobile_read_byte,
  mobile_read_u64,
  current_time
)

pub struct ViewOnceAvailable do
  reference :: Bytes
  chunk_hashes :: List<Bytes>
  message_expiry :: Option<U64>
end

pub type ViewOnceRecord do
  Available(value :: ViewOnceAvailable)
  Consumed(binding_digest :: Bytes)
end

pub type ViewOnceConsumeAction do
  Refuse
  Consume
end

## Only this closed decision is observed; no caller-selected reason or payload.
pub fn observe_view_once_consume(action :: Plaintext<ViewOnceConsumeAction>) -> ViewOnceConsumeAction do
  let allowed = case action do
    Refuse -> false
    Consume -> true
  end
  declassify(if allowed do
      Consume
    else
      Refuse
    end,
    "User explicitly opens this selected per-device view-once image; disclose only whether its authenticated current available state may be durably consumed. Image bytes, metadata, key envelopes and detailed errors remain protected.")
end

pub fn view_once_time_action(expires_at :: Plaintext<U64>,
  message_expiry :: Plaintext<Option<U64>>,
  previous :: U64,
  now :: U64) -> Plaintext<ViewOnceConsumeAction> do
  let live = U64.compare(now, previous) >= 0
    && U64.compare(now, expires_at) < 0
    && case message_expiry do
      None -> true
      Some(expiry) -> U64.compare(now, expiry) < 0
    end
  if live do
    Consume
  else
    Refuse
  end
end

fn header(kind :: String) -> Bytes!String do
  mobile_join([mobile_byte(1)?, Bytes.from_utf8(kind)], 0, Bytes.empty())
end

pub fn encode_view_once_record(value :: ViewOnceRecord) -> Bytes!String do
  case value do
    Consumed(digest) -> if Bytes.length(digest) != 32 do
      Err("view_once_storage_refused")
    else
      mobile_join([header("VOC")?, digest], 0, Bytes.empty())
    end
    Available(available) -> do
      let count = List.length(available.chunk_hashes)
      if Bytes.length(available.reference) == 0
        || Bytes.length(available.reference) > 1024
        || count < 1
        || count > 256
        || List.any(available.chunk_hashes, fn(digest) -> Bytes.length(digest) != 32 end) do
        return Err("view_once_storage_refused")
      end
      let expiry = case available.message_expiry do
        None -> mobile_join([mobile_byte(0)?, mobile_write_u64(U64.parse("0")?)?], 0, Bytes.empty())
        Some(time) -> mobile_join([mobile_byte(1)?, mobile_write_u64(time)?], 0, Bytes.empty())
      end?
      mobile_join([header("VOA")?, mobile_vector(available.reference)?, mobile_write_u16(count)?]
          ++ available.chunk_hashes
          ++ [expiry],
        0,
        Bytes.empty())
    end
  end
end

struct ViewOnceReadHashes do
  state :: BinaryReader
  hashes :: List<Bytes>
end

fn read_hashes(state :: BinaryReader,
  remaining :: Int,
  output :: List<Bytes>) -> ViewOnceReadHashes!String do
  if remaining == 0 do
    Ok(ViewOnceReadHashes { state: state, hashes: List.reverse(output) })
  else
    let digest = take_fixed(state, 32)?
    read_hashes(digest.state, remaining - 1, [digest.value] ++ output)
  end
end

pub fn decode_view_once_record(wire :: Bytes) -> ViewOnceRecord!String do
  let magic = take_fixed(mobile_reader(wire, 9235, "view_once_storage_refused")?, 4)?
  if Bytes.secure_equals(magic.value, header("VOC")?) do
    let digest = take_fixed(magic.state, 32)?
    mobile_finish(digest.state, "view_once_storage_refused")?
    return Ok(Consumed(digest.value))
  end
  if !Bytes.secure_equals(magic.value, header("VOA")?) do
    return Err("view_once_storage_refused")
  end
  let reference = take_vector_error(magic.state, 1024, "view_once_storage_refused")?
  let count_bytes = take_fixed(reference.state, 2)?
  let count = case Bytes.read_u16_be(count_bytes.value, 0) do
    Err(_) -> return Err("view_once_storage_refused")
    Ok(value) -> value
  end
  if Bytes.length(reference.value) == 0 || count < 1 || count > 256 do
    return Err("view_once_storage_refused")
  end
  let hashes = read_hashes(count_bytes.state, count, [])?
  let flag_bytes = take_fixed(hashes.state, 1)?
  let flag = mobile_read_byte(flag_bytes.value)?
  let time = take_fixed(flag_bytes.state, 8)?
  let expiry = mobile_read_u64(time.value)?
  mobile_finish(time.state, "view_once_storage_refused")?
  let message_expiry = if flag == 0 && U64.to_string(expiry) == "0" do
    None
  else if flag == 1 do
    Some(expiry)
  else
    return Err("view_once_storage_refused")
  end
  Ok(Available(ViewOnceAvailable {
    reference: reference.value,
    chunk_hashes: hashes.hashes,
    message_expiry: message_expiry
  }))
end

fn require_sources(database :: SqliteConn,
  key :: borrow StorageKey,
  before :: FanoutSnapshot) -> Unit!String do
  if List.length(before.bases) == 0 || List.length(before.bases) > 8 do
    return Err("view_once_storage_refused")
  end
  let profile = List.head(before.bases).profile
  for basis in before.bases do
    if !Bytes.secure_equals(profile, basis.profile) do
      return Err("view_once_storage_refused")
    end
    require_account_basis_bounded_with_key(database, key, basis, 65536, 66000, 4289536)?
  end
  Ok(nil)
end

fn delete_cached(database :: SqliteConn,
  key :: borrow StorageKey,
  labels :: List<String>,
  index :: Int) -> Unit!String do
  if index >= List.length(labels) do
    Ok(nil)
  else
    let hash = blob_record_hash_with_key(database, key, List.get(labels, index))?
    Sqlite.execute_values(database,
      "DELETE FROM encrypted_blobs WHERE record_hash = ?",
      [Text(hash)])?
    delete_cached(database, key, labels, index + 1)
  end
end

fn write_consumed_on(database :: SqliteConn,
  key :: borrow StorageKey,
  before :: FanoutSnapshot,
  row_label :: String,
  consumed_blob :: Bytes,
  cache_labels :: List<String>,
  expires_at :: Plaintext<U64>,
  message_expiry :: Plaintext<Option<U64>>,
  observed_at :: U64) -> Unit!String do
  require_sources(database, key, before)?
  let prewrite = current_time()?
  case observe_view_once_consume(view_once_time_action(expires_at,
    message_expiry,
    observed_at,
    prewrite)) do
    Refuse -> Err("view_once_unavailable")
    Consume -> do
      put_blob_with_key(database, key, row_label, consumed_blob)?
      delete_cached(database, key, cache_labels, 0)?
      let final_time = current_time()?
      case observe_view_once_consume(view_once_time_action(expires_at,
        message_expiry,
        prewrite,
        final_time)) do
        Refuse -> Err("view_once_unavailable")
        Consume -> Ok(nil)
      end
    end
  end
end

pub fn commit_view_once_consumed(path :: String,
  key :: borrow StorageKey,
  before :: FanoutSnapshot,
  row_label :: String,
  consumed_blob :: Bytes,
  cache_labels :: List<String>,
  expires_at :: Plaintext<U64>,
  message_expiry :: Plaintext<Option<U64>>,
  observed_at :: U64) -> Unit!String do
  let captured_labels = List.flatten(for basis in before.bases do
    basis.labels
  end)
  if String.length(row_label) == 0
    || Bytes.length(consumed_blob) == 0
    || !List.contains(captured_labels, row_label)
    || List.length(cache_labels) != 256
    || List.any(cache_labels,
      fn(label) -> label == row_label || !List.contains(captured_labels, label) end) do
    return Err("view_once_storage_refused")
  end
  let database = case Sqlite.open(path) do
    Err(_) -> return Err("database_open_failed")
    Ok(value) -> value
  end
  # Same transaction/rollback contract as Storage.Records, with a direct borrow.
  let started = case Sqlite.execute(database, "PRAGMA busy_timeout = 1000", []) do
    Err(error)
    Ok(_) -> Sqlite.execute(database, "BEGIN IMMEDIATE", [])
  end
  let written = case started do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> write_consumed_on(database,
      key,
      before,
      row_label,
      consumed_blob,
      cache_labels,
      expires_at,
      message_expiry,
      observed_at)
  end
  let result = case written do
    Err(error)
    Ok(_) -> case Sqlite.commit(database) do
      Err(_) -> Err("database_write_failed")
      Ok(_) -> Ok(nil)
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
