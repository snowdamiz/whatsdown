from Mobile.CreditAttachmentJournal import seal_attachment_binding, attachment_journal_payload
from Mobile.CreditState import (
  CreditWallet,
  empty_credit_wallet,
  encode_credit_wallet,
  decode_credit_wallet,
  credit_record_id,
  credit_wallet_physical_limit,
  credit_wallet_chunk_limit,
  valid_credit_attachment_metadata,
  credit_attachment_cursor,
  pack_credit_parts,
  unpack_credit_parts
)
from Mobile.Codec import (
  mobile_join,
  mobile_reader,
  mobile_finish,
  mobile_read_byte,
  mobile_byte,
  mobile_vector,
  take_fixed,
  take_vector,
  mobile_write_u16,
  mobile_write_u32,
  mobile_write_u64,
  mobile_read_u32,
  mobile_read_u64,
  random_bytes
)
from Storage.Blobs import blob_record_hash, ensure_schema, insert_blob, put_blob
from Storage.Keys import context, open_local, seal_local
from Storage.Records import delete_blob

pub struct CreditWalletIdentity do
  account_id :: Bytes
  device_id :: Bytes
  service_key :: Bytes
  purpose :: Int
end

pub struct CreditWalletSnapshot do
  wallet :: CreditWallet
  previous :: Bytes
  generation :: Bytes
  chunk_count :: Int
end

# Internal bounded CAS updates keep the shared transparency cursor and local
# signup profile/intent in the same transaction as the credit wallet. Dynamic
# device-set guards are restricted to this wallet's own authenticated account.
pub struct CreditCacheWrite do
  label :: String
  previous :: Bytes
  value :: Bytes
end

fn check_identity(who :: CreditWalletIdentity) -> Result<(), String> do
  if !credit_record_id(who.account_id)
    || !credit_record_id(who.service_key)
    || Bytes.length(who.device_id) != 16
    || Bytes.to_hex(who.device_id) == String.repeat("00", 16)
    || (who.purpose != 0 && who.purpose != 1) do
    Err("invalid_credit_storage_identity")
  else
    Ok(nil)
  end
end

pub fn credit_wallet_label(who :: CreditWalletIdentity) -> String do
  "credits-wallet/v1/#{Bytes.to_hex(who.service_key)}/#{who.purpose}"
end

pub fn credit_context(who :: CreditWalletIdentity, label :: String) -> Bytes!String do
  check_identity(who)?
  context(who.account_id, who.device_id, credit_wallet_label(who) <> "/" <> label, 14)
end

pub fn credit_attachment_intent_context(who :: CreditWalletIdentity,
  nonce :: Bytes) -> Bytes!String do
  if !credit_record_id(nonce) do
    return Err("invalid_credit_attachment_identity")
  end
  credit_context(who, "attachment-intent/v2/#{Bytes.to_hex(nonce)}")
end

fn chunk_label(who :: CreditWalletIdentity, generation :: Bytes, index :: Int) -> String do
  credit_wallet_label(who) <> "/#{Bytes.to_hex(generation)}/#{index}"
end

fn blob(database :: SqliteConn, label :: String) -> Bytes!String do
  let rows = case Sqlite.query_values(database,
    "SELECT ciphertext FROM encrypted_blobs WHERE record_hash = ?",
    [Text(blob_record_hash(database, label)?)]) do
    Err(_) -> return Err("credit_database_read_failed")
    Ok(value) -> value
  end
  if List.length(rows) == 0 do
    Ok(Bytes.empty())
  else if List.length(rows) != 1 do
    Err("invalid_credit_wallet_storage")
  else
    case Map.get(List.head(rows), "ciphertext") do
      Binary(value) -> if Bytes.length(value) < 1 || Bytes.length(value) > 66000 do
        Err("invalid_credit_wallet_storage")
      else
        Ok(value)
      end
      Text(_) -> Err("invalid_credit_wallet_storage")
      Null -> Err("invalid_credit_wallet_storage")
    end
  end
end

# Authenticate and validate chunks in index order before allocating the one
# joined wallet buffer. The manifest's exact size is the output bound.
fn read_chunks(database :: SqliteConn,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  generation :: Bytes,
  count :: Int,
  size :: Int) -> Bytes!String do
  let chunks = for index in 0..count do
    let label = chunk_label(who, generation, index)
    let bytes = open_local(blob(database, label)?, wrapping, credit_context(who, label)?)?
    let expected = if index + 1 < count do
      60000
    else
      size - index * 60000
    end
    if Bytes.length(bytes) != expected do
      return Err("invalid_credit_wallet_chunk")
    end
    bytes
  end
  case Bytes.concat_many(chunks, size) do
    Ok(value)
    Err(_) -> Err("byte length overflow")
  end
end

struct WalletManifest do
  revision :: U64
  generation :: Bytes
  size :: Int
  count :: Int
end

fn read_wallet_manifest(manifest :: Bytes) -> WalletManifest!String do
  if Bytes.length(manifest) != 82 || Bytes.to_hex(Bytes.slice(manifest, 0, 4)?) != "0143574d" do
    return Err("invalid_credit_wallet_manifest")
  end
  let revision = mobile_read_u64(Bytes.slice(manifest, 4, 8)?)?
  let generation = Bytes.slice(manifest, 12, 32)?
  let size = mobile_read_u32(Bytes.slice(manifest, 44, 4)?)?
  let count = case Bytes.read_u16_be(manifest, 48) do
    Err(_) -> return Err("invalid_credit_wallet_manifest")
    Ok(value) -> value
  end
  if !credit_record_id(generation)
    || size < 16
    || size > credit_wallet_physical_limit()
    || count != (size + 59999) / 60000
    || count < 1
    || count > credit_wallet_chunk_limit() do
    return Err("invalid_credit_wallet_manifest")
  end
  Ok(WalletManifest { revision: revision, generation: generation, size: size, count: count })
end

fn read_wallet(database :: SqliteConn,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> CreditWalletSnapshot!String do
  let previous = blob(database, credit_wallet_label(who))?
  if Bytes.length(previous) == 0 do
    return Ok(CreditWalletSnapshot {
      wallet: empty_credit_wallet()?,
      previous: previous,
      generation: Bytes.empty(),
      chunk_count: 0
    })
  end
  let manifest = open_local(previous, wrapping, credit_context(who, "manifest")?)?
  let framing = read_wallet_manifest(manifest)?
  let revision = framing.revision
  let generation = framing.generation
  let size = framing.size
  let count = framing.count
  let bytes = read_chunks(database, wrapping, who, generation, count, size)?
  if !Bytes.secure_equals(Crypto.sha256(bytes), Bytes.slice(manifest, 50, 32)?) do
    return Err("invalid_credit_wallet_digest")
  end
  # Every original chunk and the complete wallet digest authenticate before any
  # legacy binding is decoded or a migration write is staged.
  if Bytes.length(bytes) < 16
    || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "01435753"
    || mobile_read_u64(Bytes.slice(bytes, 4, 8)?)? != revision do
    return Err("invalid_credit_wallet_revision")
  end
  let normalized = normalize_attachment_wallet(bytes, wrapping, who)?
  let wallet = decode_credit_wallet(normalized)?
  if Bytes.secure_equals(normalized, bytes) do
    Ok(CreditWalletSnapshot {
      wallet: wallet,
      previous: previous,
      generation: generation,
      chunk_count: count
    })
  else
    # The decoder has validated the canonical normalized bytes. Seal that exact
    # representation instead of encoding the complete wallet again.
    let staged = prepare_encoded_wallet(normalized, wallet.revision, wrapping, who)?
    write_wallet(database,
      who,
      previous,
      generation,
      count,
      staged.generation,
      staged.root,
      staged.chunks)?
    Ok(CreditWalletSnapshot {
      wallet: wallet,
      previous: staged.root,
      generation: staged.generation,
      chunk_count: List.length(staged.chunks)
    })
  end
end

fn open_database(path :: String) -> SqliteConn!String do
  let database = case Sqlite.open(path) do
    Err(_) -> return Err("credit_database_open_failed")
    Ok(value) -> value
  end
  let setup = case Sqlite.execute(database, "PRAGMA busy_timeout = 1000", []) do
    Err(error)
    Ok(_) -> Sqlite.execute(database, "PRAGMA synchronous = FULL", [])
  end
  if Result.is_err(setup) do
    Sqlite.close(database)
    Err("credit_database_setup_failed")
  else
    Ok(database)
  end
end

pub fn load_credit_wallet(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> CreditWalletSnapshot!String do
  check_identity(who)?
  ensure_schema(path)?
  let database = open_database(path)?
  # Loading may atomically normalize a legacy attachment binding and replace
  # the encrypted wallet generation, so this is a migration-capable writer.
  let loaded = case Sqlite.execute(database, "BEGIN IMMEDIATE", []) do
    Err(_) -> Err("credit_database_read_failed")
    Ok(_) -> read_wallet(database, wrapping, who)
  end
  let result = case loaded do
    Err(error) -> do
      Sqlite.rollback(database)
      Err(error)
    end
    Ok(value) -> case Sqlite.commit(database) do
      Err(_) -> do
        Sqlite.rollback(database)
        Err("credit_database_read_failed")
      end
      Ok(_) -> Ok(value)
    end
  end
  Sqlite.close(database)
  result
end

struct PreparedWallet do
  generation :: Bytes
  root :: Bytes
  chunks :: List<Bytes>
end

fn prepare_wallet(wallet :: CreditWallet,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> PreparedWallet!String do
  let bytes = encode_credit_wallet(wallet)?
  prepare_encoded_wallet(bytes, wallet.revision, wrapping, who)
end

# Private callers supply only bytes accepted by the canonical encoder/decoder.
fn prepare_encoded_wallet(bytes :: Bytes,
  revision :: U64,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> PreparedWallet!String do
  let generation = random_bytes(32)?
  if !credit_record_id(generation) do
    return Err("credit_entropy_unavailable")
  end
  let count = (Bytes.length(bytes) + 59999) / 60000
  let chunks = for index in 0..count do
    let label = chunk_label(who, generation, index)
    let length = if index + 1 < count do
      60000
    else
      Bytes.length(bytes) - index * 60000
    end
    seal_local(Bytes.slice(bytes, index * 60000, length)?, wrapping, credit_context(who, label)?)?
  end
  let manifest = mobile_join([
      Bytes.from_hex("0143574d")?,
      mobile_write_u64(revision)?,
      generation,
      mobile_write_u32(Bytes.length(bytes))?,
      mobile_write_u16(count)?,
      Crypto.sha256(bytes)
    ],
    0,
    Bytes.empty())?
  let root = seal_local(manifest, wrapping, credit_context(who, "manifest")?)?
  Ok(PreparedWallet { generation: generation, root: root, chunks: chunks })
end

# A legacy record is handled only inside the authenticated storage transaction.
# Its first 32 bytes are classified before a generic CreditRecord can exist.
fn normalize_attachment_record(raw :: Bytes,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> Bytes!String do
  let state = mobile_reader(raw, 4208233, "invalid_credit_wallet_record")?
  let kind = take_fixed(state, 1)?
  let id = take_fixed(kind.state, 32)?
  let metadata = take_vector(id.state, 8192)?
  let payload = take_vector(metadata.state, 4200000)?
  mobile_finish(payload.state, "invalid_credit_wallet_record")?
  if mobile_read_byte(kind.value)? != 6 || valid_credit_attachment_metadata(metadata.value) do
    return Ok(raw)
  end
  if Bytes.length(metadata.value) != 36 && Bytes.length(metadata.value) != 68 do
    return Err("invalid_credit_attachment_material")
  end
  let binding :: Plaintext<Bytes> = Bytes.slice(metadata.value, 0, 32)?
  # Authenticate all original material before replacing any root. Preserve its
  # original ciphertext byte for byte; replay still validates grant/reference.
  let original = unpack_credit_parts(open_credit_payload(payload.value,
      wrapping,
      who,
      "attachment/#{Bytes.to_hex(id.value)}")?,
    2,
    1024)?
  if List.length(original) != 2 do
    return Err("invalid_credit_attachment_material")
  end
  let public_metadata = Bytes.concat(Bytes.from_hex("0241494a")?,
    Bytes.slice(metadata.value, 32, Bytes.length(metadata.value) - 32)?)?
  let sealed = seal_attachment_binding(binding,
    wrapping,
    credit_attachment_intent_context(who, id.value)?)?
  let private_payload = attachment_journal_payload(payload.value, sealed)?
  Bytes.concat(Bytes.concat(kind.value, id.value)?,
    Bytes.concat(mobile_vector(public_metadata)?, mobile_vector(private_payload)?)?)
end

fn normalize_attachment_wallet(bytes :: Bytes,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> Bytes!String do
  let parts = unpack_credit_parts(Bytes.slice(bytes, 12, Bytes.length(bytes) - 12)?, 8192, 4208233)?
  let normalized = for raw in parts do
    normalize_attachment_record(raw, wrapping, who)?
  end
  let records = pack_credit_parts(normalized)?
  let changed = !Bytes.secure_equals(records, Bytes.slice(bytes, 12, Bytes.length(bytes) - 12)?)
  let revision = mobile_read_u64(Bytes.slice(bytes, 4, 8)?)?
  let next = if changed do
    U64.add(revision, U64.parse("1")?)?
  else
    revision
  end
  Bytes.concat(Bytes.concat(Bytes.from_hex("01435753")?, mobile_write_u64(next)?)?, records)
end

fn write_wallet(database :: SqliteConn,
  who :: CreditWalletIdentity,
  previous :: Bytes,
  previous_generation :: Bytes,
  previous_count :: Int,
  generation :: Bytes,
  root :: Bytes,
  chunks :: List<Bytes>) -> Result<(), String> do
  let hash = blob_record_hash(database, credit_wallet_label(who))?
  let changed = if Bytes.length(previous) == 0 do
    Sqlite.execute_values(database,
      "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?) ON CONFLICT(record_hash) DO NOTHING",
      [Text(hash), Binary(root)])
  else
    Sqlite.execute_values(database,
      "UPDATE encrypted_blobs SET ciphertext = ? WHERE record_hash = ? AND ciphertext = ?",
      [Binary(root), Text(hash), Binary(previous)])
  end
  let count = case changed do
    Err(_) -> return Err("credit_database_write_failed")
    Ok(value) -> value
  end
  if count != 1 do
    return Err("credit_wallet_changed")
  end
  for index in 0..List.length(chunks) do
    insert_blob(database, chunk_label(who, generation, index), List.get(chunks, index))?
  end
  for index in 0..previous_count do
    delete_blob(database, chunk_label(who, previous_generation, index))?
  end
  Ok(nil)
end

# A returned request may be sent only AFTER this transaction succeeds. Manifest,
# chunks and old-generation deletion share one FULL-synchronous SQLite commit.
fn validate_before_snapshot(before :: CreditWalletSnapshot,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> Result<(), String> do
  let encoded = encode_credit_wallet(before.wallet)?
  if Bytes.length(before.previous) == 0 do
    if before.wallet.revision != U64.parse("0")?
      || List.length(before.wallet.records) != 0
      || Bytes.length(before.generation) != 0
      || before.chunk_count != 0 do
      return Err("invalid_credit_wallet_snapshot")
    end
  else
    let manifest = open_local(before.previous, wrapping, credit_context(who, "manifest")?)?
    let expected = mobile_join([
        Bytes.from_hex("0143574d")?,
        mobile_write_u64(before.wallet.revision)?,
        before.generation,
        mobile_write_u32(Bytes.length(encoded))?,
        mobile_write_u16(before.chunk_count)?,
        Crypto.sha256(encoded)
      ],
      0,
      Bytes.empty())?
    if !credit_record_id(before.generation)
      || before.chunk_count != (Bytes.length(encoded) + 59999) / 60000
      || !Bytes.secure_equals(manifest, expected) do
      return Err("invalid_credit_wallet_snapshot")
    end
  end
  Ok(nil)
end

pub fn commit_credit_wallet(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  before :: CreditWalletSnapshot,
  wallet :: CreditWallet) -> Result<(), String> do
  commit_credit_wallet_with_cache(path, wrapping, who, before, wallet, [])
end

pub fn commit_credit_wallet_with_cache(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  before :: CreditWalletSnapshot,
  wallet :: CreditWallet,
  cache :: List<CreditCacheWrite>) -> Result<(), String> do
  commit_credit_wallet_changes(path, wrapping, who, before, wallet, cache, [])
end

# Derive only this wallet's bounded attachment-part namespace. The manifest CAS,
# part deletion and cleanup cursor advance share the same SQLite transaction.
pub fn commit_credit_attachment_cleanup(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  before :: CreditWalletSnapshot,
  wallet :: CreditWallet,
  nonce :: Bytes,
  start :: Int,
  stop :: Int) -> Result<(), String> do
  if !credit_record_id(nonce) || start < 0 || stop <= start || stop > 8192 || stop - start > 128 do
    return Err("invalid_credit_attachment_cleanup")
  end
  let record = case List.find(before.wallet.records,
    fn(value) -> value.kind == 6 && Bytes.secure_equals(value.id, nonce) end) do
    None -> return Err("credit_attachment_not_found")
    Some(value) -> value
  end
  if !valid_credit_attachment_metadata(record.metadata)
    || credit_attachment_cursor(record.metadata)? != start do
    return Err("invalid_credit_attachment_cleanup")
  end
  let labels = for index in start..stop do
    "#{credit_wallet_label(who)}/attachment-part/#{Bytes.to_hex(nonce)}/#{index}"
  end
  commit_credit_wallet_changes(path, wrapping, who, before, wallet, [], labels)
end

fn commit_credit_wallet_changes(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  before :: CreditWalletSnapshot,
  wallet :: CreditWallet,
  cache :: List<CreditCacheWrite>,
  deletions :: List<String>) -> Result<(), String> do
  check_identity(who)?
  validate_before_snapshot(before, wrapping, who)?
  if List.length(cache) > 13 do
    return Err("invalid_credit_cache_update")
  end
  let labels = for write in cache do
    if List.contains(["outbox/v1", "delivery/v1"], write.label) do
      if Bytes.length(write.value) != 0 || Bytes.length(write.previous) > 66000 do
        return Err("invalid_credit_cache_update")
      end
    else if !List.contains([
        "transparency-checkpoint/v1",
        "transparency-view/v1",
        "transparency-view-chunk/v1/0",
        "transparency-view-chunk/v1/1",
        "transparency-view-chunk/v1/2",
        "transparency-witnesses/v2",
        "transparency-leaf/v1",
        "transparency-fork/v1",
        "anchor-schedule/v1",
        "profile/v1",
        "signup-draft/v1",
        "postage-queue/v1"
      ],
      write.label)
      && write.label != (credit_wallet_label(who) <> "/maintenance")
      && write.label != "transparency-device-set/v1/#{Bytes.to_hex(who.account_id)}"
      || Bytes.length(write.previous) > 66000
      || Bytes.length(write.value) > 66000 do
      return Err("invalid_credit_cache_update")
    end
    write.label
  end
  if Set.size(Set.from_list(labels)) != List.length(cache) do
    return Err("invalid_credit_cache_update")
  end
  if wallet.revision != U64.add(before.wallet.revision, U64.parse("1")?)? do
    return Err("invalid_credit_wallet_revision")
  end
  let staged = prepare_wallet(wallet, wrapping, who)?
  let generation = staged.generation
  let root = staged.root
  let chunks = staged.chunks
  let database = open_database(path)?
  let result = case Sqlite.execute(database, "BEGIN IMMEDIATE", []) do
    Err(_) -> Err("credit_database_write_failed")
    Ok(_) -> case write_wallet_and_cache(database,
      who,
      before,
      generation,
      root,
      chunks,
      cache,
      deletions) do
      Err(error)
      Ok(_) -> case Sqlite.commit(database) do
        Err(_) -> Err("credit_database_write_failed")
        Ok(_) -> Ok(nil)
      end
    end
  end
  if Result.is_err(result) do
    Sqlite.rollback(database)
  else
    Ok(nil)
  end
  Sqlite.close(database)
  result
end

fn write_wallet_and_cache(database :: SqliteConn,
  who :: CreditWalletIdentity,
  before :: CreditWalletSnapshot,
  generation :: Bytes,
  root :: Bytes,
  chunks :: List<Bytes>,
  cache :: List<CreditCacheWrite>,
  deletions :: List<String>) -> Result<(), String> do
  for write in cache do
    if !Bytes.secure_equals(blob(database, write.label)?, write.previous) do
      return Err("credit_transparency_changed")
    end
  end
  write_wallet(database,
    who,
    before.previous,
    before.generation,
    before.chunk_count,
    generation,
    root,
    chunks)?
  for label in deletions do
    delete_blob(database, label)?
    nil
  end
  for write in cache do
    if Bytes.length(write.value) > 0 do
      put_blob(database, write.label, write.value)?
    else
      nil
    end
  end
  Ok(nil)
end

# Payloads larger than one platform seal (issuance batches and exact CRD/body
# reservations) use authenticated length/count/hash plus separately bound chunks.
pub fn seal_credit_payload(value :: Bytes,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  label :: String) -> Bytes!String do
  if Bytes.length(value) < 1 || Bytes.length(value) > 4000000 do
    return Err("credit_payload_capacity")
  end
  let count = (Bytes.length(value) + 59999) / 60000
  let chunks = for index in 0..count do
    let length = if index + 1 < count do
      60000
    else
      Bytes.length(value) - index * 60000
    end
    seal_local(Bytes.slice(value, index * 60000, length)?,
      wrapping,
      credit_context(who, "#{label}/#{index}")?)?
  end
  let manifest = mobile_join([
      Bytes.from_hex("0143504c")?,
      mobile_write_u32(Bytes.length(value))?,
      mobile_write_u16(count)?,
      Crypto.sha256(value)
    ],
    0,
    Bytes.empty())?
  let sealed = seal_local(manifest, wrapping, credit_context(who, label <> "/manifest")?)?
  pack_credit_parts([sealed] ++ chunks)
end

fn open_payload_chunks(chunks :: List<Bytes>,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  label :: String,
  size :: Int,
  index :: Int,
  output :: Bytes) -> Bytes!String do
  if index + 1 >= List.length(chunks) do
    Ok(output)
  else
    let opened = open_local(List.get(chunks, index + 1),
      wrapping,
      credit_context(who, "#{label}/#{index}")?)?
    let expected = if index + 2 < List.length(chunks) do
      60000
    else
      size - index * 60000
    end
    if Bytes.length(opened) != expected do
      return Err("invalid_credit_payload_chunk")
    end
    open_payload_chunks(chunks,
      wrapping,
      who,
      label,
      size,
      index + 1,
      Bytes.concat(output, opened)?)
  end
end

pub fn open_credit_payload(blob :: Bytes,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  label :: String) -> Bytes!String do
  let chunks = unpack_credit_parts(blob, 68, 66000)?
  if List.length(chunks) < 2 do
    return Err("invalid_credit_payload")
  end
  let manifest = open_local(List.head(chunks),
    wrapping,
    credit_context(who, label <> "/manifest")?)?
  if Bytes.length(manifest) != 42 || Bytes.to_hex(Bytes.slice(manifest, 0, 4)?) != "0143504c" do
    return Err("invalid_credit_payload")
  end
  let size = mobile_read_u32(Bytes.slice(manifest, 4, 4)?)?
  let count = case Bytes.read_u16_be(manifest, 8) do
    Err(_) -> return Err("invalid_credit_payload")
    Ok(value) -> value
  end
  if size < 1
    || size > 4000000
    || count != (size + 59999) / 60000
    || count + 1 != List.length(chunks) do
    return Err("invalid_credit_payload")
  end
  let value = open_payload_chunks(chunks, wrapping, who, label, size, 0, Bytes.empty())?
  if !Bytes.secure_equals(Crypto.sha256(value), Bytes.slice(manifest, 10, 32)?) do
    Err("invalid_credit_payload")
  else
    Ok(value)
  end
end
