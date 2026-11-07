from Mobile.BackupArchive import (
  D4BackupSelection,
  D4BackupPendingState,
  create_pending_backup_export,
  pending_backup_export_state,
  resume_pending_backup_export,
  discard_pending_backup_export,
  repair_pending_backup_export
)
from Tests.BackupArchiveFixture import (
  D4CoreFixture,
  d4_core_fixture,
  d4_core_cleanup,
  d4_core_install_direct_history,
  d4_core_import_bundle,
  d4_core_max_bundle,
  d4_core_backup_id,
  d4_core_all_rows,
  d4_core_rows_preserved
)
from Tests.Support import repeated
from Mobile.Codec import mobile_join, mobile_byte, mobile_write_u32, mobile_write_u64
from Transport.Packet import decode_client_profile
from Storage.Keys import platform_key, context, seal_local
from Storage.Blobs import (
  blob_record_hash_with_key,
  blob_record_hashes_with_key,
  put_blob_bounded_with_key
)
from Backups.PortableV2 import PortableBackupV2Created

pub struct PendingFixture do
  base :: D4CoreFixture
  bundle :: PortableBackupV2Created
  draft_id :: Bytes
  wire_label :: String
  descriptor_label :: String
end

fn pending_join(values :: List<Bytes>) -> Bytes!String do
  mobile_join(values, 0, Bytes.empty())
end

# The exact authored storage protocol oracle is independent of production helpers.
fn pending_realm(f :: D4CoreFixture) -> Bytes!String do
  Ok(Crypto.sha256(pending_join([
    Bytes.from_utf8("morse-backup-service-realm/v1\n"),
    Bytes.from_utf8("https://core.example"),
    f.config.service_public_key
  ])?))
end

fn pending_labels(f :: D4CoreFixture) -> List<String>!String do
  let profile = decode_client_profile(f.public_profile)?
  let digest = Crypto.sha256(pending_join([
    Bytes.from_utf8("morse-backup-pending-owner/v1\n"),
    f.account_id,
    profile.device_id
  ])?)
  let prefix = "backup-pending/v1/#{Bytes.to_hex(digest)}"
  Ok(["#{prefix}/wire", "#{prefix}/descriptor"])
end

fn pending_context(f :: D4CoreFixture) -> Bytes!String do
  let profile = decode_client_profile(f.public_profile)?
  let digest = Crypto.sha256(pending_join([
    Bytes.from_utf8("morse-backup-pending-context/v1\n"),
    f.account_id,
    profile.account.authorization_public_key,
    pending_realm(f)?,
    profile.device_id
  ])?)
  context(f.account_id, profile.device_id, "backup-pending-context/v1/#{Bytes.to_hex(digest)}", 14)
end

fn pending_descriptor(f :: D4CoreFixture,
  bundle :: PortableBackupV2Created,
  draft :: Bytes) -> Bytes!String do
  let profile = decode_client_profile(f.public_profile)?
  pending_join([
    Bytes.from_utf8("BPDM"),
    mobile_byte(1)?,
    f.account_id,
    profile.account.authorization_public_key,
    pending_realm(f)?,
    profile.device_id,
    draft,
    d4_core_backup_id(bundle.wire)?,
    Crypto.sha256(bundle.wire),
    mobile_write_u32(Bytes.length(bundle.wire))?,
    mobile_write_u64(f.now)?
  ])
end

pub fn pending_install_bundle(f :: D4CoreFixture,
  bundle :: PortableBackupV2Created,
  draft :: Bytes) -> PendingFixture!String do
  let labels = pending_labels(f)?
  let profile = decode_client_profile(f.public_profile)?
  let descriptor = pending_descriptor(f, bundle, draft)?
  if Bytes.length(descriptor) != 225 do
    return Err("pending_fixture_descriptor")
  end
  let key = platform_key()?
  let sealed = seal_local(descriptor, key, pending_context(f)?)
  let result = case sealed do
    Err(error)
    Ok(blob) -> do
      let database = Sqlite.open(f.path)?
      let write = case Sqlite.execute(database, "BEGIN IMMEDIATE", []) do
        Err(error)
        Ok(_) -> do
          put_blob_bounded_with_key(database, key, List.get(labels, 0), bundle.wire, 16796864)?
          put_blob_bounded_with_key(database, key, List.get(labels, 1), blob, 4096)?
          Sqlite.commit(database)
        end
      end
      Sqlite.rollback(database)
      Sqlite.close(database)
      write
    end
  end
  Secret.destroy(key)
  result?
  Ok(PendingFixture {
    base: f,
    bundle: bundle,
    draft_id: draft,
    wire_label: List.get(labels, 0),
    descriptor_label: List.get(labels, 1)
  })
end

pub fn pending_install_with_id(f :: D4CoreFixture, draft :: Bytes) -> PendingFixture!String do
  pending_install_bundle(f, d4_core_import_bundle(f, false)?, draft)
end

pub fn d4_pending_maximum_fixture() -> PendingFixture!String do
  let f = d4_core_fixture()?
  pending_install_bundle(f, d4_core_max_bundle(f)?, repeated(214, 32)?)
end

pub fn pending_install(f :: D4CoreFixture) -> PendingFixture!String do
  pending_install_with_id(f, repeated(212, 32)?)
end

pub fn pending_fixture() -> PendingFixture!String do
  pending_install(d4_core_fixture()?)
end

pub fn pending_remove_row(f :: PendingFixture, descriptor :: Bool) -> Result<(), String> do
  let key = platform_key()?
  let database = Sqlite.open(f.base.path)?
  let label = if descriptor do
    f.descriptor_label
  else
    f.wire_label
  end
  let hashed = blob_record_hash_with_key(database, key, label)
  Secret.destroy(key)
  let result = case hashed do
    Err(error)
    Ok(hash) -> case Sqlite.execute(database,
      "DELETE FROM encrypted_blobs WHERE record_hash = ?",
      [hash]) do
      Err(error)
      Ok(_) -> Ok(nil)
    end
  end
  Sqlite.close(database)
  result
end

# An actual canonical STRICT table refuses TEXT writes. Use an owned adversarial
# non-STRICT table with the SAME declared columns, index and WITHOUT ROWID shape
# to reach the defensive typeof admission path without weakening production.
fn pending_nonstrict_fixture_on(database :: SqliteConn) -> Result<(), String> do
  Sqlite.execute(database, "ALTER TABLE encrypted_blobs RENAME TO pending_fixture_strict_rows", [])?
  Sqlite.execute(database,
    "CREATE TABLE encrypted_blobs (record_hash TEXT PRIMARY KEY CHECK(length(record_hash) = 64), ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 0)) WITHOUT ROWID",
    [])?
  Sqlite.execute(database,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) SELECT record_hash, ciphertext FROM pending_fixture_strict_rows",
    [])?
  Sqlite.execute(database, "DROP TABLE pending_fixture_strict_rows", [])?
  Sqlite.commit(database)
end

fn pending_set_wire_on(database :: SqliteConn,
  hash :: String,
  input :: Bytes,
  wrong_type :: Bool) -> Result<(), String> do
  if wrong_type do
    let changed = case Sqlite.execute(database, "BEGIN IMMEDIATE", []) do
      Err(error)
      Ok(_) -> pending_nonstrict_fixture_on(database)
    end
    case changed do
      Err(_) -> do
        Sqlite.rollback(database)
        nil
      end
      Ok(_) -> nil
    end
    changed?
  end
  let value = if wrong_type do
    Text("foreign text row")
  else
    Binary(input)
  end
  case Sqlite.execute_values_v2(database,
    "UPDATE encrypted_blobs SET ciphertext = ? WHERE record_hash = ?",
    [value, Text(hash)],
    33554432) do
    Err(error)
    Ok(_) -> Ok(nil)
  end
end

pub fn pending_set_wire(f :: PendingFixture,
  input :: Bytes,
  wrong_type :: Bool) -> Result<(), String> do
  let key = platform_key()?
  let database = Sqlite.open(f.base.path)?
  let hashed = blob_record_hash_with_key(database, key, f.wire_label)
  Secret.destroy(key)
  let result = case hashed do
    Err(error)
    Ok(hash) -> pending_set_wire_on(database, hash, input, wrong_type)
  end
  Sqlite.close(database)
  result
end

fn pending_known_state_raw(raw :: Result<Plaintext<D4BackupPendingState>, String>,
  kind :: Int,
  id :: Bytes,
  time :: U64,
  size :: Int) -> Bool do
  case raw do
    Err(_) -> false
    Ok(value) -> value.kind == kind
      && Bytes.secure_equals(value.draft_id, id)
      && U64.compare(value.created_at, time) == 0
      && value.wire_size == size
  end
end

fn pending_observe(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY authored synthetic pending export state descriptor equality or fixed refusal; no real code plaintext key digest or arbitrary error is disclosed")
end

pub fn pending_known_state(raw :: Result<Plaintext<D4BackupPendingState>, String>,
  kind :: Int,
  id :: Bytes,
  time :: U64,
  size :: Int) -> Bool do
  pending_observe(pending_known_state_raw(raw, kind, id, time, size))
end

pub fn pending_known_reply(raw :: Result<Plaintext<Bytes>, String>, expected :: Bytes) -> Bool do
  let matches = case raw do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value, expected)
  end
  pending_observe(matches)
end

fn pending_fault_with_key(f :: D4CoreFixture,
  enabled :: Bool,
  key :: borrow StorageKey) -> Result<(), String> do
  let labels = pending_labels(f)?
  let database = Sqlite.open(f.path)?
  let hashes = blob_record_hashes_with_key(database, key, labels)
  let raw = case hashes do
    Err(error)
    Ok(values) -> if enabled do
      Sqlite.execute(database,
        "CREATE TRIGGER pending_descriptor_write_fault BEFORE INSERT ON encrypted_blobs WHEN NEW.record_hash = '#{List.get(values,
          1)}' AND EXISTS (SELECT 1 FROM encrypted_blobs WHERE record_hash = '#{List.get(values,
          0)}') BEGIN SELECT RAISE(ABORT, 'pending_descriptor_fault'); END",
        [])
    else
      Sqlite.execute(database, "DROP TRIGGER pending_descriptor_write_fault", [])
    end
  end
  Sqlite.close(database)
  case raw do
    Err(error)
    Ok(_) -> Ok(nil)
  end
end

pub fn d4_pending_descriptor_write_fault(f :: D4CoreFixture,
  enabled :: Bool) -> Result<(), String> do
  let key = platform_key()?
  let result = pending_fault_with_key(f, enabled, key)
  Secret.destroy(key)
  result
end

pub fn d4_pending_known_native_refusal(raw :: Result<Plaintext<Bytes>, String>) -> Bool do
  let refused = case raw do
    Err(_) -> true
    Ok(_) -> false
  end
  pending_observe(refused)
end

# Independently authored synthetic descriptor ciphertext for a concurrent winner.
pub fn d4_pending_descriptor_cipher(f :: PendingFixture) -> Bytes!String do
  let descriptor = pending_descriptor(f.base, f.bundle, f.draft_id)?
  let key = platform_key()?
  let raw = seal_local(descriptor, key, pending_context(f.base)?)
  Secret.destroy(key)
  raw
end

pub fn d4_pending_state_refused(raw :: Result<Plaintext<D4BackupPendingState>, String>) -> Bool do
  pending_observe(Result.is_err(raw))
end
