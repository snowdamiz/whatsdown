from Attachments.Protocol import (
  AttachmentError,
  AttachmentManifest,
  attachment_padded_size,
  open_chunk,
  open_manifest,
  seal_chunk,
  seal_manifest
)
from Binary.Reader import BinaryReader
from Identity.Device import AccountKeys, authorize_device_link
from Mobile.Account import complete_link_storing, create_device_link_request
from Mobile.BackupKeys import (
  backup_account_context,
  backup_account_key,
  backup_content_key,
  backup_locator,
  backup_open_key,
  backup_seal_key,
  backup_slot
)
from Mobile.BackupSnapshot import backup_account_of, backup_import, backup_join, backup_snapshot
from Mobile.Codec import (
  current_time,
  encode_output_list,
  mobile_byte,
  mobile_join,
  mobile_read_byte,
  mobile_read_u32,
  mobile_read_u64,
  mobile_reader,
  mobile_finish,
  mobile_utf8,
  mobile_vector,
  mobile_wide,
  mobile_write_u32,
  mobile_write_u64,
  random_bytes,
  take_vector_error
)
from Mobile.DeviceSet import verified_device_set
from Mobile.Profile import load_profile, open_account
from Mobile.Transparency import require_transparency_device_set
from Mobile.Types import MobilePayloadRequest, MobileReadBytes
from Objects.Grant import ObjectControl, encode_complete, encode_delete, encode_grant, mint_grant
from Protocol.DirectoryWire import decode_device_link_request, encode_device_link_authorization
from Protocol.IdentityWire import decode_account_identity
from Protocol.V1 import AccountIdentity, DeviceLinkRequest
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import (
  context,
  local_context,
  open_local,
  open_signing,
  platform_key,
  seal_local,
  seal_signing
)
from Storage.Records import ensure_account_missing, store_record_changes
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.Backup: encrypted backups (`protocol/backup-wire-v1.md`, version 2).
##!
##! Turning backups on makes a recovery code the app shows once; the device keeps
##! only what the code derives, never the code. A backup is an object in the
##! opaque store framed exactly like an attachment of the same padded size, in
##! one of four slots per day that only the code can name. Restoring happens on a
##! device already linked to the account: it adds what the backup holds.

fn backup_mime() -> Bytes do
  Bytes.from_utf8("application/vnd.morse.backup")
end

fn day_of(now :: U64) -> Int!String do
  Ok(U64.to_int(now)? / 86400000)
end

# ---- requests: the path, then vectors that may be empty ----

pub struct BackupRequest do
  database_path :: String
  fields :: List<Bytes>
end

fn read_fields(state :: BinaryReader, count :: Int, values :: List<Bytes>) -> List<Bytes>!String do
  if count == 0 do
    mobile_finish(state, "invalid_backup_request")?
    Ok(values)
  else
    let field = take_vector_error(state, 4194304, "invalid_backup_request")?
    read_fields(field.state, count - 1, List.append(values, field.value))
  end
end

pub fn parse_backup_request(input :: Bytes, count :: Int) -> BackupRequest!String do
  let state = mobile_reader(input, 8388608, "invalid_backup_request")?
  let path = take_vector_error(state, 4096, "invalid_backup_request")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if String.length(database_path) == 0 do
    return Err("invalid_database_path")
  end
  ensure_schema(database_path)?
  Ok(BackupRequest {
    database_path: database_path,
    fields: read_fields(path.state, count, List.new())?
  })
end

# ---- the device's backup record ----
# 1 while the code waits to be confirmed, 2 once backups are on. The slots are
# every object made in the past week, each u32 day || u8 index, so turning
# backups off can delete them.

struct BackupState do
  state :: Int
  locator :: Bytes
  key_blob :: Bytes
  last_backup_at :: U64
  slots :: List<Bytes>
end

fn state_label() -> String do
  "backup/v1"
end

fn key_label() -> String do
  "backup-key/v1"
end

fn encode_state(value :: BackupState) -> Bytes!String do
  mobile_join([
      mobile_vector(mobile_byte(value.state)?)?,
      mobile_vector(value.locator)?,
      mobile_vector(value.key_blob)?,
      mobile_vector(mobile_write_u64(value.last_backup_at)?)?,
      mobile_vector(mobile_join(value.slots, 0, Bytes.empty())?)?
    ],
    0,
    Bytes.empty())
end

fn split_slots(input :: Bytes, values :: List<Bytes>) -> List<Bytes>!String do
  if Bytes.length(input) == 0 do
    Ok(values)
  else if Bytes.length(input) < 5 do
    Err("invalid_backup_state")
  else
    split_slots(Bytes.slice(input, 5, Bytes.length(input) - 5)?,
      List.append(values, Bytes.slice(input, 0, 5)?))
  end
end

fn decode_state(input :: Bytes) -> BackupState!String do
  let reader = mobile_reader(input, 4096, "invalid_backup_state")?
  let state = take_vector_error(reader, 1, "invalid_backup_state")?
  let locator = take_vector_error(state.state, 32, "invalid_backup_state")?
  let key_blob = take_vector_error(locator.state, 256, "invalid_backup_state")?
  let last = take_vector_error(key_blob.state, 8, "invalid_backup_state")?
  let slots = take_vector_error(last.state, 1280, "invalid_backup_state")?
  mobile_finish(slots.state, "invalid_backup_state")?
  Ok(BackupState {
    state: mobile_read_byte(state.value)?,
    locator: locator.value,
    key_blob: key_blob.value,
    last_backup_at: mobile_read_u64(last.value)?,
    slots: split_slots(slots.value, List.new())?
  })
end

fn load_optional(database_path :: String,
  wrapping_key :: borrow StorageKey,
  label :: String) -> Bytes!String do
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> open_local(blob, wrapping_key, local_context(label)?)
  end
end

fn load_state(database_path :: String,
  wrapping_key :: borrow StorageKey) -> Option<BackupState>!String do
  let encoded = load_optional(database_path, wrapping_key, state_label())?
  if Bytes.length(encoded) == 0 do
    Ok(None)
  else
    Ok(Some(decode_state(encoded)?))
  end
end

fn sealed_state(value :: BackupState, wrapping_key :: borrow StorageKey) -> Bytes!String do
  seal_local(encode_state(value)?, wrapping_key, local_context(state_label())?)
end

fn backups_on(database_path :: String, wrapping_key :: borrow StorageKey) -> BackupState!String do
  case load_state(database_path, wrapping_key)? do
    Some(value) -> if value.state == 2 do
      Ok(value)
    else
      Err("backup_off")
    end
    None -> Err("backup_off")
  end
end

## Turning backups on, step one: a new code, returned this once. It is not
## kept; what it derives waits for `backup_confirm`.

pub fn backup_begin(request :: BackupRequest) -> Bytes!String do
  let wrapping_key = platform_key()?
  let _local = decode_client_profile(load_profile(request.database_path)?)?
  case load_state(request.database_path, wrapping_key)? do
    Some(value) -> if value.state == 2 do
      Err("backup_already_on")
    else
      Ok(nil)
    end
    None -> Ok(nil)
  end?
  let code = random_bytes(32)?
  let key = backup_content_key(code)?
  let pending = BackupState {
    state: 1,
    locator: backup_locator(code)?,
    key_blob: backup_seal_key(key, wrapping_key, key_label())?,
    last_backup_at: mobile_wide("0")?,
    slots: List.new()
  }
  store_record_changes(request.database_path,
    [state_label()],
    [sealed_state(pending, wrapping_key)?],
    List.new())?
  Ok(code)
end

## Step two: the user types the code back. Only then are backups on.

pub fn backup_confirm(request :: BackupRequest) -> Bytes!String do
  let wrapping_key = platform_key()?
  let pending = case load_state(request.database_path, wrapping_key)? do
    Some(value) -> if value.state == 1 do
      Ok(value)
    else
      Err("backup_already_on")
    end
    None -> Err("backup_off")
  end?
  let typed = List.head(request.fields)
  if Bytes.length(typed) != 32 || !Bytes.secure_equals(backup_locator(typed)?, pending.locator) do
    return Err("backup_code_mismatch")
  end
  store_record_changes(request.database_path,
    [state_label()],
    [sealed_state(%{pending | state: 2}, wrapping_key)?],
    List.new())?
  Ok(Bytes.empty())
end

## 0 off (or waiting for the code), 2 on; then when the last backup was made.

pub fn backup_status(request :: BackupRequest) -> Bytes!String do
  let wrapping_key = platform_key()?
  let (state, last) = case load_state(request.database_path, wrapping_key)? do
    Some(value) -> if value.state == 2 do
      (2, value.last_backup_at)
    else
      (0, value.last_backup_at)
    end
    None -> (0, mobile_wide("0")?)
  end
  mobile_join([mobile_vector(mobile_byte(state)?)?, mobile_vector(mobile_write_u64(last)?)?],
    0,
    Bytes.empty())
end

# ---- making a backup ----
# `backup-outgoing/v1` holds the sealed part 0 and when the backup was taken;
# `backup-outgoing/v1/<i>` holds chunk i of the snapshot until the upload ends.

fn outgoing_label() -> String do
  "backup-outgoing/v1"
end

fn chunk_label(prefix :: String, index :: Int) -> String do
  prefix <> "/" <> Int.to_string(index)
end

fn chunk_labels(prefix :: String) -> List<String> do
  for index in 0..256 do
    chunk_label(prefix, index)
  end
end

fn backup_manifest(backup_id :: Bytes,
  plaintext_size :: Int,
  expires_at :: U64) -> AttachmentManifest do
  AttachmentManifest {
    version: 2,
    attachment_id: backup_id,
    chunk_size: 65536,
    chunk_count: (attachment_padded_size(plaintext_size) + 65535) / 65536,
    plaintext_size: plaintext_size,
    filename: Bytes.empty(),
    mime_type: backup_mime(),
    expires_at: expires_at
  }
end

fn data_chunk_count(plaintext_size :: Int) -> Int do
  (plaintext_size + 65535) / 65536
end

fn snapshot_chunk(snapshot :: Bytes,
  wrapping_key :: borrow StorageKey,
  index :: Int) -> Bytes!String do
  let start = index * 65536
  let length = if Bytes.length(snapshot) - start < 65536 do
    Bytes.length(snapshot) - start
  else
    65536
  end
  seal_local(Bytes.slice(snapshot, start, length)?,
    wrapping_key,
    local_context(chunk_label(outgoing_label(), index))?)
end

fn snapshot_chunks(snapshot :: Bytes, wrapping_key :: borrow StorageKey) -> List<Bytes>!String do
  let sealed = for index in 0..data_chunk_count(Bytes.length(snapshot)) do
    snapshot_chunk(snapshot, wrapping_key, index)?
  end
  Ok(sealed)
end

fn slot_days(slots :: List<Bytes>) -> List<Int>!String do
  let days = for slot in slots do
    mobile_read_u32(Bytes.slice(slot, 0, 4)?)?
  end
  Ok(days)
end

fn next_slot(slots :: List<Bytes>, today :: Int) -> Int!String do
  let used = List.length(List.filter(slot_days(slots)?, fn(day) do day == today end))
  if used >= 4 do
    Err("backup_limit_reached")
  else
    Ok(used)
  end
end

fn slot_of(pair :: (Bytes, Int)) -> Bytes do
  let (slot, _) = pair
  slot
end

# Objects older than a week have expired, so the record forgets them.

fn recent_slots(slots :: List<Bytes>, today :: Int) -> List<Bytes>!String do
  let kept = List.filter(List.zip(slots, slot_days(slots)?),
    fn(pair) do
      let (_, day) = pair
      day >= today - 7
    end)
  Ok(List.map(kept, fn(pair) do slot_of(pair) end))
end

# The account key, sealed for the backup, when this device holds it: only the
# device that created the account does.

fn account_key_blob(database_path :: String,
  wrapping_key :: borrow StorageKey,
  local :: ClientProfile,
  key :: borrow SecretBytes) -> Bytes!String do
  case load_blob(database_path, "account-signing-key/v1") do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(_) -> do
      let account = open_account(local, wrapping_key, database_path)?
      let backup_key = backup_account_key(key)?
      seal_signing(account.private_key, backup_key, backup_account_context(local.account_id)?)
    end
  end
end

## Takes the snapshot and seals it as an object for today's next slot. Returns
## what the host sends: object ID, upload capability, grant, completion,
## deletion, and the number of parts it then asks for with `backup_part`.

pub fn backup_prepare(request :: BackupRequest) -> Bytes!String do
  let wrapping_key = platform_key()?
  let state = backups_on(request.database_path, wrapping_key)?
  let local = decode_client_profile(load_profile(request.database_path)?)?
  let difficulty = mobile_read_u32(List.get(request.fields, 1))?
  let now = current_time()?
  let today = day_of(now)?
  let index = next_slot(state.slots, today)?
  let slot = backup_slot(state.locator, today, index)?
  let key = backup_open_key(state.key_blob, wrapping_key, key_label())?
  let snapshot = backup_snapshot(request.database_path,
    wrapping_key,
    local,
    List.head(request.fields),
    now,
    account_key_blob(request.database_path, wrapping_key, local, key)?)?
  if Bytes.length(snapshot) > 16777216 do
    return Err("backup_too_large")
  end
  let expires_at = U64.add(now, mobile_wide("518400000")?)?
  let manifest = backup_manifest(random_bytes(32)?, Bytes.length(snapshot), expires_at)
  let part_zero = case seal_manifest(key, manifest) do
    Err(_) -> Err("backup_damaged")
    Ok(value)
  end?
  let grant = encode_grant(mint_grant(slot.object_id,
    manifest.chunk_count + 1,
    expires_at,
    U64.add(now, mobile_wide("150000")?)?,
    slot.upload_capability,
    slot.download_capability,
    difficulty)?)?
  let control = ObjectControl { object_id: slot.object_id, capability: slot.upload_capability }
  let position = mobile_join([mobile_write_u32(today)?, mobile_byte(index)?], 0, Bytes.empty())?
  let updated = %{state | slots: List.append(recent_slots(state.slots, today)?, position)}
  let outgoing = mobile_join([mobile_vector(part_zero)?, mobile_vector(mobile_write_u64(now)?)?],
    0,
    Bytes.empty())?
  let chunks = data_chunk_count(Bytes.length(snapshot))
  let labels = chunk_labels(outgoing_label())
  store_record_changes(request.database_path,
    [state_label(), outgoing_label()] ++ List.take(labels, chunks),
    [
      sealed_state(updated, wrapping_key)?,
      seal_local(outgoing, wrapping_key, local_context(outgoing_label())?)?
    ]
      ++ snapshot_chunks(snapshot, wrapping_key)?,
    List.drop(labels, chunks))?
  encode_output_list([
    slot.object_id,
    slot.upload_capability,
    grant,
    encode_complete(control)?,
    encode_delete(control)?,
    mobile_write_u32(manifest.chunk_count + 1)?
  ])
end

struct Outgoing do
  part_zero :: Bytes
  created_at :: U64
end

fn load_outgoing(database_path :: String, wrapping_key :: borrow StorageKey) -> Outgoing!String do
  let encoded = load_optional(database_path, wrapping_key, outgoing_label())?
  if Bytes.length(encoded) == 0 do
    return Err("backup_not_prepared")
  end
  let reader = mobile_reader(encoded, 1024, "invalid_backup_state")?
  let part_zero = take_vector_error(reader, 514, "invalid_backup_state")?
  let created = take_vector_error(part_zero.state, 8, "invalid_backup_state")?
  mobile_finish(created.state, "invalid_backup_state")?
  Ok(Outgoing { part_zero: part_zero.value, created_at: mobile_read_u64(created.value)? })
end

## Part `index` of the prepared object: 0 the sealed manifest, then every chunk
## of the padded snapshot, padding-only ones too, as an attachment's are.

pub fn backup_part(request :: BackupRequest) -> Bytes!String do
  let wrapping_key = platform_key()?
  let state = backups_on(request.database_path, wrapping_key)?
  let outgoing = load_outgoing(request.database_path, wrapping_key)?
  let index = mobile_read_u32(List.head(request.fields))?
  if index == 0 do
    return Ok(outgoing.part_zero)
  end
  let key = backup_open_key(state.key_blob, wrapping_key, key_label())?
  let manifest = case open_manifest(key, outgoing.part_zero) do
    Err(_) -> Err("backup_damaged")
    Ok(value)
  end?
  let chunk = index - 1
  if chunk >= manifest.chunk_count do
    return Err("invalid_backup_part")
  end
  let data = if chunk < data_chunk_count(manifest.plaintext_size) do
    load_optional(request.database_path, wrapping_key, chunk_label(outgoing_label(), chunk))?
  else
    Bytes.empty()
  end
  case seal_chunk(key, manifest, chunk, data) do
    Err(_) -> Err("backup_damaged")
    Ok(value)
  end
end

## After the upload: the prepared snapshot goes either way; a stored backup
## (1) becomes the last backup.

pub fn backup_finish(request :: BackupRequest) -> Bytes!String do
  let wrapping_key = platform_key()?
  let stored = mobile_read_byte(List.head(request.fields))? == 1
  let prepared = Bytes.length(load_optional(request.database_path,
    wrapping_key,
    outgoing_label())?) > 0
  let (labels, blobs) = case load_state(request.database_path, wrapping_key)? do
    Some(state) -> if stored && prepared && state.state == 2 do
      let outgoing = load_outgoing(request.database_path, wrapping_key)?
      ([state_label()],
        [sealed_state(%{state | last_backup_at: outgoing.created_at}, wrapping_key)?])
    else
      (List.new(), List.new())
    end
    None -> (List.new(), List.new())
  end
  store_record_changes(request.database_path,
    labels,
    blobs,
    [outgoing_label()] ++ chunk_labels(outgoing_label()))?
  Ok(Bytes.empty())
end

fn slot_deletion(locator :: Bytes, slot :: Bytes) -> Bytes!String do
  let day = mobile_read_u32(Bytes.slice(slot, 0, 4)?)?
  let place = backup_slot(locator, day, mobile_read_byte(Bytes.slice(slot, 4, 1)?)?)?
  encode_delete(ObjectControl { object_id: place.object_id, capability: place.upload_capability })
end

## Backups off: forgets the key and hands back the deletion of every object of
## the past week, which the host sends. Whatever it cannot reach expires.

pub fn backup_disable(request :: BackupRequest) -> Bytes!String do
  let wrapping_key = platform_key()?
  let deletions = case load_state(request.database_path, wrapping_key)? do
    None -> Ok(List.new())
    Some(state) -> do
      let controls = for slot in state.slots do
        slot_deletion(state.locator, slot)?
      end
      Ok(controls)
    end
  end?
  store_record_changes(request.database_path,
    List.new(),
    List.new(),
    [state_label(), outgoing_label()] ++ chunk_labels(outgoing_label()))?
  encode_output_list(deletions)
end

# ---- restoring ----

## Where a code's backups may be, newest first: object ID || download
## capability for each slot from tomorrow (a clock ahead) back a week.

fn restore_slot(locator :: Bytes, today :: Int, position :: Int) -> Bytes!String do
  let place = backup_slot(locator, today + 1 - position / 4, 3 - position % 4)?
  mobile_join([place.object_id, place.download_capability], 0, Bytes.empty())
end

pub fn backup_restore_slots(request :: BackupRequest) -> Bytes!String do
  let locator = backup_locator(List.head(request.fields))?
  let today = day_of(current_time()?)?
  let slots = for position in 0..32 do
    restore_slot(locator, today, position)?
  end
  encode_output_list(slots)
end

fn restore_label() -> String do
  "backup-restore/v1"
end

fn restore_key_label() -> String do
  "backup-restore-key/v1"
end

## Opens part 0 with the code as of `now`: the backup's size, how many chunks
## follow, and a fresh place to put them.

pub fn backup_restore_begin_at(database_path :: String,
  code :: Bytes,
  part_zero :: Bytes,
  now :: U64) -> Bytes!String do
  let wrapping_key = platform_key()?
  let key = backup_content_key(code)?
  let manifest = case open_manifest(key, part_zero) do
    Err(AuthenticationRejected) -> Err("backup_code_mismatch")
    Err(_) -> Err("backup_damaged")
    Ok(value)
  end?
  if manifest.version != 2 || !Bytes.secure_equals(manifest.mime_type, backup_mime()) do
    return Err("backup_damaged")
  end
  if U64.compare(now, manifest.expires_at) >= 0 do
    return Err("backup_expired")
  end
  let pending = mobile_join([
      mobile_vector(part_zero)?,
      mobile_vector(backup_seal_key(key, wrapping_key, restore_key_label())?)?
    ],
    0,
    Bytes.empty())?
  store_record_changes(database_path,
    [restore_label()],
    [seal_local(pending, wrapping_key, local_context(restore_label())?)?],
    chunk_labels(restore_label()))?
  mobile_write_u32(manifest.chunk_count)
end

pub fn backup_restore_begin(request :: BackupRequest) -> Bytes!String do
  backup_restore_begin_at(request.database_path,
    List.head(request.fields),
    List.get(request.fields, 1),
    current_time()?)
end

struct Restoring do
  manifest :: AttachmentManifest
  key_blob :: Bytes
end

fn load_restoring(database_path :: String, wrapping_key :: borrow StorageKey) -> Restoring!String do
  let encoded = load_optional(database_path, wrapping_key, restore_label())?
  if Bytes.length(encoded) == 0 do
    return Err("backup_restore_not_started")
  end
  let reader = mobile_reader(encoded, 1024, "invalid_backup_state")?
  let part_zero = take_vector_error(reader, 514, "invalid_backup_state")?
  let key_blob = take_vector_error(part_zero.state, 256, "invalid_backup_state")?
  mobile_finish(key_blob.state, "invalid_backup_state")?
  let key = backup_open_key(key_blob.value, wrapping_key, restore_key_label())?
  case open_manifest(key, part_zero.value) do
    Err(_) -> Err("backup_damaged")
    Ok(manifest) -> Ok(Restoring { manifest: manifest, key_blob: key_blob.value })
  end
end

## One downloaded chunk, `index` counted from 0 after part 0: checked, and its
## share of the snapshot kept until `backup_restore_finish`.

pub fn backup_restore_chunk(request :: BackupRequest) -> Bytes!String do
  let wrapping_key = platform_key()?
  let restoring = load_restoring(request.database_path, wrapping_key)?
  let index = mobile_read_u32(List.head(request.fields))?
  let key = backup_open_key(restoring.key_blob, wrapping_key, restore_key_label())?
  let data = case open_chunk(key, restoring.manifest, index, List.get(request.fields, 1)) do
    Err(_) -> Err("backup_damaged")
    Ok(value)
  end?
  if Bytes.length(data) > 0 do
    let label = chunk_label(restore_label(), index)
    store_record_changes(request.database_path,
      [label],
      [seal_local(data, wrapping_key, local_context(label)?)?],
      List.new())?
  end
  Ok(Bytes.empty())
end

fn restored_chunk(database_path :: String,
  wrapping_key :: borrow StorageKey,
  index :: Int) -> Bytes!String do
  let data = load_optional(database_path, wrapping_key, chunk_label(restore_label(), index))?
  if Bytes.length(data) == 0 do
    Err("backup_incomplete")
  else
    Ok(data)
  end
end

fn restored_snapshot(database_path :: String,
  wrapping_key :: borrow StorageKey,
  manifest :: AttachmentManifest) -> Bytes!String do
  let chunks = for index in 0..data_chunk_count(manifest.plaintext_size) do
    restored_chunk(database_path, wrapping_key, index)?
  end
  let snapshot = backup_join(chunks)?
  if Bytes.length(snapshot) != manifest.plaintext_size do
    Err("backup_incomplete")
  else
    Ok(snapshot)
  end
end

## Adds what the backup holds to this device, which must belong to the same
## account. Returns conversations and groups restored, when the backup was
## made, the app's record, and the snapshot's size.

pub fn backup_restore_finish(request :: BackupRequest) -> Bytes!String do
  let wrapping_key = platform_key()?
  let local = case load_profile(request.database_path) do
    Err(_) -> Err("backup_restore_needs_account")
    Ok(profile) -> decode_client_profile(profile)
  end?
  let restoring = load_restoring(request.database_path, wrapping_key)?
  let snapshot = restored_snapshot(request.database_path, wrapping_key, restoring.manifest)?
  let imported = backup_import(request.database_path, wrapping_key, local, snapshot)?
  store_record_changes(request.database_path,
    List.new(),
    List.new(),
    [restore_label()] ++ chunk_labels(restore_label()))?
  mobile_join([
      mobile_vector(mobile_write_u32(imported.conversations)?)?,
      mobile_vector(mobile_write_u32(imported.groups)?)?,
      mobile_vector(mobile_write_u64(imported.created_at)?)?,
      mobile_vector(imported.app_state)?,
      mobile_vector(mobile_write_u32(Bytes.length(snapshot))?)?
    ],
    0,
    Bytes.empty())
end

## Whose backup is being restored, once every chunk is in: its username and
## account ID, and whether it brought the account key, so the app knows
## whether this device can restore the account on its own.

pub fn backup_restore_identity(request :: BackupRequest) -> Bytes!String do
  let wrapping_key = platform_key()?
  let restoring = load_restoring(request.database_path, wrapping_key)?
  let held = backup_account_of(restored_snapshot(request.database_path,
    wrapping_key,
    restoring.manifest)?)?
  mobile_join([
      mobile_vector(Bytes.from_utf8(held.username))?,
      mobile_vector(held.account_id)?,
      mobile_vector(mobile_byte(if Bytes.length(held.key_blob) > 0 do
        1
      else
        0
      end)?)?
    ],
    0,
    Bytes.empty())
end

fn restored_account_keys(held_blob :: Bytes,
  content_key :: borrow SecretBytes,
  account_id :: Bytes,
  public_key :: Bytes) -> AccountKeys!String do
  let backup_key = backup_account_key(content_key)?
  let private_key = case open_signing(held_blob, backup_key, backup_account_context(account_id)?) do
    Err(_) -> Err("backup_damaged")
    Ok(value)
  end?
  Ok(AccountKeys {
    account_id: account_id,
    private_key: private_key,
    public_key: SigningPublicKey { bytes: public_key }
  })
end

fn verified_account_set(database_path :: String,
  wrapping_key :: borrow StorageKey,
  wire :: Bytes,
  account_id :: Bytes,
  public_key :: Bytes) -> U64!String do
  let devices = verified_device_set(wire)?
  require_transparency_device_set(database_path, wrapping_key, devices)?
  if !Bytes.secure_equals(devices.account.account_id, account_id)
    || !Bytes.secure_equals(devices.account.authorization_public_key, public_key) do
    Err("backup_account_mismatch")
  else
    U64.add(devices.value.sequence, mobile_wide("1")?)
  end
end

## The account itself back on a fresh install, from nothing but the code. The
## backup's account key authorizes a new device at the next sequence of the
## account's device set, which must be the one the key log shows
## (`device_set_transparency_unverified` otherwise); the device keeps the
## account key, then what the backup holds is added. The host registers the
## device with the directory next. Returns what `backup_restore_finish` does.

pub fn backup_restore_account(request :: BackupRequest) -> Bytes!String do
  ensure_account_missing(request.database_path)?
  let wrapping_key = platform_key()?
  let restoring = load_restoring(request.database_path, wrapping_key)?
  let snapshot = restored_snapshot(request.database_path, wrapping_key, restoring.manifest)?
  let held = backup_account_of(snapshot)?
  if Bytes.length(held.key_blob) == 0 do
    return Err("backup_has_no_account_key")
  end
  let identity = case decode_account_identity(held.identity) do
    Err(_) -> Err("backup_damaged")
    Ok(value)
  end?
  if !Bytes.secure_equals(identity.account_id, held.account_id) do
    return Err("backup_damaged")
  end
  let sequence = verified_account_set(request.database_path,
    wrapping_key,
    List.head(request.fields),
    identity.account_id,
    identity.authorization_public_key)?
  let content_key = backup_open_key(restoring.key_blob, wrapping_key, restore_key_label())?
  let account = restored_account_keys(held.key_blob,
    content_key,
    identity.account_id,
    identity.authorization_public_key)?
  let pending = case decode_device_link_request(create_device_link_request(request.database_path)?) do
    Err(_) -> Err("link_request_encoding_failed")
    Ok(value)
  end?
  let now = current_time()?
  let authorization = case authorize_device_link(account,
    identity,
    pending,
    held.username,
    U64.add(now, mobile_wide("31536000000")?)?,
    sequence) do
    Err(_) -> Err("link_authorization_failed")
    Ok(value)
  end?
  let authorization_wire = case encode_device_link_authorization(authorization) do
    Err(_) -> Err("link_authorization_encoding_failed")
    Ok(value)
  end?
  let account_blob = seal_signing(account.private_key,
    wrapping_key,
    context(identity.account_id, pending.device_id, "account-signing-key/v1", 6)?)?
  complete_link_storing(MobilePayloadRequest {
      database_path: request.database_path,
      payload: authorization_wire
    },
    ["account-signing-key/v1"],
    [account_blob])?
  let local = decode_client_profile(load_profile(request.database_path)?)?
  let imported = backup_import(request.database_path, wrapping_key, local, snapshot)?
  mobile_join([
      mobile_vector(mobile_write_u32(imported.conversations)?)?,
      mobile_vector(mobile_write_u32(imported.groups)?)?,
      mobile_vector(mobile_write_u64(imported.created_at)?)?,
      mobile_vector(imported.app_state)?,
      mobile_vector(mobile_write_u32(Bytes.length(snapshot))?)?
    ],
    0,
    Bytes.empty())
end
