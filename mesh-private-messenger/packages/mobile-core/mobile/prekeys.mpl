from Identity.Device import DeviceKeys
from Mobile.Codec import (
  current_time,
  mobile_append,
  mobile_join,
  mobile_read_u64,
  mobile_wide,
  mobile_write_u32,
  mobile_write_u64
)
from Mobile.ContactAddress import confirmed_contact_address_writes, published_contact_address
from Mobile.Profile import load_profile, open_device
from Mobile.Types import MobileOneTimePrekey, MobilePrekeyReconcileRequest, MobilePrekeyRequest
from Prekeys.Bundle import OneTimePrekeySecrets, PrekeyError, generate_one_time_prekey
from Prekeys.Pool import (
  OneTimePrekeyPublic,
  PrekeyPublishRequest,
  decode_prekey_publish_response,
  encode_prekey_publish,
  prekey_publish_signing_bytes
)
from Protocol.V1 import AccountIdentity, DeviceCredential, DirectoryEntry, PrekeyBundle
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import (
  context,
  local_context,
  one_time_prekey_context,
  one_time_prekey_label,
  open_local,
  open_x25519,
  platform_key,
  seal_local,
  seal_x25519
)
from Storage.Records import store_last_resort_prekey, store_prekey_batch, store_prekey_reconciliation, store_record_changes
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.Prekeys implementation.

fn valid_prekey_id(id :: U64) -> Bool!String do
  Ok(U64.compare(id, mobile_wide("0")?) > 0 && U64.compare(id, mobile_wide("9223372036854775807")?) <= 0)
end

fn encode_prekey_entries(entries :: List<MobileOneTimePrekey>, index :: Int, output :: Bytes) -> Bytes!String do
  if List.length(entries) > 128 do
    Err("prekey_pool_full")
  else if index >= List.length(entries) do
    Ok(output)
  else
    let entry = List.get(entries, index)
    if !(valid_prekey_id(entry.id)?) || Bytes.length(entry.public_key) != 32 do
      Err("invalid_prekey_pool")
    else
      encode_prekey_entries(entries,
        index + 1,
        mobile_join([output, mobile_write_u64(entry.id)?, entry.public_key], 0, Bytes.empty())?)
    end
  end
end

fn decode_prekey_entries(encoded :: Bytes,
  offset :: Int,
  previous :: U64,
  entries :: List<MobileOneTimePrekey>) -> List<MobileOneTimePrekey>!String do
  if offset >= Bytes.length(encoded) do
    Ok(entries)
  else
    let id = mobile_read_u64(Bytes.slice(encoded, offset, 8)?)?
    let public_key = Bytes.slice(encoded, offset + 8, 32)?
    if !(valid_prekey_id(id)?) || U64.compare(id, previous) <= 0 do
      Err("invalid_prekey_pool")
    else
      decode_prekey_entries(encoded,
        offset + 40,
        id,
        List.append(entries,
          MobileOneTimePrekey {
            id: id,
            public_key: public_key
          }))
    end
  end
end

fn decode_prekey_pool(encoded :: Bytes) -> List<MobileOneTimePrekey>!String do
  if Bytes.length(encoded) % 40 != 0 || Bytes.length(encoded) > 5120 do
    Err("invalid_prekey_pool")
  else
    decode_prekey_entries(encoded, 0, mobile_wide("0")?, List.new())
  end
end

fn contains_prekey_id(ids :: List<U64>, id :: U64, index :: Int) -> Bool do
  if index >= List.length(ids) do
    false
  else if U64.compare(List.get(ids, index), id) == 0 do
    true
  else
    contains_prekey_id(ids, id, index + 1)
  end
end

fn mobile_prekey_ids(entries :: List<MobileOneTimePrekey>, index :: Int, output :: List<U64>) -> List<U64> do
  if index >= List.length(entries) do
    output
  else
    let entry = List.get(entries, index)
    mobile_prekey_ids(entries, index + 1, List.append(output, entry.id))
  end
end

fn encode_active_prekey_ids(ids :: List<U64>, index :: Int, previous :: U64, output :: Bytes) -> Bytes!String do
  if List.length(ids) > 64 do
    Err("active_prekey_pool_full")
  else if index >= List.length(ids) do
    Ok(output)
  else
    let id = List.get(ids, index)
    if !(valid_prekey_id(id)?) || U64.compare(id, previous) <= 0 do
      Err("invalid_active_prekey_pool")
    else
      encode_active_prekey_ids(ids, index + 1, id, mobile_append(output, mobile_write_u64(id)?)?)
    end
  end
end

fn decode_active_prekey_ids(encoded :: Bytes,
  offset :: Int,
  previous :: U64,
  entry_ids :: List<U64>,
  output :: List<U64>) -> List<U64>!String do
  if offset >= Bytes.length(encoded) do
    Ok(output)
  else
    let id = mobile_read_u64(Bytes.slice(encoded, offset, 8)?)?
    if !(valid_prekey_id(id)?) || U64.compare(id, previous) <= 0 || !contains_prekey_id(entry_ids,
      id,
      0) do
      Err("invalid_active_prekey_pool")
    else
      decode_active_prekey_ids(encoded, offset + 8, id, entry_ids, List.append(output, id))
    end
  end
end

fn decode_active_prekey_pool(encoded :: Bytes, entry_ids :: List<U64>) -> List<U64>!String do
  if Bytes.length(encoded) % 8 != 0 || Bytes.length(encoded) > 512 do
    Err("invalid_active_prekey_pool")
  else
    decode_active_prekey_ids(encoded, 0, mobile_wide("0")?, entry_ids, List.new())
  end
end

pub fn seal_prekey_pool(entries :: List<MobileOneTimePrekey>, wrapping_key :: borrow StorageKey) -> Bytes!String do
  seal_local(encode_prekey_entries(entries, 0, Bytes.empty())?,
    wrapping_key,
    local_context("one-time-prekeys/v1")?)
end

pub fn seal_active_prekey_pool(ids :: List<U64>, wrapping_key :: borrow StorageKey) -> Bytes!String do
  seal_local(encode_active_prekey_ids(ids, 0, mobile_wide("0")?, Bytes.empty())?,
    wrapping_key,
    local_context("one-time-prekey-active/v1")?)
end

pub fn seal_prekey_wide(label :: String, value :: U64, wrapping_key :: borrow StorageKey) -> Bytes!String do
  seal_local(mobile_write_u64(value)?, wrapping_key, local_context(label)?)
end

fn load_prekey_wide(database_path :: String, label :: String, wrapping_key :: borrow StorageKey) -> U64!String do
  mobile_read_u64(open_local(load_blob(database_path, label)?, wrapping_key, local_context(label)?)?)
end

fn migrate_legacy_prekey(profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  database_path :: String) -> List<MobileOneTimePrekey>!String do
  let id = profile.bundle.one_time_prekey_id
  if !(valid_prekey_id(id)?) || Bytes.length(profile.bundle.one_time_prekey) != 32 do
    Err("prekey_pool_uninitialized")
  else
    let legacy_private = open_x25519(load_blob(database_path, "one-time-prekey/v1")?,
      wrapping_key,
      context(profile.account_id, profile.device_id, "one-time-prekey/v1", 10)?)?
    let label = one_time_prekey_label(id)
    let blob = seal_x25519(legacy_private, wrapping_key, one_time_prekey_context(profile, id)?)?
    let entries = [
      MobileOneTimePrekey {
        id: id,
        public_key: profile.bundle.one_time_prekey
      }
    ]
    store_prekey_batch(database_path,
      [label],
      [blob],
      List.new(),
      seal_prekey_pool(entries, wrapping_key)?,
      seal_active_prekey_pool([id], wrapping_key)?,
      seal_prekey_wide("one-time-prekey-next-id/v1", U64.add(id, mobile_wide("1")?)?, wrapping_key)?,
      true)?
    Ok(entries)
  end
end

pub fn load_prekey_pool(profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  database_path :: String) -> List<MobileOneTimePrekey>!String do
  case load_blob(database_path, "one-time-prekeys/v1") do
    Err(error) -> if error == "local_state_not_found" do
      migrate_legacy_prekey(profile, wrapping_key, database_path)
    else
      Err(error)
    end
    Ok(blob) -> decode_prekey_pool(open_local(blob,
      wrapping_key,
      local_context("one-time-prekeys/v1")?)?)
  end
end

fn active_ids_belong(active_ids :: List<U64>, entry_ids :: List<U64>, index :: Int) -> Bool do
  if index >= List.length(active_ids) do
    true
  else if !contains_prekey_id(entry_ids, List.get(active_ids, index), 0) do
    false
  else
    active_ids_belong(active_ids, entry_ids, index + 1)
  end
end

fn inferred_active_prekey_pool(entries :: List<MobileOneTimePrekey>) -> List<U64>!String do
  let ids = mobile_prekey_ids(entries, 0, List.new())
  if List.length(ids) > 64 do
    Err("invalid_active_prekey_pool")
  else
    Ok(ids)
  end
end

pub fn load_active_prekey_pool(database_path :: String,
  entries :: List<MobileOneTimePrekey>,
  wrapping_key :: borrow StorageKey) -> List<U64>!String do
  case load_blob(database_path, "one-time-prekey-active/v1") do
    Err(error) -> if error == "local_state_not_found" do
      # Pools created before active acknowledgements treat all local entries as
      # active until count=0 recovery obtains the server truth.
      inferred_active_prekey_pool(entries)
    else
      Err(error)
    end
    Ok(blob) -> decode_active_prekey_pool(open_local(blob,
        wrapping_key,
        local_context("one-time-prekey-active/v1")?)?,
      mobile_prekey_ids(entries, 0, List.new()))
  end
end

# The reusable last-resort prekey. It shares the one-time wire format and secret
# storage, so the handshake treats it like any other prekey; only this device
# knows it must survive being used. Its identifiers start at 2^62 + 1, far above
# any one-time identifier a device will ever count up to, and only grow.
#
# It is the one prekey whose secret is not destroyed by use, so it is not kept
# for ever either. A week after it was made, the next publication names a new
# one. The old secret has to outlive that: the directory may go on handing the
# old key out until it has answered a publication naming the new one, and a
# first message sealed to it can then sit in the mailbox for up to 31 days. So
# the old secret is destroyed 35 days after the directory's answer, not before.

fn last_resort_lifetime() -> U64!String do
  mobile_wide("604800000")
end

fn last_resort_grace() -> U64!String do
  mobile_wide("3024000000")
end

fn decode_last_resort(encoded :: Bytes) -> MobileOneTimePrekey!String do
  if Bytes.length(encoded) < 40 do
    Err("invalid_last_resort_prekey")
  else
    let id = mobile_read_u64(Bytes.slice(encoded, 0, 8)?)?
    if !(valid_prekey_id(id)?) do
      Err("invalid_last_resort_prekey")
    else
      Ok(MobileOneTimePrekey {
        id: id,
        public_key: Bytes.slice(encoded, 8, 32)?
      })
    end
  end
end

fn load_last_resort_state(database_path :: String,
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

# The key being handed out: identifier, public key and, since keys are replaced,
# when it was made. A record from before then has no time and counts as due.

fn load_last_resort_record(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes!String do
  let stored = load_last_resort_state(database_path, wrapping_key, "last-resort-prekey/v1")?
  if Bytes.length(stored) == 0 || Bytes.length(stored) == 40 || Bytes.length(stored) == 48 do
    Ok(stored)
  else
    Err("invalid_last_resort_prekey")
  end
end

# Replaced keys whose secrets are still kept, oldest first: 48 bytes each, the
# identifier, the public key, and when the directory confirmed the successor
# (zero until it has).

fn load_last_resort_retired(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes!String do
  let stored = load_last_resort_state(database_path, wrapping_key, "last-resort-retired/v1")?
  if Bytes.length(stored) % 48 != 0 do
    Err("invalid_last_resort_prekey")
  else
    Ok(stored)
  end
end

fn retired_last_resort(retired :: Bytes, id :: U64, offset :: Int) -> Option<MobileOneTimePrekey>!String do
  if offset >= Bytes.length(retired) do
    Ok(None)
  else
    let candidate = decode_last_resort(Bytes.slice(retired, offset, 40)?)?
    if U64.compare(candidate.id, id) == 0 do
      Ok(Some(candidate))
    else
      retired_last_resort(retired, id, offset + 48)
    end
  end
end

# The reusable key a first message names, if it names one: the key being handed
# out, or one replaced recently enough that its messages may still arrive.

pub fn find_last_resort_prekey(database_path :: String,
  wrapping_key :: borrow StorageKey,
  id :: U64) -> Option<MobileOneTimePrekey>!String do
  let stored = load_last_resort_record(database_path, wrapping_key)?
  if Bytes.length(stored) == 0 do
    Ok(None)
  else
    let current = decode_last_resort(stored)?
    if U64.compare(current.id, id) == 0 do
      Ok(Some(current))
    else
      retired_last_resort(load_last_resort_retired(database_path, wrapping_key)?, id, 0)
    end
  end
end

fn new_last_resort_prekey(profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  database_path :: String,
  id :: U64,
  now :: U64,
  retired :: Bytes,
  removed_labels :: List<String>) -> MobileOneTimePrekey!String do
  let generated = case generate_one_time_prekey(id) do
    Err(_) -> Err("prekey_generation_failed")
    Ok(value)
  end?
  let secret = seal_x25519(generated.private_key,
    wrapping_key,
    one_time_prekey_context(profile, id)?)?
  let public_key = generated.public_key.bytes
  let retired_blob = if Bytes.length(retired) == 0 do
    Bytes.empty()
  else
    seal_local(retired, wrapping_key, local_context("last-resort-retired/v1")?)?
  end
  store_last_resort_prekey(database_path,
    one_time_prekey_label(id),
    secret,
    seal_local(mobile_join([mobile_write_u64(id)?, public_key, mobile_write_u64(now)?],
        0,
        Bytes.empty())?,
      wrapping_key,
      local_context("last-resort-prekey/v1")?)?,
    retired_blob,
    removed_labels)?
  Ok(MobileOneTimePrekey {
    id: id,
    public_key: public_key
  })
end

fn ensure_last_resort_prekey(profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  database_path :: String) -> MobileOneTimePrekey!String do
  let stored = load_last_resort_record(database_path, wrapping_key)?
  let now = current_time()?
  if Bytes.length(stored) == 0 do
    new_last_resort_prekey(profile,
      wrapping_key,
      database_path,
      mobile_wide("4611686018427387905")?,
      now,
      Bytes.empty(),
      List.new())
  else
    let current = decode_last_resort(stored)?
    let made = if Bytes.length(stored) == 48 do
      mobile_read_u64(Bytes.slice(stored, 40, 8)?)?
    else
      mobile_wide("0")?
    end
    if U64.compare(now, U64.add(made, last_resort_lifetime()?)?) < 0 do
      Ok(current)
    else
      let kept = load_last_resort_retired(database_path, wrapping_key)?
      # ponytail: sixteen replaced keys at most. A device the directory never
      # answers would otherwise add one a week; the oldest goes first.
      let dropped = if Bytes.length(kept) >= 768 do
        [one_time_prekey_label(decode_last_resort(Bytes.slice(kept, 0, 40)?)?.id)]
      else
        List.new()
      end
      let bounded = if Bytes.length(kept) >= 768 do
        Bytes.slice(kept, 48, Bytes.length(kept) - 48)?
      else
        kept
      end
      let retired = mobile_join([
          bounded,
          Bytes.slice(stored, 0, 40)?,
          mobile_write_u64(mobile_wide("0")?)?
        ],
        0,
        Bytes.empty())?
      new_last_resort_prekey(profile,
        wrapping_key,
        database_path,
        U64.add(current.id, mobile_wide("1")?)?,
        now,
        retired,
        dropped)
    end
  end
end

# The directory has answered a publication, so from now on it hands out the key
# that publication named. Replaced keys start their last 35 days here, and
# those that have had them lose their secrets.

fn settled_retired(retired :: Bytes,
  offset :: Int,
  now :: U64,
  kept :: Bytes,
  removed :: List<String>) -> Result<(Bytes, List<String>), String> do
  if offset >= Bytes.length(retired) do
    Ok((kept, removed))
  else
    let record = Bytes.slice(retired, offset, 40)?
    let confirmed = mobile_read_u64(Bytes.slice(retired, offset + 40, 8)?)?
    if U64.compare(confirmed, mobile_wide("0")?) == 0 do
      settled_retired(retired,
        offset + 48,
        now,
        mobile_join([kept, record, mobile_write_u64(now)?], 0, Bytes.empty())?,
        removed)
    else if U64.compare(now, U64.add(confirmed, last_resort_grace()?)?) >= 0 do
      settled_retired(retired,
        offset + 48,
        now,
        kept,
        List.append(removed, one_time_prekey_label(decode_last_resort(record)?.id)))
    else
      settled_retired(retired,
        offset + 48,
        now,
        mobile_append(kept, Bytes.slice(retired, offset, 48)?)?,
        removed)
    end
  end
end

fn settled_last_resort_writes(database_path :: String, wrapping_key :: borrow StorageKey) -> Result<(List<String>, List<Bytes>, List<String>), String> do
  let retired = load_last_resort_retired(database_path, wrapping_key)?
  let (kept, removed) = settled_retired(retired, 0, current_time()?, Bytes.empty(), List.new())?
  if Bytes.secure_equals(kept, retired) do
    Ok((List.new(), List.new(), List.new()))
  else
    Ok((["last-resort-retired/v1"],
      [seal_local(kept, wrapping_key, local_context("last-resort-retired/v1")?)?],
      removed))
  end
end

# First messages that used the reusable key, oldest first. One-time prekeys
# cannot be replayed because their secret is deleted; this one can.

fn load_last_resort_replays(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes!String do
  case load_blob(database_path, "last-resort-replays/v1") do
    Err(error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok(blob) -> open_local(blob, wrapping_key, local_context("last-resort-replays/v1")?)
  end
end

fn replay_recorded(seen :: Bytes, transcript_hash :: Bytes, offset :: Int) -> Bool!String do
  if offset >= Bytes.length(seen) do
    Ok(false)
  else if Bytes.secure_equals(Bytes.slice(seen, offset, 32)?, transcript_hash) do
    Ok(true)
  else
    replay_recorded(seen, transcript_hash, offset + 32)
  end
end

pub fn last_resort_replayed(database_path :: String,
  wrapping_key :: borrow StorageKey,
  transcript_hash :: Bytes) -> Bool!String do
  replay_recorded(load_last_resort_replays(database_path, wrapping_key)?, transcript_hash, 0)
end

pub fn seal_last_resort_replay(database_path :: String,
  wrapping_key :: borrow StorageKey,
  transcript_hash :: Bytes) -> Bytes!String do
  let seen = load_last_resort_replays(database_path, wrapping_key)?
  # ponytail: remembers the newest 1,024 first messages. Forgetting an older one
  # lets delivery replay it and reset that one session; rotate the key sooner or
  # raise the cap if a device ever sees that many exhausted-pool contacts.
  let kept = if Bytes.length(seen) >= 32768 do
    Bytes.slice(seen, 32, Bytes.length(seen) - 32)?
  else
    seen
  end
  seal_local(mobile_append(kept, transcript_hash)?,
    wrapping_key,
    local_context("last-resort-replays/v1")?)
end

fn generate_prekey_batch(profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  next_id :: U64,
  remaining :: Int,
  entries :: List<MobileOneTimePrekey>,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(List<MobileOneTimePrekey>, List<String>, List<Bytes>, U64), String> do
  if remaining <= 0 do
    Ok((entries, labels, blobs, next_id))
  else if !(valid_prekey_id(next_id)?) do
    Err("prekey_id_exhausted")
  else
    let generated = case generate_one_time_prekey(next_id) do
      Err(_) -> Err("prekey_generation_failed")
      Ok(value)
    end?
    let label = one_time_prekey_label(next_id)
    let blob = seal_x25519(generated.private_key,
      wrapping_key,
      one_time_prekey_context(profile, next_id)?)?
    generate_prekey_batch(profile,
      wrapping_key,
      U64.add(next_id, mobile_wide("1")?)?,
      remaining - 1,
      List.append(entries,
        MobileOneTimePrekey {
          id: next_id,
          public_key: generated.public_key.bytes
        }),
      List.append(labels, label),
      List.append(blobs, blob))
  end
end

fn append_prekeys(source :: List<MobileOneTimePrekey>,
  index :: Int,
  output :: List<MobileOneTimePrekey>) -> List<MobileOneTimePrekey> do
  if index >= List.length(source) do
    output
  else
    append_prekeys(source, index + 1, List.append(output, List.get(source, index)))
  end
end

fn public_prekeys(entries :: List<MobileOneTimePrekey>,
  index :: Int,
  output :: List<OneTimePrekeyPublic>) -> List<OneTimePrekeyPublic> do
  if index >= List.length(entries) do
    output
  else
    let entry = List.get(entries, index)
    public_prekeys(entries,
      index + 1,
      List.append(output,
        OneTimePrekeyPublic {
          id: entry.id,
          public_key: entry.public_key
        }))
  end
end

pub fn find_prekey(entries :: List<MobileOneTimePrekey>, id :: U64, index :: Int) -> MobileOneTimePrekey!String do
  if index >= List.length(entries) do
    Err("one_time_prekey_not_found")
  else
    let entry = List.get(entries, index)
    if U64.compare(entry.id, id) == 0 do
      Ok(entry)
    else
      find_prekey(entries, id, index + 1)
    end
  end
end

pub fn remove_prekey(entries :: List<MobileOneTimePrekey>,
  id :: U64,
  index :: Int,
  remaining :: List<MobileOneTimePrekey>) -> List<MobileOneTimePrekey> do
  if index >= List.length(entries) do
    remaining
  else
    let entry = List.get(entries, index)
    if U64.compare(entry.id, id) == 0 do
      remove_prekey(entries, id, index + 1, remaining)
    else
      remove_prekey(entries, id, index + 1, List.append(remaining, entry))
    end
  end
end

pub fn remove_prekey_id(ids :: List<U64>, id :: U64, index :: Int, remaining :: List<U64>) -> List<U64> do
  if index >= List.length(ids) do
    remaining
  else
    let value = List.get(ids, index)
    if U64.compare(value, id) == 0 do
      remove_prekey_id(ids, id, index + 1, remaining)
    else
      remove_prekey_id(ids, id, index + 1, List.append(remaining, value))
    end
  end
end

fn inactive_prekeys(entries :: List<MobileOneTimePrekey>,
  active_ids :: List<U64>,
  index :: Int,
  output :: List<MobileOneTimePrekey>) -> List<MobileOneTimePrekey> do
  if index >= List.length(entries) do
    output
  else
    let entry = List.get(entries, index)
    if contains_prekey_id(active_ids, entry.id, 0) do
      inactive_prekeys(entries, active_ids, index + 1, output)
    else
      inactive_prekeys(entries, active_ids, index + 1, List.append(output, entry))
    end
  end
end

fn signed_prekey_publication(profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  database_path :: String,
  entries :: List<MobileOneTimePrekey>,
  reusable :: MobileOneTimePrekey,
  contact_address :: Bytes) -> Bytes!String do
  let unsigned = PrekeyPublishRequest {
    account_id: profile.account_id,
    device_id: profile.device_id,
    prekeys: public_prekeys(entries, 0, List.new()),
    last_resort: Some(OneTimePrekeyPublic {
      id: reusable.id,
      public_key: reusable.public_key
    }),
    contact_address_hash: Some(Crypto.sha256(contact_address)),
    signature: Bytes.empty()
  }
  let device = open_device(profile, wrapping_key, database_path)?
  let signature = case Crypto.sign(device.signing_private_key,
    prekey_publish_signing_bytes(unsigned)?) do
    Err(_) -> Err("prekey_publication_signing_failed")
    Ok(value) -> Ok(value.bytes)
  end?
  encode_prekey_publish(%{unsigned | signature: signature})
end

pub fn replenish_prekeys(request :: MobilePrekeyRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let profile = decode_client_profile(load_profile(request.database_path)?)?
  let wrapping_key = platform_key()?
  let existing = load_prekey_pool(profile, wrapping_key, request.database_path)?
  let active_ids = load_active_prekey_pool(request.database_path, existing, wrapping_key)?
  let inactive = inactive_prekeys(existing, active_ids, 0, List.new())
  let reusable = ensure_last_resort_prekey(profile, wrapping_key, request.database_path)?
  # A new contact address is stored before the publication that names it leaves,
  # so the directory's answer finds it waiting to be confirmed.
  let (contact_address, address_labels, address_blobs) = published_contact_address(request.database_path,
    wrapping_key)?
  if List.length(address_labels) > 0 do
    store_record_changes(request.database_path, address_labels, address_blobs, List.new())
  else
    Ok(nil)
  end?
  if request.count == 0 do
    signed_prekey_publication(profile,
      wrapping_key,
      request.database_path,
      inactive,
      reusable,
      contact_address)
  else if List.length(active_ids) + request.count > 64 do
    Err("prekey_pool_full")
  else
    let next_id = load_prekey_wide(request.database_path,
      "one-time-prekey-next-id/v1",
      wrapping_key)?
    let (generated, labels, blobs, following_id) = generate_prekey_batch(profile,
      wrapping_key,
      next_id,
      request.count,
      List.new(),
      List.new(),
      List.new())?
    let publication = signed_prekey_publication(profile,
      wrapping_key,
      request.database_path,
      generated,
      reusable,
      contact_address)?
    let retired_overflow = if List.length(inactive) + request.count > 64 do
      List.length(inactive) + request.count - 64
    else
      0
    end
    let (retained, removed_labels) = retain_reconciled_prekeys(existing,
      active_ids,
      0,
      retired_overflow,
      List.new(),
      List.new())?
    let updated = append_prekeys(generated, 0, retained)
    store_prekey_batch(request.database_path,
      labels,
      blobs,
      removed_labels,
      seal_prekey_pool(updated, wrapping_key)?,
      seal_active_prekey_pool(active_ids, wrapping_key)?,
      seal_prekey_wide("one-time-prekey-next-id/v1", following_id, wrapping_key)?,
      false)?
    Ok(publication)
  end
end

fn retain_reconciled_prekeys(entries :: List<MobileOneTimePrekey>,
  active_ids :: List<U64>,
  index :: Int,
  drop_inactive :: Int,
  retained :: List<MobileOneTimePrekey>,
  removed_labels :: List<String>) -> Result<(List<MobileOneTimePrekey>, List<String>), String> do
  if index >= List.length(entries) do
    if drop_inactive == 0 do
      Ok((retained, removed_labels))
    else
      Err("invalid_prekey_reconciliation")
    end
  else
    let entry = List.get(entries, index)
    if contains_prekey_id(active_ids, entry.id, 0) do
      retain_reconciled_prekeys(entries,
        active_ids,
        index + 1,
        drop_inactive,
        List.append(retained, entry),
        removed_labels)
    else if drop_inactive > 0 do
      # ponytail: retain the newest 64 retired/in-flight secrets; if more than
      # 64 claimed initial messages remain undelivered, the oldest can no longer
      # decrypt. Add an acknowledged-delivery protocol before raising this cap.
      retain_reconciled_prekeys(entries,
        active_ids,
        index + 1,
        drop_inactive - 1,
        retained,
        List.append(removed_labels, one_time_prekey_label(entry.id)))
    else
      retain_reconciled_prekeys(entries,
        active_ids,
        index + 1,
        drop_inactive,
        List.append(retained, entry),
        removed_labels)
    end
  end
end

pub fn reconcile_prekeys(request :: MobilePrekeyReconcileRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let profile = decode_client_profile(load_profile(request.database_path)?)?
  let response = case decode_prekey_publish_response(request.response) do
    Err(_) -> Err("invalid_prekey_reconciliation")
    Ok(value)
  end?
  if !Bytes.secure_equals(response.account_id, profile.account_id) || !Bytes.secure_equals(response.device_id,
    profile.device_id) do
    Err("wrong_prekey_reconciliation_identity")
  else
    let wrapping_key = platform_key()?
    let entries = load_prekey_pool(profile, wrapping_key, request.database_path)?
    load_active_prekey_pool(request.database_path, entries, wrapping_key)?
    let entry_ids = mobile_prekey_ids(entries, 0, List.new())
    if !active_ids_belong(response.active_ids, entry_ids, 0) do
      Err("unknown_active_prekey")
    else
      let inactive_count = List.length(entries) - List.length(response.active_ids)
      let drop_inactive = if inactive_count > 64 do
        inactive_count - 64
      else
        0
      end
      let (retained, removed_labels) = retain_reconciled_prekeys(entries,
        response.active_ids,
        0,
        drop_inactive,
        List.new(),
        List.new())?
      store_prekey_reconciliation(request.database_path,
        removed_labels,
        seal_prekey_pool(retained, wrapping_key)?,
        seal_active_prekey_pool(response.active_ids, wrapping_key)?)?
      let (settled_labels, settled_blobs, settled_removals) = settled_last_resort_writes(request.database_path,
        wrapping_key)?
      if List.length(settled_labels) > 0 do
        store_record_changes(request.database_path, settled_labels, settled_blobs, settled_removals)
      else
        Ok(nil)
      end?
      # The directory answered, so the contact address the publication named is
      # live and may be handed to contacts.
      let (confirmed_labels, confirmed_blobs, confirmed_removals) = confirmed_contact_address_writes(request.database_path,
        wrapping_key)?
      if List.length(confirmed_labels) > 0 do
        store_record_changes(request.database_path,
          confirmed_labels,
          confirmed_blobs,
          confirmed_removals)
      else
        Ok(nil)
      end?
      mobile_write_u32(List.length(response.active_ids))
    end
  end
end
