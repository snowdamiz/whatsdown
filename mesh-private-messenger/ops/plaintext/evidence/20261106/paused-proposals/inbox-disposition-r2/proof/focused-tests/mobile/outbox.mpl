from Storage.OutboxGuard import OutboxBasis, PreparedOutboxIndex
from Storage.OutboxSettlement import OutboxSettlementSnapshot, commit_outbox_settlement
from Transport.Packet import ClientProfile, encode_client_profile, decode_client_profile
from Mobile.Profile import load_profile
from Mobile.PostageQueue import postage_owned_ids
from Binary.Reader import BinaryReader, finish, reader
from Mobile.Codec import (
  canonical_outer,
  encode_output_list,
  mobile_append,
  mobile_read_u32,
  mobile_write_u32,
  take_vector
)
from Mobile.ContactAddress import RefusedAddressSnapshot, refused_address_snapshot
from Mobile.Delivery import resolved_delivery, tracked_delivery
from Mobile.Types import MobilePayloadRequest, MobileReadBytes
from Protocol.V1 import OuterEnvelope
from Storage.Blobs import ensure_schema, load_blob, put_blob
from Storage.Keys import local_context, open_local, platform_key, seal_local
from Storage.Records import delete_blob, delete_blobs, put_blobs, with_record_transaction

##! Mobile.Outbox implementation.
# ponytail: a count, so the worst case is 256 envelopes of 64 KiB (16 MiB) on
# this device; ordinary messages are a few hundred bytes. Budget bytes instead,
# with sizes kept in the index, if that ever matters. It is this large because
# an envelope for a recipient who cannot take it now waits here, for up to
# thirty days, while everything else keeps flowing past it.

pub fn outbox_capacity() -> Int do
  256
end

fn decode_outbox_ids_parts(state :: BinaryReader,
  count :: Int,
  index :: Int,
  ids :: List<Bytes>) -> List<Bytes>!String do
  if index >= count do
    case finish(state) do
      Err(_) -> Err("invalid_outbox")
      Ok(_) -> Ok(ids)
    end
  else
    let id = take_vector(state, 16)?
    if Bytes.length(id.value) != 16 do
      Err("invalid_outbox")
    else
      decode_outbox_ids_parts(id.state, count, index + 1, List.append(ids, id.value))
    end
  end
end

fn decode_outbox_ids(input :: Bytes) -> List<Bytes>!String do
  case reader(input, 8192) do
    Err(_) -> Err("invalid_outbox")
    Ok(state) -> do
      let count = take_vector(state, 4)?
      let count_value = mobile_read_u32(count.value)?
      if count_value > outbox_capacity() do
        Err("invalid_outbox")
      else
        decode_outbox_ids_parts(count.state, count_value, 0, List.new())
      end
    end
  end
end

fn outbox_entry_label(id :: Bytes) -> String!String do
  if Bytes.length(id) != 16 do
    Err("invalid_outbox")
  else
    Ok("outbox-envelope/v1/#{Bytes.to_hex(id)}")
  end
end

fn outbox_tail_label(id :: Bytes) -> String!String do
  if Bytes.length(id) != 16 do
    Err("invalid_outbox")
  else
    Ok("outbox-envelope-tail/v1/#{Bytes.to_hex(id)}")
  end
end

pub fn load_outbox_ids(database_path :: String,
  wrapping_key :: borrow StorageKey) -> List<Bytes>!String do
  case load_blob(database_path, "outbox/v1") do
    Err(error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok(blob) -> decode_outbox_ids(open_local(blob, wrapping_key, local_context("outbox/v1")?)?)
  end
end

fn outbox_contains(ids :: List<Bytes>, id :: Bytes, index :: Int) -> Bool do
  if index >= List.length(ids) do
    false
  else if Bytes.secure_equals(List.get(ids, index), id) do
    true
  else
    outbox_contains(ids, id, index + 1)
  end
end

fn prepare_outbox(envelopes :: List<Bytes>,
  wrapping_key :: borrow StorageKey,
  index :: Int,
  ids :: List<Bytes>,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(List<Bytes>, List<String>, List<Bytes>), String> do
  if index >= List.length(envelopes) do
    Ok((ids, labels, blobs))
  else
    let envelope = List.get(envelopes, index)
    let outer = canonical_outer(envelope)?
    let label = outbox_entry_label(outer.envelope_id)?
    let envelope_length = Bytes.length(envelope)
    if envelope_length > 65606 || outbox_contains(ids, outer.envelope_id, 0) do
      Err("invalid_outbox")
    else
      let head_length = if envelope_length > 65532 do
        65532
      else
        envelope_length
      end
      let head = mobile_append(mobile_write_u32(envelope_length)?,
        Bytes.slice(envelope, 0, head_length)?)?
      let head_blob = seal_local(head, wrapping_key, local_context(label)?)?
      if envelope_length == head_length do
        prepare_outbox(envelopes,
          wrapping_key,
          index + 1,
          List.append(ids, outer.envelope_id),
          List.append(labels, label),
          List.append(blobs, head_blob))
      else
        let tail_label = outbox_tail_label(outer.envelope_id)?
        let tail = Bytes.slice(envelope, head_length, envelope_length - head_length)?
        prepare_outbox(envelopes,
          wrapping_key,
          index + 1,
          List.append(ids, outer.envelope_id),
          List.append(List.append(labels, label), tail_label),
          List.append(List.append(blobs, head_blob),
            seal_local(tail, wrapping_key, local_context(tail_label)?)?))
      end
    end
  end
end

fn slice(values :: List<Bytes>, start :: Int, stop :: Int, output :: List<Bytes>) -> List<Bytes> do
  if start >= stop || start >= List.length(values) do
    output
  else
    slice(values, start + 1, stop, List.append(output, List.get(values, start)))
  end
end

# `tracked_count` envelopes, starting at `tracked_from`, are the ones addressed
# to the other side of `message_id`: what happens to them decides whether the
# conversation shows the message as sent. Pass an empty identifier and zero for
# envelopes that carry no message a person would look for.

pub fn prepare_outbox_writes(wrapping_key :: borrow StorageKey,
  existing_ids :: List<Bytes>,
  envelopes :: List<Bytes>,
  database_path :: String,
  message_id :: Bytes,
  tracked_from :: Int,
  tracked_count :: Int,
  profile :: ClientProfile) -> Result<(List<String>, List<Bytes>, PreparedOutboxIndex), String> do
  let before = outbox_basis(database_path,
    wrapping_key,
    encode_client_profile(profile.entry, profile.account_id, profile.device_id)?)?
  let indexed = ids_from_basis(before, wrapping_key)?
  if !Bytes.secure_equals(encode_output_list(indexed)?, encode_output_list(existing_ids)?) do
    return Err("outbox_state_changed")
  end
  if List.length(existing_ids) + List.length(envelopes) > outbox_capacity() do
    Err("outbox_full")
  else
    let (ids, labels, blobs) = prepare_outbox(envelopes,
      wrapping_key,
      0,
      existing_ids,
      List.new(),
      List.new())?
    let index_blob = seal_local(encode_output_list(ids)?,
      wrapping_key,
      local_context("outbox/v1")?)?
    let first = List.length(existing_ids) + tracked_from
    let (delivery_labels, delivery_blobs) = tracked_delivery(database_path,
      wrapping_key,
      message_id,
      slice(ids, first, first + tracked_count, List.new()))?
    Ok((List.concat(labels, delivery_labels),
      List.concat(blobs, delivery_blobs),
      PreparedOutboxIndex { value: index_blob, before: before }))
  end
end

pub fn load_outbox_entry(database_path :: String,
  wrapping_key :: borrow StorageKey,
  id :: Bytes) -> Bytes!String do
  let label = outbox_entry_label(id)?
  let head = open_local(load_blob(database_path, label)?, wrapping_key, local_context(label)?)?
  if Bytes.length(head) < 4 do
    Err("invalid_outbox")
  else
    let envelope_length = mobile_read_u32(Bytes.slice(head, 0, 4)?)?
    let head_length = Bytes.length(head) - 4
    if envelope_length > 65606 || envelope_length < head_length || head_length > 65532 do
      Err("invalid_outbox")
    else
      let head_value = Bytes.slice(head, 4, head_length)?
      let value = if envelope_length == head_length do
        Ok(head_value)
      else if head_length != 65532 || envelope_length - head_length > 74 do
        Err("invalid_outbox")
      else
        let tail_label = outbox_tail_label(id)?
        let tail = open_local(load_blob(database_path, tail_label)?,
          wrapping_key,
          local_context(tail_label)?)?
        if Bytes.length(tail) != envelope_length - head_length do
          Err("invalid_outbox")
        else
          mobile_append(head_value, tail)
        end
      end?
      let outer = canonical_outer(value)?
      if Bytes.secure_equals(outer.envelope_id, id) do
        Ok(value)
      else
        Err("invalid_outbox")
      end
    end
  end
end

fn load_outbox_entries(database_path :: String,
  wrapping_key :: borrow StorageKey,
  ids :: List<Bytes>,
  index :: Int,
  entries :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(ids) || List.length(entries) >= 8 do
    Ok(entries)
  else
    load_outbox_entries(database_path,
      wrapping_key,
      ids,
      index + 1,
      List.append(entries, load_outbox_entry(database_path, wrapping_key, List.get(ids, index))?))
  end
end

fn remove_outbox_id(ids :: List<Bytes>,
  id :: Bytes,
  index :: Int,
  remaining :: List<Bytes>) -> List<Bytes> do
  if index >= List.length(ids) do
    remaining
  else if Bytes.secure_equals(List.get(ids, index), id) do
    remove_outbox_id(ids, id, index + 1, remaining)
  else
    remove_outbox_id(ids, id, index + 1, List.append(remaining, List.get(ids, index)))
  end
end

pub fn optional_outbox_blob(path :: String, label :: String) -> Bytes!String do
  case load_blob(path, label) do
    Ok(value)
    Err("local_state_not_found") -> Ok(Bytes.empty())
    Err(error)
  end
end

pub fn outbox_basis(path :: String,
  wrapping :: borrow StorageKey,
  profile :: Bytes) -> OutboxBasis!String do
  let sealed_profile = load_blob(path, "profile/v1")?
  if !Bytes.secure_equals(open_local(sealed_profile, wrapping, local_context("profile/v1")?)?,
    profile) do
    return Err("outbox_identity_changed")
  end
  Ok(OutboxBasis {
    profile: sealed_profile,
    index: optional_outbox_blob(path, "outbox/v1")?,
    postage: optional_outbox_blob(path, "postage-queue/v1")?,
    delivery: optional_outbox_blob(path, "delivery/v1")?
  })
end

pub fn ids_from_basis(before :: OutboxBasis, wrapping :: borrow StorageKey) -> List<Bytes>!String do
  if Bytes.length(before.index) == 0 do
    Ok([])
  else
    decode_outbox_ids(open_local(before.index, wrapping, local_context("outbox/v1")?)?)
  end
end

pub fn list_outbox(database_path :: String) -> Bytes!String do
  ensure_schema(database_path)?
  let wrapping_key = platform_key()?
  encode_output_list(load_outbox_entries(database_path,
    wrapping_key,
    ordinary_outbox_ids(database_path, wrapping_key)?,
    0,
    List.new())?)
end

# Entries from `offset` on, eight at a time. A sender that leaves an envelope
# queued, because its recipient cannot take it now, passes it by counting it.

pub fn page_outbox(request :: MobilePayloadRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let offset = mobile_read_u32(request.payload)?
  let wrapping_key = platform_key()?
  encode_output_list(load_outbox_entries(request.database_path,
    wrapping_key,
    ordinary_outbox_ids(request.database_path, wrapping_key)?,
    offset,
    List.new())?)
end

pub fn acknowledge_outbox(request :: MobilePayloadRequest) -> Bytes!String do
  settle_outbox(request, true)
end

# The service will never accept this envelope. It leaves the outbox like an
# accepted one, but counts against its message instead of for it.

pub fn fail_outbox(request :: MobilePayloadRequest) -> Bytes!String do
  settle_outbox(request, false)
end

fn settle_outbox(request :: MobilePayloadRequest, accepted :: Bool) -> Bytes!String do
  let profile = load_profile(request.database_path)?
  settle_outbox_current(request, profile, accepted, false, 0)?
  Ok(Bytes.empty())
end

pub fn settle_ordinary_outbox(request :: MobilePayloadRequest,
  profile :: Bytes,
  accepted :: Bool) -> Bool!String do
  settle_outbox_current(request, profile, accepted, true, 0)
end

fn settle_outbox_current(request :: MobilePayloadRequest,
  profile :: Bytes,
  accepted :: Bool,
  ordinary :: Bool,
  attempt :: Int) -> Bool!String do
  ensure_schema(request.database_path)?
  let envelope = canonical_outer(request.payload)?
  let wrapping = platform_key()?
  let before = outbox_basis(request.database_path, wrapping, profile)?
  let ids = ids_from_basis(before, wrapping)?
  if !outbox_contains(ids, envelope.envelope_id, 0) do
    return Ok(false)
  end
  if ordinary
    && List.contains(postage_owned_ids(request.database_path, wrapping)?, envelope.envelope_id) do
    return Err("outbox_postage_owned")
  end
  if !Bytes.secure_equals(load_outbox_entry(request.database_path, wrapping, envelope.envelope_id)?,
    request.payload) do
    return Err("outbox_ack_mismatch")
  end
  let remaining = remove_outbox_id(ids, envelope.envelope_id, 0, [])
  let index_blob = if List.length(remaining) == 0 do
    Bytes.empty()
  else
    seal_local(encode_output_list(remaining)?, wrapping, local_context("outbox/v1")?)?
  end
  let (labels, blobs) = resolved_delivery(request.database_path,
    wrapping,
    envelope.envelope_id,
    accepted)?
  let aliases = if accepted do
    RefusedAddressSnapshot { labels: [], previous: [] }
  else
    refused_address_snapshot(request.database_path, wrapping, envelope.mailbox_token)?
  end
  let entry_labels = [
    outbox_entry_label(envelope.envelope_id)?,
    outbox_tail_label(envelope.envelope_id)?
  ]
  let entry_blobs = for label in entry_labels do
    optional_outbox_blob(request.database_path, label)?
  end
  let removed = entry_labels ++ aliases.labels
  let snapshots = entry_blobs ++ aliases.previous
  let committed = commit_outbox_settlement(request.database_path,
    OutboxSettlementSnapshot {
      profile: before.profile,
      index: before.index,
      postage: before.postage,
      delivery: before.delivery,
      guarded_labels: removed,
      guarded_blobs: snapshots
    },
    index_blob,
    labels,
    blobs,
    removed)
  case committed do
    Err("outbox_state_changed") -> if attempt < 3 do
      settle_outbox_current(request, profile, accepted, ordinary, attempt + 1)
    else
      Err("outbox_state_changed")
    end
    Ok(_) -> Ok(true)
    Err(error)
  end
end

# Postage loads its E2E outer frames from durable native outbox records. The
# caller supplies bounded IDs, never replacement ciphertext or recipient keys.
pub fn load_postage_outbox_entries(database_path :: String,
  wrapping_key :: borrow StorageKey,
  ids :: List<Bytes>) -> List<Bytes>!String do
  if List.length(ids) < 1 || List.length(ids) > 8 do
    return Err("invalid_postage_outbox")
  end
  let existing = load_outbox_ids(database_path, wrapping_key)?
  let values = for index in 0..List.length(ids) do
    let id = List.get(ids, index)
    if Bytes.length(id) != 16 || !List.contains(existing, id) do
      return Err("invalid_postage_outbox")
    end
    for prior in 0..index do
      if Bytes.secure_equals(List.get(ids, prior), id) do
        return Err("invalid_postage_outbox")
      end
    end
    load_outbox_entry(database_path, wrapping_key, id)?
  end
  Ok(values)
end

fn ordinary_outbox_ids(path :: String, wrapping :: borrow StorageKey) -> List<Bytes>!String do
  let owned = postage_owned_ids(path, wrapping)?
  Ok(List.filter(load_outbox_ids(path, wrapping)?, fn(id) -> !List.contains(owned, id) end))
end
