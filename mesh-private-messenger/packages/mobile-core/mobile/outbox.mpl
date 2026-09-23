from Binary.Reader import BinaryReader, finish, reader
from Mobile.Codec import (
  canonical_outer,
  encode_output_list,
  mobile_append,
  mobile_read_u32,
  mobile_write_u32,
  take_vector
)
from Mobile.ContactAddress import refused_address_removals
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

fn decode_outbox_ids_parts(state :: BinaryReader, count :: Int, index :: Int, ids :: List<Bytes>) -> List<Bytes>!String do
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

pub fn load_outbox_ids(database_path :: String, wrapping_key :: borrow StorageKey) -> List<Bytes>!String do
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
  tracked_count :: Int) -> Result<(List<String>, List<Bytes>, Bytes), String> do
  if List.length(existing_ids) + List.length(envelopes) > outbox_capacity() do
    Err("outbox_full")
  else
    let (ids, labels, blobs) = prepare_outbox(envelopes,
      wrapping_key,
      0,
      existing_ids,
      List.new(),
      List.new())?
    let index_blob = seal_local(encode_output_list(ids)?, wrapping_key, local_context("outbox/v1")?)?
    let first = List.length(existing_ids) + tracked_from
    let (delivery_labels, delivery_blobs) = tracked_delivery(database_path,
      wrapping_key,
      message_id,
      slice(ids, first, first + tracked_count, List.new()))?
    Ok((List.concat(labels, delivery_labels), List.concat(blobs, delivery_blobs), index_blob))
  end
end

fn load_outbox_entry(database_path :: String, wrapping_key :: borrow StorageKey, id :: Bytes) -> Bytes!String do
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

fn remove_outbox_id(ids :: List<Bytes>, id :: Bytes, index :: Int, remaining :: List<Bytes>) -> List<Bytes> do
  if index >= List.length(ids) do
    remaining
  else if Bytes.secure_equals(List.get(ids, index), id) do
    remove_outbox_id(ids, id, index + 1, remaining)
  else
    remove_outbox_id(ids, id, index + 1, List.append(remaining, List.get(ids, index)))
  end
end

fn update_outbox_index(database :: SqliteConn, remaining :: List<Bytes>, index_blob :: Bytes) -> Result<(), String> do
  if List.length(remaining) == 0 do
    delete_blob(database, "outbox/v1")
  else
    put_blob(database, "outbox/v1", index_blob)
  end
end

fn store_outbox_ack(database_path :: String,
  id :: Bytes,
  remaining :: List<Bytes>,
  index_blob :: Bytes,
  delivery_labels :: List<String>,
  delivery_blobs :: List<Bytes>,
  removed_labels :: List<String>) -> Result<(), String> do
  with_record_transaction(database_path,
    fn (database) do
      delete_blob(database, outbox_entry_label(id)?)?
      delete_blob(database, outbox_tail_label(id)?)?
      update_outbox_index(database, remaining, index_blob)?
      put_blobs(database, delivery_labels, delivery_blobs, 0)?
      delete_blobs(database, removed_labels, 0)
    end)
end

pub fn list_outbox(database_path :: String) -> Bytes!String do
  ensure_schema(database_path)?
  let wrapping_key = platform_key()?
  encode_output_list(load_outbox_entries(database_path,
    wrapping_key,
    load_outbox_ids(database_path, wrapping_key)?,
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
    load_outbox_ids(request.database_path, wrapping_key)?,
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
  ensure_schema(request.database_path)?
  let envelope = canonical_outer(request.payload)?
  let wrapping_key = platform_key()?
  let ids = load_outbox_ids(request.database_path, wrapping_key)?
  if !outbox_contains(ids, envelope.envelope_id, 0) do
    Ok(Bytes.empty())
  else if !Bytes.secure_equals(load_outbox_entry(request.database_path,
      wrapping_key,
      envelope.envelope_id)?,
    request.payload) do
    Err("outbox_ack_mismatch")
  else
    let remaining = remove_outbox_id(ids, envelope.envelope_id, 0, List.new())
    let index_blob = if List.length(remaining) == 0 do
      Bytes.empty()
    else
      seal_local(encode_output_list(remaining)?, wrapping_key, local_context("outbox/v1")?)?
    end
    let (delivery_labels, delivery_blobs) = resolved_delivery(request.database_path,
      wrapping_key,
      envelope.envelope_id,
      accepted)?
    # An address the directory refuses for good is not used again: if it was a
    # contact address someone handed over, the next message goes to their public one.
    let removed_labels = if accepted do
      List.new()
    else
      refused_address_removals(request.database_path, wrapping_key, envelope.mailbox_token)?
    end
    store_outbox_ack(request.database_path,
      envelope.envelope_id,
      remaining,
      index_blob,
      delivery_labels,
      delivery_blobs,
      removed_labels)?
    Ok(Bytes.empty())
  end
end
