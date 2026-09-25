from Binary.Reader import BinaryReader, finish, reader
from Mobile.Codec import encode_output_list, mobile_byte, mobile_join, mobile_read_u32, mobile_zeroes, take_vector
from Mobile.Types import MobileReadBytes
from Storage.Blobs import load_blob
from Storage.Keys import local_context, open_local, seal_local

##! Whether a sent message reached anyone.
##!
##! An outbox entry is an opaque envelope, and one message fans out to several of
##! them. This record links each queued envelope that is addressed to the other
##! side to its message, so the outcome of the envelopes decides what the
##! conversation shows: a message is pending while envelopes wait and none was
##! accepted, failed once the last of them is refused for good with none
##! accepted, and sent otherwise. A delivered message leaves nothing behind.

pub struct DeliveryRecord do
  kind :: Int
  envelope_id :: Bytes
  message_id :: Bytes
end

fn link_kind() -> Int do
  1
end

fn accepted_kind() -> Int do
  2
end

fn failed_kind() -> Int do
  3
end

fn encode_record(value :: DeliveryRecord) -> Bytes!String do
  mobile_join([mobile_byte(value.kind)?, value.envelope_id, value.message_id], 0, Bytes.empty())
end

fn encode_records(values :: List<DeliveryRecord>, index :: Int, output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_records(values, index + 1, List.append(output, encode_record(List.get(values, index))?))
  end
end

fn decode_records(state :: BinaryReader, remaining :: Int, output :: List<DeliveryRecord>) -> List<DeliveryRecord>!String do
  if remaining <= 0 do
    case finish(state) do
      Err(_) -> Err("invalid_delivery_state")
      Ok(_) -> Ok(output)
    end
  else
    let record = take_vector(state, 49)?
    let length = Bytes.length(record.value)
    if length != 33 && length != 49 do
      Err("invalid_delivery_state")
    else
      let kind = case Bytes.get(record.value, 0) do
        Err(_) -> Err("invalid_delivery_state")
        Ok(value)
      end?
      if kind < 1 || kind > 3 do
        Err("invalid_delivery_state")
      else
        decode_records(record.state,
          remaining - 1,
          List.append(output,
            DeliveryRecord {
              kind: kind,
              envelope_id: Bytes.slice(record.value, 1, 16)?,
              message_id: Bytes.slice(record.value, 17, length - 17)?
            }))
      end
    end
  end
end

pub fn load_delivery(database_path :: String, wrapping_key :: borrow StorageKey) -> List<DeliveryRecord>!String do
  case load_blob(database_path, "delivery/v1") do
    Err(error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok(blob) -> do
      let encoded = open_local(blob, wrapping_key, local_context("delivery/v1")?)?
      case reader(encoded, 131072) do
        Err(_) -> Err("invalid_delivery_state")
        Ok(state) -> do
          let count = take_vector(state, 4)?
          decode_records(count.state, mobile_read_u32(count.value)?, List.new())
        end
      end
    end
  end
end

fn sealed(values :: List<DeliveryRecord>, wrapping_key :: borrow StorageKey) -> Result<(List<String>, List<Bytes>), String> do
  Ok((["delivery/v1"],
    [
      seal_local(encode_output_list(encode_records(values, 0, List.new())?)?,
        wrapping_key,
        local_context("delivery/v1")?)?
    ]))
end

fn has(values :: List<DeliveryRecord>, kind :: Int, message_id :: Bytes, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else
    let value = List.get(values, index)
    (value.kind == kind && Bytes.secure_equals(value.message_id, message_id)) || has(values,
      kind,
      message_id,
      index + 1)
  end
end

# 0 sent, 1 pending, 2 failed.

pub fn delivery_state(values :: List<DeliveryRecord>, message_id :: Bytes) -> Int do
  if has(values, failed_kind(), message_id, 0) do
    2
  else if has(values, link_kind(), message_id, 0) && !has(values, accepted_kind(), message_id, 0) do
    1
  else
    0
  end
end

fn without(values :: List<DeliveryRecord>,
  kind :: Int,
  message_id :: Bytes,
  index :: Int,
  output :: List<DeliveryRecord>) -> List<DeliveryRecord> do
  if index >= List.length(values) do
    output
  else
    let value = List.get(values, index)
    if value.kind == kind && Bytes.secure_equals(value.message_id, message_id) do
      without(values, kind, message_id, index + 1, output)
    else
      without(values, kind, message_id, index + 1, List.append(output, value))
    end
  end
end

fn marker(kind :: Int, message_id :: Bytes) -> DeliveryRecord!String do
  Ok(DeliveryRecord {
    kind: kind,
    envelope_id: mobile_zeroes(16)?,
    message_id: message_id
  })
end

fn count_kind(values :: List<DeliveryRecord>, kind :: Int, index :: Int, total :: Int) -> Int do
  if index >= List.length(values) do
    total
  else if List.get(values, index).kind == kind do
    count_kind(values, kind, index + 1, total + 1)
  else
    count_kind(values, kind, index + 1, total)
  end
end

fn drop_first(values :: List<DeliveryRecord>,
  kind :: Int,
  dropped :: Bool,
  index :: Int,
  output :: List<DeliveryRecord>) -> List<DeliveryRecord> do
  if index >= List.length(values) do
    output
  else
    let value = List.get(values, index)
    if !dropped && value.kind == kind do
      drop_first(values, kind, true, index + 1, output)
    else
      drop_first(values, kind, dropped, index + 1, List.append(output, value))
    end
  end
end

fn add_links(values :: List<DeliveryRecord>,
  message_id :: Bytes,
  envelope_ids :: List<Bytes>,
  index :: Int) -> List<DeliveryRecord> do
  if index >= List.length(envelope_ids) do
    values
  else
    add_links(List.append(values,
        DeliveryRecord {
          kind: link_kind(),
          envelope_id: List.get(envelope_ids, index),
          message_id: message_id
        }),
      message_id,
      envelope_ids,
      index + 1)
  end
end

# The envelopes of one message that are addressed to the other side. Nothing is
# written for a message with none (its own devices only, or control traffic).

pub fn tracked_delivery(database_path :: String,
  wrapping_key :: borrow StorageKey,
  message_id :: Bytes,
  envelope_ids :: List<Bytes>) -> Result<(List<String>, List<Bytes>), String> do
  let length = Bytes.length(message_id)
  if List.length(envelope_ids) == 0 || (length != 16 && length != 32) do
    Ok((List.new(), List.new()))
  else
    sealed(add_links(load_delivery(database_path, wrapping_key)?, message_id, envelope_ids, 0),
      wrapping_key)
  end
end

fn linked_message(values :: List<DeliveryRecord>, envelope_id :: Bytes, index :: Int) -> Option<Bytes> do
  if index >= List.length(values) do
    None
  else
    let value = List.get(values, index)
    if value.kind == link_kind() && Bytes.secure_equals(value.envelope_id, envelope_id) do
      Some(value.message_id)
    else
      linked_message(values, envelope_id, index + 1)
    end
  end
end

fn without_link(values :: List<DeliveryRecord>,
  envelope_id :: Bytes,
  index :: Int,
  output :: List<DeliveryRecord>) -> List<DeliveryRecord> do
  if index >= List.length(values) do
    output
  else
    let value = List.get(values, index)
    if value.kind == link_kind() && Bytes.secure_equals(value.envelope_id, envelope_id) do
      without_link(values, envelope_id, index + 1, output)
    else
      without_link(values, envelope_id, index + 1, List.append(output, value))
    end
  end
end

fn resolved(values :: List<DeliveryRecord>, message_id :: Bytes, accepted :: Bool) -> List<DeliveryRecord>!String do
  let waiting = has(values, link_kind(), message_id, 0)
  let reached = accepted || has(values, accepted_kind(), message_id, 0)
  let cleared = without(values, accepted_kind(), message_id, 0, List.new())
  if waiting && reached do
    Ok(List.append(cleared, marker(accepted_kind(), message_id)?))
  else if waiting || reached do
    Ok(cleared)
  else
    # ponytail: remembers the newest 1,024 failed messages; an older one would
    # read as sent again. Prune with the history instead if that is ever reached.
    let bounded = if count_kind(cleared, failed_kind(), 0, 0) >= 1024 do
      drop_first(cleared, failed_kind(), false, 0, List.new())
    else
      cleared
    end
    Ok(List.append(bounded, marker(failed_kind(), message_id)?))
  end
end

# An envelope left the outbox: accepted by the service, or refused for good.
# Nothing is written for an envelope that was never tracked.

pub fn resolved_delivery(database_path :: String,
  wrapping_key :: borrow StorageKey,
  envelope_id :: Bytes,
  accepted :: Bool) -> Result<(List<String>, List<Bytes>), String> do
  let values = load_delivery(database_path, wrapping_key)?
  case linked_message(values, envelope_id, 0) do
    None -> Ok((List.new(), List.new()))
    Some(message_id) -> sealed(resolved(without_link(values, envelope_id, 0, List.new()),
        message_id,
        accepted)?,
      wrapping_key)
  end
end
