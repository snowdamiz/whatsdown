from MobileCore import outbox_ack_export
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.MailboxWire import decode_mailbox_ack, encode_delivery_batch
from Protocol.V1 import DeliveredEnvelope, MailboxAck, OuterEnvelope
from Tests.Support import append, vector

fn group_request_parts(values :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    group_request_parts(values, index + 1, append(output, vector(List.get(values, index)) ?) ?)
  end
end

pub fn group_vectors(values :: List < Bytes >) -> Bytes ! String do
  group_request_parts(values, 0, Bytes.empty())
end

fn group_wide(value :: String) -> U64 ! String do
  case U64.parse(value) do
    Err( _) -> Err("test integer conversion failed")
    Ok( parsed) -> Ok(parsed)
  end
end

pub fn outer(input :: Bytes) -> OuterEnvelope ! String do
  case decode_outer_envelope(input) do
    Err( _) -> Err("outer envelope decode failed")
    Ok( value) -> Ok(value)
  end
end

pub fn ack(input :: Bytes) -> MailboxAck ! String do
  case decode_mailbox_ack(input) do
    Err( _) -> Err("mailbox ack decode failed")
    Ok( value) -> Ok(value)
  end
end

pub fn delivery_batch(envelope :: Bytes) -> Bytes ! String do
  case encode_delivery_batch([DeliveredEnvelope {
    sequence : group_wide("1") ?,
    envelope : envelope
  }]) do
    Err( _) -> Err("delivery batch encode failed")
    Ok( value) -> Ok(value)
  end
end

pub fn read_u32_at(input :: Bytes, offset :: Int) -> Int ! String do
  case Bytes.read_u32_be(input, offset) do
    Err( _) -> Err("output list decode failed")
    Ok( value) -> case U64.to_int(value) do
      Err( _) -> Err("output list decode failed")
      Ok( parsed) -> Ok(parsed)
    end
  end
end

fn output_parts(input :: Bytes, count :: Int, index :: Int, offset :: Int, items :: List < Bytes >) -> List < Bytes > ! String do
  if index >= count do
    if offset == Bytes.length(input) do
      Ok(items)
    else
      Err("output list decode failed")
    end
  else
    let length = read_u32_at(input, offset) ?
    let item = Bytes.slice(input, offset + 4, length) ?
    output_parts(input, count, index + 1, offset + 4 + length, List.append(items, item))
  end
end

pub fn output_list(input :: Bytes) -> List < Bytes > ! String do
  if Bytes.length(input) < 8 || read_u32_at(input, 0) ? != 4 do
    Err("output list decode failed")
  else
    let count = read_u32_at(input, 4) ?
    if count < 0 || count > 64 do
      Err("output list decode failed")
    else
      output_parts(input, count, 0, 8, List.new())
    end
  end
end

pub fn envelope_for(values :: List < Bytes >, mailbox :: Bytes, index :: Int) -> Bytes ! String do
  if index >= List.length(values) do
    Err("group delivery missing")
  else
    let value = List.get(values, index)
    if Bytes.secure_equals(outer(value) ?.mailbox_token, mailbox) do
      Ok(value)
    else
      envelope_for(values, mailbox, index + 1)
    end
  end
end

pub fn acknowledge(path :: String, envelopes :: List < Bytes >, index :: Int) -> Result <(), String > do
  if index >= List.length(envelopes) do
    Ok(nil)
  else
    let envelope = List.get(envelopes, index)
    if Bytes.length(outbox_ack_export(group_vectors([Bytes.from_utf8(path), envelope]) ?) ?) != 0 do
      Err("outbox acknowledgement failed")
    else
      acknowledge(path, envelopes, index + 1)
    end
  end
end
