from Mobile.Requests import parse_start_request, parse_group_send_request, parse_fanout_request
from Mobile.FanoutNetwork import parse_fanout_action
from Mobile.Sessions import parse_sync_payload, encode_sync_payload
from Protocol.EnvelopeWire import encode_inner_envelope
from Protocol.V1 import InnerEnvelope
from Transport.Packet import ClientProfile

fn refuse_start(input :: Bytes) -> Int!String do
  let value = parse_start_request(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.body))
end
fn refuse_group_send(input :: Bytes) -> Int!String do
  let value = parse_group_send_request(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.body))
end
fn refuse_sync(input :: Bytes) -> Int!String do
  let value = parse_sync_payload(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.body))
end
fn refuse_start_encoded(input :: Bytes, timestamp :: U64) -> Int!String do
  let request = parse_start_request(input)?
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: Bytes.empty(),
    sender_device_id: Bytes.empty(),
    recipient_device_id: Bytes.empty(),
    conversation_id: Bytes.empty(),
    client_message_id: Bytes.empty(),
    client_timestamp: timestamp,
    message_type: 1,
    body: request.body,
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  }
  case encode_inner_envelope(inner) do
    Err(_) -> Err("failed")
    Ok(encoded) -> Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), encoded))
  end
end
fn refuse_action(input :: Bytes) -> Int!String do
  let action = parse_fanout_action(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), action.body))
end
fn refuse_fanout(input :: Bytes) -> Int!String do
  let request = parse_fanout_request(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), request.body))
end
fn refuse_sync_encoding(input :: Bytes, local :: ClientProfile, peer :: ClientProfile, timestamp :: U64) -> Int!String do
  let request = parse_fanout_request(input)?
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: Bytes.empty(),
    sender_device_id: Bytes.empty(),
    recipient_device_id: Bytes.empty(),
    conversation_id: Bytes.empty(),
    client_message_id: Bytes.empty(),
    client_timestamp: timestamp,
    message_type: 1,
    body: request.body,
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  }
  let encoded = encode_sync_payload(local, peer, inner)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), encoded))
end
fn main() do nil end
