from Mobile.Sessions import parse_sync_payload, parse_sync_payload_typed, encode_sync_payload
from Protocol.V1 import InnerEnvelope
from Transport.Packet import ClientProfile
from Storage.Keys import seal_local

fn public_literal() -> Int do
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8("public control"))
end

fn legacy_routing(input :: Bytes) -> Int!String do
  let value = parse_sync_payload(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.peer_account_id))
end

fn typed_routing(input :: Bytes) -> Int!String do
  let value = case parse_sync_payload_typed(input) do
    Err(_) -> return Err("invalid")
    Ok(value) -> value
  end
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.peer_account_id))
end

fn encode_then_seal(local :: ClientProfile, peer :: ClientProfile, inner :: InnerEnvelope,
  key :: borrow StorageKey) -> Bytes!String do
  let encoded = encode_sync_payload(local, peer, inner)?
  seal_local(encoded, key, Bytes.from_utf8("synthetic-sync-proof"))
end

fn main() do nil end
