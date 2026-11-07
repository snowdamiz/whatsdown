from Mobile.Sessions import parse_sync_payload, parse_sync_payload_typed, encode_sync_payload, sync_history_inner
from Protocol.V1 import InnerEnvelope
from Transport.Packet import ClientProfile

fn legacy_body_http(input :: Bytes) -> Int!String do
  let request = Http.build(:post, "https://never-contact.invalid")
  let value = parse_sync_payload(input)?
  Ok(Http.body_bytes(request, value.body))
end

fn typed_body_http(input :: Bytes) -> Int!String do
  let request = Http.build(:post, "https://never-contact.invalid")
  let value = case parse_sync_payload_typed(input) do
    Err(_) -> return Err("invalid")
    Ok(value) -> value
  end
  Ok(Http.body_bytes(request, value.body))
end

fn legacy_metadata_http(input :: Plaintext<Bytes>) -> Int!String do
  let request = Http.build(:post, "https://never-contact.invalid")
  let value = parse_sync_payload(input)?
  Ok(Http.body_bytes(request, value.peer_account_id))
end

fn typed_metadata_http(input :: Plaintext<Bytes>) -> Int!String do
  let request = Http.build(:post, "https://never-contact.invalid")
  let value = case parse_sync_payload_typed(input) do
    Err(_) -> return Err("invalid")
    Ok(value) -> value
  end
  Ok(Http.body_bytes(request, value.peer_account_id))
end

fn encoder_http(local :: ClientProfile, peer :: ClientProfile, inner :: InnerEnvelope) -> Int!String do
  let request = Http.build(:post, "https://never-contact.invalid")
  let encoded = encode_sync_payload(local, peer, inner)?
  Ok(Http.body_bytes(request, encoded))
end

fn legacy_roundtrip_http(local :: ClientProfile, peer :: ClientProfile, inner :: InnerEnvelope) -> Int!String do
  let request = Http.build(:post, "https://never-contact.invalid")
  let encoded = encode_sync_payload(local, peer, inner)?
  let value = parse_sync_payload(encoded)?
  Ok(Http.body_bytes(request, value.peer_account_id))
end

fn typed_roundtrip_http(local :: ClientProfile, peer :: ClientProfile, inner :: InnerEnvelope) -> Int!String do
  let request = Http.build(:post, "https://never-contact.invalid")
  let encoded = encode_sync_payload(local, peer, inner)?
  let value = case parse_sync_payload_typed(encoded) do
    Err(_) -> return Err("invalid")
    Ok(value) -> value
  end
  Ok(Http.body_bytes(request, value.peer_account_id))
end

fn history_body_http(local :: ClientProfile, input :: Bytes, attachment :: Bytes) -> Int!String do
  let request = Http.build(:post, "https://never-contact.invalid")
  let value = sync_history_inner(local, parse_sync_payload(input)?, attachment)?
  Ok(Http.body_bytes(request, value.body))
end

fn legacy_status_http(input :: Plaintext<Bytes>) -> Int do
  let request = Http.build(:post, "https://never-contact.invalid")
  let valid = case parse_sync_payload(input) do
    Err(_) -> false
    Ok(_) -> true
  end
  if valid do
    Http.body_bytes(request, Bytes.from_utf8("constant"))
  else
    0
  end
end

fn typed_status_http(input :: Plaintext<Bytes>) -> Int do
  let request = Http.build(:post, "https://never-contact.invalid")
  let valid = case parse_sync_payload_typed(input) do
    Err(_) -> false
    Ok(_) -> true
  end
  if valid do
    Http.body_bytes(request, Bytes.from_utf8("constant"))
  else
    0
  end
end

fn legacy_caller_control(flag :: Plaintext<Bool>, input :: Bytes) -> Int!String do
  let request = Http.build(:post, "https://never-contact.invalid")
  if flag do
    let _ = parse_sync_payload(input)?
    Ok(Http.body_bytes(request, Bytes.from_utf8("constant")))
  else
    Ok(0)
  end
end

fn typed_caller_control(flag :: Plaintext<Bool>, input :: Bytes) -> Int!String do
  let request = Http.build(:post, "https://never-contact.invalid")
  if flag do
    let _ = case parse_sync_payload_typed(input) do
      Err(_) -> return Err("invalid")
      Ok(value) -> value
    end
    Ok(Http.body_bytes(request, Bytes.from_utf8("constant")))
  else
    Ok(0)
  end
end

fn main() do nil end
