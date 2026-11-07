from Protocol.EnvelopeWire import decode_inner_envelope
from Groups.GroupPayload import decode_group_payload, decode_expiring_group_payload
from Groups.Expiry import decode_timed_group_payload
from Mobile.HistoryWire import decode_history
from Storage.HistoryBlobs import open_history_blob

fn inner_body_http(input :: Bytes) -> Int!String do
  let value = case decode_inner_envelope(input) do
    Err(_) -> return Err("invalid_inner")
    Ok(value) -> value
  end
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.body))
end

fn group_body_http(input :: Bytes) -> Int!String do
  let value = decode_group_payload(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.body))
end

fn timed_group_body_http(input :: Bytes) -> Int!String do
  let value = decode_timed_group_payload(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.payload.body))
end

fn expiring_group_body_http(input :: Bytes) -> Int!String do
  let value = decode_expiring_group_payload(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.body))
end

fn history_body_http(input :: Bytes) -> Int!String do
  let entries = decode_history(input)?
  let entry = List.head(entries)
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), entry.inner.body))
end

fn restored_history_body_http(blob :: Bytes, key :: borrow StorageKey, label :: String) -> Int!String do
  let entries = decode_history(open_history_blob(blob, key, label)?)?
  let entry = List.head(entries)
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), entry.inner.body))
end

fn public_http_control() -> Int do
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8("public control"))
end

fn main() do nil end
