from Protocol.EnvelopeWire import decode_inner_envelope, encode_inner_envelope
from Groups.GroupPayload import decode_group_payload, encode_group_payload
from Groups.Expiry import decode_timed_group_payload, encode_timed_group_payload
from Mobile.HistoryWire import decode_history, encode_history
from Storage.Keys import seal_local

fn public_literal() -> Int do
  Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), Bytes.from_utf8("public control"))
end

fn direct_routing(input :: Bytes) -> Int!String do
  let value = case decode_inner_envelope(input) do
    Err(_) -> return Err("invalid_inner")
    Ok(value) -> value
  end
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.conversation_id))
end

fn group_routing(input :: Bytes) -> Int!String do
  let value = decode_group_payload(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"), value.recipient_account))
end

fn timed_framing(input :: Bytes) -> Int!String do
  let value = decode_timed_group_payload(input)?
  Ok(Http.body_bytes(Http.build(:post, "https://never-contact.invalid"),
    Bytes.from_utf8(Int.to_string(value.disappearing_seconds))))
end

fn direct_seal(input :: Bytes, key :: borrow StorageKey) -> Bytes!String do
  let value = case decode_inner_envelope(input) do
    Err(_) -> return Err("invalid_inner")
    Ok(value) -> value
  end
  seal_local(value.body, key, Bytes.from_utf8("decoded-body-proof"))
end

fn direct_reencode_seal(input :: Bytes, key :: borrow StorageKey) -> Bytes!String do
  let value = case decode_inner_envelope(input) do
    Err(_) -> return Err("invalid_inner")
    Ok(value) -> value
  end
  let encoded = case encode_inner_envelope(value) do
    Err(_) -> return Err("invalid_inner")
    Ok(value) -> value
  end
  seal_local(encoded, key, Bytes.from_utf8("decoded-body-proof"))
end

fn group_reencode_seal(input :: Bytes, key :: borrow StorageKey) -> Bytes!String do
  seal_local(encode_group_payload(decode_group_payload(input)?)?, key,
    Bytes.from_utf8("decoded-body-proof"))
end

fn timed_reencode_seal(input :: Bytes, key :: borrow StorageKey) -> Bytes!String do
  seal_local(encode_timed_group_payload(decode_timed_group_payload(input)?)?, key,
    Bytes.from_utf8("decoded-body-proof"))
end

fn history_reencode_seal(input :: Bytes, key :: borrow StorageKey) -> Bytes!String do
  seal_local(encode_history(decode_history(input)?)?, key, Bytes.from_utf8("decoded-body-proof"))
end

@display("compile-only decoded-body fixture checks the native display return permission; no probe executes")
@export("decoded_body_fixture_display") pub fn fixture_display(input :: Bytes) -> Plaintext<Bytes>!String do
  let value = decode_group_payload(input)?
  Ok(value.body)
end

fn main() do nil end
