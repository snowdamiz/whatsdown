from Protocol.DirectoryWire import (
  decode_directory_entry,
  decode_directory_lookup,
  encode_directory_entry,
  encode_directory_lookup
)
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.MailboxWire import (
  decode_delivery_batch,
  decode_mailbox_ack,
  decode_mailbox_fetch,
  encode_delivery_batch,
  encode_mailbox_ack,
  encode_mailbox_fetch,
  mailbox_ack_signing_bytes,
  mailbox_fetch_signing_bytes,
  mailbox_request_is_fresh,
  sign_mailbox_ack,
  sign_mailbox_fetch
)
from Protocol.V1 import (
  DeliveredEnvelope,
  DirectoryEntry,
  MailboxAck,
  MailboxFetch,
  OuterEnvelope,
  ProtocolError
)

fn wide(value :: Int) -> U64!ProtocolError do
  let text = value
    |> Int.to_string()
  case U64.parse(text) do
    Err(_) -> Err(MalformedEncoding)
    Ok(parsed)
  end
end

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn proof() -> Bool!ProtocolError do
  let token = repeated(7, 32)
  let directory = DirectoryEntry {
    version: 1,
    username: "device-b",
    account_identity: Bytes.from_utf8("account"),
    prekey_bundle: Bytes.from_utf8("bundle"),
    mailbox_token: token
  }
  let encoded_directory = encode_directory_entry(directory)?
  let decoded_directory = decode_directory_entry(encoded_directory)?
  assert_eq(decoded_directory.username, "device-b")
  assert(Bytes.secure_equals(decoded_directory.mailbox_token, token))
  let lookup = decode_directory_lookup(encode_directory_lookup("device-b")?)?
  assert_eq(lookup, "device-b")
  let outer = encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: repeated(9, 16),
    mailbox_token: token,
    suite: 1,
    expiration: wide(2000000000)?,
    padding_bucket: 256,
    ciphertext: Bytes.from_utf8("opaque ciphertext")
  })?
  let batch = decode_delivery_batch(encode_delivery_batch([
    DeliveredEnvelope { sequence: wide(4)?, envelope: outer }
  ])?)?
  assert(List.length(batch) == 1)
  assert(U64.compare(List.head(batch).sequence, wide(4)?) == 0)
  let trailing = case Bytes.concat(encoded_directory, Bytes.from_utf8("x")) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end?
  case decode_directory_entry(trailing) do
    Err(MalformedEncoding) -> assert(true)
    Err(_) -> assert(false)
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("delivery records round-trip and reject trailing data") do
  case proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

fn signing_pair() -> SigningKeyPair!ProtocolError do
  case Crypto.signing_generate() do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end
end

fn verified(public_key :: SigningPublicKey, signing_bytes :: Bytes, signature :: Bytes) -> Bool do
  case Crypto.verify(public_key, signing_bytes, Signature { bytes: signature }) do
    Err(_) -> false
    Ok(valid) -> valid
  end
end

fn joined(left :: Bytes, right :: Bytes) -> Bytes!ProtocolError do
  case Bytes.concat(left, right) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end
end

fn legacy_fetch_frame(token :: Bytes) -> Bytes!ProtocolError do
  let cursor = case Bytes.write_u64_be(wide(0)?) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end?
  let header = case Bytes.from_list([1, 70, 69, 84]) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end?
  joined(joined(header, token)?, cursor)
end

fn legacy_ack_frame(token :: Bytes, id :: Bytes) -> Bytes!ProtocolError do
  let header = case Bytes.from_list([1, 65, 67, 75]) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end?
  let count = case Bytes.from_list([1]) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end?
  joined(joined(joined(header, token)?, count)?, id)
end

fn signed_fetch_proof() -> Bool!ProtocolError do
  let pair = signing_pair()?
  let public_key = pair.public_key
  let private_key = pair.private_key
  let hash = Crypto.sha256(repeated(7, 32))
  let wire = sign_mailbox_fetch(private_key, hash, wide(3)?, wide(1700000000000)?)?
  assert(Bytes.length(wire) == 116)
  let fetch = decode_mailbox_fetch(wire)?
  assert(fetch.version == 2)
  assert(Bytes.secure_equals(fetch.mailbox_token_hash, hash))
  assert(U64.compare(fetch.after_sequence, wide(3)?) == 0)
  assert(U64.compare(fetch.issued_at, wide(1700000000000)?) == 0)
  assert(Bytes.secure_equals(encode_mailbox_fetch(fetch)?, wire))
  assert(verified(public_key, mailbox_fetch_signing_bytes(fetch)?, fetch.signature))
  # A different cursor, time, or mailbox is a different signed statement.
  let moved_cursor = %{fetch | after_sequence: wide(4)?}
  assert(!verified(public_key, mailbox_fetch_signing_bytes(moved_cursor)?, fetch.signature))
  let moved_time = %{fetch | issued_at: wide(1700000000001)?}
  assert(!verified(public_key, mailbox_fetch_signing_bytes(moved_time)?, fetch.signature))
  let moved_mailbox = %{fetch | mailbox_token_hash: Crypto.sha256(repeated(8, 32))}
  assert(!verified(public_key, mailbox_fetch_signing_bytes(moved_mailbox)?, fetch.signature))
  # Another device's key does not authorize this mailbox.
  let stranger = signing_pair()?
  assert(!verified(stranger.public_key, mailbox_fetch_signing_bytes(fetch)?, fetch.signature))
  Ok(true)
end

fn signed_ack_proof() -> Bool!ProtocolError do
  let pair = signing_pair()?
  let public_key = pair.public_key
  let private_key = pair.private_key
  let hash = Crypto.sha256(repeated(7, 32))
  let ids = [repeated(9, 16), repeated(10, 16)]
  let wire = sign_mailbox_ack(private_key, hash, wide(1700000000000)?, ids)?
  assert(Bytes.length(wire) == 141)
  let ack = decode_mailbox_ack(wire)?
  assert(ack.version == 2)
  assert(List.length(ack.envelope_ids) == 2)
  assert(Bytes.secure_equals(encode_mailbox_ack(ack)?, wire))
  assert(verified(public_key, mailbox_ack_signing_bytes(ack)?, ack.signature))
  # Swapping in another envelope ID must invalidate the signature.
  let other_ids = %{ack | envelope_ids: [repeated(9, 16), repeated(11, 16)]}
  assert(!verified(public_key, mailbox_ack_signing_bytes(other_ids)?, ack.signature))
  # A fetch signature is never an acknowledgement signature.
  let fetch = decode_mailbox_fetch(sign_mailbox_fetch(private_key,
    hash,
    wide(0)?,
    wide(1700000000000)?)?)?
  assert(!verified(public_key, mailbox_ack_signing_bytes(ack)?, fetch.signature))
  Ok(true)
end

fn rejection_proof() -> Bool!ProtocolError do
  let pair = signing_pair()?
  let private_key = pair.private_key
  let token = repeated(7, 32)
  let hash = Crypto.sha256(token)
  # Unauthenticated version-1 frames are no longer a supported request.
  case decode_mailbox_fetch(legacy_fetch_frame(token)?) do
    Err(UnsupportedVersion) -> assert(true)
    _ -> assert(false)
  end
  case decode_mailbox_ack(legacy_ack_frame(token, repeated(9, 16))?) do
    Err(UnsupportedVersion) -> assert(true)
    _ -> assert(false)
  end
  let wire = sign_mailbox_fetch(private_key, hash, wide(0)?, wide(1700000000000)?)?
  case decode_mailbox_fetch(joined(wire, Bytes.from_utf8("x"))?) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  let fetch = decode_mailbox_fetch(wire)?
  case encode_mailbox_fetch(%{fetch | signature: repeated(1, 63)}) do
    Err(InvalidFieldLength) -> assert(true)
    _ -> assert(false)
  end
  case encode_mailbox_fetch(%{fetch | mailbox_token_hash: repeated(1, 31)}) do
    Err(InvalidFieldLength) -> assert(true)
    _ -> assert(false)
  end
  case sign_mailbox_ack(private_key, hash, wide(1700000000000)?, List.new()) do
    Err(InvalidFieldLength) -> assert(true)
    _ -> assert(false)
  end
  let nine = [
    repeated(1, 16),
    repeated(2, 16),
    repeated(3, 16),
    repeated(4, 16),
    repeated(5, 16),
    repeated(6, 16),
    repeated(7, 16),
    repeated(8, 16),
    repeated(9, 16)
  ]
  case sign_mailbox_ack(private_key, hash, wide(1700000000000)?, nine) do
    Err(InvalidFieldLength) -> assert(true)
    _ -> assert(false)
  end
  Ok(true)
end

fn freshness_proof() -> Bool!ProtocolError do
  let now = wide(1700000000000)?
  assert(mailbox_request_is_fresh(now, now))
  assert(mailbox_request_is_fresh(wide(1699999700000)?, now))
  assert(!mailbox_request_is_fresh(wide(1699999699999)?, now))
  assert(mailbox_request_is_fresh(wide(1700000060000)?, now))
  assert(!mailbox_request_is_fresh(wide(1700000060001)?, now))
  # A request stamped near zero must not underflow the window arithmetic.
  assert(!mailbox_request_is_fresh(wide(0)?, now))
  assert(mailbox_request_is_fresh(wide(1)?, wide(2)?))
  Ok(true)
end

test("mailbox fetch is a device-signed statement bound to mailbox, cursor, and time") do
  case signed_fetch_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

test("mailbox acknowledgement signs every envelope ID under its own domain") do
  case signed_ack_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

test("unauthenticated version-1 mailbox frames and malformed requests are rejected") do
  case rejection_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

test("mailbox requests are fresh only within the signed time window") do
  case freshness_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
