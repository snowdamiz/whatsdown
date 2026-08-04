from Protocol.V1 import DeliveredEnvelope, DirectoryEntry, MailboxAck, MailboxFetch, OuterEnvelope, ProtocolError, decode_delivery_batch, decode_directory_entry, decode_directory_lookup, decode_mailbox_ack, decode_mailbox_fetch, encode_delivery_batch, encode_directory_entry, encode_directory_lookup, encode_mailbox_ack, encode_mailbox_fetch, encode_outer_envelope

fn wide(value :: Int) -> U64 ! ProtocolError do
  let text = value
    |> Int.to_string()
  case U64.parse(text) do
    Err( _) -> Err(MalformedEncoding)
    Ok( parsed) -> Ok(parsed)
  end
end

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err( _) -> Bytes.empty()
    Ok( output) -> output
  end
end

fn proof() -> Bool ! ProtocolError do
  let token = repeated(7, 32)
  let directory = DirectoryEntry {
    version : 1,
    username : "device-b",
    account_identity : Bytes.from_utf8("account"),
    prekey_bundle : Bytes.from_utf8("bundle"),
    mailbox_token : token
  }
  let encoded_directory = encode_directory_entry(directory) ?
  let decoded_directory = decode_directory_entry(encoded_directory) ?
  assert_eq(decoded_directory.username, "device-b")
  assert(Bytes.secure_equals(decoded_directory.mailbox_token, token))
  let lookup = decode_directory_lookup(encode_directory_lookup("device-b") ?) ?
  assert_eq(lookup, "device-b")
  let fetch = decode_mailbox_fetch(encode_mailbox_fetch(MailboxFetch {
    version : 1,
    mailbox_token : token,
    after_sequence : wide(3) ?
  }) ?) ?
  assert(U64.compare(fetch.after_sequence, wide(3) ?) == 0)
  let outer = encode_outer_envelope(OuterEnvelope {
    version : 1,
    envelope_id : repeated(9, 16),
    mailbox_token : token,
    suite : 1,
    expiration : wide(2000000000) ?,
    padding_bucket : 256,
    ciphertext : Bytes.from_utf8("opaque ciphertext")
  }) ?
  let batch = decode_delivery_batch(encode_delivery_batch([DeliveredEnvelope {
    sequence : wide(4) ?,
    envelope : outer
  }]) ?) ?
  assert(List.length(batch) == 1)
  assert(U64.compare(List.head(batch).sequence, wide(4) ?) == 0)
  let ack = decode_mailbox_ack(encode_mailbox_ack(MailboxAck {
    version : 1,
    mailbox_token : token,
    envelope_ids : [repeated(9, 16)]
  }) ?) ?
  assert(List.length(ack.envelope_ids) == 1)
  let trailing = case Bytes.concat(encoded_directory, Bytes.from_utf8("x")) do
    Err( _) -> Err(MalformedEncoding)
    Ok( value) -> Ok(value)
  end ?
  let _ = case decode_directory_entry(trailing) do
    Err( MalformedEncoding) -> assert(true)
    Err( _) -> assert(false)
    Ok( _) -> assert(false)
  end
  Ok(true)
end

test("delivery records round-trip and reject trailing data") do
  case proof() do
    Err( _) -> assert(false)
    Ok( value) -> assert(value)
  end
end
