from Transport.GroupRecipient import seal_group_transport, open_group_transport
from Transport.Padding import pad_message, unpad_message
from Transport.Packet import TransportPacket, encode_packet, open_initial_packet, seal_initial_packet

fn repeated(value :: Int, length :: Int) -> Bytes ! String do
  case Bytes.repeat(value, length) do
    Err( _) -> Err("test byte allocation failed")
    Ok( bytes) -> Ok(bytes)
  end
end

fn proof() -> Bool ! String do
  let body = Bytes.from_utf8("private sender and message")
  let padded = pad_message(body, 52) ?
  assert(Bytes.length(padded) + 52 == 256)
  assert(Bytes.secure_equals(unpad_message(padded, 52) ?, body))
  assert(Bytes.length(pad_message(Bytes.from_utf8("short"), 52) ?) == Bytes.length(padded))
  assert(Bytes.length(pad_message(repeated(1, 65480) ?, 52) ?) + 52 == 65536)
  case pad_message(repeated(1, 65481) ?, 52) do
    Ok( _) -> assert(false)
    Err( _) -> assert(true)
  end
  let altered = Bytes.concat(Bytes.slice(padded, 0, Bytes.length(padded) - 1) ?, repeated(1, 1) ?) ?
  case unpad_message(altered, 52) do
    Ok( _) -> assert(false)
    Err( _) -> assert(true)
  end
  let recipient = case Crypto.x25519_generate() do
    Err( _) -> Err("key generation failed")
    Ok( value) -> Ok(value)
  end ?
  let stranger = case Crypto.x25519_generate() do
    Err( _) -> Err("key generation failed")
    Ok( value) -> Ok(value)
  end ?
  let group_fields = Bytes.from_utf8("group-id:synthetic-group;roster:alice,bob;control:welcome")
  let group_sealed = seal_group_transport(group_fields, recipient.public_key) ?
  assert(Bytes.length(group_sealed) == 256)
  assert(!String.contains(Bytes.to_hex(group_sealed), Bytes.to_hex(group_fields)))
  assert(Bytes.secure_equals(open_group_transport(group_sealed, recipient.private_key) ?,
  group_fields))
  case open_group_transport(group_sealed, stranger.private_key) do
    Ok( _) -> assert(false)
    Err( _) -> nil
  end
  let group_max = seal_group_transport(repeated(7, 65480) ?, recipient.public_key) ?
  assert(Bytes.length(group_max) == 65536)
  assert(Bytes.length(open_group_transport(group_max, recipient.private_key) ?) == 65480)
  case seal_group_transport(repeated(7, 65481) ?, recipient.public_key) do
    Ok( _) -> assert(false)
    Err( _) -> nil
  end
  let group_last = Bytes.get(group_sealed, Bytes.length(group_sealed) - 1) ?
  let group_replacement = if group_last == 0 do
    1
  else
    0
  end
  let group_changed = Bytes.concat(Bytes.slice(group_sealed, 0, Bytes.length(group_sealed) - 1) ?,
  repeated(group_replacement, 1) ?) ?
  case open_group_transport(group_changed, recipient.private_key) do
    Ok( _) -> assert(false)
    Err( _) -> nil
  end
  let identity = Bytes.from_utf8("public sender identity must be hidden")
  let sealed = seal_initial_packet(identity, body, recipient.public_key) ?
  assert(Bytes.length(sealed) == 256)
  assert(!String.contains(Bytes.to_hex(sealed), Bytes.to_hex(identity)))
  case open_initial_packet(sealed, recipient.private_key) do
    Ok( InitialPacket( account, message)) -> do
      assert(Bytes.secure_equals(account, identity))
      assert(Bytes.secure_equals(message, body))
    end
    _ -> assert(false)
  end
  case open_initial_packet(sealed, stranger.private_key) do
    Ok( _) -> assert(false)
    Err( _) -> assert(true)
  end
  let last = Bytes.get(sealed, Bytes.length(sealed) - 1) ?
  let changed = if last == 0 do
    1
  else
    0
  end
  let tampered = Bytes.concat(Bytes.slice(sealed, 0, Bytes.length(sealed) - 1) ?,
  repeated(changed, 1) ?) ?
  case open_initial_packet(tampered, recipient.private_key) do
    Ok( _) -> assert(false)
    Err( _) -> assert(true)
  end
  let clear = encode_packet(InitialPacket(identity, body)) ?
  case open_initial_packet(clear, recipient.private_key) do
    Ok( _) -> assert(false)
    Err( _) -> assert(true)
  end
  Ok(true)
end

test("recipient packets conceal identities and lengths and reject wrong keys and cleartext") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
