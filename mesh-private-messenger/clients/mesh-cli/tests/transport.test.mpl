from Transport.Packet import TransportPacket, decode_packet, encode_packet

fn wire(value :: Result<Bytes, String>) -> Bytes do
  case value do
    Err(_) -> Bytes.empty()
    Ok(encoded) -> encoded
  end
end

test("client transport packets round-trip and reject trailing data") do
  let initial = wire(encode_packet(InitialPacket(Bytes.from_utf8("account"),
    Bytes.from_utf8("initial"))))
  case decode_packet(initial) do
    Err(_) -> assert(false)
    Ok(InitialPacket(account, message)) -> do
      assert(Bytes.secure_equals(account, Bytes.from_utf8("account")))
      assert(Bytes.secure_equals(message, Bytes.from_utf8("initial")))
    end
    Ok(_) -> assert(false)
  end
  let ratchet = wire(encode_packet(RatchetPacket(Bytes.from_utf8("ratchet"))))
  case decode_packet(ratchet) do
    Err(_) -> assert(false)
    Ok(RatchetPacket(message)) -> assert(Bytes.secure_equals(message, Bytes.from_utf8("ratchet")))
    Ok(_) -> assert(false)
  end
  case Bytes.concat(initial, Bytes.from_utf8("x")) do
    Err(_) -> assert(false)
    Ok(trailing) -> case decode_packet(trailing) do
      Err(_) -> assert(true)
      Ok(_) -> assert(false)
    end
  end
end
