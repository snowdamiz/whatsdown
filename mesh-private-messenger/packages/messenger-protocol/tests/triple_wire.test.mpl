from Protocol.V1 import ProtocolError
from Session.HeaderWire import OpenedHeader
from Session.BraidFragment import BraidFragment, BraidFragmentKind
from Session.TripleWire import (
  TripleHeader,
  TripleMessage,
  encode_triple_header,
  decode_triple_header,
  encode_triple_message,
  decode_triple_message,
  triple_header_aad,
  triple_body_aad
)

fn check(ok :: Bool) -> Unit!ProtocolError do
  if ok do
    Ok(nil)
  else
    Err(MalformedEncoding)
  end
end

fn hex(text :: String) -> Bytes!ProtocolError do
  case Bytes.from_hex(text) do
    Ok(v)
    Err(_) -> Err(MalformedEncoding)
  end
end

fn wide(text :: String) -> U64!ProtocolError do
  case U64.parse(text) do
    Ok(v)
    Err(_) -> Err(MalformedEncoding)
  end
end

fn repeated(byte :: Int, count :: Int) -> Bytes!ProtocolError do
  case Bytes.repeat(byte, count) do
    Ok(v)
    Err(_) -> Err(MalformedEncoding)
  end
end

fn join(parts :: List<Bytes>) -> Bytes!ProtocolError do
  case Bytes.concat_many(parts, 262144) do
    Ok(v)
    Err(_) -> Err(MalformedEncoding)
  end
end

fn slice(input :: Bytes, start :: Int, length :: Int) -> Bytes!ProtocolError do
  case Bytes.slice(input, start, length) do
    Ok(v)
    Err(_) -> Err(MalformedEncoding)
  end
end

fn changed(input :: Bytes, start :: Int, value :: Bytes) -> Bytes!ProtocolError do
  join([
    slice(input, 0, start)?,
    value,
    slice(input, start + Bytes.length(value), Bytes.length(input) - start - Bytes.length(value))?
  ])
end

fn source(data :: Bool) -> TripleHeader!ProtocolError do
  let session = repeated(34, 32)?
  Ok(TripleHeader {
    ec: OpenedHeader {
      suite: 2,
      session_id: session,
      ratchet_public_key: X25519PublicKey { bytes: repeated(51, 32)? },
      previous_chain_length: 16909060,
      message_number: 4294967295
    },
    pq_message_number: wide("18446744073709551615")?,
    fragment: BraidFragment {
      kind: if data do
        BraidVectorAckFragment
      else
        NoBraidFragment
      end,
      configuration: repeated(17, 32)?,
      session: session,
      epoch: wide("18446744073709551615")?,
      index: if data do
        65535
      else
        0
      end,
      word: if data do
        repeated(68, 64)?
      else
        Bytes.empty()
      end
    }
  })
end

fn header_literal(data :: Bool) -> Bytes!ProtocolError do
  hex(if data do
    "434850310100022222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333301020304ffffffffffffffffffffffff009443424631010311111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222ffffffffffffffff04800040ffff44444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444"
  else
    "434850310100022222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333301020304ffffffffffffffffffffffff004e43424631010011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222ffffffffffffffff"
  end)
end

fn message(data :: Bool, length :: Int) -> TripleMessage!ProtocolError do
  Ok(TripleMessage {
    header_nonce: repeated(85, 24)?,
    encrypted_header: repeated(if data do
        119
      else
        102
      end,
      if data do
        253
      else
        183
      end)?,
    nonce: repeated(136, 12)?,
    ciphertext: repeated(153, length)?
  })
end

fn frame_literal(data :: Bool) -> Bytes!ProtocolError do
  hex(if data do
    "4348463155555555555555555555555555555555555555555555555500fd777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777778888888888888888888888880000001099999999999999999999999999999999"
  else
    "4348463155555555555555555555555555555555555555555555555500b76666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666668888888888888888888888880000001099999999999999999999999999999999"
  end)
end

## Deliberately independent frame construction, including self-consistent invalid lengths.
fn unchecked_frame(header_length :: Int, body_length :: Int) -> Bytes!ProtocolError do
  let h = case Bytes.write_u16_be(header_length) do
    Ok(v) -> v
    Err(_) -> return Err(MalformedEncoding)
  end
  let n = case Bytes.write_u32_be(wide(Int.to_string(body_length))?) do
    Ok(v) -> v
    Err(_) -> return Err(MalformedEncoding)
  end
  join([
    Bytes.from_utf8("CHF1"),
    repeated(85, 24)?,
    h,
    repeated(102, header_length)?,
    repeated(136, 12)?,
    n,
    repeated(153, body_length)?
  ])
end

fn header_refused(bytes :: Bytes, value :: TripleHeader) -> Bool do
  case decode_triple_header(bytes, value.fragment.configuration, value.ec.session_id) do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn headers() -> Unit!ProtocolError do
  for data in [false, true] do
    let value = source(data)?
    let expected = header_literal(data)?
    check(Bytes.secure_equals(encode_triple_header(value)?, expected))?
    let decoded = decode_triple_header(expected, value.fragment.configuration, value.ec.session_id)?
    check(decoded.ec.suite == 2
      && decoded.ec.message_number == 4294967295
      && decoded.ec.previous_chain_length == 16909060
      && U64.compare(decoded.pq_message_number, value.pq_message_number) == 0
      && U64.compare(decoded.fragment.epoch, value.fragment.epoch) == 0
      && decoded.fragment.kind == value.fragment.kind
      && decoded.fragment.index == value.fragment.index
      && Bytes.secure_equals(decoded.fragment.word, value.fragment.word)
      && Bytes.secure_equals(decoded.ec.ratchet_public_key.bytes,
        value.ec.ratchet_public_key.bytes))?
  end
  let value = source(true)?
  for number in ["0", "1"] do
    let candidate = %{value | pq_message_number: wide(number)?}
    check(case encode_triple_header(candidate) do
      Err(_) -> number == "0"
      Ok(_) -> number == "1"
    end)?
  end
  for ec in [
    %{value.ec | suite: 1},
    %{value.ec | message_number: -1},
    %{value.ec | message_number: 4294967296},
    %{value.ec | previous_chain_length: -1},
    %{value.ec | previous_chain_length: 4294967296},
    %{value.ec | session_id: repeated(35, 32)?}
  ] do
    check(case encode_triple_header(%{value | ec: ec}) do
      Err(_) -> true
      _ -> false
    end)?
  end
  Ok(nil)
end

fn malformed_headers() -> Unit!ProtocolError do
  let value = source(true)?
  let bytes = header_literal(true)?
  for length in 0..237 do
    check(header_refused(slice(bytes, 0, length)?, value))?
  end
  check(header_refused(join([bytes, hex("00")?])?, value))?
  for offset in [0, 1, 2, 3, 4, 89, 90, 91, 92] do
    check(header_refused(changed(bytes, offset, hex("ff")?)?, value))?
  end
  # Nested EC suite/session, PQ n, fragment length/profile/scope/epoch/parameters.
  for pair in [
    (5, hex("0000")?),
    (5, hex("0001")?),
    (5, hex("0003")?),
    (7, repeated(35, 32)?),
    (79, repeated(0, 8)?),
    (87, hex("0093")?),
    (93, hex("02")?),
    (95, repeated(18, 32)?),
    (127, repeated(35, 32)?),
    (159, repeated(0, 8)?),
    (167, hex("0481")?),
    (169, hex("0041")?),
    (94, hex("07")?)
  ] do
    let (offset, replacement) = pair
    check(header_refused(changed(bytes, offset, replacement)?, value))?
  end
  for config in [Bytes.empty(), repeated(18, 32)?] do
    check(case decode_triple_header(bytes, config, value.ec.session_id) do
      Err(_) -> true
      _ -> false
    end)?
  end
  for session in [Bytes.empty(), repeated(35, 32)?] do
    check(case decode_triple_header(bytes, value.fragment.configuration, session) do
      Err(_) -> true
      _ -> false
    end)?
  end
  # Public fragment payload mutations remain syntax: no authentication is claimed.
  check(!header_refused(changed(bytes, 236, hex("45")?)?, value))?
  Ok(nil)
end

fn frames() -> Unit!ProtocolError do
  for length in [90, 182, 184, 252, 254] do
    check(case decode_triple_message(unchecked_frame(length, 16)?) do
      Err(_) -> true
      _ -> false
    end)?
  end
  for h in [183, 253] do
    for n in [15, 65169] do
      check(case decode_triple_message(unchecked_frame(h, n)?) do
        Err(_) -> true
        _ -> false
      end)?
    end
  end
  for data in [false, true] do
    let value = message(data, 16)?
    let expected = frame_literal(data)?
    check(Bytes.secure_equals(encode_triple_message(value)?, expected))?
    let decoded = decode_triple_message(expected)?
    check(Bytes.secure_equals(decoded.header_nonce, value.header_nonce)
      && Bytes.secure_equals(decoded.encrypted_header, value.encrypted_header)
      && Bytes.secure_equals(decoded.nonce, value.nonce)
      && Bytes.secure_equals(decoded.ciphertext, value.ciphertext))?
    for length in 0..Bytes.length(expected) do
      check(case decode_triple_message(slice(expected, 0, length)?) do
        Err(_) -> true
        _ -> false
      end)?
    end
    for bad in [
      join([expected, hex("00")?])?,
      changed(expected, 0, hex("04524154")?)?,
      changed(expected, 28, hex("005a")?)?,
      changed(expected, Bytes.length(expected) - 20, hex("00000011")?)?
    ] do
      check(case decode_triple_message(bad) do
        Err(_) -> true
        _ -> false
      end)?
    end
    let max = encode_triple_message(message(data, 65168)?)?
    check(Bytes.length(max) == (if data do
        65467
      else
        65397
      end))?
    check(Bytes.secure_equals(Crypto.sha256(max),
      hex(if data do
        "f26bc1b25f892592dbda59f0da9838f1de57500e5fb95a9ed7c34d001f20ce46"
      else
        "2efbdc657c20231edcdb525572f223ec31b559a94ae83e5335f153e2ecf28eba"
      end)?))?
    decode_triple_message(max)?
  end
  let value = message(true, 16)?
  for bad in [
    %{value | header_nonce: repeated(0, 23)?},
    %{value | nonce: repeated(0, 13)?},
    %{value | encrypted_header: repeated(0, 254)?},
    %{value | encrypted_header: repeated(0, 182)?},
    %{value | ciphertext: repeated(0, 15)?},
    %{value | ciphertext: repeated(0, 65169)?}
  ] do
    check(case encode_triple_message(bad) do
      Err(_) -> true
      _ -> false
    end)?
  end
  # Ciphertext mutation is syntactically valid until the later AEAD verifies it.
  decode_triple_message(changed(frame_literal(true)?, 314, hex("98")?)?)?
  Ok(nil)
end

fn aad() -> Unit!ProtocolError do
  let config = repeated(17, 32)?
  let session = repeated(34, 32)?
  let caller = Bytes.from_utf8("fixture caller")
  for invalid in [
    %{message(false, 16)? | header_nonce: repeated(85, 23)?},
    %{message(false, 16)? | nonce: repeated(136, 13)?},
    %{message(false, 16)? | encrypted_header: repeated(102, 184)?},
    %{message(true, 16)? | encrypted_header: repeated(119, 252)?}
  ] do
    check(case triple_body_aad(config, session, invalid, caller) do
      Err(_) -> true
      _ -> false
    end)?
  end
  for data in [false, true] do
    let msg = message(data, 16)?
    let h = triple_header_aad(config, session, Bytes.length(msg.encrypted_header), caller)?
    let b = triple_body_aad(config, session, msg, caller)?
    check(Bytes.secure_equals(h,
      hex(if data do
        "6d6573682d6d73672f747269706c652f76312f6865616465722d616164006d6573682d6d73672f737071722f763100111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222224348463100fd666978747572652063616c6c6572"
      else
        "6d6573682d6d73672f747269706c652f76312f6865616465722d616164006d6573682d6d73672f737071722f763100111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222224348463100b7666978747572652063616c6c6572"
      end)?))?
    check(Bytes.secure_equals(b,
      hex(if data do
        "6d6573682d6d73672f747269706c652f76312f626f64792d616164006d6573682d6d73672f737071722f763100111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222224348463155555555555555555555555555555555555555555555555500fd77777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777888888888888888888888888666978747572652063616c6c6572"
      else
        "6d6573682d6d73672f747269706c652f76312f626f64792d616164006d6573682d6d73672f737071722f763100111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222224348463155555555555555555555555555555555555555555555555500b7666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666888888888888888888888888666978747572652063616c6c6572"
      end)?))?
    check(!Bytes.secure_equals(h,
      triple_header_aad(repeated(18, 32)?, session, Bytes.length(msg.encrypted_header), caller)?))?
    check(!Bytes.secure_equals(h,
      triple_header_aad(config, repeated(35, 32)?, Bytes.length(msg.encrypted_header), caller)?))?
    check(!Bytes.secure_equals(h,
      triple_header_aad(config, session, Bytes.length(msg.encrypted_header), Bytes.empty())?))?
    for changed_msg in [
      %{msg | header_nonce: repeated(86, 24)?},
      %{msg | nonce: repeated(137, 12)?},
      %{msg | encrypted_header: repeated(120, Bytes.length(msg.encrypted_header))?}
    ] do
      check(!Bytes.secure_equals(b, triple_body_aad(config, session, changed_msg, caller)?))?
    end
    # Body content/tag is excluded from its own AAD; candidate sealing uses empty ciphertext.
    check(Bytes.secure_equals(b,
      triple_body_aad(config, session, %{msg | ciphertext: Bytes.empty()}, caller)?))?
    check(Bytes.length(triple_header_aad(config,
      session,
      Bytes.length(msg.encrypted_header),
      repeated(0, 130955)?)?) == 131072)?
    check(case triple_header_aad(config,
      session,
      Bytes.length(msg.encrypted_header),
      repeated(0, 130956)?) do
      Err(_) -> true
      _ -> false
    end)?
    let maximum = if data do
      130668
    else
      130738
    end
    check(Bytes.length(triple_body_aad(config, session, msg, repeated(0, maximum)?)?) == 131072)?
    check(case triple_body_aad(config, session, msg, repeated(0, maximum + 1)?) do
      Err(_) -> true
      _ -> false
    end)?
  end
  for length in [0, 90, 182, 184, 252, 254, 65535] do
    check(case triple_header_aad(config, session, length, caller) do
      Err(_) -> true
      _ -> false
    end)?
  end
  check(case triple_header_aad(Bytes.empty(), session, 183, caller) do
    Err(_) -> true
    _ -> false
  end)?
  check(case triple_body_aad(config, Bytes.empty(), message(false, 16)?, caller) do
    Err(_) -> true
    _ -> false
  end)?
  check(case triple_header_aad(config, session, 183, repeated(0, 131072)?) do
    Err(_) -> true
    _ -> false
  end)?
  check(case triple_body_aad(config, session, message(false, 16)?, repeated(0, 131072)?) do
    Err(_) -> true
    _ -> false
  end)?
  Ok(nil)
end

test("CHP1 literal headers and finite message counters") do
  assert(case headers() do
    Ok(_) -> true
    _ -> false
  end)
end

test("CHP1 rejects malformed nested framing and substituted scope") do
  assert(case malformed_headers() do
    Ok(_) -> true
    _ -> false
  end)
end

test("CHF1 literal frames exact transport ceiling and malformed lengths") do
  assert(case frames() do
    Ok(_) -> true
    _ -> false
  end)
end

test("Composite AAD exact independent vectors and transcript binding") do
  assert(case aad() do
    Ok(_) -> true
    _ -> false
  end)
end
