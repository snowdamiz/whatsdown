from Session.BraidFragment import (
  BraidFragmentKind,
  BraidFragment,
  encode_braid_fragment,
  decode_braid_fragment
)
from Protocol.V1 import ProtocolError
from Protocol.WirePrimitives import protocol_join

fn checked(value :: Bool) -> Unit!ProtocolError do
  if value do
    Ok(nil)
  else
    Err(MalformedEncoding)
  end
end

fn hex_bytes(value :: String) -> Bytes!ProtocolError do
  case Bytes.from_hex(value) do
    Ok(bytes)
    Err(_) -> Err(MalformedEncoding)
  end
end

fn wide(value :: String) -> U64!ProtocolError do
  case U64.parse(value) do
    Ok(number)
    Err(_) -> Err(MalformedEncoding)
  end
end

fn kind(value :: Int) -> BraidFragmentKind do
  case value do
    0 -> NoBraidFragment
    1 -> BraidHeaderFragment
    2 -> BraidVectorFragment
    3 -> BraidVectorAckFragment
    4 -> BraidAckFragment
    5 -> BraidFirstFragment
    _ -> BraidSecondFragment
  end
end

fn fixture(value :: Int) -> BraidFragment!ProtocolError do
  Ok(BraidFragment {
    kind: kind(value),
    configuration: hex_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?,
    session: hex_bytes("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")?,
    epoch: wide("72623859790382856")?,
    index: if value == 0 || value == 4 do
      0
    else
      65535
    end,
    word: if value == 0 || value == 4 do
      Bytes.empty()
    else
      hex_bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f")?
    end
  })
end

fn vector(value :: Int) -> Bytes!ProtocolError do
  let literals = [
    "434246310100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0102030405060708",
    "434246310101000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f010203040506070800600040ffff404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
    "434246310102000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f010203040506070804800040ffff404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
    "434246310103000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f010203040506070804800040ffff404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
    "434246310104000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0102030405060708",
    "434246310105000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f010203040506070803c00040ffff404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
    "434246310106000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f010203040506070800a00040ffff404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
  ]
  hex_bytes(List.get(literals, value))
end

fn replace_byte(input :: Bytes, offset :: Int, value :: Int) -> Bytes!ProtocolError do
  let first = case Bytes.slice(input, 0, offset) do
    Ok(v) -> v
    Err(_) -> return Err(MalformedEncoding)
  end
  let last = case Bytes.slice(input, offset + 1, Bytes.length(input) - offset - 1) do
    Ok(v) -> v
    Err(_) -> return Err(MalformedEncoding)
  end
  let byte = case Bytes.from_list([value]) do
    Ok(v) -> v
    Err(_) -> return Err(MalformedEncoding)
  end
  protocol_join([first, byte, last], 0, Bytes.empty())
end

fn refused(input :: Bytes, source :: BraidFragment) -> Bool do
  case decode_braid_fragment(input, source.configuration, source.session) do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn literal_cases() -> Unit!ProtocolError do
  for number in 0..7 do
    let source = fixture(number)?
    let expected = vector(number)?
    checked(Bytes.secure_equals(encode_braid_fragment(source)?, expected))?
    let decoded = decode_braid_fragment(expected, source.configuration, source.session)?
    checked(decoded.kind == source.kind
      && decoded.index == source.index
      && U64.compare(decoded.epoch, source.epoch) == 0
      && Bytes.secure_equals(decoded.word, source.word)
      && Bytes.secure_equals(decoded.configuration, source.configuration)
      && Bytes.secure_equals(decoded.session, source.session))?
  end
  Ok(nil)
end

fn malformed_cases() -> Unit!ProtocolError do
  let source = fixture(1)?
  let input = vector(1)?
  for length in 0..148 do
    let short = case Bytes.slice(input, 0, length) do
      Ok(v) -> v
      Err(_) -> return Err(MalformedEncoding)
    end
    checked(refused(short, source))?
  end
  checked(refused(protocol_join([input, Bytes.from_utf8("x")], 0, Bytes.empty())?, source))?
  for offset in [0, 1, 2, 3] do
    checked(refused(replace_byte(input, offset, 0)?, source))?
  end
  checked(refused(replace_byte(input, 4, 2)?, source))?
  for tag in [7, 255] do
    checked(refused(replace_byte(input, 5, tag)?, source))?
  end
  checked(refused(replace_byte(input, 78, 1)?, source))?
  checked(refused(replace_byte(input, 79, 95)?, source))?
  checked(refused(replace_byte(input, 80, 1)?, source))?
  checked(refused(replace_byte(input, 81, 63)?, source))?
  for tag in [0, 4] do
    checked(refused(replace_byte(input, 5, tag)?, source))?
    checked(refused(protocol_join([vector(tag)?, Bytes.from_utf8("x")], 0, Bytes.empty())?,
      source))?
  end
  # A different DATA kind cannot reuse Hdr's original-length declaration.
  for tag in [2, 3, 5, 6] do
    checked(refused(replace_byte(input, 5, tag)?, source))?
  end
  Ok(nil)
end

fn scope_and_epoch_cases() -> Unit!ProtocolError do
  let source = fixture(1)?
  let input = vector(1)?
  checked(refused(replace_byte(input, 6, 255)?, source))?
  checked(refused(replace_byte(input, 38, 255)?, source))?
  let short = hex_bytes("00")?
  checked(case decode_braid_fragment(input, short, source.session) do
    Err(_) -> true
    _ -> false
  end)?
  checked(case decode_braid_fragment(input, source.configuration, short) do
    Err(_) -> true
    _ -> false
  end)?
  let zero = wide("0")?
  checked(case encode_braid_fragment(%{source | epoch: zero}) do
    Err(_) -> true
    _ -> false
  end)?
  let prefix = case Bytes.slice(input, 0, 70) do
    Ok(v) -> v
    Err(_) -> return Err(MalformedEncoding)
  end
  let suffix = case Bytes.slice(input, 78, 70) do
    Ok(v) -> v
    Err(_) -> return Err(MalformedEncoding)
  end
  checked(refused(protocol_join([prefix, hex_bytes("0000000000000000")?, suffix],
      0,
      Bytes.empty())?,
    source))?
  let maximum = wide("18446744073709551615")?
  let max_wire = protocol_join([prefix, hex_bytes("ffffffffffffffff")?, suffix], 0, Bytes.empty())?
  checked(Bytes.secure_equals(encode_braid_fragment(%{source | epoch: maximum})?, max_wire))?
  let decoded = decode_braid_fragment(max_wire, source.configuration, source.session)?
  checked(U64.compare(decoded.epoch, maximum) == 0)?
  # Opaque payload mutations are valid syntax; the kernel must authenticate later.
  checked(case decode_braid_fragment(replace_byte(input, 147, 0)?,
    source.configuration,
    source.session) do
    Ok(_) -> true
    _ -> false
  end)?
  Ok(nil)
end

fn encoder_boundaries() -> Unit!ProtocolError do
  let source = fixture(1)?
  for index in [-1, 65536] do
    checked(case encode_braid_fragment(%{source | index: index}) do
      Err(_) -> true
      _ -> false
    end)?
  end
  let valid = encode_braid_fragment(%{source | index: 0})?
  checked(Bytes.secure_equals(valid, replace_byte(replace_byte(vector(1)?, 82, 0)?, 83, 0)?))?
  let empty = Bytes.empty()
  checked(case encode_braid_fragment(%{source | word: empty}) do
    Err(_) -> true
    _ -> false
  end)?
  checked(case encode_braid_fragment(%{source | configuration: empty}) do
    Err(_) -> true
    _ -> false
  end)?
  checked(case encode_braid_fragment(%{source | session: empty}) do
    Err(_) -> true
    _ -> false
  end)?
  let too_long = protocol_join([source.word, Bytes.from_utf8("x")], 0, empty)?
  checked(case encode_braid_fragment(%{source | word: too_long}) do
    Err(_) -> true
    _ -> false
  end)?
  for tag in [0, 4] do
    let control = fixture(tag)?
    checked(case encode_braid_fragment(%{control | index: 1}) do
      Err(_) -> true
      _ -> false
    end)?
    checked(case encode_braid_fragment(%{control | word: source.word}) do
      Err(_) -> true
      _ -> false
    end)?
  end
  Ok(nil)
end

test("CBF1 seven independent literal encodings and decodings") do
  assert(case literal_cases() do
    Ok(_) -> true
    _ -> false
  end)
end

test("CBF1 refuses truncation tails kinds and parameter substitution") do
  assert(case malformed_cases() do
    Ok(_) -> true
    _ -> false
  end)
end

test("CBF1 binds scope and nonzero full-width epoch without claiming authentication") do
  assert(case scope_and_epoch_cases() do
    Ok(_) -> true
    _ -> false
  end)
end

test("CBF1 encoder enforces index field and control canonicality") do
  assert(case encoder_boundaries() do
    Ok(_) -> true
    _ -> false
  end)
end
