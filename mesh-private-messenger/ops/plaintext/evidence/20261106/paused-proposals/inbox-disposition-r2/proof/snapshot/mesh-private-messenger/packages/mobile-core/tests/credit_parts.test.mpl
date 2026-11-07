from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Mobile.Codec import mobile_write_u32, mobile_vector

fn legacy_parts(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(parts) do
    Ok(output)
  else
    legacy_parts(parts, index + 1, Bytes.concat(output, mobile_vector(List.get(parts, index))?)?)
  end
end

fn wire_equivalence() -> Bool!String do
  for count in 0..66 do
    let parts = for index in 0..count do
      Bytes.slice(Bytes.from_hex("00ff807f0102030405060708090a0b0c")?, index % 8, index % 9)?
    end
    let packed = pack_credit_parts(parts)?
    assert(Bytes.secure_equals(packed, legacy_parts(parts, 0, mobile_write_u32(count)?)?))
    assert(unpack_credit_parts(packed, count, 16)? == parts)
    assert(Result.is_err(unpack_credit_parts(Bytes.concat(packed, Bytes.from_hex("00")?)?,
      count,
      16)))
    if count > 0 do
      assert(Result.is_err(unpack_credit_parts(packed, count - 1, 16)))
    end
  end
  Ok(true)
end

fn maximum_parts() -> Bool!String do
  let part = case Bytes.repeat(37, 1871) do
    Err(_) -> return Err("fixture_repeat_failed")
    Ok(value) -> value
  end
  let packed = pack_credit_parts(for index in 0..8192 do
    part
  end)?
  assert(Bytes.length(packed) == 15360004)
  assert(Bytes.to_hex(Crypto.sha256(packed)) == "61a1d0efb629ded66b3c5a60aaf33ca796d452308821becb9eb3d35743d98c26")
  Ok(true)
end

test("credit part encoding preserves canonical legacy framing across empty and uneven ranges") do
  case wire_equivalence() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

test("maximum credit record count uses exact vector bytes without quadratic prefix copying") do
  case maximum_parts() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn maximum_ordered_decode() -> Bool!String do
  let parts = for index in 0..8192 do
    mobile_write_u32(index)?
  end
  let wire = pack_credit_parts(parts)?
  assert(Bytes.length(wire) == 65540)
  let decoded = unpack_credit_parts(wire, 8192, 4)?
  assert(List.length(decoded) == 8192)
  for index in 0..8192 do
    assert(Bytes.secure_equals(List.get(decoded, index), mobile_write_u32(index)?))
  end
  assert(Result.is_err(unpack_credit_parts(wire, 8191, 4)))
  assert(Result.is_err(unpack_credit_parts(wire, 8192, 3)))
  assert(Result.is_err(unpack_credit_parts(Bytes.slice(wire, 0, Bytes.length(wire) - 1)?, 8192, 4)))
  Ok(true)
end

test("maximum credit part decoding preserves every distinct record and refuses framing limits") do
  case maximum_ordered_decode() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
