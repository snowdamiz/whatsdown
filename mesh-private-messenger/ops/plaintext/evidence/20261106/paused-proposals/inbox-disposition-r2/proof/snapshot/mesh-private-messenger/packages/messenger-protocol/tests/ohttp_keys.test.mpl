from Ohttp.Keys import (
  OhttpKeyConfig,
  decode_key_config,
  encode_key_config,
  decode_key_configs,
  encode_key_configs
)

fn hex(input :: String) -> Bytes do
  case Bytes.from_hex(input) do
    Err(_) -> panic("invalid OHTTP key fixture")
    Ok(value) -> value
  end
end

fn joined(parts :: List<Bytes>) -> Bytes!String do
  case Bytes.concat_many(parts, 4096) do
    Err(_) -> Err("OHTTP fixture too large")
    Ok(value)
  end
end

fn sample() -> Bytes do
  # RFC9458 Appendix A key config advertises1/1 and1/3. Its request example
  # selects AES, while this profile selects the other advertised pair.
  hex("01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003")
end

fn second() -> OhttpKeyConfig do
  OhttpKeyConfig {
    key_id: 255,
    public_key: X25519PublicKey {
      bytes: hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    }
  }
end

test("RFC key configuration selects the offered suite and encoder emits exact canonical bytes") do
  let key = decode_key_config(sample())?
  assert(key.key_id == 1)
  assert(Bytes.secure_equals(key.public_key.bytes,
    hex("31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155")))
  let canonical = hex("01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155000400010003")
  assert(Bytes.secure_equals(encode_key_config(key)?, canonical))
  assert(Bytes.secure_equals(encode_key_configs([key])?, joined([hex("0029"), canonical])?))
  assert(decode_key_config(encode_key_config(%{key | key_id: 0})?)?.key_id == 0)
  Ok(nil)
end

test("complete two-key collections preserve configured order and reject duplicate identities") do
  let first = decode_key_config(sample())?
  let encoded = encode_key_configs([first, second()])?
  let values = decode_key_configs(encoded)?
  assert(List.length(values) == 2)
  assert(List.get(values, 0).key_id == 1 && List.get(values, 1).key_id == 255)
  assert(Bytes.secure_equals(List.get(values, 1).public_key.bytes, second().public_key.bytes))
  let duplicate_id = %{second() | key_id: 1}
  let duplicate_key = %{first | key_id: 2}
  for other in [duplicate_id, duplicate_key] do
    assert(Result.is_err(encode_key_configs([first, other])))
    assert(Result.is_err(decode_key_configs(joined([
      hex("0029"),
      encode_key_config(first)?,
      hex("0029"),
      encode_key_config(other)?
    ])?)))
  end
  Ok(nil)
end

test("a malformed collection suffix never returns a recovered valid prefix") do
  let first = encode_key_configs([decode_key_config(sample())?])?
  for suffix in [hex("00"), hex("0000"), hex("0029ff0020"), hex("ffff"), hex("000101")] do
    assert(Result.is_err(decode_key_configs(joined([first, suffix])?)))
  end
  assert(Result.is_err(decode_key_configs(Bytes.empty())))
  assert(Result.is_err(decode_key_configs(sample())))
  let one = encode_key_config(second())?
  # A well-framed second entry with only an unsupported offer must also reject
  # the entire collection; it is not a recoverable or skippable suffix.
  let unsupported = joined([Bytes.slice(one, 0, 35)?, hex("000400010001")])?
  assert(Result.is_err(decode_key_configs(joined([first, hex("0029"), unsupported])?)))
  let three = joined([first, hex("0029"), one, hex("0029"), one])?
  assert(Result.is_err(decode_key_configs(three)))
  Ok(nil)
end

test("all truncations trailing bytes and malformed algorithm lengths refuse") do
  let original = sample()
  for size in 0..Bytes.length(original) do
    assert(Result.is_err(decode_key_config(Bytes.slice(original, 0, size)?)))
  end
  assert(Result.is_err(decode_key_config(joined([original, hex("00")])?)))
  let prefix = Bytes.slice(original, 0, 35)?
  for tail in [
    hex("0000"),
    hex("0003000100"),
    hex("00050001000300"),
    hex("000800010003"),
    hex("ffff00010003")
  ] do
    assert(Result.is_err(decode_key_config(joined([prefix, tail])?)))
  end
  Ok(nil)
end

test("unsupported KEM and algorithm offers cannot silently substitute the selected suite") do
  let original = sample()
  assert(Result.is_err(decode_key_config(joined([
    hex("010010"),
    Bytes.slice(original, 3, Bytes.length(original) - 3)?
  ])?)))
  let prefix = Bytes.slice(original, 0, 35)?
  for offers in [hex("000400010001"), hex("000400020003"), hex("0004ffffffff")] do
    assert(Result.is_err(decode_key_config(joined([prefix, offers])?)))
  end
  let reordered = joined([prefix, hex("000cffffffff0001000300010001")])?
  assert(decode_key_config(reordered)?.key_id == 1)
  Ok(nil)
end

test("bounded profile accepts sixteen offers and two complete maximum records only") do
  let prefix = Bytes.slice(sample(), 0, 35)?
  let offers = hex(String.repeat("00010001", 15) <> "00010003")
  let maximum = joined([prefix, hex("0040"), offers])?
  assert(Bytes.length(maximum) == 101)
  let other_prefix = Bytes.slice(encode_key_config(second())?, 0, 35)?
  let other = joined([other_prefix, hex("0040"), offers])?
  let collection = joined([hex("0065"), maximum, hex("0065"), other])?
  assert(Bytes.length(collection) == 206)
  assert(List.length(decode_key_configs(collection)?) == 2)
  assert(Result.is_err(decode_key_configs(joined([collection, hex("00")])?)))
  assert(Result.is_err(decode_key_config(joined([prefix, hex("0044"), offers, hex("00010003")])?)))
  Ok(nil)
end

test("encoder validates integer public key and collection bounds before writing") do
  let valid = second()
  for id in [-1, 256, 65536] do
    assert(Result.is_err(encode_key_config(%{valid | key_id: id})))
  end
  for size in [0, 31, 33, 256] do
    assert(Result.is_err(encode_key_config(%{valid |
      public_key: X25519PublicKey { bytes: Bytes.repeat(1, size)? }
    })))
  end
  assert(Result.is_err(encode_key_configs([])))
  assert(Result.is_err(encode_key_configs([valid, valid, valid])))
  Ok(nil)
end
