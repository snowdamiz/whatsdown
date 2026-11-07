from Mobile.OhttpPins import decode_ohttp_pins, select_ohttp_key
from Transparency.Config import decode_security_config

fn network() -> Bytes do
  Bytes.from_utf8("2\n0\nhttps://core.example\nhttps://edge.example\nhttps://objects.example\nwss://stream.example/v1/mailbox/stream\n16")
end

fn security() -> Bytes do
  Bytes.from_utf8(String.join([
      "1",
      String.repeat("11", 32),
      String.repeat("22", 32),
      String.repeat("33", 32),
      String.repeat("44", 32),
      "8"
    ],
    "\n"))
end

fn first_key() -> String do
  "31e1f05a740102751261153ed490fd94a675258c3b8e30b373beaabfba281550"
end

fn second_key() -> String do
  "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
end

fn fixture() -> Bytes do
  Bytes.from_utf8(String.join([
      "1",
      "58f2a0eda422e33cfa6cdbd5996d2f134f71a51d5105112aecdf0ec3c5c4bb21",
      "89d174605d5760bf97b433f9cf67e10123a4e8d179670e846f7a9933d509f70b",
      "18446744073709551615",
      "required",
      "2",
      "2000 4000 AQAgMeHwWnQBAnUSYRU+1JD9lKZ1JYw7jjCzc76qv7ooFVAABAABAAM=",
      "0 3000 /wAghSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmoABAABAAM="
    ],
    "\n"))
end

fn replace(frame :: Bytes, at :: Int, value :: String) -> Bytes!String do
  let fields = String.split(Bytes.to_utf8(frame)?, "\n")
  Ok(Bytes.from_utf8(String.join(for index in 0..List.length(fields) do
      if index == at do
        value
      else
        List.get(fields, index)
      end
    end,
    "\n")))
end

fn rejected(frame :: Bytes) -> Bool!String do
  Ok(Result.is_err(decode_ohttp_pins(frame, network(), decode_security_config(security())?)))
end

fn key_line(id :: String, public_key :: String, offers :: String) -> String!String do
  Ok("0 3000 " <> Bytes.to_base64(Bytes.from_hex(id <> "0020" <> public_key <> offers)?))
end

fn complete_and_selection() -> Bool!String do
  let pins = decode_ohttp_pins(fixture(), network(), decode_security_config(security())?)?
  assert(pins.required)
  assert(U64.to_string(pins.revision) == "18446744073709551615")
  assert(pins.network.core_origin == "https://core.example")
  assert(pins.network.edge_origin == "https://edge.example")
  assert(Bytes.to_hex(pins.identity) == "794a7d084b37d9998c63f4aa946b42afd7901bb1e2aa6d956bed860540539080")
  assert(List.length(pins.keys) == 2)
  assert(Bytes.to_hex(List.get(pins.keys, 0).config.public_key.bytes) == first_key())
  assert(Bytes.to_hex(List.get(pins.keys, 1).config.public_key.bytes) == second_key())
  for time in ["0", "1999", "2000", "2999", "3000", "3999"] do
    let expected = if time == "0" || time == "1999" do
      255
    else
      1
    end
    case select_ohttp_key(pins, U64.parse(time)?)? do
      None -> assert(false)
      Some(key) -> assert(key.key_id == expected)
    end
  end
  assert(Result.is_err(select_ohttp_key(pins, U64.parse("4000")?)))
  assert(Result.is_err(select_ohttp_key(pins, U64.parse("18446744073709551615")?)))
  let fields = String.split(Bytes.to_utf8(fixture())?, "\n")
  let one = Bytes.from_utf8(String.join(List.take(fields, 5) ++ ["1", List.get(fields, 6)], "\n"))
  let only = decode_ohttp_pins(one, network(), decode_security_config(security())?)?
  assert(Result.is_err(select_ohttp_key(only, U64.parse("1999")?)))
  let off = Bytes.from_utf8(String.join(List.take(fields, 4) ++ ["off", "0"], "\n"))
  let disabled = decode_ohttp_pins(off, network(), decode_security_config(security())?)?
  assert(!disabled.required && List.length(disabled.keys) == 0)
  assert(case select_ohttp_key(disabled, U64.parse("0")?)? do
    None -> true
    Some(_) -> false
  end)
  assert(!Bytes.secure_equals(pins.identity, disabled.identity))
  Ok(true)
end

fn binding() -> Bool!String do
  let s = decode_security_config(security())?
  for changed in [
    replace(network(), 2, "https://other.example")?,
    replace(network(), 3, "https://other.example")?,
    replace(network(), 4, "https://other.example")?,
    replace(network(), 5, "wss://other.example/v1/mailbox/stream")?,
    replace(network(), 6, "8")?
  ] do
    assert(Result.is_err(decode_ohttp_pins(fixture(), changed, s)))
  end
  assert(Result.is_err(decode_ohttp_pins(fixture(),
    network(),
    %{s | service_public_key: Bytes.from_hex(String.repeat("12", 32))?})))
  assert(Result.is_err(decode_ohttp_pins(fixture(), Bytes.empty(), s)))
  for at in [1, 2] do
    for text in [String.repeat("0", 64), "00", "", String.repeat("A", 64)] do
      assert(rejected(replace(fixture(), at, text)?)?)
    end
  end
  Ok(true)
end

fn shape() -> Bool!String do
  assert(rejected(Bytes.empty())?)
  assert(rejected(Bytes.from_hex("ff")?)?)
  assert(rejected(Bytes.from_utf8(String.repeat("a", 601)))?)
  assert(rejected(Bytes.from_utf8(Bytes.to_utf8(fixture())? <> "\n"))?)
  for at in [0, 4, 5] do
    for text in ["", "invalid", "01", "-1", "1\r", "1 "] do
      assert(rejected(replace(fixture(), at, text)?)?)
    end
  end
  for mode in ["off", "fallback", "Required"] do
    assert(rejected(replace(fixture(), 4, mode)?)?)
  end
  for count in ["0", "1", "3", "02"] do
    assert(rejected(replace(fixture(), 5, count)?)?)
  end
  Ok(true)
end

fn integers() -> Bool!String do
  for revision in ["0", "", "01", "-1", "+1", "1.0", "1e3", " 1", "1\r", "18446744073709551616"] do
    assert(rejected(replace(fixture(), 3, revision)?)?)
  end
  let encoded = List.get(String.split(List.get(String.split(Bytes.to_utf8(fixture())?, "\n"), 6),
      " "),
    2)
  for invalid in ["", "01", "-1", "+1", "1.0", "1e3", " 1", "18446744073709551616"] do
    assert(rejected(replace(fixture(), 6, invalid <> " 4000 " <> encoded)?)?)
    assert(rejected(replace(fixture(), 6, "0 " <> invalid <> " " <> encoded)?)?)
  end
  for bounds in ["0 0", "4000 2000", "18446744073709551615 18446744073709551615"] do
    assert(rejected(replace(fixture(), 6, bounds <> " " <> encoded)?)?)
  end
  assert(!rejected(replace(fixture(),
    6,
    "18446744073709551614 18446744073709551615 " <> encoded)?)?)
  Ok(true)
end

fn all_keys() -> Bool!String do
  assert(rejected(replace(fixture(), 7, key_line("01", second_key(), "000400010003")?)?)?)
  assert(rejected(replace(fixture(), 7, key_line("ff", first_key(), "000400010003")?)?)?)
  assert(rejected(replace(fixture(), 7, key_line("ff", second_key(), "000400010001")?)?)?)
  assert(rejected(replace(fixture(),
    7,
    key_line("ff", String.repeat("00", 32), "000400010003")?)?)?)
  let line = List.get(String.split(Bytes.to_utf8(fixture())?, "\n"), 7)
  for bad in [
    "",
    line <> " ",
    " " <> line,
    String.slice(line, 0, String.length(line) - 1),
    line <> "=",
    "0 3000 ***",
    "0  3000 " <> List.get(String.split(line, " "), 2)
  ] do
    assert(rejected(replace(fixture(), 7, bad)?)?)
  end
  Ok(true)
end

fn bounds() -> Bool!String do
  let offers = "0040" <> String.repeat("00010001", 15) <> "00010003"
  let first = replace(fixture(), 6, key_line("01", first_key(), offers)?)?
  let maximum = replace(first, 7, key_line("ff", second_key(), offers)?)?
  assert(!rejected(maximum)?)
  assert(rejected(replace(maximum, 7, key_line("ff", second_key(), offers <> "00")?)?)?)
  Ok(true)
end

fn checked(value :: Result<Bool, String>) -> Bool do
  case value do
    Ok(result) -> result
    Err(error) -> do
      println(error)
      false
    end
  end
end

test("exact build companion binds identity and selects only explicitly valid keys") do
  assert(checked(complete_and_selection()))
end

test("all network destinations and complete canonical security identity are bound") do
  assert(checked(binding()))
end

test("version mode count UTF8 and complete bounded frame shape are strict") do
  assert(checked(shape()))
end

test("revision and half-open validity use full-width canonical unsigned integers") do
  assert(checked(integers()))
end

test("an invalid second record cannot expose the first key or downgrade mode") do
  assert(checked(all_keys()))
end

test("both maximum selected-suite key records are bounded before selection") do
  assert(checked(bounds()))
end
