from Pins import CliPins, cli_pins
from Transparency.Merkle import WitnessKey

fn key(seed :: Int) -> String do
  case Bytes.repeat(seed, 32) do
    Err(_) -> ""
    Ok(value) -> Bytes.to_hex(value)
  end
end

fn delivery() -> String do
  case Crypto.x25519_generate() do
    Err(_) -> ""
    Ok(value) -> Bytes.to_hex(value.public_key.bytes)
  end
end

fn ids(pins :: CliPins) -> List<String> do
  List.map(pins.witnesses, fn witness -> witness.witness_id end)
end

fn refused(result :: Result<CliPins, String>) -> Bool do
  case result do
    Ok(_) -> false
    Err(_) -> true
  end
end

fn v2(threshold :: String) -> String do
  "2\n"
    <> key(1)
    <> "\n"
    <> delivery()
    <> "\n16\n"
    <> threshold
    <> "\n3\nwitness-a "
    <> key(2)
    <> " Morse\nwitness-b "
    <> key(3)
    <> " Morse\nwitness-c "
    <> key(4)
    <> " Morse\n-\n0\n0\n-\n-\n1"
end

test("the client pins the witness set and k from a v1 or v2 security config") do
  case cli_pins(v2("2"), "", "", "") do
    Err(_) -> assert(false)
    Ok(pins) -> do
      assert(pins.threshold == 2)
      assert(ids(pins) == ["witness-a", "witness-b", "witness-c"])
      assert(Bytes.to_hex(pins.service_key) == key(1))
    end
  end
  assert(refused(cli_pins(v2("1"), "", "", "")))
  let v1 = "1\n" <> key(1) <> "\n" <> key(2) <> "\n" <> key(3) <> "\n" <> delivery() <> "\n16"
  case cli_pins(v1, "", "", "") do
    Err(_) -> assert(false)
    Ok(pins) -> assert(pins.threshold == 2 && ids(pins) == ["witness-a", "witness-b"])
  end
end

test("without a config the client pins witness-a and witness-b, 2 of 2") do
  case cli_pins("", key(1), key(2), key(3)) do
    Err(_) -> assert(false)
    Ok(pins) -> do
      assert(pins.threshold == 2 && ids(pins) == ["witness-a", "witness-b"])
      assert(Bytes.to_hex(List.get(pins.witnesses, 1).public_key) == key(3))
    end
  end
  assert(refused(cli_pins("", key(1), key(2), "")))
end

test("the client takes the minimum session suite from the config, 1 without one") do
  let floor_two = String.slice(v2("2"), 0, String.length(v2("2")) - 1) <> "2"
  case cli_pins(floor_two, "", "", "") do
    Err(_) -> assert(false)
    Ok(pins) -> assert(pins.minimum_suite == 2)
  end
  case cli_pins(v2("2"), "", "", "") do
    Err(_) -> assert(false)
    Ok(pins) -> assert(pins.minimum_suite == 1)
  end
  case cli_pins("", key(1), key(2), key(3)) do
    Err(_) -> assert(false)
    Ok(pins) -> assert(pins.minimum_suite == 1)
  end
end

test("a config that pins the OHTTP gateway gives the client its key and relay") do
  let config = "01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155000400010003"
  case cli_pins(v2("2") <> "\n" <> config <> " https://edge.example", "", "", "") do
    Err(_) -> assert(false)
    Ok(pins) -> do
      assert(Bytes.to_hex(pins.ohttp_key_config) == config)
      assert(pins.ohttp_relay == "https://edge.example")
    end
  end
  case cli_pins(v2("2"), "", "", "") do
    Err(_) -> assert(false)
    Ok(pins) -> assert(Bytes.length(pins.ohttp_key_config) == 0 && pins.ohttp_relay == "")
  end
end
