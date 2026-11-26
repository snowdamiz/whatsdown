from Security.Config import (
  SecurityConfig,
  security_config_encode,
  security_config_majority,
  security_config_morse_run,
  security_config_parse,
  security_config_profile,
  security_config_witness_keys
)
from Transparency.Merkle import WitnessKey

fn hex_of(seed :: Int) -> String do
  case Bytes.repeat(seed, 32) do
    Err(_) -> ""
    Ok(value) -> case Crypto.signing_from_seed(value) do
      Err(_) -> ""
      Ok(pair) -> Bytes.to_hex(pair.public_key.bytes)
    end
  end
end

fn delivery_hex() -> String do
  case Bytes.repeat(77, 32) do
    Err(_) -> ""
    Ok(value) -> case Crypto.x25519_from_seed(value) do
      Err(_) -> ""
      Ok(pair) -> Bytes.to_hex(pair.public_key.bytes)
    end
  end
end

fn witness_line(id :: String, seed :: Int, label :: String) -> String do
  id <> " " <> hex_of(seed) <> " " <> label
end

fn frame_of(lines :: List<String>) -> Bytes do
  Bytes.from_utf8(String.join(lines, "\n"))
end

# A Bootstrap B1 set with the chain anchor, three RPC endpoints, one relay,
# credits off and the C2SP view on.

fn base_lines() -> List<String> do
  [
    "2",
    hex_of(1),
    delivery_hex(),
    "16",
    "2",
    "3",
    witness_line("witness-a", 2, "Morse"),
    witness_line("witness-b", 3, "Morse"),
    witness_line("witness-c", 4, "Morse"),
    "Judge11111111111111111111111111111111111111 LogAccount1111111111111111111111111111111",
    "3",
    "https://rpc-one.example/solana",
    "https://rpc-two.example",
    "https://rpc-three.example:8899/v1",
    "1",
    "https://relay.example",
    "-",
    "morseapp.io/log/main",
    "2"
  ]
end

fn replaced(values :: List<String>, position :: Int, value :: String) -> List<String> do
  for index in 0..List.length(values) do
    if index == position do
      value
    else
      List.get(values, index)
    end
  end
end

fn accepted(frame :: Bytes) -> Bool do
  case security_config_parse(frame) do
    Ok(_) -> true
    Err(_) -> false
  end
end

fn base58_anchor() -> String do
  case Bytes.repeat(9, 32) do
    Err(_) -> "-"
    Ok(program) -> case Bytes.repeat(10, 32) do
      Err(_) -> "-"
      Ok(account) -> Bytes.to_base58(program) <> " " <> Bytes.to_base58(account)
    end
  end
end

fn valid_lines() -> List<String> do
  replaced(base_lines(), 9, base58_anchor())
end

fn parse_v2() -> Bool!String do
  let frame = frame_of(valid_lines())
  let config = security_config_parse(frame)?
  assert(config.version == 2 && config.threshold == 2 && config.abuse_difficulty == 16)
  assert(List.length(config.witnesses) == 3)
  assert(List.get(config.witnesses, 2).witness_id == "witness-c")
  assert(List.get(config.witnesses, 2).label == "Morse")
  assert(Bytes.to_hex(List.get(config.witnesses, 0).public_key) == hex_of(2))
  assert(Bytes.to_hex(config.service_public_key) == hex_of(1))
  assert(List.length(config.rpc_urls) == 3
    && List.get(config.rpc_urls, 2) == "https://rpc-three.example:8899/v1")
  assert(config.relays == ["https://relay.example"])
  assert(config.issuer_origin == "" && config.c2sp_origin == "morseapp.io/log/main")
  assert(config.minimum_suite == 2 && config.log_account != "" && config.judge_program_id != "")
  assert(Bytes.secure_equals(security_config_encode(config)?, frame))
  let keys = security_config_witness_keys(config)
  assert(List.length(keys) == 3 && List.get(keys, 1).witness_id == "witness-b")
  let expected_set = Crypto.sha256(Bytes.from_utf8("morse-witness-set-v1"
    <> String.join(List.take(List.drop(valid_lines(), 4), 5), "\n")))
  assert(Bytes.secure_equals(config.set_id, expected_set))
  Ok(true)
end

test("a v2 frame parses into the pinned set and re-encodes to the same bytes") do
  case parse_v2() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn set_identity() -> Bool!String do
  let base = security_config_parse(frame_of(valid_lines()))?
  let fewer_rpc = [
    "2",
    hex_of(1),
    delivery_hex(),
    "20",
    "2",
    "3",
    witness_line("witness-a", 2, "Morse"),
    witness_line("witness-b", 3, "Morse"),
    witness_line("witness-c", 4, "Morse"),
    "-",
    "0",
    "0",
    "https://credits.example",
    "-",
    "1"
  ]
  let other = security_config_parse(frame_of(fewer_rpc))?
  assert(Bytes.secure_equals(base.set_id, other.set_id))
  assert(other.judge_program_id == "" && List.length(other.rpc_urls) == 0)
  assert(other.issuer_origin == "https://credits.example" && other.c2sp_origin == "")
  let rotated = security_config_parse(frame_of(replaced(valid_lines(),
    8,
    witness_line("witness-c", 5, "Morse"))))?
  assert(!Bytes.secure_equals(base.set_id, rotated.set_id))
  let relabelled = security_config_parse(frame_of(replaced(valid_lines(),
    8,
    witness_line("witness-c", 4, "Example Org"))))?
  assert(!Bytes.secure_equals(base.set_id, relabelled.set_id))
  Ok(true)
end

test("set_id covers exactly the threshold, count and witness lines") do
  case set_identity() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn v1_mapping() -> Bool!String do
  let frame = frame_of(["1", hex_of(1), hex_of(2), hex_of(3), delivery_hex(), "16"])
  assert(Bytes.length(frame) == 264)
  let config = security_config_parse(frame)?
  assert(config.version == 1 && config.threshold == 2 && config.minimum_suite == 1)
  assert(List.length(config.witnesses) == 2)
  assert(List.get(config.witnesses, 0).witness_id == "witness-a")
  assert(List.get(config.witnesses, 1).witness_id == "witness-b")
  assert(Bytes.to_hex(List.get(config.witnesses, 1).public_key) == hex_of(3))
  assert(List.all(config.witnesses, fn witness -> witness.label == "Morse" end))
  assert(config.judge_program_id == "" && config.relays == [] && config.rpc_urls == [])
  assert(config.issuer_origin == "" && config.c2sp_origin == "")
  assert(security_config_profile(config) == "bootstrap")
  let equivalent = security_config_parse(frame_of([
    "2",
    hex_of(1),
    delivery_hex(),
    "16",
    "2",
    "2",
    witness_line("witness-a", 2, "Morse"),
    witness_line("witness-b", 3, "Morse"),
    "-",
    "0",
    "0",
    "-",
    "-",
    "1"
  ]))?
  assert(Bytes.secure_equals(config.set_id, equivalent.set_id))
  assert(Bytes.secure_equals(security_config_encode(config)?, security_config_encode(equivalent)?))
  assert(!accepted(frame_of(["1", hex_of(1), hex_of(2), hex_of(2), delivery_hex(), "16"])))
  assert(!accepted(frame_of(["1", hex_of(1), hex_of(2), hex_of(3), delivery_hex(), "016"])))
  assert(!accepted(frame_of(["1", hex_of(1), hex_of(2), hex_of(3), delivery_hex(), "25"])))
  Ok(true)
end

test("a v1 frame maps to witness-a and witness-b, 2 of 2, everything else off") do
  case v1_mapping() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("the threshold is always a strict majority") do
  assert(security_config_majority(1) == 1)
  assert(security_config_majority(2) == 2)
  assert(security_config_majority(3) == 2)
  assert(security_config_majority(4) == 3)
  assert(security_config_majority(5) == 3)
  assert(security_config_majority(9) == 5)
  assert(security_config_majority(16) == 9)
  let lines = valid_lines()
  assert(!accepted(frame_of(replaced(lines, 4, "3"))))
  assert(!accepted(frame_of(replaced(lines, 4, "1"))))
  let four = [
    "2",
    hex_of(1),
    delivery_hex(),
    "16",
    "2",
    "4",
    witness_line("a", 2, "Morse"),
    witness_line("b", 3, "Morse"),
    witness_line("c", 4, "Org C"),
    witness_line("d", 5, "Org D"),
    "-",
    "0",
    "0",
    "-",
    "-",
    "1"
  ]
  assert(!accepted(frame_of(four)))
  assert(accepted(frame_of(replaced(four, 4, "3"))))
end

fn witness_rules() -> Bool!String do
  let lines = valid_lines()
  assert(accepted(frame_of(lines)))
  assert(!accepted(frame_of(replaced(lines, 7, witness_line("witness-a", 3, "Morse")))))
  assert(!accepted(frame_of(replaced(lines, 7, witness_line("witness-b", 2, "Morse")))))
  assert(!accepted(frame_of(replaced(lines, 7, witness_line("witness-0", 3, "Morse")))))
  assert(!accepted(frame_of(replaced(lines, 7, witness_line("Witness-b", 3, "Morse")))))
  assert(!accepted(frame_of(replaced(lines, 7, witness_line("witness_b", 3, "Morse")))))
  assert(!accepted(frame_of(replaced(lines, 7, witness_line("witness-b", 3, " Morse")))))
  assert(!accepted(frame_of(replaced(lines, 7, witness_line("witness-b", 3, "Morse ")))))
  assert(!accepted(frame_of(replaced(lines, 7, witness_line("witness-b", 3, "")))))
  assert(!accepted(frame_of(replaced(lines, 7, witness_line("witness-b", 3, "Mo\trse")))))
  assert(!accepted(frame_of(replaced(lines,
    7,
    witness_line("witness-b", 3, String.repeat("x", 49))))))
  assert(accepted(frame_of(replaced(lines,
    7,
    witness_line("witness-b", 3, String.repeat("x", 48))))))
  assert(accepted(frame_of(replaced(lines, 7, witness_line("witness-b", 3, "Two  Spaces Inside")))))
  assert(!accepted(frame_of(replaced(lines,
    7,
    "witness-b " <> String.to_upper(hex_of(3)) <> " Morse"))))
  assert(!accepted(frame_of(replaced(lines, 7, "witness-b " <> hex_of(3)))))
  assert(accepted(frame_of(replaced(lines,
    8,
    witness_line("witness-" <> String.repeat("c", 56), 4, "Morse")))))
  assert(!accepted(frame_of(replaced(lines,
    8,
    witness_line("witness-" <> String.repeat("c", 57), 4, "Morse")))))
  Ok(true)
end

test("witness IDs, keys and labels must be unique, sorted and well formed") do
  case witness_rules() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn endpoint_rules() -> Bool!String do
  let lines = valid_lines()
  assert(!accepted(frame_of(replaced(lines, 11, "http://rpc-one.example"))))
  assert(!accepted(frame_of(replaced(lines, 11, "https://user@rpc-one.example"))))
  assert(!accepted(frame_of(replaced(lines, 11, "https://rpc-one.example/?key=1"))))
  assert(!accepted(frame_of(replaced(lines, 11, "https://rpc-one.example/#top"))))
  assert(!accepted(frame_of(replaced(lines, 11, "https://"))))
  assert(!accepted(frame_of(replaced(lines, 11, "https://rpc one.example"))))
  assert(!accepted(frame_of(replaced(lines, 15, "https://relay.example/path"))))
  assert(!accepted(frame_of(replaced(lines, 16, "https://credits.example/"))))
  assert(accepted(frame_of(replaced(lines, 16, "https://credits.example"))))
  assert(!accepted(frame_of(replaced(lines, 17, "morseapp.io/log main"))))
  assert(!accepted(frame_of(replaced(lines, 18, "3"))))
  assert(!accepted(frame_of(replaced(lines, 9, "not-base58-0OIl other"))))
  assert(!accepted(frame_of(replaced(lines, 9, "Judge1111"))))
  let no_rpc = List.take(lines, 10) ++ ["0"] ++ List.drop(lines, 14)
  assert(!accepted(frame_of(no_rpc)))
  assert(!accepted(frame_of(replaced(lines, 13, "https://rpc-one.example/solana"))))
  assert(!accepted(frame_of(List.take(lines, 14)
    ++ ["2", "https://relay.example", "https://relay.example"]
    ++ List.drop(lines, 16))))
  let two_rpc = List.take(lines, 10)
    ++ ["2"]
    ++ List.take(List.drop(lines, 11), 2)
    ++ List.drop(lines, 14)
  assert(!accepted(frame_of(two_rpc)))
  let no_anchor = replaced(lines, 9, "-")
  assert(!accepted(frame_of(no_anchor)))
  assert(accepted(frame_of(replaced(no_rpc, 9, "-"))))
  let nine = for index in 0..9 do
    "https://rpc-#{index}.example"
  end
  assert(!accepted(frame_of(List.take(lines, 10) ++ ["9"] ++ nine ++ List.drop(lines, 14))))
  let relays = for index in 0..9 do
    "https://relay-#{index}.example"
  end
  assert(!accepted(frame_of(List.take(lines, 14) ++ ["9"] ++ relays ++ List.drop(lines, 16))))
  assert(accepted(frame_of(List.take(lines, 14)
    ++ ["8"]
    ++ List.take(relays, 8)
    ++ List.drop(lines, 16))))
  Ok(true)
end

test("RPC, relay and issuer endpoints are distinct bare https; an anchor needs 3 to 8 RPC URLs") do
  case endpoint_rules() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("trailing newlines, non-canonical numbers, bad keys and oversized frames are refused") do
  let lines = valid_lines()
  let text = String.join(lines, "\n")
  assert(accepted(Bytes.from_utf8(text)))
  assert(!accepted(Bytes.from_utf8(text <> "\n")))
  assert(!accepted(Bytes.from_utf8("\n" <> text)))
  assert(!accepted(frame_of(replaced(lines, 3, "016"))))
  assert(!accepted(frame_of(replaced(lines, 3, "+16"))))
  assert(!accepted(frame_of(replaced(lines, 3, " 16"))))
  assert(!accepted(frame_of(replaced(lines, 3, "0"))))
  assert(!accepted(frame_of(replaced(lines, 3, "25"))))
  assert(!accepted(frame_of(replaced(lines, 5, "03"))))
  assert(!accepted(frame_of(replaced(lines, 0, "3"))))
  assert(!accepted(frame_of(replaced(lines, 1, String.to_upper(hex_of(1))))))
  assert(!accepted(frame_of(replaced(lines, 2, String.repeat("0", 64)))))
  assert(!accepted(frame_of(List.take(lines, 18))))
  let rpc = for index in 0..8 do
    "https://rpc-#{index}.example/" <> String.repeat("p", 230)
  end
  let relays = for index in 0..8 do
    "https://relay-#{index}." <> String.repeat("r", 230) <> ".example"
  end
  let largest = List.take(lines, 10) ++ ["8"] ++ rpc ++ ["8"] ++ relays ++ List.drop(lines, 16)
  assert(Bytes.length(frame_of(largest)) > 4096)
  assert(!accepted(frame_of(largest)))
  let smaller = List.take(lines, 10)
    ++ ["8"]
    ++ rpc
    ++ ["3"]
    ++ List.take(relays, 3)
    ++ List.drop(lines, 16)
  assert(Bytes.length(frame_of(smaller)) <= 4096)
  assert(accepted(frame_of(smaller)))
end

fn profile_of(labels :: List<String>) -> String!String do
  let count = List.length(labels)
  let witness_lines = for index in 0..count do
    witness_line("w#{index}", index + 40, List.get(labels, index))
  end
  let config = security_config_parse(frame_of([
    "2",
    hex_of(1),
    delivery_hex(),
    "16",
    Int.to_string(security_config_majority(count)),
    Int.to_string(count)
  ]
    ++ witness_lines
    ++ ["-", "0", "0", "-", "-", "1"]))?
  Ok(security_config_profile(config) <> "/" <> Int.to_string(security_config_morse_run(config)))
end

fn profiles() -> Bool!String do
  assert(profile_of(["Morse", "Morse", "Morse"])? == "bootstrap/3")
  assert(profile_of(["Morse", "Morse", "Org A", "Org B", "Org C"])? == "transitional/2")
  assert(profile_of(["Morse", "Org A", "Org B", "Org C", "Org D"])? == "open/1")
  assert(profile_of(["Org A", "Org B", "Org C"])? == "open/0")
  assert(profile_of(["Morse", "Morse", "Morse", "Org A", "Org B"])? == "bootstrap/3")
  assert(profile_of(["morse", "Morse Inc", "Org A"])? == "open/0")
  Ok(true)
end

test("Morse-run witnesses are those labelled exactly Morse, and they decide the profile") do
  case profiles() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

# The pinned Oblivious HTTP gateway key (protocol/ohttp-v1.md): an optional
# last line, an RFC 9458 key configuration and the relay's origin.

fn ohttp_key() -> String do
  "01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155000400010003"
end

fn ohttp_lines(line :: String) -> List<String> do
  valid_lines() ++ [line]
end

fn ohttp_pin() -> Bool!String do
  let frame = frame_of(ohttp_lines(ohttp_key() <> " https://edge.example"))
  let config = security_config_parse(frame)?
  assert(Bytes.to_hex(config.ohttp_key_config) == ohttp_key())
  assert(config.ohttp_relay == "https://edge.example")
  assert(Bytes.secure_equals(security_config_encode(config)?, frame))
  # Without the line the frame is as before, and pins no gateway.
  let plain = security_config_parse(frame_of(valid_lines()))?
  assert(Bytes.length(plain.ohttp_key_config) == 0 && plain.ohttp_relay == "")
  # A development build may pin a relay on a loopback or private address.
  assert(accepted(frame_of(ohttp_lines(ohttp_key() <> " http://127.0.0.1:18087"))))
  assert(accepted(frame_of(ohttp_lines(ohttp_key() <> " http://10.0.2.2:18087"))))
  assert(accepted(frame_of(ohttp_lines(ohttp_key() <> " http://localhost:18087"))))
  # Refused: plain http elsewhere, a path, a key configuration without the
  # suite or cut short, uppercase hex, a dash in place of the line, a missing
  # relay, an extra field.
  assert(!accepted(frame_of(ohttp_lines(ohttp_key() <> " http://edge.example"))))
  assert(!accepted(frame_of(ohttp_lines(ohttp_key() <> " http://8.8.8.8"))))
  assert(!accepted(frame_of(ohttp_lines(ohttp_key() <> " https://edge.example/v1/ohttp"))))
  assert(!accepted(frame_of(ohttp_lines("01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155000400010001 https://edge.example"))))
  assert(!accepted(frame_of(ohttp_lines("01002031e1f05a74 https://edge.example"))))
  assert(!accepted(frame_of(ohttp_lines(String.to_upper(ohttp_key()) <> " https://edge.example"))))
  assert(!accepted(frame_of(ohttp_lines("-"))))
  assert(!accepted(frame_of(ohttp_lines(ohttp_key()))))
  assert(!accepted(frame_of(ohttp_lines(ohttp_key() <> " https://edge.example x"))))
  Ok(true)
end

test("an optional last line pins the OHTTP gateway key configuration and its relay") do
  case ohttp_pin() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
