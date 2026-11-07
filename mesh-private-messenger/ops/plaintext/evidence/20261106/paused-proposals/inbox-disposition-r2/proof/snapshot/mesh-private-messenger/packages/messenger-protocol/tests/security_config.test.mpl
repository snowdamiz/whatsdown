from Transparency.Config import (
  SecurityConfig,
  WitnessPin,
  decode_security_config,
  encode_security_config,
  pinned_witness_keys,
  witness_policy_for_log
)
from Transparency.Merkle import sign_checkpoint, sign_witness, verify_witnesses

fn key(number :: Int) -> Bytes!String do
  case Bytes.repeat(number, 32) do
    Err(_) -> Err("test allocation failed")
    Ok(value)
  end
end

fn frame(threshold :: Int,
  witness_lines :: List<String>,
  anchor :: String,
  rpcs :: List<String>,
  issuer :: String) -> Bytes do
  let rows = [
    "2",
    String.repeat("11", 32),
    String.repeat("22", 32),
    "16",
    Int.to_string(threshold),
    Int.to_string(List.length(witness_lines))
  ]
    ++ witness_lines
    ++ [anchor, Int.to_string(List.length(rpcs))]
    ++ rpcs
    ++ [issuer]
  Bytes.from_utf8(String.join(rows, "\n"))
end

fn witness(id :: String, number :: Int, operator :: String) -> String!String do
  Ok(id <> " " <> Bytes.to_hex(key(number)?) <> " " <> operator)
end

fn refused(value :: Bytes) -> Bool do
  case decode_security_config(value) do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn config_proof() -> Bool!String do
  let lines = [
    witness("a", 1, "Morse")?,
    witness("b", 2, "Outside One")?,
    witness("c", 3, "Outside Two")?
  ]
  let original = frame(2, lines, "-", List.new(), "-")
  let config = decode_security_config(original)?
  assert(config.threshold == 2 && List.length(config.witnesses) == 3)
  assert(Bytes.secure_equals(encode_security_config(config)?, original))
  let set_text = "morse-witness-set-v1" <> String.join(["2", "3"] ++ lines, "\n")
  assert(Bytes.secure_equals(config.set_id, Crypto.sha256(Bytes.from_utf8(set_text))))
  let rpcs = ["https://one.example/rpc", "https://two.example/rpc", "https://three.example/rpc"]
  let enabled = frame(2, lines, Bytes.to_base58(key(5)?), rpcs, "https://credits.example")
  assert(Bytes.secure_equals(encode_security_config(decode_security_config(enabled)?)?, enabled))
  assert(refused(frame(1, lines, "-", List.new(), "-")))
  assert(refused(frame(3, lines, "-", List.new(), "-")))
  assert(refused(frame(2,
    [List.get(lines, 1), List.get(lines, 0), List.get(lines, 2)],
    "-",
    List.new(),
    "-")))
  assert(refused(frame(2,
    [List.get(lines, 0), List.get(lines, 0), List.get(lines, 2)],
    "-",
    List.new(),
    "-")))
  assert(refused(frame(2,
    [List.get(lines, 0), witness("b", 1, "Other")?, List.get(lines, 2)],
    "-",
    List.new(),
    "-")))
  assert(refused(frame(1, [witness("UPPER", 1, "Morse")?], "-", List.new(), "-")))
  assert(refused(frame(1, [witness("a", 1, " Trailing ")?], "-", List.new(), "-")))
  assert(refused(frame(1, [witness("a", 1, String.repeat("x", 49))?], "-", List.new(), "-")))
  assert(refused(frame(2, lines, "not-base58", rpcs, "-")))
  assert(refused(frame(2, lines, "-", ["https://one.example"], "-")))
  assert(refused(frame(2,
    lines,
    "-",
    ["https://one.example/rpc-a", "https://one.example/rpc-b", "https://three.example"],
    "-")))
  assert(refused(frame(2,
    lines,
    "-",
    ["http://one.example", List.get(rpcs, 1), List.get(rpcs, 2)],
    "-")))
  assert(refused(frame(2, lines, "-", rpcs, "https://credits.example/path")))
  assert(refused(frame(2,
    lines,
    "-",
    ["https://host:99999", List.get(rpcs, 1), List.get(rpcs, 2)],
    "-")))
  assert(refused(frame(2, lines, "-", rpcs, "https://[broken")))
  assert(refused(Bytes.concat(original, Bytes.from_utf8("\n"))?))
  let legacy = Bytes.from_utf8(String.join([
      "1",
      String.repeat("11", 32),
      String.repeat("01", 32),
      String.repeat("02", 32),
      String.repeat("22", 32),
      "16"
    ],
    "\n"))
  let old = decode_security_config(legacy)?
  assert(old.threshold == 2 && List.length(old.witnesses) == 2)
  assert(List.get(old.witnesses, 0).witness_id == "witness-a")
  assert(old.anchor_address == "-" && old.issuer_origin == "-" && List.length(old.rpc_urls) == 0)
  assert(Bytes.secure_equals(encode_security_config(old)?, legacy))
  let maximum = for index in 0..16 do
    let id = if index < 10 do
      "witness-0#{index}"
    else
      "witness-#{index}"
    end
    witness(id, index, "Operator")?
  end
  assert(decode_security_config(frame(9, maximum, "-", List.new(), "-"))?.threshold == 9)
  assert(refused(frame(9,
    maximum ++ [witness("witness-16", 16, "Operator")?],
    "-",
    List.new(),
    "-")))
  Ok(true)
end

fn threshold_proof() -> Bool!String do
  let signer = case Crypto.signing_generate() do
    Err(_) -> Err("key failed")
    Ok(value)
  end?
  let a = case Crypto.signing_generate() do
    Err(_) -> Err("key failed")
    Ok(value)
  end?
  let b = case Crypto.signing_generate() do
    Err(_) -> Err("key failed")
    Ok(value)
  end?
  let c = case Crypto.signing_generate() do
    Err(_) -> Err("key failed")
    Ok(value)
  end?
  let config = decode_security_config(frame(2,
    [
      "a " <> Bytes.to_hex(a.public_key.bytes) <> " Morse",
      "b " <> Bytes.to_hex(b.public_key.bytes) <> " One",
      "c " <> Bytes.to_hex(c.public_key.bytes) <> " Two"
    ],
    "-",
    List.new(),
    "-"))?
  let checkpoint = sign_checkpoint(signer.private_key,
    signer.public_key.bytes,
    U64.parse("1")?,
    [Crypto.sha256(Bytes.from_utf8("entry"))],
    key(0)?,
    U64.parse("1000")?)?
  let signed_a = sign_witness("a", a.private_key, checkpoint)?
  let signed_b = sign_witness("b", b.private_key, checkpoint)?
  let unknown = sign_witness("unknown", c.private_key, checkpoint)?
  let keys = pinned_witness_keys(config)
  assert(!verify_witnesses(checkpoint, [signed_a], keys, config.threshold)?)
  assert(!verify_witnesses(checkpoint, [signed_a, signed_a, unknown], keys, config.threshold)?)
  assert(verify_witnesses(checkpoint,
    [unknown, signed_a, signed_a, signed_b],
    keys,
    config.threshold)?)
  Ok(true)
end

test("native config v2 pins a canonical strict-majority set and accepts legacy v1") do
  case config_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("only distinct pinned signatures contribute to the configured majority") do
  case threshold_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn migration_frame(log_version :: String,
  threshold :: String,
  old_lines :: List<String>) -> Bytes!String do
  let current = frame(2,
    [witness("a", 1, "Morse")?, witness("b", 2, "One")?, witness("c", 3, "Two")?],
    "-",
    List.new(),
    "-")
  let rows = String.split(Bytes.to_utf8(current)?, "\n")
  Ok(Bytes.from_utf8(String.join(["3"]
      ++ List.drop(rows, 1)
      ++ [log_version, threshold, Int.to_string(List.length(old_lines))]
      ++ old_lines,
    "\n")))
end

fn migration_config_proof() -> Bool!String do
  let old_lines = [witness("retired-a", 4, "Legacy One")?, witness("retired-b", 5, "Legacy Two")?]
  let wire = migration_frame("2", "2", old_lines)?
  let config = decode_security_config(wire)?
  assert(config.version == 3 && config.log_version == 2)
  assert(config.legacy_threshold == 2 && List.length(config.legacy_witnesses) == 2)
  assert(List.get(config.legacy_witnesses, 0).witness_id == "retired-a")
  assert(config.threshold == 2 && List.length(config.witnesses) == 3)
  assert(Bytes.secure_equals(encode_security_config(config)?, wire))
  let previous = decode_security_config(frame(2,
    [witness("a", 1, "Morse")?, witness("b", 2, "One")?, witness("c", 3, "Two")?],
    "-",
    List.new(),
    "-"))?
  assert(previous.log_version == 1
    && previous.legacy_threshold == 0
    && List.length(previous.legacy_witnesses) == 0)
  assert(Bytes.secure_equals(previous.set_id, config.set_id))
  let current_policy = witness_policy_for_log(config, 2)?
  let old_policy = witness_policy_for_log(config, 1)?
  assert(current_policy.threshold == 2 && List.length(current_policy.keys) == 3)
  assert(old_policy.threshold == 2 && List.length(old_policy.keys) == 2)
  assert(List.head(old_policy.keys).witness_id == "retired-a")
  assert(!Bytes.secure_equals(current_policy.set_id, old_policy.set_id))
  assert(Bytes.secure_equals(witness_policy_for_log(previous, 1)?.set_id, current_policy.set_id))
  case witness_policy_for_log(previous, 2) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case witness_policy_for_log(config, 3) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  for invalid in [
    migration_frame("1", "2", old_lines)?,
    migration_frame("02", "2", old_lines)?,
    migration_frame("3", "2", old_lines)?,
    migration_frame("2", "1", old_lines)?,
    migration_frame("2", "02", old_lines)?,
    migration_frame("2", "1", List.new())?,
    migration_frame("2", "2", [List.head(old_lines), List.head(old_lines)])?
  ] do
    assert(refused(invalid))
  end
  assert(refused(Bytes.concat(wire, Bytes.from_utf8("\n"))?))
  case encode_security_config(%{config | log_version: 1}) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  # Both sets may contain sixteen pins. The canonical v3 bound accommodates
  # these independent policies; old formats retain their original 4096 limit.
  let maximum = for index in 0..16 do
    witness(String.repeat("a", 62)
        <> (if index < 10 do
          "0#{index}"
        else
          "#{index}"
        end),
      index,
      String.repeat("O", 48))?
  end
  let base = frame(9, maximum, "-", List.new(), "-")
  let rows = String.split(Bytes.to_utf8(base)?, "\n")
  let big = Bytes.from_utf8(String.join(["3"] ++ List.drop(rows, 1) ++ ["2", "9", "16"] ++ maximum,
    "\n"))
  assert(Bytes.length(big) > 4096)
  assert(Bytes.secure_equals(encode_security_config(decode_security_config(big)?)?, big))
  assert(refused(Bytes.from_utf8(String.repeat("x", 8193))))
  Ok(true)
end

fn anchor_config_proof() -> Bool!String do
  let migration = migration_frame("2",
    "2",
    [witness("retired-a", 4, "Old")?, witness("retired-b", 5, "Old")?])?
  let rows = String.split(Bytes.to_utf8(migration)?, "\n")
  let off = Bytes.from_utf8(String.join(["4"] ++ List.drop(rows, 1) ++ ["-", "-"], "\n"))
  let config = decode_security_config(off)?
  assert(config.version == 4 && config.anchor_program == "-" && config.anchor_log_name == "-")
  assert(Bytes.secure_equals(encode_security_config(config)?, off))
  assert(witness_policy_for_log(config, 1)?.threshold == 2)
  assert(witness_policy_for_log(config, 2)?.threshold == 2)
  let enabled = %{config |
    anchor_address: "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb",
    anchor_program: String.repeat("1", 32),
    anchor_log_name: "morse-main",
    rpc_urls: ["https://one.example", "https://two.example", "https://three.example"]
  }
  let decoded = decode_security_config(encode_security_config(enabled)?)?
  assert(decoded.anchor_program == enabled.anchor_program
    && decoded.anchor_log_name == "morse-main")
  for bad in [
    %{enabled | anchor_program: "-"},
    %{enabled | anchor_program: "bad"},
    %{enabled | anchor_log_name: "-"},
    %{enabled | anchor_log_name: "Main"},
    %{enabled | anchor_log_name: String.repeat("a", 33)},
    %{enabled | anchor_address: "-"},
    %{enabled | version: 3, wire_version: 3},
    %{enabled | log_version: 1}
  ] do
    case encode_security_config(bad) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  assert(refused(Bytes.from_utf8(String.join(["4"] ++ List.drop(rows, 1), "\n"))))
  assert(refused(Bytes.concat(off, Bytes.from_utf8("\nextra"))?))
  Ok(true)
end

test("native v4 pins judge identity without changing either migration witness policy") do
  case anchor_config_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("native config v3 pins RFC log identity and preserves a separate legacy migration quorum") do
  case migration_config_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn relay_config_proof() -> Bool!String do
  let migration = migration_frame("2",
    "2",
    [witness("retired-a", 4, "Old")?, witness("retired-b", 5, "Old")?])?
  let rows = String.split(Bytes.to_utf8(migration)?, "\n")
  let disabled = Bytes.from_utf8(String.join(["5"] ++ List.drop(rows, 1) ++ ["-", "-", "-", "0"],
    "\n"))
  let config = decode_security_config(disabled)?
  assert(config.version == 5 && config.slash_mint == "-" && List.length(config.relay_urls) == 0)
  assert(Bytes.secure_equals(encode_security_config(config)?, disabled))
  let enabled = %{config |
    anchor_address: "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb",
    anchor_program: String.repeat("1", 32),
    anchor_log_name: "morse-main",
    rpc_urls: ["https://one.example", "https://two.example", "https://three.example"],
    slash_mint: Bytes.to_base58(key(9)?),
    relay_urls: ["https://relay-one.example", "https://relay-two.example:8443"]
  }
  let encoded = encode_security_config(enabled)?
  let decoded = decode_security_config(encoded)?
  assert(decoded.relay_urls == enabled.relay_urls && decoded.slash_mint == enabled.slash_mint)
  assert(Bytes.secure_equals(decoded.set_id, config.set_id))
  assert(witness_policy_for_log(decoded, 1)?.threshold == 2)
  assert(witness_policy_for_log(decoded, 2)?.threshold == 2)
  for bad in [
    %{enabled | version: 4, wire_version: 4},
    %{enabled | slash_mint: "-"},
    %{enabled | slash_mint: "bad"},
    %{enabled | slash_mint: String.repeat("1", 32)},
    %{enabled | anchor_address: "-", anchor_program: "-", anchor_log_name: "-"},
    %{enabled | relay_urls: ["http://relay.example"]},
    %{enabled | relay_urls: ["https://relay.example/"]},
    %{enabled | relay_urls: ["https://relay.example/path"]},
    %{enabled | relay_urls: ["https://relay.example?query"]},
    %{enabled | relay_urls: ["https://relay.example#fragment"]},
    %{enabled | relay_urls: ["https://user@relay.example"]},
    %{enabled | relay_urls: ["https://Relay.example"]},
    %{enabled | relay_urls: ["https://relay.example:443"]},
    %{enabled | relay_urls: ["https://relay.example", "https://relay.example"]},
    %{enabled |
      relay_urls: for i in 0..9 do
        "https://relay-#{i}.example"
      end
    }
  ] do
    case encode_security_config(bad) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  let maximum = %{enabled |
    relay_urls: for i in 0..8 do
      "https://relay-#{i}.example"
    end
  }
  assert(List.length(decode_security_config(encode_security_config(maximum)?)?.relay_urls) == 8)
  let text = Bytes.to_utf8(encoded)?
  assert(refused(Bytes.from_utf8(String.replace(text,
    "\n2\nhttps://relay-one",
    "\n3\nhttps://relay-one"))))
  assert(refused(Bytes.concat(encoded, Bytes.from_utf8("\nextra"))?))
  # Older formats cannot smuggle relay pins through a struct or trailing bytes.
  let legacy = decode_security_config(migration)?
  assert(legacy.slash_mint == "-" && List.length(legacy.relay_urls) == 0)
  assert(refused(Bytes.concat(migration, Bytes.from_utf8("\n-\n0"))?))
  Ok(true)
end

test("native v5 pins bounded relay origins and the receipt mint without weakening historical policies") do
  case relay_config_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
