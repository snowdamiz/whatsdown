from Transparency.Config import (
  decode_security_config,
  encode_security_config,
  witness_policy_for_log
)
from Transparency.AnchorChain import configured_anchor_pins

fn base_frame(version :: Int, rpcs :: List<String>) -> String do
  if version == 1 do
    String.join([
        "1",
        String.repeat("11", 32),
        String.repeat("01", 32),
        String.repeat("02", 32),
        String.repeat("22", 32),
        "16"
      ],
      "\n")
  else
    let rows = [
      Int.to_string(version),
      String.repeat("11", 32),
      String.repeat("22", 32),
      "16",
      "1",
      "1",
      "a " <> String.repeat("01", 32) <> " Morse",
      "-",
      Int.to_string(List.length(rpcs))
    ]
      ++ rpcs
      ++ ["-"]
    let legacy = if version >= 3 do
      ["2", "1", "1", "old " <> String.repeat("02", 32) <> " Retired"]
    else
      List.new()
    end
    let anchor = if version >= 4 do
      ["-", "-"]
    else
      List.new()
    end
    let relay = if version == 5 do
      ["-", "0"]
    else
      List.new()
    end
    String.join(rows ++ legacy ++ anchor ++ relay, "\n")
  end
end

fn refused(text :: String) -> Bool do
  case decode_security_config(Bytes.from_utf8(text)) do
    Ok(_) -> false
    Err(_) -> true
  end
end

fn envelope_proof() -> Bool!String do
  for version in 1..6 do
    let old = base_frame(version, List.new())
    let decoded = decode_security_config(Bytes.from_utf8(old))?
    assert(decoded.version == version && decoded.wire_version == version)
    assert(decoded.minimum_session_suite == 1)
    assert(Bytes.to_utf8(encode_security_config(decoded)?)? == old)
    for minimum in [1, 2] do
      let text = "6\n#{minimum}\n" <> old
      let config = decode_security_config(Bytes.from_utf8(text))?
      assert(config.version == version && config.wire_version == 6)
      assert(config.minimum_session_suite == minimum)
      assert(Bytes.to_utf8(encode_security_config(config)?)? == text)
      assert(Bytes.to_utf8(encode_security_config(%{config |
        wire_version: version,
        minimum_session_suite: 1
      })?)? == old)
      assert(config.log_version == if version >= 3 do
          2
        else
          1
        end)
      assert(List.length(config.relay_urls) == 0 && config.slash_mint == "-")
      assert(config.anchor_address == "-" && config.anchor_program == "-")
      case configured_anchor_pins(config)? do
        None -> nil
        Some(_) -> assert(false)
      end
      assert(witness_policy_for_log(config, 1)?.threshold == if version == 1 do
          2
        else
          1
        end)
      if version >= 3 do
        assert(witness_policy_for_log(config, 2)?.threshold == 1)
      else
        case witness_policy_for_log(config, 2) do
          Ok(_) -> assert(false)
          Err(_) -> nil
        end
      end
    end
  end
  println("c3-config-envelope:passed")
  Ok(true)
end

fn refusal_proof() -> Bool!String do
  let old = base_frame(2, List.new())
  for minimum in ["", "0", "3", "-1", "+2", "02", "2.0", " 2", "2 "] do
    assert(refused("6\n" <> minimum <> "\n" <> old))
  end
  for bad in [
    "6",
    "6\n2",
    "6\n2\n",
    "6\n2\n6\n1\n" <> old,
    "6\n2\n" <> old <> "\n",
    "6\n2\n" <> old <> "\nextra",
    "6\r\n2\n" <> old,
    "7\n2\n" <> old
  ] do
    assert(refused(bad))
  end
  let config = decode_security_config(Bytes.from_utf8(old))?
  for bad in [
    %{config | minimum_session_suite: 2},
    %{config | wire_version: 3},
    %{config | version: 6, wire_version: 6, minimum_session_suite: 2},
    %{config | wire_version: 6, minimum_session_suite: 0},
    %{config | wire_version: 6, minimum_session_suite: 3},
    %{config | wire_version: 6, minimum_session_suite: 2, log_version: 2},
    %{config | wire_version: 6, minimum_session_suite: 2, anchor_program: String.repeat("1", 32)},
    %{config | wire_version: 6, minimum_session_suite: 2, relay_urls: ["https://relay.example"]}
  ] do
    case encode_security_config(bad) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  println("c3-config-refusal:passed")
  Ok(true)
end

fn padded_rpcs(urls :: List<String>, remaining :: Int, index :: Int) -> List<String>!String do
  if index >= List.length(urls) do
    if remaining != 0 do
      Err("fixture_size_unreachable")
    else
      Ok(urls)
    end
  else
    let old = List.get(urls, index)
    let grow = if remaining < 2048 - String.length(old) do
      remaining
    else
      2048 - String.length(old)
    end
    let next = List.take(urls, index)
      ++ [old <> String.repeat("a", grow)]
      ++ List.drop(urls, index + 1)
    padded_rpcs(next, remaining - grow, index + 1)
  end
end

fn sized_frame(version :: Int, size :: Int) -> String!String do
  let urls = [
    "https://one.example/",
    "https://two.example/",
    "https://three.example/",
    "https://four.example/"
  ]
  let remaining = size - Bytes.length(Bytes.from_utf8(base_frame(version, urls)))
  if remaining < 0 do
    return Err("invalid_fixture_size")
  end
  let result = base_frame(version, padded_rpcs(urls, remaining, 0)?)
  assert(Bytes.length(Bytes.from_utf8(result)) == size)
  Ok(result)
end

fn size_proof() -> Bool!String do
  let maximum = "6\n2\n" <> sized_frame(3, 8188)?
  let decoded = decode_security_config(Bytes.from_utf8(maximum))?
  assert(Bytes.length(encode_security_config(decoded)?) == 8192)
  assert(refused("6\n2\n" <> sized_frame(3, 8189)?))
  assert(!refused(sized_frame(3, 8192)?))
  assert(!refused("6\n2\n" <> sized_frame(2, 4096)?))
  assert(refused("6\n2\n" <> sized_frame(2, 4097)?))
  println("c3-config-size:passed")
  Ok(true)
end

test("v6 wraps exact legacy feature profiles with an independent minimum") do
  case envelope_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("v6 refuses ambiguous floors, nested frames and profile authority mutation") do
  case refusal_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("v6 complete and embedded size bounds are independently enforced") do
  case size_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
