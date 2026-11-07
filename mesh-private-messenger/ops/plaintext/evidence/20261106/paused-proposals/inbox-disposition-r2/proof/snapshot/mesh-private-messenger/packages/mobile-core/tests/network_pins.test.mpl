from Mobile.NetworkPins import decode_network_pins, native_network_pins

fn frame(development :: String, core :: String, stream :: String) -> Bytes do
  Bytes.from_utf8("1\n"
    <> development
    <> "\n"
    <> core
    <> "\nhttps://edge.example\nhttps://objects.example\n"
    <> stream)
end

fn rejected(input :: Bytes) -> Bool do
  case decode_network_pins(input) do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn canonical_proof() -> Bool!String do
  let pins = decode_network_pins(frame("0",
    "https://core.example",
    "wss://stream.example/v1/mailbox/stream"))?
  assert(!pins.development)
  assert(pins.object_work_difficulty == 16)
  assert(pins.core_origin == "https://core.example")
  assert(pins.edge_origin == "https://edge.example")
  assert(pins.object_origin == "https://objects.example")
  assert(pins.stream_url == "wss://stream.example/v1/mailbox/stream")
  for core in [
    "http://127.0.0.1:18086",
    "https://core.example/",
    "https://user@core.example",
    "https://core.example?secret=1",
    "https://core.example#x",
    "https://core.example\\evil",
    "https://CORE.example",
    "https://core.example:443",
    "https://core.example\r"
  ] do
    assert(rejected(frame("0", core, "wss://stream.example/v1/mailbox/stream")))
  end
  for stream in [
    "ws://127.0.0.1:18090/v1/mailbox/stream",
    "wss://stream.example/wrong",
    "wss://stream.example/v1/mailbox/stream?auth=x",
    "wss://user@stream.example/v1/mailbox/stream",
    "wss://stream.example/v1/mailbox/stream/",
    "wss://stream.example:443/v1/mailbox/stream"
  ] do
    assert(rejected(frame("0", "https://core.example", stream)))
  end
  assert(rejected(frame("2", "https://core.example", "wss://stream.example/v1/mailbox/stream")))
  assert(rejected(Bytes.from_utf8("1\n0\nhttps://core.example\nhttps://edge.example\nhttps://objects.example\nwss://stream.example/v1/mailbox/stream\n")))
  Ok(true)
end

fn development_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let dev = Bytes.from_utf8("1\n1\nhttp://127.0.0.1:18086\nhttp://localhost:18087\nhttp://[::1]:18089\nws://127.0.0.1:18090/v1/mailbox/stream")
  let pins = decode_network_pins(dev)?
  assert(pins.development)
  for host in ["10.0.0.2", "192.168.1.2", "127.0.0.2", "localhost.attacker.example"] do
    assert(rejected(frame("1",
      "http://" <> host <> ":18086",
      "wss://stream.example/v1/mailbox/stream")))
  end
  case native_network_pins() do
    Err(error) -> assert(error == "network_configuration_required")
    Ok(_) -> assert(false)
  end
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"), dev))
  assert(native_network_pins()?.stream_url == pins.stream_url)
  Ok(true)
end

test("native network pins require canonical TLS origins and an exact mailbox path") do
  case canonical_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("development transport is loopback only and selected through the private native callback") do
  case development_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn difficulty_proof() -> Bool!String do
  let prefix = "2\n0\nhttps://core.example\nhttps://edge.example\nhttps://objects.example\nwss://stream.example/v1/mailbox/stream\n"
  for value in ["1", "16", "24"] do
    assert(Some(decode_network_pins(Bytes.from_utf8(prefix <> value))?.object_work_difficulty) == String.to_int(value))
  end
  for value in ["", "0", "25", "01", "1.0", "1e1", "-1", " 16", "16\n"] do
    assert(rejected(Bytes.from_utf8(prefix <> value)))
  end
  assert(rejected(Bytes.from_utf8("3\n0\nhttps://core.example\nhttps://edge.example\nhttps://objects.example\nwss://stream.example/v1/mailbox/stream\n16")))
  Ok(true)
end

test("native object work difficulty requires a bounded canonical versioned frame") do
  case difficulty_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
