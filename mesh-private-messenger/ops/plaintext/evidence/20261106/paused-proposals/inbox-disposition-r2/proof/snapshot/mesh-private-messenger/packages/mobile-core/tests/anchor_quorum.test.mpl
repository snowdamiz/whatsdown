from Transparency.AnchorChain import (
  AnchorPins,
  AnchorSnapshot,
  read_anchor_header,
  read_anchor_entry,
  sample_anchor_sources,
  read_anchor_log,
  anchor_addresses,
  read_anchor_witness_set
)
from Transparency.AnchorWitnessSet import AnchorWitnessSet, AnchorCosigner, anchor_cosigners
from Transparency.RpcTransport import webpki_rpc_transport, rpc_urls
from Transparency.AnchorLog import AnchorLog
from Solana.Address import ProgramDerivedAddress, find_program_address
from Solana.Read import pubkey, pubkey_string
from Transparency.AnchorRing import AnchorHeader, AnchorEntry

fn header_bytes(mode :: String) -> Bytes!String do
  let log_id = if mode == "wrong-log" do
    String.repeat("22", 32)
  else
    Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("morse-main")))
  end
  let sequence = if mode == "different" do
    "0600000000000000"
  else
    "0500000000000000"
  end
  Bytes.from_hex("4d524701"
    <> log_id
    <> "00000100"
    <> sequence
    <> "0800000000000000f401000000000000")
end

fn entry_bytes(mode :: String) -> Bytes!String do
  let sequence = if mode == "overwritten" do
    "0600000000000000"
  else
    "0500000000000000"
  end
  Bytes.from_hex(sequence
    <> "0800000000000000"
    <> String.repeat("22", 32)
    <> String.repeat("33", 32)
    <> "00f1536500000000f4010000000000000300020001000700")
end

fn respond(request :: Request, mode :: String) -> Response do
  if mode == "down" do
    return HTTP.response(503, "unavailable")
  end
  let body = Request.body(request)
  # Independent official SDK fixtures from the judge's anchor_address_fixture
  # example. Returning the right bytes at an unrelated address must not pass.
  let expected_address = if String.contains(body, "\"length\":352") do
    "2he32vXesDyeZVeYbuxNKJKYX3354iWmhuijN92XMky7"
  else if String.contains(body, "\"length\":2752") do
    "CGqsSLyfU419ptwTTGdpiwKPGrMs9niP7sM3kEAtnPDU"
  else
    "5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb"
  end
  if !String.contains(body, "\"params\":[\"" <> expected_address <> "\",") do
    return HTTP.response(400, "wrong account address")
  end
  let bytes = if String.contains(body, "\"offset\":0,")
    && String.contains(body, "\"length\":2752") do
    witness_set_bytes(mode)
  else if String.contains(body, "\"offset\":0,") && String.contains(body, "\"length\":352") do
    log_bytes(mode)
  else if String.contains(body, "\"offset\":0,") do
    header_bytes(mode)
  else if String.contains(body, "\"offset\":64,")
    && String.contains(body, "\"minContextSlot\":501") do
    entry_bytes(mode)
  else
    return HTTP.response(400, "wrong snapshot or slice")
  end
  case bytes do
    Err(_) -> HTTP.response(500, "invalid fixture")
    Ok(data) -> do
      let slot = if mode == "future" do
        "499"
      else if mode == "later" do
        "999"
      else
        "501"
      end
      let owner = if mode == "wrong-owner" do
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
      else
        "11111111111111111111111111111111"
      end
      HTTP.response(200,
        """{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":#{slot}},"value":{"data":["#{Bytes.to_base64(data)}","base64"],"executable":false,"lamports":1,"owner":"#{owner}","rentEpoch":0}}}""")
    end
  end
end

actor rpc_server(port :: Int) do
  HTTP.router()
    |> HTTP.on_post("/good", fn(r :: Request) do respond(r, "good") end)
    |> HTTP.on_post("/later", fn(r :: Request) do respond(r, "later") end)
    |> HTTP.on_post("/different", fn(r :: Request) do respond(r, "different") end)
    |> HTTP.on_post("/down", fn(r :: Request) do respond(r, "down") end)
    |> HTTP.on_post("/wrong-log", fn(r :: Request) do respond(r, "wrong-log") end)
    |> HTTP.on_post("/wrong-owner", fn(r :: Request) do respond(r, "wrong-owner") end)
    |> HTTP.on_post("/overwritten", fn(r :: Request) do respond(r, "overwritten") end)
    |> HTTP.on_post("/future", fn(r :: Request) do respond(r, "future") end)
    |> HTTP.on_post("/slashed", fn(r :: Request) do respond(r, "slashed") end)
    |> HTTP.on_post("/foreign-service", fn(r :: Request) do respond(r, "foreign-service") end)
    |> HTTP.on_post("/foreign-ring", fn(r :: Request) do respond(r, "foreign-ring") end)
    |> HTTP.serve(port)
end

fn pins(routes :: List<String>) -> AnchorPins!String do
  let address = pubkey("11111111111111111111111111111111")?
  let derived = anchor_addresses(address, "morse-main")?
  Ok(AnchorPins {
    ring: derived.ring,
    program: address,
    log_name: "morse-main",
    log_id: derived.log_id,
    rpc: webpki_rpc_transport(for index in 0..List.length(routes) do
      "http://127.0.0.1:#{19011 + index}/#{List.get(routes, index)}"
    end)?
  })
end

fn proof() -> Bool!String do
  let _one = spawn(rpc_server, 19011)
  let _two = spawn(rpc_server, 19012)
  let _three = spawn(rpc_server, 19013)
  Timer.sleep(100)
  for routes in [
    ["good", "later", "down"],
    ["different", "good", "good"],
    ["down", "good", "good"],
    ["good", "down", "later"],
    ["wrong-owner", "good", "good"]
  ] do
    let policy = pins(routes)?
    let header = read_anchor_header(policy, U64.parse("0")?)?
    assert(header.header.count == 1 && U64.to_string(header.context_slot) == "501")
    let entry = read_anchor_entry(policy, header, 0)?
    assert(U64.to_string(entry.sequence) == "5" && entry.native_bitmap == 1)
  end
  for routes in [
    ["different", "good", "down"],
    ["down", "good", "down"],
    ["wrong-log", "wrong-log", "good"],
    ["future", "future", "future"]
  ] do
    case read_anchor_header(pins(routes)?, U64.parse("0")?) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  let overwritten = pins(["overwritten", "overwritten", "overwritten"])?
  let header = read_anchor_header(overwritten, U64.parse("0")?)?
  case read_anchor_entry(overwritten, header, 0) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "anchor_snapshot_changed")
  end
  let same = pins(["good", "good", "good"])?
  let canary = anchor_addresses(same.program, "morse-canary")?
  assert(pubkey_string(canary.log) == "6ApZ5oTow3CZ9d8ggthFGpBAhj8nu4ndiGvF78HMEqru")
  assert(pubkey_string(canary.ring) == "D9mWiuuEDxC1CXJQMXgiB4zAj8yviMwwZQ3mvLUW5MD")
  for invalid in [
    %{same | ring: same.program},
    %{same | log_name: "Morse-main"},
    %{same | log_name: "morse-canary"},
    %{same | log_name: String.repeat("a", 33)}
  ] do
    case read_anchor_header(invalid, U64.parse("0")?) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  let snapshot = read_anchor_header(same, U64.parse("0")?)?
  let entry = read_anchor_entry(same, snapshot, 0)?
  let set = read_anchor_witness_set(same, entry.witness_generation, snapshot.context_slot)?
  let cosigners = anchor_cosigners(entry, set)?
  assert(List.length(cosigners) == 2 && List.get(cosigners, 0).native)
  assert(!List.get(cosigners, 1).native && List.get(cosigners, 1).witness_id == "witness-b")
  for invalid in [0, 6, 65536] do
    case read_anchor_witness_set(same, invalid, snapshot.context_slot) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  let foreign_set = pins(["wrong-log", "wrong-log", "good"])?
  case read_anchor_witness_set(foreign_set, 7, snapshot.context_slot) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  let log_id = Crypto.sha256(Bytes.from_utf8("morse-main"))
  let service_key = Bytes.from_hex(String.repeat("11", 32))?
  let log = read_anchor_log(%{same | log_id: log_id}, service_key, 2, U64.parse("0")?)?
  assert(log.name == "morse-main" && !log.service_slashed)
  let slashed = %{pins(["slashed", "slashed", "good"])? | log_id: log_id}
  assert(read_anchor_log(slashed, service_key, 2, U64.parse("0")?)?.service_slashed)
  for mode in ["foreign-service", "foreign-ring"] do
    let foreign = %{pins([mode, mode, "good"])? | log_id: log_id}
    case read_anchor_log(foreign, service_key, 2, U64.parse("0")?) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  case read_anchor_log(%{same | log_id: Bytes.from_hex(String.repeat("11", 32))?},
    service_key,
    2,
    U64.parse("0")?) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  case read_anchor_log(%{same | log_id: log_id}, service_key, 1, U64.parse("0")?) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  let candidates = pins(["good", "good", "good", "good", "good", "good", "good", "good"])?
  let sampled = sample_anchor_sources(candidates)?
  assert(List.length(rpc_urls(sampled.rpc)) == 3)
  for index in 0..3 do
    assert(List.any(rpc_urls(candidates.rpc),
      fn(value :: String) -> value == List.get(rpc_urls(sampled.rpc), index) end))
    for earlier in 0..index do
      assert(List.get(rpc_urls(sampled.rpc), earlier) != List.get(rpc_urls(sampled.rpc), index))
    end
  end
  for endpoints in [
    [List.head(rpc_urls(same.rpc))],
    [List.head(rpc_urls(same.rpc)), List.head(rpc_urls(same.rpc)), List.get(rpc_urls(same.rpc), 1)],
    ["http://127.0.0.1:19011/good", "http://127.0.0.1:19011/later", "http://127.0.0.1:19012/good"]
  ] do
    case read_anchor_header(%{same | rpc: webpki_rpc_transport(endpoints)?}, U64.parse("0")?) do
      Ok(_) -> assert(false)
      Err(error) -> assert(error == "invalid_anchor_sources")
    end
  end
  Ok(true)
end

fn log_bytes(mode :: String) -> Bytes!String do
  let name = Bytes.from_utf8("morse-main")
  let origin = Bytes.from_utf8("morseapp.io/log/main/v2")
  let slashed = if mode == "slashed" do
    "01"
  else
    "00"
  end
  let service_key = if mode == "foreign-service" do
    "55"
  else
    "11"
  end
  let ring = if mode == "foreign-ring" do
    String.repeat("33", 32)
  else
    Bytes.to_hex(anchor_addresses(pubkey("11111111111111111111111111111111")?,
      "morse-main")?.ring.bytes)
  end
  Bytes.from_hex("4d4c470102"
    <> slashed
    <> "0a00"
    <> Bytes.to_hex(name)
    <> String.repeat("00", 22)
    <> Bytes.to_hex(Crypto.sha256(name))
    <> String.repeat(service_key, 32)
    <> String.repeat("22", 32)
    <> ring
    <> String.repeat("00", 32)
    <> "007512000000000000001700"
    <> Bytes.to_hex(origin)
    <> String.repeat("00", 128 - Bytes.length(origin) + 12))
end

fn witness_set_bytes(mode :: String) -> Bytes!String do
  let log_id = if mode == "wrong-log" do
    String.repeat("22", 32)
  else
    Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("morse-main")))
  end
  let first = String.repeat("33", 32)
    <> "09"
    <> String.repeat("00", 7)
    <> Bytes.to_hex(Bytes.from_utf8("witness-a"))
    <> String.repeat("00", 55)
    <> String.repeat("44", 32)
    <> String.repeat("55", 32)
  let second = String.repeat("66", 32)
    <> "09"
    <> String.repeat("00", 7)
    <> Bytes.to_hex(Bytes.from_utf8("witness-b"))
    <> String.repeat("00", 55)
    <> String.repeat("77", 32)
    <> String.repeat("55", 32)
  Bytes.from_hex("4d575301"
    <> log_id
    <> "070002000075120000000000"
    <> String.repeat("00", 16)
    <> first
    <> second
    <> String.repeat("00", 14 * 168))
end

test("anchor reads require two distinct providers, pinned identity and a stable ring position") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
