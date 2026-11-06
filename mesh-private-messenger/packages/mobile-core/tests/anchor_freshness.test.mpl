from Transparency.AnchorChain import (
  AnchorPins,
  AnchorSnapshot,
  AnchorFreshness,
  anchor_addresses,
  read_anchor_freshness
)
from Transparency.AnchorRing import decode_anchor_header
from Solana.Read import pubkey

fn respond(request :: Request, result :: String) -> Response do
  if !String.contains(Request.body(request), "\"method\":\"getBlockTime\",\"params\":[500]") do
    return HTTP.response(400, "wrong method or slot")
  end
  HTTP.response(200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":#{result}}")
end

actor rpc_server(port :: Int) do
  HTTP.router()
    |> HTTP.on_post("/good", fn(r :: Request) do respond(r, "1700000000") end)
    |> HTTP.on_post("/other", fn(r :: Request) do respond(r, "1700000001") end)
    |> HTTP.on_post("/third", fn(r :: Request) do respond(r, "1700000002") end)
    |> HTTP.on_post("/unknown", fn(r :: Request) do respond(r, "null") end)
    |> HTTP.on_post("/negative", fn(r :: Request) do respond(r, "-1") end)
    |> HTTP.on_post("/quoted", fn(r :: Request) do respond(r, "\"1700000000\"") end)
    |> HTTP.on_post("/fraction", fn(r :: Request) do respond(r, "1700000000.5") end)
    |> HTTP.on_post("/big",
      fn(r :: Request) do respond(r, Json.encode_string(String.repeat("x", 2048))) end)
    |> HTTP.on_post("/wrong-id",
      fn(_ :: Request) do HTTP.response(200,
        """{"jsonrpc":"2.0","id":2,"result":1700000000}""") end)
    |> HTTP.on_post("/down", fn(_ :: Request) do HTTP.response(503, "down") end)
    |> HTTP.serve(port)
end

fn pins(routes :: List<String>) -> AnchorPins!String do
  let program = pubkey("11111111111111111111111111111111")?
  let addresses = anchor_addresses(program, "morse-main")?
  Ok(AnchorPins {
    ring: addresses.ring,
    program: program,
    log_name: "morse-main",
    log_id: addresses.log_id,
    endpoints: for i in 0..3 do
      "http://127.0.0.1:#{19041 + i}/#{List.get(routes, i)}"
    end
  })
end

fn snapshot() -> AnchorSnapshot!String do
  let log_id = Crypto.sha256(Bytes.from_utf8("morse-main"))
  let bytes = Bytes.from_hex("4d524701"
    <> Bytes.to_hex(log_id)
    <> "0000010005000000000000000800000000000000f401000000000000")?
  Ok(AnchorSnapshot {
    header: decode_anchor_header(bytes)?,
    bytes: bytes,
    context_slot: U64.parse("501")?
  })
end

fn proof() -> Bool!String do
  let _a = spawn(rpc_server, 19041)
  let _b = spawn(rpc_server, 19042)
  let _c = spawn(rpc_server, 19043)
  Timer.sleep(100)
  let view = snapshot()?
  for routes in [
    ["good", "good", "down"],
    ["other", "good", "good"],
    ["down", "good", "good"],
    ["good", "down", "good"]
  ] do
    let config = pins(routes)?
    let fresh = read_anchor_freshness(config, view, 1700007200)?
    assert(!fresh.stale && fresh.age_seconds == 7200 && fresh.block_time_seconds == 1700000000)
    let stale = read_anchor_freshness(config, view, 1700007201)?
    assert(stale.stale && stale.age_seconds == 7201)
  end
  assert(read_anchor_freshness(pins(["good", "other", "third"])?,
    view,
    1700000002) == Err("anchor_rpc_disagree"))
  for bad in ["unknown", "negative", "quoted", "fraction", "big", "wrong-id", "down"] do
    assert(read_anchor_freshness(pins([bad, "good", bad])?,
      view,
      1700000002) == Err("anchor_rpc_unavailable"))
  end
  let config = pins(["good", "good", "good"])?
  assert(read_anchor_freshness(config, view, 1699999999) == Err("anchor_clock_skew"))
  assert(read_anchor_freshness(config, view, -1) == Err("invalid_anchor_clock"))
  assert(read_anchor_freshness(config,
    %{view | header: %{view.header | count: 0}},
    1700000000) == Err("anchor_empty"))
  assert(read_anchor_freshness(%{config | log_name: "morse-canary"},
    view,
    1700000000) == Err("invalid_anchor_pins"))
  # Large local times never overflow into a fresh verdict.
  assert(read_anchor_freshness(config, view, 9223372036854775807)?.stale)
  Ok(true)
end

test("anchor age requires matching chain time for the finalized posting slot") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
