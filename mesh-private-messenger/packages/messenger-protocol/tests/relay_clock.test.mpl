from Transparency.RpcTransport import webpki_rpc_transport
from Transparency.RelayClock import RelayClock, check_relay_clock

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn answer(request :: Request, mode :: String) -> String!String do
  let root = Json.parse(Request.body(request))?
  let params = Json.object_get(root, "params")?
  assert(Json.as_string(Json.object_get(root, "method")?)? == "getAccountInfo")
  assert(Json.as_string(Json.array_get(params,
    0)?)? == "SysvarC1ock11111111111111111111111111111111")
  let options = Json.array_get(params, 1)?
  assert(Json.as_string(Json.object_get(options, "commitment")?)? == "finalized")
  assert(Json.as_int(Json.object_get(Json.object_get(options, "dataSlice")?, "length")?)? == 40)
  let minimum = U64.parse(Json.encode(Json.object_get(options, "minContextSlot")?))?
  let slot = if mode == "stale" do
    wide(1)?
  else
    U64.add(minimum,
      wide(if mode == "later" do
        2
      else
        1
      end)?)?
  end
  let recorded_slot = if mode == "slot" do
    wide(0)?
  else
    slot
  end
  let now = if mode == "expired" do
    1700000000 + 28 * 86400 + 1
  else if mode == "boundary" do
    1700000000 + 28 * 86400
  else if mode == "future" do
    1700000000
  else if mode == "later" do
    1700000002
  else
    1700000001
  end
  let timestamp = if mode == "negative" do
    Bytes.from_hex("ffffffffffffffff")?
  else if mode == "overflow" do
    Bytes.from_hex("ffffffffffffff7f")?
  else
    Bytes.write_uint_le(Int.to_string(now), 8)?
  end
  let data = Bytes.concat(Bytes.concat(Bytes.write_uint_le(U64.to_string(recorded_slot), 8)?,
      Bytes.from_hex(String.repeat("00", 24))?)?,
    timestamp)?
  let owner = if mode == "owner" do
    "11111111111111111111111111111111"
  else
    "Sysvar1111111111111111111111111111111111111"
  end
  Ok("""{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":#{U64.to_string(slot)}},"value":{"data":["#{Bytes.to_base64(data)}","base64"],"owner":"#{owner}","lamports":1,"executable":false,"rentEpoch":0}}}""")
end

actor server(port :: Int) do
  let router = List.reduce([
      "valid",
      "later",
      "expired",
      "boundary",
      "future",
      "negative",
      "overflow",
      "slot",
      "stale",
      "owner"
    ],
    HTTP.router(),
    fn(router, mode) do HTTP.on_post(router,
      "/" <> mode,
      fn(request :: Request) do
        case answer(request, mode) do
          Ok(body) -> HTTP.response(200, body)
          Err(error) -> HTTP.response(400, error)
        end
      end) end)
  HTTP.serve(HTTP.on_post(router, "/down", fn(_) -> HTTP.response(503, "offline") end), port)
end

fn read(routes :: List<String>, bonded :: Int) -> RelayClock!String do
  check_relay_clock(webpki_rpc_transport(for index in 0..3 do
      "http://127.0.0.1:#{19956 + index}/#{List.get(routes, index)}"
    end)?,
    wide(1700000000000)?,
    wide(1700000001000)?,
    wide(bonded)?,
    U64.parse("9007199254740993")?)
end

fn proof() -> Bool!String do
  let _one = spawn(server, 19956)
  let _two = spawn(server, 19957)
  let _three = spawn(server, 19958)
  Timer.sleep(100)
  for routes in [
    ["valid", "later", "down"],
    ["future", "valid", "later"],
    ["down", "valid", "later"]
  ] do
    let result = read(routes, 1700000000)?
    assert(result.earliest_seconds == 1700000001 && result.latest_seconds == 1700000002)
    assert(U64.to_string(result.context_slot) == "9007199254740994")
  end
  assert(read(["boundary", "boundary", "down"], 1700000000)?.earliest_seconds == 1700000000
      + 28 * 86400)
  for (mode, error) in [("future", "relay_proof_future"), ("expired", "relay_proof_expired")] do
    case read([mode, mode, "valid"], 1700000000) do
      Ok(_) -> assert(false)
      Err(value) -> assert(value == error)
    end
  end
  case read(["valid", "later", "valid"], 1700000003) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "relay_bond_from_future")
  end
  for mode in ["negative", "overflow", "slot", "stale", "owner"] do
    case read([mode, mode, "valid"], 1700000000) do
      Ok(_) -> do
        println(mode)
        assert(false)
      end
      Err(_) -> nil
    end
  end
  Ok(true)
end

test("relay admission uses two independent Clock sysvars with exact age bounds and tolerates different finalized slots") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
