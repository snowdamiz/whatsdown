from Transparency.AnchorRpc import read_anchor_account
from Transparency.RpcTransport import webpki_rpc_transport
from Solana.Read import AccountAtSlot, AccountInfo, pubkey

fn response_json(id :: Int) -> String do
  """{"jsonrpc":"2.0","id":#{id},"result":{"context":{"slot":42},"value":{"data":["AQID","base64"],"executable":false,"lamports":1,"owner":"11111111111111111111111111111111","rentEpoch":18446744073709551615}}}"""
end

fn serve_read(request :: Request) -> Response do
  let body = Request.body(request)
  if !String.contains(body, "\"commitment\":\"finalized\"")
    || !String.contains(body, "\"dataSlice\":{\"offset\":64,")
    || !String.contains(body, "\"minContextSlot\":") do
    HTTP.response(400, "missing read constraints")
  else
    HTTP.response(200, response_json(1))
  end
end

actor rpc_server() do
  HTTP.router()
    |> HTTP.on_post("/good", serve_read)
    |> HTTP.on_post("/wrong-id",
      fn(_request :: Request) do HTTP.response(200, response_json(2)) end)
    |> HTTP.on_post("/large",
      fn(_request :: Request) do HTTP.response(200, String.repeat("x", 10000)) end)
    |> HTTP.on_post("/redirect",
      fn(_request :: Request) do HTTP.response_with_headers(307,
        "",
        Map.put(Map.new(), "Location", "/good")) end)
    |> HTTP.serve(19010)
end

fn proof() -> Bool!String do
  let _server = spawn(rpc_server)
  Timer.sleep(100)
  let address = pubkey("11111111111111111111111111111111")?
  let rpc = webpki_rpc_transport([
    "http://127.0.0.1:19010/good",
    "http://127.0.0.1:19010/wrong-id",
    "http://127.0.0.1:19010/large",
    "http://127.0.0.1:19010/redirect"
  ])?
  let good = List.head(rpc.sources)
  let read = read_anchor_account(rpc,
    good,
    address,
    address,
    64,
    3,
    U64.parse("40")?)?
  assert(Bytes.to_hex(read.account.data) == "010203" && U64.to_string(read.slot) == "42")
  for endpoint in List.drop(rpc.sources, 1) do
    case read_anchor_account(rpc,
      endpoint,
      address,
      address,
      64,
      3,
      U64.parse("40")?) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  for (length, minimum) in [(2, "40"), (3, "43")] do
    case read_anchor_account(rpc,
      good,
      address,
      address,
      64,
      length,
      U64.parse(minimum)?) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  let other = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  case read_anchor_account(rpc,
    good,
    address,
    other,
    64,
    3,
    U64.parse("40")?) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  Ok(true)
end

test("anchor RPC reads bind slices, owners and context without following redirects") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
