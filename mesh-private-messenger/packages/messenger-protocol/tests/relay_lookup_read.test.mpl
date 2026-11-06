from Transparency.RpcTransport import webpki_rpc_transport
from Transparency.RelayLookupRead import RelayLookupState, read_relay_lookup, relay_lookup_report
from Solana.LookupTable import LookupTableCreation, create_lookup_table_instruction
from Solana.Read import Pubkey, pubkey

fn raw(authority :: Pubkey,
  count :: Int,
  start :: Int,
  extended :: String,
  deactivation :: String) -> Bytes!String do
  let header = Bytes.concat(Bytes.from_hex("01000000")?, Bytes.write_uint_le(deactivation, 8)?)?
  let header = Bytes.concat(header, Bytes.write_uint_le(extended, 8)?)?
  let header = Bytes.concat(header, Bytes.write_uint_le(Int.to_string(start), 1)?)?
  let header = Bytes.concat(header, Bytes.from_hex("01")?)?
  let header = Bytes.concat(header, authority.bytes)?
  Bytes.concat(Bytes.concat(header, Bytes.from_hex("0000")?)?,
    Bytes.from_hex(String.repeat("22", 32 * count))?)
end

actor server(port :: Int, authority :: Pubkey, table :: Pubkey) do
  let modes = [
    "ready",
    "extending",
    "warm",
    "cooling",
    "missing",
    "prefunded",
    "wrong-authority",
    "changed",
    "future",
    "frozen",
    "foreign",
    "down"
  ]
  let router = List.reduce(modes,
    HTTP.router(),
    fn(router, mode) do HTTP.on_post(router,
      "/" <> mode,
      fn(request :: Request) do
        case reply(request, authority, table, mode) do
          Ok(body) -> HTTP.response(200, body)
          Err(error) -> HTTP.response(503, error)
        end
      end) end)
  HTTP.serve(router, port)
end

fn reply(request :: Request,
  authority :: Pubkey,
  table :: Pubkey,
  mode :: String) -> String!String do
  if mode == "down" do
    return Err("offline")
  end
  let root = Json.parse(Request.body(request))?
  let params = Json.object_get(root, "params")?
  let config = Json.array_get(params, 1)?
  assert(Json.as_string(Json.object_get(root, "method")?)? == "getMultipleAccounts")
  assert(Json.as_string(Json.object_get(config, "commitment")?)? == "finalized")
  assert(Json.as_string(Json.array_get(Json.array_get(params, 0)?,
    0)?)? == Bytes.to_base58(table.bytes))
  assert(Json.encode(Json.object_get(config, "minContextSlot")?) == "10")
  let data = raw(if mode == "wrong-authority" do
      pubkey("11111111111111111111111111111111")?
    else
      authority
    end,
    if mode == "extending" do
      0
    else if mode == "changed" do
      2
    else
      1
    end,
    0,
    if mode == "warm" do
      "11"
    else if mode == "future" do
      "12"
    else
      "10"
    end,
    if mode == "cooling" do
      "10"
    else
      "18446744073709551615"
    end)?
  let data = if mode == "frozen" do
    Bytes.concat(Bytes.slice(data, 0, 21)?, Bytes.from_hex(String.repeat("00", 35 + 32))?)?
  else
    data
  end
  let owner = if mode == "foreign" do
    "11111111111111111111111111111111"
  else
    "AddressLookupTab1e1111111111111111111111111"
  end
  let account = if mode == "missing" do
    "null"
  else if mode == "prefunded" do
    """{"owner":"11111111111111111111111111111111","data":["","base64"],"lamports":10,"executable":false,"rentEpoch":0}"""
  else
    """{"owner":"#{owner}","data":["#{Bytes.to_base64(data)}","base64"],"lamports":1000,"executable":false,"rentEpoch":0}"""
  end
  Ok("""{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":11},"value":[#{account}]}}""")
end

fn read(authority :: Pubkey, modes :: List<String>) -> RelayLookupState!String do
  read_relay_lookup(webpki_rpc_transport(for index in 0..3 do
      "http://127.0.0.1:#{19966 + index}/#{List.get(modes, index)}"
    end)?,
    authority,
    U64.parse("10")?,
    [Pubkey { bytes: Bytes.from_hex(String.repeat("22", 32))? }],
    U64.parse("0")?)
end

fn proof() -> Bool!String do
  let authority = pubkey("5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb")?
  let created = create_lookup_table_instruction(authority, authority, U64.parse("10")?)?
  let _one = spawn(server, 19966, authority, created.address)
  let _two = spawn(server, 19967, authority, created.address)
  let _three = spawn(server, 19968, authority, created.address)
  Timer.sleep(100)
  for mode in ["ready", "extending", "warm", "cooling", "missing", "prefunded"] do
    let state = read(authority, [mode, mode, mode])?
    let report = Json.parse(relay_lookup_report(state))?
    let expected = if mode == "prefunded" do
      "missing"
    else
      mode
    end
    assert(Json.as_string(Json.object_get(report, "status")?)? == expected)
    assert(Json.as_string(Json.object_get(report, "contextSlot")?)? == "11")
  end
  assert(read(authority, ["down", "ready", "ready"])?.status == "ready")
  for mode in ["wrong-authority", "changed", "future", "frozen", "foreign"] do
    case read(authority, [mode, mode, mode]) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  case read(authority, ["ready", "extending", "down"]) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  Ok(true)
end

test("relay lookup recovery authenticates exact prefixes and authority through finalized quorum before activation") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
