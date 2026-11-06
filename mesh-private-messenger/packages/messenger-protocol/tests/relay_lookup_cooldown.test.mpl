from Transparency.RelayLookupRead import (
  RelayLookupState,
  RelayLookupCooldown,
  read_relay_lookup_cooldown,
  relay_lookup_cooldown_report
)
from Solana.Read import Pubkey, pubkey
from Solana.LookupTable import LookupTableCreation, create_lookup_table_instruction

fn cat(values :: List<Bytes>) -> Bytes!String do
  List.reduce(values, Ok(Bytes.empty()), fn(result, value) do Bytes.concat(result?, value) end)
end

fn raw_account(data :: Bytes, owner :: String) -> String do
  """{"owner":"#{owner}","data":["#{Bytes.to_base64(data)}","base64"],"executable":false,"lamports":1,"rentEpoch":0}"""
end

fn reply(request :: Request, authority :: Pubkey, table :: Pubkey) -> String!String do
  let mode = case Request.param(request, "mode") do
    Some(value) -> value
    None -> return Err("missing mode")
  end
  if mode == "down" do
    return Err("offline")
  end
  let root = Json.parse(Request.body(request))?
  let params = Json.object_get(root, "params")?
  let keys = Json.array_get(params, 0)?
  let config = Json.array_get(params, 1)?
  assert(Json.as_string(Json.object_get(root, "method")?)? == "getMultipleAccounts")
  assert(Json.as_string(Json.object_get(config, "commitment")?)? == "finalized")
  assert(Json.encode(Json.object_get(config, "minContextSlot")?) == "10")
  assert(Json.array_length(keys)? == 3)
  assert(Json.as_string(Json.array_get(keys, 0)?)? == Bytes.to_base58(table.bytes))
  assert(Json.as_string(Json.array_get(keys, 1)?)? == "SysvarC1ock11111111111111111111111111111111")
  assert(Json.as_string(Json.array_get(keys, 2)?)? == "SysvarS1otHashes111111111111111111111111111")
  let slot = case mode do
    "cooling-new" -> 1100
    "cooling-old" -> 1099
    "closable-old" -> 1699
    "same-slot" -> 1000
    _ -> 1700
  end
  let table_data = cat([
    Bytes.from_hex("01000000")?,
    Bytes.write_uint_le(if mode == "active" do
        "18446744073709551615"
      else if mode == "future-table" do
        "2000"
      else
        "1000"
      end,
      8)?,
    Bytes.write_uint_le("10", 8)?,
    Bytes.from_hex("0001")?,
    if mode == "wrong-authority" do
      Bytes.from_hex(String.repeat("00", 32))?
    else
      authority.bytes
    end,
    Bytes.from_hex("0000"
      <> String.repeat(if mode == "changed" do
          "33"
        else
          "22"
        end,
        32))?
  ])?
  let clock = cat([
    Bytes.write_uint_le(Int.to_string(if mode == "future-clock" do
        slot + 1
      else
        slot
      end),
      8)?,
    Bytes.from_hex(String.repeat("00", 32))?
  ])?
  let history = cat([Bytes.write_uint_le("512", 8)?]
    ++ for index in 0..512 do
      let history_slot = if mode == "future-history" do
        slot + 512 - index
      else if mode == "bad-history" do
        slot - 1
      else
        slot - 1 - index
      end
      cat([
        Bytes.write_uint_le(Int.to_string(history_slot), 8)?,
        Bytes.from_hex(String.repeat("00", 32))?
      ])?
    end)?
  let table_json = if mode == "missing" do
    "null"
  else
    raw_account(table_data, "AddressLookupTab1e1111111111111111111111111")
  end
  let clock_json = raw_account(clock,
    if mode == "foreign-clock" do
      "11111111111111111111111111111111"
    else
      "Sysvar1111111111111111111111111111111111111"
    end)
  let hashes_json = if mode == "missing-history" do
    "null"
  else
    raw_account(history,
      if mode == "foreign-history" do
        "11111111111111111111111111111111"
      else
        "Sysvar1111111111111111111111111111111111111"
      end)
  end
  Ok("""{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":#{slot}},"value":[#{table_json},#{clock_json},#{hashes_json}]}}""")
end

actor server(port :: Int, authority :: Pubkey, table :: Pubkey) do
  let router = HTTP.on_post(HTTP.router(),
    "/:mode",
    fn(request :: Request) do
      case reply(request, authority, table) do
        Ok(value) -> HTTP.response(200, value)
        Err(error) -> HTTP.response(503, error)
      end
    end)
  HTTP.serve(router, port)
end

fn read(authority :: Pubkey, modes :: List<String>) -> RelayLookupCooldown!String do
  read_relay_lookup_cooldown(for index in 0..3 do
      "http://127.0.0.1:#{19972 + index}/#{List.get(modes, index)}"
    end,
    authority,
    U64.parse("10")?,
    [Pubkey { bytes: Bytes.from_hex(String.repeat("22", 32))? }],
    U64.parse("0")?)
end

fn proof() -> Bool!String do
  let authority = pubkey("5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb")?
  let table = create_lookup_table_instruction(authority, authority, U64.parse("10")?)?.address
  let _one = spawn(server, 19972, authority, table)
  let _two = spawn(server, 19973, authority, table)
  let _three = spawn(server, 19974, authority, table)
  Timer.sleep(100)
  let cooling = read(authority, ["cooling-new", "cooling-old", "down"])?
  assert(cooling.table.status == "cooling" && cooling.remaining_blocks == 414)
  assert(U64.to_string(cooling.table.context_slot) == "1099")
  let closed = read(authority, ["closable-new", "closable-old", "down"])?
  assert(closed.table.status == "closable" && closed.remaining_blocks == 0)
  assert(U64.to_string(closed.table.context_slot) == "1699")
  assert(Json.as_string(Json.object_get(Json.parse(relay_lookup_cooldown_report(closed))?,
    "status")?)? == "closable")
  assert(read(authority, ["same-slot", "same-slot", "down"])?.remaining_blocks == 513)
  assert(read(authority, ["down", "closable-new", "closable-old"])?.table.status == "closable")
  assert(read(authority, ["missing", "missing", "missing"])?.table.status == "missing")
  assert(read(authority, ["active", "active", "active"])?.table.status == "ready")
  for mode in [
    "future-table",
    "future-history",
    "future-clock",
    "bad-history",
    "foreign-history",
    "missing-history",
    "foreign-clock",
    "wrong-authority",
    "changed"
  ] do
    case read(authority, [mode, mode, mode]) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  case read(authority, ["closable-new", "cooling-new", "down"]) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  Ok(true)
end

test("lookup closure requires two authenticated cooldown decisions across independently finalized banks") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
