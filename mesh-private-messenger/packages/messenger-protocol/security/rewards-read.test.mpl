from Solana.Read import (
  Pubkey,
  AccountInfo,
  AccountSlice,
  OptionalAccountSlicesAtSlot,
  pubkey,
  pubkey_string
)
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.RewardsRead import (
  RewardsState,
  RewardsReadAddresses,
  rewards_read_addresses,
  rewards_read_keys,
  read_rewards,
  decode_rewards_snapshot,
  rewards_report
)

fn text(value :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(value, key)?)
end

fn fixture_account(fixture :: Json, address :: Pubkey) -> Json!String do
  let values = Json.object_get(fixture, "accounts")?
  let matches = for index in 0..Json.array_length(values)? when text(Json.array_get(values, index)?,
    "address")? == pubkey_string(address) do
    Json.array_get(values, index)?
  end
  if List.length(matches) != 1 do
    return Err("missing or duplicated real-SBF reader account")
  end
  Ok(List.head(matches))
end

fn fixture_pins(fixture :: Json, endpoints :: List<String>) -> AnchorPins!String do
  let program = pubkey(text(fixture, "judge")?)?
  let addresses = anchor_addresses(program, text(fixture, "log_name")?)?
  Ok(AnchorPins {
    program: program,
    ring: addresses.ring,
    log_name: text(fixture, "log_name")?,
    log_id: addresses.log_id,
    endpoints: endpoints
  })
end

fn render_account(value :: Json, mode :: String) -> String!String do
  let full = Bytes.from_hex(text(value, "data_hex")?)?
  let data = Bytes.slice(full,
    0,
    if Bytes.length(full) > 8416 do
      8416
    else
      Bytes.length(full)
    end)?
  let owner = if mode == "foreign" do
    "11111111111111111111111111111111"
  else
    text(value, "owner")?
  end
  Ok("""{"data":["#{Bytes.to_base64(data)}","base64"],"space":#{text(value,
    "space")?},"owner":"#{owner}","lamports":#{text(value,
    "lamports")?},"executable":#{Json.encode(Json.object_get(value,
    "executable")?)},"rentEpoch":0}""")
end

fn reply(request :: Request, fixtures :: Json) -> String!String do
  let index = case Request.param(request, "index") do
    None -> return Err("missing index")
    Some(value) -> U64.to_int(U64.parse(value)?)?
  end
  let mode = case Request.param(request, "mode") do
    None -> return Err("missing mode")
    Some(value) -> value
  end
  if mode == "down" do
    return Err("offline")
  end
  let fixture = Json.array_get(fixtures, index)?
  let pins = fixture_pins(fixture, [])?
  let addresses = rewards_read_addresses(pins,
    pubkey(text(fixture, "program")?)?,
    pubkey(text(fixture, "mint")?)?,
    U64.parse(text(fixture, "epoch")?)?)?
  let keys = rewards_read_keys(addresses)
  let root = Json.parse(Request.body(request))?
  let params = Json.object_get(root, "params")?
  let requested = Json.array_get(params, 0)?
  let config = Json.array_get(params, 1)?
  assert(Json.as_string(Json.object_get(root, "method")?)? == "getMultipleAccounts")
  assert(Json.array_length(requested)? == 9)
  assert(Json.as_string(Json.object_get(config, "commitment")?)? == "finalized")
  assert(Json.encode(Json.object_get(config, "minContextSlot")?) == text(fixture, "context_slot")?)
  let slice = Json.object_get(config, "dataSlice")?
  assert(Json.as_int(Json.object_get(slice, "offset")?)? == 0
    && Json.as_int(Json.object_get(slice, "length")?)? == 8416)
  let accounts = for index in 0..9 do
    assert(Json.as_string(Json.array_get(requested, index)?)? == pubkey_string(List.get(keys,
        index)))
    render_account(fixture_account(fixture, List.get(keys, index))?, mode)?
  end
  let slot = if mode == "stale" do
    "0"
  else
    text(fixture, "context_slot")?
  end
  Ok("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"context\":{\"slot\":#{slot}},\"value\":[#{String.join(accounts,
    ",")}]}}")
end

actor server(port :: Int, fixtures :: Json) do
  let router = HTTP.on_post(HTTP.router(),
    "/:index/:mode",
    fn(request :: Request) do
      case reply(request, fixtures) do
        Ok(body) -> HTTP.response(200, body)
        Err(error) -> HTTP.response(503, error)
      end
    end)
  HTTP.serve(router, port)
end

fn read(fixture :: Json, index :: Int, modes :: List<String>) -> RewardsState!String do
  let pins = fixture_pins(fixture,
    for provider in 0..3 do
      "http://127.0.0.1:#{20331 + provider}/#{index}/#{List.get(modes, provider)}"
    end)?
  let log = fixture_account(fixture, pubkey(text(fixture, "log")?)?)?
  let service_key = Bytes.slice(Bytes.from_hex(text(log, "data_hex")?)?, 72, 32)?
  read_rewards(pins,
    service_key,
    1,
    pubkey(text(fixture, "program")?)?,
    pubkey(text(fixture, "mint")?)?,
    U64.parse(text(fixture, "epoch")?)?,
    U64.parse(text(fixture, "context_slot")?)?)
end

fn decode_fixture(fixture :: Json) -> RewardsState!String do
  let pins = fixture_pins(fixture, [])?
  let program = pubkey(text(fixture, "program")?)?
  let mint = pubkey(text(fixture, "mint")?)?
  let epoch = U64.parse(text(fixture, "epoch")?)?
  let keys = rewards_read_keys(rewards_read_addresses(pins, program, mint, epoch)?)
  let accounts = for address in keys do
    let raw = fixture_account(fixture, address)?
    let data = Bytes.from_hex(text(raw, "data_hex")?)?
    Some(AccountSlice {
      info: AccountInfo {
        owner: pubkey(text(raw, "owner")?)?,
        data: Bytes.slice(data,
          0,
          if Bytes.length(data) > 8416 do
            8416
          else
            Bytes.length(data)
          end)?,
        lamports: U64.parse(text(raw, "lamports")?)?,
        executable: Json.as_bool(Json.object_get(raw, "executable")?)?,
        rent_epoch: U64.parse("0")?
      },
      space: U64.parse(text(raw, "space")?)?
    })
  end
  let log = Bytes.from_hex(text(fixture_account(fixture, pubkey(text(fixture, "log")?)?)?,
    "data_hex")?)?
  decode_rewards_snapshot(pins,
    Bytes.slice(log, 72, 32)?,
    1,
    program,
    mint,
    epoch,
    OptionalAccountSlicesAtSlot {
      slot: U64.parse(text(fixture, "context_slot")?)?,
      accounts: accounts
    })
end

fn proof() -> Bool!String do
  let path = Env.get("MORSE_REWARDS_FIXTURES_PATH", "")
  if path == "" do
    return Err("MORSE_REWARDS_FIXTURES_PATH is required for real-SBF rewards reader replay")
  end
  let source = Json.parse(File.read(path)?)?
  let fixtures = Json.object_get(source, "reader_snapshots")?
  assert(Json.array_length(fixtures)? == 2)
  let _one = spawn(server, 20331, fixtures)
  let _two = spawn(server, 20332, fixtures)
  let _three = spawn(server, 20333, fixtures)
  Timer.sleep(100)
  for index in 0..2 do
    let fixture = Json.array_get(fixtures, index)?
    assert(decode_fixture(fixture)?.status == "finalized")
    let result = read(fixture, index, ["valid", "down", "valid"])?
    assert(result.status == "finalized")
    let expected = Json.object_get(fixture, "expected")?
    let report = Json.parse(rewards_report(result))?
    let pool = Json.object_get(report, "pool")?
    for field in ["accounted", "subsidy", "carry", "liabilities", "next_epoch"] do
      assert(text(pool, field)? == text(expected, field)?)
    end
    assert(result.unclaimed_amount == Some(U64.parse(text(expected, "liabilities")?)?))
    for mode in ["foreign", "stale"] do
      case read(fixture, index, [mode, mode, mode]) do
        Ok(_) -> assert(false)
        Err(_) -> nil
      end
    end
  end
  let earned = read(Json.array_get(fixtures, 0)?, 0, ["valid", "valid", "valid"])?
  let claimed = read(Json.array_get(fixtures, 1)?, 1, ["valid", "valid", "valid"])?
  assert(earned.revision_matches == Some(true) && claimed.revision_matches == Some(false))
  assert(claimed.unclaimed_amount == Some(U64.parse("0")?))
  println("authenticated real SBF finalized and claimed reward accounts through strict finalized RPC quorum")
  Ok(true)
end

test("authenticated rewards reader replays actual SBF custody and finalized claims through independent local RPCs") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
