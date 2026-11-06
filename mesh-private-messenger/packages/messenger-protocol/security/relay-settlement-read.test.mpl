from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.Fork import ForkProof, decode_fork, fork_hash
from Transparency.SlashReceipt import SlashReceipt
from Transparency.SlashReceiptRead import (
  SlashReceiptState,
  read_slash_receipt_state,
  slash_receipt_state_report
)
from Transparency.RelayDestinations import (
  RelayDestinationState,
  RelayDestinationsState,
  read_relay_destinations,
  relay_destinations_report
)
from Solana.Read import Pubkey, pubkey

fn text(value :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(value, key)?)
end

fn account(snapshot :: Json, address :: String, mode :: String) -> String!String do
  let accounts = Json.object_get(snapshot, "accounts")?
  for index in 0..Json.array_length(accounts)? do
    let record = Json.array_get(accounts, index)?
    if text(record, "address")? == address do
      let value = Json.object_get(record, "value")?
      if Json.encode(value) == "null" || (mode == "missing" && index >= 3) do
        return Ok("null")
      end
      let owner = if mode == "foreign" do
        "11111111111111111111111111111111"
      else
        text(value, "owner")?
      end
      let data = Bytes.from_hex(text(value, "data_hex")?)?
      return Ok("""{"data":["#{Bytes.to_base64(data)}","base64"],"owner":#{Json.encode_string(owner)},"lamports":#{text(value,
        "lamports")?},"executable":#{Json.encode(Json.object_get(value,
        "executable")?)},"rentEpoch":0}""")
    end
  end
  Err("unexpected_settlement_account")
end

fn response(request :: Request, snapshot :: Json, mode :: String) -> String!String do
  if mode == "down" do
    return Err("offline")
  end
  let root = Json.parse(Request.body(request))?
  assert(text(root, "method")? == "getMultipleAccounts")
  let params = Json.object_get(root, "params")?
  let options = Json.array_get(params, 1)?
  assert(text(options, "commitment")? == "finalized")
  assert(Json.encode(Json.object_get(options, "minContextSlot")?) == text(snapshot, "slot")?)
  let keys = Json.array_get(params, 0)?
  let values = for index in 0..Json.array_length(keys)? do
    account(snapshot, Json.as_string(Json.array_get(keys, index)?)?, mode)?
  end
  let slot = if mode == "stale" do
    "1"
  else
    text(snapshot, "slot")?
  end
  Ok("""{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":#{slot}},"value":[#{String.join(values,
    ",")}]}}""")
end

actor server(port :: Int, fixtures :: Json) do
  let routes = List.flat_map(for index in 0..Json.array_length(fixtures)? do
      let fixture = Json.array_get(fixtures, index)?
      let snapshots = Json.object_get(fixture, "snapshots")?
      List.flat_map(for sample in 0..Json.array_length(snapshots)? do
          for mode in ["valid", "foreign", "missing", "stale", "down"] do
            (index, sample, mode, Json.array_get(snapshots, sample)?)
          end
        end,
        fn(value) -> value end)
    end,
    fn(value) -> value end)
  let router = List.reduce(routes,
    HTTP.router(),
    fn(router, (index, sample, mode, snapshot)) do HTTP.on_post(router,
      "/#{index}/#{sample}/#{mode}",
      fn(request :: Request) do
        case response(request, snapshot, mode) do
          Ok(body) -> HTTP.response(200, body)
          Err(error) -> HTTP.response(503, error)
        end
      end) end)
  HTTP.serve(router, port)
end

fn read(fixture :: Json,
  index :: Int,
  sample :: Int,
  modes :: List<String>) -> (SlashReceiptState, RelayDestinationsState)!String do
  let program = pubkey(text(fixture, "program")?)?
  let derived = anchor_addresses(program, text(fixture, "log_name")?)?
  let pins = AnchorPins {
    program: program,
    ring: derived.ring,
    log_name: text(fixture, "log_name")?,
    log_id: derived.log_id,
    endpoints: for provider in 0..3 do
      "http://127.0.0.1:#{19978 + provider}/#{index}/#{sample}/#{List.get(modes, provider)}"
    end
  }
  let snapshot = Json.array_get(Json.object_get(fixture, "snapshots")?, sample)?
  let floor = U64.parse(text(snapshot, "slot")?)?
  let key = Bytes.from_hex(text(fixture, "service_key")?)?
  let version = Json.as_int(Json.object_get(fixture, "version")?)?
  let mint = pubkey(text(fixture, "mint")?)?
  let wire = Bytes.from_hex(text(fixture, "proof_hex")?)?
  let receipt = read_slash_receipt_state(pins,
    key,
    version,
    mint,
    fork_hash(decode_fork(wire)?)?,
    floor)?
  let destinations = read_relay_destinations(pins,
    key,
    version,
    mint,
    pubkey(text(fixture, "submitter")?)?,
    wire,
    floor)?
  Ok((receipt, destinations))
end

fn proof() -> Bool!String do
  let path = Env.get("MORSE_RELAY_SETTLEMENT_READ_FIXTURES_PATH", "")
  if path == "" do
    return Err("run prove-relay-writer.sh for fresh settlement snapshots")
  end
  let fixtures = Json.parse(File.read(path)?)?
  assert(Json.array_length(fixtures)? == 19)
  let _one = spawn(server, 19978, fixtures)
  let _two = spawn(server, 19979, fixtures)
  let _three = spawn(server, 19980, fixtures)
  Timer.sleep(100)
  for index in 0..Json.array_length(fixtures)? do
    let fixture = Json.array_get(fixtures, index)?
    let snapshots = Json.object_get(fixture, "snapshots")?
    assert(Json.array_length(snapshots)? == 4)
    for sample in 0..4 do
      let snapshot = Json.array_get(snapshots, sample)?
      let (receipt, destinations) = read(fixture, index, sample, ["valid", "valid", "valid"])?
      let step = text(snapshot, "step_id")?
      assert(U64.to_string(receipt.context_slot) == text(snapshot, "slot")?)
      assert(destinations.context_slot == receipt.context_slot)
      assert(destinations.finder.present == (step != "before-setup"))
      assert(destinations.locked.present == (step == "setup/1" || step == "settle"))
      case receipt.receipt do
        None -> assert(step != "settle")
        Some(value) -> assert(step == "settle"
          && Bytes.to_hex(value.proof_hash) == text(fixture, "proof_hash")?)
      end
      let export_path = Env.get("MORSE_RELAY_EFFECT_REPORTS_PATH", "")
      if export_path != "" do
        let log = anchor_addresses(pubkey(text(fixture, "program")?)?,
          text(fixture, "log_name")?)?.log
        File.append(export_path,
          """{"type":"settlement","log":#{Json.encode_string(Bytes.to_base58(log.bytes))},"proof_hex":#{Json.encode_string(text(fixture,
            "proof_hex")?)},"step_id":#{Json.encode_string(step)},"receipt":#{slash_receipt_state_report(receipt)},"destinations":#{relay_destinations_report(destinations)}}"""
            <> "\n")?
      end
    end
    read(fixture, index, 3, ["down", "valid", "valid"])?
    for mode in ["foreign", "stale"] do
      case read(fixture, index, 3, [mode, mode, mode]) do
        Ok(_) -> assert(false)
        Err(_) -> nil
      end
    end
    case read(fixture, index, 3, ["valid", "missing", "down"]) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  Ok(true)
end

test("Mesh authenticates actual SBF token setup and settled or absent proof receipts before phase recovery") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
