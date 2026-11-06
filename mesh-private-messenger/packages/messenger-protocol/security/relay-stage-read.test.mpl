from Transparency.RelayStageRead import (
  RelayStageState,
  RelayStageVerified,
  read_relay_stage,
  relay_stage_report
)
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Solana.Read import Pubkey, pubkey

fn text(value :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(value, key)?)
end

fn bytes(value :: Json, key :: String) -> Bytes!String do
  Bytes.from_hex(text(value, key)?)
end

fn parameter(request :: Request, name :: String) -> String!String do
  case Request.param(request, name) do
    None -> Err("missing parameter")
    Some(value) -> Ok(value)
  end
end

fn account(value :: Json, mode :: String, stage :: Bool) -> String!String do
  if Json.encode(value) == "null" do
    return Ok("null")
  end
  let raw = bytes(value, "data_hex")?
  let raw = if stage && mode == "oversized" do
    Bytes.from_hex(String.repeat("00", 9162))?
  else if stage && mode == "changed" && Bytes.length(raw) > 0 do
    Bytes.concat(Bytes.from_hex("00")?, Bytes.slice(raw, 1, Bytes.length(raw) - 1)?)?
  else
    raw
  end
  let owner = if (stage && mode == "foreign") || (!stage && mode == "wrong-log") do
    "11111111111111111111111111111111"
  else
    text(value, "owner")?
  end
  Ok("""{"data":["#{Bytes.to_base64(raw)}","base64"],"owner":"#{owner}","executable":#{Json.encode(Json.object_get(value,
    "executable")?)},"lamports":#{text(value, "lamports")?},"rentEpoch":0}""")
end

fn reply(request :: Request, fixtures :: Json) -> String!String do
  let index = U64.to_int(U64.parse(parameter(request, "case")?)?)?
  let sample = U64.to_int(U64.parse(parameter(request, "sample")?)?)?
  let mode = parameter(request, "mode")?
  if mode == "down" do
    return Err("offline")
  end
  let fixture = Json.array_get(fixtures, index)?
  let snapshot = Json.array_get(Json.object_get(fixture, "snapshots")?, sample)?
  let addresses = anchor_addresses(pubkey(text(fixture, "program")?)?, text(fixture, "log_name")?)?
  let expected = Json.object_get(snapshot, "expected")?
  let root = Json.parse(Request.body(request))?
  let params = Json.object_get(root, "params")?
  let keys = Json.array_get(params, 0)?
  let config = Json.array_get(params, 1)?
  assert(text(root, "method")? == "getMultipleAccounts")
  assert(text(config, "commitment")? == "finalized")
  assert(Json.array_length(keys)? == 2)
  assert(Json.as_string(Json.array_get(keys, 0)?)? == Bytes.to_base58(addresses.log.bytes))
  assert(Json.as_string(Json.array_get(keys, 1)?)? == text(expected, "address")?)
  assert(Json.encode(Json.object_get(config, "minContextSlot")?) == text(snapshot, "slot")?)
  let stage = if mode == "missing" do
    "null"
  else
    account(Json.object_get(snapshot, "stage")?, mode, true)?
  end
  let log = account(Json.object_get(snapshot, "log")?, mode, false)?
  let slot = if mode == "stale" do
    "0"
  else
    text(snapshot, "slot")?
  end
  Ok("""{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":#{slot}},"value":[#{log},#{stage}]}}""")
end

actor server(port :: Int, fixtures :: Json) do
  let router = HTTP.on_post(HTTP.router(),
    "/:case/:sample/:mode",
    fn(request :: Request) do
      case reply(request, fixtures) do
        Ok(body) -> HTTP.response(200, body)
        Err(error) -> HTTP.response(503, error)
      end
    end)
  HTTP.serve(router, port)
end

fn read(fixture :: Json,
  index :: Int,
  sample :: Int,
  modes :: List<String>) -> RelayStageState!String do
  let program = pubkey(text(fixture, "program")?)?
  let addresses = anchor_addresses(program, text(fixture, "log_name")?)?
  let snapshot = Json.array_get(Json.object_get(fixture, "snapshots")?, sample)?
  let pins = AnchorPins {
    program: program,
    ring: addresses.ring,
    log_id: addresses.log_id,
    log_name: text(fixture, "log_name")?,
    endpoints: for provider in 0..3 do
      "http://127.0.0.1:#{19969 + provider}/#{index}/#{sample}/#{List.get(modes, provider)}"
    end
  }
  read_relay_stage(pins,
    bytes(fixture, "service_key")?,
    Json.as_int(Json.object_get(fixture, "version")?)?,
    pubkey(text(fixture, "submitter")?)?,
    bytes(fixture, "proof_hex")?,
    U64.parse(text(snapshot, "slot")?)?)
end

fn proof() -> Bool!String do
  let path = Env.get("MORSE_RELAY_STAGE_READ_FIXTURES_PATH", "")
  if path == "" do
    return Err("run prove-relay-writer.sh for fresh SBF Stage accounts")
  end
  let fixtures = Json.parse(File.read(path)?)?
  assert(Json.array_length(fixtures)? == 19)
  let _one = spawn(server, 19969, fixtures)
  let _two = spawn(server, 19970, fixtures)
  let _three = spawn(server, 19971, fixtures)
  Timer.sleep(100)
  for index in 0..Json.array_length(fixtures)? do
    let fixture = Json.array_get(fixtures, index)?
    let snapshots = Json.object_get(fixture, "snapshots")?
    assert(Json.array_length(snapshots)? >= 5)
    for sample in 0..Json.array_length(snapshots)? do
      let value = read(fixture, index, sample, ["valid", "valid", "valid"])?
      let expected = Json.object_get(Json.array_get(snapshots, sample)?, "expected")?
      assert(value.status == text(expected, "status")?)
      assert(value.received_bytes == Json.as_int(Json.object_get(expected, "received_bytes")?)?)
      assert(value.total_bytes == Json.as_int(Json.object_get(expected, "total_bytes")?)?)
      assert(value.sealed == Json.as_bool(Json.object_get(expected, "sealed")?)?)
      let verified = Json.object_get(expected, "verified")?
      assert(List.length(value.verified) == Json.array_length(verified)?)
      for ordinal in 0..List.length(value.verified) do
        let actual = List.get(value.verified, ordinal)
        let expected = Json.array_get(verified, ordinal)?
        assert(actual.ordinal == Json.as_int(Json.object_get(expected, "ordinal")?)?)
        assert(Bytes.to_hex(actual.public_key) == text(expected, "public_key")?)
      end
      let report = Json.parse(relay_stage_report(value))?
      assert(text(report, "address")? == text(expected, "address")?)
      let export_path = Env.get("MORSE_RELAY_EFFECT_REPORTS_PATH", "")
      if export_path != "" do
        let log = anchor_addresses(pubkey(text(fixture, "program")?)?,
          text(fixture, "log_name")?)?.log
        let snapshot = Json.array_get(snapshots, sample)?
        File.append(export_path,
          """{"type":"stage","log":#{Json.encode_string(Bytes.to_base58(log.bytes))},"proof_hex":#{Json.encode_string(text(fixture,
            "proof_hex")?)},"step_id":#{Json.encode_string(text(snapshot,
            "step_id")?)},"stage":#{relay_stage_report(value)}}"""
            <> "\n")?
      end
    end
    assert(read(fixture, index, 0, ["down", "valid", "valid"])?.status == "uploading")
    for mode in ["foreign", "changed", "oversized", "wrong-log", "stale"] do
      case read(fixture, index, 0, [mode, mode, mode]) do
        Ok(_) -> assert(false)
        Err(_) -> nil
      end
    end
    case read(fixture, index, 0, ["valid", "missing", "down"]) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  Ok(true)
end

test("Mesh authenticates actual SBF Stage progress and rejects substituted or disagreeing recovery views") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
