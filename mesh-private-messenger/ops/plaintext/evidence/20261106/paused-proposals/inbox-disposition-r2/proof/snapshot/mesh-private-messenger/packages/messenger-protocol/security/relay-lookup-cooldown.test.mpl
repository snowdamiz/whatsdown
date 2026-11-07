from Transparency.RpcTransport import webpki_rpc_transport
from Transparency.RelayLookupRead import (
  RelayLookupState,
  RelayLookupCooldown,
  read_relay_lookup_cooldown,
  relay_lookup_cooldown_report
)
from Solana.Read import Pubkey, pubkey

fn text(value :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(value, name)?)
end

fn parameter(request :: Request, name :: String) -> Int!String do
  case Request.param(request, name) do
    None -> Err("missing parameter")
    Some(value) -> U64.to_int(U64.parse(value)?)
  end
end

fn account(value :: Json) -> String!String do
  if Json.encode(value) == "null" do
    return Ok("null")
  end
  let raw = Bytes.from_hex(text(value, "data_hex")?)?
  Ok("""{"owner":"#{text(value,
    "owner")?}","data":["#{Bytes.to_base64(raw)}","base64"],"executable":#{Json.encode(Json.object_get(value,
    "executable")?)},"lamports":#{text(value, "lamports")?},"rentEpoch":0}""")
end

fn reply(request :: Request, fixtures :: Json) -> String!String do
  let fixture = Json.array_get(fixtures, parameter(request, "case")?)?
  let snapshot = Json.array_get(Json.object_get(fixture, "snapshots")?,
    parameter(request, "sample")?)?
  let root = Json.parse(Request.body(request))?
  let params = Json.object_get(root, "params")?
  let keys = Json.array_get(params, 0)?
  let config = Json.array_get(params, 1)?
  assert(text(root, "method")? == "getMultipleAccounts"
    && text(config, "commitment")? == "finalized")
  assert(Json.encode(Json.object_get(config, "minContextSlot")?) == text(snapshot, "slot")?)
  assert(Json.array_length(keys)? == 3)
  assert(Json.as_string(Json.array_get(keys, 0)?)? == text(fixture, "address")?)
  assert(Json.as_string(Json.array_get(keys, 1)?)? == "SysvarC1ock11111111111111111111111111111111")
  assert(Json.as_string(Json.array_get(keys, 2)?)? == "SysvarS1otHashes111111111111111111111111111")
  let records = for name in ["table", "clock", "history"] do
    account(Json.object_get(snapshot, name)?)?
  end
  Ok("""{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":#{text(snapshot,
    "slot")?}},"value":[#{String.join(records, ",")}]}}""")
end

actor server(port :: Int, fixtures :: Json) do
  let router = HTTP.on_post(HTTP.router(),
    "/:case/:sample",
    fn(request :: Request) do
      case reply(request, fixtures) do
        Ok(value) -> HTTP.response(200, value)
        Err(error) -> HTTP.response(503, error)
      end
    end)
  HTTP.serve(router, port)
end

fn proof() -> Bool!String do
  let path = Env.get("MORSE_RELAY_LOOKUP_READ_FIXTURES_PATH", "")
  if path == "" do
    return Err("run prove-relay-writer.sh for actual SBF lookup accounts")
  end
  let fixtures = Json.parse(File.read(path)?)?
  assert(Json.array_length(fixtures)? == 4)
  let _one = spawn(server, 19975, fixtures)
  let _two = spawn(server, 19976, fixtures)
  let _three = spawn(server, 19977, fixtures)
  Timer.sleep(100)
  for index in 0..Json.array_length(fixtures)? do
    let fixture = Json.array_get(fixtures, index)?
    let snapshots = Json.object_get(fixture, "snapshots")?
    let addresses = Json.object_get(fixture, "addresses")?
    let keys = for n in 0..Json.array_length(addresses)? do
      pubkey(Json.as_string(Json.array_get(addresses, n)?)?)?
    end
    assert(Json.array_length(snapshots)? >= 10)
    for sample in 0..Json.array_length(snapshots)? do
      let snapshot = Json.array_get(snapshots, sample)?
      let value = read_relay_lookup_cooldown(webpki_rpc_transport(for provider in 0..3 do
          "http://127.0.0.1:#{19975 + provider}/#{index}/#{sample}"
        end)?,
        pubkey(text(fixture, "authority")?)?,
        U64.parse(text(fixture, "creation_slot")?)?,
        keys,
        U64.parse(text(snapshot, "slot")?)?)?
      assert(value.table.status == text(snapshot, "expected_status")?)
      assert(value.remaining_blocks == Json.as_int(Json.object_get(snapshot, "remaining_blocks")?)?)
      let report = Json.parse(relay_lookup_cooldown_report(value))?
      assert(text(report, "contextSlot")? == text(snapshot, "slot")?)
      assert(text(report, "address")? == text(fixture, "address")?)
      let export_path = Env.get("MORSE_RELAY_EFFECT_REPORTS_PATH", "")
      if export_path != "" do
        File.append(export_path,
          """{"type":"lookup","log":#{Json.encode_string(text(fixture,
            "log")?)},"proof_hex":#{Json.encode_string(text(fixture,
            "proof_hex")?)},"address":#{Json.encode_string(text(fixture,
            "address")?)},"step_id":#{Json.encode_string(text(snapshot,
            "step_id")?)},"lookup":#{relay_lookup_cooldown_report(value)}}"""
            <> "\n")?
      end
    end
  end
  Ok(true)
end

test("Mesh cooldown decisions match actual SBF closure refusals and eventual table rent recovery") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
