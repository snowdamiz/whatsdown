from Transparency.RelayAdmission import RelayAdmission, RelaySettlementPlan, admit_relay_fork
from Transparency.RelayReport import relay_admission_report
from Transparency.RelayLookup import RelayLookupPlan, prepare_relay_lookup
from Transparency.RelayStage import RelayStagePlan, RelayStageWitness, RelayStageSignature
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.SlashReceiptRead import ConfirmedSlashReceipt
from Transparency.SlashReceipt import SlashReceipt
from Transparency.Merkle import WitnessKey
from Solana.Read import Pubkey, pubkey, pubkey_string
from Solana.Tx import Instruction, AccountMeta

fn text(value :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(value, key)?)
end

fn bytes(value :: Json, key :: String) -> Bytes!String do
  Bytes.from_hex(text(value, key)?)
end

fn account(value :: Json, address :: String, mode :: String, config :: Json) -> String!String do
  let paid = mode == "paid"
  let records = Json.object_get(value,
    if paid do
      "accounts"
    else
      "before_accounts"
    end)?
  let selected = if address == "SysvarC1ock11111111111111111111111111111111" do
    Some(Json.object_get(value, "clock")?)
  else
    let matches = for index in 0..Json.array_length(records)? when text(Json.array_get(records,
        index)?,
      "address")? == address do
      Json.array_get(records, index)?
    end
    if List.length(matches) == 0 do
      None
    else
      Some(List.head(matches))
    end
  end
  if address == text(value, "receipt_address")? && paid do
    return Ok("""{"data":["#{Bytes.to_base64(bytes(value,
      "receipt_hex")?)}","base64"],"owner":"#{text(value,
      "program")?}","executable":false,"lamports":10000000,"rentEpoch":0}""")
  end
  let record = case selected do
    None -> return Ok("null")
    Some(value) -> value
  end
  let raw = bytes(record, "data_hex")?
  if mode == "gone" && Bytes.length(raw) == 426048 do
    return Ok("null")
  end
  let raw = if mode == "wrong-history"
    && address == text(Json.array_get(records, 9)?, "address")? do
    bytes(Json.array_get(records, 10)?, "data_hex")?
  else
    raw
  end
  let raw = case Json.object_get(config, "dataSlice") do
    Err(_) -> raw
    Ok(slice) -> Bytes.slice(raw,
      Json.as_int(Json.object_get(slice, "offset")?)?,
      Json.as_int(Json.object_get(slice, "length")?)?)?
  end
  Ok("""{"data":["#{Bytes.to_base64(raw)}","base64"],"owner":"#{text(record,
    "owner")?}","executable":false,"lamports":#{text(record, "lamports")?},"rentEpoch":0}""")
end

fn reply(request :: Request, value :: Json, mode :: String) -> String!String do
  let root = Json.parse(Request.body(request))?
  let params = Json.object_get(root, "params")?
  let config = Json.array_get(params, 1)?
  assert(text(config, "commitment")? == "finalized")
  let slot = Bytes.read_uint_le(bytes(Json.object_get(value, "clock")?, "data_hex")?, 0, 8)?
  assert(U64.compare(U64.parse(Json.encode(Json.object_get(config, "minContextSlot")?))?,
    U64.parse(slot)?) <= 0)
  let result = if text(root, "method")? == "getMultipleAccounts" do
    let addresses = Json.array_get(params, 0)?
    "["
      <> String.join(for index in 0..Json.array_length(addresses)? do
          account(value, Json.as_string(Json.array_get(addresses, index)?)?, mode, config)?
        end,
        ",")
      <> "]"
  else if text(root, "method")? == "getProgramAccounts" do
    assert(!Json.as_bool(Json.object_get(value, "anchored")?)?)
    let filters = Json.object_get(config, "filters")?
    let status = Bytes.get(Bytes.from_base58(text(Json.object_get(Json.array_get(filters, 3)?,
          "memcmp")?,
        "bytes")?)?,
      0)?
    let records = Json.object_get(value, "before_accounts")?
    let matches = for index in 0..Json.array_length(records)? when Bytes.length(bytes(Json.array_get(records,
        index)?,
      "data_hex")?) == 320
      && Bytes.get(bytes(Json.array_get(records, index)?, "data_hex")?, 5)? == status do
      let record = Json.array_get(records, index)?
      """{"pubkey":"#{text(record, "address")?}","account":#{account(value,
        text(record, "address")?,
        mode,
        config)?}}"""
    end
    "[" <> String.join(matches, ",") <> "]"
  else
    # Anchored attribution must use the historical set, never current registry discovery.
    assert(text(root, "method")? == "getAccountInfo")
    account(value, Json.as_string(Json.array_get(params, 0)?)?, mode, config)?
  end
  Ok("""{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":#{slot}},"value":#{result}}}""")
end

actor server(port :: Int, fixtures :: Json, count :: Int) do
  let routes = List.flat_map(for index in 0..count do
      for mode in ["ready", "gone", "wrong-history", "paid"] do
        (index, mode)
      end
    end,
    fn(values) -> values end)
  let router = List.reduce(routes,
    HTTP.router(),
    fn(router, (index, mode)) do HTTP.on_post(router,
      "/#{index}/#{mode}",
      fn(request :: Request) do
        let value = case Json.array_get(fixtures, index) do
          Ok(value) -> value
          Err(error) -> return HTTP.response(500, error)
        end
        case reply(request, value, mode) do
          Ok(body) -> HTTP.response(200, body)
          Err(error) -> HTTP.response(503, error)
        end
      end) end)
  HTTP.serve(router, port)
end

fn read(value :: Json, index :: Int, mode :: String) -> RelayAdmission!String do
  let program = pubkey(text(value, "program")?)?
  let addresses = anchor_addresses(program, text(value, "log_name")?)?
  let pins = AnchorPins {
    program: program,
    ring: addresses.ring,
    log_id: addresses.log_id,
    log_name: text(value, "log_name")?,
    endpoints: for node in 0..3 do
      "http://127.0.0.1:#{19963 + node}/#{index}/#{mode}"
    end
  }
  admit_relay_fork(pins,
    bytes(value, "service_key")?,
    Json.as_int(Json.object_get(value, "version")?)?,
    pubkey(text(value, "mint")?)?,
    Pubkey {
      bytes: Bytes.from_hex("66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a")?
    },
    bytes(value, "wire_hex")?,
    U64.parse("0")?)
end

fn proof() -> Bool!String do
  let maximum = Env.get("MORSE_RELAY_MAXIMUM_CASES", "0") == "1"
  let path_key = if maximum do
    "MORSE_RELAY_MAXIMUM_FIXTURES_PATH"
  else
    "MORSE_RELAY_ANCHORED_FIXTURES_PATH"
  end
  let fixtures = Json.parse(File.read(Env.get(path_key, ""))?)?
  let count = if maximum do
    4
  else
    9
  end
  assert(Json.array_length(fixtures)? == count)
  let paid = Env.get("MORSE_RELAY_VERIFY_PAID", "0") == "1"
  let output = Env.get("MORSE_RELAY_SETTLEMENT_PLANS_PATH", "")
  let _one = spawn(server, 19963, fixtures, count)
  let _two = spawn(server, 19964, fixtures, count)
  let _three = spawn(server, 19965, fixtures, count)
  Timer.sleep(100)
  for index in 0..count do
    let value = Json.array_get(fixtures, index)?
    let accuse = maximum
      || !(Json.as_bool(Json.object_get(value, "c2sp")?)?
        && Json.as_int(Json.object_get(value, "kind")?)? == 3)
    let anchored = !maximum || Json.as_bool(Json.object_get(value, "anchored")?)?
    let witness_count = if maximum do
      16
    else if accuse do
      1
    else
      0
    end
    let total = if maximum do
      "3200000000"
    else if accuse do
      "600000000"
    else
      "500000000"
    end
    case read(value,
      index,
      if paid do
        "paid"
      else
        "ready"
      end)? do
      AlreadySettled(confirmed) -> do
        assert(paid && confirmed.receipt.anchored == anchored)
        assert(U64.to_string(confirmed.receipt.total_slashed) == total)
        assert(List.length(confirmed.receipt.witnesses) == witness_count)
        assert(Bytes.to_base58(confirmed.receipt.finder) == text(value, "finder")?)
        assert(Bytes.to_base58(confirmed.receipt.submitter) == text(value, "submitter")?)
        Json.parse(relay_admission_report(AlreadySettled(confirmed)))?
        nil
      end
      ReadyToSubmit(plan) -> do
        assert(!paid)
        assert(Bytes.secure_equals(plan.proof, bytes(value, "wire_hex")?))
        assert(Bytes.secure_equals(plan.stage.finder, plan.submitter.bytes))
        assert(U64.to_string(plan.total_slashed) == total)
        assert(List.length(plan.stage.witnesses) == witness_count)
        assert(List.length(plan.stage.signatures) == (1 + witness_count)
            * if anchored do
              1
            else
              2
            end)
        assert(Bytes.secure_equals(plan.settlement.data,
          bytes(value, "settlement_instruction_hex")?))
        let metas = Json.object_get(value, "settlement_accounts")?
        assert(List.length(plan.settlement.accounts) == Json.array_length(metas)?)
        for position in 0..List.length(plan.settlement.accounts) do
          let meta = List.get(plan.settlement.accounts, position)
          let expected = Json.array_get(metas, position)?
          assert(meta.signer == Json.as_bool(Json.object_get(expected, "signer")?)?
            && meta.writable == Json.as_bool(Json.object_get(expected, "writable")?)?)
          if position != 0 && position != 2 && position != 7 do
            assert(pubkey_string(meta.pubkey) == text(expected, "address")?)
          end
        end
        if output != "" do
          File.append(output, relay_admission_report(ReadyToSubmit(plan)) <> "\n")?
        end
        let revisions = Env.get("MORSE_RELAY_PLAN_REVISIONS_PATH", "")
        if revisions != "" do
          let next_slot = U64.add(plan.context_slot, U64.parse("1")?)?
          let later = %{plan |
            context_slot: next_slot,
            lookup: prepare_relay_lookup(plan.submitter, plan.settlement, next_slot)?
          }
          File.append(revisions,
            """{"original":#{relay_admission_report(ReadyToSubmit(plan))},"later":#{relay_admission_report(ReadyToSubmit(later))}}"""
              <> "\n")?
        end
      end
    end
  end
  if !paid && !maximum do
    for mode in ["gone", "wrong-history"] do
      case read(Json.array_get(fixtures, 0)?, 0, mode) do
        Ok(_) -> assert(false)
        Err(_) -> nil
      end
    end
  end
  Ok(true)
end

test("relay prepares exact historical or maximum-witness settlements and authenticates their actual paid receipts") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
