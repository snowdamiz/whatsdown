from Transparency.RelayAdmission import RelayAdmission, RelaySettlementPlan, admit_relay_fork
from Transparency.RelayReport import relay_admission_report
from Transparency.RelayStage import RelayStagePlan, RelayStageSignature, RelayStageWitness
from Transparency.RelayLookup import RelayLookupPlan, prepare_relay_lookup
from Transparency.RelayDestinations import (
  RelayDestinationState,
  RelayDestinationsState,
  read_relay_destinations,
  relay_destinations_report
)
from Transparency.RelayClock import RelayClock
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.SlashReceiptRead import ConfirmedSlashReceipt
from Transparency.SlashReceipt import SlashReceipt
from Transparency.Fork import ForkProof, decode_fork, encode_fork
from Solana.Read import Pubkey, pubkey, pubkey_string
from Solana.Address import ProgramDerivedAddress, find_program_address
from Solana.Tx import Instruction, AccountMeta

fn text(value :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(value, key)?)
end

fn bytes(value :: Json, key :: String) -> Bytes!String do
  Bytes.from_hex(text(value, key)?)
end

fn field(value :: Json, key :: String) -> Json!String do
  Json.object_get(value, key)
end

fn replace(raw :: Bytes, offset :: Int, value :: Bytes) -> Bytes!String do
  Bytes.concat(Bytes.concat(Bytes.slice(raw, 0, offset)?, value)?,
    Bytes.slice(raw,
      offset + Bytes.length(value),
      Bytes.length(raw) - offset - Bytes.length(value))?)
end

fn account(value :: Json, address :: String, mode :: String) -> String!String do
  if address == "SysvarC1ock11111111111111111111111111111111" do
    if mode == "settled-old" do
      return Err("settled_proof_must_not_read_clock")
    end
    let clock = field(value, "clock")?
    let raw = bytes(clock, "data_hex")?
    let raw = if mode == "expired" do
      replace(raw, 32, Bytes.write_uint_le("1702419201", 8)?)?
    else
      raw
    end
    return Ok("""{"data":["#{Bytes.to_base64(raw)}","base64"],"owner":"#{text(clock,
      "owner")?}","executable":false,"lamports":1,"rentEpoch":0}""")
  end
  if address == text(value, "receipt_address")? do
    if mode == "settled" || mode == "settled-old" do
      return Ok("""{"data":["#{Bytes.to_base64(bytes(value,
        "receipt_hex")?)}","base64"],"owner":"#{text(value,
        "program")?}","executable":false,"lamports":10000000,"rentEpoch":0}""")
    end
    if mode == "prefunded" do
      return Ok("""{"data":["","base64"],"owner":"11111111111111111111111111111111","executable":false,"lamports":10,"rentEpoch":0}""")
    end
    return Ok("null")
  end
  if String.starts_with(mode, "destination-") do
    let metas = field(value, "settlement_accounts")?
    let locked = address == text(Json.array_get(metas, 8)?, "address")?
    if locked || address == text(Json.array_get(metas, 7)?, "address")? do
      if mode == "destination-prefunded" do
        return Ok("""{"data":["","base64"],"owner":"11111111111111111111111111111111","executable":false,"lamports":10,"rentEpoch":0}""")
      end
      let owner = if locked do
        find_program_address(pubkey(text(value, "program")?)?,
          [Bytes.from_utf8("locked"), bytes(value, "log_id")?])?.address
      else
        pubkey(text(value, "finder")?)?
      end
      let template = bytes(Json.array_get(field(value, "before_accounts")?, 4)?, "data_hex")?
      let raw = replace(replace(template, 32, owner.bytes)?, 64, Bytes.write_uint_le("0", 8)?)?
      let raw = if mode == "destination-frozen" do
        replace(raw, 108, Bytes.from_hex("02")?)?
      else if mode == "destination-overflow" do
        replace(raw, 64, Bytes.write_uint_le("18446744073709551615", 8)?)?
      else if mode == "destination-wrong-mint" do
        replace(raw, 0, Bytes.from_hex(String.repeat("33", 32))?)?
      else if mode == "destination-wrong-owner" do
        replace(raw, 32, Bytes.from_hex(String.repeat("33", 32))?)?
      else if mode == "destination-native" do
        replace(raw, 109, Bytes.write_uint_le("1", 4)?)?
      else if mode == "destination-long" do
        Bytes.concat(raw, Bytes.from_hex("00")?)?
      else if mode == "destination-locked-close" && locked do
        replace(replace(raw, 129, Bytes.write_uint_le("1", 4)?)?,
          133,
          Bytes.from_hex(String.repeat("33", 32))?)?
      else if (mode == "destination-locked-delegate" && locked)
        || (mode == "destination-finder-delegate" && !locked) do
        replace(replace(raw, 72, Bytes.write_uint_le("1", 4)?)?,
          76,
          Bytes.from_hex(String.repeat("33", 32))?)?
      else
        raw
      end
      let owner = if mode == "destination-foreign" do
        "11111111111111111111111111111111"
      else
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
      end
      let funding = if mode == "destination-unfunded" do
        "0"
      else
        "2039280"
      end
      let executable = mode == "destination-executable"
      return Ok("""{"data":["#{Bytes.to_base64(raw)}","base64"],"owner":"#{owner}","executable":#{executable},"lamports":#{funding},"rentEpoch":0}""")
    end
  end
  let accounts = field(value,
    if mode == "settled" || mode == "settled-old" || mode == "exhausted" do
      "accounts"
    else
      "before_accounts"
    end)?
  for index in 0..Json.array_length(accounts)? do
    let record = Json.array_get(accounts, index)?
    if text(record, "address")? == address do
      let raw = bytes(record, "data_hex")?
      let raw = if mode == "underfunded" && index == 7 do
        replace(raw, 64, Bytes.write_uint_le("1", 8)?)?
      else if mode == "frozen" && index == 7 do
        replace(raw, 108, Bytes.from_hex("02")?)?
      else if mode == "donations" && (index == 4 || index == 7) do
        let amount = U64.add(U64.parse(Bytes.read_uint_le(raw, 64, 8)?)?, U64.parse("9")?)?
        replace(raw, 64, Bytes.write_uint_le(U64.to_string(amount), 8)?)?
      else if mode == "withdrawn-witness" && index == 1 do
        replace(raw, 148, Bytes.write_uint_le("0", 8)?)?
      else if mode == "withdrawn-witness" && index == 5 do
        replace(replace(raw, 5, Bytes.from_hex("04")?)?,
          264,
          Bytes.write_uint_le("1600000000", 8)?)?
      else if mode == "withdrawn-witness" && index == 6 do
        replace(replace(replace(raw, 4, Bytes.from_hex("04")?)?,
            168,
            Bytes.write_uint_le("0", 8)?)?,
          184,
          Bytes.write_uint_le("1600000000", 8)?)?
      else if mode == "withdrawn-witness" && index == 7 do
        replace(raw, 64, Bytes.write_uint_le("0", 8)?)?
      else
        raw
      end
      let owner = if mode == "context-foreign" do
        "11111111111111111111111111111111"
      else
        text(record, "owner")?
      end
      return Ok("""{"data":["#{Bytes.to_base64(raw)}","base64"],"owner":"#{owner}","executable":false,"lamports":#{text(record,
        "lamports")?},"rentEpoch":0}""")
    end
  end
  Ok("null")
end

fn reply(request :: Request, value :: Json, mode :: String) -> String!String do
  if mode == "down" do
    return Err("offline")
  end
  let root = Json.parse(Request.body(request))?
  let params = field(root, "params")?
  let config = Json.array_get(params, 1)?
  assert(text(config, "commitment")? == "finalized")
  let slot = Bytes.read_uint_le(bytes(field(value, "clock")?, "data_hex")?, 0, 8)?
  assert(U64.compare(U64.parse(Json.encode(field(config, "minContextSlot")?))?,
    U64.parse(slot)?) <= 0)
  let method = text(root, "method")?
  let result = if method == "getMultipleAccounts" do
    let addresses = Json.array_get(params, 0)?
    "["
      <> String.join(for index in 0..Json.array_length(addresses)? do
          account(value, Json.as_string(Json.array_get(addresses, index)?)?, mode)?
        end,
        ",")
      <> "]"
  else if method == "getProgramAccounts" do
    let filters = field(config, "filters")?
    let status = Bytes.get(Bytes.from_base58(text(field(Json.array_get(filters, 3)?, "memcmp")?,
        "bytes")?)?,
      0)?
    if status == 2 || mode == "withdrawn-witness" || mode == "exhausted" do
      "[]"
    else
      let witness = Json.array_get(field(value, "before_accounts")?, 5)?
      "[{\"pubkey\":\"#{text(witness, "address")?}\",\"account\":#{account(value,
        text(witness, "address")?,
        mode)?}}]"
    end
  else
    assert(method == "getAccountInfo")
    let address = Json.as_string(Json.array_get(params, 0)?)?
    let encoded = account(value, address, mode)?
    # No initialized ring is needed for a fully signed pair.
    if encoded == "null" do
      return Err("account_missing")
    end
    encoded
  end
  let slot = if mode == "context-stale" do
    "1"
  else
    slot
  end
  Ok("""{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":#{slot}},"value":#{result}}}""")
end

actor server(port :: Int, fixtures :: Json) do
  let routes = List.flat_map(for index in 0..6 do
      for mode in [
        "ready",
        "settled",
        "settled-old",
        "exhausted",
        "prefunded",
        "expired",
        "underfunded",
        "frozen",
        "donations",
        "withdrawn-witness",
        "destination-ready",
        "destination-frozen",
        "destination-overflow",
        "destination-wrong-mint",
        "destination-locked-delegate",
        "destination-finder-delegate",
        "destination-prefunded",
        "destination-wrong-owner",
        "destination-native",
        "destination-long",
        "destination-locked-close",
        "destination-foreign",
        "destination-unfunded",
        "destination-executable",
        "context-foreign",
        "context-stale",
        "down"
      ] do
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

fn read(value :: Json,
  index :: Int,
  modes :: List<String>,
  wire :: Bytes) -> RelayAdmission!String do
  let program = pubkey(text(value, "program")?)?
  let addresses = anchor_addresses(program, text(value, "log_name")?)?
  let pins = AnchorPins {
    program: program,
    ring: addresses.ring,
    log_id: addresses.log_id,
    log_name: text(value, "log_name")?,
    endpoints: for node in 0..3 do
      "http://127.0.0.1:#{19960 + node}/#{index}/#{List.get(modes, node)}"
    end
  }
  admit_relay_fork(pins,
    bytes(value, "service_key")?,
    Json.as_int(field(value, "version")?)?,
    pubkey(text(value, "mint")?)?,
    Pubkey {
      bytes: Bytes.from_hex("66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a")?
    },
    wire,
    U64.parse("0")?)
end

fn ready(result :: RelayAdmission) -> RelaySettlementPlan!String do
  case result do
    ReadyToSubmit(value) -> Ok(value)
    AlreadySettled(_) -> Err("expected_new_settlement")
  end
end

fn destinations(value :: Json,
  index :: Int,
  modes :: List<String>,
  wire :: Bytes) -> RelayDestinationsState!String do
  let program = pubkey(text(value, "program")?)?
  let addresses = anchor_addresses(program, text(value, "log_name")?)?
  let pins = AnchorPins {
    program: program,
    ring: addresses.ring,
    log_id: addresses.log_id,
    log_name: text(value, "log_name")?,
    endpoints: for node in 0..3 do
      "http://127.0.0.1:#{19960 + node}/#{index}/#{List.get(modes, node)}"
    end
  }
  read_relay_destinations(pins,
    bytes(value, "service_key")?,
    Json.as_int(field(value, "version")?)?,
    pubkey(text(value, "mint")?)?,
    Pubkey {
      bytes: Bytes.from_hex("66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a")?
    },
    wire,
    U64.parse(Bytes.read_uint_le(bytes(field(value, "clock")?, "data_hex")?, 0, 8)?)?)
end

fn proof() -> Bool!String do
  let fixtures = Json.parse(File.read(Env.get("MORSE_ADJUDICATION_FIXTURES_PATH", ""))?)?
  assert(Json.array_length(fixtures)? == 6)
  let output = Env.get("MORSE_RELAY_SETTLEMENT_PLANS_PATH", "")
  let revisions = Env.get("MORSE_RELAY_PLAN_REVISIONS_PATH", "")
  if revisions != "" do
    File.write(revisions, "")?
  end
  if output != "" do
    File.write(output, "")?
  end
  let _one = spawn(server, 19960, fixtures)
  let _two = spawn(server, 19961, fixtures)
  let _three = spawn(server, 19962, fixtures)
  Timer.sleep(100)
  for index in 0..6 do
    let value = Json.array_get(fixtures, index)?
    let wire = bytes(value, "wire_hex")?
    let plan = ready(read(value, index, ["ready", "ready", "ready"], wire)?)?
    let report = relay_admission_report(ReadyToSubmit(plan))
    let document = Json.parse(report)?
    assert(text(document, "status")? == "ready")
    assert(text(document, "proof_hex")? == Bytes.to_hex(wire))
    assert(text(field(document, "estimate")?, "finder_units")? == "60000000")
    let rent = field(document, "rent_allocations")?
    assert(Json.array_length(rent)? == 5 + List.length(plan.lookup.extend))
    let upload = Json.array_get(rent, 0)?
    assert(text(upload, "step")? == "initialize"
      && text(upload, "address")? == pubkey_string(plan.stage.stage)
      && Json.as_int(field(upload, "space")?)? == 1152 + Bytes.length(wire))
    let receipt_rent = Json.array_get(rent, 3)?
    assert(text(receipt_rent, "step")? == "settle"
      && text(receipt_rent, "address")? == pubkey_string(plan.receipt)
      && Json.as_int(field(receipt_rent, "space")?)? == 384)
    if output != "" do
      File.append(output, report <> "\n")?
    end
    assert(Bytes.secure_equals(plan.proof, wire))
    assert(U64.to_string(plan.total_slashed) == "600000000"
      && U64.to_string(plan.finder_amount) == "60000000")
    assert(U64.to_string(plan.directory_slashed) == "500000000")
    assert(Bytes.to_base58(plan.stage.finder) == text(value, "finder")?)
    assert(pubkey_string(plan.receipt) == text(value, "receipt_address")?)
    assert(Bytes.secure_equals(plan.settlement.data, bytes(value, "settlement_instruction_hex")?))
    assert(List.length(plan.settlement.accounts) == 15 && List.length(plan.setup) == 2)
    assert(List.length(plan.stage.signatures) == 4)
    let expected = field(value, "settlement_accounts")?
    for position in 0..15 do
      let meta = List.get(plan.settlement.accounts, position)
      let given = Json.array_get(expected, position)?
      assert(meta.signer == Json.as_bool(field(given, "signer")?)?
        && meta.writable == Json.as_bool(field(given, "writable")?)?)
      if position != 0 && position != 2 do
        assert(pubkey_string(meta.pubkey) == text(given, "address")?)
      end
    end
    assert(plan.clock.earliest_seconds == 1700000001)
    for mode in [
      "ready",
      "destination-ready",
      "destination-finder-delegate",
      "destination-prefunded"
    ] do
      let state = destinations(value, index, [mode, mode, "down"], wire)?
      assert(state.finder.present == (mode == "destination-ready"
          || mode == "destination-finder-delegate")
        && state.locked.present == state.finder.present)
      let instruction = List.get(plan.setup, 0)
      assert(state.finder.address == List.get(instruction.accounts, 1).pubkey)
      assert(state.context_slot == plan.context_slot)
      let rendered = Json.parse(relay_destinations_report(state))?
      assert(text(rendered, "proof_hash")? == text(document, "proof_hash")?)
      assert(text(field(rendered, "finder")?, "address")? == pubkey_string(state.finder.address))
    end
    for mode in [
      "destination-frozen",
      "destination-wrong-mint",
      "destination-locked-delegate",
      "destination-wrong-owner",
      "destination-native",
      "destination-long",
      "destination-locked-close",
      "destination-foreign",
      "destination-unfunded",
      "destination-executable",
      "context-foreign",
      "context-stale"
    ] do
      case destinations(value, index, [mode, mode, "down"], wire) do
        Ok(_) -> assert(false)
        Err(_) -> nil
      end
    end
    case destinations(value, index, ["ready", "destination-ready", "down"], wire) do
      Ok(_) -> assert(false)
      Err(error) -> assert(error == "anchor_rpc_disagree")
    end
    let donated = ready(read(value, index, ["donations", "donations", "donations"], wire)?)?
    assert(U64.to_string(donated.total_slashed) == "600000018"
      && U64.to_string(donated.finder_amount) == "60000000")
    case read(value, index, ["settled", "settled", "settled"], wire)? do
      ReadyToSubmit(_) -> assert(false)
      AlreadySettled(receipt) -> assert(Bytes.to_base58(receipt.receipt.finder) == text(value,
          "finder")?)
    end
    let prefunded = ready(read(value, index, ["prefunded", "prefunded", "prefunded"], wire)?)?
    assert(prefunded.receipt == plan.receipt)
    for mode in ["expired", "underfunded", "frozen"] do
      case read(value, index, [mode, mode, mode], wire) do
        Ok(_) -> do
          println(mode)
          assert(false)
        end
        Err(_) -> nil
      end
    end
    let withdrawn = ready(read(value,
      index,
      ["withdrawn-witness", "withdrawn-witness", "withdrawn-witness"],
      wire)?)?
    assert(List.length(withdrawn.stage.witnesses) == 0
      && List.length(withdrawn.stage.signatures) == 2)
    assert(U64.to_string(withdrawn.total_slashed) == "500000000"
      && List.length(withdrawn.settlement.accounts) == 12)
    if revisions != "" do
      let next_slot = U64.add(plan.context_slot, U64.parse("1")?)?
      let later = %{plan |
        context_slot: next_slot,
        lookup: prepare_relay_lookup(plan.submitter, plan.settlement, next_slot)?
      }
      File.append(revisions,
        """{"original":#{report},"later":#{relay_admission_report(ReadyToSubmit(later))},"withdrawn":#{relay_admission_report(ReadyToSubmit(withdrawn))}}"""
          <> "\n")?
    end
    let zero_finder = encode_fork(%{decode_fork(wire)? |
      finder: Bytes.from_hex(String.repeat("00", 32))?
    })?
    let fallback = ready(read(value, index, ["ready", "ready", "ready"], zero_finder)?)?
    assert(Bytes.secure_equals(fallback.stage.finder, fallback.submitter.bytes))
    assert(fallback.receipt == plan.receipt)
    if index == 0 do
      for mode in ["destination-ready", "destination-finder-delegate"] do
        let destination = ready(read(value, index, [mode, mode, mode], wire)?)?
        assert(destination.receipt == plan.receipt)
      end
      for mode in [
        "destination-frozen",
        "destination-overflow",
        "destination-wrong-mint",
        "destination-locked-delegate",
        "exhausted"
      ] do
        case read(value, index, [mode, mode, mode], wire) do
          Ok(_) -> do
            println(mode)
            assert(false)
          end
          Err(error) -> assert(mode != "exhausted" || error == "relay_no_collectible_assets")
        end
      end
      let locked = find_program_address(plan.program,
        [Bytes.from_utf8("locked"), bytes(value, "log_id")?])?.address
      let directory = pubkey(text(Json.array_get(field(value, "settlement_accounts")?, 5)?,
        "address")?)?
      for finder in [locked, directory] do
        let alias = encode_fork(%{decode_fork(wire)? | finder: finder.bytes})?
        case read(value, index, ["ready", "ready", "ready"], alias) do
          Ok(_) -> assert(false)
          Err(error) -> assert(error == "relay_destination_alias")
        end
      end
      case read(value, index, ["settled-old", "settled-old", "settled-old"], wire)? do
        AlreadySettled(_) -> nil
        ReadyToSubmit(_) -> assert(false)
      end
    end
  end
  Ok(true)
end

test("relay admits real funded judge snapshots, prepares exact settlement accounts and recognizes completed payouts") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
