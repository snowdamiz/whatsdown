from Transparency.SlashReceipt import (
  SlashReceipt,
  SlashWitness,
  decode_slash_receipt,
  slash_receipt_address
)
from Transparency.SlashReceiptRead import (
  ConfirmedSlashReceipt,
  SlashReceiptState,
  read_slash_receipt,
  read_slash_receipt_state,
  slash_receipt_state_report,
  find_slash_receipt,
  slash_receipt_report
)
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.AnchorBond import (
  AnchorBond,
  AnchorEconomics,
  decode_anchor_bond,
  decode_anchor_economics
)
from Transparency.Fork import ForkProof, decode_fork, fork_hash
from Solana.Read import Pubkey, pubkey, pubkey_string

fn text(value :: Json, field :: String) -> String!String do
  Json.as_string(Json.object_get(value, field)?)
end

fn raw(value :: Json, field :: String) -> Bytes!String do
  case Bytes.from_hex(text(value, field)?) do
    Err(_) -> Err("invalid_fixture")
    Ok(value)
  end
end

fn fixtures() -> Json!String do
  Json.parse(File.read(Env.get("MORSE_ADJUDICATION_FIXTURES_PATH", ""))?)
end

fn replay() -> Bool!String do
  let root = fixtures()?
  assert(Json.array_length(root)? == 6)
  for index in 0..Json.array_length(root)? do
    let value = Json.array_get(root, index)?
    let receipt = decode_slash_receipt(raw(value, "receipt_hex")?)?
    let proof = decode_fork(raw(value, "wire_hex")?)?
    assert(Bytes.secure_equals(receipt.proof_hash, fork_hash(proof)?))
    assert(receipt.kind == Json.as_int(Json.object_get(value, "kind")?)?)
    assert(!receipt.anchored)
    assert(Bytes.to_base58(receipt.finder) == text(value, "finder")?)
    assert(Bytes.to_base58(receipt.submitter) == text(value, "submitter")?)
    assert(Bytes.to_base58(receipt.mint) == text(value, "mint")?)
    assert(U64.to_string(receipt.total_slashed) == "600000000")
    assert(U64.to_string(receipt.finder_amount) == "60000000")
    assert(U64.to_string(receipt.directory_slashed) == "500000000")
    assert(U64.to_string(receipt.verified_signatures) == "15")
    let bond = decode_anchor_bond(raw(value, "bond_hex")?)?
    let policy = decode_anchor_economics(raw(value, "economics_hex")?)?
    assert(bond.status == 3 && policy.directory_status == 3)
    assert(U64.to_string(bond.principal) == "0")
    assert(receipt.slashed_at == bond.slashed_at)
    assert(List.length(receipt.witnesses) == 1)
    let witness = List.head(receipt.witnesses)
    assert(Bytes.secure_equals(witness.public_key, raw(value, "signing_key")?))
    assert(Bytes.secure_equals(witness.witness, bond.witness))
    assert(U64.to_string(witness.principal) == "100000000")
    assert(U64.to_string(witness.slashed) == "100000000")
    assert(U64.to_string(witness.finder_amount) == "10000000")
    let address = slash_receipt_address(pubkey(text(value, "program")?)?,
      raw(value, "log_id")?,
      receipt.proof_hash)?
    assert(pubkey_string(address) == text(value, "receipt_address")?)
  end
  Ok(true)
end

test("Mesh decodes actual SBF slash receipts and binds them to its FRK hashes and custody state") do
  case replay() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn replace(bytes :: Bytes, offset :: Int, value :: Bytes) -> Bytes!String do
  Bytes.concat(Bytes.concat(Bytes.slice(bytes, 0, offset)?, value)?,
    Bytes.slice(bytes,
      offset + Bytes.length(value),
      Bytes.length(bytes) - offset - Bytes.length(value))?)
end

fn account_bytes(value :: Json, address :: String) -> Bytes!String do
  if address == text(value, "receipt_address")? do
    return raw(value, "receipt_hex")
  end
  let accounts = Json.object_get(value, "accounts")?
  for index in 0..Json.array_length(accounts)? do
    let account = Json.array_get(accounts, index)?
    if text(account, "address")? == address do
      return raw(account, "data_hex")
    end
  end
  Err("wrong_rpc_address")
end

fn rpc_body(request :: Request, value :: Json, mode :: String) -> String!String do
  let request = Json.parse(Request.body(request))?
  assert(text(request, "method")? == "getMultipleAccounts")
  let params = Json.object_get(request, "params")?
  let addresses = Json.array_get(params, 0)?
  let config = Json.array_get(params, 1)?
  assert(text(config, "commitment")? == "finalized")
  assert(text(config, "encoding")? == "base64")
  assert(Json.encode(Json.object_get(config, "minContextSlot")?) == "9007199254740993")
  assert(Json.array_length(addresses)? == 3)
  let values = for index in 0..3 do
    let address = Json.as_string(Json.array_get(addresses, index)?)?
    let bytes = account_bytes(value, address)?
    let receipt = address == text(value, "receipt_address")?
    if receipt && mode == "missing" do
      "null"
    else if receipt && (mode == "prefunded" || mode == "damaged") do
      let data = if mode == "prefunded" do
        ""
      else
        "AA=="
      end
      """{"data":["#{data}","base64"],"owner":"11111111111111111111111111111111","executable":false,"lamports":10,"rentEpoch":0}"""
    else
      let bytes = if receipt && mode == "wrong-hash" do
        replace(bytes, 40, Bytes.from_hex(String.repeat("12", 32))?)?
      else if receipt && mode == "wrong-mint" do
        replace(bytes, 136, Bytes.from_hex(String.repeat("12", 32))?)?
      else if receipt && mode == "wrong-log" do
        replace(bytes, 8, Bytes.from_hex(String.repeat("12", 32))?)?
      else if Bytes.length(bytes) == 352 && mode == "unslashed" do
        replace(bytes, 5, Bytes.from_hex("00")?)?
      else if receipt && mode == "different" do
        replace(bytes, 72, Bytes.from_hex(String.repeat("12", 32))?)?
      else
        bytes
      end
      let owner = if mode == "wrong-owner" do
        "11111111111111111111111111111111"
      else
        text(value, "program")?
      end
      """{"data":["#{Bytes.to_base64(bytes)}","base64"],"owner":#{Json.encode_string(owner)},"executable":false,"lamports":10000000,"rentEpoch":0}"""
    end
  end
  let slot = if mode == "too-old" do
    "1"
  else if mode == "later" do
    "9007199254740995"
  else
    "9007199254740994"
  end
  Ok("""{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":#{slot}},"value":[#{String.join(values,
    ",")}]}}""")
end

fn response(request :: Request, value :: Json, mode :: String) -> Response do
  if mode == "down" do
    return HTTP.response(503, "unavailable")
  end
  case rpc_body(request, value, mode) do
    Err(error) -> HTTP.response(400, error)
    Ok(body) -> HTTP.response(200, body)
  end
end

actor rpc_server(port :: Int, value :: Json) do
  HTTP.router()
    |> HTTP.on_post("/valid", fn(r :: Request) do response(r, value, "valid") end)
    |> HTTP.on_post("/down", fn(r :: Request) do response(r, value, "down") end)
    |> HTTP.on_post("/missing", fn(r :: Request) do response(r, value, "missing") end)
    |> HTTP.on_post("/prefunded", fn(r :: Request) do response(r, value, "prefunded") end)
    |> HTTP.on_post("/damaged", fn(r :: Request) do response(r, value, "damaged") end)
    |> HTTP.on_post("/wrong-hash", fn(r :: Request) do response(r, value, "wrong-hash") end)
    |> HTTP.on_post("/wrong-log", fn(r :: Request) do response(r, value, "wrong-log") end)
    |> HTTP.on_post("/wrong-mint", fn(r :: Request) do response(r, value, "wrong-mint") end)
    |> HTTP.on_post("/wrong-owner", fn(r :: Request) do response(r, value, "wrong-owner") end)
    |> HTTP.on_post("/unslashed", fn(r :: Request) do response(r, value, "unslashed") end)
    |> HTTP.on_post("/different", fn(r :: Request) do response(r, value, "different") end)
    |> HTTP.on_post("/too-old", fn(r :: Request) do response(r, value, "too-old") end)
    |> HTTP.on_post("/later", fn(r :: Request) do response(r, value, "later") end)
    |> HTTP.serve(port)
end

fn read(value :: Json, routes :: List<String>) -> ConfirmedSlashReceipt!String do
  let program = pubkey(text(value, "program")?)?
  let derived = anchor_addresses(program, text(value, "log_name")?)?
  let pins = AnchorPins {
    program: program,
    ring: derived.ring,
    log_name: text(value, "log_name")?,
    log_id: derived.log_id,
    endpoints: for index in 0..3 do
      "http://127.0.0.1:#{19943 + index}/#{List.get(routes, index)}"
    end
  }
  read_slash_receipt(pins,
    raw(value, "service_key")?,
    1,
    pubkey(text(value, "mint")?)?,
    fork_hash(decode_fork(raw(value, "wire_hex")?)?)?,
    U64.parse("9007199254740993")?)
end

fn authenticated() -> Bool!String do
  let value = Json.array_get(fixtures()?, 0)?
  let _one = spawn(rpc_server, 19943, value)
  let _two = spawn(rpc_server, 19944, value)
  let _three = spawn(rpc_server, 19945, value)
  Timer.sleep(100)
  for routes in [
    ["valid", "valid", "down"],
    ["down", "valid", "valid"],
    ["valid", "later", "down"]
  ] do
    let result = read(value, routes)?
    assert(U64.to_string(result.context_slot) == "9007199254740994")
    assert(U64.to_string(result.receipt.finder_amount) == "60000000")
    let report = Json.parse(slash_receipt_report(result))?
    assert(text(report, "finder_units")? == "60000000")
    assert(text(report, "total_slashed_units")? == "600000000")
    assert(text(report, "mint")? == text(value, "mint")?)
    assert(text(report, "context_slot")? == "9007199254740994")
    assert(text(Json.array_get(Json.object_get(report, "witnesses")?, 0)?,
      "slashed_units")? == "100000000")
  end
  for mode in [
    "missing",
    "prefunded",
    "damaged",
    "wrong-hash",
    "wrong-log",
    "wrong-mint",
    "wrong-owner",
    "unslashed",
    "too-old"
  ] do
    case read(value, [mode, mode, "down"]) do
      Ok(_) -> do
        println("accepted " <> mode)
        assert(false)
      end
      Err(_) -> nil
    end
  end
  case read(value, ["valid", "different", "down"]) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "anchor_rpc_disagree")
  end
  let program = pubkey(text(value, "program")?)?
  let derived = anchor_addresses(program, text(value, "log_name")?)?
  for mode in ["valid", "missing", "prefunded", "damaged"] do
    let pins = AnchorPins {
      program: program,
      ring: derived.ring,
      log_id: derived.log_id,
      log_name: text(value, "log_name")?,
      endpoints: for index in 0..3 do
        "http://127.0.0.1:#{19943 + index}/#{mode}"
      end
    }
    case find_slash_receipt(pins,
      raw(value, "service_key")?,
      1,
      pubkey(text(value, "mint")?)?,
      fork_hash(decode_fork(raw(value, "wire_hex")?)?)?,
      U64.parse("9007199254740993")?) do
      Ok(None) -> assert(mode == "missing" || mode == "prefunded")
      Ok(Some(_)) -> assert(mode == "valid")
      Err(_) -> assert(mode == "damaged")
    end
    case read_slash_receipt_state(pins,
      raw(value, "service_key")?,
      1,
      pubkey(text(value, "mint")?)?,
      fork_hash(decode_fork(raw(value, "wire_hex")?)?)?,
      U64.parse("9007199254740993")?) do
      Err(_) -> assert(mode == "damaged")
      Ok(state) -> do
        assert(mode != "damaged")
        assert(U64.to_string(state.context_slot) == "9007199254740994")
        assert(pubkey_string(state.address) == text(value, "receipt_address")?)
        let report = Json.parse(slash_receipt_state_report(state))?
        assert(text(report, "context_slot")? == "9007199254740994")
        assert(text(report, "proof_hash")? == Bytes.to_hex(fork_hash(decode_fork(raw(value,
            "wire_hex")?)?)?))
        assert(text(report, "status")? == if mode == "valid" do
            "settled"
          else
            "missing"
          end)
      end
    end
  end
  Ok(true)
end

test("finalized receipt quorum binds judge log mint and proof identity before reporting a payout") do
  case authenticated() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
