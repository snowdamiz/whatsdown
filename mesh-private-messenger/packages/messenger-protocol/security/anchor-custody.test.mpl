from Transparency.RpcTransport import webpki_rpc_transport
from Transparency.AnchorBond import (
  AnchorBond,
  AnchorEconomics,
  AnchorBondAddresses,
  decode_anchor_bond,
  decode_anchor_economics,
  witness_bond_addresses
)
from Solana.Read import Pubkey, pubkey, pubkey_string
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.AnchorCustody import (
  AnchorCustody,
  AnchorWitnessBond,
  AnchorBondBalance,
  read_anchor_custody
)
from Transparency.Merkle import WitnessKey
from Transparency.AnchorCustodyReport import anchor_custody_report

fn text(value :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(value, key)?)
end

fn same(value :: U64, expected :: Json, key :: String) -> Bool!String do
  Ok(U64.to_string(value) == text(expected, key)?)
end

fn replay() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_CUSTODY_FIXTURES_PATH", ""))?)?
  let cases = Json.object_get(root, "snapshots")?
  for index in 0..Json.array_length(cases)? do
    let value = Json.array_get(cases, index)?
    let expected = Json.object_get(value, "expected")?
    let economics = decode_anchor_economics(Bytes.from_hex(text(value, "economics_hex")?)?)?
    let bond = decode_anchor_bond(Bytes.from_hex(text(value, "bond_hex")?)?)?
    let addresses = witness_bond_addresses(pubkey(text(value, "program")?)?,
      Bytes.from_hex(text(value, "log_id")?)?,
      pubkey(text(value, "mint")?)?,
      text(value, "witness_id")?,
      Bytes.from_hex(text(value, "signing_key")?)?)?
    assert(pubkey_string(addresses.economics) == text(value, "economics_address")?)
    assert(pubkey_string(addresses.bond) == text(value, "bond_address")?)
    assert(pubkey_string(addresses.vault) == text(value, "vault_address")?)
    assert(same(economics.minimum_witness, expected, "minimum_witness")?)
    assert(same(economics.minimum_directory, expected, "minimum_directory")?)
    assert(same(economics.pending_witness, expected, "pending_witness")?)
    assert(same(economics.pending_directory, expected, "pending_directory")?)
    assert(same(economics.pending_ready, expected, "pending_ready")?)
    assert(same(economics.witness_principal, expected, "witness_principal")?)
    assert(same(economics.directory_principal, expected, "directory_principal")?)
    assert(economics.directory_status == Json.as_int(Json.object_get(expected,
        "directory_status")?)?)
    assert(bond.status == Json.as_int(Json.object_get(expected, "status")?)?)
    assert(same(bond.principal, expected, "principal")?)
    assert(same(bond.bonded_at, expected, "bonded_at")?)
    assert(same(bond.unbond_at, expected, "unbond_at")?)
    assert(Bytes.secure_equals(bond.vault, addresses.vault.bytes))
    assert(Bytes.secure_equals(bond.log_id, economics.log_id))
    assert(Bytes.secure_equals(bond.mint, economics.mint))
  end
  Ok(true)
end

test("Mesh reads exact custody accounts created by judge and token SBF execution") do
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

fn fixture(root :: Json, name :: String) -> Json!String do
  let name = if name == "pending" do
    "pending minimums"
  else if name == "unbonding" do
    "unbonding after top-up"
  else
    name
  end
  let snapshots = Json.object_get(root, "snapshots")?
  for index in 0..Json.array_length(snapshots)? do
    let value = Json.array_get(snapshots, index)?
    if text(value, "name")? == name do
      return Ok(value)
    end
  end
  Err("missing_snapshot")
end

fn rpc_body(request :: Request, root :: Json, mode :: String) -> String!String do
  let snapshot = fixture(root,
    if mode == "pending" || mode == "unbonding" || mode == "withdrawn" do
      mode
    else
      "active"
    end)?
  let request = Json.parse(Request.body(request))?
  if text(request, "method")? != "getMultipleAccounts" do
    return Err("wrong_rpc_method")
  end
  let params = Json.object_get(request, "params")?
  let addresses = Json.array_get(params, 0)?
  let config = Json.array_get(params, 1)?
  if text(config, "commitment")? != "finalized" || text(config, "encoding")? != "base64" do
    return Err("wrong_rpc_config")
  end
  let minimum = U64.parse(Json.encode(Json.object_get(config, "minContextSlot")?))?
  if U64.compare(minimum, U64.parse("9007199254740993")?) < 0 do
    return Err("wrong_minimum_context")
  end
  let accounts = Json.object_get(snapshot, "accounts")?
  let values = for index in 0..Json.array_length(addresses)? do
    let address = Json.as_string(Json.array_get(addresses, index)?)?
    let (position, account) = case find_account(accounts, address) do
      Ok(value) -> value
      Err(_) -> (-1, Json.parse("null")?)
    end
    if position == -1
      || (mode == "unconfigured" && position == 1)
      || (mode == "registered" && (position == 6 || position == 7)) do
      "null"
    else
      let bytes = Bytes.from_hex(text(account, "data_hex")?)?
      let bytes = if mode == "unconfigured" && position == 0 do
        replace(bytes, 168, Bytes.from_hex(String.repeat("00", 32))?)?
      else if mode == "registered" && position == 1 do
        replace(bytes, 148, Bytes.from_hex(String.repeat("00", 8))?)?
      else if mode == "registered" && position == 5 do
        replace(replace(bytes, 5, Bytes.from_hex("00")?)?,
          232,
          Bytes.from_hex(String.repeat("00", 40))?)?
      else if mode == "underfunded" && position == 7 do
        replace(bytes, 64, Bytes.from_hex("0100000000000000")?)?
      else if mode == "wrong-vault-owner" && position == 7 do
        replace(bytes, 32, Bytes.from_hex(String.repeat("11", 32))?)?
      else if mode == "wrong-decimals" && position == 2 do
        replace(bytes, 44, Bytes.from_hex("09")?)?
      else if mode == "foreign-witness" && position == 5 do
        replace(bytes, 72, Bytes.from_hex(String.repeat("11", 32))?)?
      else if mode == "foreign-bond" && position == 6 do
        replace(bytes, 40, Bytes.from_hex(String.repeat("11", 32))?)?
      else if mode == "changed-policy" && position == 1 && Json.array_length(addresses)? > 2 do
        # Both individually valid, but not the policy used to derive this read.
        replace(bytes, 100, Bytes.from_hex("0100000000000000")?)?
      else
        bytes
      end
      let owner = if mode == "wrong-program" do
        "11111111111111111111111111111111"
      else
        text(account, "owner")?
      end
      """{"data":["#{Bytes.to_base64(bytes)}","base64"],"owner":"#{owner}","executable":false,"lamports":#{text(account,
        "lamports")?},"rentEpoch":0}"""
    end
  end
  let slot = if mode == "too-old" do
    "9007199254740992"
  else if mode == "later" do
    "18446744073709551615"
  else
    "9007199254740994"
  end
  let values = if mode == "short" do
    List.take(values, List.length(values) - 1)
  else
    values
  end
  Ok("""{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":#{slot}},"value":[#{String.join(values,
    ",")}]}}""")
end

fn find_account(accounts :: Json, address :: String) -> (Int, Json)!String do
  for index in 0..Json.array_length(accounts)? do
    let value = Json.array_get(accounts, index)?
    if text(value, "address")? == address do
      return Ok((index, value))
    end
  end
  Err("wrong_account_address")
end

fn respond(request :: Request, root :: Json, mode :: String) -> Response do
  if mode == "down" do
    return HTTP.response(503, "unavailable")
  end
  case rpc_body(request, root, mode) do
    Err(error) -> HTTP.response(400, error)
    Ok(body) -> HTTP.response(200, body)
  end
end

actor rpc_server(port :: Int, root :: Json) do
  HTTP.router()
    |> HTTP.on_post("/active", fn(r :: Request) do respond(r, root, "active") end)
    |> HTTP.on_post("/pending", fn(r :: Request) do respond(r, root, "pending") end)
    |> HTTP.on_post("/unbonding", fn(r :: Request) do respond(r, root, "unbonding") end)
    |> HTTP.on_post("/withdrawn", fn(r :: Request) do respond(r, root, "withdrawn") end)
    |> HTTP.on_post("/unconfigured", fn(r :: Request) do respond(r, root, "unconfigured") end)
    |> HTTP.on_post("/registered", fn(r :: Request) do respond(r, root, "registered") end)
    |> HTTP.on_post("/later", fn(r :: Request) do respond(r, root, "later") end)
    |> HTTP.on_post("/down", fn(r :: Request) do respond(r, root, "down") end)
    |> HTTP.on_post("/short", fn(r :: Request) do respond(r, root, "short") end)
    |> HTTP.on_post("/too-old", fn(r :: Request) do respond(r, root, "too-old") end)
    |> HTTP.on_post("/wrong-program", fn(r :: Request) do respond(r, root, "wrong-program") end)
    |> HTTP.on_post("/underfunded", fn(r :: Request) do respond(r, root, "underfunded") end)
    |> HTTP.on_post("/wrong-vault-owner",
      fn(r :: Request) do respond(r, root, "wrong-vault-owner") end)
    |> HTTP.on_post("/wrong-decimals", fn(r :: Request) do respond(r, root, "wrong-decimals") end)
    |> HTTP.on_post("/foreign-witness", fn(r :: Request) do respond(r, root, "foreign-witness") end)
    |> HTTP.on_post("/foreign-bond", fn(r :: Request) do respond(r, root, "foreign-bond") end)
    |> HTTP.on_post("/changed-policy", fn(r :: Request) do respond(r, root, "changed-policy") end)
    |> HTTP.serve(port)
end

fn pins(value :: Json, routes :: List<String>) -> AnchorPins!String do
  let program = pubkey(text(value, "program")?)?
  let name = text(value, "log_name")?
  let derived = anchor_addresses(program, name)?
  Ok(AnchorPins {
    program: program,
    ring: derived.ring,
    log_id: derived.log_id,
    log_name: name,
    rpc: webpki_rpc_transport(for index in 0..3 do
      "http://127.0.0.1:#{19940 + index}/#{List.get(routes, index)}"
    end)?
  })
end

fn read(value :: Json, routes :: List<String>) -> AnchorCustody!String do
  read_anchor_custody(pins(value, routes)?,
    Bytes.from_hex(text(value, "service_key")?)?,
    1,
    pubkey(text(value, "mint")?)?,
    [
      WitnessKey {
        witness_id: text(value, "witness_id")?,
        public_key: Bytes.from_hex(text(value, "signing_key")?)?
      }
    ],
    U64.parse("9007199254740993")?)
end

fn reader_proof() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_CUSTODY_FIXTURES_PATH", ""))?)?
  let _one = spawn(rpc_server, 19940, root)
  let _two = spawn(rpc_server, 19941, root)
  let _three = spawn(rpc_server, 19942, root)
  Timer.sleep(100)
  let value = fixture(root, "active")?
  for name in ["active", "pending", "unbonding", "withdrawn"] do
    let expected = Json.object_get(fixture(root, name)?, "expected")?
    let result = read(value, [name, name, "down"])?
    let report = Json.parse(anchor_custody_report(result, pubkey(text(value, "mint")?)?)?)?
    assert(text(report, "context_slot")? == "9007199254740994")
    let reported = Json.array_get(Json.object_get(report, "witnesses")?, 0)?
    assert(text(Json.object_get(reported, "bond")?, "principal_units")? == text(expected,
        "principal")?)
    assert(text(reported, "id")? == "outside")
    assert(text(Json.object_get(report, "directory")?, "principal_units")? == "500000000")
    assert(U64.to_string(result.context_slot) == "9007199254740994")
    assert(List.length(result.witnesses) == 1)
    let witness = List.head(result.witnesses)
    case witness.escrow do
      None -> assert(false)
      Some(escrow) -> do
        assert(escrow.bond.status == Json.as_int(Json.object_get(expected, "status")?)?)
        assert(same(escrow.bond.principal, expected, "principal")?)
        assert(same(escrow.vault_amount, expected, "principal")?)
      end
    end
  end
  assert(U64.to_string(read(value,
    ["active", "later", "down"])?.context_slot) == "9007199254740994")
  assert(U64.to_string(read(value,
    ["down", "active", "active"])?.context_slot) == "9007199254740994")
  case read(value, ["active", "underfunded", "down"]) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "anchor_rpc_disagree")
  end
  for mode in [
    "short",
    "too-old",
    "wrong-program",
    "underfunded",
    "wrong-vault-owner",
    "wrong-decimals",
    "foreign-witness",
    "foreign-bond",
    "changed-policy"
  ] do
    case read(value, [mode, mode, "down"]) do
      Ok(_) -> do
        println("accepted " <> mode)
        assert(false)
      end
      Err(_) -> nil
    end
  end
  let unconfigured = read(value, ["unconfigured", "unconfigured", "down"])?
  case unconfigured.economics do
    None -> nil
    Some(_) -> assert(false)
  end
  let report = Json.parse(anchor_custody_report(unconfigured, pubkey(text(value, "mint")?)?)?)?
  assert(text(report, "status")? == "unconfigured")
  assert(Json.is_null(Json.object_get(report, "directory")?))
  let registered = List.head(read(value, ["registered", "registered", "down"])?.witnesses)
  assert(registered.status == "registered")
  case registered.escrow do
    None -> nil
    Some(_) -> assert(false)
  end
  let pin = pins(value, ["active", "active", "down"])?
  let key = WitnessKey {
    witness_id: text(value, "witness_id")?,
    public_key: Bytes.from_hex(text(value, "signing_key")?)?
  }
  let historical = read_anchor_custody(pin,
    Bytes.from_hex(text(value, "service_key")?)?,
    1,
    pubkey(text(value, "mint")?)?,
    [
      key,
      %{key | public_key: Bytes.from_hex(String.repeat("aa", 32))?},
      %{key | witness_id: "another-id"}
    ],
    U64.parse("9007199254740993")?)?
  assert(List.length(historical.witnesses) == 3)
  assert(List.get(historical.witnesses, 0).status == "active")
  assert(List.get(historical.witnesses, 1).status == "unregistered")
  assert(List.get(historical.witnesses, 2).status == "unregistered")
  case read_anchor_custody(pin,
    Bytes.from_hex(text(value, "service_key")?)?,
    1,
    pubkey(text(value, "mint")?)?,
    [key, key],
    U64.parse("9007199254740993")?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "invalid_anchor_pins")
  end
  case read_anchor_custody(pin,
    Bytes.from_hex(text(value, "service_key")?)?,
    1,
    pin.program,
    [],
    U64.parse("9007199254740993")?) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  Ok(true)
end

test("finalized custody reads bind whole SBF snapshots to pinned programs mints keys and real vault balances") do
  case reader_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
