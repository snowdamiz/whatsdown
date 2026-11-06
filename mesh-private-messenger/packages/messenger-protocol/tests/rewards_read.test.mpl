from Solana.Read import (
  Pubkey,
  AccountInfo,
  AccountSlice,
  OptionalAccountSlicesAtSlot,
  pubkey,
  pubkey_string
)
from Solana.Address import ProgramDerivedAddress, find_program_address
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.RewardsRead import (
  RewardsState,
  RewardsReadAddresses,
  RewardFundingState,
  rewards_read_addresses,
  rewards_read_keys,
  decode_rewards_snapshot,
  read_rewards_account_slices,
  read_rewards,
  read_reward_funding,
  decode_reward_funding_snapshot,
  rewards_report
)
from Transparency.RewardsChain import reward_funding_address

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(result, value) do Bytes.concat(result?, value) end)
end

fn zeros(length :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat("00", length))
end

fn key(value :: String) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, 32))
end

fn wide(value :: String) -> Bytes!String do
  Bytes.write_uint_le(value, 8)
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Ok(value) -> Ok(value)
    Err(_) -> Err("invalid_test_byte")
  end
end

fn patch(bytes :: Bytes, offset :: Int, value :: Bytes) -> Bytes!String do
  cat([
    Bytes.slice(bytes, 0, offset)?,
    value,
    Bytes.slice(bytes,
      offset + Bytes.length(value),
      Bytes.length(bytes) - offset - Bytes.length(value))?
  ])
end

fn pins(endpoints :: List<String>) -> AnchorPins!String do
  let judge = Pubkey { bytes: key("22")? }
  let addresses = anchor_addresses(judge, "morse-main")?
  Ok(AnchorPins {
    program: judge,
    ring: addresses.ring,
    log_name: "morse-main",
    log_id: addresses.log_id,
    endpoints: endpoints
  })
end

fn program() -> Pubkey!String do
  Ok(Pubkey { bytes: key("44")? })
end

fn asset() -> Pubkey!String do
  Ok(Pubkey { bytes: key("55")? })
end

fn account(owner :: Pubkey,
  data :: Bytes,
  space :: Int,
  executable :: Bool) -> Option<AccountSlice>!String do
  Ok(Some(AccountSlice {
    info: AccountInfo {
      owner: owner,
      data: data,
      lamports: U64.parse("10000")?,
      executable: executable,
      rent_epoch: U64.parse("0")?
    },
    space: U64.parse(Int.to_string(space))?
  }))
end

fn attendance(pins :: AnchorPins) -> Bytes!String do
  cat([
    Bytes.from_hex("4d414501")?,
    pins.log_id,
    wide("11")?,
    wide("100")?,
    wide("4200")?,
    Bytes.from_hex("010001")?,
    zeros(17)?,
    key("07")?,
    wide("95")?,
    zeros(63 * 40)?
  ])
end

fn snapshot(status :: String) -> OptionalAccountSlicesAtSlot!String do
  let pins = pins([])?
  let program = program()?
  let mint = asset()?
  let addresses = rewards_read_addresses(pins, program, mint, U64.parse("11")?)?
  let final = status == "finalized" || status == "claimed" || status == "stale-finalized"
  let claimed = status == "claimed"
  let pool = cat([
    Bytes.from_hex("4d525001")?,
    key("11")?,
    pins.program.bytes,
    addresses.log.bytes,
    pins.log_id,
    mint.bytes,
    wide("6048010")?,
    wide("11")?,
    wide(if final do
      "12"
    else
      "11"
    end)?,
    wide("1000")?,
    wide(if final do
      "0"
    else
      "10"
    end)?,
    wide(if final && !claimed do
      "110"
    else
      "0"
    end)?,
    wide(if claimed do
      "1000"
    else
      "1110"
    end)?,
    wide(if status == "collecting" || status == "stale" do
      "12"
    else
      "0"
    end)?,
    zeros(32)?,
    wide("0")?,
    key("66")?,
    zeros(4)?
  ])?
  let week = attendance(pins)?
  let ledger = if status == "open" || status == "awaiting-economics" do
    cat([
      Bytes.from_hex("4d524501")?,
      addresses.pool.bytes,
      wide("11")?,
      wide("100")?,
      zeros(8364)?
    ])?
  else
    cat([
      Bytes.from_hex("4d524501")?,
      addresses.pool.bytes,
      wide("11")?,
      wide("100")?,
      byte(if final do
        2
      else
        1
      end)?,
      Bytes.from_hex("010100")?,
      Crypto.sha256(week),
      wide("100")?,
      wide("300")?,
      wide("0")?,
      wide("0")?,
      wide("0")?,
      wide("110")?,
      wide("0")?,
      wide(if final do
        "110"
      else
        "0"
      end)?,
      wide("0")?,
      wide(if claimed do
        "1"
      else
        "0"
      end)?,
      wide("7257600")?,
      wide("2")?,
      zeros(40)?,
      key("07")?,
      key("08")?,
      key("09")?,
      wide("300")?,
      wide("0")?,
      wide("0")?,
      wide(if final do
        "110"
      else
        "0"
      end)?,
      zeros(63 * 128)?
    ])?
  end
  let vault = cat([
    mint.bytes,
    addresses.pool.bytes,
    wide(if claimed do
      "1005"
    else
      "1115"
    end)?,
    zeros(36)?,
    byte(1)?,
    zeros(56)?
  ])?
  let mint_data = cat([zeros(36)?, wide("10000")?, Bytes.from_hex("0601")?, zeros(36)?])?
  let log = cat([
    Bytes.from_hex("4d4c470101000a01")?,
    Bytes.from_utf8("morse-main"),
    zeros(22)?,
    pins.log_id,
    key("11")?,
    key("22")?,
    pins.ring.bytes,
    key("33")?,
    zeros(152)?
  ])?
  let clock = cat([
    Bytes.from_hex("4d414301")?,
    pins.log_id,
    wide("6048010")?,
    wide("100")?,
    wide("11")?,
    wide("11")?,
    zeros(8348)?
  ])?
  let economics = cat([
    Bytes.from_hex("4d454301")?,
    pins.log_id,
    mint.bytes,
    key("66")?,
    wide("1")?,
    wide("1")?,
    zeros(32)?,
    wide("1")?,
    wide("1")?,
    byte(1)?,
    zeros(3)?,
    wide(if status == "stale" || status == "stale-finalized" do
      "3"
    else
      "2"
    end)?,
    zeros(16)?
  ])?
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let image = cat([
    Bytes.write_uint_le("2", 4)?,
    find_program_address(loader, [program.bytes])?.address.bytes
  ])?
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  Ok(OptionalAccountSlicesAtSlot {
    slot: U64.parse("9007199254740993")?,
    accounts: [
      if status == "absent" do
        None
      else
        account(program, pool, 304, false)?
      end,
      if status == "absent" || status == "awaiting" do
        None
      else
        account(program, ledger, 8416, false)?
      end,
      if status == "absent" do
        None
      else
        account(token, vault, 165, false)?
      end,
      account(token, mint_data, 82, false)?,
      account(pins.program, log, 352, false)?,
      account(pins.program, clock, 65616, false)?,
      account(pins.program, week, 2640, false)?,
      if status == "awaiting-economics" do
        None
      else
        account(pins.program, economics, 192, false)?
      end,
      account(loader, image, 36, true)?
    ]
  })
end

fn decode(value :: OptionalAccountSlicesAtSlot) -> RewardsState!String do
  decode_rewards_snapshot(pins([])?, key("11")?, 1, program()?, asset()?, U64.parse("11")?, value)
end

fn mutated(value :: OptionalAccountSlicesAtSlot,
  index :: Int,
  offset :: Int,
  bytes :: Bytes) -> OptionalAccountSlicesAtSlot!String do
  let changed = case List.get(value.accounts, index) do
    None -> return Err("missing fixture account")
    Some(account) -> Some(%{account |
      info: %{account.info | data: patch(account.info.data, offset, bytes)?}
    })
  end
  Ok(%{value |
    accounts: List.take(value.accounts, index) ++ [changed] ++ List.drop(value.accounts, index + 1)
  })
end

fn funding_snapshot(missing :: Bool) -> OptionalAccountSlicesAtSlot!String do
  let base = snapshot("stale-finalized")?
  let addresses = rewards_read_addresses(pins([])?, program()?, asset()?, U64.parse("11")?)?
  let funder = Pubkey { bytes: key("0a")? }
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let ata = pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?
  let source = find_program_address(ata, [funder.bytes, token.bytes, asset()?.bytes])?.address
  let wire = cat([
    Bytes.from_hex("4d524601")?,
    addresses.pool.bytes,
    funder.bytes,
    key("0b")?,
    wide("11")?,
    byte(1)?,
    zeros(3)?,
    wide("7")?,
    source.bytes,
    asset()?.bytes,
    wide("6652800")?
  ])?
  Ok(%{base |
    accounts: List.append(base.accounts,
      if missing do
        None
      else
        account(program()?, wire, 192, false)?
      end)
  })
end

fn decode_funding(view :: OptionalAccountSlicesAtSlot) -> RewardFundingState!String do
  decode_reward_funding_snapshot(pins([])?,
    key("11")?,
    1,
    program()?,
    asset()?,
    U64.parse("11")?,
    Pubkey { bytes: key("0a")? },
    key("0b")?,
    view)
end

fn proof() -> Bool!String do
  for status in [
    "absent",
    "awaiting",
    "open",
    "collecting",
    "finalized",
    "claimed",
    "stale",
    "stale-finalized",
    "awaiting-economics"
  ] do
    let value = decode(snapshot(status)?)?
    let expected = if status == "claimed" || status == "stale-finalized" do
      "finalized"
    else if status == "stale" do
      "collecting"
    else if status == "awaiting-economics" do
      "awaiting"
    else
      status
    end
    assert(value.status == expected)
    let report = Json.parse(rewards_report(value))?
    assert(Json.as_string(Json.object_get(report, "program_pin")?)? == "operator_selected")
    assert(Json.as_string(Json.object_get(report, "context_slot")?)? == "9007199254740993")
    if status == "claimed" do
      assert(value.unclaimed_amount == Some(U64.parse("0")?))
    else if status == "finalized" || status == "stale-finalized" do
      assert(value.unclaimed_amount == Some(U64.parse("110")?))
    end
    if status == "stale" || status == "stale-finalized" do
      assert(value.revision_matches == Some(false))
    end
    if status == "awaiting-economics" do
      assert(value.economics == None && value.awaiting == "economics")
    end
    assert(!String.contains(Json.encode(report), "USDC")
      && !String.contains(Json.encode(report), "independent"))
  end
  let base = snapshot("finalized")?
  let maximum = "18446744073709551615"
  let weighted = mutated(mutated(base, 6, 44, wide(maximum)?)?, 6, 112, wide(maximum)?)?
  let week = case List.get(weighted.accounts, 6) do
    None -> return Err("fixture missing")
    Some(value) -> value.info.data
  end
  let weight = cat([wide("18446744073709551613")?, wide("2")?])?
  let weighted = mutated(mutated(mutated(mutated(mutated(mutated(weighted,
              1,
              56,
              Crypto.sha256(week))?,
            1,
            88,
            wide(maximum)?)?,
          1,
          96,
          weight)?,
        1,
        320,
        weight)?,
      0,
      212,
      wide(maximum)?)?,
    2,
    64,
    wide(maximum)?)?
  let report = Json.parse(rewards_report(decode(weighted)?))?
  let pool_report = Json.object_get(report, "pool")?
  let epoch_report = Json.object_get(report, "epoch_state")?
  assert(Json.as_string(Json.object_get(pool_report, "accounted")?)? == maximum)
  assert(Json.as_string(Json.object_get(epoch_report, "posts")?)? == maximum)
  assert(Json.as_string(Json.object_get(epoch_report, "total_weight")?)? == "55340232221128654845")
  for (index, offset, bytes) in [
    (0, 36, key("77")?),
    (0, 68, key("77")?),
    (0, 100, key("77")?),
    (0, 132, key("77")?),
    (0, 164, wide("6048011")?),
    (1, 4, key("77")?),
    (1, 36, wide("12")?),
    (1, 56, key("77")?),
    (1, 88, wide("101")?),
    (1, 224, key("06")?),
    (2, 0, key("77")?),
    (2, 32, key("77")?),
    (2, 64, wide("1110")?),
    (2, 72, Bytes.from_hex("01000000")?),
    (2, 108, byte(2)?),
    (2, 109, Bytes.from_hex("01000000")?),
    (2, 129, Bytes.from_hex("01000000")?),
    (3, 44, byte(9)?),
    (3, 45, byte(0)?),
    (4, 72, key("77")?),
    (4, 7, byte(0)?),
    (5, 4, key("77")?),
    (6, 4, key("77")?),
    (7, 36, key("77")?),
    (8, 0, Bytes.from_hex("01000000")?)
  ] do
    let bad = if index == 2 && offset == 64 do
      mutated(base, index, offset, wide("1109")?)?
    else
      mutated(base, index, offset, bytes)?
    end
    case decode(bad) do
      Ok(_) -> do
        println("accepted rewards mutation #{index}:#{offset}")
        assert(false)
      end
      Err(_) -> nil
    end
  end
  for index in 0..9 do
    let original = case List.get(base.accounts, index) do
      None -> return Err("fixture missing")
      Some(value) -> value
    end
    for changed in [
      %{original | info: %{original.info | owner: Pubkey { bytes: key("77")? }}},
      %{original | info: %{original.info | executable: index != 8}},
      %{original | info: %{original.info | lamports: U64.parse("0")?}},
      %{original | space: U64.add(original.space, U64.parse("1")?)?}
    ] do
      case decode(%{base |
        accounts: List.take(base.accounts, index)
          ++ [Some(changed)]
          ++ List.drop(base.accounts, index + 1)
      }) do
        Ok(_) -> assert(false)
        Err(_) -> nil
      end
    end
  end
  case decode(%{base | accounts: List.take(base.accounts, 8)}) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  case decode(mutated(base, 0, 180, wide("11")?)?) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  let funding = funding_snapshot(false)?
  assert(decode_funding(funding)?.status == "funded")
  assert(decode_funding(funding)?.rewards.revision_matches == Some(false))
  assert(decode_funding(funding_snapshot(true)?)?.status == "missing")
  for (offset, value) in [
    (4, key("77")?),
    (36, key("77")?),
    (68, key("77")?),
    (100, wide("12")?),
    (120, key("77")?),
    (152, key("77")?)
  ] do
    case decode_funding(mutated(funding, 9, offset, value)?) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  Ok(true)
end

fn render_account(value :: Option<AccountSlice>, index :: Int, mode :: String) -> String!String do
  let value = case value do
    None -> return Ok("null")
    Some(value) -> value
  end
  let info = value.info
  let owner = if mode == "foreign" && index == 0 do
    Bytes.to_base58(key("77")?)
  else
    pubkey_string(info.owner)
  end
  let space = U64.to_string(value.space)
  let space = if mode == "quoted-space" && index == 5 do
    Json.encode_string(space)
  else if mode == "clock-space" && index == 5 do
    "80"
  else
    space
  end
  let lamports = if mode == "zero-rent" && index == 0 do
    "0"
  else
    U64.to_string(info.lamports)
  end
  let executable = if mode == "not-executable" && index == 8 do
    "false"
  else if info.executable do
    "true"
  else
    "false"
  end
  let data = if mode == "oversized" && index == 5 do
    cat([info.data, byte(0)?])?
  else if mode == "short-clock" && index == 5 do
    Bytes.slice(info.data, 0, 80)?
  else
    info.data
  end
  Ok("""{"owner":"#{owner}","space":#{space},"lamports":#{lamports},"executable":#{executable},"rentEpoch":0,"data":["#{Bytes.to_base64(data)}","base64"]}""")
end

fn rpc_reply(request :: Request) -> String!String do
  let mode = case Request.param(request, "mode") do
    None -> return Err("missing mode")
    Some(value) -> value
  end
  if mode == "down" do
    return Err("offline")
  end
  let selected = if List.contains([
      "absent",
      "awaiting",
      "open",
      "collecting",
      "stale",
      "claimed",
      "stale-finalized",
      "awaiting-economics"
    ],
    mode) do
    mode
  else
    "finalized"
  end
  let root = Json.parse(Request.body(request))?
  let params = Json.object_get(root, "params")?
  let keys = Json.array_get(params, 0)?
  let count = Json.array_length(keys)?
  let view = if count == 10 do
    funding_snapshot(mode == "missing-receipt")?
  else
    snapshot(selected)?
  end
  let view = if mode == "changed" do
    mutated(view, 0, 4, key("77")?)?
  else if mode == "wrong-hash" do
    mutated(view, 1, 56, key("77")?)?
  else if mode == "wrong-log" do
    mutated(view, 4, 72, key("77")?)?
  else
    view
  end
  let options = Json.array_get(params, 1)?
  let expected = rewards_read_keys(rewards_read_addresses(pins([])?,
    program()?,
    asset()?,
    U64.parse("11")?)?)
  assert(Json.as_string(Json.object_get(root, "method")?)? == "getMultipleAccounts")
  assert(count == 9 || count == 10)
  for index in 0..9 do
    assert(Json.as_string(Json.array_get(keys, index)?)? == pubkey_string(List.get(expected,
        index)))
  end
  if count == 10 do
    let address = reward_funding_address(program()?, Pubkey { bytes: key("0a")? }, key("0b")?)?
    assert(Json.as_string(Json.array_get(keys, 9)?)? == pubkey_string(address))
  end
  assert(Json.as_string(Json.object_get(options, "commitment")?)? == "finalized")
  assert(Json.encode(Json.object_get(options, "minContextSlot")?) == "9007199254740993")
  let slice = Json.object_get(options, "dataSlice")?
  assert(Json.as_int(Json.object_get(slice, "offset")?)? == 0
    && Json.as_int(Json.object_get(slice, "length")?)? == 8416)
  let accounts = "["
    <> String.join(for index in 0..count do
        render_account(List.get(view.accounts, index), index, mode)?
      end,
      ",")
    <> "]"
  let accounts = if mode == "values-string" do
    Json.encode_string(accounts)
  else if mode == "short-batch" do
    "[]"
  else
    accounts
  end
  let slot = if mode == "stale-context" do
    "9007199254740992"
  else if mode == "high-context" do
    "9007199254741093"
  else if mode == "quoted-slot" do
    "\"9007199254740993\""
  else
    "9007199254740993"
  end
  let context = "{\"slot\":#{slot}}"
  let context = if mode == "context-string" do
    Json.encode_string(context)
  else
    context
  end
  let result = "{\"context\":#{context},\"value\":#{accounts}}"
  let result = if mode == "result-string" do
    Json.encode_string(result)
  else
    result
  end
  let id = if mode == "wrong-id" do
    "2"
  else
    "1"
  end
  Ok("{\"jsonrpc\":\"2.0\",\"id\":#{id},\"result\":#{result}}")
end

actor rpc_server(port :: Int) do
  let router = HTTP.on_post(HTTP.router(),
    "/:mode",
    fn(request :: Request) do
      case rpc_reply(request) do
        Ok(body) -> HTTP.response(200, body)
        Err(error) -> HTTP.response(503, error)
      end
    end)
  HTTP.serve(router, port)
end

fn provider_pins(modes :: List<String>) -> AnchorPins!String do
  pins(for index in 0..3 do
    "http://127.0.0.1:#{20321 + index}/#{List.get(modes, index)}"
  end)
end

fn read_modes(modes :: List<String>) -> RewardsState!String do
  read_rewards(provider_pins(modes)?,
    key("11")?,
    1,
    program()?,
    asset()?,
    U64.parse("11")?,
    U64.parse("9007199254740993")?)
end

fn provider_proof() -> Bool!String do
  let _one = spawn(rpc_server, 20321)
  let _two = spawn(rpc_server, 20322)
  let _three = spawn(rpc_server, 20323)
  Timer.sleep(100)
  for mode in [
    "absent",
    "awaiting",
    "open",
    "collecting",
    "valid",
    "claimed",
    "stale",
    "stale-finalized",
    "awaiting-economics"
  ] do
    let expected = if mode == "valid" || mode == "claimed" || mode == "stale-finalized" do
      "finalized"
    else if mode == "stale" do
      "collecting"
    else if mode == "awaiting-economics" do
      "awaiting"
    else
      mode
    end
    assert(read_modes([mode, mode, mode])?.status == expected)
    assert(read_modes([mode, "down", mode])?.status == expected)
  end
  assert(read_modes([
    "valid",
    "high-context",
    "down"
  ])?.context_slot == U64.parse("9007199254740993")?)
  for mode in [
    "foreign",
    "quoted-space",
    "clock-space",
    "zero-rent",
    "not-executable",
    "oversized",
    "short-clock",
    "wrong-hash",
    "wrong-log",
    "values-string",
    "short-batch",
    "stale-context",
    "quoted-slot",
    "context-string",
    "result-string",
    "wrong-id"
  ] do
    case read_modes([mode, mode, mode]) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
    assert(read_modes([mode, "valid", "valid"])?.status == "finalized")
  end
  assert(read_modes(["valid", "changed", "down"]) == Err("anchor_rpc_disagree"))
  assert(read_modes(["down", "valid", "down"]) == Err("anchor_rpc_unavailable"))
  let pins = provider_pins(["valid", "high-context", "down"])?
  let keys = rewards_read_keys(rewards_read_addresses(pins,
    program()?,
    asset()?,
    U64.parse("11")?)?)
  let raw = read_rewards_account_slices(pins, keys, 8416, U64.parse("9007199254740993")?)?
  assert(raw.slot == U64.parse("9007199254740993")? && List.length(raw.accounts) == 9)
  for length in [0, 8417] do
    assert(read_rewards_account_slices(pins,
      keys,
      length,
      U64.parse("9007199254740993")?) == Err("invalid_rewards_batch"))
  end
  for mode in ["funded", "missing-receipt"] do
    let view = read_reward_funding(provider_pins([mode, "down", mode])?,
      key("11")?,
      1,
      program()?,
      asset()?,
      U64.parse("11")?,
      Pubkey { bytes: key("0a")? },
      key("0b")?,
      U64.parse("9007199254740993")?)?
    assert(view.status == if mode == "funded" do
        "funded"
      else
        "missing"
      end)
  end
  assert(read_reward_funding(provider_pins(["funded", "missing-receipt", "down"])?,
    key("11")?,
    1,
    program()?,
    asset()?,
    U64.parse("11")?,
    Pubkey { bytes: key("0a")? },
    key("0b")?,
    U64.parse("9007199254740993")?) == Err("anchor_rpc_disagree"))
  Ok(true)
end

test("rewards require strict common-bank whole-batch independent-provider agreement") do
  case provider_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("rewards authenticate custody and immutable pool context while preserving finalized claims after revision changes") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
