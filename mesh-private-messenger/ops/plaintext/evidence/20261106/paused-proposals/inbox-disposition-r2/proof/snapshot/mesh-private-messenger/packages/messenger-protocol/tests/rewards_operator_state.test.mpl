from Transparency.RpcTransport import webpki_rpc_transport
from Solana.Read import Pubkey, AccountInfo, AccountSlice, OptionalAccountSlicesAtSlot, pubkey
from Solana.Address import ProgramDerivedAddress, find_program_address
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.RewardsRead import (
  RewardsState,
  RewardsReadAddresses,
  rewards_read_addresses,
  decode_rewards_snapshot
)
from Transparency.RewardsChain import RewardPoolAccount, RewardEpochAccount, RewardClaimRow
from Transparency.RewardsOperator import (
  RewardOperatorIntent,
  decode_reward_intent,
  select_reward_step
)

# Self-contained synthetic account fixtures use the same strict reader boundary
# as production. No remote provider, external fixture or wall clock is involved.
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
    Ok(value)
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
    rpc: webpki_rpc_transport(endpoints)?
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

fn intent(action :: String, epoch :: String, row :: Int) -> RewardOperatorIntent!String do
  let extra = if action == "fund" do
    """, "funder":"#{Bytes.to_base58(key("11")?)}","kind":1,"amount":"7","operation_id":#{Json.encode_string(Bytes.to_hex(key("77")?))}"""
  else if action == "claim" do
    ",\"row\":#{row}"
  else
    ""
  end
  decode_reward_intent("""{"action":"#{action}","program":"#{Bytes.to_base58(program()?.bytes)}","mint":"#{Bytes.to_base58(asset()?.bytes)}","payer":"#{Bytes.to_base58(key("11")?)}","log":"morse-main","epoch":"#{epoch}"#{extra}}""")
end

fn step(action :: String, mode :: String, time :: String) -> String!String do
  select_reward_step(intent(action, "11", 0)?, decode(snapshot(mode)?)?, U64.parse(time)?)
end

fn partial_week() -> Bool!String do
  let first_full = decode(snapshot("awaiting")?)?
  let epoch = U64.parse("10")?
  let addresses = rewards_read_addresses(pins([])?, program()?, asset()?, epoch)?
  # The reader already refuses a pre-first-full query. Project only the query
  # epoch to exercise the pure selector's own boundary with authenticated pool,
  # activation and custody fields; no fabricated balance or entitlement is added.
  let partial = %{first_full | epoch_number: epoch, addresses: addresses}
  let selected = select_reward_step(intent("fund", "10", 0)?, partial, U64.parse("6048011")?)?
  assert(selected == "waiting:first-full-epoch")
  Ok(true)
end

test("activation partial-week funding waits for the pool's first complete epoch") do
  case partial_week() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn ordering() -> Bool!String do
  assert(step("fund", "awaiting", "6652801")? == "open")
  assert(step("fund", "open", "6652801")? == "fund")
  assert(step("fund", "open", "7257601")? == "waiting:funding-week")
  assert(step("settle", "awaiting", "6652801")? == "waiting:week-end")
  assert(step("settle", "open", "6652801")? == "waiting:week-end")
  assert(step("settle", "awaiting", "7257601")? == "open")
  assert(step("settle", "open", "7257601")? == "begin")
  let future = mutated(mutated(mutated(snapshot("open")?, 1, 36, wide("12")?)?,
      6,
      36,
      wide("12")?)?,
    5,
    60,
    wide("12")?)?
  let state = decode_rewards_snapshot(pins([])?,
    key("11")?,
    1,
    program()?,
    asset()?,
    U64.parse("12")?,
    future)?
  assert(select_reward_step(intent("settle", "12", 0)?,
    state,
    U64.parse("7862401")?)? == "waiting:previous-epoch")
  let no_economics = decode(snapshot("awaiting-economics")?)?
  assert(select_reward_step(intent("settle", "11", 0)?,
    no_economics,
    U64.parse("7257601")?)? == "waiting:economics")
  Ok(true)
end

test("settlement waits for prior and current weeks while funding stays in its current epoch") do
  case ordering() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn staging() -> Bool!String do
  let collecting = decode(snapshot("collecting")?)?
  let operation = intent("settle", "11", 0)?
  assert(select_reward_step(operation, collecting, U64.parse("7261199")?)? == "finalize")
  assert(select_reward_step(operation, collecting, U64.parse("7261200")?)? == "cancel")
  assert(select_reward_step(operation, collecting, U64.parse("7261201")?)? == "cancel")
  assert(step("settle", "stale", "7257601")? == "cancel")
  let underfunded = mutated(mutated(mutated(snapshot("collecting")?, 1, 112, wide("2000")?)?,
      1,
      120,
      wide("2000")?)?,
    1,
    336,
    wide("2000")?)?
  assert(select_reward_step(operation,
    decode(underfunded)?,
    U64.parse("7257601")?)? == "waiting:floor-funding")
  let partial = mutated(mutated(mutated(snapshot("collecting")?, 1, 53, byte(0)?)?,
      1,
      96,
      zeros(16)?)?,
    1,
    224,
    zeros(128)?)?
  assert(select_reward_step(operation, decode(partial)?, U64.parse("7257601")?)? == "append")
  Ok(true)
end

test("staging cancels at revision or deadline boundaries and waits for an underfunded floor") do
  case staging() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn claims() -> Bool!String do
  let claim = intent("claim", "11", 0)?
  assert(step("claim", "open", "7257601")? == "waiting:settlement")
  assert(step("claim", "collecting", "7257601")? == "waiting:settlement")
  assert(step("claim", "finalized", "7257601")? == "claim")
  assert(step("claim", "claimed", "7257601")? == "complete")
  assert(step("claim", "stale-finalized", "7257601")? == "claim")
  let finalized = decode(snapshot("finalized")?)?
  let record = case finalized.record do
    None -> return Err("fixture epoch missing")
    Some(value) -> value
  end
  assert(Bytes.secure_equals(List.head(record.rows).witness, key("07")?))
  assert(Bytes.secure_equals(List.head(record.rows).payout, key("08")?))
  assert(Bytes.secure_equals(List.head(record.rows).bond, key("09")?))
  assert(select_reward_step(intent("claim", "11", 1)?,
    finalized,
    U64.parse("7257601")?) == Err("invalid_rewards_claim_row"))
  let zero = mutated(mutated(mutated(mutated(mutated(mutated(snapshot("finalized")?,
              0,
              196,
              wide("110")?)?,
            0,
            204,
            wide("0")?)?,
          1,
          96,
          zeros(16)?)?,
        1,
        144,
        wide("0")?)?,
      1,
      152,
      wide("110")?)?,
    1,
    320,
    zeros(16)?)?
  let zero = mutated(zero, 1, 344, wide("0")?)?
  assert(select_reward_step(claim, decode(zero)?, U64.parse("7257601")?)? == "complete")
  assert(select_reward_step(%{claim | program: asset()?},
    finalized,
    U64.parse("7257601")?) == Err("rewards_intent_snapshot_mismatch"))
  Ok(true)
end

test("claims use the canonical finalized row and complete paid or zero entitlements") do
  case claims() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
