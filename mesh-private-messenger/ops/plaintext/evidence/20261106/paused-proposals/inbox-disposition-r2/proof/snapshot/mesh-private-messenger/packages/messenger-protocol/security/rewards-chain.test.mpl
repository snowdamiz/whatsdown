from Solana.Read import Pubkey, pubkey, pubkey_string
from Transparency.RewardsChain import (
  RewardPoolAccount,
  RewardEpochAccount,
  RewardClaimRow,
  RewardMemberAccount,
  decode_reward_pool,
  decode_reward_member,
  decode_reward_epoch,
  reward_pool_address,
  reward_epoch_address,
  reward_member_address,
  reward_pool_vault
)

# Mandatory local-SBF fixture proof. Fixture configuration supplies the pins for
# this test only; raw codecs do not authenticate production RPC or owner data.
pub struct RewardFixtureSnapshot do
  pool :: RewardPoolAccount
  record :: RewardEpochAccount
  vault_balance :: U64
end

fn string(value :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(value, key)?)
end

fn total(values :: List<U64>, sum :: U64) -> U64!String do
  if List.length(values) == 0 do
    Ok(sum)
  else
    total(List.tail(values), U64.add(sum, List.head(values))?)
  end
end

fn account(snapshot :: Json, address :: Pubkey, owner :: Pubkey) -> Bytes!String do
  let accounts = Json.object_get(snapshot, "accounts")?
  let matches = for index in 0..Json.array_length(accounts)? when string(Json.array_get(accounts,
      index)?,
    "address")? == pubkey_string(address) do
    Json.array_get(accounts, index)?
  end
  if List.length(matches) != 1 do
    return Err("SBF reward fixture missing or duplicated account #{pubkey_string(address)}")
  end
  let value = List.head(matches)
  if string(value, "owner")? != pubkey_string(owner)
    || Json.as_bool(Json.object_get(value, "executable")?)? do
    return Err("SBF reward fixture owner/executable mismatch")
  end
  Bytes.from_hex(string(value, "data_hex")?)
end

fn replay_snapshot(value :: Json) -> RewardFixtureSnapshot!String do
  let program = pubkey(string(value, "program")?)?
  let judge = pubkey(string(value, "judge")?)?
  let address = reward_pool_address(program)?
  assert(pubkey_string(address) == string(value, "pool")?)
  let pool = decode_reward_pool(account(value, address, program)?)?
  assert(Bytes.secure_equals(pool.judge, judge.bytes))
  assert(Bytes.to_hex(pool.log_id) == string(value, "log_id")?)
  let expected = Json.object_get(value, "expected")?
  assert(U64.to_string(pool.accounted) == string(expected, "accounted")?)
  assert(U64.to_string(pool.subsidy) == string(expected, "subsidy")?)
  assert(U64.to_string(pool.carry) == string(expected, "carry")?)
  assert(U64.to_string(pool.liabilities) == string(expected, "liabilities")?)
  assert(U64.to_string(pool.next_epoch) == string(expected, "next_epoch")?)
  assert(pool.active_epoch == None)
  let epoch = U64.parse(string(value, "epoch")?)?
  let ledger = reward_epoch_address(program, epoch)?
  assert(pubkey_string(ledger) == string(value, "ledger")?)
  let record = decode_reward_epoch(account(value, ledger, program)?)?
  assert(record.status == 2 && record.epoch == epoch)
  assert(Bytes.secure_equals(record.pool, address.bytes))
  let rows = record.rows
  assert(List.length(rows) == record.expected && record.expected > 0)
  let zero = U64.parse("0")?
  let payable = List.filter(rows, fn(row) -> row.amount != zero end)
  assert(List.length(payable) > 0)
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let vault = reward_pool_vault(program, Pubkey { bytes: pool.mint })?
  let vault_data = account(value, vault, token)?
  assert(Bytes.length(vault_data) == 165)
  assert(Bytes.secure_equals(Bytes.slice(vault_data, 0, 32)?, pool.mint))
  assert(Bytes.secure_equals(Bytes.slice(vault_data, 32, 32)?, address.bytes))
  let vault_balance = case Bytes.read_u64_le(vault_data, 64) do
    Ok(balance) -> balance
    Err(_) -> return Err("invalid SBF reward vault balance")
  end
  assert(U64.compare(vault_balance, pool.accounted) >= 0)
  let accounts = Json.object_get(value, "accounts")?
  let members = for index in 0..Json.array_length(accounts)? when String.starts_with(string(Json.array_get(accounts,
        index)?,
      "data_hex")?,
    "4d524d01") do
    let member = Json.array_get(accounts, index)?
    let decoded = decode_reward_member(Bytes.from_hex(string(member, "data_hex")?)?)?
    let derived = reward_member_address(program, Pubkey { bytes: decoded.witness })?
    assert(pubkey_string(derived) == string(member, "address")?)
    account(value, derived, program)?
    decoded
  end
  assert(List.length(members) > 0)
  # Current membership can change after settlement; fixed claims bind the
  # immutable witness identity without reapplying today's admission status.
  for row in payable do
    assert(List.length(List.filter(members,
      fn(member) -> Bytes.secure_equals(member.witness, row.witness) end)) == 1)
  end
  Ok(RewardFixtureSnapshot { pool: pool, record: record, vault_balance: vault_balance })
end

fn replay() -> Bool!String do
  let path = Env.get("MORSE_REWARDS_FIXTURES_PATH", "")
  if path == "" do
    return Err("MORSE_REWARDS_FIXTURES_PATH is required for the real-SBF reward proof")
  end
  let root = Json.parse(File.read(path)?)?
  assert(Json.as_int(Json.object_get(root, "version")?)? == 1)
  let snapshots = Json.object_get(root, "snapshots")?
  assert(Json.array_length(snapshots)? == 2)
  let settled_source = Json.array_get(snapshots, 0)?
  let claimed_source = Json.array_get(snapshots, 1)?
  assert(string(settled_source, "name")? == "settled")
  assert(string(claimed_source, "name")? == "claimed")
  let settled = replay_snapshot(settled_source)?
  let paid = replay_snapshot(claimed_source)?
  assert(settled.record.claimed_mask == U64.parse("0")?)
  assert(paid.record.claimed_mask != U64.parse("0")?)
  let paid_rows = List.filter(paid.record.rows, fn(row) -> row.claimed end)
  assert(List.length(paid_rows) > 0)
  assert(List.length(settled.record.rows) == List.length(paid.record.rows))
  for index in 0..List.length(settled.record.rows) do
    let before = List.get(settled.record.rows, index)
    let paid_row = List.get(paid.record.rows, index)
    assert(Bytes.secure_equals(before.witness, paid_row.witness)
      && Bytes.secure_equals(before.payout, paid_row.payout)
      && Bytes.secure_equals(before.bond, paid_row.bond)
      && before.weight == paid_row.weight
      && before.floor == paid_row.floor
      && before.amount == paid_row.amount)
  end
  let amount = total(for row in paid_rows do
      row.amount
    end,
    U64.parse("0")?)?
  assert(U64.subtract(settled.pool.accounted, paid.pool.accounted)? == amount)
  assert(U64.subtract(settled.pool.liabilities, paid.pool.liabilities)? == amount)
  assert(U64.subtract(settled.vault_balance, paid.vault_balance)? == amount)
  assert(settled.pool.subsidy == paid.pool.subsidy && settled.pool.carry == paid.pool.carry)
  println("matched canonical reward PDAs, raw account layouts, fixed allocations and claim accounting in 2 real-SBF snapshots")
  Ok(true)
end

test("public Mesh reward codecs replay real SBF settlement and claim accounts") do
  case replay() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
