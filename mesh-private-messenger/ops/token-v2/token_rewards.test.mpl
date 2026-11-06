from Transparency.TokenRewards import (
  decode_token_reserve_profile,
  decode_token_reward_usdc_pool,
  decode_token_reward_pool,
  decode_token_reserve_receipt,
  decode_token_reward_epoch,
  token_reward_pool_address,
  token_reward_epoch_address,
  token_reserve_profile_address,
  token_reserve_receipt_address,
  token_reward_rows_hash
)
from Solana.Read import pubkey
from Transparency.RewardsChain import decode_reward_epoch, decode_reward_pool

fn field(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn raw(accounts :: Json, name :: String) -> Bytes!String do
  Bytes.from_hex(field(Json.object_get(accounts, name)?, "data_hex")?)
end

fn address(accounts :: Json, name :: String) -> Bytes!String do
  Ok(pubkey(field(Json.object_get(accounts, name)?, "address")?)?.bytes)
end

fn changed(bytes :: Bytes, at :: Int, value :: Bytes) -> Bytes!String do
  Bytes.concat(Bytes.concat(Bytes.slice(bytes, 0, at)?, value)?,
    Bytes.slice(bytes, at + Bytes.length(value), Bytes.length(bytes) - at - Bytes.length(value))?)
end

fn actual_rewards() -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_CUSTODY_FIXTURES_PATH", ""))?)?
  let snapshots = Json.object_get(root, "snapshots")?
  let checked = for index in 0..Json.array_length(snapshots)? do
    let snapshot = Json.array_get(snapshots, index)?
    let name = field(snapshot, "name")?
    if name == "token-rewards-finalized" || name == "token-rewards-claimed" do
      let accounts = Json.object_get(snapshot, "accounts")?
      let token = pubkey(field(snapshot, "token_program")?)?
      let rewards = pubkey(field(snapshot, "rewards_program")?)?
      let profile_raw = raw(accounts, "reserve_profile")?
      let profile = decode_token_reserve_profile(profile_raw)?
      let pool_raw = raw(accounts, "token_pool")?
      let pool = decode_token_reward_pool(pool_raw)?
      let receipt_raw = raw(accounts, "reserve_receipt")?
      let receipt = decode_token_reserve_receipt(receipt_raw)?
      let main = raw(accounts, "epoch")?
      let companion = raw(accounts, "token_epoch")?
      let epoch = decode_token_reward_epoch(main, companion)?
      let dollars_raw = raw(accounts, "pool")?
      let dollars = decode_token_reward_usdc_pool(dollars_raw)?
      assert(Result.is_err(decode_reward_epoch(main)))
      assert(Result.is_err(decode_reward_pool(dollars_raw)))
      assert(dollars.mint == address(accounts, "usdc")?
        && dollars.judge == profile.judge
        && dollars.log == profile.log
        && dollars.next_epoch == U64.add(epoch.epoch, U64.parse("1")?)?)
      assert(epoch.epoch == U64.parse(field(snapshot, "epoch")?)? && epoch.status == 2)
      assert(epoch.expected == 64 && List.length(epoch.rows) == 64)
      assert(epoch.shortfall_usd == U64.parse("50000000")?
        && epoch.allocated_morse == U64.parse("500000000000")?)
      assert(epoch.twap == U64.parse("100")? && epoch.source_revision == U64.parse("1")?)
      assert(pool.pool == address(accounts, "pool")?
        && pool.binding == address(accounts, "binding")?
        && pool.token_program == token.bytes)
      assert(profile.pool == pool.pool
        && profile.token_pool == address(accounts, "token_pool")?
        && profile.rewards == rewards.bytes)
      assert(profile.judge == pubkey(field(snapshot, "program")?)?.bytes
        && profile.mint == pool.mint
        && profile.usdc_mint == address(accounts, "usdc")?)
      assert(pool.profile == address(accounts, "reserve_profile")?
        && pool.oracle == address(accounts, "oracle")?
        && pool.vault == address(accounts, "pool_morse_vault")?)
      assert(epoch.token_pool == profile.token_pool && epoch.ledger == address(accounts, "epoch")?)
      assert(token_reward_pool_address(rewards)?.bytes == epoch.token_pool)
      assert(token_reward_epoch_address(rewards, epoch.epoch)?.bytes == address(accounts,
          "token_epoch")?)
      assert(token_reserve_profile_address(token)?.bytes == pool.profile)
      assert(token_reserve_receipt_address(token, epoch.epoch)?.bytes == epoch.reserve_receipt)
      assert(epoch.reserve_receipt == address(accounts, "reserve_receipt")?)
      assert(receipt.profile == pool.profile
        && receipt.pool == pool.pool
        && receipt.token_epoch == address(accounts, "token_epoch")?)
      assert(receipt.epoch == epoch.epoch
        && receipt.usd_gap == epoch.shortfall_usd
        && receipt.twap == epoch.twap
        && receipt.amount_morse == epoch.allocated_morse)
      assert(receipt.destination == pool.vault
        && receipt.mint == pool.mint
        && receipt.source_revision == epoch.source_revision)
      assert(receipt.rows_hash == token_reward_rows_hash(main, companion)?)
      assert(List.get(epoch.rows, 63).amount_morse != U64.parse("0")?)
      if name == "token-rewards-finalized" do
        assert(pool.liabilities_morse == epoch.allocated_morse
          && epoch.claimed_amount_morse == U64.parse("0")?)
        assert(dollars.liabilities == epoch.allocated_usd)
      else
        assert(pool.liabilities_morse == U64.parse("0")?
          && epoch.claimed_amount_morse == epoch.allocated_morse)
        assert(dollars.liabilities == U64.parse("0")?)
        assert(List.get(epoch.rows, 63).claimed_morse)
      end
      assert(Result.is_err(decode_token_reserve_profile(changed(profile_raw,
        316,
        Bytes.from_hex("01")?)?)))
      assert(Result.is_err(decode_token_reward_pool(changed(pool_raw,
        260,
        Bytes.write_uint_le("1", 8)?)?)))
      assert(Result.is_err(decode_token_reserve_receipt(changed(receipt_raw,
        124,
        Bytes.write_uint_le("500000000001", 8)?)?)))
      assert(Result.is_err(decode_token_reserve_receipt(changed(receipt_raw,
        244,
        Bytes.from_hex("01")?)?)))
      assert(Result.is_err(decode_token_reward_epoch(changed(main, 54, Bytes.from_hex("3f")?)?,
        companion)))
      assert(Result.is_err(decode_token_reward_epoch(main,
        changed(companion, 149, Bytes.from_hex("01")?)?)))
      assert(Result.is_err(decode_token_reward_epoch(main,
        changed(companion, 76, Bytes.write_uint_le("101", 8)?)?)))
      assert(Result.is_err(decode_token_reward_epoch(main,
        changed(companion, 92, Bytes.from_hex("ffffffffffffffff")?)?)))
      assert(Result.is_err(decode_token_reward_epoch(changed(main, 3, Bytes.from_hex("01")?)?,
        companion)))
      let bit63 = Bytes.get(companion, 123)?
      let flipped = if bit63 >= 128 do
        bit63 - 128
      else
        bit63 + 128
      end
      assert(Result.is_err(decode_token_reward_epoch(main,
        changed(companion, 123, Bytes.write_uint_le(Int.to_string(flipped), 1)?)?)))
      1
    else
      0
    end
  end
  assert(List.reduce(checked, 0, fn(total, value) do total + value end) == 2)
  Ok(true)
end

test("token reward reserve snapshots conserve exact asset units, allocations and all64 claim bits") do
  assert(actual_rewards() == Ok(true))
end
