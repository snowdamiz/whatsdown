from Transparency.RewardsChain import RewardPoolAccount, decode_reward_pool
from Solana.Read import Pubkey
from Solana.Address import find_program_address

# Explicit asset units. These raw codecs must be used with authenticated owners,
# canonical addresses, pinned code/configuration and a coherent finalized context.
pub struct TokenReserveProfileAccount do
  config :: Bytes
  mint :: Bytes
  usdc_mint :: Bytes
  judge :: Bytes
  log :: Bytes
  binding :: Bytes
  rewards :: Bytes
  pool :: Bytes
  token_pool :: Bytes
  ready_at :: U64
  rewards_slot :: U64
  judge_slot :: U64
end

pub struct TokenRewardPoolAccount do
  pool :: Bytes
  binding :: Bytes
  token_program :: Bytes
  config :: Bytes
  mint :: Bytes
  oracle :: Bytes
  profile :: Bytes
  vault :: Bytes
  accounted_morse :: U64
  liabilities_morse :: U64
  activation_epoch :: U64
end

pub struct TokenReserveFundingReceipt do
  profile :: Bytes
  pool :: Bytes
  token_epoch :: Bytes
  epoch :: U64
  usd_gap :: U64
  twap :: U64
  amount_morse :: U64
  source_revision :: U64
  funded_at :: U64
  mint :: Bytes
  destination :: Bytes
  rows_hash :: Bytes
end

pub struct TokenRewardClaimRow do
  witness :: Bytes
  payout :: Bytes
  bond :: Bytes
  weight :: U128
  floor_usd :: U64
  amount_usd :: U64
  claimed_usd :: Bool
  gap_usd :: U64
  amount_morse :: U64
  claimed_morse :: Bool
end

pub struct TokenRewardEpochAccount do
  pool :: Bytes
  token_pool :: Bytes
  ledger :: Bytes
  epoch :: U64
  revenue_usd :: U64
  status :: Int
  expected :: Int
  attendance_hash :: Bytes
  posts :: U64
  weight :: U128
  floors_usd :: U64
  base_floor_usd :: U64
  available_usd :: U64
  subsidy_used_usd :: U64
  allocated_usd :: U64
  carry_usd :: U64
  claimed_usd :: U64
  snapshot_at :: U64
  eligibility_revision :: U64
  twap :: U64
  source_revision :: U64
  shortfall_usd :: U64
  allocated_morse :: U64
  claimed_morse :: U64
  claimed_amount_morse :: U64
  reserve_receipt :: Bytes
  rows :: List<TokenRewardClaimRow>
end

fn part(bytes :: Bytes, at :: Int, count :: Int) -> Bytes!String do
  Bytes.slice(bytes, at, count)
end

fn zeroes(bytes :: Bytes, at :: Int, count :: Int) -> Bool!String do
  Ok(Bytes.to_hex(part(bytes, at, count)?) == String.repeat("00", count))
end

fn header(bytes :: Bytes, count :: Int, magic :: String) -> Bool!String do
  Ok(Bytes.length(bytes) == count && Bytes.to_hex(part(bytes, 0, 4)?) == magic)
end

fn wide(bytes :: Bytes, at :: Int) -> U64!String do
  U64.parse(Bytes.read_uint_le(bytes, at, 8)?)
end

fn time(bytes :: Bytes, at :: Int) -> U64!String do
  let value = wide(bytes, at)?
  if U64.compare(value, U64.parse("9223372036854775807")?) > 0 do
    Err("invalid_token_rewards")
  else
    Ok(value)
  end
end

fn large(bytes :: Bytes, at :: Int) -> U128!String do
  U128.add(U128.parse(U64.to_string(wide(bytes, at)?))?,
    U128.multiply(U128.parse(U64.to_string(wide(bytes, at + 8)?))?,
      U128.parse("18446744073709551616")?)?)
end

fn big(value :: U64) -> U128!String do
  U128.parse(U64.to_string(value))
end

fn narrow(value :: U128) -> U64!String do
  U64.parse(U128.to_string(value))
end

fn sum(values :: List<U64>) -> U64!String do
  List.reduce(values, U64.parse("0"), fn(total, value) do U64.add(total?, value) end)
end

fn weight_sum(values :: List<U128>) -> U128!String do
  List.reduce(values, U128.parse("0"), fn(total, value) do U128.add(total?, value) end)
end

fn paid(bytes :: Bytes, at :: Int, index :: Int) -> Bool!String do
  let value = Bytes.get(bytes, at + index / 8)?
  Ok((value / List.get([1, 2, 4, 8, 16, 32, 64, 128], index % 8)) % 2 == 1)
end

pub fn decode_token_reserve_profile(bytes :: Bytes) -> TokenReserveProfileAccount!String do
  if !header(bytes, 320, "4d525302")? || !zeroes(bytes, 316, 4)? do
    return Err("invalid_token_rewards")
  end
  for at in [4, 36, 68, 100, 132, 164, 196, 228, 260] do
    if zeroes(bytes, at, 32)? do
      return Err("invalid_token_rewards")
    end
  end
  let value = TokenReserveProfileAccount {
    config: part(bytes, 4, 32)?,
    mint: part(bytes, 36, 32)?,
    usdc_mint: part(bytes, 68, 32)?,
    judge: part(bytes, 100, 32)?,
    log: part(bytes, 132, 32)?,
    binding: part(bytes, 164, 32)?,
    rewards: part(bytes, 196, 32)?,
    pool: part(bytes, 228, 32)?,
    token_pool: part(bytes, 260, 32)?,
    ready_at: time(bytes, 292)?,
    rewards_slot: wide(bytes, 300)?,
    judge_slot: wide(bytes, 308)?
  }
  if value.ready_at == U64.parse("0")?
    || value.mint == value.usdc_mint
    || value.judge == value.rewards do
    return Err("invalid_token_rewards")
  end
  Ok(value)
end

# The existing fields remain USD values; only the explicit version changes.
pub fn decode_token_reward_usdc_pool(bytes :: Bytes) -> RewardPoolAccount!String do
  if !header(bytes, 304, "4d525002")? do
    return Err("invalid_token_rewards")
  end
  decode_reward_pool(Bytes.concat(Bytes.concat(part(bytes, 0, 3)?, Bytes.from_hex("01")?)?,
    part(bytes, 4, 300)?)?)
end

pub fn decode_token_reward_pool(bytes :: Bytes) -> TokenRewardPoolAccount!String do
  if !header(bytes, 320, "4d525402")? || !zeroes(bytes, 284, 36)? do
    return Err("invalid_token_rewards")
  end
  for at in [4, 36, 68, 100, 132, 164, 196, 228] do
    if zeroes(bytes, at, 32)? do
      return Err("invalid_token_rewards")
    end
  end
  let value = TokenRewardPoolAccount {
    pool: part(bytes, 4, 32)?,
    binding: part(bytes, 36, 32)?,
    token_program: part(bytes, 68, 32)?,
    config: part(bytes, 100, 32)?,
    mint: part(bytes, 132, 32)?,
    oracle: part(bytes, 164, 32)?,
    profile: part(bytes, 196, 32)?,
    vault: part(bytes, 228, 32)?,
    accounted_morse: wide(bytes, 260)?,
    liabilities_morse: wide(bytes, 268)?,
    activation_epoch: wide(bytes, 276)?
  }
  if value.accounted_morse != value.liabilities_morse do
    return Err("invalid_token_rewards")
  end
  Ok(value)
end

pub fn decode_token_reserve_receipt(bytes :: Bytes) -> TokenReserveFundingReceipt!String do
  if !header(bytes, 256, "4d525202")? || !zeroes(bytes, 244, 12)? do
    return Err("invalid_token_rewards")
  end
  for at in [4, 36, 68, 148, 180, 212] do
    if zeroes(bytes, at, 32)? do
      return Err("invalid_token_rewards")
    end
  end
  let value = TokenReserveFundingReceipt {
    profile: part(bytes, 4, 32)?,
    pool: part(bytes, 36, 32)?,
    token_epoch: part(bytes, 68, 32)?,
    epoch: wide(bytes, 100)?,
    usd_gap: wide(bytes, 108)?,
    twap: wide(bytes, 116)?,
    amount_morse: wide(bytes, 124)?,
    source_revision: wide(bytes, 132)?,
    funded_at: time(bytes, 140)?,
    mint: part(bytes, 148, 32)?,
    destination: part(bytes, 180, 32)?,
    rows_hash: part(bytes, 212, 32)?
  }
  let zero = U64.parse("0")?
  if value.usd_gap == zero
    || value.twap == zero
    || value.amount_morse == zero
    || value.source_revision == zero
    || value.funded_at == zero
    || U64.compare(value.amount_morse, U64.parse("500000000000")?) > 0
    || U64.compare(U64.divide(value.funded_at, U64.parse("604800")?)?, value.epoch) <= 0 do
    return Err("invalid_token_rewards")
  end
  Ok(value)
end

fn claimed_total(rows :: List<TokenRewardClaimRow>) -> U64!String do
  sum(for row in rows do
    if row.claimed_morse do
      row.amount_morse
    else
      U64.parse("0")?
    end
  end)
end

fn check_final_rows(rows :: List<TokenRewardClaimRow>,
  weight :: U128,
  pot :: U64,
  floors :: U64,
  expected_gap :: U64,
  twap :: U64) -> Bool!String do
  let count = List.length(rows)
  let zero = U64.parse("0")?
  let nothing = U128.parse("0")?
  let checked = for index in 0..count do
    let row = List.get(rows, index)
    let before = sum(for earlier in List.take(rows, index) do
      earlier.floor_usd
    end)?
    let usd = if expected_gap != zero do
      U64.subtract(narrow(U128.multiply_divide(big(U64.add(before, row.floor_usd)?)?,
          big(pot)?,
          big(floors)?)?)?,
        narrow(U128.multiply_divide(big(before)?, big(pot)?, big(floors)?)?)?)?
    else if weight == nothing do
      zero
    else
      U64.add(row.floor_usd,
        narrow(U128.multiply_divide(big(U64.subtract(pot, floors)?)?, row.weight, weight)?)?)?
    end
    let gap = if expected_gap != zero do
      U64.subtract(row.floor_usd, usd)?
    else
      zero
    end
    let morse = if gap == zero do
      zero
    else
      if twap == zero do
        return Err("invalid_token_rewards")
      end
      let product = U128.multiply(big(gap)?, U128.parse("1000000")?)?
      let price = big(twap)?
      let quotient = U128.divide(product, price)?
      narrow(if U128.multiply(quotient, price)? == product do
        quotient
      else
        U128.add(quotient, U128.parse("1")?)?
      end)?
    end
    if row.amount_usd != usd || row.gap_usd != gap || row.amount_morse != morse do
      return Err("invalid_token_rewards")
    end
    true
  end
  if List.length(checked) != count do
    return Err("invalid_token_rewards")
  end
  Ok(true)
end

pub fn decode_token_reward_epoch(main :: Bytes, token :: Bytes) -> TokenRewardEpochAccount!String do
  if !header(main, 8416, "4d524502")?
    || !header(token, 1280, "4d544502")?
    || zeroes(main, 4, 32)?
    || zeroes(token, 4, 32)?
    || zeroes(token, 36, 32)?
    || !zeroes(main, 55, 1)?
    || !zeroes(main, 184, 40)?
    || !zeroes(token, 149, 3)?
    || !zeroes(token, 184, 72)? do
    return Err("invalid_token_rewards")
  end
  let status = Bytes.get(main, 52)?
  let count = Bytes.get(main, 53)?
  let expected = Bytes.get(main, 54)?
  let epoch = wide(main, 36)?
  if status > 2
    || count > 64
    || expected > 64
    || count > expected
    || Bytes.get(token, 148)? != status
    || wide(token, 68)? != epoch
    || !zeroes(main, 224 + count * 128, (64 - count) * 128)?
    || !zeroes(token, 256 + count * 16, (64 - count) * 16)? do
    return Err("invalid_token_rewards")
  end
  let zero = U64.parse("0")?
  let nothing = U128.parse("0")?
  let posts = wide(main, 88)?
  let denominator = U128.multiply(big(posts)?, U128.parse("3")?)?
  let base = wide(main, 120)?
  let rows = for index in 0..count do
    let at = 224 + index * 128
    let weight = large(main, at + 96)?
    let floor = wide(main, at + 112)?
    let amount = wide(main, at + 120)?
    let gap = wide(token, 256 + index * 16)?
    let morse = wide(token, 264 + index * 16)?
    let usd_claimed = paid(main, 160, index)?
    let morse_claimed = paid(token, 116, index)?
    let witness = part(main, at, 32)?
    if zeroes(main, at, 32)?
      || zeroes(main, at + 32, 32)?
      || zeroes(main, at + 64, 32)?
      || U128.compare(weight, denominator) > 0
      || U64.compare(floor, base) > 0
      || (weight == nothing && (floor != zero || amount != zero || gap != zero || morse != zero))
      || (usd_claimed && amount == zero)
      || (morse_claimed && morse == zero)
      || (status != 2
        && (amount != zero || gap != zero || morse != zero || usd_claimed || morse_claimed))
      || (index > 0 && Bytes.to_hex(part(main, at - 128, 32)?) >= Bytes.to_hex(witness)) do
      return Err("invalid_token_rewards")
    end
    let correct_floor = if denominator == nothing do
      zero
    else
      narrow(U128.multiply_divide(big(base)?, weight, denominator)?)?
    end
    if floor != correct_floor do
      return Err("invalid_token_rewards")
    end
    TokenRewardClaimRow {
      witness: witness,
      payout: part(main, at + 32, 32)?,
      bond: part(main, at + 64, 32)?,
      weight: weight,
      floor_usd: floor,
      amount_usd: amount,
      claimed_usd: usd_claimed,
      gap_usd: gap,
      amount_morse: morse,
      claimed_morse: morse_claimed
    }
  end
  let value = TokenRewardEpochAccount {
    pool: part(main, 4, 32)?,
    token_pool: part(token, 4, 32)?,
    ledger: part(token, 36, 32)?,
    epoch: epoch,
    revenue_usd: wide(main, 44)?,
    status: status,
    expected: expected,
    attendance_hash: part(main, 56, 32)?,
    posts: posts,
    weight: large(main, 96)?,
    floors_usd: wide(main, 112)?,
    base_floor_usd: base,
    available_usd: wide(main, 128)?,
    subsidy_used_usd: wide(main, 136)?,
    allocated_usd: wide(main, 144)?,
    carry_usd: wide(main, 152)?,
    claimed_usd: wide(main, 160)?,
    snapshot_at: time(main, 168)?,
    eligibility_revision: wide(main, 176)?,
    twap: wide(token, 76)?,
    source_revision: wide(token, 84)?,
    shortfall_usd: wide(token, 100)?,
    allocated_morse: wide(token, 108)?,
    claimed_morse: wide(token, 116)?,
    claimed_amount_morse: wide(token, 124)?,
    reserve_receipt: part(token, 152, 32)?,
    rows: rows
  }
  for index in count..64 do
    if paid(main, 160, index)? || paid(token, 116, index)? do
      return Err("invalid_token_rewards")
    end
  end
  if status == 0 do
    if !zeroes(main, 52, 8364)? || !zeroes(token, 76, 1204)? do
      return Err("invalid_token_rewards")
    end
  else
    if zeroes(main, 56, 32)?
      || value.snapshot_at == zero
      || time(token, 92)? != value.snapshot_at
      || value.source_revision == zero
      || U64.compare(U64.divide(value.snapshot_at, U64.parse("604800")?)?, epoch) <= 0
      || (posts == zero && expected != 0)
      || U64.compare(value.available_usd, value.revenue_usd) < 0
      || value.weight != weight_sum(for row in rows do
          row.weight
        end)?
      || value.floors_usd != sum(for row in rows do
          row.floor_usd
        end)? do
      return Err("invalid_token_rewards")
    end
    if status == 1 do
      if !zeroes(main, 136, 32)? || !zeroes(token, 100, 48)? || !zeroes(token, 152, 32)? do
        return Err("invalid_token_rewards")
      end
    else
      let pot = U64.add(value.available_usd, value.subsidy_used_usd)?
      let maximum_subsidy = if U64.compare(value.floors_usd, value.available_usd) > 0 do
        U64.subtract(value.floors_usd, value.available_usd)?
      else
        zero
      end
      if count != expected
        || wide(token, 140)? != value.floors_usd
        || wide(token, 132)? != value.allocated_usd
        || U64.compare(value.subsidy_used_usd, maximum_subsidy) > 0
        || value.allocated_usd != sum(for row in rows do
            row.amount_usd
          end)?
        || U64.add(value.allocated_usd, value.carry_usd)? != pot
        || value.shortfall_usd != sum(for row in rows do
            row.gap_usd
          end)?
        || value.allocated_morse != sum(for row in rows do
            row.amount_morse
          end)?
        || value.claimed_amount_morse != claimed_total(rows)?
        || U64.compare(value.allocated_morse, U64.parse("500000000000")?) > 0
        || ((value.allocated_morse == zero) != zeroes(token, 152, 32)?) do
        return Err("invalid_token_rewards")
      end
      let expected_gap = if U64.compare(value.floors_usd, pot) > 0 do
        U64.subtract(value.floors_usd, pot)?
      else
        zero
      end
      if value.shortfall_usd != expected_gap do
        return Err("invalid_token_rewards")
      end
      check_final_rows(rows, value.weight, pot, value.floors_usd, expected_gap, value.twap)?
      nil
    end
  end
  Ok(value)
end

pub fn token_reward_pool_address(rewards :: Pubkey) -> Pubkey!String do
  Ok(find_program_address(rewards, [Bytes.from_utf8("token-pool")])?.address)
end

pub fn token_reward_epoch_address(rewards :: Pubkey, epoch :: U64) -> Pubkey!String do
  Ok(find_program_address(rewards,
    [Bytes.from_utf8("token-epoch"), Bytes.write_uint_le(U64.to_string(epoch), 8)?])?.address)
end

pub fn token_reserve_profile_address(program :: Pubkey) -> Pubkey!String do
  Ok(find_program_address(program, [Bytes.from_utf8("reserve-config")])?.address)
end

pub fn token_reserve_receipt_address(program :: Pubkey, epoch :: U64) -> Pubkey!String do
  Ok(find_program_address(program,
    [Bytes.from_utf8("reserve-epoch"), Bytes.write_uint_le(U64.to_string(epoch), 8)?])?.address)
end

pub fn token_reward_rows_hash(main :: Bytes, token :: Bytes) -> Bytes!String do
  let epoch = decode_token_reward_epoch(main, token)?
  Ok(Crypto.sha256(Bytes.concat(part(main, 224, List.length(epoch.rows) * 128)?,
    part(token, 256, List.length(epoch.rows) * 16)?)?))
end
