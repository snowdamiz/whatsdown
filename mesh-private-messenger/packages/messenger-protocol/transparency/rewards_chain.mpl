from Solana.Read import Pubkey, pubkey
from Solana.Address import ProgramDerivedAddress, find_program_address

# Raw codecs and address derivation only. They do not authenticate RPC owners,
# executable programs, canonical account addresses, finalized context or caller
# pins. A syntactically valid program address confers no trust or reward rights.
pub struct RewardAddresses do
  pool :: Pubkey
  member :: Pubkey
  epoch :: Pubkey
  vault :: Pubkey
end

pub struct RewardPoolAccount do
  governance :: Bytes
  judge :: Bytes
  log :: Bytes
  log_id :: Bytes
  mint :: Bytes
  network_started :: U64
  first_full_epoch :: U64
  next_epoch :: U64
  subsidy :: U64
  carry :: U64
  liabilities :: U64
  accounted :: U64
  active_epoch :: Option<U64>
  pending_governance :: Bytes
  governance_ready :: U64
  morse_witness :: Bytes
end

pub struct RewardMemberAccount do
  witness :: Bytes
  status :: Int
  pending :: Int
  ready_at :: U64
  effective_at :: U64
end

pub struct RewardClaimRow do
  witness :: Bytes
  payout :: Bytes
  bond :: Bytes
  weight :: U128
  floor :: U64
  amount :: U64
  claimed :: Bool
end

pub struct RewardEpochAccount do
  pool :: Bytes
  epoch :: U64
  revenue :: U64
  status :: Int
  expected :: Int
  attendance_hash :: Bytes
  posts :: U64
  total_weight :: U128
  floor_required :: U64
  base_floor :: U64
  available :: U64
  subsidy_used :: U64
  allocated :: U64
  carry :: U64
  claimed_mask :: U64
  started_at :: U64
  eligibility_revision :: U64
  rows :: List<RewardClaimRow>
end

pub struct RewardFundingReceipt do
  pool :: Bytes
  funder :: Bytes
  operation_id :: Bytes
  epoch :: U64
  kind :: Int
  amount :: U64
  source :: Bytes
  mint :: Bytes
  funded_at :: U64
end

pub fn reward_funding_address(program :: Pubkey,
  funder :: Pubkey,
  operation_id :: Bytes) -> Pubkey!String do
  if !key(funder.bytes)? || !key(operation_id)? do
    return Err("invalid_rewards_chain")
  end
  Ok(find_program_address(program,
    [Bytes.from_utf8("funding"), funder.bytes, operation_id])?.address)
end

pub fn decode_reward_funding_receipt(bytes :: Bytes) -> RewardFundingReceipt!String do
  if Bytes.length(bytes) != 192
    || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d524601"
    || !zeroes(bytes, 109, 3)? do
    return Err("invalid_rewards_chain")
  end
  for offset in [4, 36, 68, 120, 152] do
    if !key(Bytes.slice(bytes, offset, 32)?)? do
      return Err("invalid_rewards_chain")
    end
  end
  let value = RewardFundingReceipt {
    pool: Bytes.slice(bytes, 4, 32)?,
    funder: Bytes.slice(bytes, 36, 32)?,
    operation_id: Bytes.slice(bytes, 68, 32)?,
    epoch: wide(bytes, 100)?,
    kind: Bytes.get(bytes, 108)?,
    amount: wide(bytes, 112)?,
    source: Bytes.slice(bytes, 120, 32)?,
    mint: Bytes.slice(bytes, 152, 32)?,
    funded_at: time(bytes, 184)?
  }
  let zero = U64.parse("0")?
  if value.kind > 1
    || value.amount == zero
    || value.funded_at == zero
    || value.epoch != U64.divide(value.funded_at, U64.parse("604800")?)? do
    return Err("invalid_rewards_chain")
  end
  Ok(value)
end

pub fn reward_pool_address(program :: Pubkey) -> Pubkey!String do
  Ok(find_program_address(program, [Bytes.from_utf8("pool")])?.address)
end

pub fn reward_member_address(program :: Pubkey, witness :: Pubkey) -> Pubkey!String do
  if !key(witness.bytes)? do
    return Err("invalid_rewards_chain")
  end
  Ok(find_program_address(program, [Bytes.from_utf8("member"), witness.bytes])?.address)
end

pub fn reward_epoch_address(program :: Pubkey, epoch :: U64) -> Pubkey!String do
  let encoded = Bytes.write_uint_le(U64.to_string(epoch), 8)?
  Ok(find_program_address(program, [Bytes.from_utf8("epoch"), encoded])?.address)
end

pub fn reward_pool_vault(program :: Pubkey, mint :: Pubkey) -> Pubkey!String do
  if !key(mint.bytes)? do
    return Err("invalid_rewards_chain")
  end
  let pool = reward_pool_address(program)?
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let ata = pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?
  Ok(find_program_address(ata, [pool.bytes, token.bytes, mint.bytes])?.address)
end

pub fn reward_addresses(program :: Pubkey,
  witness :: Pubkey,
  epoch :: U64,
  mint :: Pubkey) -> RewardAddresses!String do
  Ok(RewardAddresses {
    pool: reward_pool_address(program)?,
    member: reward_member_address(program, witness)?,
    epoch: reward_epoch_address(program, epoch)?,
    vault: reward_pool_vault(program, mint)?
  })
end

fn zeroes(bytes :: Bytes, offset :: Int, length :: Int) -> Bool!String do
  Ok(Bytes.to_hex(Bytes.slice(bytes, offset, length)?) == String.repeat("00", length))
end

fn key(bytes :: Bytes) -> Bool!String do
  Ok(Bytes.length(bytes) == 32 && !zeroes(bytes, 0, 32)?)
end

fn wide(bytes :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_le(bytes, offset) do
    Ok(value)
    Err(_) -> Err("invalid_rewards_chain")
  end
end

fn wide128(bytes :: Bytes, offset :: Int) -> U128!String do
  let low = U128.parse(U64.to_string(wide(bytes, offset)?))?
  let high = U128.parse(U64.to_string(wide(bytes, offset + 8)?))?
  U128.add(U128.multiply(high, U128.parse("18446744073709551616")?)?, low)
end

fn time(bytes :: Bytes, offset :: Int) -> U64!String do
  let value = wide(bytes, offset)?
  if U64.compare(value, U64.parse("9223372036854775807")?) > 0 do
    Err("invalid_rewards_chain")
  else
    Ok(value)
  end
end

fn claimed(bytes :: Bytes, index :: Int) -> Bool!String do
  let byte = Bytes.get(bytes, 160 + index / 8)?
  let divisor = List.get([1, 2, 4, 8, 16, 32, 64, 128], index % 8)
  Ok((byte / divisor) % 2 == 1)
end

fn total(values :: List<U64>, sum :: U64) -> U64!String do
  if List.length(values) == 0 do
    Ok(sum)
  else
    total(List.tail(values), U64.add(sum, List.head(values))?)
  end
end

fn total_weights(values :: List<U128>, sum :: U128) -> U128!String do
  if List.length(values) == 0 do
    Ok(sum)
  else
    total_weights(List.tail(values), U128.add(sum, List.head(values))?)
  end
end

pub fn decode_reward_pool(bytes :: Bytes) -> RewardPoolAccount!String do
  if Bytes.length(bytes) != 304
    || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d525001"
    || !zeroes(bytes, 300, 4)? do
    return Err("invalid_rewards_chain")
  end
  for offset in [4, 36, 68, 100, 132, 268] do
    if !key(Bytes.slice(bytes, offset, 32)?)? do
      return Err("invalid_rewards_chain")
    end
  end
  let zero = U64.parse("0")?
  let started = time(bytes, 164)?
  let first = wide(bytes, 172)?
  let next = wide(bytes, 180)?
  let subsidy = wide(bytes, 188)?
  let carry = wide(bytes, 196)?
  let liabilities = wide(bytes, 204)?
  let accounted = wide(bytes, 212)?
  let active = wide(bytes, 220)?
  let ready = time(bytes, 260)?
  if started == zero
    || first != U64.add(U64.divide(started, U64.parse("604800")?)?, U64.parse("1")?)?
    || U64.compare(next, first) < 0
    || (active != zero && active != U64.add(next, U64.parse("1")?)?)
    || U64.compare(U64.add(U64.add(subsidy, carry)?, liabilities)?, accounted) > 0
    || ((ready == zero) != zeroes(bytes, 228, 32)?)
    || (ready != zero && U64.compare(ready, started) < 0) do
    return Err("invalid_rewards_chain")
  end
  let active_epoch = if active == zero do
    None
  else
    Some(U64.subtract(active, U64.parse("1")?)?)
  end
  Ok(RewardPoolAccount {
    governance: Bytes.slice(bytes, 4, 32)?,
    judge: Bytes.slice(bytes, 36, 32)?,
    log: Bytes.slice(bytes, 68, 32)?,
    log_id: Bytes.slice(bytes, 100, 32)?,
    mint: Bytes.slice(bytes, 132, 32)?,
    network_started: started,
    first_full_epoch: first,
    next_epoch: next,
    subsidy: subsidy,
    carry: carry,
    liabilities: liabilities,
    accounted: accounted,
    active_epoch: active_epoch,
    pending_governance: Bytes.slice(bytes, 228, 32)?,
    governance_ready: ready,
    morse_witness: Bytes.slice(bytes, 268, 32)?
  })
end

pub fn decode_reward_member(bytes :: Bytes) -> RewardMemberAccount!String do
  if Bytes.length(bytes) != 64
    || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d524d01"
    || !key(Bytes.slice(bytes, 4, 32)?)?
    || !zeroes(bytes, 38, 2)?
    || !zeroes(bytes, 56, 8)? do
    return Err("invalid_rewards_chain")
  end
  let status = Bytes.get(bytes, 36)?
  let pending = Bytes.get(bytes, 37)?
  let ready = time(bytes, 40)?
  let effective = time(bytes, 48)?
  let zero = U64.parse("0")?
  if status > 2
    || pending > 2
    || (ready == zero && pending != 0)
    || (status != 0 && effective == zero)
    || (ready != zero && U64.compare(ready, effective) < 0)
    || (status == 2 && ready != zero && pending != 2) do
    return Err("invalid_rewards_chain")
  end
  Ok(RewardMemberAccount {
    witness: Bytes.slice(bytes, 4, 32)?,
    status: status,
    pending: pending,
    ready_at: ready,
    effective_at: effective
  })
end

pub fn decode_reward_epoch(bytes :: Bytes) -> RewardEpochAccount!String do
  if Bytes.length(bytes) != 8416
    || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d524501"
    || !key(Bytes.slice(bytes, 4, 32)?)?
    || !zeroes(bytes, 55, 1)?
    || !zeroes(bytes, 184, 40)? do
    return Err("invalid_rewards_chain")
  end
  let status = Bytes.get(bytes, 52)?
  let count = Bytes.get(bytes, 53)?
  let expected = Bytes.get(bytes, 54)?
  if status > 2
    || count > 64
    || expected > 64
    || count > expected
    || !zeroes(bytes, 224 + count * 128, (64 - count) * 128)? do
    return Err("invalid_rewards_chain")
  end
  let zero = U64.parse("0")?
  let wide_zero = U128.parse("0")?
  let posts = wide(bytes, 88)?
  let base = wide(bytes, 120)?
  let denominator = U128.multiply(U128.parse(U64.to_string(posts))?, U128.parse("3")?)?
  let rows = for index in 0..count do
    let offset = 224 + index * 128
    let witness = Bytes.slice(bytes, offset, 32)?
    let payout = Bytes.slice(bytes, offset + 32, 32)?
    let bond = Bytes.slice(bytes, offset + 64, 32)?
    let weight = wide128(bytes, offset + 96)?
    let floor = wide(bytes, offset + 112)?
    let amount = wide(bytes, offset + 120)?
    let paid = claimed(bytes, index)?
    if !key(witness)?
      || !key(payout)?
      || !key(bond)?
      || U128.compare(weight, denominator) > 0
      || U64.compare(floor, base) > 0
      || (weight == wide_zero && (floor != zero || amount != zero))
      || (status != 2 && amount != zero)
      || (status == 2 && U64.compare(amount, floor) < 0)
      || (paid && amount == zero)
      || (index > 0
        && Bytes.to_hex(Bytes.slice(bytes, offset - 128, 32)?) >= Bytes.to_hex(witness)) do
      return Err("invalid_rewards_chain")
    end
    RewardClaimRow {
      witness: witness,
      payout: payout,
      bond: bond,
      weight: weight,
      floor: floor,
      amount: amount,
      claimed: paid
    }
  end
  let value = RewardEpochAccount {
    pool: Bytes.slice(bytes, 4, 32)?,
    epoch: wide(bytes, 36)?,
    revenue: wide(bytes, 44)?,
    status: status,
    expected: expected,
    attendance_hash: Bytes.slice(bytes, 56, 32)?,
    posts: posts,
    total_weight: wide128(bytes, 96)?,
    floor_required: wide(bytes, 112)?,
    base_floor: base,
    available: wide(bytes, 128)?,
    subsidy_used: wide(bytes, 136)?,
    allocated: wide(bytes, 144)?,
    carry: wide(bytes, 152)?,
    claimed_mask: wide(bytes, 160)?,
    started_at: time(bytes, 168)?,
    eligibility_revision: wide(bytes, 176)?,
    rows: rows
  }
  for index in 0..64 do
    if claimed(bytes, index)? && (status != 2 || index >= count) do
      return Err("invalid_rewards_chain")
    end
  end
  if status == 0 do
    if !zeroes(bytes, 52, 8364)? do
      return Err("invalid_rewards_chain")
    end
  else
    if zeroes(bytes, 56, 32)?
      || value.started_at == zero
      || U64.compare(U64.divide(value.started_at, U64.parse("604800")?)?, value.epoch) <= 0
      || (posts == zero && expected != 0)
      || U64.compare(value.available, value.revenue) < 0
      || value.total_weight != total_weights(for row in rows do
            row.weight
          end,
          wide_zero)?
      || value.floor_required != total(for row in rows do
            row.floor
          end,
          zero)? do
      return Err("invalid_rewards_chain")
    end
    if status == 1 do
      if value.subsidy_used != zero || value.allocated != zero || value.carry != zero do
        return Err("invalid_rewards_chain")
      end
    else
      let subsidy = if U64.compare(value.floor_required, value.available) > 0 do
        U64.subtract(value.floor_required, value.available)?
      else
        zero
      end
      if count != expected
        || value.subsidy_used != subsidy
        || value.allocated != total(for row in rows do
              row.amount
            end,
            zero)?
        || U64.add(value.allocated, value.carry)? != U64.add(value.available,
            value.subsidy_used)? do
        return Err("invalid_rewards_chain")
      end
    end
  end
  Ok(value)
end
