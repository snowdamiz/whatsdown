from RewardRead import TokenRewardReadState, token_reward_rpc_sources
from Transparency.TokenWrite import TokenRewardWriteContext, token_reward_write_addresses
from Transparency.RewardsWrite import (
  RewardAppendWitness,
  RewardWriteContext,
  reward_witness_address
)
from Transparency.Merkle import WitnessKey
from Solana.Read import (
  Pubkey,
  OptionalAccountSlicesAtSlot,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  rpc_send
)

pub fn token_reward_next_witnesses(state :: TokenRewardReadState) -> List<Pubkey>!String do
  let record = case state.record do
    None -> return Err("token_rewards_epoch_missing")
    Some(value) -> value
  end
  let week = case state.attendance do
    None -> return Err("token_rewards_attendance_missing")
    Some(value) -> value
  end
  let start = List.length(record.rows)
  if record.status != 1
    || !week.sealed
    || record.expected != List.length(week.rows)
    || start >= record.expected do
    return Err("token_rewards_append_not_needed")
  end
  let stop = if start + 3 < record.expected do
    start + 3
  else
    record.expected
  end
  Ok(for index in start..stop do
    Pubkey { bytes: List.get(week.rows, index).witness }
  end)
end

fn zeroes(bytes :: Bytes, at :: Int, size :: Int) -> Bool!String do
  Ok(Bytes.to_hex(Bytes.slice(bytes, at, size)?) == String.repeat("00", size))
end

# These reads resolve immutable identity preimages only. They do not assert a
# cross-call bank snapshot or make custody, admission or attendance eligibility
# decisions. The rewards program fences revisions and checks all four row roles.
pub fn decode_token_reward_identities(context :: TokenRewardWriteContext,
  state :: TokenRewardReadState,
  keys :: List<Pubkey>,
  snapshot :: OptionalAccountSlicesAtSlot) -> List<RewardAppendWitness>!String do
  let a = token_reward_write_addresses(context, state.pool.next_epoch)?
  if state.pool.judge != context.judge.bytes
    || state.pool.log != a.base.log.bytes
    || state.pool.log_id != a.base.log_id
    || List.length(keys) > 64
    || List.length(snapshot.accounts) != List.length(keys)
    || U64.compare(snapshot.slot, state.context_slot) < 0 do
    return Err("token_rewards_identity_context_mismatch")
  end
  let base = RewardWriteContext {
    program: context.program,
    judge: context.judge,
    log_name: context.log_name,
    mint: context.usdc_mint
  }
  case state.record do
    Some(record) -> if record.pool != a.base.pool.bytes do
      return Err("token_rewards_identity_context_mismatch")
    end
    None -> nil
  end
  let result = for index in 0..List.length(keys) do
    let value = case List.get(snapshot.accounts, index) do
      None -> return Err("token_rewards_witness_missing")
      Some(value) -> value
    end
    let data = value.info.data
    if value.info.owner != context.judge
      || value.info.executable
      || value.info.lamports == U64.parse("0")?
      || value.space != U64.parse("320")?
      || Bytes.length(data) != 320
      || Bytes.to_hex(Bytes.slice(data, 0, 4)?) != "4d574901" do
      return Err("token_rewards_witness_mismatch")
    end
    let size = Bytes.get(data, 4)?
    if size < 1
      || size > 64
      || Bytes.get(data, 5)? > 4
      || Bytes.get(data, 6)? > 1
      || Bytes.get(data, 7)? != 0
      || !zeroes(data, 8 + size, 64 - size)?
      || zeroes(data, 72, 32)?
      || zeroes(data, 104, 32)?
      || zeroes(data, 136, 32)?
      || Bytes.slice(data, 200, 32)? != a.base.log_id
      || !zeroes(data, 272, 48)? do
      return Err("token_rewards_witness_identity_mismatch")
    end
    let key = WitnessKey {
      witness_id: Bytes.to_utf8(Bytes.slice(data, 8, size)?)?,
      public_key: Bytes.slice(data, 72, 32)?
    }
    let address = List.get(keys, index)
    if reward_witness_address(base, key)? != address do
      return Err("token_rewards_witness_identity_mismatch")
    end
    RewardAppendWitness { witness: address, key: key }
  end
  Ok(result)
end

fn read_identities_from(client :: Int,
  url :: String,
  context :: TokenRewardWriteContext,
  state :: TokenRewardReadState,
  keys :: List<Pubkey>) -> List<RewardAppendWitness>!String do
  let request = get_multiple_accounts_slice_request(3,
    keys,
    "finalized",
    0,
    320,
    Some(state.context_slot))?
  let response = rpc_send(client, url, request, 5000, 65536)?
  decode_token_reward_identities(context,
    state,
    keys,
    optional_accounts_slice_from_response(response)?)
end

fn agree(first :: List<RewardAppendWitness>!String,
  second :: List<RewardAppendWitness>!String) -> Option<List<RewardAppendWitness>> do
  case first do
    Err(_) -> None
    Ok(first) -> case second do
      Err(_) -> None
      Ok(second) -> if first == second do
        Some(first)
      else
        None
      end
    end
  end
end

pub fn read_token_reward_identities_quorum(client :: Int,
  urls :: List<String>,
  test_mode :: Bool,
  context :: TokenRewardWriteContext,
  state :: TokenRewardReadState,
  keys :: List<Pubkey>) -> List<RewardAppendWitness>!String do
  token_reward_rpc_sources(urls, test_mode)?
  let first = read_identities_from(client, List.get(urls, 0), context, state, keys)
  let second = read_identities_from(client, List.get(urls, 1), context, state, keys)
  case agree(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = read_identities_from(client, List.get(urls, 2), context, state, keys)
  case agree(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case agree(second, third) do
    Some(value) -> Ok(value)
    None -> Err("token_rewards_identity_rpc_no_agreement")
  end
end

pub fn decode_token_reward_append_identities(context :: TokenRewardWriteContext,
  state :: TokenRewardReadState,
  snapshot :: OptionalAccountSlicesAtSlot) -> List<RewardAppendWitness>!String do
  decode_token_reward_identities(context, state, token_reward_next_witnesses(state)?, snapshot)
end

pub fn read_token_reward_append_quorum(client :: Int,
  urls :: List<String>,
  test_mode :: Bool,
  context :: TokenRewardWriteContext,
  state :: TokenRewardReadState) -> List<RewardAppendWitness>!String do
  read_token_reward_identities_quorum(client,
    urls,
    test_mode,
    context,
    state,
    token_reward_next_witnesses(state)?)
end
