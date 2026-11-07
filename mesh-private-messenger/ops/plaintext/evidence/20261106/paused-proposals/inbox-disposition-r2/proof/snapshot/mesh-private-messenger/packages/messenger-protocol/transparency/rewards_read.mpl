from Transparency.RpcTransport import RpcEndpoint, RpcTransport, rpc_urls, rpc_fatal_error
from Solana.Read import (
  Pubkey,
  AccountSlice,
  OptionalAccountSlicesAtSlot,
  Mint,
  TokenAccount,
  pubkey,
  pubkey_string,
  pubkey_equal,
  mint,
  token_account,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response
)
from Solana.Address import ProgramDerivedAddress, find_program_address
from Transparency.AnchorChain import (
  AnchorPins,
  AnchorAddresses,
  anchor_addresses,
  sample_anchor_sources
)
from Transparency.AnchorRpc import read_anchor_rpc_response
from Transparency.AnchorLog import AnchorLog, decode_anchor_log
from Transparency.AnchorBond import AnchorEconomics, decode_anchor_economics
from Transparency.Attendance import (
  AttendanceClock,
  AttendanceEpoch,
  AttendanceRow,
  AttendanceAddresses,
  attendance_addresses,
  decode_attendance_clock,
  decode_attendance_epoch
)
from Transparency.RewardsChain import (
  RewardPoolAccount,
  RewardEpochAccount,
  RewardClaimRow,
  RewardFundingReceipt,
  reward_pool_address,
  reward_epoch_address,
  reward_pool_vault,
  reward_funding_address,
  decode_reward_pool,
  decode_reward_epoch,
  decode_reward_funding_receipt
)

pub struct RewardsReadAddresses do
  program :: Pubkey
  pool :: Pubkey
  epoch :: Pubkey
  vault :: Pubkey
  mint :: Pubkey
  log :: Pubkey
  clock :: Pubkey
  attendance :: Pubkey
  economics :: Pubkey
end

pub struct RewardsState do
  status :: String
  awaiting :: String
  program :: Pubkey
  mint :: Pubkey
  judge :: Pubkey
  log_name :: String
  epoch_number :: U64
  context_slot :: U64
  addresses :: RewardsReadAddresses
  pool :: Option<RewardPoolAccount>
  record :: Option<RewardEpochAccount>
  vault_balance :: Option<U64>
  vault_surplus :: Option<U64>
  mint_state :: Mint
  log :: AnchorLog
  clock :: Option<AttendanceClock>
  attendance :: Option<AttendanceEpoch>
  economics :: Option<AnchorEconomics>
  revision_matches :: Option<Bool>
  unclaimed_amount :: Option<U64>
  snapshot :: OptionalAccountSlicesAtSlot
end

pub struct RewardFundingState do
  status :: String
  receipt_address :: Pubkey
  context_slot :: U64
  rewards :: RewardsState
  receipt :: Option<RewardFundingReceipt>
  snapshot :: OptionalAccountSlicesAtSlot
end

struct RewardsObservation do
  state :: RewardsState
end

fn zero_key(value :: Pubkey) -> Bool do
  Bytes.length(value.bytes) != 32 || Bytes.to_hex(value.bytes) == String.repeat("00", 32)
end

pub fn rewards_read_addresses(pins :: AnchorPins,
  program :: Pubkey,
  mint :: Pubkey,
  epoch :: U64) -> RewardsReadAddresses!String do
  let anchor = anchor_addresses(pins.program, pins.log_name)?
  if zero_key(program)
    || zero_key(mint)
    || pubkey_equal(program, pins.program)
    || !Bytes.secure_equals(anchor.log_id, pins.log_id)
    || !pubkey_equal(anchor.ring, pins.ring) do
    return Err("invalid_rewards_pins")
  end
  let attendance = attendance_addresses(pins.program, pins.log_id, epoch)?
  Ok(RewardsReadAddresses {
    program: program,
    pool: reward_pool_address(program)?,
    epoch: reward_epoch_address(program, epoch)?,
    vault: reward_pool_vault(program, mint)?,
    mint: mint,
    log: anchor.log,
    clock: attendance.clock,
    attendance: attendance.epoch,
    economics: find_program_address(pins.program,
      [Bytes.from_utf8("economics"), pins.log_id])?.address
  })
end

pub fn rewards_read_keys(addresses :: RewardsReadAddresses) -> List<Pubkey> do
  [
    addresses.pool,
    addresses.epoch,
    addresses.vault,
    addresses.mint,
    addresses.log,
    addresses.clock,
    addresses.attendance,
    addresses.economics,
    addresses.program
  ]
end

fn absent(value :: Option<AccountSlice>) -> Bool do
  case value do
    None -> true
    Some(value) -> !value.info.executable
      && U64.to_string(value.space) == "0"
      && Bytes.length(value.info.data) == 0
      && Bytes.to_hex(value.info.owner.bytes) == String.repeat("00", 32)
  end
end

fn authenticated(value :: Option<AccountSlice>,
  owner :: Pubkey,
  space :: Int,
  length :: Int,
  executable :: Bool) -> AccountSlice!String do
  let value = case value do
    None -> return Err("rewards_account_missing")
    Some(value) -> value
  end
  if !pubkey_equal(value.info.owner, owner)
    || value.info.executable != executable
    || value.info.lamports == U64.parse("0")?
    || value.space != U64.parse(Int.to_string(space))?
    || Bytes.length(value.info.data) != length do
    return Err("rewards_account_mismatch")
  end
  Ok(value)
end

fn executable(program :: Pubkey, value :: Option<AccountSlice>) -> Result<(), String> do
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let image = authenticated(value, loader, 36, 36, true)?.info.data
  let metadata = find_program_address(loader, [program.bytes])?.address
  if Bytes.to_hex(Bytes.slice(image, 0, 4)?) != "02000000"
    || !Bytes.secure_equals(Bytes.slice(image, 4, 32)?, metadata.bytes) do
    return Err("rewards_executable_mismatch")
  end
  Ok(nil)
end

fn vault(value :: Option<AccountSlice>,
  token :: Pubkey,
  asset :: Pubkey,
  pool :: Pubkey) -> TokenAccount!String do
  let value = token_account(authenticated(value, token, 165, 165, false)?.info)?
  if !pubkey_equal(value.mint, asset)
    || !pubkey_equal(value.owner, pool)
    || value.state != 1
    || value.delegate != None
    || value.native_reserve != None
    || value.close_authority != None do
    return Err("rewards_vault_mismatch")
  end
  Ok(value)
end

fn unclaimed(rows :: List<RewardClaimRow>, amount :: U64) -> U64!String do
  if List.length(rows) == 0 do
    return Ok(amount)
  end
  let row = List.head(rows)
  unclaimed(List.tail(rows),
    if row.claimed do
      amount
    else
      U64.add(amount, row.amount)?
    end)
end

# One ordered batch from one bank. Only read_rewards establishes independent
# provider agreement and binds the minimum finalized context. The selected
# rewards program and mint are operator read pins, not native release trust.
pub fn decode_rewards_snapshot(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  program :: Pubkey,
  asset :: Pubkey,
  epoch :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> RewardsState!String do
  let addresses = rewards_read_addresses(pins, program, asset, epoch)?
  if Bytes.length(service_key) != 32
    || (version != 1 && version != 2)
    || List.length(snapshot.accounts) != 9 do
    return Err("invalid_rewards_pins")
  end
  executable(program, List.get(snapshot.accounts, 8))?
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let mint_state = mint(authenticated(List.get(snapshot.accounts, 3), token, 82, 82, false)?.info)?
  if !mint_state.initialized || mint_state.decimals != 6 do
    return Err("rewards_mint_mismatch")
  end
  let log = decode_anchor_log(authenticated(List.get(snapshot.accounts, 4),
    pins.program,
    352,
    352,
    false)?.info.data)?
  if log.version != version
    || log.name != pins.log_name
    || !Bytes.secure_equals(log.log_id, pins.log_id)
    || !Bytes.secure_equals(log.service_public_key, service_key)
    || !Bytes.secure_equals(log.ring_address, pins.ring.bytes) do
    return Err("rewards_log_mismatch")
  end
  let pool = if absent(List.get(snapshot.accounts, 0)) do
    None
  else
    Some(decode_reward_pool(authenticated(List.get(snapshot.accounts, 0),
      program,
      304,
      304,
      false)?.info.data)?)
  end
  let clock = if !log.attendance_enabled do
    if pool != None do
      return Err("rewards_attendance_disabled")
    end
    None
  else
    let account = authenticated(List.get(snapshot.accounts, 5), pins.program, 65616, 8416, false)?
    let value = decode_attendance_clock(Bytes.slice(account.info.data, 0, 80)?)?
    if !Bytes.secure_equals(value.log_id, pins.log_id)
      || value.activated_at == U64.parse("0")?
      || U64.compare(value.activated_slot, snapshot.slot) > 0 do
      return Err("rewards_clock_mismatch")
    end
    Some(value)
  end
  let attendance = if absent(List.get(snapshot.accounts, 6)) do
    None
  else
    let value = decode_attendance_epoch(authenticated(List.get(snapshot.accounts, 6),
      pins.program,
      2640,
      2640,
      false)?.info.data)?
    let clock = case clock do
      None -> return Err("rewards_attendance_disabled")
      Some(value) -> value
    end
    let zero = U64.parse("0")?
    if !Bytes.secure_equals(value.log_id, pins.log_id)
      || value.epoch != epoch
      || U64.compare(value.epoch, U64.subtract(clock.first_full_epoch, U64.parse("1")?)?) < 0
      || U64.compare(value.max_post_slot, snapshot.slot) > 0
      || (value.posts != zero
        && (U64.compare(value.max_post_slot, clock.activated_slot) < 0
          || U64.compare(value.epoch, clock.latest_post_epoch) > 0)) do
      return Err("rewards_attendance_mismatch")
    end
    if value.sealed
      && value.posts != zero
      && U64.compare(snapshot.slot, U64.add(value.max_post_slot, U64.parse("1500")?)?) <= 0 do
      return Err("rewards_attendance_context_mismatch")
    end
    Some(value)
  end
  let economics = if absent(List.get(snapshot.accounts, 7)) do
    None
  else
    let value = decode_anchor_economics(authenticated(List.get(snapshot.accounts, 7),
      pins.program,
      192,
      192,
      false)?.info.data)?
    if !Bytes.secure_equals(value.log_id, pins.log_id)
      || !Bytes.secure_equals(value.mint, asset.bytes) do
      return Err("rewards_economics_mismatch")
    end
    Some(value)
  end
  let balance = if absent(List.get(snapshot.accounts, 2)) do
    if pool != None do
      return Err("rewards_vault_missing")
    end
    None
  else
    Some(vault(List.get(snapshot.accounts, 2), token, asset, addresses.pool)?.amount)
  end
  let initial = RewardsState {
    status: "absent",
    awaiting: "",
    program: program,
    mint: asset,
    judge: pins.program,
    log_name: pins.log_name,
    epoch_number: epoch,
    context_slot: snapshot.slot,
    addresses: addresses,
    pool: pool,
    record: None,
    vault_balance: balance,
    vault_surplus: None,
    mint_state: mint_state,
    log: log,
    clock: clock,
    attendance: attendance,
    economics: economics,
    revision_matches: None,
    unclaimed_amount: None,
    snapshot: snapshot
  }
  let pool = case pool do
    None -> do
      if !absent(List.get(snapshot.accounts, 1)) do
        return Err("rewards_epoch_without_pool")
      end
      return Ok(initial)
    end
    Some(value) -> value
  end
  let clock = case clock do
    None -> return Err("rewards_clock_missing")
    Some(value) -> value
  end
  if !Bytes.secure_equals(pool.judge, pins.program.bytes)
    || !Bytes.secure_equals(pool.log, addresses.log.bytes)
    || !Bytes.secure_equals(pool.log_id, pins.log_id)
    || !Bytes.secure_equals(pool.mint, asset.bytes)
    || pool.network_started != clock.activated_at
    || pool.first_full_epoch != clock.first_full_epoch
    || U64.compare(epoch, pool.first_full_epoch) < 0 do
    return Err("rewards_pool_mismatch")
  end
  let balance = case balance do
    None -> return Err("rewards_vault_missing")
    Some(value) -> value
  end
  if U64.compare(balance, pool.accounted) < 0 do
    return Err("rewards_vault_underfunded")
  end
  let state = %{initial |
    status: "awaiting",
    awaiting: if economics == None do
      "economics"
    else
      "epoch"
    end,
    vault_surplus: Some(U64.subtract(balance, pool.accounted)?)
  }
  if absent(List.get(snapshot.accounts, 1)) do
    if U64.compare(epoch, pool.next_epoch) < 0 || pool.active_epoch == Some(epoch) do
      return Err("rewards_epoch_missing")
    end
    return Ok(state)
  end
  let record = decode_reward_epoch(authenticated(List.get(snapshot.accounts, 1),
    program,
    8416,
    8416,
    false)?.info.data)?
  if !Bytes.secure_equals(record.pool, addresses.pool.bytes) || record.epoch != epoch do
    return Err("rewards_epoch_mismatch")
  end
  if record.status == 0 do
    if U64.compare(epoch, pool.next_epoch) < 0 || pool.active_epoch == Some(epoch) do
      return Err("rewards_epoch_mismatch")
    end
  else
    let attendance = case attendance do
      None -> return Err("rewards_attendance_missing")
      Some(value) -> value
    end
    if economics == None do
      return Err("rewards_economics_missing")
    end
    let attendance_bytes = authenticated(List.get(snapshot.accounts, 6),
      pins.program,
      2640,
      2640,
      false)?.info.data
    if !attendance.sealed
      || record.expected != List.length(attendance.rows)
      || record.posts != attendance.posts
      || !Bytes.secure_equals(record.attendance_hash, Crypto.sha256(attendance_bytes)) do
      return Err("rewards_attendance_mismatch")
    end
    for index in 0..List.length(record.rows) do
      if !Bytes.secure_equals(List.get(record.rows, index).witness,
        List.get(attendance.rows, index).witness) do
        return Err("rewards_attendance_row_mismatch")
      end
    end
    if record.status == 1 do
      if epoch != pool.next_epoch
        || pool.active_epoch != Some(epoch)
        || record.available != U64.add(pool.carry, record.revenue)? do
        return Err("rewards_stage_mismatch")
      end
    else if U64.compare(epoch, pool.next_epoch) >= 0
      || (pool.next_epoch == U64.add(epoch, U64.parse("1")?)? && pool.carry != record.carry) do
      return Err("rewards_finalized_mismatch")
    end
  end
  let zero = U64.parse("0")?
  if record.status != 2 do
    let free = U64.subtract(U64.subtract(U64.subtract(pool.accounted, pool.subsidy)?, pool.carry)?,
      pool.liabilities)?
    if U64.compare(free, record.revenue) < 0 do
      return Err("rewards_revenue_unaccounted")
    end
  end
  let unpaid = if record.status == 2 do
    let amount = unclaimed(record.rows, zero)?
    if U64.compare(pool.liabilities, amount) < 0 do
      return Err("rewards_liability_mismatch")
    end
    Some(amount)
  else
    None
  end
  let matches = case economics do
    None
    Some(value) -> if record.status == 0 do
      None
    else
      Some(value.eligibility_revision == record.eligibility_revision)
    end
  end
  Ok(%{state |
    status: if economics == None do
      "awaiting"
    else if record.status == 0 do
      "open"
    else if record.status == 1 do
      "collecting"
    else
      "finalized"
    end,
    awaiting: if economics == None do
      "economics"
    else
      ""
    end,
    record: Some(record),
    revision_matches: matches,
    unclaimed_amount: unpaid
  })
end

fn observe(endpoint :: RpcEndpoint,
  pins :: AnchorPins,
  key :: Bytes,
  version :: Int,
  program :: Pubkey,
  asset :: Pubkey,
  epoch :: U64,
  minimum :: U64) -> RewardsObservation!String do
  let addresses = rewards_read_addresses(pins, program, asset, epoch)?
  let request = get_multiple_accounts_slice_request(1,
    rewards_read_keys(addresses),
    "finalized",
    0,
    8416,
    Some(minimum))?
  let response = read_anchor_rpc_response(pins.rpc, endpoint, request, 65536)?
  let snapshot = optional_accounts_slice_from_response(response)?
  if U64.compare(snapshot.slot, minimum) < 0 do
    return Err("rewards_stale_context")
  end
  Ok(RewardsObservation {
    state: decode_rewards_snapshot(pins, key, version, program, asset, epoch, snapshot)?
  })
end

fn same_snapshot(a :: OptionalAccountSlicesAtSlot, b :: OptionalAccountSlicesAtSlot) -> Bool do
  if List.length(a.accounts) != List.length(b.accounts) do
    return false
  end
  for index in 0..List.length(a.accounts) do
    case (List.get(a.accounts, index), List.get(b.accounts, index)) do
      (None, None) -> nil
      (Some(x), Some(y)) -> if x.space != y.space
        || x.info.executable != y.info.executable
        || x.info.lamports != y.info.lamports
        || !pubkey_equal(x.info.owner, y.info.owner)
        || !Bytes.secure_equals(x.info.data, y.info.data) do
        return false
      end
      _ -> return false
    end
  end
  true
end

fn read_slices_from(rpc :: RpcTransport, endpoint :: RpcEndpoint,
  addresses :: List<Pubkey>,
  length :: Int,
  minimum :: U64) -> OptionalAccountSlicesAtSlot!String do
  let request = get_multiple_accounts_slice_request(1,
    addresses,
    "finalized",
    0,
    length,
    Some(minimum))?
  let response = read_anchor_rpc_response(rpc, endpoint, request, 65536)?
  let snapshot = optional_accounts_slice_from_response(response)?
  if List.length(snapshot.accounts) != List.length(addresses)
    || U64.compare(snapshot.slot, minimum) < 0 do
    return Err("invalid_rewards_response")
  end
  for account in snapshot.accounts do
    case account do
      None -> nil
      Some(value) -> if Bytes.length(value.info.data) > length do
        return Err("invalid_rewards_response")
      end
    end
  end
  Ok(snapshot)
end

fn agree_slices(first :: OptionalAccountSlicesAtSlot!String,
  second :: OptionalAccountSlicesAtSlot!String) -> Option<OptionalAccountSlicesAtSlot> do
  case (first, second) do
    (Ok(a), Ok(b)) -> if same_snapshot(a, b) do
      Some(%{a |
        slot: if U64.compare(a.slot, b.slot) < 0 do
          a.slot
        else
          b.slot
        end
      })
    else
      None
    end
    _ -> None
  end
end

# Generic bounded transport for additional operator reads, including ordered
# Witness batches and operation receipts. Agreement includes full spaces and
# owners; callers still authenticate each owner, canonical address and schema.
pub fn read_rewards_account_slices(pins :: AnchorPins,
  addresses :: List<Pubkey>,
  slice_length :: Int,
  minimum_slot :: U64) -> OptionalAccountSlicesAtSlot!String do
  if List.length(addresses) < 1
    || List.length(addresses) > 64
    || slice_length < 1
    || slice_length > 8416 do
    return Err("invalid_rewards_batch")
  end
  let sampled = sample_anchor_sources(pins)?
  let first = read_slices_from(sampled.rpc, List.get(sampled.rpc.sources, 0),
    addresses,
    slice_length,
    minimum_slot)
  case first do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  let second = read_slices_from(sampled.rpc, List.get(sampled.rpc.sources, 1),
    addresses,
    slice_length,
    minimum_slot)
  case second do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  case agree_slices(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = read_slices_from(sampled.rpc, List.get(sampled.rpc.sources, 2),
    addresses,
    slice_length,
    minimum_slot)
  case third do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  case agree_slices(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case agree_slices(second, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let valid = List.filter([first, second, third],
    fn(result) do
      case result do
        Ok(_) -> true
        Err(_) -> false
      end
    end)
  if List.length(valid) >= 2 do
    Err("anchor_rpc_disagree")
  else
    Err("anchor_rpc_unavailable")
  end
end

pub fn decode_reward_funding_snapshot(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  program :: Pubkey,
  asset :: Pubkey,
  epoch :: U64,
  funder :: Pubkey,
  operation_id :: Bytes,
  snapshot :: OptionalAccountSlicesAtSlot) -> RewardFundingState!String do
  let address = reward_funding_address(program, funder, operation_id)?
  if List.length(snapshot.accounts) != 10 do
    return Err("invalid_reward_funding_snapshot")
  end
  let rewards = decode_rewards_snapshot(pins,
    service_key,
    version,
    program,
    asset,
    epoch,
    %{snapshot | accounts: List.take(snapshot.accounts, 9)})?
  let state = RewardFundingState {
    status: "missing",
    receipt_address: address,
    context_slot: snapshot.slot,
    rewards: rewards,
    receipt: None,
    snapshot: snapshot
  }
  if absent(List.get(snapshot.accounts, 9)) do
    return Ok(state)
  end
  if rewards.pool == None do
    return Err("reward_funding_pool_missing")
  end
  let receipt = decode_reward_funding_receipt(authenticated(List.get(snapshot.accounts, 9),
    program,
    192,
    192,
    false)?.info.data)?
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let ata = pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?
  let source = find_program_address(ata, [funder.bytes, token.bytes, asset.bytes])?.address
  if !Bytes.secure_equals(receipt.pool, rewards.addresses.pool.bytes)
    || !Bytes.secure_equals(receipt.funder, funder.bytes)
    || !Bytes.secure_equals(receipt.operation_id, operation_id)
    || !Bytes.secure_equals(receipt.mint, asset.bytes)
    || !Bytes.secure_equals(receipt.source, source.bytes)
    || receipt.epoch != epoch do
    return Err("reward_funding_identity_mismatch")
  end
  Ok(%{state | status: "funded", receipt: Some(receipt)})
end

# Receipt lookup authenticates the old operation's epoch in the same bank as
# current custody. A later claim or eligibility revision does not undo funding.
pub fn read_reward_funding(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  program :: Pubkey,
  asset :: Pubkey,
  epoch :: U64,
  funder :: Pubkey,
  operation_id :: Bytes,
  minimum_slot :: U64) -> RewardFundingState!String do
  if Bytes.length(service_key) != 32 || (version != 1 && version != 2) do
    return Err("invalid_rewards_pins")
  end
  let addresses = rewards_read_addresses(pins, program, asset, epoch)?
  let receipt = reward_funding_address(program, funder, operation_id)?
  let snapshot = read_rewards_account_slices(pins,
    List.append(rewards_read_keys(addresses), receipt),
    8416,
    minimum_slot)?
  decode_reward_funding_snapshot(pins,
    service_key,
    version,
    program,
    asset,
    epoch,
    funder,
    operation_id,
    snapshot)
end

fn agree(first :: RewardsObservation!String,
  second :: RewardsObservation!String) -> Option<RewardsState> do
  case (first, second) do
    (Ok(a), Ok(b)) -> if same_snapshot(a.state.snapshot, b.state.snapshot) do
      let slot = if U64.compare(a.state.context_slot, b.state.context_slot) < 0 do
        a.state.context_slot
      else
        b.state.context_slot
      end
      Some(%{a.state | context_slot: slot, snapshot: %{a.state.snapshot | slot: slot}})
    else
      None
    end
    _ -> None
  end
end

pub fn read_rewards(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  program :: Pubkey,
  asset :: Pubkey,
  epoch :: U64,
  minimum_slot :: U64) -> RewardsState!String do
  rewards_read_addresses(pins, program, asset, epoch)?
  if Bytes.length(service_key) != 32 || (version != 1 && version != 2) do
    return Err("invalid_rewards_pins")
  end
  let pins = sample_anchor_sources(pins)?
  let first = observe(List.get(pins.rpc.sources, 0),
    pins,
    service_key,
    version,
    program,
    asset,
    epoch,
    minimum_slot)
  case first do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  let second = observe(List.get(pins.rpc.sources, 1),
    pins,
    service_key,
    version,
    program,
    asset,
    epoch,
    minimum_slot)
  case second do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  case agree(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = observe(List.get(pins.rpc.sources, 2),
    pins,
    service_key,
    version,
    program,
    asset,
    epoch,
    minimum_slot)
  case third do
    Err(error) when rpc_fatal_error(error) -> return Err(error)
    _ -> nil
  end
  case agree(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case agree(second, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let valid = List.filter([first, second, third],
    fn(result) do
      case result do
        Ok(_) -> true
        Err(_) -> false
      end
    end)
  if List.length(valid) >= 2 do
    Err("anchor_rpc_disagree")
  else
    Err("anchor_rpc_unavailable")
  end
end

fn optional_wide(value :: Option<U64>) -> String do
  case value do
    None -> "null"
    Some(value) -> Json.encode_string(U64.to_string(value))
  end
end

fn optional_bool(value :: Option<Bool>) -> String do
  case value do
    None -> "null"
    Some(value) -> if value do
      "true"
    else
      "false"
    end
  end
end

fn pool_json(value :: Option<RewardPoolAccount>) -> String do
  case value do
    None -> "null"
    Some(p) -> """{"governance":"#{Bytes.to_base58(p.governance)}","network_started":"#{U64.to_string(p.network_started)}","first_full_epoch":"#{U64.to_string(p.first_full_epoch)}","next_epoch":"#{U64.to_string(p.next_epoch)}","subsidy":"#{U64.to_string(p.subsidy)}","carry":"#{U64.to_string(p.carry)}","liabilities":"#{U64.to_string(p.liabilities)}","accounted":"#{U64.to_string(p.accounted)}","active_epoch":#{optional_wide(p.active_epoch)},"pending_governance":"#{Bytes.to_base58(p.pending_governance)}","governance_ready":"#{U64.to_string(p.governance_ready)}","morse_witness":"#{Bytes.to_base58(p.morse_witness)}"}"""
  end
end

fn record_json(state :: RewardsState) -> String do
  let value = case state.record do
    None -> return "null"
    Some(value) -> value
  end
  let rows = String.join(for index in 0..List.length(value.rows) do
      let row = List.get(value.rows, index)
      """{"index":#{index},"witness":"#{Bytes.to_base58(row.witness)}","payout":"#{Bytes.to_base58(row.payout)}","bond":"#{Bytes.to_base58(row.bond)}","weight":"#{U128.to_string(row.weight)}","floor":"#{U64.to_string(row.floor)}","amount":"#{U64.to_string(row.amount)}","claimed":#{row.claimed}}"""
    end,
    ",")
  """{"status":#{value.status},"expected_rows":#{value.expected},"collected_rows":#{List.length(value.rows)},"revenue":"#{U64.to_string(value.revenue)}","attendance_hash":"#{Bytes.to_hex(value.attendance_hash)}","posts":"#{U64.to_string(value.posts)}","total_weight":"#{U128.to_string(value.total_weight)}","floor_required":"#{U64.to_string(value.floor_required)}","base_floor":"#{U64.to_string(value.base_floor)}","available":"#{U64.to_string(value.available)}","subsidy_used":"#{U64.to_string(value.subsidy_used)}","allocated":"#{U64.to_string(value.allocated)}","carry":"#{U64.to_string(value.carry)}","claimed_mask":"#{U64.to_string(value.claimed_mask)}","started_at":"#{U64.to_string(value.started_at)}","eligibility_revision":"#{U64.to_string(value.eligibility_revision)}","revision_matches":#{optional_bool(state.revision_matches)},"unclaimed_amount":#{optional_wide(state.unclaimed_amount)},"rows":[#{rows}]}"""
end

pub fn rewards_report(value :: RewardsState) -> String do
  let a = value.addresses
  let revision = case value.economics do
    None
    Some(value) -> Some(value.eligibility_revision)
  end
  let awaiting = if value.awaiting == "" do
    "null"
  else
    Json.encode_string(value.awaiting)
  end
  """{"schema_version":1,"program_pin":"operator_selected","status":#{Json.encode_string(value.status)},"awaiting":#{awaiting},"program":"#{pubkey_string(value.program)}","mint":"#{pubkey_string(value.mint)}","judge":"#{pubkey_string(value.judge)}","log_name":#{Json.encode_string(value.log_name)},"epoch":"#{U64.to_string(value.epoch_number)}","context_slot":"#{U64.to_string(value.context_slot)}","addresses":{"pool":"#{pubkey_string(a.pool)}","epoch":"#{pubkey_string(a.epoch)}","vault":"#{pubkey_string(a.vault)}","mint":"#{pubkey_string(a.mint)}","log":"#{pubkey_string(a.log)}","clock":"#{pubkey_string(a.clock)}","attendance":"#{pubkey_string(a.attendance)}","economics":"#{pubkey_string(a.economics)}","program":"#{pubkey_string(a.program)}"},"pool":#{pool_json(value.pool)},"epoch_state":#{record_json(value)},"vault_balance":#{optional_wide(value.vault_balance)},"vault_surplus":#{optional_wide(value.vault_surplus)},"current_eligibility_revision":#{optional_wide(revision)}}"""
end
