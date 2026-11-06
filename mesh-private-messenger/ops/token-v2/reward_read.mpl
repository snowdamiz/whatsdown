from Solana.Read import (
  Pubkey,
  AccountSlice,
  OptionalAccountSlicesAtSlot,
  pubkey,
  mint,
  token_account,
  clock_sysvar,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  rpc_send
)
from Solana.Address import find_program_address
from Transparency.AnchorChain import anchor_addresses
from Transparency.AnchorLog import decode_anchor_log
from Transparency.Attendance import (
  AttendanceEpoch,
  decode_attendance_clock,
  decode_attendance_epoch
)
from Transparency.RewardsChain import RewardPoolAccount
from Transparency.TokenWrite import TokenRewardWriteContext, token_reward_write_addresses
from Transparency.TokenCustody import (
  TokenCollateralEconomics,
  decode_token_collateral_economics,
  decode_token_collateral_binding
)
from Transparency.TokenRewards import (
  TokenRewardPoolAccount,
  TokenRewardEpochAccount,
  decode_token_reward_usdc_pool,
  decode_token_reward_pool,
  decode_token_reward_epoch,
  decode_token_reserve_profile,
  decode_token_reserve_receipt,
  token_reward_rows_hash
)
from Transparency.TokenChain import (
  decode_token_config,
  decode_token_allocation,
  decode_token_oracle,
  token_oracle_twap
)

pub struct TokenRewardReadPins do
  context :: TokenRewardWriteContext
  governance :: Pubkey
  token_governance :: Pubkey
  service_key :: Bytes
  log_version :: Int
  network_started :: U64
  token_slot :: U64
  judge_slot :: U64
  rewards_slot :: U64
  source_program :: Pubkey
  source :: Pubkey
  feed :: Bytes
  source_revision :: U64
end

pub struct TokenRewardReadState do
  status :: String
  context_slot :: U64
  timestamp :: U64
  pool :: RewardPoolAccount
  token_pool :: TokenRewardPoolAccount
  economics :: TokenCollateralEconomics
  attendance :: Option<AttendanceEpoch>
  record :: Option<TokenRewardEpochAccount>
  usdc_balance :: U64
  morse_balance :: U64
  usdc_surplus :: U64
  morse_surplus :: U64
  reserve_remaining :: U64
  claimed_usd :: U64
  claimed_morse :: U64
  code_current :: Bool
  source_current :: Bool
  revision_matches :: Bool
  stage_expired :: Bool
  twap :: Option<U64>
  digest :: Bytes
end

fn pda(program :: Pubkey, seeds :: List<Bytes>) -> Pubkey!String do
  Ok(find_program_address(program, seeds)?.address)
end

fn nonzero(value :: Bytes) -> Bool do
  Bytes.length(value) == 32 && Bytes.to_hex(value) != String.repeat("00", 32)
end

fn valid_pins(pins :: TokenRewardReadPins) -> Bool!String do
  for key in [pins.governance, pins.token_governance, pins.source_program, pins.source] do
    if !nonzero(key.bytes) do
      return Err("invalid_token_rewards_read_pins")
    end
  end
  if !nonzero(pins.service_key)
    || !nonzero(pins.feed)
    || (pins.log_version != 1 && pins.log_version != 2)
    || pins.network_started == U64.parse("0")?
    || pins.source_revision == U64.parse("0")? do
    return Err("invalid_token_rewards_read_pins")
  end
  Ok(true)
end

pub fn token_reward_read_keys(pins :: TokenRewardReadPins, epoch :: U64) -> List<Pubkey>!String do
  valid_pins(pins)?
  let c = pins.context
  let a = token_reward_write_addresses(c, epoch)?
  Ok([
    a.base.pool,
    a.token_pool,
    a.base.epoch,
    a.token_epoch,
    a.base.vault,
    a.morse_vault,
    c.usdc_mint,
    a.morse,
    a.base.log,
    a.base.economics,
    a.binding,
    a.token_config,
    a.oracle,
    a.reserve_profile,
    pubkey("SysvarC1ock11111111111111111111111111111111")?,
    a.base.clock,
    a.base.attendance_epoch,
    c.token,
    a.token_data,
    c.judge,
    a.judge_data,
    c.program,
    pda(pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?, [c.program.bytes])?,
    a.reserve_receipt,
    a.reserve_allocation,
    a.reserve_vault
  ])
end

fn required(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  space :: U64,
  size :: Int,
  executable :: Bool) -> AccountSlice!String do
  let value = case List.get(snapshot.accounts, index) do
    None -> return Err("token_rewards_account_missing")
    Some(value) -> value
  end
  if value.info.owner != owner
    || value.info.executable != executable
    || value.info.lamports == U64.parse("0")?
    || value.space != space
    || Bytes.length(value.info.data) != size do
    return Err("token_rewards_account_mismatch")
  end
  Ok(value)
end

fn owned(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  size :: Int) -> Bytes!String do
  Ok(required(snapshot, index, owner, U64.parse(Int.to_string(size))?, size, false)?.info.data)
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

fn number(bytes :: Bytes, at :: Int) -> U64!String do
  U64.parse(Bytes.read_uint_le(bytes, at, 8)?)
end

fn code(snapshot :: OptionalAccountSlicesAtSlot,
  program :: Pubkey,
  image_index :: Int,
  data_index :: Int) -> U64!String do
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let image = required(snapshot, image_index, loader, U64.parse("36")?, 36, true)?.info.data
  let pd = pda(loader, [program.bytes])?
  if Bytes.to_hex(Bytes.slice(image, 0, 4)?) != "02000000"
    || Bytes.slice(image, 4, 32)? != pd.bytes do
    return Err("token_rewards_executable_mismatch")
  end
  let value = case List.get(snapshot.accounts, data_index) do
    None -> return Err("token_rewards_program_data_missing")
    Some(value) -> value
  end
  if U64.compare(value.space, U64.parse("45")?) < 0
    || U64.compare(value.space, U64.parse("10485760")?) > 0 do
    return Err("token_rewards_program_data_mismatch")
  end
  let size = if U64.compare(value.space, U64.parse("8416")?) > 0 do
    8416
  else
    U64.to_int(value.space)?
  end
  let data = required(snapshot, data_index, loader, value.space, size, false)?.info.data
  let slot = number(data, 4)?
  if Bytes.to_hex(Bytes.slice(data, 0, 4)?) != "03000000"
    || Bytes.get(data, 12)? > 1
    || U64.compare(slot, snapshot.slot) > 0 do
    return Err("token_rewards_program_data_mismatch")
  end
  Ok(slot)
end

fn vault(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  mint_key :: Pubkey,
  owner :: Pubkey) -> U64!String do
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let info = required(snapshot, index, token, U64.parse("165")?, 165, false)?.info
  let value = token_account(info)?
  if value.mint != mint_key
    || value.owner != owner
    || value.state != 1
    || value.delegate != None
    || value.native_reserve != None
    || value.close_authority != None
    || value.delegated_amount != U64.parse("0")? do
    return Err("token_rewards_vault_mismatch")
  end
  Ok(value.amount)
end

fn digest(keys :: List<Pubkey>, snapshot :: OptionalAccountSlicesAtSlot) -> Bytes!String do
  let parts = for index in 0..List.length(keys) do
    let body = case List.get(snapshot.accounts, index) do
      None -> Bytes.from_hex("00")?
      Some(value) ->
        let prefix = Bytes.concat(Bytes.concat(Bytes.concat(Bytes.from_hex(if value.info.executable do
                "0101"
              else
                "0100"
              end)?,
              value.info.owner.bytes)?,
            Bytes.write_uint_le(U64.to_string(value.space), 8)?)?,
          Bytes.write_uint_le(U64.to_string(value.info.lamports), 8)?)?
        Bytes.concat(prefix, Crypto.sha256(value.info.data))?
    end
    Bytes.concat(List.get(keys, index).bytes, body)?
  end
  let bytes = List.reduce(parts,
    Ok(Bytes.from_utf8("morse-token-reward-snapshot-v2")),
    fn(result, part) do Bytes.concat(result?, part) end)?
  Ok(Crypto.sha256(bytes))
end

pub fn decode_token_reward_snapshot(pins :: TokenRewardReadPins,
  epoch :: U64,
  minimum :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> TokenRewardReadState!String do
  let keys = token_reward_read_keys(pins, epoch)?
  if List.length(snapshot.accounts) != 26 || U64.compare(snapshot.slot, minimum) < 0 do
    return Err("invalid_token_rewards_snapshot")
  end
  let c = pins.context
  let a = token_reward_write_addresses(c, epoch)?
  let anchor = anchor_addresses(c.judge, c.log_name)?
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let pool = decode_token_reward_usdc_pool(owned(snapshot, 0, c.program, 304)?)?
  let morse_pool = decode_token_reward_pool(owned(snapshot, 1, c.program, 320)?)?
  let log = decode_anchor_log(owned(snapshot, 8, c.judge, 352)?)?
  let economics = decode_token_collateral_economics(owned(snapshot, 9, c.judge, 192)?)?
  let binding = decode_token_collateral_binding(owned(snapshot, 10, c.judge, 320)?)?
  let config = decode_token_config(owned(snapshot, 11, c.token, 320)?)?
  let oracle_raw = owned(snapshot, 12, c.token, 5728)?
  let oracle = decode_token_oracle(oracle_raw)?
  let profile = decode_token_reserve_profile(owned(snapshot, 13, c.token, 320)?)?
  let clock_account = required(snapshot,
    14,
    pubkey("Sysvar1111111111111111111111111111111111111")?,
    U64.parse("40")?,
    40,
    false)?
  let clock = clock_sysvar(clock_account.info)?
  if clock.slot != snapshot.slot || clock.unix_timestamp <= 0 do
    return Err("token_rewards_clock_mismatch")
  end
  let now = U64.parse(Int.to_string(clock.unix_timestamp))?
  let attendance_clock_raw = required(snapshot,
    15,
    c.judge,
    U64.parse("65616")?,
    8416,
    false)?.info.data
  let attendance_clock = decode_attendance_clock(Bytes.slice(attendance_clock_raw, 0, 80)?)?
  if pool.governance != pins.governance.bytes
    || pool.judge != c.judge.bytes
    || pool.log != a.base.log.bytes
    || pool.log_id != anchor.log_id
    || pool.mint != c.usdc_mint.bytes
    || pool.network_started != pins.network_started
    || pool.network_started != attendance_clock.activated_at
    || pool.first_full_epoch != attendance_clock.first_full_epoch
    || attendance_clock.log_id != anchor.log_id
    || U64.compare(attendance_clock.activated_slot, snapshot.slot) > 0
    || U64.compare(epoch, pool.first_full_epoch) < 0
    || log.name != c.log_name
    || log.version != pins.log_version
    || log.log_id != anchor.log_id
    || log.ring_address != anchor.ring.bytes
    || log.service_public_key != pins.service_key
    || !log.attendance_enabled
    || economics.log_id != anchor.log_id
    || economics.usdc_mint != c.usdc_mint.bytes do
    return Err("token_rewards_context_mismatch")
  end
  if binding.log != a.base.log.bytes
    || binding.log_id != anchor.log_id
    || binding.token_program != c.token.bytes
    || binding.config != a.token_config.bytes
    || binding.mint != a.morse.bytes
    || binding.oracle != a.oracle.bytes
    || binding.rewards_program != c.program.bytes
    || binding.rewards_pool != a.base.pool.bytes
    || binding.activated_at == U64.parse("0")?
    || U64.compare(binding.activated_at, now) > 0
    || morse_pool.pool != a.base.pool.bytes
    || morse_pool.binding != a.binding.bytes
    || morse_pool.token_program != c.token.bytes
    || morse_pool.config != a.token_config.bytes
    || morse_pool.mint != a.morse.bytes
    || morse_pool.oracle != a.oracle.bytes
    || morse_pool.profile != a.reserve_profile.bytes
    || morse_pool.vault != a.morse_vault.bytes
    || morse_pool.activation_epoch != binding.activated_epoch
    || U64.compare(pool.next_epoch, binding.activated_epoch) < 0
    || config.governance != pins.token_governance
    || config.mint != a.morse
    || U64.compare(config.started, now) > 0
    || oracle.config != a.token_config
    || oracle.mint != a.morse
    || U64.compare(oracle.last_slot, snapshot.slot) > 0 do
    return Err("token_rewards_binding_mismatch")
  end
  if profile.config != a.token_config.bytes
    || profile.mint != a.morse.bytes
    || profile.usdc_mint != c.usdc_mint.bytes
    || profile.judge != c.judge.bytes
    || profile.log != a.base.log.bytes
    || profile.binding != a.binding.bytes
    || profile.rewards != c.program.bytes
    || profile.pool != a.base.pool.bytes
    || profile.token_pool != a.token_pool.bytes
    || U64.compare(profile.ready_at, now) > 0
    || profile.rewards_slot != binding.rewards_slot do
    return Err("token_rewards_profile_mismatch")
  end
  let dollars = mint(required(snapshot, 6, token, U64.parse("82")?, 82, false)?.info)?
  let morse = mint(required(snapshot, 7, token, U64.parse("82")?, 82, false)?.info)?
  if !dollars.initialized
    || dollars.decimals != 6
    || !morse.initialized
    || morse.decimals != 6
    || morse.mint_authority != None
    || morse.freeze_authority != None
    || U64.compare(morse.supply, U64.parse("1000000000000000")?) > 0 do
    return Err("token_rewards_mint_mismatch")
  end
  let usd_balance = vault(snapshot, 4, c.usdc_mint, a.base.pool)?
  let morse_balance = vault(snapshot, 5, a.morse, a.base.pool)?
  let usd_surplus = U64.subtract(usd_balance, pool.accounted)?
  let morse_surplus = U64.subtract(morse_balance, morse_pool.accounted_morse)?
  let allocation = decode_token_allocation(owned(snapshot, 24, c.token, 128)?)?
  if allocation.kind != 4
    || allocation.config != a.token_config
    || allocation.mint != a.morse
    || allocation.total != U64.parse("150000000000000")?
    || allocation.started != config.started
    || allocation.beneficiary != List.get(config.beneficiaries, 4) do
    return Err("token_rewards_reserve_mismatch")
  end
  let remaining = U64.subtract(allocation.total, allocation.claimed)?
  if U64.compare(vault(snapshot, 25, a.morse, a.reserve_allocation)?, remaining) < 0 do
    return Err("token_rewards_reserve_underfunded")
  end
  let token_slot = code(snapshot, c.token, 17, 18)?
  let judge_slot = code(snapshot, c.judge, 19, 20)?
  let rewards_slot = code(snapshot, c.program, 21, 22)?
  let code_current = token_slot == pins.token_slot
    && judge_slot == pins.judge_slot
    && rewards_slot == pins.rewards_slot
    && token_slot == binding.token_slot
    && rewards_slot == binding.rewards_slot
    && rewards_slot == profile.rewards_slot
    && judge_slot == profile.judge_slot
  let source_current = oracle.receiver == pins.source_program
    && oracle.source == pins.source
    && oracle.feed == pins.feed
    && oracle.revision == pins.source_revision
  let twap = case token_oracle_twap(oracle_raw, now) do
    Ok(value) -> Some(value)
    Err(_) -> None
  end
  let attendance = if absent(List.get(snapshot.accounts, 16)) do
    None
  else
    let value = decode_attendance_epoch(owned(snapshot, 16, c.judge, 2640)?)?
    if value.log_id != anchor.log_id
      || value.epoch != epoch
      || U64.compare(value.max_post_slot, snapshot.slot) > 0 do
      return Err("token_rewards_attendance_mismatch")
    end
    Some(value)
  end
  let initial = TokenRewardReadState {
    status: "awaiting_epoch",
    context_slot: snapshot.slot,
    timestamp: now,
    pool: pool,
    token_pool: morse_pool,
    economics: economics,
    attendance: attendance,
    record: None,
    usdc_balance: usd_balance,
    morse_balance: morse_balance,
    usdc_surplus: usd_surplus,
    morse_surplus: morse_surplus,
    reserve_remaining: remaining,
    claimed_usd: U64.parse("0")?,
    claimed_morse: U64.parse("0")?,
    code_current: code_current,
    source_current: source_current,
    revision_matches: false,
    stage_expired: false,
    twap: twap,
    digest: digest(keys, snapshot)?
  }
  if absent(List.get(snapshot.accounts, 2)) || absent(List.get(snapshot.accounts, 3)) do
    if !absent(List.get(snapshot.accounts, 2))
      || !absent(List.get(snapshot.accounts, 3))
      || !absent(List.get(snapshot.accounts, 23))
      || U64.compare(epoch, pool.next_epoch) < 0
      || pool.active_epoch == Some(epoch) do
      return Err("token_rewards_epoch_missing")
    end
    return Ok(initial)
  end
  let main_raw = owned(snapshot, 2, c.program, 8416)?
  let token_raw = owned(snapshot, 3, c.program, 1280)?
  let record = decode_token_reward_epoch(main_raw, token_raw)?
  # The wire's claimed_usd is a bitmap. Liabilities use the sum of paid rows.
  let claimed_dollars = List.reduce(record.rows,
    Ok(U64.parse("0")?),
    fn(total, row) do
      if row.claimed_usd do
        U64.add(total?, row.amount_usd)
      else
        total
      end
    end)?
  if record.pool != a.base.pool.bytes
    || record.token_pool != a.token_pool.bytes
    || record.ledger != a.base.epoch.bytes
    || record.epoch != epoch do
    return Err("token_rewards_epoch_mismatch")
  end
  if record.status == 0 do
    if U64.compare(epoch, pool.next_epoch) < 0 || pool.active_epoch == Some(epoch) do
      return Err("token_rewards_epoch_mismatch")
    end
  else
    let week = case attendance do
      None -> return Err("token_rewards_attendance_missing")
      Some(value) -> value
    end
    if !week.sealed
      || record.expected != List.length(week.rows)
      || record.posts != week.posts
      || record.attendance_hash != Crypto.sha256(owned(snapshot, 16, c.judge, 2640)?) do
      return Err("token_rewards_attendance_mismatch")
    end
    for index in 0..List.length(record.rows) do
      if List.get(record.rows, index).witness != List.get(week.rows, index).witness do
        return Err("token_rewards_attendance_mismatch")
      end
    end
    if record.status == 1 do
      if epoch != pool.next_epoch
        || pool.active_epoch != Some(epoch)
        || record.available_usd != U64.add(pool.carry, record.revenue_usd)? do
        return Err("token_rewards_stage_mismatch")
      end
    else if U64.compare(epoch, pool.next_epoch) >= 0
      || (pool.next_epoch == U64.add(epoch, U64.parse("1")?)? && pool.carry != record.carry_usd)
      || U64.compare(pool.liabilities, U64.subtract(record.allocated_usd, claimed_dollars)?) < 0
      || U64.compare(morse_pool.liabilities_morse,
        U64.subtract(record.allocated_morse, record.claimed_amount_morse)?) < 0 do
      return Err("token_rewards_finalized_mismatch")
    end
  end
  if record.status != 2 do
    let free = U64.subtract(U64.subtract(U64.subtract(pool.accounted, pool.subsidy)?, pool.carry)?,
      pool.liabilities)?
    if U64.compare(free, record.revenue_usd) < 0 do
      return Err("token_rewards_revenue_unaccounted")
    end
  end
  if record.status == 2 && record.allocated_morse != U64.parse("0")? do
    let receipt = decode_token_reserve_receipt(owned(snapshot, 23, c.token, 256)?)?
    if receipt.profile != a.reserve_profile.bytes
      || receipt.pool != a.base.pool.bytes
      || receipt.token_epoch != a.token_epoch.bytes
      || receipt.epoch != epoch
      || receipt.usd_gap != record.shortfall_usd
      || receipt.twap != record.twap
      || receipt.amount_morse != record.allocated_morse
      || receipt.source_revision != record.source_revision
      || receipt.mint != a.morse.bytes
      || receipt.destination != a.morse_vault.bytes
      || receipt.rows_hash != token_reward_rows_hash(main_raw, token_raw)?
      || U64.compare(receipt.funded_at, record.snapshot_at) < 0
      || U64.compare(receipt.funded_at, now) > 0 do
      return Err("token_rewards_receipt_mismatch")
    end
  else if !absent(List.get(snapshot.accounts, 23)) do
    return Err("token_rewards_unexpected_receipt")
  end
  let stage_expired = record.status == 1
    && U64.compare(now, U64.add(record.snapshot_at, U64.parse("3600")?)?) >= 0
  Ok(%{initial |
    status: if record.status == 0 do
      "open"
    else if record.status == 1 do
      "collecting"
    else
      "finalized"
    end,
    record: Some(record),
    claimed_usd: claimed_dollars,
    claimed_morse: record.claimed_amount_morse,
    revision_matches: economics.revision == record.eligibility_revision
      && oracle.revision == record.source_revision,
    stage_expired: stage_expired
  })
end

# Exactly26 canonical roles, one finalized bank, full sizes and bounded slices.
# Quorum below authenticates agreement; a raw decoded state is not chain proof.
pub fn read_token_reward_from(client :: Int,
  url :: String,
  pins :: TokenRewardReadPins,
  epoch :: U64,
  minimum :: U64) -> TokenRewardReadState!String do
  let request = get_multiple_accounts_slice_request(1,
    token_reward_read_keys(pins, epoch)?,
    "finalized",
    0,
    8416,
    Some(minimum))?
  let response = rpc_send(client, url, request, 5000, 524288)?
  decode_token_reward_snapshot(pins,
    epoch,
    minimum,
    optional_accounts_slice_from_response(response)?)
end

fn agree(first :: TokenRewardReadState!String,
  second :: TokenRewardReadState!String) -> Option<TokenRewardReadState> do
  case first do
    Err(_) -> None
    Ok(first) -> case second do
      Err(_) -> None
      Ok(second) -> if first.digest == second.digest do
        Some(first)
      else
        None
      end
    end
  end
end

pub fn token_reward_rpc_sources(urls :: List<String>, test_mode :: Bool) -> Bool!String do
  if List.length(urls) != 3 do
    return Err("invalid_token_rewards_rpc_sources")
  end
  for index in 0..3 do
    let url = List.get(urls, index)
    if String.length(url) > 2048
      || String.contains(url, "\n")
      || String.contains(url, "\r")
      || String.contains(url, "#")
      || (!String.starts_with(url, "https://")
        && !(test_mode && String.starts_with(url, "http://127.0.0.1:"))) do
      return Err("invalid_token_rewards_rpc_sources")
    end
    for other in 0..index do
      if url == List.get(urls, other) do
        return Err("invalid_token_rewards_rpc_sources")
      end
    end
  end
  Ok(true)
end

pub fn read_token_reward_quorum(client :: Int,
  urls :: List<String>,
  test_mode :: Bool,
  pins :: TokenRewardReadPins,
  epoch :: U64,
  minimum :: U64) -> TokenRewardReadState!String do
  token_reward_rpc_sources(urls, test_mode)?
  let first = read_token_reward_from(client, List.get(urls, 0), pins, epoch, minimum)
  let second = read_token_reward_from(client, List.get(urls, 1), pins, epoch, minimum)
  case agree(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = read_token_reward_from(client, List.get(urls, 2), pins, epoch, minimum)
  case agree(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case agree(second, third) do
    Some(value) -> Ok(value)
    None -> Err("token_rewards_rpc_no_agreement")
  end
end
