##! Derived from qualified ops/public-chain/collateral_accounts.mpl; raw snapshot authentication only.
from Transparency.NetworkCollateralPins import CollateralPins, collateral_pda
from Solana.Read import (
  Pubkey,
  AccountSlice,
  OptionalAccountSlicesAtSlot,
  pubkey,
  mint,
  token_account,
  clock_sysvar
)
from Transparency.AnchorChain import anchor_addresses
from Transparency.AnchorLog import AnchorLog, decode_anchor_log
from Transparency.TokenChain import token_addresses, decode_token_config
from Transparency.TokenCustody import (
  TokenCollateralEconomics,
  TokenCollateralBinding,
  decode_token_collateral_economics,
  decode_token_collateral_binding
)
from Transparency.RewardsChain import RewardPoolAccount, decode_reward_pool
from Transparency.TokenRewards import decode_token_reward_usdc_pool

pub struct CollateralContext do
  slot :: U64
  timestamp :: U64
  code_current :: Bool
  log :: AnchorLog
  economics :: TokenCollateralEconomics
  binding :: TokenCollateralBinding
  pool :: RewardPoolAccount
end

pub fn collateral_number(value :: Bytes, at :: Int) -> U64!String do
  U64.parse(Bytes.read_uint_le(value, at, 8)?)
end

pub fn collateral_zeroes(value :: Bytes, at :: Int, count :: Int) -> Bool!String do
  Ok(Bytes.to_hex(Bytes.slice(value, at, count)?) == String.repeat("00", count))
end

pub fn collateral_absent(value :: Option<AccountSlice>) -> Bool do
  case value do
    None -> true
    Some(account) -> !account.info.executable
      && U64.to_string(account.space) == "0"
      && Bytes.length(account.info.data) == 0
      && Bytes.to_hex(account.info.owner.bytes) == String.repeat("00", 32)
  end
end

pub fn collateral_required(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  space :: U64,
  length :: Int,
  executable :: Bool) -> AccountSlice!String do
  let account = case List.get(snapshot.accounts, index) do
    None -> return Err("public_collateral_account_missing")
    Some(value) -> value
  end
  if account.info.owner != owner
    || account.info.executable != executable
    || account.info.lamports == U64.parse("0")?
    || account.space != space
    || Bytes.length(account.info.data) != length do
    return Err("public_collateral_account_mismatch")
  end
  Ok(account)
end

pub fn collateral_owned(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  length :: Int) -> Bytes!String do
  Ok(collateral_required(snapshot,
    index,
    owner,
    U64.parse(Int.to_string(length))?,
    length,
    false)?.info.data)
end

pub fn collateral_vault(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  expected_mint :: Pubkey,
  owner :: Pubkey) -> Option<U64>!String do
  if collateral_absent(List.get(snapshot.accounts, index)) do
    return Ok(None)
  end
  let token = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let value = token_account(collateral_required(snapshot,
    index,
    token,
    U64.parse("165")?,
    165,
    false)?.info)?
  if value.mint != expected_mint
    || value.owner != owner
    || value.state != 1
    || value.delegate != None
    || value.native_reserve != None
    || value.close_authority != None
    || value.delegated_amount != U64.parse("0")? do
    return Err("public_collateral_vault_mismatch")
  end
  Ok(Some(value.amount))
end

fn code(snapshot :: OptionalAccountSlicesAtSlot,
  program :: Pubkey,
  image_index :: Int,
  data_index :: Int) -> U64!String do
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let image = collateral_required(snapshot,
    image_index,
    loader,
    U64.parse("36")?,
    36,
    true)?.info.data
  let address = collateral_pda(loader, [program.bytes])?
  if Bytes.to_hex(Bytes.slice(image, 0, 4)?) != "02000000"
    || Bytes.slice(image, 4, 32)? != address.bytes do
    return Err("public_collateral_executable_mismatch")
  end
  let account = case List.get(snapshot.accounts, data_index) do
    None -> return Err("public_collateral_program_data_missing")
    Some(value) -> value
  end
  if U64.compare(account.space, U64.parse("45")?) < 0
    || U64.compare(account.space, U64.parse("10485760")?) > 0 do
    return Err("public_collateral_program_data_mismatch")
  end
  let length = if U64.compare(account.space, U64.parse("8416")?) > 0 do
    8416
  else
    U64.to_int(account.space)?
  end
  let data = collateral_required(snapshot,
    data_index,
    loader,
    account.space,
    length,
    false)?.info.data
  let slot = collateral_number(data, 4)?
  if Bytes.to_hex(Bytes.slice(data, 0, 4)?) != "03000000"
    || Bytes.get(data, 12)? > 1
    || U64.compare(slot, snapshot.slot) > 0 do
    return Err("public_collateral_program_data_mismatch")
  end
  Ok(slot)
end

pub fn collateral_context(pins :: CollateralPins,
  snapshot :: OptionalAccountSlicesAtSlot,
  minimum :: U64) -> CollateralContext!String do
  if List.length(snapshot.accounts) < 14 || U64.compare(snapshot.slot, minimum) < 0 do
    return Err("public_collateral_snapshot_mismatch")
  end
  let anchor = anchor_addresses(pins.judge, pins.log_name)?
  let token = token_addresses(pins.token)?
  let log = decode_anchor_log(collateral_owned(snapshot, 0, pins.judge, 352)?)?
  let economics = decode_token_collateral_economics(collateral_owned(snapshot,
    1,
    pins.judge,
    192)?)?
  let binding = decode_token_collateral_binding(collateral_owned(snapshot, 2, pins.judge, 320)?)?
  let config = decode_token_config(collateral_owned(snapshot, 3, pins.token, 320)?)?
  let pool_raw = collateral_owned(snapshot, 6, pins.rewards, 304)?
  let pool = if Bytes.get(pool_raw, 3)? == 2 do
    decode_token_reward_usdc_pool(pool_raw)?
  else
    decode_reward_pool(pool_raw)?
  end
  let clock = clock_sysvar(collateral_required(snapshot,
    7,
    pubkey("Sysvar1111111111111111111111111111111111111")?,
    U64.parse("40")?,
    40,
    false)?.info)?
  if clock.slot != snapshot.slot || clock.unix_timestamp <= 0 do
    return Err("public_collateral_clock_mismatch")
  end
  let now = U64.parse(Int.to_string(clock.unix_timestamp))?
  let pool_address = collateral_pda(pins.rewards, [Bytes.from_utf8("pool")])?
  if log.name != pins.log_name
    || log.version != pins.log_version
    || log.log_id != anchor.log_id
    || log.ring_address != anchor.ring.bytes
    || log.service_public_key != pins.service_key
    || economics.log_id != anchor.log_id
    || economics.usdc_mint != pins.usdc.bytes
    || config.governance != pins.token_governance
    || config.mint != pins.morse
    || U64.compare(config.started, now) > 0
    || pool.governance != pins.rewards_governance.bytes
    || pool.judge != pins.judge.bytes
    || pool.log != anchor.log.bytes
    || pool.log_id != anchor.log_id
    || pool.mint != pins.usdc.bytes
    || pool.network_started != pins.network_started
    || U64.compare(pool.network_started, now) > 0 do
    return Err("public_collateral_context_mismatch")
  end
  if binding.log != anchor.log.bytes
    || binding.log_id != anchor.log_id
    || binding.token_program != pins.token.bytes
    || binding.config != token.config.bytes
    || binding.mint != pins.morse.bytes
    || binding.oracle != token.oracle.bytes
    || binding.rewards_program != pins.rewards.bytes
    || binding.rewards_pool != pool_address.bytes
    || binding.activated_at == U64.parse("0")?
    || U64.compare(binding.activated_at, now) > 0 do
    return Err("public_collateral_binding_mismatch")
  end
  let spl = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let dollars = mint(collateral_required(snapshot, 4, spl, U64.parse("82")?, 82, false)?.info)?
  let morse = mint(collateral_required(snapshot, 5, spl, U64.parse("82")?, 82, false)?.info)?
  if !dollars.initialized
    || dollars.decimals != 6
    || !morse.initialized
    || morse.decimals != 6
    || morse.mint_authority != None
    || morse.freeze_authority != None
    || U64.compare(morse.supply, U64.parse("1000000000000000")?) > 0 do
    return Err("public_collateral_mint_mismatch")
  end
  let judge_slot = code(snapshot, pins.judge, 8, 9)?
  let token_slot = code(snapshot, pins.token, 10, 11)?
  let rewards_slot = code(snapshot, pins.rewards, 12, 13)?
  Ok(CollateralContext {
    slot: snapshot.slot,
    timestamp: now,
    code_current: judge_slot == pins.judge_slot
      && token_slot == pins.token_slot
      && rewards_slot == pins.rewards_slot
      && token_slot == binding.token_slot
      && rewards_slot == binding.rewards_slot,
    log: log,
    economics: economics,
    binding: binding,
    pool: pool
  })
end

pub fn collateral_digest(keys :: List<Pubkey>,
  snapshot :: OptionalAccountSlicesAtSlot,
  domain :: String) -> Bytes!String do
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
  let start = Bytes.concat(Bytes.from_utf8(domain),
    Bytes.write_uint_le(U64.to_string(snapshot.slot), 8)?)?
  let material = List.reduce(parts, Ok(start), fn(result, part) do Bytes.concat(result?, part) end)?
  Ok(Crypto.sha256(material))
end
