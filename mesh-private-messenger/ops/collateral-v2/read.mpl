##! Authenticated bounded finalized snapshots; no signing or submission.
from Accounts import (
  operator_required,
  operator_owned,
  operator_absent,
  operator_number,
  operator_code,
  operator_optional_vault,
  operator_snapshot_digest
)
from Solana.Read import (
  Pubkey,
  AccountSlice,
  OptionalAccountSlicesAtSlot,
  pubkey,
  mint,
  clock_sysvar,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  rpc_send
)
from Transparency.TokenCollateralWrite import (
  TokenCollateralContext,
  TokenCollateralSubject,
  collateral_public_key,
  token_collateral_addresses,
  token_collateral_subject
)
from Transparency.TokenCustody import (
  TokenCollateralEconomics,
  TokenCollateralBinding,
  TokenCollateralBond,
  TokenCollateralPending,
  decode_token_collateral_economics,
  decode_token_collateral_binding,
  decode_token_collateral_bond,
  decode_token_collateral_pending
)
from Transparency.AnchorBond import decode_anchor_economics, decode_anchor_bond
from Transparency.AnchorRpc import validate_anchor_sources
from Transparency.AnchorLog import AnchorLog, decode_anchor_log
from Transparency.TokenChain import (
  decode_token_config,
  decode_token_oracle,
  token_oracle_twap,
  token_payout_address
)
from Transparency.RewardsChain import RewardPoolAccount, decode_reward_pool
from Transparency.TokenRewards import decode_token_reward_usdc_pool

pub struct CollateralOperatorPins do
  context :: TokenCollateralContext
  governance :: Pubkey
  service_key :: Bytes
  log_version :: Int
  network_started :: U64
  judge_slot :: U64
  token_slot :: U64
  rewards_slot :: U64
  source_program :: Pubkey
  source :: Pubkey
  feed :: Bytes
  source_revision :: U64
end

pub struct CollateralOperatorState do
  slot :: U64
  timestamp :: U64
  digest :: Bytes
  selection :: Bytes
  log :: AnchorLog
  economics :: TokenCollateralEconomics
  legacy_economics :: Bool
  binding :: Option<TokenCollateralBinding>
  pool :: RewardPoolAccount
  oracle_current :: Bool
  binding_current :: Bool
  binding_release_current :: Bool
  oracle_twap :: Option<U64>
  twap :: Option<U64>
  directory :: Option<TokenCollateralBond>
  directory_pending :: Option<TokenCollateralPending>
  bond :: Option<TokenCollateralBond>
  legacy_bond :: Bool
  pending :: Option<TokenCollateralPending>
  subject_owner :: Bytes
  registry_status :: Int
  usdc_balance :: U64
  morse_balance :: U64
  source_usdc :: U64
  source_morse :: U64
end

pub fn validate_collateral_operator_pins(pins :: CollateralOperatorPins) -> Bool!String do
  token_collateral_addresses(pins.context)?
  for key in [pins.governance, pins.source_program, pins.source] do
    if !collateral_public_key(key) do
      return Err("collateral_operator_pins")
    end
  end
  if Bytes.length(pins.service_key) != 32
    || Bytes.to_hex(pins.service_key) == String.repeat("00", 32)
    || Bytes.length(pins.feed) != 32
    || Bytes.to_hex(pins.feed) == String.repeat("00", 32)
    || (pins.log_version != 1 && pins.log_version != 2)
    || pins.network_started == U64.parse("0")?
    || pins.source_revision == U64.parse("0")? do
    return Err("collateral_operator_pins")
  end
  Ok(true)
end

# Exactly27 roles. Duplicated directory roles are intentional for one uniform API.
pub fn collateral_operator_keys(pins :: CollateralOperatorPins,
  subject :: TokenCollateralSubject,
  operator :: Pubkey) -> List<Pubkey>!String do
  validate_collateral_operator_pins(pins)?
  if !collateral_public_key(operator) do
    return Err("collateral_operator_owner")
  end
  let c = pins.context
  let a = token_collateral_addresses(c)?
  let d = token_collateral_subject(c, CollateralDirectory, 0)?
  let dm = token_collateral_subject(c, CollateralDirectory, 1)?
  let s = token_collateral_subject(c, subject, 0)?
  let sm = token_collateral_subject(c, subject, 1)?
  Ok([
    a.judge_config,
    a.log,
    a.economics,
    a.binding,
    a.token_config,
    c.usdc_mint,
    a.morse_mint,
    a.oracle,
    a.pool,
    pubkey("SysvarC1ock11111111111111111111111111111111")?,
    c.judge,
    a.judge_data,
    c.token,
    a.token_data,
    c.rewards,
    a.rewards_data,
    d.bond,
    d.pending,
    d.vault,
    dm.vault,
    case s.witness do
      Some(value) -> value
      None -> a.log
    end,
    s.bond,
    s.pending,
    s.vault,
    sm.vault,
    token_payout_address(operator, c.usdc_mint)?,
    token_payout_address(operator, a.morse_mint)?
  ])
end

fn economics(raw :: Bytes) -> TokenCollateralEconomics!String do
  if Bytes.get(raw, 3)? == 2 do
    return decode_token_collateral_economics(raw)
  end
  let v = decode_anchor_economics(raw)?
  Ok(TokenCollateralEconomics {
    log_id: v.log_id,
    usdc_mint: v.mint,
    directory_owner: v.directory_owner,
    witness_target_usd: v.minimum_witness,
    directory_target_usd: v.minimum_directory,
    ready_at: v.ready_at,
    pending_witness_usd: v.pending_witness,
    pending_directory_usd: v.pending_directory,
    pending_ready: v.pending_ready,
    witness_usdc: v.witness_principal,
    directory_usdc: v.directory_principal,
    directory_status: v.directory_status,
    directory_asset: 0,
    revision: v.eligibility_revision,
    witness_morse: U64.parse("0")?,
    directory_morse: U64.parse("0")?
  })
end

fn bond(raw :: Bytes) -> TokenCollateralBond!String do
  if Bytes.get(raw, 3)? == 2 do
    return decode_token_collateral_bond(raw)
  end
  let v = decode_anchor_bond(raw)?
  Ok(TokenCollateralBond {
    asset: 0,
    status: v.status,
    witness: v.kind == 1,
    log_id: v.log_id,
    witness_address: v.witness,
    owner: v.owner,
    mint: v.mint,
    vault: v.vault,
    principal: v.principal,
    bonded_at: v.bonded_at,
    unbond_at: v.unbond_at,
    slashed_at: v.slashed_at,
    underwater_since: U64.parse("0")?
  })
end

pub fn decode_operator_bond(pins :: CollateralOperatorPins,
  snapshot :: OptionalAccountSlicesAtSlot,
  subject :: TokenCollateralSubject,
  index :: Int,
  now :: U64) -> Option<TokenCollateralBond>!String do
  if operator_absent(List.get(snapshot.accounts, index)) do
    return Ok(None)
  end
  let raw = operator_owned(snapshot, index, pins.context.judge, 208)?
  let value = bond(raw)?
  let s = token_collateral_subject(pins.context, subject, value.asset)?
  let a = token_collateral_addresses(pins.context)?
  let witness = case s.witness do
    None -> Bytes.from_hex(String.repeat("00", 32))?
    Some(key) -> key.bytes
  end
  if value.log_id != a.log_id
    || value.witness_address != witness
    || value.witness != (s.witness != None)
    || value.mint != s.mint.bytes
    || value.vault != s.vault.bytes
    || U64.compare(value.bonded_at, now) > 0
    || U64.compare(value.unbond_at, now) > 0
    || U64.compare(value.slashed_at, now) > 0
    || U64.compare(value.underwater_since, now) > 0 do
    return Err("collateral_operator_bond_binding")
  end
  Ok(Some(value))
end

pub fn decode_operator_pending(pins :: CollateralOperatorPins,
  snapshot :: OptionalAccountSlicesAtSlot,
  subject :: TokenCollateralSubject,
  index :: Int,
  value :: Option<TokenCollateralBond>,
  now :: U64) -> Option<TokenCollateralPending>!String do
  if operator_absent(List.get(snapshot.accounts, index)) do
    case value do
      Some(v) -> if v.asset == 1 do
        return Err("collateral_operator_pending_missing")
      end
      None -> nil
    end
    return Ok(None)
  end
  let b = case value do
    None -> return Err("collateral_operator_orphan_pending")
    Some(v) -> v
  end
  let p = decode_token_collateral_pending(operator_owned(snapshot, index, pins.context.judge, 96)?)?
  let s = token_collateral_subject(pins.context, subject, b.asset)?
  if p.bond != s.bond.bytes
    || p.mint != s.mint.bytes
    || U64.compare(p.opened_at, now) > 0
    || (b.asset == 0 && p.target_usd != U64.parse("0")?)
    || (b.asset == 1 && p.target_usd == U64.parse("0")?) do
    return Err("collateral_operator_pending_binding")
  end
  Ok(Some(p))
end

pub fn decode_collateral_operator_unpriced_snapshot(pins :: CollateralOperatorPins,
  subject :: TokenCollateralSubject,
  operator :: Pubkey,
  minimum :: U64,
  reference_time :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> CollateralOperatorState!String do
  let keys = collateral_operator_keys(pins, subject, operator)?
  if List.length(snapshot.accounts) != 27 || U64.compare(snapshot.slot, minimum) < 0 do
    return Err("collateral_operator_snapshot")
  end
  let c = pins.context
  let a = token_collateral_addresses(c)?
  let zero = U64.parse("0")?
  let config = operator_owned(snapshot, 0, c.judge, 40)?
  if Bytes.to_hex(Bytes.slice(config, 0, 4)?) != "4d434601"
    || Bytes.slice(config, 4, 32)? != pins.governance.bytes
    || Bytes.to_hex(Bytes.slice(config, 36, 4)?) != "00000000" do
    return Err("collateral_operator_governance")
  end
  let clock = clock_sysvar(operator_required(snapshot,
    9,
    pubkey("Sysvar1111111111111111111111111111111111111")?,
    U64.parse("40")?,
    40,
    false)?.info)?
  if clock.slot != snapshot.slot || clock.unix_timestamp <= 0 do
    return Err("collateral_operator_clock")
  end
  let now = U64.parse(Int.to_string(clock.unix_timestamp))?
  if U64.compare(now, reference_time) > 0
    || U64.compare(U64.subtract(reference_time, now)?, U64.parse("300")?) > 0 do
    return Err("collateral_operator_stale")
  end
  let log = decode_anchor_log(operator_owned(snapshot, 1, c.judge, 352)?)?
  let eraw = operator_owned(snapshot, 2, c.judge, 192)?
  let e = economics(eraw)?
  let token = decode_token_config(operator_owned(snapshot, 4, c.token, 320)?)?
  let pool_raw = operator_owned(snapshot, 8, c.rewards, 304)?
  let pool = if Bytes.get(pool_raw, 3)? == 2 do
    decode_token_reward_usdc_pool(pool_raw)?
  else
    decode_reward_pool(pool_raw)?
  end
  if log.log_id != a.log_id
    || log.name != c.log_name
    || log.version != pins.log_version
    || log.service_public_key != pins.service_key
    || log.ring_address != a.ring.bytes
    || e.log_id != a.log_id
    || e.usdc_mint != c.usdc_mint.bytes
    || token.governance != pins.governance
    || token.mint != a.morse_mint
    || U64.compare(token.started, now) > 0
    || pool.governance != pins.governance.bytes
    || pool.judge != c.judge.bytes
    || pool.log != a.log.bytes
    || pool.log_id != a.log_id
    || pool.mint != c.usdc_mint.bytes
    || pool.network_started != pins.network_started
    || U64.compare(pool.network_started, now) > 0 do
    return Err("collateral_operator_context")
  end
  let spl = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let usd = mint(operator_required(snapshot, 5, spl, U64.parse("82")?, 82, false)?.info)?
  let morse = mint(operator_required(snapshot, 6, spl, U64.parse("82")?, 82, false)?.info)?
  if !usd.initialized
    || usd.decimals != 6
    || !morse.initialized
    || morse.decimals != 6
    || morse.mint_authority != None
    || morse.freeze_authority != None
    || U64.compare(morse.supply, U64.parse("1000000000000000")?) > 0 do
    return Err("collateral_operator_mint")
  end
  if operator_code(snapshot, c.judge, 10, 11)? != pins.judge_slot
    || operator_code(snapshot, c.token, 12, 13)? != pins.token_slot
    || operator_code(snapshot, c.rewards, 14, 15)? != pins.rewards_slot do
    return Err("collateral_operator_code_changed")
  end
  let oraw = operator_owned(snapshot, 7, c.token, 5728)?
  let oracle = decode_token_oracle(oraw)?
  if oracle.config != a.token_config
    || oracle.mint != a.morse_mint
    || U64.compare(oracle.last_slot, snapshot.slot) > 0 do
    return Err("collateral_operator_oracle_binding")
  end
  let binding = if operator_absent(List.get(snapshot.accounts, 3)) do
    None
  else
    let b = decode_token_collateral_binding(operator_owned(snapshot, 3, c.judge, 320)?)?
    if b.log != a.log.bytes
      || b.log_id != a.log_id
      || b.token_program != c.token.bytes
      || b.config != a.token_config.bytes
      || b.mint != a.morse_mint.bytes
      || b.oracle != a.oracle.bytes
      || b.rewards_program != c.rewards.bytes
      || b.rewards_pool != a.pool.bytes
      || U64.compare(b.token_slot, snapshot.slot) > 0
      || U64.compare(b.rewards_slot, snapshot.slot) > 0
      || U64.compare(b.activated_at, now) > 0 do
      return Err("collateral_operator_binding")
    end
    Some(b)
  end
  if (Bytes.get(eraw, 3)? == 2) != (case binding do
      None -> false
      Some(b) -> b.activated_at != zero
    end) do
    return Err("collateral_operator_activation_mismatch")
  end
  let oracle_current = oracle.receiver == pins.source_program
    && oracle.source == pins.source
    && oracle.feed == pins.feed
    && oracle.revision == pins.source_revision
  let binding_current = case binding do
    None -> true
    Some(b) -> b.token_slot == pins.token_slot
      && b.rewards_slot == pins.rewards_slot
      && b.source_revision == pins.source_revision
  end
  let binding_release_current = case binding do
    None -> true
    Some(b) -> b.token_slot == pins.token_slot && b.rewards_slot == pins.rewards_slot
  end
  let current_twap = if oracle_current do
    case token_oracle_twap(oraw, now) do
      Ok(price) -> Some(price)
      Err(_) -> None
    end
  else
    None
  end
  let directory = decode_operator_bond(pins, snapshot, CollateralDirectory, 16, now)?
  let dp = decode_operator_pending(pins, snapshot, CollateralDirectory, 17, directory, now)?
  case directory do
    None -> if e.directory_status != 0 || e.directory_usdc != zero || e.directory_morse != zero do
      return Err("collateral_operator_directory_missing")
    end
    Some(d) -> if d.owner != e.directory_owner
      || d.status != e.directory_status
      || d.asset != e.directory_asset
      || d.principal != (if d.asset == 0 do
          e.directory_usdc
        else
          e.directory_morse
        end)
      || log.directory_bond_vault != d.vault
      || log.service_slashed != (d.status == 3) do
      return Err("collateral_operator_directory_binding")
    end
  end
  let b = decode_operator_bond(pins, snapshot, subject, 21, now)?
  let pending = decode_operator_pending(pins, snapshot, subject, 22, b, now)?
  let record_owner = case subject do
    CollateralDirectory -> e.directory_owner
    CollateralWitness(key) ->
      let raw = operator_owned(snapshot, 20, c.judge, 320)?
      let len = Bytes.get(raw, 4)?
      if Bytes.to_hex(Bytes.slice(raw, 0, 4)?) != "4d574901"
        || len != String.length(key.witness_id)
        || Bytes.to_utf8(Bytes.slice(raw, 8, len)?)? != key.witness_id
        || Bytes.to_hex(Bytes.slice(raw, 8 + len, 64 - len)?) != String.repeat("00", 64 - len)
        || Bytes.slice(raw, 72, 32)? != key.public_key
        || Bytes.get(raw, 5)? > 4
        || Bytes.get(raw, 6)? > 1
        || Bytes.get(raw, 7)? != 0
        || Bytes.slice(raw, 200, 32)? != a.log_id
        || Bytes.to_hex(Bytes.slice(raw, 272, 48)?) != String.repeat("00", 48) do
        return Err("collateral_operator_registry")
      end
      case b do
        None -> if Bytes.get(raw, 5)? != 0 do
          return Err("collateral_operator_registry_bond_missing")
        end
        Some(v) -> if Bytes.get(raw, 5)? != v.status
          || Bytes.slice(raw, 104, 32)? != v.owner
          || Bytes.slice(raw, 232, 32)? != v.vault
          || operator_number(raw, 264)? != v.unbond_at do
          return Err("collateral_operator_registry_bond")
        end
      end
      Bytes.slice(raw, 104, 32)?
  end
  let sa = token_collateral_subject(c, subject, 0)?
  let usa = operator_optional_vault(snapshot, 23, c.usdc_mint, sa.bond)?
  let msa = operator_optional_vault(snapshot, 24, a.morse_mint, sa.bond)?
  # Validate both directory ATAs even when selecting a witness.
  let dua = operator_optional_vault(snapshot,
    18,
    c.usdc_mint,
    token_collateral_subject(c, CollateralDirectory, 0)?.bond)?
  let dma = operator_optional_vault(snapshot,
    19,
    a.morse_mint,
    token_collateral_subject(c, CollateralDirectory, 0)?.bond)?
  case directory do
    Some(v) -> if U64.compare(if v.asset == 0 do
        dua
      else
        dma
      end,
      if v.status == 1 || v.status == 2 do
        U64.add(v.principal,
          case dp do
            None -> zero
            Some(p) -> p.amount
          end)?
      else
        zero
      end) < 0 do
      return Err("collateral_operator_directory_underfunded")
    end
    None -> nil
  end
  case b do
    Some(v) ->
      let liability = if v.status == 1 || v.status == 2 do
        U64.add(v.principal,
          case pending do
            None -> zero
            Some(p) -> p.amount
          end)?
      else
        zero
      end
      if U64.compare(if v.asset == 0 do
          usa
        else
          msa
        end,
        liability) < 0 do
        return Err("collateral_operator_underfunded")
      end
    None -> nil
  end
  Ok(CollateralOperatorState {
    slot: snapshot.slot,
    timestamp: now,
    digest: operator_snapshot_digest(keys, snapshot)?,
    selection: collateral_selection_digest(pins, subject, operator)?,
    log: log,
    economics: e,
    legacy_economics: Bytes.get(eraw, 3)? == 1,
    binding: binding,
    pool: pool,
    oracle_current: oracle_current,
    binding_current: binding_current,
    binding_release_current: binding_release_current,
    oracle_twap: current_twap,
    twap: if binding_current do
      current_twap
    else
      None
    end,
    directory: directory,
    directory_pending: dp,
    bond: b,
    legacy_bond: if operator_absent(List.get(snapshot.accounts, 21)) do
      false
    else
      Bytes.get(operator_owned(snapshot, 21, c.judge, 208)?, 3)? == 1
    end,
    pending: pending,
    subject_owner: record_owner,
    registry_status: case b do
      None -> 0
      Some(v) -> v.status
    end,
    usdc_balance: usa,
    morse_balance: msa,
    source_usdc: operator_optional_vault(snapshot, 25, c.usdc_mint, operator)?,
    source_morse: operator_optional_vault(snapshot, 26, a.morse_mint, operator)?
  })
end

fn read_one(client :: Int,
  url :: String,
  pins :: CollateralOperatorPins,
  subject :: TokenCollateralSubject,
  operator :: Pubkey,
  minimum :: U64,
  now :: U64) -> CollateralOperatorState!String do
  let request = get_multiple_accounts_slice_request(1,
    collateral_operator_keys(pins, subject, operator)?,
    "finalized",
    0,
    9216,
    Some(minimum))?
  decode_collateral_operator_unpriced_snapshot(pins,
    subject,
    operator,
    minimum,
    now,
    optional_accounts_slice_from_response(rpc_send(client, url, request, 5000, 1048576)?)?)
end

# A caller supplies three configured distinct origins, never response redirects.
# Every accepted pair agrees on bank slot as well as all selected roles.
pub fn read_collateral_operator_unpriced(client :: Int,
  sources :: List<String>,
  pins :: CollateralOperatorPins,
  subject :: TokenCollateralSubject,
  operator :: Pubkey,
  minimum :: U64) -> CollateralOperatorState!String do
  validate_collateral_operator_sources(sources)?
  let now = U64.parse(Int.to_string(DateTime.to_unix_secs(DateTime.utc_now())))?
  let a = read_one(client, List.get(sources, 0), pins, subject, operator, minimum, now)
  let b = read_one(client, List.get(sources, 1), pins, subject, operator, minimum, now)
  let c = read_one(client, List.get(sources, 2), pins, subject, operator, minimum, now)
  collateral_operator_freshness(collateral_operator_quorum(a, b, c)?,
    U64.parse(Int.to_string(DateTime.to_unix_secs(DateTime.utc_now())))?)
end

pub fn collateral_operator_quorum(a :: CollateralOperatorState!String,
  b :: CollateralOperatorState!String,
  c :: CollateralOperatorState!String) -> CollateralOperatorState!String do
  for pair in [(a, b), (a, c), (b, c)] do
    case pair do
      (Ok(x), Ok(y)) -> if x.digest == y.digest && x.selection == y.selection do
        return Ok(x)
      end
      _ -> nil
    end
  end
  Err("collateral_operator_quorum_unavailable_or_disagreed")
end

pub fn collateral_selection_digest(pins :: CollateralOperatorPins,
  subject :: TokenCollateralSubject,
  operator :: Pubkey) -> Bytes!String do
  let keys = collateral_operator_keys(pins, subject, operator)?
  let body = List.reduce(keys,
    Ok(Bytes.empty()),
    fn(result, key) do Bytes.concat(result?, key.bytes) end)?
  let fields = [
    pins.governance.bytes,
    pins.service_key,
    Bytes.write_uint_le(Int.to_string(pins.log_version), 1)?,
    Bytes.write_uint_le(U64.to_string(pins.network_started), 8)?,
    Bytes.write_uint_le(U64.to_string(pins.judge_slot), 8)?,
    Bytes.write_uint_le(U64.to_string(pins.token_slot), 8)?,
    Bytes.write_uint_le(U64.to_string(pins.rewards_slot), 8)?,
    pins.source_program.bytes,
    pins.source.bytes,
    pins.feed,
    Bytes.write_uint_le(U64.to_string(pins.source_revision), 8)?
  ]
  Ok(Crypto.sha256(List.reduce(fields,
    Ok(body),
    fn(result, value) do Bytes.concat(result?, value) end)?))
end

pub fn validate_collateral_operator_sources(sources :: List<String>) -> Bool!String do
  if List.length(sources) != 3 do
    return Err("collateral_operator_sources")
  end
  case validate_anchor_sources(sources) do
    Err(_) -> return Err("collateral_operator_sources")
    Ok(_) -> nil
  end
  for source in sources do
    let origin = case Http.url_origin(source) do
      Err(_) -> return Err("collateral_operator_sources")
      Ok(value) -> value
    end
    if source != origin do
      return Err("collateral_operator_sources")
    end
  end
  Ok(true)
end

# Re-check at completion: slow/disagreeing providers cannot extend the age bound.
pub fn collateral_operator_freshness(value :: CollateralOperatorState,
  reference_time :: U64) -> CollateralOperatorState!String do
  if U64.compare(value.timestamp, reference_time) > 0
    || U64.compare(U64.subtract(reference_time, value.timestamp)?, U64.parse("300")?) > 0 do
    return Err("collateral_operator_stale")
  end
  Ok(value)
end

pub fn decode_collateral_operator_snapshot(pins :: CollateralOperatorPins,
  subject :: TokenCollateralSubject,
  operator :: Pubkey,
  minimum :: U64,
  reference_time :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> CollateralOperatorState!String do
  let result = decode_collateral_operator_unpriced_snapshot(pins,
    subject,
    operator,
    minimum,
    reference_time,
    snapshot)?
  if !result.oracle_current || !result.binding_current do
    return Err("collateral_operator_oracle_binding")
  end
  Ok(result)
end

pub fn read_collateral_operator(client :: Int,
  sources :: List<String>,
  pins :: CollateralOperatorPins,
  subject :: TokenCollateralSubject,
  operator :: Pubkey,
  minimum :: U64) -> CollateralOperatorState!String do
  let value = read_collateral_operator_unpriced(client, sources, pins, subject, operator, minimum)?
  if !value.oracle_current || !value.binding_current do
    return Err("collateral_operator_oracle_binding")
  end
  Ok(value)
end
