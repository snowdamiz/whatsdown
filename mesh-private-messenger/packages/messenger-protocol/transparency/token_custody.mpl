from Solana.Read import Pubkey
from Solana.Address import find_program_address

# Explicit v2 units. Raw decoders never confer owner/PDA/finality authenticity.
pub struct TokenCollateralBond do
  asset :: Int
  status :: Int
  witness :: Bool
  log_id :: Bytes
  witness_address :: Bytes
  owner :: Bytes
  mint :: Bytes
  vault :: Bytes
  principal :: U64
  bonded_at :: U64
  unbond_at :: U64
  slashed_at :: U64
  underwater_since :: U64
end

pub fn decode_token_collateral_bond(bytes :: Bytes) -> TokenCollateralBond!String do
  if !header(bytes, 208, "4d424402")? || !zeroes(bytes, 7, 1)? do
    return Err("invalid_token_collateral")
  end
  let status = Bytes.get(bytes, 4)?
  let kind = Bytes.get(bytes, 5)?
  let asset = Bytes.get(bytes, 6)?
  if status < 1 || status > 4 || kind > 1 || asset > 1 do
    return Err("invalid_token_collateral")
  end
  for offset in [8, 72, 104, 136] do
    if zeroes(bytes, offset, 32)? do
      return Err("invalid_token_collateral")
    end
  end
  if (kind == 1) == zeroes(bytes, 40, 32)? do
    return Err("invalid_token_collateral")
  end
  let value = TokenCollateralBond {
    asset: asset,
    status: status,
    witness: kind == 1,
    log_id: part(bytes, 8, 32)?,
    witness_address: part(bytes, 40, 32)?,
    owner: part(bytes, 72, 32)?,
    mint: part(bytes, 104, 32)?,
    vault: part(bytes, 136, 32)?,
    principal: wide(bytes, 168)?,
    bonded_at: time(bytes, 176)?,
    unbond_at: time(bytes, 184)?,
    slashed_at: time(bytes, 192)?,
    underwater_since: time(bytes, 200)?
  }
  let zero = U64.parse("0")?
  if value.bonded_at == zero
    || (asset == 0 && value.underwater_since != zero)
    || (asset == 1 && U64.compare(value.principal, U64.parse("1000000000000000")?) > 0)
    || (value.underwater_since != zero && U64.compare(value.underwater_since, value.bonded_at) < 0)
    || ((status == 1 || status == 2) && value.principal == zero)
    || ((status == 3 || status == 4) && value.principal != zero)
    || (status == 1 && (value.unbond_at != zero || value.slashed_at != zero))
    || ((status == 2 || status == 4)
      && (U64.compare(value.unbond_at, value.bonded_at) < 0 || value.slashed_at != zero))
    || (status == 3 && U64.compare(value.slashed_at, value.bonded_at) < 0) do
    return Err("invalid_token_collateral")
  end
  Ok(value)
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
    Err("invalid_token_collateral")
  else
    Ok(value)
  end
end

pub struct TokenCollateralEconomics do
  log_id :: Bytes
  usdc_mint :: Bytes
  directory_owner :: Bytes
  witness_target_usd :: U64
  directory_target_usd :: U64
  ready_at :: U64
  pending_witness_usd :: U64
  pending_directory_usd :: U64
  pending_ready :: U64
  witness_usdc :: U64
  directory_usdc :: U64
  directory_status :: Int
  directory_asset :: Int
  revision :: U64
  witness_morse :: U64
  directory_morse :: U64
end

pub fn decode_token_collateral_economics(bytes :: Bytes) -> TokenCollateralEconomics!String do
  if !header(bytes, 192, "4d454302")? || !zeroes(bytes, 166, 2)? do
    return Err("invalid_token_collateral")
  end
  for offset in [4, 36, 68] do
    if zeroes(bytes, offset, 32)? do
      return Err("invalid_token_collateral")
    end
  end
  let value = TokenCollateralEconomics {
    log_id: part(bytes, 4, 32)?,
    usdc_mint: part(bytes, 36, 32)?,
    directory_owner: part(bytes, 68, 32)?,
    witness_target_usd: wide(bytes, 100)?,
    directory_target_usd: wide(bytes, 108)?,
    ready_at: time(bytes, 116)?,
    pending_witness_usd: wide(bytes, 124)?,
    pending_directory_usd: wide(bytes, 132)?,
    pending_ready: time(bytes, 140)?,
    witness_usdc: wide(bytes, 148)?,
    directory_usdc: wide(bytes, 156)?,
    directory_status: Bytes.get(bytes, 164)?,
    directory_asset: Bytes.get(bytes, 165)?,
    revision: wide(bytes, 168)?,
    witness_morse: wide(bytes, 176)?,
    directory_morse: wide(bytes, 184)?
  }
  let zero = U64.parse("0")?
  if value.witness_target_usd == zero
    || U64.compare(value.directory_target_usd, value.witness_target_usd) < 0
    || value.directory_status > 4
    || value.directory_asset > 1
    || (value.pending_ready == zero
      && (value.pending_witness_usd != zero || value.pending_directory_usd != zero))
    || (value.pending_ready != zero
      && (value.pending_witness_usd == zero
        || U64.compare(value.pending_directory_usd, value.pending_witness_usd) < 0))
    || U64.compare(U64.add(value.witness_morse, value.directory_morse)?,
      U64.parse("1000000000000000")?) > 0
    || (value.directory_asset == 0 && value.directory_morse != zero)
    || (value.directory_asset == 1 && value.directory_usdc != zero)
    || ((value.directory_status == 1 || value.directory_status == 2)
      && value.directory_usdc == zero
      && value.directory_morse == zero)
    || ((value.directory_status == 0 || value.directory_status == 3 || value.directory_status == 4)
      && (value.directory_usdc != zero || value.directory_morse != zero)) do
    return Err("invalid_token_collateral")
  end
  Ok(value)
end

pub struct TokenCollateralPending do
  bond :: Bytes
  mint :: Bytes
  amount :: U64
  opened_at :: U64
  target_usd :: U64
end

pub fn decode_token_collateral_pending(bytes :: Bytes) -> TokenCollateralPending!String do
  if !header(bytes, 96, "4d425002")?
    || !zeroes(bytes, 92, 4)?
    || zeroes(bytes, 4, 32)?
    || zeroes(bytes, 36, 32)? do
    return Err("invalid_token_collateral")
  end
  let value = TokenCollateralPending {
    bond: part(bytes, 4, 32)?,
    mint: part(bytes, 36, 32)?,
    amount: wide(bytes, 68)?,
    opened_at: time(bytes, 76)?,
    target_usd: wide(bytes, 84)?
  }
  let zero = U64.parse("0")?
  if (value.amount == zero) != (value.opened_at == zero) do
    return Err("invalid_token_collateral")
  end
  Ok(value)
end

pub struct TokenCollateralBinding do
  log :: Bytes
  log_id :: Bytes
  token_program :: Bytes
  config :: Bytes
  mint :: Bytes
  oracle :: Bytes
  rewards_program :: Bytes
  rewards_pool :: Bytes
  ready_at :: U64
  activated_at :: U64
  activated_epoch :: U64
  token_slot :: U64
  rewards_slot :: U64
  source_revision :: U64
end

pub fn decode_token_collateral_binding(bytes :: Bytes) -> TokenCollateralBinding!String do
  if !header(bytes, 320, "4d4a4202")? || !zeroes(bytes, 308, 12)? do
    return Err("invalid_token_collateral")
  end
  for offset in [4, 36, 68, 100, 132, 164, 196, 228] do
    if zeroes(bytes, offset, 32)? do
      return Err("invalid_token_collateral")
    end
  end
  let value = TokenCollateralBinding {
    log: part(bytes, 4, 32)?,
    log_id: part(bytes, 36, 32)?,
    token_program: part(bytes, 68, 32)?,
    config: part(bytes, 100, 32)?,
    mint: part(bytes, 132, 32)?,
    oracle: part(bytes, 164, 32)?,
    rewards_program: part(bytes, 196, 32)?,
    rewards_pool: part(bytes, 228, 32)?,
    ready_at: time(bytes, 260)?,
    activated_at: time(bytes, 268)?,
    activated_epoch: wide(bytes, 276)?,
    token_slot: wide(bytes, 284)?,
    rewards_slot: wide(bytes, 292)?,
    source_revision: wide(bytes, 300)?
  }
  let zero = U64.parse("0")?
  if value.ready_at == zero
    || value.source_revision == zero
    || value.token_program == value.rewards_program
    || (value.activated_at == zero && value.activated_epoch != zero)
    || (value.activated_at != zero
      && (U64.compare(value.activated_at, value.ready_at) < 0
        || value.activated_epoch != U64.divide(value.activated_at, U64.parse("604800")?)?)) do
    return Err("invalid_token_collateral")
  end
  Ok(value)
end

pub fn token_binding_address(judge :: Pubkey, log_id :: Bytes) -> Pubkey!String do
  if Bytes.length(log_id) != 32 do
    return Err("invalid_token_collateral")
  end
  Ok(find_program_address(judge, [Bytes.from_utf8("token-binding"), log_id])?.address)
end

pub fn token_pending_address(judge :: Pubkey, bond :: Pubkey) -> Pubkey!String do
  Ok(find_program_address(judge, [Bytes.from_utf8("bond-pending"), bond.bytes])?.address)
end
