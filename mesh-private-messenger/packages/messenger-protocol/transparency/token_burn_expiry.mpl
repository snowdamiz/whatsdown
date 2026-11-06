# Raw byte validation and prepared instruction only; neither is chain proof.
from Solana.Read import Pubkey, pubkey
from Solana.Tx import AccountMeta
from Transparency.TokenBurn import decode_token_burn_profile
from Transparency.TokenBurnWrite import token_burn_addresses
from Transparency.TokenBurnCarryWrite import token_burn_carry_addresses
from Transparency.TokenChain import token_addresses
from Solana.Tx import Instruction
from Transparency.TokenBurn import TokenBurnProfile

pub struct TokenBurnUnfundedWeek do
  profile :: Pubkey
  config :: Pubkey
  usdc :: Pubkey
  treasury :: Pubkey
  epoch :: U64
  funding_deadline :: U64
  expired_at :: U64
  profile_hash :: Bytes
end

pub struct TokenBurnExpiryReceipt do
  profile :: Pubkey
  week :: Pubkey
  config :: Pubkey
  usdc :: Pubkey
  treasury :: Pubkey
  epoch :: U64
  funding_deadline :: U64
  expired_at :: U64
  profile_hash :: Bytes
  tombstone_hash :: Bytes
end

fn expiry_part(data :: Bytes, at :: Int, length :: Int) -> Bytes!String do
  Bytes.slice(data, at, length)
end

fn expiry_key(data :: Bytes, at :: Int) -> Pubkey!String do
  let key = expiry_part(data, at, 32)?
  if Bytes.to_hex(key) == String.repeat("00", 32) do
    return Err("invalid_burn_expiry_key")
  end
  Ok(Pubkey { bytes: key })
end

fn expiry_wide(data :: Bytes, at :: Int) -> U64!String do
  U64.parse(Bytes.read_uint_le(data, at, 8)?)
end

pub fn token_burn_expiry_deadline(epoch :: U64) -> U64!String do
  let value = U64.add(U64.multiply(epoch, U64.parse("604800")?)?, U64.parse("25200")?)?
  if U64.compare(value, U64.parse("9223372036854775807")?) > 0 do
    return Err("invalid_burn_expiry_epoch")
  end
  Ok(value)
end

fn expiry_time(epoch :: U64, deadline :: U64, expired :: U64) -> Result<(), String> do
  if deadline != token_burn_expiry_deadline(epoch)?
    || U64.compare(expired, deadline) < 0
    || U64.compare(expired, U64.parse("9223372036854775807")?) > 0 do
    return Err("invalid_burn_expiry_time")
  end
  Ok(nil)
end

pub fn decode_token_burn_unfunded_week(data :: Bytes) -> TokenBurnUnfundedWeek!String do
  if Bytes.length(data) != 192
    || Bytes.to_hex(expiry_part(data, 0, 4)?) != "4d425801"
    || Bytes.to_hex(expiry_part(data, 188, 4)?) != "00000000" do
    return Err("invalid_burn_unfunded_week")
  end
  let epoch = expiry_wide(data, 132)?
  let deadline = expiry_wide(data, 140)?
  let expired = expiry_wide(data, 148)?
  expiry_time(epoch, deadline, expired)?
  Ok(TokenBurnUnfundedWeek {
    profile: expiry_key(data, 4)?,
    config: expiry_key(data, 36)?,
    usdc: expiry_key(data, 68)?,
    treasury: expiry_key(data, 100)?,
    epoch: epoch,
    funding_deadline: deadline,
    expired_at: expired,
    profile_hash: expiry_part(data, 156, 32)?
  })
end

pub fn decode_token_burn_expiry_receipt(data :: Bytes) -> TokenBurnExpiryReceipt!String do
  if Bytes.length(data) != 256
    || Bytes.to_hex(expiry_part(data, 0, 4)?) != "4d425501"
    || Bytes.to_hex(expiry_part(data, 252, 4)?) != "00000000" do
    return Err("invalid_burn_expiry_receipt")
  end
  let epoch = expiry_wide(data, 164)?
  let deadline = expiry_wide(data, 172)?
  let expired = expiry_wide(data, 180)?
  expiry_time(epoch, deadline, expired)?
  Ok(TokenBurnExpiryReceipt {
    profile: expiry_key(data, 4)?,
    week: expiry_key(data, 36)?,
    config: expiry_key(data, 68)?,
    usdc: expiry_key(data, 100)?,
    treasury: expiry_key(data, 132)?,
    epoch: epoch,
    funding_deadline: deadline,
    expired_at: expired,
    profile_hash: expiry_part(data, 188, 32)?,
    tombstone_hash: expiry_part(data, 220, 32)?
  })
end

pub fn match_token_burn_unfunded(program :: Pubkey,
  raw_profile :: Bytes,
  epoch :: U64,
  raw_week :: Bytes,
  raw_receipt :: Bytes) -> TokenBurnUnfundedWeek!String do
  let profile = decode_token_burn_profile(raw_profile)?
  let addresses = token_burn_addresses(program, profile, epoch, 0)?
  let week = decode_token_burn_unfunded_week(raw_week)?
  let receipt = decode_token_burn_expiry_receipt(raw_receipt)?
  if week.profile != addresses.profile
    || week.config != profile.config
    || week.usdc != profile.usdc
    || week.treasury != profile.treasury
    || week.epoch != epoch
    || week.profile_hash != Crypto.sha256(raw_profile)
    || receipt.profile != week.profile
    || receipt.week != addresses.week
    || receipt.config != week.config
    || receipt.usdc != week.usdc
    || receipt.treasury != week.treasury
    || receipt.epoch != week.epoch
    || receipt.funding_deadline != week.funding_deadline
    || receipt.expired_at != week.expired_at
    || receipt.profile_hash != week.profile_hash
    || receipt.tombstone_hash != Crypto.sha256(raw_week) do
    return Err("burn_expiry_subject_mismatch")
  end
  Ok(week)
end

fn expiry_meta(key :: Pubkey, writable :: Bool) -> AccountMeta do
  AccountMeta { pubkey: key, signer: false, writable: writable }
end

pub fn token_burn_expire_instruction(program :: Pubkey,
  payer :: Pubkey,
  profile :: TokenBurnProfile,
  epoch :: U64) -> Instruction!String do
  if Bytes.length(payer.bytes) != 32 || Bytes.to_hex(payer.bytes) == String.repeat("00", 32) do
    return Err("invalid_burn_expiry_payer")
  end
  token_burn_expiry_deadline(epoch)?
  let token = token_addresses(program)?
  let addresses = token_burn_addresses(program, profile, epoch, 0)?
  let carry = token_burn_carry_addresses(program, profile.usdc, epoch)?
  Ok(Instruction {
    program_id: program,
    data: Bytes.concat(Bytes.from_hex("0f")?, Bytes.write_uint_le(U64.to_string(epoch), 8)?)?,
    accounts: [
      AccountMeta { pubkey: payer, signer: true, writable: true },
      expiry_meta(token.config, false),
      expiry_meta(token.mint, false),
      expiry_meta(addresses.profile, false),
      expiry_meta(addresses.week, true),
      expiry_meta(carry.receipt, true),
      expiry_meta(pubkey("11111111111111111111111111111111")?, false)
    ]
  })
end
