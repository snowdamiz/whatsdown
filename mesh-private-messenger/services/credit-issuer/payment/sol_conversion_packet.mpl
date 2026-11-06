from Solana.Read import Pubkey, Hash, pubkey
from Solana.Address import find_program_address
from Solana.Tx import (
  AccountMeta,
  Instruction,
  LegacyMessage,
  compile_legacy_message,
  serialize_legacy_message,
  compute_unit_limit_instruction
)
from Solana.TransactionRead import signed_transaction, SignedTransaction

pub struct SolConversionProfile do
  treasury_config :: Bytes
  owner :: Pubkey
  payer :: Pubkey
  usdc :: Pubkey
  pool :: Pubkey
  amm_config :: Pubkey
  authority :: Pubkey
  input_vault :: Pubkey
  output_vault :: Pubkey
  observation :: Pubkey
  oracle :: Pubkey
  amm_hash :: Bytes
  raydium_code :: Bytes
  token_code :: Bytes
  rent :: U64
  maximum_fee :: U64
end

pub struct SolConversionPacket do
  intent_id :: Bytes
  profile_hash :: Bytes
  lamports :: U64
  minimum :: U64
  blockhash :: Hash
  message :: Bytes
end

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(total, value) do Bytes.concat(total?, value) end)
end

fn wide(value :: U64) -> Bytes!String do
  Bytes.write_uint_le(U64.to_string(value), 8)
end

pub fn conversion_token_program() -> Pubkey!String do
  pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
end

pub fn conversion_native_mint() -> Pubkey!String do
  pubkey("So11111111111111111111111111111111111111112")
end

pub fn conversion_raydium_program() -> Pubkey!String do
  pubkey("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C")
end

pub fn conversion_destination(profile :: SolConversionProfile) -> Pubkey!String do
  Ok(find_program_address(pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?,
    [profile.owner.bytes, conversion_token_program()?.bytes, profile.usdc.bytes])?.address)
end

fn before(a :: Bytes, b :: Bytes, at :: Int) -> Bool!String do
  if at == 32 do
    Ok(false)
  else if Bytes.get(a, at)? == Bytes.get(b, at)? do
    before(a, b, at + 1)
  else
    Ok(Bytes.get(a, at)? < Bytes.get(b, at)?)
  end
end

# Profile acceptance validates the complete static role graph. Runtime admission
# additionally authenticates actual account/code bytes in one finalized bank.
pub fn sol_conversion_profile_hash(profile :: SolConversionProfile) -> Bytes!String do
  let keys = [
    profile.owner,
    profile.payer,
    profile.usdc,
    profile.pool,
    profile.amm_config,
    profile.authority,
    profile.input_vault,
    profile.output_vault,
    profile.observation,
    profile.oracle
  ]
  let native = conversion_native_mint()?
  let ray = conversion_raydium_program()?
  for index in 0..List.length(keys) do
    let key = List.get(keys, index).bytes
    if Bytes.length(key) != 32
      || Bytes.to_hex(key) == String.repeat("00", 32)
      || List.any(List.take(keys, index), fn(prior) do prior.bytes == key end)
      || key == native.bytes
      || key == conversion_token_program()?.bytes
      || key == ray.bytes do
      return Err("invalid_sol_conversion_profile")
    end
  end
  for digest in [
    profile.treasury_config,
    profile.raydium_code,
    profile.token_code,
    profile.amm_hash
  ] do
    if Bytes.length(digest) != 32 || Bytes.to_hex(digest) == String.repeat("00", 32) do
      return Err("invalid_sol_conversion_profile")
    end
  end
  if U64.compare(profile.rent, U64.parse("1000000")?) < 0
    || U64.compare(profile.rent, U64.parse("10000000")?) > 0
    || profile.maximum_fee == U64.parse("0")?
    || U64.compare(profile.maximum_fee, U64.parse("1000000")?) > 0 do
    return Err("invalid_sol_conversion_cost_bounds")
  end
  let sorted = if before(native.bytes, profile.usdc.bytes, 0)? do
    [native.bytes, profile.usdc.bytes]
  else
    [profile.usdc.bytes, native.bytes]
  end
  if profile.authority != find_program_address(ray,
      [Bytes.from_utf8("vault_and_lp_mint_auth_seed")])?.address
    || profile.pool != find_program_address(ray,
        [
          Bytes.from_utf8("pool"),
          profile.amm_config.bytes,
          List.get(sorted, 0),
          List.get(sorted, 1)
        ])?.address
    || profile.input_vault != find_program_address(ray,
        [Bytes.from_utf8("pool_vault"), profile.pool.bytes, native.bytes])?.address
    || profile.output_vault != find_program_address(ray,
        [Bytes.from_utf8("pool_vault"), profile.pool.bytes, profile.usdc.bytes])?.address
    || profile.observation != find_program_address(ray,
        [Bytes.from_utf8("observation"), profile.pool.bytes])?.address do
    return Err("invalid_sol_conversion_pool_roles")
  end
  Ok(Crypto.sha256(cat([
    Bytes.from_utf8("morse-sol-conversion-profile-v1"),
    profile.treasury_config,
    cat(for value in keys do
      value.bytes
    end)?,
    profile.raydium_code,
    profile.token_code,
    profile.amm_hash,
    wide(profile.rent)?,
    wide(profile.maximum_fee)?
  ])?))
end

pub fn conversion_escrow(profile :: SolConversionProfile, id :: Bytes) -> Pubkey!String do
  if Bytes.length(id) != 32 do
    return Err("invalid_sol_conversion_identity")
  end
  # SystemProgram.createAccountWithSeed accepts at most32 seed bytes. The full
  # intent is journal-bound; a truncated-seed collision refuses an occupied escrow.
  let seed = String.slice(Bytes.to_hex(id), 0, 32)
  Ok(Pubkey {
    bytes: Crypto.sha256(cat([
      profile.owner.bytes,
      Bytes.from_utf8(seed),
      conversion_token_program()?.bytes
    ])?)
  })
end

fn meta(key :: Pubkey, signer :: Bool, writable :: Bool) -> AccountMeta do
  AccountMeta { pubkey: key, signer: signer, writable: writable }
end

# A fixed direct RaydiumCP ExactIn route: no aggregator-supplied transaction,
# extra instruction, tip, arbitrary account, delegate or principal deduction.
pub fn sol_conversion_message(profile :: SolConversionProfile,
  id :: Bytes,
  lamports :: U64,
  minimum :: U64,
  blockhash :: Hash) -> LegacyMessage!String do
  sol_conversion_profile_hash(profile)?
  if lamports == U64.parse("0")?
    || minimum == U64.parse("0")?
    || Bytes.length(blockhash.bytes) != 32 do
    return Err("invalid_sol_conversion_amount")
  end
  let token = conversion_token_program()?
  let native = conversion_native_mint()?
  let system = pubkey("11111111111111111111111111111111")?
  let escrow = conversion_escrow(profile, id)?
  let destination = conversion_destination(profile)?
  let seed = Bytes.from_utf8(String.slice(Bytes.to_hex(id), 0, 32))
  let create = Instruction {
    program_id: system,
    accounts: [
      meta(profile.payer, true, true),
      meta(escrow, false, true),
      meta(profile.owner, true, false)
    ],
    data: cat([
      Bytes.from_hex("03000000")?,
      profile.owner.bytes,
      wide(U64.parse("32")?)?,
      seed,
      wide(profile.rent)?,
      wide(U64.parse("165")?)?,
      token.bytes
    ])?
  }
  let initialize = Instruction {
    program_id: token,
    accounts: [meta(escrow, false, true), meta(native, false, false)],
    data: cat([Bytes.from_hex("12")?, profile.owner.bytes])?
  }
  let transfer = Instruction {
    program_id: system,
    accounts: [meta(profile.owner, true, true), meta(escrow, false, true)],
    data: cat([Bytes.from_hex("02000000")?, wide(lamports)?])?
  }
  let sync = Instruction {
    program_id: token,
    accounts: [meta(escrow, false, true)],
    data: Bytes.from_hex("11")?
  }
  let swap = Instruction {
    program_id: conversion_raydium_program()?,
    accounts: [
      meta(profile.owner, true, false),
      meta(profile.authority, false, false),
      meta(profile.amm_config, false, false),
      meta(profile.pool, false, true),
      meta(escrow, false, true),
      meta(destination, false, true),
      meta(profile.input_vault, false, true),
      meta(profile.output_vault, false, true),
      meta(token, false, false),
      meta(token, false, false),
      meta(native, false, false),
      meta(profile.usdc, false, false),
      meta(profile.observation, false, true)
    ],
    data: cat([
      Bytes.slice(Crypto.sha256(Bytes.from_utf8("global:swap_base_input")), 0, 8)?,
      wide(lamports)?,
      wide(minimum)?
    ])?
  }
  let close = Instruction {
    program_id: token,
    accounts: [
      meta(escrow, false, true),
      meta(profile.payer, false, true),
      meta(profile.owner, true, false)
    ],
    data: Bytes.from_hex("09")?
  }
  let message = compile_legacy_message(profile.payer,
    blockhash,
    [compute_unit_limit_instruction(600000)?, create, initialize, transfer, sync, swap, close])?
  let encoded = serialize_legacy_message(message)?
  if Bytes.length(encoded) + 129 > 1232 do
    return Err("sol_conversion_packet_too_large")
  end
  Ok(message)
end

pub fn sol_conversion_packet(profile :: SolConversionProfile,
  plan :: SolConversionPacket,
  wire :: Bytes) -> SignedTransaction!String do
  if Bytes.length(wire) < 129
    || Bytes.length(wire) > 1232
    || plan.profile_hash != sol_conversion_profile_hash(profile)? do
    return Err("invalid_sol_conversion_packet")
  end
  let expected = serialize_legacy_message(sol_conversion_message(profile,
    plan.intent_id,
    plan.lamports,
    plan.minimum,
    plan.blockhash)?)?
  let decoded = signed_transaction(wire, Bytes.slice(wire, 1, 64)?)?
  if plan.message != expected
    || decoded.message != expected
    || decoded.version != -1
    || List.length(decoded.signatures) != 2 do
    return Err("invalid_sol_conversion_packet")
  end
  Ok(decoded)
end
