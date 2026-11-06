# Prepared instructions only; the bank reader authenticates context and availability separately.
from Transparency.TokenBurn import TokenBurnProfile
from Transparency.TokenBurnWrite import token_burn_addresses, token_burn_fund_instruction
from Transparency.TokenChain import token_addresses, token_payout_address
from Solana.Read import Pubkey, pubkey
from Solana.Address import find_program_address
from Solana.Tx import Instruction, AccountMeta

pub struct TokenBurnCarryAddresses do
  carry :: Pubkey
  carry_vault :: Pubkey
  receipt :: Pubkey
end

fn carry_meta(key :: Pubkey, writable :: Bool) -> AccountMeta do
  AccountMeta { pubkey: key, signer: false, writable: writable }
end

pub fn token_burn_carry_addresses(program :: Pubkey,
  usdc :: Pubkey,
  epoch :: U64) -> TokenBurnCarryAddresses!String do
  let token = token_addresses(program)?
  if Bytes.length(usdc.bytes) != 32
    || Bytes.to_hex(usdc.bytes) == String.repeat("00", 32)
    || usdc == token.mint do
    return Err("invalid_burn_carry_mint")
  end
  let authority = find_program_address(program, [Bytes.from_utf8("burn-carry")])?.address
  Ok(TokenBurnCarryAddresses {
    carry: authority,
    carry_vault: token_payout_address(authority, usdc)?,
    receipt: find_program_address(program,
      [Bytes.from_utf8("burn-carry-epoch"), Bytes.write_uint_le(U64.to_string(epoch), 8)?])?.address
  })
end

pub fn token_burn_close_instruction(program :: Pubkey,
  payer :: Pubkey,
  profile :: TokenBurnProfile,
  epoch :: U64) -> Instruction!String do
  if Bytes.length(payer.bytes) != 32 || Bytes.to_hex(payer.bytes) == String.repeat("00", 32) do
    return Err("invalid_burn_carry_payer")
  end
  if U64.compare(U64.multiply(U64.add(epoch, U64.parse("1")?)?, U64.parse("604800")?)?,
    U64.parse("9223372036854775807")?) > 0 do
    return Err("invalid_burn_carry_epoch")
  end
  let token = token_addresses(program)?
  let burn = token_burn_addresses(program, profile, epoch, 0)?
  let a = token_burn_carry_addresses(program, profile.usdc, epoch)?
  Ok(Instruction {
    program_id: program,
    data: Bytes.concat(Bytes.from_hex("0d")?, Bytes.write_uint_le(U64.to_string(epoch), 8)?)?,
    accounts: [
      AccountMeta { pubkey: payer, signer: true, writable: true },
      carry_meta(token.config, false),
      carry_meta(token.mint, false),
      carry_meta(burn.profile, false),
      carry_meta(burn.week, true),
      carry_meta(burn.week_vault, true),
      carry_meta(a.carry, true),
      carry_meta(a.carry_vault, true),
      carry_meta(a.receipt, true),
      carry_meta(profile.usdc, false),
      carry_meta(pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?, false),
      carry_meta(pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?, false),
      carry_meta(pubkey("11111111111111111111111111111111")?, false)
    ]
  })
end

pub fn token_burn_fund_v2_instruction(program :: Pubkey,
  payer :: Pubkey,
  profile :: TokenBurnProfile,
  epoch :: U64,
  cash :: U64,
  carry :: U64,
  weights :: List<U64>,
  entropy :: List<U64>) -> Instruction!String do
  let total = U64.add(cash, carry)?
  let old = token_burn_fund_instruction(program, payer, profile, epoch, total, weights, entropy)?
  let a = token_burn_carry_addresses(program, profile.usdc, epoch)?
  let parts = [
    Bytes.from_hex("0e")?,
    Bytes.slice(old.data, 1, 8)?,
    Bytes.write_uint_le(U64.to_string(cash), 8)?,
    Bytes.write_uint_le(U64.to_string(carry), 8)?,
    Bytes.slice(old.data, 17, 288)?
  ]
  let data = List.reduce(parts,
    Ok(Bytes.empty()),
    fn(result, value) do Bytes.concat(result?, value) end)?
  Ok(Instruction {
    program_id: program,
    data: data,
    accounts: old.accounts ++ [carry_meta(a.carry, true), carry_meta(a.carry_vault, true)]
  })
end
