from Payment.SolConversionPacket import (
  SolConversionProfile,
  SolConversionPacket,
  sol_conversion_packet,
  conversion_escrow,
  conversion_destination,
  conversion_native_mint,
  conversion_token_program
)
from Solana.TransactionRead import (
  FinalizedTransaction,
  FinalizedTransactionOutcome,
  TransactionTokenBalance
)
from Solana.Read import Pubkey

pub struct SolConversionExecution do
  successful :: Bool
  signature :: Bytes
  slot :: U64
  fee :: U64
  received :: U64
  receipt :: Bytes
end

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(total, value) do Bytes.concat(total?, value) end)
end

fn index(transaction :: FinalizedTransaction, address :: Pubkey) -> Int!String do
  let found = List.filter(for i in 0..List.length(transaction.signed.accounts) do
      i
    end,
    fn(i) do List.get(transaction.signed.accounts, i).pubkey == address end)
  if List.length(found) != 1 do
    Err("sol_conversion_outcome_account")
  else
    Ok(List.head(found))
  end
end

fn amount(rows :: List<TransactionTokenBalance>,
  at :: Int,
  asset :: Pubkey,
  owner :: Pubkey,
  decimals :: Int) -> U64!String do
  let found = List.filter(rows, fn(row) do row.account_index == at end)
  if List.length(found) != 1 do
    return Err("sol_conversion_outcome_token")
  end
  let row = List.head(found)
  if row.mint != asset
    || row.owner != Some(owner)
    || row.program_id != Some(conversion_token_program()?)
    || row.decimals != decimals do
    return Err("sol_conversion_outcome_token")
  end
  Ok(row.amount)
end

pub fn sol_conversion_outcome(profile :: SolConversionProfile,
  plan :: SolConversionPacket,
  packet :: Bytes,
  prepared_slot :: U64,
  outcome :: FinalizedTransactionOutcome) -> SolConversionExecution!String do
  sol_conversion_packet(profile, plan, packet)?
  let value = outcome.transaction
  if value.signed.wire != packet
    || prepared_slot == U64.parse("0")?
    || U64.compare(value.slot, prepared_slot) < 0
    || U64.compare(value.fee, profile.maximum_fee) > 0 do
    return Err("sol_conversion_outcome_mismatch")
  end
  let successful = outcome.execution_error == None
  let zero = U64.parse("0")?
  let spent = if successful do
    plan.lamports
  else
    zero
  end
  let payer = index(value, profile.payer)?
  let owner = index(value, profile.owner)?
  let escrow = index(value, conversion_escrow(profile, plan.intent_id)?)?
  let input_vault = index(value, profile.input_vault)?
  let output_vault = index(value, profile.output_vault)?
  let destination = index(value, conversion_destination(profile)?)?
  if List.length(value.pre_token_balances) != 3 || List.length(value.post_token_balances) != 3 do
    return Err("sol_conversion_outcome_token")
  end
  let before = amount(value.pre_token_balances, destination, profile.usdc, profile.owner, 6)?
  let current = amount(value.post_token_balances, destination, profile.usdc, profile.owner, 6)?
  let received = U64.subtract(current, before)?
  if (successful && U64.compare(received, plan.minimum) < 0) || (!successful && received != zero) do
    return Err("sol_conversion_output_shortfall")
  end
  let native = conversion_native_mint()?
  if amount(value.post_token_balances,
    input_vault,
    native,
    profile.authority,
    9)? != U64.add(amount(value.pre_token_balances, input_vault, native, profile.authority, 9)?,
      spent)?
    || amount(value.pre_token_balances,
      output_vault,
      profile.usdc,
      profile.authority,
      6)? != U64.add(amount(value.post_token_balances,
          output_vault,
          profile.usdc,
          profile.authority,
          6)?,
        received)? do
    return Err("sol_conversion_vault_delta")
  end
  for at in 0..List.length(value.signed.accounts) do
    let pre = List.get(value.pre_balances, at)
    let post = List.get(value.post_balances, at)
    let valid = if at == payer do
      pre == U64.add(post, value.fee)?
    else if at == owner do
      pre == U64.add(post, spent)?
    else if at == input_vault do
      post == U64.add(pre, spent)?
    else if at == escrow do
      pre == zero && post == zero
    else
      pre == post
    end
    if !valid do
      return Err("sol_conversion_lamport_delta")
    end
  end
  let receipt = cat([
    Bytes.from_utf8("MCS1"),
    plan.intent_id,
    plan.profile_hash,
    value.signed.signature,
    Crypto.sha256(packet),
    Bytes.write_uint_le(U64.to_string(value.slot), 8)?,
    Bytes.write_uint_le(U64.to_string(spent), 8)?,
    Bytes.write_uint_le(U64.to_string(received), 8)?,
    Bytes.write_uint_le(U64.to_string(value.fee), 8)?,
    Bytes.from_hex(if successful do
      "01"
    else
      "00"
    end)?
  ])?
  Ok(SolConversionExecution {
    successful: successful,
    signature: value.signed.signature,
    slot: value.slot,
    fee: value.fee,
    received: received,
    receipt: receipt
  })
end
