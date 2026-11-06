from Payment.Treasury import TreasuryChainConfig, treasury_config_hash
from Payment.Verify import validate_payment_ata_setup
from Storage.Treasury import TreasuryMovement
from Solana.Read import spl_token_program, pubkey_equal
from Solana.TransactionRead import (
  FinalizedTransaction,
  FinalizedTransactionOutcome,
  TransactionTokenBalance
)

pub fn movement_index(value :: FinalizedTransaction, address :: Bytes) -> Int!String do
  for index in 0..List.length(value.signed.accounts) do
    if Bytes.secure_equals(List.get(value.signed.accounts, index).pubkey.bytes, address) do
      return Ok(index)
    end
  end
  Err("missing_treasury_account")
end

pub fn movement_token(rows :: List<TransactionTokenBalance>,
  index :: Int,
  owner :: Bytes,
  mint :: Bytes,
  missing_zero :: Bool) -> U64!String do
  for row in rows do
    if row.account_index == index do
      let actual_owner = case row.owner do
        Some(key) -> key.bytes
        None -> return Err("missing_treasury_token_owner")
      end
      let program = case row.program_id do
        Some(key) -> key
        None -> return Err("missing_treasury_token_program")
      end
      if !Bytes.secure_equals(actual_owner, owner)
        || !Bytes.secure_equals(row.mint.bytes, mint)
        || row.decimals != 6
        || !pubkey_equal(program, spl_token_program()?) do
        return Err("invalid_treasury_token_metadata")
      end
      return Ok(row.amount)
    end
  end
  if missing_zero do
    Ok(U64.parse("0")?)
  else
    Err("missing_treasury_token_balance")
  end
end

pub fn unchanged_tokens(value :: FinalizedTransaction) -> Result<(), String> do
  if List.length(value.pre_token_balances) != List.length(value.post_token_balances) do
    return Err("failed_treasury_token_effect")
  end
  for before in value.pre_token_balances do
    let owner = case before.owner do
      Some(key) -> key.bytes
      None -> return Err("missing_treasury_token_owner")
    end
    if movement_token(value.post_token_balances,
      before.account_index,
      owner,
      before.mint.bytes,
      false)? != before.amount do
      return Err("failed_treasury_token_effect")
    end
  end
  Ok(nil)
end

# This checks a configured provider's finalized execution assertion against the
# exact committed packet and its canonical movement policy. It is not a light
# client; signatures bind the packet, while provider trust binds chain effects.
pub fn validate_treasury_outcome(movement :: TreasuryMovement,
  config :: TreasuryChainConfig,
  outcome :: FinalizedTransactionOutcome) -> Bool!String do
  let value = outcome.transaction
  if !Bytes.secure_equals(treasury_config_hash(config)?, movement.config_hash)
    || !Bytes.secure_equals(value.signed.wire, movement.packet)
    || !Bytes.secure_equals(value.signed.signature, movement.transaction_signature)
    || !Bytes.secure_equals(value.signed.message, movement.message)
    || !Bytes.secure_equals(List.head(value.signed.accounts).pubkey.bytes, config.fee_payer)
    || value.slot == U64.parse("0")? do
    return Err("treasury_outcome_packet_mismatch")
  end
  let failed = case outcome.execution_error do
    None -> false
    Some(_) -> true
  end
  let source = movement_index(value, movement.source)?
  let destination = movement_index(value, movement.destination)?
  let rent = if !failed && movement.quote.asset == 0 do
    let before = List.get(value.pre_balances, destination)
    let current = List.get(value.post_balances, destination)
    U64.subtract(current, before)?
  else
    U64.parse("0")?
  end
  for index in 0..List.length(value.signed.accounts) do
    let before = List.get(value.pre_balances, index)
    let current = List.get(value.post_balances, index)
    let expected = if index == 0 do
      U64.subtract(before, U64.add(value.fee, rent)?)?
    else if !failed && movement.quote.asset == 1 && index == source do
      U64.subtract(before, movement.amount)?
    else if !failed && movement.quote.asset == 1 && index == destination do
      U64.add(before, movement.amount)?
    else if !failed && movement.quote.asset == 0 && index == destination do
      U64.add(before, rent)?
    else
      before
    end
    if current != expected do
      return Err("treasury_balance_effect_mismatch")
    end
  end
  if failed do
    unchanged_tokens(value)?
    return Ok(false)
  end
  if movement.quote.asset == 1 do
    if value.inner_instruction_count != 0
      || List.length(value.pre_token_balances) != 0
      || List.length(value.post_token_balances) != 0 do
      return Err("unexpected_treasury_sol_metadata")
    end
    return Ok(true)
  end
  let target_quote = %{movement.quote |
    destination: movement.destination,
    deposit_owner: movement.destination_owner
  }
  let created = validate_payment_ata_setup(value, target_quote, config.fee_payer, 1)?
  if List.length(value.pre_token_balances) != (if created do
      1
    else
      2
    end)
    || List.length(value.post_token_balances) != 2 do
    return Err("unexpected_treasury_token_metadata")
  end
  let source_before = movement_token(value.pre_token_balances,
    source,
    movement.quote.deposit_owner,
    config.mint,
    false)?
  let source_after = movement_token(value.post_token_balances,
    source,
    movement.quote.deposit_owner,
    config.mint,
    false)?
  let target_before = movement_token(value.pre_token_balances,
    destination,
    movement.destination_owner,
    config.mint,
    created)?
  let target_after = movement_token(value.post_token_balances,
    destination,
    movement.destination_owner,
    config.mint,
    false)?
  if U64.subtract(source_before, source_after)? != movement.amount
    || U64.subtract(target_after, target_before)? != movement.amount do
    return Err("treasury_token_effect_mismatch")
  end
  Ok(true)
end
