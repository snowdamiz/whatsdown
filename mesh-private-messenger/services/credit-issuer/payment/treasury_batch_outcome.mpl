from Payment.Treasury import TreasuryChainConfig
from Payment.TreasuryBatch import treasury_batch_message
from Payment.TreasuryBatchTypes import TreasuryPaymentBatch
from Payment.TreasuryOutcome import movement_index, movement_token, unchanged_tokens
from Payment.Verify import validate_payment_ata_setup
from Storage.Treasury import TreasuryMovement
from Solana.TransactionRead import FinalizedTransactionOutcome
from Solana.Read import Hash, Pubkey
from Solana.Nonce import NonceAccountState
from Solana.Tx import serialize_legacy_message

pub struct TreasuryBatchCost do
  movement_id :: Bytes
  fee :: U64
  rent :: U64
end

pub fn treasury_sum(values :: List<U64>) -> U64!String do
  if List.length(values) == 0 do
    return U64.parse("0")
  end
  U64.add(List.head(values), treasury_sum(List.drop(values, 1))?)
end

fn batch_amount(members :: List<TreasuryMovement>,
  address :: Bytes,
  destination :: Bool) -> U64!String do
  let amounts = for member in members do
    if Bytes.secure_equals(if destination do
        member.destination
      else
        member.source
      end,
      address) do
      member.amount
    else
      U64.parse("0")?
    end
  end
  treasury_sum(amounts)
end

fn batch_previous_destination(members :: List<TreasuryMovement>, index :: Int) -> Bool do
  let member = List.get(members, index)
  List.any(List.take(members, index),
    fn(previous) do Bytes.secure_equals(previous.destination, member.destination) end)
end

fn batch_setup_index(members :: List<TreasuryMovement>, index :: Int) -> Int do
  1
    + List.reduce(for item in 0..index do
        if batch_previous_destination(members, item) do
          1
        else
          2
        end
      end,
      0,
      fn(total, value) do total + value end)
end

pub fn treasury_batch_fee(total :: U64, count :: Int, index :: Int) -> U64!String do
  if count < 1 || count > 4 || index < 0 || index >= count do
    return Err("treasury_batch_size")
  end
  let divisor = U64.parse(Int.to_string(count))?
  let base = U64.divide(total, divisor)?
  let remainder = U64.subtract(total, U64.multiply(base, divisor)?)?
  if U64.compare(U64.parse(Int.to_string(index))?, remainder) < 0 do
    U64.add(base, U64.parse("1")?)
  else
    Ok(base)
  end
end

# Finality is one atomic packet outcome, never independent per-member success.
# Fees divide equally in canonical member order; remainder units go to the first
# members. ATA rent is charged once to the first member using that destination.
pub fn treasury_batch_costs(batch :: TreasuryPaymentBatch,
  config :: TreasuryChainConfig,
  outcome :: FinalizedTransactionOutcome) -> List<TreasuryBatchCost>!String do
  let value = outcome.transaction
  let nonce = NonceAccountState {
    authority: Pubkey { bytes: config.nonce_authority },
    nonce: Hash { bytes: batch.nonce_value },
    lamports_per_signature: U64.parse("0")?
  }
  let expected = serialize_legacy_message(treasury_batch_message(batch, config, nonce)?)?
  if !Bytes.secure_equals(batch.nonce_address, config.nonce_address)
    || !Bytes.secure_equals(value.signed.wire, batch.packet)
    || !Bytes.secure_equals(value.signed.signature, batch.transaction_signature)
    || !Bytes.secure_equals(value.signed.message, batch.message)
    || !Bytes.secure_equals(expected, batch.message)
    || !Bytes.secure_equals(List.head(value.signed.accounts).pubkey.bytes, config.fee_payer)
    || value.slot == U64.parse("0")? do
    return Err("treasury_batch_outcome_mismatch")
  end
  let failed = case outcome.execution_error do
    None -> false
    Some(_) -> true
  end
  let asset = List.head(batch.members).quote.asset
  let rents = for index in 0..List.length(batch.members) do
    let member = List.get(batch.members, index)
    if failed || asset == 1 || batch_previous_destination(batch.members, index) do
      U64.parse("0")?
    else
      let destination = movement_index(value, member.destination)?
      let setup = batch_setup_index(batch.members, index)
      let inner = List.filter(value.inner_instructions,
        fn(group) do group.instruction_index == setup end)
      let scoped = %{value | inner_instructions: inner, inner_instruction_count: List.length(inner)}
      validate_payment_ata_setup(scoped,
        %{member.quote | destination: member.destination, deposit_owner: member.destination_owner},
        config.fee_payer,
        setup)?
      U64.subtract(List.get(value.post_balances, destination),
        List.get(value.pre_balances, destination))?
    end
  end
  let rent = treasury_sum(rents)?
  if !failed && asset == 0 do
    for group in value.inner_instructions do
      let expected_indices = for index in 0..List.length(batch.members) do
        if batch_previous_destination(batch.members, index) do
          -1
        else
          batch_setup_index(batch.members, index)
        end
      end
      if !List.contains(expected_indices, group.instruction_index) do
        return Err("unexpected_treasury_batch_inner")
      end
    end
  end
  for index in 0..List.length(value.signed.accounts) do
    let address = List.get(value.signed.accounts, index).pubkey.bytes
    let before = List.get(value.pre_balances, index)
    let current = List.get(value.post_balances, index)
    let expected_balance = if index == 0 do
      U64.subtract(before, U64.add(value.fee, rent)?)?
    else if failed do
      before
    else if asset == 1 do
      U64.add(U64.subtract(before, batch_amount(batch.members, address, false)?)?,
        batch_amount(batch.members, address, true)?)?
    else
      let additions = for ordinal in 0..List.length(batch.members) do
        if Bytes.secure_equals(List.get(batch.members, ordinal).destination, address) do
          List.get(rents, ordinal)
        else
          U64.parse("0")?
        end
      end
      U64.add(before, treasury_sum(additions)?)?
    end
    if current != expected_balance do
      return Err("treasury_batch_balance_mismatch")
    end
  end
  if failed do
    unchanged_tokens(value)?
  else if asset == 1 do
    if value.inner_instruction_count != 0
      || List.length(value.pre_token_balances) != 0
      || List.length(value.post_token_balances) != 0 do
      return Err("unexpected_treasury_sol_metadata")
    end
  else
    let allowed = for account in value.signed.accounts do
      let address = account.pubkey.bytes
      List.any(batch.members,
        fn(member) do Bytes.secure_equals(member.source, address)
          || Bytes.secure_equals(member.destination, address) end)
    end
    for row in value.pre_token_balances ++ value.post_token_balances do
      if !List.get(allowed, row.account_index) do
        return Err("unexpected_treasury_token_metadata")
      end
    end
    for index in 0..List.length(value.signed.accounts) do
      if List.get(allowed, index) do
        let address = List.get(value.signed.accounts, index).pubkey.bytes
        let owners = List.filter(batch.members,
          fn(member) do Bytes.secure_equals(member.source, address)
            || Bytes.secure_equals(member.destination, address) end)
        let member = List.head(owners)
        let is_source = Bytes.secure_equals(member.source, address)
        let owner = if is_source do
          member.quote.deposit_owner
        else
          member.destination_owner
        end
        let before = movement_token(value.pre_token_balances,
          index,
          owner,
          config.mint,
          !is_source)?
        let current = movement_token(value.post_token_balances, index, owner, config.mint, false)?
        if current != U64.add(U64.subtract(before, batch_amount(batch.members, address, false)?)?,
            batch_amount(batch.members, address, true)?)? do
          return Err("treasury_batch_token_mismatch")
        end
      end
    end
    nil
  end
  Ok(for index in 0..List.length(batch.members) do
    TreasuryBatchCost {
      movement_id: List.get(batch.members, index).movement_id,
      fee: treasury_batch_fee(value.fee, List.length(batch.members), index)?,
      rent: List.get(rents, index)
    }
  end)
end
