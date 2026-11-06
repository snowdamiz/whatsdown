from Bounty.Transfer import BountyTransfer, bounty_token_account, authenticate_bounty_transfer
from Solana.Read import Pubkey, pubkey_equal, spl_token_program
from Solana.TransactionRead import (
  SignedTransaction,
  FinalizedTransactionOutcome,
  TransactionTokenBalance
)

pub struct BountyTransferSettlement do
  signature :: Bytes
  wire_hash :: Bytes
  slot :: U64
  fee :: U64
  execution_error :: String
end

fn position(signed :: SignedTransaction, address :: Pubkey) -> Int!String do
  for index in 0..List.length(signed.accounts) do
    if pubkey_equal(List.get(signed.accounts, index).pubkey, address) do
      return Ok(index)
    end
  end
  Err("bounty_transfer_account_missing")
end

fn balance(rows :: List<TransactionTokenBalance>,
  index :: Int,
  mint :: Bytes,
  owner :: Bytes,
  decimals :: Int,
  optional :: Bool) -> U64!String do
  let matches = List.filter(rows, fn(row) do row.account_index == index end)
  if optional && List.length(matches) == 0 do
    return U64.parse("0")
  end
  if List.length(matches) != 1 do
    return Err("invalid_bounty_transfer_balance")
  end
  let row = List.head(matches)
  let actual_owner = case row.owner do
    None -> return Err("invalid_bounty_transfer_balance")
    Some(value) -> value
  end
  let program = case row.program_id do
    None -> return Err("invalid_bounty_transfer_balance")
    Some(value) -> value
  end
  if !Bytes.secure_equals(row.mint.bytes, mint)
    || !Bytes.secure_equals(actual_owner.bytes, owner)
    || row.decimals != decimals
    || !pubkey_equal(program, spl_token_program()?) do
    return Err("invalid_bounty_transfer_balance")
  end
  Ok(row.amount)
end

# Each pinned provider must independently prove this exact signed transaction
# and its token deltas. Native recovery then requires agreement from two sources.
pub fn bounty_transfer_settlement(outcome :: FinalizedTransactionOutcome,
  wire :: Bytes,
  intent :: BountyTransfer,
  payer :: Pubkey,
  usdc :: Bytes,
  purpose :: Int,
  minimum_slot :: U64) -> BountyTransferSettlement!String do
  let signed = authenticate_bounty_transfer(wire, intent, payer, usdc, purpose)?
  let tx = outcome.transaction
  if !Bytes.secure_equals(tx.signed.wire, wire) || U64.compare(tx.slot, minimum_slot) < 0 do
    return Err("bounty_transfer_outcome_mismatch")
  end
  let error = case outcome.execution_error do
    None -> ""
    Some(value) -> if String.length(value) == 0 || String.length(value) > 256 do
      return Err("invalid_bounty_transfer_error")
    else
      value
    end
  end
  if error == "" do
    let source = position(signed, bounty_token_account(intent.finder, intent.mint)?)?
    let destination = position(signed, bounty_token_account(intent.destination, intent.mint)?)?
    let before = balance(tx.pre_token_balances,
      source,
      intent.mint,
      intent.finder,
      intent.decimals,
      false)?
    let remaining = balance(tx.post_token_balances,
      source,
      intent.mint,
      intent.finder,
      intent.decimals,
      false)?
    let received_before = balance(tx.pre_token_balances,
      destination,
      intent.mint,
      intent.destination,
      intent.decimals,
      true)?
    let received_after = balance(tx.post_token_balances,
      destination,
      intent.mint,
      intent.destination,
      intent.decimals,
      false)?
    if U64.subtract(before, remaining)? != intent.amount
      || U64.subtract(received_after, received_before)? != intent.amount do
      return Err("bounty_transfer_amount_mismatch")
    end
  end
  Ok(BountyTransferSettlement {
    signature: signed.signature,
    wire_hash: Crypto.sha256(wire),
    slot: tx.slot,
    fee: tx.fee,
    execution_error: error
  })
end

pub fn bounty_settlements_agree(left :: BountyTransferSettlement,
  right :: BountyTransferSettlement) -> Bool do
  Bytes.secure_equals(left.signature, right.signature)
    && Bytes.secure_equals(left.wire_hash, right.wire_hash)
    && left.slot == right.slot
    && left.fee == right.fee
    && left.execution_error == right.execution_error
end
