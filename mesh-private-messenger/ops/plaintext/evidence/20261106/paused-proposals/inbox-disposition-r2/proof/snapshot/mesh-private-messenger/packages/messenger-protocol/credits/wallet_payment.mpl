from Credits.Issuance import CreditQuote, encode_credit_quote
from Credits.Payment import solana_pay_url
from Solana.Read import Pubkey, pubkey, pubkey_equal, spl_token_program
from Solana.Address import find_program_address
from Solana.Tx import (
  AccountMeta,
  Instruction,
  create_associated_token_idempotent_instruction,
  transfer_checked_instruction
)
from Solana.TransactionRead import SignedTransaction, signed_transaction

fn same(left :: Bytes, right :: Bytes) -> Bool do
  Bytes.secure_equals(left, right)
end

fn associated(owner :: Bytes, mint :: Bytes) -> Pubkey!String do
  Ok(find_program_address(pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?,
    [owner, spl_token_program()?.bytes, mint])?.address)
end

# Public payment instructions only. The native signer reconstructs these same
# bounded instructions; the Mesh journal independently checks its signed result.
pub fn wallet_payment_instructions(quote :: CreditQuote,
  payer :: Pubkey) -> List<Instruction>!String do
  encode_credit_quote(quote)?
  let reference = AccountMeta {
    pubkey: Pubkey { bytes: quote.quote_id },
    signer: false,
    writable: false
  }
  if quote.asset == 1 do
    Ok([
      Instruction {
        program_id: pubkey("11111111111111111111111111111111")?,
        accounts: [
          AccountMeta { pubkey: payer, signer: true, writable: true },
          AccountMeta {
            pubkey: Pubkey { bytes: quote.destination },
            signer: false,
            writable: true
          },
          reference
        ],
        data: Bytes.concat(Bytes.from_hex("02000000")?,
          Bytes.write_uint_le(U64.to_string(quote.amount), 8)?)?
      }
    ])
  else
    let setup = create_associated_token_idempotent_instruction(payer,
      Pubkey { bytes: quote.destination },
      Pubkey { bytes: quote.deposit_owner },
      Pubkey { bytes: quote.mint })?
    let transfer = transfer_checked_instruction(associated(payer.bytes, quote.mint)?,
      Pubkey { bytes: quote.mint },
      Pubkey { bytes: quote.destination },
      payer,
      quote.amount,
      6)?
    Ok([
      setup,
      Instruction {
        program_id: transfer.program_id,
        accounts: transfer.accounts ++ [reference],
        data: transfer.data
      }
    ])
  end
end

# Only the canonical SDK launch shape is supported: legacy, sole signer, one
# System transfer or canonical ATA CreateIdempotent plus TransferChecked. No
# extra keys, compute instructions, lookup tables or arbitrary calls are signed.
pub fn authenticate_wallet_payment(wire :: Bytes,
  quote :: CreditQuote,
  pinned_mint :: Bytes,
  purpose :: Int,
  blockhash :: Bytes) -> SignedTransaction!String do
  solana_pay_url(quote, pinned_mint, purpose, quote.issued_at)?
  if Bytes.length(wire) < 65 || Bytes.get(wire, 0)? != 1 do
    return Err("invalid_wallet_payment_signatures")
  end
  let value = signed_transaction(wire, Bytes.slice(wire, 1, 64)?)?
  if value.version != -1
    || value.header.num_required_signatures != 1
    || !same(value.recent_blockhash, blockhash) do
    return Err("invalid_wallet_payment_message")
  end
  let payer = List.head(value.accounts).pubkey
  let keys = if quote.asset == 1 do
    [
      payer.bytes,
      quote.destination,
      pubkey("11111111111111111111111111111111")?.bytes,
      quote.quote_id
    ]
  else
    [
      payer.bytes,
      associated(payer.bytes, quote.mint)?.bytes,
      quote.destination,
      quote.deposit_owner,
      quote.mint,
      pubkey("11111111111111111111111111111111")?.bytes,
      spl_token_program()?.bytes,
      pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?.bytes,
      quote.quote_id
    ]
  end
  for index in 0..List.length(keys) do
    for previous in 0..index do
      if same(List.get(keys, index), List.get(keys, previous)) do
        return Err("invalid_wallet_payment_alias")
      end
    end
  end
  let expected = wallet_payment_instructions(quote, payer)?
  if List.length(value.instructions) != List.length(expected) do
    return Err("invalid_wallet_payment_instructions")
  end
  for index in 0..List.length(expected) do
    let wanted = List.get(expected, index)
    let actual = List.get(value.instructions, index)
    if !pubkey_equal(wanted.program_id, actual.program_id)
      || !same(wanted.data, actual.data)
      || List.length(wanted.accounts) != List.length(actual.accounts) do
      return Err("invalid_wallet_payment_instruction")
    end
    for position in 0..List.length(wanted.accounts) do
      if !pubkey_equal(List.get(wanted.accounts, position).pubkey,
        List.get(actual.accounts, position).pubkey) do
        return Err("invalid_wallet_payment_account")
      end
    end
  end
  # Roles are global message privileges, not per-instruction requested flags.
  # Recompute the exact union and reject every unused/extra signed key.
  for account in value.accounts do
    let used = List.any(expected,
      fn(ix) do pubkey_equal(ix.program_id, account.pubkey)
        || List.any(ix.accounts, fn(meta) do pubkey_equal(meta.pubkey, account.pubkey) end) end)
    let signer = List.any(expected,
      fn(ix) do List.any(ix.accounts,
        fn(meta) do pubkey_equal(meta.pubkey, account.pubkey) && meta.signer end) end)
    let writable = List.any(expected,
      fn(ix) do List.any(ix.accounts,
        fn(meta) do pubkey_equal(meta.pubkey, account.pubkey) && meta.writable end) end)
    if !used || account.signer != signer || account.writable != writable do
      return Err("invalid_wallet_payment_privileges")
    end
  end
  # Every expected role must exist; duplicate message keys are rejected by the
  # public parser, so this also rejects aliases that merge distinct roles.
  for ix in expected do
    for meta in ix.accounts do
      if !List.any(value.accounts, fn(account) do pubkey_equal(meta.pubkey, account.pubkey) end) do
        return Err("missing_wallet_payment_account")
      end
    end
  end
  if same(payer.bytes, quote.deposit_owner)
    || same(payer.bytes, quote.destination)
    || same(payer.bytes, quote.quote_id)
    || same(payer.bytes, quote.mint) do
    return Err("invalid_wallet_payment_payer")
  end
  Ok(value)
end
