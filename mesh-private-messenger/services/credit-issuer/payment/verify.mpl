from Credits.Issuance import CreditQuote, encode_credit_quote
from Solana.Read import Pubkey, RpcResponse, pubkey, pubkey_equal, spl_token_program
from Solana.Address import find_program_address
from Solana.Tx import AccountMeta, Instruction
from Solana.TransactionRead import (
  FinalizedTransaction,
  TransactionTokenBalance,
  get_finalized_transaction,
  finalized_transaction_from_response
)

pub struct PaymentReceipt do
  transaction_signature :: Bytes
  payer :: Bytes
  slot :: U64
  block_time :: U64
  received_amount :: U64
end

fn zero(value :: Bytes) -> Bool do
  Bytes.to_hex(value) == String.repeat("00", Bytes.length(value))
end

fn equal(left :: Bytes, right :: Bytes) -> Bool do
  Bytes.secure_equals(left, right)
end

pub fn payment_token_address(owner :: Bytes, mint :: Bytes) -> Bytes!String do
  if Bytes.length(owner) != 32 || Bytes.length(mint) != 32 do
    return Err("invalid_payment_address")
  end
  let token = spl_token_program()?
  Ok(find_program_address(pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?,
    [owner, token.bytes, mint])?.address.bytes)
end

pub fn check_payment_quote(quote :: CreditQuote,
  pinned_mint :: Bytes,
  price_observed_at :: U64,
  now :: U64) -> Result<(), String> do
  encode_credit_quote(quote)?
  if Bytes.length(pinned_mint) != 32
    || zero(pinned_mint)
    || U64.compare(now, quote.issued_at) < 0
    || equal(quote.quote_id, quote.deposit_owner)
    || equal(quote.quote_id, quote.destination) do
    return Err("invalid_payment_quote")
  end
  if quote.asset == 0 do
    if !equal(quote.mint, pinned_mint)
      || !equal(quote.destination, payment_token_address(quote.deposit_owner, pinned_mint)?) do
      return Err("invalid_payment_mint_or_destination")
    end
  else if !equal(quote.destination, quote.deposit_owner)
    || U64.compare(price_observed_at, quote.issued_at) > 0
    || U64.compare(U64.subtract(quote.issued_at, price_observed_at)?, U64.parse("60")?) > 0 do
    return Err("stale_payment_price")
  end
  Ok(nil)
end

fn role(account :: AccountMeta, address :: Bytes, signer :: Bool, writable :: Bool) -> Bool do
  equal(account.pubkey.bytes, address) && account.signer == signer && account.writable == writable
end

fn account_index(value :: FinalizedTransaction, address :: Bytes) -> Int!String do
  for index in 0..List.length(value.signed.accounts) do
    if equal(List.get(value.signed.accounts, index).pubkey.bytes, address) do
      return Ok(index)
    end
  end
  Err("missing_payment_account")
end

fn token_balance(values :: List<TransactionTokenBalance>,
  index :: Int,
  mint :: Bytes,
  owner :: Bytes) -> U64!String do
  for value in values do
    if value.account_index == index do
      let recorded_owner = case value.owner do
        None -> return Err("missing_payment_token_owner")
        Some(key) -> key.bytes
      end
      let recorded_program = case value.program_id do
        None -> return Err("missing_payment_token_program")
        Some(key) -> key
      end
      if value.decimals != 6
        || !equal(value.mint.bytes, mint)
        || !equal(recorded_owner, owner)
        || !pubkey_equal(recorded_program, spl_token_program()?) do
        return Err("invalid_payment_token_balance")
      end
      return Ok(value.amount)
    end
  end
  Err("missing_payment_token_balance")
end

fn token_present(values :: List<TransactionTokenBalance>, index :: Int) -> Bool do
  List.any(values, fn(value) do value.account_index == index end)
end

fn inner_accounts(value :: Instruction, program :: Pubkey, keys :: List<Bytes>) -> Bool do
  if !pubkey_equal(value.program_id, program) || List.length(value.accounts) != List.length(keys) do
    return false
  end
  for index in 0..List.length(keys) do
    if !equal(List.get(value.accounts, index).pubkey.bytes, List.get(keys, index)) do
      return false
    end
  end
  true
end

pub fn validate_payment_ata_setup(value :: FinalizedTransaction,
  quote :: CreditQuote,
  payer :: Bytes,
  index :: Int) -> Bool!String do
  let ata = pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?
  let system = pubkey("11111111111111111111111111111111")?
  let token = spl_token_program()?
  let instruction = List.get(value.signed.instructions, index)
  if !pubkey_equal(instruction.program_id, ata)
    || Bytes.to_hex(instruction.data) != "01"
    || List.length(instruction.accounts) != 6
    || !role(List.get(instruction.accounts, 0), payer, true, true)
    || !role(List.get(instruction.accounts, 1), quote.destination, false, true)
    || !role(List.get(instruction.accounts, 2), quote.deposit_owner, false, false)
    || !role(List.get(instruction.accounts, 3), quote.mint, false, false)
    || !role(List.get(instruction.accounts, 4), system.bytes, false, false)
    || !role(List.get(instruction.accounts, 5), token.bytes, false, false) do
    return Err("invalid_payment_ata_setup")
  end
  let ata_meta = List.get(value.signed.accounts, account_index(value, ata.bytes)?)
  if ata_meta.signer || ata_meta.writable do
    return Err("invalid_payment_ata_program")
  end
  let destination = account_index(value, quote.destination)?
  let existed = token_present(value.pre_token_balances, destination)
  if existed do
    if value.inner_instruction_count != 0 do
      return Err("unexpected_existing_ata_inner")
    end
    return Ok(false)
  end
  if value.inner_instruction_count != 1 || List.length(value.inner_instructions) != 1 do
    return Err("missing_payment_ata_inner")
  end
  let group = List.get(value.inner_instructions, 0)
  let rows = group.instructions
  let count = List.length(rows)
  if group.instruction_index != index || count < 4 || count > 6 do
    return Err("invalid_payment_ata_inner")
  end
  let size = List.get(rows, 0)
  if !inner_accounts(size, token, [quote.mint])
    || (Bytes.to_hex(size.data) != "15" && Bytes.to_hex(size.data) != "150700") do
    return Err("invalid_payment_ata_size")
  end
  let immutable = List.get(rows, count - 2)
  let initialize = List.get(rows, count - 1)
  if !inner_accounts(immutable, token, [quote.destination])
    || Bytes.to_hex(immutable.data) != "16"
    || !inner_accounts(initialize, token, [quote.destination, quote.mint])
    || Bytes.to_hex(initialize.data) != "12#{Bytes.to_hex(quote.deposit_owner)}" do
    return Err("invalid_payment_ata_initialize")
  end
  let before = List.get(value.pre_balances, destination)
  let current = List.get(value.post_balances, destination)
  if U64.compare(current, before) < 0 do
    return Err("invalid_payment_ata_rent")
  end
  let added = U64.subtract(current, before)?
  if count == 4 do
    let create = List.get(rows, 1)
    if !inner_accounts(create, system, [payer, quote.destination])
      || Bytes.length(create.data) != 52
      || Bytes.read_uint_le(create.data, 0, 4)? != "0"
      || U64.parse(Bytes.read_uint_le(create.data, 4, 8)?)? != added
      || Bytes.read_uint_le(create.data, 12, 8)? != "165"
      || !equal(Bytes.slice(create.data, 20, 32)?, token.bytes)
      || before != U64.parse("0")? do
      return Err("invalid_payment_ata_create")
    end
  else
    let allocate = List.get(rows, count - 4)
    let assign = List.get(rows, count - 3)
    if before == U64.parse("0")?
      || !inner_accounts(allocate, system, [quote.destination])
      || Bytes.length(allocate.data) != 12
      || Bytes.read_uint_le(allocate.data, 0, 4)? != "8"
      || Bytes.read_uint_le(allocate.data, 4, 8)? != "165"
      || !inner_accounts(assign, system, [quote.destination])
      || Bytes.length(assign.data) != 36
      || Bytes.read_uint_le(assign.data, 0, 4)? != "1"
      || !equal(Bytes.slice(assign.data, 4, 32)?, token.bytes) do
      return Err("invalid_payment_ata_allocate")
    end
    if count == 6 do
      let transfer = List.get(rows, 1)
      if !inner_accounts(transfer, system, [payer, quote.destination])
        || Bytes.length(transfer.data) != 12
        || Bytes.read_uint_le(transfer.data, 0, 4)? != "2"
        || U64.parse(Bytes.read_uint_le(transfer.data, 4, 8)?)? != added do
        return Err("invalid_payment_ata_fund")
      end
    else if added != U64.parse("0")? do
      return Err("invalid_payment_ata_rent")
    end
  end
  Ok(true)
end

fn increase(before :: U64, current :: U64, amount :: U64) -> Bool!String do
  if U64.compare(current, before) < 0 do
    Ok(false)
  else
    Ok(U64.subtract(current, before)? == amount)
  end
end

fn decrease(before :: U64, current :: U64, amount :: U64) -> Bool!String do
  if U64.compare(before, current) < 0 do
    Ok(false)
  else
    Ok(U64.subtract(before, current)? == amount)
  end
end

fn transfer_amount(value :: FinalizedTransaction,
  quote :: CreditQuote,
  payer :: Bytes,
  instruction :: Instruction,
  created :: Bool) -> U64!String do
  let accounts = instruction.accounts
  if quote.asset == 1 do
    if !pubkey_equal(instruction.program_id, pubkey("11111111111111111111111111111111")?)
      || List.length(accounts) != 3
      || Bytes.length(instruction.data) != 12
      || Bytes.read_uint_le(instruction.data, 0, 4)? != "2"
      || !role(List.get(accounts, 0), payer, true, true)
      || !role(List.get(accounts, 1), quote.destination, false, true)
      || !role(List.get(accounts, 2), quote.quote_id, false, false) do
      return Err("invalid_sol_payment_instruction")
    end
    let amount = U64.parse(Bytes.read_uint_le(instruction.data, 4, 8)?)?
    let destination = account_index(value, quote.destination)?
    if !increase(List.get(value.pre_balances, destination),
      List.get(value.post_balances, destination),
      amount)?
      || !decrease(List.get(value.pre_balances, 0),
        List.get(value.post_balances, 0),
        U64.add(amount, value.fee)?)?
      || List.length(value.pre_token_balances) != 0
      || List.length(value.post_token_balances) != 0 do
      return Err("invalid_sol_payment_balance")
    end
    Ok(amount)
  else
    let source = payment_token_address(payer, quote.mint)?
    if !pubkey_equal(instruction.program_id, spl_token_program()?)
      || List.length(accounts) != 5
      || Bytes.length(instruction.data) != 10
      || Bytes.get(instruction.data, 0)? != 12
      || Bytes.get(instruction.data, 9)? != 6
      || !role(List.get(accounts, 0), source, false, true)
      || !role(List.get(accounts, 1), quote.mint, false, false)
      || !role(List.get(accounts, 2), quote.destination, false, true)
      || !role(List.get(accounts, 3), payer, true, true)
      || !role(List.get(accounts, 4), quote.quote_id, false, false) do
      return Err("invalid_usdc_payment_instruction")
    end
    let amount = U64.parse(Bytes.read_uint_le(instruction.data, 1, 8)?)?
    let source_index = account_index(value, source)?
    let destination = account_index(value, quote.destination)?
    let before_destination = if created do
      U64.parse("0")?
    else
      token_balance(value.pre_token_balances, destination, quote.mint, quote.deposit_owner)?
    end
    let rent = U64.subtract(List.get(value.post_balances, destination),
      List.get(value.pre_balances, destination))?
    if !created && rent != U64.parse("0")? do
      return Err("unexpected_payment_rent")
    end
    if List.length(value.pre_token_balances) != (if created do
        1
      else
        2
      end)
      || List.length(value.post_token_balances) != 2
      || !decrease(token_balance(value.pre_token_balances, source_index, quote.mint, payer)?,
        token_balance(value.post_token_balances, source_index, quote.mint, payer)?,
        amount)?
      || !increase(before_destination,
        token_balance(value.post_token_balances, destination, quote.mint, quote.deposit_owner)?,
        amount)?
      || !decrease(List.get(value.pre_balances, 0),
        List.get(value.post_balances, 0),
        U64.add(value.fee, rent)?)? do
      return Err("invalid_usdc_payment_balance")
    end
    Ok(amount)
  end
end

pub fn observe_payment_transfer(value :: FinalizedTransaction,
  quote :: CreditQuote,
  pinned_mint :: Bytes,
  price_observed_at :: U64,
  now :: U64) -> PaymentReceipt!String do
  check_payment_quote(quote, pinned_mint, price_observed_at, now)?
  let signed = value.signed
  let count = List.length(signed.instructions)
  if signed.header.num_required_signatures != 1
    || count < 1
    || count > 4
    || value.inner_instruction_count < 0 do
    return Err("unsupported_payment_shape")
  end
  let payer = List.get(signed.accounts, 0).pubkey.bytes
  if equal(payer, quote.deposit_owner) || equal(payer, quote.quote_id) || zero(payer) do
    return Err("invalid_payment_payer")
  end
  let block_time = case value.block_time do
    None -> return Err("missing_payment_time")
    Some(time) -> if time < 0 do
      return Err("invalid_payment_time")
    else
      U64.parse(Int.to_string(time))?
    end
  end
  if U64.compare(block_time, quote.issued_at) < 0
    || U64.compare(block_time, quote.expires_at) >= 0
    || U64.compare(block_time, now) > 0 do
    return Err("payment_outside_quote_window")
  end
  let compute = pubkey("ComputeBudget111111111111111111111111111111")?
  let ata = pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?
  let setup_index = if count >= 2
    && pubkey_equal(List.get(signed.instructions, count - 2).program_id, ata) do
    count - 2
  else
    -1
  end
  if setup_index >= 0 && quote.asset != 0 do
    return Err("unsupported_payment_setup")
  end
  let compute_count = count - 1 - (if setup_index >= 0 do
      1
    else
      0
    end)
  if compute_count > 2 do
    return Err("unsupported_payment_prefix")
  end
  let created = if setup_index >= 0 do
    validate_payment_ata_setup(value, quote, payer, setup_index)?
  else
    if value.inner_instruction_count != 0 do
      return Err("unexpected_payment_inner")
    end
    false
  end
  let prefixes = for index in 0..compute_count do
    let instruction = List.get(signed.instructions, index)
    if !pubkey_equal(instruction.program_id, compute) || List.length(instruction.accounts) != 0 do
      return Err("unsupported_payment_prefix")
    end
    let tag = Bytes.get(instruction.data, 0)?
    if !((tag == 2 && Bytes.length(instruction.data) == 5)
      || (tag == 3 && Bytes.length(instruction.data) == 9)) do
      return Err("unsupported_payment_prefix")
    end
    tag
  end
  if List.length(prefixes) == 2 && List.get(prefixes, 0) == List.get(prefixes, 1) do
    return Err("duplicate_payment_compute_budget")
  end
  let expected_accounts = if quote.asset == 1 do
    4
  else if setup_index >= 0 do
    9
  else
    6
  end
  if List.length(signed.accounts) != expected_accounts
      + (if compute_count > 0 do
        1
      else
        0
      end) do
    return Err("unexpected_payment_accounts")
  end
  let instruction = List.get(signed.instructions, count - 1)
  let program_meta = List.get(signed.accounts, account_index(value, instruction.program_id.bytes)?)
  if program_meta.signer || program_meta.writable do
    return Err("invalid_payment_program_role")
  end
  if compute_count > 0 do
    let compute_meta = List.get(signed.accounts, account_index(value, compute.bytes)?)
    if compute_meta.signer || compute_meta.writable do
      return Err("invalid_payment_compute_role")
    end
  end
  let amount = transfer_amount(value, quote, payer, instruction, created)?
  let destination_index = account_index(value, quote.destination)?
  for index in 0..List.length(value.pre_balances) do
    if index != 0
      && index != destination_index
      && List.get(value.pre_balances, index) != List.get(value.post_balances, index) do
      return Err("unexpected_payment_lamport_change")
    end
  end
  if amount == U64.parse("0")? do
    return Err("empty_credit_deposit")
  end
  Ok(PaymentReceipt {
    transaction_signature: signed.signature,
    payer: payer,
    slot: value.slot,
    block_time: block_time,
    received_amount: amount
  })
end

fn check_payment(value :: FinalizedTransaction,
  quote :: CreditQuote,
  pinned_mint :: Bytes,
  price_observed_at :: U64,
  now :: U64) -> PaymentReceipt!String do
  let payment = observe_payment_transfer(value, quote, pinned_mint, price_observed_at, now)?
  let maximum = U128.divide(U128.multiply(U128.parse(U64.to_string(quote.amount))?,
      U128.parse("101")?)?,
    U128.parse("100")?)?
  if U64.compare(payment.received_amount, quote.amount) < 0
    || U128.compare(U128.parse(U64.to_string(payment.received_amount))?, maximum) > 0 do
    return Err("payment_amount_outside_tolerance")
  end
  Ok(payment)
end

# Test/replay boundary: response must come from the issuer's configured RPC.
# Production issuance uses verify_credit_payment below, never caller metadata.
pub fn verify_payment_response(response :: RpcResponse,
  signature :: Bytes,
  id :: Int,
  quote :: CreditQuote,
  pinned_mint :: Bytes,
  price_observed_at :: U64,
  now :: U64) -> Option<PaymentReceipt>!String do
  case finalized_transaction_from_response(response, signature, id)? do
    None -> Ok(None)
    Some(value) -> Ok(Some(check_payment(value, quote, pinned_mint, price_observed_at, now)?))
  end
end

pub fn verify_credit_payment(client :: Int,
  url :: String,
  signature :: Bytes,
  id :: Int,
  quote :: CreditQuote,
  pinned_mint :: Bytes,
  price_observed_at :: U64,
  now :: U64) -> Option<PaymentReceipt>!String do
  check_payment_quote(quote, pinned_mint, price_observed_at, now)?
  case get_finalized_transaction(client, url, signature, id, 10000, 262144)? do
    None -> Ok(None)
    Some(value) -> Ok(Some(check_payment(value, quote, pinned_mint, price_observed_at, now)?))
  end
end
