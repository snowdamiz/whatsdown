from Solana.Read import Pubkey, pubkey, pubkey_equal, spl_token_program
from Solana.Address import find_program_address
from Solana.Tx import (
  Instruction,
  create_associated_token_idempotent_instruction,
  transfer_checked_instruction
)
from Solana.TransactionRead import SignedTransaction, signed_transaction

# Typed native SDK request. The app never accepts a caller-supplied instruction
# list, mint, quantity, finder key or derivation index for a bounty movement.
pub struct BountyTransfer do
  index :: U64
  finder :: Bytes
  destination :: Bytes
  mint :: Bytes
  amount :: U64
  blockhash :: Bytes
  issued_at :: U64
  expires_at :: U64
  purpose :: Int
  decimals :: Int
end

fn nonzero(bytes :: Bytes) -> Bool do
  Bytes.length(bytes) == 32 && Bytes.to_hex(bytes) != String.repeat("00", 32)
end

fn same(left :: Bytes, right :: Bytes) -> Bool do
  Bytes.secure_equals(left, right)
end

fn valid(value :: BountyTransfer) -> Result<(), String> do
  if U64.compare(value.index, U64.parse("2147483648")?) >= 0
    || value.amount == U64.parse("0")?
    || !nonzero(value.finder)
    || !nonzero(value.destination)
    || !nonzero(value.mint)
    || !nonzero(value.blockhash)
    || same(value.finder, value.destination)
    || U64.add(value.issued_at, U64.parse("300")?)? != value.expires_at
    || value.purpose < 0
    || value.purpose > 1
    || value.decimals < 0
    || value.decimals > 18 do
    return Err("invalid_bounty_transfer")
  end
  Ok(nil)
end

fn wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Ok(bytes)
    Err(_) -> Err("invalid_bounty_transfer")
  end
end

fn number(bytes :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(bytes, offset) do
    Ok(value)
    Err(_) -> Err("invalid_bounty_transfer")
  end
end

pub fn encode_bounty_transfer(value :: BountyTransfer) -> Bytes!String do
  valid(value)?
  let flags = case Bytes.from_list([value.purpose, value.decimals]) do
    Ok(bytes) -> bytes
    Err(_) -> return Err("invalid_bounty_transfer")
  end
  List.reduce([
      Bytes.from_hex("01425754")?,
      wide(value.index)?,
      value.finder,
      value.destination,
      value.mint,
      wide(value.amount)?,
      value.blockhash,
      wide(value.issued_at)?,
      wide(value.expires_at)?,
      flags
    ],
    Ok(Bytes.empty()),
    fn(state, part) do
      case state do
        Err(error)
        Ok(bytes) -> Bytes.concat(bytes, part)
      end
    end)
end

pub fn decode_bounty_transfer(bytes :: Bytes) -> BountyTransfer!String do
  if Bytes.length(bytes) != 166 || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "01425754" do
    return Err("invalid_bounty_transfer")
  end
  let value = BountyTransfer {
    index: number(bytes, 4)?,
    finder: Bytes.slice(bytes, 12, 32)?,
    destination: Bytes.slice(bytes, 44, 32)?,
    mint: Bytes.slice(bytes, 76, 32)?,
    amount: number(bytes, 108)?,
    blockhash: Bytes.slice(bytes, 116, 32)?,
    issued_at: number(bytes, 148)?,
    expires_at: number(bytes, 156)?,
    purpose: Bytes.get(bytes, 164)?,
    decimals: Bytes.get(bytes, 165)?
  }
  valid(value)?
  Ok(value)
end

pub fn validate_bounty_transfer(value :: BountyTransfer,
  usdc :: Bytes,
  purpose :: Int,
  now :: U64) -> Result<(), String> do
  valid(value)?
  if !nonzero(usdc)
    || value.purpose != purpose
    || (same(value.mint, usdc) && value.decimals != 6)
    || U64.compare(now, value.issued_at) < 0
    || U64.compare(now, value.expires_at) >= 0 do
    return Err("invalid_bounty_transfer_context")
  end
  Ok(nil)
end

pub fn bounty_token_account(owner :: Bytes, mint :: Bytes) -> Pubkey!String do
  Ok(find_program_address(pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?,
    [owner, spl_token_program()?.bytes, mint])?.address)
end

pub fn bounty_transfer_instructions(value :: BountyTransfer,
  payer :: Pubkey) -> List<Instruction>!String do
  valid(value)?
  if !nonzero(payer.bytes) do
    return Err("invalid_bounty_transfer_payer")
  end
  let source = bounty_token_account(value.finder, value.mint)?
  let destination = bounty_token_account(value.destination, value.mint)?
  let roles = [
    payer.bytes,
    value.finder,
    value.mint,
    source.bytes,
    destination.bytes,
    pubkey("11111111111111111111111111111111")?.bytes,
    spl_token_program()?.bytes,
    pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?.bytes
  ]
  for index in 0..List.length(roles) do
    for previous in 0..index do
      if same(List.get(roles, index), List.get(roles, previous)) do
        return Err("invalid_bounty_transfer_alias")
      end
    end
  end
  if !same(value.destination, payer.bytes)
    && List.any(roles, fn(role) do same(role, value.destination) end) do
    return Err("invalid_bounty_transfer_alias")
  end
  Ok([
    create_associated_token_idempotent_instruction(payer,
      destination,
      Pubkey { bytes: value.destination },
      Pubkey { bytes: value.mint })?,
    transfer_checked_instruction(source,
      Pubkey { bytes: value.mint },
      destination,
      Pubkey { bytes: value.finder },
      value.amount,
      value.decimals)?
  ])
end

# Authenticate every signature and reconstruct the complete account-role union.
# Packet verification remains valid after expiry for recovery; a first send or
# signature commit separately checks the current native clock.
pub fn authenticate_bounty_transfer(wire :: Bytes,
  intent :: BountyTransfer,
  payer :: Pubkey,
  usdc :: Bytes,
  purpose :: Int) -> SignedTransaction!String do
  validate_bounty_transfer(intent, usdc, purpose, intent.issued_at)?
  if Bytes.length(wire) < 129 || Bytes.get(wire, 0)? != 2 do
    return Err("invalid_bounty_transfer_signatures")
  end
  let value = signed_transaction(wire, Bytes.slice(wire, 1, 64)?)?
  if value.version != -1
    || value.header.num_required_signatures != 2
    || !same(value.recent_blockhash, intent.blockhash)
    || !same(List.get(value.accounts, 0).pubkey.bytes, payer.bytes)
    || !same(List.get(value.accounts, 1).pubkey.bytes, intent.finder) do
    return Err("invalid_bounty_transfer_message")
  end
  let expected = bounty_transfer_instructions(intent, payer)?
  if List.length(value.instructions) != List.length(expected) do
    return Err("invalid_bounty_transfer_instructions")
  end
  for index in 0..List.length(expected) do
    let wanted = List.get(expected, index)
    let actual = List.get(value.instructions, index)
    if !pubkey_equal(wanted.program_id, actual.program_id)
      || !same(wanted.data, actual.data)
      || List.length(wanted.accounts) != List.length(actual.accounts) do
      return Err("invalid_bounty_transfer_instruction")
    end
    for position in 0..List.length(wanted.accounts) do
      if !pubkey_equal(List.get(wanted.accounts, position).pubkey,
        List.get(actual.accounts, position).pubkey) do
        return Err("invalid_bounty_transfer_account")
      end
    end
  end
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
      return Err("invalid_bounty_transfer_privileges")
    end
  end
  Ok(value)
end
