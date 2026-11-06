from Solana.Read import Pubkey
from Solana.Address import ProgramDerivedAddress, find_program_address

# A codec is not authentication. Use the configured judge's derived receipt
# account and a finalized RPC quorum before presenting these amounts as paid.
pub struct SlashWitness do
  witness :: Bytes
  public_key :: Bytes
  principal :: U64
  slashed :: U64
  finder_amount :: U64
end

pub struct SlashReceipt do
  kind :: Int
  anchored :: Bool
  log_id :: Bytes
  proof_hash :: Bytes
  finder :: Bytes
  submitter :: Bytes
  mint :: Bytes
  first_checkpoint :: Bytes
  second_checkpoint :: Bytes
  slashed_at :: U64
  total_slashed :: U64
  finder_amount :: U64
  directory_slashed :: U64
  verified_signatures :: U64
  witnesses :: List<SlashWitness>
end

fn zeroes(bytes :: Bytes) -> Bool do
  Bytes.to_hex(bytes) == String.repeat("00", Bytes.length(bytes))
end

fn wide(bytes :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_le(bytes, offset) do
    Err(_) -> Err("invalid_slash_receipt")
    Ok(value)
  end
end

fn totals(rows :: List<SlashWitness>, amount :: U64, finder :: U64) -> (U64, U64)!String do
  if List.length(rows) == 0 do
    Ok((amount, finder))
  else
    let row = List.head(rows)
    totals(List.tail(rows), U64.add(amount, row.slashed)?, U64.add(finder, row.finder_amount)?)
  end
end

pub fn decode_slash_receipt(bytes :: Bytes) -> SlashReceipt!String do
  if Bytes.length(bytes) < 288
    || Bytes.length(bytes) > 1824
    || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d505201"
    || Bytes.get(bytes, 7)? != 0
    || !zeroes(Bytes.slice(bytes, 272, 16)?) do
    return Err("invalid_slash_receipt")
  end
  let count = Bytes.get(bytes, 6)?
  let kind = Bytes.get(bytes, 4)?
  let anchored = Bytes.get(bytes, 5)?
  if count > 16
    || Bytes.length(bytes) != 288 + 96 * count
    || kind < 1
    || kind > 3
    || anchored > 1 do
    return Err("invalid_slash_receipt")
  end
  let zero = U64.parse("0")?
  let ten = U64.parse("10")?
  let rows = for index in 0..count do
    let offset = 288 + 96 * index
    let row = SlashWitness {
      witness: Bytes.slice(bytes, offset, 32)?,
      public_key: Bytes.slice(bytes, offset + 32, 32)?,
      principal: wide(bytes, offset + 64)?,
      slashed: wide(bytes, offset + 72)?,
      finder_amount: wide(bytes, offset + 80)?
    }
    if zeroes(row.witness)
      || zeroes(row.public_key)
      || !zeroes(Bytes.slice(bytes, offset + 88, 8)?)
      || U64.compare(row.principal, row.slashed) > 0
      || (row.principal == zero && row.slashed != zero)
      || row.finder_amount != U64.divide(row.slashed, ten)? do
      return Err("invalid_slash_receipt")
    end
    row
  end
  for row in rows do
    if List.length(List.filter(rows,
      fn(other) do Bytes.secure_equals(other.witness, row.witness) end)) != 1 do
      return Err("invalid_slash_receipt")
    end
  end
  let value = SlashReceipt {
    kind: kind,
    anchored: anchored == 1,
    log_id: Bytes.slice(bytes, 8, 32)?,
    proof_hash: Bytes.slice(bytes, 40, 32)?,
    finder: Bytes.slice(bytes, 72, 32)?,
    submitter: Bytes.slice(bytes, 104, 32)?,
    mint: Bytes.slice(bytes, 136, 32)?,
    first_checkpoint: Bytes.slice(bytes, 168, 32)?,
    second_checkpoint: Bytes.slice(bytes, 200, 32)?,
    slashed_at: wide(bytes, 232)?,
    total_slashed: wide(bytes, 240)?,
    finder_amount: wide(bytes, 248)?,
    directory_slashed: wide(bytes, 256)?,
    verified_signatures: wide(bytes, 264)?,
    witnesses: rows
  }
  if zeroes(value.finder)
    || zeroes(value.submitter)
    || zeroes(value.mint)
    || value.slashed_at == zero
    || U64.compare(value.slashed_at, U64.parse("9223372036854775807")?) > 0
    || value.total_slashed == zero
    || U64.compare(value.verified_signatures, U64.parse("17179869183")?) > 0 do
    return Err("invalid_slash_receipt")
  end
  let service_bits = U64.to_int(value.verified_signatures)? % 4
  if (value.anchored && service_bits != 1) || (!value.anchored && service_bits != 3) do
    return Err("invalid_slash_receipt")
  end
  let (total, finder) = totals(rows,
    value.directory_slashed,
    U64.divide(value.directory_slashed, ten)?)?
  if total != value.total_slashed || finder != value.finder_amount do
    return Err("invalid_slash_receipt")
  end
  Ok(value)
end

pub fn slash_receipt_address(program :: Pubkey,
  log_id :: Bytes,
  proof_hash :: Bytes) -> Pubkey!String do
  if Bytes.length(log_id) != 32 || Bytes.length(proof_hash) != 32 do
    return Err("invalid_slash_receipt_identity")
  end
  Ok(find_program_address(program, [Bytes.from_utf8("proof"), log_id, proof_hash])?.address)
end
