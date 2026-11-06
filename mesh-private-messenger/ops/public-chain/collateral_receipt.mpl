# Bytes only: ownership, canonical proof PDA, release pins and finality belong to
# CollateralRead. This mirrors token_proof.rs HEADER400/ROW144, never MPRv1.
pub struct PublicCollateralReceiptRow do
  identity :: Bytes
  witness :: Bytes
  public_key :: Bytes
  asset :: Int
  bonded_at :: U64
  principal :: U64
  slashed :: U64
  finder :: U64
end

pub struct PublicCollateralReceipt do
  kind :: Int
  anchored :: Bool
  settled :: Bool
  log_id :: Bytes
  proof_hash :: Bytes
  finder :: Bytes
  submitter :: Bytes
  usdc_mint :: Bytes
  morse_mint :: Bytes
  first_hash :: Bytes
  second_hash :: Bytes
  prepared_at :: U64
  usdc_slashed :: U64
  usdc_finder :: U64
  directory_usdc :: U64
  morse_slashed :: U64
  morse_finder :: U64
  directory_morse :: U64
  verified_signature_mask :: U64
  verified_signatures :: U64
  stage :: Bytes
  deadline_ms :: U64
  directory_bonded_at :: U64
  directory_asset :: Int
  settled_at :: U64
  rows :: List<PublicCollateralReceiptRow>
end

fn part(value :: Bytes, at :: Int, count :: Int) -> Bytes!String do
  Bytes.slice(value, at, count)
end

fn number(value :: Bytes, at :: Int) -> U64!String do
  U64.parse(Bytes.read_uint_le(value, at, 8)?)
end

fn zeroes(value :: Bytes, at :: Int, count :: Int) -> Bool!String do
  Ok(Bytes.to_hex(part(value, at, count)?) == String.repeat("00", count))
end

fn time(value :: Bytes, at :: Int) -> U64!String do
  let result = number(value, at)?
  if U64.compare(result, U64.parse("9223372036854775807")?) > 0 do
    Err("invalid_public_collateral_receipt")
  else
    Ok(result)
  end
end

# The stage stores a bit for each verified signature, not a numeric count.
# Count its eight bytes so the unsigned high bit never passes through Int.
fn signature_count(value :: Bytes) -> U64!String do
  let counts = for index in 0..8 do
    let byte = Bytes.get(value, 320 + index)?
    List.reduce([1, 2, 4, 8, 16, 32, 64, 128],
      0,
      fn(total, divisor) do total + (byte / divisor) % 2 end)
  end
  U64.parse(Int.to_string(List.reduce(counts, 0, fn(total, count) do total + count end)))
end

pub fn decode_public_collateral_receipt(value :: Bytes) -> PublicCollateralReceipt!String do
  if Bytes.length(value) < 400 || Bytes.length(value) > 2704 do
    return Err("invalid_public_collateral_receipt")
  end
  let kind = Bytes.get(value, 4)?
  let anchored = Bytes.get(value, 5)?
  let count = Bytes.get(value, 6)?
  let settled = Bytes.get(value, 7)?
  if Bytes.to_hex(part(value, 0, 4)?) != "4d505202"
    || kind < 1
    || kind > 3
    || anchored > 1
    || count > 16
    || settled > 1
    || Bytes.length(value) != 400 + count * 144
    || Bytes.get(value, 376)? > 1
    || !zeroes(value, 377, 7)?
    || !zeroes(value, 392, 8)? do
    return Err("invalid_public_collateral_receipt")
  end
  for at in [8, 40, 72, 104, 136, 168, 200, 232, 328] do
    if zeroes(value, at, 32)? do
      return Err("invalid_public_collateral_receipt")
    end
  end
  let zero = U64.parse("0")?
  let prepared_at = time(value, 264)?
  let bonded_at = time(value, 368)?
  let settled_at = time(value, 384)?
  let deadline = number(value, 360)?
  if part(value, 136, 32)? == part(value, 168, 32)?
    || prepared_at == zero
    || bonded_at == zero
    || U64.compare(bonded_at, prepared_at) > 0
    || U64.compare(U64.multiply(prepared_at, U64.parse("1000")?)?, deadline) > 0
    || (settled == 0 && (!zeroes(value, 272, 48)? || settled_at != zero))
    || (settled == 1
      && (U64.compare(settled_at, prepared_at) < 0
        || U64.compare(U64.multiply(settled_at, U64.parse("1000")?)?, deadline) > 0)) do
    return Err("invalid_public_collateral_receipt")
  end
  let rows = for index in 0..count do
    let at = 400 + index * 144
    let asset = Bytes.get(value, at + 96)?
    let bonded = time(value, at + 104)?
    let principal = number(value, at + 112)?
    let slashed = number(value, at + 120)?
    let finder = number(value, at + 128)?
    if zeroes(value, at, 32)?
      || zeroes(value, at + 32, 32)?
      || zeroes(value, at + 64, 32)?
      || asset > 1
      || !zeroes(value, at + 97, 7)?
      || !zeroes(value, at + 136, 8)?
      || bonded == zero
      || U64.compare(bonded, prepared_at) > 0
      || (settled == 0 && !zeroes(value, at + 112, 24)?)
      || U64.compare(slashed, principal) < 0
      || finder != U64.divide(slashed, U64.parse("10")?)? do
      return Err("invalid_public_collateral_receipt")
    end
    for previous in 0..index do
      if part(value, 400 + previous * 144, 32)? == part(value, at, 32)? do
        return Err("invalid_public_collateral_receipt")
      end
    end
    PublicCollateralReceiptRow {
      identity: part(value, at, 32)?,
      witness: part(value, at + 32, 32)?,
      public_key: part(value, at + 64, 32)?,
      asset: asset,
      bonded_at: bonded,
      principal: principal,
      slashed: slashed,
      finder: finder
    }
  end
  let directory_asset = Bytes.get(value, 376)?
  let directory_usdc = number(value, 288)?
  let directory_morse = number(value, 312)?
  if (directory_asset == 0 && directory_morse != zero)
    || (directory_asset == 1 && directory_usdc != zero) do
    return Err("invalid_public_collateral_receipt")
  end
  let totals = for asset in 0..2 do
    let directory = if asset == 0 do
      directory_usdc
    else
      directory_morse
    end
    let slashed = List.reduce(rows,
      Ok(directory),
      fn(total, row) do
        if row.asset == asset do
          U64.add(total?, row.slashed)
        else
          total
        end
      end)?
    let finder = List.reduce(rows,
      Ok(U64.divide(directory, U64.parse("10")?)?),
      fn(total, row) do
        if row.asset == asset do
          U64.add(total?, row.finder)
        else
          total
        end
      end)?
    (slashed, finder)
  end
  let (usdc_slashed, usdc_finder) = List.get(totals, 0)
  let (morse_slashed, morse_finder) = List.get(totals, 1)
  if settled == 1
    && (usdc_slashed != number(value, 272)?
      || usdc_finder != number(value, 280)?
      || morse_slashed != number(value, 296)?
      || morse_finder != number(value, 304)?
      || (usdc_slashed == zero && morse_slashed == zero)) do
    return Err("invalid_public_collateral_receipt")
  end
  Ok(PublicCollateralReceipt {
    kind: kind,
    anchored: anchored == 1,
    settled: settled == 1,
    log_id: part(value, 8, 32)?,
    proof_hash: part(value, 40, 32)?,
    finder: part(value, 72, 32)?,
    submitter: part(value, 104, 32)?,
    usdc_mint: part(value, 136, 32)?,
    morse_mint: part(value, 168, 32)?,
    first_hash: part(value, 200, 32)?,
    second_hash: part(value, 232, 32)?,
    prepared_at: prepared_at,
    usdc_slashed: usdc_slashed,
    usdc_finder: usdc_finder,
    directory_usdc: directory_usdc,
    morse_slashed: morse_slashed,
    morse_finder: morse_finder,
    directory_morse: directory_morse,
    verified_signature_mask: number(value, 320)?,
    verified_signatures: signature_count(value)?,
    stage: part(value, 328, 32)?,
    deadline_ms: deadline,
    directory_bonded_at: bonded_at,
    directory_asset: directory_asset,
    settled_at: settled_at,
    rows: rows
  })
end
