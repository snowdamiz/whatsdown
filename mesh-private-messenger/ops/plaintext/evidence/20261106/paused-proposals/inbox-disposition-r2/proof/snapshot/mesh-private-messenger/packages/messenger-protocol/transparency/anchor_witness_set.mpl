from Transparency.Config import valid_witness_id
from Transparency.AnchorRing import AnchorEntry, anchor_bitmap_contains

# Decoding alone authenticates neither an account nor a release trust policy.
# The reader must authenticate the program, PDA, log and generation first.
pub struct AnchorWitness do
  address :: Bytes
  witness_id :: String
  public_key :: Bytes
  payout :: Bytes
end

pub struct AnchorWitnessSet do
  log_id :: Bytes
  generation :: Int
  ready_at :: U64
  witnesses :: List<AnchorWitness>
end

pub struct AnchorCosigner do
  witness_id :: String
  public_key :: Bytes
  native :: Bool
end

fn zeroes(bytes :: Bytes, offset :: Int, length :: Int) -> Bool!String do
  Ok(Bytes.to_hex(Bytes.slice(bytes, offset, length)?) == String.repeat("00", length))
end

fn member(bytes :: Bytes) -> AnchorWitness!String do
  let length = Bytes.get(bytes, 32)?
  if length == 0
    || length > 64
    || !zeroes(bytes, 33, 7)?
    || !zeroes(bytes, 40 + length, 64 - length)?
    || zeroes(bytes, 0, 32)?
    || zeroes(bytes, 104, 32)?
    || zeroes(bytes, 136, 32)? do
    return Err("invalid_anchor_witness_set")
  end
  let id = Bytes.to_utf8(Bytes.slice(bytes, 40, length)?)?
  if !valid_witness_id(id) do
    return Err("invalid_anchor_witness_set")
  end
  Ok(AnchorWitness {
    address: Bytes.slice(bytes, 0, 32)?,
    witness_id: id,
    public_key: Bytes.slice(bytes, 104, 32)?,
    payout: Bytes.slice(bytes, 136, 32)?
  })
end

pub fn decode_anchor_witness_set(bytes :: Bytes) -> AnchorWitnessSet!String do
  if Bytes.length(bytes) != 2752 || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d575301" do
    return Err("invalid_anchor_witness_set")
  end
  let generation = case Bytes.read_u16_le(bytes, 36) do
    Err(_) -> return Err("invalid_anchor_witness_set")
    Ok(value) -> value
  end
  let ready_at = case Bytes.read_u64_le(bytes, 40) do
    Err(_) -> return Err("invalid_anchor_witness_set")
    Ok(value) -> value
  end
  let count = Bytes.get(bytes, 38)?
  if generation == 0
    || count == 0
    || count > 16
    || Bytes.get(bytes, 39)? != 0
    || U64.compare(ready_at, U64.parse("9223372036854775807")?) > 0
    || !zeroes(bytes, 48, 16)?
    || !zeroes(bytes, 64 + count * 168, (16 - count) * 168)? do
    return Err("invalid_anchor_witness_set")
  end
  let witnesses = for index in 0..count do
    member(Bytes.slice(bytes, 64 + index * 168, 168)?)?
  end
  for index in 0..count do
    let witness = List.get(witnesses, index)
    if index > 0 && List.get(witnesses, index - 1).witness_id >= witness.witness_id do
      return Err("invalid_anchor_witness_set")
    end
    for earlier in 0..index do
      let previous = List.get(witnesses, earlier)
      if Bytes.secure_equals(previous.public_key, witness.public_key)
        || Bytes.secure_equals(previous.address, witness.address) do
        return Err("invalid_anchor_witness_set")
      end
    end
  end
  Ok(AnchorWitnessSet {
    log_id: Bytes.slice(bytes, 4, 32)?,
    generation: generation,
    ready_at: ready_at,
    witnesses: witnesses
  })
end

# Attribution only: a chain-registered witness is not automatically a native
# release pin, and C2SP signatures do not acquire Morse's stronger semantics.
pub fn anchor_cosigners(entry :: AnchorEntry,
  set :: AnchorWitnessSet) -> List<AnchorCosigner>!String do
  let count = List.length(set.witnesses)
  if count == 0
    || count > 16
    || set.generation <= 0
    || set.generation > 65535
    || entry.witness_generation != set.generation
    || entry.cosign_bitmap < 0
    || entry.cosign_bitmap > 65535
    || entry.native_bitmap < 0
    || entry.native_bitmap > 65535 do
    return Err("anchor_witness_set_mismatch")
  end
  for index in 0..16 do
    if (index >= count && anchor_bitmap_contains(entry.cosign_bitmap, index))
      || (anchor_bitmap_contains(entry.native_bitmap, index)
        && !anchor_bitmap_contains(entry.cosign_bitmap, index)) do
      return Err("anchor_witness_set_mismatch")
    end
  end
  Ok(for index in 0..count when anchor_bitmap_contains(entry.cosign_bitmap, index) do
    let witness = List.get(set.witnesses, index)
    AnchorCosigner {
      witness_id: witness.witness_id,
      public_key: witness.public_key,
      native: anchor_bitmap_contains(entry.native_bitmap, index)
    }
  end)
end
