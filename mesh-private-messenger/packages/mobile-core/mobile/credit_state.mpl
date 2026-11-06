from Binary.Reader import BinaryReader
from Mobile.Codec import (
  mobile_reader,
  mobile_finish,
  take_fixed,
  take_vector,
  mobile_byte,
  mobile_read_byte,
  mobile_read_u32,
  mobile_read_u64,
  mobile_vector,
  mobile_write_u32,
  mobile_write_u64
)

# Every bearer token and blinding-state payload is separately sealed. These
# records contain ciphertext plus local metadata and enter an encrypted wallet.
# 1 admitted issuer, 2 pending purchase, 3 completed token, 4 exact reservation.
# 6 sealed attachment intent, 7 immutable native wallet payment journal.
# 8 sealed recipient-postage batch, original snapshot and reply-key handle.
pub struct CreditRecord do
  kind :: Int
  id :: Bytes
  metadata :: Bytes
  payload :: Bytes
end

pub struct CreditWallet do
  revision :: U64
  records :: List<CreditRecord>
end

pub fn empty_credit_wallet() -> CreditWallet!String do
  Ok(CreditWallet { revision: U64.parse("0")?, records: [] })
end

pub fn credit_record_id(value :: Bytes) -> Bool do
  Bytes.length(value) == 32 && Bytes.to_hex(value) != String.repeat("00", 32)
end

# Business capacity stays at the old encoded-wallet limit. Only canonical v2
# attachment envelopes receive their exact structural overhead as headroom.
pub fn credit_wallet_physical_limit() -> Int do
  15360000 + 8192 * 91
end

pub fn credit_wallet_chunk_limit() -> Int do
  (credit_wallet_physical_limit() + 59999) / 60000
end

pub fn pack_credit_parts(parts :: List<Bytes>) -> Bytes!String do
  let prefix = mobile_write_u32(List.length(parts))?
  let framed = for part in parts do
    mobile_vector(part)?
  end
  # Preserve the generic encoder's address-space bound; wallet admission applies
  # its own smaller logical limit after framing. The limit reserves no storage.
  case Bytes.concat_many([prefix] ++ framed, 9223372036854775807) do
    Ok(value) -> Ok(value)
    Err(_) -> Err("byte length overflow")
  end
end

# Accumulate in wire order: appending preserves earlier immutable views and
# avoids copying every preceding list when the record count reaches 8192.
fn read_parts(state :: BinaryReader,
  count :: Int,
  maximum :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if count == 0 do
    mobile_finish(state, "invalid_credit_wallet")?
    Ok(output)
  else
    let part = take_vector(state, maximum)?
    read_parts(part.state, count - 1, maximum, List.append(output, part.value))
  end
end

pub fn unpack_credit_parts(input :: Bytes,
  maximum_count :: Int,
  maximum_part :: Int) -> List<Bytes>!String do
  let state = mobile_reader(input, credit_wallet_physical_limit(), "invalid_credit_wallet")?
  let count = take_fixed(state, 4)?
  let size = mobile_read_u32(count.value)?
  if size > maximum_count do
    Err("credit_wallet_capacity")
  else
    read_parts(count.state, size, maximum_part, [])
  end
end

fn record_order(left :: CreditRecord, right :: CreditRecord) -> Int do
  if left.kind < right.kind do
    -1
  else if left.kind > right.kind do
    1
  else if Bytes.to_hex(left.id) < Bytes.to_hex(right.id) do
    -1
  else if Bytes.to_hex(left.id) > Bytes.to_hex(right.id) do
    1
  else
    0
  end
end

fn validate_record(value :: CreditRecord) -> Result<(), String> do
  if value.kind < 1
    || (value.kind > 4 && value.kind != 6 && value.kind != 7 && value.kind != 8)
    || !credit_record_id(value.id)
    || Bytes.length(value.metadata) > 8192
    || Bytes.length(value.payload) > 4200000 do
    return Err("invalid_credit_wallet_record")
  end
  if value.kind == 6 do
    if valid_credit_attachment_metadata(value.metadata) do
      credit_attachment_journal_parts(value.payload)?
      nil
    else if Bytes.length(value.metadata) != 36 && Bytes.length(value.metadata) != 68 do
      return Err("invalid_credit_attachment_material")
    else
      nil
    end
  end
  Ok(nil)
end

fn encode_record(value :: CreditRecord) -> Bytes!String do
  validate_record(value)?
  Bytes.concat(Bytes.concat(mobile_byte(value.kind)?, value.id)?,
    Bytes.concat(mobile_vector(value.metadata)?, mobile_vector(value.payload)?)?)
end

# Attachment v2 public metadata carries only its version, cleanup cursor and
# optional immutable action ID. The private binding is sealed in its payload.
pub fn valid_credit_attachment_metadata(value :: Bytes) -> Bool do
  (Bytes.length(value) == 8 || Bytes.length(value) == 40)
    && String.starts_with(Bytes.to_hex(value), "0241494a")
end

fn storage_envelope_size(value :: Bytes) -> Int!String do
  if Bytes.length(value) < 67 || !String.starts_with(Bytes.to_hex(value), "010001") do
    return Err("invalid_credit_attachment_material")
  end
  let size = mobile_read_u32(Bytes.slice(value, 47, 4)?)?
  if size > 65536 || Bytes.length(value) != 67 + size do
    Err("invalid_credit_attachment_material")
  else
    Ok(size)
  end
end

# This is structural admission for capacity accounting, not an AEAD claim.
pub fn credit_attachment_journal_parts(payload :: Bytes) -> List<Bytes>!String do
  let parts = unpack_credit_parts(payload, 3, 4200000)?
  if List.length(parts) != 3 || Bytes.to_hex(List.head(parts)) != "02414950" do
    return Err("invalid_credit_attachment_material")
  end
  if Bytes.length(List.get(parts, 2)) != 99 || storage_envelope_size(List.get(parts, 2))? != 32 do
    return Err("invalid_credit_attachment_material")
  end
  let original = unpack_credit_parts(List.get(parts, 1), 2, 66000)?
  if List.length(original) != 2 || storage_envelope_size(List.head(original))? != 42 do
    return Err("invalid_credit_attachment_material")
  end
  let material_size = storage_envelope_size(List.get(original, 1))?
  # Existing attachment material is exactly two <=1024-byte vectors, so its
  # complete private frame is12..2060 bytes and uses one storage chunk.
  if material_size < 12 || material_size > 2060 do
    Err("invalid_credit_attachment_material")
  else
    Ok(parts)
  end
end

pub fn credit_attachment_cursor(value :: Bytes) -> Int!String do
  if !valid_credit_attachment_metadata(value) do
    Err("invalid_credit_attachment_material")
  else
    mobile_read_u32(Bytes.slice(value, 4, 4)?)
  end
end

fn decode_record(input :: Bytes) -> CreditRecord!String do
  let state = mobile_reader(input, 4208233, "invalid_credit_wallet_record")?
  let kind = take_fixed(state, 1)?
  let id = take_fixed(kind.state, 32)?
  let metadata = take_vector(id.state, 8192)?
  let payload = take_vector(metadata.state, 4200000)?
  mobile_finish(payload.state, "invalid_credit_wallet_record")?
  let record_kind = mobile_read_byte(kind.value)?
  if record_kind == 6 && !valid_credit_attachment_metadata(metadata.value) do
    return Err("legacy_credit_attachment_requires_private_load")
  end
  let value = CreditRecord {
    kind: record_kind,
    id: id.value,
    metadata: metadata.value,
    payload: payload.value
  }
  validate_record(value)?
  Ok(value)
end

pub fn encode_credit_wallet(value :: CreditWallet) -> Bytes!String do
  if List.length(value.records) > 8192 do
    return Err("credit_wallet_capacity")
  end
  let ordered = List.sort(value.records, record_order)
  let encoded = for index in 0..List.length(ordered) do
    let item = List.get(ordered, index)
    if index > 0 && record_order(List.get(ordered, index - 1), item) == 0 do
      return Err("duplicate_credit_wallet_record")
    end
    encode_record(item)?
  end
  let output = Bytes.concat(Bytes.concat(Bytes.from_hex("01435753")?,
      mobile_write_u64(value.revision)?)?,
    pack_credit_parts(encoded)?)?
  credit_wallet_logical_size(value.records, Bytes.length(output))?
  Ok(output)
end

fn credit_wallet_logical_size(records :: List<CreditRecord>, physical :: Int) -> Int!String do
  if List.length(records) > 8192 || physical > credit_wallet_physical_limit() do
    return Err("credit_wallet_capacity")
  end
  let eligible = for record in records do
    if record.kind == 6 && valid_credit_attachment_metadata(record.metadata) do
      credit_attachment_journal_parts(record.payload)?
      true
    else
      false
    end
  end
  let attachments = List.length(List.filter(eligible, fn(value) -> value end))
  let logical = physical - attachments * 91
  if logical > 15360000 do
    Err("credit_wallet_capacity")
  else
    Ok(logical)
  end
end

pub fn decode_credit_wallet(input :: Bytes) -> CreditWallet!String do
  if Bytes.length(input) < 16
    || Bytes.length(input) > credit_wallet_physical_limit()
    || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01435753" do
    return Err("invalid_credit_wallet")
  end
  let parts = unpack_credit_parts(Bytes.slice(input, 12, Bytes.length(input) - 12)?, 8192, 4208233)?
  let records = for part in parts do
    decode_record(part)?
  end
  let value = CreditWallet {
    revision: mobile_read_u64(Bytes.slice(input, 4, 8)?)?,
    records: records
  }
  # Fixed-width integers and exact vectors already have one wire encoding.
  # Check the remaining canonical constraints without rebuilding all payloads.
  # Preserve duplicate and logical-capacity failures before ordering failures.
  let ordered = List.sort(records, record_order)
  for index in 1..List.length(ordered) do
    if record_order(List.get(ordered, index - 1), List.get(ordered, index)) == 0 do
      return Err("duplicate_credit_wallet_record")
    end
  end
  credit_wallet_logical_size(records, Bytes.length(input))?
  for index in 1..List.length(records) do
    if record_order(List.get(records, index - 1), List.get(records, index)) > 0 do
      return Err("invalid_credit_wallet")
    end
  end
  Ok(value)
end

pub fn find_credit_record(wallet :: CreditWallet,
  kind :: Int,
  id :: Bytes) -> Option<CreditRecord> do
  List.find(wallet.records,
    fn(value) do value.kind == kind && Bytes.secure_equals(value.id, id) end)
end

pub fn put_credit_record(wallet :: CreditWallet, record :: CreditRecord) -> CreditWallet do
  CreditWallet {
    revision: wallet.revision,
    records: [record]
      ++ List.filter(wallet.records,
        fn(value) do value.kind != record.kind || !Bytes.secure_equals(value.id, record.id) end)
  }
end

pub fn remove_credit_records(wallet :: CreditWallet,
  kind :: Int,
  ids :: List<Bytes>) -> CreditWallet do
  CreditWallet {
    revision: wallet.revision,
    records: List.filter(wallet.records,
      fn(value) do value.kind != kind
        || !List.any(ids, fn(id) do Bytes.secure_equals(value.id, id) end) end)
  }
end
