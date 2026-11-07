from Mobile.CreditState import (
  CreditRecord,
  CreditWallet,
  encode_credit_wallet,
  decode_credit_wallet,
  pack_credit_parts,
  unpack_credit_parts
)
from Mobile.Codec import mobile_byte, mobile_vector, mobile_write_u64
from Tests.Support import repeated

fn record(kind :: Int, id :: Int) -> CreditRecord!String do
  Ok(CreditRecord {
    kind: kind,
    id: repeated(id, 32)?,
    metadata: Bytes.from_hex("0001ff")?,
    payload: Bytes.from_hex("ff000102030405")?
  })
end

fn raw(value :: CreditRecord) -> Bytes!String do
  Bytes.concat(Bytes.concat(mobile_byte(value.kind)?, value.id)?,
    Bytes.concat(mobile_vector(value.metadata)?, mobile_vector(value.payload)?)?)
end

fn frame(parts :: List<Bytes>) -> Bytes!String do
  Bytes.concat(Bytes.concat(Bytes.from_hex("01435753")?,
      mobile_write_u64(U64.parse("18446744073709551615")?)?)?,
    pack_credit_parts(parts)?)
end

fn canonical() -> Bool!String do
  let records = for kind in [1, 2, 3, 4, 7, 8] do
    record(kind, 1)?
  end
  let wire = frame(for value in records do
    raw(value)?
  end)?
  let decoded = decode_credit_wallet(wire)?
  assert(decoded.revision == U64.parse("18446744073709551615")?)
  assert(decoded.records == records)
  assert(encode_credit_wallet(decoded) == Ok(wire))
  assert(decode_credit_wallet(frame([])?) == Ok(CreditWallet {
      revision: decoded.revision,
      records: []
    }))
  # Fixed-width counters and length prefixes have one representation; every
  # truncation or extra suffix must still fail after removing re-encoding.
  for length in 0..Bytes.length(wire) do
    assert(Result.is_err(decode_credit_wallet(Bytes.slice(wire, 0, length)?)))
  end
  assert(decode_credit_wallet(Bytes.concat(wire,
    Bytes.from_hex("00")?)?) == Err("invalid_credit_wallet"))
  Ok(true)
end

test("wallet canonical decoding preserves exact fixed-width framing and record bytes") do
  case canonical() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn refusals() -> Bool!String do
  let a = raw(record(2, 1)?)?
  let b = raw(record(2, 2)?)?
  let c = raw(record(3, 1)?)?
  assert(Result.is_ok(decode_credit_wallet(frame([a, b, c])?)))
  assert(decode_credit_wallet(frame([b, a, c])?) == Err("invalid_credit_wallet"))
  assert(decode_credit_wallet(frame([a, c, b])?) == Err("invalid_credit_wallet"))
  assert(decode_credit_wallet(frame([a, a])?) == Err("duplicate_credit_wallet_record"))
  # Duplicates take precedence over noncanonical order even when separated.
  assert(decode_credit_wallet(frame([b, a, b])?) == Err("duplicate_credit_wallet_record"))
  let invalid = raw(record(5, 1)?)?
  assert(decode_credit_wallet(frame([b, a, b, invalid])?) == Err("invalid_credit_wallet_record"))
  assert(decode_credit_wallet(frame([
    raw(%{record(2, 1)? | id: repeated(0, 32)?})?
  ])?) == Err("invalid_credit_wallet_record"))
  let legacy = raw(%{record(6, 1)? | metadata: repeated(7, 36)?})?
  assert(decode_credit_wallet(frame([
    legacy
  ])?) == Err("legacy_credit_attachment_requires_private_load"))
  let malformed_wrapper = raw(%{record(6, 1)? | metadata: Bytes.from_hex("0241494a00000000")?})?
  assert(Result.is_err(decode_credit_wallet(frame([malformed_wrapper])?)))
  Ok(true)
end

test("wallet canonical decoding keeps ordering duplicate and private-loader refusals") do
  case refusals() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
