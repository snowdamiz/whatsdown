from Transparency.SlashReceipt import (
  SlashReceipt,
  SlashWitness,
  decode_slash_receipt,
  slash_receipt_address
)
from Solana.Read import pubkey

fn join(parts :: List<Bytes>, output :: Bytes) -> Bytes!String do
  if List.length(parts) == 0 do
    Ok(output)
  else
    join(List.tail(parts), Bytes.concat(output, List.head(parts))?)
  end
end

fn wide(text :: String) -> Bytes!String do
  case Bytes.write_uint_le(text, 8) do
    Err(_) -> Err("fixture_integer")
    Ok(value)
  end
end

fn replace(bytes :: Bytes, offset :: Int, value :: Bytes) -> Bytes!String do
  join([
      Bytes.slice(bytes, 0, offset)?,
      value,
      Bytes.slice(bytes,
        offset + Bytes.length(value),
        Bytes.length(bytes) - offset - Bytes.length(value))?
    ],
    Bytes.empty())
end

fn fixture() -> Bytes!String do
  join([
      Bytes.from_hex("4d50520101000100"
        <> String.repeat("11", 32)
        <> String.repeat("22", 32)
        <> String.repeat("33", 32)
        <> String.repeat("44", 32)
        <> String.repeat("55", 32)
        <> String.repeat("66", 32)
        <> String.repeat("77", 32))?,
      wide("1700000001")?,
      wide("18446744073709551615")?,
      wide("1844674407370955160")?,
      wide("18446744073709551606")?,
      wide("15")?,
      Bytes.from_hex(String.repeat("00", 16))?,
      Bytes.from_hex(String.repeat("88", 32) <> String.repeat("99", 32))?,
      wide("1")?,
      wide("9")?,
      wide("0")?,
      wide("0")?
    ],
    Bytes.empty())
end

fn refused(bytes :: Bytes) do
  case decode_slash_receipt(bytes) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
end

fn proof() -> Bool!String do
  let wire = fixture()?
  let value = decode_slash_receipt(wire)?
  assert(value.kind == 1 && !value.anchored && List.length(value.witnesses) == 1)
  assert(U64.to_string(value.total_slashed) == "18446744073709551615")
  assert(U64.to_string(value.finder_amount) == "1844674407370955160")
  assert(U64.to_string(List.head(value.witnesses).slashed) == "9")
  for length in 0..384 do
    refused(Bytes.slice(wire, 0, length)?)
  end
  refused(Bytes.concat(wire, Bytes.from_hex("00")?)?)
  for offset in [0, 4, 5, 6, 7, 272, 287, 376, 383] do
    refused(replace(wire, offset, Bytes.from_hex("ff")?)?)
  end
  for offset in [72, 104, 136, 288, 320] do
    refused(replace(wire, offset, Bytes.from_hex(String.repeat("00", 32))?)?)
  end
  for offset in [240, 248, 256, 352, 360, 368] do
    refused(replace(wire, offset, wide("10")?)?)
  end
  refused(replace(wire, 232, wide("9223372036854775808")?)?)
  refused(replace(wire, 232, wide("0")?)?)
  for bits in ["0", "1", "2", "17179869184", "18446744073709551615"] do
    refused(replace(wire, 264, wide(bits)?)?)
  end
  let anchored = replace(replace(wire, 5, Bytes.from_hex("01")?)?, 264, wide("5")?)?
  assert(decode_slash_receipt(anchored)?.anchored)
  refused(replace(anchored, 264, wide("7")?)?)
  let row = Bytes.slice(wire, 288, 96)?
  let duplicated = Bytes.concat(replace(wire, 6, Bytes.from_hex("02")?)?, row)?
  # Keep the arithmetic valid so this isolates duplicate identity rejection.
  let duplicated = replace(replace(replace(replace(duplicated, 240, wide("118")?)?,
        248,
        wide("10")?)?,
      256,
      wide("100")?)?,
    264,
    wide("63")?)?
  refused(duplicated)
  let header = replace(replace(replace(replace(Bytes.slice(wire, 0, 288)?,
          6,
          Bytes.from_hex("10")?)?,
        256,
        wide("18446744073709551599")?)?,
      248,
      wide("1844674407370955159")?)?,
    264,
    wide("17179869183")?)?
  let rows = for index in 0..16 do
    let address = case Bytes.from_list(for _ in 0..32 do
      index + 1
    end) do
      Err(_) -> return Err("fixture_address")
      Ok(value) -> value
    end
    replace(replace(replace(row, 0, address)?, 64, wide("1")?)?, 72, wide("1")?)?
  end
  let maximum = join(rows, header)?
  assert(Bytes.length(maximum) == 1824)
  assert(List.length(decode_slash_receipt(maximum)?.witnesses) == 16)
  for length in 0..1824 do
    refused(Bytes.slice(maximum, 0, length)?)
  end
  refused(Bytes.concat(maximum, row)?)
  let zero = wide("0")?
  let empty = replace(replace(replace(replace(Bytes.slice(wire, 0, 288)?,
          6,
          Bytes.from_hex("00")?)?,
        240,
        wide("10")?)?,
      248,
      wide("1")?)?,
    256,
    wide("10")?)?
  assert(List.length(decode_slash_receipt(empty)?.witnesses) == 0)
  refused(replace(replace(replace(empty, 240, zero)?, 248, zero)?, 256, zero)?)
  let program = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let address = slash_receipt_address(program, value.log_id, value.proof_hash)?
  assert(!Bytes.secure_equals(address.bytes,
    slash_receipt_address(program, value.proof_hash, value.log_id)?.bytes))
  case slash_receipt_address(program, Bytes.empty(), value.proof_hash) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  Ok(true)
end

test("slash receipts preserve u64 amounts and refuse inconsistent payouts or identities") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
