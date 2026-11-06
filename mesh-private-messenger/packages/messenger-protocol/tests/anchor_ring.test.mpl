from Transparency.AnchorRing import (
  AnchorHeader,
  AnchorEntry,
  decode_anchor_header,
  decode_anchor_entry,
  anchor_entry_offset,
  anchor_entry_in_header
)

# Independent little-endian fixtures; no encoder under test constructs these.
fn header_bytes(head :: String, count :: String) -> Bytes!String do
  Bytes.from_hex("4d524701"
    <> String.repeat("11", 32)
    <> head
    <> count
    <> "ffffffffffffffff"
    <> "ffffffffffffffff"
    <> "f401000000000000")
end

fn entry_bytes(tail :: String) -> Bytes!String do
  Bytes.from_hex("ffffffffffffffffffffffffffffffff"
    <> String.repeat("22", 32)
    <> String.repeat("33", 32)
    <> "00f1536500000000f401000000000000"
    <> tail)
end

fn proof() -> Bool!String do
  let header = decode_anchor_header(header_bytes("ff0f", "0010")?)?
  let entry = decode_anchor_entry(entry_bytes("0300020101000700")?)?
  assert(header.head == 4095 && header.count == 4096)
  assert(U64.to_string(header.last_sequence) == "18446744073709551615")
  assert(U64.to_string(entry.tree_size) == "18446744073709551615")
  assert(entry.log_version == 2 && entry.rollback && entry.cosign_bitmap == 3)
  assert(entry.native_bitmap == 1 && entry.witness_generation == 7)
  assert(anchor_entry_offset(header, 0)? == 425944)
  assert(anchor_entry_offset(header, 4095)? == 64)
  assert(anchor_entry_in_header(header, entry, 0))
  assert(!anchor_entry_in_header(header, %{entry | slot: U64.parse("501")?}, 0))
  assert(!anchor_entry_in_header(header, %{entry | sequence: U64.parse("1")?}, 0))
  let wrapped = %{header | head: 0}
  assert(anchor_entry_offset(wrapped, 1)? == 425944)
  for invalid in [
    header_bytes("0010", "0010")?,
    header_bytes("0000", "0110")?,
    header_bytes("0200", "0200")?,
    header_bytes("0000", "0000")?,
    Bytes.concat(header_bytes("ff0f", "0010")?, Bytes.from_hex("00")?)?
  ] do
    case decode_anchor_header(invalid) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  for tail in ["0100020002000700", "0300030001000700", "0300020201000700"] do
    case decode_anchor_entry(entry_bytes(tail)?) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  case anchor_entry_offset(header, 4096) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  let empty = decode_anchor_header(Bytes.from_hex("4d524701"
    <> String.repeat("11", 32)
    <> String.repeat("00", 28))?)?
  assert(empty.count == 0)
  case anchor_entry_offset(empty, 0) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  Ok(true)
end

test("anchor ring slices retain u64 values, canonical bounds and overwritten-entry checks") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
