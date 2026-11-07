from Transparency.AnchorWitnessSet import decode_anchor_witness_set, anchor_cosigners
from Transparency.AnchorRing import decode_anchor_entry

fn zeros(count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat("00", count))
end

fn join(parts :: List<Bytes>, output :: Bytes) -> Bytes!String do
  if List.length(parts) == 0 do
    Ok(output)
  else
    join(List.tail(parts), Bytes.concat(output, List.head(parts))?)
  end
end

fn member(id :: String, address :: String, key :: String) -> Bytes!String do
  join([
      Bytes.from_hex(String.repeat(address, 32))?,
      Bytes.from_hex("09")?,
      zeros(7)?,
      Bytes.from_utf8(id),
      zeros(55)?,
      Bytes.from_hex(String.repeat(key, 32))?,
      Bytes.from_hex(String.repeat("44", 32))?
    ],
    Bytes.empty())
end

fn record(second :: Bytes) -> Bytes!String do
  join([
      Bytes.from_hex("4d575301")?,
      Crypto.sha256(Bytes.from_utf8("morse-main")),
      Bytes.from_hex("ffff02000075120000000000")?,
      zeros(16)?,
      member("witness-a", "11", "22")?,
      second,
      zeros(14 * 168)?
    ],
    Bytes.empty())
end

fn replace(bytes :: Bytes, offset :: Int, value :: Int) -> Bytes!String do
  let replacement = case Bytes.from_list([value]) do
    Err(_) -> return Err("invalid fixture")
    Ok(value) -> value
  end
  join([
      Bytes.slice(bytes, 0, offset)?,
      replacement,
      Bytes.slice(bytes, offset + 1, Bytes.length(bytes) - offset - 1)?
    ],
    Bytes.empty())
end

fn proof() -> Bool!String do
  let wire = record(member("witness-b", "33", "55")?)?
  let set = decode_anchor_witness_set(wire)?
  assert(Bytes.length(wire) == 2752 && set.generation == 65535)
  assert(U64.to_string(set.ready_at) == "1209600" && List.length(set.witnesses) == 2)
  assert(List.get(set.witnesses, 1).witness_id == "witness-b")
  let entry = decode_anchor_entry(join([zeros(96)?, Bytes.from_hex("030002000100ffff")?],
    Bytes.empty())?)?
  let cosigners = anchor_cosigners(entry, set)?
  assert(List.length(cosigners) == 2)
  assert(List.get(cosigners, 0).native && !List.get(cosigners, 1).native)
  assert(Bytes.to_hex(List.get(cosigners, 1).public_key) == String.repeat("55", 32))
  case decode_anchor_entry(join([zeros(96)?, Bytes.from_hex("0100020001000000")?],
    Bytes.empty())?) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  for bad in [
    record(member("witness-a", "33", "55")?)?,
    record(member("witness-b", "33", "22")?)?,
    record(member("witness-b", "11", "55")?)?
  ] do
    case decode_anchor_witness_set(bad) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  for (offset, value) in [
    (0, 0),
    (38, 0),
    (38, 17),
    (39, 1),
    (47, 128),
    (48, 1),
    (64 + 32, 65),
    (64 + 33, 1),
    (64 + 40, 65),
    (64 + 103, 1),
    (2751, 1)
  ] do
    case decode_anchor_witness_set(replace(wire, offset, value)?) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  for invalid in [
    %{entry | witness_generation: 1},
    %{entry | cosign_bitmap: 4},
    %{entry | native_bitmap: 4}
  ] do
    case anchor_cosigners(invalid, set) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  Ok(true)
end

test("immutable generations preserve witness key attribution and native signature kind") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
