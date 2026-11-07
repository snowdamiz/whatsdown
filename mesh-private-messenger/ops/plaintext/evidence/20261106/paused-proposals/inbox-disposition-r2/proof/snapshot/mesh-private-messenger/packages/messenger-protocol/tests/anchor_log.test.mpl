from Transparency.AnchorLog import AnchorLog, decode_anchor_log

fn join(parts :: List<Bytes>, output :: Bytes) -> Bytes!String do
  if List.length(parts) == 0 do
    Ok(output)
  else
    join(List.tail(parts), Bytes.concat(output, List.head(parts))?)
  end
end

fn record(slashed :: Int) -> Bytes!String do
  let name = Bytes.from_utf8("morse-main")
  let origin = Bytes.from_utf8("morseapp.io/log/main/v2")
  join([
      Bytes.from_hex("4d4c470102")?,
      byte(slashed)?,
      Bytes.from_hex("0a00")?,
      name,
      Bytes.from_hex(String.repeat("00", 22))?,
      Crypto.sha256(name),
      Bytes.from_hex(String.repeat("11", 32))?,
      Bytes.from_hex(String.repeat("22", 32))?,
      Bytes.from_hex(String.repeat("33", 32))?,
      Bytes.from_hex(String.repeat("00", 32))?,
      Bytes.from_hex("007512000000000000001700")?,
      origin,
      Bytes.from_hex(String.repeat("00", 128 - Bytes.length(origin) + 12))?
    ],
    Bytes.empty())
end

fn replace(bytes :: Bytes, offset :: Int, value :: Int) -> Bytes!String do
  join([
      Bytes.slice(bytes, 0, offset)?,
      byte(value)?,
      Bytes.slice(bytes, offset + 1, Bytes.length(bytes) - offset - 1)?
    ],
    Bytes.empty())
end

fn proof() -> Bool!String do
  let wire = record(0)?
  let log = decode_anchor_log(wire)?
  assert(Bytes.length(wire) == 352 && log.name == "morse-main")
  assert(log.version == 2 && !log.service_slashed && log.witness_generation == 0)
  assert(log.origin == "morseapp.io/log/main/v2" && U64.to_string(log.ready_at) == "1209600")
  assert(decode_anchor_log(record(1)?)?.service_slashed)
  assert(!log.attendance_enabled)
  assert(decode_anchor_log(replace(wire, 7, 1)?)?.attendance_enabled)
  assert(Bytes.to_hex(log.ring_address) == String.repeat("33", 32))
  for (offset, value) in [
    (0, 0),
    (4, 3),
    (5, 2),
    (6, 33),
    (7, 2),
    (8, 65),
    (39, 1),
    (40, 0),
    (207, 128),
    (210, 129),
    (212, 10),
    (212, 43),
    (339, 1),
    (351, 1)
  ] do
    case decode_anchor_log(replace(wire, offset, value)?) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  for invalid in [Bytes.slice(wire, 0, 351)?, Bytes.concat(wire, Bytes.from_hex("00")?)?] do
    case decode_anchor_log(invalid) do
      Ok(_) -> assert(false)
      Err(_) -> nil
    end
  end
  Ok(true)
end

test("judge Log records bind names, service identity, readiness and slash status") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid fixture byte")
    Ok(bytes)
  end
end
