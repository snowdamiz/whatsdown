from Protocol.V1 import ProtocolError
from Backups.FileBundle import BackupFileBundle, encode_backup_file, decode_backup_file

fn bf_check(value :: Bool) -> Unit!ProtocolError do
  if value do
    Ok(nil)
  else
    Err(InvalidPolicy)
  end
end

fn bf_hex(value :: String) -> Bytes!ProtocolError do
  case Bytes.from_hex(value) do
    Err(_) -> Err(MalformedEncoding)
    Ok(v)
  end
end

fn bf_repeat(value :: Int, n :: Int) -> Bytes!ProtocolError do
  case Bytes.repeat(value, n) do
    Err(_) -> Err(MalformedEncoding)
    Ok(v)
  end
end

fn bf_join(values :: List<Bytes>) -> Bytes!ProtocolError do
  case Bytes.concat_many(values, 16800000) do
    Err(_) -> Err(OversizedInput)
    Ok(v)
  end
end

fn bf_u32(n :: Int) -> Bytes!ProtocolError do
  let wide = case U64.parse(Int.to_string(n)) do
    Err(_) -> return Err(MalformedEncoding)
    Ok(v) -> v
  end
  case Bytes.write_u32_be(wide) do
    Err(_) -> Err(MalformedEncoding)
    Ok(v)
  end
end

fn bf_vector(input :: Bytes) -> Bytes!ProtocolError do
  bf_join([bf_u32(Bytes.length(input))?, input])
end

fn bf_change(input :: Bytes, start :: Int, value :: Bytes) -> Bytes!ProtocolError do
  let left = case Bytes.slice(input, 0, start) do
    Err(_) -> return Err(MalformedEncoding)
    Ok(v) -> v
  end
  let right = case Bytes.slice(input,
    start + Bytes.length(value),
    Bytes.length(input) - start - Bytes.length(value)) do
    Err(_) -> return Err(MalformedEncoding)
    Ok(v) -> v
  end
  bf_join([left, value, right])
end

fn bf_manifest() -> Bytes!ProtocolError do
  bf_hex("0145424d010c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00010000000000030133333333333333333333333333333333333333333333333333333333333333330d0d0d0d0d0d0d0d0d0d0d0d000000680e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e")
end

fn bf_chunk(i :: Int, n :: Int) -> Bytes!ProtocolError do
  bf_join([
    bf_hex("01424348")?,
    bf_repeat(51, 32)?,
    bf_u32(i)?,
    bf_repeat(15, 12)?,
    bf_vector(bf_repeat(16, n + 16)?)?
  ])
end

fn bf_source() -> BackupFileBundle!ProtocolError do
  Ok(BackupFileBundle { manifest: bf_manifest()?, chunks: [bf_chunk(0, 2)?, bf_chunk(1, 1)?] })
end

fn bf_literal() -> Bytes!ProtocolError do
  bf_hex("014d4246000000b60145424d010c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c00010000000000030133333333333333333333333333333333333333333333333333333333333333330d0d0d0d0d0d0d0d0d0d0d0d000000680e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e00020000004a014243483333333333333333333333333333333333333333333333333333333333333333000000000f0f0f0f0f0f0f0f0f0f0f0f0000001210101010101010101010101010101010101000000049014243483333333333333333333333333333333333333333333333333333333333333333000000010f0f0f0f0f0f0f0f0f0f0f0f000000111010101010101010101010101010101010")
end

fn bf_refused(input :: Bytes) -> Bool do
  case decode_backup_file(input) do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn bf_bad(value :: BackupFileBundle) -> Bool do
  case encode_backup_file(value) do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn bf_agreement() -> Bool!ProtocolError do
  let literal = bf_literal()?
  bf_check(Bytes.secure_equals(encode_backup_file(bf_source()?)?, literal))?
  let decoded = decode_backup_file(literal)?
  bf_check(List.length(decoded.chunks) == 2)?
  bf_check(Bytes.secure_equals(encode_backup_file(decoded)?, literal))?
  # Syntactically changed ciphertext is still opaque: only P1 authentication rejects it.
  let changed = bf_change(literal, Bytes.length(literal) - 1, bf_hex("42")?)?
  let _ = decode_backup_file(changed)?
  Ok(true)
end

fn bf_structure() -> Bool!ProtocolError do
  let _ = bf_agreement()?
  let value = bf_source()?
  let first = List.head(value.chunks)
  let next = List.get(value.chunks, 1)
  let bad = [
    %{value | manifest: Bytes.empty()},
    %{value | manifest: bf_change(value.manifest, 0, bf_hex("02")?)?},
    %{value | manifest: bf_change(value.manifest, 21, bf_u32(8)?)?},
    %{value | chunks: []},
    %{value | chunks: [first, first]},
    %{value | chunks: [next, first]},
    %{value | chunks: [bf_change(first, 0, bf_hex("02")?)?]},
    %{value | chunks: [bf_change(first, 4, bf_repeat(52, 32)?)?]},
    %{value | chunks: [bf_change(first, 52, bf_u32(17)?)?]},
    %{value | chunks: [bf_chunk(0, 0)?]},
    %{value | chunks: [bf_chunk(0, 65537)?]}
  ]
  bf_check(List.all(bad, bf_bad))?
  Ok(true)
end

fn bf_hostile() -> Bool!ProtocolError do
  let _ = bf_agreement()?
  let literal = bf_literal()?
  let bad = [
    bf_change(literal, 0, bf_hex("02")?)?,
    bf_change(literal, 4, bf_hex("ffffffff")?)?,
    bf_change(literal, 190, bf_hex("0000")?)?,
    bf_change(literal, 190, bf_hex("0101")?)?,
    bf_change(literal, 192, bf_hex("ffffffff")?)?,
    bf_join([literal, bf_hex("00")?])?
  ]
  bf_check(List.all(bad, bf_refused))?
  for n in 0..Bytes.length(literal) do
    let short = case Bytes.slice(literal, 0, n) do
      Err(_) -> return Err(MalformedEncoding)
      Ok(v) -> v
    end
    bf_check(bf_refused(short))?
  end
  bf_check(bf_refused(bf_repeat(0, 16796865)?))?
  Ok(true)
end

fn bf_bounds() -> Bool!ProtocolError do
  let _ = bf_agreement()?
  let manifest = bf_manifest()?
  let one = BackupFileBundle { manifest: manifest, chunks: [bf_chunk(0, 1)?] }
  let _ = decode_backup_file(encode_backup_file(one)?)?
  let chunks = for i in 0..256 do
    bf_chunk(i, 65536)?
  end
  let maximum = BackupFileBundle { manifest: manifest, chunks: chunks }
  let encoded = encode_backup_file(maximum)?
  bf_check(Bytes.length(encoded) == 16796864)?
  bf_check(Bytes.secure_equals(Crypto.sha256(encoded),
    bf_hex("73d469fc991ca85bdf2c7f34a50fbaca968ff6979304e59f57edbe3a8f2addab")?))?
  let restored = decode_backup_file(encoded)?
  bf_check(List.length(restored.chunks) == 256
    && Bytes.secure_equals(List.get(restored.chunks, 255), List.get(chunks, 255)))?
  bf_check(bf_bad(%{maximum | chunks: chunks ++ [bf_chunk(256, 1)?]}))?
  Ok(true)
end

test("D4 backup file matches independent opaque framing literal without claiming authentication") do
  assert(case bf_agreement() do
    Ok(true) -> true
    _ -> false
  end)
end

test("D4 backup file refuses profile chunk shape wrong backup duplicate and reordered indices") do
  assert(case bf_structure() do
    Ok(true) -> true
    _ -> false
  end)
end

test("D4 backup file rejects hostile lengths counts truncations and trailing bytes") do
  assert(case bf_hostile() do
    Ok(true) -> true
    _ -> false
  end)
end

test("D4 backup file accepts exact256 maximal chunks and independent full-container digest") do
  assert(case bf_bounds() do
    Ok(true) -> true
    _ -> false
  end)
end
