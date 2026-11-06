from Binary.Reader import BinaryReader
from Mobile.Codec import (
  mobile_finish,
  mobile_join,
  mobile_read_u32,
  mobile_reader,
  mobile_vector,
  mobile_write_u32,
  random_bytes,
  take_fixed,
  take_vector_error
)
from Storage.Keys import local_context, open_local, seal_local

## A journal is at most256KiB, while an individual platform-wrapped value is
## at most64KiB. Larger records remain one SQLite blob: a sealed manifest binds
## their length, digest and fresh generation; each sealed part binds its index.
## No unauthenticated count causes more than four bounded decryptions.
fn chunk_context(label :: String, generation :: Bytes, suffix :: String) -> Bytes!String do
  local_context(label <> "/chunks/v1/" <> Bytes.to_hex(generation) <> "/" <> suffix)
end

pub fn seal_journal_blob(value :: Bytes,
  wrapping :: borrow StorageKey,
  label :: String) -> Bytes!String do
  let size = Bytes.length(value)
  if size == 0 || size > 262144 do
    return Err("journal_record_too_large")
  end
  if size <= 65536 do
    return seal_local(value, wrapping, local_context(label)?)
  end
  let generation = random_bytes(32)?
  let count = (size + 65535) / 65536
  let manifest = mobile_join([
      Bytes.from_utf8("JCM1"),
      mobile_write_u32(size)?,
      generation,
      Crypto.sha256(value)
    ],
    0,
    Bytes.empty())?
  let root = seal_local(manifest, wrapping, chunk_context(label, generation, "manifest")?)?
  let parts = for index in 0..count do
    let length = if index + 1 < count do
      65536
    else
      size - index * 65536
    end
    let chunk = Bytes.slice(value, index * 65536, length)?
    mobile_vector(seal_local(chunk,
      wrapping,
      chunk_context(label, generation, Int.to_string(index))?)?)?
  end
  mobile_join([Bytes.from_utf8("JCB1"), generation, mobile_vector(root)?] ++ parts,
    0,
    Bytes.empty())
end

pub fn open_journal_blob(blob :: Bytes,
  wrapping :: borrow StorageKey,
  label :: String) -> Bytes!String do
  if Bytes.length(blob) > 265000 do
    return Err("invalid_journal_blob")
  end
  if Bytes.length(blob) < 4
    || !Bytes.secure_equals(Bytes.slice(blob, 0, 4)?, Bytes.from_utf8("JCB1")) do
    return open_local(blob, wrapping, local_context(label)?)
  end
  let state = mobile_reader(blob, 265000, "invalid_journal_blob")?
  let magic = take_fixed(state, 4)?
  let generation = take_fixed(magic.state, 32)?
  let root = take_vector_error(generation.state, 66000, "invalid_journal_blob")?
  let manifest = open_local(root.value,
    wrapping,
    chunk_context(label, generation.value, "manifest")?)?
  if Bytes.length(manifest) != 72
    || !Bytes.secure_equals(Bytes.slice(manifest, 0, 4)?, Bytes.from_utf8("JCM1"))
    || !Bytes.secure_equals(Bytes.slice(manifest, 8, 32)?, generation.value) do
    return Err("invalid_journal_blob")
  end
  let size = mobile_read_u32(Bytes.slice(manifest, 4, 4)?)?
  if size <= 65536 || size > 262144 do
    return Err("invalid_journal_blob")
  end
  let count = (size + 65535) / 65536
  let parts = read_journal_parts(root.state, wrapping, label, generation.value, size, count, 0, [])?
  let value = mobile_join(parts, 0, Bytes.empty())?
  if Bytes.length(value) != size
    || !Bytes.secure_equals(Crypto.sha256(value), Bytes.slice(manifest, 40, 32)?) do
    Err("invalid_journal_blob")
  else
    Ok(value)
  end
end

fn read_journal_parts(state :: BinaryReader,
  wrapping :: borrow StorageKey,
  label :: String,
  generation :: Bytes,
  size :: Int,
  count :: Int,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if index == count do
    mobile_finish(state, "invalid_journal_blob")?
    Ok(output)
  else
    let part = take_vector_error(state, 66000, "invalid_journal_blob")?
    let value = open_local(part.value,
      wrapping,
      chunk_context(label, generation, Int.to_string(index))?)?
    let expected = if index + 1 < count do
      65536
    else
      size - index * 65536
    end
    if Bytes.length(value) != expected do
      return Err("invalid_journal_blob")
    end
    read_journal_parts(part.state,
      wrapping,
      label,
      generation,
      size,
      count,
      index + 1,
      List.append(output, value))
  end
end
