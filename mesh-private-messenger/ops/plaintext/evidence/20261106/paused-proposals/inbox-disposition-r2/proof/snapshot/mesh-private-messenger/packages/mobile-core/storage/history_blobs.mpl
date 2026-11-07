from Binary.Reader import BinaryReader
from Mobile.Codec import (
  mobile_finish,
  mobile_join,
  mobile_read_u32,
  mobile_reader,
  mobile_vector,
  mobile_write_u16,
  mobile_write_u32,
  random_bytes,
  take_fixed,
  take_vector
)
from Mobile.HistoryLimits import (
  history_chunk_bytes,
  history_max_blob_bytes,
  history_max_parts,
  history_max_plaintext_bytes
)
from Storage.Keys import local_context, open_local, seal_local

##! One SQLite BLOB contains an authenticated manifest and bounded sealed parts.
##! Its replacement remains atomic with session/outbox writes. No chunk rows
##! outlive an index, and a read cannot mix generations from separate queries.

fn part_context(label :: String, generation :: Bytes, index :: Int) -> Bytes!String do
  local_context("#{label}/chunks/v2/#{Bytes.to_hex(generation)}/#{index}")
end

fn manifest_context(label :: String, generation :: Bytes) -> Bytes!String do
  local_context("#{label}/chunks/v2/#{Bytes.to_hex(generation)}/manifest")
end

# A balanced join avoids retaining every large prefix while constructing or
# opening a full history. Every frame and part count has a fixed upper bound.
fn combine(parts :: List<Bytes>, start :: Int, count :: Int) -> Bytes!String do
  if count == 0 do
    Ok(Bytes.empty())
  else if count == 1 do
    Ok(List.get(parts, start))
  else
    let left_count = count / 2
    Bytes.concat(combine(parts, start, left_count)?,
      combine(parts, start + left_count, count - left_count)?)
  end
end

fn short_count(value :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u16_be(value, offset) do
    Err(_) -> Err("invalid_history_blob")
    Ok(count)
  end
end

fn history_part(value :: Bytes, offset :: Int, length :: Int) -> Bytes!String do
  let part = Bytes.slice(value, offset, length)
  if declassify(Result.is_err(part),
    "sealed history part framing discloses only its one-bit bounds failure status; extracted content remains private") do
    Err("invalid_history_blob")
  else
    Ok(Result.unwrap_or(part, Bytes.empty()))
  end
end

# Every chunk/root seal is prepared before a private seal failure is observed.
# The ordered checks below preserve the first error and cannot return a partial blob.
fn checked_history_chunks(prepared :: List<Result<Bytes, String>>,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(prepared) do
    Ok(output)
  else
    let chunk = List.get(prepared, index)?
    checked_history_chunks(prepared, index + 1, List.append(output, chunk))
  end
end

fn prepare_history_part_seal(value :: Bytes,
  wrapping :: borrow StorageKey,
  label :: String,
  generation :: Bytes,
  index :: Int,
  length :: Int) -> Bytes!String do
  seal_local(history_part(value, index * history_chunk_bytes(), length)?,
    wrapping,
    part_context(label, generation, index)?)
end

fn prepare_history_root_seal(value :: Bytes,
  wrapping :: borrow StorageKey,
  label :: String,
  generation :: Bytes,
  size :: Int,
  count :: Int) -> Bytes!String do
  let manifest = mobile_join([
      Bytes.from_utf8("HCM2"),
      mobile_write_u32(size)?,
      mobile_write_u16(count)?,
      generation,
      Crypto.sha256(Bytes.from_utf8(label)),
      Crypto.sha256(value)
    ],
    0,
    Bytes.empty())?
  seal_local(manifest, wrapping, manifest_context(label, generation)?)
end

pub fn seal_history_blob(value :: Bytes,
  wrapping :: borrow StorageKey,
  label :: String) -> Bytes!String do
  let measured = Bytes.length(value)
  let bounded_size = if measured < 8 || measured > history_max_plaintext_bytes() do
    0
  else
    measured
  end
  let size = declassify(bounded_size,
    "chunked encrypted local-history storage discloses only its valid8..16794632 encoded byte length through ciphertext sizes, or0 for invalid capacity; history content and digest remain private")
  if String.length(label) == 0 || String.length(label) > 256 do
    return Err("invalid_history_label")
  end
  if size == 0 do
    return Err("history_capacity")
  end
  if size <= 65536 do
    return seal_local(value, wrapping, local_context(label)?)
  end
  let generation = random_bytes(32)?
  let count = (size + history_chunk_bytes() - 1) / history_chunk_bytes()
  let prepared_chunks = for index in 0..count do
    let length = if index + 1 < count do
      history_chunk_bytes()
    else
      size - index * history_chunk_bytes()
    end
    prepare_history_part_seal(value, wrapping, label, generation, index, length)
  end
  let prepared_root = prepare_history_root_seal(value, wrapping, label, generation, size, count)
  let chunks = checked_history_chunks(prepared_chunks, 0, [])?
  let root = prepared_root?
  let parts = [root] ++ chunks
  let header = mobile_join([
      Bytes.from_utf8("HCB2"),
      generation,
      mobile_write_u16(List.length(parts))?
    ],
    0,
    Bytes.empty())?
  let frames = [header]
    ++ for part in parts do
      mobile_vector(part)?
    end
  let encoded = combine(frames, 0, List.length(frames))?
  if Bytes.length(encoded) > history_max_blob_bytes() do
    Err("history_capacity")
  else
    Ok(encoded)
  end
end

fn read_parts(state :: BinaryReader, count :: Int, output :: List<Bytes>) -> List<Bytes>!String do
  if count == 0 do
    mobile_finish(state, "invalid_history_blob")?
    Ok(List.reverse(output))
  else
    let part = take_vector(state, 66000)?
    read_parts(part.state, count - 1, [part.value] ++ output)
  end
end

pub fn open_history_blob(blob :: Bytes,
  wrapping :: borrow StorageKey,
  label :: String) -> Bytes!String do
  if String.length(label) == 0
    || String.length(label) > 256
    || Bytes.length(blob) > history_max_blob_bytes() do
    return Err("invalid_history_blob")
  end
  # Old histories are genuine platform-wrapped values. New magic cannot collide
  # with their version/algorithm header; a damaged new header fails old AEAD.
  if Bytes.length(blob) < 4
    || !Bytes.secure_equals(Bytes.slice(blob, 0, 4)?, Bytes.from_utf8("HCB2")) do
    return open_local(blob, wrapping, local_context(label)?)
  end
  let state = mobile_reader(blob, history_max_blob_bytes(), "invalid_history_blob")?
  let magic = take_fixed(state, 4)?
  let generation = take_fixed(magic.state, 32)?
  let count_bytes = take_fixed(generation.state, 2)?
  let count = short_count(count_bytes.value, 0)?
  if count < 2 || count > history_max_parts() do
    return Err("invalid_history_blob")
  end
  let parts = read_parts(count_bytes.state, count, [])?
  let manifest = open_local(List.head(parts), wrapping, manifest_context(label, generation.value)?)?
  if Bytes.length(manifest) != 106
    || !Bytes.secure_equals(Bytes.slice(manifest, 0, 4)?, Bytes.from_utf8("HCM2")) do
    return Err("invalid_history_blob")
  end
  let size = mobile_read_u32(Bytes.slice(manifest, 4, 4)?)?
  let data_count = short_count(manifest, 8)?
  if size <= 65536
    || size > history_max_plaintext_bytes()
    || data_count != (size + history_chunk_bytes() - 1) / history_chunk_bytes()
    || data_count + 1 != count
    || !Bytes.secure_equals(Bytes.slice(manifest, 10, 32)?, generation.value)
    || !Bytes.secure_equals(Bytes.slice(manifest, 42, 32)?,
      Crypto.sha256(Bytes.from_utf8(label))) do
    return Err("invalid_history_blob")
  end
  let opened = for index in 0..data_count do
    let value = open_local(List.get(parts, index + 1),
      wrapping,
      part_context(label, generation.value, index)?)?
    let expected = if index + 1 < data_count do
      history_chunk_bytes()
    else
      size - index * history_chunk_bytes()
    end
    if Bytes.length(value) != expected do
      return Err("invalid_history_blob")
    end
    value
  end
  let value = combine(opened, 0, List.length(opened))?
  if Bytes.length(value) != size
    || !Bytes.secure_equals(Crypto.sha256(value), Bytes.slice(manifest, 74, 32)?) do
    Err("invalid_history_blob")
  else
    Ok(value)
  end
end
