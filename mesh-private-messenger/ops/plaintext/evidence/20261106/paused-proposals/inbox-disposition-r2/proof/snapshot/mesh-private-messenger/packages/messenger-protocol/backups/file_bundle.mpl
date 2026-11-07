##! Structural Backup Wire v1 framing only. No authentication, account or import authority.
from Protocol.V1 import ProtocolError
from Backups.Protocol import profile_from_backup
from Binary.Reader import BinaryReader
from Protocol.WirePrimitives import (
  protocol_as_int,
  protocol_open,
  protocol_require_end,
  protocol_take_fixed,
  protocol_take_u16,
  protocol_take_vector,
  protocol_write_length,
  protocol_write_u16
)

pub struct BackupFileBundle do
  manifest :: Bytes
  chunks :: List<Bytes>
end

fn bundle_join(parts :: List<Bytes>) -> Bytes!ProtocolError do
  case Bytes.concat_many(parts, 16796864) do
    Err(_) -> Err(OversizedInput)
    Ok(value)
  end
end

fn bundle_magic() -> Bytes!ProtocolError do
  case Bytes.from_list([1, 77, 66, 70]) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end
end

fn bundle_slice(input :: Bytes, start :: Int, size :: Int) -> Bytes!ProtocolError do
  case Bytes.slice(input, start, size) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end
end

fn bundle_u32(input :: Bytes, start :: Int) -> Int!ProtocolError do
  case Bytes.read_u32_be(input, start) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value) -> protocol_as_int(value)
  end
end

fn bundle_vector(input :: Bytes) -> Bytes!ProtocolError do
  bundle_join([protocol_write_length(Bytes.length(input))?, input])
end

fn bundle_chunks_valid(chunks :: List<Bytes>,
  backup_id :: Bytes,
  index :: Int,
  size :: Int) -> Unit!ProtocolError do
  if index >= List.length(chunks) do
    return Ok(nil)
  end
  let chunk = List.get(chunks, index)
  let length = Bytes.length(chunk)
  if length < 73 || length > 65608 do
    return Err(MalformedEncoding)
  end
  let magic = case Bytes.from_list([1, 66, 67, 72]) do
    Err(_) -> return Err(MalformedEncoding)
    Ok(v) -> v
  end
  if !Bytes.secure_equals(bundle_slice(chunk, 0, 4)?, magic)
    || !Bytes.secure_equals(bundle_slice(chunk, 4, 32)?, backup_id)
    || bundle_u32(chunk, 36)? != index do
    return Err(MalformedEncoding)
  end
  let ciphertext = bundle_u32(chunk, 52)?
  if ciphertext < 17 || ciphertext > 65552 || length != 56 + ciphertext do
    return Err(MalformedEncoding)
  end
  let next = size + ciphertext - 16
  if next > 16777216 do
    return Err(OversizedInput)
  end
  bundle_chunks_valid(chunks, backup_id, index + 1, next)
end

fn bundle_valid(value :: BackupFileBundle) -> Unit!ProtocolError do
  if List.length(value.chunks) < 1 || List.length(value.chunks) > 256 do
    return Err(OversizedInput)
  end
  if Bytes.length(value.manifest) != 182 do
    return Err(MalformedEncoding)
  end
  # Pure canonical wrapper/profile validation; this neither derives a key nor opens AEAD.
  case profile_from_backup(value.manifest) do
    Err(_) -> return Err(MalformedEncoding)
    Ok(_) -> nil
  end
  bundle_chunks_valid(value.chunks, bundle_slice(value.manifest, 30, 32)?, 0, 0)
end

pub fn encode_backup_file(value :: BackupFileBundle) -> Bytes!ProtocolError do
  bundle_valid(value)?
  let chunks = for chunk in value.chunks do
    bundle_vector(chunk)?
  end
  bundle_join([
    bundle_magic()?,
    bundle_vector(value.manifest)?,
    protocol_write_u16(List.length(value.chunks))?
  ]
    ++ chunks)
end

fn bundle_read_chunks(state :: BinaryReader,
  remaining :: Int,
  output :: List<Bytes>) -> Result<(BinaryReader, List<Bytes>), ProtocolError> do
  if remaining == 0 do
    Ok((state, List.reverse(output)))
  else
    let chunk = protocol_take_vector(state, 65608)?
    bundle_read_chunks(chunk.state, remaining - 1, [chunk.value] ++ output)
  end
end

pub fn decode_backup_file(input :: Bytes) -> BackupFileBundle!ProtocolError do
  let magic = protocol_take_fixed(protocol_open(input, 16796864)?, 4)?
  if !Bytes.secure_equals(magic.value, bundle_magic()?) do
    return Err(MalformedEncoding)
  end
  let manifest = protocol_take_vector(magic.state, 182)?
  if Bytes.length(manifest.value) != 182 do
    return Err(MalformedEncoding)
  end
  # Admit the exact canonical public wrapper before copying any chunk vector.
  case profile_from_backup(manifest.value) do
    Err(_) -> return Err(MalformedEncoding)
    Ok(_) -> nil
  end
  let count = protocol_take_u16(manifest.state)?
  if count.value < 1 || count.value > 256 do
    return Err(OversizedInput)
  end
  let (finished, chunks) = bundle_read_chunks(count.state, count.value, [])?
  protocol_require_end(finished)?
  let value = BackupFileBundle { manifest: manifest.value, chunks: chunks }
  bundle_valid(value)?
  Ok(value)
end
