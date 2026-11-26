from Binary.Reader import BinaryReader, finish, read_fixed, read_vector, reader

pub type AttachmentError do
  InvalidManifest
  InvalidChunk
  InvalidChunkIndex
  InvalidChunkSize
  AuthenticationRejected
  InvalidPadding
  CryptoFailure(error :: CryptoError)
end

pub struct AttachmentManifest do
  version :: Int
  attachment_id :: Bytes
  chunk_size :: Int
  chunk_count :: Int
  plaintext_size :: Int
  filename :: Bytes
  mime_type :: Bytes
  expires_at :: U64
end

struct EncryptedManifest do
  attachment_id :: Bytes
  nonce :: Bytes
  ciphertext :: Bytes
end

struct EncryptedChunk do
  index :: Int
  nonce :: Bytes
  ciphertext :: Bytes
end

struct ReadBytes do
  state :: BinaryReader
  value :: Bytes
end

struct ReadInt do
  state :: BinaryReader
  value :: Int
end

struct ReadWide do
  state :: BinaryReader
  value :: U64
end

fn append(left :: Bytes, right :: Bytes) -> Bytes!AttachmentError do
  case Bytes.concat(left, right) do
    Err(_) -> Err(InvalidManifest)
    Ok(value)
  end
end

fn join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!AttachmentError do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index))?)
  end
end

fn byte(value :: Int) -> Bytes!AttachmentError do
  case Bytes.from_list([value]) do
    Err(_) -> Err(InvalidManifest)
    Ok(encoded)
  end
end

fn write_u32(value :: Int) -> Bytes!AttachmentError do
  if value < 0 do
    Err(InvalidManifest)
  else
    case U64.parse(Int.to_string(value)) do
      Err(_) -> Err(InvalidManifest)
      Ok(wide) -> case Bytes.write_u32_be(wide) do
        Err(_) -> Err(InvalidManifest)
        Ok(encoded)
      end
    end
  end
end

fn write_u64(value :: U64) -> Bytes!AttachmentError do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err(InvalidManifest)
    Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes!AttachmentError do
  join([write_u32(Bytes.length(value))?, value], 0, Bytes.empty())
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes!AttachmentError do
  case read_fixed(state, length) do
    Err(_) -> Err(InvalidManifest)
    Ok((next, value)) -> Ok(ReadBytes { state: next, value: value })
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes!AttachmentError do
  case read_vector(state, maximum) do
    Err(_) -> Err(InvalidManifest)
    Ok((next, value)) -> Ok(ReadBytes { state: next, value: value })
  end
end

fn take_u32(state :: BinaryReader) -> ReadInt!AttachmentError do
  let encoded = take_fixed(state, 4)?
  case Bytes.read_u32_be(encoded.value, 0) do
    Err(_) -> Err(InvalidManifest)
    Ok(value) -> case U64.to_int(value) do
      Err(_) -> Err(InvalidManifest)
      Ok(parsed) -> Ok(ReadInt { state: encoded.state, value: parsed })
    end
  end
end

fn take_u64(state :: BinaryReader) -> ReadWide!AttachmentError do
  let encoded = take_fixed(state, 8)?
  case Bytes.read_u64_be(encoded.value, 0) do
    Err(_) -> Err(InvalidManifest)
    Ok(value) -> Ok(ReadWide { state: encoded.state, value: value })
  end
end

# The version byte and tag, returning the version for the caller to check.

fn start_any(input :: Bytes, maximum :: Int, expected :: String) -> ReadInt!AttachmentError do
  if Bytes.length(input) > maximum do
    Err(InvalidManifest)
  else
    case reader(input, maximum) do
      Err(_) -> Err(InvalidManifest)
      Ok(initial) -> do
        let version = take_fixed(initial, 1)?
        let magic = take_fixed(version.state, 3)?
        case Bytes.get(version.value, 0) do
          Ok(value) -> if Bytes.secure_equals(magic.value, Bytes.from_utf8(expected)) do
            Ok(ReadInt { state: magic.state, value: value })
          else
            Err(InvalidManifest)
          end
          Err(_) -> Err(InvalidManifest)
        end
      end
    end
  end
end

fn start(input :: Bytes, maximum :: Int, expected :: String) -> BinaryReader!AttachmentError do
  let started = start_any(input, maximum, expected)?
  if started.value == 1 do
    Ok(started.state)
  else
    Err(InvalidManifest)
  end
end

fn done(state :: BinaryReader) -> Result<(), AttachmentError> do
  case finish(state) do
    Err(_) -> Err(InvalidManifest)
    Ok(_) -> Ok(nil)
  end
end

# Version 2 pads every object to a size bucket, so object storage sees one of
# 53 sizes instead of the exact one: a single 64 KiB chunk for anything that
# fits, then four steps per doubling up to the 512 MiB ceiling. A step is a
# quarter of the power of two below the size, so no file above one chunk grows
# by more than 25% (attachment-wire-v1.md, "Version 2"). Buckets above 16 MiB
# cost credits ("Large files").

fn highest_power(value :: Int, power :: Int) -> Int do
  if power * 2 > value do
    power
  else
    highest_power(value, power * 2)
  end
end

pub fn attachment_padded_size(plaintext_size :: Int) -> Int do
  if plaintext_size <= 65536 do
    65536
  else
    let step = highest_power(plaintext_size, 1) / 4
    (plaintext_size + step - 1) / step * step
  end
end

## Files up to 16 MiB are free. A larger bucket costs one credit for every 16
## MiB it holds beyond the first (plan §6.10), from 1 at 20 MiB to 31 at 512 MiB.

pub fn attachment_credit_cost(plaintext_size :: Int) -> Int do
  (attachment_padded_size(plaintext_size) + 16777215) / 16777216 - 1
end

fn padded_size(value :: AttachmentManifest) -> Int do
  if value.version == 2 do
    attachment_padded_size(value.plaintext_size)
  else
    value.plaintext_size
  end
end

fn validate_padding(value :: AttachmentManifest) -> Result<(), AttachmentError> do
  if value.version == 1 do
    Ok(nil)
  else if value.version != 2
    || value.chunk_size != 65536
    || value.plaintext_size > 536870912
    || value.chunk_count != (padded_size(value) + 65535) / 65536 do
    Err(InvalidManifest)
  else
    Ok(nil)
  end
end

# Version 1 stays at 256 chunks (16 MiB); version 2 goes to 8,192 (512 MiB),
# and hosts move one chunk at a time.

fn maximum_chunks(version :: Int) -> Int do
  if version == 2 do
    8192
  else
    256
  end
end

fn validate_manifest(value :: AttachmentManifest) -> Result<(), AttachmentError> do
  validate_padding(value)?
  if Bytes.length(value.attachment_id) != 32 do
    Err(InvalidManifest)
  else if value.chunk_size <= 0
    || value.chunk_size > 65536
    || value.chunk_count <= 0
    || value.chunk_count > maximum_chunks(value.version) do
    Err(InvalidManifest)
  else
    let maximum_size = value.chunk_count * value.chunk_size
    let minimum_size = (value.chunk_count - 1) * value.chunk_size
    if value.plaintext_size <= 0
      || padded_size(value) <= minimum_size
      || padded_size(value) > maximum_size do
      Err(InvalidManifest)
    else if Bytes.length(value.filename) > 255
      || Bytes.length(value.mime_type) <= 0
      || Bytes.length(value.mime_type) > 127 do
      Err(InvalidManifest)
    else
      Ok(nil)
    end
  end
end

fn encode_manifest(value :: AttachmentManifest) -> Bytes!AttachmentError do
  validate_manifest(value)?
  let padding = if value.version == 2 do
    zeros(382 - Bytes.length(value.filename) - Bytes.length(value.mime_type))?
  else
    Bytes.empty()
  end
  join([
      byte(value.version)?,
      Bytes.from_utf8("AMF"),
      value.attachment_id,
      write_u32(value.chunk_size)?,
      write_u32(value.chunk_count)?,
      write_u32(value.plaintext_size)?,
      write_u64(value.expires_at)?,
      vector(value.filename)?,
      vector(value.mime_type)?,
      padding
    ],
    0,
    Bytes.empty())
end

fn zeros(length :: Int) -> Bytes!AttachmentError do
  case Bytes.repeat(0, length) do
    Err(_) -> Err(InvalidPadding)
    Ok(value)
  end
end

fn all_zero(value :: Bytes) -> Bool!AttachmentError do
  Ok(Bytes.secure_equals(value, zeros(Bytes.length(value))?))
end

# A version 2 manifest is always 446 bytes, zero-filled after the MIME type, so
# its encrypted form is always 514 bytes whatever the filename.

fn manifest_padding(state :: BinaryReader,
  version :: Int,
  input :: Bytes,
  filename :: Bytes,
  mime_type :: Bytes) -> Result<(), AttachmentError> do
  if version == 1 do
    done(state)
  else if Bytes.length(input) != 446 do
    Err(InvalidManifest)
  else
    let padding = take_fixed(state, 382 - Bytes.length(filename) - Bytes.length(mime_type))?
    if !all_zero(padding.value)? do
      Err(InvalidManifest)
    else
      done(padding.state)
    end
  end
end

fn decode_manifest(input :: Bytes) -> AttachmentManifest!AttachmentError do
  let started = start_any(input, 446, "AMF")?
  if started.value != 1 && started.value != 2 do
    return Err(InvalidManifest)
  end
  let attachment_id = take_fixed(started.state, 32)?
  let chunk_size = take_u32(attachment_id.state)?
  let chunk_count = take_u32(chunk_size.state)?
  let plaintext_size = take_u32(chunk_count.state)?
  let expires_at = take_u64(plaintext_size.state)?
  let filename = take_vector(expires_at.state, 255)?
  let mime_type = take_vector(filename.state, 127)?
  manifest_padding(mime_type.state, started.value, input, filename.value, mime_type.value)?
  let value = AttachmentManifest {
    version: started.value,
    attachment_id: attachment_id.value,
    chunk_size: chunk_size.value,
    chunk_count: chunk_count.value,
    plaintext_size: plaintext_size.value,
    filename: filename.value,
    mime_type: mime_type.value,
    expires_at: expires_at.value
  }
  validate_manifest(value)?
  Ok(value)
end

fn manifest_label() -> Bytes do
  Bytes.from_utf8("mesh-msg/v1/attachment-manifest")
end

fn chunk_label() -> Bytes do
  Bytes.from_utf8("mesh-msg/v1/attachment-chunk")
end

fn attachment_key_label() -> Bytes do
  Bytes.from_utf8("mesh-msg/v1/attachment-key")
end

fn manifest_aad(attachment_id :: Bytes) -> Bytes!AttachmentError do
  join([manifest_label(), attachment_id], 0, Bytes.empty())
end

fn chunk_aad(value :: AttachmentManifest, index :: Int) -> Bytes!AttachmentError do
  join([chunk_label(), Crypto.sha256(encode_manifest(value)?), write_u32(index)?], 0, Bytes.empty())
end

fn derive_key(secret :: borrow SecretBytes,
  salt :: Bytes,
  info :: Bytes) -> AeadKey!AttachmentError do
  let material = case Crypto.hkdf_sha256(secret, salt, info, 32) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end?
  case Crypto.aead_key(material) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn nonce() -> Bytes!AttachmentError do
  case Crypto.random_bytes(12) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn seal(key :: borrow AeadKey,
  nonce_value :: Bytes,
  authenticated_data :: Bytes,
  plaintext :: Bytes) -> Bytes!AttachmentError do
  case Crypto.aead_seal(key, nonce_value, authenticated_data, plaintext) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn open(key :: borrow AeadKey,
  nonce_value :: Bytes,
  authenticated_data :: Bytes,
  ciphertext :: Bytes) -> Bytes!AttachmentError do
  case Crypto.aead_open(key, nonce_value, authenticated_data, ciphertext) do
    Err(AuthenticationFailed) -> Err(AuthenticationRejected)
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn encode_encrypted_manifest(value :: EncryptedManifest) -> Bytes!AttachmentError do
  if Bytes.length(value.attachment_id) != 32
    || Bytes.length(value.nonce) != 12
    || Bytes.length(value.ciphertext) < 16
    || Bytes.length(value.ciphertext) > 462 do
    Err(InvalidManifest)
  else
    join([
        byte(1)?,
        Bytes.from_utf8("EAM"),
        value.attachment_id,
        value.nonce,
        vector(value.ciphertext)?
      ],
      0,
      Bytes.empty())
  end
end

fn decode_encrypted_manifest(input :: Bytes) -> EncryptedManifest!AttachmentError do
  let attachment_id = take_fixed(start(input, 514, "EAM")?, 32)?
  let nonce_value = take_fixed(attachment_id.state, 12)?
  let ciphertext = take_vector(nonce_value.state, 462)?
  done(ciphertext.state)?
  if Bytes.length(ciphertext.value) < 16 do
    Err(InvalidManifest)
  else
    Ok(EncryptedManifest {
      attachment_id: attachment_id.value,
      nonce: nonce_value.value,
      ciphertext: ciphertext.value
    })
  end
end

# The chunk's length as sealed: in version 2 the padded stream is cut into
# chunks, so trailing chunks may be partly or wholly zero padding.

fn expected_chunk_size(value :: AttachmentManifest, index :: Int) -> Int!AttachmentError do
  validate_manifest(value)?
  if index < 0 || index >= value.chunk_count do
    Err(InvalidChunkIndex)
  else if index == value.chunk_count - 1 do
    Ok(padded_size(value) - ((value.chunk_count - 1) * value.chunk_size))
  else
    Ok(value.chunk_size)
  end
end

# The file's own bytes in that chunk; the rest of the chunk is padding.

fn chunk_data_size(value :: AttachmentManifest, index :: Int) -> Int!AttachmentError do
  let sealed = expected_chunk_size(value, index)?
  let remaining = value.plaintext_size - index * value.chunk_size
  if remaining <= 0 do
    Ok(0)
  else if remaining < sealed do
    Ok(remaining)
  else
    Ok(sealed)
  end
end

fn strip_padding(plaintext :: Bytes, data_size :: Int) -> Bytes!AttachmentError do
  let padding = case Bytes.slice(plaintext, data_size, Bytes.length(plaintext) - data_size) do
    Err(_) -> Err(InvalidChunkSize)
    Ok(value)
  end?
  if !all_zero(padding)? do
    Err(InvalidPadding)
  else
    case Bytes.slice(plaintext, 0, data_size) do
      Err(_) -> Err(InvalidChunkSize)
      Ok(value)
    end
  end
end

fn encode_chunk(value :: EncryptedChunk) -> Bytes!AttachmentError do
  if value.index < 0
    || value.index >= 8192
    || Bytes.length(value.nonce) != 12
    || Bytes.length(value.ciphertext) < 16
    || Bytes.length(value.ciphertext) > 65552 do
    Err(InvalidChunk)
  else
    join([
        byte(1)?,
        Bytes.from_utf8("ACH"),
        write_u32(value.index)?,
        value.nonce,
        vector(value.ciphertext)?
      ],
      0,
      Bytes.empty())
  end
end

fn decode_chunk(input :: Bytes) -> EncryptedChunk!AttachmentError do
  let index = take_u32(start(input, 65576, "ACH")?)?
  let nonce_value = take_fixed(index.state, 12)?
  let ciphertext = take_vector(nonce_value.state, 65552)?
  done(ciphertext.state)?
  if index.value >= 8192 || Bytes.length(ciphertext.value) < 16 do
    Err(InvalidChunk)
  else
    Ok(EncryptedChunk {
      index: index.value,
      nonce: nonce_value.value,
      ciphertext: ciphertext.value
    })
  end
end

pub fn generate_attachment_key() -> SecretBytes!AttachmentError do
  case Secret.random(32) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

pub fn generate_attachment_id() -> Bytes!AttachmentError do
  case Crypto.random_bytes(32) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

pub fn seal_manifest(secret :: borrow SecretBytes,
  value :: AttachmentManifest) -> Bytes!AttachmentError do
  let plaintext = encode_manifest(value)?
  let nonce_value = nonce()?
  let authenticated_data = manifest_aad(value.attachment_id)?
  let key = derive_key(secret, value.attachment_id, attachment_key_label())?
  let ciphertext = seal(key, nonce_value, authenticated_data, plaintext)?
  encode_encrypted_manifest(EncryptedManifest {
    attachment_id: value.attachment_id,
    nonce: nonce_value,
    ciphertext: ciphertext
  })
end

pub fn open_manifest(secret :: borrow SecretBytes,
  input :: Bytes) -> AttachmentManifest!AttachmentError do
  let encrypted = decode_encrypted_manifest(input)?
  let authenticated_data = manifest_aad(encrypted.attachment_id)?
  let key = derive_key(secret, encrypted.attachment_id, attachment_key_label())?
  let plaintext = open(key, encrypted.nonce, authenticated_data, encrypted.ciphertext)?
  let value = decode_manifest(plaintext)?
  if Bytes.secure_equals(value.attachment_id, encrypted.attachment_id) do
    Ok(value)
  else
    Err(InvalidManifest)
  end
end

pub fn seal_chunk(secret :: borrow SecretBytes,
  manifest :: AttachmentManifest,
  index :: Int,
  plaintext :: Bytes) -> Bytes!AttachmentError do
  let sealed_size = expected_chunk_size(manifest, index)?
  if Bytes.length(plaintext) != chunk_data_size(manifest, index)? do
    Err(InvalidChunkSize)
  else
    let padded = append(plaintext, zeros(sealed_size - Bytes.length(plaintext))?)?
    let nonce_value = nonce()?
    let key = derive_key(secret, manifest.attachment_id, attachment_key_label())?
    let ciphertext = seal(key, nonce_value, chunk_aad(manifest, index)?, padded)?
    encode_chunk(EncryptedChunk { index: index, nonce: nonce_value, ciphertext: ciphertext })
  end
end

pub fn open_chunk(secret :: borrow SecretBytes,
  manifest :: AttachmentManifest,
  expected_index :: Int,
  input :: Bytes) -> Bytes!AttachmentError do
  let expected_size = expected_chunk_size(manifest, expected_index)?
  let encrypted = decode_chunk(input)?
  if encrypted.index != expected_index do
    Err(InvalidChunkIndex)
  else if Bytes.length(encrypted.ciphertext) != expected_size + 16 do
    Err(InvalidChunkSize)
  else
    let key = derive_key(secret, manifest.attachment_id, attachment_key_label())?
    let plaintext = open(key,
      encrypted.nonce,
      chunk_aad(manifest, expected_index)?,
      encrypted.ciphertext)?
    if Bytes.length(plaintext) == expected_size do
      strip_padding(plaintext, chunk_data_size(manifest, expected_index)?)
    else
      Err(InvalidChunkSize)
    end
  end
end
