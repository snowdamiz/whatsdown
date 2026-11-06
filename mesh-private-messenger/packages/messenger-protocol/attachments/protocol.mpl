from Binary.Reader import BinaryReader, finish, read_fixed, read_vector, reader

pub type AttachmentError do
  InvalidManifest
  InvalidChunk
  InvalidChunkIndex
  InvalidChunkSize
  AuthenticationRejected
  CryptoFailure(error :: CryptoError)
end

pub struct AttachmentManifest do
  version :: Int
  attachment_id :: Bytes
  chunk_size :: Int
  chunk_count :: Int
  plaintext_size :: Int
  filename :: Plaintext<Bytes>
  mime_type :: Plaintext<Bytes>
  expires_at :: U64
end

struct EncryptedManifest do
  version :: Int
  attachment_id :: Bytes
  nonce :: Bytes
  ciphertext :: Bytes
end

struct EncryptedChunk do
  version :: Int
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

fn start(input :: Bytes, maximum :: Int, expected :: String) -> BinaryReader!AttachmentError do
  if Bytes.length(input) > maximum do
    Err(InvalidManifest)
  else
    case reader(input, maximum) do
      Err(_) -> Err(InvalidManifest)
      Ok(initial) -> do
        let version = take_fixed(initial, 1)?
        let magic = take_fixed(version.state, 3)?
        if (Bytes.secure_equals(version.value, byte(1)?)
          || Bytes.secure_equals(version.value, byte(2)?)
          || Bytes.secure_equals(version.value, byte(4)?)
          || (expected == "ACH" && Bytes.secure_equals(version.value, byte(3)?)))
          && Bytes.secure_equals(magic.value, Bytes.from_utf8(expected)) do
          Ok(magic.state)
        else
          Err(InvalidManifest)
        end
      end
    end
  end
end

fn done(state :: BinaryReader) -> Result<(), AttachmentError> do
  case finish(state) do
    Err(_) -> Err(InvalidManifest)
    Ok(_) -> Ok(nil)
  end
end

fn validate_manifest(value :: AttachmentManifest) -> Result<(), AttachmentError> do
  # Legacy v1 stays capped at 16MiB. Large v2 uses fixed64KiB chunks so hosts
  # can stream through the existing bounded seal/open calls without whole files.
  if (value.version != 1 && value.version != 2 && value.version != 4)
    || Bytes.length(value.attachment_id) != 32 do
    Err(InvalidManifest)
  else if value.chunk_size <= 0
    || value.chunk_size > 65536
    || value.chunk_count <= 0
    || (value.version == 1 && value.chunk_count > 256)
    || (value.version == 4
      && (value.chunk_size != 65536
        || value.chunk_count > 8192
        || value.plaintext_size < 1
        || value.plaintext_size > 536870912
        || value.chunk_count != (value.plaintext_size + 65535) / 65536))
    || (value.version == 2
      && (value.chunk_size != 65536
        || value.chunk_count > 8192
        || value.plaintext_size <= 16777216
        || value.plaintext_size > 536870912
        || value.chunk_count != (value.plaintext_size + 65535) / 65536)) do
    Err(InvalidManifest)
  else
    let maximum_size = value.chunk_count * value.chunk_size
    let minimum_size = (value.chunk_count - 1) * value.chunk_size
    if value.plaintext_size <= minimum_size || value.plaintext_size > maximum_size do
      Err(InvalidManifest)
    else if !declassify(Bytes.length(value.filename) <= 255
        && Bytes.length(value.mime_type) > 0
        && Bytes.length(value.mime_type) <= 127,
      "attachment manifest admission discloses only whether filename length is at most 255 bytes and MIME length is 1..127 bytes; metadata bytes and unrelated private control remain private") do
      Err(InvalidManifest)
    else
      Ok(nil)
    end
  end
end

fn encode_manifest(value :: AttachmentManifest) -> Bytes!AttachmentError do
  validate_manifest(value)?
  let encoded = join([
      byte(value.version)?,
      Bytes.from_utf8("AMF"),
      value.attachment_id,
      write_u32(value.chunk_size)?,
      write_u32(value.chunk_count)?,
      write_u32(value.plaintext_size)?,
      write_u64(value.expires_at)?,
      vector(value.filename)?,
      vector(value.mime_type)?
    ],
    0,
    Bytes.empty())?
  if value.version == 4 do
    let padding = case Bytes.repeat(0, 446 - Bytes.length(encoded)) do
      Err(_) -> return Err(InvalidManifest)
      Ok(value) -> value
    end
    append(encoded, padding)
  else
    Ok(encoded)
  end
end

fn decode_manifest(input :: Bytes) -> AttachmentManifest!AttachmentError do
  let attachment_id = take_fixed(start(input, 446, "AMF")?, 32)?
  let chunk_size = take_u32(attachment_id.state)?
  let chunk_count = take_u32(chunk_size.state)?
  let plaintext_size = take_u32(chunk_count.state)?
  let expires_at = take_u64(plaintext_size.state)?
  let filename = take_vector(expires_at.state, 255)?
  let mime_type = take_vector(filename.state, 127)?
  if Bytes.get(input, 0) == Ok(4) do
    if Bytes.length(input) != 446 do
      return Err(InvalidManifest)
    end
    let padding = take_fixed(mime_type.state, 446 - mime_type.state.offset)?
    let zeroes = case Bytes.repeat(0, Bytes.length(padding.value)) do
      Err(_) -> return Err(InvalidManifest)
      Ok(value) -> value
    end
    if !Bytes.secure_equals(padding.value, zeroes) do
      return Err(InvalidManifest)
    end
    done(padding.state)?
  else
    done(mime_type.state)?
  end
  let value = AttachmentManifest {
    version: case Bytes.get(input, 0) do
      Err(_) -> return Err(InvalidManifest)
      Ok(output) -> output
    end,
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

fn manifest_label(version :: Int) -> Bytes do
  Bytes.from_utf8("mesh-msg/v#{version}/attachment-manifest")
end

fn chunk_label(version :: Int) -> Bytes do
  Bytes.from_utf8("mesh-msg/v#{version}/attachment-chunk")
end

fn attachment_key_label(version :: Int) -> Bytes do
  Bytes.from_utf8("mesh-msg/v#{version}/attachment-key")
end

fn manifest_aad(attachment_id :: Bytes, version :: Int) -> Bytes!AttachmentError do
  join([manifest_label(version), attachment_id], 0, Bytes.empty())
end

fn chunk_aad(value :: AttachmentManifest, index :: Int) -> Bytes!AttachmentError do
  join([chunk_label(value.version), Crypto.sha256(encode_manifest(value)?), write_u32(index)?],
    0,
    Bytes.empty())
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
  case declassify_discriminant(Crypto.aead_seal(key, nonce_value, authenticated_data, plaintext),
    "attachment encryption exposes only success or failure; encrypted content, error payloads, and unrelated private control remain private") do
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
  if (value.version != 1 && value.version != 2 && value.version != 4)
    || (value.version == 4 && Bytes.length(value.ciphertext) != 462)
    || Bytes.length(value.attachment_id) != 32
    || Bytes.length(value.nonce) != 12
    || Bytes.length(value.ciphertext) < 16
    || Bytes.length(value.ciphertext) > 462 do
    Err(InvalidManifest)
  else
    join([
        byte(value.version)?,
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
  if Bytes.length(ciphertext.value) < 16
    || (Bytes.get(input, 0) == Ok(4) && Bytes.length(ciphertext.value) != 462) do
    Err(InvalidManifest)
  else
    Ok(EncryptedManifest {
      version: case Bytes.get(input, 0) do
        Err(_) -> return Err(InvalidManifest)
        Ok(output) -> output
      end,
      attachment_id: attachment_id.value,
      nonce: nonce_value.value,
      ciphertext: ciphertext.value
    })
  end
end

fn expected_chunk_size(value :: AttachmentManifest, index :: Int) -> Int!AttachmentError do
  validate_manifest(value)?
  if index < 0 || index >= value.chunk_count do
    Err(InvalidChunkIndex)
  else if index == value.chunk_count - 1 do
    Ok(value.plaintext_size - ((value.chunk_count - 1) * value.chunk_size))
  else
    Ok(value.chunk_size)
  end
end

fn encode_chunk(value :: EncryptedChunk) -> Bytes!AttachmentError do
  if (value.version != 1 && value.version != 2 && value.version != 3 && value.version != 4)
    || value.index < 0
    || (value.version == 1 && value.index >= 256)
    || ((value.version == 2 || value.version == 3 || value.version == 4) && value.index >= 8192)
    || Bytes.length(value.nonce) != 12
    || Bytes.length(value.ciphertext) < 16
    || Bytes.length(value.ciphertext) > 65552 do
    Err(InvalidChunk)
  else
    join([
        byte(value.version)?,
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
  let version = case Bytes.get(input, 0) do
    Err(_) -> return Err(InvalidChunk)
    Ok(output) -> output
  end
  if (version == 1 && index.value >= 256)
    || ((version == 2 || version == 3 || version == 4) && index.value >= 8192)
    || Bytes.length(ciphertext.value) < 16 do
    Err(InvalidChunk)
  else
    Ok(EncryptedChunk {
      version: version,
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

fn seal_manifest_bytes(secret :: borrow SecretBytes,
  attachment_id :: Bytes,
  version :: Int,
  plaintext :: Bytes) -> Bytes!AttachmentError do
  let nonce_value = nonce()?
  let authenticated_data = manifest_aad(attachment_id, version)?
  let key = derive_key(secret, attachment_id, attachment_key_label(version))?
  let ciphertext = seal(key, nonce_value, authenticated_data, plaintext)?
  encode_encrypted_manifest(EncryptedManifest {
    version: version,
    attachment_id: attachment_id,
    nonce: nonce_value,
    ciphertext: ciphertext
  })
end

pub fn seal_manifest(secret :: borrow SecretBytes,
  value :: AttachmentManifest) -> Bytes!AttachmentError do
  # Encoding failures have exactly one public class: InvalidManifest. Encrypt
  # the data/fallback before observing the reviewed framing decision; neither
  # private lengths nor encoding control select the nonce, key, or AAD.
  let encoded = encode_manifest(value)
  let framing_valid = declassify(Result.is_ok(encoded),
    "attachment manifest framing exposes only whether bounded encoding succeeded; filename and MIME bytes, lengths, error payloads, and unrelated private control remain private")
  let encrypted = seal_manifest_bytes(secret,
    value.attachment_id,
    value.version,
    Result.unwrap_or(encoded, Bytes.empty()))
  if framing_valid do
    encrypted
  else
    Err(InvalidManifest)
  end
end

pub fn open_manifest(secret :: borrow SecretBytes,
  input :: Bytes) -> AttachmentManifest!AttachmentError do
  let encrypted = decode_encrypted_manifest(input)?
  let authenticated_data = manifest_aad(encrypted.attachment_id, encrypted.version)?
  let key = derive_key(secret, encrypted.attachment_id, attachment_key_label(encrypted.version))?
  let plaintext = open(key, encrypted.nonce, authenticated_data, encrypted.ciphertext)?
  let value = decode_manifest(plaintext)?
  if value.version == encrypted.version
    && Bytes.secure_equals(value.attachment_id, encrypted.attachment_id) do
    Ok(value)
  else
    Err(InvalidManifest)
  end
end

pub fn open_chunk(secret :: borrow SecretBytes,
  manifest :: AttachmentManifest,
  expected_index :: Int,
  input :: Bytes) -> Result<Plaintext<Bytes>, AttachmentError> do
  if manifest.version != 1 && manifest.version != 2 do
    return Err(InvalidChunk)
  end
  let expected_size = expected_chunk_size(manifest, expected_index)?
  let encrypted = decode_chunk(input)?
  if encrypted.version != manifest.version || encrypted.index != expected_index do
    Err(InvalidChunkIndex)
  else if Bytes.length(encrypted.ciphertext) != expected_size + 16 do
    Err(InvalidChunkSize)
  else
    let key = derive_key(secret, manifest.attachment_id, attachment_key_label(manifest.version))?
    let plaintext = open(key,
      encrypted.nonce,
      chunk_aad(manifest, expected_index)?,
      encrypted.ciphertext)?
    if Bytes.length(plaintext) == expected_size do
      Ok(plaintext)
    else
      Err(InvalidChunkSize)
    end
  end
end

# ACH3 authenticates the exact canonical encrypted manifest, so no filename or
# MIME-derived plaintext digest is part of the public AEAD metadata. EAM1/2 and
# their manifest encryption stay unchanged. The 24-byte prefix plus 16-byte tag
# preserves the existing maximum 65,576-byte chunk frame.
fn bound_chunk_aad(encrypted_manifest :: Bytes,
  index :: Int,
  version :: Int) -> Bytes!AttachmentError do
  join([chunk_label(version), Crypto.sha256(encrypted_manifest), write_u32(index)?],
    0,
    Bytes.empty())
end

pub fn seal_bound_chunk(secret :: borrow SecretBytes,
  encrypted_manifest :: Bytes,
  index :: Int,
  plaintext :: Bytes) -> Bytes!AttachmentError do
  let envelope = decode_encrypted_manifest(encrypted_manifest)?
  if index < 0 || index >= 8192 do
    return Err(InvalidChunkIndex)
  end
  let version = if envelope.version == 4 do
    4
  else
    3
  end
  let payload = if version == 4 do
    if Bytes.length(plaintext) < 1 || Bytes.length(plaintext) > 65536 do
      return Err(InvalidChunkSize)
    end
    let padding = case Bytes.repeat(0, 65536 - Bytes.length(plaintext)) do
      Err(_) -> return Err(InvalidChunkSize)
      Ok(value) -> value
    end
    append(plaintext, padding)?
  else
    plaintext
  end
  let nonce_value = nonce()?
  let key = derive_key(secret, envelope.attachment_id, attachment_key_label(version))?
  let ciphertext = seal(key,
    nonce_value,
    bound_chunk_aad(encrypted_manifest, index, version)?,
    payload)?
  let wire = encode_chunk(EncryptedChunk {
    version: version,
    index: index,
    nonce: nonce_value,
    ciphertext: ciphertext
  })?
  # Authentication and exact-size admission happen before returning any wire.
  # Input length is bounded and padding is constructed above. Encryption
  # precedes decrypted-manifest admission here; metadata validity does not
  # select the public nonce/AAD/key arguments of that sealing operation.
  let manifest = open_manifest(secret, encrypted_manifest)?
  let expected = expected_chunk_size(manifest, index)?
  if Bytes.length(plaintext) != expected
    || Bytes.length(ciphertext) != (if version == 4 do
        65536
      else
        expected
      end)
        + 16 do
    Err(InvalidChunkSize)
  else
    Ok(wire)
  end
end

pub fn open_bound_chunk(secret :: borrow SecretBytes,
  encrypted_manifest :: Bytes,
  expected_index :: Int,
  input :: Bytes) -> Result<Plaintext<Bytes>, AttachmentError> do
  let version = case Bytes.get(input, 0) do
    Err(_) -> return Err(InvalidChunk)
    Ok(value) -> value
  end
  if version == 1 || version == 2 do
    return open_chunk(secret, open_manifest(secret, encrypted_manifest)?, expected_index, input)
  end
  if version != 3 && version != 4 do
    return Err(InvalidChunk)
  end
  let manifest = open_manifest(secret, encrypted_manifest)?
  if (version == 4) != (manifest.version == 4) do
    return Err(InvalidChunk)
  end
  let expected_size = expected_chunk_size(manifest, expected_index)?
  let encrypted = decode_chunk(input)?
  if encrypted.index != expected_index do
    return Err(InvalidChunkIndex)
  end
  let wire_size = if version == 4 do
    65536
  else
    expected_size
  end
  if Bytes.length(encrypted.ciphertext) != wire_size + 16 do
    return Err(InvalidChunkSize)
  end
  let key = derive_key(secret, manifest.attachment_id, attachment_key_label(version))?
  let plaintext = open(key,
    encrypted.nonce,
    bound_chunk_aad(encrypted_manifest, expected_index, version)?,
    encrypted.ciphertext)?
  if Bytes.length(plaintext) != wire_size do
    return Err(InvalidChunkSize)
  end
  if version == 4 do
    let tail = case Bytes.slice(plaintext, expected_size, wire_size - expected_size) do
      Err(_) -> return Err(InvalidChunkSize)
      Ok(value) -> value
    end
    let zeroes = case Bytes.repeat(0, wire_size - expected_size) do
      Err(_) -> return Err(InvalidChunkSize)
      Ok(value) -> value
    end
    if !Bytes.secure_equals(tail, zeroes) do
      return Err(InvalidChunkSize)
    end
    case Bytes.slice(plaintext, 0, expected_size) do
      Err(_) -> Err(InvalidChunkSize)
      Ok(value) -> Ok(value)
    end
  else
    Ok(plaintext)
  end
end

# Object stores can enforce a paid byte budget without a plaintext key. This
# checks only public framing, indices, lengths and the committed EAM hash;
# recipients still perform AEAD authentication before exposing plaintext.
pub fn validate_large_attachment_part(object_id :: Bytes,
  plaintext_size :: Int,
  manifest_size :: Int,
  manifest_sha256 :: Bytes,
  part_index :: Int,
  input :: Bytes) -> Bool!AttachmentError do
  if plaintext_size <= 16777216
    || plaintext_size > 536870912
    || manifest_size < 68
    || manifest_size > 514
    || Bytes.length(object_id) != 32
    || Bytes.length(manifest_sha256) != 32 do
    return Err(InvalidManifest)
  end
  let count = (plaintext_size + 65535) / 65536
  if part_index == 0 do
    if Bytes.length(input) != manifest_size
      || !Bytes.secure_equals(Crypto.sha256(input), manifest_sha256) do
      return Ok(false)
    end
    let value = decode_encrypted_manifest(input)?
    Ok(value.version == 2 && Bytes.secure_equals(value.attachment_id, object_id))
  else if part_index < 1 || part_index > count do
    Err(InvalidChunkIndex)
  else
    let expected = if part_index == count do
      plaintext_size - (count - 1) * 65536
    else
      65536
    end
    let value = decode_chunk(input)?
    Ok((value.version == 2 || value.version == 3)
      && value.index == part_index - 1
      && Bytes.length(value.ciphertext) == expected + 16
      && Bytes.length(input) == expected + 40)
  end
end

# LAG2 authorizes only a rounded public capacity and a fixed EAM4 commitment.
# This is framing admission, not recipient AEAD authentication.
pub fn validate_bucketed_attachment_part(object_id :: Bytes,
  capacity :: Int,
  manifest_sha256 :: Bytes,
  part_index :: Int,
  input :: Bytes) -> Bool!AttachmentError do
  if capacity <= 16777216
    || capacity > 536870912
    || capacity % 65536 != 0
    || Bytes.length(object_id) != 32
    || Bytes.length(manifest_sha256) != 32 do
    return Err(InvalidManifest)
  end
  let count = capacity / 65536
  if part_index == 0 do
    if Bytes.length(input) != 514 || !Bytes.secure_equals(Crypto.sha256(input), manifest_sha256) do
      return Ok(false)
    end
    let value = decode_encrypted_manifest(input)?
    Ok(value.version == 4 && Bytes.secure_equals(value.attachment_id, object_id))
  else if part_index < 1 || part_index > count do
    Err(InvalidChunkIndex)
  else
    let value = decode_chunk(input)?
    Ok(value.version == 4
      && value.index == part_index - 1
      && Bytes.length(value.ciphertext) == 65552
      && Bytes.length(input) == 65576)
  end
end
