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

fn append(left :: Bytes, right :: Bytes) -> Bytes ! AttachmentError do
  case Bytes.concat(left, right) do
    Err(_) -> Err(InvalidManifest)
    Ok(value) -> Ok(value)
  end
end

fn join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! AttachmentError do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn byte(value :: Int) -> Bytes ! AttachmentError do
  case Bytes.from_list([value]) do
    Err(_) -> Err(InvalidManifest)
    Ok(encoded) -> Ok(encoded)
  end
end

fn write_u32(value :: Int) -> Bytes ! AttachmentError do
  if value < 0 do
    Err(InvalidManifest)
  else
    case U64.parse(Int.to_string(value)) do
      Err(_) -> Err(InvalidManifest)
      Ok(wide) -> case Bytes.write_u32_be(wide) do
        Err(_) -> Err(InvalidManifest)
        Ok(encoded) -> Ok(encoded)
      end
    end
  end
end

fn write_u64(value :: U64) -> Bytes ! AttachmentError do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err(InvalidManifest)
    Ok(encoded) -> Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes ! AttachmentError do
  join([write_u32(Bytes.length(value)) ?, value], 0, Bytes.empty())
end

fn take_fixed(state :: BinaryReader, length :: Int) -> ReadBytes ! AttachmentError do
  case read_fixed(state, length) do
    Err(_) -> Err(InvalidManifest)
    Ok((next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
  end
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> ReadBytes ! AttachmentError do
  case read_vector(state, maximum) do
    Err(_) -> Err(InvalidManifest)
    Ok((next, value)) -> Ok(ReadBytes {
      state : next,
      value : value
    })
  end
end

fn take_u32(state :: BinaryReader) -> ReadInt ! AttachmentError do
  let encoded = take_fixed(state, 4) ?
  case Bytes.read_u32_be(encoded.value, 0) do
    Err(_) -> Err(InvalidManifest)
    Ok(value) -> case U64.to_int(value) do
      Err(_) -> Err(InvalidManifest)
      Ok(parsed) -> Ok(ReadInt {
        state : encoded.state,
        value : parsed
      })
    end
  end
end

fn take_u64(state :: BinaryReader) -> ReadWide ! AttachmentError do
  let encoded = take_fixed(state, 8) ?
  case Bytes.read_u64_be(encoded.value, 0) do
    Err(_) -> Err(InvalidManifest)
    Ok(value) -> Ok(ReadWide {
      state : encoded.state,
      value : value
    })
  end
end

fn start(input :: Bytes, maximum :: Int, expected :: String) -> BinaryReader ! AttachmentError do
  if Bytes.length(input) > maximum do
    Err(InvalidManifest)
  else
    case reader(input, maximum) do
      Err(_) -> Err(InvalidManifest)
      Ok(initial) -> do
        let version = take_fixed(initial, 1) ?
        let magic = take_fixed(version.state, 3) ?
        if Bytes.secure_equals(version.value, byte(1) ?) && Bytes.secure_equals(magic.value,
        Bytes.from_utf8(expected)) do
          Ok(magic.state)
        else
          Err(InvalidManifest)
        end
      end
    end
  end
end

fn done(state :: BinaryReader) -> Result <(), AttachmentError > do
  case finish(state) do
    Err(_) -> Err(InvalidManifest)
    Ok(_) -> Ok(nil)
  end
end

fn validate_manifest(value :: AttachmentManifest) -> Result <(), AttachmentError > do
  # ponytail: 256 x 64 KiB caps this first slice at 16 MiB; raise it with streaming file APIs.
  if value.version != 1 || Bytes.length(value.attachment_id) != 32 do
    Err(InvalidManifest)
  else if value.chunk_size <= 0 || value.chunk_size > 65536 || value.chunk_count <= 0 || value.chunk_count > 256 do
    Err(InvalidManifest)
  else
    let maximum_size = value.chunk_count * value.chunk_size
    let minimum_size = (value.chunk_count - 1) * value.chunk_size
    if value.plaintext_size <= minimum_size || value.plaintext_size > maximum_size do
      Err(InvalidManifest)
    else if Bytes.length(value.filename) > 255 || Bytes.length(value.mime_type) <= 0 || Bytes.length(value.mime_type) > 127 do
      Err(InvalidManifest)
    else
      Ok(nil)
    end
  end
end

fn encode_manifest(value :: AttachmentManifest) -> Bytes ! AttachmentError do
  validate_manifest(value) ?
  join([byte(1) ?, Bytes.from_utf8("AMF"), value.attachment_id, write_u32(value.chunk_size) ?, write_u32(value.chunk_count) ?, write_u32(value.plaintext_size) ?, write_u64(value.expires_at) ?, vector(value.filename) ?, vector(value.mime_type) ?],
  0,
  Bytes.empty())
end

fn decode_manifest(input :: Bytes) -> AttachmentManifest ! AttachmentError do
  let attachment_id = take_fixed(start(input, 446, "AMF") ?, 32) ?
  let chunk_size = take_u32(attachment_id.state) ?
  let chunk_count = take_u32(chunk_size.state) ?
  let plaintext_size = take_u32(chunk_count.state) ?
  let expires_at = take_u64(plaintext_size.state) ?
  let filename = take_vector(expires_at.state, 255) ?
  let mime_type = take_vector(filename.state, 127) ?
  done(mime_type.state) ?
  let value = AttachmentManifest {
    version : 1,
    attachment_id : attachment_id.value,
    chunk_size : chunk_size.value,
    chunk_count : chunk_count.value,
    plaintext_size : plaintext_size.value,
    filename : filename.value,
    mime_type : mime_type.value,
    expires_at : expires_at.value
  }
  validate_manifest(value) ?
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

fn manifest_aad(attachment_id :: Bytes) -> Bytes ! AttachmentError do
  join([manifest_label(), attachment_id], 0, Bytes.empty())
end

fn chunk_aad(value :: AttachmentManifest, index :: Int) -> Bytes ! AttachmentError do
  join([chunk_label(), Crypto.sha256(encode_manifest(value) ?), write_u32(index) ?],
  0,
  Bytes.empty())
end

fn derive_key(secret :: borrow SecretBytes, salt :: Bytes, info :: Bytes) -> AeadKey ! AttachmentError do
  let material = case Crypto.hkdf_sha256(secret, salt, info, 32) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end ?
  case Crypto.aead_key(material) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end
end

fn nonce() -> Bytes ! AttachmentError do
  case Crypto.random_bytes(12) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end
end

fn seal(key :: borrow AeadKey,
nonce_value :: Bytes,
authenticated_data :: Bytes,
plaintext :: Bytes) -> Bytes ! AttachmentError do
  case Crypto.aead_seal(key, nonce_value, authenticated_data, plaintext) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end
end

fn open(key :: borrow AeadKey,
nonce_value :: Bytes,
authenticated_data :: Bytes,
ciphertext :: Bytes) -> Bytes ! AttachmentError do
  case Crypto.aead_open(key, nonce_value, authenticated_data, ciphertext) do
    Err(AuthenticationFailed) -> Err(AuthenticationRejected)
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end
end

fn encode_encrypted_manifest(value :: EncryptedManifest) -> Bytes ! AttachmentError do
  if Bytes.length(value.attachment_id) != 32 || Bytes.length(value.nonce) != 12 || Bytes.length(value.ciphertext) < 16 || Bytes.length(value.ciphertext) > 462 do
    Err(InvalidManifest)
  else
    join([byte(1) ?, Bytes.from_utf8("EAM"), value.attachment_id, value.nonce, vector(value.ciphertext) ?],
    0,
    Bytes.empty())
  end
end

fn decode_encrypted_manifest(input :: Bytes) -> EncryptedManifest ! AttachmentError do
  let attachment_id = take_fixed(start(input, 514, "EAM") ?, 32) ?
  let nonce_value = take_fixed(attachment_id.state, 12) ?
  let ciphertext = take_vector(nonce_value.state, 462) ?
  done(ciphertext.state) ?
  if Bytes.length(ciphertext.value) < 16 do
    Err(InvalidManifest)
  else
    Ok(EncryptedManifest {
      attachment_id : attachment_id.value,
      nonce : nonce_value.value,
      ciphertext : ciphertext.value
    })
  end
end

fn expected_chunk_size(value :: AttachmentManifest, index :: Int) -> Int ! AttachmentError do
  validate_manifest(value) ?
  if index < 0 || index >= value.chunk_count do
    Err(InvalidChunkIndex)
  else if index == value.chunk_count - 1 do
    Ok(value.plaintext_size - ((value.chunk_count - 1) * value.chunk_size))
  else
    Ok(value.chunk_size)
  end
end

fn encode_chunk(value :: EncryptedChunk) -> Bytes ! AttachmentError do
  if value.index < 0 || value.index >= 256 || Bytes.length(value.nonce) != 12 || Bytes.length(value.ciphertext) < 16 || Bytes.length(value.ciphertext) > 65552 do
    Err(InvalidChunk)
  else
    join([byte(1) ?, Bytes.from_utf8("ACH"), write_u32(value.index) ?, value.nonce, vector(value.ciphertext) ?],
    0,
    Bytes.empty())
  end
end

fn decode_chunk(input :: Bytes) -> EncryptedChunk ! AttachmentError do
  let index = take_u32(start(input, 65576, "ACH") ?) ?
  let nonce_value = take_fixed(index.state, 12) ?
  let ciphertext = take_vector(nonce_value.state, 65552) ?
  done(ciphertext.state) ?
  if index.value >= 256 || Bytes.length(ciphertext.value) < 16 do
    Err(InvalidChunk)
  else
    Ok(EncryptedChunk {
      index : index.value,
      nonce : nonce_value.value,
      ciphertext : ciphertext.value
    })
  end
end

pub fn generate_attachment_key() -> SecretBytes ! AttachmentError do
  case Secret.random(32) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end
end

pub fn generate_attachment_id() -> Bytes ! AttachmentError do
  case Crypto.random_bytes(32) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value) -> Ok(value)
  end
end

pub fn seal_manifest(secret :: borrow SecretBytes, value :: AttachmentManifest) -> Bytes ! AttachmentError do
  let plaintext = encode_manifest(value) ?
  let nonce_value = nonce() ?
  let authenticated_data = manifest_aad(value.attachment_id) ?
  let key = derive_key(secret, value.attachment_id, attachment_key_label()) ?
  let ciphertext = seal(key, nonce_value, authenticated_data, plaintext) ?
  encode_encrypted_manifest(EncryptedManifest {
    attachment_id : value.attachment_id,
    nonce : nonce_value,
    ciphertext : ciphertext
  })
end

pub fn open_manifest(secret :: borrow SecretBytes, input :: Bytes) -> AttachmentManifest ! AttachmentError do
  let encrypted = decode_encrypted_manifest(input) ?
  let authenticated_data = manifest_aad(encrypted.attachment_id) ?
  let key = derive_key(secret, encrypted.attachment_id, attachment_key_label()) ?
  let plaintext = open(key, encrypted.nonce, authenticated_data, encrypted.ciphertext) ?
  let value = decode_manifest(plaintext) ?
  if Bytes.secure_equals(value.attachment_id, encrypted.attachment_id) do
    Ok(value)
  else
    Err(InvalidManifest)
  end
end

pub fn seal_chunk(secret :: borrow SecretBytes,
manifest :: AttachmentManifest,
index :: Int,
plaintext :: Bytes) -> Bytes ! AttachmentError do
  if Bytes.length(plaintext) != expected_chunk_size(manifest, index) ? do
    Err(InvalidChunkSize)
  else
    let nonce_value = nonce() ?
    let key = derive_key(secret, manifest.attachment_id, attachment_key_label()) ?
    let ciphertext = seal(key, nonce_value, chunk_aad(manifest, index) ?, plaintext) ?
    encode_chunk(EncryptedChunk {
      index : index,
      nonce : nonce_value,
      ciphertext : ciphertext
    })
  end
end

pub fn open_chunk(secret :: borrow SecretBytes,
manifest :: AttachmentManifest,
expected_index :: Int,
input :: Bytes) -> Bytes ! AttachmentError do
  let expected_size = expected_chunk_size(manifest, expected_index) ?
  let encrypted = decode_chunk(input) ?
  if encrypted.index != expected_index do
    Err(InvalidChunkIndex)
  else if Bytes.length(encrypted.ciphertext) != expected_size + 16 do
    Err(InvalidChunkSize)
  else
    let key = derive_key(secret, manifest.attachment_id, attachment_key_label()) ?
    let plaintext = open(key,
    encrypted.nonce,
    chunk_aad(manifest, expected_index) ?,
    encrypted.ciphertext) ?
    if Bytes.length(plaintext) == expected_size do
      Ok(plaintext)
    else
      Err(InvalidChunkSize)
    end
  end
end
