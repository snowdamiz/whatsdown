from Attachments.Protocol import AttachmentError, AttachmentManifest

##! Test/proof-only original ACH1/2 writer. Never import this module into an
##! application package. Legacy readers remain in Attachments.Protocol; every
##! new application writer must bind the encrypted manifest with ACH3.

pub struct LegacyAttachmentManifest do
  version :: Int
  attachment_id :: Bytes
  chunk_size :: Int
  chunk_count :: Int
  plaintext_size :: Int
  filename :: Bytes
  mime_type :: Bytes
  expires_at :: U64
end

pub fn copy_legacy_fixture_manifest(value :: AttachmentManifest) -> LegacyAttachmentManifest do
  LegacyAttachmentManifest {
    version: value.version,
    attachment_id: value.attachment_id,
    chunk_size: value.chunk_size,
    chunk_count: value.chunk_count,
    plaintext_size: value.plaintext_size,
    filename: value.filename,
    mime_type: value.mime_type,
    expires_at: value.expires_at
  }
end

struct EncryptedChunk do
  version :: Int
  index :: Int
  nonce :: Bytes
  ciphertext :: Bytes
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

fn validate_manifest(value :: LegacyAttachmentManifest) -> Result<(), AttachmentError> do
  # Legacy v1 stays capped at 16MiB. Large v2 uses fixed64KiB chunks so hosts
  # can stream through the existing bounded seal/open calls without whole files.
  if (value.version != 1 && value.version != 2) || Bytes.length(value.attachment_id) != 32 do
    Err(InvalidManifest)
  else if value.chunk_size <= 0
    || value.chunk_size > 65536
    || value.chunk_count <= 0
    || (value.version == 1 && value.chunk_count > 256)
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
    else if Bytes.length(value.filename) > 255
      || Bytes.length(value.mime_type) <= 0
      || Bytes.length(value.mime_type) > 127 do
      Err(InvalidManifest)
    else
      Ok(nil)
    end
  end
end

fn encode_manifest(value :: LegacyAttachmentManifest) -> Bytes!AttachmentError do
  validate_manifest(value)?
  join([
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
    Bytes.empty())
end

fn chunk_label(version :: Int) -> Bytes do
  Bytes.from_utf8("mesh-msg/v#{version}/attachment-chunk")
end

fn attachment_key_label(version :: Int) -> Bytes do
  Bytes.from_utf8("mesh-msg/v#{version}/attachment-key")
end

fn chunk_aad(value :: LegacyAttachmentManifest, index :: Int) -> Bytes!AttachmentError do
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
  case Crypto.aead_seal(key, nonce_value, authenticated_data, plaintext) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn expected_chunk_size(value :: LegacyAttachmentManifest, index :: Int) -> Int!AttachmentError do
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
  if (value.version != 1 && value.version != 2 && value.version != 3)
    || value.index < 0
    || (value.version == 1 && value.index >= 256)
    || ((value.version == 2 || value.version == 3) && value.index >= 8192)
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

pub fn legacy_fixture_chunk(secret :: borrow SecretBytes,
  manifest :: LegacyAttachmentManifest,
  index :: Int,
  plaintext :: Bytes) -> Bytes!AttachmentError do
  if Bytes.length(plaintext) != expected_chunk_size(manifest, index)? do
    Err(InvalidChunkSize)
  else
    let nonce_value = nonce()?
    let key = derive_key(secret, manifest.attachment_id, attachment_key_label(manifest.version))?
    let ciphertext = seal(key, nonce_value, chunk_aad(manifest, index)?, plaintext)?
    encode_chunk(EncryptedChunk {
      version: manifest.version,
      index: index,
      nonce: nonce_value,
      ciphertext: ciphertext
    })
  end
end
