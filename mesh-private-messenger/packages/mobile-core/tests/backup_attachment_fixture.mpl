##! Authored synthetic reader fixture; no real attachment, keys or history.
from Identity.Device import DeviceKeys
from Attachments.Protocol import (
  AttachmentError, AttachmentManifest, generate_attachment_key,
  seal_manifest, seal_bound_chunk
)
from Mobile.Attachments import encode_reference
from Mobile.Types import MobileAttachmentReference
from Tests.LegacyAttachmentFixture import LegacyAttachmentManifest, legacy_fixture_chunk
from Tests.Support import repeated, append

pub struct BackupAttachmentFixtureMaterial do
  reference :: Bytes
  replacement :: Bytes
  wrong_outer_id :: Bytes
  wire :: Bytes
  legacy :: Bytes
  index :: Int
end

fn fixture_protocol(raw :: Result<Bytes, AttachmentError>) -> Bytes!String do
  case raw do
    Err(_) -> Err("reader_fixture_protocol")
    Ok(value) -> Ok(value)
  end
end

fn fixture_wrap(device :: borrow DeviceKeys,
  secret :: borrow SecretBytes,
  object_id :: Bytes) -> Bytes!String do
  case Crypto.hpke_seal_secret(device.identity_public_key,
    Bytes.from_utf8("mesh-msg/v1/attachment-key-wrap"),
    append(Bytes.from_utf8("mesh-msg/v1/attachment-reference"), object_id)?,
    secret) do
    Err(_) -> Err("reader_fixture_wrap")
    Ok(value) -> Ok(value)
  end
end

fn fixture_material_with_key(device :: borrow DeviceKeys,
  secret :: borrow SecretBytes,
  version :: Int,
  expires :: U64) -> BackupAttachmentFixtureMaterial!String do
  let object_id = repeated(80 + version, 32)?
  let count = if version == 2 do 257 else 1 end
  let size = if version == 2 do 16777217 else 1 end
  let name = Bytes.from_utf8("authored-reader.bin")
  let mime = Bytes.from_utf8("application/octet-stream")
  let manifest = AttachmentManifest {
    version: version, attachment_id: object_id, chunk_size: 65536,
    chunk_count: count, plaintext_size: size, filename: name,
    mime_type: mime, expires_at: expires
  }
  let encrypted = fixture_protocol(seal_manifest(secret, manifest))?
  let reference = MobileAttachmentReference {
    object_id: object_id, download_capability: repeated(91, 32)?,
    encrypted_manifest: encrypted,
    wrapped_key: fixture_wrap(device, secret, object_id)?
  }
  let other_id = repeated(99, 32)?
  let wrong_outer_id = encode_reference(%{reference |
    object_id: other_id,
    wrapped_key: fixture_wrap(device, secret, other_id)?
  })?
  let legacy = if version == 1 || version == 2 do
    fixture_protocol(legacy_fixture_chunk(secret, LegacyAttachmentManifest {
      version: version, attachment_id: object_id, chunk_size: 65536,
      chunk_count: count, plaintext_size: size, filename: name,
      mime_type: mime, expires_at: expires
    }, count - 1, Bytes.from_utf8("x")))?
  else
    Bytes.empty()
  end
  Ok(BackupAttachmentFixtureMaterial {
    reference: encode_reference(reference)?,
    replacement: encode_reference(%{reference |
      encrypted_manifest: fixture_protocol(seal_manifest(secret, manifest))?
    })?,
    wrong_outer_id: wrong_outer_id,
    wire: fixture_protocol(seal_bound_chunk(secret, encrypted, count - 1, Bytes.from_utf8("x")))?,
    legacy: legacy,
    index: count - 1
  })
end

pub fn backup_attachment_fixture_material(device :: borrow DeviceKeys,
  version :: Int,
  expires :: U64) -> BackupAttachmentFixtureMaterial!String do
  let secret = case generate_attachment_key() do
    Err(_) -> return Err("reader_fixture_key")
    Ok(value) -> value
  end
  let result = fixture_material_with_key(device, secret, version, expires)
  Secret.destroy(secret)
  result
end

pub fn backup_attachment_fixture_damage(wire :: Bytes) -> Bytes!String do
  let last = Bytes.length(wire) - 1
  let value = Bytes.get(wire, last)?
  let changed = case Bytes.from_list([if value == 0 do 1 else 0 end]) do
    Err(_) -> return Err("reader_fixture_damage_byte")
    Ok(bytes) -> bytes
  end
  append(Bytes.slice(wire, 0, last)?,
    changed)
end

pub fn backup_attachment_fixture_drop_device(device :: consume DeviceKeys) do
  nil
end
