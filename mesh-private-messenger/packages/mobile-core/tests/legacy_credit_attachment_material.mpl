# Test-only legacy v2 material; uses the original domains and exact manifest.
from Attachments.Protocol import AttachmentManifest, generate_attachment_key, seal_manifest
from Identity.Device import DeviceKeys
from Mobile.Attachments import LargeAttachmentMaterial, encode_reference
from Mobile.Types import MobileAttachmentReference
from Mobile.Codec import random_bytes

pub fn fixture_legacy_material(device :: borrow DeviceKeys,
  filename :: Plaintext<Bytes>,
  mime_type :: Plaintext<Bytes>,
  plaintext_size :: Int,
  expires_at_ms :: U64) -> LargeAttachmentMaterial!String do
  let object_id = random_bytes(32)?
  let secret = case generate_attachment_key() do
    Err(_) -> return Err("fixture_key_failed")
    Ok(value) -> value
  end
  let encrypted = case seal_manifest(secret,
    AttachmentManifest {
      version: 2,
      attachment_id: object_id,
      chunk_size: 65536,
      chunk_count: (plaintext_size + 65535) / 65536,
      plaintext_size: plaintext_size,
      filename: filename,
      mime_type: mime_type,
      expires_at: expires_at_ms
    }) do
    Err(_) -> return Err("fixture_manifest_failed")
    Ok(value) -> value
  end
  let wrapped = case Crypto.hpke_seal_secret(device.identity_public_key,
    Bytes.from_utf8("mesh-msg/v1/attachment-key-wrap"),
    Bytes.concat(Bytes.from_utf8("mesh-msg/v1/attachment-reference"), object_id)?,
    secret) do
    Err(_) -> return Err("fixture_wrap_failed")
    Ok(value) -> value
  end
  let upload = random_bytes(32)?
  let download = random_bytes(32)?
  let reference = encode_reference(MobileAttachmentReference {
    object_id: object_id,
    download_capability: download,
    encrypted_manifest: encrypted,
    wrapped_key: wrapped
  })?
  Ok(LargeAttachmentMaterial {
    reference: reference,
    object_id: object_id,
    upload_capability: upload,
    download_capability: download,
    encrypted_manifest: encrypted
  })
end
