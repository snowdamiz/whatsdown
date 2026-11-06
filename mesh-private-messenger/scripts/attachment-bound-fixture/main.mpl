from Attachments.Protocol import (
  AttachmentManifest,
  AttachmentError,
  generate_attachment_key,
  seal_manifest,
  seal_bound_chunk
)
from Mobile.Attachments import encode_reference
from Mobile.Types import MobileAttachmentReference
from Mobile.Codec import mobile_join
from Mobile.CreditState import pack_credit_parts
from Transport.Packet import decode_client_profile

fn protocol(value :: Result<Bytes, AttachmentError>) -> Bytes!String do
  case value do
    Err(_) -> Err("fixture attachment operation failed")
    Ok(output) -> Ok(output)
  end
end

fn bytes(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("fixture bytes failed")
    Ok(output) -> Ok(output)
  end
end

fn fixture() -> Bytes!String do
  let profile = decode_client_profile(Bytes.from_base64(Env.get("MORSE_ATTACHMENT_FIXTURE_PROFILE",
    ""))?)?
  let secret = case generate_attachment_key() do
    Err(_) -> return Err("fixture key failed")
    Ok(value) -> value
  end
  let id = bytes(47, 32)?
  let manifest = AttachmentManifest {
    version: 1,
    attachment_id: id,
    chunk_size: 65536,
    chunk_count: 2,
    plaintext_size: 65537,
    filename: Bytes.from_utf8("native-bound-fixture.bin"),
    mime_type: Bytes.from_utf8("application/octet-stream"),
    expires_at: U64.parse("4102444800000")?
  }
  let encrypted = protocol(seal_manifest(secret, manifest))?
  let alternate = protocol(seal_manifest(secret, manifest))?
  let wrapped = case Crypto.hpke_seal_secret(X25519PublicKey {
      bytes: profile.credential.dh_public_key
    },
    Bytes.from_utf8("mesh-msg/v1/attachment-key-wrap"),
    mobile_join([Bytes.from_utf8("mesh-msg/v1/attachment-reference"), id], 0, Bytes.empty())?,
    secret) do
    Err(_) -> return Err("fixture wrapping failed")
    Ok(value) -> value
  end
  let reference = MobileAttachmentReference {
    object_id: id,
    download_capability: bytes(49, 32)?,
    encrypted_manifest: encrypted,
    wrapped_key: wrapped
  }
  let first = protocol(seal_bound_chunk(secret, encrypted, 0, bytes(37, 65536)?))?
  let last = protocol(seal_bound_chunk(secret, encrypted, 1, bytes(37, 1)?))?
  pack_credit_parts([
    encode_reference(reference)?,
    encode_reference(%{reference | encrypted_manifest: alternate})?,
    first,
    last
  ])
end

fn main() do
  case fixture() do
    Err(error) -> do
      println(error)
      Process.exit(1)
    end
    Ok(value) -> println(Bytes.to_base64(value))
  end
end
