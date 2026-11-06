from Mobile.Codec import mobile_byte, mobile_write_u32, mobile_write_u64, mobile_join
from Tests.LegacyAttachmentFixture import (
  LegacyAttachmentManifest,
  copy_legacy_fixture_manifest,
  legacy_fixture_chunk
)
from Attachments.Protocol import (
  AttachmentError,
  AttachmentManifest,
  generate_attachment_key,
  seal_manifest,
  seal_bound_chunk
)
from Mobile.Attachments import (
  encode_reference,
  open_attachment_chunk,
  seal_attachment_chunk,
  seal_large_attachment_chunk
)
from Mobile.Profile import open_device, load_profile
from Storage.Keys import platform_key
from Mobile.Types import MobileAttachmentReference, MobileAttachmentChunkRequest
from MobileCore import create_account_export
from Tests.GroupLifecycleWire import group_vectors
from Tests.Support import database_path, repeated, append
from Transport.Packet import decode_client_profile

fn public_legacy_metadata(value :: AttachmentManifest) -> LegacyAttachmentManifest do
  declassify(copy_legacy_fixture_manifest(value),
    "synthetic public legacy attachment fixture metadata only; no application disclosure")
end

fn protocol(value :: Result<Bytes, AttachmentError>) -> Bytes!String do
  case value do
    Err(_) -> Err("bound reader fixture protocol failure")
    Ok(output)
  end
end

fn exact(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "synthetic public native attachment reader equality only; no application disclosure")
end

fn opened_equals(value :: Bytes!String, expected :: Bytes) -> Plaintext<Bool> do
  case value do
    Ok(bytes) -> Bytes.secure_equals(bytes, expected)
    Err(_) -> false
  end
end

# Authenticated AMF with an empty MIME value reaches metadata admission rather
# than merely failing a tampered ciphertext tag. The key, framing and AAD are
# the unchanged public EAM1/2 protocol; only fixture-owned literal data is used.
fn malformed_metadata(secret :: borrow SecretBytes, id :: Bytes, version :: Int) -> Bytes!String do
  let clear = mobile_join([
      mobile_byte(version)?,
      Bytes.from_utf8("AMF"),
      id,
      mobile_write_u32(65536)?,
      mobile_write_u32(if version == 1 do
        1
      else
        257
      end)?,
      mobile_write_u32(if version == 1 do
        1
      else
        16777217
      end)?,
      mobile_write_u64(U64.parse("4102444800000")?)?,
      mobile_write_u32(7)?,
      Bytes.from_utf8("fixture"),
      mobile_write_u32(0)?
    ],
    0,
    Bytes.empty())?
  let material = case Crypto.hkdf_sha256(secret,
    id,
    Bytes.from_utf8("mesh-msg/v#{version}/attachment-key"),
    32) do
    Err(_) -> return Err("fixture derivation failed")
    Ok(value) -> value
  end
  let key = case Crypto.aead_key(material) do
    Err(_) -> return Err("fixture key failed")
    Ok(value) -> value
  end
  let nonce = repeated(63, 12)?
  let ciphertext = case Crypto.aead_seal(key,
    nonce,
    append(Bytes.from_utf8("mesh-msg/v#{version}/attachment-manifest"), id)?,
    clear) do
    Err(_) -> return Err("fixture seal failed")
    Ok(value) -> value
  end
  mobile_join([
      mobile_byte(version)?,
      Bytes.from_utf8("EAM"),
      id,
      nonce,
      mobile_write_u32(Bytes.length(ciphertext))?,
      ciphertext
    ],
    0,
    Bytes.empty())
end

fn exercise(version :: Int) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("bound_attachment_reader")?
  let profile = decode_client_profile(create_account_export(group_vectors([
    Bytes.from_utf8(path),
    Bytes.from_utf8("boundreader")
  ])?)?)?
  let secret = case generate_attachment_key() do
    Err(_) -> return Err("fixture key failed")
    Ok(value) -> value
  end
  let id = repeated(47, 32)?
  let manifest = AttachmentManifest {
    version: version,
    attachment_id: id,
    chunk_size: 65536,
    chunk_count: if version == 1 do
      1
    else
      257
    end,
    plaintext_size: if version == 1 do
      1
    else
      16777217
    end,
    filename: Bytes.from_utf8("private-name.bin"),
    mime_type: Bytes.from_utf8("application/octet-stream"),
    expires_at: U64.parse("4102444800000")?
  }
  let encrypted = protocol(seal_manifest(secret, manifest))?
  let wrapped = case Crypto.hpke_seal_secret(X25519PublicKey {
      bytes: profile.credential.dh_public_key
    },
    Bytes.from_utf8("mesh-msg/v1/attachment-key-wrap"),
    append(Bytes.from_utf8("mesh-msg/v1/attachment-reference"), id)?,
    secret) do
    Err(_) -> return Err("fixture wrapping failed")
    Ok(value) -> value
  end
  let reference = MobileAttachmentReference {
    object_id: id,
    download_capability: repeated(49, 32)?,
    encrypted_manifest: encrypted,
    wrapped_key: wrapped
  }
  let payload = Bytes.from_utf8("x")
  let index = manifest.chunk_count - 1
  let wire = protocol(seal_bound_chunk(secret, encrypted, index, payload))?
  let request = MobileAttachmentChunkRequest {
    database_path: path,
    reference: encode_reference(reference)?,
    index: index,
    payload: wire
  }
  assert(exact(opened_equals(open_attachment_chunk(request), payload)))
  # Identical clear metadata with a different encrypted envelope cannot replace
  # the exact EAM committed by the received ACH3 frame.
  let replaced = encode_reference(%{reference |
    encrypted_manifest: protocol(seal_manifest(secret, manifest))?
  })?
  assert(exact(Result.is_err(open_attachment_chunk(%{request | reference: replaced}))))
  assert(exact(Result.is_err(open_attachment_chunk(%{request | index: index + 1}))))
  # Legacy ciphertext remains readable, but every new production write binds
  # the exact encrypted manifest so its private filename/MIME hash never is AAD.
  let legacy = protocol(legacy_fixture_chunk(secret,
    public_legacy_metadata(manifest),
    index,
    payload))?
  assert(Bytes.get(legacy, 0) == Ok(version))
  assert(exact(opened_equals(open_attachment_chunk(%{request | payload: legacy}), payload)))
  let written = seal_attachment_chunk(%{request | payload: payload})?
  assert(Bytes.get(written, 0) == Ok(3))
  assert(exact(opened_equals(open_attachment_chunk(%{request | payload: written}), payload)))
  assert(exact(Result.is_err(open_attachment_chunk(%{request |
    reference: replaced,
    payload: written
  }))))
  let key = platform_key()?
  let device = open_device(profile, key, path)?
  let before = load_profile(path)?
  let malformed = encode_reference(%{reference |
    encrypted_manifest: malformed_metadata(secret, id, version)?
  })?
  # The original manifest error precedes an invalid index or payload. Prepared
  # ciphertext from a fallback/error path must never escape as a successful wire.
  assert(seal_attachment_chunk(%{request |
    reference: malformed,
    index: -1,
    payload: Bytes.empty()
  }) == Err("invalid_attachment_manifest"))
  assert(seal_large_attachment_chunk(device,
    malformed,
    -1,
    Bytes.empty()) == Err("invalid_attachment_manifest"))
  assert(seal_attachment_chunk(%{request |
    payload: Bytes.empty()
  }) == Err("invalid_attachment_chunk_size"))
  if version == 1 do
    assert(seal_large_attachment_chunk(device,
      request.reference,
      -1,
      Bytes.empty()) == Err("invalid_large_attachment_manifest"))
  end
  assert(Bytes.secure_equals(load_profile(path)?, before))
  if version == 2 do
    let paid = seal_large_attachment_chunk(device, request.reference, index, payload)?
    assert(Bytes.get(paid, 0) == Ok(3))
    assert(exact(opened_equals(open_attachment_chunk(%{request | payload: paid}), payload)))
    assert(exact(Result.is_err(open_attachment_chunk(%{request |
      reference: replaced,
      payload: paid
    }))))
  end
  File.delete(path)?
  Ok(true)
end

test("native writer binds EAM1 ciphertext and preserves legacy reads") do
  case exercise(1) do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

test("native free and paid writers bind EAM2 ciphertext and preserve legacy reads") do
  case exercise(2) do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
