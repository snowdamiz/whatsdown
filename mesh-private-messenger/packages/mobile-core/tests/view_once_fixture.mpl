##! Authored small ciphertext and genuine local account custody; no transport claim.
from MobileCore import create_account_export
from Mobile.Profile import load_profile, open_device
from Mobile.ViewOnce import ViewOnceSelection, ViewOnceImage
from Attachments.ViewOnce import ViewOnceBinding, ViewOnceReference, open_view_once_key
from Attachments.Protocol import (
  AttachmentManifest,
  AttachmentError,
  generate_attachment_key,
  seal_manifest,
  seal_bound_chunk,
  open_bound_chunk
)
from Mobile.Attachments import encode_reference, open_attachment_chunk_with_device
from Mobile.Types import MobileAttachmentReference
from Mobile.Codec import mobile_join, mobile_vector, mobile_write_u16
from Identity.Device import DeviceKeys
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_blobs, erase_local_state
from Storage.Blobs import load_blob
from Tests.Support import repeated, append
from Transport.Packet import decode_client_profile

pub struct ViewOnceFixture do
  path :: String
  profile :: Bytes
  binding :: ViewOnceBinding
  reference :: ViewOnceReference
  wire :: Bytes
  ordinary :: Bytes
  chunk :: Bytes
  valid_chunk :: Bytes
  png :: Bytes
  row_label :: String
  row_blob :: Bytes
  record_wire :: Bytes
end

struct ViewOnceMaterial do
  reference :: ViewOnceReference
  wire :: Bytes
  ordinary :: Bytes
  chunk :: Bytes
  png :: Bytes
end

fn fixture_bytes(value :: Result<Bytes, BytesError>) -> Bytes!String do
  case value do
    Err(_) -> Err("view_once_fixture_bytes")
    Ok(bytes)
  end
end

pub fn view_once_fixture_binding_wire(value :: ViewOnceBinding) -> Bytes!String do
  mobile_join([
      value.sender_account_id,
      value.sender_device_id,
      value.receiver_account_id,
      value.receiver_device_id,
      value.conversation_id,
      value.message_id
    ],
    0,
    Bytes.empty())
end

fn fixture_protocol(value :: Result<Bytes, AttachmentError>) -> Bytes!String do
  case value do
    Err(_) -> Err("view_once_fixture_crypto")
    Ok(bytes)
  end
end

fn fixture_material(device :: borrow DeviceKeys,
  binding :: ViewOnceBinding,
  secret :: borrow SecretBytes,
  expires :: U64) -> ViewOnceMaterial!String do
  let png = case Bytes.from_hex("89504e470d0a1a0a0000000d4948445200000001000000010804000000b51c0c020000000b4944415478da6364f80f00010501012718e3660000000049454e44ae426082") do
    Err(_) -> return Err("view_once_fixture_literal")
    Ok(bytes) -> bytes
  end
  let object_id = repeated(91, 32)?
  let capability = repeated(92, 32)?
  let manifest = fixture_protocol(seal_manifest(secret,
    AttachmentManifest {
      version: 4,
      attachment_id: object_id,
      chunk_size: 65536,
      chunk_count: 1,
      plaintext_size: Bytes.length(png),
      filename: Bytes.empty(),
      mime_type: Bytes.from_utf8("image/png"),
      expires_at: expires
    }))?
  # Independent literal-domain encoder. The subject codec is never fixture setup.
  let aad = mobile_join([
      Bytes.from_utf8("morse/view-once/v1/reference\n"),
      view_once_fixture_binding_wire(binding)?,
      object_id,
      capability,
      Crypto.sha256(manifest)
    ],
    0,
    Bytes.empty())?
  let wrapped = case Crypto.hpke_seal_secret(device.identity_public_key,
    Bytes.from_utf8("morse/view-once/v1/image-key"),
    aad,
    secret) do
    Err(_) -> return Err("view_once_fixture_wrap")
    Ok(bytes) -> bytes
  end
  let ordinary_wrapped = case Crypto.hpke_seal_secret(device.identity_public_key,
    Bytes.from_utf8("mesh-msg/v1/attachment-key-wrap"),
    append(Bytes.from_utf8("mesh-msg/v1/attachment-reference"), object_id)?,
    secret) do
    Err(_) -> return Err("view_once_fixture_wrap")
    Ok(bytes) -> bytes
  end
  let reference = ViewOnceReference {
    binding: binding,
    object_id: object_id,
    download_capability: capability,
    encrypted_manifest: manifest,
    wrapped_key: wrapped
  }
  let wire = mobile_join([
      Bytes.from_hex("01564f52")?,
      view_once_fixture_binding_wire(binding)?,
      object_id,
      capability,
      mobile_vector(manifest)?,
      mobile_vector(wrapped)?
    ],
    0,
    Bytes.empty())?
  let ordinary = encode_reference(MobileAttachmentReference {
    object_id: object_id,
    download_capability: capability,
    encrypted_manifest: manifest,
    wrapped_key: ordinary_wrapped
  })?
  let chunk = fixture_protocol(seal_bound_chunk(secret, manifest, 0, png))?
  let authenticated = case Crypto.hpke_open_secret(device.identity_private_key,
    Bytes.from_utf8("morse/view-once/v1/image-key"),
    aad,
    wrapped) do
    Err(_) -> false
    Ok(opened_key) -> do
      let opened = open_bound_chunk(opened_key, manifest, 0, chunk)
      Secret.destroy(opened_key)
      case opened do
        Err(_) -> false
        Ok(bytes) -> Bytes.secure_equals(bytes, png)
      end
    end
  end
  if !declassify(authenticated,
    "TEST ONLY fixture-readiness equality over this authored small PNG and generated HPKE EAM4 ACH4 material; no real data keys references errors or prior caller control") do
    return Err("view_once_fixture_authentication")
  end
  Ok(ViewOnceMaterial {
    reference: reference,
    wire: wire,
    ordinary: ordinary,
    chunk: chunk,
    png: png
  })
end

fn retire_device(device :: consume DeviceKeys) do
  nil
end

pub fn view_once_fixture(mode :: Int) -> ViewOnceFixture!String do
  if !Test.install_in_memory_secure_store() do
    return Err("view_once_fixture_store")
  end
  let root = Env.get("MORSE_C1_FIXTURE_ROOT", "")
  if String.length(root) == 0 do
    return Err("view_once_fixture_root")
  end
  let entropy = case Crypto.random_bytes(8) do
    Err(_) -> return Err("view_once_fixture_entropy")
    Ok(bytes) -> bytes
  end
  let path = root <> "/vo-" <> Bytes.to_hex(entropy) <> ".db"
  create_account_export(mobile_join([
      mobile_vector(Bytes.from_utf8(path))?,
      mobile_vector(Bytes.from_utf8("viewonce"))?
    ],
    0,
    Bytes.empty())?)?
  let profile = load_profile(path)?
  let parsed = decode_client_profile(profile)?
  let binding = ViewOnceBinding {
    sender_account_id: repeated(41, 32)?,
    sender_device_id: repeated(42, 16)?,
    receiver_account_id: parsed.account_id,
    receiver_device_id: parsed.device_id,
    conversation_id: repeated(43, 16)?,
    message_id: repeated(44, 16)?
  }
  let key = platform_key()?
  let device = open_device(parsed, key, path)?
  let secret = case generate_attachment_key() do
    Err(_) -> return Err("view_once_fixture_key")
    Ok(value) -> value
  end
  let material = fixture_material(device,
    binding,
    secret,
    U64.parse(if mode == 1 do
      "946684800000"
    else
      "4102444800000"
    end)?)
  Secret.destroy(secret)
  retire_device(device)
  let material = material?
  let row_label = "view-once/v1/#{Bytes.to_hex(binding.conversation_id)}/#{Bytes.to_hex(binding.message_id)}"
  let chunk = if mode == 3 do
    let last = Bytes.length(material.chunk) - 1
    append(Bytes.slice(material.chunk, 0, last)?,
      fixture_bytes(Bytes.from_list([
        if Bytes.get(material.chunk, last)? == 0 do
          1
        else
          0
        end
      ]))?)?
  else
    material.chunk
  end
  let expiry = if mode == 2 do
    append(fixture_bytes(Bytes.from_list([1]))?,
      fixture_bytes(Bytes.write_u64_be(U64.parse("946684800000")?))?)?
  else
    append(fixture_bytes(Bytes.from_list([0]))?,
      fixture_bytes(Bytes.write_u64_be(U64.parse("0")?))?)?
  end
  let available = mobile_join([
      Bytes.from_hex("01564f41")?,
      mobile_vector(material.wire)?,
      mobile_write_u16(1)?,
      Crypto.sha256(chunk),
      expiry
    ],
    0,
    Bytes.empty())?
  let sealed = seal_local(available, key, local_context(row_label)?)
  Secret.destroy(key)
  let sealed = sealed?
  store_updated_blobs(path, [row_label, row_label <> "/part/0"], [sealed, chunk])?
  if !Bytes.secure_equals(load_blob(path, row_label)?, sealed)
    || !Bytes.secure_equals(load_blob(path, row_label <> "/part/0")?, chunk) do
    return Err("view_once_fixture_readback")
  end
  println("VO_FIXTURE_READY")
  println("VO_CIPHERTEXT_READY")
  Ok(ViewOnceFixture {
    path: path,
    profile: profile,
    binding: binding,
    reference: material.reference,
    wire: material.wire,
    ordinary: material.ordinary,
    chunk: chunk,
    valid_chunk: material.chunk,
    png: material.png,
    row_label: row_label,
    row_blob: sealed,
    record_wire: available
  })
end

pub fn view_once_fixture_selection(value :: ViewOnceFixture) -> ViewOnceSelection do
  ViewOnceSelection {
    database_path: value.path,
    profile: value.profile,
    conversation_id: value.binding.conversation_id,
    message_id: value.binding.message_id
  }
end

pub fn view_once_fixture_clear(value :: ViewOnceFixture) -> Unit!String do
  erase_local_state(value.path)
end

pub fn view_once_fixture_match(value :: Result<Plaintext<ViewOnceImage>, String>,
  expected :: Bytes) -> Plaintext<Bool> do
  case value do
    Err(_) -> false
    Ok(image) -> Bytes.secure_equals(image.content, expected)
  end
end

pub fn view_once_fixture_refused(value :: Result<Plaintext<ViewOnceImage>, String>) -> Plaintext<Bool> do
  case value do
    Err(_) -> true
    Ok(_) -> false
  end
end

pub fn view_once_fixture_reference_opens(value :: ViewOnceFixture) -> Plaintext<Bool>!String do
  let parsed = decode_client_profile(value.profile)?
  let key = platform_key()?
  let device = open_device(parsed, key, value.path)?
  let result = case open_view_once_key(device, value.binding, value.wire) do
    Err(_) -> false
    Ok(secret) -> do
      let opened = open_bound_chunk(secret, value.reference.encrypted_manifest, 0, value.chunk)
      Secret.destroy(secret)
      case opened do
        Err(_) -> false
        Ok(bytes) -> Bytes.secure_equals(bytes, value.png)
      end
    end
  end
  retire_device(device)
  Secret.destroy(key)
  Ok(result)
end

pub fn view_once_fixture_generic_opens(value :: ViewOnceFixture,
  ordinary :: Bool) -> Plaintext<Bool>!String do
  let parsed = decode_client_profile(value.profile)?
  let key = platform_key()?
  let device = open_device(parsed, key, value.path)?
  let wire = if ordinary do
    value.ordinary
  else
    encode_reference(MobileAttachmentReference {
      object_id: value.reference.object_id,
      download_capability: value.reference.download_capability,
      encrypted_manifest: value.reference.encrypted_manifest,
      wrapped_key: value.reference.wrapped_key
    })?
  end
  let opened = open_attachment_chunk_with_device(device, wire, 0, value.chunk)
  retire_device(device)
  Secret.destroy(key)
  Ok(case opened do
    Err(_) -> false
    Ok(bytes) -> Bytes.secure_equals(bytes, value.png)
  end)
end

pub fn view_once_fixture_trigger(value :: ViewOnceFixture, enabled :: Bool) -> Unit!String do
  let database = Sqlite.open(value.path)?
  let result = Sqlite.execute(database,
    if enabled do
      "CREATE TRIGGER vo_owned_rollback BEFORE DELETE ON encrypted_blobs BEGIN SELECT RAISE(ABORT, 'vo_owned_rollback'); END"
    else
      "DROP TRIGGER vo_owned_rollback"
    end,
    [])
  Sqlite.close(database)
  case result do
    Err(_) -> Err("view_once_fixture_trigger")
    Ok(_) -> Ok(nil)
  end
end

pub fn view_once_fixture_row(value :: ViewOnceFixture) -> Bytes!String do
  load_blob(value.path, value.row_label)
end

pub fn view_once_fixture_repair_cache(value :: ViewOnceFixture) -> Unit!String do
  let wire = mobile_join([
      Bytes.from_hex("01564f41")?,
      mobile_vector(value.wire)?,
      mobile_write_u16(1)?,
      Crypto.sha256(value.valid_chunk),
      fixture_bytes(Bytes.from_list([0]))?,
      fixture_bytes(Bytes.write_u64_be(U64.parse("0")?))?
    ],
    0,
    Bytes.empty())?
  let key = platform_key()?
  let sealed = seal_local(wire, key, local_context(value.row_label)?)
  Secret.destroy(key)
  store_updated_blobs(value.path,
    [value.row_label, value.row_label <> "/part/0"],
    [sealed?, value.valid_chunk])
end
