##! Known synthetic values, real custody/history/HPKE/EAM; no HTTP or fake authority.
from Tests.BackupArchiveFixture import (
  D4CoreFixture,
  d4_core_fixture,
  d4_core_install_direct_history,
  d4_core_actual_group
)
from Tests.BackupAttachmentFixture import backup_attachment_fixture_damage
from Tests.Support import repeated, append
from Mobile.Profile import open_device
from Identity.Device import DeviceKeys
from Transport.Packet import decode_client_profile
from Attachments.Protocol import (
  AttachmentManifest,
  generate_attachment_key,
  seal_manifest,
  seal_bound_chunk
)
from Mobile.Attachments import encode_reference, decode_reference
from Mobile.Types import MobileAttachmentReference, MobileGroupHistoryEntry
from Mobile.Codec import mobile_join, mobile_byte, mobile_vector, mobile_write_u32
from Mobile.HistoryWire import decode_history, encode_history
from Mobile.GroupState import encode_group_history, group_history_label
from Storage.Keys import platform_key, local_context, seal_local
from Storage.HistoryBlobs import open_history_blob, seal_history_blob
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs

# Test host absence is status1, so the fixture explicitly supplies the same
# canonical system-root choice as the qualified reader network fixture. This is
# a public fixture input, not a production Missing fallback or an auth override.
pub fn preflight_fixture() -> D4CoreFixture!String do
  let fixture = d4_core_fixture()?
  let selector = Bytes.from_utf8("messenger/issuer-tls-root/v1")
  let frame = Bytes.from_hex("01000000000000")?
  if !Test.set_push_token(selector, frame) do
    return Err("preflight_fixture_issuer_frame_install")
  end
  let actual = Host.push_get_token(selector)?
  if !Bytes.secure_equals(actual, frame) do
    return Err("preflight_fixture_issuer_frame_readback")
  end
  println("AUTH_PREFLIGHT_EXPLICIT_ISSUER_FRAME_READY")
  Ok(fixture)
end

pub struct PreflightFileSpec do
  tag :: Int
  version :: Int
  size :: Int
  filename :: Bytes
  mime_type :: Bytes
  expires_at :: U64
  mutation :: Int
end

pub struct PreflightFileMaterial do
  reference :: Bytes
  manifest :: AttachmentManifest
  chunk :: Bytes
end

pub fn preflight_file_spec(tag :: Int, version :: Int, size :: Int) -> PreflightFileSpec!String do
  Ok(PreflightFileSpec {
    tag: tag,
    version: version,
    size: size,
    filename: Bytes.from_utf8("fixture.bin"),
    mime_type: Bytes.from_utf8("application/octet-stream"),
    expires_at: U64.parse("4102444800000")?,
    mutation: 0
  })
end

fn preflight_material_with_secret(device :: borrow DeviceKeys,
  secret :: borrow SecretBytes,
  spec :: PreflightFileSpec) -> PreflightFileMaterial!String do
  let object_id = repeated(spec.tag, 32)?
  let manifest = AttachmentManifest {
    version: spec.version,
    attachment_id: object_id,
    chunk_size: 65536,
    chunk_count: (spec.size + 65535) / 65536,
    plaintext_size: spec.size,
    filename: spec.filename,
    mime_type: spec.mime_type,
    expires_at: spec.expires_at
  }
  let sealed = case seal_manifest(secret, manifest) do
    Err(_) -> return Err("preflight_fixture_manifest")
    Ok(value) -> value
  end
  let outer = if spec.mutation == 2 do
    repeated(spec.tag + 1, 32)?
  else
    object_id
  end
  let encrypted = if spec.mutation == 3 do
    backup_attachment_fixture_damage(sealed)?
  else
    sealed
  end
  let wrapped = case Crypto.hpke_seal_secret(device.identity_public_key,
    Bytes.from_utf8("mesh-msg/v1/attachment-key-wrap"),
    append(Bytes.from_utf8("mesh-msg/v1/attachment-reference"), outer)?,
    secret) do
    Err(_) -> return Err("preflight_fixture_hpke")
    Ok(value) -> value
  end
  let key_wire = if spec.mutation == 1 do
    backup_attachment_fixture_damage(wrapped)?
  else
    wrapped
  end
  let chunk = if spec.size == 1 do
    case seal_bound_chunk(secret, sealed, 0, Bytes.from_utf8("x")) do
      Err(_) -> return Err("preflight_fixture_chunk")
      Ok(value) -> value
    end
  else
    Bytes.empty()
  end
  Ok(PreflightFileMaterial {
    reference: encode_reference(MobileAttachmentReference {
      object_id: outer,
      download_capability: repeated(spec.tag + 2, 32)?,
      encrypted_manifest: encrypted,
      wrapped_key: key_wire
    })?,
    manifest: manifest,
    chunk: chunk
  })
end

fn preflight_material(device :: borrow DeviceKeys,
  spec :: PreflightFileSpec) -> PreflightFileMaterial!String do
  let secret = case generate_attachment_key() do
    Err(_) -> return Err("preflight_fixture_secret")
    Ok(value) -> value
  end
  let result = preflight_material_with_secret(device, secret, spec)
  Secret.destroy(secret)
  result
end

fn preflight_drop_device(device :: consume DeviceKeys) do
  nil
end

fn preflight_files_with_key(f :: D4CoreFixture,
  specs :: List<PreflightFileSpec>,
  key :: borrow StorageKey) -> List<PreflightFileMaterial>!String do
  let profile = decode_client_profile(f.public_profile)?
  let device = open_device(profile, key, f.path)?
  let result = preflight_files_with_device(device, specs)
  preflight_drop_device(device)
  result
end

fn preflight_files_with_device(device :: borrow DeviceKeys,
  specs :: List<PreflightFileSpec>) -> List<PreflightFileMaterial>!String do
  Ok(for spec in specs do
    preflight_material(device, spec)?
  end)
end

pub fn preflight_files(f :: D4CoreFixture,
  specs :: List<PreflightFileSpec>) -> List<PreflightFileMaterial>!String do
  let key = platform_key()?
  let result = preflight_files_with_key(f, specs, key)
  Secret.destroy(key)
  result
end

pub fn preflight_batch(parts :: List<Bytes>) -> Bytes!String do
  if List.length(parts) == 0 do
    return Ok(Bytes.empty())
  end
  if List.length(parts) == 1 do
    return Ok(List.head(parts))
  end
  mobile_join([
      mobile_byte(1)?,
      Bytes.from_utf8("ATB"),
      mobile_write_u32(List.length(parts))?,
      mobile_join(for part in parts do
          mobile_vector(part)?
        end,
        0,
        Bytes.empty())?
    ],
    0,
    Bytes.empty())
end

fn preflight_direct_wire(f :: D4CoreFixture,
  attachment :: Bytes,
  sparse :: Bool,
  excluded_only :: Bool,
  key :: borrow StorageKey) -> Bytes!String do
  let before = load_blob(f.path, f.source_label)?
  let rows = decode_history(open_history_blob(before, key, f.source_label)?)?
  if List.length(rows) != 1 do
    return Err("preflight_fixture_history_cardinality")
  end
  let row = List.head(rows)
  let inner = row.inner
  let updated_inner = %{inner | body: Bytes.from_utf8("x"), attachment_manifest: attachment}
  let updated = %{row | inner: updated_inner}
  let selected = if sparse || excluded_only do
    let timed_inner = %{inner |
      body: Bytes.from_utf8("excluded"),
      disappearing_seconds: 60,
      attachment_manifest: Bytes.from_utf8("invalid timed reference must not authenticate")
    }
    if excluded_only do
      [%{row | inner: timed_inner}]
    else
      [%{row | inner: timed_inner}, updated]
    end
  else
    [updated]
  end
  seal_history_blob(encode_history(selected)?, key, f.source_label)
end

pub fn preflight_install_direct(f :: D4CoreFixture,
  parts :: List<Bytes>,
  sparse :: Bool) -> Unit!String do
  d4_core_install_direct_history(f)?
  let encoded = preflight_batch(parts)?
  let key = platform_key()?
  let result = preflight_direct_wire(f, encoded, sparse, false, key)
  Secret.destroy(key)
  store_updated_blobs(f.path, [f.source_label], [result?])
end

pub fn preflight_install_excluded_direct(f :: D4CoreFixture) -> Unit!String do
  d4_core_install_direct_history(f)?
  let key = platform_key()?
  let result = preflight_direct_wire(f, Bytes.empty(), false, true, key)
  Secret.destroy(key)
  store_updated_blobs(f.path, [f.source_label], [result?])
end

fn preflight_group_reference(f :: D4CoreFixture,
  value :: PreflightFileMaterial,
  addressed :: Bool) -> Bytes!String do
  let reference = case decode_reference(value.reference) do
    Err(error) -> return Err(error)
    Ok(decoded) -> decoded
  end
  let profile = decode_client_profile(f.public_profile)?
  let account = if addressed do
    profile.account_id
  else
    repeated(201, 32)?
  end
  let device = if addressed do
    profile.device_id
  else
    repeated(202, 16)?
  end
  mobile_join([
      mobile_byte(1)?,
      Bytes.from_utf8("ATG"),
      reference.object_id,
      reference.download_capability,
      mobile_vector(reference.encrypted_manifest)?,
      mobile_write_u32(1)?,
      account,
      device,
      mobile_vector(reference.wrapped_key)?
    ],
    0,
    Bytes.empty())
end

pub fn preflight_install_group(f :: D4CoreFixture,
  materials :: List<PreflightFileMaterial>) -> Bytes!String do
  if List.length(materials) != 3 do
    return Err("preflight_fixture_group_cardinality")
  end
  let group = d4_core_actual_group(f)?
  let parts = for index in 0..3 do
    preflight_group_reference(f, List.get(materials, index), index != 1)?
  end
  let profile = decode_client_profile(f.public_profile)?
  let encoded = encode_group_history([
    MobileGroupHistoryEntry {
      disappearing_seconds: 0,
      message_id: Bytes.empty(),
      direction: 1,
      epoch: U64.parse("1")?,
      sender_account_id: profile.account_id,
      sender_device_id: profile.device_id,
      timestamp: f.now,
      body: Bytes.from_utf8("x"),
      attachment: preflight_batch(parts)?
    }
  ])?
  let key = platform_key()?
  let sealed = seal_local(encoded, key, local_context(group_history_label(group))?)
  Secret.destroy(key)
  store_updated_blobs(f.path, [group_history_label(group)], [sealed?])?
  Ok(group)
end
