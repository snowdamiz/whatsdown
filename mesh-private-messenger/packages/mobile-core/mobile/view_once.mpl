##! Captured local image consumption. No HTTP, native export or caller clock.
from Identity.Device import DeviceKeys
from Storage.FanoutCommit import FanoutSnapshot, combine_fanout_snapshots
from Storage.AccountGuard import AccountBasis, load_account_basis_bounded_with_key
from Storage.Keys import platform_key, open_local, local_context, seal_local
from Storage.ViewOnce import (
  ViewOnceAvailable,
  ViewOnceRecord,
  ViewOnceConsumeAction,
  decode_view_once_record,
  encode_view_once_record,
  observe_view_once_consume,
  view_once_time_action,
  commit_view_once_consumed
)
from Mobile.Profile import open_device_from_blobs
from Mobile.Codec import current_time, mobile_wide
from Transport.Packet import ClientProfile, decode_client_profile
from Attachments.ViewOnce import (
  ViewOnceReference,
  decode_view_once_reference,
  open_view_once_key,
  view_once_binding_digest
)
from Attachments.Protocol import open_manifest, open_bound_chunk

pub struct ViewOnceSelection do
  database_path :: String
  profile :: Bytes
  conversation_id :: Bytes
  message_id :: Bytes
end

pub type ViewOnceImageFormat do
  ViewOncePng
  ViewOnceJpeg
end

pub struct ViewOnceImage do
  format :: ViewOnceImageFormat
  content :: Plaintext<Bytes>
end

pub resource struct PreparedViewOnce do
  path :: String
  key :: StorageKey
  device :: DeviceKeys
  before :: FanoutSnapshot
  row_label :: String
  cache_labels :: List<String>
  consumed_blob :: Bytes
  image :: Plaintext<ViewOnceImage>
  expires_at :: Plaintext<U64>
  message_expiry :: Plaintext<Option<U64>>
  observed_at :: U64
end

struct CompletedViewOnce do
  image :: ViewOnceImage
  expires_at :: U64
  message_expiry :: Option<U64>
  binding_digest :: Bytes
end

fn capture_caches(path :: String,
  key :: borrow StorageKey,
  profile :: Bytes,
  labels :: List<String>,
  offset :: Int,
  bases :: List<AccountBasis>) -> FanoutSnapshot!String do
  if offset >= List.length(labels) do
    Ok(FanoutSnapshot { bases: bases })
  else
    let basis = load_account_basis_bounded_with_key(path,
      key,
      List.take(List.drop(labels, offset), 64),
      65536,
      66000,
      4289536)?
    if !Bytes.secure_equals(basis.profile, profile) do
      return Err("view_once_unavailable")
    end
    capture_caches(path, key, profile, labels, offset + 64, List.append(bases, basis))
  end
end

fn captured_blob(before :: FanoutSnapshot, label :: String) -> Bytes!String do
  for basis in before.bases do
    if List.length(basis.labels) != List.length(basis.records) do
      return Err("view_once_unavailable")
    end
    for index in 0..List.length(basis.labels) do
      if List.get(basis.labels, index) == label do
        let value = List.get(basis.records, index)
        if Bytes.length(value) == 0 do
          return Err("view_once_unavailable")
        end
        return Ok(value)
      end
    end
  end
  Err("view_once_unavailable")
end

fn held_device_matches(device :: borrow DeviceKeys, profile :: ClientProfile) -> Bool do
  let challenge = Crypto.sha256(profile.encoded)
  let signing = case Crypto.sign(device.signing_private_key, challenge) do
    Err(_) -> false
    Ok(signature) -> case Crypto.verify(SigningPublicKey {
        bytes: profile.credential.signing_public_key
      },
      challenge,
      signature) do
      Err(_) -> false
      Ok(valid) -> valid
    end
  end
  let identity = case Crypto.x25519_public(device.identity_private_key) do
    Err(_) -> false
    Ok(key) -> Bytes.secure_equals(key.bytes, profile.credential.dh_public_key)
  end
  signing && identity && Bytes.secure_equals(device.device_id, profile.device_id)
end

fn opened_parts(secret :: borrow SecretBytes,
  reference :: ViewOnceReference,
  available :: ViewOnceAvailable,
  before :: FanoutSnapshot,
  labels :: List<String>,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(available.chunk_hashes) do
    Ok(List.reverse(output))
  else
    let wire = captured_blob(before, List.get(labels, index))?
    if !Bytes.secure_equals(Crypto.sha256(wire), List.get(available.chunk_hashes, index)) do
      return Err("view_once_unavailable")
    end
    let chunk = case open_bound_chunk(secret, reference.encrypted_manifest, index, wire) do
      Err(_) -> return Err("view_once_unavailable")
      Ok(bytes) -> bytes
    end
    opened_parts(secret, reference, available, before, labels, index + 1, [chunk] ++ output)
  end
end

fn opened_image(secret :: borrow SecretBytes,
  reference :: ViewOnceReference,
  available :: ViewOnceAvailable,
  before :: FanoutSnapshot,
  labels :: List<String>) -> CompletedViewOnce!String do
  let manifest = case open_manifest(secret, reference.encrypted_manifest) do
    Err(_) -> return Err("view_once_unavailable")
    Ok(value) -> value
  end
  if manifest.version != 4
    || manifest.plaintext_size < 1
    || manifest.plaintext_size > 16777216
    || manifest.chunk_size != 65536
    || manifest.chunk_count < 1
    || manifest.chunk_count > 256
    || manifest.chunk_count != (manifest.plaintext_size + 65535) / 65536
    || manifest.chunk_count != List.length(available.chunk_hashes)
    || !Bytes.secure_equals(manifest.attachment_id, reference.object_id) do
    return Err("view_once_unavailable")
  end
  let png = Bytes.secure_equals(manifest.mime_type, Bytes.from_utf8("image/png"))
  let jpeg = Bytes.secure_equals(manifest.mime_type, Bytes.from_utf8("image/jpeg"))
  if !png && !jpeg do
    return Err("view_once_unavailable")
  end
  let parts = opened_parts(secret, reference, available, before, labels, 0, [])?
  let content :: Plaintext<Bytes> = case Bytes.concat_many(parts, 16777216) do
    Err(_) -> return Err("view_once_unavailable")
    Ok(bytes) -> bytes
  end
  if Bytes.length(content) != manifest.plaintext_size do
    return Err("view_once_unavailable")
  end
  let valid_header = if png do
    Bytes.length(content) >= 8
      && Bytes.secure_equals(Bytes.slice(content, 0, 8)?, Bytes.from_hex("89504e470d0a1a0a")?)
  else
    Bytes.length(content) >= 4
      && Bytes.secure_equals(Bytes.slice(content, 0, 3)?, Bytes.from_hex("ffd8ff")?)
      && Bytes.secure_equals(Bytes.slice(content, Bytes.length(content) - 2, 2)?,
        Bytes.from_hex("ffd9")?)
  end
  if !valid_header do
    return Err("view_once_unavailable")
  end
  Ok(CompletedViewOnce {
    image: ViewOnceImage {
      format: if png do
        ViewOncePng
      else
        ViewOnceJpeg
      end,
      content: content
    },
    expires_at: manifest.expires_at,
    message_expiry: available.message_expiry,
    binding_digest: view_once_binding_digest(reference.binding)?
  })
end

fn authenticate_private(device :: borrow DeviceKeys,
  profile :: ClientProfile,
  selection :: ViewOnceSelection,
  before :: FanoutSnapshot,
  labels :: List<String>,
  opened_profile :: Result<Plaintext<Bytes>, String>,
  opened_record :: Result<Plaintext<Bytes>, String>) -> CompletedViewOnce!String do
  let stored_profile :: Plaintext<Bytes> = opened_profile?
  if !Bytes.secure_equals(stored_profile, selection.profile) do
    return Err("view_once_unavailable")
  end
  if !held_device_matches(device, profile) do
    return Err("view_once_unavailable")
  end
  let raw :: Plaintext<Bytes> = opened_record?
  let available = case decode_view_once_record(raw)? do
    Consumed(_) -> return Err("view_once_unavailable")
    Available(value) -> value
  end
  let reference = decode_view_once_reference(available.reference)?
  if !Bytes.secure_equals(reference.binding.receiver_account_id, profile.account_id)
    || !Bytes.secure_equals(reference.binding.receiver_device_id, profile.device_id)
    || !Bytes.secure_equals(reference.binding.conversation_id, selection.conversation_id)
    || !Bytes.secure_equals(reference.binding.message_id, selection.message_id) do
    return Err("view_once_unavailable")
  end
  let secret = open_view_once_key(device, reference.binding, available.reference)?
  let result = opened_image(secret, reference, available, before, labels)
  Secret.destroy(secret)
  result
end

fn totalized_complete(raw :: Result<CompletedViewOnce, String>,
  zero :: U64) -> Plaintext<CompletedViewOnce> do
  case raw do
    Ok(value) -> value
    Err(_) -> CompletedViewOnce {
      image: ViewOnceImage { format: ViewOncePng, content: Bytes.empty() },
      expires_at: zero,
      message_expiry: Some(zero),
      binding_digest: Bytes.empty()
    }
  end
end

fn preparation_action(raw :: Result<CompletedViewOnce, String>,
  record :: Result<Bytes, String>,
  previous :: U64,
  now :: U64) -> Plaintext<ViewOnceConsumeAction> do
  case raw do
    Err(_) -> Refuse
    Ok(value) -> case record do
      Err(_) -> Refuse
      Ok(_) -> view_once_time_action(value.expires_at, value.message_expiry, previous, now)
    end
  end
end

fn reject_captured(key :: consume StorageKey,
  device :: consume DeviceKeys) -> PreparedViewOnce!String do
  Err("view_once_unavailable")
end

pub fn prepare_view_once(selection :: ViewOnceSelection) -> PreparedViewOnce!String do
  if String.length(selection.database_path) == 0
    || String.length(selection.database_path) > 4096
    || Bytes.length(selection.profile) == 0
    || Bytes.length(selection.profile) > 36134
    || Bytes.length(selection.conversation_id) != 16
    || Bytes.length(selection.message_id) != 16 do
    return Err("view_once_unavailable")
  end
  let row_label = "view-once/v1/#{Bytes.to_hex(selection.conversation_id)}/#{Bytes.to_hex(selection.message_id)}"
  let labels = for index in 0..256 do
    "#{row_label}/part/#{Int.to_string(index)}"
  end
  let key = platform_key()?
  let initial = load_account_basis_bounded_with_key(selection.database_path,
    key,
    ["device-signing-key/v1", "device-identity-key/v1", row_label],
    65536,
    66000,
    263536)?
  let profile = decode_client_profile(selection.profile)?
  let device = open_device_from_blobs(profile,
    key,
    List.get(initial.records, 0),
    List.get(initial.records, 1))?
  let caches = capture_caches(selection.database_path, key, initial.profile, labels, 0, [])?
  let before = combine_fanout_snapshots(FanoutSnapshot { bases: [initial] }, caches)?
  let zero = mobile_wide("0")?
  let started = current_time()?
  # Both effects complete before either private Result is inspected.
  let opened_profile = open_local(initial.profile, key, local_context("profile/v1")?)
  let opened_record = open_local(captured_blob(before, row_label)?, key, local_context(row_label)?)
  let raw = authenticate_private(device,
    profile,
    selection,
    before,
    labels,
    opened_profile,
    opened_record)
  # Observe the real completion sample without matching a private Result tag.
  let completed_at = current_time()?
  let complete = totalized_complete(raw, zero)
  let record = encode_view_once_record(Consumed(complete.binding_digest))
  case observe_view_once_consume(preparation_action(raw, record, started, completed_at)) do
    Refuse -> reject_captured(key, device)
    Consume -> do
      let consumed_blob = seal_local(Result.unwrap_or(record, Bytes.empty()),
        key,
        local_context(row_label)?)?
      Ok(PreparedViewOnce {
        path: selection.database_path,
        key: key,
        device: device,
        before: before,
        row_label: row_label,
        cache_labels: labels,
        consumed_blob: consumed_blob,
        image: complete.image,
        expires_at: complete.expires_at,
        message_expiry: complete.message_expiry,
        observed_at: completed_at
      })
    end
  end
end

pub fn consume_prepared_view_once(prepared :: consume PreparedViewOnce) -> Plaintext<ViewOnceImage>!String do
  let committed = commit_view_once_consumed(prepared.path,
    prepared.key,
    prepared.before,
    prepared.row_label,
    prepared.consumed_blob,
    prepared.cache_labels,
    prepared.expires_at,
    prepared.message_expiry,
    prepared.observed_at)
  let result = case committed do
    Err(_) -> Err("view_once_unavailable")
    Ok(_) -> Ok(prepared.image)
  end
  retire_prepared_view_once(prepared)
  result
end

pub fn consume_view_once(selection :: ViewOnceSelection) -> Plaintext<ViewOnceImage>!String do
  let prepared = prepare_view_once(selection)?
  consume_prepared_view_once(prepared)
end

pub fn retire_prepared_view_once(prepared :: consume PreparedViewOnce) do
  nil
end
