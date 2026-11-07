##! Attachment preparation retains the whole operation's original custody.
from Identity.Device import DeviceKeys
from Attachments.Protocol import AttachmentManifest
from Mobile.Attachments import (
  attachment_manifest,
  decode_reference,
  open_attachment_chunk_with_device
)
from Mobile.AttachmentTransport import (
  legacy_attachment_download_response,
  issuer_attachment_download_response_with_frame
)
from Mobile.BackupAuthority import D4BackupAuthority, require_backup_authority_current_with_key
from Mobile.Codec import current_time
from Mobile.NativeIssuerTls import decode_issuer_tls_root
from Mobile.Profile import open_device_from_blobs
from Storage.FanoutCommit import FanoutSnapshot
from Transport.Packet import ClientProfile

pub resource struct D4BackupAttachmentReader do
  authority :: D4BackupAuthority
  device :: DeviceKeys
  issuer_tls_frame :: Option<Bytes>
end

pub type BackupAttachmentChunk do
  BackupAttachmentAvailable(content :: Plaintext<Bytes>)
  BackupAttachmentUnavailable
  BackupAttachmentExpired
end

fn captured_device_blob(sources :: FanoutSnapshot, label :: String) -> Bytes!String do
  for basis in sources.bases do
    if List.length(basis.labels) != List.length(basis.records) do
      return Err("invalid_backup_snapshot")
    end
    for index in 0..List.length(basis.labels) do
      if List.get(basis.labels, index) == label do
        let value = List.get(basis.records, index)
        if Bytes.length(value) == 0 do
          return Err("backup_source_missing")
        end
        return Ok(value)
      end
    end
  end
  Err("backup_source_not_captured")
end

# Match both actual private keys, rather than trusting the public fields stored
# beside them. These are the same signing and identity guarantees as capture.
fn reader_device_matches(device :: borrow DeviceKeys, profile :: ClientProfile) -> Unit!String do
  let challenge = Bytes.concat(Bytes.from_utf8("morse-backup-custody/v1\n"),
    Crypto.sha256(profile.encoded))?
  let signing_matches = case Crypto.sign(device.signing_private_key, challenge) do
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
  let identity_matches = case Crypto.x25519_public(device.identity_private_key) do
    Err(_) -> false
    Ok(public_key) -> Bytes.secure_equals(public_key.bytes, profile.credential.dh_public_key)
  end
  if !signing_matches || !identity_matches do
    Err("backup_custody_invalid")
  else
    Ok(nil)
  end
end

fn issuer_frame_result(raw :: Result<Bytes, String>) -> Option<Bytes>!String do
  case raw do
    Err(error) -> if error == "host_callback_failed:4:2" do
      Ok(None)
    else
      Err("issuer_tls_config_unavailable")
    end
    Ok(frame) -> if Bytes.length(frame) < 7 || Bytes.length(frame) > 67591 do
      Err("issuer_tls_config_invalid")
    else
      Ok(Some(frame))
    end
  end
end

# Only the Host boundary's exact not-found status denotes an absent selector.
# The explicit seven-byte empty-root frame remains a present system-root choice.
pub fn decode_backup_issuer_frame_result(raw :: Result<Bytes, String>,
  issuer_origin :: String) -> Option<Bytes>!String do
  let frame = issuer_frame_result(raw)?
  case frame do
    None -> Ok(None)
    Some(bytes) -> do
      decode_issuer_tls_root(bytes, issuer_origin)?
      Ok(Some(bytes))
    end
  end
end

fn capture_reader_frame(authority :: D4BackupAuthority,
  device :: borrow DeviceKeys) -> Option<Bytes>!String do
  reader_device_matches(device, authority.profile)?
  decode_backup_issuer_frame_result(Host.push_get_token(Bytes.from_utf8("messenger/issuer-tls-root/v1")),
    authority.config.issuer_origin)
end

fn reject_reader_device(device :: consume DeviceKeys,
  error :: String) -> D4BackupAttachmentReader!String do
  Err(error)
end

fn reject_reader(reader :: consume D4BackupAttachmentReader,
  error :: String) -> D4BackupAttachmentReader!String do
  Err(error)
end

pub fn capture_backup_attachment_reader(path :: String,
  authority :: D4BackupAuthority,
  wrapping_key :: borrow StorageKey) -> D4BackupAttachmentReader!String do
  let signing = captured_device_blob(authority.sources, "device-signing-key/v1")?
  let identity = captured_device_blob(authority.sources, "device-identity-key/v1")?
  let device = open_device_from_blobs(authority.profile, wrapping_key, signing, identity)?
  let frame = case capture_reader_frame(authority, device) do
    Err(error) -> return reject_reader_device(device, error)
    Ok(value) -> value
  end
  let reader = D4BackupAttachmentReader {
    authority: authority,
    device: device,
    issuer_tls_frame: frame
  }
  case reader_fence(path, wrapping_key, reader) do
    Err(error) -> reject_reader(reader, error)
    Ok(_) -> Ok(reader)
  end
end

pub fn backup_attachment_manifest(reader :: borrow D4BackupAttachmentReader,
  reference :: Bytes) -> AttachmentManifest!String do
  attachment_manifest(reader.device, reference)
end

fn require_reader_authority_time(captured_at :: U64,
  fresh_through :: U64,
  now :: U64) -> Unit!String do
  if U64.compare(now, captured_at) < 0 do
    Err("backup_clock_rollback")
  else if U64.compare(now, fresh_through) > 0 do
    Err("backup_authority_expired")
  else
    Ok(nil)
  end
end

# Shared completion policy; real operations supply their own observed samples.
# False denotes strict attachment expiry; authority failures remain errors.
pub fn backup_attachment_read_completion(captured_at :: U64,
  fresh_through :: U64,
  expires_at :: U64,
  before :: U64,
  now :: U64) -> Bool!String do
  require_reader_authority_time(captured_at, fresh_through, before)?
  if U64.compare(now, before) < 0 do
    return Err("backup_clock_rollback")
  end
  require_reader_authority_time(captured_at, fresh_through, now)?
  Ok(U64.compare(now, expires_at) < 0)
end

# Pure guard math; actual operations always obtain their own current time.
pub fn require_backup_attachment_read_time(captured_at :: U64,
  fresh_through :: U64,
  expires_at :: U64,
  now :: U64) -> Unit!String do
  let live = backup_attachment_read_completion(captured_at, fresh_through, expires_at, now, now)?
  if live do
    Ok(nil)
  else
    Err("backup_attachment_expired")
  end
end

fn reader_download(reader :: borrow D4BackupAttachmentReader,
  reference :: Bytes,
  manifest :: AttachmentManifest,
  index :: Int) -> Result<Plaintext<BackupAttachmentChunk>, String> do
  let value = decode_reference(reference)?
  let response = if manifest.version == 2
    || (manifest.version == 4 && manifest.plaintext_size > 16777216) do
    let frame = case reader.issuer_tls_frame do
      None -> return Err("issuer_tls_config_unavailable")
      Some(bytes) -> bytes
    end
    issuer_attachment_download_response_with_frame(reader.authority.config,
      frame,
      value.object_id,
      value.download_capability,
      index + 1)?
  else
    legacy_attachment_download_response(reader.authority.context.pins.network,
      value.object_id,
      value.download_capability,
      index + 1)?
  end
  if response.status == 404 || response.status == 410 do
    Ok(BackupAttachmentUnavailable)
  else if response.status != 200 do
    Err("backup_attachment_http_" <> Int.to_string(response.status))
  else
    let content = open_attachment_chunk_with_device(reader.device, reference, index, response.body)?
    Ok(BackupAttachmentAvailable(content))
  end
end

pub fn fetch_backup_attachment_chunk(path :: String,
  wrapping_key :: borrow StorageKey,
  reader :: borrow D4BackupAttachmentReader,
  reference :: Bytes,
  index :: Int) -> Result<Plaintext<BackupAttachmentChunk>, String> do
  let manifest = backup_attachment_manifest(reader, reference)?
  if (manifest.version != 1 && manifest.version != 2 && manifest.version != 4)
    || index < 0
    || index >= manifest.chunk_count do
    return Err("invalid_attachment_chunk_index")
  end
  reader_fence(path, wrapping_key, reader)?
  let before = current_time()?
  require_reader_authority_time(reader.authority.captured_at,
    reader.authority.fresh_through,
    before)?
  if U64.compare(before, manifest.expires_at) >= 0 do
    reader_fence(path, wrapping_key, reader)?
    let now = current_time()?
    let _live = backup_attachment_read_completion(reader.authority.captured_at,
      reader.authority.fresh_through,
      manifest.expires_at,
      before,
      now)?
    return Ok(BackupAttachmentExpired)
  end
  # Collect the entire transport/authentication result before the final fence.
  # No transaction is held while HTTP or attachment crypto runs.
  let prepared = reader_download(reader, reference, manifest, index)
  reader_fence(path, wrapping_key, reader)?
  let now = current_time()?
  let live = backup_attachment_read_completion(reader.authority.captured_at,
    reader.authority.fresh_through,
    manifest.expires_at,
    before,
    now)?
  let content = prepared?
  if live do
    Ok(content)
  else
    Ok(BackupAttachmentExpired)
  end
end

# The writer compares only original ciphertexts, exact raw native resources,
# bounded index authority and the real clock. No payload opening or new key.
pub fn require_backup_attachment_reader_current_on(database :: SqliteConn,
  wrapping_key :: borrow StorageKey,
  reader :: borrow D4BackupAttachmentReader) -> Unit!String do
  require_backup_authority_current_with_key(database, reader.authority, wrapping_key)?
  let current = issuer_frame_result(Host.push_get_token(Bytes.from_utf8("messenger/issuer-tls-root/v1")))?
  if current != reader.issuer_tls_frame do
    Err("account_state_changed")
  else
    Ok(nil)
  end
end

fn reader_fence(path :: String,
  wrapping_key :: borrow StorageKey,
  reader :: borrow D4BackupAttachmentReader) -> Unit!String do
  let database = case Sqlite.open(path) do
    Err(_) -> return Err("database_open_failed")
    Ok(value) -> value
  end
  let started = case Sqlite.execute(database, "PRAGMA busy_timeout = 1000", []) do
    Err(error)
    Ok(_) -> Sqlite.execute(database, "BEGIN IMMEDIATE", [])
  end
  let result = case started do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> case require_backup_attachment_reader_current_on(database, wrapping_key, reader) do
      Err(error)
      Ok(_) -> case Sqlite.commit(database) do
        Err(_) -> Err("database_write_failed")
        Ok(_) -> Ok(nil)
      end
    end
  end
  case result do
    Err(_) -> do
      Sqlite.rollback(database)
      nil
    end
    Ok(_) -> nil
  end
  Sqlite.close(database)
  result
end

# Whole captured operations retain this same reader and caller-owned key.
# This is the existing fence, not a refreshed custody or source snapshot.
pub fn require_backup_attachment_reader_current(path :: String,
  wrapping_key :: borrow StorageKey,
  reader :: borrow D4BackupAttachmentReader) -> Unit!String do
  reader_fence(path, wrapping_key, reader)
end
