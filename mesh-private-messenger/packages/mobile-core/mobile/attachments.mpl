from Mobile.AttachmentMetadata import attachment_input_admitted
from Attachments.Protocol import (
  AttachmentError,
  AttachmentManifest,
  generate_attachment_id,
  generate_attachment_key,
  open_bound_chunk,
  open_manifest,
  seal_bound_chunk,
  seal_manifest
)
from Binary.Reader import BinaryReader
from Identity.Device import DeviceKeys
from Mobile.Codec import (
  current_time,
  encode_output_list,
  mobile_byte,
  mobile_finish,
  mobile_join,
  mobile_read_u32,
  mobile_reader,
  mobile_vector,
  mobile_wide,
  mobile_write_u32,
  mobile_write_u64,
  random_bytes,
  take_fixed,
  take_vector_error
)
from Mobile.Profile import load_profile, open_device
from Mobile.Types import (
  MobileAttachmentChunkRequest,
  MobileAttachmentPrepareRequest,
  MobileAttachmentRecipient,
  MobileAttachmentReference,
  MobileReadBytes
)
from Objects.Grant import ObjectControl, encode_complete, encode_delete, encode_grant, mint_grant
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.Attachments implementation.

# Pure positional syntax only. The whole backup operation separately proves
# captured source custody and authenticates every addressed manifest before I/O.
pub type BackupAttachmentReferenceSlot do
  BackupAttachmentReference(reference :: Plaintext<Bytes>)
  BackupAttachmentNoRecipient
end

pub fn backup_attachment_reference_slots(encoded :: Plaintext<Bytes>,
  scope_kind :: Int,
  account_id :: Bytes,
  device_id :: Bytes) -> Result<Plaintext<List<BackupAttachmentReferenceSlot>>, String> do
  if (scope_kind != 1 && scope_kind != 2)
    || Bytes.length(account_id) != 32
    || Bytes.length(device_id) != 16 do
    return Err("invalid_backup_attachment_reference")
  end
  let parts = attachment_parts(encoded,
    if scope_kind == 1 do
      1024
    else
      65536
    end)?
  let slots = for part in parts do
    backup_attachment_reference_slot(part, scope_kind, account_id, device_id)?
  end
  Ok(slots)
end

# Capture preserves every source position; ordinary group reads keep their
# existing first-match/filter behavior below. These helpers perform syntax only.
fn backup_attachment_group_key(state :: BinaryReader,
  remaining :: Int,
  account_id :: Bytes,
  device_id :: Bytes,
  found :: Bytes,
  matches :: Int) -> Bytes!String do
  if remaining == 0 do
    mobile_finish(state, "invalid_backup_attachment_reference")?
    Ok(found)
  else
    let entry_account = take_fixed(state, 32)?
    let entry_device = take_fixed(entry_account.state, 16)?
    let wrapped = take_vector_error(entry_device.state, 160, "invalid_backup_attachment_reference")?
    if Bytes.length(wrapped.value) == 0 do
      return Err("invalid_backup_attachment_reference")
    end
    let here = Bytes.secure_equals(entry_account.value, account_id)
      && Bytes.secure_equals(entry_device.value, device_id)
    let count = matches
      + if here do
        1
      else
        0
      end
    if count > 1 do
      return Err("invalid_backup_attachment_reference")
    end
    backup_attachment_group_key(wrapped.state,
      remaining - 1,
      account_id,
      device_id,
      if here do
        wrapped.value
      else
        found
      end,
      count)
  end
end

fn backup_attachment_group_slot(input :: Bytes,
  account_id :: Bytes,
  device_id :: Bytes) -> BackupAttachmentReferenceSlot!String do
  let state = mobile_reader(input, 65536, "invalid_backup_attachment_reference")?
  let header = take_fixed(state, 4)?
  let object_id = take_fixed(header.state, 32)?
  let capability = take_fixed(object_id.state, 32)?
  let encrypted_manifest = take_vector_error(capability.state,
    640,
    "invalid_backup_attachment_reference")?
  let count = take_fixed(encrypted_manifest.state, 4)?
  let length = mobile_read_u32(count.value)?
  if !Bytes.secure_equals(header.value, group_header()?)
    || Bytes.length(encrypted_manifest.value) == 0
    || length < 1
    || length > 256 do
    return Err("invalid_backup_attachment_reference")
  end
  let wrapped = backup_attachment_group_key(count.state,
    length,
    account_id,
    device_id,
    Bytes.empty(),
    0)?
  if Bytes.length(wrapped) == 0 do
    Ok(BackupAttachmentNoRecipient)
  else
    let reference = encode_reference(MobileAttachmentReference {
      object_id: object_id.value,
      download_capability: capability.value,
      encrypted_manifest: encrypted_manifest.value,
      wrapped_key: wrapped
    })?
    Ok(BackupAttachmentReference(reference))
  end
end

fn backup_attachment_reference_slot(part :: Bytes,
  scope_kind :: Int,
  account_id :: Bytes,
  device_id :: Bytes) -> BackupAttachmentReferenceSlot!String do
  if scope_kind == 2
    && Bytes.length(part) >= 4
    && Bytes.secure_equals(Bytes.slice(part, 0, 4)?, group_header()?) do
    backup_attachment_group_slot(part, account_id, device_id)
  else
    let _checked = decode_reference(part)?
    Ok(BackupAttachmentReference(part))
  end
end

##!
##! An attachment reference (ATR) travels inside the authenticated, encrypted message and
##! names one opaque object plus the encrypted manifest. Its attachment key is HPKE-wrapped
##! to exactly one device identity key, so every stored copy is readable only by the device
##! that holds it. Group messages carry an ATG: one manifest with a wrapped key per member.

pub fn attachment_chunk_size() -> Int do
  65536
end

fn maximum_attachment_size() -> Int do
  256 * attachment_chunk_size()
end

fn reference_header() -> Bytes!String do
  mobile_join([mobile_byte(1)?, Bytes.from_utf8("ATR")], 0, Bytes.empty())
end

fn group_header() -> Bytes!String do
  mobile_join([mobile_byte(1)?, Bytes.from_utf8("ATG")], 0, Bytes.empty())
end

# A bounded ATB list contains ATR references, ATG envelopes, or opened summaries.
# Single attachments retain their original representation.

fn batch_header() -> Bytes!String do
  mobile_join([mobile_byte(1)?, Bytes.from_utf8("ATB")], 0, Bytes.empty())
end

fn read_batch_parts(state :: BinaryReader,
  remaining :: Int,
  maximum :: Int,
  values :: List<Bytes>) -> List<Bytes>!String do
  if remaining == 0 do
    mobile_finish(state, "invalid_attachment_reference")?
    Ok(values)
  else
    let part = take_vector_error(state, maximum, "invalid_attachment_reference")?
    if Bytes.length(part.value) == 0 do
      return Err("invalid_attachment_reference")
    end
    read_batch_parts(part.state, remaining - 1, maximum, List.append(values, part.value))
  end
end

fn attachment_parts(input :: Bytes, maximum :: Int) -> List<Bytes>!String do
  if Bytes.length(input) == 0 do
    return Ok([])
  end
  let state = mobile_reader(input, 65536, "invalid_attachment_reference")?
  let header = take_fixed(state, 4)?
  if !Bytes.secure_equals(header.value, batch_header()?) do
    if Bytes.length(input) > maximum do
      return Err("invalid_attachment_reference")
    end
    return Ok([input])
  end
  let count = take_fixed(header.state, 4)?
  let length = mobile_read_u32(count.value)?
  if length < 2 || length > 10 do
    return Err("invalid_attachment_reference")
  end
  read_batch_parts(count.state, length, maximum, [])
end

fn encode_batch(values :: List<Bytes>) -> Bytes!String do
  case values do
    [] -> Ok(Bytes.empty())
    [value] -> Ok(value)
    _ ->
      let parts = for value in values do
        mobile_vector(value)?
      end
      mobile_join([
          batch_header()?,
          mobile_write_u32(List.length(values))?,
          mobile_join(parts, 0, Bytes.empty())?
        ],
        0,
        Bytes.empty())
  end
end

fn wrap_info() -> Bytes do
  Bytes.from_utf8("mesh-msg/v1/attachment-key-wrap")
end

fn wrap_aad(object_id :: Bytes) -> Bytes!String do
  mobile_join([Bytes.from_utf8("mesh-msg/v1/attachment-reference"), object_id], 0, Bytes.empty())
end

fn attachment_error_class(error :: AttachmentError) -> Int do
  case error do
    InvalidManifest -> 1
    InvalidChunk -> 2
    InvalidChunkIndex -> 3
    InvalidChunkSize -> 4
    AuthenticationRejected -> 5
    CryptoFailure(_) -> 6
  end
end

fn describe_attachment_error(error :: AttachmentError) -> String do
  let status = declassify(attachment_error_class(error),
    "attachment operations expose only six fixed failure classes; filename and MIME bytes, nested CryptoError payloads, and unrelated private control remain private")
  case status do
    1 -> "invalid_attachment_manifest"
    2 -> "invalid_attachment_chunk"
    3 -> "invalid_attachment_chunk_index"
    4 -> "invalid_attachment_chunk_size"
    5 -> "attachment_authentication_failed"
    6 -> "attachment_crypto_failed"
    _ -> "invalid_attachment_manifest"
  end
end

fn valid_reference(value :: MobileAttachmentReference) -> Bool do
  Bytes.length(value.object_id) == 32
    && Bytes.length(value.download_capability) == 32
    && Bytes.length(value.encrypted_manifest) > 0
    && Bytes.length(value.encrypted_manifest) <= 640
    && Bytes.length(value.wrapped_key) > 0
    && Bytes.length(value.wrapped_key) <= 160
end

pub fn encode_reference(value :: MobileAttachmentReference) -> Bytes!String do
  if !valid_reference(value) do
    Err("invalid_attachment_reference")
  else
    mobile_join([
        reference_header()?,
        value.object_id,
        value.download_capability,
        mobile_vector(value.encrypted_manifest)?,
        mobile_vector(value.wrapped_key)?
      ],
      0,
      Bytes.empty())
  end
end

fn read_reference(input :: Bytes) -> MobileAttachmentReference!String do
  let state = mobile_reader(input, 1024, "invalid_attachment_reference")?
  let header = take_fixed(state, 4)?
  let object_id = take_fixed(header.state, 32)?
  let download_capability = take_fixed(object_id.state, 32)?
  let encrypted_manifest = take_vector_error(download_capability.state,
    640,
    "invalid_attachment_reference")?
  let wrapped_key = take_vector_error(encrypted_manifest.state,
    160,
    "invalid_attachment_reference")?
  mobile_finish(wrapped_key.state, "invalid_attachment_reference")?
  let value = MobileAttachmentReference {
    object_id: object_id.value,
    download_capability: download_capability.value,
    encrypted_manifest: encrypted_manifest.value,
    wrapped_key: wrapped_key.value
  }
  if !Bytes.secure_equals(header.value, reference_header()?) || !valid_reference(value) do
    Err("invalid_attachment_reference")
  else
    Ok(value)
  end
end

pub fn decode_reference(input :: Bytes) -> MobileAttachmentReference!String do
  case read_reference(input) do
    Err(_) -> Err("invalid_attachment_reference")
    Ok(value)
  end
end

## Empty input means "no attachment"; anything else must be a well-formed reference.

pub fn validate_attachment(input :: Bytes) -> Result<(), String> do
  let parts = attachment_parts(input, 1024)?
  for part in parts do
    decode_reference(part)?
  end
  Ok(nil)
end

fn wrap_key(secret :: borrow SecretBytes, object_id :: Bytes, recipient :: Bytes) -> Bytes!String do
  if Bytes.length(recipient) != 32 do
    Err("invalid_attachment_recipient")
  else
    case Crypto.hpke_seal_secret(X25519PublicKey { bytes: recipient },
      wrap_info(),
      wrap_aad(object_id)?,
      secret) do
      Err(_) -> Err("attachment_key_wrap_failed")
      Ok(sealed)
    end
  end
end

fn unwrap_key(device :: borrow DeviceKeys,
  value :: MobileAttachmentReference) -> SecretBytes!String do
  case Crypto.hpke_open_secret(device.identity_private_key,
    wrap_info(),
    wrap_aad(value.object_id)?,
    value.wrapped_key) do
    Err(_) -> Err("attachment_key_unwrap_failed")
    Ok(secret)
  end
end

fn opened_manifest(secret :: borrow SecretBytes,
  encrypted_manifest :: Bytes) -> AttachmentManifest!String do
  case open_manifest(secret, encrypted_manifest) do
    Err(error) -> Err(describe_attachment_error(error))
    Ok(value)
  end
end

# Authenticated metadata for transport planning. An outer ATR object substitution
# must not redirect a valid manifest to a different download location.
pub fn attachment_manifest(device :: borrow DeviceKeys,
  reference :: Bytes) -> AttachmentManifest!String do
  let value = decode_reference(reference)?
  let secret = unwrap_key(device, value)?
  let manifest = opened_manifest(secret, value.encrypted_manifest)?
  if (manifest.version == 2 || manifest.version == 4)
    && !Bytes.secure_equals(value.object_id, manifest.attachment_id) do
    return Err("invalid_attachment_reference")
  end
  Ok(manifest)
end

## Re-address a locally held reference to another device identity key.

fn rewrap_parts(device :: borrow DeviceKeys,
  parts :: List<Bytes>,
  recipient :: Bytes,
  index :: Int,
  output :: List<Bytes>) -> Bytes!String do
  if index >= List.length(parts) do
    encode_batch(output)
  else
    let value = decode_reference(List.get(parts, index))?
    let secret = unwrap_key(device, value)?
    let wrapped = encode_reference(%{value |
      wrapped_key: wrap_key(secret, value.object_id, recipient)?
    })?
    rewrap_parts(device, parts, recipient, index + 1, List.append(output, wrapped))
  end
end

pub fn rewrap_reference(device :: borrow DeviceKeys,
  encoded :: Bytes,
  recipient :: Bytes) -> Bytes!String do
  rewrap_parts(device, attachment_parts(encoded, 1024)?, recipient, 0, [])
end

fn encode_group_entries(object_id :: Bytes,
  secret :: borrow SecretBytes,
  recipients :: List<MobileAttachmentRecipient>,
  index :: Int,
  output :: Bytes) -> Bytes!String do
  if index >= List.length(recipients) do
    Ok(output)
  else
    let recipient = List.get(recipients, index)
    if Bytes.length(recipient.account_id) != 32 || Bytes.length(recipient.device_id) != 16 do
      Err("invalid_attachment_recipient")
    else
      let wrapped = wrap_key(secret, object_id, recipient.public_key)?
      let entry = mobile_join([recipient.account_id, recipient.device_id, mobile_vector(wrapped)?],
        0,
        Bytes.empty())?
      encode_group_entries(object_id,
        secret,
        recipients,
        index + 1,
        mobile_join([output, entry], 0, Bytes.empty())?)
    end
  end
end

## Build the group envelope (ATG) from a locally held reference for every listed device.

fn encode_single_group_attachment(device :: borrow DeviceKeys,
  encoded :: Bytes,
  recipients :: List<MobileAttachmentRecipient>) -> Bytes!String do
  if Bytes.length(encoded) == 0 do
    Ok(Bytes.empty())
  else if List.length(recipients) == 0 || List.length(recipients) > 256 do
    Err("invalid_attachment_recipient")
  else
    let value = decode_reference(encoded)?
    let secret = unwrap_key(device, value)?
    let entries = encode_group_entries(value.object_id, secret, recipients, 0, Bytes.empty())?
    mobile_join([
        group_header()?,
        value.object_id,
        value.download_capability,
        mobile_vector(value.encrypted_manifest)?,
        mobile_write_u32(List.length(recipients))?,
        entries
      ],
      0,
      Bytes.empty())
  end
end

fn encode_group_parts(device :: borrow DeviceKeys,
  parts :: List<Bytes>,
  recipients :: List<MobileAttachmentRecipient>,
  index :: Int,
  output :: List<Bytes>) -> Bytes!String do
  if index >= List.length(parts) do
    encode_batch(output)
  else
    let envelope = encode_single_group_attachment(device, List.get(parts, index), recipients)?
    encode_group_parts(device, parts, recipients, index + 1, List.append(output, envelope))
  end
end

pub fn encode_group_attachment(device :: borrow DeviceKeys,
  encoded :: Bytes,
  recipients :: List<MobileAttachmentRecipient>) -> Bytes!String do
  encode_group_parts(device, attachment_parts(encoded, 1024)?, recipients, 0, [])
end

fn find_group_entry(state :: BinaryReader,
  remaining :: Int,
  account_id :: Bytes,
  device_id :: Bytes,
  found :: Bytes) -> MobileReadBytes!String do
  if remaining <= 0 do
    mobile_finish(state, "invalid_group_attachment")?
    Ok(MobileReadBytes { state: state, value: found })
  else
    let entry_account = take_fixed(state, 32)?
    let entry_device = take_fixed(entry_account.state, 16)?
    let wrapped = take_vector_error(entry_device.state, 160, "invalid_group_attachment")?
    let matches = Bytes.secure_equals(entry_account.value, account_id)
      && Bytes.secure_equals(entry_device.value, device_id)
    find_group_entry(wrapped.state,
      remaining - 1,
      account_id,
      device_id,
      if matches && Bytes.length(found) == 0 do
        wrapped.value
      else
        found
      end)
  end
end

## Extract this device's reference from a group envelope. Empty input or a missing
## entry yields an empty reference so the text body still lands in history.

pub fn group_attachment_reference(input :: Bytes,
  account_id :: Bytes,
  device_id :: Bytes) -> Bytes!String do
  let parts = attachment_parts(input, 65536)?
  let references = for part in parts do
    read_group_attachment(part, account_id, device_id)?
  end
  encode_batch(List.filter(references, fn(value) do Bytes.length(value) > 0 end))
end

fn read_group_attachment(input :: Bytes, account_id :: Bytes, device_id :: Bytes) -> Bytes!String do
  if Bytes.length(input) == 0 do
    Ok(Bytes.empty())
  else
    let state = mobile_reader(input, 65536, "invalid_group_attachment")?
    let header = take_fixed(state, 4)?
    let object_id = take_fixed(header.state, 32)?
    let download_capability = take_fixed(object_id.state, 32)?
    let encrypted_manifest = take_vector_error(download_capability.state,
      640,
      "invalid_group_attachment")?
    let count = take_fixed(encrypted_manifest.state, 4)?
    let count_value = mobile_read_u32(count.value)?
    if !Bytes.secure_equals(header.value, group_header()?)
      || count_value == 0
      || count_value > 256 do
      Err("invalid_group_attachment")
    else
      let wrapped = find_group_entry(count.state,
        count_value,
        account_id,
        device_id,
        Bytes.empty())?
      if Bytes.length(wrapped.value) == 0 do
        Ok(Bytes.empty())
      else
        encode_reference(MobileAttachmentReference {
          object_id: object_id.value,
          download_capability: download_capability.value,
          encrypted_manifest: encrypted_manifest.value,
          wrapped_key: wrapped.value
        })
      end
    end
  end
end

fn summarize_parts(device :: borrow DeviceKeys,
  parts :: List<Bytes>,
  index :: Int,
  output :: List<Bytes>) -> Bytes!String do
  if index >= List.length(parts) do
    encode_batch(output)
  else
    let part = List.get(parts, index)
    let value = decode_reference(part)?
    let secret = unwrap_key(device, value)?
    let manifest = opened_manifest(secret, value.encrypted_manifest)?
    let summary = encode_output_list([
      part,
      value.object_id,
      value.download_capability,
      manifest.filename,
      manifest.mime_type,
      mobile_write_u32(manifest.plaintext_size)?,
      mobile_write_u32(manifest.chunk_count)?,
      mobile_write_u32(manifest.chunk_size)?,
      mobile_write_u64(manifest.expires_at)?
    ])?
    summarize_parts(device, parts, index + 1, List.append(output, summary))
  end
end

fn summarize_reference(device :: borrow DeviceKeys, encoded :: Bytes) -> Bytes!String do
  summarize_parts(device, attachment_parts(encoded, 1024)?, 0, [])
end

## History export: the opened manifest metadata next to the opaque local reference.
## Unreadable references summarize as empty rather than hiding the whole conversation.

pub fn attachment_summary(device :: borrow DeviceKeys, encoded :: Bytes) -> Plaintext<Bytes> do
  if Bytes.length(encoded) == 0 do
    Bytes.empty()
  else
    case summarize_reference(device, encoded) do
      Err(_) -> Bytes.empty()
      Ok(value) -> value
    end
  end
end

fn chunk_count_for(plaintext_size :: Int) -> Int do
  (plaintext_size + attachment_chunk_size() - 1) / attachment_chunk_size()
end

## Mint everything the host needs to upload one attachment: the local reference, the
## object grant (with proof of work), completion and deletion controls, and part 0.

pub fn prepare_attachment(request :: MobileAttachmentPrepareRequest) -> Bytes!String do
  if request.plaintext_size <= 0 || request.plaintext_size > maximum_attachment_size() do
    Err("attachment_too_large")
  else if !attachment_input_admitted(request.filename, request.mime_type, false) do
    Err("invalid_attachment_metadata")
  else
    ensure_schema(request.database_path)?
    let local = decode_client_profile(load_profile(request.database_path)?)?
    let wrapping_key = platform_key()?
    let device = open_device(local, wrapping_key, request.database_path)?
    let now = current_time()?
    let expires_at = case U64.add(now, mobile_wide("518400000")?) do
      Err(_) -> Err("invalid_attachment_expiry")
      Ok(value)
    end?
    let work_expires_at = case U64.add(now, mobile_wide("150000")?) do
      Err(_) -> Err("invalid_attachment_expiry")
      Ok(value)
    end?
    let attachment_id = case generate_attachment_id() do
      Err(error) -> Err(describe_attachment_error(error))
      Ok(value)
    end?
    let secret = case generate_attachment_key() do
      Err(error) -> Err(describe_attachment_error(error))
      Ok(value)
    end?
    let chunk_count = chunk_count_for(request.plaintext_size)
    let manifest = AttachmentManifest {
      version: 4,
      attachment_id: attachment_id,
      chunk_size: attachment_chunk_size(),
      chunk_count: chunk_count,
      plaintext_size: request.plaintext_size,
      filename: request.filename,
      mime_type: request.mime_type,
      expires_at: expires_at
    }
    let encrypted_manifest = case seal_manifest(secret, manifest) do
      Err(error) -> Err(describe_attachment_error(error))
      Ok(value)
    end?
    let object_id = attachment_id
    let upload_capability = random_bytes(32)?
    let download_capability = random_bytes(32)?
    let grant = encode_grant(mint_grant(object_id,
      chunk_count + 1,
      expires_at,
      work_expires_at,
      upload_capability,
      download_capability,
      request.difficulty)?)?
    let control = ObjectControl { object_id: object_id, capability: upload_capability }
    let reference = encode_reference(MobileAttachmentReference {
      object_id: object_id,
      download_capability: download_capability,
      encrypted_manifest: encrypted_manifest,
      wrapped_key: wrap_key(secret, object_id, device.identity_public_key.bytes)?
    })?
    encode_output_list([
      reference,
      object_id,
      upload_capability,
      grant,
      encode_complete(control)?,
      encode_delete(control)?,
      encrypted_manifest
    ])
  end
end

# Large uploads use the same device-wrapped reference and bounded chunk path.
# The caller must persist this material before constructing a credit request.
pub struct LargeAttachmentMaterial do
  reference :: Bytes
  object_id :: Bytes
  upload_capability :: Bytes
  download_capability :: Bytes
  encrypted_manifest :: Bytes
end

pub fn prepare_large_attachment_material(device :: borrow DeviceKeys,
  filename :: Plaintext<Bytes>,
  mime_type :: Plaintext<Bytes>,
  plaintext_size :: Int,
  expires_at_ms :: U64) -> LargeAttachmentMaterial!String do
  if plaintext_size <= 16777216 || plaintext_size > 536870912 do
    return Err("attachment_too_large")
  end
  let object_id = random_bytes(32)?
  let secret = case generate_attachment_key() do
    Err(error) -> return Err(describe_attachment_error(error))
    Ok(value) -> value
  end
  let encrypted_manifest = case seal_manifest(secret,
    AttachmentManifest {
      version: 4,
      attachment_id: object_id,
      chunk_size: attachment_chunk_size(),
      chunk_count: chunk_count_for(plaintext_size),
      plaintext_size: plaintext_size,
      filename: filename,
      mime_type: mime_type,
      expires_at: expires_at_ms
    }) do
    Err(error) -> return Err(describe_attachment_error(error))
    Ok(value) -> value
  end
  let upload = random_bytes(32)?
  let download = random_bytes(32)?
  let reference = encode_reference(MobileAttachmentReference {
    object_id: object_id,
    download_capability: download,
    encrypted_manifest: encrypted_manifest,
    wrapped_key: wrap_key(secret, object_id, device.identity_public_key.bytes)?
  })?
  Ok(LargeAttachmentMaterial {
    reference: reference,
    object_id: object_id,
    upload_capability: upload,
    download_capability: download,
    encrypted_manifest: encrypted_manifest
  })
end

pub fn seal_large_attachment_chunk(device :: borrow DeviceKeys,
  reference :: Bytes,
  index :: Int,
  plaintext :: Bytes) -> Bytes!String do
  let value = decode_reference(reference)?
  let secret = unwrap_key(device, value)?
  # Prepare the public EAM-bound operation before observing private metadata
  # admission. Its failure still wins, and no speculative wire is returned.
  let manifest_result = opened_manifest(secret, value.encrypted_manifest)
  let wire = seal_bound_chunk(secret, value.encrypted_manifest, index, plaintext)
  let manifest = manifest_result?
  if manifest.version != 2 && (manifest.version != 4 || manifest.plaintext_size <= 16777216) do
    return Err("invalid_large_attachment_manifest")
  end
  chunk_result(wire)
end

fn chunk_result(value :: Result<Bytes, AttachmentError>) -> Bytes!String do
  case value do
    Err(error) -> Err(describe_attachment_error(error))
    Ok(output)
  end
end

fn attachment_key_material(database_path :: String,
  reference :: Bytes) -> Result<(SecretBytes, Bytes), String> do
  ensure_schema(database_path)?
  let local = decode_client_profile(load_profile(database_path)?)?
  let wrapping_key = platform_key()?
  let device = open_device(local, wrapping_key, database_path)?
  let value = decode_reference(reference)?
  let secret = unwrap_key(device, value)?
  Ok((secret, value.encrypted_manifest))
end

pub fn seal_attachment_chunk(request :: MobileAttachmentChunkRequest) -> Bytes!String do
  let (secret, encrypted_manifest) = attachment_key_material(request.database_path,
    request.reference)?
  let manifest_result = opened_manifest(secret, encrypted_manifest)
  let wire = seal_bound_chunk(secret, encrypted_manifest, request.index, request.payload)
  let manifest = manifest_result?
  if request.index < 0 || request.index >= manifest.chunk_count do
    Err("invalid_attachment_chunk_index")
  else
    chunk_result(wire)
  end
end

# Use the same held device for reference authentication and payload opening.
# Modern manifests bind the outer route ID; v1 retains its legacy routing contract.
pub fn open_attachment_chunk_with_device(device :: borrow DeviceKeys,
  reference :: Bytes,
  index :: Int,
  ciphertext :: Bytes) -> Result<Plaintext<Bytes>, String> do
  let value = decode_reference(reference)?
  let secret = unwrap_key(device, value)?
  let manifest = opened_manifest(secret, value.encrypted_manifest)?
  if (manifest.version == 2 || manifest.version == 4)
    && !Bytes.secure_equals(value.object_id, manifest.attachment_id) do
    return Err("invalid_attachment_reference")
  end
  if index < 0 || index >= manifest.chunk_count do
    Err("invalid_attachment_chunk_index")
  else
    chunk_result(open_bound_chunk(secret, value.encrypted_manifest, index, ciphertext))
  end
end

pub fn open_attachment_chunk(request :: MobileAttachmentChunkRequest) -> Result<Plaintext<Bytes>, String> do
  ensure_schema(request.database_path)?
  let local = decode_client_profile(load_profile(request.database_path)?)?
  let wrapping_key = platform_key()?
  let device = open_device(local, wrapping_key, request.database_path)?
  open_attachment_chunk_with_device(device, request.reference, request.index, request.payload)
end

# The required reader capability is chosen from the actual opaque reference,
# never a host/UI flag. Public framing is conservative; key unwrap/manifest
# authentication still happens before encrypted message admission or download.
pub fn attachment_requires_buckets(input :: Bytes) -> Bool!String do
  let parts = attachment_parts(input, 1024)?
  let versions = for part in parts do
    let reference = decode_reference(part)?
    let version = Bytes.get(reference.encrypted_manifest, 0)?
    if version != 1 && version != 2 && version != 4 do
      return Err("invalid_attachment_reference")
    end
    version
  end
  Ok(List.contains(versions, 4))
end
