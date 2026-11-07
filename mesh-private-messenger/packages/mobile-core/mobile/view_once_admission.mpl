##! Authenticated reference admission; this module performs no object requests.
from Identity.Device import DeviceKeys
from Attachments.ViewOnce import ViewOnceBinding, decode_view_once_reference, open_view_once_key
from Attachments.Protocol import open_manifest
from Storage.ViewOnce import (
  ViewOncePending,
  ViewOnceRecord,
  decode_view_once_record,
  encode_view_once_record
)
from Storage.AccountGuard import AccountBasis
from Storage.Keys import open_local, seal_local, local_context
from Mobile.Types import MobileHistoryMatch

pub type ViewOnceAdmissionAction do
  AdmitNew
  AdmitDuplicate
  RefuseAdmission
  AdmissionStorageUnavailable
end

pub struct ViewOnceAdmissionWrite do
  label :: String
  blob :: Bytes
  identity_label :: String
  identity_blob :: Bytes
  logical_label :: String
  logical_blob :: Bytes
  duplicate :: Bool
end

## Preparation carries a private decision; callers have no authority to expose it.
pub struct ViewOncePreparedWrite do
  decision :: Plaintext<ViewOnceAdmissionAction>
  label :: String
  sealed :: Result<Bytes, String>
  identity_label :: String
  identity_blob :: Result<Bytes, String>
  logical_label :: String
  logical_blob :: Result<Bytes, String>
end

pub fn view_once_epoch_label() -> String do
  "view-once/admission-epoch/v1"
end

pub fn seal_view_once_epoch(key :: borrow StorageKey,
  account :: Bytes,
  device :: Bytes) -> Bytes!String do
  if Bytes.length(account) != 32 || Bytes.length(device) != 16 do
    return Err("invalid_receive_basis")
  end
  let raw = case Bytes.concat_many([Bytes.from_hex("01564f45")?, account, device], 52) do
    Err(_) -> return Err("view_once_storage_refused")
    Ok(value) -> value
  end
  seal_local(raw, key, local_context(view_once_epoch_label())?)
end

## Direct conversations are named by their account pair; session, device and
## wire aliases do not define a new logical message for that peer.
pub fn view_once_logical_label(account :: Bytes,
  peer :: Bytes,
  message :: Bytes) -> String!String do
  if Bytes.length(account) != 32 || Bytes.length(peer) != 32 || Bytes.length(message) != 16 do
    return Err("invalid_receive_basis")
  end
  let tuple = case Bytes.concat_many([
      Bytes.from_utf8("morse/view-once/message/v2\n"),
      account,
      peer,
      message
    ],
    128) do
    Err(_) -> return Err("invalid_receive_basis")
    Ok(value) -> value
  end
  Ok("view-once/message/v2/#{Bytes.to_hex(Crypto.sha256(tuple))}")
end

pub fn view_once_row_label(version :: Int, conversation :: Bytes, message :: Bytes) -> String do
  "view-once/v#{version}/#{Bytes.to_hex(conversation)}/#{Bytes.to_hex(message)}"
end

pub fn view_once_identity_label(binding :: ViewOnceBinding) -> String!String do
  if Bytes.length(binding.sender_account_id) != 32
    || Bytes.length(binding.sender_device_id) != 16
    || Bytes.length(binding.receiver_account_id) != 32
    || Bytes.length(binding.receiver_device_id) != 16
    || Bytes.length(binding.conversation_id) != 16
    || Bytes.length(binding.message_id) != 16 do
    return Err("invalid_receive_basis")
  end
  let tuple = case Bytes.concat_many([
      Bytes.from_utf8("morse/view-once/key/v2\n"),
      binding.sender_account_id,
      binding.sender_device_id,
      binding.receiver_account_id,
      binding.receiver_device_id,
      binding.conversation_id,
      binding.message_id
    ],
    160) do
    Err(_) -> return Err("invalid_receive_basis")
    Ok(value) -> value
  end
  Ok("view-once/id/v2/#{Bytes.to_hex(Crypto.sha256(tuple))}")
end

## Fixed-width fields make this independent of the local history alias.
pub fn view_once_identity_digest(account :: Bytes,
  peer :: Bytes,
  wire_conversation :: Bytes,
  message :: Bytes,
  reference :: Bytes) -> Bytes!String do
  if Bytes.length(account) != 32
    || Bytes.length(peer) != 32
    || Bytes.length(wire_conversation) != 16
    || Bytes.length(message) != 16 do
    return Err("invalid_receive_basis")
  end
  case Bytes.concat_many([
      Bytes.from_utf8("morse/view-once/identity/v2\n"),
      account,
      peer,
      wire_conversation,
      message,
      Crypto.sha256(reference)
    ],
    160) do
    Err(_) -> Err("view_once_storage_refused")
    Ok(value) -> Ok(Crypto.sha256(value))
  end
end

fn captured_row(basis :: AccountBasis, label :: String) -> Bytes!String do
  if List.length(basis.labels) != List.length(basis.records) do
    return Err("invalid_receive_basis")
  end
  for index in 0..List.length(basis.labels) do
    if List.get(basis.labels, index) == label do
      return Ok(List.get(basis.records, index))
    end
  end
  Err("invalid_receive_basis")
end

pub fn require_view_once_epoch(key :: borrow StorageKey,
  basis :: AccountBasis,
  account :: Bytes,
  device :: Bytes) -> Unit!String do
  let label = view_once_epoch_label()
  let blob = captured_row(basis, label)?
  let expected = case Bytes.concat_many([Bytes.from_hex("01564f45")?, account, device], 52) do
    Err(_) -> return Err("invalid_receive_basis")
    Ok(value) -> value
  end
  let valid :: Plaintext<Bool> = if Bytes.length(account) != 32
    || Bytes.length(device) != 16
    || Bytes.length(blob) == 0 do
    false
  else
    case open_local(blob, key, local_context(label)?) do
      Err(_) -> false
      Ok(raw) -> Bytes.secure_equals(raw, expected)
    end
  end
  if valid do
    Ok(nil)
  else
    Err("view_once_reference_refused")
  end
end

pub fn captured_view_once_exists(basis :: AccountBasis,
  legacy_label :: String,
  label :: String,
  identity_label :: String,
  logical_label :: String) -> Bool!String do
  let legacy = captured_row(basis, legacy_label)?
  let current = captured_row(basis, label)?
  let identity = captured_row(basis, identity_label)?
  let logical = captured_row(basis, logical_label)?
  Ok(Bytes.length(legacy) > 0
    || Bytes.length(current) > 0
    || Bytes.length(identity) > 0
    || Bytes.length(logical) > 0)
end

fn identity_matches(key :: borrow StorageKey,
  label :: String,
  blob :: Bytes,
  digest :: Bytes,
  reference_digest :: Bytes,
  content_digest :: Bytes,
  conversation :: Bytes,
  peer :: Bytes,
  require_selector :: Bool) -> Plaintext<Bool> do
  case local_context(label) do
    Err(_) -> false
    Ok(context) -> case open_local(blob, key, context) do
      Err(_) -> false
      Ok(raw) -> Bytes.length(raw) == 148
        && Bytes.secure_equals(Result.unwrap_or(Bytes.slice(raw, 0, 4), Bytes.empty()),
          Result.unwrap_or(Bytes.from_hex("02564f49"), Bytes.empty()))
        && Bytes.secure_equals(Result.unwrap_or(Bytes.slice(raw, 4, 32), Bytes.empty()), digest)
        && Bytes.secure_equals(Result.unwrap_or(Bytes.slice(raw, 36, 32), Bytes.empty()),
          reference_digest)
        && Bytes.secure_equals(Result.unwrap_or(Bytes.slice(raw, 68, 32), Bytes.empty()),
          content_digest)
        && (!require_selector
          || Bytes.secure_equals(Result.unwrap_or(Bytes.slice(raw, 100, 16), Bytes.empty()),
            conversation))
        && Bytes.secure_equals(Result.unwrap_or(Bytes.slice(raw, 116, 32), Bytes.empty()), peer)
    end
  end
end

fn same_message_expiry(a :: Option<U64>, b :: Option<U64>) -> Bool do
  case (a, b) do
    (None, None) -> true
    (Some(left), Some(right)) -> U64.compare(left, right) == 0
    _ -> false
  end
end

fn same_pending(a :: ViewOncePending, b :: ViewOncePending) -> Bool do
  Bytes.secure_equals(a.reference, b.reference)
    && U64.compare(a.expires_at, b.expires_at) == 0
    && same_message_expiry(a.message_expiry, b.message_expiry)
end

fn existing_action(raw :: Bytes, pending :: ViewOncePending) -> ViewOnceAdmissionAction do
  case decode_view_once_record(raw) do
    Err(_) -> RefuseAdmission
    Ok(record) -> case record do
      Available(value) -> if Bytes.secure_equals(value.reference, pending.reference)
        && same_message_expiry(value.message_expiry, pending.message_expiry) do
        AdmitDuplicate
      else
        RefuseAdmission
      end
      Consumed(_) -> RefuseAdmission
      PendingFetch(value) -> if same_pending(value, pending) do
        AdmitDuplicate
      else
        RefuseAdmission
      end
      Ready(value) -> if same_pending(ViewOncePending {
          reference: value.available.reference,
          expires_at: value.expires_at,
          message_expiry: value.available.message_expiry
        },
        pending) do
        AdmitDuplicate
      else
        RefuseAdmission
      end
      ConsumedV2(digest) -> if Bytes.secure_equals(digest, Crypto.sha256(pending.reference)) do
        AdmitDuplicate
      else
        RefuseAdmission
      end
      Expired(digest) -> if Bytes.secure_equals(digest, Crypto.sha256(pending.reference)) do
        AdmitDuplicate
      else
        RefuseAdmission
      end
    end
  end
end

fn prior_action(key :: borrow StorageKey,
  legacy_label :: String,
  legacy :: Bytes,
  label :: String,
  current :: Bytes,
  pending :: ViewOncePending) -> ViewOnceAdmissionAction do
  if Bytes.length(legacy) > 0 && Bytes.length(current) > 0 do
    return RefuseAdmission
  end
  if Bytes.length(legacy) > 0 do
    let context = case local_context(legacy_label) do
      Err(_) -> return RefuseAdmission
      Ok(value) -> value
    end
    return case open_local(legacy, key, context) do
      Err(_) -> RefuseAdmission
      Ok(raw) -> existing_action(raw, pending)
    end
  end
  if Bytes.length(current) > 0 do
    let context = case local_context(label) do
      Err(_) -> return RefuseAdmission
      Ok(value) -> value
    end
    return case open_local(current, key, context) do
      Err(_) -> RefuseAdmission
      Ok(raw) -> existing_action(raw, pending)
    end
  end
  AdmitNew
end

## Both versions are captured before this decision. A terminal legacy row
## cannot prove the full reference identity, so it always refuses re-admission.
pub fn prepare_view_once_write_parts(key :: borrow StorageKey,
  basis :: AccountBasis,
  conversation :: Bytes,
  wire_conversation :: Bytes,
  message :: Bytes,
  account :: Bytes,
  peer :: Bytes,
  identity_label :: String,
  logical_label :: String,
  pending :: Plaintext<ViewOncePending>,
  history_match :: Result<Plaintext<MobileHistoryMatch>, String>,
  content_digest :: Result<Plaintext<Bytes>, String>,
  now :: U64) -> ViewOncePreparedWrite!String do
  if Bytes.length(conversation) != 16
    || Bytes.length(wire_conversation) != 16
    || Bytes.length(message) != 16
    || Bytes.length(account) != 32
    || Bytes.length(peer) != 32 do
    return Err("invalid_receive_basis")
  end
  let legacy_label = view_once_row_label(1, conversation, message)
  let label = view_once_row_label(2, conversation, message)
  let legacy = captured_row(basis, legacy_label)?
  let current = captured_row(basis, label)?
  let identity = captured_row(basis, identity_label)?
  let logical = captured_row(basis, logical_label)?
  let action = prior_action(key, legacy_label, legacy, label, current, pending)
  let encoded = encode_view_once_record(PendingFetch(pending))
  let sealed = seal_local(Result.unwrap_or(encoded, Bytes.empty()), key, local_context(label)?)
  let digest = view_once_identity_digest(account,
    peer,
    wire_conversation,
    message,
    pending.reference)
  let expected_digest = Result.unwrap_or(digest, Bytes.empty())
  let reference_digest = Crypto.sha256(pending.reference)
  let message_digest = Result.unwrap_or(content_digest, Bytes.empty())
  let identity_encoded = Bytes.concat_many([
      Bytes.from_hex("02564f49")?,
      expected_digest,
      reference_digest,
      message_digest,
      conversation,
      peer
    ],
    148)
  let identity_blob = seal_local(Result.unwrap_or(identity_encoded, Bytes.empty()),
    key,
    local_context(identity_label)?)
  let logical_blob = seal_local(Result.unwrap_or(identity_encoded, Bytes.empty()),
    key,
    local_context(logical_label)?)
  let identity_present = Bytes.length(identity) > 0
  let logical_present = Bytes.length(logical) > 0
  let identity_ok = if identity_present do
    identity_matches(key,
      identity_label,
      identity,
      expected_digest,
      reference_digest,
      message_digest,
      conversation,
      peer,
      Bytes.length(legacy) > 0 || Bytes.length(current) > 0)
  else
    false
  end
  let logical_ok = if logical_present do
    identity_matches(key,
      logical_label,
      logical,
      expected_digest,
      reference_digest,
      message_digest,
      conversation,
      peer,
      Bytes.length(legacy) > 0 || Bytes.length(current) > 0)
  else
    false
  end
  let live = U64.compare(now, pending.expires_at) < 0
    && case pending.message_expiry do
      None -> true
      Some(expiry) -> U64.compare(now, expiry) < 0
    end
  let match_value = Result.unwrap_or(history_match, HistoryConflict)
  let decision = if Result.is_err(history_match)
    || Result.is_err(digest)
    || Result.is_err(content_digest)
    || Bytes.length(message_digest) != 32
    || Result.is_err(identity_encoded) do
    AdmissionStorageUnavailable
  else if identity_present != logical_present
    || (identity_present && (!identity_ok || !logical_ok)) do
    RefuseAdmission
  else if !identity_present && action != AdmitNew do
    RefuseAdmission
  else
    case action do
      AdmitNew -> if identity_present && match_value != HistoryConflict do
        AdmitDuplicate
      else if identity_present || match_value != HistoryAbsent || !live do
        RefuseAdmission
      else if Result.is_ok(encoded) do
        AdmitNew
      else
        AdmissionStorageUnavailable
      end
      AdmitDuplicate -> if match_value == HistoryConflict do
        RefuseAdmission
      else
        AdmitDuplicate
      end
      RefuseAdmission
      AdmissionStorageUnavailable
    end
  end
  Ok(ViewOncePreparedWrite {
    decision: decision,
    label: label,
    sealed: sealed,
    identity_label: identity_label,
    identity_blob: identity_blob,
    logical_label: logical_label,
    logical_blob: logical_blob
  })
end

## This public helper preserves its private result status for arbitrary callers.
pub fn prepare_view_once_write(key :: borrow StorageKey,
  basis :: AccountBasis,
  conversation :: Bytes,
  wire_conversation :: Bytes,
  message :: Bytes,
  account :: Bytes,
  peer :: Bytes,
  identity_label :: String,
  logical_label :: String,
  pending :: Plaintext<ViewOncePending>,
  history_match :: Result<Plaintext<MobileHistoryMatch>, String>,
  content_digest :: Result<Plaintext<Bytes>, String>,
  now :: U64) -> ViewOnceAdmissionWrite!String do
  let prepared = prepare_view_once_write_parts(key,
    basis,
    conversation,
    wire_conversation,
    message,
    account,
    peer,
    identity_label,
    logical_label,
    pending,
    history_match,
    content_digest,
    now)?
  case prepared.decision do
    RefuseAdmission -> Err("view_once_reference_refused")
    AdmissionStorageUnavailable -> Err("view_once_storage_refused")
    AdmitDuplicate -> Ok(ViewOnceAdmissionWrite {
      label: prepared.label,
      blob: Bytes.empty(),
      identity_label: prepared.identity_label,
      identity_blob: Bytes.empty(),
      logical_label: prepared.logical_label,
      logical_blob: Bytes.empty(),
      duplicate: true
    })
    AdmitNew -> Ok(ViewOnceAdmissionWrite {
      label: prepared.label,
      blob: prepared.sealed?,
      identity_label: prepared.identity_label,
      identity_blob: prepared.identity_blob?,
      logical_label: prepared.logical_label,
      logical_blob: prepared.logical_blob?,
      duplicate: false
    })
  end
end

fn validated_pending(device :: borrow DeviceKeys,
  expected :: ViewOnceBinding,
  wire :: Bytes,
  message_expiry :: Option<U64>) -> ViewOncePending!String do
  let reference = decode_view_once_reference(wire)?
  let secret = open_view_once_key(device, expected, wire)?
  let opened = open_manifest(secret, reference.encrypted_manifest)
  Secret.destroy(secret)
  let manifest = case opened do
    Err(_) -> return Err("view_once_reference_refused")
    Ok(value) -> value
  end
  let png = Bytes.secure_equals(manifest.mime_type, Bytes.from_utf8("image/png"))
  let jpeg = Bytes.secure_equals(manifest.mime_type, Bytes.from_utf8("image/jpeg"))
  if manifest.version != 4
    || manifest.plaintext_size < 1
    || manifest.plaintext_size > 16777216
    || manifest.chunk_size != 65536
    || manifest.chunk_count < 1
    || manifest.chunk_count > 256
    || manifest.chunk_count != (manifest.plaintext_size + 65535) / 65536
    || !Bytes.secure_equals(manifest.attachment_id, reference.object_id)
    || (!png && !jpeg) do
    return Err("view_once_reference_refused")
  end
  Ok(ViewOncePending {
    reference: wire,
    expires_at: manifest.expires_at,
    message_expiry: message_expiry
  })
end

## Keep the result status private until an authenticated receive reviews it.
pub fn prepare_view_once_pending(device :: borrow DeviceKeys,
  expected :: ViewOnceBinding,
  wire :: Bytes,
  message_expiry :: Option<U64>,
  now :: U64) -> Result<Plaintext<ViewOncePending>, String> do
  let prepared :: Plaintext<Result<ViewOncePending, String>> = validated_pending(device,
    expected,
    wire,
    message_expiry)
  prepared
end
