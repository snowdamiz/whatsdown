from Attachments.Layout import attachment_bucket_capacity
from Mobile.CreditAttachmentJournal import (
  attachment_binding,
  seal_attachment_binding,
  open_attachment_binding,
  attachment_intent_matches,
  attachment_journal_payload,
  attachment_journal_parts
)
from Credits.Action import encode_credit_action, credit_action_id
from Credits.ActionWire import CreditActionSubmission, encode_credit_action_submission
from Credits.Attachment import (
  decode_credit_attachment_grant,
  encode_credit_attachment_grant,
  CreditAttachmentGrant,
  credit_attachment_action
)
from Credits.Wire import decode_credit_frame
from Identity.Device import DeviceKeys
from Mobile.Attachments import prepare_large_attachment_material, decode_reference
from Mobile.Codec import mobile_write_u32
from Mobile.CreditState import (
  CreditRecord,
  credit_record_id,
  valid_credit_attachment_metadata,
  find_credit_record,
  put_credit_record,
  pack_credit_parts,
  unpack_credit_parts
)
from Mobile.CreditWallet import (
  CreditSpendPlan,
  reserve_credit_spend,
  credit_reservation_status,
  credit_operation_nonce_seen
)
from Objects.Grant import ObjectControl, encode_complete, encode_delete
from Storage.Credits import (
  CreditWalletIdentity,
  credit_attachment_intent_context,
  load_credit_wallet,
  commit_credit_wallet,
  seal_credit_payload,
  open_credit_payload
)

# This contains bounded metadata only. A host streams each file range separately
# through the existing seal_attachment_chunk API; no whole-file Bytes value.
pub struct CreditAttachmentPlan do
  nonce :: Bytes
  reference :: Bytes
  encrypted_manifest :: Bytes
  grant :: Bytes
  submission :: Bytes
  complete :: Bytes
  delete :: Bytes
  spend :: CreditSpendPlan
end

fn label(nonce :: Bytes) -> String do
  "attachment/#{Bytes.to_hex(nonce)}"
end

fn read_material(record :: CreditRecord,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> List<Bytes>!String do
  let parts = unpack_credit_parts(open_credit_payload(List.get(attachment_journal_parts(record.payload)?,
        1),
      wrapping,
      who,
      label(record.id))?,
    2,
    1024)?
  if record.kind != 6
    || !valid_credit_attachment_metadata(record.metadata)
    || List.length(parts) != 2 do
    return Err("invalid_credit_attachment_material")
  end
  let grant = decode_credit_attachment_grant(List.get(parts, 0))?
  let reference = decode_reference(List.get(parts, 1))?
  if !Bytes.secure_equals(grant.operation_nonce, record.id)
    || (grant.layout_version == 1 && Bytes.get(reference.encrypted_manifest, 0) != Ok(2))
    || (grant.layout_version == 2 && Bytes.get(reference.encrypted_manifest, 0) != Ok(4))
    || !Bytes.secure_equals(grant.object_id, reference.object_id)
    || !Bytes.secure_equals(grant.download_capability, reference.download_capability)
    || grant.manifest_size != Bytes.length(reference.encrypted_manifest)
    || !Bytes.secure_equals(grant.manifest_sha256, Crypto.sha256(reference.encrypted_manifest)) do
    return Err("invalid_credit_attachment_material")
  end
  if Bytes.length(record.metadata) == 40
    && !Bytes.secure_equals(Bytes.slice(record.metadata, 8, 32)?,
      credit_action_id(credit_attachment_action(grant)?)?) do
    return Err("invalid_credit_attachment_material")
  end
  Ok(parts)
end

fn plan(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  record :: CreditRecord,
  now_ms :: U64) -> CreditAttachmentPlan!String do
  let parts = read_material(record, wrapping, who)?
  let grant_body = List.get(parts, 0)
  let grant = decode_credit_attachment_grant(grant_body)?
  let reference = List.get(parts, 1)
  let action = credit_attachment_action(grant)?
  let spend = reserve_credit_spend(path,
    wrapping,
    who,
    encode_credit_action(action)?,
    grant_body,
    U64.divide(now_ms, U64.parse("1000")?)?)?
  let control = ObjectControl { object_id: grant.object_id, capability: grant.upload_capability }
  Ok(CreditAttachmentPlan {
    nonce: record.id,
    reference: reference,
    encrypted_manifest: decode_reference(reference)?.encrypted_manifest,
    grant: grant_body,
    submission: encode_credit_action_submission(CreditActionSubmission {
      action: action,
      request_body: grant_body,
      frame: decode_credit_frame(spend.frame)?
    })?,
    complete: encode_complete(control)?,
    delete: encode_delete(control)?,
    spend: spend
  })
end

pub fn saved_credit_attachment_grant(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  nonce :: Bytes) -> CreditAttachmentGrant!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 6, nonce) do
    None -> return Err("credit_attachment_not_found")
    Some(value) -> value
  end
  decode_credit_attachment_grant(List.get(read_material(record, wrapping, who)?, 0))
end

pub fn credit_attachment_reference(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  nonce :: Bytes) -> Bytes!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 6, nonce) do
    None -> return Err("credit_attachment_not_found")
    Some(value) -> value
  end
  Ok(List.get(read_material(record, wrapping, who)?, 1))
end

pub fn recover_credit_attachment(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  nonce :: Bytes,
  now_ms :: U64) -> CreditAttachmentPlan!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 6, nonce) do
    None -> return Err("credit_attachment_not_found")
    Some(value) -> value
  end
  plan(path, wrapping, who, record, now_ms)
end

# Persist wrapped keys, capabilities and the immutable LAG before selecting any
# tokens. CAS failure sends nothing; recovery never creates another object/key.
pub fn prepare_credit_attachment(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  device :: borrow DeviceKeys,
  nonce :: Bytes,
  filename :: Plaintext<Bytes>,
  mime_type :: Plaintext<Bytes>,
  plaintext_size :: Int,
  now_ms :: U64) -> CreditAttachmentPlan!String do
  if !credit_record_id(nonce) || !Bytes.secure_equals(device.device_id, who.device_id) do
    return Err("invalid_credit_attachment_identity")
  end
  let binding = attachment_binding(filename, mime_type, plaintext_size)?
  let before = load_credit_wallet(path, wrapping, who)?
  case find_credit_record(before.wallet, 6, nonce) do
    Some(record) -> do
      let saved = open_attachment_binding(record.payload,
        wrapping,
        credit_attachment_intent_context(who, nonce)?)?
      if !attachment_intent_matches(saved.digest, binding.digest) do
        return Err("credit_attachment_intent_changed")
      end
      return plan(path, wrapping, who, record, now_ms)
    end
    None -> nil
  end
  if credit_operation_nonce_seen(before.wallet, 1, nonce)? do
    return Err("credit_attachment_intent_retired")
  end
  let material_statuses = for record in List.filter(before.wallet.records,
    fn(record) -> record.kind == 6 end) do
    let id = if Bytes.length(record.metadata) == 40 do
      Bytes.slice(record.metadata, 8, 32)?
    else
      let material = read_material(record, wrapping, who)?
      credit_action_id(credit_attachment_action(decode_credit_attachment_grant(List.head(material))?)?)?
    end
    case credit_reservation_status(before.wallet, id)? do
      None -> true
      Some(value) -> value == 0
    end
  end
  if List.length(List.filter(material_statuses, fn(value) -> value end)) >= 128 do
    return Err("credit_attachment_capacity")
  end
  let expires = U64.add(now_ms, U64.parse("518400000")?)?
  let material = prepare_large_attachment_material(device,
    filename,
    mime_type,
    plaintext_size,
    expires)?
  let grant = encode_credit_attachment_grant(CreditAttachmentGrant {
    layout_version: 2,
    operation_nonce: nonce,
    object_id: material.object_id,
    upload_capability: material.upload_capability,
    download_capability: material.download_capability,
    size_bytes: attachment_bucket_capacity(plaintext_size)?,
    manifest_size: Bytes.length(material.encrypted_manifest),
    manifest_sha256: Crypto.sha256(material.encrypted_manifest),
    expires_at_ms: expires,
    action_expires_at: U64.add(U64.divide(now_ms, U64.parse("1000")?)?, U64.parse("600")?)?
  })?
  let record = CreditRecord {
    kind: 6,
    id: nonce,
    metadata: Bytes.concat(Bytes.concat(Bytes.from_hex("0241494a")?, mobile_write_u32(0)?)?,
      credit_action_id(credit_attachment_action(decode_credit_attachment_grant(grant)?)?)?)?,
    payload: attachment_journal_payload(seal_credit_payload(pack_credit_parts([
          grant,
          material.reference
        ])?,
        wrapping,
        who,
        label(nonce))?,
      seal_attachment_binding(binding.digest,
        wrapping,
        credit_attachment_intent_context(who, nonce)?)?)?
  }
  let wallet = put_credit_record(%{before.wallet |
      revision: U64.add(before.wallet.revision, U64.parse("1")?)?
    },
    record)
  commit_credit_wallet(path, wrapping, who, before, wallet)?
  plan(path, wrapping, who, record, now_ms)
end
