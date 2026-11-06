from Tests.BlobFixture import fixture_record_hash
from Tests.LegacyCreditAttachmentFixture import fixture_prepare_legacy_credit_attachment
from Mobile.CreditAttachment import CreditAttachmentPlan
from Mobile.CreditAttachmentJournal import attachment_journal_parts
from Mobile.Codec import mobile_write_u32
from Tests.LegacyAttachmentFixture import (
  LegacyAttachmentManifest,
  copy_legacy_fixture_manifest,
  legacy_fixture_chunk
)
from Attachments.Protocol import AttachmentManifest
import File
from Attachments.Protocol import open_manifest, open_chunk
from Credits.Attachment import (
  credit_attachment_action,
  decode_credit_attachment_grant,
  credit_attachment_result,
  encode_credit_attachment_result,
  credit_attachment_effect_id
)
from Credits.ActionWire import (
  decode_credit_action_submission,
  sign_credit_action_receipt,
  encode_credit_action_receipt
)
from Credits.Issuer import CreditIssuerKey
from Credits.Cancellation import sign_credit_cancellation, encode_credit_cancellation
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Identity.Device import DeviceKeys
from Mobile.Attachments import decode_reference
from Mobile.CreditAttachmentParts import (
  seal_credit_attachment_part,
  recover_credit_attachment_part,
  prune_credit_attachment_parts
)
from Mobile.CreditAttachment import prepare_credit_attachment, recover_credit_attachment
from Mobile.CreditMaintenance import maintain_credit_storage
from Mobile.CreditState import (
  CreditWallet,
  CreditRecord,
  pack_credit_parts,
  find_credit_record,
  put_credit_record
)
from Mobile.CreditWallet import (
  add_credit_issuer,
  completed_credit_record,
  accept_credit_attachment_receipt,
  credit_wallet_balance,
  accept_credit_cancellation,
  recover_credit_reservation
)
from Storage.Credits import (
  CreditWalletIdentity,
  load_credit_wallet,
  commit_credit_wallet,
  credit_wallet_label
)
from Storage.Records import with_record_transaction
from Storage.CreditAttachment import insert_credit_attachment_part
from Storage.Keys import platform_key
from Tests.Support import database_path, repeated

fn public_legacy_metadata(value :: AttachmentManifest) -> LegacyAttachmentManifest do
  declassify(copy_legacy_fixture_manifest(value),
    "synthetic public legacy attachment fixture metadata only; no application disclosure")
end

fn exact_fixture(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "synthetic public legacy attachment chunk equality only; no application disclosure")
end

# Synthetic public names recreate both historical journal layouts; the actual
# preparation/recovery/cancellation path must migrate them without new material.
fn historical_intent(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  nonce :: Bytes,
  name :: Bytes,
  mime :: Bytes,
  with_action :: Bool) -> Bool!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 6, nonce) do
    None -> return Err("fixture attachment missing")
    Some(value) -> value
  end
  let original_ciphertext = List.get(attachment_journal_parts(record.payload)?, 1)
  let binding = Crypto.sha256(pack_credit_parts([name, mime, mobile_write_u32(16777217)?])?)
  let metadata = Bytes.concat(binding, mobile_write_u32(0)?)?
  let legacy = CreditRecord {
    kind: 6,
    id: nonce,
    payload: original_ciphertext,
    metadata: if with_action do
      Bytes.concat(metadata, Bytes.slice(record.metadata, 8, 32)?)?
    else
      metadata
    end
  }
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    put_credit_record(%{before.wallet |
        revision: U64.add(before.wallet.revision, U64.parse("1")?)?
      },
      legacy))?
  let reopened = load_credit_wallet(path, wrapping, who)?
  let normalized = case find_credit_record(reopened.wallet, 6, nonce) do
    None -> return Err("fixture attachment missing after migration")
    Some(value) -> value
  end
  assert(Bytes.secure_equals(List.get(attachment_journal_parts(normalized.payload)?, 1),
    original_ciphertext))
  assert(reopened.wallet.revision == U64.add(before.wallet.revision, U64.parse("2")?)?)
  Ok(true)
end

fn proof(legacy :: Bool) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let path = database_path("credit_attachment")?
  let core = case Crypto.signing_generate() do
    Err(_) -> return Err("test signing failed")
    Ok(value) -> value
  end
  let signing = case Crypto.signing_generate() do
    Err(_) -> return Err("test signing failed")
    Ok(value) -> value
  end
  let identity = case Crypto.x25519_generate() do
    Err(_) -> return Err("test identity failed")
    Ok(value) -> value
  end
  let device_id = repeated(42, 16)?
  let signing_public = signing.public_key
  let identity_public = identity.public_key
  let device = DeviceKeys {
    device_id: device_id,
    signing_private_key: signing.private_key,
    signing_public_key: signing_public,
    identity_private_key: identity.private_key,
    identity_public_key: identity_public
  }
  let who = CreditWalletIdentity {
    account_id: repeated(41, 32)?,
    device_id: device_id,
    service_key: core.public_key.bytes,
    purpose: 1
  }
  let now = U64.parse("25921000")?
  let now_ms = U64.multiply(now, U64.parse("1000")?)?
  let nonce = repeated(51, 32)?
  let name = Bytes.from_utf8("private-name.bin")
  let mime = Bytes.from_utf8("application/octet-stream")
  # Even insufficient balance saves immutable wrapped material before returning.
  assert(Result.is_err(fixture_prepare_for(legacy,
    path,
    wrapping,
    who,
    device,
    nonce,
    name,
    mime,
    16777217,
    now_ms)))
  assert(historical_intent(path, wrapping, who, nonce, name, mime, false)?)
  let before = load_credit_wallet(path, wrapping, who)?
  let material = List.filter(before.wallet.records, fn(record) do record.kind == 6 end)
  assert(List.length(material) == 1)
  assert(Bytes.length(List.head(material).payload) < 2048)
  let signer = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("test RSA failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(signer) do
    Err(_) -> return Err("test RSA public failed")
    Ok(value) -> value
  end
  let issuer = CreditIssuerKey {
    epoch: U64.parse("10")?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: core.public_key.bytes
  }
  let base = add_credit_issuer(before.wallet, issuer, now, 1)?
  let purchased = U64.subtract(now, U64.parse("600")?)?
  let pending = blind_credit(issuer, who.service_key, purchased)?
  let signature = sign_credit_request(signer, issuer, pending.request)?
  let token = completed_credit_record(finalize_credit(issuer, pending, signature)?,
    issuer,
    purchased,
    wrapping,
    who)?
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet {
      revision: U64.add(base.revision, U64.parse("1")?)?,
      records: base.records ++ [token]
    })?
  let plan = fixture_prepare_for(legacy,
    path,
    wrapping,
    who,
    device,
    nonce,
    name,
    mime,
    16777217,
    now_ms)?
  assert(plan.spend.credits == 1 && plan.spend.status == 0)
  assert(Bytes.length(plan.grant) == 186 && Bytes.length(plan.submission) < 1024)
  let retry = recover_credit_attachment(path,
    wrapping,
    who,
    nonce,
    U64.add(now_ms, U64.parse("3600000")?)?)?
  assert(Bytes.secure_equals(retry.submission, plan.submission))
  assert(Bytes.secure_equals(retry.reference, plan.reference))
  assert(Result.is_err(fixture_prepare_for(legacy,
    path,
    wrapping,
    who,
    device,
    nonce,
    Bytes.from_utf8("changed.bin"),
    mime,
    16777217,
    now_ms)))
  # Two original sizes in one public64KiB capacity interval are distinct
  # private intents. A retry cannot reuse the grant to encrypt a new file.
  let fixed_revision = load_credit_wallet(path, wrapping, who)?.wallet.revision
  assert(Result.is_err(fixture_prepare_for(legacy,
    path,
    wrapping,
    who,
    device,
    nonce,
    name,
    mime,
    16777218,
    now_ms)))
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == fixed_revision)
  assert(Bytes.secure_equals(recover_credit_attachment(path,
      wrapping,
      who,
      nonce,
      now_ms)?.submission,
    plan.submission))
  let reference = decode_reference(plan.reference)?
  let secret = case Crypto.hpke_open_secret(device.identity_private_key,
    Bytes.from_utf8("mesh-msg/v1/attachment-key-wrap"),
    Bytes.concat(Bytes.from_utf8("mesh-msg/v1/attachment-reference"), reference.object_id)?,
    reference.wrapped_key) do
    Err(_) -> return Err("test unwrap failed")
    Ok(value) -> value
  end
  let manifest = case open_manifest(secret, reference.encrypted_manifest) do
    Err(_) -> return Err("test manifest failed")
    Ok(value) -> value
  end
  assert(manifest.version == (if legacy do
      2
    else
      4
    end)
    && manifest.plaintext_size == 16777217
    && manifest.chunk_count == 257)
  let last = case legacy_fixture_chunk(secret,
    public_legacy_metadata(%{manifest | version: 2}),
    256,
    Bytes.from_utf8("x")) do
    Err(_) -> return Err("test chunk failed")
    Ok(value) -> value
  end
  assert(Bytes.length(last) == 41)
  assert(exact_fixture(case open_chunk(secret, %{manifest | version: 2}, 256, last) do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value, Bytes.from_utf8("x"))
  end))
  let staged = seal_credit_attachment_part(path,
    wrapping,
    who,
    device,
    nonce,
    256,
    Bytes.from_utf8("x"),
    now_ms)?
  assert(Bytes.length(staged) == (if legacy do
      41
    else
      65576
    end))
  assert(Bytes.get(staged, 0) == Ok(if legacy do
      3
    else
      4
    end))
  assert(Bytes.secure_equals(staged,
    seal_credit_attachment_part(path,
      wrapping,
      who,
      device,
      nonce,
      256,
      Bytes.from_utf8("x"),
      now_ms)?))
  assert(Bytes.secure_equals(staged,
    recover_credit_attachment_part(path, wrapping, who, nonce, 256)?))
  let full = seal_credit_attachment_part(path,
    wrapping,
    who,
    device,
    nonce,
    0,
    repeated(61, 65536)?,
    now_ms)?
  assert(Bytes.length(full) == 65576)
  assert(Bytes.secure_equals(full, recover_credit_attachment_part(path, wrapping, who, nonce, 0)?))
  assert(Result.is_err(seal_credit_attachment_part(path,
    wrapping,
    who,
    device,
    nonce,
    256,
    Bytes.from_utf8("y"),
    now_ms)))
  let submission = decode_credit_action_submission(plan.submission)?
  let grant = decode_credit_attachment_grant(plan.grant)?
  let action = credit_attachment_action(grant)?
  let result = encode_credit_attachment_result(credit_attachment_result(grant)?)?
  let receipt = sign_credit_action_receipt(core.private_key,
    submission,
    credit_attachment_effect_id(action)?,
    now,
    result)?
  let wire = encode_credit_action_receipt(receipt)?
  assert(Result.is_err(accept_credit_attachment_receipt(path,
    wrapping,
    who,
    Bytes.from_utf8("200 OK"))))
  let forged = sign_credit_action_receipt(device.signing_private_key,
    submission,
    receipt.effect_id,
    now,
    result)?
  assert(Result.is_err(accept_credit_attachment_receipt(path,
    wrapping,
    who,
    encode_credit_action_receipt(forged)?)))
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 1)
  let completed = accept_credit_attachment_receipt(path, wrapping, who, wire)?
  assert(completed.status == 1)
  assert(accept_credit_attachment_receipt(path, wrapping, who, wire)?.status == 1)
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 0)
  let changed = sign_credit_action_receipt(core.private_key,
    submission,
    receipt.effect_id,
    U64.add(now, U64.parse("1")?)?,
    result)?
  assert(Result.is_err(accept_credit_attachment_receipt(path,
    wrapping,
    who,
    encode_credit_action_receipt(changed)?)))
  assert(recover_credit_attachment(path, wrapping, who, nonce, now_ms)?.spend.status == 1)
  assert(Result.is_err(prune_credit_attachment_parts(path, wrapping, who, nonce, 0, now_ms)))
  let prune_at = U64.add(grant.expires_at_ms, U64.parse("604800000")?)?
  assert(Result.is_err(prune_credit_attachment_parts(path, wrapping, who, nonce, 256, prune_at)))
  let wallet_hash = fixture_record_hash(path, credit_wallet_label(who))?
  with_record_transaction(path,
    fn(database) do
      case Sqlite.execute(database,
        "CREATE TRIGGER fail_attachment_cursor BEFORE UPDATE ON encrypted_blobs WHEN OLD.record_hash = '#{wallet_hash}' BEGIN SELECT RAISE(ABORT, 'forced cleanup failure'); END",
        []) do
        Err(_) -> Err("test trigger failed")
        Ok(_) -> Ok(nil)
      end
    end)?
  assert(Result.is_err(prune_credit_attachment_parts(path, wrapping, who, nonce, 0, prune_at)))
  # Deletion and cursor advancement must be indivisible: a failed manifest CAS
  # cannot lose the only durable copy of an encrypted upload part.
  assert(Bytes.secure_equals(full, recover_credit_attachment_part(path, wrapping, who, nonce, 0)?))
  with_record_transaction(path,
    fn(database) do
      case Sqlite.execute(database, "DROP TRIGGER fail_attachment_cursor", []) do
        Err(_) -> Err("test trigger failed")
        Ok(_) -> Ok(nil)
      end
    end)?
  assert(prune_credit_attachment_parts(path, wrapping, who, nonce, 0, prune_at)? == 128)
  assert(Result.is_err(recover_credit_attachment_part(path, wrapping, who, nonce, 0)))
  assert(Bytes.secure_equals(staged,
    recover_credit_attachment_part(path, wrapping, who, nonce, 256)?))
  assert(prune_credit_attachment_parts(path, wrapping, who, nonce, 128, prune_at)? == 256)
  assert(prune_credit_attachment_parts(path, wrapping, who, nonce, 256, prune_at)? == 257)
  assert(Result.is_err(recover_credit_attachment(path, wrapping, who, nonce, now_ms)))
  # A core-signed non-consumption receipt releases staged disk space promptly.
  # Pending and paid uploads above remain protected by the recovery deadline.
  let cancellation_nonce = repeated(52, 32)?
  let new_pending = blind_credit(issuer, who.service_key, purchased)?
  let new_signature = sign_credit_request(signer, issuer, new_pending.request)?
  let new_token = completed_credit_record(finalize_credit(issuer, new_pending, new_signature)?,
    issuer,
    purchased,
    wrapping,
    who)?
  let refill = load_credit_wallet(path, wrapping, who)?
  commit_credit_wallet(path,
    wrapping,
    who,
    refill,
    CreditWallet {
      revision: U64.add(refill.wallet.revision, U64.parse("1")?)?,
      records: refill.wallet.records ++ [new_token]
    })?
  let cancellable = fixture_prepare_for(legacy,
    path,
    wrapping,
    who,
    device,
    cancellation_nonce,
    name,
    mime,
    16777217,
    now_ms)?
  assert(historical_intent(path, wrapping, who, cancellation_nonce, name, mime, true)?)
  let recovered_cancellable = recover_credit_attachment(path,
    wrapping,
    who,
    cancellation_nonce,
    now_ms)?
  assert(Bytes.secure_equals(recovered_cancellable.submission, cancellable.submission))
  assert(Bytes.secure_equals(recovered_cancellable.reference, cancellable.reference))
  seal_credit_attachment_part(path,
    wrapping,
    who,
    device,
    cancellation_nonce,
    0,
    repeated(62, 65536)?,
    now_ms)?
  assert(Result.is_err(prune_credit_attachment_parts(path,
    wrapping,
    who,
    cancellation_nonce,
    0,
    now_ms)))
  let cancel_submission = decode_credit_action_submission(cancellable.submission)?
  let cancelled_at = cancel_submission.action.expires_at
  let forged_cancel = encode_credit_cancellation(sign_credit_cancellation(device.signing_private_key,
    cancel_submission,
    cancelled_at)?)?
  assert(Result.is_err(accept_credit_cancellation(path, wrapping, who, forged_cancel)))
  assert(Result.is_err(prune_credit_attachment_parts(path,
    wrapping,
    who,
    cancellation_nonce,
    0,
    now_ms)))
  let cancel = encode_credit_cancellation(sign_credit_cancellation(core.private_key,
    cancel_submission,
    cancelled_at)?)?
  let before_cancel = load_credit_wallet(path, wrapping, who)?
  assert(accept_credit_cancellation(path, wrapping, who, cancel)?.status == 2)
  assert(prune_credit_attachment_parts(path, wrapping, who, cancellation_nonce, 0, now_ms)? == 128)
  # Model encryption begun before cancellation and finished after cleanup.
  assert(Result.is_err(insert_credit_attachment_part(path,
    who,
    before_cancel,
    cancellation_nonce,
    0,
    repeated(63, 100)?)))
  assert(Result.is_err(seal_credit_attachment_part(path,
    wrapping,
    who,
    device,
    cancellation_nonce,
    0,
    repeated(62, 65536)?,
    now_ms)))
  assert(prune_credit_attachment_parts(path,
    wrapping,
    who,
    cancellation_nonce,
    128,
    now_ms)? == 256)
  assert(prune_credit_attachment_parts(path,
    wrapping,
    who,
    cancellation_nonce,
    256,
    now_ms)? == 257)
  assert(recover_credit_reservation(path,
    wrapping,
    who,
    cancellable.spend.operation_id)?.status == 2)
  assert(Result.is_err(recover_credit_attachment_part(path, wrapping, who, cancellation_nonce, 0)))
  # Explicit balance maintenance drives the same bounded cursor automatically,
  # retaining the exact signed cancellation after the material/parts are gone.
  let automatic_nonce = repeated(53, 32)?
  let automatic = fixture_prepare_for(legacy,
    path,
    wrapping,
    who,
    device,
    automatic_nonce,
    name,
    mime,
    16777217,
    now_ms)?
  let automatic_part = seal_credit_attachment_part(path,
    wrapping,
    who,
    device,
    automatic_nonce,
    0,
    repeated(64, 65536)?,
    now_ms)?
  let automatic_submission = decode_credit_action_submission(automatic.submission)?
  let automatic_cancel = encode_credit_cancellation(sign_credit_cancellation(core.private_key,
    automatic_submission,
    automatic_submission.action.expires_at)?)?
  accept_credit_cancellation(path, wrapping, who, automatic_cancel)?
  assert(maintain_credit_storage(path, wrapping, who, now)?.scanned <= 64)
  assert(Result.is_err(recover_credit_attachment_part(path, wrapping, who, automatic_nonce, 0)))
  assert(maintain_credit_storage(path, wrapping, who, now)?.scanned <= 64)
  assert(maintain_credit_storage(path, wrapping, who, now)?.scanned <= 64)
  assert(Result.is_err(recover_credit_attachment(path, wrapping, who, automatic_nonce, now_ms)))
  assert(recover_credit_reservation(path, wrapping, who, automatic.spend.operation_id)?.status == 2)
  assert(Result.is_err(fixture_prepare_for(legacy,
    path,
    wrapping,
    who,
    device,
    automatic_nonce,
    name,
    mime,
    16777217,
    now_ms)))
  File.delete(path)?
  Ok(true)
end

test("paid attachment material survives unknown outcomes and spends only on an exact pinned receipt") do
  case proof(false) do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn fixture_prepare_for(legacy :: Bool,
  path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  device :: borrow DeviceKeys,
  nonce :: Bytes,
  filename :: Plaintext<Bytes>,
  mime_type :: Plaintext<Bytes>,
  size :: Int,
  now_ms :: U64) -> CreditAttachmentPlan!String do
  if legacy do
    fixture_prepare_legacy_credit_attachment(path,
      wrapping,
      who,
      device,
      nonce,
      filename,
      mime_type,
      size,
      now_ms)
  else
    prepare_credit_attachment(path, wrapping, who, device, nonce, filename, mime_type, size, now_ms)
  end
end

test("exact legacy LAG1/EAM2 reservations still reopen, replay, settle and cancel without conversion") do
  case proof(true) do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
