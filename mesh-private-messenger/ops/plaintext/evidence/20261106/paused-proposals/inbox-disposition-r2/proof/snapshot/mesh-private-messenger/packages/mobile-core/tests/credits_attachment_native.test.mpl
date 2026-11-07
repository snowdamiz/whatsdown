from Tests.LegacyAttachmentFixture import (
  LegacyAttachmentManifest,
  copy_legacy_fixture_manifest,
  legacy_fixture_chunk
)
from Attachments.Protocol import AttachmentManifest
from Tests.AttachmentAuthorizationFixture import fixture_paid_attachment_authorization
from Tests.AttachmentFixture import (
  fixture_credit_attachments,
  fixture_attachment_download_plan,
  fixture_attachment_fetch_chunk
)
from Mobile.CreditAttachmentNative import (
  native_credit_attachment_grant,
  native_credit_attachment_upload,
  native_credit_attachment_complete,
  native_credit_attachment_delete
)
from Mobile.CreditNonce import issued_credit_intent_nonce, require_fresh_credit_intent_nonce
import File
from Credits.ActionWire import (
  decode_credit_action_submission,
  sign_credit_action_receipt,
  encode_credit_action_receipt
)
from Credits.Attachment import (
  decode_credit_attachment_grant,
  credit_attachment_result,
  encode_credit_attachment_result,
  credit_attachment_effect_id
)
from Credits.Issuer import CreditIssuerKey
from Credits.Cancellation import sign_credit_cancellation, encode_credit_cancellation
from Mobile.CreditWallet import (
  accept_credit_cancellation,
  prune_credit_history,
  recover_credit_reservation
)
from Mobile.CreditAttachmentParts import prune_credit_attachment_parts
from Mobile.CreditAttachment import prepare_credit_attachment
from Mobile.Profile import open_device
from Credits.Policy import issuer_epoch, spent_retention_until
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Mobile.Codec import current_time, mobile_write_u32
from Mobile.Attachments import prepare_attachment, decode_reference
from Attachments.Protocol import open_manifest
from Mobile.Types import MobileAttachmentPrepareRequest
from MobileCore import (
  credit_attachment_prepare_export,
  credit_attachment_recover_export,
  credit_attachment_receipt_export,
  credit_attachment_part_export,
  credit_attachment_part_recover_export,
  credit_attachment_preview_export
)
from Mobile.CreditState import CreditWallet, pack_credit_parts, unpack_credit_parts
from Mobile.CreditWallet import add_credit_issuer, completed_credit_record, credit_wallet_balance
from MobileCore import create_account_export
from Storage.Credits import (
  CreditWalletIdentity,
  load_credit_wallet,
  commit_credit_wallet,
  credit_wallet_label,
  seal_credit_payload
)
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs
from Storage.Keys import platform_key
from Tests.Support import database_path, repeated, append, vector
from Tests.GroupLifecycleWire import output_list
from Transparency.Config import SecurityConfig, WitnessPin, witness_set_id, encode_security_config
from Transport.Packet import decode_client_profile

fn public_legacy_metadata(value :: AttachmentManifest) -> LegacyAttachmentManifest do
  declassify(copy_legacy_fixture_manifest(value),
    "synthetic public legacy attachment fixture metadata only; no application disclosure")
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("paid_attachment_native")?
  let profile = decode_client_profile(create_account_export(append(vector(Bytes.from_utf8(path))?,
    vector(Bytes.from_utf8("paid-native"))?)?)?)?
  let signer = case Crypto.signing_generate() do
    Err(_) -> return Err("test key failed")
    Ok(value) -> value
  end
  let witness = case Crypto.signing_generate() do
    Err(_) -> return Err("test witness key failed")
    Ok(value) -> value
  end
  let pins = [
    WitnessPin {
      witness_id: "outside",
      public_key: witness.public_key.bytes,
      operator_label: "Outside"
    }
  ]
  let config = SecurityConfig {
    version: 3,
    wire_version: 3,
    minimum_session_suite: 1,
    service_public_key: signer.public_key.bytes,
    delivery_public_key: repeated(56, 32)?,
    abuse_difficulty: 1,
    threshold: 1,
    witnesses: pins,
    set_id: witness_set_id(pins, 1)?,
    anchor_address: "-",
    anchor_program: "-",
    anchor_log_name: "-",
    rpc_urls: [],
    issuer_origin: Env.get("MORSE_ATTACHMENT_TLS_ORIGIN", "https://edge.example"),
    log_version: 2,
    legacy_threshold: 1,
    legacy_witnesses: pins,
    relay_urls: [],
    slash_mint: "-"
  }
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(config)?))
  let authorization = fixture_paid_attachment_authorization(path,
    profile,
    config,
    signer.private_key,
    witness.private_key)?
  let tls_fixture = Env.get("MORSE_ATTACHMENT_TLS_FIXTURE", "")
  let nonce = issued_credit_intent_nonce(current_time()?)?
  let request = pack_credit_parts([
    Bytes.from_utf8(path),
    nonce,
    Bytes.from_utf8("private.bin"),
    Bytes.from_utf8("application/octet-stream"),
    mobile_write_u32(16777217)?,
    authorization
  ])?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.empty()))
  assert(Result.is_err(credit_attachment_prepare_export(request)))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.from_hex("0101")?))
  let who = CreditWalletIdentity {
    account_id: profile.account_id,
    device_id: profile.device_id,
    service_key: signer.public_key.bytes,
    purpose: 1
  }
  let wrapping = platform_key()?
  let now = U64.divide(current_time()?, U64.parse("1000")?)?
  let rsa = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("test RSA failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(rsa) do
    Err(_) -> return Err("test public failed")
    Ok(value) -> value
  end
  let key = CreditIssuerKey {
    epoch: issuer_epoch(now)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: signer.public_key.bytes
  }
  let purchased = U64.subtract(now, U64.parse("600")?)?
  let before = load_credit_wallet(path, wrapping, who)?
  let base = add_credit_issuer(before.wallet, key, now, 1)?
  let pending = blind_credit(key, who.service_key, purchased)?
  let signature = sign_credit_request(rsa, key, pending.request)?
  let token = completed_credit_record(finalize_credit(key, pending, signature)?,
    key,
    purchased,
    wrapping,
    who)?
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: U64.parse("1")?, records: base.records ++ [token] })?
  let preview_request = pack_credit_parts([Bytes.from_utf8(path), mobile_write_u32(16777217)?])?
  let preview = unpack_credit_parts(credit_attachment_preview_export(preview_request)?, 9, 64)?
  assert(List.length(preview) == 9 && Bytes.to_hex(List.head(preview)) == "01415056")
  assert(Bytes.length(List.get(preview, 1)) == 32 && Bytes.to_hex(List.get(preview, 2)) == "01")
  assert(Bytes.secure_equals(List.get(preview, 4), mobile_write_u32(1)?))
  assert(Bytes.secure_equals(List.get(preview, 5), mobile_write_u32(1)?))
  let second_preview = unpack_credit_parts(credit_attachment_preview_export(preview_request)?,
    9,
    64)?
  assert(!Bytes.secure_equals(List.get(preview, 1), List.get(second_preview, 1)))
  let inventory_request = pack_credit_parts([Bytes.from_utf8(path)])?
  assert(List.length(unpack_credit_parts(fixture_credit_attachments(inventory_request)?,
    130,
    2048)?) == 2)
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == U64.parse("1")?)
  for size in [16777216, 536870913] do
    assert(Result.is_err(credit_attachment_prepare_export(pack_credit_parts([
      Bytes.from_utf8(path),
      nonce,
      Bytes.from_utf8("private.bin"),
      Bytes.from_utf8("application/octet-stream"),
      mobile_write_u32(size)?,
      authorization
    ])?)))
  end
  let stale_nonce = issued_credit_intent_nonce(U64.subtract(current_time()?,
    U64.parse("900001")?)?)?
  let before_stale = load_credit_wallet(path, wrapping, who)?.wallet.revision
  assert(Result.is_err(credit_attachment_prepare_export(pack_credit_parts([
    Bytes.from_utf8(path),
    stale_nonce,
    Bytes.from_utf8("private.bin"),
    Bytes.from_utf8("application/octet-stream"),
    mobile_write_u32(16777217)?,
    authorization
  ])?)))
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == before_stale)
  let prepared = credit_attachment_prepare_export(request)?
  let parts = unpack_credit_parts(prepared, 12, 4096)?
  assert(List.length(parts) == 12 && Bytes.to_hex(List.head(parts)) == "014d4341")
  assert(Bytes.to_utf8(List.get(parts, 5))? == config.issuer_origin)
  assert(Bytes.to_utf8(List.get(parts, 6))? == "/v1/attachments/paid-grant")
  let recover = pack_credit_parts([Bytes.from_utf8(path), nonce])?
  let grant_request = pack_credit_parts([Bytes.from_utf8(path), nonce, authorization])?
  assert(Bytes.secure_equals(prepared, credit_attachment_recover_export(recover)?))
  let listed = unpack_credit_parts(fixture_credit_attachments(inventory_request)?, 130, 2048)?
  assert(Bytes.to_hex(List.head(listed)) == "01414956" && List.length(listed) == 3)
  let row = unpack_credit_parts(List.get(listed, 2), 11, 255)?
  assert(List.length(row) == 11 && Bytes.secure_equals(List.head(row), nonce))
  assert(Bytes.to_hex(List.get(row, 2)) == "00")
  assert(Bytes.to_utf8(List.get(row, 3))? == "private.bin")
  assert(Bytes.secure_equals(List.get(row, 5), mobile_write_u32(16777217)?))
  assert(Bytes.secure_equals(List.get(listed, 1), List.get(parts, 4)))
  assert(Bytes.secure_equals(prepared, credit_attachment_recover_export(recover)?))
  let part_request = pack_credit_parts([
    Bytes.from_utf8(path),
    nonce,
    mobile_write_u32(256)?,
    Bytes.from_utf8("x")
  ])?
  let ciphertext = credit_attachment_part_export(part_request)?
  assert(Bytes.length(ciphertext) == 65576)
  assert(Bytes.get(ciphertext, 0) == Ok(4))
  assert(Bytes.secure_equals(ciphertext, credit_attachment_part_export(part_request)?))
  assert(Bytes.secure_equals(ciphertext,
    credit_attachment_part_recover_export(pack_credit_parts([
      Bytes.from_utf8(path),
      nonce,
      mobile_write_u32(256)?
    ])?)?))
  assert(Result.is_err(credit_attachment_part_export(pack_credit_parts([
    Bytes.from_utf8(path),
    nonce,
    mobile_write_u32(256)?,
    Bytes.from_utf8("y")
  ])?)))
  let full_request = pack_credit_parts([
    Bytes.from_utf8(path),
    nonce,
    mobile_write_u32(0)?,
    repeated(71, 65536)?
  ])?
  let full = credit_attachment_part_export(full_request)?
  assert(Bytes.length(full) == 65576)
  assert(Bytes.secure_equals(full, credit_attachment_part_export(full_request)?))
  # A legacy encoded part stays recoverable, but cannot replace the committed
  # new-format part or authorize a mixed-profile upload under a LAG2 grant.
  let saved_label = "#{credit_wallet_label(who)}/attachment-part/#{Bytes.to_hex(nonce)}/0"
  let saved_new = load_blob(path, saved_label)?
  let reference = decode_reference(List.get(parts, 8))?
  let device = open_device(profile, wrapping, path)?
  let secret = case Crypto.hpke_open_secret(device.identity_private_key,
    Bytes.from_utf8("mesh-msg/v1/attachment-key-wrap"),
    append(Bytes.from_utf8("mesh-msg/v1/attachment-reference"), reference.object_id)?,
    reference.wrapped_key) do
    Err(_) -> return Err("legacy fixture unwrap failed")
    Ok(value) -> value
  end
  let manifest = case open_manifest(secret, reference.encrypted_manifest) do
    Err(_) -> return Err("legacy fixture manifest failed")
    Ok(value) -> value
  end
  let legacy = case legacy_fixture_chunk(secret,
    public_legacy_metadata(%{manifest | version: 2}),
    0,
    repeated(71, 65536)?) do
    Err(_) -> return Err("legacy fixture chunk failed")
    Ok(value) -> value
  end
  assert(Bytes.get(legacy, 0) == Ok(2))
  store_updated_blobs(path,
    [saved_label],
    [
      seal_credit_payload(pack_credit_parts([Crypto.sha256(repeated(71, 65536)?), legacy])?,
        wrapping,
        who,
        saved_label)?
    ])?
  assert(Bytes.secure_equals(credit_attachment_part_recover_export(pack_credit_parts([
      Bytes.from_utf8(path),
      nonce,
      mobile_write_u32(0)?
    ])?)?,
    legacy))
  assert(native_credit_attachment_grant(grant_request) == Err("attachment_legacy_upload"))
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 1)
  store_updated_blobs(path, [saved_label], [saved_new])?
  assert(Result.is_err(credit_attachment_part_export(pack_credit_parts([
    Bytes.from_utf8(path),
    nonce,
    mobile_write_u32(0)?,
    repeated(71, 65537)?
  ])?)))
  let submission = decode_credit_action_submission(List.get(parts, 7))?
  let grant = decode_credit_attachment_grant(submission.request_body)?
  let receipt = sign_credit_action_receipt(signer.private_key,
    submission,
    credit_attachment_effect_id(submission.action)?,
    now,
    encode_credit_attachment_result(credit_attachment_result(grant)?)?)?
  let response = pack_credit_parts([Bytes.from_utf8(path), encode_credit_action_receipt(receipt)?])?
  assert(Result.is_err(credit_attachment_receipt_export(pack_credit_parts([
    Bytes.from_utf8(path),
    Bytes.from_utf8("200 OK")
  ])?)))
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 1)
  if tls_fixture != "" do
    # Missing staged parts cannot cause even a grant HTTP request.
    File.write(tls_fixture <> "/mode", "grant")?
    assert(Result.is_err(native_credit_attachment_grant(grant_request)))
    assert(File.read(tls_fixture <> "/count")? == "0")
    for index in 1..256 do
      credit_attachment_part_export(pack_credit_parts([
        Bytes.from_utf8(path),
        nonce,
        mobile_write_u32(index)?,
        repeated(71, 65536)?
      ])?)?
    end
    assert(Test.set_push_token(Bytes.from_utf8("messenger/issuer-tls-root/v1"),
      Bytes.from_hex("01000000000000")?))
    assert(Result.is_err(native_credit_attachment_grant(grant_request)))
    assert(File.read(tls_fixture <> "/count")? == "0")
    assert(Test.set_push_token(Bytes.from_utf8("messenger/issuer-tls-root/v1"),
      Bytes.from_hex(File.read(tls_fixture <> "/root.hex")?)?))
    File.write(tls_fixture <> "/grant.hex", Bytes.to_hex(List.get(parts, 7)))?
    File.write(tls_fixture <> "/receipt.hex", Bytes.to_hex(encode_credit_action_receipt(receipt)?))?
    for mode in ["failure", "redirect", "empty", "oversized", "forged", "drop"] do
      File.write(tls_fixture <> "/mode", mode)?
      assert(Result.is_err(native_credit_attachment_grant(grant_request)))
      assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 1)
      assert(Bytes.secure_equals(Bytes.from_hex(File.read(tls_fixture <> "/request.hex")?)?,
        List.get(parts, 7)))
    end
    File.write(tls_fixture <> "/mode", "grant")?
    let granted = unpack_credit_parts(native_credit_attachment_grant(grant_request)?, 12, 4096)?
    assert(Bytes.to_hex(List.get(granted, 3)) == "01")
    assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 0)
    # Repost the identical grant after central success to repair lost object commit.
    native_credit_attachment_grant(grant_request)?
    let first_part = pack_credit_parts([Bytes.from_utf8(path), nonce, mobile_write_u32(1)?])?
    File.write(tls_fixture <> "/mode", "put-drop")?
    assert(Result.is_err(native_credit_attachment_upload(first_part)))
    File.write(tls_fixture <> "/mode", "put")?
    native_credit_attachment_upload(first_part)?
    native_credit_attachment_upload(pack_credit_parts([
      Bytes.from_utf8(path),
      nonce,
      mobile_write_u32(0)?
    ])?)?
    native_credit_attachment_upload(pack_credit_parts([
      Bytes.from_utf8(path),
      nonce,
      mobile_write_u32(257)?
    ])?)?
    let sent = File.read(tls_fixture <> "/count")?
    assert(Result.is_err(native_credit_attachment_upload(pack_credit_parts([
      Bytes.from_utf8(path),
      nonce,
      mobile_write_u32(258)?
    ])?)))
    assert(File.read(tls_fixture <> "/count")? == sent)
    File.write(tls_fixture <> "/mode", "complete-pending")?
    assert(Bytes.to_hex(native_credit_attachment_complete(recover)?) == "00")
    File.write(tls_fixture <> "/mode", "complete")?
    assert(Bytes.to_hex(native_credit_attachment_complete(recover)?) == "01")
    File.write(tls_fixture <> "/mode", "get")?
    let download_first = pack_credit_parts([
      Bytes.from_utf8(path),
      List.get(parts, 8),
      mobile_write_u32(0)?
    ])?
    let download_last = pack_credit_parts([
      Bytes.from_utf8(path),
      List.get(parts, 8),
      mobile_write_u32(256)?
    ])?
    # Existing recipients may download when new purchasing is disabled.
    assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.empty()))
    assert(Bytes.secure_equals(fixture_attachment_fetch_chunk(download_first)?,
      repeated(71, 65536)?))
    assert(Bytes.secure_equals(fixture_attachment_fetch_chunk(download_last)?,
      Bytes.from_utf8("x")))
    File.write(tls_fixture <> "/mode", "get-forged")?
    assert(Result.is_err(fixture_attachment_fetch_chunk(download_first)))
    File.write(tls_fixture <> "/mode", "get-oversized")?
    assert(Result.is_err(fixture_attachment_fetch_chunk(download_first)))
    let downloads = File.read(tls_fixture <> "/count")?
    assert(Result.is_err(fixture_attachment_fetch_chunk(pack_credit_parts([
      Bytes.from_utf8(path),
      List.get(parts, 8),
      mobile_write_u32(257)?
    ])?)))
    assert(File.read(tls_fixture <> "/count")? == downloads)
    assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.from_hex("0101")?))
    File.write(tls_fixture <> "/mode", "delete-pending")?
    assert(Bytes.to_hex(native_credit_attachment_delete(recover)?) == "00")
    File.write(tls_fixture <> "/mode", "delete")?
    assert(Bytes.to_hex(native_credit_attachment_delete(recover)?) == "01")
  end
  let completed = unpack_credit_parts(credit_attachment_receipt_export(response)?, 12, 4096)?
  assert(Bytes.to_hex(List.get(completed, 3)) == "01")
  assert(Bytes.secure_equals(List.get(parts, 6), List.get(completed, 6)))
  assert(Bytes.secure_equals(List.get(parts, 7), List.get(completed, 7)))
  assert(Bytes.secure_equals(List.get(parts, 8), List.get(completed, 8)))
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 0)
  let finished_inventory = unpack_credit_parts(fixture_credit_attachments(inventory_request)?,
    130,
    2048)?
  let finished_row = unpack_credit_parts(List.get(finished_inventory, 2), 11, 255)?
  assert(Bytes.to_hex(List.get(finished_row, 2)) == "01")
  # A material saved before an insufficient-balance error must be visible without
  # reserving anything during listing or silently creating a new upload.
  let unreserved = issued_credit_intent_nonce(current_time()?)?
  assert(Result.is_err(credit_attachment_prepare_export(pack_credit_parts([
    Bytes.from_utf8(path),
    unreserved,
    Bytes.from_utf8("unreserved.bin"),
    Bytes.from_utf8("application/octet-stream"),
    mobile_write_u32(16777217)?,
    authorization
  ])?)))
  let unchanged = load_credit_wallet(path, wrapping, who)?.wallet.revision
  let unreserved_inventory = unpack_credit_parts(fixture_credit_attachments(inventory_request)?,
    130,
    2048)?
  assert(List.length(unreserved_inventory) == 4)
  let unreserved_rows = for raw in List.drop(unreserved_inventory, 2) do
    unpack_credit_parts(raw, 11, 255)?
  end
  assert(Result.is_ok(require_fresh_credit_intent_nonce(path,
    wrapping,
    who,
    1,
    unreserved,
    U64.add(current_time()?, U64.parse("3600000")?)?)))
  let unreserved_row = case List.find(unreserved_rows,
    fn(row) -> Bytes.secure_equals(List.head(row), unreserved) end) do
    None -> return Err("missing_unreserved_attachment")
    Some(value) -> value
  end
  assert(Bytes.secure_equals(List.head(unreserved_row), unreserved))
  assert(Bytes.to_hex(List.get(unreserved_row, 2)) == "03")
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == unchanged)
  # Recipients retain authenticated download access with new spending disabled.
  assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.empty()))
  assert(Result.is_err(credit_attachment_preview_export(preview_request)))
  let download_request = pack_credit_parts([Bytes.from_utf8(path), List.get(parts, 8)])?
  let download = unpack_credit_parts(fixture_attachment_download_plan(download_request)?, 11, 2048)?
  assert(List.length(download) == 11 && Bytes.to_hex(List.head(download)) == "01414450")
  assert(Bytes.to_hex(List.get(download, 1)) == "04")
  assert(Bytes.to_utf8(List.get(download, 2))? == config.issuer_origin)
  assert(Bytes.to_utf8(List.get(download, 3))? == "/v2/objects/#{Bytes.to_hex(List.get(download,
      5))}/parts/")
  assert(Bytes.secure_equals(List.get(download, 4), List.get(parts, 8)))
  assert(Bytes.secure_equals(List.get(download, 9), mobile_write_u32(16777217)?))
  assert(Result.is_err(fixture_attachment_download_plan(pack_credit_parts([
    Bytes.from_utf8(path),
    Bytes.from_utf8("forged manifest")
  ])?)))
  let legacy = output_list(prepare_attachment(MobileAttachmentPrepareRequest {
    database_path: path,
    filename: Bytes.from_utf8("legacy.bin"),
    mime_type: Bytes.from_utf8("application/octet-stream"),
    plaintext_size: 1,
    difficulty: 1
  })?)?
  let legacy_download = unpack_credit_parts(fixture_attachment_download_plan(pack_credit_parts([
      Bytes.from_utf8(path),
      List.head(legacy)
    ])?)?,
    11,
    2048)?
  assert(Bytes.to_hex(List.get(legacy_download, 1)) == "04")
  assert(Bytes.length(List.get(legacy_download, 2)) == 0
    && Bytes.length(List.get(legacy_download, 3)) == 0)
  # Successful/cancelled materials are recoverable history, not a lifetime
  # limit on new uploads. The AIV ABI keeps all pending rows and recent history.
  assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.from_hex("0101")?))
  let refill_pending = blind_credit(key, who.service_key, purchased)?
  let refill_signature = sign_credit_request(rsa, key, refill_pending.request)?
  let refill_token = completed_credit_record(finalize_credit(key,
      refill_pending,
      refill_signature)?,
    key,
    purchased,
    wrapping,
    who)?
  let refill = load_credit_wallet(path, wrapping, who)?
  commit_credit_wallet(path,
    wrapping,
    who,
    refill,
    %{refill.wallet |
      revision: U64.add(refill.wallet.revision, U64.parse("1")?)?,
      records: refill.wallet.records ++ [refill_token]
    })?
  # A later deposit cannot let a transport-only operation reserve an old draft.
  let transport_revision = load_credit_wallet(path, wrapping, who)?.wallet.revision
  let unreserved_request = pack_credit_parts([Bytes.from_utf8(path), unreserved])?
  assert(Result.is_err(native_credit_attachment_upload(pack_credit_parts([
    Bytes.from_utf8(path),
    unreserved,
    mobile_write_u32(0)?
  ])?)))
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == transport_revision)
  assert(Result.is_err(native_credit_attachment_complete(unreserved_request)))
  assert(Result.is_err(native_credit_attachment_delete(unreserved_request)))
  assert(Result.is_err(native_credit_attachment_grant(pack_credit_parts([
    Bytes.from_utf8(path),
    unreserved,
    authorization
  ])?)))
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == transport_revision)
  assert(credit_wallet_balance(path, wrapping, who, now)?.available == 1)
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 0)
  let device = open_device(profile, wrapping, path)?
  for index in 0..129 do
    let next_nonce = Crypto.sha256(Bytes.from_utf8("attachment-history/#{index}"))
    let next = prepare_credit_attachment(path,
      wrapping,
      who,
      device,
      next_nonce,
      Bytes.from_utf8("history.bin"),
      Bytes.from_utf8("application/octet-stream"),
      16777217,
      U64.multiply(now, U64.parse("1000")?)?)?
    let submission = decode_credit_action_submission(next.submission)?
    accept_credit_cancellation(path,
      wrapping,
      who,
      encode_credit_cancellation(sign_credit_cancellation(signer.private_key,
        submission,
        submission.action.expires_at)?)?)?
    nil
  end
  let pending_again = unpack_credit_parts(credit_attachment_recover_export(pack_credit_parts([
      Bytes.from_utf8(path),
      unreserved
    ])?)?,
    15,
    65536)?
  let recent = unpack_credit_parts(fixture_credit_attachments(inventory_request)?, 130, 2048)?
  assert(List.length(recent) == 130)
  let pending_rows = for raw in List.drop(recent, 2) do
    let row = unpack_credit_parts(raw, 11, 2048)?
    Bytes.secure_equals(List.head(row), unreserved) && Bytes.to_hex(List.get(row, 2)) == "00"
  end
  assert(List.any(pending_rows, fn(value) -> value end))
  let original_submission = decode_credit_action_submission(List.get(parts, 7))?
  let original_grant = decode_credit_attachment_grant(original_submission.request_body)?
  let cleanup_ms = U64.add(original_grant.expires_at_ms, U64.parse("604800000")?)?
  assert(prune_credit_attachment_parts(path, wrapping, who, nonce, 0, cleanup_ms)? == 128)
  assert(prune_credit_attachment_parts(path, wrapping, who, nonce, 128, cleanup_ms)? == 256)
  assert(prune_credit_attachment_parts(path, wrapping, who, nonce, 256, cleanup_ms)? == 257)
  assert(Result.is_err(credit_attachment_prepare_export(request)))
  let terminal_deadline = spent_retention_until(key.epoch)?
  for pass in 0..6 do
    assert(prune_credit_history(path, wrapping, who, terminal_deadline)?.scanned <= 64)
  end
  assert(Result.is_err(recover_credit_reservation(path, wrapping, who, List.get(parts, 2))))
  # Simulate restart with the system clock back at its original value. The
  # retired nonce cannot generate another grant, even after its CAR was pruned.
  let before_reopen = load_credit_wallet(path, wrapping, who)?.wallet.revision
  assert(Result.is_err(credit_attachment_prepare_export(request)))
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == before_reopen)
  File.delete(path)?
  Ok(true)
end

test("native paid attachment contracts pin identity and keep every transfer bounded and recoverable") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
