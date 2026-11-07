from Tests.BlobFixture import fixture_record_hash
from Mobile.CreditNonce import issued_credit_intent_nonce, require_fresh_credit_intent_nonce
from Mobile.Sessions import updated_session_record
from Mobile.History import updated_history
from Mobile.Codec import encode_output_list
from Mobile.Types import MobileSessionRecord
from Protocol.V1 import InnerEnvelope
from Storage.Keys import seal_local, local_context
import File
from Credits.Action import decode_credit_action, encode_credit_action
from Credits.ActionWire import sign_credit_action_receipt, encode_credit_action_receipt
from Credits.Cancellation import sign_credit_cancellation, encode_credit_cancellation
from Credits.Postage import (
  decode_credit_postage_request,
  CreditPostageResult,
  encode_credit_postage_result,
  credit_postage_effect_id
)
from Credits.PostageBox import decode_sealed_postage_batch, open_postage_credit_box
from Credits.PostageReply import seal_postage_reply
from Credits.PostagePolicy import (
  sign_postage_policy,
  bundle_with_postage_policy,
  decode_postage_policy,
  verify_postage_policy
)
from Credits.Issuer import CreditIssuerKey
from Credits.Policy import issuer_epoch
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Mobile.Codec import current_time, mobile_write_u64
from Mobile.CreditPostage import recover_credit_postage, accept_credit_postage_response
from MobileCore import (
  credit_postage_prepare_export,
  credit_postage_preview_export,
  credit_postage_candidate_export,
  credit_postage_inventory_export,
  credit_postage_recover_export,
  credit_postage_receipt_export,
  credit_postage_continue_export,
  postage_policy_publish_export,
  postage_policy_view_export,
  postage_policy_prepare_export
)
from Mobile.Credits import (
  native_credit_reserve,
  native_credit_reservation,
  native_credit_receipt,
  native_credit_action_recovery
)
from Mobile.CreditState import (
  CreditWallet,
  find_credit_record,
  pack_credit_parts,
  unpack_credit_parts
)
from Mobile.CreditWallet import add_credit_issuer, completed_credit_record, credit_wallet_balance
from Mobile.Outbox import prepare_outbox_writes, load_outbox_ids, list_outbox
from Tests.GroupLifecycleWire import output_list
from Mobile.Profile import open_account
from Mobile.Transparency import verify_transparency_response
from Mobile.Types import MobileTransparencyRequest
from MobileCore import create_account_export
from Privacy.Edge import decode_stamped_request
from Protocol.DirectoryWire import encode_device_set
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import DeviceSet, OuterEnvelope
from Storage.Credits import (
  CreditWalletIdentity,
  load_credit_wallet,
  commit_credit_wallet,
  open_credit_payload
)
from Storage.Keys import platform_key
from Storage.Records import store_updated_blobs, with_record_transaction, delete_blob
from Tests.Support import database_path, repeated, append, vector
from Transparency.Config import SecurityConfig, WitnessPin, witness_set_id, encode_security_config
from Transparency.Merkle import (
  leaf_hash_for,
  merkle_root_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_tree_checkpoint_for,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence, encode_transparency_evidence
from Transport.Packet import decode_client_profile

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("postage_native_sender")?
  let peer_path = database_path("postage_native_recipient")?
  let profile = decode_client_profile(create_account_export(append(vector(Bytes.from_utf8(path))?,
    vector(Bytes.from_utf8("postage-sender"))?)?)?)?
  let peer = decode_client_profile(create_account_export(append(vector(Bytes.from_utf8(peer_path))?,
    vector(Bytes.from_utf8("postage-recipient"))?)?)?)?
  let wrapping = platform_key()?
  let owner = open_account(peer, wrapping, peer_path)?
  let core = case Crypto.signing_generate() do
    Err(_) -> return Err("test signer failed")
    Ok(value) -> value
  end
  let attacker = case Crypto.signing_generate() do
    Err(_) -> return Err("test signer failed")
    Ok(value) -> value
  end
  let witness = case Crypto.signing_generate() do
    Err(_) -> return Err("test witness failed")
    Ok(value) -> value
  end
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> return Err("test delivery failed")
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
    service_public_key: core.public_key.bytes,
    delivery_public_key: delivery.public_key.bytes,
    abuse_difficulty: 1,
    threshold: 1,
    witnesses: pins,
    set_id: witness_set_id(pins, 1)?,
    anchor_address: "-",
    anchor_program: "-",
    anchor_log_name: "-",
    rpc_urls: [],
    issuer_origin: Env.get("MORSE_POSTAGE_TLS_ORIGIN", "https://edge.example"),
    log_version: 2,
    legacy_threshold: 1,
    legacy_witnesses: pins,
    relay_urls: [],
    slash_mint: "-"
  }
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    encode_security_config(config)?))
  assert(Test.set_push_token(Bytes.from_utf8("messenger/credits/v1"), Bytes.from_hex("0101")?))
  let tls_fixture = Env.get("MORSE_POSTAGE_TLS_FIXTURE", "")
  if tls_fixture != "" do
    assert(Test.set_push_token(Bytes.from_utf8("messenger/issuer-tls-root/v1"),
      Bytes.from_hex(File.read(tls_fixture <> "/root.hex")?)?))
  end
  let now_ms = current_time()?
  let now = U64.divide(now_ms, U64.parse("1000")?)?
  let policy = sign_postage_policy(owner,
    peer.device_id,
    U64.parse("1")?,
    U64.parse("1")?,
    1,
    now_ms)?
  let bundle = case decode_prekey_bundle(peer.entry.prekey_bundle) do
    Err(_) -> return Err("test bundle failed")
    Ok(value) -> value
  end
  let bundled = case encode_prekey_bundle(bundle_with_postage_policy(bundle, policy)?) do
    Err(_) -> return Err("test bundle failed")
    Ok(value) -> value
  end
  let devices = DeviceSet {
    version: 1,
    username: peer.entry.username,
    account_identity: peer.entry.account_identity,
    sequence: U64.parse("2")?,
    devices: [%{peer.entry | prekey_bundle: bundled}],
    revoked_device_ids: []
  }
  let devices_wire = case encode_device_set(devices) do
    Err(_) -> return Err("test devices failed")
    Ok(value) -> value
  end
  let outer = OuterEnvelope {
    version: 1,
    envelope_id: repeated(61, 16)?,
    mailbox_token: peer.entry.mailbox_token,
    suite: 1,
    expiration: U64.add(now_ms, U64.parse("86400000")?)?,
    padding_bucket: 65536,
    ciphertext: repeated(72, 65536)?
  }
  let outer_wire = case encode_outer_envelope(outer) do
    Err(_) -> return Err("test outer failed")
    Ok(value) -> value
  end
  let (labels, blobs, index_blob) = prepare_outbox_writes(wrapping,
    [],
    [outer_wire],
    path,
    repeated(81, 16)?,
    0,
    1,
    profile)?
  store_updated_blobs(path, labels ++ ["outbox/v1"], blobs ++ [index_blob.value])?
  let session_id = repeated(83, 32)?
  let conversation = repeated(82, 16)?
  let message_id = repeated(81, 16)?
  let session = MobileSessionRecord {
    snapshot: Bytes.from_hex("01")?,
    local_account_id: profile.account_id,
    local_device_id: profile.device_id,
    peer_account_id: peer.account_id,
    peer_device_id: peer.device_id,
    peer_username: peer.entry.username,
    peer_mailbox: peer.entry.mailbox_token,
    conversation_id: conversation,
    request_state: 0,
    blocked: false,
    verified: false,
    key_changed: false,
    disappearing_seconds: 0,
    strongest_suite: 1,
    safety_number: Bytes.empty(),
    peer_transport_key: peer.credential.dh_public_key
  }
  let session_label = "session/v1/#{Bytes.to_hex(session_id)}"
  let (history_labels, history_blobs) = updated_history(path,
    wrapping,
    InnerEnvelope {
      version: 1,
      sender_account_id: profile.account_id,
      sender_device_id: profile.device_id,
      recipient_device_id: peer.device_id,
      conversation_id: conversation,
      client_message_id: message_id,
      client_timestamp: now_ms,
      message_type: 1,
      body: Bytes.from_utf8("postage request"),
      reply_reference: Bytes.empty(),
      attachment_manifest: Bytes.empty(),
      receipt_policy: 0,
      disappearing_seconds: 0,
      extensions: []
    },
    1)?
  store_updated_blobs(path,
    ["sessions/v1", session_label] ++ history_labels,
    [
      seal_local(session_id, wrapping, local_context("sessions/v1")?)?,
      seal_local(updated_session_record(Bytes.from_hex("01")?, session)?,
        wrapping,
        local_context(session_label)?)?
    ]
      ++ history_blobs)?
  let nonce = issued_credit_intent_nonce(current_time()?)?
  let request = pack_credit_parts([
    Bytes.from_utf8(path),
    nonce,
    devices_wire,
    pack_credit_parts([outer.envelope_id])?
  ])?
  # A valid account signature alone is insufficient: no token can be reserved
  # until the exact recipient snapshot enters the pinned witnessed local view.
  assert(Result.is_err(credit_postage_prepare_export(request)))
  let leaves = [leaf_hash_for(2, devices_wire)?]
  let checkpoint = sign_tree_checkpoint_for(2,
    core.private_key,
    core.public_key.bytes,
    U64.parse("1")?,
    U64.parse("1")?,
    merkle_root_for(2, leaves)?,
    repeated(0, 32)?,
    now_ms)?
  let evidence = encode_transparency_evidence(TransparencyEvidence {
    entry_bytes: devices_wire,
    inclusion: compact_inclusion_proof_for(2, leaves, 0)?,
    consistency: compact_consistency_proof_for(2, [], leaves)?,
    checkpoint: checkpoint,
    witnesses: [sign_witness("outside", witness.private_key, checkpoint)?]
  })?
  verify_transparency_response(MobileTransparencyRequest {
    database_path: path,
    username: peer.entry.username,
    evidence: evidence,
    directory_url: ""
  })?
  verify_transparency_response(MobileTransparencyRequest {
    database_path: peer_path,
    username: peer.entry.username,
    evidence: evidence,
    directory_url: ""
  })?
  let view = unpack_credit_parts(postage_policy_view_export(pack_credit_parts([
      Bytes.from_utf8(path),
      peer.account_id
    ])?)?,
    6,
    4096)?
  assert(Bytes.to_hex(List.head(view)) == "024d5056" && Bytes.to_hex(List.get(view, 4)) == "01")
  let publication = unpack_credit_parts(postage_policy_prepare_export(pack_credit_parts([
      Bytes.from_utf8(peer_path),
      Bytes.from_hex("05")?
    ])?)?,
    8,
    1024)?
  let proposed = decode_postage_policy(List.get(publication, 7))?
  assert(proposed.credits == 5
    && proposed.revision == U64.parse("2")?
    && verify_postage_policy(proposed, peer.account)?)
  let pending_view = unpack_credit_parts(postage_policy_view_export(pack_credit_parts([
      Bytes.from_utf8(peer_path),
      peer.account_id
    ])?)?,
    6,
    4096)?
  assert(List.length(pending_view) == 6 && Bytes.to_hex(List.head(pending_view)) == "024d5056")
  let restored_intent = unpack_credit_parts(List.get(pending_view, 5), 8, 2048)?
  assert(Bytes.secure_equals(List.get(restored_intent, 7), List.get(publication, 7)))
  Timer.sleep(2)
  let policy_retry = unpack_credit_parts(postage_policy_prepare_export(pack_credit_parts([
      Bytes.from_utf8(peer_path),
      Bytes.from_hex("05")?
    ])?)?,
    8,
    2048)?
  assert(Bytes.secure_equals(List.get(publication, 7), List.get(policy_retry, 7)))
  assert(Result.is_err(postage_policy_prepare_export(pack_credit_parts([
    Bytes.from_utf8(peer_path),
    Bytes.from_hex("19")?
  ])?)))
  if tls_fixture != "" do
    let policy_request = pack_credit_parts([
      Bytes.from_utf8(peer_path),
      List.get(publication, 2),
      List.get(publication, 3),
      Bytes.from_hex("05")?
    ])?
    File.write(tls_fixture <> "/mode", "policy")?
    assert(Result.is_ok(postage_policy_publish_export(policy_request)))
    let sent = decode_postage_policy(Bytes.from_hex(File.read(tls_fixture <> "/request.hex")?)?)?
    assert(sent.credits == 5
      && sent.revision == proposed.revision
      && sent.expected_device_set_revision == proposed.expected_device_set_revision
      && verify_postage_policy(sent, peer.account)?)
    let calls = File.read(tls_fixture <> "/count")?
    assert(Result.is_err(postage_policy_publish_export(pack_credit_parts([
      Bytes.from_utf8(peer_path),
      mobile_write_u64(U64.parse("3")?)?,
      List.get(publication, 3),
      Bytes.from_hex("05")?
    ])?)))
    assert(File.read(tls_fixture <> "/count")? == calls)
  end
  # Signing (and any HTTP ack) never changes the witnessed setting.
  let unchanged = unpack_credit_parts(postage_policy_view_export(pack_credit_parts([
      Bytes.from_utf8(path),
      peer.account_id
    ])?)?,
    6,
    4096)?
  assert(Bytes.to_hex(List.get(unchanged, 4)) == "01")
  with_record_transaction(peer_path,
    fn(database) -> delete_blob(database, "account-signing-key/v1") end)?
  assert(Result.is_err(postage_policy_prepare_export(pack_credit_parts([
    Bytes.from_utf8(peer_path),
    Bytes.from_hex("05")?
  ])?)))
  assert(Result.is_ok(postage_policy_view_export(pack_credit_parts([
    Bytes.from_utf8(peer_path),
    peer.account_id
  ])?)))
  let who = CreditWalletIdentity {
    account_id: profile.account_id,
    device_id: profile.device_id,
    service_key: core.public_key.bytes,
    purpose: 1
  }
  let rsa = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("test RSA failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(rsa) do
    Err(_) -> return Err("test RSA public failed")
    Ok(value) -> value
  end
  let purchased = U64.subtract(now, U64.parse("600")?)?
  let issuer = CreditIssuerKey {
    epoch: issuer_epoch(purchased)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: core.public_key.bytes
  }
  let before = load_credit_wallet(path, wrapping, who)?
  let base = add_credit_issuer(before.wallet, issuer, now, 1)?
  let tokens = for _index in 0..2 do
    let pending = blind_credit(issuer, who.service_key, purchased)?
    let signed = sign_credit_request(rsa, issuer, pending.request)?
    completed_credit_record(finalize_credit(issuer, pending, signed)?,
      issuer,
      purchased,
      wrapping,
      who)?
  end
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: U64.parse("1")?, records: base.records ++ tokens })?
  let context = unpack_credit_parts(credit_postage_candidate_export(pack_credit_parts([
      Bytes.from_utf8(path),
      outer.envelope_id
    ])?)?,
    5,
    128)?
  assert(Bytes.to_hex(List.head(context)) == "014d5043"
    && Bytes.secure_equals(List.get(context, 1), peer.account_id)
    && Bytes.secure_equals(List.get(context, 3), message_id))
  let preview = unpack_credit_parts(credit_postage_preview_export(pack_credit_parts([
      Bytes.from_utf8(path),
      devices_wire,
      outer.envelope_id
    ])?)?,
    13,
    256)?
  assert(Bytes.to_hex(List.head(preview)) == "014d5042" && Bytes.length(List.get(preview, 1)) == 32)
  assert(Bytes.secure_equals(List.get(preview, 4), message_id)
    && Bytes.to_hex(List.get(preview, 9)) == "0001"
    && Bytes.to_hex(List.get(preview, 10)) == "01")
  assert(Bytes.secure_equals(List.get(preview, 6), pack_credit_parts([outer.envelope_id])?))
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == U64.parse("1")?)
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 0
    && List.length(output_list(list_outbox(path)?)?) == 1)
  assert(List.length(unpack_credit_parts(credit_postage_inventory_export(pack_credit_parts([
      Bytes.from_utf8(path)
    ])?)?,
    19,
    1024)?) == 3)
  let output = unpack_credit_parts(credit_postage_prepare_export(request)?, 9, 600000)?
  assert(Bytes.to_hex(List.head(output)) == "014d5053" && Bytes.to_hex(List.get(output, 3)) == "00")
  assert(Bytes.to_utf8(List.get(output, 7))? == "/v1/credits/postage")
  let (_stamp, wire) = decode_stamped_request(List.get(output, 8), 541865)?
  let batch = decode_sealed_postage_batch(wire)?
  let submission = open_postage_credit_box(delivery.private_key,
    batch.deliveries,
    batch.credit_box)?
  let descriptor = decode_credit_postage_request(submission.request_body)?
  let recover_request = pack_credit_parts([Bytes.from_utf8(path), nonce])?
  let recovered_output = unpack_credit_parts(credit_postage_recover_export(recover_request)?,
    9,
    600000)?
  let (_retry_stamp, retry_wire) = decode_stamped_request(List.get(recovered_output, 8), 541865)?
  assert(Bytes.secure_equals(wire, retry_wire))
  assert(!String.contains(Bytes.to_hex(List.get(output, 8)), Bytes.to_hex(peer.account_id)))
  assert(!String.contains(Bytes.to_hex(List.get(output, 8)),
    Bytes.to_hex(List.head(submission.frame.tokens).input.nonce)))
  let inventory = unpack_credit_parts(credit_postage_inventory_export(pack_credit_parts([
      Bytes.from_utf8(path)
    ])?)?,
    19,
    1024)?
  assert(List.length(inventory) == 4 && Bytes.to_hex(List.head(inventory)) == "014d5049")
  let row = unpack_credit_parts(List.get(inventory, 3), 9, 256)?
  assert(Bytes.secure_equals(List.get(row, 0), nonce)
    && Bytes.secure_equals(List.get(row, 1), message_id)
    && Bytes.secure_equals(List.get(row, 2), peer.account_id)
    && Bytes.to_hex(List.get(row, 5)) == "00")
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 1)
  assert(List.length(load_outbox_ids(path, wrapping)?) == 1)
  assert(List.length(output_list(list_outbox(path)?)?) == 0)
  let generic = pack_credit_parts([Bytes.from_utf8(path), List.get(output, 2)])?
  assert(Result.is_err(native_credit_reservation(generic)))
  assert(Result.is_err(native_credit_action_recovery(generic)))
  assert(Result.is_err(native_credit_reserve(pack_credit_parts([
    Bytes.from_utf8(path),
    encode_credit_action(submission.action)?,
    submission.request_body
  ])?)))
  assert(Result.is_err(credit_postage_prepare_export(pack_credit_parts([
    Bytes.from_utf8(path),
    repeated(73, 32)?,
    devices_wire,
    pack_credit_parts([outer.envelope_id])?
  ])?)))
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 1)
  let after_time = recover_credit_postage(path,
    wrapping,
    who,
    nonce,
    U64.add(now_ms, U64.parse("700000")?)?)?
  assert(Bytes.secure_equals(after_time.batch, wire) && after_time.spend.status == 0)
  let result = encode_credit_postage_result(CreditPostageResult {
    recipient_account_id: peer.account_id,
    batch_digest: descriptor.batch_digest,
    policy_revision: descriptor.policy_revision,
    device_set_revision: descriptor.device_set_revision,
    enqueued_count: 1,
    charged_credits: 1
  })?
  let receipt = sign_credit_action_receipt(core.private_key,
    submission,
    credit_postage_effect_id(submission.action)?,
    now,
    result)?
  let raw = encode_credit_action_receipt(receipt)?
  let sealed = seal_postage_reply(X25519PublicKey { bytes: descriptor.reply_public_key },
    batch.deliveries,
    raw)?
  let bad_receipt = encode_credit_action_receipt(sign_credit_action_receipt(attacker.private_key,
    submission,
    receipt.effect_id,
    now,
    result)?)?
  let forged = seal_postage_reply(X25519PublicKey { bytes: descriptor.reply_public_key },
    batch.deliveries,
    bad_receipt)?
  assert(Result.is_err(credit_postage_receipt_export(pack_credit_parts([
    Bytes.from_utf8(path),
    nonce,
    forged
  ])?)))
  assert(Result.is_err(credit_postage_receipt_export(pack_credit_parts([
    Bytes.from_utf8(path),
    nonce,
    Bytes.from_utf8("200 OK")
  ])?)))
  assert(Result.is_err(native_credit_receipt(pack_credit_parts([Bytes.from_utf8(path), raw])?)))
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 1
    && List.length(load_outbox_ids(path, wrapping)?) == 1)
  if tls_fixture != "" do
    File.write(tls_fixture <> "/response.hex", Bytes.to_hex(forged))?
    for mode in ["failure", "redirect", "empty", "oversized", "forged", "drop"] do
      File.write(tls_fixture <> "/mode", mode)?
      assert(Result.is_err(credit_postage_continue_export(recover_request)))
      assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 1
        && List.length(load_outbox_ids(path, wrapping)?) == 1)
      let (_attempt_stamp, attempt) = decode_stamped_request(Bytes.from_hex(File.read(tls_fixture
          <> "/request.hex")?)?,
        541865)?
      assert(Bytes.secure_equals(attempt, wire))
    end
    File.write(tls_fixture <> "/response.hex", Bytes.to_hex(sealed))?
    File.write(tls_fixture <> "/mode", "valid")?
  end
  # A durable CAR may commit immediately before a local outbox-ack failure.
  # Restart must keep ordinary transport suppressed, then recover the effect.
  let head_hash = fixture_record_hash(path,
    "outbox-envelope/v1/#{Bytes.to_hex(outer.envelope_id)}")?
  with_record_transaction(path,
    fn(database) do
      case Sqlite.execute(database,
        "CREATE TRIGGER fail_postage_ack BEFORE DELETE ON encrypted_blobs WHEN OLD.record_hash = '#{head_hash}' BEGIN SELECT RAISE(ABORT, 'forced ack failure'); END",
        []) do
        Err(_) -> Err("test trigger failed")
        Ok(_) -> Ok(nil)
      end
    end)?
  if tls_fixture != "" do
    assert(Result.is_err(credit_postage_continue_export(recover_request)))
  else
    assert(Result.is_err(credit_postage_receipt_export(pack_credit_parts([
      Bytes.from_utf8(path),
      nonce,
      sealed
    ])?)))
  end
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 0
    && List.length(load_outbox_ids(path, wrapping)?) == 1
    && List.length(output_list(list_outbox(path)?)?) == 0)
  with_record_transaction(path,
    fn(database) do
      case Sqlite.execute(database, "DROP TRIGGER fail_postage_ack", []) do
        Err(_) -> Err("test trigger failed")
        Ok(_) -> Ok(nil)
      end
    end)?
  let completed_wire = if tls_fixture != "" do
    credit_postage_continue_export(recover_request)?
  else
    credit_postage_receipt_export(pack_credit_parts([Bytes.from_utf8(path), nonce, sealed])?)?
  end
  let completed = unpack_credit_parts(completed_wire, 9, 600000)?
  if tls_fixture != "" do
    let calls = File.read(tls_fixture <> "/count")?
    assert(Bytes.secure_equals(credit_postage_continue_export(recover_request)?, completed_wire))
    assert(File.read(tls_fixture <> "/count")? == calls)
  end
  assert(Bytes.to_hex(List.get(completed, 3)) == "01" && Bytes.length(List.get(completed, 8)) == 0)
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 0
    && credit_wallet_balance(path, wrapping, who, now)?.available == 1)
  assert(List.length(load_outbox_ids(path, wrapping)?) == 0)
  let terminal = case find_credit_record(load_credit_wallet(path, wrapping, who)?.wallet,
    8,
    nonce) do
    None -> return Err("missing_postage_terminal")
    Some(value) -> value
  end
  assert(Bytes.length(open_credit_payload(terminal.payload,
    wrapping,
    who,
    "postage/#{Bytes.to_hex(nonce)}")?) < 2048)
  assert(Result.is_ok(credit_postage_receipt_export(pack_credit_parts([
    Bytes.from_utf8(path),
    nonce,
    sealed
  ])?)))
  assert(Result.is_ok(credit_postage_recover_export(recover_request)))
  # More than sixteen terminal cancellations must not exhaust the bounded
  # pending-material budget. Each proof releases exactly the saved frame and
  # returns its original envelope to ordinary transport; no time-only release.
  let next_outer = %{outer | envelope_id: repeated(62, 16)?}
  let next_wire = case encode_outer_envelope(next_outer) do
    Err(_) -> return Err("test outer failed")
    Ok(value) -> value
  end
  let (next_labels, next_blobs, next_index) = prepare_outbox_writes(wrapping,
    [],
    [next_wire],
    path,
    message_id,
    0,
    1,
    profile)?
  store_updated_blobs(path, next_labels ++ ["outbox/v1"], next_blobs ++ [next_index.value])?
  for index in 0..17 do
    let next_nonce = issued_credit_intent_nonce(current_time()?)?
    let prepared = unpack_credit_parts(credit_postage_prepare_export(pack_credit_parts([
        Bytes.from_utf8(path),
        next_nonce,
        devices_wire,
        pack_credit_parts([next_outer.envelope_id])?
      ])?)?,
      9,
      600000)?
    let (_stamp, next_batch_wire) = decode_stamped_request(List.get(prepared, 8), 541865)?
    let next_batch = decode_sealed_postage_batch(next_batch_wire)?
    let next_submission = open_postage_credit_box(delivery.private_key,
      next_batch.deliveries,
      next_batch.credit_box)?
    let next_request = decode_credit_postage_request(next_submission.request_body)?
    let cancelled_at = U64.add(next_submission.action.expires_at, U64.parse("1")?)?
    let cancellation = encode_credit_cancellation(sign_credit_cancellation(core.private_key,
      next_submission,
      cancelled_at)?)?
    assert(Result.is_err(native_credit_receipt(pack_credit_parts([
      Bytes.from_utf8(path),
      cancellation
    ])?)))
    assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 1
      && List.length(output_list(list_outbox(path)?)?) == 0)
    let encrypted = seal_postage_reply(X25519PublicKey { bytes: next_request.reply_public_key },
      next_batch.deliveries,
      cancellation)?
    let cancelled = accept_credit_postage_response(path,
      wrapping,
      who,
      next_nonce,
      encrypted,
      U64.multiply(cancelled_at, U64.parse("1000")?)?)?
    assert(cancelled.spend.status == 2
      && credit_wallet_balance(path, wrapping, who, now)?.reserved == 0
      && List.length(output_list(list_outbox(path)?)?) == 1)
    assert(accept_credit_postage_response(path,
      wrapping,
      who,
      next_nonce,
      encrypted,
      now_ms)?.spend.status == 2)
    let saved = case find_credit_record(load_credit_wallet(path, wrapping, who)?.wallet,
      8,
      next_nonce) do
      None -> return Err("missing_postage_terminal")
      Some(value) -> value
    end
    assert(Bytes.length(open_credit_payload(saved.payload,
      wrapping,
      who,
      "postage/#{Bytes.to_hex(next_nonce)}")?) < 2048)
  end
  let terminal_inventory = unpack_credit_parts(credit_postage_inventory_export(pack_credit_parts([
      Bytes.from_utf8(path)
    ])?)?,
    147,
    1024)?
  assert(List.length(terminal_inventory) == 21)
  File.delete(path)?
  File.delete(peer_path)?
  Ok(true)
end

test("native postage persists opaque exact retries, requires witnessed price and completes only pinned receipts") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
