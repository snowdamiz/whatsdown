from Tests.BlobFixture import fixture_record_hash
import File
from Credits.Action import encode_credit_action, credit_action_id
from Credits.ActionWire import (
  CreditActionSubmission,
  sign_credit_action_receipt,
  encode_credit_action_receipt
)
from Credits.Attachment import (
  CreditAttachmentGrant,
  encode_credit_attachment_grant,
  credit_attachment_action,
  credit_attachment_effect_id,
  credit_attachment_result,
  encode_credit_attachment_result
)
from Credits.Cancellation import sign_credit_cancellation, encode_credit_cancellation
from Credits.Issuer import CreditIssuerKey
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Credits.Wire import decode_credit_frame, credit_nullifier
from Credits.Policy import spent_retention_until
from Mobile.CreditState import CreditWallet, put_credit_record
from Mobile.CreditWallet import (
  add_credit_issuer,
  completed_credit_record,
  reserve_credit_spend,
  recover_credit_reservation,
  accept_credit_cancellation,
  accept_credit_attachment_receipt,
  credit_nullifier_spent,
  stored_credit_receipt,
  prune_credit_history,
  credit_wallet_balance
)
from Storage.Credits import CreditWalletIdentity, load_credit_wallet, commit_credit_wallet
from Storage.Keys import platform_key
from Storage.Records import with_record_transaction
from Storage.CreditMaintenance import credit_maintenance_label, load_credit_maintenance
from Tests.Support import database_path, repeated

fn grant(index :: Int, now :: U64) -> CreditAttachmentGrant!String do
  Ok(CreditAttachmentGrant {
    layout_version: 1,
    operation_nonce: Crypto.sha256(Bytes.from_utf8("history/#{index}")),
    object_id: repeated(42, 32)?,
    upload_capability: repeated(44, 32)?,
    download_capability: repeated(45, 32)?,
    size_bytes: 16777217,
    manifest_size: 128,
    manifest_sha256: repeated(46, 32)?,
    expires_at_ms: U64.multiply(U64.add(now, U64.parse("86400")?)?, U64.parse("1000")?)?,
    action_expires_at: U64.add(now, U64.parse("300")?)?
  })
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let path = database_path("credit_history")?
  let core = case Crypto.signing_generate() do
    Err(_) -> return Err("test key failed")
    Ok(value) -> value
  end
  let who = CreditWalletIdentity {
    account_id: repeated(41, 32)?,
    device_id: repeated(42, 16)?,
    service_key: core.public_key.bytes,
    purpose: 1
  }
  let signer = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("test RSA failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(signer) do
    Err(_) -> return Err("test RSA failed")
    Ok(value) -> value
  end
  let issuer = CreditIssuerKey {
    epoch: U64.parse("10")?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: core.public_key.bytes
  }
  let now = U64.parse("25921000")?
  let purchased = U64.subtract(now, U64.parse("600")?)?
  let tokens = for index in 0..2 do
    let pending = blind_credit(issuer, who.service_key, purchased)?
    let request = pending.request
    completed_credit_record(finalize_credit(issuer,
        pending,
        sign_credit_request(signer, issuer, request)?)?,
      issuer,
      purchased,
      wrapping,
      who)?
  end
  let before = load_credit_wallet(path, wrapping, who)?
  let base = add_credit_issuer(before.wallet, issuer, now, who.purpose)?
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: U64.parse("1")?, records: base.records ++ tokens })?
  for index in 0..129 do
    let value = grant(index, now)?
    let reserved = reserve_credit_spend(path,
      wrapping,
      who,
      encode_credit_action(credit_attachment_action(value)?)?,
      encode_credit_attachment_grant(value)?,
      now)?
    let submission = CreditActionSubmission {
      action: credit_attachment_action(value)?,
      request_body: reserved.request_body,
      frame: decode_credit_frame(reserved.frame)?
    }
    let receipt = encode_credit_cancellation(sign_credit_cancellation(core.private_key,
      submission,
      value.action_expires_at)?)?
    assert(accept_credit_cancellation(path, wrapping, who, receipt)?.status == 2)
    assert(recover_credit_reservation(path, wrapping, who, reserved.operation_id)?.status == 2)
  end
  assert(List.length(List.filter(load_credit_wallet(path, wrapping, who)?.wallet.records,
    fn(record) -> record.kind == 4 end)) == 129)
  let completed_value = grant(500, now)?
  let completed_action = credit_attachment_action(completed_value)?
  let completed_body = encode_credit_attachment_grant(completed_value)?
  let chosen = reserve_credit_spend(path,
    wrapping,
    who,
    encode_credit_action(completed_action)?,
    completed_body,
    now)?
  let completed_submission = CreditActionSubmission {
    action: completed_action,
    request_body: chosen.request_body,
    frame: decode_credit_frame(chosen.frame)?
  }
  let signed = encode_credit_action_receipt(sign_credit_action_receipt(core.private_key,
    completed_submission,
    credit_attachment_effect_id(completed_action)?,
    now,
    encode_credit_attachment_result(credit_attachment_result(completed_value)?)?)?)?
  let completed = accept_credit_attachment_receipt(path, wrapping, who, signed)?
  let spent_id = credit_nullifier(List.head(completed_submission.frame.tokens).input)?
  assert(credit_nullifier_spent(load_credit_wallet(path, wrapping, who)?.wallet, spent_id)?)
  # A retained spent nullifier remains irreversible even if an internal caller
  # mistakenly attempts to put the original encrypted bearer token back.
  let original = case List.find(tokens, fn(value) -> Bytes.secure_equals(value.id, spent_id) end) do
    None -> return Err("test token not found")
    Some(value) -> value
  end
  let snapshot = load_credit_wallet(path, wrapping, who)?
  commit_credit_wallet(path,
    wrapping,
    who,
    snapshot,
    put_credit_record(%{snapshot.wallet |
        revision: U64.add(snapshot.wallet.revision, U64.parse("1")?)?
      },
      original))?
  assert(Result.is_err(credit_wallet_balance(path, wrapping, who, now)))
  let reintroduced = grant(501, now)?
  assert(Result.is_err(reserve_credit_spend(path,
    wrapping,
    who,
    encode_credit_action(credit_attachment_action(reintroduced)?)?,
    encode_credit_attachment_grant(reintroduced)?,
    now)))
  let snapshot = load_credit_wallet(path, wrapping, who)?
  commit_credit_wallet(path,
    wrapping,
    who,
    snapshot,
    %{snapshot.wallet |
      revision: U64.add(snapshot.wallet.revision, U64.parse("1")?)?,
      records: List.filter(snapshot.wallet.records,
        fn(value) -> value.kind != 3 || !Bytes.secure_equals(value.id, spent_id) end)
    })?
  let pending_value = grant(999, now)?
  let unknown = reserve_credit_spend(path,
    wrapping,
    who,
    encode_credit_action(credit_attachment_action(pending_value)?)?,
    encode_credit_attachment_grant(pending_value)?,
    now)?
  let deadline = spent_retention_until(issuer.epoch)?
  let kept = prune_credit_history(path, wrapping, who, U64.subtract(deadline, U64.parse("1")?)?)?
  assert(kept.scanned <= 64 && kept.removed == 0)
  assert(Bytes.secure_equals(case stored_credit_receipt(path,
      wrapping,
      who,
      completed.operation_id)? do
      None -> Bytes.empty()
      Some(value) -> value
    end,
    signed))
  assert(reserve_credit_spend(path,
    wrapping,
    who,
    chosen.action,
    chosen.request_body,
    deadline)?.status == 1)
  let before_failure = load_credit_wallet(path, wrapping, who)?
  let old_cursor = load_credit_maintenance(path, wrapping, who)?
  let cursor_hash = fixture_record_hash(path, credit_maintenance_label(who))?
  with_record_transaction(path,
    fn(database) do
      case Sqlite.execute(database,
        "CREATE TRIGGER fail_credit_cursor BEFORE UPDATE ON encrypted_blobs WHEN OLD.record_hash = '#{cursor_hash}' BEGIN SELECT RAISE(ABORT, 'forced cursor failure'); END",
        []) do
        Err(_) -> Err("test trigger failed")
        Ok(_) -> Ok(nil)
      end
    end)?
  assert(Result.is_err(prune_credit_history(path, wrapping, who, deadline)))
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == before_failure.wallet.revision)
  assert(Bytes.secure_equals(load_credit_maintenance(path, wrapping, who)?.previous,
    old_cursor.previous))
  with_record_transaction(path,
    fn(database) do
      case Sqlite.execute(database, "DROP TRIGGER fail_credit_cursor", []) do
        Err(_) -> Err("test trigger failed")
        Ok(_) -> Ok(nil)
      end
    end)?
  for iteration in 0..6 do
    assert(prune_credit_history(path, wrapping, who, deadline)?.scanned <= 64)
  end
  let retained = load_credit_wallet(path, wrapping, who)?.wallet
  assert(List.length(List.filter(retained.records, fn(value) -> value.kind == 4 end)) == 1)
  assert(List.length(List.filter(retained.records, fn(value) -> value.kind == 3 end)) == 1)
  assert(!credit_nullifier_spent(retained, spent_id)?)
  assert(Bytes.secure_equals(recover_credit_reservation(path,
      wrapping,
      who,
      unknown.operation_id)?.frame,
    unknown.frame))
  assert(Result.is_err(recover_credit_reservation(path, wrapping, who, completed.operation_id)))
  # Even if the host clock regresses, the expired descriptor cannot recreate a
  # pruned completed operation; the pending unknown request remains reserved.
  assert(Result.is_err(reserve_credit_spend(path,
    wrapping,
    who,
    chosen.action,
    chosen.request_body,
    now)))
  assert(credit_wallet_balance(path, wrapping, who, deadline)?.reserved == 1)
  File.delete(path)?
  Ok(true)
end

test("resolved exact reservations do not exhaust the pending reservation budget") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
