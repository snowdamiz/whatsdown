import File
from Credits.Action import encode_credit_action
from Credits.ActionWire import (
  CreditActionSubmission,
  sign_credit_action_receipt,
  encode_credit_action_receipt
)
from Credits.Retention import (
  CreditRetentionResult,
  sign_credit_retention_request,
  encode_credit_retention_request,
  credit_retention_action,
  encode_credit_retention_result
)
from Credits.Issuer import CreditIssuerKey
from Credits.Policy import spent_retention_until
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Credits.Wire import decode_credit_frame
from Mobile.CreditState import CreditWallet
from Mobile.CreditWallet import (
  add_credit_issuer,
  completed_credit_record,
  reserve_credit_spend,
  accept_credit_retention_receipt,
  credit_retention_deadline,
  credit_wallet_balance,
  prune_credit_history,
  recover_credit_reservation
)
from Storage.Credits import CreditWalletIdentity, load_credit_wallet, commit_credit_wallet
from Storage.Keys import platform_key
from Tests.Support import database_path, repeated

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let path = database_path("credits_retention")?
  let core_pair = case Crypto.signing_generate() do
    Err(_) -> return Err("test core key failed")
    Ok(value) -> value
  end
  let device_pair = case Crypto.signing_generate() do
    Err(_) -> return Err("test device key failed")
    Ok(value) -> value
  end
  let who = CreditWalletIdentity {
    account_id: repeated(41, 32)?,
    device_id: repeated(42, 16)?,
    service_key: core_pair.public_key.bytes,
    purpose: 1
  }
  let signer = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("test RSA failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(signer) do
    Err(_) -> return Err("test public failed")
    Ok(value) -> value
  end
  let issuer = CreditIssuerKey {
    epoch: U64.parse("10")?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: Crypto.sha256(Bytes.from_utf8("test-only quote key"))
  }
  let now = U64.parse("25921000")?
  let purchased = U64.subtract(now, U64.parse("600")?)?
  let before = load_credit_wallet(path, wrapping, who)?
  let base = add_credit_issuer(before.wallet, issuer, now, 1)?
  let tokens = for index in 0..10 do
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
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: U64.parse("1")?, records: base.records ++ tokens })?
  let mailbox = repeated(81, 32)?
  let request = sign_credit_retention_request(device_pair.private_key,
    mailbox,
    repeated(82, 32)?,
    32,
    U64.add(now, U64.parse("300")?)?,
    U64.multiply(now, U64.parse("1000")?)?)?
  let reserved = reserve_credit_spend(path,
    wrapping,
    who,
    encode_credit_action(credit_retention_action(request)?)?,
    encode_credit_retention_request(request)?,
    now)?
  let pending_until = credit_retention_deadline(path,
    wrapping,
    who,
    mailbox,
    device_pair.public_key)?
  assert(pending_until == U64.add(U64.multiply(request.action_expires_at, U64.parse("1000")?)?,
      U64.parse("3110400000")?)?)
  let submission = CreditActionSubmission {
    action: credit_retention_action(request)?,
    request_body: reserved.request_body,
    frame: decode_credit_frame(reserved.frame)?
  }
  let until = U64.add(U64.multiply(now, U64.parse("1000")?)?, U64.parse("15552000000")?)?
  let result = encode_credit_retention_result(CreditRetentionResult {
    mailbox_hash: mailbox,
    days: 32,
    effective_until_ms: until
  })?
  let receipt = sign_credit_action_receipt(core_pair.private_key,
    submission,
    repeated(83, 32)?,
    now,
    result)?
  let wire = encode_credit_action_receipt(receipt)?
  let forged = sign_credit_action_receipt(device_pair.private_key,
    submission,
    receipt.effect_id,
    now,
    result)?
  assert(Result.is_err(accept_credit_retention_receipt(path,
    wrapping,
    who,
    mailbox,
    encode_credit_action_receipt(forged)?)))
  let wrong_result = encode_credit_retention_result(CreditRetentionResult {
    mailbox_hash: repeated(84, 32)?,
    days: 32,
    effective_until_ms: until
  })?
  assert(Result.is_err(accept_credit_retention_receipt(path,
    wrapping,
    who,
    mailbox,
    encode_credit_action_receipt(sign_credit_action_receipt(core_pair.private_key,
      submission,
      receipt.effect_id,
      now,
      wrong_result)?)?)))
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 10)
  let completed = accept_credit_retention_receipt(path, wrapping, who, mailbox, wire)?
  assert(completed.status == 1)
  assert(accept_credit_retention_receipt(path,
    wrapping,
    who,
    mailbox,
    wire)?.revision == completed.revision)
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 0)
  assert(credit_retention_deadline(path,
    wrapping,
    who,
    mailbox,
    device_pair.public_key)? == U64.add(until, U64.parse("345600000")?)?)
  assert(Result.is_err(accept_credit_retention_receipt(path,
    wrapping,
    who,
    mailbox,
    encode_credit_action_receipt(sign_credit_action_receipt(core_pair.private_key,
      submission,
      repeated(85, 32)?,
      now,
      result)?)?)))
  # An existing longer parking grant may dominate this32-day request. Token
  # retention expiry must never erase the184-day key custody proof.
  assert(prune_credit_history(path,
    wrapping,
    who,
    spent_retention_until(issuer.epoch)?)?.removed == 0)
  assert(recover_credit_reservation(path, wrapping, who, completed.operation_id)?.status == 1)
  let boundary = U64.add(U64.divide(until, U64.parse("1000")?)?, U64.parse("345600")?)?
  assert(prune_credit_history(path,
    wrapping,
    who,
    U64.subtract(boundary, U64.parse("1")?)?)?.removed == 0)
  assert(prune_credit_history(path, wrapping, who, boundary)?.removed == 1)
  assert(credit_retention_deadline(path,
    wrapping,
    who,
    mailbox,
    device_pair.public_key)? == U64.parse("0")?)
  File.delete(path)?
  Ok(true)
end

test("only an exact pinned-core retention receipt consumes a reservation and narrows key custody") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
