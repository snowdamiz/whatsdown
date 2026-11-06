import File
from Credits.Action import CreditAction, credit_action_id, encode_credit_action
from Credits.Attachment import CreditAttachmentGrant, encode_credit_attachment_grant
from Credits.Issuer import CreditIssuerKey
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Mobile.CreditState import CreditWallet, put_credit_record
from Mobile.CreditWallet import (
  add_credit_issuer,
  completed_credit_record,
  reserve_credit_spend,
  recover_credit_reservation,
  complete_credit_reservation,
  credit_wallet_balance
)
from Storage.Credits import CreditWalletIdentity, load_credit_wallet, commit_credit_wallet
from Storage.Keys import platform_key
from Tests.Support import database_path, repeated

fn action(nonce :: Int, quantity :: String, body :: Bytes, now :: U64) -> Bytes!String do
  encode_credit_action(CreditAction {
    kind: 1,
    operation_nonce: repeated(nonce, 32)?,
    target: repeated(42, 32)?,
    expires_at: U64.add(now, U64.parse("300")?)?,
    quantity: U64.parse(quantity)?,
    request_sha256: Crypto.sha256(body)
  })
end

fn body_for(nonce :: Int, quantity :: Int, now :: U64) -> Bytes!String do
  encode_credit_attachment_grant(CreditAttachmentGrant {
    layout_version: 1,
    operation_nonce: repeated(nonce, 32)?,
    object_id: repeated(42, 32)?,
    upload_capability: repeated(44, 32)?,
    download_capability: repeated(45, 32)?,
    size_bytes: quantity,
    manifest_size: 128,
    manifest_sha256: repeated(46, 32)?,
    expires_at_ms: U64.multiply(U64.add(now, U64.parse("86400")?)?, U64.parse("1000")?)?,
    action_expires_at: U64.add(now, U64.parse("300")?)?
  })
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let path = database_path("credit_reservation")?
  let who = CreditWalletIdentity {
    account_id: repeated(41, 32)?,
    device_id: repeated(42, 16)?,
    service_key: repeated(43, 32)?,
    purpose: 1
  }
  let signing = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("test key generation failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(signing) do
    Err(_) -> return Err("test public key failed")
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
  let base = add_credit_issuer(before.wallet, issuer, now, who.purpose)?
  let tokens = for index in 0..4 do
    let pending = blind_credit(issuer, who.service_key, purchased)?
    let request = pending.request
    let token = finalize_credit(issuer, pending, sign_credit_request(signing, issuer, request)?)?
    let bought = if index == 3 do
      U64.add(purchased, U64.parse("1")?)?
    else
      purchased
    end
    completed_credit_record(token, issuer, bought, wrapping, who)?
  end
  let ready = CreditWallet { revision: U64.parse("1")?, records: base.records ++ tokens }
  commit_credit_wallet(path, wrapping, who, before, ready)?
  let balance = credit_wallet_balance(path, wrapping, who, now)?
  assert(balance.available == 3 && balance.delayed == 1 && balance.reserved == 0)
  let body = body_for(51, 33554433, now)?
  # An untrusted presentation layer cannot reserve one token for a two-token
  # upload by lying in the descriptor while keeping the real grant body.
  assert(Result.is_err(reserve_credit_spend(path,
    wrapping,
    who,
    action(51, "16777217", body, now)?,
    body,
    now)))
  let descriptor = action(51, "33554433", body, now)?
  let selected = reserve_credit_spend(path, wrapping, who, descriptor, body, now)?
  assert(selected.credits == 2 && selected.status == 0)
  let recovered = recover_credit_reservation(path, wrapping, who, selected.operation_id)?
  assert(Bytes.secure_equals(recovered.frame, selected.frame))
  assert(Bytes.secure_equals(recovered.request_body, body))
  let balance = credit_wallet_balance(path, wrapping, who, now)?
  assert(balance.available == 1 && balance.delayed == 1 && balance.reserved == 2)
  # Time and an unknown network outcome never release or select another set.
  let retry = reserve_credit_spend(path,
    wrapping,
    who,
    descriptor,
    body,
    U64.add(now, U64.parse("1000")?)?)?
  assert(Bytes.secure_equals(retry.frame, selected.frame))
  assert(Result.is_err(reserve_credit_spend(path,
    wrapping,
    who,
    action(51, "50331649", body, now)?,
    body,
    now)))
  let before_failure = load_credit_wallet(path, wrapping, who)?
  let larger = body_for(52, 50331649, now)?
  assert(Result.is_err(reserve_credit_spend(path,
    wrapping,
    who,
    action(52, "50331649", larger, now)?,
    larger,
    now)))
  assert(Result.is_err(reserve_credit_spend(path,
    wrapping,
    who,
    action(53, "1", body, now)?,
    body,
    now)))
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == before_failure.wallet.revision)
  # Only the trusted core-result adapter may call this internal local commit.
  complete_credit_reservation(path, wrapping, who, selected.operation_id)?
  complete_credit_reservation(path, wrapping, who, selected.operation_id)?
  let completed = reserve_credit_spend(path, wrapping, who, descriptor, body, now)?
  assert(completed.status == 1 && Bytes.secure_equals(completed.frame, selected.frame))
  let balance = credit_wallet_balance(path, wrapping, who, now)?
  assert(balance.available == 1 && balance.delayed == 1 && balance.reserved == 0)
  let future = credit_wallet_balance(path, wrapping, who, U64.parse("31105000")?)?
  assert(future.available == 0 && future.expired == 2)
  File.delete(path)?
  Ok(true)
end

test("credit reservations survive retries and expiry without reselection or early spending") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
