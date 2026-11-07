import File
from Credits.Action import encode_credit_action
from Credits.Cancellation import sign_credit_cancellation, encode_credit_cancellation
from Credits.ActionWire import (
  CreditActionSubmission,
  sign_credit_action_receipt,
  encode_credit_action_receipt
)
from Credits.Signup import (
  CreditSignupRequest,
  CreditSignupResult,
  credit_signup_action,
  encode_credit_signup_request,
  encode_credit_signup_result
)
from Credits.SignupPolicy import sign_credit_signup_policy
from Credits.Issuer import CreditIssuerKey
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Credits.Wire import decode_credit_frame
from Identity.Device import generate_account
from Protocol.IdentityWire import encode_account_identity
from Protocol.DirectoryWire import encode_directory_entry
from Protocol.V1 import DirectoryEntry
from Mobile.CreditState import CreditWallet
from Mobile.CreditWallet import (
  add_credit_issuer,
  completed_credit_record,
  reserve_credit_spend,
  reserve_credit_signup_spend,
  accept_credit_signup_receipt,
  credit_wallet_balance,
  accept_credit_cancellation,
  recover_credit_reservation,
  complete_credit_reservation
)
from Storage.Credits import CreditWalletIdentity, load_credit_wallet, commit_credit_wallet
from Storage.Keys import platform_key
from Tests.Support import database_path, repeated

fn pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test key failed")
    Ok(value)
  end
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let path = database_path("credit_cancellation")?
  let core = pair()?
  let attacker = pair()?
  let now = U64.parse("25921000")?
  let (_account_keys, account) = case generate_account(now, U64.parse("1")?) do
    Err(_) -> return Err("test account failed")
    Ok(value) -> value
  end
  let identity = case encode_account_identity(account) do
    Err(_) -> return Err("test identity failed")
    Ok(value) -> value
  end
  let entry = case encode_directory_entry(DirectoryEntry {
    version: 1,
    username: "native-signup",
    account_identity: identity,
    prekey_bundle: repeated(51, 32)?,
    mailbox_token: repeated(52, 32)?
  }) do
    Err(_) -> return Err("test entry failed")
    Ok(value) -> value
  end
  let who = CreditWalletIdentity {
    account_id: account.account_id,
    device_id: repeated(42, 16)?,
    service_key: core.public_key.bytes,
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
    quote_public_key: core.public_key.bytes
  }
  let purchased = U64.subtract(now, U64.parse("600")?)?
  let before = load_credit_wallet(path, wrapping, who)?
  let base = add_credit_issuer(before.wallet, issuer, now, 1)?
  let tokens = for _index in 0..20 do
    let pending = blind_credit(issuer, who.service_key, purchased)?
    let signature = sign_credit_request(signer, issuer, pending.request)?
    completed_credit_record(finalize_credit(issuer, pending, signature)?,
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
  let request = CreditSignupRequest {
    operation_nonce: repeated(53, 32)?,
    action_expires_at: U64.add(now, U64.parse("300")?)?,
    entry: entry
  }
  let body = encode_credit_signup_request(request)?
  let action = encode_credit_action(credit_signup_action(request)?)?
  let policy = sign_credit_signup_policy(core.private_key, 1, true, 16, 17, now)?
  let forged = sign_credit_signup_policy(attacker.private_key, 1, true, 16, 17, now)?
  assert(Result.is_err(reserve_credit_spend(path, wrapping, who, action, body, now)))
  assert(Result.is_err(reserve_credit_signup_spend(path, wrapping, who, action, body, forged, now)))
  assert(Result.is_err(reserve_credit_signup_spend(path,
    wrapping,
    who,
    action,
    body,
    sign_credit_signup_policy(core.private_key, 0, true, 16, 17, now)?,
    now)))
  assert(Result.is_err(reserve_credit_signup_spend(path,
    wrapping,
    who,
    action,
    body,
    sign_credit_signup_policy(core.private_key, 1, false, 16, 17, now)?,
    now)))
  assert(Result.is_err(reserve_credit_signup_spend(path,
    wrapping,
    who,
    action,
    body,
    sign_credit_signup_policy(core.private_key, 1, true, 16, 16, now)?,
    now)))
  assert(Result.is_err(reserve_credit_signup_spend(path,
    wrapping,
    who,
    action,
    body,
    policy,
    U64.add(now, U64.parse("60")?)?)))
  assert(credit_wallet_balance(path, wrapping, who, now)?.available == 20)
  assert(load_credit_wallet(path, wrapping, who)?.wallet.revision == U64.parse("1")?)
  let reserved = reserve_credit_signup_spend(path, wrapping, who, action, body, policy, now)?
  assert(reserved.credits == 20 && reserved.status == 0)
  let recovered = reserve_credit_signup_spend(path,
    wrapping,
    who,
    action,
    body,
    policy,
    U64.add(now, U64.parse("1000")?)?)?
  assert(Bytes.secure_equals(recovered.frame, reserved.frame))
  let submission = CreditActionSubmission {
    action: credit_signup_action(request)?,
    request_body: body,
    frame: decode_credit_frame(reserved.frame)?
  }
  let cancelled_at = request.action_expires_at
  let cancellation = encode_credit_cancellation(sign_credit_cancellation(core.private_key,
    submission,
    cancelled_at)?)?
  let forged_cancel = encode_credit_cancellation(sign_credit_cancellation(attacker.private_key,
    submission,
    cancelled_at)?)?
  assert(Result.is_err(accept_credit_cancellation(path, wrapping, who, forged_cancel)))
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 20)
  let changed_frame = %{submission.frame | tokens: List.reverse(submission.frame.tokens)}
  let wrong_cancel = encode_credit_cancellation(sign_credit_cancellation(core.private_key,
    %{submission | frame: changed_frame},
    cancelled_at)?)?
  assert(Result.is_err(accept_credit_cancellation(path, wrapping, who, wrong_cancel)))
  let released = accept_credit_cancellation(path, wrapping, who, cancellation)?
  assert(released.status == 2)
  assert(accept_credit_cancellation(path, wrapping, who, cancellation)?.status == 2)
  assert(recover_credit_reservation(path, wrapping, who, released.operation_id)?.status == 2)
  let balance = credit_wallet_balance(path, wrapping, who, now)?
  assert(balance.available == 20 && balance.reserved == 0)
  # A stale completion cannot delete the now-reusable tokens.
  assert(Result.is_err(complete_credit_reservation(path, wrapping, who, released.operation_id)))
  let stale_result = encode_credit_signup_result(CreditSignupResult {
    account_id: who.account_id,
    entry_sha256: Crypto.sha256(entry)
  })?
  let stale_receipt = encode_credit_action_receipt(sign_credit_action_receipt(core.private_key,
    submission,
    repeated(54, 32)?,
    now,
    stale_result)?)?
  assert(Result.is_err(accept_credit_signup_receipt(path, wrapping, who, stale_receipt)))
  let fresh_request = %{request | operation_nonce: repeated(56, 32)?}
  let fresh_body = encode_credit_signup_request(fresh_request)?
  let fresh = reserve_credit_signup_spend(path,
    wrapping,
    who,
    encode_credit_action(credit_signup_action(fresh_request)?)?,
    fresh_body,
    policy,
    now)?
  assert(fresh.status == 0 && fresh.credits == 20)
  # Replaying the saved cancellation cannot unreserve a newer operation.
  assert(accept_credit_cancellation(path, wrapping, who, cancellation)?.status == 2)
  assert(credit_wallet_balance(path, wrapping, who, now)?.reserved == 20)
  File.delete(path)?
  Ok(true)
end

test("only exact signed cancellation releases tokens and stale receipts cannot affect their next reservation") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
