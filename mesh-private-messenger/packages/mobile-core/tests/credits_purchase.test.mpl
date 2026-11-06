from Credits.QuoteAuth import sign_credit_quote, encode_signed_credit_quote
import File
from Credits.Issuer import CreditIssuerKey, issuer_key_id
from Credits.Issuance import (
  CreditQuote,
  CreditIssueResponse,
  decode_credit_quote_request,
  decode_credit_issue_request,
  encode_credit_quote,
  encode_credit_issue_response,
  credit_batch_hash
)
from Credits.Token import sign_credit_request
from Mobile.CreditState import CreditWallet
from Mobile.CreditWallet import add_credit_issuer, credit_wallet_balance
from Mobile.CreditPurchase import (
  prepare_credit_purchase,
  recover_credit_purchase,
  accept_credit_quote,
  record_credit_payment,
  finalize_credit_purchase
)
from Storage.Credits import CreditWalletIdentity, load_credit_wallet, commit_credit_wallet
from Storage.Keys import platform_key
from Tests.Support import database_path, repeated

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let path = database_path("credit_purchase")?
  let who = CreditWalletIdentity {
    account_id: repeated(61, 32)?,
    device_id: repeated(62, 16)?,
    service_key: repeated(63, 32)?,
    purpose: 1
  }
  let signing = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("test key failed")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(signing) do
    Err(_) -> return Err("test public key failed")
    Ok(value) -> value
  end
  let quote_pair = case Crypto.signing_generate() do Err(_) -> return Err("test quote key failed") Ok(value) -> value end
  let issuer = CreditIssuerKey { epoch: U64.parse("10")?, purpose: 1, spki: public.bytes, quote_public_key: quote_pair.public_key.bytes }
  let now = U64.parse("25921000")?
  let before = load_credit_wallet(path, wrapping, who)?
  let admitted = add_credit_issuer(before.wallet, issuer, now, who.purpose)?
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: U64.parse("1")?, records: admitted.records })?
  let prepared = prepare_credit_purchase(path, wrapping, who, 100, 0, now)?
  assert(prepared.stage == 0 && prepared.credits == 100 && Bytes.length(prepared.quote) == 0)
  let request = decode_credit_quote_request(prepared.quote_request)?
  assert(Bytes.secure_equals(request.issuer_key_id, issuer_key_id(issuer)?))
  let reopened = recover_credit_purchase(path, wrapping, who, prepared.purchase_id)?
  let retry = prepare_credit_purchase(path, wrapping, who, 100, 0, U64.add(now, U64.parse("1")?)?)?
  assert(Bytes.secure_equals(reopened.quote_request, prepared.quote_request))
  assert(Bytes.secure_equals(retry.purchase_id, prepared.purchase_id))
  assert(Result.is_err(prepare_credit_purchase(path, wrapping, who, 500, 0, now)))
  let quote = CreditQuote {
    quote_id: repeated(71, 32)?,
    deposit_owner: repeated(72, 32)?,
    destination: repeated(73, 32)?,
    mint: repeated(74, 32)?,
    asset: 0,
    amount: U64.parse("5000000")?,
    purpose: 1,
    credits: 100,
    issued_at: now,
    expires_at: U64.add(now, U64.parse("900")?)?,
    issuer_key_id: request.issuer_key_id,
    batch_hash: request.batch_hash
  }
  let foreign = CreditQuote {
    quote_id: quote.quote_id,
    deposit_owner: quote.deposit_owner,
    destination: quote.destination,
    mint: quote.mint,
    asset: quote.asset,
    amount: quote.amount,
    purpose: quote.purpose,
    credits: quote.credits,
    issued_at: quote.issued_at,
    expires_at: quote.expires_at,
    issuer_key_id: quote.issuer_key_id,
    batch_hash: repeated(75, 32)?
  }
  assert(Result.is_err(accept_credit_quote(path,
    wrapping,
    who,
    prepared.purchase_id,
    encode_signed_credit_quote(sign_credit_quote(quote_pair.private_key, foreign)?)?,
    now)))
  assert(Result.is_err(accept_credit_quote(path, wrapping, who, prepared.purchase_id, encode_credit_quote(quote)?, now)))
  let attacker = case Crypto.signing_generate() do Err(_) -> return Err("test attacker key failed") Ok(value) -> value end
  assert(Result.is_err(accept_credit_quote(path, wrapping, who, prepared.purchase_id,
    encode_signed_credit_quote(sign_credit_quote(attacker.private_key, quote)?)?, now)))
  let quote_wire = encode_signed_credit_quote(sign_credit_quote(quote_pair.private_key, quote)?)?
  let quoted = accept_credit_quote(path,
    wrapping,
    who,
    prepared.purchase_id,
    quote_wire,
    now)?
  assert(quoted.stage == 1)
  assert(Bytes.secure_equals(recover_credit_purchase(path, wrapping, who, prepared.purchase_id)?.quote, encode_credit_quote(quote)?))
  let paid = record_credit_payment(path,
    wrapping,
    who,
    prepared.purchase_id,
    repeated(76, 64)?,
    now)?
  assert(paid.stage == 2)
  let issue = decode_credit_issue_request(paid.issue_request)?
  assert(Bytes.secure_equals(credit_batch_hash(issue.requests)?, request.batch_hash))
  assert(Bytes.secure_equals(record_credit_payment(path,
      wrapping,
      who,
      prepared.purchase_id,
      repeated(76, 64)?,
      now)?.issue_request,
    paid.issue_request))
  assert(Result.is_err(record_credit_payment(path,
    wrapping,
    who,
    prepared.purchase_id,
    repeated(77, 64)?,
    now)))
  let signatures = for item in issue.requests do
    sign_credit_request(signing, issuer, item)?
  end
  let response = encode_credit_issue_response(CreditIssueResponse {
    quote_id: issue.quote_id,
    batch_hash: request.batch_hash,
    signatures: signatures
  })?
  let bad = encode_credit_issue_response(CreditIssueResponse {
    quote_id: issue.quote_id,
    batch_hash: request.batch_hash,
    signatures: [repeated(0, 256)?] ++ List.drop(signatures, 1)
  })?
  assert(Result.is_err(finalize_credit_purchase(path,
    wrapping,
    who,
    prepared.purchase_id,
    bad,
    now)))
  assert(recover_credit_purchase(path, wrapping, who, prepared.purchase_id)?.stage == 2)
  let done = finalize_credit_purchase(path, wrapping, who, prepared.purchase_id, response, now)?
  assert(done.stage == 3 && Bytes.length(done.issue_request) == 0)
  assert(finalize_credit_purchase(path,
    wrapping,
    who,
    prepared.purchase_id,
    response,
    U64.add(now, U64.parse("700")?)?)?.revision == done.revision)
  assert(Result.is_err(finalize_credit_purchase(path,
    wrapping,
    who,
    prepared.purchase_id,
    bad,
    now)))
  let early = credit_wallet_balance(path, wrapping, who, U64.add(now, U64.parse("599")?)?)?
  let ready = credit_wallet_balance(path, wrapping, who, U64.add(now, U64.parse("600")?)?)?
  assert(early.available == 0 && early.delayed == 100 && early.pending_purchases == 0)
  assert(ready.available == 100 && ready.delayed == 0)
  File.delete(path)?
  Ok(true)
end

test("credit purchase commits its blinded batch before quote and atomically recovers issuance") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
