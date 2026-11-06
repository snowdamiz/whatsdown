from Credits.Issuer import CreditIssuerKey
from Credits.Issuance import CreditQuote, decode_credit_quote_request
from Credits.QuoteAuth import sign_credit_quote, encode_signed_credit_quote
from Mobile.CreditState import CreditWallet, CreditRecord, put_credit_record
from Mobile.CreditWallet import add_credit_issuer
from Mobile.CreditPurchase import (
  prepare_credit_purchase,
  prepare_credit_purchase_again,
  recover_credit_purchase,
  accept_credit_quote,
  record_credit_payment
)
from Storage.Credits import CreditWalletIdentity, load_credit_wallet, commit_credit_wallet
from Storage.Keys import platform_key
from Tests.Support import database_path, repeated
import File

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let path = database_path("credit_purchase_again")?
  let who = CreditWalletIdentity {
    account_id: repeated(61, 32)?,
    device_id: repeated(62, 16)?,
    service_key: repeated(63, 32)?,
    purpose: 1
  }
  let secret = case Crypto.blind_rsa_generate() do
    Err(_) -> return Err("key")
    Ok(value) -> value
  end
  let public = case Crypto.blind_rsa_public(secret) do
    Err(_) -> return Err("public")
    Ok(value) -> value
  end
  Secret.destroy(secret)
  let pair = case Crypto.signing_generate() do
    Err(_) -> return Err("quote key")
    Ok(value) -> value
  end
  let issuer = CreditIssuerKey {
    epoch: U64.parse("10")?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: pair.public_key.bytes
  }
  let now = U64.parse("25921000")?
  let before = load_credit_wallet(path, wrapping, who)?
  let admitted = add_credit_issuer(before.wallet, issuer, now, 1)?
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: U64.parse("1")?, records: admitted.records })?
  assert(Result.is_err(prepare_credit_purchase_again(path, wrapping, who, 100, 0, now)))
  let first = prepare_credit_purchase(path, wrapping, who, 100, 0, now)?
  assert(Result.is_err(prepare_credit_purchase_again(path, wrapping, who, 100, 0, now)))
  let request = decode_credit_quote_request(first.quote_request)?
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
  let wire = encode_signed_credit_quote(sign_credit_quote(pair.private_key, quote)?)?
  let accepted = accept_credit_quote(path, wrapping, who, first.purchase_id, wire, now)?
  assert(Result.is_err(prepare_credit_purchase_again(path,
    wrapping,
    who,
    100,
    0,
    U64.subtract(quote.expires_at, U64.parse("1")?)?)))
  let expired = quote.expires_at
  # A signed payment intent blocks replacement even after quote expiry.
  let before_intent = load_credit_wallet(path, wrapping, who)?
  let with_intent = put_credit_record(before_intent.wallet,
    CreditRecord {
      kind: 7,
      id: first.purchase_id,
      metadata: Bytes.from_hex("02")?,
      payload: Bytes.from_utf8("signed")
    })
  commit_credit_wallet(path,
    wrapping,
    who,
    before_intent,
    CreditWallet {
      revision: U64.add(with_intent.revision, U64.parse("1")?)?,
      records: with_intent.records
    })?
  assert(Result.is_err(prepare_credit_purchase_again(path, wrapping, who, 100, 0, expired)))
  let before_remove = load_credit_wallet(path, wrapping, who)?
  let without = put_credit_record(before_remove.wallet,
    CreditRecord {
      kind: 7,
      id: first.purchase_id,
      metadata: Bytes.from_hex("01")?,
      payload: Bytes.from_utf8("unsigned")
    })
  commit_credit_wallet(path,
    wrapping,
    who,
    before_remove,
    CreditWallet {
      revision: U64.add(without.revision, U64.parse("1")?)?,
      records: without.records
    })?
  let retry = prepare_credit_purchase(path, wrapping, who, 100, 0, expired)?
  assert(Bytes.secure_equals(retry.purchase_id, first.purchase_id))
  let next = prepare_credit_purchase_again(path, wrapping, who, 100, 0, expired)?
  assert(!Bytes.secure_equals(next.purchase_id, first.purchase_id))
  assert(!Bytes.secure_equals(next.quote_request, first.quote_request))
  assert(Bytes.secure_equals(recover_credit_purchase(path, wrapping, who, first.purchase_id)?.quote,
    accepted.quote))
  # An external payment broadcast before expiry remains recoverable later.
  let paid = record_credit_payment(path,
    wrapping,
    who,
    first.purchase_id,
    repeated(76, 64)?,
    expired)?
  assert(paid.stage == 2)
  assert(Result.is_err(prepare_credit_purchase_again(path, wrapping, who, 100, 0, expired)))
  File.delete(path)?
  Ok(true)
end

test("explicit buy again preserves expired quotes but never replaces a payment intent") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
