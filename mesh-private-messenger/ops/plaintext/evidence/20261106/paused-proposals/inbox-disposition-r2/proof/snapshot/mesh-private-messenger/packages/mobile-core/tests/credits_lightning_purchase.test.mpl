from Credits.Lightning import (
  sign_lightning_quote,
  encode_signed_lightning_quote,
  LightningQuote,
  decode_lightning_quote_request,
  decode_lightning_issue_request,
  encode_lightning_quote
)
from Credits.LightningCancellation import sign_lightning_cancellation, encode_lightning_cancellation
from Credits.Policy import issuer_epoch
import File
from Credits.Issuer import CreditIssuerKey, issuer_key_id
from Credits.Issuance import (
  CreditIssueResponse,
  encode_credit_issue_response,
  credit_batch_hash
)
from Credits.Token import sign_credit_request
from Mobile.CreditState import CreditWallet
from Mobile.CreditWallet import add_credit_issuer, credit_wallet_balance
from Mobile.CreditPurchase import (
  prepare_credit_purchase,
  prepare_lightning_purchase,
  recover_credit_purchase,
  accept_credit_quote,
  record_credit_payment,
  finalize_credit_purchase
)
from Storage.Credits import CreditWalletIdentity, load_credit_wallet, commit_credit_wallet
from Storage.Keys import platform_key
from Tests.Support import database_path, repeated

fn proof(canceled :: Bool) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let wrapping = platform_key()?
  let path = database_path(if canceled do
    "credit_lightning_canceled"
  else
    "credit_lightning_purchase"
  end)?
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
  let quote_pair = case Crypto.signing_generate() do
    Err(_) -> return Err("test quote key failed")
    Ok(value) -> value
  end
  let now = U64.parse("1792605690")?
  let issuer = CreditIssuerKey {
    epoch: issuer_epoch(now)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: quote_pair.public_key.bytes
  }
  let before = load_credit_wallet(path, wrapping, who)?
  let admitted = add_credit_issuer(before.wallet, issuer, now, who.purpose)?
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: U64.parse("1")?, records: admitted.records })?
  let prepared = prepare_lightning_purchase(path, wrapping, who, 100, 2, now, false)?
  assert(prepared.stage == 0 && prepared.credits == 100 && Bytes.length(prepared.quote) == 0)
  let request = decode_lightning_quote_request(prepared.quote_request)?
  assert(Bytes.secure_equals(request.issuer_key_id, issuer_key_id(issuer)?))
  let reopened = recover_credit_purchase(path, wrapping, who, prepared.purchase_id)?
  let retry = prepare_lightning_purchase(path,
    wrapping,
    who,
    100,
    2,
    U64.add(now, U64.parse("1")?)?,
    false)?
  assert(Bytes.secure_equals(reopened.quote_request, prepared.quote_request))
  assert(Bytes.secure_equals(retry.purchase_id, prepared.purchase_id))
  assert(Result.is_err(prepare_credit_purchase(path, wrapping, who, 500, 0, now)))
  assert(Result.is_err(prepare_lightning_purchase(path, wrapping, who, 100, 1, now, false)))
  let quote = LightningQuote {
    quote_id: repeated(71, 32)?,
    network: 2,
    purpose: 1,
    credits: 100,
    amount_msat: U64.parse("5000000")?,
    issued_at: now,
    expires_at: U64.add(now, U64.parse("900")?)?,
    issuer_key_id: request.issuer_key_id,
    batch_hash: request.batch_hash,
    payment_hash: Bytes.from_hex("4a1f7d9811fbfea271b1329eec67b1c852ff1e0e52c4783ae871069a919a7e69")?,
    payee: Bytes.from_hex("03659ee9278803e3667d20d2d081dffc7d6bd6145e4e1bca9fb4a941bfd932dbc2")?,
    invoice: "lnbcrt50u1p4d3l06pp5fg0hmxq3l0l2yud3x20wcea3epf078sw2tz8swhgwyrf4yv60e5sdq4f4hhyum9yp3hyetyd968xcqzzsxqzuysp5xe8fr3fkk2pzgw5nkuy7y8k834jyq0e3e6kpa2vzykfhvaly5sts9qxpqysgqmhy4l6nwn2padyzpmek4hhme5ke5an3g0wasatmllw78wqnhwcjkrsa7zfrff4sttax2gw87lhjvux9wdn7ya0x2caumx57grdkyd9spgyzdct"
  }
  let foreign = %{quote | batch_hash: repeated(75, 32)?}
  assert(Result.is_err(accept_credit_quote(path,
    wrapping,
    who,
    prepared.purchase_id,
    encode_signed_lightning_quote(sign_lightning_quote(quote_pair.private_key, foreign)?)?,
    now)))
  assert(Result.is_err(accept_credit_quote(path,
    wrapping,
    who,
    prepared.purchase_id,
    encode_lightning_quote(quote)?,
    now)))
  let attacker = case Crypto.signing_generate() do
    Err(_) -> return Err("test attacker key failed")
    Ok(value) -> value
  end
  assert(Result.is_err(accept_credit_quote(path,
    wrapping,
    who,
    prepared.purchase_id,
    encode_signed_lightning_quote(sign_lightning_quote(attacker.private_key, quote)?)?,
    now)))
  let quote_wire = encode_signed_lightning_quote(sign_lightning_quote(quote_pair.private_key,
    quote)?)?
  let quoted = accept_credit_quote(path, wrapping, who, prepared.purchase_id, quote_wire, now)?
  assert(quoted.stage == 1 && quoted.asset == 2)
  assert(Result.is_err(record_credit_payment(path,
    wrapping,
    who,
    prepared.purchase_id,
    repeated(76, 64)?,
    now)))
  assert(Bytes.secure_equals(recover_credit_purchase(path,
      wrapping,
      who,
      prepared.purchase_id)?.quote,
    encode_lightning_quote(quote)?))
  let paid = record_credit_payment(path, wrapping, who, prepared.purchase_id, Bytes.empty(), now)?
  assert(paid.stage == 2)
  let issue = decode_lightning_issue_request(paid.issue_request)?
  assert(Bytes.secure_equals(credit_batch_hash(issue.requests)?, request.batch_hash))
  assert(Bytes.secure_equals(record_credit_payment(path,
      wrapping,
      who,
      prepared.purchase_id,
      Bytes.empty(),
      now)?.issue_request,
    paid.issue_request))
  assert(Result.is_err(record_credit_payment(path,
    wrapping,
    who,
    prepared.purchase_id,
    repeated(77, 64)?,
    now)))
  let cancellation = encode_lightning_cancellation(sign_lightning_cancellation(quote_pair.private_key,
    quote,
    now)?)?
  if canceled do
    let corrupt = encode_lightning_cancellation(sign_lightning_cancellation(attacker.private_key,
      quote,
      now)?)?
    let foreign = encode_lightning_cancellation(sign_lightning_cancellation(quote_pair.private_key,
      %{quote | quote_id: repeated(78, 32)?},
      now)?)?
    let future = encode_lightning_cancellation(sign_lightning_cancellation(quote_pair.private_key,
      quote,
      U64.add(now, U64.parse("1")?)?)?)?
    for invalid in [
      Bytes.empty(),
      corrupt,
      foreign,
      future,
      Bytes.concat(cancellation, repeated(0, 1)?)?
    ] do
      assert(Result.is_err(finalize_credit_purchase(path,
        wrapping,
        who,
        prepared.purchase_id,
        invalid,
        now)))
      assert(recover_credit_purchase(path,
        wrapping,
        who,
        prepared.purchase_id)?.revision == paid.revision)
    end
    let done = finalize_credit_purchase(path,
      wrapping,
      who,
      prepared.purchase_id,
      cancellation,
      now)?
    assert(done.stage == 4 && Bytes.length(done.issue_request) == 0)
    assert(recover_credit_purchase(path, wrapping, who, prepared.purchase_id)?.stage == 4)
    assert(finalize_credit_purchase(path,
      wrapping,
      who,
      prepared.purchase_id,
      cancellation,
      now)?.revision == done.revision)
    assert(Result.is_err(finalize_credit_purchase(path,
      wrapping,
      who,
      prepared.purchase_id,
      corrupt,
      now)))
    assert(Result.is_err(record_credit_payment(path,
      wrapping,
      who,
      prepared.purchase_id,
      Bytes.empty(),
      now)))
    # Even an authenticated outer snapshot cannot relabel the sealed terminal
    # payload as success or restore a live blind request.
    for changed_stage in [1, 2, 3] do
      let original = load_credit_wallet(path, wrapping, who)?
      let changed = for record in original.wallet.records do
        if record.kind == 2 && Bytes.secure_equals(record.id, prepared.purchase_id) do
          %{record |
            metadata: Bytes.concat(repeated(changed_stage, 1)?,
              Bytes.slice(record.metadata, 1, 16)?)?
          }
        else
          record
        end
      end
      commit_credit_wallet(path,
        wrapping,
        who,
        original,
        CreditWallet {
          revision: U64.add(original.wallet.revision, U64.parse("1")?)?,
          records: changed
        })?
      assert(Result.is_err(recover_credit_purchase(path, wrapping, who, prepared.purchase_id)))
      let modified = load_credit_wallet(path, wrapping, who)?
      commit_credit_wallet(path,
        wrapping,
        who,
        modified,
        CreditWallet {
          revision: U64.add(modified.wallet.revision, U64.parse("1")?)?,
          records: original.wallet.records
        })?
    end
    let balance = credit_wallet_balance(path, wrapping, who, now)?
    assert(balance.available == 0 && balance.delayed == 0 && balance.pending_purchases == 0)
    let next = prepare_lightning_purchase(path, wrapping, who, 100, 2, now, false)?
    assert(next.stage == 0 && !Bytes.secure_equals(next.purchase_id, prepared.purchase_id))
    assert(!Bytes.secure_equals(next.quote_request, prepared.quote_request))
    File.delete(path)?
    return Ok(true)
  end
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
  assert(Result.is_err(finalize_credit_purchase(path,
    wrapping,
    who,
    prepared.purchase_id,
    cancellation,
    now)))
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

test("Lightning purchase seals its batch, rejects rail swaps and finalizes without a Solana signature") do
  case proof(false) do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

test("only an authenticated Lightning cancellation releases a pending purchase without minting credits") do
  case proof(true) do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
