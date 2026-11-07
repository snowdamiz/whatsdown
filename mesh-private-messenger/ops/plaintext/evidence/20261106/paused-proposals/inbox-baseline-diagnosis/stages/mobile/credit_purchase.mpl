from Credits.Lightning import decode_signed_lightning_quote
from Credits.LightningCancellation import (
  decode_lightning_cancellation,
  verify_lightning_cancellation
)
from Credits.Issuer import CreditIssuerKey, issuer_key_id, encode_issuer_key, decode_issuer_key
from Credits.Issuance import decode_credit_issue_response, credit_batch_hash
from Mobile.CreditPurchaseIntent import (
  PurchaseIntent,
  PurchaseQuote,
  decode_purchase_intent,
  encode_purchase_intent,
  verified_purchase_quote,
  purchase_issue_requests,
  encode_purchase_issue,
  matches_purchase_payment
)
from Credits.Policy import credit_pack, issuer_epoch, issuer_epoch_accepted
from Credits.Storage import seal_pending_credit, open_pending_credit
from Credits.Token import blind_credit, finalize_credit
from Credits.Wire import CreditTokenRequest, encode_token_request
from Mobile.CreditState import (
  CreditRecord,
  CreditWallet,
  credit_record_id,
  find_credit_record,
  put_credit_record,
  pack_credit_parts,
  unpack_credit_parts
)
from Mobile.CreditWallet import credit_issuer_keys, completed_credit_record, credit_nullifier_spent
from Mobile.Codec import random_bytes, mobile_byte, mobile_join, mobile_write_u64, mobile_read_u64
from Storage.Credits import (
  CreditWalletIdentity,
  CreditWalletSnapshot,
  credit_context,
  load_credit_wallet,
  commit_credit_wallet,
  seal_credit_payload,
  open_credit_payload
)

pub struct CreditPurchasePlan do
  purchase_id :: Bytes
  # 0 quote request durable, 1 quote durable/payment allowed, 2 issue request
  # durable, 3 completed, 4 authenticated cancellation. Unknown outcomes
  # preserve the same stage and body.
  stage :: Int
  credits :: Int
  asset :: Int
  quote_request :: Bytes
  quote :: Bytes
  issue_request :: Bytes
  revision :: U64
end

struct StoredPurchase do
  issuer :: CreditIssuerKey
  quote_request :: Bytes
  pending :: List<Bytes>
  quote :: Bytes
  issue_request :: Bytes
  # Stage 3 stores the issuance hash; stage 4 stores the signed cancellation.
  # Distinct lengths bind the terminal kind inside the encrypted payload.
  response_hash :: Bytes
end

struct BlindedRecord do
  request :: CreditTokenRequest
  sealed :: Bytes
end

fn verified_quote(value :: StoredPurchase) -> PurchaseQuote!String do
  verified_purchase_quote(value.quote_request, value.quote, value.issuer, None)
end

fn purchase_label(id :: Bytes) -> String do
  "purchase/#{Bytes.to_hex(id)}"
end

fn token_label(id :: Bytes, index :: Int) -> String do
  "#{purchase_label(id)}/pending/#{index}"
end

fn stage(record :: CreditRecord) -> Int!String do
  if record.kind != 2 || !credit_record_id(record.id) || Bytes.length(record.metadata) != 17 do
    return Err("invalid_credit_purchase")
  end
  let value = Bytes.get(record.metadata, 0)?
  if value > 4 do
    Err("invalid_credit_purchase")
  else
    Ok(value)
  end
end

fn open_purchase(record :: CreditRecord,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> StoredPurchase!String do
  let current_stage = stage(record)?
  let parts = unpack_credit_parts(open_credit_payload(record.payload,
      wrapping,
      who,
      purchase_label(record.id))?,
    6,
    3000000)?
  if List.length(parts) != 6 do
    return Err("invalid_credit_purchase")
  end
  let value = StoredPurchase {
    issuer: decode_issuer_key(List.get(parts, 0))?,
    quote_request: List.get(parts, 1),
    pending: unpack_credit_parts(List.get(parts, 2), 2000, 5000)?,
    quote: List.get(parts, 3),
    issue_request: List.get(parts, 4),
    response_hash: List.get(parts, 5)
  }
  let request = decode_purchase_intent(value.quote_request)?
  if value.issuer.purpose != who.purpose
    || request.purpose != who.purpose
    || !Bytes.secure_equals(request.issuer_key_id, issuer_key_id(value.issuer)?)
    || (current_stage < 3 && List.length(value.pending) != request.credits)
    || (current_stage == 3
      && (List.length(value.pending) != 0 || !credit_record_id(value.response_hash)))
    || (current_stage == 4
      && (request.asset != 2
        || List.length(value.pending) != 0
        || Bytes.length(value.response_hash) != 205))
    || (current_stage < 3 && Bytes.length(value.response_hash) != 0)
    || (current_stage == 0 && Bytes.length(value.quote) != 0)
    || (current_stage != 2 && Bytes.length(value.issue_request) != 0) do
    return Err("invalid_credit_purchase")
  end
  if current_stage == 4 do
    let quote = decode_signed_lightning_quote(value.quote)?.quote
    if !verify_lightning_cancellation(decode_lightning_cancellation(value.response_hash)?,
      quote,
      value.issuer)? do
      return Err("invalid_credit_cancellation")
    end
  end
  if current_stage > 0 do
    let quote = verified_quote(value)?
    # Recovery can outlive quote expiry. Admission was time-checked when saved;
    # immutable intent/key/commitment are still checked on every recovery.
    if current_stage == 2 do
      purchase_issue_requests(quote, value.issue_request)?
      nil
    else
      nil
    end
  end
  Ok(value)
end

fn record_purchase(id :: Bytes,
  current_stage :: Int,
  created :: U64,
  completed :: U64,
  value :: StoredPurchase,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> CreditRecord!String do
  let payload = pack_credit_parts([
    encode_issuer_key(value.issuer)?,
    value.quote_request,
    pack_credit_parts(value.pending)?,
    value.quote,
    value.issue_request,
    value.response_hash
  ])?
  Ok(CreditRecord {
    kind: 2,
    id: id,
    metadata: mobile_join([
        mobile_byte(current_stage)?,
        mobile_write_u64(created)?,
        mobile_write_u64(completed)?
      ],
      0,
      Bytes.empty())?,
    payload: seal_credit_payload(payload, wrapping, who, purchase_label(id))?
  })
end

fn plan(record :: CreditRecord,
  value :: StoredPurchase,
  revision :: U64) -> CreditPurchasePlan!String do
  Ok(CreditPurchasePlan {
    purchase_id: record.id,
    stage: stage(record)?,
    credits: decode_purchase_intent(value.quote_request)?.credits,
    asset: decode_purchase_intent(value.quote_request)?.asset,
    quote_request: value.quote_request,
    quote: if Bytes.length(value.quote) == 0 do
      Bytes.empty()
    else
      verified_quote(value)?.wire
    end,
    issue_request: value.issue_request,
    revision: revision
  })
end

fn selected(before :: CreditWalletSnapshot, id :: Bytes) -> CreditRecord!String do
  if !credit_record_id(id) do
    return Err("invalid_credit_purchase_id")
  end
  case find_credit_record(before.wallet, 2, id) do
    None -> Err("credit_purchase_not_found")
    Some(value) -> Ok(value)
  end
end

pub fn recover_credit_purchase(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  id :: Bytes) -> CreditPurchasePlan!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let record = selected(before, id)?
  plan(record, open_purchase(record, wrapping, who)?, before.wallet.revision)
end

pub fn credit_purchase_ids(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> List<Bytes>!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let records = List.filter(before.wallet.records, fn(value) do value.kind == 2 end)
  for record in records do
    stage(record)?
  end
  Ok(for record in records do
    record.id
  end)
end

pub fn prepare_credit_purchase(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  credits :: Int,
  asset :: Int,
  now :: U64) -> CreditPurchasePlan!String do
  prepare_purchase(path, wrapping, who, credits, asset, -1, now, false)
end

# Only an explicit new-purchase action may leave an expired, unpaid quote
# behind. The old sealed batch remains independently recoverable. A reserved
# native wallet payment or recorded external signature always blocks this.
pub fn prepare_credit_purchase_again(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  credits :: Int,
  asset :: Int,
  now :: U64) -> CreditPurchasePlan!String do
  prepare_purchase(path, wrapping, who, credits, asset, -1, now, true)
end

pub fn prepare_lightning_purchase(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  credits :: Int,
  network :: Int,
  now :: U64,
  again :: Bool) -> CreditPurchasePlan!String do
  prepare_purchase(path, wrapping, who, credits, 2, network, now, again)
end

fn payment_signed(wallet :: CreditWallet, id :: Bytes) -> Bool do
  case find_credit_record(wallet, 7, id) do
    None -> false
    Some(value) -> do
      if Bytes.length(value.metadata) != 1 do
        return true
      end
      case Bytes.get(value.metadata, 0) do
        Err(_) -> true
        Ok(stage) -> stage >= 2
      end
    end
  end
end

fn prepare_purchase(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  credits :: Int,
  asset :: Int,
  network :: Int,
  now :: U64,
  again :: Bool) -> CreditPurchasePlan!String do
  credit_pack(credits)?
  if (asset != 0 && asset != 1 && asset != 2)
    || (asset != 2 && network != -1)
    || (asset == 2
      && ((who.purpose == 0 && network != 0)
        || (who.purpose == 1 && (network < 1 || network > 4)))) do
    return Err("invalid_credit_purchase_asset")
  end
  let before = load_credit_wallet(path, wrapping, who)?
  let purchases = List.filter(before.wallet.records, fn(record) do record.kind == 2 end)
  let expired = for record in purchases do
    if stage(record)? < 3 do
      let value = open_purchase(record, wrapping, who)?
      if again do
        if stage(record)? == 1
          && verified_quote(value)?.expires_at <= now
          && !payment_signed(before.wallet, record.id) do
          true
        else
          return Err("credit_purchase_pending")
        end
      else
        let request = decode_purchase_intent(value.quote_request)?
        if request.credits != credits || request.asset != asset || request.network != network do
          return Err("credit_purchase_pending")
        end
        return plan(record, value, before.wallet.revision)
      end
    else
      false
    end
  end
  if again && !List.any(expired, fn(value) do value end) do
    return Err("credit_expired_purchase_required")
  end
  if List.length(purchases) >= 2048
    || List.length(List.filter(before.wallet.records, fn(record) do record.kind == 3 end))
      + credits > 4096 do
    return Err("credit_wallet_capacity")
  end
  let epoch = issuer_epoch(now)?
  let issuer = case List.find(credit_issuer_keys(before.wallet, who.purpose)?,
    fn(key) do key.epoch == epoch end) do
    None -> return Err("credit_issuer_not_ready")
    Some(value) -> value
  end
  let id = random_bytes(32)?
  if !credit_record_id(id) || Option.is_some(find_credit_record(before.wallet, 2, id)) do
    return Err("credit_entropy_unavailable")
  end
  let blinded = for index in 0..credits do
    let pending = blind_credit(issuer, who.service_key, now)?
    let request = pending.request
    BlindedRecord {
      request: request,
      sealed: seal_pending_credit(pending, wrapping, credit_context(who, token_label(id, index))?)?
    }
  end
  let requests = for item in blinded do
    item.request
  end
  let request = encode_purchase_intent(PurchaseIntent {
    credits: credits,
    asset: asset,
    network: network,
    purpose: who.purpose,
    issuer_key_id: issuer_key_id(issuer)?,
    batch_hash: credit_batch_hash(requests)?
  })?
  let value = StoredPurchase {
    issuer: issuer,
    quote_request: request,
    pending: for item in blinded do
      item.sealed
    end,
    quote: Bytes.empty(),
    issue_request: Bytes.empty(),
    response_hash: Bytes.empty()
  }
  let record = record_purchase(id, 0, now, U64.parse("0")?, value, wrapping, who)?
  let wallet = put_credit_record(before.wallet, record)
  let revision = U64.add(wallet.revision, U64.parse("1")?)?
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: revision, records: wallet.records })?
  plan(record, value, revision)
end

fn save_purchase(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  before :: CreditWalletSnapshot,
  record :: CreditRecord,
  value :: StoredPurchase,
  current_stage :: Int) -> CreditPurchasePlan!String do
  let updated = record_purchase(record.id,
    current_stage,
    mobile_read_u64(Bytes.slice(record.metadata, 1, 8)?)?,
    U64.parse("0")?,
    value,
    wrapping,
    who)?
  let wallet = put_credit_record(before.wallet, updated)
  let revision = U64.add(wallet.revision, U64.parse("1")?)?
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: revision, records: wallet.records })?
  plan(updated, value, revision)
end

pub fn accept_credit_quote(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  id :: Bytes,
  response :: Bytes,
  now :: U64) -> CreditPurchasePlan!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let record = selected(before, id)?
  let value = open_purchase(record, wrapping, who)?
  if stage(record)? > 0 do
    if !Bytes.secure_equals(response, value.quote) do
      return Err("credit_quote_changed")
    end
    return plan(record, value, before.wallet.revision)
  end
  verified_purchase_quote(value.quote_request, response, value.issuer, Some(now))?
  save_purchase(path,
    wrapping,
    who,
    before,
    record,
    StoredPurchase {
      issuer: value.issuer,
      quote_request: value.quote_request,
      pending: value.pending,
      quote: response,
      issue_request: Bytes.empty(),
      response_hash: Bytes.empty()
    },
    1)
end

pub fn record_credit_payment(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  id :: Bytes,
  signature :: Bytes,
  now :: U64) -> CreditPurchasePlan!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let record = selected(before, id)?
  let value = open_purchase(record, wrapping, who)?
  if stage(record)? == 2 do
    if !matches_purchase_payment(verified_quote(value)?, value.issue_request, signature)? do
      return Err("credit_payment_changed")
    end
    return plan(record, value, before.wallet.revision)
  end
  if stage(record)? != 1 do
    return Err("credit_quote_required")
  end
  let quote = verified_quote(value)?
  # A payment already broadcast before expiry may be attached/recovered later.
  # The issuer authenticates its on-chain time; local time never claims finality.
  let requests = for index in 0..List.length(value.pending) do
    let pending = open_pending_credit(List.get(value.pending, index),
      wrapping,
      credit_context(who, token_label(id, index))?)?
    let request = pending.request
    Secret.destroy(pending.state)
    request
  end
  let issue = encode_purchase_issue(quote, signature, requests)?
  save_purchase(path,
    wrapping,
    who,
    before,
    record,
    StoredPurchase {
      issuer: value.issuer,
      quote_request: value.quote_request,
      pending: value.pending,
      quote: value.quote,
      issue_request: issue,
      response_hash: Bytes.empty()
    },
    2)
end

pub fn finalize_credit_purchase(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  id :: Bytes,
  response :: Bytes,
  now :: U64) -> CreditPurchasePlan!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let record = selected(before, id)?
  let value = open_purchase(record, wrapping, who)?
  if stage(record)? == 3 || stage(record)? == 4 do
    let proof = if stage(record)? == 3 do
      Crypto.sha256(response)
    else
      response
    end
    if !Bytes.secure_equals(proof, value.response_hash) do
      return Err("credit_issuance_changed")
    end
    return plan(record, value, before.wallet.revision)
  end
  if stage(record)? != 2 do
    return Err("credit_payment_required")
  end
  if Bytes.length(response) == 205 do
    let canceled = decode_lightning_cancellation(response)?
    if decode_purchase_intent(value.quote_request)?.asset != 2 do
      return Err("invalid_credit_cancellation")
    end
    let quote = decode_signed_lightning_quote(value.quote)?.quote
    if !verify_lightning_cancellation(canceled, quote, value.issuer)?
      || U64.compare(canceled.canceled_at, now) > 0 do
      return Err("invalid_credit_cancellation")
    end
    # Recovery may outlive the minting epoch. Cancellation mints no token.
    # The authenticated statement and terminal kind stay sealed together;
    # blind state is retired only by this atomic wallet commit.
    return save_purchase(path,
      wrapping,
      who,
      before,
      record,
      StoredPurchase {
        issuer: value.issuer,
        quote_request: value.quote_request,
        pending: [],
        quote: value.quote,
        issue_request: Bytes.empty(),
        response_hash: response
      },
      4)
  end
  if !issuer_epoch_accepted(value.issuer.epoch, now)? do
    return Err("expired_credit_issuance")
  end
  let issued = decode_credit_issue_response(response)?
  let quote = verified_quote(value)?
  let requests = purchase_issue_requests(quote, value.issue_request)?
  if !Bytes.secure_equals(issued.quote_id, quote.quote_id)
    || !Bytes.secure_equals(issued.batch_hash, quote.batch_hash)
    || List.length(issued.signatures) != quote.credits do
    return Err("credit_issuance_mismatch")
  end
  let records = for index in 0..quote.credits do
    let pending = open_pending_credit(List.get(value.pending, index),
      wrapping,
      credit_context(who, token_label(id, index))?)?
    if !Bytes.secure_equals(encode_token_request(pending.request)?,
      encode_token_request(List.get(requests, index))?) do
      return Err("credit_pending_changed")
    end
    let token = finalize_credit(value.issuer, pending, List.get(issued.signatures, index))?
    let completed = completed_credit_record(token, value.issuer, now, wrapping, who)?
    if Option.is_some(find_credit_record(before.wallet, 3, completed.id))
      || credit_nullifier_spent(before.wallet, completed.id)? do
      return Err("duplicate_credit_token")
    end
    completed
  end
  let identities = for item in records do
    Bytes.to_hex(item.id)
  end
  if Set.size(Set.from_list(identities)) != quote.credits do
    return Err("duplicate_credit_token")
  end
  let done = StoredPurchase {
    issuer: value.issuer,
    quote_request: value.quote_request,
    pending: [],
    quote: value.quote,
    issue_request: Bytes.empty(),
    response_hash: Crypto.sha256(response)
  }
  let marker = record_purchase(id,
    3,
    mobile_read_u64(Bytes.slice(record.metadata, 1, 8)?)?,
    now,
    done,
    wrapping,
    who)?
  let wallet = put_credit_record(before.wallet, marker)
  let revision = U64.add(wallet.revision, U64.parse("1")?)?
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet { revision: revision, records: wallet.records ++ records })?
  plan(marker, done, revision)
end
