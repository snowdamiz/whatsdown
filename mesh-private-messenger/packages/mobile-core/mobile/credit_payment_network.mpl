from Credits.Issuance import decode_credit_quote
from Credits.Payment import solana_pay_url
from Credits.WalletPayment import authenticate_wallet_payment
from Mobile.CreditPurchase import recover_credit_purchase, record_credit_payment
from Mobile.CreditState import (
  CreditRecord,
  CreditWallet,
  find_credit_record,
  put_credit_record,
  pack_credit_parts,
  unpack_credit_parts
)
from Mobile.Codec import current_time, mobile_byte, mobile_read_u64, mobile_write_u64
from Storage.Credits import (
  CreditWalletIdentity,
  CreditWalletSnapshot,
  load_credit_wallet,
  commit_credit_wallet,
  seal_credit_payload,
  open_credit_payload
)
from Solana.Read import (
  get_latest_blockhash_request,
  latest_blockhash_from_response,
  get_block_height_request,
  block_height_from_response
)
from Solana.TransactionSend import send_transaction_request, sent_signature_from_response
from Transparency.AnchorRpc import validate_anchor_sources, read_anchor_rpc_response

pub struct CreditWalletPaymentPlan do
  purchase_id :: Bytes
  # 0 reserved before RPC, 1 hash reserved before prompt, 2 signed before send,
  # 3 RPC acknowledged. Neither 2 nor 3 claims on-chain finality.
  status :: Int
  quote :: Bytes
  payer :: Bytes
  blockhash :: Bytes
  context_slot :: U64
  last_valid_block_height :: U64
  wire :: Bytes
  signature :: Bytes
end

# Never let a slow signature check or a failed provider attempt carry an
# unsigned/unsent payment across expiry. The supplied time is also a floor,
# preserving a caller's already-observed later clock if wall time moves back.
fn payment_time(observed :: U64) -> U64!String do
  let current = U64.divide(current_time()?, U64.parse("1000")?)?
  Ok(if U64.compare(current, observed) > 0 do
    current
  else
    observed
  end)
end

fn label(id :: Bytes) -> String do
  "wallet-payment/v1/#{Bytes.to_hex(id)}"
end

fn opened(record :: CreditRecord,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  mint :: Bytes) -> CreditWalletPaymentPlan!String do
  if record.kind != 7 || Bytes.length(record.metadata) != 1 do
    return Err("invalid_wallet_payment_record")
  end
  let status = Bytes.get(record.metadata, 0)?
  let parts = unpack_credit_parts(open_credit_payload(record.payload,
      wrapping,
      who,
      label(record.id))?,
    6,
    1232)?
  if status > 3 || List.length(parts) != 6 do
    return Err("invalid_wallet_payment_record")
  end
  let quote = List.get(parts, 0)
  let hash = List.get(parts, 1)
  let slot = mobile_read_u64(List.get(parts, 2))?
  let height = mobile_read_u64(List.get(parts, 3))?
  let wire = List.get(parts, 4)
  let payer = List.get(parts, 5)
  if Bytes.length(payer) != 32 || Bytes.to_hex(payer) == String.repeat("00", 32) do
    return Err("invalid_wallet_payment_payer")
  end
  let decoded = decode_credit_quote(quote)?
  solana_pay_url(decoded, mint, who.purpose, decoded.issued_at)?
  if (status == 0
    && (Bytes.length(hash) != 0 || slot != U64.parse("0")? || height != U64.parse("0")?))
    || (status > 0 && Bytes.length(hash) != 32)
    || (status < 2 && Bytes.length(wire) != 0) do
    return Err("invalid_wallet_payment_record")
  end
  let signature = if status >= 2 do
    let signed = authenticate_wallet_payment(wire, decoded, mint, who.purpose, hash)?
    if !Bytes.secure_equals(List.head(signed.accounts).pubkey.bytes, payer) do
      return Err("wallet_payment_payer_changed")
    end
    signed.signature
  else
    Bytes.empty()
  end
  Ok(CreditWalletPaymentPlan {
    purchase_id: record.id,
    status: status,
    quote: quote,
    payer: payer,
    blockhash: hash,
    context_slot: slot,
    last_valid_block_height: height,
    wire: wire,
    signature: signature
  })
end

fn stored(value :: CreditWalletPaymentPlan,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity) -> CreditRecord!String do
  Ok(CreditRecord {
    kind: 7,
    id: value.purchase_id,
    metadata: mobile_byte(value.status)?,
    payload: seal_credit_payload(pack_credit_parts([
        value.quote,
        value.blockhash,
        mobile_write_u64(value.context_slot)?,
        mobile_write_u64(value.last_valid_block_height)?,
        value.wire,
        value.payer
      ])?,
      wrapping,
      who,
      label(value.purchase_id))?
  })
end

fn save(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  before :: CreditWalletSnapshot,
  value :: CreditWalletPaymentPlan) -> CreditWalletPaymentPlan!String do
  let wallet = put_credit_record(before.wallet, stored(value, wrapping, who)?)
  commit_credit_wallet(path,
    wrapping,
    who,
    before,
    CreditWallet {
      revision: U64.add(before.wallet.revision, U64.parse("1")?)?,
      records: wallet.records
    })?
  Ok(value)
end

pub fn recover_credit_wallet_payment(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  id :: Bytes,
  mint :: Bytes) -> CreditWalletPaymentPlan!String do
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 7, id) do
    None -> return Err("wallet_payment_not_started")
    Some(value) -> value
  end
  let value = opened(record, wrapping, who, mint)?
  let purchase = recover_credit_purchase(path, wrapping, who, id)?
  if !Bytes.secure_equals(purchase.quote, value.quote) do
    return Err("wallet_payment_quote_changed")
  end
  Ok(value)
end

pub fn prepare_credit_wallet_payment(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  id :: Bytes,
  mint :: Bytes,
  endpoints :: List<String>,
  payer :: Bytes,
  now :: U64) -> CreditWalletPaymentPlan!String do
  validate_anchor_sources(endpoints)?
  if Bytes.length(payer) != 32 || Bytes.to_hex(payer) == String.repeat("00", 32) do
    return Err("invalid_wallet_payment_payer")
  end
  let purchase = recover_credit_purchase(path, wrapping, who, id)?
  let before = load_credit_wallet(path, wrapping, who)?
  let current = case find_credit_record(before.wallet, 7, id) do
    Some(record) -> opened(record, wrapping, who, mint)?
    None -> do
      if purchase.stage != 1 do
        return Err("credit_payment_not_pending")
      end
      solana_pay_url(decode_credit_quote(purchase.quote)?, mint, who.purpose, now)?
      save(path,
        wrapping,
        who,
        before,
        CreditWalletPaymentPlan {
          purchase_id: id,
          status: 0,
          quote: purchase.quote,
          payer: payer,
          blockhash: Bytes.empty(),
          context_slot: U64.parse("0")?,
          last_valid_block_height: U64.parse("0")?,
          wire: Bytes.empty(),
          signature: Bytes.empty()
        })?
    end
  end
  if !Bytes.secure_equals(current.quote, purchase.quote) do
    return Err("wallet_payment_quote_changed")
  end
  if current.status >= 2 do
    return Ok(current)
  end
  if !Bytes.secure_equals(current.payer, payer) do
    return Err("wallet_payment_payer_changed")
  end
  solana_pay_url(decode_credit_quote(current.quote)?, mint, who.purpose, now)?
  if purchase.stage != 1 do
    return Err("credit_payment_not_pending")
  end
  let observed_height = if current.status == 1 do
    # A cancelled prompt can leave an unsigned hash after its chain lifetime.
    # Refresh only unsigned plans; signed records returned above never query.
    let raw = read_anchor_rpc_response(List.head(endpoints),
      get_block_height_request(43, "confirmed")?,
      256)?
    let height = block_height_from_response(raw)?.value
    if U64.compare(height, current.last_valid_block_height) <= 0 do
      return Ok(current)
    end
    height
  else
    U64.parse("0")?
  end
  # At most three provider attempts total: height + two latest-hash attempts on
  # unsigned resume, or three latest-hash attempts on initial preparation.
  # Every attempt is bounded to 3 seconds/2048 bytes and follows no redirects.
  let attempts = if current.status == 1 do
    2
  else
    3
  end
  for index in 0..attempts do
    let response = read_anchor_rpc_response(List.get(endpoints, index),
      get_latest_blockhash_request(41, "confirmed")?,
      2048)
    case response do
      Err(_) -> nil
      Ok(raw) -> case latest_blockhash_from_response(raw) do
        Err(_) -> nil
        Ok(hash) -> do
          if current.status == 1
            && (U64.compare(hash.last_valid_block_height, observed_height) <= 0
              || U64.compare(hash.context_slot, current.context_slot) < 0
              || Bytes.secure_equals(hash.blockhash.bytes, current.blockhash)) do
            continue
          end
          let fresh = load_credit_wallet(path, wrapping, who)?
          let previous = case find_credit_record(fresh.wallet, 7, id) do
            None -> return Err("wallet_payment_changed")
            Some(record) -> opened(record, wrapping, who, mint)?
          end
          if previous.status >= 2
            || previous.status != current.status
            || (current.status == 1
              && !Bytes.secure_equals(previous.blockhash, current.blockhash)) do
            return Ok(previous)
          end
          return save(path,
            wrapping,
            who,
            fresh,
            CreditWalletPaymentPlan {
              purchase_id: id,
              status: 1,
              quote: current.quote,
              payer: payer,
              blockhash: hash.blockhash.bytes,
              context_slot: hash.context_slot,
              last_valid_block_height: hash.last_valid_block_height,
              wire: Bytes.empty(),
              signature: Bytes.empty()
            })
        end
      end
    end
  end
  Err("wallet_rpc_unavailable")
end

pub fn commit_credit_wallet_payment(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  id :: Bytes,
  mint :: Bytes,
  wire :: Bytes,
  endpoints :: List<String>,
  now :: U64) -> CreditWalletPaymentPlan!String do
  let current = recover_credit_wallet_payment(path, wrapping, who, id, mint)?
  if current.status >= 2 do
    if !Bytes.secure_equals(current.wire, wire) do
      return Err("wallet_payment_packet_changed")
    end
    return Ok(current)
  end
  if current.status != 1 do
    return Err("wallet_payment_not_prepared")
  end
  let quote = decode_credit_quote(current.quote)?
  # A prompt can outlive the quote. No unsigned plan may cross this boundary
  # after expiry, even if the SDK previously approved it.
  solana_pay_url(quote, mint, who.purpose, now)?
  let signed = authenticate_wallet_payment(wire, quote, mint, who.purpose, current.blockhash)?
  if !Bytes.secure_equals(List.head(signed.accounts).pubkey.bytes, current.payer) do
    return Err("wallet_payment_payer_changed")
  end
  # A foreground prompt may outlive the hash while its quote remains valid.
  # This packet has never been broadcast; leave it unsigned/retryable rather
  # than making a known-dead hash an immutable uncertain payment.
  validate_anchor_sources(endpoints)?
  let height_raw = read_anchor_rpc_response(List.head(endpoints),
    get_block_height_request(43, "confirmed")?,
    256)?
  if U64.compare(block_height_from_response(height_raw)?.value,
    current.last_valid_block_height) > 0 do
    return Err("wallet_payment_blockhash_expired")
  end
  let before = load_credit_wallet(path, wrapping, who)?
  let record = case find_credit_record(before.wallet, 7, id) do
    None -> return Err("wallet_payment_changed")
    Some(value) -> value
  end
  let latest = opened(record, wrapping, who, mint)?
  if latest.status != 1 || !Bytes.secure_equals(latest.blockhash, current.blockhash) do
    return Err("wallet_payment_changed")
  end
  let purchase = recover_credit_purchase(path, wrapping, who, id)?
  if purchase.stage != 1 do
    return Err("credit_payment_not_pending")
  end
  solana_pay_url(quote, mint, who.purpose, payment_time(now)?)?
  save(path,
    wrapping,
    who,
    before,
    CreditWalletPaymentPlan {
      purchase_id: id,
      status: 2,
      quote: current.quote,
      payer: current.payer,
      blockhash: current.blockhash,
      context_slot: current.context_slot,
      last_valid_block_height: current.last_valid_block_height,
      wire: wire,
      signature: signed.signature
    })
end

pub fn submit_credit_wallet_payment(path :: String,
  wrapping :: borrow StorageKey,
  who :: CreditWalletIdentity,
  id :: Bytes,
  mint :: Bytes,
  endpoints :: List<String>,
  now :: U64) -> CreditWalletPaymentPlan!String do
  validate_anchor_sources(endpoints)?
  let current = recover_credit_wallet_payment(path, wrapping, who, id, mint)?
  if current.status < 2 do
    return Err("wallet_payment_signature_required")
  end
  # Persist the exact payment signature in the issuance journal before the
  # first network call. A crash between the two durable records is repaired here.
  let purchase = recover_credit_purchase(path, wrapping, who, id)?
  if purchase.stage == 3 do
    return Ok(current)
  end
  record_credit_payment(path, wrapping, who, id, current.signature, now)?
  # A crash may have preceded the first actual send. Even identical bytes could
  # first execute after the quote window and become uncreditable. After expiry
  # only issuer finality/replay may recover this signature; never broadcast.
  if U64.compare(now, decode_credit_quote(current.quote)?.expires_at) >= 0 do
    return Ok(current)
  end
  for index in 0..3 do
    if U64.compare(payment_time(now)?, decode_credit_quote(current.quote)?.expires_at) >= 0 do
      return Ok(current)
    end
    let response = read_anchor_rpc_response(List.get(endpoints, index),
      send_transaction_request(42, current.wire, current.signature, current.context_slot)?,
      2048)
    case response do
      Err(_) -> nil
      Ok(raw) -> case sent_signature_from_response(raw, current.signature) do
        Err(_) -> nil
        Ok(_) -> do
          let before = load_credit_wallet(path, wrapping, who)?
          let acknowledged = CreditWalletPaymentPlan {
            purchase_id: id,
            status: 3,
            quote: current.quote,
            payer: current.payer,
            blockhash: current.blockhash,
            context_slot: current.context_slot,
            last_valid_block_height: current.last_valid_block_height,
            wire: current.wire,
            signature: current.signature
          }
          # An unrelated concurrent wallet commit can win the CAS. The packet
          # remains immutable; report conservatively journaled and retry later.
          case save(path, wrapping, who, before, acknowledged) do
            Ok(value) -> return Ok(value)
            Err(_) -> return Ok(current)
          end
        end
      end
    end
  end
  # Timeout, wrong ID/signature, RPC error or unavailable transport is an
  # uncertain submission. Keep the exact packet and return its durable signature.
  Ok(current)
end
