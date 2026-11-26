from Credits.CreditCrypto import credits_blind_batch, credits_new_inputs
from Credits.CreditFrames import (
  CreditIssueRequest,
  CreditIssueResponse,
  CreditQuote,
  credits_decode_issue_response,
  credits_decode_quote,
  credits_encode_issue_request
)
from Credits.IssuerKey import IssuerKey, credits_epoch_at, credits_key_valid_at
from Mobile.CreditsBuy import (
  CreditPurchase,
  credits_encode_purchase,
  credits_fields,
  credits_find_purchase,
  credits_http_within,
  credits_issuer_origin,
  credits_load_purchases,
  credits_now,
  credits_path,
  credits_purchase_write,
  credits_service_url,
  credits_small,
  credits_state_expired,
  credits_state_issued,
  credits_state_issuing,
  credits_state_operator,
  credits_state_paid,
  credits_state_quoted,
  credits_state_reissue,
  credits_state_unpaid,
  credits_store_writes,
  credits_text
)
from Mobile.CreditsStore import (
  credits_cooldown_ms,
  credits_find_key,
  credits_key_id,
  credits_load_keys,
  credits_load_shelves,
  credits_merge_writes,
  credits_shelve,
  credits_shelves_write
)
from Storage.Keys import platform_key
from Transparency.Codec import tcodec_join, tcodec_u8

##! Mobile.CreditsIssue: collecting a paid quote's tokens (protocol/credits-v1.md
##! "Issuance"). This is the one part of mobile-core that needs a Mesh release
##! with `Crypto.BlindRsa` (Credits.CreditCrypto).
##!
##! Blinding states are affine: they cannot be kept in a list, persisted or
##! handed across the FFI. The whole exchange therefore happens inside this one
##! call: blind a fresh batch, post it to the issuer through the privacy edge,
##! finalize each signature (which verifies it) and seal the tokens, all before
##! returning. A lost answer is retried with the same batch, which the issuer
##! answers from what it stored.
##!
##! While the issuer answers 202 (payment not final yet) it stores nothing, so
##! the call returns at once and the app asks again later with a new batch;
##! nothing long-running holds the core. Before a batch leaves, the purchase
##! is marked `issuing`. If the app dies before the answer is stored, the next
##! call finds it `issuing` and sends a new batch: the issuer signs it if it
##! never saw the first, and answers 409 if it did, which only Morse can sort
##! out (the purchase becomes `operator`: the blinding states that could open
##! the stored signatures died with the app).
##!
##! Outcomes (u8): 1 issued, 2 pending (not paid or not final yet), 3 expired,
##! 4 unpaid (short, late or not this quote's payment: refundable on request),
##! 5 operator, 6 key stale (refresh issuer keys, then ask again), 7 issuer
##! unavailable (try later), 8 interrupted (no answer: ask again), 9 current
##! (a purchase offered for collecting again that the issuer still honours).

fn outcome(code :: Int, value :: CreditPurchase) -> Bytes!String do
  tcodec_join([tcodec_u8(code)?, credits_encode_purchase(value)?])
end

fn settled_outcome(state :: Int) -> Int do
  if state == 4 do
    1
  else if state == 5 do
    3
  else if state == 6 do
    4
  else
    5
  end
end

# The key to blind for: this epoch's (the issuer signs with no other), else
# the key the quote named.

fn issue_key(keys :: List<IssuerKey>, quoted :: Bytes, now :: Int) -> Option<IssuerKey> do
  case List.find(keys,
    fn key -> key.epoch == credits_epoch_at(now) && credits_key_valid_at(key, now) end) do
    Some(key)
    None -> case credits_find_key(keys, quoted) do
      Some(key) -> if credits_key_valid_at(key, now) do
        Some(key)
      else
        None
      end
      None
    end
  end
end

fn retryable(status :: Int) -> Bool do
  status == 500 || status == 502 || status == 504
end

# One CIR through the edge: the same bytes again on no answer or a server
# error that may have come after the issuer stored the batch.

fn post_issue(url :: String, body :: Bytes, attempt :: Int) -> Bytes!String do
  # A 2,000 credit batch is half a megabyte each way: give a slow link a minute.
  let answer = case credits_http_within("POST", url, body, 1048576, 60000) do
    Err(error) -> if attempt < 3 do
      Timer.sleep(1000 * attempt)
      return post_issue(url, body, attempt + 1)
    else
      return Err(error)
    end
    Ok(value) -> value
  end
  if answer.status == 200 do
    Ok(answer.body)
  else if retryable(answer.status) && attempt < 3 do
    Timer.sleep(1000 * attempt)
    post_issue(url, body, attempt + 1)
  else
    Err("credits_issue_status:" <> Int.to_string(answer.status))
  end
end

fn exchange(url :: String,
  quote_id :: Bytes,
  payment :: String,
  key_id :: Bytes,
  blinded :: List<Bytes>) -> List<Bytes>!String do
  let body = credits_encode_issue_request(CreditIssueRequest {
    quote_id: quote_id,
    payment: payment,
    token_key_id: key_id,
    blinded: blinded
  })?
  let answer = case credits_decode_issue_response(post_issue(url, body, 1)?) do
    Err(_) -> Err("credits_issue_invalid")
    Ok(value)
  end?
  if !Bytes.secure_equals(answer.quote_id, quote_id)
    || !Bytes.secure_equals(answer.token_key_id, key_id) do
    Err("credits_issue_invalid")
  else
    Ok(answer.signatures)
  end
end

fn store(path :: String,
  purchases :: List<CreditPurchase>,
  value :: CreditPurchase,
  wrapping_key :: borrow StorageKey) -> Result<(), String> do
  credits_store_writes(path, credits_purchase_write(purchases, value, wrapping_key)?)
end

fn unpaid_state(value :: CreditPurchase) -> Int do
  if value.payment == "" do
    credits_state_quoted()
  else
    credits_state_paid()
  end
end

# What an issuer refusal means for the purchase: (its next state, outcome).

fn refused(error :: String, value :: CreditPurchase, was :: Int) -> (Int, Int) do
  if was == credits_state_reissue() && error == "credits_issue_status:409" do
    # The issuer still stands by the first batch: its key was never revoked.
    (credits_state_issued(), 9)
  else if error == "credits_issue_status:202" do
    (unpaid_state(value), 2)
  else if error == "credits_issue_status:410" || error == "credits_issue_status:404" do
    (credits_state_expired(), 3)
  else if error == "credits_issue_status:402" do
    (credits_state_unpaid(), 4)
  else if error == "credits_issue_status:412" do
    (unpaid_state(value), 6)
  else if error == "credits_network"
    || error == "credits_issue_status:500"
    || error == "credits_issue_status:502"
    || error == "credits_issue_status:504" do
    # No usable answer: the issuer may have signed. The next call finds out.
    (credits_state_issuing(), 8)
  else if error == "credits_issue_status:409"
    || error == "credits_issue_invalid"
    || error == "credit signature does not verify"
    || error == "the issuer answered a different number of signatures" do
    (credits_state_operator(), 5)
  else
    (unpaid_state(value), 7)
  end
end

fn collect(path :: String,
  edge :: String,
  value :: CreditPurchase,
  payment :: String,
  wrapping_key :: borrow StorageKey) -> Bytes!String do
  let quote = credits_decode_quote(value.quote)?
  let now = credits_now()
  let keys = credits_load_keys(path, wrapping_key)?
  let key = case issue_key(keys.keys, quote.token_key_id, now) do
    None -> return Err("credits_keys_needed")
    Some(found) -> found
  end
  let key_id = credits_key_id(key)
  let sending = %{value | state: credits_state_issuing(), payment: payment, updated_at: now}
  # Recorded before anything leaves: a crash from here on is an `issuing` purchase.
  store(path, credits_load_purchases(path, wrapping_key)?, sending, wrapping_key)?
  let url = edge <> "/v1/credits/issue"
  let result = credits_blind_batch(key,
    credits_new_inputs(key, quote.batch)?,
    fn blinded -> exchange(url, quote.quote_id, payment, key_id, blinded) end)
  let purchases = credits_load_purchases(path, wrapping_key)?
  case result do
    Err(error) -> do
      let (state, code) = refused(error, sending, value.state)
      let next = %{sending | state: state, updated_at: credits_now()}
      store(path, purchases, next, wrapping_key)?
      outcome(code, next)
    end
    Ok(tokens) -> do
      let done = %{sending |
        state: credits_state_issued(),
        issued: List.length(tokens),
        key_id: key_id,
        updated_at: credits_now()
      }
      let (shelves, shelf_writes) = credits_shelve(tokens,
        key_id,
        credits_now() + credits_cooldown_ms(),
        false,
        credits_load_shelves(path, wrapping_key)?,
        wrapping_key)?
      credits_store_writes(path,
        credits_merge_writes(credits_merge_writes(shelf_writes,
            credits_shelves_write(shelves, wrapping_key)?),
          credits_purchase_write(purchases, done, wrapping_key)?))?
      outcome(1, done)
    end
  end
end

## Collects a purchase's tokens, or says why not yet. Request: vector32(path)
## || vector32(edge URL) || vector32(purchase id16) || vector32(payment: the
## wallet's transaction signature, base58, or empty). Answer: u8 outcome ||
## the purchase (Mobile.CreditsBuy).

pub fn credits_issue(request :: Bytes) -> Bytes!String do
  let fields = credits_fields(request, 4)?
  let path = credits_path(List.get(fields, 0))?
  let edge = credits_service_url(List.get(fields, 1))?
  let id = List.get(fields, 2)
  let given = credits_text(List.get(fields, 3))?
  credits_issuer_origin()?
  if Bytes.length(id) != 16 || String.length(given) > 128 do
    return Err("invalid_credits_request")
  end
  let wrapping_key = platform_key()?
  let value = credits_find_purchase(credits_load_purchases(path, wrapping_key)?, id)?
  # An `operator` purchase is tried again only when the person asks: after
  # Morse re-opens its quote (credit-issuer reissue), a fresh batch is signed
  # once; until then the issuer answers 409 and it stays `operator`.
  let open = value.state == credits_state_quoted()
    || value.state == credits_state_paid()
    || value.state == credits_state_issuing()
    || value.state == credits_state_reissue()
    || value.state == credits_state_operator()
  if !open do
    outcome(settled_outcome(value.state), value)
  else
    let payment = if given == "" do
      value.payment
    else
      given
    end
    collect(path, edge, value, payment, wrapping_key)
  end
end
