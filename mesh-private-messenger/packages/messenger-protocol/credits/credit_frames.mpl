##! Credit frames (protocol/credits-v1.md). Integers big-endian, vectors carry
##! a u32 length, every frame starts `u8 1 ‖ magic`, and none allows trailing
##! bytes.
##!
##! - CRD `binding32 ‖ u8 count (1–64) ‖ count × token354`, written in front of
##!   the request body it pays for; binding = SHA-256(that body). No token twice.
##! - RDQ `u8 action ‖ vector32(CRD)` and RDR `redemption_id16 ‖ u8 credits`:
##!   the internal redeem route of the directory-delivery core.
##! - CQR `u8 pack ‖ u8 asset`, CQT the issuer's quote.
##! - CIR `quote_id32 ‖ vector32(payment) ‖ token_key_id32 ‖ u16 count ‖
##!   count × blinded256`, CIS `quote_id32 ‖ token_key_id32 ‖ u16 count ‖
##!   count × blind_signature256`; count is the quote's pack size.
##! - HLD `redemption_id16 ‖ vector32(body)`: a request the privacy edge
##!   forwards after redeeming its CRD frame, naming the hold it took.

from Binary.Reader import BinaryReader
from Credits.CreditToken import credits_decode_token, credits_nullifier
from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_start,
  tcodec_take_fixed,
  tcodec_take_u16,
  tcodec_take_u64,
  tcodec_take_u8,
  tcodec_take_vector,
  tcodec_u16,
  tcodec_u64,
  tcodec_u8,
  tcodec_vector
)

pub struct CreditFrame do
  binding :: Bytes
  tokens :: List<Bytes>
end

pub struct CreditRedemption do
  redemption_id :: Bytes
  credits :: Int
end

pub struct CreditQuoteRequest do
  pack :: Int
  asset :: Int
end

pub struct CreditQuote do
  quote_id :: Bytes
  pack :: Int
  asset :: Int
  batch :: Int
  amount :: Int
  expires_at :: Int
  token_key_id :: Bytes
  payment_request :: String
end

pub struct CreditIssueRequest do
  quote_id :: Bytes
  payment :: String
  token_key_id :: Bytes
  blinded :: List<Bytes>
end

pub struct CreditIssueResponse do
  quote_id :: Bytes
  token_key_id :: Bytes
  signatures :: List<Bytes>
end

## The proof-of-work label of a quote request: a quote is a PWR frame around
## CQR, so every quote costs its asker work and allocates nothing for free.

pub fn credits_quote_work_label() -> String do
  "mesh-msg/v1/work/credit-quote"
end

pub fn credits_frame_max() -> Int do
  64
end

## Redeem actions. The core records the action with the hold; what each one
## entitles is the service's business (plan §6.10 extras).

pub fn credits_action_envelope() -> Int do
  1
end

pub fn credits_action_storage() -> Int do
  2
end

pub fn credits_action_signup() -> Int do
  3
end

pub fn credits_action_file() -> Int do
  4
end

## Packs 1, 2, 3: 100, 500 and 2,000 credits.

pub fn credits_pack_size(pack :: Int) -> Int!String do
  case pack do
    1 -> Ok(100)
    2 -> Ok(500)
    3 -> Ok(2000)
    _ -> Err("unknown credit pack")
  end
end

## A pack's price in micro-US dollars (USDC base units): $0.05 a credit.

pub fn credits_pack_price(pack :: Int) -> Int!String do
  Ok(credits_pack_size(pack)? * 50000)
end

## Assets 1 USDC, 2 SOL, 3 BTC (Lightning).

pub fn credits_asset_name(asset :: Int) -> String!String do
  case asset do
    1 -> Ok("usdc")
    2 -> Ok("sol")
    3 -> Ok("btc")
    _ -> Err("unknown credit asset")
  end
end

fn wire(value :: Result<Bytes, String>) -> Bytes!String do
  case value do
    Err(_) -> Err("invalid credits wire")
    Ok(output)
  end
end

fn header(magic :: String) -> Bytes!String do
  tcodec_join([tcodec_u8(1)?, Bytes.from_utf8(magic)])
end

fn distinct(values :: List<Bytes>) -> Bool do
  List.all(values,
    fn value -> List.length(List.filter(values,
      fn other -> Bytes.secure_equals(other, value) end)) == 1 end)
end

fn checked_tokens(tokens :: List<Bytes>) -> List<Bytes>!String do
  if List.length(tokens) < 1 || List.length(tokens) > credits_frame_max() do
    Err("a CRD frame carries 1 to 64 tokens")
  else
    let nullifiers = for token in tokens do
      credits_nullifier(token)?
    end
    if distinct(nullifiers) do
      Ok(nullifiers)
    else
      Err("a CRD frame carries each token once")
    end
  end
end

pub fn credits_encode_frame(binding :: Bytes, tokens :: List<Bytes>) -> Bytes!String do
  checked_tokens(tokens)?
  if Bytes.length(binding) != 32 do
    Err("invalid credit binding")
  else
    tcodec_join([header("CRD")?, binding, tcodec_u8(List.length(tokens))?] ++ tokens)
  end
end

## The nullifiers of a frame's tokens, in frame order.

pub fn credits_frame_nullifiers(frame :: CreditFrame) -> List<Bytes>!String do
  checked_tokens(frame.tokens)
end

fn tokens_from(state :: BinaryReader,
  count :: Int,
  output :: List<Bytes>) -> (BinaryReader, List<Bytes>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let token = tcodec_take_fixed(state, 354)?
    credits_decode_token(token.value)?
    tokens_from(token.state, count, List.append(output, token.value))
  end
end

fn frame_from(input :: Bytes) -> CreditFrame!String do
  let binding = tcodec_take_fixed(tcodec_start(input, 22693, 1, "CRD")?, 32)?
  let count = tcodec_take_u8(binding.state)?
  let (last, tokens) = tokens_from(count.state, count.value, List.new())?
  tcodec_done(last)?
  checked_tokens(tokens)?
  Ok(CreditFrame { binding: binding.value, tokens: tokens })
end

pub fn credits_decode_frame(input :: Bytes) -> CreditFrame!String do
  case frame_from(input) do
    Err(_) -> Err("invalid credits wire")
    Ok(frame)
  end
end

## The request a client sends when it pays with credits: the CRD frame, then
## the body the route takes anyway.

pub fn credits_attach(tokens :: List<Bytes>, body :: Bytes) -> Bytes!String do
  tcodec_join([credits_encode_frame(Crypto.sha256(body), tokens)?, body])
end

fn starts_with_frame(request :: Bytes) -> Bool do
  case (Bytes.slice(request, 0, 4), Bytes.from_hex("01435244")) do
    (Ok(prefix), Ok(magic)) -> Bytes.secure_equals(prefix, magic)
    _ -> false
  end
end

fn split(request :: Bytes) -> (Option<CreditFrame>, Bytes)!String do
  let count = case Bytes.get(request, 36) do
    Err(_) -> Err("invalid credits wire")
    Ok(value)
  end?
  let length = 37 + count * 354
  let frame = credits_decode_frame(wire(Bytes.slice(request, 0, length))?)?
  let body = wire(Bytes.slice(request, length, Bytes.length(request) - length))?
  if Bytes.secure_equals(frame.binding, Crypto.sha256(body)) do
    Ok((Some(frame), body))
  else
    Err("credit binding does not match the request")
  end
end

## Splits a request into its CRD frame (if it starts with one) and the body,
## refusing a frame whose binding is not SHA-256 of the rest.

pub fn credits_detach(request :: Bytes) -> (Option<CreditFrame>, Bytes)!String do
  if starts_with_frame(request) do
    split(request)
  else
    Ok((None, request))
  end
end

fn valid_action(action :: Int) -> Bool do
  action >= credits_action_envelope() && action <= credits_action_file()
end

pub fn credits_encode_redeem(action :: Int, frame :: Bytes) -> Bytes!String do
  credits_decode_frame(frame)?
  if !valid_action(action) do
    Err("unknown credit action")
  else
    tcodec_join([header("RDQ")?, tcodec_u8(action)?, tcodec_vector(frame)?])
  end
end

fn redeem_from(input :: Bytes) -> (Int, CreditFrame)!String do
  let action = tcodec_take_u8(tcodec_start(input, 22702, 1, "RDQ")?)?
  let frame = tcodec_take_vector(action.state, 22693)?
  tcodec_done(frame.state)?
  if !valid_action(action.value) do
    Err("unknown credit action")
  else
    Ok((action.value, credits_decode_frame(frame.value)?))
  end
end

pub fn credits_decode_redeem(input :: Bytes) -> (Int, CreditFrame)!String do
  case redeem_from(input) do
    Err(_) -> Err("invalid credits wire")
    Ok(pair)
  end
end

pub fn credits_encode_redemption(value :: CreditRedemption) -> Bytes!String do
  if Bytes.length(value.redemption_id) != 16
    || value.credits < 1
    || value.credits > credits_frame_max() do
    Err("invalid credit redemption")
  else
    tcodec_join([header("RDR")?, value.redemption_id, tcodec_u8(value.credits)?])
  end
end

fn redemption_from(input :: Bytes) -> CreditRedemption!String do
  let id = tcodec_take_fixed(tcodec_start(input, 21, 1, "RDR")?, 16)?
  let credits = tcodec_take_u8(id.state)?
  tcodec_done(credits.state)?
  if credits.value < 1 || credits.value > credits_frame_max() do
    Err("invalid credit redemption")
  else
    Ok(CreditRedemption { redemption_id: id.value, credits: credits.value })
  end
end

pub fn credits_decode_redemption(input :: Bytes) -> CreditRedemption!String do
  case redemption_from(input) do
    Err(_) -> Err("invalid credits wire")
    Ok(value)
  end
end

fn checked_quote_request(value :: CreditQuoteRequest) -> CreditQuoteRequest!String do
  credits_pack_size(value.pack)?
  credits_asset_name(value.asset)?
  Ok(value)
end

pub fn credits_encode_quote_request(value :: CreditQuoteRequest) -> Bytes!String do
  checked_quote_request(value)?
  tcodec_join([header("CQR")?, tcodec_u8(value.pack)?, tcodec_u8(value.asset)?])
end

fn quote_request_from(input :: Bytes) -> CreditQuoteRequest!String do
  let pack = tcodec_take_u8(tcodec_start(input, 6, 1, "CQR")?)?
  let asset = tcodec_take_u8(pack.state)?
  tcodec_done(asset.state)?
  checked_quote_request(CreditQuoteRequest { pack: pack.value, asset: asset.value })
end

pub fn credits_decode_quote_request(input :: Bytes) -> CreditQuoteRequest!String do
  case quote_request_from(input) do
    Err(_) -> Err("invalid credits wire")
    Ok(value)
  end
end

fn checked_quote(value :: CreditQuote) -> CreditQuote!String do
  checked_quote_request(CreditQuoteRequest { pack: value.pack, asset: value.asset })?
  let text = Bytes.length(Bytes.from_utf8(value.payment_request))
  if Bytes.length(value.quote_id) != 32
    || Bytes.length(value.token_key_id) != 32
    || value.batch != credits_pack_size(value.pack)?
    || value.amount < 1
    || value.expires_at < 0
    || text < 1
    || text > 4096 do
    Err("invalid credit quote")
  else
    Ok(value)
  end
end

pub fn credits_encode_quote(value :: CreditQuote) -> Bytes!String do
  checked_quote(value)?
  tcodec_join([
    header("CQT")?,
    value.quote_id,
    tcodec_u8(value.pack)?,
    tcodec_u8(value.asset)?,
    tcodec_u16(value.batch)?,
    tcodec_u64(value.amount)?,
    tcodec_u64(value.expires_at)?,
    value.token_key_id,
    tcodec_vector(Bytes.from_utf8(value.payment_request))?
  ])
end

fn quote_from(input :: Bytes) -> CreditQuote!String do
  let id = tcodec_take_fixed(tcodec_start(input, 4186, 1, "CQT")?, 32)?
  let pack = tcodec_take_u8(id.state)?
  let asset = tcodec_take_u8(pack.state)?
  let batch = tcodec_take_u16(asset.state)?
  let amount = tcodec_take_u64(batch.state)?
  let expires_at = tcodec_take_u64(amount.state)?
  let key_id = tcodec_take_fixed(expires_at.state, 32)?
  let request = tcodec_take_vector(key_id.state, 4096)?
  tcodec_done(request.state)?
  checked_quote(CreditQuote {
    quote_id: id.value,
    pack: pack.value,
    asset: asset.value,
    batch: batch.value,
    amount: amount.value,
    expires_at: expires_at.value,
    token_key_id: key_id.value,
    payment_request: Bytes.to_utf8(request.value)?
  })
end

pub fn credits_decode_quote(input :: Bytes) -> CreditQuote!String do
  case quote_from(input) do
    Err(_) -> Err("invalid credits wire")
    Ok(value)
  end
end

fn pack_count(count :: Int) -> Bool do
  count == 100 || count == 500 || count == 2000
end

fn checked_blocks(values :: List<Bytes>) -> List<Bytes>!String do
  if pack_count(List.length(values))
    && List.all(values, fn value -> Bytes.length(value) == 256 end) do
    Ok(values)
  else
    Err("a credit batch is a whole pack of 256-byte values")
  end
end

fn blocks_from(state :: BinaryReader,
  count :: Int,
  output :: List<Bytes>) -> (BinaryReader, List<Bytes>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let value = tcodec_take_fixed(state, 256)?
    blocks_from(value.state, count, List.append(output, value.value))
  end
end

fn take_blocks(state :: BinaryReader) -> (BinaryReader, List<Bytes>)!String do
  let count = tcodec_take_u16(state)?
  if !pack_count(count.value) do
    Err("a credit batch is a whole pack")
  else
    blocks_from(count.state, count.value, List.new())
  end
end

fn checked_payment(payment :: String) -> String!String do
  if Bytes.length(Bytes.from_utf8(payment)) > 128 do
    Err("invalid credit payment reference")
  else
    Ok(payment)
  end
end

pub fn credits_encode_issue_request(value :: CreditIssueRequest) -> Bytes!String do
  checked_blocks(value.blinded)?
  checked_payment(value.payment)?
  if Bytes.length(value.quote_id) != 32 || Bytes.length(value.token_key_id) != 32 do
    Err("invalid credit issue request")
  else
    tcodec_join([
      header("CIR")?,
      value.quote_id,
      tcodec_vector(Bytes.from_utf8(value.payment))?,
      value.token_key_id,
      tcodec_u16(List.length(value.blinded))?
    ]
      ++ value.blinded)
  end
end

fn issue_request_from(input :: Bytes) -> CreditIssueRequest!String do
  let id = tcodec_take_fixed(tcodec_start(input, 512202, 1, "CIR")?, 32)?
  let payment = tcodec_take_vector(id.state, 128)?
  let key_id = tcodec_take_fixed(payment.state, 32)?
  let (last, blinded) = take_blocks(key_id.state)?
  tcodec_done(last)?
  Ok(CreditIssueRequest {
    quote_id: id.value,
    payment: checked_payment(Bytes.to_utf8(payment.value)?)?,
    token_key_id: key_id.value,
    blinded: blinded
  })
end

pub fn credits_decode_issue_request(input :: Bytes) -> CreditIssueRequest!String do
  case issue_request_from(input) do
    Err(_) -> Err("invalid credits wire")
    Ok(value)
  end
end

## What the issuer stores with a quote to recognise a resubmission: the key the
## batch was blinded for and the blinded messages in order, not the payment.

pub fn credits_blinded_hash(value :: CreditIssueRequest) -> Bytes!String do
  Ok(Crypto.sha256(tcodec_join([
    Bytes.from_utf8("morse-credits/v1/blinded-batch"),
    value.token_key_id
  ]
    ++ value.blinded)?))
end

pub fn credits_encode_issue_response(value :: CreditIssueResponse) -> Bytes!String do
  checked_blocks(value.signatures)?
  if Bytes.length(value.quote_id) != 32 || Bytes.length(value.token_key_id) != 32 do
    Err("invalid credit issue response")
  else
    tcodec_join([
      header("CIS")?,
      value.quote_id,
      value.token_key_id,
      tcodec_u16(List.length(value.signatures))?
    ]
      ++ value.signatures)
  end
end

fn issue_response_from(input :: Bytes) -> CreditIssueResponse!String do
  let id = tcodec_take_fixed(tcodec_start(input, 512070, 1, "CIS")?, 32)?
  let key_id = tcodec_take_fixed(id.state, 32)?
  let (last, signatures) = take_blocks(key_id.state)?
  tcodec_done(last)?
  Ok(CreditIssueResponse { quote_id: id.value, token_key_id: key_id.value, signatures: signatures })
end

pub fn credits_decode_issue_response(input :: Bytes) -> CreditIssueResponse!String do
  case issue_response_from(input) do
    Err(_) -> Err("invalid credits wire")
    Ok(value)
  end
end

## What the privacy edge forwards to the core after a redemption: the hold it
## took, then the bytes the core acts on (a sealed delivery).

pub fn credits_encode_held(redemption_id :: Bytes, body :: Bytes) -> Bytes!String do
  if Bytes.length(redemption_id) != 16 do
    Err("invalid credit redemption")
  else
    tcodec_join([header("HLD")?, redemption_id, tcodec_vector(body)?])
  end
end

fn held_from(input :: Bytes) -> (Option<Bytes>, Bytes)!String do
  let id = tcodec_take_fixed(tcodec_start(input, 16777216, 1, "HLD")?, 16)?
  let body = tcodec_take_vector(id.state, 16777192)?
  tcodec_done(body.state)?
  Ok((Some(id.value), body.value))
end

## (Some(redemption id), body) for a held request, (None, input) for anything
## that does not start with `u8 1 ‖ "HLD"`.

pub fn credits_decode_held(input :: Bytes) -> (Option<Bytes>, Bytes)!String do
  let tagged = case (Bytes.slice(input, 0, 4), Bytes.from_hex("01484c44")) do
    (Ok(prefix), Ok(magic)) -> Bytes.secure_equals(prefix, magic)
    _ -> false
  end
  if !tagged do
    Ok((None, input))
  else
    case held_from(input) do
      Err(_) -> Err("invalid credits wire")
      Ok(pair)
    end
  end
end

## WRK, the directory's answer about registration work: `u8 1 ‖ "WRK" ‖ u8
## difficulty (the base the stamp must meet now) ‖ u8 credits (the priority
## sign-up price that skips a raised difficulty)`.

pub fn credits_encode_work(difficulty :: Int, credits :: Int) -> Bytes!String do
  if difficulty < 1 || difficulty > 24 || credits < 1 || credits > credits_frame_max() do
    Err("invalid work answer")
  else
    tcodec_join([header("WRK")?, tcodec_u8(difficulty)?, tcodec_u8(credits)?])
  end
end

fn work_from(input :: Bytes) -> (Int, Int)!String do
  let difficulty = tcodec_take_u8(tcodec_start(input, 6, 1, "WRK")?)?
  let credits = tcodec_take_u8(difficulty.state)?
  tcodec_done(credits.state)?
  Ok((difficulty.value, credits.value))
end

## (difficulty, credits).

pub fn credits_decode_work(input :: Bytes) -> (Int, Int)!String do
  case work_from(input) do
    Err(_) -> Err("invalid work answer")
    Ok(pair)
  end
end
