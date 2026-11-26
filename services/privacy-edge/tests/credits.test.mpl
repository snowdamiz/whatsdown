from Api.Binary import forward_quote, forward_to_issuer, submit_envelope, submit_paid
from Credits.CreditFrames import (
  CreditRedemption,
  credits_attach,
  credits_decode_held,
  credits_decode_redeem,
  credits_encode_redemption
)
from Credits.CreditToken import CreditToken, credits_encode_token
from Privacy.Edge import (
  encode_sealed_delivery,
  encode_stamped_request,
  mint_request_stamp,
  seal_delivery
)
from Credits.CreditFrames import credits_quote_work_label
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import OuterEnvelope

fn repeated(value :: Int, count :: Int) -> Bytes do
  case Bytes.repeat(value, count) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn bearer(request :: Request) -> Bool do
  Request.header(request, "authorization") == Some("Bearer 0123456789abcdef0123456789abcdef")
    || Request.header(request, "Authorization") == Some("Bearer 0123456789abcdef0123456789abcdef")
end

# A core that redeems any well-formed RDQ once per request and accepts a held
# sealed delivery: enough to see what the edge sends where.

fn fake_redeem(request :: Request) -> Response do
  if !bearer(request) do
    HTTP.response(401, "")
  else
    case credits_decode_redeem(Request.body_bytes(request)) do
      Err(_) -> HTTP.response(400, "")
      Ok((action, frame)) -> case credits_encode_redemption(CreditRedemption {
        redemption_id: repeated(action, 16),
        credits: List.length(frame.tokens)
      }) do
        Err(_) -> HTTP.response(500, "")
        Ok(body) -> HTTP.response_bytes(201, body)
      end
    end
  end
end

fn fake_sealed(request :: Request) -> Response do
  if !bearer(request) do
    HTTP.response(401, "")
  else
    case credits_decode_held(Request.body_bytes(request)) do
      Ok((Some(id), _sealed)) -> if Bytes.secure_equals(id, repeated(1, 16)) do
        HTTP.response(202, "")
      else
        HTTP.response(409, "")
      end
      _ -> HTTP.response(400, "")
    end
  end
end

fn fake_quote(request :: Request) -> Response do
  if Request.header(request, "authorization") == None
    && Request.header(request, "x-forwarded-for") == None do
    HTTP.response_bytes(201, Request.body_bytes(request))
  else
    HTTP.response(400, "")
  end
end

fn fake_retention(request :: Request) -> Response do
  case credits_decode_held(Request.body_bytes(request)) do
    Ok((Some(id), frame)) -> if bearer(request)
      && Bytes.secure_equals(id, repeated(2, 16))
      && Bytes.secure_equals(frame, Bytes.from_utf8("MRT")) do
      HTTP.response(201, "")
    else
      HTTP.response(400, "")
    end
    _ -> HTTP.response(400, "")
  end
end

actor fake_core() do
  HTTP.router()
    |> HTTP.on_post("/internal/v1/mailbox/retention", fake_retention)
    |> HTTP.on_post("/internal/v1/credits/redeem", fake_redeem)
    |> HTTP.on_post("/internal/v1/envelopes/sealed", fake_sealed)
    |> HTTP.on_post("/v1/credits/quote", fake_quote)
    |> HTTP.serve(18996)
end

fn sealed() -> Bytes!String do
  let pair = case Crypto.x25519_from_seed(Bytes.from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")?) do
    Err(_) -> Err("key failed")
    Ok(value)
  end?
  let outer = case encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: repeated(1, 16),
    mailbox_token: repeated(2, 32),
    suite: 1,
    expiration: U64.parse("4102444800000")?,
    padding_bucket: 256,
    ciphertext: repeated(3, 32)
  }) do
    Err(_) -> Err("envelope failed")
    Ok(value)
  end?
  encode_sealed_delivery(seal_delivery(outer, pair.public_key)?)
end

fn credited() -> Bool!String do
  let token = credits_encode_token(CreditToken {
    nonce: repeated(9, 32),
    challenge_digest: repeated(2, 32),
    token_key_id: repeated(3, 32),
    authenticator: repeated(4, 256)
  })?
  let result = submit_envelope(credits_attach([token], sealed()?)?,
    U64.parse("1000")?,
    U64.parse("300000")?,
    8,
    "http://127.0.0.1:18996",
    "0123456789abcdef0123456789abcdef")?
  let quote = forward_to_issuer("http://127.0.0.1:18996", "/v1/credits/quote", Bytes.from_utf8("q"))
  let storage = submit_paid(credits_attach([token], Bytes.from_utf8("MRT"))?,
    2,
    "/internal/v1/mailbox/retention",
    "http://127.0.0.1:18996",
    "0123456789abcdef0123456789abcdef")?
  let unpaid = submit_paid(Bytes.from_utf8("MRT"),
    2,
    "/internal/v1/mailbox/retention",
    "http://127.0.0.1:18996",
    "0123456789abcdef0123456789abcdef")?
  let payload = Bytes.from_hex("0143515201")?
  let quote_request = Bytes.concat(payload, Bytes.from_hex("01")?)?
  let stamp = mint_request_stamp(credits_quote_work_label(),
    quote_request,
    U64.parse("200000")?,
    8)?
  let stamped = encode_stamped_request(stamp, quote_request)?
  let now = U64.parse("1000")?
  let window = U64.parse("300000")?
  let paid_quote = forward_quote(stamped, now, window, 8, "http://127.0.0.1:18996")
  let unpaid_quote = forward_quote(stamped, now, window, 24, "http://127.0.0.1:18996")
  let bare_quote = forward_quote(quote_request, now, window, 8, "http://127.0.0.1:18996")
  Ok(result.status == 202
    && paid_quote.status == 201
    && Bytes.secure_equals(paid_quote.body, stamped)
    && unpaid_quote.status == 429
    && bare_quote.status == 400
    && storage.status == 201
    && unpaid.status == 402
    && quote.status == 201
    && Bytes.secure_equals(quote.body, Bytes.from_utf8("q"))
    && forward_to_issuer("", "/v1/credits/quote", Bytes.from_utf8("q")).status == 404)
end

test("the edge redeems at the core with its bearer, then forwards the held delivery") do
  let _server = spawn(fake_core)
  Timer.sleep(100)
  case credited() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
  Process.request_shutdown()
  Timer.sleep(50)
end
