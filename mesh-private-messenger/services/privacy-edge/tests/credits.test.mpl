from Credits.QuoteAuth import (
  SignedCreditQuote,
  encode_signed_credit_quote,
  decode_signed_credit_quote
)
from Api.Credits import forward_credit
from Credits.Issuance import (
  CreditQuoteRequest,
  CreditQuote,
  encode_credit_quote_request,
  encode_credit_quote
)

fn query() -> CreditQuoteRequest!String do
  Ok(CreditQuoteRequest {
    credits: 100,
    asset: 0,
    purpose: 1,
    issuer_key_id: Bytes.from_hex(String.repeat("11", 32))?,
    batch_hash: Bytes.from_hex(String.repeat("22", 32))?
  })
end

fn quote_body() -> Bytes!String do
  let input = query()?
  let quote = CreditQuote {
    quote_id: Bytes.from_hex(String.repeat("33", 32))?,
    deposit_owner: Bytes.from_hex(String.repeat("44", 32))?,
    destination: Bytes.from_hex(String.repeat("55", 32))?,
    mint: Bytes.from_hex(String.repeat("66", 32))?,
    asset: 0,
    amount: U64.parse("5000000")?,
    purpose: 1,
    credits: 100,
    issued_at: U64.parse("1700000000")?,
    expires_at: U64.parse("1700000900")?,
    issuer_key_id: input.issuer_key_id,
    batch_hash: input.batch_hash
  }
  encode_signed_credit_quote(SignedCreditQuote {
    quote: quote,
    signature: Bytes.from_hex(String.repeat("aa", 64))?
  })
end

fn upstream(request :: Request) -> Response do
  let authorization = case Request.header(request, "authorization") do
    Some(value) -> value
    None -> ""
  end
  let clean = Request.header(request, "cookie") == None
    && Request.header(request, "x-forwarded-for") == None
    && Request.header(request, "x-account-id") == None
  if authorization != "Bearer 0123456789abcdef0123456789abcdef" || !clean do
    return HTTP.response(401, "private diagnostic")
  end
  let expected = case query() do
    Ok(value) -> encode_credit_quote_request(value)
    Err(error)
  end
  case expected do
    Ok(value) -> if !Bytes.secure_equals(value, Request.body_bytes(request)) do
      return HTTP.response(400, "private diagnostic")
    end
    Err(_) -> return HTTP.response(500, "")
  end
  case quote_body() do
    Ok(value) -> HTTP.response_bytes(200, value)
    Err(_) -> HTTP.response(500, "")
  end
end

fn broken(_request :: Request) -> Response do
  HTTP.response(200, "not a quote")
end

fn unsigned(_request :: Request) -> Response do
  let body = case quote_body() do
    Ok(value) -> case decode_signed_credit_quote(value) do
      Ok(signed) -> encode_credit_quote(signed.quote)
      Err(error)
    end
    Err(error)
  end
  case body do
    Ok(value) -> HTTP.response_bytes(200, value)
    Err(_) -> HTTP.response(500, "")
  end
end

actor issuer() do
  HTTP.router()
    |> HTTP.on_post("/internal/v1/credits/quote", upstream)
    |> HTTP.on_post("/broken/internal/v1/credits/quote", broken)
    |> HTTP.on_post("/unsigned/internal/v1/credits/quote", unsigned)
    |> HTTP.serve(18996)
end

fn proof() -> Bool!String do
  let body = encode_credit_quote_request(query()?)?
  let token = "0123456789abcdef0123456789abcdef"
  let url = "http://127.0.0.1:18996"
  let value = forward_credit("quote", body, url, token)?
  assert(value.status == 200)
  assert(Bytes.secure_equals(value.body, quote_body()?))
  assert(forward_credit("quote", Bytes.empty(), url, token)?.status == 400)
  assert(forward_credit("quote", body, url, "")?.status == 503)
  assert(forward_credit("quote", body, url <> "/broken", token)?.status == 502)
  assert(forward_credit("quote", body, url <> "/unsigned", token)?.status == 502)
  assert(forward_credit("redeem", body, url, token)?.status == 400)
  Ok(true)
end

test("credit edge forwards canonical anonymous bodies with a separate purchase credential") do
  let _server = spawn(issuer)
  Timer.sleep(100)
  let result = proof()
  Process.request_shutdown()
  Timer.sleep(50)
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
