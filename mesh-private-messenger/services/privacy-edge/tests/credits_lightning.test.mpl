from Credits.Lightning import (
  LightningIssueRequest,
  encode_lightning_issue_request,
  decode_lightning_issue_request
)
from Credits.LightningCancellation import LightningCancellation, encode_lightning_cancellation
from Credits.Issuance import credit_batch_hash
from Credits.Wire import CreditTokenRequest
from Credits.Lightning import (
  LightningQuoteRequest,
  LightningQuote,
  SignedLightningQuote,
  encode_lightning_quote_request,
  encode_lightning_quote,
  encode_signed_lightning_quote,
  decode_signed_lightning_quote
)
from Api.Credits import forward_credit

fn query() -> LightningQuoteRequest!String do
  Ok(LightningQuoteRequest {
    credits: 100,
    network: 2,
    purpose: 1,
    issuer_key_id: Bytes.from_hex(String.repeat("11", 32))?,
    batch_hash: Bytes.from_hex(String.repeat("22", 32))?
  })
end

fn quote_body() -> Bytes!String do
  let input = query()?
  let quote = LightningQuote {
    quote_id: Bytes.from_hex(String.repeat("33", 32))?,
    network: 2,
    purpose: 1,
    credits: 100,
    amount_msat: U64.parse("5000000")?,
    issued_at: U64.parse("1792605690")?,
    expires_at: U64.parse("1792606590")?,
    issuer_key_id: input.issuer_key_id,
    batch_hash: input.batch_hash,
    payment_hash: Bytes.from_hex("4a1f7d9811fbfea271b1329eec67b1c852ff1e0e52c4783ae871069a919a7e69")?,
    payee: Bytes.from_hex("03659ee9278803e3667d20d2d081dffc7d6bd6145e4e1bca9fb4a941bfd932dbc2")?,
    invoice: "lnbcrt50u1p4d3l06pp5fg0hmxq3l0l2yud3x20wcea3epf078sw2tz8swhgwyrf4yv60e5sdq4f4hhyum9yp3hyetyd968xcqzzsxqzuysp5xe8fr3fkk2pzgw5nkuy7y8k834jyq0e3e6kpa2vzykfhvaly5sts9qxpqysgqmhy4l6nwn2padyzpmek4hhme5ke5an3g0wasatmllw78wqnhwcjkrsa7zfrff4sttax2gw87lhjvux9wdn7ya0x2caumx57grdkyd9spgyzdct"
  }
  encode_signed_lightning_quote(SignedLightningQuote {
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
    Ok(value) -> encode_lightning_quote_request(value)
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
    Ok(value) -> case decode_signed_lightning_quote(value) do
      Ok(signed) -> encode_lightning_quote(signed.quote)
      Err(error)
    end
    Err(error)
  end
  case body do
    Ok(value) -> HTTP.response_bytes(200, value)
    Err(_) -> HTTP.response(500, "")
  end
end

fn cancellation_reply(request :: Request, field :: Int) -> Response do
  let encoded = cancellation_body(Request.body_bytes(request), field)
  case encoded do
    Ok(value) -> HTTP.response_bytes(200, value)
    Err(_) -> HTTP.response(500, "private diagnostic")
  end
end

fn cancellation_body(body :: Bytes, field :: Int) -> Bytes!String do
  let input = decode_lightning_issue_request(body)?
  let foreign = Bytes.from_hex(String.repeat("ee", 32))?
  encode_lightning_cancellation(LightningCancellation {
    quote_id: if field == 1 do
      foreign
    else
      input.quote_id
    end,
    payment_hash: if field == 2 do
      foreign
    else
      input.payment_hash
    end,
    batch_hash: if field == 3 do
      foreign
    else
      credit_batch_hash(input.requests)?
    end,
    issuer_key_id: Bytes.from_hex(String.repeat("11", 32))?,
    purpose: 1,
    canceled_at: U64.parse("1792605690")?,
    signature: Bytes.from_hex(String.repeat("aa", 64))?
  })
end

actor issuer() do
  HTTP.router()
    |> HTTP.on_post("/internal/v1/credits/lightning/quote", upstream)
    |> HTTP.on_post("/broken/internal/v1/credits/lightning/quote", broken)
    |> HTTP.on_post("/unsigned/internal/v1/credits/lightning/quote", unsigned)
    |> HTTP.on_post("/internal/v1/credits/lightning/issue",
      fn(request) do cancellation_reply(request, 0) end)
    |> HTTP.on_post("/wrong-id/internal/v1/credits/lightning/issue",
      fn(request) do cancellation_reply(request, 1) end)
    |> HTTP.on_post("/wrong-hash/internal/v1/credits/lightning/issue",
      fn(request) do cancellation_reply(request, 2) end)
    |> HTTP.on_post("/wrong-batch/internal/v1/credits/lightning/issue",
      fn(request) do cancellation_reply(request, 3) end)
    |> HTTP.on_post("/broken/internal/v1/credits/lightning/issue", broken)
    |> HTTP.serve(18993)
end

fn proof() -> Bool!String do
  let body = encode_lightning_quote_request(query()?)?
  let token = "0123456789abcdef0123456789abcdef"
  let url = "http://127.0.0.1:18993"
  let value = forward_credit("lightning/quote", body, url, token)?
  assert(value.status == 200)
  assert(Bytes.secure_equals(value.body, quote_body()?))
  assert(forward_credit("lightning/quote", Bytes.empty(), url, token)?.status == 400)
  assert(forward_credit("lightning/quote", body, url, "")?.status == 503)
  assert(forward_credit("lightning/quote", body, url <> "/broken", token)?.status == 502)
  assert(forward_credit("lightning/quote", body, url <> "/unsigned", token)?.status == 502)
  assert(forward_credit("redeem", body, url, token)?.status == 400)
  let issue = encode_lightning_issue_request(LightningIssueRequest {
    quote_id: Bytes.from_hex(String.repeat("33", 32))?,
    payment_hash: Bytes.from_hex(String.repeat("44", 32))?,
    requests: for index in 0..100 do
      CreditTokenRequest {
        truncated_key_id: 85,
        blinded_message: Bytes.concat(Bytes.from_hex(String.repeat("00", 254))?,
          Bytes.write_uint_le(Int.to_string(index + 1), 2)?)?
      }
    end
  })?
  let canceled = forward_credit("lightning/issue", issue, url, token)?
  assert(canceled.status == 200 && Bytes.secure_equals(canceled.body, cancellation_body(issue, 0)?))
  for suffix in ["/wrong-id", "/wrong-hash", "/wrong-batch", "/broken"] do
    let rejected = forward_credit("lightning/issue", issue, url <> suffix, token)?
    assert(rejected.status == 502 && Bytes.length(rejected.body) == 0)
  end
  Ok(true)
end

test("credit edge forwards canonical anonymous Lightning bodies with a separate purchase credential") do
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
