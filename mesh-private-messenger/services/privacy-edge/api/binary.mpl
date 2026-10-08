from Privacy.Edge import (
  decode_stamped_request,
  internal_delivery_authorization,
  sealed_delivery_bytes,
  verify_request_stamp,
  verify_submission
)
from Credits.CreditFrames import credits_quote_work_label
from Privacy.CreditEdge import CreditEdgeResult, credit_edge_paid, credit_edge_submit

pub struct EdgeResult do
  status :: Int
  body :: Bytes
end

fn response(status :: Int, body :: Bytes) -> EdgeResult do
  EdgeResult { status: status, body: body }
end

pub fn prepare_submission(body :: Bytes,
  now :: U64,
  maximum_future :: U64,
  difficulty :: Int) -> EdgeResult do
  case verify_submission(body, now, maximum_future, difficulty) do
    Err(_) -> response(400, Bytes.empty())
    Ok(false) -> response(429, Bytes.empty())
    Ok(true) -> case sealed_delivery_bytes(body) do
      Err(_) -> response(400, Bytes.empty())
      Ok(sealed) -> response(200, sealed)
    end
  end
end

pub fn forward_submission(body :: Bytes,
  internal_url :: String,
  internal_token :: String) -> EdgeResult!String do
  let authorization = internal_delivery_authorization(internal_token)?
  case Http.build(:post, internal_url <> "/internal/v1/envelopes/sealed")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Authorization", authorization)
    |> Http.body_bytes(body)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(1024)
    |> Http.send() do
    Err(_) -> Ok(response(502, Bytes.empty()))
    Ok(forwarded) -> Ok(response(forwarded.status, forwarded.body_bytes))
  end
end

fn post(url :: String,
  authorization :: String,
  body :: Bytes,
  maximum_response :: Int) -> CreditEdgeResult!String do
  let builder = Http.build(:post, url)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(10000)
    |> Http.max_response_bytes(maximum_response)
  let request = if authorization == "" do
    builder
  else
    Http.header(builder, "Authorization", authorization)
  end
  case Http.send(request) do
    Err(error) -> Err("core unreachable: #{error}")
    Ok(answer) -> Ok(CreditEdgeResult { status: answer.status, body: answer.body_bytes })
  end
end

## One envelope submission: PRV as before, or a CRD frame beside or instead of
## the work, redeemed at the core before the sealed delivery goes on as HLD.

pub fn submit_envelope(body :: Bytes,
  now :: U64,
  maximum_future :: U64,
  difficulty :: Int,
  internal_url :: String,
  internal_token :: String) -> EdgeResult!String do
  let authorization = internal_delivery_authorization(internal_token)?
  let result = credit_edge_submit(body,
    now,
    maximum_future,
    difficulty,
    fn request -> post(internal_url <> "/internal/v1/credits/redeem",
      authorization,
      request,
      64) end,
    fn request -> post(internal_url <> "/internal/v1/envelopes/sealed",
      authorization,
      request,
      1024) end)
  Ok(response(result.status, result.body))
end

## A request only credits pay for (longer storage: action 2 to the core's
## /internal/v1/mailbox/retention): CRD ‖ the device-signed request.

pub fn submit_paid(body :: Bytes,
  action :: Int,
  path :: String,
  internal_url :: String,
  internal_token :: String) -> EdgeResult!String do
  let authorization = internal_delivery_authorization(internal_token)?
  let result = credit_edge_paid(body,
    action,
    fn request -> post(internal_url <> "/internal/v1/credits/redeem",
      authorization,
      request,
      64) end,
    fn request -> post(internal_url <> path, authorization, request, 1024) end)
  Ok(response(result.status, result.body))
end

## Credit purchases go through the edge to the issuer, so the issuer never
## sees a buyer's network address: the body only, no client header.

pub fn forward_to_issuer(issuer_url :: String, path :: String, body :: Bytes) -> EdgeResult do
  if issuer_url == "" do
    response(404, Bytes.empty())
  else
    case post(issuer_url <> path, "", body, 1048576) do
      Err(_) -> response(502, Bytes.empty())
      Ok(answer) -> response(answer.status, answer.body)
    end
  end
end

## A quote request must carry proof of work for its own label (PWR around
## CQR): the edge refuses a malformed (400) or unpaid (429) one before the
## issuer is asked, and forwards the whole stamped frame, which the issuer
## checks again and spends once.

pub fn forward_quote(body :: Bytes,
  now :: U64,
  maximum_future :: U64,
  difficulty :: Int,
  issuer_url :: String) -> EdgeResult do
  case decode_stamped_request(body, 6) do
    Err(_) -> response(400, Bytes.empty())
    Ok((stamp, payload)) -> case verify_request_stamp(credits_quote_work_label(),
      payload,
      stamp,
      now,
      maximum_future,
      difficulty) do
      Ok(true) -> forward_to_issuer(issuer_url, "/v1/credits/quote", body)
      Ok(false) -> response(429, Bytes.empty())
      Err(_) -> response(400, Bytes.empty())
    end
  end
end

## Oblivious HTTP relay (RFC 9458; protocol/ohttp-v1.md). An encapsulated
## request goes to the core's gateway as it came, with the edge's bearer and
## no client header; the gateway's answer comes back as it went. The edge
## holds no gateway key, so it sees neither request nor answer, only their
## sizes. At most one HPKE-sealed Binary HTTP message: 7 + 32 + 65,536 + 16
## bytes up, a mebibyte and its framing down.

pub fn relay_ohttp(body :: Bytes,
  internal_url :: String,
  internal_token :: String) -> EdgeResult!String do
  let authorization = internal_delivery_authorization(internal_token)?
  if Bytes.length(body) < 7 + 32 + 16 || Bytes.length(body) > 7 + 32 + 65536 + 16 do
    Ok(response(400, Bytes.empty()))
  else
    case Http.build(:post, internal_url <> "/internal/v1/ohttp")
      |> Http.header("Content-Type", "message/ohttp-req")
      |> Http.header("Authorization", authorization)
      |> Http.body_bytes(body)
      |> Http.timeout(10000)
      |> Http.max_response_bytes(1048576 + 64)
      |> Http.max_redirects(0)
      |> Http.send() do
      Err(_) -> Ok(response(502, Bytes.empty()))
      Ok(answer) -> Ok(response(answer.status, answer.body_bytes))
    end
  end
end
