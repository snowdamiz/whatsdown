from Api.Credits import forward_credit
from Credits.Action import encode_credit_action, credit_action_id
from Credits.ActionWire import (
  CreditActionSubmission,
  CreditActionReceipt,
  encode_credit_action_submission,
  decode_credit_action_submission,
  encode_credit_action_receipt
)
from Credits.Retention import (
  CreditRetentionRequest,
  CreditRetentionResult,
  encode_credit_retention_request,
  encode_credit_retention_result,
  credit_retention_action
)
from Credits.Wire import CreditFrame, CreditToken, CreditTokenInput, encode_credit_frame

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

fn submission() -> CreditActionSubmission!String do
  let retention = CreditRetentionRequest {
    mailbox_hash: bytes("11", 32)?,
    operation_nonce: bytes("22", 32)?,
    days: 62,
    action_expires_at: U64.parse("1700000900")?,
    issued_at_ms: U64.parse("1700000000000")?,
    signature: bytes("33", 64)?
  }
  let body = encode_credit_retention_request(retention)?
  let token = CreditToken {
    input: CreditTokenInput {
      nonce: bytes("44", 32)?,
      challenge_digest: bytes("55", 32)?,
      token_key_id: bytes("66", 32)?
    },
    authenticator: bytes("77", 256)?
  }
  Ok(CreditActionSubmission {
    action: credit_retention_action(retention)?,
    request_body: body,
    frame: CreditFrame { binding: Crypto.sha256(body), tokens: [token] }
  })
end

fn receipt(input :: CreditActionSubmission, wrong_frame :: Bool) -> Bytes!String do
  let result = encode_credit_retention_result(CreditRetentionResult {
    mailbox_hash: input.action.target,
    days: 62,
    effective_until_ms: U64.parse("1705356800000")?
  })?
  encode_credit_action_receipt(CreditActionReceipt {
    operation_id: credit_action_id(input.action)?,
    action_sha256: Crypto.sha256(encode_credit_action(input.action)?),
    frame_sha256: if wrong_frame do
      bytes("88", 32)?
    else
      Crypto.sha256(encode_credit_frame(input.frame)?)
    end,
    effect_id: bytes("99", 32)?,
    applied_at: U64.parse("1700000000")?,
    result: result,
    signature: bytes("aa", 64)?
  })
end

fn answer(request :: Request, status :: Int, wrong_frame :: Bool) -> Response do
  if Request.header(request, "authorization") != None
    || Request.header(request, "cookie") != None
    || Request.header(request, "x-forwarded-for") != None do
    return HTTP.response(401, "private diagnostic")
  end
  let result = case decode_credit_action_submission(Request.body_bytes(request)) do
    Ok(value) -> receipt(value, wrong_frame)
    Err(error)
  end
  case result do
    Ok(body) -> HTTP.response_bytes(status, body)
    Err(_) -> HTTP.response(400, "private diagnostic")
  end
end

fn fresh(request :: Request) -> Response do
  answer(request, 201, false)
end

fn retry(request :: Request) -> Response do
  answer(request, 200, false)
end

fn different(request :: Request) -> Response do
  answer(request, 200, true)
end

fn denied(_request :: Request) -> Response do
  HTTP.response(403, "owner mismatch: private diagnostic")
end

actor core() do
  HTTP.router()
    |> HTTP.on_post("/v1/credits/retention", fresh)
    |> HTTP.on_post("/retry/v1/credits/retention", retry)
    |> HTTP.on_post("/different/v1/credits/retention", different)
    |> HTTP.on_post("/denied/v1/credits/retention", denied)
    |> HTTP.serve(18997)
end

fn proof() -> Bool!String do
  let input = submission()?
  let body = encode_credit_action_submission(input)?
  let url = "http://127.0.0.1:18997"
  let value = forward_credit("retention", body, url, "must-not-be-forwarded")?
  assert(value.status == 201)
  assert(Bytes.secure_equals(value.body, receipt(input, false)?))
  assert(forward_credit("retention", body, url <> "/retry", "")?.status == 200)
  assert(forward_credit("retention", body, url <> "/different", "")?.status == 502)
  let refusal = forward_credit("retention", body, url <> "/denied", "")?
  assert(refusal.status == 403)
  assert(Bytes.length(refusal.body) == 0)
  assert(forward_credit("retention", Bytes.empty(), url, "")?.status == 400)
  let mismatched = encode_credit_action_submission(%{input |
    action: %{input.action | quantity: U64.parse("180")?}
  })?
  assert(forward_credit("retention", mismatched, url, "")?.status == 400)
  Ok(true)
end

test("paid retention forwards the exact anonymous reservation and only its canonical bound receipt") do
  let _server = spawn(core)
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
