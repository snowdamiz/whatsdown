from Api.Credits import forward_credit
from Credits.Action import encode_credit_action, credit_action_id
from Credits.ActionWire import (
  CreditActionSubmission,
  CreditActionReceipt,
  encode_credit_action_submission,
  decode_credit_action_submission,
  encode_credit_action_receipt
)
from Credits.Cancellation import (
  CreditCancellation,
  encode_credit_cancellation,
  decode_credit_cancellation
)
from Credits.Signup import (
  CreditSignupRequest,
  CreditSignupResult,
  encode_credit_signup_request,
  decode_credit_signup_request,
  encode_credit_signup_result,
  credit_signup_action
)
from Identity.Device import generate_account
from Protocol.IdentityWire import encode_account_identity
from Protocol.DirectoryWire import encode_directory_entry
from Protocol.V1 import DirectoryEntry
from Credits.SignupPolicy import (
  sign_credit_signup_policy,
  encode_credit_signup_policy,
  decode_credit_signup_policy
)
from Credits.Wire import CreditFrame, CreditToken, CreditTokenInput, encode_credit_frame

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

fn submission() -> CreditActionSubmission!String do
  let (_keys, account) = case generate_account(U64.parse("1000")?, U64.parse("1")?) do
    Err(_) -> return Err("test account failed")
    Ok(value) -> value
  end
  let identity = case encode_account_identity(account) do
    Err(_) -> return Err("test identity failed")
    Ok(value) -> value
  end
  let entry = case encode_directory_entry(DirectoryEntry {
    version: 1,
    username: "edge-signup",
    account_identity: identity,
    prekey_bundle: bytes("11", 32)?,
    mailbox_token: bytes("12", 32)?
  }) do
    Err(_) -> return Err("test entry failed")
    Ok(value) -> value
  end
  let signup = CreditSignupRequest {
    operation_nonce: bytes("22", 32)?,
    action_expires_at: U64.parse("1700000900")?,
    entry: entry
  }
  let body = encode_credit_signup_request(signup)?
  let token = CreditToken {
    input: CreditTokenInput {
      nonce: bytes("44", 32)?,
      challenge_digest: bytes("55", 32)?,
      token_key_id: bytes("66", 32)?
    },
    authenticator: bytes("77", 256)?
  }
  Ok(CreditActionSubmission {
    action: credit_signup_action(signup)?,
    request_body: body,
    frame: CreditFrame { binding: Crypto.sha256(body), tokens: [token] }
  })
end

fn receipt(input :: CreditActionSubmission, wrong_frame :: Bool) -> Bytes!String do
  let result = encode_credit_signup_result(CreditSignupResult {
    account_id: input.action.target,
    entry_sha256: Crypto.sha256(decode_credit_signup_request(input.request_body)?.entry)
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
  HTTP.response(409, "already registered: private diagnostic")
end

fn policy_answer(request :: Request) -> Response do
  if Bytes.length(Request.body_bytes(request)) != 0
    || Request.header(request, "authorization") != None do
    return HTTP.response(400, "private diagnostic")
  end
  let key = case Crypto.signing_generate() do
    Err(_) -> return HTTP.response(503, "private diagnostic")
    Ok(value) -> value
  end
  let output = sign_credit_signup_policy(key.private_key,
    1,
    true,
    16,
    17,
    case U64.parse("1700000000") do
      Ok(value) -> value
      Err(_) -> return HTTP.response(503, "")
    end)
  let encoded = case output do
    Err(error)
    Ok(value) -> encode_credit_signup_policy(value)
  end
  case encoded do
    Err(_) -> HTTP.response(503, "private diagnostic")
    Ok(value) -> HTTP.response_bytes(200, value)
  end
end

fn malformed_policy(_request :: Request) -> Response do
  HTTP.response(200, "not a policy")
end

fn cancellation(request :: Request, wrong_frame :: Bool) -> Response do
  if Request.header(request, "authorization") != None
    || Request.header(request, "cookie") != None do
    return HTTP.response(401, "private diagnostic")
  end
  let input = case decode_credit_action_submission(Request.body_bytes(request)) do
    Err(_) -> return HTTP.response(400, "private diagnostic")
    Ok(value) -> value
  end
  let result = cancellation_wire(input, wrong_frame)
  case result do
    Err(_) -> HTTP.response(503, "private diagnostic")
    Ok(value) -> HTTP.response_bytes(200, value)
  end
end

fn cancellation_wire(input :: CreditActionSubmission, wrong_frame :: Bool) -> Bytes!String do
  encode_credit_cancellation(CreditCancellation {
    operation_id: credit_action_id(input.action)?,
    action_sha256: Crypto.sha256(encode_credit_action(input.action)?),
    frame_sha256: if wrong_frame do
      bytes("88", 32)?
    else
      Crypto.sha256(encode_credit_frame(input.frame)?)
    end,
    cancelled_at: input.action.expires_at,
    signature: bytes("aa", 64)?
  })
end

fn cancelled(request :: Request) -> Response do
  cancellation(request, false)
end

fn wrong_cancellation(request :: Request) -> Response do
  cancellation(request, true)
end

actor core() do
  HTTP.router()
    |> HTTP.on_post("/v1/credits/reconcile", retry)
    |> HTTP.on_post("/cancel/v1/credits/reconcile", cancelled)
    |> HTTP.on_post("/wrong/v1/credits/reconcile", wrong_cancellation)
    |> HTTP.on_post("/denied/v1/credits/reconcile", denied)
    |> HTTP.on_post("/v1/credits/signup", fresh)
    |> HTTP.on_post("/retry/v1/credits/signup", retry)
    |> HTTP.on_post("/different/v1/credits/signup", different)
    |> HTTP.on_post("/denied/v1/credits/signup", denied)
    |> HTTP.on_post("/v1/credits/signup-policy", policy_answer)
    |> HTTP.on_post("/bad/v1/credits/signup-policy", malformed_policy)
    |> HTTP.serve(18991)
end

fn proof() -> Bool!String do
  let input = submission()?
  let body = encode_credit_action_submission(input)?
  let url = "http://127.0.0.1:18991"
  assert(forward_credit("reconcile", body, url, "must-not-forward")?.status == 200)
  let cancel = forward_credit("reconcile", body, url <> "/cancel", "must-not-forward")?
  assert(cancel.status == 200)
  assert(Bytes.secure_equals(decode_credit_cancellation(cancel.body)?.operation_id,
    credit_action_id(input.action)?))
  assert(forward_credit("reconcile", body, url <> "/wrong", "")?.status == 502)
  let refused = forward_credit("reconcile", body, url <> "/denied", "")?
  assert(refused.status == 409 && Bytes.length(refused.body) == 0)
  let policy = forward_credit("signup-policy", Bytes.empty(), url, "must-not-be-forwarded")?
  assert(policy.status == 200)
  assert(decode_credit_signup_policy(policy.body)?.current_difficulty == 17)
  assert(forward_credit("signup-policy", Bytes.empty(), url <> "/bad", "")?.status == 502)
  assert(forward_credit("signup-policy", body, url, "")?.status == 400)
  let value = forward_credit("signup", body, url, "must-not-be-forwarded")?
  assert(value.status == 201)
  assert(Bytes.secure_equals(value.body, receipt(input, false)?))
  assert(forward_credit("signup", body, url <> "/retry", "")?.status == 200)
  assert(forward_credit("signup", body, url <> "/different", "")?.status == 502)
  let refusal = forward_credit("signup", body, url <> "/denied", "")?
  assert(refusal.status == 409)
  assert(Bytes.length(refusal.body) == 0)
  assert(forward_credit("signup", Bytes.empty(), url, "")?.status == 400)
  let mismatched = encode_credit_action_submission(%{input |
    action: %{input.action | operation_nonce: bytes("fe", 32)?}
  })?
  assert(forward_credit("signup", mismatched, url, "")?.status == 400)
  Ok(true)
end

test("priority signup forwards the exact anonymous reservation and only its canonical bound receipt") do
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
