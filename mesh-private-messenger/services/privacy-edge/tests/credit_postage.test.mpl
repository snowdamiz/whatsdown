from Api.Postage import prepare_postage, forward_postage, forward_postage_policy
from Credits.PostageBox import SealedPostageBatch, encode_sealed_postage_batch
from Credits.PostagePolicy import PostagePolicy, encode_postage_policy
from Privacy.Edge import (
  RequestStamp,
  SealedDelivery,
  encode_sealed_delivery,
  mint_request_stamp,
  encode_stamped_request,
  verify_request_stamp
)

fn repeated(value :: Int, size :: Int) -> Bytes!String do
  case Bytes.repeat(value, size) do
    Err(_) -> Err("test allocation failed")
    Ok(value)
  end
end

struct StampCandidate do
  stamp :: RequestStamp
  valid :: Bool
end

fn batch() -> Bytes!String do
  let delivery = encode_sealed_delivery(SealedDelivery {
    ephemeral_public_key: repeated(41, 32)?,
    nonce: repeated(42, 12)?,
    ciphertext: repeated(43, 32)?
  })?
  encode_sealed_postage_batch(SealedPostageBatch {
    deliveries: [delivery],
    credit_box: Bytes.concat(Bytes.from_hex("01504342")?, repeated(44, 16432)?)?
  })
end

fn reply() -> Bytes!String do
  Bytes.concat(Bytes.from_hex("01504352")?, repeated(45, 560)?)
end

fn policy() -> Bytes!String do
  encode_postage_policy(PostagePolicy {
    account_id: repeated(51, 32)?,
    publisher_device_id: repeated(52, 16)?,
    revision: U64.parse("1")?,
    expected_device_set_revision: U64.parse("9007199254740993")?,
    credits: 5,
    issued_at_ms: U64.parse("1700000000000")?,
    signature: repeated(53, 64)?
  })
end

fn policy_reply(request :: Request) -> Response do
  if Request.header(request, "authorization") != None
    || Request.header(request, "cookie") != None do
    return HTTP.response(401, "private policy header")
  end
  let expected = case policy() do
    Err(_) -> return HTTP.response(500, "")
    Ok(value) -> value
  end
  if !Bytes.secure_equals(Request.body_bytes(request), expected) do
    return HTTP.response(400, "private policy error")
  end
  HTTP.response_bytes(201,
    case Bytes.from_hex("0020000000000002") do
      Err(_) -> Bytes.empty()
      Ok(value) -> value
    end)
end

fn bad_policy(_request :: Request) -> Response do
  HTTP.response(200, "false")
end

fn limited_policy(_request :: Request) -> Response do
  HTTP.response(429, "private account rate-limit diagnostic")
end

fn oversized(_request :: Request) -> Response do
  HTTP.response_bytes(200,
    case repeated(45, 565) do
      Err(_) -> Bytes.empty()
      Ok(value) -> value
    end)
end

fn answer(request :: Request, status :: Int) -> Response do
  if Request.header(request, "authorization") != Some("Bearer 0123456789abcdef0123456789abcdef")
    || Request.header(request, "cookie") != None
    || Request.header(request, "x-forwarded-for") != None
    || Request.header(request, "x-account-id") != None do
    return HTTP.response(401, "private header diagnostic")
  end
  let expected = case batch() do
    Err(_) -> return HTTP.response(500, "")
    Ok(value) -> value
  end
  if !Bytes.secure_equals(expected, Request.body_bytes(request)) do
    return HTTP.response(400, "private request diagnostic")
  end
  if status == 200 || status == 201 do
    case reply() do
      Err(_) -> HTTP.response(500, "")
      Ok(value) -> HTTP.response_bytes(status, value)
    end
  else
    HTTP.response(status, "private refusal diagnostic")
  end
end

fn fresh(request :: Request) -> Response do
  answer(request, 201)
end

fn retry(request :: Request) -> Response do
  answer(request, 200)
end

fn refused(request :: Request) -> Response do
  answer(request, 429)
end

fn plaintext(_request :: Request) -> Response do
  HTTP.response(200, "CAR must remain encrypted")
end

fn redirect(_request :: Request) -> Response do
  HTTP.response_with_headers(302,
    "private redirect",
    Map.put(Map.new(), "Location", "http://127.0.0.1:18989/internal/credits/postage"))
end

actor core() do
  HTTP.router()
    |> HTTP.on_post("/internal/credits/postage", fresh)
    |> HTTP.on_post("/internal/credits/postage/reconcile", retry)
    |> HTTP.on_post("/refused/internal/credits/postage", refused)
    |> HTTP.on_post("/plain/internal/credits/postage", plaintext)
    |> HTTP.on_post("/redirect/internal/credits/postage", redirect)
    |> HTTP.on_post("/oversized/internal/credits/postage", oversized)
    |> HTTP.on_post("/v1/credits/postage-policy", policy_reply)
    |> HTTP.on_post("/bad/v1/credits/postage-policy", bad_policy)
    |> HTTP.on_post("/limited/v1/credits/postage-policy", limited_policy)
    |> HTTP.serve(18989)
end

fn proof() -> Bool!String do
  let body = batch()?
  let now = U64.parse("1700000000000")?
  let limit = U64.parse("300000")?
  let expiry = U64.add(now, U64.parse("240000")?)?
  let stamp = mint_request_stamp("mesh-msg/v1/work/postage", body, expiry, 1)?
  let encoded = encode_stamped_request(stamp, body)?
  let admitted = prepare_postage(encoded, now, limit, 1, false)
  assert(admitted.status == 200 && Bytes.secure_equals(admitted.body, body))
  assert(prepare_postage(body, now, limit, 1, false).status == 400)
  assert(prepare_postage(encoded, U64.add(expiry, U64.parse("1")?)?, limit, 1, false).status == 429)
  assert(prepare_postage(repeated(0, 541886)?, now, limit, 1, false).status == 400)
  # Choose a valid low-cost stamp that fails the other domain, avoiding a flaky
  # assumption that a randomly mined stamp can never satisfy both difficulty1s.
  let disjoint = List.find(for offset in 0..32 do
      let until = U64.add(expiry, U64.parse(Int.to_string(offset))?)?
      let candidate = mint_request_stamp("mesh-msg/v1/work/postage", body, until, 1)?
      StampCandidate {
        stamp: candidate,
        valid: verify_request_stamp("mesh-msg/v1/work/postage/reconcile",
          body,
          candidate,
          now,
          limit,
          1)?
      }
    end,
    fn(candidate) do !candidate.valid end)
  case disjoint do
    None -> return Err("test needs a stamp valid in only its own domain")
    Some(value) -> do
      assert(prepare_postage(encode_stamped_request(value.stamp, body)?,
        now,
        limit,
        1,
        true).status == 429)
    end
  end
  let recovery_stamp = mint_request_stamp("mesh-msg/v1/work/postage/reconcile", body, expiry, 1)?
  assert(prepare_postage(encode_stamped_request(recovery_stamp, body)?,
    now,
    limit,
    1,
    true).status == 200)
  let malformed = Bytes.from_utf8("plain CAP")
  let malformed_stamp = mint_request_stamp("mesh-msg/v1/work/postage", malformed, expiry, 1)?
  assert(prepare_postage(encode_stamped_request(malformed_stamp, malformed)?,
    now,
    limit,
    1,
    false).status == 400)
  let url = "http://127.0.0.1:18989"
  let token = "0123456789abcdef0123456789abcdef"
  let sent = forward_postage(body, url, token, false)?
  assert(sent.status == 201 && Bytes.secure_equals(sent.body, reply()?))
  assert(forward_postage(body, url, token, true)?.status == 200)
  assert(forward_postage(body, url, "", false)?.status == 503)
  assert(forward_postage(malformed, url, token, false)?.status == 400)
  let refused_reply = forward_postage(body, url <> "/refused", token, false)?
  assert(refused_reply.status == 429 && Bytes.length(refused_reply.body) == 0)
  assert(forward_postage(body, url <> "/plain", token, false)?.status == 502)
  assert(forward_postage(body, url <> "/redirect", token, false)?.status == 502)
  assert(forward_postage(body, url <> "/oversized", token, false)?.status == 502)
  let policy_result = forward_postage_policy(policy()?, url)?
  assert(policy_result.status == 201 && Bytes.to_hex(policy_result.body) == "0020000000000002")
  assert(forward_postage_policy(policy()?, url <> "/bad")?.status == 502)
  let limited = forward_postage_policy(policy()?, url <> "/limited")?
  assert(limited.status == 429 && Bytes.length(limited.body) == 0)
  assert(forward_postage_policy(malformed, url)?.status == 400)
  Ok(true)
end

test("postage edge admits only bounded work-stamped opaque batches and strips private diagnostics") do
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
