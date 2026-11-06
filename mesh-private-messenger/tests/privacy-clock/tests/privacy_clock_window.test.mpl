from MobileCore import privacy_submission_export
from Api.Binary import prepare_submission
from Privacy.Edge import (
  AnonymousAbuseToken,
  PrivacySubmission,
  decode_privacy_submission,
  encode_privacy_submission
)
from Tests.FixtureConfig import install_security_config

# The fixture APK and actual edge both use difficulty 1. The edge's five-minute
# policy is passed to the exact function called by its HTTP handler, unchanged.
fn edge_window() -> U64!String do
  U64.parse("300000")
end

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn now() -> U64!String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test signing key failed")
    Ok(value) -> Ok(value)
  end
end

struct CapturedMint do
  started :: U64
  finished :: U64
  submission :: Bytes
  expires_at :: U64
end

fn captured_mint() -> CapturedMint!String do
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> Err("test delivery key failed")
    Ok(value) -> Ok(value)
  end?
  let service_pair = signing_pair()?
  let witness_a = signing_pair()?
  let witness_b = signing_pair()?
  if !install_security_config(service_pair.public_key.bytes,
    witness_a.public_key.bytes,
    witness_b.public_key.bytes,
    delivery.public_key.bytes,
    1) do
    return Err("test public config failed")
  end
  # Exact public canonical outer fixture retained from privacy_submission.test.
  # No registered mailbox, profile, account, history or authority is created.
  let outer = Bytes.from_hex("014d5347000102030405060708090a0b0c0d0e0f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00010000018bcfe568000000010000000008a0a1a2a3a4a5a6a7")?
  let started = now()?
  let submission = privacy_submission_export(outer)?
  let finished = now()?
  if U64.compare(finished, started) < 0
    || U64.compare(U64.subtract(finished, started)?, wide("58000")?) > 0 do
    return Err("test mint clock capture unsuitable")
  end
  let decoded = decode_privacy_submission(submission)?
  Ok(CapturedMint {
    started: started,
    finished: finished,
    submission: submission,
    expires_at: decoded.token.expires_at
  })
end

fn present_clock_admitted() -> Bool!String do
  let mint = captured_mint()?
  Ok(prepare_submission(mint.submission, mint.finished, edge_window()?, 1).status == 200)
end

fn small_behind_clock_admitted() -> Bool!String do
  let mint = captured_mint()?
  # Service time one second behind captured mint start, so proof/transport
  # elapsed time cannot accidentally erase the tested clock difference.
  let service_now = U64.subtract(mint.started, wide("1000")?)?
  Ok(prepare_submission(mint.submission, service_now, edge_window()?, 1).status == 200)
end

fn outside_policy_refused() -> Bool!String do
  let mint = captured_mint()?
  let expired = U64.add(mint.expires_at, wide("1")?)?
  let too_far_ahead = U64.subtract(mint.expires_at, wide("300001")?)?
  Ok(prepare_submission(mint.submission, expired, edge_window()?, 1).status == 429
    && prepare_submission(mint.submission, too_far_ahead, edge_window()?, 1).status == 429)
end

fn altered_work_refused(submission :: PrivacySubmission,
  service_now :: U64,
  attempt :: Int) -> Bool!String do
  if attempt > 128 do
    return Ok(false)
  end
  let altered = encode_privacy_submission(PrivacySubmission {
    token: AnonymousAbuseToken {
      expires_at: submission.token.expires_at,
      nonce: submission.token.nonce + attempt
    },
    sealed: submission.sealed
  })?
  let answer = prepare_submission(altered, service_now, edge_window()?, 1)
  if answer.status == 429 do
    Ok(true)
  else if answer.status == 200 do
    # A changed nonce can independently satisfy difficulty 1. Search boundedly
    # for one that does not; never mistake a still-valid proof for a bypass.
    altered_work_refused(submission, service_now, attempt + 1)
  else
    Ok(false)
  end
end

fn work_binding_retained() -> Bool!String do
  let mint = captured_mint()?
  altered_work_refused(decode_privacy_submission(mint.submission)?, mint.finished, 1)
end

test("actual native privacy submission is admitted at captured completed clock") do
  case present_clock_admitted() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

test("actual native privacy submission tolerates edge one second behind captured mint start") do
  case small_behind_clock_admitted() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

test("actual edge retains expired and beyond five minute refusal") do
  case outside_policy_refused() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

test("actual edge still refuses altered canonical proof of work") do
  case work_binding_retained() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
