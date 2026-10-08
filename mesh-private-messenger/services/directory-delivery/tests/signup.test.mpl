from Api.Binary import BinaryResult
from Api.Signup import signup_request, signup_work_request
from Credits.CreditFrames import credits_attach, credits_decode_work
from Credits.IssuerKey import credits_epoch_at
from Privacy.Edge import encode_stamped_request, mint_request_stamp, verify_request_stamp
from Tests.CreditsSupport import (
  credits_test_announce,
  credits_test_count,
  credits_test_issuer,
  credits_test_key,
  credits_test_reset,
  credits_test_tokens
)
from Tests.MailboxSupport import test_directory_entry_wire

fn database() -> PoolHandle!String do
  Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    4,
    5000)
end

fn now_ms() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

fn repeated(value :: Int, count :: Int) -> Bytes do
  case Bytes.repeat(value, count) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn base() -> Int do
  6
end

fn label() -> String do
  "mesh-msg/v1/work/register"
end

# A stamp with work for `difficulty` and not for one more bit, so a raised
# requirement is certain to refuse it.

fn stamp_exactly(payload :: Bytes, difficulty :: Int, attempt :: Int) -> Bytes!String do
  let expires = U64.parse(Int.to_string(now_ms() + 200000 + attempt))?
  let stamp = mint_request_stamp(label(), payload, expires, difficulty)?
  let now = U64.parse(Int.to_string(now_ms()))?
  if verify_request_stamp(label(), payload, stamp, now, U64.parse("300000")?, difficulty + 1)? do
    stamp_exactly(payload, difficulty, attempt + 1)
  else
    encode_stamped_request(stamp, payload)
  end
end

fn register(pool :: PoolHandle, body :: Bytes) -> Int do
  signup_request(pool, body, now_ms(), base(), 1, "test").status
end

fn check(label :: String, value :: Bool!String) do
  case value do
    Err(error) -> do
      println("#{label}: #{error}")
      assert(false)
    end
    Ok(passed) -> do
      if !passed do
        println("#{label}: false")
      end
      assert(passed)
    end
  end
end

fn surge() -> Bool!String do
  let pool = database()?
  credits_test_reset(pool)?
  let first = register(pool,
    stamp_exactly(test_directory_entry_wire("surge-one", repeated(71, 32))?, base(), 0)?)
  let second = register(pool,
    stamp_exactly(test_directory_entry_wire("surge-two", repeated(72, 32))?, base(), 0)?)
  let third_entry = test_directory_entry_wire("surge-three", repeated(73, 32))?
  let refused = signup_request(pool,
    stamp_exactly(third_entry, base(), 0)?,
    now_ms(),
    base(),
    1,
    "test")
  let (asked, price) = credits_decode_work(refused.body)?
  let raised = register(pool, stamp_exactly(third_entry, base() + 1, 0)?)
  let work = credits_decode_work(signup_work_request(pool, base(), 1).body)?
  let off = signup_work_request(pool, base(), 0).body
  Pool.close(pool)
  Ok(first == 201
    && second == 201
    && refused.status == 429
    && asked == base() + 1
    && price == 20
    && raised == 201
    && Tuple.first(work) == base() + 2
    && credits_decode_work(off)? == (base(), 20))
end

test("registration work rises a bit per doubling of the sign-up rate over its target") do
  check("surge", surge())
end

fn priority() -> Bool!String do
  let pool = database()?
  credits_test_reset(pool)?
  register(pool,
    stamp_exactly(test_directory_entry_wire("priority-one", repeated(81, 32))?, base(), 0)?)
  register(pool,
    stamp_exactly(test_directory_entry_wire("priority-two", repeated(82, 32))?, base(), 0)?)
  let issuer = credits_test_issuer()?
  let key = credits_test_key(issuer, 2, credits_epoch_at(now_ms()))?
  credits_test_announce(pool, key)?
  let tokens = credits_test_tokens(issuer, key, 20)?
  let short_entry = test_directory_entry_wire("priority-short", repeated(83, 32))?
  let short = register(pool,
    credits_attach(List.drop(tokens, 1), stamp_exactly(short_entry, base(), 0)?)?)
  let spent_after_short = credits_test_count(pool, "credit_spent")?
  let entry = test_directory_entry_wire("priority-paid", repeated(84, 32))?
  let paid = register(pool, credits_attach(tokens, stamp_exactly(entry, base(), 0)?)?)
  let other = test_directory_entry_wire("priority-replay", repeated(85, 32))?
  let replayed = register(pool, credits_attach(tokens, stamp_exactly(other, base(), 0)?)?)
  let spent = credits_test_count(pool, "credit_spent")?
  let accounts = credits_test_count(pool, "messenger_accounts WHERE username LIKE 'priority-%'")?
  Pool.close(pool)
  Ok(short == 402
    && spent_after_short == 0
    && paid == 201
    && replayed == 422
    && spent == 20
    && accounts == 3)
end

test("20 credits register at the pinned base during a surge, and are spent only by a registration") do
  check("priority", priority())
end
