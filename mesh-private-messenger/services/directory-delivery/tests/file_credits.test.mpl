from Api.Binary import BinaryResult
from Api.CreditRoutes import credits_redeem_request
from Credits.CreditFrames import credits_attach
from Credits.IssuerKey import credits_epoch_at
from Objects.CreditGrant import object_grant_entitle, object_grant_split
from Objects.Grant import encode_grant, mint_grant
from Privacy.CreditEdge import CreditEdgeResult
from Tests.CreditsSupport import (
  credits_test_announce,
  credits_test_count,
  credits_test_issuer,
  credits_test_key,
  credits_test_reset,
  credits_test_tokens
)

# Files over 16 MiB (credits-v1.md "Large files"): the object store's grant path
# against the core itself, exactly as the store runs it over HTTP, with tokens
# of a test issuer key announced into the log.

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

fn grant_for(parts :: Int) -> Bytes!String do
  let random = case Crypto.random_bytes(96) do
    Err(_) -> Err("random bytes failed")
    Ok(value)
  end?
  encode_grant(mint_grant(Bytes.slice(random, 0, 32)?,
    parts,
    U64.parse(Int.to_string(now_ms() + 86400000))?,
    U64.parse(Int.to_string(now_ms() + 60000))?,
    Bytes.slice(random, 32, 32)?,
    Bytes.slice(random, 64, 32)?,
    1)?)
end

fn store_grant(pool :: PoolHandle, request :: Bytes, parts :: Int) -> Int!String do
  let (frame, _) = object_grant_split(request)?
  Ok(object_grant_entitle(frame,
    parts,
    fn(body) do
      let answer = credits_redeem_request(pool, "test", body, now_ms())
      Ok(CreditEdgeResult { status: answer.status, body: answer.body })
    end))
end

fn file_credits_total(pool :: PoolHandle) -> Int!String do
  let rows = Pool.query_values(pool,
    "SELECT coalesce(sum(credits), 0)::text AS value FROM credit_spend_totals WHERE action = 4",
    [])?
  case rows do
    [row] -> case Map.get(row, "value") do
      Text(value) -> case String.to_int(value) do
        Some(parsed) -> Ok(parsed)
        None -> Err("total failed")
      end
      _ -> Err("total failed")
    end
    _ -> Err("total failed")
  end
end

fn check(label :: String, value :: Bool, failures :: List<String>) -> List<String> do
  if value do
    failures
  else
    List.append(failures, label)
  end
end

# A 20 MiB grant spends 1 credit and a 40 MiB grant 2. A frame is spent whole
# and once: the same frame again, or one holding a spent token, is refused and
# spends nothing new; a short frame and a free grant never reach the spent set;
# tokens of an unannounced key are not credits.

fn large_files() -> List<String>!String do
  let pool = database()?
  credits_test_reset(pool)?
  let before = file_credits_total(pool)?
  let issuer = credits_test_issuer()?
  let key = credits_test_key(issuer, 2, credits_epoch_at(now_ms()))?
  credits_test_announce(pool, key)?
  let tokens = credits_test_tokens(issuer, key, 3)?
  let stranger = credits_test_issuer()?
  let forged = credits_test_tokens(stranger,
    credits_test_key(stranger, 2, credits_epoch_at(now_ms()))?,
    1)?
  let first = List.get(tokens, 0)
  let second = List.get(tokens, 1)
  let third = List.get(tokens, 2)
  let twenty = grant_for(321)?
  let forty = grant_for(641)?
  let free = store_grant(pool, credits_attach([third], grant_for(257)?)?, 257)?
  let missing = store_grant(pool, twenty, 321)?
  let paid = store_grant(pool, credits_attach([first], twenty)?, 321)?
  let replayed = store_grant(pool, credits_attach([first], twenty)?, 321)?
  let reused = store_grant(pool, credits_attach([first, second], forty)?, 641)?
  let short = store_grant(pool, credits_attach([second], forty)?, 641)?
  let not_credits = store_grant(pool, credits_attach(forged ++ [second], forty)?, 641)?
  let forty_paid = store_grant(pool, credits_attach([second, third], forty)?, 641)?
  let spent = credits_test_count(pool, "credit_spent")?
  let holds = credits_test_count(pool, "credit_holds WHERE action = 4")?
  let total = file_credits_total(pool)? - before
  Pool.close(pool)
  let failures = check("a free grant spent credits", free == 0, [])
  let failures = check("a 20 MiB grant without credits: #{missing}", missing == 402, failures)
  let failures = check("a 20 MiB grant with 1 credit: #{paid}", paid == 0, failures)
  let failures = check("a replayed frame: #{replayed}", replayed == 409, failures)
  let failures = check("a frame with a spent token: #{reused}", reused == 409, failures)
  let failures = check("a 40 MiB grant with 1 credit: #{short}", short == 402, failures)
  let failures = check("tokens of an unannounced key: #{not_credits}", not_credits == 422, failures)
  let failures = check("a 40 MiB grant with 2 credits: #{forty_paid}", forty_paid == 0, failures)
  let failures = check("#{spent} tokens spent, not 3", spent == 3, failures)
  let failures = check("#{holds} file holds, not 2", holds == 2, failures)
  Ok(check("#{total} file credits counted, not 3", total == 3, failures))
end

test("large files spend 1 credit per extra 16 MiB at the core, once; short or spent frames grant nothing") do
  case large_files() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(failures) -> do
      for failure in failures do
        println(failure)
      end
      assert(List.length(failures) == 0)
    end
  end
end
