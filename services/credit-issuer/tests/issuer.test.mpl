from Api.IssuerApi import IssuerResult, issuer_issue_request, issuer_quote_request
from Credits.CreditCrypto import credits_blind_batch, credits_new_inputs, credits_verify_token
from Privacy.Edge import encode_stamped_request, mint_request_stamp
from Credits.CreditFrames import (
  CreditIssueRequest,
  credits_quote_work_label,
  CreditQuote,
  CreditQuoteRequest,
  credits_decode_issue_response,
  credits_decode_quote,
  credits_encode_issue_request,
  credits_encode_quote_request
)
from Credits.IssuerKey import IssuerKey, credits_epoch_at, credits_issuer_key
from Issuer.Derivation import issuer_deposit_key
from Issuer.KeyStore import (
  issuer_announce_keys,
  issuer_key_health,
  issuer_provision_key,
  issuer_revoke_key,
  issuer_signing_key,
  issuer_wrapping_key
)
from Issuer.Quotes import issuer_reference
from Issuer.Refunds import issuer_refund, issuer_refund_plan
from Issuer.Reissues import issuer_reissue
from Issuer.Settings import IssuerSettings
from Issuer.Settlement import issuer_settlement
from Issuer.Sweeper import issuer_sweep
from Tests.World import (
  world_payer,
  world_payment,
  world_seed,
  world_settings,
  world_start
)

fn database() -> PoolHandle!String do
  Pool.open(Env.get("CREDIT_ISSUER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/credit_issuer_test?sslmode=disable"),
    1,
    4,
    5000)
end

fn reset(pool :: PoolHandle) -> Result<(), String> do
  Pool.execute(pool,
    "TRUNCATE reissues, refunds, sweeps, payments, quotes, issuer_keys, quote_stamps",
    [])?
  Pool.execute(pool, "ALTER SEQUENCE deposit_index_seq RESTART", [])?
  Ok(nil)
end

fn scalar(pool :: PoolHandle, sql :: String) -> String!String do
  let rows = Pool.query_values(pool, sql, [])?
  case rows do
    [row] -> case Map.get(row, "value") do
      Text(value) -> Ok(value)
      _ -> Ok("")
    end
    _ -> Err("expected one row")
  end
end

fn now_ms() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

fn wrapping_public() -> Bytes!String do
  let wrapping = issuer_wrapping_key()?
  case Crypto.x25519_public(wrapping) do
    Err(_) -> Err("wrapping key failed")
    Ok(public) -> Ok(public.bytes)
  end
end

## Test key n (1–3) from tests/test-keys.env, sealed and recorded.

fn provision(pool :: PoolHandle, n :: Int, purpose :: String, epoch :: Int) -> Bytes!String do
  let pkcs8 = case Env.get_secret_hex("MORSE_CREDIT_TEST_ISSUER_KEY_#{n}_HEX") do
    Err(_) -> Err("source services/credit-issuer/tests/test-keys.env first")
    Ok(value)
  end?
  issuer_provision_key(pool, wrapping_public()?, pkcs8, purpose, epoch)
end

fn ready(pool :: PoolHandle, settings :: IssuerSettings) -> Bytes!String do
  reset(pool)?
  let key_id = provision(pool, 1, "test", credits_epoch_at(now_ms()))?
  issuer_announce_keys(pool, settings, now_ms())?
  Ok(key_id)
end

fn signing(pool :: PoolHandle, settings :: IssuerSettings) -> IssuerKey!String do
  case issuer_signing_key(pool, "test", now_ms())? do
    None -> Err("no signing key")
    Some(row) -> credits_issuer_key(2, settings.issuer_name, row.epoch, row.spki)
  end
end

## A quote request as clients send it: CQR inside a PWR stamp.

fn stamped_quote(settings :: IssuerSettings, pack :: Int, asset :: Int) -> Bytes!String do
  let payload = credits_encode_quote_request(CreditQuoteRequest { pack: pack, asset: asset })?
  let stamp = mint_request_stamp(credits_quote_work_label(),
    payload,
    U64.parse(Int.to_string(now_ms() + 240000))?,
    settings.quote_difficulty)?
  encode_stamped_request(stamp, payload)
end

fn quote(pool :: PoolHandle,
  settings :: IssuerSettings,
  pack :: Int,
  asset :: Int) -> CreditQuote!String do
  let answer = issuer_quote_request(pool, settings, stamped_quote(settings, pack, asset)?, now_ms())
  if answer.status != 201 do
    Err("quote answered #{answer.status}")
  else
    credits_decode_quote(answer.body)
  end
end

fn deposit_of(value :: CreditQuote) -> String do
  List.get(String.split(String.slice(value.payment_request,
        7,
        String.length(value.payment_request)),
      "?"),
    0)
end

fn issue(pool :: PoolHandle,
  settings :: IssuerSettings,
  value :: CreditQuote,
  payment :: String,
  blinded :: List<Bytes>) -> IssuerResult!String do
  let wrapping = issuer_wrapping_key()?
  let body = credits_encode_issue_request(CreditIssueRequest {
    quote_id: value.quote_id,
    payment: payment,
    token_key_id: value.token_key_id,
    blinded: blinded
  })?
  Ok(issuer_issue_request(pool, settings, body, wrapping, now_ms()))
end

fn exchange(pool :: PoolHandle,
  settings :: IssuerSettings,
  value :: CreditQuote,
  payment :: String,
  blinded :: List<Bytes>) -> List<Bytes>!String do
  let answer = issue(pool, settings, value, payment, blinded)?
  if answer.status != 200 do
    Err("issue answered #{answer.status}")
  else
    Ok(credits_decode_issue_response(answer.body)?.signatures)
  end
end

fn fake_blinded(count :: Int, fill :: Int) -> List<Bytes> do
  for _index in 0..count do
    case Bytes.repeat(fill, 256) do
      Err(_) -> Bytes.empty()
      Ok(value) -> value
    end
  end
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

fn rotation() -> Bool!String do
  let pool = database()?
  reset(pool)?
  let settings = world_settings("test")
  let epoch = credits_epoch_at(now_ms())
  let current = provision(pool, 1, "test", epoch)?
  let before = issuer_signing_key(pool, "test", now_ms())?
  let duplicate = case provision(pool, 2, "test", epoch) do
    Err(_) -> true
    Ok(_) -> false
  end
  provision(pool, 2, "test", epoch + 1)?
  let announced = issuer_announce_keys(pool, settings, now_ms())?
  let again = issuer_announce_keys(pool, settings, now_ms())?
  let (current_ready, next_ready) = issuer_key_health(pool, "test", now_ms())?
  let signing_now = issuer_signing_key(pool, "test", now_ms())?
  let next_epoch = issuer_signing_key(pool, "test", (epoch + 1) * 2592000000)?
  let pkcs8_hex = String.slice(Env.get("MORSE_CREDIT_TEST_ISSUER_KEY_1_HEX", ""), 200, 264)
  let sealed_rows = Pool.query_values(pool,
    "SELECT encode(sealed_key, 'hex') AS sealed FROM issuer_keys",
    [])?
  let plaintext_stored = List.any(sealed_rows,
    fn row -> case Map.get(row, "sealed") do
      Text(sealed) -> String.contains(sealed, pkcs8_hex)
      _ -> true
    end end)
  issuer_revoke_key(pool, settings, "test", epoch, now_ms())?
  let revoked = issuer_signing_key(pool, "test", now_ms())?
  let replacement = provision(pool, 3, "test", epoch)?
  issuer_announce_keys(pool, settings, now_ms())?
  let replaced = issuer_signing_key(pool, "test", now_ms())?
  Pool.close(pool)
  Ok(before == None
    && duplicate
    && announced == 2
    && again == 0
    && current_ready
    && next_ready
    && case signing_now do
      Some(row) -> row.key_id == current
      None -> false
    end
    && next_epoch != None
    && !plaintext_stored
    && revoked == None
    && case replaced do
      Some(row) -> row.key_id == replacement
      None -> false
    end)
end

test("keys are provisioned sealed, announced into the log, rotated by epoch and replaced after revocation") do
  world_start()
  check("rotation", rotation())
end

fn usdc_pack() -> Bool!String do
  let pool = database()?
  let settings = world_settings("test")
  ready(pool, settings)?
  let key = signing(pool, settings)?
  let value = quote(pool, settings, 1, 1)?
  let deposit = issuer_deposit_key(world_seed(), 0)?
  let payment = world_payment(deposit.address, 2, 5000000)?
  let tokens = credits_blind_batch(key,
    credits_new_inputs(key, 100)?,
    fn blinded -> exchange(pool, settings, value, payment, blinded) end)?
  let verified = List.all(tokens, fn token -> credits_verify_token(key, token) == Ok(true) end)
  let blinded = fake_blinded(100, 1)
  let other = quote(pool, settings, 1, 1)?
  # A transaction that paid another deposit pays nothing here.
  let reused = issue(pool, settings, other, payment, blinded)?.status
  let first = issue(pool, settings, value, payment, blinded)?.status
  let resubmitted = issue(pool, settings, other, "", fake_blinded(100, 2))?
  let repeated = issue(pool, settings, other, "", fake_blinded(100, 2))?
  let wrong_count = issue(pool, settings, value, payment, fake_blinded(500, 1))?.status
  Pool.close(pool)
  Ok(Bytes.length(value.quote_id) == 32
    && value.batch == 100
    && value.amount == 5000000
    && deposit_of(value) == deposit.address
    && String.contains(value.payment_request, "amount=5&spl-token=")
    && String.contains(value.payment_request,
      "&reference=" <> Bytes.to_base58(issuer_reference(value.quote_id)?))
    && !String.contains(value.payment_request, Bytes.to_base58(value.quote_id))
    && List.length(tokens) == 100
    && verified
    && reused == 402
    && first == 409
    && resubmitted.status == 200
    && Bytes.secure_equals(resubmitted.body, repeated.body)
    && wrong_count == 409)
end

test("a USDC quote issues a whole pack once; the same batch gets the same signatures") do
  world_start()
  check("usdc pack", usdc_pack())
end

fn sol_tolerance() -> Bool!String do
  let pool = database()?
  let settings = world_settings("test")
  ready(pool, settings)?
  let short = quote(pool, settings, 1, 2)?
  let exact = quote(pool, settings, 1, 2)?
  # $5 at $150 a SOL is 33,333,333.3 lamports, quoted as 33,333,334; 1% short
  # is 33,000,001 and pays, one lamport less does not.
  let underpaid = issue(pool,
    settings,
    short,
    world_payment(deposit_of(short), 1, 33000000)?,
    fake_blinded(100, 3))?.status
  let tolerated = issue(pool,
    settings,
    exact,
    world_payment(deposit_of(exact), 1, 33000001)?,
    fake_blinded(100, 3))?.status
  let state = scalar(pool,
    "SELECT string_agg(state, ',' ORDER BY deposit_index) AS value FROM quotes")?
  Pool.close(pool)
  Ok(short.amount == 33333334
    && String.contains(short.payment_request, "amount=0.033333334&reference=")
    && underpaid == 402
    && tolerated == 200
    && state == "underpaid,issued")
end

test("SOL is priced from the oracle and may be 1% short, not more") do
  world_start()
  check("sol tolerance", sol_tolerance())
end

fn refusals() -> Bool!String do
  let pool = database()?
  let settings = world_settings("test")
  ready(pool, settings)?
  let late = quote(pool, settings, 1, 2)?
  let failed = quote(pool, settings, 1, 2)?
  let pending = quote(pool, settings, 1, 2)?
  let late_status = issue(pool,
    settings,
    late,
    world_payment(deposit_of(late), 4, 40000000)?,
    fake_blinded(100, 4))?.status
  let failed_status = issue(pool,
    settings,
    failed,
    world_payment(deposit_of(failed), 3, 40000000)?,
    fake_blinded(100, 4))?.status
  let pending_status = issue(pool,
    settings,
    pending,
    world_payment(deposit_of(pending), 5, 40000000)?,
    fake_blinded(100, 4))?.status
  let payments = scalar(pool, "SELECT count(*)::text AS value FROM payments")?
  let stale = issue(pool,
    settings,
    %{pending | token_key_id: Crypto.sha256(Bytes.from_utf8("other key"))},
    world_payment(deposit_of(pending), 1, 40000000)?,
    fake_blinded(100, 4))?.status
  let off = issuer_quote_request(pool,
    world_settings("off"),
    stamped_quote(settings, 1, 1)?,
    now_ms()).status
  let no_lightning = issuer_quote_request(pool,
    %{settings | lnd_url: ""},
    stamped_quote(settings, 1, 3)?,
    now_ms()).status
  let only_usdc = issuer_quote_request(pool,
    %{settings | assets: ["usdc"]},
    stamped_quote(settings, 1, 2)?,
    now_ms()).status
  Pool.close(pool)
  Ok(late_status == 402
    && failed_status == 402
    && pending_status == 202
    && payments == "1"
    && stale == 412
    && off == 503
    && no_lightning == 422
    && only_usdc == 422)
end

test("late, failed and unfinalized payments issue nothing; off and missing rails refuse quotes") do
  world_start()
  check("refusals", refusals())
end

fn lightning() -> Bool!String do
  let pool = database()?
  let settings = world_settings("test")
  ready(pool, settings)?
  let key = signing(pool, settings)?
  let value = quote(pool, settings, 1, 3)?
  let tokens = credits_blind_batch(key,
    credits_new_inputs(key, 100)?,
    fn blinded -> exchange(pool, settings, value, "", blinded) end)?
  Pool.close(pool)
  Ok(value.amount == 8334
    && value.payment_request == "lnbcrt83340n1test"
    && List.length(tokens) == 100
    && credits_verify_token(key, List.get(tokens, 99))?)
end

test("a settled Lightning invoice issues its pack") do
  world_start()
  check("lightning", lightning())
end

fn sweeping() -> Bool!String do
  let pool = database()?
  let settings = world_settings("test")
  ready(pool, settings)?
  let usdc = quote(pool, settings, 1, 1)?
  let sol = quote(pool, settings, 1, 2)?
  issue(pool, settings, usdc, world_payment(deposit_of(usdc), 2, 5000000)?, fake_blinded(100, 5))?
  issue(pool, settings, sol, world_payment(deposit_of(sol), 1, 33333334)?, fake_blinded(100, 5))?
  let first = issuer_sweep(pool, settings)?
  let second = issuer_sweep(pool, settings)?
  let swept = scalar(pool, "SELECT count(*)::text AS value FROM quotes WHERE swept_at IS NOT NULL")?
  let sweeps = scalar(pool,
    "SELECT count(*)::text AS value FROM sweeps WHERE finalized_at IS NOT NULL")?
  Pool.close(pool)
  Ok(first.sent == 2 && second.finalized == 2 && second.sent == 0 && swept == "2" && sweeps == "2")
end

test("deposits are swept in signed batches and marked once the sweep is final") do
  world_start()
  check("sweeping", sweeping())
end

fn refunding() -> Bool!String do
  let pool = database()?
  let settings = world_settings("test")
  ready(pool, settings)?
  let short = quote(pool, settings, 1, 2)?
  issue(pool, settings, short, world_payment(deposit_of(short), 1, 1000)?, fake_blinded(100, 6))?
  let plan = issuer_refund_plan(pool, settings, short.quote_id)?
  let unconfirmed = case issuer_refund(pool, settings, short.quote_id, "yes") do
    Err(_) -> true
    Ok(_) -> false
  end
  let signature = issuer_refund(pool, settings, short.quote_id, Bytes.to_hex(short.quote_id))?
  let again = case issuer_refund(pool, settings, short.quote_id, Bytes.to_hex(short.quote_id)) do
    Err(_) -> true
    Ok(_) -> false
  end
  let swept = issuer_sweep(pool, settings)?
  Pool.close(pool)
  Ok(plan.destination == world_payer()
    && plan.amount == 33333334
    && unconfirmed
    && String.length(signature) > 80
    && again
    && swept.sent == 0)
end

test("an underpaid deposit is refunded to its payer only on the operator's confirmation") do
  world_start()
  check("refunding", refunding())
end

fn settling() -> Bool!String do
  let pool = database()?
  let settings = world_settings("test")
  ready(pool, settings)?
  let usdc = quote(pool, settings, 2, 1)?
  let sol = quote(pool, settings, 1, 2)?
  issue(pool, settings, usdc, world_payment(deposit_of(usdc), 2, 25000000)?, fake_blinded(500, 7))?
  issue(pool, settings, sol, world_payment(deposit_of(sol), 1, 33333334)?, fake_blinded(100, 7))?
  let week = scalar(pool,
    "SELECT date_trunc('week', now() AT TIME ZONE 'UTC')::date::text AS value")?
  let before_token = Json.parse(issuer_settlement(pool, "20/80", week)?)?
  let after_token = Json.parse(issuer_settlement(pool, "20/30/50", week)?)?
  let tuesday = case issuer_settlement(pool, "20/80", "2026-09-29") do
    Err(_) -> true
    Ok(_) -> false
  end
  Pool.close(pool)
  Ok(Json.as_string(Json.object_get(before_token, "revenue_micro_usd")?)? == "30000000"
    && Json.as_string(Json.object_get(before_token, "pool_usdc_base_units")?)? == "6000000"
    && Json.as_string(Json.object_get(before_token, "operations_usdc_base_units")?)? == "24000000"
    && Json.as_string(Json.object_get(after_token, "burn_usdc_base_units")?)? == "9000000"
    && Json.as_string(Json.object_get(after_token, "operations_usdc_base_units")?)? == "15000000"
    && Json.as_int(Json.object_get(before_token, "quotes")?)? == 2
    && tuesday)
end

test("the weekly settlement splits the week's revenue 20/80, or 20/30/50 after the token") do
  world_start()
  check("settling", settling())
end

fn throttling() -> Bool!String do
  let pool = database()?
  let settings = world_settings("test")
  ready(pool, settings)?
  let request = stamped_quote(settings, 1, 1)?
  let first = issuer_quote_request(pool, settings, request, now_ms()).status
  let replayed = issuer_quote_request(pool, settings, request, now_ms()).status
  let unstamped = issuer_quote_request(pool,
    settings,
    credits_encode_quote_request(CreditQuoteRequest { pack: 1, asset: 1 })?,
    now_ms()).status
  let expired_stamp = issuer_quote_request(pool,
    settings,
    stamped_quote(settings, 1, 1)?,
    now_ms() + 600000).status
  let capped = %{settings | max_open_quotes: 2}
  let second = issuer_quote_request(pool, capped, stamped_quote(settings, 1, 1)?, now_ms()).status
  let third = issuer_quote_request(pool, capped, stamped_quote(settings, 1, 1)?, now_ms()).status
  Pool.execute(pool, "UPDATE quotes SET expires_at = now() - interval '1 second'", [])?
  let reclaimed = issuer_quote_request(pool,
    capped,
    stamped_quote(settings, 1, 1)?,
    now_ms()).status
  Pool.close(pool)
  Ok(first == 201
    && replayed == 429
    && unstamped == 400
    && expired_stamp == 429
    && second == 201
    && third == 429
    && reclaimed == 201)
end

test("a quote costs work once, and unpaid quotes are capped until they expire") do
  world_start()
  check("throttling", throttling())
end

fn refused(value :: Result<(), String>) -> Bool do
  case value do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn reissuing() -> Bool!String do
  let pool = database()?
  let settings = world_settings("test")
  ready(pool, settings)?
  let key = signing(pool, settings)?
  let value = quote(pool, settings, 1, 1)?
  let id = Bytes.to_hex(value.quote_id)
  let never_opened = refused(issuer_reissue(pool, value.quote_id, id, ""))
  # The first batch is signed, then its blinding states are lost.
  issue(pool, settings, value, world_payment(deposit_of(value), 2, 5000000)?, fake_blinded(100, 1))?
  let issued_at = scalar(pool,
    "SELECT issued_at::text AS value FROM quotes WHERE state = 'issued'")?
  let lost = issue(pool, settings, value, "", fake_blinded(100, 2))?.status
  let unconfirmed = refused(issuer_reissue(pool, value.quote_id, "yes", ""))
  issuer_reissue(pool, value.quote_id, id, "payment proof checked")?
  let twice = refused(issuer_reissue(pool, value.quote_id, id, ""))
  let tokens = credits_blind_batch(key,
    credits_new_inputs(key, 100)?,
    fn blinded -> exchange(pool, settings, value, "", blinded) end)?
  let verified = List.all(tokens, fn token -> credits_verify_token(key, token) == Ok(true) end)
  let third_batch = issue(pool, settings, value, "", fake_blinded(100, 3))?.status
  let audit = scalar(pool,
    "SELECT note || '|' || (signed_at IS NOT NULL)::text || '|' || (SELECT issued_at::text FROM quotes WHERE state = 'issued') AS value FROM reissues")?
  let unpaid = quote(pool, settings, 1, 1)?
  let open_refused = refused(issuer_reissue(pool,
    unpaid.quote_id,
    Bytes.to_hex(unpaid.quote_id),
    ""))
  Pool.execute(pool,
    "UPDATE quotes SET expires_at = now() - interval '1 second' WHERE state = 'open'",
    [])?
  let expired_refused = refused(issuer_reissue(pool,
    unpaid.quote_id,
    Bytes.to_hex(unpaid.quote_id),
    ""))
  Pool.close(pool)
  Ok(never_opened
    && lost == 409
    && unconfirmed
    && twice
    && List.length(tokens) == 100
    && verified
    && third_batch == 409
    && audit == "payment proof checked|true|" <> issued_at
    && open_refused
    && expired_refused)
end

test("an operator re-issue signs one new batch for an issued quote, once, and only for a paid one") do
  world_start()
  check("reissuing", reissuing())
end
