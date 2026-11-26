from Api.Binary import BinaryResult, submit_configured_sealed_request
from Api.CreditRoutes import credits_redeem_request, credits_totals_request
from Api.MailboxRoutes import (
  claim_with_policy_request,
  mailbox_policy_request,
  mailbox_retention_request
)
from Credits.CreditFrames import (
  credits_decode_redemption,
  credits_encode_frame,
  credits_encode_held,
  credits_encode_redeem
)
from Credits.IssuerKey import IssuerKey, credits_epoch_at
from Credits.MailboxExtras import (
  credits_decode_claim_answer,
  credits_decode_policy,
  credits_decode_retention_answer,
  credits_sign_policy,
  credits_sign_retention
)
from Identity.Device import DeviceKeys
from Prekeys.Pool import PrekeyClaimRequest, encode_prekey_claim
from Privacy.Edge import encode_sealed_delivery, seal_delivery
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import OuterEnvelope
from Storage.ContactAddress import publish_contact_address
from Storage.Devices import resolve_devices
from Storage.Retention import purge_envelopes
from Tests.CreditsSupport import (
  credits_test_announce,
  credits_test_count,
  credits_test_issuer,
  credits_test_key,
  credits_test_reset,
  credits_test_tokens
)
from Tests.MailboxSupport import register_test_mailbox

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

fn day() -> Int do
  86400000
end

fn repeated(value :: Int, count :: Int) -> Bytes do
  case Bytes.repeat(value, count) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
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

fn reset(pool :: PoolHandle) -> Result<(), String> do
  credits_test_reset(pool)?
  Pool.execute(pool,
    "TRUNCATE messenger_mailbox_policies, messenger_mailbox_retention, credit_spend_totals",
    [])?
  Ok(nil)
end

fn sealed_for(address :: Bytes, id :: Int, expiration_ms :: Int) -> Bytes!String do
  let pair = case Crypto.x25519_from_seed(Bytes.from_hex(Env.get("MESSENGER_DELIVERY_SEALING_SEED_HEX",
    ""))?) do
    Err(_) -> Err("delivery key failed")
    Ok(value)
  end?
  let outer = case encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: repeated(id, 16),
    mailbox_token: address,
    suite: 4,
    expiration: U64.parse(Int.to_string(expiration_ms))?,
    padding_bucket: 256,
    ciphertext: repeated(3, 32)
  }) do
    Err(_) -> Err("envelope failed")
    Ok(value)
  end?
  encode_sealed_delivery(seal_delivery(outer, pair.public_key)?)
end

## A hold for `action` paid with `count` fresh tokens of `key`.

fn hold(pool :: PoolHandle,
  issuer :: borrow BlindRsaSecretKey,
  key :: IssuerKey,
  action :: Int,
  count :: Int) -> Bytes!String do
  let frame = credits_encode_frame(Crypto.sha256(Bytes.from_utf8("paid")),
    credits_test_tokens(issuer, key, count)?)?
  let answer = credits_redeem_request(pool, "test", credits_encode_redeem(action, frame)?, now_ms())
  if answer.status != 201 do
    Err("redeem answered #{answer.status}")
  else
    Ok(credits_decode_redemption(answer.body)?.redemption_id)
  end
end

fn deliver(pool :: PoolHandle,
  sealed :: Bytes,
  redemption :: Option<Bytes>) -> BinaryResult!String do
  let body = case redemption do
    None -> sealed
    Some(id) -> credits_encode_held(id, sealed)?
  end
  submit_configured_sealed_request(pool, body)
end

fn postage() -> Bool!String do
  let pool = database()?
  reset(pool)?
  let token = repeated(42, 32)
  let mailbox_hash = Crypto.sha256(token)
  let device = register_test_mailbox(pool, "priced-recipient", token)?
  let stranger = register_test_mailbox(pool, "other-device", repeated(43, 32))?
  let contact = repeated(44, 32)
  publish_contact_address(pool, mailbox_hash, Crypto.sha256(contact))?
  let policy = credits_sign_policy(device.signing_private_key, mailbox_hash, 2, 5)?
  let older = credits_sign_policy(device.signing_private_key, mailbox_hash, 1, 1)?
  let forged = credits_sign_policy(stranger.signing_private_key, mailbox_hash, 3, 0)?
  let set = mailbox_policy_request(pool, policy).status
  let again = mailbox_policy_request(pool, policy).status
  let stale = mailbox_policy_request(pool, older).status
  let unauthorized = mailbox_policy_request(pool, forged).status
  let issuer = credits_test_issuer()?
  let key = credits_test_key(issuer, 2, credits_epoch_at(now_ms()))?
  credits_test_announce(pool, key)?
  let later = now_ms() + day()
  let unpaid = deliver(pool, sealed_for(token, 1, later)?, None)?
  let short = deliver(pool, sealed_for(token, 2, later)?, Some(hold(pool, issuer, key, 1, 1)?))?
  let paid = deliver(pool, sealed_for(token, 3, later)?, Some(hold(pool, issuer, key, 1, 5)?))?
  let from_contact = deliver(pool, sealed_for(contact, 4, later)?, None)?
  let asked = credits_decode_policy(unpaid.body)?
  let monday = credits_test_scalar(pool,
    "SELECT date_trunc('week', now() AT TIME ZONE 'UTC')::date::text AS value")?
  let totals = Json.parse(Bytes.to_utf8(credits_totals_request(pool, Some(monday)).body)?)?
  let envelopes = credits_test_count(pool, "messenger_envelopes")?
  Pool.close(pool)
  Ok(set == 201
    && again == 200
    && stale == 409
    && unauthorized == 403
    && unpaid.status == 402
    && asked.postage == 5
    && Bytes.secure_equals(unpaid.body, policy)
    && short.status == 402
    && paid.status == 202
    && from_contact.status == 202
    && envelopes == 2
    && Json.as_int(Json.object_get(totals, "postage")?)? == 6)
end

fn credits_test_scalar(pool :: PoolHandle, sql :: String) -> String!String do
  let rows = Pool.query_values(pool, sql, [])?
  case rows do
    [row] -> case Map.get(row, "value") do
      Text(value) -> Ok(value)
      _ -> Err("not text")
    end
    _ -> Err("expected one row")
  end
end

test("a priced public address takes only envelopes paying its postage; its contact address never charges") do
  check("postage", postage())
end

fn claim() -> Bool!String do
  let pool = database()?
  reset(pool)?
  let token = repeated(52, 32)
  let device = register_test_mailbox(pool, "claimed-recipient", token)?
  let policy = credits_sign_policy(device.signing_private_key, Crypto.sha256(token), 9, 25)?
  let stored = mailbox_policy_request(pool, policy).status
  let base = case resolve_devices(pool, "claimed-recipient")? do
    None -> Err("device set missing")
    Some(set) -> Ok(List.get(set.devices, 0).prekey_bundle)
  end?
  let account = credits_test_scalar(pool,
    "SELECT encode(account_id, 'hex') AS value FROM messenger_devices WHERE mailbox_token_hash = sha256(decode(repeat('34', 32), 'hex'))")?
  let request = encode_prekey_claim(PrekeyClaimRequest {
    account_id: Bytes.from_hex(account)?,
    device_id: device.device_id,
    base_bundle_hash: Crypto.sha256(base),
    reservation_id: repeated(7, 16)
  })?
  let version_two = Bytes.concat(Bytes.from_hex("02")?,
    Bytes.slice(request, 1, Bytes.length(request) - 1)?)?
  let answer = claim_with_policy_request(pool, version_two)
  let (bundle, found) = credits_decode_claim_answer(answer.body)?
  Pool.close(pool)
  Ok(stored == 201
    && answer.status == 200
    && Bytes.length(bundle) > 0
    && case found do
      Some(value) -> value.postage == 25
      None -> false
    end)
end

test("a version 2 prekey claim tells the sender the postage before the first message") do
  check("claim", claim())
end

fn stored_until(pool :: PoolHandle, id :: Int) -> Int!String do
  let value = credits_test_scalar(pool,
    "SELECT expiration_ms::text AS value FROM messenger_envelopes WHERE envelope_id = decode(repeat(lpad(to_hex("
      <> Int.to_string(id)
      <> "), 2, '0'), 16), 'hex')")?
  case String.to_int(value) do
    Some(parsed) -> Ok(parsed)
    None -> Err("no expiration")
  end
end

fn storage() -> Bool!String do
  let pool = database()?
  reset(pool)?
  let token = repeated(62, 32)
  let mailbox_hash = Crypto.sha256(token)
  let device = register_test_mailbox(pool, "storing-recipient", token)?
  let stranger = register_test_mailbox(pool, "storing-other", repeated(63, 32))?
  let issuer = credits_test_issuer()?
  let key = credits_test_key(issuer, 2, credits_epoch_at(now_ms()))?
  credits_test_announce(pool, key)?
  let now = now_ms()
  let base_edge = deliver(pool, sealed_for(token, 1, now + 31 * day() - 60000)?, None)?.status
  let base_past = deliver(pool, sealed_for(token, 2, now + 32 * day())?, None)?.status
  let request = credits_sign_retention(device.signing_private_key, mailbox_hash, 3, now_ms())?
  let underpaid = mailbox_retention_request(pool,
    credits_encode_held(hold(pool, issuer, key, 2, 10)?, request)?,
    now_ms()).status
  let untaken = credits_test_count(pool, "credit_holds WHERE taken_at IS NULL")?
  let forged = mailbox_retention_request(pool,
    credits_encode_held(hold(pool, issuer, key, 2, 30)?,
      credits_sign_retention(stranger.signing_private_key, mailbox_hash, 3, now_ms())?)?,
    now_ms()).status
  let stale = mailbox_retention_request(pool,
    credits_encode_held(hold(pool, issuer, key, 2, 30)?,
      credits_sign_retention(device.signing_private_key, mailbox_hash, 3, now_ms() - 600000)?)?,
    now_ms()).status
  let granted = mailbox_retention_request(pool,
    credits_encode_held(hold(pool, issuer, key, 2, 30)?, request)?,
    now_ms())
  let (days, until_ms) = credits_decode_retention_answer(granted.body)?
  let entitled_edge = deliver(pool,
    sealed_for(token, 3, now_ms() + 121 * day() - 60000)?,
    None)?.status
  let entitled_past = deliver(pool, sealed_for(token, 4, now_ms() + 122 * day())?, None)?.status
  let short_lived = deliver(pool, sealed_for(token, 5, now_ms() + day())?, None)?.status
  let kept = stored_until(pool, 5)?
  purge_envelopes(pool, 3600, 128)?
  let after_purge = credits_test_count(pool, "messenger_envelopes")?
  Pool.execute(pool,
    "UPDATE messenger_mailbox_retention SET entitled_until = now() - interval '1 second'",
    [])?
  let lapsed = deliver(pool, sealed_for(token, 6, now_ms() + 32 * day())?, None)?.status
  let monday = credits_test_scalar(pool,
    "SELECT date_trunc('week', now() AT TIME ZONE 'UTC')::date::text AS value")?
  let totals = Json.parse(Bytes.to_utf8(credits_totals_request(pool, Some(monday)).body)?)?
  Pool.close(pool)
  Ok(base_edge == 202
    && base_past == 400
    && underpaid == 402
    && untaken == 1
    && forged == 403
    && stale == 403
    && granted.status == 201
    && days == 120
    && until_ms > now + 119 * day()
    && entitled_edge == 202
    && entitled_past == 400
    && short_lived == 202
    && kept >= now + 120 * day() - 60000
    && after_purge == 3
    && lapsed == 400
    && Json.as_int(Json.object_get(totals, "storage")?)? == 100)
end

test("paid storage keeps a mailbox's envelopes up to its entitlement, and only while it lasts") do
  check("storage", storage())
end
