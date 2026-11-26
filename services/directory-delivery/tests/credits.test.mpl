from Api.Binary import BinaryResult, submit_configured_sealed_request
from Api.CreditRoutes import (
  credits_health_request,
  credits_issuer_keys_request,
  credits_issuer_leaf_request,
  credits_redeem_request
)
from Credits.CreditFrames import (
  CreditFrame,
  credits_attach,
  credits_decode_redemption,
  credits_encode_frame,
  credits_encode_held,
  credits_encode_redeem
)
from Credits.IssuerKey import (
  IssuerKey,
  credits_decode_issuer_key,
  credits_decode_issuer_keys,
  credits_encode_issuer_key,
  credits_epoch_at,
  credits_epoch_length
)
from Privacy.CreditEdge import CreditEdgeResult, credit_edge_submit
from Privacy.Edge import encode_sealed_delivery, seal_delivery
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import OuterEnvelope
from Storage.Credits import (
  credits_prune,
  credits_record_mode,
  credits_redeem,
  credits_take_hold_on_connection
)
from Storage.Transparency import latest_checkpoint
from Storage.TransparencyPruning import transparency_prune
from Runtime.CreditStats import credits_stats_record, credits_stats_snapshot, credits_stats_start
from Tests.CreditsSupport import (
  credits_test_announce,
  credits_test_count,
  credits_test_issuer,
  credits_test_key,
  credits_test_reset,
  credits_test_revoke,
  credits_test_tokens
)
from Tests.MailboxSupport import register_test_mailbox
from Tests.TransparencySupport import transparency_test_attest, transparency_test_witness_key
from Transparency.Client import transparency_verify_evidence_v2
from Transparency.CompactWire import transparency_decode_evidence_v2
from Transparency.Merkle import WitnessKey

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

fn epoch() -> Int do
  credits_epoch_at(now_ms())
end

fn redeem(pool :: PoolHandle, mode :: String, tokens :: List<Bytes>) -> Int!String do
  let frame = credits_encode_frame(Crypto.sha256(Bytes.from_utf8("body")), tokens)?
  Ok(credits_redeem_request(pool, mode, credits_encode_redeem(1, frame)?, now_ms()).status)
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

fn announcing() -> Bool!String do
  let pool = database()?
  credits_test_reset(pool)?
  let issuer = credits_test_issuer()?
  let other = credits_test_issuer()?
  let key = credits_test_key(issuer, 2, epoch())?
  let first = credits_test_announce(pool, key)?
  let again = credits_test_announce(pool, key)?
  let rival = credits_test_announce(pool, credits_test_key(other, 2, epoch())?)?
  let live = credits_test_announce(pool, credits_test_key(other, 1, epoch())?)?
  let garbage = credits_issuer_leaf_status(pool, Bytes.from_utf8("not a leaf"))
  let leaves = credits_test_count(pool, "transparency_entries")?
  Pool.close(pool)
  Ok(first == 201 && again == 200 && rival == 409 && live == 201 && garbage == 400 && leaves == 2)
end

fn credits_issuer_leaf_status(pool :: PoolHandle, body :: Bytes) -> Int do
  credits_issuer_leaf_request(pool, body).status
end

test("an issuer key enters the log once, and a second key for its epoch is refused") do
  check("announcing", announcing())
end

fn whole_frames() -> Bool!String do
  let pool = database()?
  credits_test_reset(pool)?
  let issuer = credits_test_issuer()?
  let key = credits_test_key(issuer, 2, epoch())?
  credits_test_announce(pool, key)?
  let tokens = credits_test_tokens(issuer, key, 3)?
  let pair = List.take(tokens, 2)
  let first = redeem(pool, "test", pair)?
  let replay = redeem(pool, "test", pair)?
  let mixed = redeem(pool, "test", [List.get(tokens, 2), List.get(tokens, 0)])?
  let spent_after_mixed = credits_test_count(pool, "credit_spent")?
  let last = redeem(pool, "test", [List.get(tokens, 2)])?
  let holds = credits_test_count(pool, "credit_holds")?
  Pool.close(pool)
  Ok(first == 201
    && replay == 409
    && mixed == 409
    && spent_after_mixed == 2
    && last == 201
    && holds == 2)
end

test("a frame is spent whole and once: one spent token refuses all of it") do
  check("whole frames", whole_frames())
end

fn refusals() -> Bool!String do
  let pool = database()?
  credits_test_reset(pool)?
  let issuer = credits_test_issuer()?
  let key = credits_test_key(issuer, 2, epoch())?
  let unlogged = credits_test_tokens(issuer, key, 1)?
  let before_logged = redeem(pool, "test", unlogged)?
  credits_test_announce(pool, key)?
  let other_purpose = redeem(pool, "live", unlogged)?
  let closed = redeem(pool, "off", unlogged)?
  credits_record_mode(pool, "test")?
  credits_record_mode(pool, "off")?
  let grace = redeem(pool, "off", unlogged)?
  let old_issuer = credits_test_issuer()?
  let expired_key = credits_test_key(old_issuer, 2, epoch() - 2)?
  credits_test_announce(pool, expired_key)?
  let expired = redeem(pool, "test", credits_test_tokens(old_issuer, expired_key, 1)?)?
  let previous_issuer = credits_test_issuer()?
  let previous_key = credits_test_key(previous_issuer, 2, epoch() - 1)?
  credits_test_announce(pool, previous_key)?
  let previous_tokens = credits_test_tokens(previous_issuer, previous_key, 2)?
  let previous = redeem(pool, "test", List.take(previous_tokens, 1))?
  let revoked_status = credits_test_revoke(pool, previous_key)?
  let revoked = redeem(pool, "test", List.drop(previous_tokens, 1))?
  let spent = credits_test_count(pool, "credit_spent")?
  Pool.close(pool)
  Ok(before_logged == 422
    && other_purpose == 422
    && closed == 403
    && grace == 201
    && expired == 422
    && previous == 201
    && revoked_status == 201
    && revoked == 422
    && spent == 2)
end

test("only tokens of logged, unrevoked keys of the redeemed purpose in their window count") do
  check("refusals", refusals())
end

fn racing(pool :: PoolHandle, tokens :: List<Bytes>) -> Int!String do
  let frame = CreditFrame { binding: Crypto.sha256(Bytes.from_utf8("race")), tokens: tokens }
  case credits_redeem(pool, "test", 1, frame, now_ms())? do
    Redeemed(_) -> Ok(1)
    _ -> Ok(0)
  end
end

fn concurrent() -> Bool!String do
  let pool = database()?
  credits_test_reset(pool)?
  let issuer = credits_test_issuer()?
  let key = credits_test_key(issuer, 2, epoch())?
  credits_test_announce(pool, key)?
  let tokens = credits_test_tokens(issuer, key, 20)?
  # Two services redeem the same tokens at the same moment, in two orders.
  let forward = Job.async(fn -> racing(pool, tokens) end)
  let backward = Job.async(fn -> racing(pool, List.reverse(tokens)) end)
  let first = Job.await(forward)
  let second = Job.await(backward)
  let spent = credits_test_count(pool, "credit_spent")?
  Pool.close(pool)
  let wins = case (first, second) do
    (Ok(Ok(a)), Ok(Ok(b))) -> a + b
    _ -> -1
  end
  Ok(wins == 1 && spent == 20)
end

test("two redemptions of the same tokens at once spend them once") do
  check("concurrent", concurrent())
end

fn take_twice(pool :: PoolHandle, id :: Bytes, action :: Int) -> Option<(Int, Bytes)>!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> credits_take_hold_on_connection(conn, id, action) end)
end

fn holds() -> Bool!String do
  let pool = database()?
  credits_test_reset(pool)?
  let issuer = credits_test_issuer()?
  let key = credits_test_key(issuer, 2, epoch())?
  credits_test_announce(pool, key)?
  let frame = credits_encode_frame(Crypto.sha256(Bytes.from_utf8("hold")),
    credits_test_tokens(issuer, key, 2)?)?
  let answer = credits_redeem_request(pool, "test", credits_encode_redeem(2, frame)?, now_ms())
  let redemption = credits_decode_redemption(answer.body)?
  let wrong_action = take_twice(pool, redemption.redemption_id, 1)?
  let taken = take_twice(pool, redemption.redemption_id, 2)?
  let again = take_twice(pool, redemption.redemption_id, 2)?
  Pool.close(pool)
  Ok(redemption.credits == 2
    && wrong_action == None
    && taken == Some((2, Crypto.sha256(Bytes.from_utf8("hold"))))
    && again == None)
end

test("a hold is taken once, by the action it was redeemed for") do
  check("holds", holds())
end

fn pinned() -> List<WitnessKey>!String do
  let a = transparency_test_witness_key("witness-a")?
  let b = transparency_test_witness_key("witness-b")?
  Ok([
    WitnessKey { witness_id: "witness-a", public_key: a.public_key.bytes },
    WitnessKey { witness_id: "witness-b", public_key: b.public_key.bytes }
  ])
end

fn listing() -> Bool!String do
  let pool = database()?
  credits_test_reset(pool)?
  let issuer = credits_test_issuer()?
  let key = credits_test_key(issuer, 2, epoch())?
  credits_test_announce(pool, key)?
  let revoked_issuer = credits_test_issuer()?
  let revoked_key = credits_test_key(revoked_issuer, 1, epoch())?
  credits_test_announce(pool, revoked_key)?
  credits_test_revoke(pool, revoked_key)?
  let first = credits_issuer_keys_request(pool, None, now_ms())
  let checkpoint = case latest_checkpoint(pool)? do
    None -> Err("no checkpoint")
    Some(value) -> Ok(value)
  end?
  transparency_test_attest(pool, "witness-a", checkpoint)?
  transparency_test_attest(pool, "witness-b", checkpoint)?
  let answer = credits_issuer_keys_request(pool, None, now_ms())
  let evidence = credits_decode_issuer_keys(answer.body)?
  let verified = case evidence do
    [only] -> do
      let decoded = transparency_decode_evidence_v2(only)?
      let log_key = SigningPublicKey {
        bytes: Bytes.from_hex(Env.get("MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX", ""))?
      }
      let now = U64.parse(Int.to_string(now_ms()))?
      transparency_verify_evidence_v2(decoded, log_key, pinned()?, 2, "-", Bytes.empty(), now)?
        && credits_decode_issuer_key(decoded.entry_bytes)? == key
    end
    _ -> false
  end
  let bad_size = credits_issuer_keys_request(pool, Some("99"), now_ms()).status
  Pool.close(pool)
  Ok(first.status == 200 && answer.status == 200 && verified && bad_size == 400)
end

test("the issuer-key listing proves each current key into the witnessed log") do
  check("listing", listing())
end

fn pruning() -> Bool!String do
  let pool = database()?
  credits_test_reset(pool)?
  let issuer = credits_test_issuer()?
  let key = credits_test_key(issuer, 2, epoch())?
  credits_test_announce(pool, key)?
  let live_issuer = credits_test_issuer()?
  credits_test_announce(pool, credits_test_key(live_issuer, 1, epoch())?)?
  let current = epoch()
  let rows = [(current - 3, "aa"), (current - 2, "bb"), (current - 1, "cc"), (current, "dd")]
  for (key_epoch, fill) in rows do
    Pool.execute_values(pool,
      "INSERT INTO credit_spent (nullifier, key_epoch) VALUES (decode(repeat($1, 32), 'hex'), $2::bigint)",
      [Text(fill), Text(Int.to_string(key_epoch))])?
  end
  # Epoch current - 2's key stopped at the start of this epoch: its tokens go
  # 7 days later. Measured from 8 days into this epoch, current - 2 goes too.
  let start = current * credits_epoch_length()
  let early = credits_prune(pool, start + 86400000)?
  let later = credits_prune(pool, start + 8 * 86400000)?
  Pool.execute(pool,
    "UPDATE transparency_entries SET created_at = now() - interval '200 days'",
    [])?
  let log = transparency_prune(pool, "on", 100)?
  let kept = credits_test_count(pool,
    "transparency_entries WHERE entry_bytes IS NOT NULL AND pruned_at IS NULL")?
  let left = credits_test_count(pool, "credit_spent")?
  Pool.close(pool)
  Ok(early == 1 && later == 1 && left == 2 && log.ran && log.entries == 0 && kept == 2)
end

test("spent tokens go 7 days after their key stops, and issuer leaves are never pruned") do
  check("pruning", pruning())
end

fn repeated(value :: Int, count :: Int) -> Bytes do
  case Bytes.repeat(value, count) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn sealed_for(mailbox_token :: Bytes, envelope_id :: Int) -> Bytes!String do
  let seed = Bytes.from_hex(Env.get("MESSENGER_DELIVERY_SEALING_SEED_HEX", ""))?
  let pair = case Crypto.x25519_from_seed(seed) do
    Err(_) -> Err("delivery key failed")
    Ok(value)
  end?
  let outer = case encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: repeated(envelope_id, 16),
    mailbox_token: mailbox_token,
    suite: 1,
    expiration: U64.parse(Int.to_string(now_ms() + 86400000))?,
    padding_bucket: 256,
    ciphertext: repeated(3, 32)
  }) do
    Err(_) -> Err("envelope failed")
    Ok(value)
  end?
  encode_sealed_delivery(seal_delivery(outer, pair.public_key)?)
end

# The edge's credit path against the core itself: redeem, then the held sealed
# delivery, exactly as the edge sends them over HTTP.

fn through_the_edge(pool :: PoolHandle, body :: Bytes) -> Int!String do
  let now = U64.parse(Int.to_string(now_ms()))?
  let result = credit_edge_submit(body,
    now,
    U64.parse("300000")?,
    8,
    fn request do
      let answer = credits_redeem_request(pool, "test", request, now_ms())
      Ok(CreditEdgeResult { status: answer.status, body: answer.body })
    end,
    fn request do
      let answer = submit_configured_sealed_request(pool, request)?
      Ok(CreditEdgeResult { status: answer.status, body: answer.body })
    end)
  Ok(result.status)
end

fn end_to_end() -> Bool!String do
  let pool = database()?
  credits_test_reset(pool)?
  let mailbox_token = repeated(42, 32)
  register_test_mailbox(pool, "credit-recipient", mailbox_token)?
  let issuer = credits_test_issuer()?
  let key = credits_test_key(issuer, 2, epoch())?
  credits_test_announce(pool, key)?
  let tokens = credits_test_tokens(issuer, key, 2)?
  let body = credits_attach(tokens, sealed_for(mailbox_token, 7)?)?
  let delivered = through_the_edge(pool, body)?
  let replayed = through_the_edge(pool, body)?
  let other_envelope = through_the_edge(pool,
    credits_attach(tokens, sealed_for(mailbox_token, 8)?)?)?
  let spent = credits_test_count(pool, "credit_spent")?
  let envelopes = credits_test_count(pool, "messenger_envelopes")?
  let taken = credits_test_count(pool, "credit_holds WHERE taken_at IS NOT NULL")?
  let orphan = submit_configured_sealed_request(pool,
    credits_encode_held(repeated(5, 16), sealed_for(mailbox_token, 9)?)?)?.status
  Pool.close(pool)
  Ok(delivered == 202
    && replayed == 409
    && other_envelope == 409
    && spent == 2
    && envelopes == 1
    && taken == 1
    && orphan == 409)
end

test("credits on an envelope reach the core through the edge path, spent once; a replay is refused") do
  check("end to end", end_to_end())
end

fn health() -> Bool!String do
  let pool = database()?
  credits_test_reset(pool)?
  let issuer = credits_test_issuer()?
  credits_test_announce(pool, credits_test_key(issuer, 1, epoch())?)?
  credits_stats_start()
  for duration in 1..101 do
    credits_stats_record(duration, duration == 50)
  end
  let answer = credits_health_request(pool, "live", credits_stats_snapshot(), now_ms())
  let report = Json.parse(Bytes.to_utf8(answer.body)?)?
  Pool.close(pool)
  Ok(answer.status == 200
    && Json.as_int(Json.object_get(report, "live_keys")?)? == 1
    && Json.as_int(Json.object_get(report, "test_keys")?)? == 0
    && Json.as_int(Json.object_get(report, "redemptions")?)? == 100
    && Json.as_int(Json.object_get(report, "spent_set_failures")?)? == 1
    && Json.as_int(Json.object_get(report, "redeem_p95_ms")?)? == 95)
end

test("credit health reports accepted keys, spent-set failures and the redemption p95") do
  check("health", health())
end
