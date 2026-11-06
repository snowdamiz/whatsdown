from Credits.ActionWire import (
  CreditActionSubmission,
  encode_credit_action_submission,
  decode_credit_action_receipt,
  verify_credit_action_receipt
)
from Credits.Retention import (
  sign_credit_retention_request,
  encode_credit_retention_request,
  credit_retention_action,
  decode_credit_retention_result
)
from Credits.Issuer import CreditIssuerKey, encode_issuer_key
from Credits.Policy import issuer_epoch
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Credits.Wire import CreditFrame
from Storage.CreditIssuers import announce_credit_issuer, admit_credit_issuer
from Storage.Delivery import enqueue_envelope, fetch_mailbox, DeliveryInsert
from Storage.MailboxAuth import mailbox_owner
from Storage.Retention import purge_envelopes
from Tests.MailboxSupport import register_test_mailbox, mailbox_test_now
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.V1 import OuterEnvelope
from Transparency.Merkle import (
  leaf_hash_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence

struct Reply do
  status :: Int
  body :: Bytes
end

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

fn pair(name :: String) -> SigningKeyPair!String do
  let seed = case Env.get_secret_hex(name) do
    Ok(value) -> value
    Err(_) -> return Err("test signer missing")
  end
  case Crypto.signing_from_secret(seed) do
    Ok(value)
    Err(_) -> Err("test signer invalid")
  end
end

fn post_paid(base :: String, body :: Bytes) -> Reply!String do
  println("RETENTION_SEND bytes #{Bytes.length(body)}")
  let response = Http.build(:post, base <> "/v1/credits/retention")
    |> Http.header("Accept-Encoding", "identity")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(15000)
    |> Http.max_response_bytes(512)
    |> Http.send()
  let value = response?
  println("RETENTION_RESPONSE #{value.status}")
  Ok(Reply { status: value.status, body: value.body_bytes })
end

fn scalar(pool :: PoolHandle, query :: String) -> String!String do
  let rows = Pool.query(pool, query, [])?
  Ok(Map.get(List.head(rows), "value"))
end

fn proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL", "")
  let base = Env.get("CREDIT_TEST_CORE_URL", "")
  if !String.contains(url, "/credits_retention_test?")
    || !String.starts_with(base, "http://127.0.0.1:") do
    return Err("paid retention proof requires its disposable local PostgreSQL/HTTP harness")
  end
  let pool = Pool.open(url, 1, 4, 5000)?
  assert(post_paid(base, Bytes.empty())?.status == 400)
  let secret = case Crypto.blind_rsa_generate() do
    Ok(value) -> value
    Err(_) -> return Err("test RSA failed")
  end
  let public = case Crypto.blind_rsa_public(secret) do
    Ok(value) -> value
    Err(_) -> return Err("test RSA public failed")
  end
  let now_ms = mailbox_test_now()?
  let now = U64.divide(now_ms, wide(1000)?)?
  let core_pair = pair("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX")?
  let first = pair("CREDIT_FIXTURE_WITNESS_A_SEED")?
  let second = pair("CREDIT_FIXTURE_WITNESS_B_SEED")?
  let key = CreditIssuerKey {
    epoch: issuer_epoch(now)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: core_pair.public_key.bytes
  }
  let leaf = encode_issuer_key(key)?
  let announced = announce_credit_issuer(pool, leaf)?
  let tree = [leaf_hash_for(2, leaf)?]
  admit_credit_issuer(pool,
    TransparencyEvidence {
      entry_bytes: leaf,
      inclusion: compact_inclusion_proof_for(2, tree, 0)?,
      consistency: compact_consistency_proof_for(2, [], tree)?,
      checkpoint: announced.checkpoint,
      witnesses: [
        sign_witness("witness-a", first.private_key, announced.checkpoint)?,
        sign_witness("witness-b", second.private_key, announced.checkpoint)?
      ]
    })?
  let token = bytes("17", 32)?
  let owner = register_test_mailbox(pool, "credit-retention-owner", token)?
  let mailbox = Crypto.sha256(token)
  let request = sign_credit_retention_request(owner.signing_private_key,
    mailbox,
    bytes("22", 32)?,
    180,
    U64.add(now, wide(600)?)?,
    now_ms)?
  let body = encode_credit_retention_request(request)?
  let tokens = for _index in 0..50 do
    let pending = blind_credit(key, core_pair.public_key.bytes, now)?
    let signed = sign_credit_request(secret, key, pending.request)?
    finalize_credit(key, pending, signed)?
  end
  let submission = CreditActionSubmission {
    action: credit_retention_action(request)?,
    request_body: body,
    frame: CreditFrame { binding: Crypto.sha256(body), tokens: tokens }
  }
  let encoded = encode_credit_action_submission(submission)?
  assert(post_paid(Env.get("CREDIT_TEST_DISABLED_CORE_URL", ""), encoded)?.status == 503)
  let stranger = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("test stranger failed")
  end
  let forged = sign_credit_retention_request(stranger.private_key,
    mailbox,
    request.operation_nonce,
    180,
    request.action_expires_at,
    request.issued_at_ms)?
  let forged_body = encode_credit_retention_request(forged)?
  let forged_submission = CreditActionSubmission {
    action: credit_retention_action(forged)?,
    request_body: forged_body,
    frame: %{submission.frame | binding: Crypto.sha256(forged_body)}
  }
  assert(post_paid(base, encode_credit_action_submission(forged_submission)?)?.status == 403)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "0")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_holds")? == "0")
  let original_expiration = U64.add(mailbox_test_now()?, wide(3600000)?)?
  let envelope = OuterEnvelope {
    version: 1,
    envelope_id: bytes("35", 16)?,
    mailbox_token: token,
    suite: 1,
    expiration: original_expiration,
    padding_bucket: 256,
    ciphertext: Bytes.from_utf8("original ciphertext")
  }
  assert(enqueue_envelope(pool, envelope)? == Accepted)
  Pool.execute(pool,
    "CREATE FUNCTION credit_test_fail_retention() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'simulated parking effect failure'; END $$",
    [])?
  Pool.execute(pool,
    "CREATE TRIGGER credit_test_fail_retention BEFORE UPDATE OF credit_retention_until_ms ON messenger_mailboxes FOR EACH ROW EXECUTE FUNCTION credit_test_fail_retention()",
    [])?
  assert(post_paid(base, encoded)?.status == 503)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "0")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_holds")? == "0")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_action_effects")? == "0")
  assert(scalar(pool,
    "SELECT max(credit_retention_until_ms)::text AS value FROM messenger_mailboxes")? == "0")
  Pool.execute(pool, "DROP TRIGGER credit_test_fail_retention ON messenger_mailboxes", [])?
  Pool.execute(pool, "DROP FUNCTION credit_test_fail_retention()", [])?
  let raced = Job.map([0, 1], fn(_index) do post_paid(base, encoded) end)
  let replies = for reply in raced do
    reply??
  end
  for reply in replies do
    println("RETENTION_HTTP_STATUS #{reply.status}")
  end
  assert(List.length(List.filter(replies, fn(reply) do reply.status == 201 end)) == 1)
  assert(List.length(List.filter(replies, fn(reply) do reply.status == 200 end)) == 1)
  let response = List.head(replies).body
  assert(Bytes.secure_equals(response, List.get(replies, 1).body))
  let receipt = decode_credit_action_receipt(response)?
  assert(verify_credit_action_receipt(receipt, core_pair.public_key, submission)?)
  let result = decode_credit_retention_result(receipt.result)?
  assert(Bytes.secure_equals(result.mailbox_hash, mailbox) && result.days == 180)
  assert(result.effective_until_ms == U64.add(U64.multiply(receipt.applied_at, wide(1000)?)?,
      wide(180 * 86400000)?)?)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "50")
  assert(scalar(pool,
    "SELECT count(*)::text AS value FROM credit_holds WHERE consumed_at IS NOT NULL")? == "1")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_action_effects")? == "1")
  assert(scalar(pool,
    "SELECT expiration_ms::text AS value FROM messenger_envelopes")? == U64.to_string(original_expiration))
  assert(scalar(pool,
    "SELECT storage_until_ms::text AS value FROM messenger_envelopes")? == U64.to_string(result.effective_until_ms))
  let original_owner = case mailbox_owner(pool, mailbox)? do
    Some(value) -> value
    None -> return Err("owner disappeared")
  end
  # Simulate passage past the original queue TTL without altering the paid
  # storage deadline. The delivered original header/ciphertext stay untouched.
  Pool.execute(pool, "UPDATE messenger_envelopes SET expiration_ms = 1", [])?
  assert(purge_envelopes(pool, 3600, 100)? == 0)
  let fetched = fetch_mailbox(pool, original_owner, wide(0)?)?
  assert(List.length(fetched) == 1)
  let delivered = case decode_outer_envelope(List.head(fetched).envelope) do
    Ok(value) -> value
    Err(_) -> return Err("invalid delivered retained envelope")
  end
  assert(delivered.expiration == wide(1)?
    && Bytes.secure_equals(delivered.ciphertext, envelope.ciphertext))
  Pool.execute(pool, "UPDATE messenger_mailboxes SET active = false", [])?
  let recovered = post_paid(base, encoded)?
  assert(recovered.status == 200 && Bytes.secure_equals(recovered.body, response))
  Pool.execute(pool, "UPDATE messenger_mailboxes SET active = true", [])?
  let next = %{envelope |
    envelope_id: bytes("36", 16)?,
    expiration: U64.add(mailbox_test_now()?, wide(3600000)?)?
  }
  assert(enqueue_envelope(pool, next)? == Accepted)
  assert(scalar(pool,
    "SELECT min(storage_until_ms)::text AS value FROM messenger_envelopes")? == U64.to_string(result.effective_until_ms))
  Pool.execute(pool,
    "UPDATE messenger_envelopes SET acknowledged_at = clock_timestamp() - interval '2 hours'",
    [])?
  assert(purge_envelopes(pool, 3600, 100)? == 2)
  let changed = %{submission |
    frame: %{submission.frame | tokens: List.reverse(submission.frame.tokens)}
  }
  assert(post_paid(base, encode_credit_action_submission(changed)?)?.status == 409)
  Pool.close(pool)
  Ok(true)
end

test("paid mailbox parking consumes once with its durable effect and authenticated exact receipt") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
