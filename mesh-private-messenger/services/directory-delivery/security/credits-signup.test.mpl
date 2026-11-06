from Credits.ActionWire import (
  CreditActionSubmission,
  encode_credit_action_submission,
  decode_credit_action_receipt,
  verify_credit_action_receipt
)
from Credits.Cancellation import decode_credit_cancellation, verify_credit_cancellation
from Storage.Credits import redeem_credits, prune_credit_ledger
from Runtime.Workers import next_work_at
from Credits.Signup import (
  CreditSignupRequest,
  encode_credit_signup_request,
  credit_signup_action,
  decode_credit_signup_result
)
from Credits.SignupPolicy import (
  decode_credit_signup_policy,
  verify_credit_signup_policy,
  credit_signup_policy_price
)
from Credits.Issuer import CreditIssuerKey, encode_issuer_key
from Credits.Policy import issuer_epoch
from Credits.Token import blind_credit, sign_credit_request, finalize_credit
from Credits.Wire import CreditFrame
from Storage.CreditIssuers import announce_credit_issuer, admit_credit_issuer
from Tests.MailboxSupport import test_directory_entry_wire, mailbox_test_now
from Protocol.DirectoryWire import decode_directory_entry, encode_directory_entry
from Transparency.Merkle import (
  leaf_hash_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence, TransparencyLookup, encode_transparency_lookup
from Privacy.Edge import mint_request_stamp, encode_stamped_request

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

fn post_action(base :: String, operation :: String, body :: Bytes) -> Reply!String do
  let response = Http.build(:post, base <> "/v1/credits/" <> operation)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(15000)
    |> Http.max_response_bytes(512)
    |> Http.send()
  let value = response?
  Ok(Reply { status: value.status, body: value.body_bytes })
end

fn post_paid(base :: String, body :: Bytes) -> Reply!String do
  post_action(base, "signup", body)
end

fn scalar(pool :: PoolHandle, query :: String) -> String!String do
  let rows = Pool.query(pool, query, [])?
  Ok(Map.get(List.head(rows), "value"))
end

fn policy(base :: String) -> Bytes!String do
  let response = Http.build(:post, base <> "/v1/credits/signup-policy")
    |> Http.body_bytes(Bytes.empty())
    |> Http.timeout(5000)
    |> Http.max_response_bytes(88)
    |> Http.send()
  let value = response?
  assert(value.status == 200)
  Ok(value.body_bytes)
end

fn proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL", "")
  let base = Env.get("CREDIT_TEST_CORE_URL", "")
  let base_difficulty = Env.get("CREDIT_TEST_BASE_CORE_URL", "")
  if !String.contains(url, "/credits_signup_test?")
    || !String.starts_with(base, "http://127.0.0.1:") do
    return Err("priority signup proof requires its disposable local PostgreSQL/HTTP harness")
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
  let now = U64.divide(mailbox_test_now()?, wide(1000)?)?
  let core_pair = pair("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX")?
  let paid_policy = decode_credit_signup_policy(policy(base)?)?
  let policy_now = U64.divide(mailbox_test_now()?, wide(1000)?)?
  assert(verify_credit_signup_policy(paid_policy, core_pair.public_key, 1, policy_now)?)
  assert(credit_signup_policy_price(paid_policy, core_pair.public_key, 1, policy_now)? == 20)
  let free_policy = decode_credit_signup_policy(policy(base_difficulty)?)?
  assert(credit_signup_policy_price(free_policy,
    core_pair.public_key,
    1,
    U64.divide(mailbox_test_now()?, wide(1000)?)?)? == 0)
  let disabled_policy = decode_credit_signup_policy(policy(Env.get("CREDIT_TEST_DISABLED_CORE_URL",
    ""))?)?
  assert(!disabled_policy.credits_enabled)
  assert(verify_credit_signup_policy(disabled_policy,
    core_pair.public_key,
    1,
    U64.divide(mailbox_test_now()?, wide(1000)?)?)?)
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
  let request = CreditSignupRequest {
    operation_nonce: bytes("22", 32)?,
    action_expires_at: U64.add(now, wide(600)?)?,
    entry: test_directory_entry_wire("credit-signup-owner", bytes("17", 32)?)?
  }
  let body = encode_credit_signup_request(request)?
  let tokens = for _index in 0..20 do
    let pending = blind_credit(key, core_pair.public_key.bytes, now)?
    let signed = sign_credit_request(secret, key, pending.request)?
    finalize_credit(key, pending, signed)?
  end
  let submission = CreditActionSubmission {
    action: credit_signup_action(request)?,
    request_body: body,
    frame: CreditFrame { binding: Crypto.sha256(body), tokens: tokens }
  }
  let encoded = encode_credit_action_submission(submission)?
  assert(post_paid(Env.get("CREDIT_TEST_DISABLED_CORE_URL", ""), encoded)?.status == 503)
  # No charge when the free base difficulty is in effect.
  assert(post_paid(base_difficulty, encoded)?.status == 409)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "0")
  let entry = case decode_directory_entry(request.entry) do
    Err(_) -> return Err("fixture entry invalid")
    Ok(value) -> value
  end
  let malformed = case encode_directory_entry(%{entry | prekey_bundle: bytes("ff", 32)?}) do
    Err(_) -> return Err("fixture invalid bundle encoding failed")
    Ok(value) -> %{request | entry: value}
  end
  let malformed_body = encode_credit_signup_request(malformed)?
  let malformed_submission = CreditActionSubmission {
    action: credit_signup_action(malformed)?,
    request_body: malformed_body,
    frame: %{submission.frame | binding: Crypto.sha256(malformed_body)}
  }
  assert(post_paid(base, encode_credit_action_submission(malformed_submission)?)?.status == 400)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "0")
  # A downstream registration failure rolls back spent tokens AND account/log.
  Pool.execute(pool,
    "CREATE FUNCTION credit_test_fail_signup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'simulated registration effect failure'; END $$",
    [])?
  Pool.execute(pool,
    "CREATE TRIGGER credit_test_fail_signup BEFORE INSERT ON messenger_devices FOR EACH ROW EXECUTE FUNCTION credit_test_fail_signup()",
    [])?
  assert(post_paid(base, encoded)?.status == 503)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "0")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_holds")? == "0")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM messenger_accounts")? == "0")
  Pool.execute(pool, "DROP TRIGGER credit_test_fail_signup ON messenger_devices", [])?
  Pool.execute(pool, "DROP FUNCTION credit_test_fail_signup()", [])?
  let raced = Job.map([0, 1], fn(_index) do post_paid(base, encoded) end)
  let replies = for reply in raced do
    reply??
  end
  assert(List.length(List.filter(replies, fn(reply) do reply.status == 201 end)) == 1)
  assert(List.length(List.filter(replies, fn(reply) do reply.status == 200 end)) == 1)
  let receipt_bytes = List.head(replies).body
  assert(Bytes.secure_equals(receipt_bytes, List.get(replies, 1).body))
  let receipt = decode_credit_action_receipt(receipt_bytes)?
  assert(verify_credit_action_receipt(receipt, core_pair.public_key, submission)?)
  let result = decode_credit_signup_result(receipt.result)?
  assert(Bytes.secure_equals(result.account_id, submission.action.target))
  assert(Bytes.secure_equals(result.entry_sha256, Crypto.sha256(request.entry)))
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "20")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM messenger_accounts")? == "1")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM messenger_devices")? == "1")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_action_effects")? == "1")
  # Completed retries ignore changed price, not the exact original binding.
  let recovered = post_paid(base_difficulty, encoded)?
  assert(recovered.status == 200 && Bytes.secure_equals(recovered.body, receipt_bytes))
  let another = %{request | operation_nonce: bytes("33", 32)?}
  let another_body = encode_credit_signup_request(another)?
  let fresh_tokens = for _index in 0..20 do
    let pending = blind_credit(key, core_pair.public_key.bytes, now)?
    let signed = sign_credit_request(secret, key, pending.request)?
    finalize_credit(key, pending, signed)?
  end
  let already_registered = CreditActionSubmission {
    action: credit_signup_action(another)?,
    request_body: another_body,
    frame: CreditFrame { binding: Crypto.sha256(another_body), tokens: fresh_tokens }
  }
  assert(post_paid(base, encode_credit_action_submission(already_registered)?)?.status == 409)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "20")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_holds")? == "1")
  # Reconciliation always returns the exact completion, even before expiry.
  let reconciled = post_action(base, "reconcile", encoded)?
  assert(reconciled.status == 200 && Bytes.secure_equals(reconciled.body, receipt_bytes))
  assert(post_action(base,
    "reconcile",
    encode_credit_action_submission(already_registered)?)?.status == 425)
  let recovery_now = U64.divide(mailbox_test_now()?, wide(1000)?)?
  let held_request = %{another |
    operation_nonce: bytes("44", 32)?,
    action_expires_at: U64.add(recovery_now, wide(2)?)?
  }
  let held_body = encode_credit_signup_request(held_request)?
  let held = CreditActionSubmission {
    action: credit_signup_action(held_request)?,
    request_body: held_body,
    frame: CreditFrame { binding: Crypto.sha256(held_body), tokens: fresh_tokens }
  }
  assert(redeem_credits(pool, held.action, held.request_body, held.frame)?.created)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "40")
  Timer.sleep(2100)
  let held_wire = encode_credit_action_submission(held)?
  let cancelled = post_action(base, "reconcile", held_wire)?
  assert(cancelled.status == 200)
  let cancellation = decode_credit_cancellation(cancelled.body)?
  assert(verify_credit_cancellation(cancellation, core_pair.public_key, held)?)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "20")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_holds")? == "1")
  let retry_cancel = post_action(base, "reconcile", held_wire)?
  assert(Bytes.secure_equals(retry_cancel.body, cancelled.body))
  # Never-submitted expired requests produce stateless exact proofs; a bearer
  # cannot allocate unlimited cancellation rows by inventing old nonces.
  let never = %{held_request | operation_nonce: bytes("47", 32)?}
  let never_body = encode_credit_signup_request(never)?
  let never_submission = CreditActionSubmission {
    action: credit_signup_action(never)?,
    request_body: never_body,
    frame: %{held.frame | binding: Crypto.sha256(never_body)}
  }
  let never_wire = encode_credit_action_submission(never_submission)?
  let never_reply = post_action(base, "reconcile", never_wire)?
  assert(never_reply.status == 200)
  assert(verify_credit_cancellation(decode_credit_cancellation(never_reply.body)?,
    core_pair.public_key,
    never_submission)?)
  assert(Bytes.secure_equals(never_reply.body, post_action(base, "reconcile", never_wire)?.body))
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_cancellations")? == "1")
  # A changed expiry with the same operation ID must remain fenced.
  let changed = %{held_request | action_expires_at: U64.add(recovery_now, wide(600)?)?}
  let changed_body = encode_credit_signup_request(changed)?
  let changed_submission = CreditActionSubmission {
    action: credit_signup_action(changed)?,
    request_body: changed_body,
    frame: %{held.frame | binding: Crypto.sha256(changed_body)}
  }
  assert(post_paid(base, encode_credit_action_submission(changed_submission)?)?.status == 409)
  assert(post_action(base,
    "reconcile",
    encode_credit_action_submission(changed_submission)?)?.status == 409)
  # The released exact tokens can pay for a distinct, real successful signup.
  let replacement = %{changed |
    operation_nonce: bytes("45", 32)?,
    entry: test_directory_entry_wire("credit-signup-recovered", bytes("18", 32)?)?
  }
  let replacement_body = encode_credit_signup_request(replacement)?
  let replacement_submission = CreditActionSubmission {
    action: credit_signup_action(replacement)?,
    request_body: replacement_body,
    frame: %{held.frame | binding: Crypto.sha256(replacement_body)}
  }
  assert(post_paid(base, encode_credit_action_submission(replacement_submission)?)?.status == 201)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "40")
  # Reusing those spent tokens in an unknown expired action cannot mint release evidence.
  let spent = %{held_request | operation_nonce: bytes("46", 32)?}
  let spent_body = encode_credit_signup_request(spent)?
  let spent_submission = CreditActionSubmission {
    action: credit_signup_action(spent)?,
    request_body: spent_body,
    frame: %{held.frame | binding: Crypto.sha256(spent_body)}
  }
  assert(post_action(base,
    "reconcile",
    encode_credit_action_submission(spent_submission)?)?.status == 409)
  # Real HTTP action passes its consume boundary before expiry, then pauses
  # in the database effect. Reconciliation arrives after expiry and must wait
  # for that transaction, returning CAR rather than releasing spent tokens.
  let racing_tokens = for _index in 0..20 do
    let pending = blind_credit(key, core_pair.public_key.bytes, now)?
    let signed = sign_credit_request(secret, key, pending.request)?
    finalize_credit(key, pending, signed)?
  end
  let racing_entry = test_directory_entry_wire("credit-signup-racing", bytes("19", 32)?)?
  Pool.execute(pool,
    "CREATE FUNCTION credit_test_slow_signup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(4); RETURN NEW; END $$",
    [])?
  Pool.execute(pool,
    "CREATE TRIGGER credit_test_slow_signup BEFORE INSERT ON messenger_devices FOR EACH ROW EXECUTE FUNCTION credit_test_slow_signup()",
    [])?
  let racing_now = U64.divide(mailbox_test_now()?, wide(1000)?)?
  let racing_request = %{held_request |
    operation_nonce: bytes("48", 32)?,
    action_expires_at: U64.add(racing_now, wide(2)?)?,
    entry: racing_entry
  }
  let racing_body = encode_credit_signup_request(racing_request)?
  let racing_submission = CreditActionSubmission {
    action: credit_signup_action(racing_request)?,
    request_body: racing_body,
    frame: CreditFrame { binding: Crypto.sha256(racing_body), tokens: racing_tokens }
  }
  let racing_wire = encode_credit_action_submission(racing_submission)?
  let raced_recovery = Job.map([0, 1],
    fn(index) do
      if index == 0 do
        post_paid(base, racing_wire)
      else
        Timer.sleep(2300)
        post_action(base, "reconcile", racing_wire)
      end
    end)
  let first_reply = List.get(raced_recovery, 0)??
  let second_reply = List.get(raced_recovery, 1)??
  assert(first_reply.status == 201 && second_reply.status == 200)
  assert(Bytes.secure_equals(first_reply.body, second_reply.body))
  assert(verify_credit_action_receipt(decode_credit_action_receipt(second_reply.body)?,
    core_pair.public_key,
    racing_submission)?)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_cancellations")? == "1")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "60")
  Pool.execute(pool, "DROP TRIGGER credit_test_slow_signup ON messenger_devices", [])?
  Pool.execute(pool, "DROP FUNCTION credit_test_slow_signup()", [])?
  # Cancellation fences participate in bounded ledger retention and wakeups.
  Pool.execute(pool, "DELETE FROM messenger_outbox_events", [])?
  Pool.execute(pool, "DELETE FROM messenger_envelopes", [])?
  Pool.execute(pool,
    "UPDATE credit_cancellations SET retain_until = floor(extract(epoch FROM clock_timestamp()))::bigint + 60",
    [])?
  let expected_due = case String.to_int(scalar(pool,
    "SELECT ((retain_until + 1) * 1000)::text AS value FROM credit_cancellations")?) do
    None -> return Err("test cancellation deadline failed")
    Some(value) -> value
  end
  assert(next_work_at(pool)? == expected_due)
  prune_credit_ledger(pool, 1)?
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_cancellations")? == "1")
  Pool.execute(pool,
    "INSERT INTO credit_cancellations SELECT sha256(('test-expired-'||n)::bytea), action, frame_hash, receipt, 1 FROM credit_cancellations CROSS JOIN generate_series(1,3) n",
    [])?
  prune_credit_ledger(pool, 1)?
  assert(scalar(pool,
    "SELECT count(*)::text AS value FROM credit_cancellations WHERE retain_until=1")? == "2")
  assert(scalar(pool,
    "SELECT count(*)::text AS value FROM credit_cancellations WHERE retain_until>1")? == "1")
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "60")
  # Signup has its own raised work requirement. Free signup follows the signed
  # policy, while other anonymous endpoints keep the shipped base difficulty.
  let free_entry = test_directory_entry_wire("free-raised-policy", bytes("20", 32)?)?
  let work_expiry = U64.add(mailbox_test_now()?, wide(240000)?)?
  let free_stamp = mint_request_stamp("mesh-msg/v1/work/register", free_entry, work_expiry, 17)?
  let free_reply = Http.build(:put, base <> "/v1/devices/register")
    |> Http.body_bytes(encode_stamped_request(free_stamp, free_entry)?)
    |> Http.timeout(10000)
    |> Http.max_response_bytes(512)
    |> Http.send()
  assert(free_reply?.status == 201)
  let lookup = encode_transparency_lookup(TransparencyLookup {
    username: "never-registered",
    previous_tree_size: 0
  })?
  let lookup_stamp = mint_request_stamp("mesh-msg/v1/work/resolve", lookup, work_expiry, 16)?
  let lookup_reply = Http.build(:post, base <> "/v1/devices/resolve")
    |> Http.body_bytes(encode_stamped_request(lookup_stamp, lookup)?)
    |> Http.timeout(10000)
    |> Http.max_response_bytes(512)
    |> Http.send()
  assert(lookup_reply?.status == 404)
  assert(scalar(pool, "SELECT count(*)::text AS value FROM credit_spent")? == "60")
  Pool.close(pool)
  Ok(true)
end

test("priority signup atomically registers one account, charges once and recovers exact signed completion") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
