from Credits.QuoteAuth import decode_signed_credit_quote, verify_credit_quote
from Credits.Issuance import (
  CreditQuoteRequest,
  CreditQuote,
  CreditIssueRequest,
  encode_credit_quote,
  encode_credit_quote_request,
  encode_credit_issue_request,
  encode_credit_issue_response,
  credit_batch_hash
)
from Credits.Issuer import CreditIssuerKey, issuer_key_id, encode_issuer_key
from Credits.Policy import issuer_epoch
from Credits.Token import blind_credit, finalize_credit, verify_credit_token
from Payment.Verify import PaymentReceipt, payment_token_address
from Storage.Issuance import (
  insert_issuer_key,
  insert_quote,
  issue_paid_on_connection,
  load_quote,
  admit_issuer_key
)
from Storage.Quotes import (
  create_quote_on_connection,
  create_quote_with_revenue_policy,
  quote_amount
)
from Api.Purchases import IssuerPolicy, quote_response, issue_response
from Storage.Keys import ensure_current_key
from Transparency.Merkle import (
  WitnessKey,
  leaf_hash_for,
  merkle_root_for,
  compact_inclusion_proof_for,
  compact_consistency_proof_for,
  sign_tree_checkpoint_for,
  sign_witness
)
from Transparency.Wire import TransparencyEvidence

fn wide(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

pub struct LedgerSeed do
  service_key :: Bytes
  key :: CreditIssuerKey
end

pub struct PaidBatch do
  request :: CreditIssueRequest
  payment :: PaymentReceipt
end

fn ledger(conn :: borrow PgConn) -> LedgerSeed!String do
  let wrapping = case StorageKey.platform() do
    Ok(value) -> value
    Err(_) -> return Err("fixture storage failed")
  end
  let private = case Crypto.blind_rsa_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture key failed")
  end
  let public = case Crypto.blind_rsa_public(private) do
    Ok(value) -> value
    Err(_) -> return Err("fixture public failed")
  end
  let now = wide(1700000000)?
  let service_pair = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture service failed")
  end
  let witness = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture witness failed")
  end
  let quote_pair = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture quote signer failed")
  end
  let service_key = service_pair.public_key.bytes
  let key = CreditIssuerKey {
    epoch: issuer_epoch(now)?,
    purpose: 1,
    spki: public.bytes,
    quote_public_key: quote_pair.public_key.bytes
  }
  insert_issuer_key(conn, key, private, quote_pair.private_key, wrapping, service_key)?
  insert_issuer_key(conn, key, private, quote_pair.private_key, wrapping, service_key)?
  assert(Result.is_err(insert_issuer_key(conn,
    %{key | quote_public_key: witness.public_key.bytes},
    private,
    witness.private_key,
    wrapping,
    service_key)))
  let entry = encode_issuer_key(key)?
  let tree = [leaf_hash_for(2, entry)?]
  let checkpoint = sign_tree_checkpoint_for(2,
    service_pair.private_key,
    service_key,
    wide(1)?,
    wide(1)?,
    merkle_root_for(2, tree)?,
    bytes("00", 32)?,
    wide(1700000000000)?)?
  let evidence = TransparencyEvidence {
    entry_bytes: entry,
    inclusion: compact_inclusion_proof_for(2, tree, 0)?,
    consistency: compact_consistency_proof_for(2, [], tree)?,
    checkpoint: checkpoint,
    witnesses: [sign_witness("outside", witness.private_key, checkpoint)?]
  }
  admit_issuer_key(conn,
    evidence,
    service_pair.public_key,
    [WitnessKey { witness_id: "outside", public_key: witness.public_key.bytes }],
    1,
    now,
    1)?
  let pending = blind_credit(key, service_key, now)?
  let first_request = pending.request
  let others = for _index in 0..99 do
    let next = blind_credit(key, service_key, now)?
    next.request
  end
  let requests = [first_request] ++ others
  let mint = bytes("44", 32)?
  let quote_request = CreditQuoteRequest {
    credits: 100,
    asset: 0,
    purpose: 1,
    issuer_key_id: issuer_key_id(key)?,
    batch_hash: credit_batch_hash(requests)?
  }
  let value = create_quote_with_revenue_policy(conn,
    quote_request,
    mint,
    wide(0)?,
    now,
    now,
    wrapping,
    service_key,
    2)?
  let policy_rows = Pg.query_values(conn,
    "SELECT policy_version::text FROM issuer_quotes WHERE quote_id=$1",
    [Binary(value.quote_id)])?
  assert(fixture_policy_text(Map.get(List.head(policy_rows), "policy_version"))? == "2")
  let retried_quote = create_quote_on_connection(conn,
    quote_request,
    mint,
    wide(0)?,
    now,
    wide(1700000001)?,
    wrapping,
    service_key)?
  assert(Bytes.secure_equals(encode_credit_quote(value)?, encode_credit_quote(retried_quote)?))
  let legacy = create_quote_on_connection(conn,
    %{quote_request | batch_hash: bytes("f1", 32)?},
    mint,
    wide(0)?,
    now,
    now,
    wrapping,
    service_key)?
  let legacy_policy = Pg.query_values(conn,
    "SELECT policy_version::text FROM issuer_quotes WHERE quote_id=$1",
    [Binary(legacy.quote_id)])?
  assert(fixture_policy_text(Map.get(List.head(legacy_policy), "policy_version"))? == "1")
  assert(Result.is_err(create_quote_on_connection(conn,
    %{quote_request | credits: 500},
    mint,
    wide(0)?,
    now,
    now,
    wrapping,
    service_key)))
  # SOL conversion rounds upward once, using an issuer-owned one-minute price.
  assert(quote_amount(100, 1, wide(3000000)?)? == wide(1666666667)?)
  assert(quote_amount(100, 0, wide(0)?)? == wide(5000000)?)
  assert(Result.is_err(quote_amount(100, 1, wide(0)?)))
  assert(load_quote(conn, value.quote_id)?.credits == 100)
  let request = CreditIssueRequest {
    quote_id: value.quote_id,
    transaction_signature: bytes("55", 64)?,
    requests: requests
  }
  let payment = PaymentReceipt {
    transaction_signature: request.transaction_signature,
    payer: bytes("66", 32)?,
    slot: wide(100)?,
    block_time: now,
    received_amount: value.amount
  }
  # These calls operate inside the surrounding transaction; the higher-level
  # workflow verifies finalized RPC payment before entering this boundary.
  # Public payment data cannot race a different blind batch into this quote.
  let attacker = %{request | requests: List.reverse(request.requests)}
  assert(Result.is_err(issue_paid_on_connection(conn,
    attacker,
    payment,
    wrapping,
    service_key,
    now)))
  let response = issue_paid_on_connection(conn, request, payment, wrapping, service_key, now)?
  assert(List.length(response.signatures) == 100)
  let revenue = Pg.query_values(conn,
    "SELECT amount::text FROM issuer_credit_revenue WHERE quote_id=$1 AND payment_signature=$2",
    [Binary(value.quote_id), Binary(payment.transaction_signature)])?
  assert(List.length(revenue) == 1)
  let recorded_amount = case Map.get(List.head(revenue), "amount") do
    Text(value) -> value
    _ -> return Err("invalid_revenue_row")
  end
  assert(recorded_amount == U64.to_string(payment.received_amount))
  let token = finalize_credit(key, pending, List.head(response.signatures))?
  assert(verify_credit_token(key, token, service_key, now, 1)?)
  let replay = issue_paid_on_connection(conn,
    request,
    payment,
    wrapping,
    service_key,
    wide(1800000000)?)?
  assert(Bytes.secure_equals(encode_credit_issue_response(response)?,
    encode_credit_issue_response(replay)?))
  let changed = %{request | transaction_signature: bytes("77", 64)?}
  assert(Result.is_err(issue_paid_on_connection(conn,
    changed,
    payment,
    wrapping,
    service_key,
    now)))
  let swapped = %{request | requests: List.reverse(request.requests)}
  assert(Result.is_err(issue_paid_on_connection(conn,
    swapped,
    payment,
    wrapping,
    service_key,
    now)))
  Ok(LedgerSeed { service_key: service_key, key: key })
end

test("issuer commits one paid blind batch and replays exact signatures after key expiry") do
  Test.install_in_memory_secure_store()
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 4, 5000) do
    Ok(value) -> value
    Err(error) -> do
      println(error)
      assert(false)
      return
    end
  end
  let result = Repo.transaction(pool, fn(conn :: borrow PgConn) do ledger(conn) end)
  let checked = case result do
    Ok(seed) -> concurrency(pool, seed)
    Err(error)
  end
  Pool.close(pool)
  case checked do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn prepare_race(conn :: borrow PgConn,
  seed :: LedgerSeed,
  id :: String,
  tx :: String) -> PaidBatch!String do
  let wrapping = case StorageKey.platform() do
    Ok(value) -> value
    Err(_) -> return Err("fixture storage failed")
  end
  let deposit = case Crypto.signing_generate() do
    Ok(value) -> value
    Err(_) -> return Err("fixture deposit failed")
  end
  let now = wide(1700000000)?
  let requests = for _index in 0..100 do
    let pending = blind_credit(seed.key, seed.service_key, now)?
    pending.request
  end
  let mint = bytes("44", 32)?
  let quote = CreditQuote {
    quote_id: bytes(id, 32)?,
    deposit_owner: deposit.public_key.bytes,
    destination: payment_token_address(deposit.public_key.bytes, mint)?,
    mint: mint,
    asset: 0,
    amount: wide(5000000)?,
    purpose: 1,
    credits: 100,
    issued_at: now,
    expires_at: wide(1700000900)?,
    issuer_key_id: issuer_key_id(seed.key)?,
    batch_hash: credit_batch_hash(requests)?
  }
  insert_quote(conn, quote, deposit.private_key, wrapping, seed.service_key, now)?
  Ok(PaidBatch {
    request: CreditIssueRequest {
      quote_id: quote.quote_id,
      transaction_signature: bytes(tx, 64)?,
      requests: requests
    },
    payment: PaymentReceipt {
      transaction_signature: bytes(tx, 64)?,
      payer: bytes("66", 32)?,
      slot: wide(100)?,
      block_time: now,
      received_amount: quote.amount
    }
  })
end

fn issue(pool :: PoolHandle, seed :: LedgerSeed, batch :: PaidBatch) -> String!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let wrapping = case StorageKey.platform() do
        Ok(value) -> value
        Err(_) -> return Err("fixture storage failed")
      end
      let response = issue_paid_on_connection(conn,
        batch.request,
        batch.payment,
        wrapping,
        seed.service_key,
        wide(1700000010)?)?
      Ok(Bytes.to_hex(Crypto.sha256(encode_credit_issue_response(response)?)))
    end)
end

fn unissued(pool :: PoolHandle, id :: Bytes) -> Bool!String do
  let rows = Pool.query_values(pool,
    "SELECT issued_response FROM issuer_quotes WHERE quote_id = $1",
    [Binary(id)])?
  Ok(case Map.get(List.head(rows), "issued_response") do
    Null -> true
    _ -> false
  end)
end

fn concurrency(pool :: PoolHandle, seed :: LedgerSeed) -> Bool!String do
  let batch = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do prepare_race(conn, seed, "12", "56") end)?
  # A failed authorization must leave the committed quote reusable.
  for amount in [wide(4999999)?, wide(5050001)?] do
    assert(Result.is_err(issue(pool,
      seed,
      %{batch | payment: %{batch.payment | received_amount: amount}})))
    assert(unissued(pool, batch.request.quote_id)?)
  end
  let raced = Job.map([0, 1, 2, 3], fn(_index) do issue(pool, seed, batch) end)
  let hashes = for result in raced do
    result??
  end
  assert(List.length(hashes) == 4)
  let rollback_batch = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do prepare_race(conn, seed, "14", "58") end)?
  Pool.query(pool,
    "CREATE FUNCTION reject_revenue_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced revenue insert failure'; END $$",
    [])?
  Pool.query(pool,
    "CREATE TRIGGER reject_revenue_fixture BEFORE INSERT ON issuer_credit_revenue FOR EACH ROW EXECUTE FUNCTION reject_revenue_fixture()",
    [])?
  let failed_issue = issue(pool, seed, rollback_batch)
  let still_unissued = unissued(pool, rollback_batch.request.quote_id)?
  Pool.query(pool, "DROP TRIGGER reject_revenue_fixture ON issuer_credit_revenue", [])?
  Pool.query(pool, "DROP FUNCTION reject_revenue_fixture()", [])?
  assert(Result.is_err(failed_issue))
  assert(still_unissued)
  issue(pool, seed, rollback_batch)?
  for hash in hashes do
    assert(hash == List.head(hashes))
  end
  # Even a buggy caller cannot reassign one confirmed transaction to two quotes.
  let other = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do prepare_race(conn, seed, "13", "56") end)?
  assert(Result.is_err(issue(pool, seed, other)))
  assert(unissued(pool, other.request.quote_id)?)
  let corrected = %{other |
    request: %{other.request | transaction_signature: bytes("57", 64)?},
    payment: %{other.payment | transaction_signature: bytes("57", 64)?}
  }
  issue(pool, seed, corrected)?
  assert(!unissued(pool, other.request.quote_id)?)
  let wrapping = case StorageKey.platform() do
    Ok(value) -> value
    Err(_) -> return Err("fixture storage failed")
  end
  let policy = IssuerPolicy {
    enabled: true,
    revenue_policy: 1,
    purpose: 1,
    service_key: seed.service_key,
    mint: bytes("44", 32)?,
    rpc_url: "http://127.0.0.1:1/unreachable",
    oracle_account: "11111111111111111111111111111111"
  }
  # A committed response survives RPC outage and epoch expiry, including when
  # new issuance is switched off. HTTP never accepts a caller payment receipt.
  let body = encode_credit_issue_request(corrected.request)?
  let recovered = issue_response(pool,
    %{policy | enabled: false},
    body,
    fixture_key,
    wide(1800000000)?)
  assert(recovered.status == 200)
  assert(Bytes.to_hex(Crypto.sha256(recovered.body)) == issue(pool, seed, corrected)?)
  assert(issue_response(pool, policy, Bytes.empty(), fixture_key, wide(1700000000)?).status == 400)
  let changed = %{corrected.request | transaction_signature: bytes("99", 64)?}
  assert(issue_response(pool,
    policy,
    encode_credit_issue_request(changed)?,
    fixture_key,
    wide(1700000000)?).status == 409)
  let changed_batch = %{corrected.request | requests: List.reverse(corrected.request.requests)}
  assert(issue_response(pool,
    policy,
    encode_credit_issue_request(changed_batch)?,
    fixture_key,
    wide(1700000000)?).status == 409)
  let quote = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_quote(conn, corrected.request.quote_id) end)?
  let query = CreditQuoteRequest {
    credits: quote.credits,
    asset: quote.asset,
    purpose: quote.purpose,
    issuer_key_id: quote.issuer_key_id,
    batch_hash: quote.batch_hash
  }
  let quote_body = encode_credit_quote_request(query)?
  let quote_replay = quote_response(pool, policy, quote_body, fixture_key, wide(1800000000)?)
  assert(quote_replay.status == 200)
  let authenticated = decode_signed_credit_quote(quote_replay.body)?
  assert(verify_credit_quote(authenticated, seed.key)?)
  assert(Bytes.secure_equals(encode_credit_quote(authenticated.quote)?,
    encode_credit_quote(quote)?))
  let replay_again = quote_response(pool, policy, quote_body, fixture_key, wide(1800000001)?)
  assert(Bytes.secure_equals(quote_replay.body, replay_again.body))
  assert(quote_response(pool,
    %{policy | enabled: false},
    quote_body,
    fixture_key,
    wide(1700000000)?).status == 503)
  assert(quote_response(pool,
    %{policy | purpose: 0},
    quote_body,
    fixture_key,
    wide(1700000000)?).status == 400)
  assert(quote_response(pool, policy, Bytes.empty(), fixture_key, wide(1700000000)?).status == 400)
  let active = ensure_current_key(pool, 1, wide(1700000000)?, fixture_key, seed.service_key)?
  assert(active.admitted)
  assert(issuer_key_id(active.key)? == issuer_key_id(seed.key)?)
  let rotations = Job.map([0, 1],
    fn(_index) do ensure_current_key(pool, 1, wide(1800000000)?, fixture_key, seed.service_key) end)
  let ids = for rotated in rotations do
    let value = rotated??
    assert(!value.admitted)
    assert(value.key.epoch == issuer_epoch(wide(1800000000)?)?)
    issuer_key_id(value.key)?
  end
  assert(List.head(ids) == List.get(ids, 1))
  assert(List.head(ids) != issuer_key_id(seed.key)?)
  # Migration002 preserves old development records, never silently assigns a
  # new quote authority to an already-known RSA key or returns a bare quote.
  Pool.execute_values(pool,
    "UPDATE issuer_keys SET quote_public_key = NULL, sealed_quote_key = NULL WHERE key_id = $1",
    [Binary(List.head(ids))])?
  assert(Result.is_err(ensure_current_key(pool,
    1,
    wide(1800000000)?,
    fixture_key,
    seed.service_key)))
  let legacy = Pool.query_values(pool,
    "SELECT quote_public_key, sealed_quote_key FROM issuer_keys WHERE key_id = $1",
    [Binary(List.head(ids))])?
  assert(case Map.get(List.head(legacy), "quote_public_key") do
    Null -> true
    _ -> false
  end)
  assert(case Map.get(List.head(legacy), "sealed_quote_key") do
    Null -> true
    _ -> false
  end)
  Pool.execute_values(pool,
    "UPDATE issuer_quotes SET signed_quote = NULL WHERE quote_id = $1",
    [Binary(quote.quote_id)])?
  assert(quote_response(pool, policy, quote_body, fixture_key, wide(1800000002)?).status == 503)
  Ok(true)
end

fn fixture_key() -> StorageKey!String do
  case StorageKey.platform() do
    Ok(value)
    Err(_) -> Err("fixture storage failed")
  end
end

fn fixture_policy_text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_policy_fixture")
  end
end
