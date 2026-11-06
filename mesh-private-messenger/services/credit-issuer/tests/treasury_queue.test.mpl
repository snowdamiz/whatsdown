from Credits.Issuance import CreditQuote, encode_credit_quote
from Storage.TreasuryQueue import TreasuryObservationJob, claim_treasury_observations

# This fixture exercises SQL scheduling only. No synthetic response is accepted
# as a chain payment or passed to the real observation/signing worker.
fn queue_fixture(conn :: borrow PgConn,
  domain :: String,
  purpose :: Int,
  count :: Int) -> Result<(), String> do
  let key_id = Crypto.sha256(Bytes.from_utf8(domain))
  Pg.execute_values(conn,
    "INSERT INTO issuer_keys(key_id,epoch,purpose,spki,sealed_private_key) VALUES($1,$2::numeric,$3::smallint,$4,$5)",
    [
      Binary(key_id),
      Text(Bytes.read_uint_le(key_id, 0, 8)?),
      Text(Int.to_string(purpose)),
      Binary(Bytes.from_hex(String.repeat(Bytes.to_hex(key_id), 10)
        <> Bytes.to_hex(Bytes.slice(key_id, 0, 22)?))?),
      Binary(Bytes.from_hex(String.repeat("11", 68))?)
    ])?
  for index in 0..count do
    let quote_id = Crypto.sha256(Bytes.from_utf8(domain <> Int.to_string(index)))
    let quote = CreditQuote {
      quote_id: quote_id,
      deposit_owner: quote_id,
      destination: quote_id,
      mint: Bytes.from_hex(String.repeat("00", 32))?,
      asset: 1,
      amount: U64.parse("1000000")?,
      purpose: purpose,
      credits: 100,
      issued_at: U64.parse("1700000000")?,
      expires_at: U64.parse("1700000900")?,
      issuer_key_id: key_id,
      batch_hash: quote_id
    }
    Pg.execute_values(conn,
      "INSERT INTO issuer_quotes(quote_id,quote,key_id,batch_hash,deposit_owner,sealed_deposit_key,price_observed_at,payment_signature,payment_payer,payment_slot,payment_time,payment_amount,issued_response) VALUES($1,$2,$3,$1,$1,$4,0,$5,$1,1,1700000010,1000000,$6)",
      [
        Binary(quote_id),
        Binary(encode_credit_quote(quote)?),
        Binary(key_id),
        Binary(Bytes.from_hex(String.repeat("11", 99))?),
        Binary(Bytes.concat(quote_id, quote_id)?),
        Binary(Bytes.from_hex(String.repeat("00", 25670))?)
      ])?
  end
  Ok(nil)
end

fn drain_queue(pool :: PoolHandle,
  scope :: Bytes,
  now :: U64,
  remaining :: Int) -> List<TreasuryObservationJob>!String do
  if remaining == 0 do
    return Err("fixture_queue_did_not_drain")
  end
  let page = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do claim_treasury_observations(conn, 1, scope, now) end)?
  assert(List.length(page) <= 8)
  if List.length(page) == 0 do
    Ok([])
  else
    Ok(List.concat(page, drain_queue(pool, scope, now, remaining - 1)?))
  end
end

fn queue_proof(pool :: PoolHandle) -> Bool!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      queue_fixture(conn, "treasury-queue-test", 1, 10)?
      queue_fixture(conn, "treasury-queue-live", 0, 1)
    end)?
  let scope = Crypto.sha256(Bytes.from_utf8("queue-config"))
  let now = U64.parse("1700000100")?
  let expected = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let rows = Pg.query_values(conn,
        "SELECT COUNT(*)::text AS count FROM issuer_quotes q JOIN issuer_keys k USING(key_id) LEFT JOIN issuer_treasury_movements m ON m.payment_signature=q.payment_signature WHERE k.purpose=1 AND q.issued_response IS NOT NULL AND m.movement_id IS NULL",
        [])?
      case Map.get(List.head(rows), "count") do
        Text(value) -> U64.to_int(U64.parse(value)?)
        _ -> Err("invalid_fixture_count")
      end
    end)?
  let results = Job.map([0, 1],
    fn(_index) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do claim_treasury_observations(conn, 1, scope, now) end) end)
  let first = List.get(results, 0)??
  let second = List.get(results, 1)??
  assert(List.length(first) <= 8 && List.length(second) <= 8)
  let claimed = List.concat(List.concat(first, second), drain_queue(pool, scope, now, 128)?)
  assert(List.length(claimed) == expected)
  let ids = for item in claimed do
    Bytes.to_hex(item.quote_id)
  end
  for id in ids do
    assert(List.length(List.filter(ids, fn(value) do value == id end)) == 1)
  end
  for index in 0..10 do
    assert(List.contains(ids,
      Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("treasury-queue-test" <> Int.to_string(index))))))
  end
  assert(!List.contains(ids, Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("treasury-queue-live0")))))
  let deferred = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do claim_treasury_observations(conn, 1, scope, now) end)?
  assert(List.length(deferred) == 0)
  let retry = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do claim_treasury_observations(conn,
      1,
      scope,
      U64.add(now, U64.parse("60")?)?) end)?
  assert(List.length(retry) == 8)
  let live = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do claim_treasury_observations(conn, 0, scope, now) end)?
  assert(List.length(live) >= 1 && List.length(live) <= 8)
  assert(List.any(live,
    fn(value) do Bytes.secure_equals(value.quote_id,
      Crypto.sha256(Bytes.from_utf8("treasury-queue-live0"))) end))
  Ok(true)
end

test("bounded observation claims skip concurrent or unavailable rows and isolate credit purpose") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 4, 5000) do
    Ok(value) -> value
    Err(error) -> do
      println(error)
      assert(false)
      return
    end
  end
  let result = queue_proof(pool)
  Pool.close(pool)
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
