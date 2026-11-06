from Credits.Issuance import CreditQuote, encode_credit_quote
from Storage.TreasuryQueue import ready_treasury_batch_members, claim_treasury_funding
from Storage.Treasury import load_treasury_movement
from Payment.Verify import payment_token_address

fn qp_key(domain :: String) -> Bytes do
  Crypto.sha256(Bytes.from_utf8("treasury-queue-policy/" <> domain))
end

fn qp_bytes(byte :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(byte, count))
end

fn qp_number(value :: DbValue) -> U64!String do
  case value do
    Text(output) -> U64.parse(output)
    _ -> Err("invalid_queue_policy_fixture")
  end
end

# Scheduling fixtures only. These rows never reach chain observation or signing;
# the actual SBF/Agave probes separately authenticate deposits and execute packets.
fn qp_movement(conn :: borrow PgConn,
  domain :: String,
  scope :: Bytes,
  asset :: Int,
  kind :: Int,
  mint :: Bytes,
  ready :: Int) -> Bytes!String do
  let id = qp_key(domain)
  let key_id = qp_key("key/" <> domain)
  let quote = CreditQuote {
    quote_id: id,
    deposit_owner: id,
    destination: if asset == 0 do
      payment_token_address(id, mint)?
    else
      id
    end,
    mint: mint,
    asset: asset,
    amount: U64.parse("5000000")?,
    purpose: 1,
    credits: 100,
    issued_at: U64.parse("1700000000")?,
    expires_at: U64.parse("1700000900")?,
    issuer_key_id: key_id,
    batch_hash: id
  }
  let signature = Bytes.concat(id, id)?
  Pg.execute_values(conn,
    "INSERT INTO issuer_keys(key_id,epoch,purpose,spki,sealed_private_key) VALUES($1,$2::numeric,1,$3,$4)",
    [
      Binary(key_id),
      Text(Bytes.read_uint_le(key_id, 0, 8)?),
      Binary(Bytes.from_hex(String.repeat(Bytes.to_hex(key_id), 10)
        <> Bytes.to_hex(Bytes.slice(key_id, 0, 22)?))?),
      Binary(qp_bytes("11", 68)?)
    ])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_quotes(quote_id,quote,key_id,batch_hash,deposit_owner,sealed_deposit_key,price_observed_at) VALUES($1,$2,$3,$1,$1,$4,0)",
    [Binary(id), Binary(encode_credit_quote(quote)?), Binary(key_id), Binary(qp_bytes("11", 99)?)])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_payment_observations(payment_signature,quote_id,payer,slot,payment_time,amount,wire_sha256,disposition) VALUES($1,$2,$3,1,1700000010,5000000,$2,0)",
    [Binary(signature), Binary(id), Binary(qp_key("payer/" <> domain))])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_treasury_movements(movement_id,payment_signature,kind,config_hash,source,destination,destination_owner,amount,ready_at) VALUES($1,$2,$3::smallint,$4,$5,$6,$6,5000000,$7::numeric)",
    [
      Binary(id),
      Binary(signature),
      Text(Int.to_string(kind)),
      Binary(scope),
      Binary(quote.destination),
      Binary(qp_key("target/" <> domain)),
      Text(Int.to_string(ready))
    ])?
  Ok(id)
end

fn qp_ready_proof(pool :: PoolHandle) -> Bool!String do
  let scope = qp_key("ready-config")
  let zero = qp_bytes("00", 32)?
  let mint = qp_bytes("44", 32)?
  let now = U64.parse("2000")?
  let expected = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let ids = for index in 0..5 do
        qp_movement(conn, "sol-refund/" <> Int.to_string(index), scope, 1, 1, zero, 1000 + index)?
      end
      qp_movement(conn, "sol-sweep", scope, 1, 0, zero, 1010)?
      qp_movement(conn, "token-refund", scope, 0, 1, mint, 1011)?
      qp_movement(conn, "token-refund-other-mint", scope, 0, 1, qp_bytes("45", 32)?, 1012)?
      qp_movement(conn, "future-refund", scope, 1, 1, zero, 3000)?
      qp_movement(conn, "foreign-earlier", qp_key("other-config"), 1, 1, zero, 1)?
      let reserved = qp_movement(conn, "reserved-earlier", scope, 1, 1, zero, 2)?
      Pg.execute_values(conn,
        "UPDATE issuer_treasury_movements SET message=$2,nonce_address=$3,nonce_value=$3 WHERE movement_id=$1",
        [Binary(reserved), Binary(qp_bytes("01", 1)?), Binary(qp_key("reserved-nonce"))])?
      Ok(ids)
    end)?
  # Selection is advisory: concurrent readers may see the same candidates.
  # The actual four-process batch proof qualifies exclusive immutable reservation.
  let concurrent = Job.map([0, 1],
    fn(_) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do ready_treasury_batch_members(conn, scope, now) end) end)
  for result in concurrent do
    let selected = result??
    assert(List.length(selected) == 4)
    for index in 0..4 do
      assert(Bytes.secure_equals(List.get(selected, index), List.get(expected, index)))
    end
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do # Simulate assignment by the already-qualified batch boundary, preserving
      # state/message constraints; these rows are now ineligible for new selection.
      for id in expected do
        Pg.execute_values(conn,
          "UPDATE issuer_treasury_movements SET message=$2,nonce_address=$1,nonce_value=$1 WHERE movement_id=$1",
          [Binary(id), Binary(qp_bytes("01", 1)?)])?
      end
      let sweep = ready_treasury_batch_members(conn, scope, now)?
      assert(List.length(sweep) == 1 && Bytes.secure_equals(List.head(sweep), qp_key("sol-sweep")))
      Pg.execute_values(conn,
        "UPDATE issuer_treasury_movements SET message=$2,nonce_address=$1,nonce_value=$1 WHERE movement_id=$1",
        [Binary(List.head(sweep)), Binary(qp_bytes("01", 1)?)])?
      let token = ready_treasury_batch_members(conn, scope, now)?
      assert(List.length(token) == 1
        && Bytes.secure_equals(List.head(token), qp_key("token-refund")))
      let member = load_treasury_movement(conn, List.head(token))?
      assert(member.quote.asset == 0
        && member.kind == 1
        && Bytes.secure_equals(member.quote.mint, mint))
      Ok(true)
    end)
end

fn qp_week(conn :: borrow PgConn,
  week :: Int,
  scope :: Bytes,
  asset :: Int,
  witness :: Int) -> U64!String do
  let rows = Pg.query_values(conn,
    "INSERT INTO issuer_treasury_weekly(week,asset,cutoff,mint,config_hash,amount,witness,operations,carry_before,carry_after,membership_hash) VALUES($1::numeric,$2::smallint,0,$3,$4,$5::numeric,$6::numeric,$7::numeric,0,0,$4) RETURNING batch_id::text",
    [
      Text(Int.to_string(week)),
      Text(Int.to_string(asset)),
      Binary(qp_bytes(if asset == 0 do
          "44"
        else
          "00"
        end,
        32)?),
      Binary(scope),
      Text(Int.to_string(witness * 5)),
      Text(Int.to_string(witness)),
      Text(Int.to_string(witness * 4))
    ])?
  qp_number(Map.get(List.head(rows), "batch_id"))
end

fn qp_intent(conn :: borrow PgConn, batch :: U64, state :: Int) -> Result<(), String> do
  let id = qp_key("funding-intent/" <> U64.to_string(batch))
  Pg.execute_values(conn,
    "INSERT INTO issuer_treasury_rewards_intents(intent_id,batch_id,epoch,pool,funder,source,mint,amount,state,receipt) VALUES($1,$2::bigint,1,$3,$3,$3,$3,1,$4::smallint,$5)",
    [
      Binary(id),
      Text(U64.to_string(batch)),
      Binary(qp_key("public-pin")),
      Text(Int.to_string(state)),
      if state == 1 do
        Binary(qp_bytes("01", 192)?)
      else
        Null
      end
    ])?
  Ok(nil)
end

fn qp_funding_proof(pool :: PoolHandle) -> Bool!String do
  let scope = qp_key("funding-config")
  let now = U64.parse("1000000")?
  let eligible = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let ids = for index in 0..12 do
        qp_week(conn, 800000 + index, scope, 0, 1)?
      end
      qp_intent(conn, List.get(ids, 0), 0)?
      qp_intent(conn, List.get(ids, 1), 2)?
      let funded = qp_week(conn, 800012, scope, 0, 1)?
      qp_intent(conn, funded, 1)?
      qp_week(conn, 800013, scope, 1, 1)?
      qp_week(conn, 800014, scope, 0, 0)?
      qp_week(conn, 800015, qp_key("foreign-funding-config"), 0, 1)?
      let deferred = qp_week(conn, 800016, scope, 0, 1)?
      Pg.execute_values(conn,
        "INSERT INTO issuer_treasury_funding_jobs(batch_id,next_attempt) VALUES($1::bigint,$2::numeric)",
        [Text(U64.to_string(deferred)), Text(U64.to_string(U64.add(now, U64.parse("120")?)?))])?
      Ok(ids)
    end)?
  let races = Job.map([0, 1],
    fn(_) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do claim_treasury_funding(conn, scope, now) end) end)
  let first = List.get(races, 0)??
  let second = List.get(races, 1)??
  assert(List.length(first) <= 8 && List.length(second) <= 8)
  let claimed = first ++ second
  assert(List.length(claimed) == 12)
  for id in eligible do
    assert(List.length(List.filter(claimed, fn(actual) do actual == id end)) == 1)
  end
  let empty = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do claim_treasury_funding(conn,
      scope,
      U64.add(now, U64.parse("59")?)?) end)?
  assert(List.length(empty) == 0)
  let retry = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do claim_treasury_funding(conn,
      scope,
      U64.add(now, U64.parse("60")?)?) end)?
  assert(List.length(retry) == 8)
  assert(List.all(retry, fn(id) do List.contains(eligible, id) end))
  let remainder = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do claim_treasury_funding(conn,
      scope,
      U64.add(now, U64.parse("60")?)?) end)?
  assert(List.length(remainder) == 4)
  assert(List.all(remainder, fn(id) do !List.contains(retry, id) end))
  # Remove only this scheduling fixture's closed-week rows so later accounting
  # tests are independent of module enumeration order and its synthetic dates.
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let scopes = [Binary(scope), Binary(qp_key("foreign-funding-config"))]
      Pg.execute_values(conn,
        "DELETE FROM issuer_treasury_funding_jobs WHERE batch_id IN(SELECT batch_id FROM issuer_treasury_weekly WHERE config_hash=$1 OR config_hash=$2)",
        scopes)?
      Pg.execute_values(conn,
        "DELETE FROM issuer_treasury_rewards_intents WHERE batch_id IN(SELECT batch_id FROM issuer_treasury_weekly WHERE config_hash=$1 OR config_hash=$2)",
        scopes)?
      Pg.execute_values(conn,
        "DELETE FROM issuer_treasury_weekly WHERE config_hash=$1 OR config_hash=$2",
        scopes)?
      Ok(nil)
    end)?
  Ok(true)
end

test("ready queue selects bounded compatible policy and excludes reserved future or foreign movements") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 4, 5000) do
    Ok(value) -> value
    Err(_) -> do
      assert(false)
      return
    end
  end
  let result = qp_ready_proof(pool)
  Pool.close(pool)
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

test("funding leases claim every page once under concurrency and exclude wrong scope completed SOL or empty liabilities") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 4, 5000) do
    Ok(value) -> value
    Err(_) -> do
      assert(false)
      return
    end
  end
  let result = qp_funding_proof(pool)
  Pool.close(pool)
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
