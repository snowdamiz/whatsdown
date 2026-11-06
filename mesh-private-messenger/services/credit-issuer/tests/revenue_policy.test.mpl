from Storage.TreasuryFunding import reserve_treasury_funding, load_treasury_funding
from Payment.Treasury import TreasuryChainConfig, treasury_config_hash
from Transparency.RewardsChain import reward_pool_address
from Solana.Read import Pubkey
from Storage.LightningRevenue import freeze_lightning_revenue_week
from Payment.RevenuePolicy import credit_revenue_policy_hash, split_credit_revenue
from Storage.Treasury import record_issued_credit_revenue, freeze_treasury_week
from Storage.RevenuePolicy import freeze_policy_treasury_week
from Credits.Issuance import CreditQuote, encode_credit_quote
from Payment.Verify import payment_token_address

fn rp_key(value :: String) -> Bytes do
  Crypto.sha256(Bytes.from_utf8("policy-proof/" <> value))
end

fn rp_bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

fn rp_text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_policy_fixture")
  end
end

# SQL fixtures isolate accounting from the separately qualified chain verifier.
# Every movement here has an issued payment and finalized-success state.
fn rp_event(conn :: borrow PgConn,
  domain :: String,
  version :: Int,
  amount :: Int,
  scope :: Bytes) -> Bytes!String do
  let id = rp_key(domain)
  let key = rp_key("key/" <> domain)
  let mint = rp_bytes("44", 32)?
  let quote = CreditQuote {
    quote_id: id,
    deposit_owner: id,
    destination: payment_token_address(id, mint)?,
    mint: mint,
    asset: 0,
    amount: U64.parse("5000000")?,
    purpose: 1,
    credits: 100,
    issued_at: U64.parse("1700000000")?,
    expires_at: U64.parse("1700000900")?,
    issuer_key_id: key,
    batch_hash: id
  }
  let signature = Bytes.concat(id, id)?
  Pg.execute_values(conn,
    "INSERT INTO issuer_keys(key_id,epoch,purpose,spki,sealed_private_key) VALUES($1,$2::numeric,1,$3,$4)",
    [
      Binary(key),
      Text(Bytes.read_uint_le(key, 0, 8)?),
      Binary(Bytes.from_hex(String.repeat(Bytes.to_hex(key), 10)
        <> Bytes.to_hex(Bytes.slice(key, 0, 22)?))?),
      Binary(rp_bytes("11", 68)?)
    ])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_quotes(quote_id,quote,key_id,batch_hash,deposit_owner,sealed_deposit_key,price_observed_at,policy_version,policy_hash,payment_signature,payment_payer,payment_slot,payment_time,payment_amount,issued_response) VALUES($1,$2,$3,$1,$1,$4,0,$5::smallint,$6,$7,$1,1,1700000010,$8::numeric,$9)",
    [
      Binary(id),
      Binary(encode_credit_quote(quote)?),
      Binary(key),
      Binary(rp_bytes("11", 99)?),
      Text(Int.to_string(version)),
      Binary(credit_revenue_policy_hash(version)?),
      Binary(signature),
      Text(Int.to_string(amount)),
      Binary(rp_bytes("01", 25670)?)
    ])?
  record_issued_credit_revenue(conn, id)?
  record_issued_credit_revenue(conn, id)?
  Pg.execute_values(conn,
    "INSERT INTO issuer_payment_observations(payment_signature,quote_id,payer,slot,payment_time,amount,wire_sha256,disposition) VALUES($1,$2,$2,1,1700000010,$3::numeric,$2,0)",
    [Binary(signature), Binary(id), Text(Int.to_string(amount))])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_treasury_movements(movement_id,payment_signature,kind,config_hash,source,destination,destination_owner,amount,ready_at,state,nonce_address,nonce_value,message,packet,transaction_signature,finalized_slot,fee) VALUES($1,$2,0,$3,$1,$1,$1,$4::numeric,0,2,$1,$1,$5,$5,$2,1,5000)",
    [
      Binary(id),
      Binary(signature),
      Binary(scope),
      Text(Int.to_string(amount)),
      Binary(rp_bytes("01", 1)?)
    ])?
  Ok(id)
end

fn rp_proof(pool :: PoolHandle) -> Bool!String do
  let scope = rp_key("scope")
  let mint = rp_bytes("44", 32)?
  let week = U64.parse("4000")?
  let now = U64.parse("2419804800")?
  let first = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      rp_event(conn, "legacy", 1, 3, scope)?
      let legacy = freeze_treasury_week(conn, week, 0, mint, scope, now)?
      assert(legacy.amount == U64.parse("3")?
        && legacy.witness == U64.parse("0")?
        && legacy.operations == U64.parse("3")?)
      rp_event(conn, "token-first", 2, 3, scope)?
      let split = freeze_policy_treasury_week(conn, week, 0, mint, scope, 2, now)?
      assert(split.amount == U64.parse("3")?
        && split.witness == U64.parse("0")?
        && split.operations == U64.parse("1")?)
      let detail = Pg.query_values(conn,
        "SELECT burn::text,reserve_before::text,reserve_after::text,policy_version::text FROM issuer_treasury_weekly WHERE batch_id=$1::bigint",
        [Text(U64.to_string(split.batch_id))])?
      let row = List.head(detail)
      assert(rp_text(Map.get(row, "burn"))? == "0"
        && rp_text(Map.get(row, "reserve_before"))? == "0"
        && rp_text(Map.get(row, "reserve_after"))? == "2")
      assert(rp_text(Map.get(row, "policy_version"))? == "2")
      assert(split.batch_id != legacy.batch_id)
      assert(freeze_treasury_week(conn, week, 0, mint, scope, now)?.batch_id == legacy.batch_id)
      Ok(split.batch_id)
    end)?
  let immutable = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.execute_values(conn,
        "UPDATE issuer_quotes SET policy_version=1,policy_hash=$2 WHERE quote_id=$1",
        [Binary(rp_key("token-first")), Binary(credit_revenue_policy_hash(1)?)])?
      Ok(true)
    end)
  assert(Result.is_err(immutable))
  let corrupt = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.execute_values(conn,
        "UPDATE issuer_treasury_weekly SET operations=operations+reserve_after,reserve_after=0 WHERE batch_id=$1::bigint",
        [Text(U64.to_string(first))])?
      Ok(true)
    end)
  assert(Result.is_err(corrupt))
  let changed_payment = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.execute_values(conn,
        "UPDATE issuer_quotes SET payment_amount=4 WHERE quote_id=$1",
        [Binary(rp_key("token-first"))])?
      record_issued_credit_revenue(conn, rp_key("token-first"))?
      Ok(true)
    end)
  assert(Result.is_err(changed_payment))
  let next = U64.add(week, U64.parse("1")?)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      rp_event(conn, "token-next", 2, 7, scope)?
      # Foreign treasury revenue never enters this lane.
      rp_event(conn, "foreign-config", 2, 100, rp_key("foreign"))?
      Ok(nil)
    end)?
  let races = Job.map([0, 1, 2, 3],
    fn(_) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        let batch = freeze_policy_treasury_week(conn,
          next,
          0,
          mint,
          scope,
          2,
          U64.add(now, U64.parse("604800")?)?)?
        assert(batch.amount == U64.parse("7")?
          && batch.witness == U64.parse("2")?
          && batch.operations == U64.parse("4")?)
        Ok(batch.batch_id)
      end) end)
  let ids = for result in races do
    result??
  end
  for id in ids do
    assert(id == List.head(ids))
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let rows = Pg.query_values(conn,
        "SELECT burn::text,reserve_before::text,reserve_after::text FROM issuer_treasury_weekly WHERE batch_id=$1::bigint",
        [Text(U64.to_string(List.head(ids)))])?
      let row = List.head(rows)
      assert(rp_text(Map.get(row, "burn"))? == "3"
        && rp_text(Map.get(row, "reserve_before"))? == "2"
        && rp_text(Map.get(row, "reserve_after"))? == "0")
      let liabilities = Pg.query_values(conn,
        "SELECT amount::text,state::text FROM issuer_treasury_burn_liabilities WHERE batch_id=$1::bigint",
        [Text(U64.to_string(List.head(ids)))])?
      assert(List.length(liabilities) == 1
        && rp_text(Map.get(List.head(liabilities), "amount"))? == "3"
        && rp_text(Map.get(List.head(liabilities), "state"))? == "0")
      assert(freeze_policy_treasury_week(conn, week, 0, mint, scope, 2, now)?.batch_id == first)
      let members = Pg.query_values(conn,
        "SELECT COUNT(*)::text AS count FROM issuer_treasury_weekly_events",
        [])?
      assert(rp_text(Map.get(List.head(members), "count"))? == "3")
      let mismatch = Pg.query_values(conn,
        "SELECT COUNT(*)::text AS count FROM issuer_credit_revenue e JOIN issuer_quotes q USING(quote_id) WHERE e.policy_version<>q.policy_version OR e.policy_hash<>q.policy_hash",
        [])?
      assert(rp_text(Map.get(List.head(mismatch), "count"))? == "0")
      Ok(true)
    end)
end

test("versioned issued revenue preserves historical20/80 and reserves exact20/30/50 dust across concurrent weekly retries") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 6, 5000) do
    Ok(value) -> value
    Err(error) -> do
      IO.eprintln(error)
      assert(false)
      return
    end
  end
  let result = rp_proof(pool)
  Pool.close(pool)
  case result do
    Err(error) -> IO.eprintln(error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end

fn rp_lightning_event(conn :: borrow PgConn,
  domain :: String,
  version :: Int,
  amount :: String,
  backend :: Bytes) -> Result<(), String> do
  let id = rp_key("lightning/" <> domain)
  let key = rp_key("lightning-key/" <> domain)
  Pg.execute_values(conn,
    "INSERT INTO issuer_keys(key_id,epoch,purpose,spki,sealed_private_key) VALUES($1,$2::numeric,1,$3,$4)",
    [
      Binary(key),
      Text(Bytes.read_uint_le(key, 0, 8)?),
      Binary(Bytes.from_hex(String.repeat(Bytes.to_hex(key), 10)
        <> Bytes.to_hex(Bytes.slice(key, 0, 22)?))?),
      Binary(rp_bytes("11", 68)?)
    ])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_lightning_quotes(quote_id,request,key_id,batch_hash,backend_hash,service_key,payment_hash,sealed_preimage,amount_msat,reserved_at,price_observed_at,policy_version,policy_hash) VALUES($1,$2,$3,$1,$4,$1,$1,$5,$6::numeric,1700000000,1700000000,$7::smallint,$8)",
    [
      Binary(id),
      Binary(rp_bytes("01", 72)?),
      Binary(key),
      Binary(backend),
      Binary(rp_bytes("01", 99)?),
      Text(amount),
      Text(Int.to_string(version)),
      Binary(credit_revenue_policy_hash(version)?)
    ])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_lightning_revenue(quote_id,backend_hash,received_msat,settled_at,policy_version,policy_hash) SELECT quote_id,backend_hash,amount_msat,1700000010,policy_version,policy_hash FROM issuer_lightning_quotes WHERE quote_id=$1",
    [Binary(id)])?
  Ok(nil)
end

fn rp_lightning(pool :: PoolHandle) -> Bool!String do
  let backend = rp_key("lightning-backend")
  let other = rp_key("lightning-backend-other")
  let week = U64.parse("5000")?
  let now = U64.parse("3024604800")?
  let first = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      rp_lightning_event(conn, "v1", 1, "3", backend)?
      rp_lightning_event(conn, "v2first", 2, "3", backend)?
      rp_lightning_event(conn, "other", 2, "9007199254740993", other)?
      let legacy = freeze_lightning_revenue_week(conn, week, backend, 1, now)?
      assert(legacy.amount == U64.parse("3")? && legacy.allocation.operations == U64.parse("3")?)
      let token = freeze_lightning_revenue_week(conn, week, backend, 2, now)?
      assert(token.amount == U64.parse("3")?
        && token.allocation.operations == U64.parse("1")?
        && token.allocation.reserve_after == 2)
      rp_lightning_event(conn, "v2late", 2, "7", backend)?
      assert(freeze_lightning_revenue_week(conn, week, backend, 2, now)?.batch_id == token.batch_id)
      let external = freeze_lightning_revenue_week(conn, week, other, 2, now)?
      assert(external.amount == U64.parse("9007199254740993")?
        && external.allocation.witness == U64.parse("1801439850948198")?
        && external.allocation.burn == U64.parse("2702159776422297")?
        && external.allocation.operations == U64.parse("4503599627370496")?
        && external.allocation.reserve_after == 2)
      Ok(token.batch_id)
    end)?
  let races = Job.map([0, 1, 2],
    fn(_) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        let token = freeze_lightning_revenue_week(conn,
          U64.add(week, U64.parse("1")?)?,
          backend,
          2,
          U64.add(now, U64.parse("604800")?)?)?
        assert(token.amount == U64.parse("7")?
          && token.allocation.witness == U64.parse("2")?
          && token.allocation.burn == U64.parse("3")?
          && token.allocation.operations == U64.parse("4")?
          && token.allocation.reserve_before == 2
          && token.allocation.reserve_after == 0)
        Ok(token.batch_id)
      end) end)
  let ids = for value in races do
    value??
  end
  for id in ids do
    assert(id == List.head(ids))
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      assert(freeze_lightning_revenue_week(conn, week, backend, 2, now)?.batch_id == first)
      let funding = Pg.query_values(conn,
        "SELECT COUNT(*)::text AS count FROM issuer_treasury_rewards_intents",
        [])?
      assert(rp_text(Map.get(List.head(funding), "count"))? == "0")
      Ok(true)
    end)
end

test("Lightning revenue allocations remain exact original millisatoshis and never create USDC funding") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 6, 5000) do
    Ok(value) -> value
    Err(error) -> do
      IO.eprintln(error)
      assert(false)
      return
    end
  end
  let result = rp_lightning(pool)
  Pool.close(pool)
  case result do
    Err(error) -> IO.eprintln(error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end

fn rp_funding_identity_proof(pool :: PoolHandle) -> Bool!String do
  let program = Pubkey { bytes: rp_key("funding-program") }
  let config = TreasuryChainConfig {
    providers_hash: rp_key("providers"),
    cluster: rp_key("cluster"),
    mint: rp_bytes("44", 32)?,
    treasury_owner: rp_key("treasury"),
    fee_payer: rp_key("fee"),
    nonce_authority: rp_key("authority"),
    nonce_address: rp_key("nonce"),
    rewards_program: program.bytes,
    rewards_pool: reward_pool_address(program)?.bytes
  }
  let intent = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let scope = treasury_config_hash(config)?
      # Independent immutable accounting fixture; this tests the funding boundary,
      # not a configuration rotation of the earlier freeze/carry lane.
      let rows = Pg.query_values(conn,
        "INSERT INTO issuer_treasury_weekly(week,asset,cutoff,mint,config_hash,amount,witness,burn,operations,carry_before,carry_after,burn_carry_after,operations_carry_after,reserve_after,membership_hash,policy_version,policy_hash) VALUES(4100,0,0,$1,$2,5000003,1000000,1500000,2500001,0,6,9,5,2,$3,2,$4) RETURNING batch_id::text",
        [
          Binary(config.mint),
          Binary(scope),
          Binary(rp_key("funding-members")),
          Binary(credit_revenue_policy_hash(2)?)
        ])?
      let batch_id = U64.parse(rp_text(Map.get(List.head(rows), "batch_id"))?)?
      case reserve_treasury_funding(conn, batch_id, config, U64.parse("4102")?)? do
        None -> Err("missing_policy_funding")
        Some(value) -> Ok(value)
      end
    end)?
  for column in ["amount", "intent_id", "source", "mint"] do
    let invalid = Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        let update = case column do
          "amount" -> "UPDATE issuer_treasury_rewards_intents SET amount=amount+1 WHERE intent_id=$1"
          "intent_id" -> "UPDATE issuer_treasury_rewards_intents SET intent_id=$2 WHERE intent_id=$1"
          "source" -> "UPDATE issuer_treasury_rewards_intents SET source=$2 WHERE intent_id=$1"
          _ -> "UPDATE issuer_treasury_rewards_intents SET mint=$2 WHERE intent_id=$1"
        end
        let values = if column == "amount" do
          [Binary(intent.intent_id)]
        else
          [Binary(intent.intent_id), Binary(rp_key("tampered-funding"))]
        end
        Pg.execute_values(conn, update, values)?
        let id = if column == "intent_id" do
          rp_key("tampered-funding")
        else
          intent.intent_id
        end
        load_treasury_funding(conn, id)?
        Ok(true)
      end)
    assert(Result.is_err(invalid))
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      assert(load_treasury_funding(conn, intent.intent_id)?.amount == intent.amount)
      Ok(true)
    end)
end

test("policy2 funding direct loads reject changed committed identity, amount, mint and source") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 6, 5000) do
    Ok(value) -> value
    Err(error) -> do
      IO.eprintln(error)
      assert(false)
      return
    end
  end
  let result = rp_funding_identity_proof(pool)
  Pool.close(pool)
  case result do
    Err(error) -> IO.eprintln(error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
