from Storage.TreasuryBurn import (
  reserve_credit_burn_handoff,
  expire_credit_burn_handoff,
  confirm_credit_burn_handoff,
  load_credit_burn_handoff
)
from Payment.RevenuePolicy import split_credit_revenue
from Transparency.TokenBurn import decode_token_burn_profile
from Solana.Read import pubkey

fn field(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn bytes(root :: Json, index :: Int) -> Bytes!String do
  Bytes.from_hex(field(Json.array_get(Json.object_get(root, "accounts")?, index)?, "data_hex")?)
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_expiry_fixture")
  end
end

fn proof(pool :: PoolHandle) -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_EXPIRY_FIXTURES_PATH",
    "ops/token-expiry/fixtures/tombstone.json"))?)?
  let program = pubkey(field(root, "program")?)?
  let payer = pubkey(field(root, "payer")?)?
  let epoch = U64.parse(field(root, "epoch")?)?
  let raw_profile = bytes(root, 2)?
  let profile = decode_token_burn_profile(raw_profile)?
  let raw = bytes(root, 5)?
  let receipt = bytes(root, 6)?
  let slot = U64.parse(field(root, "context_slot")?)?
  let scope = Crypto.sha256(Bytes.from_utf8("credit-expiry-ledger-fixture"))
  let split = split_credit_revenue(2, U64.parse("40000000")?, 0, 0, 0)?
  let members = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let ids = for week in [
        2700,
        2701
      ] do # Synthetic accounting fixture; the permanent expiry and later funding
        # frames are genuine SBF outputs of this same profile and schedule.
        let rows = Pg.query_values(conn,
          "INSERT INTO issuer_treasury_weekly(week,asset,cutoff,mint,config_hash,amount,witness,burn,operations,carry_before,carry_after,burn_carry_before,burn_carry_after,operations_carry_before,operations_carry_after,reserve_before,reserve_after,membership_hash,policy_version,policy_hash) VALUES($1::numeric,0,0,$2,$3,40000000,8000000,12000000,20000000,0,0,0,0,0,0,0,0,$3,2,$4) RETURNING batch_id::text",
          [
            Text(Int.to_string(week)),
            Binary(profile.usdc.bytes),
            Binary(scope),
            Binary(split.policy_hash)
          ])?
        let id = U64.parse(text(Map.get(List.head(rows), "batch_id"))?)?
        Pg.execute_values(conn,
          "INSERT INTO issuer_treasury_burn_liabilities(batch_id,amount) VALUES($1::bigint,12000000)",
          [Text(U64.to_string(id))])?
        id
      end
      Ok(ids)
    end)?
  let weights = for _ in 0..24 do
    U64.parse("1")?
  end
  let entropy = for index in 0..24 do
    U64.parse(Int.to_string(index * 999999))?
  end
  let first = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      case reserve_credit_burn_handoff(conn,
        scope,
        program,
        payer,
        raw_profile,
        epoch,
        U64.parse("0")?,
        weights,
        entropy,
        profile.ready_at)? do
        None -> Err("missing_expiry_intent")
        Some(value) -> Ok(value)
      end
    end)?
  let later = U64.add(epoch, U64.parse("1")?)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      assert(Option.is_none(reserve_credit_burn_handoff(conn,
        scope,
        program,
        payer,
        raw_profile,
        later,
        U64.parse("0")?,
        weights,
        entropy,
        U64.multiply(later, U64.parse("604800")?)?)?))
      Ok(nil)
    end)?
  let id = first.intent.intent_id
  let malformed = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do expire_credit_burn_handoff(conn,
      id,
      raw,
      Bytes.from_hex(String.repeat("00", 256))?,
      slot) end)
  assert(Result.is_err(malformed))
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.execute(conn,
        "CREATE FUNCTION fail_late_expiry_member() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.batch_id="
          <> U64.to_string(List.get(members, 1))
          <> " THEN RAISE EXCEPTION 'forced_late_expiry_member_failure'; END IF; RETURN NEW; END $$",
        [])?
      Pg.execute(conn,
        "CREATE TRIGGER zz_fail_late_expiry_member BEFORE UPDATE ON issuer_treasury_burn_members FOR EACH ROW EXECUTE FUNCTION fail_late_expiry_member()",
        [])?
      Ok(nil)
    end)?
  let forced = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do expire_credit_burn_handoff(conn, id, raw, receipt, slot) end)
  case forced do
    Ok(_) -> return Err("expiry_must_fail_atomically")
    Err(error) -> do
      IO.eprintln(error)
      assert(String.contains(error, "forced_late_expiry_member_failure"))
    end
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      assert(load_credit_burn_handoff(conn, id)?.state == 0)
      Pg.execute(conn,
        "DROP TRIGGER zz_fail_late_expiry_member ON issuer_treasury_burn_members",
        [])?
      Pg.execute(conn, "DROP FUNCTION fail_late_expiry_member()", [])?
      Ok(nil)
    end)?
  let releases = Job.map([0, 1, 2, 3, 4, 5],
    fn(_) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do expire_credit_burn_handoff(conn,
        id,
        raw,
        receipt,
        slot) end) end)
  for result in releases do
    let value = result??
    assert(value.state == 2)
  end
  let children = Job.map([0, 1, 2, 3, 4, 5],
    fn(_) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        case reserve_credit_burn_handoff(conn,
          scope,
          program,
          payer,
          raw_profile,
          later,
          U64.parse("0")?,
          weights,
          entropy,
          U64.multiply(later, U64.parse("604800")?)?)? do
          None -> Err("expired_members_not_released")
          Some(value) -> Ok(value)
        end
      end) end)
  let ids = for result in children do
    let value = result??
    value.intent.intent_id
  end
  let child = List.head(ids)
  for other in ids do
    assert(other == child && child != id)
  end
  let later_frame = bytes(Json.object_get(root, "later_funded")?, 5)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let funded = confirm_credit_burn_handoff(conn, child, later_frame, None, slot)?
      assert(funded.state == 1 && funded.intent.cash == U64.parse("24000000")?)
      let before = Pg.query_values(conn,
        "SELECT batch_id::text,state::text,encode(funding_hash,'hex') AS hash FROM issuer_treasury_burn_liabilities ORDER BY batch_id",
        [])?
      assert(expire_credit_burn_handoff(conn, id, raw, receipt, slot)?.state == 2)
      let post_rows = Pg.query_values(conn,
        "SELECT batch_id::text,state::text,encode(funding_hash,'hex') AS hash FROM issuer_treasury_burn_liabilities ORDER BY batch_id",
        [])?
      let old_markers = for row in before do
        text(Map.get(row, "batch_id"))?
          <> ":"
          <> text(Map.get(row, "state"))?
          <> ":"
          <> text(Map.get(row, "hash"))?
      end
      let new_markers = for row in post_rows do
        text(Map.get(row, "batch_id"))?
          <> ":"
          <> text(Map.get(row, "state"))?
          <> ":"
          <> text(Map.get(row, "hash"))?
      end
      assert(Json.encode(old_markers) == Json.encode(new_markers))
      let history = Pg.query_values(conn,
        "SELECT COUNT(*)::text AS total,SUM(CASE WHEN released THEN 1 ELSE 0 END)::text AS released FROM issuer_treasury_burn_members",
        [])?
      assert(text(Map.get(List.head(history), "total"))? == "4"
        && text(Map.get(List.head(history), "released"))? == "2")
      assert(load_credit_burn_handoff(conn,
        id)?.intent.instruction.data == first.intent.instruction.data)
      assert(load_credit_burn_handoff(conn, child)?.state == 1)
      Ok(nil)
    end)?
  IO.eprintln("MORSE_CREDIT_BURN_EXPIRY atomic_finalized_release_six_races_immutable_history_future_actual_fund_and_old_receipt_inert")
  Ok(true)
end

test("finalized permanent expiry releases only old members and never affects a later real funded intent") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 6, 5000) do
    Ok(value) -> value
    Err(error) -> do
      IO.eprintln(error)
      assert(false)
      return
    end
  end
  let result = proof(pool)
  Pool.close(pool)
  case result do
    Err(error) -> IO.eprintln(error)
    Ok(_) -> nil
  end
  assert(result == Ok(true))
end
