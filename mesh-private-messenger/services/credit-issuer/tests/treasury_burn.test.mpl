from Storage.TreasuryBurn import (
  reserve_credit_burn_handoff,
  load_credit_burn_handoff,
  confirm_credit_burn_handoff
)
from Payment.RevenuePolicy import split_credit_revenue
from Transparency.TokenBurn import TokenBurnProfile, decode_token_burn_profile
from Solana.Read import Pubkey, pubkey

struct BurnJournalFixture do
  program :: Pubkey
  payer :: Pubkey
  profile :: TokenBurnProfile
  raw_profile :: Bytes
  epoch :: U64
  now :: U64
  scope :: Bytes
  snapshots :: Json
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_burn_journal_fixture")
  end
end

fn field(root :: Json, name :: String) -> String!String do
  Json.as_string(Json.object_get(root, name)?)
end

fn frame(snapshot :: Json, index :: Int) -> Bytes!String do
  Bytes.from_hex(field(Json.array_get(Json.object_get(snapshot, "accounts")?, index)?, "data_hex")?)
end

fn fixture() -> BurnJournalFixture!String do
  let root = Json.parse(File.read(Env.get("MORSE_TOKEN_CARRY_FIXTURES_PATH",
    "ops/credit-burn-handoff/fixtures/carry-accounts.json"))?)?
  let snapshots = Json.object_get(root, "snapshots")?
  let snapshot = Json.array_get(snapshots, 2)?
  let raw = frame(snapshot, 2)?
  let epoch = U64.parse(field(snapshot, "epoch")?)?
  Ok(BurnJournalFixture {
    program: pubkey(field(snapshot, "program")?)?,
    payer: pubkey(field(snapshot, "payer")?)?,
    profile: decode_token_burn_profile(raw)?,
    raw_profile: raw,
    epoch: epoch,
    now: U64.multiply(epoch, U64.parse("604800")?)?,
    scope: Crypto.sha256(Bytes.from_utf8("credit-burn-journal-fixture")),
    snapshots: snapshots
  })
end

# Accounting fixtures only. The actual fund program, SPL CPIs and resulting
# frame/closed receipt are replayed independently from the archived SBF proof.
fn weekly(conn :: borrow PgConn,
  f :: BurnJournalFixture,
  week :: Int,
  scope :: Bytes,
  amount :: String,
  carries :: List<Int>) -> U64!String do
  let split = split_credit_revenue(2,
    U64.parse(amount)?,
    List.get(carries, 0),
    List.get(carries, 1),
    List.get(carries, 2))?
  let rows = Pg.query_values(conn,
    "INSERT INTO issuer_treasury_weekly(week,asset,cutoff,mint,config_hash,amount,witness,burn,operations,carry_before,carry_after,burn_carry_before,burn_carry_after,operations_carry_before,operations_carry_after,reserve_before,reserve_after,membership_hash,policy_version,policy_hash) VALUES($1::numeric,0,0,$2,$3,$4::numeric,$5::numeric,$6::numeric,$7::numeric,$8::smallint,$9::smallint,$10::smallint,$11::smallint,$12::smallint,$13::smallint,$14::smallint,$15::smallint,$3,2,$16) RETURNING batch_id::text",
    [
      Text(Int.to_string(week)),
      Binary(f.profile.usdc.bytes),
      Binary(scope),
      Text(amount),
      Text(U64.to_string(split.witness)),
      Text(U64.to_string(split.burn)),
      Text(U64.to_string(split.operations)),
      Text(Int.to_string(List.get(carries, 0))),
      Text(Int.to_string(split.carry_witness)),
      Text(Int.to_string(List.get(carries, 1))),
      Text(Int.to_string(split.carry_burn)),
      Text(Int.to_string(List.get(carries, 2))),
      Text(Int.to_string(split.carry_operations)),
      Text(Int.to_string(split.reserve_before)),
      Text(Int.to_string(split.reserve_after)),
      Binary(split.policy_hash)
    ])?
  let id = U64.parse(text(Map.get(List.head(rows), "batch_id"))?)?
  Pg.execute_values(conn,
    "INSERT INTO issuer_treasury_burn_liabilities(batch_id,amount) SELECT batch_id,burn FROM issuer_treasury_weekly WHERE batch_id=$1::bigint",
    [Text(U64.to_string(id))])?
  Ok(id)
end

fn proof(pool :: PoolHandle) -> Bool!String do
  let f = fixture()?
  let members = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let one = weekly(conn, f, 2700, f.scope, "233333334", [0, 0, 0])?
      let two = weekly(conn, f, 2701, f.scope, "166666666", [8, 2, 0])?
      weekly(conn, f, 2702, Crypto.sha256(Bytes.from_utf8("foreign")), "1000000000", [0, 0, 0])?
      Ok([one, two])
    end)?
  let weights = for _index in 0..24 do
    U64.parse("1")?
  end
  let entropy = for index in 0..24 do
    U64.parse(Int.to_string(index * 999999))?
  end
  let carry = U64.parse("120000000")?
  let races = Job.map([0, 1, 2, 3, 4, 5],
    fn(_) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        case reserve_credit_burn_handoff(conn,
          f.scope,
          f.program,
          f.payer,
          f.raw_profile,
          f.epoch,
          carry,
          weights,
          entropy,
          f.now)? do
          None -> Err("missing_burn_intent")
          Some(stored) -> Ok(stored.intent.intent_id)
        end
      end) end)
  let ids = for result in races do
    result??
  end
  let id = List.head(ids)
  for other in ids do
    assert(other == id)
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let loaded = load_credit_burn_handoff(conn, id)?
      assert(loaded.state == 0
        && loaded.intent.cash == U64.parse("120000000")?
        && loaded.intent.carry == carry)
      assert(List.length(loaded.intent.allocations) == 2)
      for index in 0..2 do
        assert(List.get(loaded.intent.allocations, index).batch_id == List.get(members, index))
      end
      let replay = case reserve_credit_burn_handoff(conn,
        f.scope,
        f.program,
        f.payer,
        f.raw_profile,
        f.epoch,
        carry,
        List.reverse(weights),
        List.reverse(entropy),
        U64.add(f.now, U64.parse("6048000")?)?)? do
        None -> return Err("missing_burn_replay")
        Some(value) -> value
      end
      assert(replay.intent.intent_id == id
        && replay.intent.instruction.data == loaded.intent.instruction.data)
      assert(Result.is_err(reserve_credit_burn_handoff(conn,
        Crypto.sha256(Bytes.from_utf8("foreign")),
        f.program,
        f.payer,
        f.raw_profile,
        f.epoch,
        carry,
        weights,
        entropy,
        f.now)))
      Pg.execute(conn,
        "CREATE FUNCTION fail_second_burn_member() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.batch_id="
          <> U64.to_string(List.get(members, 1))
          <> " THEN RAISE EXCEPTION 'forced_late_burn_member_failure'; END IF; RETURN NEW; END $$",
        [])?
      Pg.execute(conn,
        "CREATE TRIGGER fail_second_burn_member BEFORE UPDATE ON issuer_treasury_burn_liabilities FOR EACH ROW EXECUTE FUNCTION fail_second_burn_member()",
        [])?
      Ok(true)
    end)?
  let active = frame(Json.array_get(f.snapshots, 2)?, 5)?
  let failed = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do confirm_credit_burn_handoff(conn,
      id,
      active,
      None,
      U64.parse("100")?) end)
  assert(Result.is_err(failed))
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      assert(load_credit_burn_handoff(conn, id)?.state == 0)
      let rows = Pg.query_values(conn,
        "SELECT COUNT(*)::text AS count FROM issuer_treasury_burn_liabilities WHERE state=1",
        [])?
      assert(text(Map.get(List.head(rows), "count"))? == "0")
      Pg.execute(conn,
        "DROP TRIGGER fail_second_burn_member ON issuer_treasury_burn_liabilities",
        [])?
      Pg.execute(conn, "DROP FUNCTION fail_second_burn_member()", [])?
      Ok(true)
    end)?
  let closed = Json.array_get(f.snapshots, 4)?
  let confirms = Job.map([0, 1, 2, 3],
    fn(index) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        let value = if index % 2 == 0 do
          confirm_credit_burn_handoff(conn, id, active, None, U64.parse("100")?)?
        else
          confirm_credit_burn_handoff(conn,
            id,
            frame(closed, 5)?,
            Some(frame(closed, 9)?),
            U64.parse("100")?)?
        end
        assert(value.state == 1)
        Ok(true)
      end) end)
  for result in confirms do
    assert(result??)
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let done = load_credit_burn_handoff(conn, id)?
      assert(done.state == 1 && done.intent.intent_id == id)
      let rows = Pg.query_values(conn,
        "SELECT COUNT(*)::text AS count,SUM(amount)::text AS amount FROM issuer_treasury_burn_liabilities WHERE state=1",
        [])?
      assert(text(Map.get(List.head(rows), "count"))? == "2"
        && text(Map.get(List.head(rows), "amount"))? == "120000000")
      let none = reserve_credit_burn_handoff(conn,
        f.scope,
        f.program,
        f.payer,
        f.raw_profile,
        U64.add(f.epoch, U64.parse("1")?)?,
        U64.parse("0")?,
        weights,
        entropy,
        f.now)?
      assert(Option.is_none(none))
      Ok(true)
    end)
end

test("six burn reservations converge on exact members and late member update rollback preserves every liability") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 8, 5000) do
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
