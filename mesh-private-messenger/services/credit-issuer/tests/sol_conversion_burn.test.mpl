from Tests.SolConversionFixture import (
  conversion_fixture_config,
  conversion_fixture_text,
  conversion_fixture_bank,
  conversion_fixture_outcome
)
from Storage.SolConversion import (
  reserve_sol_conversion,
  prepare_sol_conversion,
  commit_sol_conversion,
  reconcile_sol_conversion
)
from Storage.TreasuryBurn import reserve_credit_burn_handoff, load_credit_burn_handoff
from Transparency.TokenChain import token_addresses
from Transparency.TokenBurn import TokenBurnProfile
from Solana.Address import find_program_address
from Solana.Read import Pubkey, pubkey

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(a, b) do Bytes.concat(a?, b) end)
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(v) -> Ok(v)
    _ -> Err("fixture_row")
  end
end

# Prepared burn role graph only; this is NOT an authenticated burn profile bank.
# Actual conversion accounts/wire/deltas below are genuine SBF exports. Existing
# burn network admission remains required before any external funding handoff.
fn raw_profile(root :: Json, program :: Pubkey) -> Bytes!String do
  let config = conversion_fixture_config(root)?
  let token = token_addresses(program)?
  let native = config.profile.usdc
  let sorted = if Bytes.to_hex(native.bytes) < Bytes.to_hex(token.mint.bytes) do
    [native.bytes, token.mint.bytes]
  else
    [token.mint.bytes, native.bytes]
  end
  let ray = pubkey("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C")?
  let factory = config.profile.amm_config
  let pool = find_program_address(ray,
    [Bytes.from_utf8("pool"), factory.bytes, List.get(sorted, 0), List.get(sorted, 1)])?.address
  let vault0 = find_program_address(ray,
    [Bytes.from_utf8("pool_vault"), pool.bytes, List.get(sorted, 0)])?.address
  let vault1 = find_program_address(ray,
    [Bytes.from_utf8("pool_vault"), pool.bytes, List.get(sorted, 1)])?.address
  let observation = find_program_address(ray, [Bytes.from_utf8("observation"), pool.bytes])?.address
  cat([
    Bytes.from_hex("4d545301")?,
    token.config.bytes,
    native.bytes,
    config.profile.owner.bytes,
    pool.bytes,
    factory.bytes,
    vault0.bytes,
    vault1.bytes,
    observation.bytes,
    Bytes.write_uint_le("1000", 8)?,
    Bytes.write_uint_le("1000", 8)?,
    Bytes.write_uint_le(conversion_fixture_text(root, "now")?, 8)?,
    config.profile.amm_hash,
    Bytes.from_hex("00000000")?
  ])
end

fn exercise(pool :: PoolHandle) -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_BANK", ""))?)?
  let executed = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_EXECUTION", ""))?)?
  let config = conversion_fixture_config(root)?
  assert(Json.encode(Json.object_get(root, "bucket")?) == "1")
  let id = Bytes.from_hex(conversion_fixture_text(root, "id")?)?
  let bank = conversion_fixture_bank(root, config.profile, id)?
  let wire = Bytes.from_base64(conversion_fixture_text(executed, "wire")?)?
  let signature = Bytes.from_base58(conversion_fixture_text(executed, "signature")?)?
  let outcome = conversion_fixture_outcome(executed, wire, signature)?
  let program = Pubkey {
    bytes: Crypto.sha256(Bytes.from_utf8("owned-converted-burn-prepare-only"))
  }
  let raw = raw_profile(root, program)?
  let epoch = U64.add(U64.divide(bank.now, U64.parse("604800")?)?, U64.parse("1")?)?
  let weights = for _ in 0..24 do
    U64.parse("1")?
  end
  let entropy = for i in 0..24 do
    U64.parse(Int.to_string(i * 999999))?
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.execute_values(conn,
        "INSERT INTO issuer_treasury_weekly(batch_id,week,asset,cutoff,mint,config_hash,amount,witness,burn,operations,carry_before,carry_after,membership_hash,policy_version,policy_hash) VALUES(1,1,1,1,$1,$2,5000000000,1000000000,1500000000,2500000000,0,0,$3,2,$4)",
        [
          Binary(Bytes.from_hex(String.repeat("00", 32))?),
          Binary(config.profile.treasury_config),
          Binary(Bytes.from_hex(conversion_fixture_text(root, "membership_hash")?)?),
          Binary(Bytes.from_hex(conversion_fixture_text(root, "policy_hash")?)?)
        ])?
      assert(Result.is_err(reserve_sol_conversion(conn, config.profile, U64.parse("1")?, 1)))
      Pg.execute(conn,
        "INSERT INTO issuer_treasury_burn_liabilities(batch_id,amount) VALUES(1,1500000000)",
        [])?
      assert(Option.is_none(reserve_credit_burn_handoff(conn,
        config.profile.treasury_config,
        program,
        config.profile.owner,
        raw,
        epoch,
        U64.parse("0")?,
        weights,
        entropy,
        bank.now)?))
      assert(reserve_sol_conversion(conn, config.profile, U64.parse("1")?, 1)? == id)
      let saved = prepare_sol_conversion(conn,
        config.profile,
        id,
        bank,
        Bytes.from_base58(conversion_fixture_text(root, "blockhash")?)?,
        U64.parse("1100")?)?
      commit_sol_conversion(conn, config.profile, id, saved.ordinal, wire, bank, bank.now)?
      reconcile_sol_conversion(conn, config.profile, id, saved.ordinal, outcome)?
      Pg.execute_values(conn,
        "INSERT INTO issuer_treasury_weekly(batch_id,week,asset,cutoff,mint,config_hash,amount,witness,burn,operations,carry_before,carry_after,membership_hash,policy_version,policy_hash) VALUES(2,1,0,1,$1,$2,1000,200,300,500,0,0,$3,2,$4)",
        [
          Binary(config.profile.usdc.bytes),
          Binary(config.profile.treasury_config),
          Binary(Crypto.sha256(Bytes.from_utf8("normal USDC accounting fixture"))),
          Binary(Bytes.from_hex(conversion_fixture_text(root, "policy_hash")?)?)
        ])?
      Pg.execute(conn,
        "INSERT INTO issuer_treasury_burn_liabilities(batch_id,amount) VALUES(2,300)",
        [])?
      Ok(nil)
    end)?
  let races = Job.map([0, 1, 2, 3, 4, 5],
    fn(_) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        case reserve_credit_burn_handoff(conn,
          config.profile.treasury_config,
          program,
          config.profile.owner,
          raw,
          epoch,
          U64.parse("0")?,
          weights,
          entropy,
          bank.now)? do
          None -> Err("missing_burn_handoff")
          Some(value) -> Ok(value.intent.intent_id)
        end
      end) end)
  let ids = for result in races do
    result??
  end
  for other in ids do
    assert(other == List.head(ids))
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let saved = load_credit_burn_handoff(conn, List.head(ids))?
      let actual = U64.parse(conversion_fixture_text(executed, "received_usdc")?)?
      assert(saved.intent.cash == U64.add(actual, U64.parse("300")?)?)
      assert(List.length(saved.intent.allocations) == 2)
      assert(List.get(saved.intent.allocations, 0).amount == actual)
      assert(Bytes.get(saved.intent.instruction.data, 0)? == 14)
      let source = List.head(Pg.query_values(conn,
        "SELECT amount::text FROM issuer_treasury_burn_liabilities WHERE batch_id=1",
        [])?)
      assert(text(Map.get(source, "amount"))? == "1500000000")
      let binding_row = List.head(Pg.query_values(conn,
        "SELECT encode(conversion_id,'hex') AS id FROM issuer_treasury_burn_members WHERE batch_id=1 AND NOT released",
        [])?)
      assert(text(Map.get(binding_row, "id"))? == Bytes.to_hex(id))
      assert(Option.is_none(reserve_credit_burn_handoff(conn,
        config.profile.treasury_config,
        program,
        config.profile.owner,
        raw,
        U64.add(epoch, U64.parse("1")?)?,
        U64.parse("0")?,
        weights,
        entropy,
        U64.multiply(epoch, U64.parse("604800")?)?)?))
      Ok(nil)
    end)?
  Ok(true)
end

test("actual converted burn output joins normal USDC in one canonical reservation; six workers cannot value lamports or spend output twice") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 8, 5000) do
    Ok(value) -> value
    Err(error) -> do
      println(error)
      assert(false)
      return
    end
  end
  let result = exercise(pool)
  Pool.close(pool)
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
