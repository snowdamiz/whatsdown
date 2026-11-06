from Runtime.TreasuryKeys import provision_treasury_keys, open_treasury_signer

fn open_fixture_key() -> StorageKey!String do
  case StorageKey.platform() do
    Ok(value)
    Err(_) -> Err("fixture_key_unavailable")
  end
end

fn signer_refused(result :: Result<SigningPrivateKey, String>) -> Bool do
  case result do
    Err(_) -> true
    Ok(key) -> do
      Secret.destroy(key)
      false
    end
  end
end

fn key_proof(pool :: PoolHandle) -> Bool!String do
  let service_key = Crypto.sha256(Bytes.from_utf8("treasury-operational-keys-test"))
  let results = Job.map([0, 1, 2, 3, 4, 5],
    fn(_index) do provision_treasury_keys(pool, service_key, 1, open_fixture_key) end)
  let keys = for result in results do
    result??
  end
  let first = List.head(keys)
  assert(!Bytes.secure_equals(first.fee_payer, first.nonce_authority))
  for value in keys do
    assert(Bytes.secure_equals(value.fee_payer, first.fee_payer))
    assert(Bytes.secure_equals(value.nonce_authority, first.nonce_authority))
  end
  let wrapping = open_fixture_key()?
  let signer = open_treasury_signer(pool, service_key, 1, 0, first.fee_payer, wrapping)?
  let challenge = Bytes.from_utf8("treasury-key-durable-identity")
  let signed = case Crypto.sign(signer, challenge) do
    Ok(value) -> value
    Err(_) -> return Err("fixture_sign_failed")
  end
  assert(case Crypto.verify(SigningPublicKey { bytes: first.fee_payer }, challenge, signed) do
    Ok(value) -> value
    Err(_) -> false
  end)
  assert(signer_refused(open_treasury_signer(pool,
    service_key,
    1,
    0,
    first.nonce_authority,
    wrapping)))
  assert(signer_refused(open_treasury_signer(pool, service_key, 0, 0, first.fee_payer, wrapping)))
  assert(signer_refused(open_treasury_signer(pool, service_key, 1, 2, first.fee_payer, wrapping)))
  let live = provision_treasury_keys(pool, service_key, 0, open_fixture_key)?
  assert(!Bytes.secure_equals(live.fee_payer, first.fee_payer))
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.execute_values(conn,
        "UPDATE issuer_treasury_keys SET sealed_key=(SELECT sealed_key FROM issuer_treasury_keys WHERE service_key=$1 AND purpose=0 AND role=0) WHERE service_key=$1 AND purpose=1 AND role=0",
        [Binary(service_key)])?
      Ok(true)
    end)?
  assert(signer_refused(open_treasury_signer(pool, service_key, 1, 0, first.fee_payer, wrapping)))
  assert(Result.is_err(provision_treasury_keys(pool, service_key, 1, open_fixture_key)))
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.execute_values(conn,
        "DELETE FROM issuer_treasury_keys WHERE service_key=$1",
        [Binary(service_key)])?
      Ok(true)
    end)?
  Ok(true)
end

fn rollback_proof(pool :: PoolHandle) -> Bool!String do
  let service_key = Crypto.sha256(Bytes.from_utf8("treasury-key-atomic-pair"))
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.execute_values(conn,
        "CREATE FUNCTION reject_treasury_key_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.role=1 THEN RAISE EXCEPTION 'forced second signer failure'; END IF; RETURN NEW; END $$",
        [])?
      Pg.execute_values(conn,
        "CREATE TRIGGER reject_treasury_key_fixture BEFORE INSERT ON issuer_treasury_keys FOR EACH ROW EXECUTE FUNCTION reject_treasury_key_fixture()",
        [])?
      Ok(true)
    end)?
  assert(Result.is_err(provision_treasury_keys(pool, service_key, 1, open_fixture_key)))
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let rows = Pg.query_values(conn,
        "SELECT public_key FROM issuer_treasury_keys WHERE service_key=$1",
        [Binary(service_key)])?
      assert(List.length(rows) == 0)
      Pg.execute_values(conn,
        "DROP TRIGGER reject_treasury_key_fixture ON issuer_treasury_keys",
        [])?
      Pg.execute_values(conn, "DROP FUNCTION reject_treasury_key_fixture()", [])?
      Ok(true)
    end)?
  let created = provision_treasury_keys(pool, service_key, 1, open_fixture_key)?
  # A partially deleted pair is corruption, not permission to create a new role.
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.execute_values(conn,
        "DELETE FROM issuer_treasury_keys WHERE service_key=$1 AND role=1",
        [Binary(service_key)])?
      Ok(true)
    end)?
  assert(Result.is_err(provision_treasury_keys(pool, service_key, 1, open_fixture_key)))
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let rows = Pg.query_values(conn,
        "SELECT public_key FROM issuer_treasury_keys WHERE service_key=$1",
        [Binary(service_key)])?
      assert(List.length(rows) == 1)
      assert(case Map.get(List.head(rows), "public_key") do
        Binary(value) -> Bytes.secure_equals(value, created.fee_payer)
        _ -> false
      end)
      Pg.execute_values(conn,
        "DELETE FROM issuer_treasury_keys WHERE service_key=$1",
        [Binary(service_key)])?
      Ok(true)
    end)
end

test("six provisioners persist one sealed signer pair and purpose or role substitution fails closed") do
  Test.install_in_memory_secure_store()
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 6, 5000) do
    Ok(value) -> value
    Err(error) -> do
      println(error)
      assert(false)
      return
    end
  end
  let result = case key_proof(pool) do
    Ok(_) -> rollback_proof(pool)
    Err(error)
  end
  Pool.close(pool)
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end
