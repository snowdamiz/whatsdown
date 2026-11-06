from Storage.TransparencyRetention import prune_on_connection

fn scalar(conn :: borrow PgConn, sql :: String) -> String!String do
  Ok(Map.get(List.head(Pg.query(conn, sql, [])?), "value"))
end

fn check(conn :: borrow PgConn) -> Result<(), String> do
  Pg.execute(conn,
    "TRUNCATE transparency_anchors, transparency_v2_anchors, witness_signatures, witness_v2_signatures, transparency_checkpoints, transparency_v2_checkpoints, transparency_maintenance",
    [])?
  for table in ["transparency_checkpoints", "transparency_v2_checkpoints"] do
    for sequence in 1..5 do
      let age = if sequence == 3 do
        35
      else
        40
      end
      Pg.execute(conn,
        "INSERT INTO "
          <> table
          <> " (sequence, tree_size, tree_root, previous_checkpoint_hash, timestamp_ms, service_public_key, service_signature, created_at) VALUES ($1::bigint, 1, repeat('r', 32)::bytea, repeat('p', 32)::bytea, 1, repeat('k', 32)::bytea, repeat('s', 64)::bytea, now() - $2::integer * interval '1 day')",
        [Int.to_string(sequence), Int.to_string(age)])?
    end
  end
  Pg.execute(conn,
    "INSERT INTO transparency_anchors (checkpoint_sequence, tree_size, checkpoint_hash, ring_index, tx_signature, slot) VALUES (1, 1, repeat('h', 32)::bytea, 0, 'legacy', 1)",
    [])?
  Pg.execute(conn,
    "INSERT INTO transparency_v2_anchors (checkpoint_sequence, tree_size, checkpoint_hash, ring_index, tx_signature, slot) VALUES (2, 1, repeat('h', 32)::bytea, 0, 'rfc', 1)",
    [])?
  Pg.execute(conn,
    "INSERT INTO witness_v2_signatures (checkpoint_sequence, witness_id, witness_public_key, checkpoint_hash, signature) SELECT sequence, 'external', repeat('w', 32)::bytea, repeat('h', 32)::bytea, repeat('s', 72)::bytea FROM transparency_v2_checkpoints",
    [])?
  let preview = prune_on_connection(conn, true, 100, 1)?
  assert(preview.checkpoints == 1)
  assert(scalar(conn, "SELECT count(*)::text AS value FROM transparency_v2_checkpoints")? == "4")
  let first = prune_on_connection(conn, false, 100, 1)?
  assert(first.checkpoints == 1)
  assert(scalar(conn,
    "SELECT string_agg(sequence::text, ',' ORDER BY sequence) AS value FROM transparency_checkpoints")? == "1,3,4")
  assert(scalar(conn, "SELECT count(*)::text AS value FROM transparency_v2_checkpoints")? == "4")
  let second = prune_on_connection(conn, false, 100, 2)?
  assert(second.checkpoints == 1)
  assert(scalar(conn,
    "SELECT string_agg(sequence::text, ',' ORDER BY sequence) AS value FROM transparency_v2_checkpoints")? == "2,3,4")
  assert(scalar(conn, "SELECT count(*)::text AS value FROM witness_v2_signatures")? == "3")
  assert(prune_on_connection(conn, false, 100, 2)?.checkpoints == 0)
  assert(scalar(conn,
    "SELECT checkpoints_pruned::text AS value FROM transparency_maintenance")? == "2")
  Ok(nil)
end

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)?
  let result :: Bool!String = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      check(conn)?
      Err("retention_test_rollback")
    end)
  Pool.close(pool)
  case result do
    Err(error) -> if error == "retention_test_rollback" do
      Ok(true)
    else
      Err(error)
    end
    Ok(_) -> Err("test did not roll back")
  end
end

test("RFC and legacy checkpoint retention share a daily cap and keep their own anchors and latest roots") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
