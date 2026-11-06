from Protocol.DirectoryWire import encode_device_set
from Protocol.V1 import DeviceSet, DirectoryEntry
from Runtime.Workers import run_scheduled
from Storage.Transparency import append_entry_on_connection, forget_account_entries_on_connection
from Storage.TransparencyRecords import backfill_records_on_connection, entry_bytes_on_connection
from Storage.TransparencyRetention import prune_on_connection
from Storage.TransparencyTree import tree_inclusion, tree_root
from Transparency.Merkle import leaf_hash, verify_inclusion

fn filled(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("test allocation failed")
    Ok(bytes)
  end
end

fn scalar(conn :: borrow PgConn, sql :: String) -> String!String do
  let rows = Pg.query(conn, sql, [])?
  Ok(Map.get(List.head(rows), "value"))
end

fn encoded(sequence :: Int, second_device :: Bool) -> Bytes!String do
  let device = DirectoryEntry {
    version: 1,
    username: "alice",
    account_identity: Bytes.from_utf8("account"),
    prekey_bundle: filled(12, 1184)?,
    mailbox_token: filled(1, 32)?
  }
  let devices = if second_device do
    [device, %{device | mailbox_token: filled(2, 32)?}]
  else
    [device]
  end
  case encode_device_set(DeviceSet {
    version: 1,
    username: "alice",
    account_identity: device.account_identity,
    sequence: U64.parse(Int.to_string(sequence))?,
    devices: devices,
    revoked_device_ids: List.new()
  }) do
    Err(_) -> Err("invalid fixture")
    Ok(value)
  end
end

fn checkpoint(conn :: borrow PgConn, sequence :: Int, age :: Int) -> Result<(), String> do
  Pg.execute(conn,
    "INSERT INTO transparency_checkpoints (sequence, tree_size, tree_root, previous_checkpoint_hash, timestamp_ms, service_public_key, service_signature, created_at) VALUES ($1::bigint, 3, repeat('r', 32)::bytea, repeat('p', 32)::bytea, 1, repeat('k', 32)::bytea, repeat('s', 64)::bytea, now() - $2::integer * interval '1 day')",
    [Int.to_string(sequence), Int.to_string(age)])?
  Pg.execute(conn,
    "INSERT INTO witness_signatures (checkpoint_sequence, witness_id, witness_public_key, checkpoint_hash, signature) VALUES ($1::bigint, 'test', repeat('w', 32)::bytea, repeat('h', 32)::bytea, repeat('s', 64)::bytea)",
    [Int.to_string(sequence)])?
  Ok(nil)
end

fn retention_proof(conn :: borrow PgConn) -> Bool!String do
  Pg.execute(conn,
    "TRUNCATE credit_issuer_announcements, transparency_entry_devices, transparency_device_records, transparency_anchors, witness_signatures, transparency_checkpoints, transparency_entries, transparency_nodes, transparency_maintenance RESTART IDENTITY",
    [])?
  Pg.execute(conn, "UPDATE credit_issuer_cursor SET checkpoint = ''::bytea WHERE singleton", [])?
  let account = filled(3, 32)?
  let first = encoded(1, false)?
  let second = encoded(2, true)?
  let third = encoded(3, true)?
  assert(append_entry_on_connection(conn, account, first, true)? == 1)
  assert(append_entry_on_connection(conn, account, second, false)? == 2)
  assert(append_entry_on_connection(conn, account, third, false)? == 3)
  assert(scalar(conn, "SELECT count(*)::text AS value FROM transparency_device_records")? == "2")
  assert(scalar(conn,
    "SELECT count(*)::text AS value FROM transparency_entries WHERE entry_bytes IS NOT NULL")? == "0")
  assert(Bytes.secure_equals(entry_bytes_on_connection(conn, 1)?, first))
  assert(Bytes.secure_equals(entry_bytes_on_connection(conn, 2)?, second))
  assert(Bytes.secure_equals(entry_bytes_on_connection(conn, 3)?, third))
  let root = tree_root(conn, 3)?
  # Only the first transition is outside retention; even a very old current
  # entry must survive. Check the exact boundary inside the transaction clock.
  Pg.execute(conn,
    "UPDATE transparency_entries SET created_at = now() - CASE sequence WHEN 1 THEN interval '91 days' WHEN 2 THEN interval '90 days' ELSE interval '200 days' END",
    [])?
  checkpoint(conn, 1, 40)?
  checkpoint(conn, 2, 39)?
  checkpoint(conn, 3, 35)?
  checkpoint(conn, 4, 100)?
  Pg.execute(conn,
    "INSERT INTO transparency_anchors (checkpoint_sequence, tree_size, checkpoint_hash, ring_index, tx_signature, slot) VALUES (2, 3, repeat('h', 32)::bytea, 0, 'test-anchor', 1)",
    [])?
  let preview = prune_on_connection(conn, true, 100, 1)?
  assert(preview.entries == 1 && preview.checkpoints == 1)
  assert(scalar(conn,
    "SELECT count(*)::text AS value FROM transparency_entries WHERE pruned_at IS NOT NULL")? == "0")
  assert(scalar(conn, "SELECT count(*)::text AS value FROM transparency_maintenance")? == "0")
  let applied = prune_on_connection(conn, false, 100, 1)?
  assert(applied.entries == 1 && applied.checkpoints == 1)
  assert(scalar(conn,
    "SELECT string_agg(sequence::text, ',' ORDER BY sequence) AS value FROM transparency_checkpoints")? == "2,3,4")
  assert(scalar(conn, "SELECT count(*)::text AS value FROM witness_signatures")? == "3")
  case entry_bytes_on_connection(conn, 1) do
    Err(error) -> assert(error == "transparency_entry_pruned")
    Ok(_) -> assert(false)
  end
  assert(Bytes.secure_equals(entry_bytes_on_connection(conn, 2)?, second))
  assert(Bytes.secure_equals(entry_bytes_on_connection(conn, 3)?, third))
  assert(Bytes.secure_equals(tree_root(conn, 3)?, root))
  assert(verify_inclusion(leaf_hash(first)?, tree_inclusion(conn, 0, 3)?, root)?)
  # A repeated scheduled run cannot exceed the durable daily allowance.
  Pg.execute(conn,
    "UPDATE transparency_entries SET created_at = now() - interval '91 days' WHERE sequence = 2",
    [])?
  let capped = prune_on_connection(conn, false, 100, 1)?
  assert(capped.entries == 0 && capped.checkpoints == 0)
  assert(Bytes.secure_equals(entry_bytes_on_connection(conn, 2)?, second))
  # Deletion forgets all records immediately, including shared history.
  forget_account_entries_on_connection(conn, account)?
  assert(scalar(conn, "SELECT count(*)::text AS value FROM transparency_device_records")? == "0")
  assert(scalar(conn, "SELECT count(*)::text AS value FROM transparency_entry_devices")? == "0")
  assert(Bytes.secure_equals(tree_root(conn, 3)?, root))
  Ok(true)
end

fn backfill_proof(conn :: borrow PgConn) -> Bool!String do
  Pg.execute(conn,
    "TRUNCATE credit_issuer_announcements, transparency_entry_devices, transparency_device_records, transparency_anchors, witness_signatures, transparency_checkpoints, transparency_entries, transparency_nodes RESTART IDENTITY",
    [])?
  Pg.execute(conn, "UPDATE credit_issuer_cursor SET checkpoint = ''::bytea WHERE singleton", [])?
  let original = encoded(1, false)?
  Pg.execute_values(conn,
    "INSERT INTO transparency_entries (account_commitment, entry_bytes, leaf_hash, leaf_index) VALUES (repeat('a', 32)::bytea, $1, $2, 0)",
    [Binary(original), Binary(leaf_hash(original)?)])?
  assert(backfill_records_on_connection(conn, 100)? == 1)
  assert(Bytes.secure_equals(entry_bytes_on_connection(conn, 1)?, original))
  assert(backfill_records_on_connection(conn, 100)? == 0)
  # Corrupt legacy data is left intact, never silently normalized.
  Pg.execute_values(conn,
    "INSERT INTO transparency_entries (account_commitment, entry_bytes, leaf_hash, leaf_index) VALUES (repeat('b', 32)::bytea, $1, repeat('x', 32)::bytea, 1)",
    [Binary(encoded(2, true)?)])?
  case backfill_records_on_connection(conn, 100) do
    Err(error) -> assert(error == "transparency_entry_hash_mismatch")
    Ok(_) -> assert(false)
  end
  assert(scalar(conn,
    "SELECT count(*)::text AS value FROM transparency_entries WHERE entry_bytes IS NOT NULL")? == "1")
  Ok(true)
end

fn proof(backfill :: Bool) -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)?
  let result :: Bool!String = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      if backfill do
        backfill_proof(conn)?
      else
        retention_proof(conn)?
      end
      Err("retention_test_rollback")
    end)
  Pool.close(pool)
  case result do
    Err(error) -> if error == "retention_test_rollback" do
      Ok(true)
    else
      Err(error)
    end
    Ok(_) -> Err("retention test did not roll back")
  end
end

test("deduplicated entries survive bounded pruning with current entries, anchors and hashes intact") do
  case proof(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("backfill verifies canonical entry hashes before replacing legacy bytes") do
  case proof(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn scheduled_proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.execute(conn,
        "TRUNCATE messenger_retired_prekeys, messenger_one_time_prekeys, credit_cancellations, credit_issuer_announcements, credit_attachment_objects, credit_action_effects, credit_spent, credit_holds, transparency_entry_devices, transparency_device_records, transparency_anchors, witness_signatures, transparency_checkpoints, transparency_entries, transparency_nodes, transparency_maintenance, messenger_outbox_events, messenger_envelopes RESTART IDENTITY",
        [])?
      Pg.execute(conn,
        "UPDATE credit_issuer_cursor SET checkpoint = ''::bytea WHERE singleton",
        [])?
      let account = filled(3, 32)?
      append_entry_on_connection(conn, account, encoded(1, false)?, true)?
      append_entry_on_connection(conn, account, encoded(2, true)?, false)?
      Pg.execute(conn,
        "UPDATE transparency_entries SET created_at = now() - interval '91 days' WHERE sequence = 1",
        [])?
      Ok(true)
    end)?
  let before = DateTime.to_unix_ms(DateTime.utc_now())
  let due = run_scheduled(pool)?
  let mode = Env.get("MORSE_TRANSPARENCY_RETENTION", "off")
  if mode == "off" do
    assert(due == 0)
  else
    assert(due >= before + 3600000 && due <= DateTime.to_unix_ms(DateTime.utc_now()) + 3600000)
  end
  let content = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do entry_bytes_on_connection(conn, 1) end)
  if mode == "on" do
    case content do
      Err(error) -> assert(error == "transparency_entry_pruned")
      Ok(_) -> assert(false)
    end
  else
    assert(Bytes.secure_equals(content?, encoded(1, false)?))
  end
  let next_due = run_scheduled(pool)?
  assert((mode == "off") == (next_due == 0))
  Pool.close(pool)
  Ok(true)
end

test("scheduled retention respects its mode and preserves an idle-service wakeup") do
  case scheduled_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
