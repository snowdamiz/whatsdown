from Protocol.DirectoryWire import encode_device_set
from Protocol.V1 import DeviceSet, DirectoryEntry
from Storage.Transparency import append_entry_on_connection, create_checkpoint_for_on_connection
from Storage.TransparencyCutover import (
  begin_cutover_on_connection,
  accept_legacy_seal_on_connection,
  copy_cutover_batch_on_connection,
  legacy_bridge_on_connection
)
from Storage.TransparencyLog import writable_log_version
from Storage.TransparencyRecords import entry_bytes_on_connection
from Storage.TransparencyTree import tree_size_for, tree_root_for
from Transparency.Merkle import WitnessKey, sign_witness, checkpoint_hash
from Transparency.Migration import verify_legacy_bridge
from Transparency.Wire import encode_checkpoint

fn signing_pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test signing key failed")
    Ok(value)
  end
end

fn filled(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("fixture allocation failed")
    Ok(bytes)
  end
end

fn encoded(sequence :: Int) -> Bytes!String do
  let device = DirectoryEntry {
    version: 1,
    username: "alice",
    account_identity: Bytes.from_utf8("account"),
    prekey_bundle: filled(12, 1184)?,
    mailbox_token: filled(1, 32)?
  }
  case encode_device_set(DeviceSet {
    version: 1,
    username: device.username,
    account_identity: device.account_identity,
    sequence: U64.parse(Int.to_string(sequence))?,
    devices: [device],
    revoked_device_ids: List.new()
  }) do
    Err(_) -> Err("invalid fixture")
    Ok(value)
  end
end

fn transaction_proof(conn :: borrow PgConn) -> Bool!String do
  Pg.execute(conn,
    "TRUNCATE credit_issuer_announcements, transparency_v2_anchors, transparency_entry_devices, transparency_device_records, transparency_anchors, witness_signatures, transparency_checkpoints, transparency_entries, transparency_nodes, transparency_v2_nodes, transparency_v2_checkpoints, witness_v2_signatures, transparency_log_cutover RESTART IDENTITY",
    [])?
  Pg.execute(conn, "UPDATE credit_issuer_cursor SET checkpoint = ''::bytea WHERE singleton", [])?
  let signer = signing_pair()?
  let a = signing_pair()?
  let b = signing_pair()?
  let keys = [
    WitnessKey { witness_id: "a", public_key: a.public_key.bytes },
    WitnessKey { witness_id: "b", public_key: b.public_key.bytes }
  ]
  let first = encoded(1)?
  let latest = encoded(2)?
  let account = filled(3, 32)?
  assert(writable_log_version(conn)? == 1)
  append_entry_on_connection(conn, account, first, true)?
  let previous = create_checkpoint_for_on_connection(conn,
    1,
    signer.private_key,
    signer.public_key.bytes)?
  append_entry_on_connection(conn, account, latest, false)?
  # Only the latest transition for each account is copied; the signed account
  # sequence and content-addressed device records stay unchanged.
  append_entry_on_connection(conn, filled(4, 32)?, first, true)?
  let seal = begin_cutover_on_connection(conn, signer.private_key, signer.public_key.bytes)?
  assert(U64.to_int(seal.tree_size)? == 3)
  let frozen_root = tree_root_for(conn, 1, 3)?
  let repeated = begin_cutover_on_connection(conn, signer.private_key, signer.public_key.bytes)?
  assert(Bytes.secure_equals(checkpoint_hash(seal)?, checkpoint_hash(repeated)?))
  case append_entry_on_connection(conn, account, encoded(3)?, false) do
    Err(error) -> assert(error == "transparency_migration_in_progress")
    Ok(_) -> assert(false)
  end
  let att_a = sign_witness("a", a.private_key, seal)?
  let att_b = sign_witness("b", b.private_key, seal)?
  case accept_legacy_seal_on_connection(conn, [att_a], keys, 2) do
    Err(error) -> assert(error == "legacy_seal_quorum_missing")
    Ok(_) -> assert(false)
  end
  assert(tree_size_for(conn, 2)? == 0)
  accept_legacy_seal_on_connection(conn, [att_a, att_b], keys, 2)?
  accept_legacy_seal_on_connection(conn, [att_a, att_b], keys, 2)?
  assert(tree_size_for(conn, 2)? == 1)
  assert(!copy_cutover_batch_on_connection(conn, 1, signer.private_key, signer.public_key.bytes)?)
  assert(tree_size_for(conn, 2)? == 2)
  case writable_log_version(conn) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  assert(!copy_cutover_batch_on_connection(conn, 1, signer.private_key, signer.public_key.bytes)?)
  assert(tree_size_for(conn, 2)? == 3)
  assert(copy_cutover_batch_on_connection(conn, 1, signer.private_key, signer.public_key.bytes)?)
  assert(copy_cutover_batch_on_connection(conn, 1, signer.private_key, signer.public_key.bytes)?)
  assert(writable_log_version(conn)? == 2)
  let current = create_checkpoint_for_on_connection(conn,
    2,
    signer.private_key,
    signer.public_key.bytes)?
  assert(current.version == 2 && U64.to_int(current.tree_size)? == 3)
  assert(U64.to_int(current.sequence)? == 1)
  let bridge = legacy_bridge_on_connection(conn, 1, 3)?
  assert(verify_legacy_bridge(current,
    bridge,
    signer.public_key,
    keys,
    2,
    encode_checkpoint(previous)?)?)
  let rows = Pg.query(conn,
    "SELECT sequence::text FROM transparency_entries WHERE log_version = 2 ORDER BY leaf_index",
    [])?
  assert(List.length(rows) == 2)
  assert(Bytes.secure_equals(entry_bytes_on_connection(conn, 4)?, latest))
  assert(Bytes.secure_equals(entry_bytes_on_connection(conn, 5)?, first))
  let next = append_entry_on_connection(conn, account, encoded(3)?, false)?
  assert(Bytes.secure_equals(entry_bytes_on_connection(conn, next)?, encoded(3)?))
  assert(tree_size_for(conn, 2)? == 4)
  assert(tree_size_for(conn, 1)? == 3)
  assert(Bytes.secure_equals(tree_root_for(conn, 1, 3)?, frozen_root))
  let legacy = create_checkpoint_for_on_connection(conn,
    1,
    signer.private_key,
    signer.public_key.bytes)?
  assert(Bytes.secure_equals(checkpoint_hash(legacy)?, checkpoint_hash(seal)?))
  assert(Bytes.secure_equals(entry_bytes_on_connection(conn, 1)?, first))
  Ok(true)
end

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)?
  let result :: Bool!String = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      transaction_proof(conn)?
      Err("cutover_test_rollback")
    end)
  Pool.close(pool)
  case result do
    Err(error) -> if error == "cutover_test_rollback" do
      Ok(true)
    else
      Err(error)
    end
    Ok(_) -> Err("cutover test did not roll back")
  end
end

test("witnessed RFC cutover seals legacy history, copies bounded batches and atomically activates") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

from Storage.Transparency import (
  polled_checkpoint_for,
  latest_checkpoint_for,
  configured_checkpoint_note
)
from Storage.Transparency import forget_account_entries_on_connection
from Transparency.Merkle import sign_tree_checkpoint_for, verify_inclusion, leaf_hash_for
from Transparency.C2sp import decode_checkpoint_note, verify_checkpoint_note
from Transparency.Wire import decode_checkpoint

fn test_signer() -> SigningKeyPair!String do
  let secret = case Env.get_secret_hex("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX") do
    Err(_) -> return Err("fixture signer configuration missing")
    Ok(value) -> value
  end
  case Crypto.signing_from_secret(secret) do
    Err(_) -> Err("fixture signing key failed")
    Ok(value)
  end
end

fn reset_cutover(conn :: borrow PgConn) -> Result<(), String> do
  Pg.execute(conn,
    "TRUNCATE credit_issuer_announcements, transparency_v2_anchors, transparency_entry_devices, transparency_device_records, transparency_anchors, witness_signatures, transparency_checkpoints, transparency_entries, transparency_nodes, transparency_v2_nodes, transparency_v2_checkpoints, witness_v2_signatures, transparency_log_cutover RESTART IDENTITY",
    [])?
  Pg.execute(conn, "UPDATE credit_issuer_cursor SET checkpoint = ''::bytea WHERE singleton", [])?
  Ok(nil)
end

fn prepare_durable(conn :: borrow PgConn) -> Bytes!String do
  reset_cutover(conn)?
  let signer = test_signer()?
  append_entry_on_connection(conn, filled(3, 32)?, encoded(1)?, true)?
  append_entry_on_connection(conn, filled(4, 32)?, encoded(2)?, true)?
  append_entry_on_connection(conn, filled(5, 32)?, encoded(3)?, true)?
  let fresh = begin_cutover_on_connection(conn, signer.private_key, signer.public_key.bytes)?
  # Model the sealed maintenance window lasting past freshness. Refreshing this
  # checkpoint would invalidate the committed bridge and the old quorum.
  let seal = sign_tree_checkpoint_for(1,
    signer.private_key,
    signer.public_key.bytes,
    fresh.sequence,
    fresh.tree_size,
    fresh.tree_root,
    fresh.previous_checkpoint_hash,
    U64.parse("1000")?)?
  Pg.execute_values(conn,
    "UPDATE transparency_checkpoints SET timestamp_ms = 1000, service_signature = $1",
    [Binary(seal.signature)])?
  Pg.execute_values(conn,
    "UPDATE transparency_log_cutover SET legacy_checkpoint = $1",
    [Binary(encode_checkpoint(seal)?)])?
  let pin = WitnessKey { witness_id: "fixture", public_key: signer.public_key.bytes }
  accept_legacy_seal_on_connection(conn,
    [sign_witness("fixture", signer.private_key, seal)?],
    [pin],
    1)?
  assert(!copy_cutover_batch_on_connection(conn, 1, signer.private_key, signer.public_key.bytes)?)
  # Delete one copied and one not-yet-copied account. Neither can be resurrected
  # by a later batch or an old retained device record.
  forget_account_entries_on_connection(conn, filled(3, 32)?)?
  forget_account_entries_on_connection(conn, filled(5, 32)?)?
  Ok(encode_checkpoint(seal)?)
end

fn finish_batch(conn :: borrow PgConn) -> Bool!String do
  let signer = test_signer()?
  copy_cutover_batch_on_connection(conn, 1, signer.private_key, signer.public_key.bytes)
end

from Api.Binary import (
  checkpoint_request_for,
  resolve_devices_request_for,
  checkpoint_request,
  consistency_request_for,
  legacy_bridge_request,
  checkpoint_note_request
)
from Transparency.Migration import encode_bridge_query, decode_legacy_bridge, legacy_bridge_leaf
from Transparency.Wire import encode_consistency_range, decode_consistency_proof

fn durable_proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
    "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000)?
  let sealed = Repo.transaction(pool, fn(conn :: borrow PgConn) -> prepare_durable(conn) end)?
  assert(latest_checkpoint_for(pool, 2)? == None)
  assert(checkpoint_request_for(pool, 2).status == 404)
  assert(checkpoint_note_request(pool).status == 404)
  let unavailable = resolve_devices_request_for(pool, 2, Bytes.empty())
  assert(unavailable.status == 404
    && Bytes.to_utf8(unavailable.body)? == "transparency_v2_not_active")
  case configured_checkpoint_note(pool) do
    Err(error) -> assert(error == "transparency_v2_not_active")
    Ok(_) -> assert(false)
  end
  let interrupted :: Bool!String = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      assert(!finish_batch(conn)?)
      Err("simulated interrupted batch")
    end)
  assert(interrupted == Err("simulated interrupted batch"))
  Pool.close(pool)
  # A fresh pool/connection must resume from the committed cursor, never an
  # in-memory flag or the rolled-back batch's SQL sequence allocation.
  let reopened = Pool.open(url, 1, 2, 5000)?
  let signer = test_signer()?
  let old = case polled_checkpoint_for(reopened, 1)? do
    Some(value) -> value
    None -> return Err("lost legacy seal")
  end
  assert(Bytes.secure_equals(encode_checkpoint(old)?, sealed))
  assert(!Repo.transaction(reopened, fn(conn :: borrow PgConn) -> finish_batch(conn) end)?)
  assert(Repo.transaction(reopened, fn(conn :: borrow PgConn) -> finish_batch(conn) end)?)
  let current = case polled_checkpoint_for(reopened, 2)? do
    Some(value) -> value
    None -> return Err("missing RFC checkpoint")
  end
  assert(current.version == 2 && U64.to_int(current.tree_size)? == 3)
  assert(checkpoint_request(reopened).status == 200)
  assert(Bytes.secure_equals(checkpoint_request(reopened).body, sealed))
  let response = checkpoint_request_for(reopened, 2)
  assert(response.status == 200 && decode_checkpoint(response.body)?.version == 2)
  let consistency = consistency_request_for(reopened, 2, encode_consistency_range(1, 3)?)
  assert(consistency.status == 200 && decode_consistency_proof(consistency.body)?.version == 3)
  let bridge_response = legacy_bridge_request(reopened, encode_bridge_query(3, 3)?)
  assert(bridge_response.status == 200)
  let bridge = decode_legacy_bridge(bridge_response.body)?
  assert(verify_inclusion(leaf_hash_for(2, legacy_bridge_leaf(bridge.checkpoint)?)?,
    bridge.inclusion,
    current.tree_root)?)
  let note_response = checkpoint_note_request(reopened)
  assert(note_response.status == 200)
  let note = decode_checkpoint_note(note_response.body)?
  assert(verify_checkpoint_note(note, signer.public_key)?)
  let old = case polled_checkpoint_for(reopened, 1)? do
    Some(value) -> value
    None -> return Err("lost legacy seal")
  end
  assert(Bytes.secure_equals(encode_checkpoint(old)?, sealed))
  let rows = Pool.query(reopened,
    "SELECT count(*)::text AS count FROM transparency_entries WHERE log_version = 2 AND entry_header IS NOT NULL",
    [])?
  assert(Map.get(List.head(rows), "count") == "1")
  Repo.transaction(reopened, fn(conn :: borrow PgConn) -> reset_cutover(conn) end)?
  Pool.close(reopened)
  Ok(true)
end

test("cutover resumes after connection loss and rollback without resurrecting deleted accounts or refreshing its seal") do
  case durable_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
