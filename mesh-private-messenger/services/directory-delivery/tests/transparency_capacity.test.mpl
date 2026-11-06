from Api.Binary import register_device_request, resolve_devices_request
from Storage.Transparency import (
  compact_proofs_enabled,
  consistency_from,
  entry_count,
  evidence_for_username,
  transparency_new_account_ceiling,
  transparency_proof_ceiling
)
from Tests.MailboxSupport import register_test_mailbox, test_directory_entry_wire
from Transparency.Merkle import InclusionProof, verify_consistency, verify_inclusion, leaf_hash
from Transparency.Wire import TransparencyEvidence

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn reset(pool :: PoolHandle) -> Result<(), String> do
  Pool.execute(pool,
    "TRUNCATE messenger_retired_prekeys, credit_postage_policies, credit_issuer_announcements, transparency_entry_devices, transparency_device_records, transparency_anchors, transparency_maintenance, messenger_mailbox_aliases, messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
    [])?
  Pool.execute(pool, "UPDATE credit_issuer_cursor SET checkpoint = ''::bytea WHERE singleton", [])?
  Ok(nil)
end

# Junk transitions, as a registration flood would leave behind.

fn fill_log(pool :: PoolHandle, until :: Int) -> Result<(), String> do
  Pool.execute_values(pool,
    "INSERT INTO transparency_entries (account_commitment, entry_bytes, leaf_hash, leaf_index) SELECT sha256(('commitment-' || n)::bytea), 'flood'::bytea, sha256(('leaf-' || n)::bytea), n FROM generate_series((SELECT count(*) FROM transparency_entries)::integer, $1::integer - 1) AS n",
    [Text(Int.to_string(until))])?
  Pool.execute_values(pool,
    "INSERT INTO transparency_nodes (level, node_index, hash) SELECT 0, leaf_index, leaf_hash FROM transparency_entries ON CONFLICT DO NOTHING",
    [])?
  fill_nodes(pool, 0)?
  Ok(nil)
end

fn fill_nodes(pool :: PoolHandle, level :: Int) -> Result<(), String> do
  # Each bulk level changes the level distribution dramatically. Keep the
  # planner from choosing a nested scan for a previously empty level.
  Pool.execute(pool, "ANALYZE transparency_nodes", [])?
  let changed = Pool.execute_values(pool,
    "INSERT INTO transparency_nodes (level, node_index, hash) SELECT $1::integer + 1, l.node_index / 2, sha256(convert_to('mesh-msg/v1/transparency-node', 'UTF8') || l.hash || r.hash) FROM transparency_nodes l JOIN transparency_nodes r ON r.level = l.level AND r.node_index = l.node_index + 1 WHERE l.level = $1::integer AND l.node_index % 2 = 0 ON CONFLICT DO NOTHING",
    [Text(Int.to_string(level))])?
  if changed > 0 do
    fill_nodes(pool, level + 1)
  else
    Ok(nil)
  end
end

fn rollback_proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)?
  reset(pool)?
  let _resident = register_test_mailbox(pool, "resident", repeated(41, 32))?
  # Once a deployment has grown beyond v1, toggling the rollout flag off must
  # preserve both lookups and account changes. A smaller proof is mandatory.
  fill_log(pool, 4097)?
  let evidence = evidence_for_username(pool, "resident", 0, repeated(91, 32))?
  assert(evidence.inclusion.version == 2 && evidence.consistency.version == 2)
  assert(verify_inclusion(leaf_hash(evidence.entry_bytes)?,
    evidence.inclusion,
    evidence.checkpoint.tree_root)?)
  let newcomer = test_directory_entry_wire("newcomer", repeated(42, 32))?
  assert(register_device_request(pool, newcomer).status == 201)
  assert(entry_count(pool)? == 4098)
  reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("a compact tree remains usable if the rollout flag is disabled after growth") do
  case rollback_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn accounts(pool :: PoolHandle) -> Int!String do
  let rows = Pool.query_values(pool, "SELECT count(*)::text AS value FROM messenger_accounts", [])?
  case Map.get(List.head(rows), "value") do
    Text(value) -> case String.to_int(value) do
      None -> Err("invalid account count")
      Some(count) -> Ok(count)
    end
    _ -> Err("invalid account count")
  end
end

fn proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
    "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000)?
  reset(pool)?
  if compact_proofs_enabled() do
    let result = compact_capacity(pool)
    Pool.close(pool)
    return result
  end
  let seed = repeated(91, 32)
  assert(transparency_new_account_ceiling() < transparency_proof_ceiling())
  let _resident = register_test_mailbox(pool, "resident", repeated(41, 32))?
  assert(entry_count(pool)? == 1)
  # A flood stops at the new-account ceiling: the newcomer is refused cleanly
  # and nothing about it is committed.
  fill_log(pool, transparency_new_account_ceiling())?
  assert(entry_count(pool)? == transparency_new_account_ceiling())
  let newcomer = test_directory_entry_wire("newcomer", repeated(42, 32))?
  assert(register_device_request(pool, newcomer).status == 507)
  assert(accounts(pool)? == 1)
  assert(entry_count(pool)? == transparency_new_account_ceiling())
  # Existing accounts keep the reserved room, and lookups keep working: the
  # flood can close registration but can never take the directory down.
  let evidence = evidence_for_username(pool, "resident", 0, seed)?
  assert(evidence.inclusion.tree_size == transparency_new_account_ceiling())
  # Even a log forced to the proof ceiling still answers for every account.
  fill_log(pool, transparency_proof_ceiling())?
  assert(entry_count(pool)? == transparency_proof_ceiling())
  let full = evidence_for_username(pool, "resident", 0, seed)?
  assert(full.inclusion.tree_size == transparency_proof_ceiling())
  assert(register_device_request(pool, newcomer).status == 507)
  assert(entry_count(pool)? == transparency_proof_ceiling())
  Pool.close(pool)
  Ok(true)
end

fn compact_capacity(pool :: PoolHandle) -> Bool!String do
  let seed = repeated(91, 32)
  let _resident = register_test_mailbox(pool, "resident", repeated(41, 32))?
  let first = evidence_for_username(pool, "resident", 0, seed)?
  fill_log(pool, 1000000)?
  let evidence = evidence_for_username(pool, "resident", 1, seed)?
  assert(evidence.inclusion.version == 2 && evidence.consistency.version == 2)
  assert(evidence.inclusion.tree_size == 1000000)
  assert(List.length(evidence.inclusion.leaf_hashes) <= 20)
  assert(List.length(evidence.consistency.leaf_hashes) <= 21)
  assert(verify_inclusion(leaf_hash(evidence.entry_bytes)?,
    evidence.inclusion,
    evidence.checkpoint.tree_root)?)
  assert(verify_consistency(first.checkpoint.tree_root,
    evidence.checkpoint.tree_root,
    evidence.consistency)?)
  let newcomer = test_directory_entry_wire("newcomer", repeated(42, 32))?
  assert(register_device_request(pool, newcomer).status == 201)
  assert(entry_count(pool)? == 1000001)
  let next = evidence_for_username(pool, "newcomer", 1000000, seed)?
  assert(verify_inclusion(leaf_hash(next.entry_bytes)?, next.inclusion, next.checkpoint.tree_root)?)
  assert(verify_consistency(evidence.checkpoint.tree_root,
    next.checkpoint.tree_root,
    consistency_from(pool, 1000000)?)?)
  reset(pool)?
  Ok(true)
end

test("directory capacity preserves legacy safety and supports a million compact leaves") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
