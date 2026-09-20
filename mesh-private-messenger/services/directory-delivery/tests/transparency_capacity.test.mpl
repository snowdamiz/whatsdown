from Api.Binary import register_device_request, resolve_devices_request
from Storage.Transparency import entry_count, evidence_for_username, transparency_new_account_ceiling, transparency_proof_ceiling
from Tests.MailboxSupport import register_test_mailbox, test_directory_entry_wire
from Transparency.Merkle import InclusionProof
from Transparency.Wire import TransparencyEvidence

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err( _) -> Bytes.empty()
    Ok( output) -> output
  end
end

fn reset(pool :: PoolHandle) -> Result <(), String > do
  let _ = Pool.execute(pool,
  "TRUNCATE messenger_mailbox_aliases, messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
  []) ?
  Ok(nil)
end

# Junk transitions, as a registration flood would leave behind.

fn fill_log(pool :: PoolHandle, until :: Int) -> Result <(), String > do
  let _ = Pool.execute_values(pool,
  "INSERT INTO transparency_entries (account_commitment, entry_bytes, leaf_hash) SELECT sha256(('commitment-' || n)::bytea), 'flood'::bytea, sha256(('leaf-' || n)::bytea) FROM generate_series(1, $1::integer - (SELECT count(*) FROM transparency_entries)::integer) AS n",
  [Text(Int.to_string(until))]) ?
  Ok(nil)
end

fn accounts(pool :: PoolHandle) -> Int ! String do
  let rows = Pool.query_values(pool, "SELECT count(*)::text AS value FROM messenger_accounts", []) ?
  case Map.get(List.head(rows), "value") do
    Text( value) -> case String.to_int(value) do
      None -> Err("invalid account count")
      Some( count) -> Ok(count)
    end
    _ -> Err("invalid account count")
  end
end

fn proof() -> Bool ! String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000) ?
  reset(pool) ?
  let seed = repeated(91, 32)
  assert(transparency_new_account_ceiling() < transparency_proof_ceiling())
  let _resident = register_test_mailbox(pool, "resident", repeated(41, 32)) ?
  assert(entry_count(pool) ? == 1)
  # A flood stops at the new-account ceiling: the newcomer is refused cleanly
  # and nothing about it is committed.
  fill_log(pool, transparency_new_account_ceiling()) ?
  assert(entry_count(pool) ? == transparency_new_account_ceiling())
  let newcomer = test_directory_entry_wire("newcomer", repeated(42, 32)) ?
  assert(register_device_request(pool, newcomer).status == 507)
  assert(accounts(pool) ? == 1)
  assert(entry_count(pool) ? == transparency_new_account_ceiling())
  # Existing accounts keep the reserved room, and lookups keep working: the
  # flood can close registration but can never take the directory down.
  let evidence = evidence_for_username(pool, "resident", 0, seed) ?
  assert(evidence.inclusion.tree_size == transparency_new_account_ceiling())
  # Even a log forced to the proof ceiling still answers for every account.
  fill_log(pool, transparency_proof_ceiling()) ?
  assert(entry_count(pool) ? == transparency_proof_ceiling())
  let full = evidence_for_username(pool, "resident", 0, seed) ?
  assert(full.inclusion.tree_size == transparency_proof_ceiling())
  assert(register_device_request(pool, newcomer).status == 507)
  assert(entry_count(pool) ? == transparency_proof_ceiling())
  Pool.close(pool)
  Ok(true)
end

test("a registration flood closes registration but never takes lookups down") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
