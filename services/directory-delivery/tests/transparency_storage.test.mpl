from Protocol.DirectoryWire import decode_device_set
from Protocol.V1 import DeviceSet
from Runtime.Workers import next_work_at, run_scheduled
from Storage.Transparency import (
  create_checkpoint,
  evidence_v2_for_username,
  transparency_consistency_v2
)
from Storage.TransparencyPruning import transparency_prune, transparency_pruning_due
from Storage.TransparencyWitnesses import transparency_seed_registry
from Tests.TransparencySupport import (
  transparency_test_account,
  transparency_test_append,
  transparency_test_attest,
  transparency_test_bytes,
  transparency_test_reset,
  transparency_test_scalar,
  transparency_test_set,
  transparency_test_witness_key
)
from Transparency.Client import transparency_verify_evidence_v2
from Transparency.CompactWire import CompactConsistency, TransparencyEvidenceV2
from Transparency.Merkle import TransparencyCheckpoint, WitnessKey
from Transparency.Tree import tlog_verify_consistency
from Transparency.Wire import encode_checkpoint

fn database() -> PoolHandle!String do
  Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)
end

fn count(pool :: PoolHandle, sql :: String) -> Int!String do
  case String.to_int(transparency_test_scalar(pool, sql)?) do
    None -> Err("expected a count")
    Some(value) -> Ok(value)
  end
end

fn rebuilt_count(pool :: PoolHandle) -> Int!String do
  count(pool,
    "SELECT count(*)::text AS value FROM transparency_entries WHERE sha256('mesh-msg/v1/transparency-leaf'::bytea || COALESCE(entry_bytes, transparency_entry_rebuild(entry_header, record_hashes, entry_trailer))) = leaf_hash")
end

fn records(pool :: PoolHandle) -> Int!String do
  count(pool, "SELECT count(*)::text AS value FROM transparency_device_records")
end

# Each device record is stored once however many entries list it, and every
# entry rebuilds to exactly the bytes its leaf hashes.

fn records_proof() -> Bool!String do
  let pool = database()?
  transparency_test_reset(pool)?
  let alice = transparency_test_bytes(1, 32)
  transparency_test_append(pool, alice, transparency_test_set("alice", 1, [11], [])?)?
  assert(records(pool)? == 1)
  transparency_test_append(pool, alice, transparency_test_set("alice", 2, [11, 12], [])?)?
  transparency_test_append(pool, alice, transparency_test_set("alice", 3, [11, 12, 13], [])?)?
  transparency_test_append(pool, alice, transparency_test_set("alice", 4, [11, 13], [12])?)?
  assert(records(pool)? == 3)
  assert(rebuilt_count(pool)? == 4)
  assert(count(pool,
    "SELECT count(*)::text AS value FROM transparency_entries WHERE entry_bytes IS NULL AND cardinality(record_hashes) > 0")? == 4)
  # Anything but a device set is refused and leaves nothing behind.
  let refused = case transparency_test_append(pool, alice, Bytes.from_utf8("not a device set")) do
    Err(_) -> true
    Ok(_) -> false
  end
  assert(refused)
  assert(count(pool, "SELECT count(*)::text AS value FROM transparency_entries")? == 4)
  # Entries stored whole before device records existed move over (migration
  # 020): each only once it rebuilds to its leaf hash. One that cannot keeps
  # its bytes.
  Pool.execute(pool,
    "UPDATE transparency_entries SET entry_bytes = transparency_entry_rebuild(entry_header, record_hashes, entry_trailer)",
    [])?
  Pool.execute(pool,
    "UPDATE transparency_entries SET entry_header = NULL, record_hashes = NULL, entry_trailer = NULL",
    [])?
  Pool.execute(pool,
    "UPDATE transparency_entries SET leaf_hash = sha256('tampered'::bytea) WHERE leaf_index = 3",
    [])?
  Pool.execute(pool, "DELETE FROM transparency_device_records", [])?
  assert(transparency_test_scalar(pool,
    "SELECT transparency_move_to_records()::text AS value")? == "1")
  assert(count(pool,
    "SELECT count(*)::text AS value FROM transparency_entries WHERE entry_bytes IS NULL AND record_hashes IS NOT NULL")? == 3)
  assert(count(pool,
    "SELECT count(*)::text AS value FROM transparency_entries WHERE leaf_index = 3 AND entry_bytes IS NOT NULL AND record_hashes IS NULL")? == 1)
  assert(records(pool)? == 3)
  assert(rebuilt_count(pool)? == 3)
  transparency_test_reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("device records are stored once and every entry rebuilds to its leaf hash") do
  case records_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn backdate(pool :: PoolHandle, leaf_index :: Int, days :: Int) -> Result<(), String> do
  Pool.execute_values(pool,
    "UPDATE transparency_entries SET created_at = now() - ($2::integer * interval '1 day') WHERE leaf_index = $1::bigint",
    [Text(Int.to_string(leaf_index)), Text(Int.to_string(days))])?
  Ok(nil)
end

fn tree_snapshot(pool :: PoolHandle) -> String!String do
  transparency_test_scalar(pool,
    "SELECT concat((SELECT encode(sha256(string_agg(leaf_hash, ''::bytea ORDER BY leaf_index)), 'hex') FROM transparency_entries), ':', (SELECT encode(sha256(string_agg(hash, ''::bytea ORDER BY tree, level, node_index)), 'hex') FROM transparency_nodes)) AS value")
end

fn unpruned(pool :: PoolHandle) -> String!String do
  transparency_test_scalar(pool,
    "SELECT string_agg(leaf_index::text, ',' ORDER BY leaf_index) AS value FROM transparency_entries WHERE pruned_at IS NULL")
end

fn pinned_witnesses() -> List<WitnessKey>!String do
  let a = transparency_test_witness_key("witness-a")?
  let b = transparency_test_witness_key("witness-b")?
  Ok([
    WitnessKey { witness_id: "witness-a", public_key: a.public_key.bytes },
    WitnessKey { witness_id: "witness-b", public_key: b.public_key.bytes }
  ])
end

fn now() -> U64!String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

# alice: 0 [11], 1 [11, 12], 2 [11, 13] (current); bob: 3 [21] (current).
# Entry 0 was superseded 150 days ago, entry 1 only 30 days ago.

fn pruning_log(pool :: PoolHandle) -> Result<(), String> do
  let alice = transparency_test_bytes(1, 32)
  let bob = transparency_test_bytes(2, 32)
  transparency_test_account(pool, "alice", alice)?
  transparency_test_account(pool, "bob", bob)?
  transparency_test_append(pool, alice, transparency_test_set("alice", 1, [11], [])?)?
  transparency_test_append(pool, alice, transparency_test_set("alice", 2, [11, 12], [])?)?
  transparency_test_append(pool, alice, transparency_test_set("alice", 3, [11, 13], [12])?)?
  transparency_test_append(pool, bob, transparency_test_set("bob", 1, [21], [])?)?
  backdate(pool, 0, 200)?
  backdate(pool, 1, 150)?
  backdate(pool, 2, 30)?
  backdate(pool, 3, 200)?
  Ok(nil)
end

fn verified_lookup(pool :: PoolHandle,
  seed :: Bytes,
  username :: String,
  previous :: Bytes,
  previous_size :: Int) -> Bool!String do
  let before = evidence_v2_for_username(pool, username, previous_size, seed)?
  let first = transparency_test_attest(pool, "witness-a", before.checkpoint)?
  let second = transparency_test_attest(pool, "witness-b", before.checkpoint)?
  assert((first == 201 || first == 200) && (second == 201 || second == 200))
  let evidence = evidence_v2_for_username(pool, username, previous_size, seed)?
  let log_key = case Crypto.signing_from_seed(seed) do
    Err(_) -> Err("service key failed")
    Ok(value)
  end?
  transparency_verify_evidence_v2(evidence,
    SigningPublicKey { bytes: log_key.public_key.bytes },
    pinned_witnesses()?,
    2,
    "-",
    previous,
    now()?)
end

fn pruning_proof() -> Bool!String do
  let pool = database()?
  transparency_test_reset(pool)?
  transparency_seed_registry(pool)?
  let seed = transparency_test_bytes(91, 32)
  pruning_log(pool)?
  let first = create_checkpoint(pool, seed)?
  let tree = tree_snapshot(pool)?
  # A dry run counts and changes nothing.
  let dry = transparency_prune(pool, "dry-run", 100)?
  assert(dry.ran && dry.entries == 1 && dry.records == 0)
  assert(unpruned(pool)? == "0,1,2,3")
  # One run a day: today's is spent until the day turns.
  assert(!transparency_prune(pool, "on", 100)?.ran)
  Pool.execute(pool, "DELETE FROM transparency_pruning_runs", [])?
  let pruned = transparency_prune(pool, "on", 100)?
  assert(pruned.ran && pruned.entries == 1 && pruned.records == 0)
  # Only the entry superseded for more than 90 days lost its bytes: never a
  # current entry (bob's is 200 days old), never one inside the window, never
  # a hash or a node.
  assert(unpruned(pool)? == "1,2,3")
  assert(tree_snapshot(pool)? == tree)
  assert(count(pool,
    "SELECT count(*)::text AS value FROM transparency_entries WHERE leaf_index = 0 AND entry_header IS NULL AND record_hashes IS NULL AND entry_bytes IS NULL AND octet_length(leaf_hash) = 32")? == 1)
  assert(records(pool)? == 4)
  # Once entry 2 has stood for 90 days, entry 1 goes, and with it device 12's
  # record, which no remaining entry lists. Device 11's stays.
  backdate(pool, 2, 91)?
  Pool.execute(pool, "DELETE FROM transparency_pruning_runs", [])?
  let second = transparency_prune(pool, "on", 100)?
  assert(second.entries == 1 && second.records == 1)
  assert(unpruned(pool)? == "2,3")
  assert(records(pool)? == 3)
  assert(tree_snapshot(pool)? == tree)
  # Lookups and proofs still verify, including consistency from before.
  let current = evidence_v2_for_username(pool, "alice", 0, seed)?
  let alice_set = case decode_device_set(current.entry_bytes) do
    Err(_) -> Err("alice's current set did not decode")
    Ok(value)
  end?
  assert(List.length(alice_set.devices) == 2)
  assert(verified_lookup(pool, seed, "alice", encode_checkpoint(first)?, 4)?)
  assert(verified_lookup(pool, seed, "bob", Bytes.empty(), 0)?)
  let later = transparency_consistency_v2(pool, 1, 4, 4)?
  assert(tlog_verify_consistency(1,
    4,
    4,
    later.path,
    first.tree_root,
    current.checkpoint.tree_root))
  # The daily cap bounds a run.
  transparency_test_append(pool,
    transparency_test_bytes(2, 32),
    transparency_test_set("bob", 2, [21, 22], [])?)?
  transparency_test_append(pool,
    transparency_test_bytes(2, 32),
    transparency_test_set("bob", 3, [21, 23], [22])?)?
  backdate(pool, 4, 120)?
  backdate(pool, 5, 100)?
  Pool.execute(pool, "DELETE FROM transparency_pruning_runs", [])?
  assert(transparency_prune(pool, "on", 1)?.entries == 1)
  assert(unpruned(pool)? == "2,4,5")
  transparency_test_reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("pruning drops only superseded bytes past 90 days, and proofs still verify") do
  case pruning_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn age_checkpoints(pool :: PoolHandle, days :: Int, below :: Int) -> Result<(), String> do
  Pool.execute_values(pool,
    "UPDATE transparency_checkpoints SET created_at = now() - ($1::integer * interval '1 day') WHERE sequence < $2::bigint",
    [Text(Int.to_string(days)), Text(Int.to_string(below))])?
  Ok(nil)
end

fn checkpoints_proof() -> Bool!String do
  let pool = database()?
  transparency_test_reset(pool)?
  let seed = transparency_test_bytes(91, 32)
  let account = transparency_test_bytes(3, 32)
  let sequences = for index in 0..6 do
    transparency_test_append(pool,
      account,
      transparency_test_set("carol", index + 1, [31 + index], [])?)?
    create_checkpoint(pool, seed)?.sequence
  end
  assert(List.length(sequences) == 6)
  # Checkpoints 1-4 are 40 days old, 5 and 6 recent; 2 is anchored. Each has
  # a stored witness signature.
  age_checkpoints(pool, 40, 5)?
  Pool.execute(pool,
    "INSERT INTO witness_signatures (checkpoint_sequence, witness_id, witness_public_key, checkpoint_hash, signature) SELECT sequence, 'witness-a', sha256('key'::bytea), sha256(tree_root), tree_root || tree_root FROM transparency_checkpoints",
    [])?
  Pool.execute(pool,
    "INSERT INTO transparency_anchors (checkpoint_sequence, tree_size, checkpoint_hash, ring_index, tx_signature, slot) SELECT sequence, tree_size, sha256(tree_root), 7, 'signature', 1 FROM transparency_checkpoints WHERE sequence = 2",
    [])?
  let dry = transparency_prune(pool, "dry-run", 100)?
  assert(dry.checkpoints == 3)
  assert(count(pool, "SELECT count(*)::text AS value FROM transparency_checkpoints")? == 6)
  Pool.execute(pool, "DELETE FROM transparency_pruning_runs", [])?
  assert(transparency_prune(pool, "on", 100)?.checkpoints == 3)
  assert(transparency_test_scalar(pool,
    "SELECT string_agg(sequence::text, ',' ORDER BY sequence) AS value FROM transparency_checkpoints")? == "2,5,6")
  assert(transparency_test_scalar(pool,
    "SELECT string_agg(checkpoint_sequence::text, ',' ORDER BY checkpoint_sequence) AS value FROM witness_signatures")? == "2,5,6")
  # Even an old newest checkpoint stays.
  age_checkpoints(pool, 40, 100)?
  Pool.execute(pool, "DELETE FROM transparency_pruning_runs", [])?
  assert(transparency_prune(pool, "on", 100)?.checkpoints == 1)
  assert(transparency_test_scalar(pool,
    "SELECT string_agg(sequence::text, ',' ORDER BY sequence) AS value FROM transparency_checkpoints")? == "2,6")
  transparency_test_reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("checkpoint pruning keeps the newest and every anchored checkpoint") do
  case checkpoints_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn scheduled_proof() -> Bool!String do
  let pool = database()?
  transparency_test_reset(pool)?
  let started = DateTime.to_unix_ms(DateTime.utc_now())
  assert(transparency_pruning_due(pool)? <= DateTime.to_unix_ms(DateTime.utc_now()))
  # The scheduled job runs today's pruning, then asks to be woken by the next
  # UTC midnight.
  run_scheduled(pool)?
  assert(count(pool, "SELECT count(*)::text AS value FROM transparency_pruning_runs")? == 1)
  let due = next_work_at(pool)?
  assert(due > started && due <= started + 86400000)
  assert(due == transparency_pruning_due(pool)?)
  run_scheduled(pool)?
  assert(count(pool, "SELECT count(*)::text AS value FROM transparency_pruning_runs")? == 1)
  transparency_test_reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("the scheduled job prunes once a day") do
  case scheduled_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
