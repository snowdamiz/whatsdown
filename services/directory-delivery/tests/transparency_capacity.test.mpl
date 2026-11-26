from Api.Binary import register_device_request, resolve_devices_request
from Storage.Transparency import (
  create_checkpoint,
  entry_count,
  evidence_v2_for_username,
  transparency_consistency_v2
)
from Storage.TransparencyWitnesses import transparency_seed_registry
from Tests.MailboxSupport import register_test_mailbox, test_directory_entry_wire
from Tests.TransparencySupport import (
  transparency_test_attest,
  transparency_test_bytes,
  transparency_test_reset,
  transparency_test_witness_key
)
from Transparency.Client import transparency_verify_evidence_v2
from Transparency.CompactWire import CompactConsistency, CompactInclusion, TransparencyEvidenceV2
from Transparency.Merkle import TransparencyCheckpoint, WitnessKey
from Transparency.Tree import (
  tlog_leaf,
  tlog_list_oracle,
  tlog_range_root,
  tlog_verify_consistency,
  tlog_verify_inclusion
)
from Transparency.Wire import TransparencyLookup, encode_checkpoint, encode_transparency_lookup

fn size() -> Int do
  1000000
end

fn clock() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

fn report(label :: String, started :: Int) -> Int do
  let now = clock()
  println("capacity: #{label} in #{now - started} ms")
  now
end

# Junk transitions a registration flood would leave, bulk-inserted as hashes:
# the entries themselves are already pruned.

fn flood(pool :: PoolHandle, until :: Int) -> Result<(), String> do
  Pool.execute_values(pool,
    "INSERT INTO transparency_entries (account_commitment, leaf_hash, leaf_index, pruned_at) SELECT sha256(('commitment-' || n)::bytea), sha256(('leaf-' || n)::bytea), n, now() FROM generate_series((SELECT max(leaf_index) + 1 FROM transparency_entries), $1::bigint - 1) AS n",
    [Text(Int.to_string(until))])?
  Ok(nil)
end

fn stored(pool :: PoolHandle, tree :: Int, level :: Int, index :: Int) -> Bytes!String do
  let rows = Pool.query_values(pool,
    "SELECT hash FROM transparency_nodes WHERE tree = $1::smallint AND level = $2::integer AND node_index = $3::bigint",
    [Text(Int.to_string(tree)), Text(Int.to_string(level)), Text(Int.to_string(index))])?
  case rows do
    [row] -> case Map.get(row, "hash") do
      Binary(value) -> Ok(value)
      _ -> Err("invalid node")
    end
    _ -> Err("missing node #{tree}/#{level}/#{index}")
  end
end

fn leaves(pool :: PoolHandle, start :: Int, count :: Int, tree :: Int) -> List<Bytes>!String do
  let rows = Pool.query_values(pool,
    "SELECT leaf_hash FROM transparency_entries WHERE leaf_index >= $1::bigint AND leaf_index < $1::bigint + $2::bigint ORDER BY leaf_index",
    [Text(Int.to_string(start)), Text(Int.to_string(count))])?
  Ok(for row in rows do
    case Map.get(row, "leaf_hash") do
      Binary(value) -> if tree == 2 do
        tlog_leaf(2, value)?
      else
        value
      end
      _ -> Bytes.empty()
    end
  end)
end

fn width(level :: Int) -> Int do
  if level == 0 do
    1
  else
    2 * width(level - 1)
  end
end

# The node SQL built at (level, index) equals the root Mesh computes over the
# leaves beneath it.

fn sampled(pool :: PoolHandle, tree :: Int, level :: Int, index :: Int) -> Bool!String do
  let span = width(level)
  let below = leaves(pool, index * span, span, tree)?
  let computed = tlog_range_root(tree, tlog_list_oracle(tree, below), 0, span)?
  Ok(List.length(below) == span && Bytes.secure_equals(computed, stored(pool, tree, level, index)?))
end

fn level_matches(pool :: PoolHandle, level :: Int) -> Bool!String do
  let last = size() / width(level) - 1
  let first = sampled(pool, 1, level, 0)?
  let middle = sampled(pool, 1, level, last / 2)?
  let edge = sampled(pool, 1, level, last)?
  let rfc_middle = sampled(pool, 2, level, last / 3)?
  let rfc_edge = sampled(pool, 2, level, last)?
  Ok(first && middle && edge && rfc_middle && rfc_edge)
end

fn samples_match(pool :: PoolHandle) -> Bool!String do
  let low = level_matches(pool, 0)?
  let pairs = level_matches(pool, 1)?
  let small = level_matches(pool, 4)?
  let medium = level_matches(pool, 9)?
  let large = level_matches(pool, 12)?
  Ok(low && pairs && small && medium && large)
end

fn trusted() -> List<WitnessKey>!String do
  let a = transparency_test_witness_key("witness-a")?
  let b = transparency_test_witness_key("witness-b")?
  Ok([
    WitnessKey { witness_id: "witness-a", public_key: a.public_key.bytes },
    WitnessKey { witness_id: "witness-b", public_key: b.public_key.bytes }
  ])
end

fn service_key(seed :: Bytes) -> SigningPublicKey!String do
  case Crypto.signing_from_seed(seed) do
    Err(_) -> Err("service key failed")
    Ok(value) -> Ok(SigningPublicKey { bytes: value.public_key.bytes })
  end
end

fn now_ms() -> U64!String do
  U64.parse(Int.to_string(clock()))
end

fn verified(pool :: PoolHandle,
  seed :: Bytes,
  username :: String,
  previous :: TransparencyCheckpoint) -> Bool!String do
  let evidence = evidence_v2_for_username(pool, username, U64.to_int(previous.tree_size)?, seed)?
  let a = transparency_test_attest(pool, "witness-a", evidence.checkpoint)?
  let b = transparency_test_attest(pool, "witness-b", evidence.checkpoint)?
  assert((a == 201 || a == 200) && (b == 201 || b == 200))
  let signed = evidence_v2_for_username(pool, username, U64.to_int(previous.tree_size)?, seed)?
  assert(List.length(signed.inclusion.path) <= 20)
  transparency_verify_evidence_v2(signed,
    service_key(seed)?,
    trusted()?,
    2,
    "-",
    encode_checkpoint(previous)?,
    now_ms()?)
end

fn proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
    "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 600000)?
  transparency_test_reset(pool)?
  transparency_seed_registry(pool)?
  let seed = transparency_test_bytes(91, 32)
  let _resident = register_test_mailbox(pool, "resident", transparency_test_bytes(41, 32))?
  let started = clock()
  flood(pool, size())?
  let inserted = report("inserted 999,999 leaves", started)
  Pool.query_values(pool, "SELECT transparency_build_nodes()::text AS levels", [])?
  let built = report("built both trees' nodes in SQL", inserted)
  assert(entry_count(pool)? == size())
  assert(samples_match(pool)?)
  let sampled_at = report("checked sampled nodes against Mesh", built)
  let million = create_checkpoint(pool, seed)?
  assert(U64.to_int(million.tree_size)? == size())
  let signed_at = report("signed a checkpoint from the right edge", sampled_at)
  # Registration no longer stops at any ceiling: a newcomer lands at leaf
  # 1,000,000, its nodes computed on append from the SQL-built right edge.
  let newcomer = test_directory_entry_wire("newcomer", transparency_test_bytes(42, 32))?
  assert(register_device_request(pool, newcomer).status == 201)
  let registered = report("registered past the old ceiling", signed_at)
  assert(entry_count(pool)? == size() + 1)
  assert(verified(pool, seed, "newcomer", million)?)
  assert(verified(pool, seed, "resident", million)?)
  let looked_up = report("verified two compact lookups", registered)
  # The consistency proof between the two checkpoints verifies.
  let current = create_checkpoint(pool, seed)?
  let proof = transparency_consistency_v2(pool, 1, size(), U64.to_int(current.tree_size)?)?
  assert(tlog_verify_consistency(1,
    size(),
    size() + 1,
    proof.path,
    million.tree_root,
    current.tree_root))
  # Version 1 clients fail closed: no full list fits a proof any more.
  let old_client = resolve_devices_request(pool,
    encode_transparency_lookup(TransparencyLookup { username: "resident", previous_tree_size: 0 })?)
  assert(old_client.status == 426)
  report("checked consistency and the v1 refusal", looked_up)
  report("whole capacity run", started)
  transparency_test_reset(pool)?
  Pool.close(pool)
  Ok(true)
end

test("the log grows to a million entries and keeps answering compact proofs") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
