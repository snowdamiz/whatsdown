from Storage.TransparencyTree import (
  DtreeNode,
  dtree_append_on_connection,
  dtree_consistency_nodes,
  dtree_consistency_on_connection,
  dtree_inclusion_nodes,
  dtree_inclusion_on_connection,
  dtree_list_oracle_subset,
  dtree_root_on_connection,
  dtree_size_on_connection
)
from Transparency.Merkle import merkle_root
from Transparency.Tree import (
  tlog_consistency_path,
  tlog_inclusion_path,
  tlog_leaf,
  tlog_list_oracle,
  tlog_root,
  tlog_verify_consistency,
  tlog_verify_inclusion
)

fn leaves(count :: Int) -> List<Bytes> do
  for index in 0..count do
    Crypto.sha256(Bytes.from_utf8("tree leaf #{index}"))
  end
end

fn same_paths(left :: List<Bytes>, right :: List<Bytes>) -> Bool do
  if List.length(left) != List.length(right) do
    false
  else
    let equal = for index in 0..List.length(left) do
      Bytes.secure_equals(List.get(left, index), List.get(right, index))
    end
    List.all(equal, fn value -> value end)
  end
end

# The nodes a proof reads are all the generator ever asks for: with only those
# available, every proof is the one the full tree gives.

fn subset_proofs_match(tree :: Int, size :: Int) -> Bool!String do
  let all = leaves(size)
  let full = tlog_list_oracle(tree, all)
  let inclusions = for index in 0..size do
    same_paths(tlog_inclusion_path(tree,
        dtree_list_oracle_subset(tree, all, dtree_inclusion_nodes(index, size)),
        index,
        size)?,
      tlog_inclusion_path(tree, full, index, size)?)
  end
  let consistencies = for old_size in 1..size do
    same_paths(tlog_consistency_path(tree,
        dtree_list_oracle_subset(tree, all, dtree_consistency_nodes(old_size, size)),
        old_size,
        size)?,
      tlog_consistency_path(tree, full, old_size, size)?)
  end
  Ok(List.all(inclusions, fn value -> value end) && List.all(consistencies, fn value -> value end))
end

test("proofs need only the nodes the directory reads for them") do
  let results = for size in 1..48 do
    case subset_proofs_match(1, size) do
      Ok(morse) -> morse
        && case subset_proofs_match(2, size) do
          Ok(rfc6962) -> rfc6962
          Err(_) -> false
        end
      Err(_) -> false
    end
  end
  assert(List.all(results, fn value -> value end))
end

fn reset(pool :: PoolHandle) -> Result<(), String> do
  Pool.execute(pool,
    "TRUNCATE messenger_mailbox_aliases, messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
    [])?
  Ok(nil)
end

fn append_leaf(conn :: borrow PgConn, index :: Int, leaf :: Bytes) -> Result<(), String> do
  Pg.execute_values(conn,
    "INSERT INTO transparency_entries (account_commitment, leaf_hash, leaf_index, pruned_at) VALUES (sha256($1), $1, $2::bigint, now())",
    [Binary(leaf), Text(Int.to_string(index))])?
  dtree_append_on_connection(conn, index, leaf)
end

fn node_snapshot(pool :: PoolHandle) -> String!String do
  let rows = Pool.query_values(pool,
    "SELECT concat(count(*), ':', encode(sha256(string_agg(tree::text || '/' || level::text || '/' || node_index::text || '/' || encode(hash, 'hex'), ',' ORDER BY tree, level, node_index)::bytea), 'hex')) AS value FROM transparency_nodes",
    [])?
  case Map.get(List.head(rows), "value") do
    Text(value) -> Ok(value)
    _ -> Err("invalid node snapshot")
  end
end

fn stored_tree_proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
    "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000)?
  reset(pool)?
  let all = leaves(70)
  let checks = for index in 0..70 do
    Repo.transaction(pool,
      fn(conn :: borrow PgConn) -> append_leaf(conn, index, List.get(all, index)) end)?
    let size = index + 1
    let prefix = List.take(all, size)
    Repo.transaction(pool, fn(conn :: borrow PgConn) -> stored_checks(conn, prefix, size) end)?
  end
  assert(List.all(checks, fn value -> value end))
  # Nodes appended one leaf at a time equal the ones SQL builds from the
  # leaves in bulk (the backfill and the capacity test both use it).
  let appended = node_snapshot(pool)?
  Pool.query_values(pool, "SELECT transparency_build_nodes()::text AS levels", [])?
  assert(node_snapshot(pool)? == appended)
  reset(pool)?
  Pool.close(pool)
  Ok(true)
end

# RFC 6962 leaves wrap the Morse leaf hashes: SHA-256(0x00 || leaf hash).

fn rfc6962_leaves(prefix :: List<Bytes>) -> List<Bytes>!String do
  Ok(for leaf in prefix do
    tlog_leaf(2, leaf)?
  end)
end

fn stored_checks(conn :: borrow PgConn, prefix :: List<Bytes>, size :: Int) -> Bool!String do
  let morse_root = dtree_root_on_connection(conn, 1, size)?
  let rfc_root = dtree_root_on_connection(conn, 2, size)?
  let index = size / 3
  let old_size = (size + 1) / 2
  let old_root = dtree_root_on_connection(conn, 1, old_size)?
  Ok(dtree_size_on_connection(conn)? == size
    && Bytes.secure_equals(morse_root, merkle_root(prefix)?)
    && Bytes.secure_equals(rfc_root,
      tlog_root(2, tlog_list_oracle(2, rfc6962_leaves(prefix)?), size)?)
    && tlog_verify_inclusion(1,
      List.get(prefix, index),
      index,
      size,
      dtree_inclusion_on_connection(conn, 1, index, size)?,
      morse_root)
    && tlog_verify_consistency(1,
      old_size,
      size,
      dtree_consistency_on_connection(conn, 1, old_size, size)?,
      old_root,
      morse_root))
end

test("stored nodes give the roots and proofs of every tree size") do
  case stored_tree_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
