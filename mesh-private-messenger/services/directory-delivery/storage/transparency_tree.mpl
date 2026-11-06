from Transparency.Merkle import ConsistencyProof, InclusionProof, merkle_root_for, node_hash_for
from Transparency.LeafProof import LeafProof

# Only complete subtrees are stored. (level, node_index) names an immutable
# range of 2^level leaves. Tiles group 256 consecutive nodes at each level.
# The final partial subtree is folded at read time, so historical proofs never
# depend on a mutable right edge. Callers append inside their entry transaction.

fn integer(value :: DbValue) -> Int!String do
  case value do
    Text(text) -> case String.to_int(text) do
      Some(number) -> Ok(number)
      None -> Err("invalid tree integer")
    end
    _ -> Err("invalid tree integer")
  end
end

pub fn tree_size_for(conn :: borrow PgConn, version :: Int) -> Int!String do
  let table = node_table(version)?
  let rows = Pg.query_values(conn,
    "SELECT COALESCE(max(node_index) + 1, 0)::text AS size FROM #{table} WHERE level = 0",
    [])?
  case rows do
    [row] -> integer(Map.get(row, "size"))
    _ -> Err("invalid tree size")
  end
end

fn stored_node(conn :: borrow PgConn, version :: Int, level :: Int, index :: Int) -> Bytes!String do
  let table = node_table(version)?
  let rows = Pg.query_values(conn,
    "SELECT hash FROM #{table} WHERE level = $1::integer AND node_index = $2::bigint",
    [Text(Int.to_string(level)), Text(Int.to_string(index))])?
  case rows do
    [row] -> case Map.get(row, "hash") do
      Binary(hash) -> if Bytes.length(hash) == 32 do
        Ok(hash)
      else
        Err("invalid tree node")
      end
      _ -> Err("invalid tree node")
    end
    _ -> Err("missing tree node")
  end
end

fn append_node(conn :: borrow PgConn,
  version :: Int,
  level :: Int,
  index :: Int,
  hash :: Bytes) -> Result<(), String> do
  let table = node_table(version)?
  let changed = Pg.execute_values(conn,
    "INSERT INTO #{table} (level, node_index, hash) VALUES ($1::integer, $2::bigint, $3)",
    [Text(Int.to_string(level)), Text(Int.to_string(index)), Binary(hash)])?
  if changed != 1 do
    Err("tree append failed")
  else if index % 2 == 1 do
    append_node(conn,
      version,
      level + 1,
      index / 2,
      node_hash_for(version, stored_node(conn, version, level, index - 1)?, hash)?)
  else
    Ok(nil)
  end
end

pub fn append_tree_leaf_for(conn :: borrow PgConn,
  version :: Int,
  index :: Int,
  hash :: Bytes) -> Result<(), String> do
  Pg.query_values(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  if index < 0
    || index >= 4294967295
    || Bytes.length(hash) != 32
    || index != tree_size_for(conn, version)? do
    Err("stale tree append")
  else
    append_node(conn, version, 0, index, hash)
  end
end

fn largest_power(count :: Int, power :: Int, level :: Int) -> (Int, Int) do
  if power * 2 <= count do
    largest_power(count, power * 2, level + 1)
  else
    (power, level)
  end
end

fn range_root(conn :: borrow PgConn, version :: Int, start :: Int, count :: Int) -> Bytes!String do
  let (power, level) = largest_power(count, 1, 0)
  let left = stored_node(conn, version, level, start / power)?
  if power == count do
    Ok(left)
  else
    node_hash_for(version, left, range_root(conn, version, start + power, count - power)?)
  end
end

pub fn tree_root_for(conn :: borrow PgConn, version :: Int, count :: Int) -> Bytes!String do
  if count < 0 || count > 4294967295 || count > tree_size_for(conn, version)? do
    Err("invalid tree size")
  else if count == 0 do
    merkle_root_for(version, List.new())
  else
    range_root(conn, version, 0, count)
  end
end

fn inclusion_nodes(conn :: borrow PgConn,
  version :: Int,
  start :: Int,
  count :: Int,
  index :: Int) -> List<Bytes>!String do
  if count == 1 do
    Ok(List.new())
  else
    let (split, _level) = largest_power(count - 1, 1, 0)
    if index < split do
      Ok(List.append(inclusion_nodes(conn, version, start, split, index)?,
        range_root(conn, version, start + split, count - split)?))
    else
      Ok(List.append(inclusion_nodes(conn, version, start + split, count - split, index - split)?,
        range_root(conn, version, start, split)?))
    end
  end
end

pub fn tree_inclusion_for(conn :: borrow PgConn,
  version :: Int,
  index :: Int,
  count :: Int) -> InclusionProof!String do
  if index < 0 || index >= count || count > 4294967295 || count > tree_size_for(conn, version)? do
    Err("invalid inclusion size")
  else
    Ok(InclusionProof {
      version: version + 1,
      leaf_index: index,
      tree_size: count,
      leaf_hashes: inclusion_nodes(conn, version, 0, count, index)?
    })
  end
end

# Hashes and compact paths survive entry/checkpoint pruning. Reading a prefix
# never substitutes a newer size and never needs the original account record.
pub fn tree_leaf_proof_for(conn :: borrow PgConn,
  version :: Int,
  index :: Int,
  count :: Int) -> LeafProof!String do
  if index < 0 || index >= count || count <= 0 || count > 4294967295 do
    return Err("invalid_leaf_query")
  end
  if count > tree_size_for(conn, version)? do
    return Err("transparency_tree_unavailable")
  end
  Ok(LeafProof {
    leaf_hash: stored_node(conn, version, 0, index)?,
    inclusion: tree_inclusion_for(conn, version, index, count)?
  })
end

fn consistency_nodes(conn :: borrow PgConn,
  version :: Int,
  start :: Int,
  old_size :: Int,
  count :: Int,
  known :: Bool) -> List<Bytes>!String do
  if old_size == count do
    if known do
      Ok(List.new())
    else
      Ok([range_root(conn, version, start, count)?])
    end
  else
    let (split, _level) = largest_power(count - 1, 1, 0)
    if old_size <= split do
      Ok(List.append(consistency_nodes(conn, version, start, old_size, split, known)?,
        range_root(conn, version, start + split, count - split)?))
    else
      Ok(List.append(consistency_nodes(conn,
          version,
          start + split,
          old_size - split,
          count - split,
          false)?,
        range_root(conn, version, start, split)?))
    end
  end
end

pub fn tree_consistency_for(conn :: borrow PgConn,
  version :: Int,
  old_size :: Int,
  new_size :: Int) -> ConsistencyProof!String do
  if old_size < 0
    || old_size > new_size
    || new_size > 4294967295
    || new_size > tree_size_for(conn, version)? do
    Err("invalid consistency size")
  else
    let path = if old_size == 0 do
      List.new()
    else
      consistency_nodes(conn, version, 0, old_size, new_size, true)?
    end
    Ok(ConsistencyProof {
      version: version + 1,
      old_tree_size: old_size,
      new_tree_size: new_size,
      leaf_hashes: path
    })
  end
end

# SQL identifiers are selected only from this closed local allowlist. The two
# profiles share the tree algorithm and transaction lock, never stored nodes.
fn node_table(version :: Int) -> String!String do
  if version == 1 do
    Ok("transparency_nodes")
  else if version == 2 do
    Ok("transparency_v2_nodes")
  else
    Err("unsupported_transparency_log")
  end
end

# Existing directory paths keep using the legacy log until explicit cutover.
pub fn tree_size(conn :: borrow PgConn) -> Int!String do
  tree_size_for(conn, 1)
end

pub fn append_tree_leaf(conn :: borrow PgConn, index :: Int, hash :: Bytes) -> Result<(), String> do
  append_tree_leaf_for(conn, 1, index, hash)
end

pub fn tree_root(conn :: borrow PgConn, count :: Int) -> Bytes!String do
  tree_root_for(conn, 1, count)
end

pub fn tree_inclusion(conn :: borrow PgConn, index :: Int, count :: Int) -> InclusionProof!String do
  tree_inclusion_for(conn, 1, index, count)
end

pub fn tree_consistency(conn :: borrow PgConn,
  old_size :: Int,
  new_size :: Int) -> ConsistencyProof!String do
  tree_consistency_for(conn, 1, old_size, new_size)
end
