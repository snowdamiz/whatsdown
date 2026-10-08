##! The directory's two Merkle trees over one list of leaves. Tree 1 hashes as
##! Morse does and is what checkpoints sign; tree 2 hashes as RFC 6962 does,
##! over the Morse leaf hashes, and is what C2SP witnesses cosign.
##!
##! The hash of every complete subtree is stored once, by (tree, level, index),
##! when its last leaf is appended, and never changes. A root or a proof reads
##! the few nodes it can need in one query and hands them to Transparency.Tree
##! as its node oracle, so nothing ever reads the whole log.

from Transparency.Codec import tcodec_join
from Transparency.Tree import (
  tlog_consistency_path,
  tlog_inclusion_path,
  tlog_leaf,
  tlog_node,
  tlog_root
)

pub struct DtreeNode do
  level :: Int
  index :: Int
end

struct StoredNode do
  tree :: Int
  level :: Int
  index :: Int
  hash :: Bytes
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid transparency node row")
  end
end

fn integer(value :: DbValue) -> Int!String do
  case String.to_int(text(value)?) do
    None -> Err("invalid transparency node row")
    Some(output) -> Ok(output)
  end
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid transparency node row")
  end
end

# The complete subtrees a tree of `size` leaves splits into: one per set bit of
# size, at index (size >> level) - 1. They are the whole right edge.

fn right_edge(remaining :: Int, level :: Int, output :: List<DtreeNode>) -> List<DtreeNode> do
  if remaining == 0 do
    output
  else if remaining % 2 == 1 do
    right_edge(remaining / 2,
      level + 1,
      List.append(output, DtreeNode { level: level, index: remaining - 1 }))
  else
    right_edge(remaining / 2, level + 1, output)
  end
end

pub fn dtree_right_edge(size :: Int) -> List<DtreeNode> do
  right_edge(size, 0, List.new())
end

# Every complete ancestor of leaf `index`, and each one's sibling. `count` is
# the number of complete nodes at `level`.

fn path_nodes(index :: Int,
  count :: Int,
  level :: Int,
  output :: List<DtreeNode>) -> List<DtreeNode> do
  if count == 0 do
    output
  else
    let sibling = if index % 2 == 0 do
      index + 1
    else
      index - 1
    end
    let own = if index < count do
      List.append(output, DtreeNode { level: level, index: index })
    else
      output
    end
    let both = if sibling < count do
      List.append(own, DtreeNode { level: level, index: sibling })
    else
      own
    end
    path_nodes(index / 2, count / 2, level + 1, both)
  end
end

## The nodes an inclusion path of leaf `index` in a tree of `size` reads: the
## siblings along its path, and the right edge that partial subtrees split into.

pub fn dtree_inclusion_nodes(index :: Int, size :: Int) -> List<DtreeNode> do
  path_nodes(index, size, 0, List.new()) ++ dtree_right_edge(size)
end

## The nodes a consistency proof from old_size to new_size reads: the path of
## the old tree's last leaf, and the new tree's right edge.

pub fn dtree_consistency_nodes(old_size :: Int, new_size :: Int) -> List<DtreeNode> do
  if old_size <= 0 || old_size >= new_size do
    List.new()
  else
    path_nodes(old_size - 1, new_size, 0, List.new()) ++ dtree_right_edge(new_size)
  end
end

fn node_key(level :: Int, index :: Int) -> String do
  "#{level}:#{index}"
end

fn stored_node(nodes :: Map<String, Bytes>, level :: Int, index :: Int) -> Bytes!String do
  let key = node_key(level, index)
  if Map.has_key(nodes, key) do
    Ok(Map.get(nodes, key))
  else
    Err("missing_transparency_node")
  end
end

## A node oracle over nodes already read.

pub fn dtree_oracle(nodes :: Map<String, Bytes>) -> Fun(Int, Int) -> Bytes!String do
  fn level, index -> stored_node(nodes, level, index) end
end

fn joined(values :: List<Int>) -> String do
  String.join(List.map(values, fn value -> Int.to_string(value) end), ",")
end

## Reads the wanted nodes of one tree in one query. Nodes that do not exist
## (yet) are simply absent.

pub fn dtree_read_on_connection(conn :: borrow PgConn,
  tree :: Int,
  wanted :: List<DtreeNode>) -> Map<String, Bytes>!String do
  let rows = Pg.query_values(conn,
    "SELECT stored.level::text AS level, stored.node_index::text AS node_index, stored.hash FROM transparency_nodes AS stored JOIN unnest(string_to_array($2, ',')::integer[], string_to_array($3, ',')::bigint[]) AS wanted (level, node_index) ON stored.level = wanted.level AND stored.node_index = wanted.node_index WHERE stored.tree = $1::smallint",
    [
      Text(Int.to_string(tree)),
      Text(joined(List.map(wanted, fn node -> node.level end))),
      Text(joined(List.map(wanted, fn node -> node.index end)))
    ])?
  let pairs = for row in rows do
    (node_key(integer(Map.get(row, "level"))?, integer(Map.get(row, "node_index"))?),
      binary(Map.get(row, "hash"))?)
  end
  Ok(Map.from_list(pairs))
end

## Leaves in the log: one past the highest leaf index.

pub fn dtree_size_on_connection(conn :: borrow PgConn) -> Int!String do
  let rows = Pg.query_values(conn,
    "SELECT COALESCE(max(leaf_index) + 1, 0)::text AS size FROM transparency_entries",
    [])?
  case rows do
    [row] -> integer(Map.get(row, "size"))
    _ -> Err("transparency size failed")
  end
end

pub fn dtree_root_on_connection(conn :: borrow PgConn, tree :: Int, size :: Int) -> Bytes!String do
  let nodes = dtree_read_on_connection(conn, tree, dtree_right_edge(size))?
  tlog_root(tree, dtree_oracle(nodes), size)
end

pub fn dtree_inclusion_on_connection(conn :: borrow PgConn,
  tree :: Int,
  index :: Int,
  size :: Int) -> List<Bytes>!String do
  let nodes = dtree_read_on_connection(conn, tree, dtree_inclusion_nodes(index, size))?
  tlog_inclusion_path(tree, dtree_oracle(nodes), index, size)
end

## The root at `size` and the inclusion path of `index`, from one read.

pub fn dtree_view_on_connection(conn :: borrow PgConn,
  tree :: Int,
  index :: Int,
  size :: Int) -> (Bytes, List<Bytes>)!String do
  let oracle = dtree_oracle(dtree_read_on_connection(conn,
    tree,
    dtree_inclusion_nodes(index, size))?)
  Ok((tlog_root(tree, oracle, size)?, tlog_inclusion_path(tree, oracle, index, size)?))
end

pub fn dtree_consistency_on_connection(conn :: borrow PgConn,
  tree :: Int,
  old_size :: Int,
  new_size :: Int) -> List<Bytes>!String do
  let nodes = dtree_read_on_connection(conn, tree, dtree_consistency_nodes(old_size, new_size))?
  tlog_consistency_path(tree, dtree_oracle(nodes), old_size, new_size)
end

# The new leaf is node (0, index); while it is a right child it completes its
# parent, whose left child is on the old tree's right edge.

fn completed(tree :: Int,
  left_nodes :: Fun(Int, Int) -> Bytes!String,
  level :: Int,
  index :: Int,
  hash :: Bytes,
  output :: List<StoredNode>) -> List<StoredNode>!String do
  let next = List.append(output, StoredNode { tree: tree, level: level, index: index, hash: hash })
  if index % 2 == 0 do
    Ok(next)
  else
    let parent = tlog_node(tree, left_nodes(level, index - 1)?, hash)?
    completed(tree, left_nodes, level + 1, index / 2, parent, next)
  end
end

fn insert_nodes(conn :: borrow PgConn, nodes :: List<StoredNode>) -> Result<(), String> do
  let hashes = tcodec_join(List.map(nodes, fn node -> node.hash end))?
  let changed = Pg.execute_values(conn,
    "INSERT INTO transparency_nodes (tree, level, node_index, hash) SELECT node.tree, node.level, node.node_index, substring($4::bytea FROM (node.ordinal::integer - 1) * 32 + 1 FOR 32) FROM unnest(string_to_array($1, ',')::smallint[], string_to_array($2, ',')::integer[], string_to_array($3, ',')::bigint[]) WITH ORDINALITY AS node (tree, level, node_index, ordinal)",
    [
      Text(joined(List.map(nodes, fn node -> node.tree end))),
      Text(joined(List.map(nodes, fn node -> node.level end))),
      Text(joined(List.map(nodes, fn node -> node.index end))),
      Binary(hashes)
    ])?
  if changed == List.length(nodes) do
    Ok(nil)
  else
    Err("transparency node insert failed")
  end
end

## Stores every node that leaf `index` (the log's newest, Morse leaf hash
## `leaf`) completes, in both trees. Call under the log's append lock, in the
## transaction that appends the leaf.

pub fn dtree_append_on_connection(conn :: borrow PgConn,
  index :: Int,
  leaf :: Bytes) -> Result<(), String> do
  let edge = dtree_right_edge(index)
  let morse = completed(1,
    dtree_oracle(dtree_read_on_connection(conn, 1, edge)?),
    0,
    index,
    leaf,
    List.new())?
  let rfc6962 = completed(2,
    dtree_oracle(dtree_read_on_connection(conn, 2, edge)?),
    0,
    index,
    tlog_leaf(2, leaf)?,
    List.new())?
  insert_nodes(conn, morse ++ rfc6962)
end
