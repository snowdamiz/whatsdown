##! The monitor's own copy of the log's Morse leaf hashes, fetched from the
##! directory and kept only while it hashes to an anchored root. It is what
##! lets the monitor prove a contradiction (FRK kind 2) after the directory
##! has rewritten history: the old tree's leaves and paths come from here.
##! Leaves are stored in chunks of 1,024 (32 KiB); the right edge of the tree
##! (one root per complete subtree) is kept so each sync hashes only new leaves.

from Monitor.Directory import monitor_dir_leaves
from Monitor.Store import (
  monitor_chunk_get,
  monitor_chunk_put,
  monitor_chunks_clear,
  monitor_kv_get,
  monitor_kv_int,
  monitor_kv_put,
  monitor_store_atomic
)
from Transparency.Tree import tlog_empty_root, tlog_node

pub type MirrorStep do
  MirrorVerified
  MirrorBehind
  MirrorAhead
  MirrorMismatch
end

fn chunk_leaves() -> Int do
  1024
end

fn frontier_read(db :: SqliteConn) -> List<Bytes>!String do
  let text = monitor_kv_get(db, "mirror_frontier")?
  if text == "" do
    Ok(List.new())
  else
    Ok(for part in String.split(text, ",") do
      case Bytes.from_hex(part) do
        Err(_) -> Bytes.empty()
        Ok(value) -> value
      end
    end)
  end
end

fn frontier_text(frontier :: List<Bytes>) -> String do
  String.join(List.map(frontier, fn value -> Bytes.to_hex(value) end), ",")
end

# Adds one leaf to a tree of size leaves: complete subtrees merge while the
# low bits of size are set.

fn push(frontier :: List<Bytes>, size :: Int, node :: Bytes) -> List<Bytes>!String do
  if size % 2 == 1 do
    let count = List.length(frontier)
    push(List.take(frontier, count - 1),
      size / 2,
      tlog_node(1, List.get(frontier, count - 1), node)?)
  else
    Ok(List.append(frontier, node))
  end
end

fn push_all(frontier :: List<Bytes>, size :: Int, leaves :: List<Bytes>) -> List<Bytes>!String do
  case leaves do
    [] -> Ok(frontier)
    leaf :: rest -> push_all(push(frontier, size, leaf)?, size + 1, rest)
  end
end

fn fold_root(frontier :: List<Bytes>, index :: Int, right :: Bytes) -> Bytes!String do
  if index < 0 do
    Ok(right)
  else
    fold_root(frontier, index - 1, tlog_node(1, List.get(frontier, index), right)?)
  end
end

fn frontier_root(frontier :: List<Bytes>) -> Bytes!String do
  let count = List.length(frontier)
  if count == 0 do
    tlog_empty_root(1)
  else
    fold_root(frontier, count - 2, List.get(frontier, count - 1))
  end
end

fn joined(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts,
    Ok(Bytes.empty()),
    fn acc, part -> case acc do
      Err(error)
      Ok(bytes) -> case Bytes.concat(bytes, part) do
        Err(_) -> Err("mirror chunk too large")
        Ok(value)
      end
    end end)
end

pub fn monitor_mirror_size(db :: SqliteConn) -> Int!String do
  monitor_kv_int(db, "mirror_size")
end

pub fn monitor_mirror_verified(db :: SqliteConn) -> Int!String do
  monitor_kv_int(db, "mirror_verified")
end

fn reset(db :: SqliteConn) -> Result<(), String> do
  monitor_store_atomic(db,
    fn() do
      monitor_chunks_clear(db)?
      monitor_kv_put(db, "mirror_size", "0")?
      monitor_kv_put(db, "mirror_verified", "0")?
      monitor_kv_put(db, "mirror_frontier", "")
    end)
end

fn append(db :: SqliteConn, size :: Int, leaves :: List<Bytes>) -> Result<(), String> do
  let chunk = size / chunk_leaves()
  let existing = monitor_chunk_get(db, chunk)?
  let stored = Bytes.length(existing) / 32
  if stored != size % chunk_leaves() do
    Err("mirror chunk #{chunk} holds #{stored} leaves, expected #{size % chunk_leaves()}")
  else
    let bytes = joined([existing] ++ leaves)?
    let frontier = push_all(frontier_read(db)?, size, leaves)?
    monitor_store_atomic(db,
      fn() do
        monitor_chunk_put(db, chunk, bytes)?
        monitor_kv_put(db, "mirror_size", Int.to_string(size + List.length(leaves)))?
        monitor_kv_put(db, "mirror_frontier", frontier_text(frontier))
      end)
  end
end

fn fetch(db :: SqliteConn, base :: String, target :: Int, budget :: Int) -> Bool!String do
  let size = monitor_mirror_size(db)?
  if size >= target do
    Ok(true)
  else if budget <= 0 do
    Ok(false)
  else
    let room = chunk_leaves() - size % chunk_leaves()
    let wanted = if target - size < room do
      target - size
    else
      room
    end
    let leaves = monitor_dir_leaves(base, size, wanted)?
    if List.length(leaves) == 0 do
      Ok(false)
    else
      append(db, size, leaves)?
      fetch(db, base, target, budget - 1)
    end
  end
end

# Brings the copy up to target_size (at most budget directory requests) and,
# once there, checks it against the anchored root. A mismatch means the
# directory's leaves are not the anchored tree: the copy is discarded and
# rebuilt from the directory's current history.

pub fn monitor_mirror_sync(db :: SqliteConn,
  base :: String,
  target_size :: Int,
  target_root :: Bytes,
  budget :: Int) -> MirrorStep!String do
  let size = monitor_mirror_size(db)?
  if size > target_size do
    Ok(MirrorAhead)
  else if !fetch(db, base, target_size, budget)? do
    Ok(MirrorBehind)
  else if Bytes.secure_equals(frontier_root(frontier_read(db)?)?, target_root) do
    monitor_kv_put(db, "mirror_verified", Int.to_string(target_size))?
    Ok(MirrorVerified)
  else
    reset(db)?
    Ok(MirrorMismatch)
  end
end

fn leaf_at(bytes :: Bytes, offset :: Int) -> Bytes!String do
  case Bytes.slice(bytes, offset * 32, 32) do
    Err(_) -> Err("missing mirror leaf")
    Ok(value)
  end
end

fn reduce(hashes :: List<Bytes>) -> Bytes!String do
  case hashes do
    [single] -> Ok(single)
    _ -> do
      let pairs = List.length(hashes) / 2
      reduce(for index in 0..pairs do
        tlog_node(1, List.get(hashes, 2 * index), List.get(hashes, 2 * index + 1))?
      end)
    end
  end
end

fn width(level :: Int) -> Int do
  if level <= 0 do
    1
  else
    2 * width(level - 1)
  end
end

# The hash of the complete subtree at (level, index): inside one chunk it is
# hashed from the chunk's leaves; above a chunk, from its two halves.

fn node(db :: SqliteConn, size :: Int, level :: Int, index :: Int) -> Bytes!String do
  let count = width(level)
  if level < 0 || index < 0 || (index + 1) * count > size do
    Err("missing mirror node")
  else if count > chunk_leaves() do
    tlog_node(1, node(db, size, level - 1, 2 * index)?, node(db, size, level - 1, 2 * index + 1)?)
  else
    let first = index * count
    let bytes = monitor_chunk_get(db, first / chunk_leaves())?
    let start = first % chunk_leaves()
    reduce(for offset in 0..count do
      leaf_at(bytes, start + offset)?
    end)
  end
end

# A node oracle (Transparency.Tree) over the copy's first size leaves.

pub fn monitor_mirror_oracle(db :: SqliteConn, size :: Int) -> Fun(Int, Int) -> Bytes!String do
  fn level, index -> node(db, size, level, index) end
end

pub fn monitor_mirror_leaf(db :: SqliteConn, index :: Int) -> Bytes!String do
  leaf_at(monitor_chunk_get(db, index / chunk_leaves())?, index % chunk_leaves())
end

fn first_mismatch(mine :: Bytes, theirs :: List<Bytes>, offset :: Int) -> Option<Int> do
  case theirs do
    [] -> None
    leaf :: rest -> case leaf_at(mine, offset) do
      Err(_) -> Some(offset)
      Ok(value) -> if Bytes.secure_equals(value, leaf) do
        first_mismatch(mine, rest, offset + 1)
      else
        Some(offset)
      end
    end
  end
end

# The first index below limit where the directory's current leaves differ
# from the copy. ponytail: a linear scan (limit / 1024 requests); a top-down
# search over subtree hashes would need a directory route for them.

pub fn monitor_mirror_first_difference(db :: SqliteConn,
  base :: String,
  limit :: Int,
  chunk :: Int) -> Option<Int>!String do
  let start = chunk * chunk_leaves()
  if start >= limit do
    Ok(None)
  else
    let count = if limit - start < chunk_leaves() do
      limit - start
    else
      chunk_leaves()
    end
    let theirs = monitor_dir_leaves(base, start, count)?
    if List.length(theirs) < count do
      Err("the directory served fewer leaves than its tree holds")
    else
      case first_mismatch(monitor_chunk_get(db, chunk)?, theirs, 0) do
        Some(offset) -> Ok(Some(start + offset))
        None -> monitor_mirror_first_difference(db, base, limit, chunk + 1)
      end
    end
  end
end
