##! RFC 9162 inclusion paths and consistency proofs (sections 2.1.3 and 2.1.4)
##! over either tree the directory keeps: tree 1 hashes with Morse's domain
##! labels, tree 2 with RFC 6962's 0x00/0x01 prefixes. Proofs are generated
##! from a node oracle, so a caller never loads every leaf.

from Transparency.Merkle import leaf_hash

# Tree sizes stay below 2^62: every size, index and path fits Int.

pub fn tlog_size_limit() -> Int do
  4_611_686_018_427_387_904
end

fn prefix_byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid_transparency_tree")
    Ok(output)
  end
end

fn concat(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("invalid_transparency_tree")
    Ok(value)
  end
end

pub fn tlog_leaf(tree :: Int, data :: Bytes) -> Bytes!String do
  if tree == 1 do
    leaf_hash(data)
  else if tree == 2 do
    Ok(Crypto.sha256(concat(prefix_byte(0)?, data)?))
  else
    Err("invalid_transparency_tree")
  end
end

pub fn tlog_node(tree :: Int, left :: Bytes, right :: Bytes) -> Bytes!String do
  let prefix = if tree == 1 do
    Ok(Bytes.from_utf8("mesh-msg/v1/transparency-node"))
  else if tree == 2 do
    prefix_byte(1)
  else
    Err("invalid_transparency_tree")
  end?
  if Bytes.length(left) != 32 || Bytes.length(right) != 32 do
    Err("invalid_transparency_tree")
  else
    Ok(Crypto.sha256(concat(concat(prefix, left)?, right)?))
  end
end

pub fn tlog_empty_root(tree :: Int) -> Bytes!String do
  if tree == 1 do
    Ok(Crypto.sha256(Bytes.from_utf8("mesh-msg/v1/transparency-empty")))
  else if tree == 2 do
    Ok(Crypto.sha256(Bytes.empty()))
  else
    Err("invalid_transparency_tree")
  end
end

# Largest power of two strictly below count (count >= 2).

fn split(count :: Int, power :: Int) -> Int do
  if power * 2 < count do
    split(count, power * 2)
  else
    power
  end
end

fn power_of_two(count :: Int) -> Bool do
  count == 1 || (count > 1 && split(count, 1) * 2 == count)
end

fn level_of(count :: Int, level :: Int) -> Int do
  if count <= 1 do
    level
  else
    level_of(count / 2, level + 1)
  end
end

fn width_of(level :: Int, width :: Int) -> Int do
  if level <= 0 do
    width
  else
    width_of(level - 1, width * 2)
  end
end

fn node_bytes(value :: Bytes) -> Bytes!String do
  if Bytes.length(value) != 32 do
    Err("invalid_transparency_node")
  else
    Ok(value)
  end
end

# MTH(D[start:start+count]): an aligned complete subtree is one oracle read,
# anything else (the right edge) splits as RFC 6962 does.

pub fn tlog_range_root(tree :: Int,
  oracle :: Fun(Int, Int) -> Bytes!String,
  start :: Int,
  count :: Int) -> Bytes!String do
  if count < 1 || start < 0 do
    Err("invalid_transparency_tree")
  else if power_of_two(count) && start % count == 0 do
    node_bytes(oracle(level_of(count, 0), start / count)?)
  else
    let left = split(count, 1)
    tlog_node(tree,
      tlog_range_root(tree, oracle, start, left)?,
      tlog_range_root(tree, oracle, start + left, count - left)?)
  end
end

pub fn tlog_root(tree :: Int,
  oracle :: Fun(Int, Int) -> Bytes!String,
  size :: Int) -> Bytes!String do
  if size < 0 || size >= tlog_size_limit() do
    Err("invalid_transparency_tree")
  else if size == 0 do
    tlog_empty_root(tree)
  else
    tlog_range_root(tree, oracle, 0, size)
  end
end

fn list_range(tree :: Int, leaves :: List<Bytes>, start :: Int, count :: Int) -> Bytes!String do
  if count == 1 do
    node_bytes(List.get(leaves, start))
  else
    let half = count / 2
    tlog_node(tree,
      list_range(tree, leaves, start, half)?,
      list_range(tree, leaves, start + half, half)?)
  end
end

fn list_node(tree :: Int, leaves :: List<Bytes>, level :: Int, index :: Int) -> Bytes!String do
  let width = width_of(level, 1)
  if level < 0 || level > 61 || index < 0 || width > List.length(leaves) do
    Err("missing_transparency_node")
  else if index >= List.length(leaves) / width do
    Err("missing_transparency_node")
  else
    list_range(tree, leaves, index * width, width)
  end
end

# A node oracle over an in-memory list of leaf hashes (tests and small callers).

pub fn tlog_list_oracle(tree :: Int, leaves :: List<Bytes>) -> Fun(Int, Int) -> Bytes!String do
  fn level, index -> list_node(tree, leaves, level, index) end
end

fn path_from(tree :: Int,
  oracle :: Fun(Int, Int) -> Bytes!String,
  index :: Int,
  start :: Int,
  count :: Int) -> List<Bytes>!String do
  if count <= 1 do
    Ok(List.new())
  else
    let left = split(count, 1)
    if index < start + left do
      Ok(List.append(path_from(tree, oracle, index, start, left)?,
        tlog_range_root(tree, oracle, start + left, count - left)?))
    else
      Ok(List.append(path_from(tree, oracle, index, start + left, count - left)?,
        tlog_range_root(tree, oracle, start, left)?))
    end
  end
end

# PATH(m, D[n]) of RFC 9162 section 2.1.3.1, leaf-side sibling first.

pub fn tlog_inclusion_path(tree :: Int,
  oracle :: Fun(Int, Int) -> Bytes!String,
  index :: Int,
  size :: Int) -> List<Bytes>!String do
  if index < 0 || index >= size || size >= tlog_size_limit() do
    Err("invalid_inclusion_proof")
  else
    path_from(tree, oracle, index, 0, size)
  end
end

fn subproof(tree :: Int,
  oracle :: Fun(Int, Int) -> Bytes!String,
  old_size :: Int,
  start :: Int,
  count :: Int,
  whole :: Bool) -> List<Bytes>!String do
  if old_size == count do
    if whole do
      Ok(List.new())
    else
      Ok([tlog_range_root(tree, oracle, start, count)?])
    end
  else
    let left = split(count, 1)
    if old_size <= left do
      Ok(List.append(subproof(tree, oracle, old_size, start, left, whole)?,
        tlog_range_root(tree, oracle, start + left, count - left)?))
    else
      Ok(List.append(subproof(tree, oracle, old_size - left, start + left, count - left, false)?,
        tlog_range_root(tree, oracle, start, left)?))
    end
  end
end

# PROOF(m, D[n]) of RFC 9162 section 2.1.4.1; empty from size 0 and for m == n.

pub fn tlog_consistency_path(tree :: Int,
  oracle :: Fun(Int, Int) -> Bytes!String,
  old_size :: Int,
  new_size :: Int) -> List<Bytes>!String do
  if old_size < 0 || old_size > new_size || new_size >= tlog_size_limit() do
    Err("invalid_consistency_proof")
  else if old_size == 0 || old_size == new_size do
    Ok(List.new())
  else
    subproof(tree, oracle, old_size, 0, new_size, true)
  end
end

fn hashes_valid(values :: List<Bytes>, limit :: Int) -> Bool do
  List.length(values) <= limit && List.all(values, fn value -> Bytes.length(value) == 32 end)
end

# Right-shift both until the index is odd or zero.

fn shift_to_odd(index :: Int, last :: Int) -> (Int, Int) do
  if index == 0 || index % 2 == 1 do
    (index, last)
  else
    shift_to_odd(index / 2, last / 2)
  end
end

fn shift_past_odd(index :: Int, last :: Int) -> (Int, Int) do
  if index % 2 == 1 do
    shift_past_odd(index / 2, last / 2)
  else
    (index, last)
  end
end

fn inclusion_walk(tree :: Int,
  path :: List<Bytes>,
  position :: Int,
  index :: Int,
  last :: Int,
  hash :: Bytes) -> Bytes!String do
  if position >= List.length(path) do
    if last == 0 do
      Ok(hash)
    else
      Err("invalid_inclusion_proof")
    end
  else if last == 0 do
    Err("invalid_inclusion_proof")
  else
    let sibling = List.get(path, position)
    if index % 2 == 1 || index == last do
      let (next_index, next_last) = shift_to_odd(index, last)
      inclusion_walk(tree,
        path,
        position + 1,
        next_index / 2,
        next_last / 2,
        tlog_node(tree, sibling, hash)?)
    else
      inclusion_walk(tree, path, position + 1, index / 2, last / 2, tlog_node(tree, hash, sibling)?)
    end
  end
end

# RFC 9162 section 2.1.3.2.

pub fn tlog_verify_inclusion(tree :: Int,
  leaf :: Bytes,
  index :: Int,
  size :: Int,
  path :: List<Bytes>,
  root :: Bytes) -> Bool do
  if index < 0
    || index >= size
    || size >= tlog_size_limit()
    || Bytes.length(leaf) != 32
    || Bytes.length(root) != 32
    || !hashes_valid(path, 64) do
    false
  else
    case inclusion_walk(tree, path, 0, index, size - 1, leaf) do
      Err(_) -> false
      Ok(computed) -> Bytes.secure_equals(computed, root)
    end
  end
end

fn consistency_walk(tree :: Int,
  path :: List<Bytes>,
  position :: Int,
  index :: Int,
  last :: Int,
  old_hash :: Bytes,
  new_hash :: Bytes) -> (Bytes, Bytes)!String do
  if position >= List.length(path) do
    if last == 0 do
      Ok((old_hash, new_hash))
    else
      Err("invalid_consistency_proof")
    end
  else if last == 0 do
    Err("invalid_consistency_proof")
  else
    let value = List.get(path, position)
    if index % 2 == 1 || index == last do
      let (next_index, next_last) = shift_to_odd(index, last)
      consistency_walk(tree,
        path,
        position + 1,
        next_index / 2,
        next_last / 2,
        tlog_node(tree, value, old_hash)?,
        tlog_node(tree, value, new_hash)?)
    else
      consistency_walk(tree,
        path,
        position + 1,
        index / 2,
        last / 2,
        old_hash,
        tlog_node(tree, new_hash, value)?)
    end
  end
end

fn verify_nonempty_consistency(tree :: Int,
  old_size :: Int,
  new_size :: Int,
  path :: List<Bytes>,
  old_root :: Bytes,
  new_root :: Bytes) -> Bool do
  let full = if power_of_two(old_size) do
    [old_root] ++ path
  else
    path
  end
  let (index, last) = shift_past_odd(old_size - 1, new_size - 1)
  let first = List.get(full, 0)
  case consistency_walk(tree, full, 1, index, last, first, first) do
    Err(_) -> false
    Ok((old_hash, new_hash)) -> Bytes.secure_equals(old_hash, old_root)
      && Bytes.secure_equals(new_hash, new_root)
  end
end

# RFC 9162 section 2.1.4.2. From size 0 the proof is empty and the old root
# must be the empty root; equal sizes need an empty proof and equal roots.

pub fn tlog_verify_consistency(tree :: Int,
  old_size :: Int,
  new_size :: Int,
  path :: List<Bytes>,
  old_root :: Bytes,
  new_root :: Bytes) -> Bool do
  let empty = case tlog_empty_root(tree) do
    Err(_) -> Bytes.empty()
    Ok(value) -> value
  end
  if old_size < 0
    || old_size > new_size
    || new_size >= tlog_size_limit()
    || Bytes.length(empty) != 32
    || Bytes.length(old_root) != 32
    || Bytes.length(new_root) != 32
    || !hashes_valid(path, 128) do
    false
  else if old_size == 0 do
    List.length(path) == 0
      && Bytes.secure_equals(old_root, empty)
      && (new_size > 0 || Bytes.secure_equals(new_root, empty))
  else if old_size == new_size do
    List.length(path) == 0 && Bytes.secure_equals(old_root, new_root)
  else if List.length(path) == 0 do
    false
  else
    verify_nonempty_consistency(tree, old_size, new_size, path, old_root, new_root)
  end
end
