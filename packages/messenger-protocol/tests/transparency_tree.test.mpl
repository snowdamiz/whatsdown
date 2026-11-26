from Transparency.Merkle import leaf_hash, merkle_root
from Transparency.Tree import (
  tlog_consistency_path,
  tlog_empty_root,
  tlog_inclusion_path,
  tlog_leaf,
  tlog_list_oracle,
  tlog_node,
  tlog_root,
  tlog_verify_consistency,
  tlog_verify_inclusion
)

fn hex(text :: String) -> Bytes!String do
  case Bytes.from_hex(text) do
    Err(_) -> Err("bad hex " <> text)
    Ok(value)
  end
end

fn hexes(values :: List<String>) -> List<Bytes>!String do
  Ok(List.map(values,
    fn text -> case Bytes.from_hex(text) do
      Ok(value) -> value
      Err(_) -> Bytes.empty()
    end end))
end

fn joined(left :: Bytes, right :: Bytes) -> Bytes!String do
  case Bytes.concat(left, right) do
    Err(_) -> Err("concat failed")
    Ok(value)
  end
end

# An independent reference: hashes each node itself instead of using Transparency.Tree.

fn reference_node(tree :: Int, left :: Bytes, right :: Bytes) -> Bytes!String do
  let prefix = if tree == 1 do
    Bytes.from_utf8("mesh-msg/v1/transparency-node")
  else
    hex("01")?
  end
  Ok(Crypto.sha256(joined(joined(prefix, left)?, right)?))
end

fn reference_root(tree :: Int, leaves :: List<Bytes>, start :: Int, count :: Int) -> Bytes!String do
  if count == 0 do
    if tree == 1 do
      Ok(Crypto.sha256(Bytes.from_utf8("mesh-msg/v1/transparency-empty")))
    else
      Ok(Crypto.sha256(Bytes.empty()))
    end
  else if count == 1 do
    Ok(List.get(leaves, start))
  else
    let split = reference_split(count, 1)
    reference_node(tree,
      reference_root(tree, leaves, start, split)?,
      reference_root(tree, leaves, start + split, count - split)?)
  end
end

fn reference_split(count :: Int, power :: Int) -> Int do
  if power * 2 < count do
    reference_split(count, power * 2)
  else
    power
  end
end

fn morse_leaves(count :: Int) -> List<Bytes>!String do
  Ok(for index in 0..count do
    case leaf_hash(Bytes.from_utf8("entry-#{index}")) do
      Ok(value) -> value
      Err(_) -> Bytes.empty()
    end
  end)
end

fn flip(value :: Bytes) -> Bytes!String do
  let first = case Bytes.get(value, 0) do
    Err(_) -> Err("empty")
    Ok(byte)
  end?
  let rest = case Bytes.slice(value, 1, Bytes.length(value) - 1) do
    Err(_) -> Err("slice")
    Ok(bytes)
  end?
  let head = case Bytes.from_list([(first + 1) % 256]) do
    Err(_) -> Err("byte")
    Ok(bytes)
  end?
  joined(head, rest)
end

fn replaced(values :: List<Bytes>, position :: Int, value :: Bytes) -> List<Bytes> do
  for index in 0..List.length(values) do
    if index == position do
      value
    else
      List.get(values, index)
    end
  end
end

fn rfc6962_leaves() -> List<Bytes>!String do
  let inputs = [
    Bytes.empty(),
    hex("00")?,
    hex("10")?,
    hex("2021")?,
    hex("3031")?,
    hex("40414243")?,
    hex("5051525354555657")?,
    hex("606162636465666768696a6b6c6d6e6f")?
  ]
  Ok(List.map(inputs,
    fn input -> case tlog_leaf(2, input) do
      Ok(value) -> value
      Err(_) -> Bytes.empty()
    end end))
end

# RFC 6962 roots for sizes 0..8 of the RFC 9162 / certificate-transparency
# test tree, as published in transparency-dev/merkle testonly/constants.go.

fn rfc6962_roots() -> List<Bytes>!String do
  hexes([
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
  ])
end

fn same_list(left :: List<Bytes>, right :: List<Bytes>) -> Bool do
  List.length(left) == List.length(right)
    && List.all(List.zip(left, right),
      fn pair -> Bytes.secure_equals(Tuple.first(pair), Tuple.second(pair)) end)
end

fn rfc6962_known_answers() -> Bool!String do
  let leaves = rfc6962_leaves()?
  let roots = rfc6962_roots()?
  assert(Bytes.to_hex(List.get(leaves,
    0)) == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d")
  assert(Bytes.to_hex(List.get(leaves,
    7)) == "46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1")
  let oracle = tlog_list_oracle(2, leaves)
  assert(Bytes.secure_equals(tlog_empty_root(2)?, List.get(roots, 0)))
  for size in 0..9 do
    assert(Bytes.secure_equals(tlog_root(2, oracle, size)?, List.get(roots, size)))
  end
  let inclusion_cases = [
    (0,
      8,
      [
        "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"
      ]),
    (5,
      8,
      [
        "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"
      ]),
    (2, 3, ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"]),
    (1,
      5,
      [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"
      ]),
    (0, 1, [])
  ]
  for (index, size, expected) in inclusion_cases do
    let path = tlog_inclusion_path(2, oracle, index, size)?
    assert(same_list(path, hexes(expected)?))
    assert(tlog_verify_inclusion(2,
      List.get(leaves, index),
      index,
      size,
      path,
      List.get(roots, size)))
  end
  let consistency_cases = [
    (1,
      8,
      [
        "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"
      ]),
    (6,
      8,
      [
        "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
        "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"
      ]),
    (2,
      5,
      [
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"
      ]),
    (6,
      7,
      [
        "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
        "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"
      ]),
    (1, 1, [])
  ]
  for (old_size, new_size, expected) in consistency_cases do
    let path = tlog_consistency_path(2, oracle, old_size, new_size)?
    assert(same_list(path, hexes(expected)?))
    assert(tlog_verify_consistency(2,
      old_size,
      new_size,
      path,
      List.get(roots, old_size),
      List.get(roots, new_size)))
  end
  Ok(true)
end

test("the rfc6962 hasher reproduces RFC 6962 known answers for roots, paths and proofs") do
  case rfc6962_known_answers() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn inclusion_properties(tree :: Int, leaves :: List<Bytes>, size :: Int) -> Bool!String do
  let oracle = tlog_list_oracle(tree, leaves)
  let root = reference_root(tree, leaves, 0, size)?
  assert(Bytes.secure_equals(tlog_root(tree, oracle, size)?, root))
  for index in 0..size do
    let leaf = List.get(leaves, index)
    let path = tlog_inclusion_path(tree, oracle, index, size)?
    assert(tlog_verify_inclusion(tree, leaf, index, size, path, root))
    if size < List.length(leaves) do
      let larger_root = reference_root(tree, leaves, 0, size + 1)?
      assert(!tlog_verify_inclusion(tree, leaf, index, size + 1, path, larger_root))
    else
      nil
    end
    if size > 1 do
      assert(!tlog_verify_inclusion(tree, leaf, (index + 1) % size, size, path, root))
      assert(!tlog_verify_inclusion(tree,
        List.get(leaves, (index + 1) % size),
        index,
        size,
        path,
        root))
    else
      nil
    end
  end
  Ok(true)
end

fn consistency_properties(tree :: Int, leaves :: List<Bytes>, new_size :: Int) -> Bool!String do
  let oracle = tlog_list_oracle(tree, leaves)
  let new_root = reference_root(tree, leaves, 0, new_size)?
  for old_size in 0..new_size + 1 do
    let old_root = reference_root(tree, leaves, 0, old_size)?
    let path = tlog_consistency_path(tree, oracle, old_size, new_size)?
    assert(tlog_verify_consistency(tree, old_size, new_size, path, old_root, new_root))
    if old_size > 0 && old_size < new_size do
      assert(!tlog_verify_consistency(tree, old_size, new_size, path, new_root, new_root))
      assert(!tlog_verify_consistency(tree, old_size, new_size, path, old_root, old_root))
      assert(!tlog_verify_consistency(tree, old_size - 1, new_size, path, old_root, new_root))
    else
      nil
    end
  end
  Ok(true)
end

fn every_size_pair() -> Bool!String do
  let leaves = morse_leaves(40)?
  assert(Bytes.secure_equals(tlog_root(1, tlog_list_oracle(1, leaves), 40)?, merkle_root(leaves)?))
  for size in 1..41 do
    inclusion_properties(1, leaves, size)?
    consistency_properties(1, leaves, size)?
  end
  let wrapped = List.map(leaves,
    fn value -> case tlog_leaf(2, value) do
      Ok(hash) -> hash
      Err(_) -> Bytes.empty()
    end end)
  for size in 1..41 do
    inclusion_properties(2, wrapped, size)?
    consistency_properties(2, wrapped, size)?
  end
  Ok(true)
end

test("compact proofs verify for every leaf and every (old, new) size pair up to 40 leaves") do
  case every_size_pair() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn tampered_paths() -> Bool!String do
  let leaves = morse_leaves(23)?
  let oracle = tlog_list_oracle(1, leaves)
  let root = reference_root(1, leaves, 0, 23)?
  let old_root = reference_root(1, leaves, 0, 11)?
  let inclusion = tlog_inclusion_path(1, oracle, 13, 23)?
  let consistency = tlog_consistency_path(1, oracle, 11, 23)?
  for position in 0..List.length(inclusion) do
    let bad = replaced(inclusion, position, flip(List.get(inclusion, position))?)
    assert(!tlog_verify_inclusion(1, List.get(leaves, 13), 13, 23, bad, root))
  end
  for position in 0..List.length(consistency) do
    let bad = replaced(consistency, position, flip(List.get(consistency, position))?)
    assert(!tlog_verify_consistency(1, 11, 23, bad, old_root, root))
  end
  let short_inclusion = List.take(inclusion, List.length(inclusion) - 1)
  assert(!tlog_verify_inclusion(1, List.get(leaves, 13), 13, 23, short_inclusion, root))
  assert(!tlog_verify_inclusion(1, List.get(leaves, 13), 13, 23, inclusion ++ [root], root))
  assert(!tlog_verify_consistency(1,
    11,
    23,
    List.take(consistency, List.length(consistency) - 1),
    old_root,
    root))
  assert(!tlog_verify_consistency(1, 11, 23, consistency ++ [root], old_root, root))
  assert(!tlog_verify_inclusion(1, List.get(leaves, 13), 13, 23, [Bytes.empty()], root))
  let substituted = replaced(leaves, 4, List.get(leaves, 5))
  let substituted_root = reference_root(1, substituted, 0, 23)?
  let forked = tlog_consistency_path(1, tlog_list_oracle(1, substituted), 11, 23)?
  assert(!tlog_verify_consistency(1, 11, 23, forked, old_root, substituted_root))
  assert(!tlog_verify_inclusion(2, List.get(leaves, 13), 13, 23, inclusion, root))
  Ok(true)
end

test("tampered, truncated, extended and cross-tree paths are rejected") do
  case tampered_paths() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn edge_cases() -> Bool!String do
  let leaves = morse_leaves(5)?
  let oracle = tlog_list_oracle(1, leaves)
  let empty = tlog_empty_root(1)?
  let root = reference_root(1, leaves, 0, 5)?
  assert(Bytes.secure_equals(tlog_root(1, oracle, 0)?, empty))
  assert(List.length(tlog_consistency_path(1, oracle, 0, 5)?) == 0)
  assert(tlog_verify_consistency(1, 0, 5, [], empty, root))
  assert(!tlog_verify_consistency(1, 0, 5, [], root, root))
  assert(!tlog_verify_consistency(1, 0, 5, [root], empty, root))
  assert(tlog_verify_consistency(1, 0, 0, [], empty, empty))
  assert(!tlog_verify_consistency(1, 0, 0, [], empty, root))
  assert(List.length(tlog_consistency_path(1, oracle, 5, 5)?) == 0)
  assert(tlog_verify_consistency(1, 5, 5, [], root, root))
  assert(!tlog_verify_consistency(1, 5, 5, [], root, empty))
  assert(!tlog_verify_consistency(1, 5, 5, [root], root, root))
  assert(!tlog_verify_consistency(1, 5, 4, [], root, root))
  case tlog_consistency_path(1, oracle, 5, 4) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  case tlog_inclusion_path(1, oracle, 5, 5) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  case tlog_inclusion_path(1, oracle, 0, 0) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  case tlog_inclusion_path(1, oracle, 0, 6) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  assert(!tlog_verify_inclusion(1, List.get(leaves, 0), 0, 0, [], empty))
  assert(tlog_verify_inclusion(1, List.get(leaves, 0), 0, 1, [], List.get(leaves, 0)))
  let limit = 4_611_686_018_427_387_904
  case tlog_root(1, oracle, limit) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  assert(!tlog_verify_consistency(1, 5, limit, [root], root, root))
  case tlog_node(3, root, root) do
    Ok(_) -> assert(false)
    Err(_) -> nil
  end
  Ok(true)
end

test("empty, equal-size, out-of-range and oversized trees follow the stated rules") do
  case edge_cases() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

# Every leaf of this synthetic tree is the same hash, so a complete subtree at
# level L hashes in L steps: a tree far past the old 4,096 ceiling proves in
# O(log n) oracle reads without materialising a single leaf list.

fn uniform_node(level :: Int, leaf :: Bytes) -> Bytes!String do
  if level == 0 do
    Ok(leaf)
  else
    let child = uniform_node(level - 1, leaf)?
    tlog_node(1, child, child)
  end
end

fn huge_tree() -> Bool!String do
  let leaf = leaf_hash(Bytes.from_utf8("uniform"))?
  let oracle = fn level, index -> uniform_node(level, leaf) end
  let old_size = 1_099_511_627_776 + 4097
  let new_size = 3_298_534_883_328 + 12_345
  let old_root = tlog_root(1, oracle, old_size)?
  let new_root = tlog_root(1, oracle, new_size)?
  let path = tlog_inclusion_path(1, oracle, new_size - 2, new_size)?
  assert(List.length(path) <= 64)
  assert(tlog_verify_inclusion(1, leaf, new_size - 2, new_size, path, new_root))
  let consistency = tlog_consistency_path(1, oracle, old_size, new_size)?
  assert(List.length(consistency) <= 128)
  assert(tlog_verify_consistency(1, old_size, new_size, consistency, old_root, new_root))
  assert(!tlog_verify_consistency(1, old_size + 1, new_size, consistency, old_root, new_root))
  Ok(true)
end

test("proofs over a tree of three trillion leaves stay logarithmic") do
  case huge_tree() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
