from Groups.Tree import GroupMember, GroupTreeError, TreeKemParentNode, apply_update_path, copath, direct_path, empty_tree, insert_member, member_at, member_count, remove_member, resolution, tree_hash, validate_member

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn wide(value :: Int) -> U64 ! GroupTreeError do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err(InvalidMember)
    Ok(output) -> Ok(output)
  end
end

fn member(value :: Int) -> GroupMember ! GroupTreeError do
  Ok(GroupMember {
    version : 1,
    account_id : repeated(value, 32),
    device_id : repeated(value, 16),
    signing_public_key : SigningPublicKey { bytes : repeated(value + 1, 32) },
    init_public_key : X25519PublicKey { bytes : repeated(value + 2, 32) },
    leaf_public_key : X25519PublicKey { bytes : repeated(value + 5, 32) },
    mailbox_token : repeated(value + 3, 32),
    directory_sequence : wide(value) ?,
    transparency_checkpoint_hash : repeated(value + 4, 32),
    witness_count : 2,
    extensions : [1]
  })
end

fn path_node(index :: Int, value :: Int, unmerged :: List < Int >) -> TreeKemParentNode do
  TreeKemParentNode {
    node_index : index,
    public_key : X25519PublicKey { bytes : repeated(value, 32) },
    unmerged_leaves : unmerged
  }
end

fn proof() -> Bool ! GroupTreeError do
  let empty = empty_tree() ?
  let empty_hash = tree_hash(empty)
  let first_member = member(1) ?
  case validate_member(% {first_member | leaf_public_key : first_member.init_public_key }) do
    Err(InvalidMember) -> assert(true)
    _ -> assert(false)
  end
  let (first_tree, first_index) = insert_member(empty, first_member) ?
  let (second_tree, second_index) = insert_member(first_tree, member(2) ?) ?
  assert(first_index == 0)
  assert(second_index == 1)
  assert(member_count(second_tree) == 2)
  assert(!Bytes.secure_equals(tree_hash(second_tree), empty_hash))
  let path = direct_path(first_index) ?
  let siblings = copath(first_index) ?
  assert(List.length(path) == 6)
  assert(List.get(path, 0) == 31)
  assert(List.get(path, 5) == 0)
  assert(List.get(siblings, 0) == 64)
  assert(List.get(siblings, 5) == 2)
  let blank_parent_resolution = resolution(second_tree, 31) ?
  assert(List.length(blank_parent_resolution) == 2)
  assert(List.get(blank_parent_resolution, 0).node_index == 63)
  assert(Bytes.secure_equals(List.get(blank_parent_resolution, 0).public_key.bytes,
  (member(1) ?).leaf_public_key.bytes))
  let updated = apply_update_path(second_tree,
  first_index,
  [path_node(31, 101, [second_index]), path_node(15, 102, [second_index]), path_node(7,
  103,
  [second_index]), path_node(3, 104, [second_index]), path_node(1, 105, [second_index]), path_node(0,
  106,
  [second_index])]) ?
  let parent_resolution = resolution(updated, 31) ?
  assert(List.length(parent_resolution) == 2)
  assert(List.get(parent_resolution, 0).node_index == 31)
  assert(List.get(parent_resolution, 1).node_index == 64)
  assert(!Bytes.secure_equals(tree_hash(updated), tree_hash(second_tree)))
  case apply_update_path(updated, first_index, [path_node(31, 110, [first_index])]) do
    Err(InvalidParent) -> assert(true)
    _ -> assert(false)
  end
  let removed = remove_member(updated, first_index) ?
  assert(member_count(removed) == 1)
  let removed_resolution = resolution(removed, 31) ?
  assert(List.length(removed_resolution) == 1)
  assert(List.get(removed_resolution, 0).node_index == 64)
  case member_at(removed, first_index) do
    Err(MissingMember) -> assert(true)
    _ -> assert(false)
  end
  case member_at(removed, second_index) do
    Ok(found) -> assert(Bytes.secure_equals(found.device_id, (member(2) ?).device_id))
    Err(_) -> assert(false)
  end
  Ok(true)
end

test("group tree path-copies bounded leaves") do
  case proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
