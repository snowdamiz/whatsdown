from Groups.Tree import GroupMember, GroupTreeError, empty_tree, insert_member, member_at, member_count, remove_member, tree_hash

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err( _) -> Bytes.empty()
    Ok( output) -> output
  end
end

fn wide(value :: Int) -> U64 ! GroupTreeError do
  case U64.parse(Int.to_string(value)) do
    Err( _) -> Err(InvalidMember)
    Ok( output) -> Ok(output)
  end
end

fn member(value :: Int) -> GroupMember ! GroupTreeError do
  Ok(GroupMember {
    version : 1,
    account_id : repeated(value, 32),
    device_id : repeated(value, 16),
    signing_public_key : SigningPublicKey { bytes : repeated(value + 1, 32) },
    init_public_key : X25519PublicKey { bytes : repeated(value + 2, 32) },
    mailbox_token : repeated(value + 3, 32),
    directory_sequence : wide(value) ?,
    transparency_checkpoint_hash : repeated(value + 4, 32),
    witness_count : 2,
    extensions : [1]
  })
end

fn proof() -> Bool ! GroupTreeError do
  let empty = empty_tree() ?
  let empty_hash = tree_hash(empty)
  let ( first_tree, first_index) = insert_member(empty, member(1) ?) ?
  let ( second_tree, second_index) = insert_member(first_tree, member(2) ?) ?
  assert(first_index == 0)
  assert(second_index == 1)
  assert(member_count(second_tree) == 2)
  assert(!Bytes.secure_equals(tree_hash(second_tree), empty_hash))
  let removed = remove_member(second_tree, first_index) ?
  assert(member_count(removed) == 1)
  case member_at(removed, first_index) do
    Err( MissingMember) -> assert(true)
    _ -> assert(false)
  end
  case member_at(removed, second_index) do
    Ok( found) -> assert(Bytes.secure_equals(found.device_id, (member(2) ?).device_id))
    Err( _) -> assert(false)
  end
  Ok(true)
end

test("group tree path-copies bounded leaves") do
  case proof() do
    Err( _) -> assert(false)
    Ok( value) -> assert(value)
  end
end
