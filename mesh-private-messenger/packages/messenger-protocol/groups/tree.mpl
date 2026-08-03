pub type GroupTreeError do
  DuplicateMember

  GroupFull

  InvalidIndex

  InvalidMember

  MissingMember
end

pub struct GroupMember do
  version :: Int
  account_id :: Bytes
  device_id :: Bytes
  signing_public_key :: SigningPublicKey
  init_public_key :: X25519PublicKey
  mailbox_token :: Bytes
  directory_sequence :: U64
  transparency_checkpoint_hash :: Bytes
  witness_count :: Int
  extensions :: List < Int >
end

pub struct IndexedGroupMember do
  leaf_index :: Int
  member :: GroupMember
end

pub struct GroupTree do
  members :: List < IndexedGroupMember >
  hashes :: List < Bytes >
  count :: Int
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! GroupTreeError do
  case Bytes.concat(left, right) do
    Err( _) -> Err(InvalidMember)
    Ok( value) -> Ok(value)
  end
end

fn write_u16(value :: Int) -> Bytes ! GroupTreeError do
  case Bytes.write_u16_be(value) do
    Err( _) -> Err(InvalidMember)
    Ok( encoded) -> Ok(encoded)
  end
end

fn write_u64(value :: U64) -> Bytes ! GroupTreeError do
  case Bytes.write_u64_be(value) do
    Err( _) -> Err(InvalidMember)
    Ok( encoded) -> Ok(encoded)
  end
end

fn byte(value :: Int) -> Bytes ! GroupTreeError do
  case Bytes.from_list([value]) do
    Err( _) -> Err(InvalidMember)
    Ok( encoded) -> Ok(encoded)
  end
end

fn valid_extensions(values :: List < Int >, index :: Int, previous :: Int) -> Bool do
  if List.length(values) > 16 do
    false
  else if index >= List.length(values) do
    true
  else
    let value = List.get(values, index)
    value > previous && value > 0 && value <= 65535 && valid_extensions(values, index + 1, value)
  end
end

pub fn validate_member(value :: GroupMember) -> Result <(), GroupTreeError > do
  let valid = value.version == 1 && Bytes.length(value.account_id) == 32 && Bytes.length(value.device_id) == 16 && Bytes.length(value.signing_public_key.bytes) == 32 && Bytes.length(value.init_public_key.bytes) == 32 && Bytes.length(value.mailbox_token) == 32 && Bytes.length(value.transparency_checkpoint_hash) == 32 && value.witness_count >= 0 && value.witness_count <= 255 && valid_extensions(value.extensions,
  0,
  0)
  if valid do
    Ok(nil)
  else
    Err(InvalidMember)
  end
end

fn encode_extensions(values :: List < Int >, index :: Int, output :: Bytes) -> Bytes ! GroupTreeError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_extensions(values, index + 1, append(output, write_u16(List.get(values, index)) ?) ?)
  end
end

pub fn encode_member(value :: GroupMember) -> Bytes ! GroupTreeError do
  validate_member(value) ?
  let output = append(byte(value.version) ?, value.account_id) ?
  let output = append(output, value.device_id) ?
  let output = append(output, value.signing_public_key.bytes) ?
  let output = append(output, value.init_public_key.bytes) ?
  let output = append(output, value.mailbox_token) ?
  let output = append(output, write_u64(value.directory_sequence) ?) ?
  let output = append(output, value.transparency_checkpoint_hash) ?
  let output = append(output, byte(value.witness_count) ?) ?
  encode_extensions(value.extensions, 0, append(output, byte(List.length(value.extensions)) ?) ?)
end

fn empty_leaf_hash(index :: Int) -> Bytes ! GroupTreeError do
  let prefix = append(Bytes.from_utf8("mesh-mls/v1/tree-leaf"), write_u16(index) ?) ?
  Ok(Crypto.sha256(append(prefix, byte(0) ?) ?))
end

fn occupied_leaf_hash(index :: Int, member :: GroupMember) -> Bytes ! GroupTreeError do
  let prefix = append(Bytes.from_utf8("mesh-mls/v1/tree-leaf"), write_u16(index) ?) ?
  Ok(Crypto.sha256(append(append(prefix, byte(1) ?) ?, encode_member(member) ?) ?))
end

fn parent_hash(index :: Int, left :: Bytes, right :: Bytes) -> Bytes ! GroupTreeError do
  let value = append(Bytes.from_utf8("mesh-mls/v1/tree-parent"), write_u16(index) ?) ?
  let value = append(value, left) ?
  Ok(Crypto.sha256(append(value, right) ?))
end

fn leaf_hashes(index :: Int, output :: List < Bytes >) -> List < Bytes > ! GroupTreeError do
  if index >= 64 do
    Ok(output)
  else
    leaf_hashes(index + 1, List.append(output, empty_leaf_hash(index) ?))
  end
end

fn parent_layer(children :: List < Bytes >,
first_node :: Int,
index :: Int,
output :: List < Bytes >) -> List < Bytes > ! GroupTreeError do
  if index >= List.length(children) / 2 do
    Ok(output)
  else
    parent_layer(children,
    first_node,
    index + 1,
    List.append(output,
    parent_hash(first_node + index,
    List.get(children, index * 2),
    List.get(children, index * 2 + 1)) ?))
  end
end

fn all_empty_hashes() -> List < Bytes > ! GroupTreeError do
  let leaves = leaf_hashes(0, List.new()) ?
  let level_one = parent_layer(leaves, 31, 0, List.new()) ?
  let level_two = parent_layer(level_one, 15, 0, List.new()) ?
  let level_three = parent_layer(level_two, 7, 0, List.new()) ?
  let level_four = parent_layer(level_three, 3, 0, List.new()) ?
  let level_five = parent_layer(level_four, 1, 0, List.new()) ?
  let root = parent_layer(level_five, 0, 0, List.new()) ?
  Ok(List.concat(root,
  List.concat(level_five,
  List.concat(level_four,
  List.concat(level_three, List.concat(level_two, List.concat(level_one, leaves)))))))
end

pub fn empty_tree() -> GroupTree ! GroupTreeError do
  Ok(GroupTree {
    members : List.new(),
    hashes : all_empty_hashes() ?,
    count : 0
  })
end

pub fn tree_hash(value :: borrow GroupTree) -> Bytes do
  List.get(value.hashes, 0)
end

pub fn member_count(value :: borrow GroupTree) -> Int do
  value.count
end

fn indexed_member_at(values :: List < IndexedGroupMember >, leaf_index :: Int, index :: Int) -> IndexedGroupMember ! GroupTreeError do
  if index >= List.length(values) do
    Err(MissingMember)
  else
    let value = List.get(values, index)
    if value.leaf_index == leaf_index do
      Ok(value)
    else
      indexed_member_at(values, leaf_index, index + 1)
    end
  end
end

pub fn member_at(value :: borrow GroupTree, index :: Int) -> GroupMember ! GroupTreeError do
  if index < 0 || index >= 64 do
    Err(InvalidIndex)
  else
    Ok((indexed_member_at(value.members, index, 0) ?).member)
  end
end

fn replace_hash(values :: List < Bytes >, index :: Int, value :: Bytes) -> List < Bytes > do
  List.concat(List.append(List.take(values, index), value), List.drop(values, index + 1))
end

fn update_hash_path(hashes :: List < Bytes >, node :: Int, hash :: Bytes) -> List < Bytes > ! GroupTreeError do
  let updated = replace_hash(hashes, node, hash)
  if node == 0 do
    Ok(updated)
  else
    let parent = (node - 1) / 2
    let left = parent * 2 + 1
    update_hash_path(updated,
    parent,
    parent_hash(parent, List.get(updated, left), List.get(updated, left + 1)) ?)
  end
end

pub fn find_member_index(value :: GroupTree, account_id :: Bytes, device_id :: Bytes) -> Int do
  find_member_index_from(value, account_id, device_id, 0)
end

fn find_member_index_from(value :: GroupTree, account_id :: Bytes, device_id :: Bytes, index :: Int) -> Int do
  if index >= 64 do
    -1
  else
    case member_at(value, index) do
      Ok( member) -> if Bytes.secure_equals(member.account_id, account_id) && Bytes.secure_equals(member.device_id,
      device_id) do
        index
      else
        find_member_index_from(value, account_id, device_id, index + 1)
      end
      Err( _) -> find_member_index_from(value, account_id, device_id, index + 1)
    end
  end
end

fn first_open(value :: GroupTree, index :: Int) -> Int do
  if index >= 64 do
    -1
  else
    case member_at(value, index) do
      Err( MissingMember) -> index
      Err( _) -> -1
      Ok( _) -> first_open(value, index + 1)
    end
  end
end

fn compare_indexed(left :: IndexedGroupMember, right :: IndexedGroupMember) -> Int do
  left.leaf_index - right.leaf_index
end

fn set_member(value :: GroupTree, index :: Int, member :: GroupMember) -> GroupTree ! GroupTreeError do
  if index < 0 || index >= 64 do
    Err(InvalidIndex)
  else
    case member_at(value, index) do
      Ok( _) -> Err(DuplicateMember)
      Err( MissingMember) -> do
        let hashes = update_hash_path(value.hashes, 63 + index, occupied_leaf_hash(index, member) ?) ?
        Ok(GroupTree {
          members : List.sort(List.append(value.members,
          IndexedGroupMember {
            leaf_index : index,
            member : member
          }),
          compare_indexed),
          hashes : hashes,
          count : value.count + 1
        })
      end
      Err( _) -> Err(InvalidIndex)
    end
  end
end

pub fn insert_member(value :: GroupTree, member :: GroupMember) -> Result <( GroupTree, Int), GroupTreeError > do
  validate_member(member) ?
  if find_member_index(value, member.account_id, member.device_id) >= 0 do
    Err(DuplicateMember)
  else
    let index = first_open(value, 0)
    if index < 0 do
      Err(GroupFull)
    else
      Ok((set_member(value, index, member) ?, index))
    end
  end
end

fn without_member(values :: List < IndexedGroupMember >,
leaf_index :: Int,
index :: Int,
output :: List < IndexedGroupMember >) -> List < IndexedGroupMember > do
  if index >= List.length(values) do
    output
  else
    let value = List.get(values, index)
    if value.leaf_index == leaf_index do
      without_member(values, leaf_index, index + 1, output)
    else
      without_member(values, leaf_index, index + 1, List.append(output, value))
    end
  end
end

pub fn remove_member(value :: GroupTree, index :: Int) -> GroupTree ! GroupTreeError do
  if index < 0 || index >= 64 do
    Err(InvalidIndex)
  else
    case member_at(value, index) do
      Err( error) -> Err(error)
      Ok( _) -> do
        let hashes = update_hash_path(value.hashes, 63 + index, empty_leaf_hash(index) ?) ?
        Ok(GroupTree {
          members : without_member(value.members, index, 0, List.new()),
          hashes : hashes,
          count : value.count - 1
        })
      end
    end
  end
end

pub fn indexed_members(value :: GroupTree) -> List < IndexedGroupMember > do
  value.members
end

fn restore_members(values :: List < IndexedGroupMember >, index :: Int, tree :: GroupTree) -> GroupTree ! GroupTreeError do
  if index >= List.length(values) do
    Ok(tree)
  else
    let value = List.get(values, index)
    validate_member(value.member) ?
    if find_member_index(tree, value.member.account_id, value.member.device_id) >= 0 do
      Err(DuplicateMember)
    else
      restore_members(values, index + 1, set_member(tree, value.leaf_index, value.member) ?)
    end
  end
end

pub fn tree_from_members(values :: List < IndexedGroupMember >) -> GroupTree ! GroupTreeError do
  if List.length(values) == 0 || List.length(values) > 64 do
    Err(InvalidMember)
  else
    restore_members(values, 0, empty_tree() ?)
  end
end

# ponytail: immutable list replacement copies at most 127 cached nodes; use a persistent vector if the 64-leaf group cap grows.
