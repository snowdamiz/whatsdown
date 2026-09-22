pub type GroupTreeError do
  DuplicateMember

  GroupFull

  InvalidIndex

  InvalidMember

  InvalidParent

  MissingMember
end

pub struct GroupMember do
  version :: Int
  account_id :: Bytes
  device_id :: Bytes
  signing_public_key :: SigningPublicKey
  init_public_key :: X25519PublicKey
  leaf_public_key :: X25519PublicKey
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

pub struct TreeKemParentNode do
  node_index :: Int
  public_key :: X25519PublicKey
  unmerged_leaves :: List < Int >
end

pub struct TreeKemResolutionNode do
  node_index :: Int
  public_key :: X25519PublicKey
end

pub struct GroupTree do
  members :: List < IndexedGroupMember >
  parent_nodes :: List < TreeKemParentNode >
  hashes :: List < Bytes >
  count :: Int
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! GroupTreeError do
  case Bytes.concat(left, right) do
    Err(_) -> Err(InvalidMember)
    Ok(value) -> Ok(value)
  end
end

fn write_u16(value :: Int) -> Bytes ! GroupTreeError do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err(InvalidMember)
    Ok(encoded) -> Ok(encoded)
  end
end

fn write_u64(value :: U64) -> Bytes ! GroupTreeError do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err(InvalidMember)
    Ok(encoded) -> Ok(encoded)
  end
end

fn byte(value :: Int) -> Bytes ! GroupTreeError do
  case Bytes.from_list([value]) do
    Err(_) -> Err(InvalidMember)
    Ok(encoded) -> Ok(encoded)
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
  let valid = value.version == 1 && Bytes.length(value.account_id) == 32 && Bytes.length(value.device_id) == 16 && Bytes.length(value.signing_public_key.bytes) == 32 && Bytes.length(value.init_public_key.bytes) == 32 && Bytes.length(value.leaf_public_key.bytes) == 32 && !Bytes.secure_equals(value.init_public_key.bytes,
  value.leaf_public_key.bytes) && Bytes.length(value.mailbox_token) == 32 && Bytes.length(value.transparency_checkpoint_hash) == 32 && value.witness_count >= 0 && value.witness_count <= 255 && valid_extensions(value.extensions,
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
  let output = append(output, value.leaf_public_key.bytes) ?
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

fn parent_node_from(values :: List < TreeKemParentNode >, node_index :: Int, index :: Int) -> Option < TreeKemParentNode > do
  if index >= List.length(values) do
    None
  else
    let value = List.get(values, index)
    if value.node_index == node_index do
      Some(value)
    else
      parent_node_from(values, node_index, index + 1)
    end
  end
end

fn encode_unmerged(values :: List < Int >, index :: Int, output :: Bytes) -> Bytes ! GroupTreeError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_unmerged(values, index + 1, append(output, write_u16(List.get(values, index)) ?) ?)
  end
end

fn parent_state(index :: Int, values :: List < TreeKemParentNode >) -> Bytes ! GroupTreeError do
  case parent_node_from(values, index, 0) do
    None -> Ok(byte(0) ?)
    Some(value) -> do
      let output = append(byte(1) ?, value.public_key.bytes) ?
      encode_unmerged(value.unmerged_leaves,
      0,
      append(output, byte(List.length(value.unmerged_leaves)) ?) ?)
    end
  end
end

fn parent_hash(index :: Int,
left :: Bytes,
right :: Bytes,
parent_nodes :: List < TreeKemParentNode >) -> Bytes ! GroupTreeError do
  let value = append(Bytes.from_utf8("mesh-mls/v1/tree-parent"), write_u16(index) ?) ?
  let value = append(value, parent_state(index, parent_nodes) ?) ?
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
output :: List < Bytes >,
parent_nodes :: List < TreeKemParentNode >) -> List < Bytes > ! GroupTreeError do
  if index >= List.length(children) / 2 do
    Ok(output)
  else
    parent_layer(children,
    first_node,
    index + 1,
    List.append(output,
    parent_hash(first_node + index,
    List.get(children, index * 2),
    List.get(children, index * 2 + 1),
    parent_nodes) ?),
    parent_nodes)
  end
end

fn all_hashes_from_leaves(leaves :: List < Bytes >, parent_nodes :: List < TreeKemParentNode >) -> List < Bytes > ! GroupTreeError do
  let level_one = parent_layer(leaves, 31, 0, List.new(), parent_nodes) ?
  let level_two = parent_layer(level_one, 15, 0, List.new(), parent_nodes) ?
  let level_three = parent_layer(level_two, 7, 0, List.new(), parent_nodes) ?
  let level_four = parent_layer(level_three, 3, 0, List.new(), parent_nodes) ?
  let level_five = parent_layer(level_four, 1, 0, List.new(), parent_nodes) ?
  let root = parent_layer(level_five, 0, 0, List.new(), parent_nodes) ?
  Ok(List.concat(root,
  List.concat(level_five,
  List.concat(level_four,
  List.concat(level_three, List.concat(level_two, List.concat(level_one, leaves)))))))
end

fn all_empty_hashes() -> List < Bytes > ! GroupTreeError do
  let parent_nodes :: List < TreeKemParentNode > = List.new()
  all_hashes_from_leaves(leaf_hashes(0, List.new()) ?, parent_nodes)
end

pub fn empty_tree() -> GroupTree ! GroupTreeError do
  Ok(GroupTree {
    members : List.new(),
    parent_nodes : List.new(),
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

fn path_from(node :: Int, output :: List < Int >) -> List < Int > do
  if node == 0 do
    output
  else
    let parent = (node - 1) / 2
    path_from(parent, List.append(output, parent))
  end
end

pub fn direct_path(leaf_index :: Int) -> List < Int > ! GroupTreeError do
  if leaf_index < 0 || leaf_index >= 64 do
    Err(InvalidIndex)
  else
    Ok(path_from(63 + leaf_index, List.new()))
  end
end

fn sibling(node :: Int) -> Int do
  if node % 2 == 1 do
    node + 1
  else
    node - 1
  end
end

fn copath_from(node :: Int, output :: List < Int >) -> List < Int > do
  if node == 0 do
    output
  else
    copath_from((node - 1) / 2, List.append(output, sibling(node)))
  end
end

pub fn copath(leaf_index :: Int) -> List < Int > ! GroupTreeError do
  if leaf_index < 0 || leaf_index >= 64 do
    Err(InvalidIndex)
  else
    Ok(copath_from(63 + leaf_index, List.new()))
  end
end

pub fn node_contains_leaf(node_index :: Int, leaf_index :: Int) -> Bool do
  if leaf_index < 0 || leaf_index >= 64 do
    false
  else
    node_contains_node(node_index, 63 + leaf_index)
  end
end

fn node_contains_node(node_index :: Int, current :: Int) -> Bool do
  if current == node_index do
    true
  else if current == 0 do
    false
  else
    node_contains_node(node_index, (current - 1) / 2)
  end
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

fn update_hash_path(hashes :: List < Bytes >,
parent_nodes :: List < TreeKemParentNode >,
node :: Int,
hash :: Bytes) -> List < Bytes > ! GroupTreeError do
  let updated = replace_hash(hashes, node, hash)
  if node == 0 do
    Ok(updated)
  else
    let parent = (node - 1) / 2
    let left = parent * 2 + 1
    update_hash_path(updated,
    parent_nodes,
    parent,
    parent_hash(parent, List.get(updated, left), List.get(updated, left + 1), parent_nodes) ?)
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
      Ok(member) -> if Bytes.secure_equals(member.account_id, account_id) && Bytes.secure_equals(member.device_id,
      device_id) do
        index
      else
        find_member_index_from(value, account_id, device_id, index + 1)
      end
      Err(_) -> find_member_index_from(value, account_id, device_id, index + 1)
    end
  end
end

fn first_open(value :: GroupTree, index :: Int) -> Int do
  if index >= 64 do
    -1
  else
    case member_at(value, index) do
      Err(MissingMember) -> index
      Err(_) -> -1
      Ok(_) -> first_open(value, index + 1)
    end
  end
end

fn compare_int(left :: Int, right :: Int) -> Int do
  left - right
end

fn insert_indexed(values :: List < IndexedGroupMember >,
value :: IndexedGroupMember,
index :: Int,
output :: List < IndexedGroupMember >) -> List < IndexedGroupMember > do
  if index >= List.length(values) do
    List.append(output, value)
  else
    let current = List.get(values, index)
    if value.leaf_index < current.leaf_index do
      List.concat(List.append(output, value), List.drop(values, index))
    else
      insert_indexed(values, value, index + 1, List.append(output, current))
    end
  end
end

fn without_parent(values :: List < TreeKemParentNode >,
node_index :: Int,
index :: Int,
output :: List < TreeKemParentNode >) -> List < TreeKemParentNode > do
  if index >= List.length(values) do
    output
  else
    let value = List.get(values, index)
    if value.node_index == node_index do
      without_parent(values, node_index, index + 1, output)
    else
      without_parent(values, node_index, index + 1, List.append(output, value))
    end
  end
end

fn insert_parent(values :: List < TreeKemParentNode >,
value :: TreeKemParentNode,
index :: Int,
output :: List < TreeKemParentNode >) -> List < TreeKemParentNode > do
  if index >= List.length(values) do
    List.append(output, value)
  else
    let current = List.get(values, index)
    if value.node_index < current.node_index do
      List.concat(List.append(output, value), List.drop(values, index))
    else
      insert_parent(values, value, index + 1, List.append(output, current))
    end
  end
end

fn put_parent(values :: List < TreeKemParentNode >, value :: TreeKemParentNode) -> List < TreeKemParentNode > do
  insert_parent(without_parent(values, value.node_index, 0, List.new()), value, 0, List.new())
end

fn mark_unmerged(values :: List < TreeKemParentNode >,
leaf_index :: Int,
index :: Int,
output :: List < TreeKemParentNode >) -> List < TreeKemParentNode > do
  if index >= List.length(values) do
    output
  else
    let value = List.get(values, index)
    let next = if node_contains_leaf(value.node_index, leaf_index) do
      % {value | unmerged_leaves : List.sort(List.append(value.unmerged_leaves, leaf_index),
      compare_int) }
    else
      value
    end
    mark_unmerged(values, leaf_index, index + 1, List.append(output, next))
  end
end

fn blank_parent_path(values :: List < TreeKemParentNode >, path :: List < Int >, index :: Int) -> List < TreeKemParentNode > do
  if index >= List.length(path) do
    values
  else
    blank_parent_path(without_parent(values, List.get(path, index), 0, List.new()), path, index + 1)
  end
end

fn set_member(value :: GroupTree, index :: Int, member :: GroupMember) -> GroupTree ! GroupTreeError do
  if index < 0 || index >= 64 do
    Err(InvalidIndex)
  else
    case member_at(value, index) do
      Ok(_) -> Err(DuplicateMember)
      Err(MissingMember) -> do
        let parent_nodes = mark_unmerged(value.parent_nodes, index, 0, List.new())
        let hashes = update_hash_path(value.hashes,
        parent_nodes,
        63 + index,
        occupied_leaf_hash(index, member) ?) ?
        Ok(GroupTree {
          members : insert_indexed(value.members,
          IndexedGroupMember {
            leaf_index : index,
            member : member
          },
          0,
          List.new()),
          parent_nodes : parent_nodes,
          hashes : hashes,
          count : value.count + 1
        })
      end
      Err(_) -> Err(InvalidIndex)
    end
  end
end

pub fn insert_member(value :: GroupTree, member :: GroupMember) -> Result <(GroupTree, Int), GroupTreeError > do
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

fn validate_unmerged(value :: borrow GroupTree,
node_index :: Int,
values :: List < Int >,
index :: Int,
previous :: Int,
committer_leaf :: Int) -> Result <(), GroupTreeError > do
  if List.length(values) > 64 do
    Err(InvalidParent)
  else if index >= List.length(values) do
    Ok(nil)
  else
    let leaf_index = List.get(values, index)
    if leaf_index == committer_leaf || leaf_index <= previous || leaf_index < 0 || leaf_index >= 64 || !node_contains_leaf(node_index,
    leaf_index) do
      Err(InvalidParent)
    else
      case member_at(value, leaf_index) do
        Err(_) -> Err(InvalidParent)
        Ok(_) -> validate_unmerged(value, node_index, values, index + 1, leaf_index, committer_leaf)
      end
    end
  end
end

fn listed_leaf(values :: List < Int >, wanted :: Int, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else
    List.get(values, index) == wanted || listed_leaf(values, wanted, index + 1)
  end
end

fn has_merged_member(value :: borrow GroupTree,
node_index :: Int,
unmerged :: List < Int >,
index :: Int) -> Bool do
  if index >= List.length(value.members) do
    false
  else
    let leaf_index = List.get(value.members, index).leaf_index
    (node_contains_leaf(node_index, leaf_index) && !listed_leaf(unmerged, leaf_index, 0)) || has_merged_member(value,
    node_index,
    unmerged,
    index + 1)
  end
end

fn validate_parent(value :: borrow GroupTree, parent :: TreeKemParentNode, committer_leaf :: Int) -> Result <(), GroupTreeError > do
  if parent.node_index < 0 || parent.node_index >= 63 || Bytes.length(parent.public_key.bytes) != 32 || !has_merged_member(value,
  parent.node_index,
  parent.unmerged_leaves,
  0) do
    Err(InvalidParent)
  else
    validate_unmerged(value, parent.node_index, parent.unmerged_leaves, 0, -1, committer_leaf)
  end
end

fn replace_update_nodes(value :: borrow GroupTree,
expected :: List < Int >,
nodes :: List < TreeKemParentNode >,
index :: Int,
output :: List < TreeKemParentNode >,
committer_leaf :: Int) -> List < TreeKemParentNode > ! GroupTreeError do
  if index >= List.length(nodes) do
    Ok(output)
  else
    let node = List.get(nodes, index)
    if node.node_index != List.get(expected, index) do
      Err(InvalidParent)
    else
      validate_parent(value, node, committer_leaf) ?
      replace_update_nodes(value,
      expected,
      nodes,
      index + 1,
      put_parent(output, node),
      committer_leaf)
    end
  end
end

pub fn apply_update_path(value :: GroupTree,
committer_leaf :: Int,
nodes :: List < TreeKemParentNode >) -> GroupTree ! GroupTreeError do
  member_at(value, committer_leaf) ?
  let expected = direct_path(committer_leaf) ?
  if List.length(nodes) != List.length(expected) do
    Err(InvalidParent)
  else
    let parent_nodes = replace_update_nodes(value,
    expected,
    nodes,
    0,
    value.parent_nodes,
    committer_leaf) ?
    let leaf_node = 63 + committer_leaf
    let hashes = update_hash_path(value.hashes,
    parent_nodes,
    leaf_node,
    List.get(value.hashes, leaf_node)) ?
    Ok(% {value | parent_nodes : parent_nodes, hashes : hashes })
  end
end

fn unmerged_resolution(value :: borrow GroupTree,
leaves :: List < Int >,
index :: Int,
output :: List < TreeKemResolutionNode >) -> List < TreeKemResolutionNode > ! GroupTreeError do
  if index >= List.length(leaves) do
    Ok(output)
  else
    let leaf_index = List.get(leaves, index)
    let member = member_at(value, leaf_index) ?
    unmerged_resolution(value,
    leaves,
    index + 1,
    List.append(output,
    TreeKemResolutionNode {
      node_index : 63 + leaf_index,
      public_key : member.leaf_public_key
    }))
  end
end

pub fn resolution(value :: borrow GroupTree, node_index :: Int) -> List < TreeKemResolutionNode > ! GroupTreeError do
  if node_index < 0 || node_index >= 127 do
    Err(InvalidIndex)
  else if node_index >= 63 do
    case member_at(value, node_index - 63) do
      Err(MissingMember) -> Ok(List.new())
      Err(error) -> Err(error)
      Ok(member) -> Ok([TreeKemResolutionNode {
        node_index : node_index,
        public_key : member.leaf_public_key
      }])
    end
  else
    case parent_node_from(value.parent_nodes, node_index, 0) do
      Some(parent) -> unmerged_resolution(value,
      parent.unmerged_leaves,
      0,
      [TreeKemResolutionNode {
        node_index : node_index,
        public_key : parent.public_key
      }])
      None -> do
        let left = resolution(value, node_index * 2 + 1) ?
        Ok(List.concat(left, resolution(value, node_index * 2 + 2) ?))
      end
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

fn replace_member(values :: List < IndexedGroupMember >,
leaf_index :: Int,
member :: GroupMember,
index :: Int,
output :: List < IndexedGroupMember >) -> List < IndexedGroupMember > do
  if index >= List.length(values) do
    output
  else
    let value = List.get(values, index)
    let next = if value.leaf_index == leaf_index do
      IndexedGroupMember {
        leaf_index : leaf_index,
        member : member
      }
    else
      value
    end
    replace_member(values, leaf_index, member, index + 1, List.append(output, next))
  end
end

pub fn update_leaf_public_key(value :: GroupTree, leaf_index :: Int, public_key :: X25519PublicKey) -> GroupTree ! GroupTreeError do
  let member = member_at(value, leaf_index) ?
  let updated = % {member | leaf_public_key : public_key }
  validate_member(updated) ?
  let hashes = update_hash_path(value.hashes,
  value.parent_nodes,
  63 + leaf_index,
  occupied_leaf_hash(leaf_index, updated) ?) ?
  Ok(% {value | members : replace_member(value.members, leaf_index, updated, 0, List.new()), hashes : hashes })
end

pub fn remove_member(value :: GroupTree, index :: Int) -> GroupTree ! GroupTreeError do
  if index < 0 || index >= 64 do
    Err(InvalidIndex)
  else
    case member_at(value, index) do
      Err(error) -> Err(error)
      Ok(_) -> do
        let parent_nodes = blank_parent_path(value.parent_nodes, direct_path(index) ?, 0)
        let hashes = update_hash_path(value.hashes,
        parent_nodes,
        63 + index,
        empty_leaf_hash(index) ?) ?
        Ok(GroupTree {
          members : without_member(value.members, index, 0, List.new()),
          parent_nodes : parent_nodes,
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

pub fn public_parent_nodes(value :: GroupTree) -> List < TreeKemParentNode > do
  value.parent_nodes
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

fn validate_public_parents(tree :: borrow GroupTree,
values :: List < TreeKemParentNode >,
index :: Int,
previous :: Int) -> Result <(), GroupTreeError > do
  if List.length(values) > 63 do
    Err(InvalidParent)
  else if index >= List.length(values) do
    Ok(nil)
  else
    let value = List.get(values, index)
    if value.node_index <= previous do
      Err(InvalidParent)
    else
      validate_parent(tree, value, -1) ?
      validate_public_parents(tree, values, index + 1, value.node_index)
    end
  end
end

pub fn tree_from_public(members :: List < IndexedGroupMember >,
parent_nodes :: List < TreeKemParentNode >) -> GroupTree ! GroupTreeError do
  let tree = tree_from_members(members) ?
  validate_public_parents(tree, parent_nodes, 0, -1) ?
  let hashes = all_hashes_from_leaves(List.drop(tree.hashes, 63), parent_nodes) ?
  Ok(% {tree | parent_nodes : parent_nodes, hashes : hashes })
end

# ponytail: immutable list replacement copies at most 127 cached nodes; use a persistent vector if the 64-leaf group cap grows.
