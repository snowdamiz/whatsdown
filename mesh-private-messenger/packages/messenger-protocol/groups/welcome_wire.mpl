##! Groups.WelcomeWire for the bounded messenger group protocol.

from Binary.Reader import BinaryReader
from Groups.CommitWire import (
  decode_group_commit,
  group_decode_member_wire,
  encode_group_commit,
  group_extensions_bytes,
  group_parent_bytes,
  group_policy_bytes,
  group_read_extensions,
  group_read_unmerged,
  group_validate_commit_shape
)
from Groups.GroupCodec import (
  group_append,
  group_byte,
  group_join,
  group_tree_error,
  group_tree_member_error,
  group_tree_path_error,
  group_valid_extensions,
  group_validate_members,
  group_validate_policy,
  group_vector,
  group_wire_end,
  group_wire_fixed,
  group_wire_start,
  group_wire_u16,
  group_wire_u64,
  group_wire_u8,
  group_wire_vector,
  group_write_u16
)
from Groups.Mls import (
  GroupCommit,
  GroupError,
  GroupProposal,
  GroupReadBytes,
  GroupReadInt,
  GroupReadInts,
  GroupReadMembers,
  GroupReadParents,
  GroupReadWide,
  GroupTransparencyPolicy,
  GroupWelcome,
  TreeKemUpdateNode
)
from Groups.Tree import (
  GroupMember,
  GroupTree,
  GroupTreeError,
  IndexedGroupMember,
  TreeKemParentNode,
  apply_update_path,
  direct_path,
  encode_member,
  member_at,
  node_contains_leaf,
  tree_from_public,
  tree_hash
)

pub fn group_encode_members(values :: List < IndexedGroupMember >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    let member = case encode_member(value.member) do
      Err(error) -> Err(TreeFailure(error))
      Ok(encoded) -> Ok(encoded)
    end ?
    group_encode_members(values,
    index + 1,
    group_join([output, group_write_u16(value.leaf_index) ?, group_vector(member) ?],
    0,
    Bytes.empty()) ?)
  end
end

pub fn group_read_members(state :: BinaryReader,
count :: Int,
index :: Int,
previous :: Int,
output :: List < IndexedGroupMember >) -> GroupReadMembers ! GroupError do
  if count <= 0 || count > 64 do
    Err(InvalidGroup)
  else if index >= count do
    Ok(GroupReadMembers {
      state : state,
      value : output
    })
  else
    let leaf = group_wire_u16(state) ?
    let member = group_wire_vector(leaf.state, 251) ?
    if leaf.value < 0 || leaf.value >= 64 || leaf.value <= previous do
      Err(InvalidGroup)
    else
      group_read_members(member.state,
      count,
      index + 1,
      leaf.value,
      List.append(output,
      IndexedGroupMember {
        leaf_index : leaf.value,
        member : group_decode_member_wire(member.value) ?
      }))
    end
  end
end

pub fn group_encode_parents(values :: List < TreeKemParentNode >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    group_encode_parents(values,
    index + 1,
    group_append(output, group_parent_bytes(List.get(values, index)) ?) ?)
  end
end

pub fn group_update_parents(values :: List < TreeKemUpdateNode >,
index :: Int,
output :: List < TreeKemParentNode >) -> List < TreeKemParentNode > do
  if index >= List.length(values) do
    output
  else
    group_update_parents(values, index + 1, List.append(output, List.get(values, index).parent))
  end
end

pub fn group_public_update_nodes(values :: List < TreeKemParentNode >,
index :: Int,
output :: List < TreeKemUpdateNode >) -> List < TreeKemUpdateNode > do
  if index >= List.length(values) do
    output
  else
    group_public_update_nodes(values,
    index + 1,
    List.append(output,
    TreeKemUpdateNode {
      parent : List.get(values, index),
      ciphertexts : List.new()
    }))
  end
end

pub fn group_read_parents(state :: BinaryReader,
count :: Int,
index :: Int,
previous :: Int,
output :: List < TreeKemParentNode >) -> GroupReadParents ! GroupError do
  if count < 0 || count > 63 do
    Err(InvalidGroup)
  else if index >= count do
    Ok(GroupReadParents {
      state : state,
      value : output
    })
  else
    let node_index = group_wire_u16(state) ?
    let public_key = group_wire_fixed(node_index.state, 32) ?
    let unmerged_count = group_wire_u8(public_key.state) ?
    let unmerged = group_read_unmerged(unmerged_count.state,
    unmerged_count.value,
    0,
    -1,
    List.new()) ?
    if node_index.value < 0 || node_index.value >= 63 || node_index.value <= previous do
      Err(InvalidGroup)
    else
      group_read_parents(unmerged.state,
      count,
      index + 1,
      node_index.value,
      List.append(output,
      TreeKemParentNode {
        node_index : node_index.value,
        public_key : X25519PublicKey { bytes : public_key.value },
        unmerged_leaves : unmerged.value
      }))
    end
  end
end

pub fn group_joiner_level(committer_leaf :: Int, recipient_leaf :: Int, index :: Int) -> Int ! GroupError do
  let path = group_tree_path_error(direct_path(committer_leaf)) ?
  if index >= List.length(path) do
    Err(InvalidGroup)
  else if node_contains_leaf(List.get(path, index), recipient_leaf) do
    Ok(index)
  else
    group_joiner_level(committer_leaf, recipient_leaf, index + 1)
  end
end

fn same_member(left :: GroupMember, right :: GroupMember) -> Bool ! GroupError do
  Ok(Bytes.secure_equals(case encode_member(left) do
    Err(error) -> Err(TreeFailure(error))
    Ok(value) -> Ok(value)
  end ?,
  case encode_member(right) do
    Err(error) -> Err(TreeFailure(error))
    Ok(value) -> Ok(value)
  end ?))
end

fn welcome_proposal_matches(value :: GroupProposal, tree :: borrow GroupTree, recipient_leaf :: Int) -> Bool ! GroupError do
  case value do
    AddMember(leaf, added) -> if leaf != recipient_leaf do
      Ok(false)
    else
      case member_at(tree, leaf) do
        Err(_) -> Ok(false)
        Ok(member) -> same_member(member, added)
      end
    end
    RemoveMember(_) -> Ok(false)
    UpdateKeys -> Ok(false)
  end
end

pub fn group_validate_welcome_shape(value :: GroupWelcome) -> Result <(), GroupError > do
  group_validate_commit_shape(value.commit) ?
  if !group_valid_extensions(value.extensions, 0, 0) || value.recipient_leaf < 0 || value.recipient_leaf >= 64 do
    Err(InvalidGroup)
  else
    group_validate_policy(value.policy) ?
    group_validate_members(value.members, value.extensions, value.policy, 0) ?
    let group_tree = group_tree_error(tree_from_public(value.members, value.parent_nodes)) ?
    let proposal_matches = welcome_proposal_matches(value.commit.proposal,
    group_tree,
    value.recipient_leaf) ?
    if !proposal_matches || !Bytes.secure_equals(tree_hash(group_tree), value.commit.tree_hash) || value.commit.committer_leaf == value.recipient_leaf || value.joiner_path_level != group_joiner_level(value.commit.committer_leaf,
    value.recipient_leaf,
    0) ? || Bytes.length(value.joiner_path_secret) != 80 || Bytes.length(value.joiner_epoch_secret) != (if value.commit.version == 2 do
      80
    else
      0
    end) do
      Err(InvalidGroup)
    else
      let committer = group_tree_member_error(member_at(group_tree, value.commit.committer_leaf)) ?
      if !Bytes.secure_equals(committer.leaf_public_key.bytes,
      value.commit.update_path.leaf_public_key.bytes) do
        Err(InvalidGroup)
      else
        let checked = group_tree_error(apply_update_path(group_tree,
        value.commit.committer_leaf,
        group_update_parents(value.commit.update_path.nodes, 0, List.new()))) ?
        if Bytes.secure_equals(tree_hash(checked), value.commit.tree_hash) do
          Ok(nil)
        else
          Err(InvalidGroup)
        end
      end
    end
  end
end

pub fn encode_group_welcome(value :: GroupWelcome) -> Bytes ! GroupError do
  group_validate_welcome_shape(value) ?
  let commit = encode_group_commit(value.commit) ?
  let body = group_join([group_vector(commit) ?, group_byte(List.length(value.members)) ?, group_encode_members(value.members,
  0,
  Bytes.empty()) ?, group_extensions_bytes(value.extensions) ?, group_policy_bytes(value.policy) ?, group_write_u16(value.recipient_leaf) ?, group_byte(List.length(value.parent_nodes)) ?, group_encode_parents(value.parent_nodes,
  0,
  Bytes.empty()) ?, group_byte(value.joiner_path_level) ?, value.joiner_path_secret, value.joiner_epoch_secret],
  0,
  Bytes.empty()) ?
  if Bytes.length(body) > 65523 do
    Err(InvalidGroup)
  else
    group_join([group_byte(1) ?, Bytes.from_utf8("GWL"), body], 0, Bytes.empty())
  end
end

pub fn decode_group_welcome(input :: Bytes) -> GroupWelcome ! GroupError do
  let commit = group_wire_vector(group_wire_start(input, 65527, "GWL") ?, 8200) ?
  let member_count = group_wire_u8(commit.state) ?
  let members = group_read_members(member_count.state, member_count.value, 0, -1, List.new()) ?
  let extension_count = group_wire_u8(members.state) ?
  let extensions = group_read_extensions(extension_count.state,
  extension_count.value,
  0,
  0,
  List.new()) ?
  let minimum_sequence = group_wire_u64(extensions.state) ?
  let checkpoint = group_wire_fixed(minimum_sequence.state, 32) ?
  let witness = group_wire_u8(checkpoint.state) ?
  let recipient = group_wire_u16(witness.state) ?
  let parent_count = group_wire_u8(recipient.state) ?
  let parents = group_read_parents(parent_count.state, parent_count.value, 0, -1, List.new()) ?
  let group_joiner_level = group_wire_u8(parents.state) ?
  let joiner_secret = group_wire_fixed(group_joiner_level.state, 80) ?
  let decoded_commit = decode_group_commit(commit.value) ?
  let epoch_secret = group_wire_fixed(joiner_secret.state,
  if decoded_commit.version == 2 do
    80
  else
    0
  end) ?
  group_wire_end(epoch_secret.state) ?
  let value = GroupWelcome {
    commit : decoded_commit,
    members : members.value,
    extensions : extensions.value,
    policy : GroupTransparencyPolicy {
      minimum_directory_sequence : minimum_sequence.value,
      checkpoint_hash : checkpoint.value,
      witness_threshold : witness.value
    },
    recipient_leaf : recipient.value,
    parent_nodes : parents.value,
    joiner_path_level : group_joiner_level.value,
    joiner_path_secret : joiner_secret.value,
    joiner_epoch_secret : epoch_secret.value
  }
  group_validate_welcome_shape(value) ?
  Ok(value)
end
