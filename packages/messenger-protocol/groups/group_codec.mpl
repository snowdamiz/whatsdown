from Groups.Mls import invalid_group_member_error

##! Groups.GroupCodec for the bounded messenger group protocol.

from Binary.Reader import (
  BinaryReader,
  finish,
  read_fixed,
  read_u16_be,
  read_u8,
  read_vector,
  reader
)
from Groups.Mls import (
  GroupDeliveryTarget,
  GroupError,
  GroupReadBytes,
  GroupReadInt,
  GroupReadPolicy,
  GroupReadWide,
  GroupTransparencyPolicy
)
from Groups.Tree import (
  GroupMember,
  GroupTree,
  GroupTreeError,
  IndexedGroupMember,
  TreeKemResolutionNode,
  indexed_members,
  validate_member
)

pub fn group_append(left :: Bytes, right :: Bytes) -> Bytes!GroupError do
  case Bytes.concat(left, right) do
    Err(_) -> Err(InvalidGroup)
    Ok(value)
  end
end

pub fn group_join(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!GroupError do
  if index >= List.length(parts) do
    Ok(output)
  else
    group_join(parts, index + 1, group_append(output, List.get(parts, index))?)
  end
end

pub fn group_byte(value :: Int) -> Bytes!GroupError do
  case Bytes.from_list([value]) do
    Err(_) -> Err(InvalidGroup)
    Ok(encoded)
  end
end

pub fn group_write_u16(value :: Int) -> Bytes!GroupError do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err(InvalidGroup)
    Ok(encoded)
  end
end

pub fn group_write_u32(value :: Int) -> Bytes!GroupError do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err(InvalidGroup)
    Ok(wide) -> case Bytes.write_u32_be(wide) do
      Err(_) -> Err(InvalidGroup)
      Ok(encoded)
    end
  end
end

pub fn group_write_u64(value :: U64) -> Bytes!GroupError do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err(InvalidGroup)
    Ok(encoded)
  end
end

pub fn group_vector(value :: Bytes) -> Bytes!GroupError do
  group_append(group_write_u32(Bytes.length(value))?, value)
end

pub fn group_zero() -> U64!GroupError do
  case U64.parse("0") do
    Err(_) -> Err(InvalidGroup)
    Ok(value)
  end
end

fn one() -> U64!GroupError do
  case U64.parse("1") do
    Err(_) -> Err(InvalidGroup)
    Ok(value)
  end
end

pub fn group_next_epoch(value :: U64) -> U64!GroupError do
  case U64.add(value, one()?) do
    Err(_) -> Err(InvalidGroup)
    Ok(next)
  end
end

pub fn group_tree_error(value :: Result<GroupTree, GroupTreeError>) -> GroupTree!GroupError do
  case value do
    Err(error) -> Err(TreeFailure(error))
    Ok(output)
  end
end

pub fn group_tree_path_error(value :: Result<List<Int>, GroupTreeError>) -> List<Int>!GroupError do
  case value do
    Err(error) -> Err(TreeFailure(error))
    Ok(output)
  end
end

pub fn group_tree_resolution_error(value :: Result<List<TreeKemResolutionNode>, GroupTreeError>) -> List<TreeKemResolutionNode>!GroupError do
  case value do
    Err(error) -> Err(TreeFailure(error))
    Ok(output)
  end
end

pub fn group_tree_member_error(value :: Result<GroupMember, GroupTreeError>) -> GroupMember!GroupError do
  case value do
    Err(error) -> Err(TreeFailure(error))
    Ok(output)
  end
end

pub fn group_member_error(value :: Result<(), GroupTreeError>) -> Result<(), GroupError> do
  case value do
    Err(error) -> Err(TreeFailure(error))
    Ok(_) -> Ok(nil)
  end
end

pub fn group_valid_extensions(values :: List<Int>, index :: Int, previous :: Int) -> Bool do
  if List.length(values) > 16 do
    false
  else if index >= List.length(values) do
    true
  else
    let value = List.get(values, index)
    value > previous
      && value > 0
      && value <= 65535
      && group_valid_extensions(values, index + 1, value)
  end
end

fn has_extension(values :: List<Int>, wanted :: Int, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if List.get(values, index) == wanted do
    true
  else
    has_extension(values, wanted, index + 1)
  end
end

fn supports_extensions(member :: GroupMember, extensions :: List<Int>, index :: Int) -> Bool do
  if index >= List.length(extensions) do
    true
  else
    has_extension(member.extensions, List.get(extensions, index), 0)
      && supports_extensions(member, extensions, index + 1)
  end
end

fn all_members_support(values :: List<IndexedGroupMember>,
  extension :: Int,
  index :: Int) -> Bool do
  if index >= List.length(values) do
    true
  else
    has_extension(List.get(values, index).member.extensions, extension, 0)
      && all_members_support(values, extension, index + 1)
  end
end

fn negotiated_extensions(values :: List<IndexedGroupMember>,
  preferred :: List<Int>,
  index :: Int,
  output :: List<Int>) -> List<Int> do
  if index >= List.length(preferred) do
    output
  else
    let extension = List.get(preferred, index)
    let next = if all_members_support(values, extension, 0) do
      List.append(output, extension)
    else
      output
    end
    negotiated_extensions(values, preferred, index + 1, next)
  end
end

pub fn negotiate_group_extensions(tree :: borrow GroupTree,
  preferred :: List<Int>) -> List<Int>!GroupError do
  let members = indexed_members(tree)
  if List.length(members) == 0 || !group_valid_extensions(preferred, 0, 0) do
    Err(InvalidGroup)
  else
    Ok(negotiated_extensions(members, preferred, 0, List.new()))
  end
end

fn collect_delivery_targets(values :: List<IndexedGroupMember>,
  excluded_leaf :: Int,
  index :: Int,
  output :: List<GroupDeliveryTarget>) -> List<GroupDeliveryTarget> do
  if index >= List.length(values) do
    output
  else
    let value = List.get(values, index)
    let next = if value.leaf_index == excluded_leaf do
      output
    else
      List.append(output,
        GroupDeliveryTarget {
          leaf_index: value.leaf_index,
          account_id: value.member.account_id,
          device_id: value.member.device_id,
          mailbox_token: value.member.mailbox_token
        })
    end
    collect_delivery_targets(values, excluded_leaf, index + 1, next)
  end
end

pub fn delivery_targets(tree :: borrow GroupTree,
  excluded_leaf :: Int) -> List<GroupDeliveryTarget>!GroupError do
  if excluded_leaf < -1 || excluded_leaf >= 64 do
    Err(InvalidGroup)
  else
    Ok(collect_delivery_targets(indexed_members(tree), excluded_leaf, 0, List.new()))
  end
end

# A version 1 policy (no set_id) keeps its old bounds; a policy under a pinned
# witness set carries that set's strict majority, 1 to 16.

pub fn group_validate_policy(value :: GroupTransparencyPolicy) -> Result<(), GroupError> do
  let legacy = Bytes.length(value.set_id) == 0
    && value.witness_threshold >= 0
    && value.witness_threshold <= 255
  let pinned = Bytes.length(value.set_id) == 32
    && value.witness_threshold >= 1
    && value.witness_threshold <= 16
  if Bytes.length(value.checkpoint_hash) != 32 || (!legacy && !pinned) do
    Err(InvalidPolicy)
  else
    Ok(nil)
  end
end

# The policy a commit leaves: unchanged, or moved to the committer's set.

pub fn group_policy_after(policy :: GroupTransparencyPolicy,
  witness_set :: Bytes) -> GroupTransparencyPolicy!GroupError do
  if Bytes.length(witness_set) == 0 do
    Ok(policy)
  else if Bytes.length(witness_set) != 33 do
    Err(InvalidPolicy)
  else
    let set_id = case Bytes.slice(witness_set, 0, 32) do
      Err(_) -> Err(InvalidPolicy)
      Ok(value)
    end?
    let threshold = case Bytes.get(witness_set, 32) do
      Err(_) -> Err(InvalidPolicy)
      Ok(value)
    end?
    let moved = %{policy | set_id: set_id, witness_threshold: threshold}
    group_validate_policy(moved)?
    Ok(moved)
  end
end

pub fn group_validate_member_policy(member :: GroupMember,
  extensions :: List<Int>,
  policy :: GroupTransparencyPolicy) -> Result<(), GroupError> do
  group_member_error(validate_member(member))?
  group_validate_policy(policy)?
  let current = U64.compare(member.directory_sequence, policy.minimum_directory_sequence) >= 0
  let checkpoint = Bytes.secure_equals(member.transparency_checkpoint_hash, policy.checkpoint_hash)
  # A member's witness count is the k its build pinned when it joined; a set
  # change moves the policy, not the members already in the group.
  let witnessed = if Bytes.length(policy.set_id) == 0 do
    member.witness_count >= policy.witness_threshold
  else
    member.witness_count >= 1
  end
  if current && checkpoint && witnessed && supports_extensions(member, extensions, 0) do
    Ok(nil)
  else
    Err(invalid_group_member_error())
  end
end

pub fn group_wire_reader(input :: Bytes, maximum :: Int) -> BinaryReader!GroupError do
  if Bytes.length(input) > maximum do
    Err(InvalidGroup)
  else
    case reader(input, maximum) do
      Err(_) -> Err(InvalidGroup)
      Ok(state)
    end
  end
end

pub fn group_wire_u8(state :: BinaryReader) -> GroupReadInt!GroupError do
  case read_u8(state) do
    Err(_) -> Err(InvalidGroup)
    Ok((next, value)) -> Ok(GroupReadInt { state: next, value: value })
  end
end

pub fn group_wire_u16(state :: BinaryReader) -> GroupReadInt!GroupError do
  case read_u16_be(state) do
    Err(_) -> Err(InvalidGroup)
    Ok((next, value)) -> Ok(GroupReadInt { state: next, value: value })
  end
end

pub fn group_wire_fixed(state :: BinaryReader, length :: Int) -> GroupReadBytes!GroupError do
  case read_fixed(state, length) do
    Err(_) -> Err(InvalidGroup)
    Ok((next, value)) -> Ok(GroupReadBytes { state: next, value: value })
  end
end

pub fn group_wire_vector(state :: BinaryReader, maximum :: Int) -> GroupReadBytes!GroupError do
  case read_vector(state, maximum) do
    Err(_) -> Err(InvalidGroup)
    Ok((next, value)) -> Ok(GroupReadBytes { state: next, value: value })
  end
end

pub fn group_wire_u32(state :: BinaryReader) -> GroupReadInt!GroupError do
  let encoded = group_wire_fixed(state, 4)?
  case Bytes.read_u32_be(encoded.value, 0) do
    Err(_) -> Err(InvalidGroup)
    Ok(wide) -> case U64.to_int(wide) do
      Err(_) -> Err(InvalidGroup)
      Ok(value) -> Ok(GroupReadInt { state: encoded.state, value: value })
    end
  end
end

pub fn group_wire_u64(state :: BinaryReader) -> GroupReadWide!GroupError do
  let encoded = group_wire_fixed(state, 8)?
  case Bytes.read_u64_be(encoded.value, 0) do
    Err(_) -> Err(InvalidGroup)
    Ok(value) -> Ok(GroupReadWide { state: encoded.state, value: value })
  end
end

pub fn group_wire_end(state :: BinaryReader) -> Result<(), GroupError> do
  case finish(state) do
    Err(_) -> Err(InvalidGroup)
    Ok(_) -> Ok(nil)
  end
end

pub fn group_wire_magic(state :: BinaryReader, expected :: String) -> BinaryReader!GroupError do
  let encoded = Bytes.from_utf8(expected)
  let value = group_wire_fixed(state, Bytes.length(encoded))?
  if Bytes.secure_equals(value.value, encoded) do
    Ok(value.state)
  else
    Err(InvalidGroup)
  end
end

pub fn group_wire_start(input :: Bytes,
  maximum :: Int,
  magic :: String) -> BinaryReader!GroupError do
  let version = group_wire_u8(group_wire_reader(input, maximum)?)?
  if version.value == 1 do
    group_wire_magic(version.state, magic)
  else
    Err(InvalidGroup)
  end
end

# Frames that gained a version 2 (a policy under a pinned witness set): the
# reader after the magic, and which version it was.

pub fn group_wire_start_versioned(input :: Bytes,
  maximum :: Int,
  magic :: String) -> GroupReadInt!GroupError do
  let version = group_wire_u8(group_wire_reader(input, maximum)?)?
  if version.value == 1 || version.value == 2 do
    Ok(GroupReadInt { state: group_wire_magic(version.state, magic)?, value: version.value })
  else
    Err(InvalidGroup)
  end
end

# Version 1 frames carry a version 1 policy; version 2 frames a pinned set.

pub fn group_policy_version(policy :: GroupTransparencyPolicy) -> Int do
  if Bytes.length(policy.set_id) == 0 do
    1
  else
    2
  end
end

pub fn group_read_policy(state :: BinaryReader, version :: Int) -> GroupReadPolicy!GroupError do
  let minimum_sequence = group_wire_u64(state)?
  let checkpoint = group_wire_fixed(minimum_sequence.state, 32)?
  let witness = group_wire_u8(checkpoint.state)?
  let set_id = group_wire_fixed(witness.state,
    if version == 2 do
      32
    else
      0
    end)?
  let value = GroupTransparencyPolicy {
    minimum_directory_sequence: minimum_sequence.value,
    checkpoint_hash: checkpoint.value,
    witness_threshold: witness.value,
    set_id: set_id.value
  }
  group_validate_policy(value)?
  if group_policy_version(value) != version do
    Err(InvalidPolicy)
  else
    Ok(GroupReadPolicy { state: set_id.state, value: value })
  end
end

pub fn group_validate_members(values :: List<IndexedGroupMember>,
  extensions :: List<Int>,
  policy :: GroupTransparencyPolicy,
  index :: Int) -> Result<(), GroupError> do
  if index >= List.length(values) do
    Ok(nil)
  else
    group_validate_member_policy(List.get(values, index).member, extensions, policy)?
    group_validate_members(values, extensions, policy, index + 1)
  end
end
