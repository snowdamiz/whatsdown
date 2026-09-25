##! Groups.GroupSnapshot for the bounded messenger group protocol.

from Groups.KeySchedule import group_empty_keys
from Binary.Reader import BinaryReader
from Groups.CommitWire import group_extensions_bytes, group_policy_bytes, group_read_extensions, group_read_levels
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
  group_wire_u32,
  group_wire_u64,
  group_wire_u8,
  group_wire_vector,
  group_write_u16,
  group_write_u32,
  group_write_u64,
  group_zero
)
from Groups.Mls import (
  GroupError,
  GroupReadBytes,
  GroupReadGenerations,
  GroupReadInt,
  GroupReadInts,
  GroupReadMembers,
  GroupReadParents,
  GroupReadWide,
  GroupSnapshotOutcome,
  GroupState,
  GroupTransparencyPolicy,
  ParsedGroupSnapshot,
  SenderGeneration,
  TreeKemKeyMaterial
)
from Groups.Tree import (
  GroupMember,
  GroupTree,
  GroupTreeError,
  IndexedGroupMember,
  TreeKemParentNode,
  direct_path,
  indexed_members,
  member_at,
  public_parent_nodes,
  tree_from_public,
  tree_hash
)
from Groups.WelcomeWire import group_encode_members, group_encode_parents, group_read_members, group_read_parents

fn generation_seen(values :: List<SenderGeneration>, leaf_index :: Int, limit :: Int, index :: Int) -> Bool do
  if index >= limit do
    false
  else if List.get(values, index).leaf_index == leaf_index do
    true
  else
    generation_seen(values, leaf_index, limit, index + 1)
  end
end

fn validate_generations(values :: List<SenderGeneration>, tree :: borrow GroupTree, index :: Int) -> Result<(), GroupError> do
  if List.length(values) > 64 do
    Err(InvalidGroup)
  else if index >= List.length(values) do
    Ok(nil)
  else
    let value = List.get(values, index)
    if value.leaf_index < 0 || value.leaf_index >= 64 || value.generation < 0 || generation_seen(values,
      value.leaf_index,
      index,
      0) do
      Err(InvalidGroup)
    else
      case member_at(tree, value.leaf_index) do
        Err(_) -> Err(InvalidGroup)
        Ok(_) -> validate_generations(values, tree, index + 1)
      end
    end
  end
end

fn encode_generations(values :: List<SenderGeneration>, index :: Int, output :: Bytes) -> Bytes!GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    encode_generations(values,
      index + 1,
      group_join([output, group_write_u16(value.leaf_index)?, group_write_u32(value.generation)?],
        0,
        Bytes.empty())?)
  end
end

fn read_generations(state :: BinaryReader,
  count :: Int,
  index :: Int,
  output :: List<SenderGeneration>) -> GroupReadGenerations!GroupError do
  if count < 0 || count > 64 do
    Err(InvalidGroup)
  else if index >= count do
    Ok(GroupReadGenerations {
      state: state,
      value: output
    })
  else
    let leaf = group_wire_u16(state)?
    let generation = group_wire_u32(leaf.state)?
    if leaf.value < 0 || leaf.value >= 64 || generation_seen(output,
      leaf.value,
      List.length(output),
      0) do
      Err(InvalidGroup)
    else
      read_generations(generation.state,
        count,
        index + 1,
        List.append(output,
          SenderGeneration {
            leaf_index: leaf.value,
            generation: generation.value
          }))
    end
  end
end

fn local_identity_matches(tree :: borrow GroupTree,
  local_leaf :: Int,
  account_id :: Bytes,
  device_id :: Bytes) -> Bool do
  case member_at(tree, local_leaf) do
    Err(_) -> false
    Ok(member) -> Bytes.secure_equals(member.account_id, account_id) && Bytes.secure_equals(member.device_id,
      device_id)
  end
end

fn valid_levels(values :: List<Int>, index :: Int, previous :: Int) -> Bool do
  if List.length(values) > 6 do
    false
  else if index >= List.length(values) do
    true
  else
    let value = List.get(values, index)
    value >= 0 && value < 6 && value > previous && valid_levels(values, index + 1, value)
  end
end

fn encode_levels(values :: List<Int>, index :: Int, output :: Bytes) -> Bytes!GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_levels(values, index + 1, group_append(output, group_byte(List.get(values, index))?)?)
  end
end

fn validate_snapshot_state(state :: borrow GroupState,
  account_id :: Bytes,
  device_id :: Bytes,
  snapshot_version :: U64) -> Result<(), GroupError> do
  let valid = (state.version == 1 || state.version == 2) && state.suite == 3 && Bytes.length(state.group_id) == 32 && Bytes.length(state.tree_hash_cache) == 32 && Bytes.length(state.transcript_hash) == 32 && state.local_leaf >= 0 && state.local_leaf < 64 && state.next_generation >= 0 && Bytes.length(account_id) == 32 && Bytes.length(device_id) == 16 && U64.compare(snapshot_version,
    group_zero()?) > 0 && Bytes.secure_equals(state.tree_hash_cache, tree_hash(state.tree))
  if !valid || !group_valid_extensions(state.extensions, 0, 0) || !valid_levels(state.key_material.available_levels,
    0,
    -1) || !local_identity_matches(state.tree, state.local_leaf, account_id, device_id) do
    Err(InvalidGroup)
  else
    group_validate_policy(state.policy)?
    group_validate_members(indexed_members(state.tree), state.extensions, state.policy, 0)?
    validate_generations(state.received_generations, state.tree, 0)
  end
end

fn group_snapshot_header(state :: borrow GroupState,
  account_id :: Bytes,
  device_id :: Bytes,
  snapshot_version :: U64) -> Bytes!GroupError do
  validate_snapshot_state(state, account_id, device_id, snapshot_version)?
  let members = indexed_members(state.tree)
  let parents = public_parent_nodes(state.tree)
  group_join([
      group_byte(1)?,
      Bytes.from_utf8("GST"),
      group_byte(state.version)?,
      group_write_u16(state.suite)?,
      state.group_id,
      group_write_u64(state.epoch)?,
      group_write_u64(snapshot_version)?,
      state.tree_hash_cache,
      state.transcript_hash,
      group_write_u16(state.local_leaf)?,
      group_write_u32(state.next_generation)?,
      group_byte(List.length(members))?,
      group_encode_members(members, 0, Bytes.empty())?,
      group_byte(List.length(parents))?,
      group_encode_parents(parents, 0, Bytes.empty())?,
      group_byte(List.length(state.received_generations))?,
      encode_generations(state.received_generations, 0, Bytes.empty())?,
      group_extensions_bytes(state.extensions)?,
      group_byte(List.length(state.key_material.available_levels))?,
      encode_levels(state.key_material.available_levels, 0, Bytes.empty())?,
      group_policy_bytes(state.policy)?
    ],
    0,
    Bytes.empty())
end

fn group_storage_context(account_id :: Bytes,
  device_id :: Bytes,
  group_id :: Bytes,
  header :: Bytes,
  purpose :: Int,
  key_slot :: Int,
  snapshot_version :: U64) -> Bytes!GroupError do
  if Bytes.length(account_id) != 32 || Bytes.length(device_id) != 16 || Bytes.length(group_id) != 32 || (purpose != 12 && purpose != 16 && purpose != 17) || (purpose == 12 && key_slot != 8 && key_slot != 9) || (purpose == 16 && key_slot != 0) || (purpose == 17 && (key_slot < 1 || key_slot > 7)) do
    Err(InvalidGroup)
  else
    let object = Crypto.sha256(group_join([
        Bytes.from_utf8("mesh-msg/v1/group-snapshot-object"),
        header,
        group_write_u16(purpose)?,
        group_byte(key_slot)?
      ],
      0,
      Bytes.empty())?)
    group_join([
        group_byte(1)?,
        account_id,
        device_id,
        group_id,
        object,
        group_write_u16(purpose)?,
        group_write_u64(snapshot_version)?
      ],
      0,
      Bytes.empty())
  end
end

fn seal_group_private(value :: borrow X25519PrivateKey,
  wrapping_key :: borrow StorageKey,
  context :: Bytes) -> Bytes!GroupError do
  case X25519PrivateKey.seal_for_storage(value, wrapping_key, context) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(sealed)
  end
end

fn seal_group_snapshot(state :: borrow GroupState,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes,
  snapshot_version :: U64) -> Bytes!GroupError do
  let header = group_snapshot_header(state, account_id, device_id, snapshot_version)?
  let context = group_storage_context(account_id,
    device_id,
    state.group_id,
    header,
    16,
    0,
    snapshot_version)?
  let sealed = case Secret.seal_for_storage(state.key_material.epoch_secret, wrapping_key, context) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end?
  let leaf_private = seal_group_private(state.key_material.leaf_private_key,
    wrapping_key,
    group_storage_context(account_id, device_id, state.group_id, header, 17, 1, snapshot_version)?)?
  let level0 = seal_group_private(state.key_material.level0_private_key,
    wrapping_key,
    group_storage_context(account_id, device_id, state.group_id, header, 17, 2, snapshot_version)?)?
  let level1 = seal_group_private(state.key_material.level1_private_key,
    wrapping_key,
    group_storage_context(account_id, device_id, state.group_id, header, 17, 3, snapshot_version)?)?
  let level2 = seal_group_private(state.key_material.level2_private_key,
    wrapping_key,
    group_storage_context(account_id, device_id, state.group_id, header, 17, 4, snapshot_version)?)?
  let level3 = seal_group_private(state.key_material.level3_private_key,
    wrapping_key,
    group_storage_context(account_id, device_id, state.group_id, header, 17, 5, snapshot_version)?)?
  let level4 = seal_group_private(state.key_material.level4_private_key,
    wrapping_key,
    group_storage_context(account_id, device_id, state.group_id, header, 17, 6, snapshot_version)?)?
  let level5 = seal_group_private(state.key_material.level5_private_key,
    wrapping_key,
    group_storage_context(account_id, device_id, state.group_id, header, 17, 7, snapshot_version)?)?
  let chains = if state.version == 2 do
    seal_group_map(state.key_material.sender_chains,
      wrapping_key,
      group_storage_context(account_id, device_id, state.group_id, header, 12, 8, snapshot_version)?)?
  else
    Bytes.empty()
  end
  let skipped = if state.version == 2 do
    seal_group_map(state.key_material.skipped_keys,
      wrapping_key,
      group_storage_context(account_id, device_id, state.group_id, header, 12, 9, snapshot_version)?)?
  else
    Bytes.empty()
  end
  let maps = if state.version == 2 do
    group_join([group_vector(chains)?, group_vector(skipped)?], 0, Bytes.empty())?
  else
    Bytes.empty()
  end
  if Bytes.length(header) + Bytes.length(maps) > 64711 || Bytes.length(sealed) != 99 || Bytes.length(leaf_private) != 99 || Bytes.length(level0) != 99 || Bytes.length(level1) != 99 || Bytes.length(level2) != 99 || Bytes.length(level3) != 99 || Bytes.length(level4) != 99 || Bytes.length(level5) != 99 do
    Err(InvalidGroup)
  else
    group_join([
        header,
        group_vector(sealed)?,
        group_vector(leaf_private)?,
        group_vector(level0)?,
        group_vector(level1)?,
        group_vector(level2)?,
        group_vector(level3)?,
        group_vector(level4)?,
        group_vector(level5)?,
        maps
      ],
      0,
      Bytes.empty())
  end
end

pub fn group_snapshot(state :: consume GroupState,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes,
  snapshot_version :: U64) -> GroupSnapshotOutcome do
  if U64.compare(snapshot_version, state.snapshot_version) <= 0 do
    GroupSnapshotRejected(state, RollbackRejected)
  else
    case seal_group_snapshot(state, wrapping_key, account_id, device_id, snapshot_version) do
      Err(error) -> GroupSnapshotRejected(state, error)
      Ok(blob) -> GroupSnapshotSealed(%{state | snapshot_version: snapshot_version}, blob)
    end
  end
end

fn parse_group_snapshot(input :: Bytes) -> ParsedGroupSnapshot!GroupError do
  let state_version = group_wire_u8(group_wire_start(input, 65535, "GST")?)?
  let suite = group_wire_u16(state_version.state)?
  let group_id = group_wire_fixed(suite.state, 32)?
  let epoch = group_wire_u64(group_id.state)?
  let snapshot_version = group_wire_u64(epoch.state)?
  let snapshot_tree_hash = group_wire_fixed(snapshot_version.state, 32)?
  let transcript_hash = group_wire_fixed(snapshot_tree_hash.state, 32)?
  let local_leaf = group_wire_u16(transcript_hash.state)?
  let next_generation = group_wire_u32(local_leaf.state)?
  let member_count = group_wire_u8(next_generation.state)?
  let members = group_read_members(member_count.state, member_count.value, 0, -1, List.new())?
  let parent_count = group_wire_u8(members.state)?
  let parents = group_read_parents(parent_count.state, parent_count.value, 0, -1, List.new())?
  let generation_count = group_wire_u8(parents.state)?
  let generations = read_generations(generation_count.state, generation_count.value, 0, List.new())?
  let extension_count = group_wire_u8(generations.state)?
  let extensions = group_read_extensions(extension_count.state,
    extension_count.value,
    0,
    0,
    List.new())?
  let level_count = group_wire_u8(extensions.state)?
  let levels = group_read_levels(level_count.state, level_count.value, 0, -1, List.new())?
  let minimum_sequence = group_wire_u64(levels.state)?
  let checkpoint = group_wire_fixed(minimum_sequence.state, 32)?
  let witness = group_wire_u8(checkpoint.state)?
  let sealed = group_wire_vector(witness.state, 99)?
  let leaf_private = group_wire_vector(sealed.state, 99)?
  let level0 = group_wire_vector(leaf_private.state, 99)?
  let level1 = group_wire_vector(level0.state, 99)?
  let level2 = group_wire_vector(level1.state, 99)?
  let level3 = group_wire_vector(level2.state, 99)?
  let level4 = group_wire_vector(level3.state, 99)?
  let level5 = group_wire_vector(level4.state, 99)?
  let chains = group_wire_vector_if(level5.state, state_version.value)?
  let skipped = group_wire_vector_if(chains.state, state_version.value)?
  group_wire_end(skipped.state)?
  if Bytes.length(sealed.value) != 99 || Bytes.length(leaf_private.value) != 99 || Bytes.length(level0.value) != 99 || Bytes.length(level1.value) != 99 || Bytes.length(level2.value) != 99 || Bytes.length(level3.value) != 99 || Bytes.length(level4.value) != 99 || Bytes.length(level5.value) != 99 do
    Err(InvalidGroup)
  else
    Ok(ParsedGroupSnapshot {
      version: state_version.value,
      suite: suite.value,
      group_id: group_id.value,
      epoch: epoch.value,
      snapshot_version: snapshot_version.value,
      tree_hash: snapshot_tree_hash.value,
      transcript_hash: transcript_hash.value,
      local_leaf: local_leaf.value,
      next_generation: next_generation.value,
      members: members.value,
      parent_nodes: parents.value,
      received_generations: generations.value,
      extensions: extensions.value,
      available_levels: levels.value,
      policy: GroupTransparencyPolicy {
        minimum_directory_sequence: minimum_sequence.value,
        checkpoint_hash: checkpoint.value,
        witness_threshold: witness.value
      },
      sealed_sender_chains: chains.value,
      sealed_skipped_keys: skipped.value,
      sealed_epoch_secret: sealed.value,
      sealed_leaf_private: leaf_private.value,
      sealed_level0_private: level0.value,
      sealed_level1_private: level1.value,
      sealed_level2_private: level2.value,
      sealed_level3_private: level3.value,
      sealed_level4_private: level4.value,
      sealed_level5_private: level5.value
    })
  end
end

fn parsed_group_header(value :: ParsedGroupSnapshot) -> Bytes!GroupError do
  group_join([
      group_byte(1)?,
      Bytes.from_utf8("GST"),
      group_byte(value.version)?,
      group_write_u16(value.suite)?,
      value.group_id,
      group_write_u64(value.epoch)?,
      group_write_u64(value.snapshot_version)?,
      value.tree_hash,
      value.transcript_hash,
      group_write_u16(value.local_leaf)?,
      group_write_u32(value.next_generation)?,
      group_byte(List.length(value.members))?,
      group_encode_members(value.members, 0, Bytes.empty())?,
      group_byte(List.length(value.parent_nodes))?,
      group_encode_parents(value.parent_nodes, 0, Bytes.empty())?,
      group_byte(List.length(value.received_generations))?,
      encode_generations(value.received_generations, 0, Bytes.empty())?,
      group_extensions_bytes(value.extensions)?,
      group_byte(List.length(value.available_levels))?,
      encode_levels(value.available_levels, 0, Bytes.empty())?,
      group_policy_bytes(value.policy)?
    ],
    0,
    Bytes.empty())
end

fn validate_parsed_snapshot(value :: ParsedGroupSnapshot, account_id :: Bytes, device_id :: Bytes) -> GroupTree!GroupError do
  let valid = (value.version == 1 || value.version == 2) && value.suite == 3 && Bytes.length(value.group_id) == 32 && Bytes.length(value.tree_hash) == 32 && Bytes.length(value.transcript_hash) == 32 && value.local_leaf >= 0 && value.local_leaf < 64 && value.next_generation >= 0 && Bytes.length(account_id) == 32 && Bytes.length(device_id) == 16 && U64.compare(value.snapshot_version,
    group_zero()?) > 0 && group_valid_extensions(value.extensions, 0, 0) && valid_levels(value.available_levels,
    0,
    -1)
  if !valid do
    Err(InvalidGroup)
  else
    group_validate_policy(value.policy)?
    group_validate_members(value.members, value.extensions, value.policy, 0)?
    let group_tree = group_tree_error(tree_from_public(value.members, value.parent_nodes))?
    if !Bytes.secure_equals(tree_hash(group_tree), value.tree_hash) || !local_identity_matches(group_tree,
      value.local_leaf,
      account_id,
      device_id) do
      Err(InvalidGroup)
    else
      validate_generations(value.received_generations, group_tree, 0)?
      Ok(group_tree)
    end
  end
end

fn unseal_group_private(blob :: Bytes, wrapping_key :: borrow StorageKey, context :: Bytes) -> X25519PrivateKey!GroupError do
  case X25519PrivateKey.unseal_from_storage(blob, wrapping_key, context) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn parent_public_key(values :: List<TreeKemParentNode>, node_index :: Int, index :: Int) -> X25519PublicKey!GroupError do
  if index >= List.length(values) do
    Err(InvalidGroup)
  else
    let value = List.get(values, index)
    if value.node_index == node_index do
      Ok(value.public_key)
    else
      parent_public_key(values, node_index, index + 1)
    end
  end
end

fn level_is_available(values :: List<Int>, level :: Int, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else
    List.get(values, index) == level || level_is_available(values, level, index + 1)
  end
end

fn validate_private_key(value :: borrow X25519PrivateKey, expected :: X25519PublicKey) -> Result<(), GroupError> do
  case Crypto.x25519_public(value) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(actual) -> if Bytes.secure_equals(actual.bytes, expected.bytes) do
      Ok(nil)
    else
      Err(AuthenticationRejected)
    end
  end
end

fn validate_parent_private(value :: borrow X25519PrivateKey,
  parents :: List<TreeKemParentNode>,
  path :: List<Int>,
  available :: List<Int>,
  level :: Int) -> Result<(), GroupError> do
  if level_is_available(available, level, 0) do
    validate_private_key(value, parent_public_key(parents, List.get(path, level), 0)?)
  else
    Ok(nil)
  end
end

pub fn restore_group(blob :: Bytes,
  wrapping_key :: borrow StorageKey,
  account_id :: Bytes,
  device_id :: Bytes,
  minimum_version :: U64) -> GroupState!GroupError do
  let value = parse_group_snapshot(blob)?
  if U64.compare(value.snapshot_version, minimum_version) < 0 do
    Err(RollbackRejected)
  else
    let group_tree = validate_parsed_snapshot(value, account_id, device_id)?
    let header = parsed_group_header(value)?
    let context = group_storage_context(account_id,
      device_id,
      value.group_id,
      header,
      16,
      0,
      value.snapshot_version)?
    let secret = case Secret.unseal_from_storage(value.sealed_epoch_secret, wrapping_key, context) do
      Err(error) -> Err(CryptoFailure(error))
      Ok(output)
    end?
    let leaf_private = unseal_group_private(value.sealed_leaf_private,
      wrapping_key,
      group_storage_context(account_id,
        device_id,
        value.group_id,
        header,
        17,
        1,
        value.snapshot_version)?)?
    let level0 = unseal_group_private(value.sealed_level0_private,
      wrapping_key,
      group_storage_context(account_id,
        device_id,
        value.group_id,
        header,
        17,
        2,
        value.snapshot_version)?)?
    let level1 = unseal_group_private(value.sealed_level1_private,
      wrapping_key,
      group_storage_context(account_id,
        device_id,
        value.group_id,
        header,
        17,
        3,
        value.snapshot_version)?)?
    let level2 = unseal_group_private(value.sealed_level2_private,
      wrapping_key,
      group_storage_context(account_id,
        device_id,
        value.group_id,
        header,
        17,
        4,
        value.snapshot_version)?)?
    let level3 = unseal_group_private(value.sealed_level3_private,
      wrapping_key,
      group_storage_context(account_id,
        device_id,
        value.group_id,
        header,
        17,
        5,
        value.snapshot_version)?)?
    let level4 = unseal_group_private(value.sealed_level4_private,
      wrapping_key,
      group_storage_context(account_id,
        device_id,
        value.group_id,
        header,
        17,
        6,
        value.snapshot_version)?)?
    let level5 = unseal_group_private(value.sealed_level5_private,
      wrapping_key,
      group_storage_context(account_id,
        device_id,
        value.group_id,
        header,
        17,
        7,
        value.snapshot_version)?)?
    let local_member = group_tree_member_error(member_at(group_tree, value.local_leaf))?
    validate_private_key(leaf_private, local_member.leaf_public_key)?
    let path = group_tree_path_error(direct_path(value.local_leaf))?
    validate_parent_private(level0, value.parent_nodes, path, value.available_levels, 0)?
    validate_parent_private(level1, value.parent_nodes, path, value.available_levels, 1)?
    validate_parent_private(level2, value.parent_nodes, path, value.available_levels, 2)?
    validate_parent_private(level3, value.parent_nodes, path, value.available_levels, 3)?
    validate_parent_private(level4, value.parent_nodes, path, value.available_levels, 4)?
    validate_parent_private(level5, value.parent_nodes, path, value.available_levels, 5)?
    Ok(GroupState {
      version: value.version,
      suite: value.suite,
      group_id: value.group_id,
      epoch: value.epoch,
      tree: group_tree,
      tree_hash_cache: value.tree_hash,
      transcript_hash: value.transcript_hash,
      key_material: TreeKemKeyMaterial {
        sender_chains: if value.version == 2 do
          unseal_group_map(value.sealed_sender_chains,
            wrapping_key,
            group_storage_context(account_id,
              device_id,
              value.group_id,
              header,
              12,
              8,
              value.snapshot_version)?)?
        else
          group_empty_keys()?
        end,
        skipped_keys: if value.version == 2 do
          unseal_group_map(value.sealed_skipped_keys,
            wrapping_key,
            group_storage_context(account_id,
              device_id,
              value.group_id,
              header,
              12,
              9,
              value.snapshot_version)?)?
        else
          group_empty_keys()?
        end,
        epoch_secret: secret,
        leaf_private_key: leaf_private,
        level0_private_key: level0,
        level1_private_key: level1,
        level2_private_key: level2,
        level3_private_key: level3,
        level4_private_key: level4,
        level5_private_key: level5,
        available_levels: value.available_levels
      },
      local_leaf: value.local_leaf,
      next_generation: value.next_generation,
      received_generations: value.received_generations,
      extensions: value.extensions,
      policy: value.policy,
      snapshot_version: value.snapshot_version
    })
  end
end

fn group_wire_vector_if(reader :: BinaryReader, version :: Int) -> GroupReadBytes!GroupError do
  if version == 2 do
    group_wire_vector(reader, 16384)
  else
    Ok(GroupReadBytes {
      state: reader,
      value: Bytes.empty()
    })
  end
end

fn seal_group_map(map :: borrow SecretMap, key :: borrow StorageKey, context :: Bytes) -> Bytes!GroupError do
  case SecretMap.seal_for_storage(map, key, context) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end

fn unseal_group_map(blob :: Bytes, key :: borrow StorageKey, context :: Bytes) -> SecretMap!GroupError do
  case SecretMap.unseal_from_storage(blob, key, context) do
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end
end
