from Binary.Reader import BinaryReader, finish, read_fixed, read_u16_be, read_u8, read_vector, reader
from Groups.Tree import GroupMember, GroupTree, GroupTreeError, IndexedGroupMember, TreeKemParentNode, TreeKemResolutionNode, apply_update_path, copath, direct_path, empty_tree, encode_member, indexed_members, insert_member, member_at, node_contains_leaf, public_parent_nodes, remove_member, resolution, tree_from_members, tree_from_public, tree_hash, update_leaf_public_key, validate_member

pub type GroupError do
  AuthenticationRejected

  CryptoFailure( error :: CryptoError)

  FutureEpoch

  InvalidGroup

  InvalidMember

  InvalidPolicy

  Replay

  RemovedMember

  RollbackRejected

  StaleEpoch

  TreeFailure( error :: GroupTreeError)
end

pub struct GroupTransparencyPolicy do
  minimum_directory_sequence :: U64
  checkpoint_hash :: Bytes
  witness_threshold :: Int
end

pub type GroupProposal do
  AddMember( leaf_index :: Int, member :: GroupMember)

  RemoveMember( leaf_index :: Int)
end

pub struct TreeKemCiphertext do
  recipient_node :: Int
  sealed :: Bytes
end

pub struct TreeKemUpdateNode do
  parent :: TreeKemParentNode
  ciphertexts :: List < TreeKemCiphertext >
end

pub struct TreeKemUpdatePath do
  leaf_public_key :: X25519PublicKey
  nodes :: List < TreeKemUpdateNode >
end

pub struct GroupCommit do
  version :: Int
  suite :: Int
  group_id :: Bytes
  prior_epoch :: U64
  epoch :: U64
  committer_leaf :: Int
  prior_transcript_hash :: Bytes
  tree_hash :: Bytes
  proposal :: GroupProposal
  update_path :: TreeKemUpdatePath
  signature :: Signature
end

pub struct GroupWelcome do
  commit :: GroupCommit
  members :: List < IndexedGroupMember >
  extensions :: List < Int >
  policy :: GroupTransparencyPolicy
  recipient_leaf :: Int
  parent_nodes :: List < TreeKemParentNode >
  joiner_path_level :: Int
  joiner_path_secret :: Bytes
end

pub struct SenderGeneration do
  leaf_index :: Int
  generation :: Int
end

pub struct GroupDeliveryTarget do
  leaf_index :: Int
  mailbox_token :: Bytes
end

struct TreeMessageContext do
  hash :: Bytes
  sender :: GroupMember
end

struct OpenMessageContext do
  suite :: Int
  group_id :: Bytes
  epoch :: U64
  last_generation :: Int
  tree :: TreeMessageContext
end

struct EncryptMessageContext do
  suite :: Int
  group_id :: Bytes
  epoch :: U64
  tree_hash :: Bytes
  sender_leaf :: Int
  generation :: Int
end

pub resource struct TreeKemKeyMaterial do
  epoch_secret :: SecretBytes
  leaf_private_key :: X25519PrivateKey
  level0_private_key :: X25519PrivateKey
  level1_private_key :: X25519PrivateKey
  level2_private_key :: X25519PrivateKey
  level3_private_key :: X25519PrivateKey
  level4_private_key :: X25519PrivateKey
  level5_private_key :: X25519PrivateKey
  available_levels :: List < Int >
end

pub resource struct GroupState do
  version :: Int
  suite :: Int
  group_id :: Bytes
  epoch :: U64
  tree :: GroupTree
  tree_hash_cache :: Bytes
  transcript_hash :: Bytes
  key_material :: TreeKemKeyMaterial
  local_leaf :: Int
  next_generation :: Int
  received_generations :: List < SenderGeneration >
  extensions :: List < Int >
  policy :: GroupTransparencyPolicy
  snapshot_version :: U64
end

pub struct GroupMessage do
  version :: Int
  suite :: Int
  group_id :: Bytes
  epoch :: U64
  tree_hash :: Bytes
  sender_leaf :: Int
  generation :: Int
  nonce :: Bytes
  ciphertext :: Bytes
  signature :: Signature
end

struct GroupReadInt do
  state :: BinaryReader
  value :: Int
end

struct GroupReadWide do
  state :: BinaryReader
  value :: U64
end

struct GroupReadBytes do
  state :: BinaryReader
  value :: Bytes
end

struct GroupReadInts do
  state :: BinaryReader
  value :: List < Int >
end

struct GroupReadProposal do
  state :: BinaryReader
  value :: GroupProposal
end

struct GroupReadCiphertexts do
  state :: BinaryReader
  value :: List < TreeKemCiphertext >
end

struct GroupReadUpdateNodes do
  state :: BinaryReader
  value :: List < TreeKemUpdateNode >
end

struct GroupReadParents do
  state :: BinaryReader
  value :: List < TreeKemParentNode >
end

struct GroupReadMembers do
  state :: BinaryReader
  value :: List < IndexedGroupMember >
end

struct GroupReadGenerations do
  state :: BinaryReader
  value :: List < SenderGeneration >
end

struct ParsedGroupSnapshot do
  version :: Int
  suite :: Int
  group_id :: Bytes
  epoch :: U64
  snapshot_version :: U64
  tree_hash :: Bytes
  transcript_hash :: Bytes
  local_leaf :: Int
  next_generation :: Int
  members :: List < IndexedGroupMember >
  parent_nodes :: List < TreeKemParentNode >
  received_generations :: List < SenderGeneration >
  extensions :: List < Int >
  available_levels :: List < Int >
  policy :: GroupTransparencyPolicy
  sealed_epoch_secret :: Bytes
  sealed_leaf_private :: Bytes
  sealed_level0_private :: Bytes
  sealed_level1_private :: Bytes
  sealed_level2_private :: Bytes
  sealed_level3_private :: Bytes
  sealed_level4_private :: Bytes
  sealed_level5_private :: Bytes
end

pub type CommitApplyOutcome do
  CommitApplied( state :: GroupState)

  CommitRejected( state :: GroupState, error :: GroupError)
end

pub type GroupAddOutcome do
  GroupMemberAdded( state :: GroupState, commit :: GroupCommit, welcome :: GroupWelcome)

  GroupAddRejected( state :: GroupState, error :: GroupError)
end

pub type GroupRemoveOutcome do
  GroupMemberRemoved( state :: GroupState, commit :: GroupCommit)

  GroupRemoveRejected( state :: GroupState, error :: GroupError)
end

pub type GroupEncryptOutcome do
  GroupMessageEncrypted( state :: GroupState, message :: GroupMessage)

  GroupEncryptRejected( state :: GroupState, error :: GroupError)
end

pub type GroupDecryptOutcome do
  MessageOpened( state :: GroupState, plaintext :: Bytes)

  MessageRejected( state :: GroupState, error :: GroupError)
end

pub type GroupSnapshotOutcome do
  GroupSnapshotSealed( state :: GroupState, blob :: Bytes)

  GroupSnapshotRejected( state :: GroupState, error :: GroupError)
end

resource struct PreparedGroupAdd do
  tree :: GroupTree
  key_material :: TreeKemKeyMaterial
  commit :: GroupCommit
  welcome :: GroupWelcome
  transcript_hash :: Bytes
end

resource struct PreparedGroupRemove do
  tree :: GroupTree
  key_material :: TreeKemKeyMaterial
  commit :: GroupCommit
  transcript_hash :: Bytes
end

resource struct GeneratedTreeKemPath do
  key_material :: TreeKemKeyMaterial
  secret0 :: SecretBytes
  secret1 :: SecretBytes
  secret2 :: SecretBytes
  secret3 :: SecretBytes
  secret4 :: SecretBytes
  secret5 :: SecretBytes
  leaf_public_key :: X25519PublicKey
  parents :: List < TreeKemParentNode >
end

resource struct OpenedPathSecret do
  secret :: SecretBytes
  level :: Int
end

type TreeKemPathPatch do
  TreeKemPatch0( epoch_secret :: SecretBytes, level0 :: X25519PrivateKey, level1 :: X25519PrivateKey, level2 :: X25519PrivateKey, level3 :: X25519PrivateKey, level4 :: X25519PrivateKey, level5 :: X25519PrivateKey)

  TreeKemPatch1( epoch_secret :: SecretBytes, level1 :: X25519PrivateKey, level2 :: X25519PrivateKey, level3 :: X25519PrivateKey, level4 :: X25519PrivateKey, level5 :: X25519PrivateKey)

  TreeKemPatch2( epoch_secret :: SecretBytes, level2 :: X25519PrivateKey, level3 :: X25519PrivateKey, level4 :: X25519PrivateKey, level5 :: X25519PrivateKey)

  TreeKemPatch3( epoch_secret :: SecretBytes, level3 :: X25519PrivateKey, level4 :: X25519PrivateKey, level5 :: X25519PrivateKey)

  TreeKemPatch4( epoch_secret :: SecretBytes, level4 :: X25519PrivateKey, level5 :: X25519PrivateKey)

  TreeKemPatch5( epoch_secret :: SecretBytes, level5 :: X25519PrivateKey)
end

struct PreparedAppliedCommit do
  tree :: GroupTree
  context :: Bytes
end

resource struct PreparedJoin do
  tree :: GroupTree
  path_secret :: SecretBytes
  path_level :: Int
  context :: Bytes
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! GroupError do
  case Bytes.concat(left, right) do
    Err( _) -> Err(InvalidGroup)
    Ok( value) -> Ok(value)
  end
end

fn join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(parts) do
    Ok(output)
  else
    join(parts, index + 1, append(output, List.get(parts, index)) ?)
  end
end

fn byte(value :: Int) -> Bytes ! GroupError do
  case Bytes.from_list([value]) do
    Err( _) -> Err(InvalidGroup)
    Ok( encoded) -> Ok(encoded)
  end
end

fn write_u16(value :: Int) -> Bytes ! GroupError do
  case Bytes.write_u16_be(value) do
    Err( _) -> Err(InvalidGroup)
    Ok( encoded) -> Ok(encoded)
  end
end

fn write_u32(value :: Int) -> Bytes ! GroupError do
  case U64.parse(Int.to_string(value)) do
    Err( _) -> Err(InvalidGroup)
    Ok( wide) -> case Bytes.write_u32_be(wide) do
      Err( _) -> Err(InvalidGroup)
      Ok( encoded) -> Ok(encoded)
    end
  end
end

fn write_u64(value :: U64) -> Bytes ! GroupError do
  case Bytes.write_u64_be(value) do
    Err( _) -> Err(InvalidGroup)
    Ok( encoded) -> Ok(encoded)
  end
end

fn vector(value :: Bytes) -> Bytes ! GroupError do
  append(write_u32(Bytes.length(value)) ?, value)
end

fn zero() -> U64 ! GroupError do
  case U64.parse("0") do
    Err( _) -> Err(InvalidGroup)
    Ok( value) -> Ok(value)
  end
end

fn one() -> U64 ! GroupError do
  case U64.parse("1") do
    Err( _) -> Err(InvalidGroup)
    Ok( value) -> Ok(value)
  end
end

fn next_epoch(value :: U64) -> U64 ! GroupError do
  case U64.add(value, one() ?) do
    Err( _) -> Err(InvalidGroup)
    Ok( next) -> Ok(next)
  end
end

fn tree_error(value :: Result < GroupTree, GroupTreeError >) -> GroupTree ! GroupError do
  case value do
    Err( error) -> Err(TreeFailure(error))
    Ok( output) -> Ok(output)
  end
end

fn tree_path_error(value :: Result < List < Int >, GroupTreeError >) -> List < Int > ! GroupError do
  case value do
    Err( error) -> Err(TreeFailure(error))
    Ok( output) -> Ok(output)
  end
end

fn tree_resolution_error(value :: Result < List < TreeKemResolutionNode >, GroupTreeError >) -> List < TreeKemResolutionNode > ! GroupError do
  case value do
    Err( error) -> Err(TreeFailure(error))
    Ok( output) -> Ok(output)
  end
end

fn tree_member_error(value :: Result < GroupMember, GroupTreeError >) -> GroupMember ! GroupError do
  case value do
    Err( error) -> Err(TreeFailure(error))
    Ok( output) -> Ok(output)
  end
end

fn member_error(value :: Result <(), GroupTreeError >) -> Result <(), GroupError > do
  case value do
    Err( error) -> Err(TreeFailure(error))
    Ok( _) -> Ok(nil)
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

fn has_extension(values :: List < Int >, wanted :: Int, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if List.get(values, index) == wanted do
    true
  else
    has_extension(values, wanted, index + 1)
  end
end

fn supports_extensions(member :: GroupMember, extensions :: List < Int >, index :: Int) -> Bool do
  if index >= List.length(extensions) do
    true
  else
    has_extension(member.extensions, List.get(extensions, index), 0) && supports_extensions(member,
    extensions,
    index + 1)
  end
end

fn all_members_support(values :: List < IndexedGroupMember >, extension :: Int, index :: Int) -> Bool do
  if index >= List.length(values) do
    true
  else
    has_extension(List.get(values, index).member.extensions, extension, 0) && all_members_support(values,
    extension,
    index + 1)
  end
end

fn negotiated_extensions(values :: List < IndexedGroupMember >,
preferred :: List < Int >,
index :: Int,
output :: List < Int >) -> List < Int > do
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

pub fn negotiate_group_extensions(tree :: borrow GroupTree, preferred :: List < Int >) -> List < Int > ! GroupError do
  let members = indexed_members(tree)
  if List.length(members) == 0 || !valid_extensions(preferred, 0, 0) do
    Err(InvalidGroup)
  else
    Ok(negotiated_extensions(members, preferred, 0, List.new()))
  end
end

fn collect_delivery_targets(values :: List < IndexedGroupMember >,
excluded_leaf :: Int,
index :: Int,
output :: List < GroupDeliveryTarget >) -> List < GroupDeliveryTarget > do
  if index >= List.length(values) do
    output
  else
    let value = List.get(values, index)
    let next = if value.leaf_index == excluded_leaf do
      output
    else
      List.append(output,
      GroupDeliveryTarget {
        leaf_index : value.leaf_index,
        mailbox_token : value.member.mailbox_token
      })
    end
    collect_delivery_targets(values, excluded_leaf, index + 1, next)
  end
end

pub fn delivery_targets(tree :: borrow GroupTree, excluded_leaf :: Int) -> List < GroupDeliveryTarget > ! GroupError do
  if excluded_leaf < -1 || excluded_leaf >= 64 do
    Err(InvalidGroup)
  else
    Ok(collect_delivery_targets(indexed_members(tree), excluded_leaf, 0, List.new()))
  end
end

fn validate_policy(value :: GroupTransparencyPolicy) -> Result <(), GroupError > do
  if Bytes.length(value.checkpoint_hash) != 32 || value.witness_threshold < 0 || value.witness_threshold > 255 do
    Err(InvalidPolicy)
  else
    Ok(nil)
  end
end

fn validate_member_policy(member :: GroupMember,
extensions :: List < Int >,
policy :: GroupTransparencyPolicy) -> Result <(), GroupError > do
  member_error(validate_member(member)) ?
  validate_policy(policy) ?
  let current = U64.compare(member.directory_sequence, policy.minimum_directory_sequence) >= 0
  let checkpoint = Bytes.secure_equals(member.transparency_checkpoint_hash, policy.checkpoint_hash)
  if current && checkpoint && member.witness_count >= policy.witness_threshold && supports_extensions(member,
  extensions,
  0) do
    Ok(nil)
  else
    Err(InvalidMember)
  end
end

fn encode_extensions(values :: List < Int >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_extensions(values, index + 1, append(output, write_u16(List.get(values, index)) ?) ?)
  end
end

fn extensions_bytes(values :: List < Int >) -> Bytes ! GroupError do
  if !valid_extensions(values, 0, 0) do
    Err(InvalidGroup)
  else
    encode_extensions(values, 0, byte(List.length(values)) ?)
  end
end

fn policy_bytes(value :: GroupTransparencyPolicy) -> Bytes ! GroupError do
  join([write_u64(value.minimum_directory_sequence) ?, value.checkpoint_hash, byte(value.witness_threshold) ?],
  0,
  Bytes.empty())
end

fn proposal_bytes(value :: GroupProposal) -> Bytes ! GroupError do
  case value do
    AddMember( leaf_index, member) -> join([byte(1) ?, write_u16(leaf_index) ?, vector(case encode_member(member) do
      Err( error) -> Err(TreeFailure(error))
      Ok( encoded) -> Ok(encoded)
    end ?) ?],
    0,
    Bytes.empty())
    RemoveMember( leaf_index) -> join([byte(2) ?, write_u16(leaf_index) ?], 0, Bytes.empty())
  end
end

fn commit_context(version :: Int,
suite :: Int,
group_id :: Bytes,
prior_epoch :: U64,
epoch :: U64,
committer_leaf :: Int,
prior_transcript_hash :: Bytes,
next_tree_hash :: Bytes,
proposal :: GroupProposal) -> Bytes ! GroupError do
  join([Bytes.from_utf8("mesh-mls/v1/commit"), byte(version) ?, write_u16(suite) ?, group_id, write_u64(prior_epoch) ?, write_u64(epoch) ?, write_u16(committer_leaf) ?, prior_transcript_hash, next_tree_hash, proposal_bytes(proposal) ?],
  0,
  Bytes.empty())
end

fn unmerged_bytes(values :: List < Int >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    unmerged_bytes(values, index + 1, append(output, write_u16(List.get(values, index)) ?) ?)
  end
end

fn parent_bytes(value :: TreeKemParentNode) -> Bytes ! GroupError do
  join([write_u16(value.node_index) ?, value.public_key.bytes, byte(List.length(value.unmerged_leaves)) ?, unmerged_bytes(value.unmerged_leaves,
  0,
  Bytes.empty()) ?],
  0,
  Bytes.empty())
end

fn update_public_bytes(values :: List < TreeKemUpdateNode >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    update_public_bytes(values,
    index + 1,
    append(output, parent_bytes(List.get(values, index).parent) ?) ?)
  end
end

fn ciphertext_bytes(values :: List < TreeKemCiphertext >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    ciphertext_bytes(values,
    index + 1,
    join([output, write_u16(value.recipient_node) ?, value.sealed], 0, Bytes.empty()) ?)
  end
end

fn update_ciphertexts_bytes(values :: List < TreeKemUpdateNode >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    update_ciphertexts_bytes(values,
    index + 1,
    join([output, byte(List.length(value.ciphertexts)) ?, ciphertext_bytes(value.ciphertexts,
    0,
    Bytes.empty()) ?],
    0,
    Bytes.empty()) ?)
  end
end

fn update_path_context(version :: Int,
suite :: Int,
group_id :: Bytes,
prior_epoch :: U64,
epoch :: U64,
committer_leaf :: Int,
prior_transcript_hash :: Bytes,
next_tree_hash :: Bytes,
proposal :: GroupProposal,
update_path :: TreeKemUpdatePath) -> Bytes ! GroupError do
  let prefix = commit_context(version,
  suite,
  group_id,
  prior_epoch,
  epoch,
  committer_leaf,
  prior_transcript_hash,
  next_tree_hash,
  proposal) ?
  join([prefix, update_path.leaf_public_key.bytes, byte(List.length(update_path.nodes)) ?, update_public_bytes(update_path.nodes,
  0,
  Bytes.empty()) ?],
  0,
  Bytes.empty())
end

fn commit_unsigned(value :: GroupCommit) -> Bytes ! GroupError do
  let context = update_path_context(value.version,
  value.suite,
  value.group_id,
  value.prior_epoch,
  value.epoch,
  value.committer_leaf,
  value.prior_transcript_hash,
  value.tree_hash,
  value.proposal,
  value.update_path) ?
  update_ciphertexts_bytes(value.update_path.nodes, 0, context)
end

fn signed_commit_bytes(value :: GroupCommit) -> Bytes ! GroupError do
  append(commit_unsigned(value) ?, value.signature.bytes)
end

fn wire_reader(input :: Bytes, maximum :: Int) -> BinaryReader ! GroupError do
  if Bytes.length(input) > maximum do
    Err(InvalidGroup)
  else
    case reader(input, maximum) do
      Err( _) -> Err(InvalidGroup)
      Ok( state) -> Ok(state)
    end
  end
end

fn wire_u8(state :: BinaryReader) -> GroupReadInt ! GroupError do
  case read_u8(state) do
    Err( _) -> Err(InvalidGroup)
    Ok( ( next, value)) -> Ok(GroupReadInt {
      state : next,
      value : value
    })
    Ok( _) -> Err(InvalidGroup)
  end
end

fn wire_u16(state :: BinaryReader) -> GroupReadInt ! GroupError do
  case read_u16_be(state) do
    Err( _) -> Err(InvalidGroup)
    Ok( ( next, value)) -> Ok(GroupReadInt {
      state : next,
      value : value
    })
    Ok( _) -> Err(InvalidGroup)
  end
end

fn wire_fixed(state :: BinaryReader, length :: Int) -> GroupReadBytes ! GroupError do
  case read_fixed(state, length) do
    Err( _) -> Err(InvalidGroup)
    Ok( ( next, value)) -> Ok(GroupReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err(InvalidGroup)
  end
end

fn wire_vector(state :: BinaryReader, maximum :: Int) -> GroupReadBytes ! GroupError do
  case read_vector(state, maximum) do
    Err( _) -> Err(InvalidGroup)
    Ok( ( next, value)) -> Ok(GroupReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err(InvalidGroup)
  end
end

fn wire_u32(state :: BinaryReader) -> GroupReadInt ! GroupError do
  let encoded = wire_fixed(state, 4) ?
  case Bytes.read_u32_be(encoded.value, 0) do
    Err( _) -> Err(InvalidGroup)
    Ok( wide) -> case U64.to_int(wide) do
      Err( _) -> Err(InvalidGroup)
      Ok( value) -> Ok(GroupReadInt {
        state : encoded.state,
        value : value
      })
    end
  end
end

fn wire_u64(state :: BinaryReader) -> GroupReadWide ! GroupError do
  let encoded = wire_fixed(state, 8) ?
  case Bytes.read_u64_be(encoded.value, 0) do
    Err( _) -> Err(InvalidGroup)
    Ok( value) -> Ok(GroupReadWide {
      state : encoded.state,
      value : value
    })
  end
end

fn wire_end(state :: BinaryReader) -> Result <(), GroupError > do
  case finish(state) do
    Err( _) -> Err(InvalidGroup)
    Ok( _) -> Ok(nil)
  end
end

fn wire_magic(state :: BinaryReader, expected :: String) -> BinaryReader ! GroupError do
  let encoded = Bytes.from_utf8(expected)
  let value = wire_fixed(state, Bytes.length(encoded)) ?
  if Bytes.secure_equals(value.value, encoded) do
    Ok(value.state)
  else
    Err(InvalidGroup)
  end
end

fn wire_start(input :: Bytes, maximum :: Int, magic :: String) -> BinaryReader ! GroupError do
  let version = wire_u8(wire_reader(input, maximum) ?) ?
  if version.value == 1 do
    wire_magic(version.state, magic)
  else
    Err(InvalidGroup)
  end
end

fn read_extensions(state :: BinaryReader,
count :: Int,
index :: Int,
previous :: Int,
output :: List < Int >) -> GroupReadInts ! GroupError do
  if count < 0 || count > 16 do
    Err(InvalidGroup)
  else if index >= count do
    Ok(GroupReadInts {
      state : state,
      value : output
    })
  else
    let extension = wire_u16(state) ?
    if extension.value <= previous || extension.value <= 0 do
      Err(InvalidGroup)
    else
      read_extensions(extension.state,
      count,
      index + 1,
      extension.value,
      List.append(output, extension.value))
    end
  end
end

fn read_levels(state :: BinaryReader,
count :: Int,
index :: Int,
previous :: Int,
output :: List < Int >) -> GroupReadInts ! GroupError do
  if count < 0 || count > 6 do
    Err(InvalidGroup)
  else if index >= count do
    Ok(GroupReadInts {
      state : state,
      value : output
    })
  else
    let level = wire_u8(state) ?
    if level.value < 0 || level.value >= 6 || level.value <= previous do
      Err(InvalidGroup)
    else
      read_levels(level.state, count, index + 1, level.value, List.append(output, level.value))
    end
  end
end

fn decode_member_wire(input :: Bytes) -> GroupMember ! GroupError do
  let version = wire_u8(wire_reader(input, 251) ?) ?
  let account_id = wire_fixed(version.state, 32) ?
  let device_id = wire_fixed(account_id.state, 16) ?
  let signing_public_key = wire_fixed(device_id.state, 32) ?
  let init_public_key = wire_fixed(signing_public_key.state, 32) ?
  let leaf_public_key = wire_fixed(init_public_key.state, 32) ?
  let mailbox_token = wire_fixed(leaf_public_key.state, 32) ?
  let directory_sequence = wire_u64(mailbox_token.state) ?
  let checkpoint = wire_fixed(directory_sequence.state, 32) ?
  let witness_count = wire_u8(checkpoint.state) ?
  let extension_count = wire_u8(witness_count.state) ?
  let extensions = read_extensions(extension_count.state, extension_count.value, 0, 0, List.new()) ?
  wire_end(extensions.state) ?
  let value = GroupMember {
    version : version.value,
    account_id : account_id.value,
    device_id : device_id.value,
    signing_public_key : SigningPublicKey { bytes : signing_public_key.value },
    init_public_key : X25519PublicKey { bytes : init_public_key.value },
    leaf_public_key : X25519PublicKey { bytes : leaf_public_key.value },
    mailbox_token : mailbox_token.value,
    directory_sequence : directory_sequence.value,
    transparency_checkpoint_hash : checkpoint.value,
    witness_count : witness_count.value,
    extensions : extensions.value
  }
  member_error(validate_member(value)) ?
  Ok(value)
end

fn read_proposal(state :: BinaryReader) -> GroupReadProposal ! GroupError do
  let kind = wire_u8(state) ?
  let leaf = wire_u16(kind.state) ?
  if leaf.value < 0 || leaf.value >= 64 do
    Err(InvalidGroup)
  else if kind.value == 1 do
    let member = wire_vector(leaf.state, 251) ?
    Ok(GroupReadProposal {
      state : member.state,
      value : AddMember(leaf.value, decode_member_wire(member.value) ?)
    })
  else if kind.value == 2 do
    Ok(GroupReadProposal {
      state : leaf.state,
      value : RemoveMember(leaf.value)
    })
  else
    Err(InvalidGroup)
  end
end

fn read_unmerged(state :: BinaryReader,
count :: Int,
index :: Int,
previous :: Int,
output :: List < Int >) -> GroupReadInts ! GroupError do
  if count < 0 || count > 64 do
    Err(InvalidGroup)
  else if index >= count do
    Ok(GroupReadInts {
      state : state,
      value : output
    })
  else
    let leaf = wire_u16(state) ?
    if leaf.value < 0 || leaf.value >= 64 || leaf.value <= previous do
      Err(InvalidGroup)
    else
      read_unmerged(leaf.state, count, index + 1, leaf.value, List.append(output, leaf.value))
    end
  end
end

fn read_ciphertexts(state :: BinaryReader,
count :: Int,
index :: Int,
output :: List < TreeKemCiphertext >) -> GroupReadCiphertexts ! GroupError do
  if count < 0 || count > 64 do
    Err(InvalidGroup)
  else if index >= count do
    Ok(GroupReadCiphertexts {
      state : state,
      value : output
    })
  else
    let recipient = wire_u16(state) ?
    let sealed = wire_fixed(recipient.state, 80) ?
    if recipient.value < 0 || recipient.value >= 127 do
      Err(InvalidGroup)
    else
      read_ciphertexts(sealed.state,
      count,
      index + 1,
      List.append(output,
      TreeKemCiphertext {
        recipient_node : recipient.value,
        sealed : sealed.value
      }))
    end
  end
end

fn read_update_nodes(state :: BinaryReader,
count :: Int,
index :: Int,
output :: List < TreeKemParentNode >) -> GroupReadParents ! GroupError do
  if count != 6 do
    Err(InvalidGroup)
  else if index >= count do
    Ok(GroupReadParents {
      state : state,
      value : output
    })
  else
    let node_index = wire_u16(state) ?
    let public_key = wire_fixed(node_index.state, 32) ?
    let unmerged_count = wire_u8(public_key.state) ?
    let unmerged = read_unmerged(unmerged_count.state, unmerged_count.value, 0, -1, List.new()) ?
    read_update_nodes(unmerged.state,
    count,
    index + 1,
    List.append(output,
    TreeKemParentNode {
      node_index : node_index.value,
      public_key : X25519PublicKey { bytes : public_key.value },
      unmerged_leaves : unmerged.value
    }))
  end
end

fn read_update_ciphertexts(state :: BinaryReader,
parents :: List < TreeKemParentNode >,
index :: Int,
output :: List < TreeKemUpdateNode >) -> GroupReadUpdateNodes ! GroupError do
  if index >= List.length(parents) do
    Ok(GroupReadUpdateNodes {
      state : state,
      value : output
    })
  else
    let ciphertext_count = wire_u8(state) ?
    let ciphertexts = read_ciphertexts(ciphertext_count.state,
    ciphertext_count.value,
    0,
    List.new()) ?
    read_update_ciphertexts(ciphertexts.state,
    parents,
    index + 1,
    List.append(output,
    TreeKemUpdateNode {
      parent : List.get(parents, index),
      ciphertexts : ciphertexts.value
    }))
  end
end

fn validate_proposal_shape(value :: GroupProposal) -> Result <(), GroupError > do
  case value do
    AddMember( leaf, member) -> if leaf < 0 || leaf >= 64 do
      Err(InvalidGroup)
    else
      member_error(validate_member(member))
    end
    RemoveMember( leaf) -> if leaf < 0 || leaf >= 64 do
      Err(InvalidGroup)
    else
      Ok(nil)
    end
  end
end

fn validate_ciphertexts_shape(values :: List < TreeKemCiphertext >, index :: Int) -> Result <(), GroupError > do
  if List.length(values) > 64 do
    Err(InvalidGroup)
  else if index >= List.length(values) do
    Ok(nil)
  else
    let value = List.get(values, index)
    if value.recipient_node < 0 || value.recipient_node >= 127 || Bytes.length(value.sealed) != 80 do
      Err(InvalidGroup)
    else
      validate_ciphertexts_shape(values, index + 1)
    end
  end
end

fn validate_update_nodes_shape(values :: List < TreeKemUpdateNode >,
expected :: List < Int >,
index :: Int,
total_ciphertexts :: Int) -> Result <(), GroupError > do
  if List.length(values) != 6 || List.length(expected) != 6 || total_ciphertexts > 64 do
    Err(InvalidGroup)
  else if index >= List.length(values) do
    Ok(nil)
  else
    let value = List.get(values, index)
    if value.parent.node_index != List.get(expected, index) || Bytes.length(value.parent.public_key.bytes) != 32 || List.length(value.parent.unmerged_leaves) != 0 do
      Err(InvalidGroup)
    else
      validate_ciphertexts_shape(value.ciphertexts, 0) ?
      validate_update_nodes_shape(values,
      expected,
      index + 1,
      total_ciphertexts + List.length(value.ciphertexts))
    end
  end
end

fn validate_commit_shape(value :: GroupCommit) -> Result <(), GroupError > do
  let valid = value.version == 1 && value.suite == 3 && Bytes.length(value.group_id) == 32 && value.committer_leaf >= 0 && value.committer_leaf < 64 && Bytes.length(value.prior_transcript_hash) == 32 && Bytes.length(value.tree_hash) == 32 && Bytes.length(value.signature.bytes) == 64
  if !valid do
    Err(InvalidGroup)
  else if U64.compare(value.epoch, next_epoch(value.prior_epoch) ?) != 0 do
    Err(InvalidGroup)
  else
    validate_proposal_shape(value.proposal) ?
    if Bytes.length(value.update_path.leaf_public_key.bytes) != 32 do
      Err(InvalidGroup)
    else
      validate_update_nodes_shape(value.update_path.nodes,
      tree_path_error(direct_path(value.committer_leaf)) ?,
      0,
      0)
    end
  end
end

pub fn encode_group_commit(value :: GroupCommit) -> Bytes ! GroupError do
  validate_commit_shape(value) ?
  let body = signed_commit_bytes(value) ?
  if Bytes.length(body) > 8192 do
    Err(InvalidGroup)
  else
    join([byte(1) ?, Bytes.from_utf8("GCM"), vector(body) ?], 0, Bytes.empty())
  end
end

fn decode_commit_body(input :: Bytes) -> GroupCommit ! GroupError do
  let domain = wire_magic(wire_reader(input, 8192) ?, "mesh-mls/v1/commit") ?
  let version = wire_u8(domain) ?
  let suite = wire_u16(version.state) ?
  let group_id = wire_fixed(suite.state, 32) ?
  let prior_epoch = wire_u64(group_id.state) ?
  let epoch = wire_u64(prior_epoch.state) ?
  let committer = wire_u16(epoch.state) ?
  let prior_transcript = wire_fixed(committer.state, 32) ?
  let tree = wire_fixed(prior_transcript.state, 32) ?
  let proposal = read_proposal(tree.state) ?
  let leaf_public = wire_fixed(proposal.state, 32) ?
  let node_count = wire_u8(leaf_public.state) ?
  let parents = read_update_nodes(node_count.state, node_count.value, 0, List.new()) ?
  let nodes = read_update_ciphertexts(parents.state, parents.value, 0, List.new()) ?
  let signature = wire_fixed(nodes.state, 64) ?
  wire_end(signature.state) ?
  let value = GroupCommit {
    version : version.value,
    suite : suite.value,
    group_id : group_id.value,
    prior_epoch : prior_epoch.value,
    epoch : epoch.value,
    committer_leaf : committer.value,
    prior_transcript_hash : prior_transcript.value,
    tree_hash : tree.value,
    proposal : proposal.value,
    update_path : TreeKemUpdatePath {
      leaf_public_key : X25519PublicKey { bytes : leaf_public.value },
      nodes : nodes.value
    },
    signature : Signature { bytes : signature.value }
  }
  validate_commit_shape(value) ?
  Ok(value)
end

pub fn decode_group_commit(input :: Bytes) -> GroupCommit ! GroupError do
  let body = wire_vector(wire_start(input, 8200, "GCM") ?, 8192) ?
  wire_end(body.state) ?
  decode_commit_body(body.value)
end

fn encode_members(values :: List < IndexedGroupMember >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    let member = case encode_member(value.member) do
      Err( error) -> Err(TreeFailure(error))
      Ok( encoded) -> Ok(encoded)
    end ?
    encode_members(values,
    index + 1,
    join([output, write_u16(value.leaf_index) ?, vector(member) ?], 0, Bytes.empty()) ?)
  end
end

fn read_members(state :: BinaryReader,
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
    let leaf = wire_u16(state) ?
    let member = wire_vector(leaf.state, 251) ?
    if leaf.value < 0 || leaf.value >= 64 || leaf.value <= previous do
      Err(InvalidGroup)
    else
      read_members(member.state,
      count,
      index + 1,
      leaf.value,
      List.append(output,
      IndexedGroupMember {
        leaf_index : leaf.value,
        member : decode_member_wire(member.value) ?
      }))
    end
  end
end

fn encode_parents(values :: List < TreeKemParentNode >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_parents(values, index + 1, append(output, parent_bytes(List.get(values, index)) ?) ?)
  end
end

fn update_parents(values :: List < TreeKemUpdateNode >,
index :: Int,
output :: List < TreeKemParentNode >) -> List < TreeKemParentNode > do
  if index >= List.length(values) do
    output
  else
    update_parents(values, index + 1, List.append(output, List.get(values, index).parent))
  end
end

fn public_update_nodes(values :: List < TreeKemParentNode >,
index :: Int,
output :: List < TreeKemUpdateNode >) -> List < TreeKemUpdateNode > do
  if index >= List.length(values) do
    output
  else
    public_update_nodes(values,
    index + 1,
    List.append(output,
    TreeKemUpdateNode {
      parent : List.get(values, index),
      ciphertexts : List.new()
    }))
  end
end

fn read_parents(state :: BinaryReader,
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
    let node_index = wire_u16(state) ?
    let public_key = wire_fixed(node_index.state, 32) ?
    let unmerged_count = wire_u8(public_key.state) ?
    let unmerged = read_unmerged(unmerged_count.state, unmerged_count.value, 0, -1, List.new()) ?
    if node_index.value < 0 || node_index.value >= 63 || node_index.value <= previous do
      Err(InvalidGroup)
    else
      read_parents(unmerged.state,
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

fn joiner_level(committer_leaf :: Int, recipient_leaf :: Int, index :: Int) -> Int ! GroupError do
  let path = tree_path_error(direct_path(committer_leaf)) ?
  if index >= List.length(path) do
    Err(InvalidGroup)
  else if node_contains_leaf(List.get(path, index), recipient_leaf) do
    Ok(index)
  else
    joiner_level(committer_leaf, recipient_leaf, index + 1)
  end
end

fn same_member(left :: GroupMember, right :: GroupMember) -> Bool ! GroupError do
  Ok(Bytes.secure_equals(case encode_member(left) do
    Err( error) -> Err(TreeFailure(error))
    Ok( value) -> Ok(value)
  end ?,
  case encode_member(right) do
    Err( error) -> Err(TreeFailure(error))
    Ok( value) -> Ok(value)
  end ?))
end

fn welcome_proposal_matches(value :: GroupProposal, tree :: borrow GroupTree, recipient_leaf :: Int) -> Bool ! GroupError do
  case value do
    AddMember( leaf, added) -> if leaf != recipient_leaf do
      Ok(false)
    else
      case member_at(tree, leaf) do
        Err( _) -> Ok(false)
        Ok( member) -> same_member(member, added)
      end
    end
    RemoveMember( _) -> Ok(false)
  end
end

fn validate_welcome_shape(value :: GroupWelcome) -> Result <(), GroupError > do
  validate_commit_shape(value.commit) ?
  if !valid_extensions(value.extensions, 0, 0) || value.recipient_leaf < 0 || value.recipient_leaf >= 64 do
    Err(InvalidGroup)
  else
    validate_policy(value.policy) ?
    validate_members(value.members, value.extensions, value.policy, 0) ?
    let group_tree = tree_error(tree_from_public(value.members, value.parent_nodes)) ?
    let proposal_matches = welcome_proposal_matches(value.commit.proposal,
    group_tree,
    value.recipient_leaf) ?
    if !proposal_matches || !Bytes.secure_equals(tree_hash(group_tree), value.commit.tree_hash) || value.commit.committer_leaf == value.recipient_leaf || value.joiner_path_level != joiner_level(value.commit.committer_leaf,
    value.recipient_leaf,
    0) ? || Bytes.length(value.joiner_path_secret) != 80 do
      Err(InvalidGroup)
    else
      let committer = tree_member_error(member_at(group_tree, value.commit.committer_leaf)) ?
      if !Bytes.secure_equals(committer.leaf_public_key.bytes,
      value.commit.update_path.leaf_public_key.bytes) do
        Err(InvalidGroup)
      else
        let checked = tree_error(apply_update_path(group_tree,
        value.commit.committer_leaf,
        update_parents(value.commit.update_path.nodes, 0, List.new()))) ?
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
  validate_welcome_shape(value) ?
  let commit = encode_group_commit(value.commit) ?
  let body = join([vector(commit) ?, byte(List.length(value.members)) ?, encode_members(value.members,
  0,
  Bytes.empty()) ?, extensions_bytes(value.extensions) ?, policy_bytes(value.policy) ?, write_u16(value.recipient_leaf) ?, byte(List.length(value.parent_nodes)) ?, encode_parents(value.parent_nodes,
  0,
  Bytes.empty()) ?, byte(value.joiner_path_level) ?, value.joiner_path_secret],
  0,
  Bytes.empty()) ?
  if Bytes.length(body) > 65531 do
    Err(InvalidGroup)
  else
    join([byte(1) ?, Bytes.from_utf8("GWL"), body], 0, Bytes.empty())
  end
end

pub fn decode_group_welcome(input :: Bytes) -> GroupWelcome ! GroupError do
  let commit = wire_vector(wire_start(input, 65535, "GWL") ?, 8200) ?
  let member_count = wire_u8(commit.state) ?
  let members = read_members(member_count.state, member_count.value, 0, -1, List.new()) ?
  let extension_count = wire_u8(members.state) ?
  let extensions = read_extensions(extension_count.state, extension_count.value, 0, 0, List.new()) ?
  let minimum_sequence = wire_u64(extensions.state) ?
  let checkpoint = wire_fixed(minimum_sequence.state, 32) ?
  let witness = wire_u8(checkpoint.state) ?
  let recipient = wire_u16(witness.state) ?
  let parent_count = wire_u8(recipient.state) ?
  let parents = read_parents(parent_count.state, parent_count.value, 0, -1, List.new()) ?
  let joiner_level = wire_u8(parents.state) ?
  let joiner_secret = wire_fixed(joiner_level.state, 80) ?
  wire_end(joiner_secret.state) ?
  let value = GroupWelcome {
    commit : decode_group_commit(commit.value) ?,
    members : members.value,
    extensions : extensions.value,
    policy : GroupTransparencyPolicy {
      minimum_directory_sequence : minimum_sequence.value,
      checkpoint_hash : checkpoint.value,
      witness_threshold : witness.value
    },
    recipient_leaf : recipient.value,
    parent_nodes : parents.value,
    joiner_path_level : joiner_level.value,
    joiner_path_secret : joiner_secret.value
  }
  validate_welcome_shape(value) ?
  Ok(value)
end

fn validate_message_shape(value :: GroupMessage) -> Result <(), GroupError > do
  let valid = value.version == 1 && value.suite == 3 && Bytes.length(value.group_id) == 32 && Bytes.length(value.tree_hash) == 32 && value.sender_leaf >= 0 && value.sender_leaf < 64 && value.generation >= 0 && Bytes.length(value.nonce) == 12 && Bytes.length(value.ciphertext) >= 16 && Bytes.length(value.ciphertext) <= 65536 && Bytes.length(value.signature.bytes) == 64
  if valid do
    Ok(nil)
  else
    Err(InvalidGroup)
  end
end

pub fn encode_group_message(value :: GroupMessage) -> Bytes ! GroupError do
  validate_message_shape(value) ?
  join([byte(1) ?, Bytes.from_utf8("GMS"), byte(value.version) ?, write_u16(value.suite) ?, value.group_id, write_u64(value.epoch) ?, value.tree_hash, write_u16(value.sender_leaf) ?, write_u32(value.generation) ?, value.nonce, vector(value.ciphertext) ?, value.signature.bytes],
  0,
  Bytes.empty())
end

pub fn decode_group_message(input :: Bytes) -> GroupMessage ! GroupError do
  let version = wire_u8(wire_start(input, 65750, "GMS") ?) ?
  let suite = wire_u16(version.state) ?
  let group_id = wire_fixed(suite.state, 32) ?
  let epoch = wire_u64(group_id.state) ?
  let tree = wire_fixed(epoch.state, 32) ?
  let sender = wire_u16(tree.state) ?
  let generation = wire_u32(sender.state) ?
  let nonce = wire_fixed(generation.state, 12) ?
  let ciphertext = wire_vector(nonce.state, 65536) ?
  let signature = wire_fixed(ciphertext.state, 64) ?
  wire_end(signature.state) ?
  let value = GroupMessage {
    version : version.value,
    suite : suite.value,
    group_id : group_id.value,
    epoch : epoch.value,
    tree_hash : tree.value,
    sender_leaf : sender.value,
    generation : generation.value,
    nonce : nonce.value,
    ciphertext : ciphertext.value,
    signature : Signature { bytes : signature.value }
  }
  validate_message_shape(value) ?
  Ok(value)
end

fn generation_seen(values :: List < SenderGeneration >,
leaf_index :: Int,
limit :: Int,
index :: Int) -> Bool do
  if index >= limit do
    false
  else if List.get(values, index).leaf_index == leaf_index do
    true
  else
    generation_seen(values, leaf_index, limit, index + 1)
  end
end

fn validate_generations(values :: List < SenderGeneration >, tree :: borrow GroupTree, index :: Int) -> Result <(), GroupError > do
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
        Err( _) -> Err(InvalidGroup)
        Ok( _) -> validate_generations(values, tree, index + 1)
      end
    end
  end
end

fn encode_generations(values :: List < SenderGeneration >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    encode_generations(values,
    index + 1,
    join([output, write_u16(value.leaf_index) ?, write_u32(value.generation) ?], 0, Bytes.empty()) ?)
  end
end

fn read_generations(state :: BinaryReader,
count :: Int,
index :: Int,
output :: List < SenderGeneration >) -> GroupReadGenerations ! GroupError do
  if count < 0 || count > 64 do
    Err(InvalidGroup)
  else if index >= count do
    Ok(GroupReadGenerations {
      state : state,
      value : output
    })
  else
    let leaf = wire_u16(state) ?
    let generation = wire_u32(leaf.state) ?
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
        leaf_index : leaf.value,
        generation : generation.value
      }))
    end
  end
end

fn local_identity_matches(tree :: borrow GroupTree,
local_leaf :: Int,
account_id :: Bytes,
device_id :: Bytes) -> Bool do
  case member_at(tree, local_leaf) do
    Err( _) -> false
    Ok( member) -> Bytes.secure_equals(member.account_id, account_id) && Bytes.secure_equals(member.device_id,
    device_id)
  end
end

fn valid_levels(values :: List < Int >, index :: Int, previous :: Int) -> Bool do
  if List.length(values) > 6 do
    false
  else if index >= List.length(values) do
    true
  else
    let value = List.get(values, index)
    value >= 0 && value < 6 && value > previous && valid_levels(values, index + 1, value)
  end
end

fn encode_levels(values :: List < Int >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_levels(values, index + 1, append(output, byte(List.get(values, index)) ?) ?)
  end
end

fn validate_snapshot_state(state :: borrow GroupState,
account_id :: Bytes,
device_id :: Bytes,
snapshot_version :: U64) -> Result <(), GroupError > do
  let valid = state.version == 1 && state.suite == 3 && Bytes.length(state.group_id) == 32 && Bytes.length(state.tree_hash_cache) == 32 && Bytes.length(state.transcript_hash) == 32 && state.local_leaf >= 0 && state.local_leaf < 64 && state.next_generation >= 0 && Bytes.length(account_id) == 32 && Bytes.length(device_id) == 16 && U64.compare(snapshot_version,
  zero() ?) > 0 && Bytes.secure_equals(state.tree_hash_cache, tree_hash(state.tree))
  if !valid || !valid_extensions(state.extensions, 0, 0) || !valid_levels(state.key_material.available_levels,
  0,
  -1) || !local_identity_matches(state.tree, state.local_leaf, account_id, device_id) do
    Err(InvalidGroup)
  else
    validate_policy(state.policy) ?
    validate_members(indexed_members(state.tree), state.extensions, state.policy, 0) ?
    validate_generations(state.received_generations, state.tree, 0)
  end
end

fn group_snapshot_header(state :: borrow GroupState,
account_id :: Bytes,
device_id :: Bytes,
snapshot_version :: U64) -> Bytes ! GroupError do
  validate_snapshot_state(state, account_id, device_id, snapshot_version) ?
  let members = indexed_members(state.tree)
  let parents = public_parent_nodes(state.tree)
  join([byte(1) ?, Bytes.from_utf8("GST"), byte(state.version) ?, write_u16(state.suite) ?, state.group_id, write_u64(state.epoch) ?, write_u64(snapshot_version) ?, state.tree_hash_cache, state.transcript_hash, write_u16(state.local_leaf) ?, write_u32(state.next_generation) ?, byte(List.length(members)) ?, encode_members(members,
  0,
  Bytes.empty()) ?, byte(List.length(parents)) ?, encode_parents(parents, 0, Bytes.empty()) ?, byte(List.length(state.received_generations)) ?, encode_generations(state.received_generations,
  0,
  Bytes.empty()) ?, extensions_bytes(state.extensions) ?, byte(List.length(state.key_material.available_levels)) ?, encode_levels(state.key_material.available_levels,
  0,
  Bytes.empty()) ?, policy_bytes(state.policy) ?],
  0,
  Bytes.empty())
end

fn group_storage_context(account_id :: Bytes,
device_id :: Bytes,
group_id :: Bytes,
header :: Bytes,
purpose :: Int,
key_slot :: Int,
snapshot_version :: U64) -> Bytes ! GroupError do
  if Bytes.length(account_id) != 32 || Bytes.length(device_id) != 16 || Bytes.length(group_id) != 32 || (purpose != 16 && purpose != 17) || (purpose == 16 && key_slot != 0) || (purpose == 17 && (key_slot < 1 || key_slot > 7)) do
    Err(InvalidGroup)
  else
    let object = Crypto.sha256(join([Bytes.from_utf8("mesh-msg/v1/group-snapshot-object"), header, write_u16(purpose) ?, byte(key_slot) ?],
    0,
    Bytes.empty()) ?)
    join([byte(1) ?, account_id, device_id, group_id, object, write_u16(purpose) ?, write_u64(snapshot_version) ?],
    0,
    Bytes.empty())
  end
end

fn seal_group_private(value :: borrow X25519PrivateKey,
wrapping_key :: borrow StorageKey,
context :: Bytes) -> Bytes ! GroupError do
  case X25519PrivateKey.seal_for_storage(value, wrapping_key, context) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( sealed) -> Ok(sealed)
  end
end

fn seal_group_snapshot(state :: borrow GroupState,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes,
snapshot_version :: U64) -> Bytes ! GroupError do
  let header = group_snapshot_header(state, account_id, device_id, snapshot_version) ?
  let context = group_storage_context(account_id,
  device_id,
  state.group_id,
  header,
  16,
  0,
  snapshot_version) ?
  let sealed = case Secret.seal_for_storage(state.key_material.epoch_secret, wrapping_key, context) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end ?
  let leaf_private = seal_group_private(state.key_material.leaf_private_key,
  wrapping_key,
  group_storage_context(account_id, device_id, state.group_id, header, 17, 1, snapshot_version) ?) ?
  let level0 = seal_group_private(state.key_material.level0_private_key,
  wrapping_key,
  group_storage_context(account_id, device_id, state.group_id, header, 17, 2, snapshot_version) ?) ?
  let level1 = seal_group_private(state.key_material.level1_private_key,
  wrapping_key,
  group_storage_context(account_id, device_id, state.group_id, header, 17, 3, snapshot_version) ?) ?
  let level2 = seal_group_private(state.key_material.level2_private_key,
  wrapping_key,
  group_storage_context(account_id, device_id, state.group_id, header, 17, 4, snapshot_version) ?) ?
  let level3 = seal_group_private(state.key_material.level3_private_key,
  wrapping_key,
  group_storage_context(account_id, device_id, state.group_id, header, 17, 5, snapshot_version) ?) ?
  let level4 = seal_group_private(state.key_material.level4_private_key,
  wrapping_key,
  group_storage_context(account_id, device_id, state.group_id, header, 17, 6, snapshot_version) ?) ?
  let level5 = seal_group_private(state.key_material.level5_private_key,
  wrapping_key,
  group_storage_context(account_id, device_id, state.group_id, header, 17, 7, snapshot_version) ?) ?
  if Bytes.length(header) > 64711 || Bytes.length(sealed) != 99 || Bytes.length(leaf_private) != 99 || Bytes.length(level0) != 99 || Bytes.length(level1) != 99 || Bytes.length(level2) != 99 || Bytes.length(level3) != 99 || Bytes.length(level4) != 99 || Bytes.length(level5) != 99 do
    Err(InvalidGroup)
  else
    join([header, vector(sealed) ?, vector(leaf_private) ?, vector(level0) ?, vector(level1) ?, vector(level2) ?, vector(level3) ?, vector(level4) ?, vector(level5) ?],
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
      Err( error) -> GroupSnapshotRejected(state, error)
      Ok( blob) -> GroupSnapshotSealed(% { state | snapshot_version : snapshot_version }, blob)
    end
  end
end

fn parse_group_snapshot(input :: Bytes) -> ParsedGroupSnapshot ! GroupError do
  let state_version = wire_u8(wire_start(input, 65535, "GST") ?) ?
  let suite = wire_u16(state_version.state) ?
  let group_id = wire_fixed(suite.state, 32) ?
  let epoch = wire_u64(group_id.state) ?
  let snapshot_version = wire_u64(epoch.state) ?
  let snapshot_tree_hash = wire_fixed(snapshot_version.state, 32) ?
  let transcript_hash = wire_fixed(snapshot_tree_hash.state, 32) ?
  let local_leaf = wire_u16(transcript_hash.state) ?
  let next_generation = wire_u32(local_leaf.state) ?
  let member_count = wire_u8(next_generation.state) ?
  let members = read_members(member_count.state, member_count.value, 0, -1, List.new()) ?
  let parent_count = wire_u8(members.state) ?
  let parents = read_parents(parent_count.state, parent_count.value, 0, -1, List.new()) ?
  let generation_count = wire_u8(parents.state) ?
  let generations = read_generations(generation_count.state, generation_count.value, 0, List.new()) ?
  let extension_count = wire_u8(generations.state) ?
  let extensions = read_extensions(extension_count.state, extension_count.value, 0, 0, List.new()) ?
  let level_count = wire_u8(extensions.state) ?
  let levels = read_levels(level_count.state, level_count.value, 0, -1, List.new()) ?
  let minimum_sequence = wire_u64(levels.state) ?
  let checkpoint = wire_fixed(minimum_sequence.state, 32) ?
  let witness = wire_u8(checkpoint.state) ?
  let sealed = wire_vector(witness.state, 99) ?
  let leaf_private = wire_vector(sealed.state, 99) ?
  let level0 = wire_vector(leaf_private.state, 99) ?
  let level1 = wire_vector(level0.state, 99) ?
  let level2 = wire_vector(level1.state, 99) ?
  let level3 = wire_vector(level2.state, 99) ?
  let level4 = wire_vector(level3.state, 99) ?
  let level5 = wire_vector(level4.state, 99) ?
  wire_end(level5.state) ?
  if Bytes.length(sealed.value) != 99 || Bytes.length(leaf_private.value) != 99 || Bytes.length(level0.value) != 99 || Bytes.length(level1.value) != 99 || Bytes.length(level2.value) != 99 || Bytes.length(level3.value) != 99 || Bytes.length(level4.value) != 99 || Bytes.length(level5.value) != 99 do
    Err(InvalidGroup)
  else
    Ok(ParsedGroupSnapshot {
      version : state_version.value,
      suite : suite.value,
      group_id : group_id.value,
      epoch : epoch.value,
      snapshot_version : snapshot_version.value,
      tree_hash : snapshot_tree_hash.value,
      transcript_hash : transcript_hash.value,
      local_leaf : local_leaf.value,
      next_generation : next_generation.value,
      members : members.value,
      parent_nodes : parents.value,
      received_generations : generations.value,
      extensions : extensions.value,
      available_levels : levels.value,
      policy : GroupTransparencyPolicy {
        minimum_directory_sequence : minimum_sequence.value,
        checkpoint_hash : checkpoint.value,
        witness_threshold : witness.value
      },
      sealed_epoch_secret : sealed.value,
      sealed_leaf_private : leaf_private.value,
      sealed_level0_private : level0.value,
      sealed_level1_private : level1.value,
      sealed_level2_private : level2.value,
      sealed_level3_private : level3.value,
      sealed_level4_private : level4.value,
      sealed_level5_private : level5.value
    })
  end
end

fn parsed_group_header(value :: ParsedGroupSnapshot) -> Bytes ! GroupError do
  join([byte(1) ?, Bytes.from_utf8("GST"), byte(value.version) ?, write_u16(value.suite) ?, value.group_id, write_u64(value.epoch) ?, write_u64(value.snapshot_version) ?, value.tree_hash, value.transcript_hash, write_u16(value.local_leaf) ?, write_u32(value.next_generation) ?, byte(List.length(value.members)) ?, encode_members(value.members,
  0,
  Bytes.empty()) ?, byte(List.length(value.parent_nodes)) ?, encode_parents(value.parent_nodes,
  0,
  Bytes.empty()) ?, byte(List.length(value.received_generations)) ?, encode_generations(value.received_generations,
  0,
  Bytes.empty()) ?, extensions_bytes(value.extensions) ?, byte(List.length(value.available_levels)) ?, encode_levels(value.available_levels,
  0,
  Bytes.empty()) ?, policy_bytes(value.policy) ?],
  0,
  Bytes.empty())
end

fn validate_parsed_snapshot(value :: ParsedGroupSnapshot, account_id :: Bytes, device_id :: Bytes) -> GroupTree ! GroupError do
  let valid = value.version == 1 && value.suite == 3 && Bytes.length(value.group_id) == 32 && Bytes.length(value.tree_hash) == 32 && Bytes.length(value.transcript_hash) == 32 && value.local_leaf >= 0 && value.local_leaf < 64 && value.next_generation >= 0 && Bytes.length(account_id) == 32 && Bytes.length(device_id) == 16 && U64.compare(value.snapshot_version,
  zero() ?) > 0 && valid_extensions(value.extensions, 0, 0) && valid_levels(value.available_levels,
  0,
  -1)
  if !valid do
    Err(InvalidGroup)
  else
    validate_policy(value.policy) ?
    validate_members(value.members, value.extensions, value.policy, 0) ?
    let group_tree = tree_error(tree_from_public(value.members, value.parent_nodes)) ?
    if !Bytes.secure_equals(tree_hash(group_tree), value.tree_hash) || !local_identity_matches(group_tree,
    value.local_leaf,
    account_id,
    device_id) do
      Err(InvalidGroup)
    else
      validate_generations(value.received_generations, group_tree, 0) ?
      Ok(group_tree)
    end
  end
end

fn unseal_group_private(blob :: Bytes, wrapping_key :: borrow StorageKey, context :: Bytes) -> X25519PrivateKey ! GroupError do
  case X25519PrivateKey.unseal_from_storage(blob, wrapping_key, context) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end
end

fn parent_public_key(values :: List < TreeKemParentNode >, node_index :: Int, index :: Int) -> X25519PublicKey ! GroupError do
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

fn level_is_available(values :: List < Int >, level :: Int, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else
    List.get(values, index) == level || level_is_available(values, level, index + 1)
  end
end

fn validate_private_key(value :: borrow X25519PrivateKey, expected :: X25519PublicKey) -> Result <(), GroupError > do
  case Crypto.x25519_public(value) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( actual) -> if Bytes.secure_equals(actual.bytes, expected.bytes) do
      Ok(nil)
    else
      Err(AuthenticationRejected)
    end
  end
end

fn validate_parent_private(value :: borrow X25519PrivateKey,
parents :: List < TreeKemParentNode >,
path :: List < Int >,
available :: List < Int >,
level :: Int) -> Result <(), GroupError > do
  if level_is_available(available, level, 0) do
    validate_private_key(value, parent_public_key(parents, List.get(path, level), 0) ?)
  else
    Ok(nil)
  end
end

pub fn restore_group(blob :: Bytes,
wrapping_key :: borrow StorageKey,
account_id :: Bytes,
device_id :: Bytes,
minimum_version :: U64) -> GroupState ! GroupError do
  let value = parse_group_snapshot(blob) ?
  if U64.compare(value.snapshot_version, minimum_version) < 0 do
    Err(RollbackRejected)
  else
    let group_tree = validate_parsed_snapshot(value, account_id, device_id) ?
    let header = parsed_group_header(value) ?
    let context = group_storage_context(account_id,
    device_id,
    value.group_id,
    header,
    16,
    0,
    value.snapshot_version) ?
    let secret = case Secret.unseal_from_storage(value.sealed_epoch_secret, wrapping_key, context) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( output) -> Ok(output)
    end ?
    let leaf_private = unseal_group_private(value.sealed_leaf_private,
    wrapping_key,
    group_storage_context(account_id,
    device_id,
    value.group_id,
    header,
    17,
    1,
    value.snapshot_version) ?) ?
    let level0 = unseal_group_private(value.sealed_level0_private,
    wrapping_key,
    group_storage_context(account_id,
    device_id,
    value.group_id,
    header,
    17,
    2,
    value.snapshot_version) ?) ?
    let level1 = unseal_group_private(value.sealed_level1_private,
    wrapping_key,
    group_storage_context(account_id,
    device_id,
    value.group_id,
    header,
    17,
    3,
    value.snapshot_version) ?) ?
    let level2 = unseal_group_private(value.sealed_level2_private,
    wrapping_key,
    group_storage_context(account_id,
    device_id,
    value.group_id,
    header,
    17,
    4,
    value.snapshot_version) ?) ?
    let level3 = unseal_group_private(value.sealed_level3_private,
    wrapping_key,
    group_storage_context(account_id,
    device_id,
    value.group_id,
    header,
    17,
    5,
    value.snapshot_version) ?) ?
    let level4 = unseal_group_private(value.sealed_level4_private,
    wrapping_key,
    group_storage_context(account_id,
    device_id,
    value.group_id,
    header,
    17,
    6,
    value.snapshot_version) ?) ?
    let level5 = unseal_group_private(value.sealed_level5_private,
    wrapping_key,
    group_storage_context(account_id,
    device_id,
    value.group_id,
    header,
    17,
    7,
    value.snapshot_version) ?) ?
    let local_member = tree_member_error(member_at(group_tree, value.local_leaf)) ?
    validate_private_key(leaf_private, local_member.leaf_public_key) ?
    let path = tree_path_error(direct_path(value.local_leaf)) ?
    validate_parent_private(level0, value.parent_nodes, path, value.available_levels, 0) ?
    validate_parent_private(level1, value.parent_nodes, path, value.available_levels, 1) ?
    validate_parent_private(level2, value.parent_nodes, path, value.available_levels, 2) ?
    validate_parent_private(level3, value.parent_nodes, path, value.available_levels, 3) ?
    validate_parent_private(level4, value.parent_nodes, path, value.available_levels, 4) ?
    validate_parent_private(level5, value.parent_nodes, path, value.available_levels, 5) ?
    Ok(GroupState {
      version : value.version,
      suite : value.suite,
      group_id : value.group_id,
      epoch : value.epoch,
      tree : group_tree,
      tree_hash_cache : value.tree_hash,
      transcript_hash : value.transcript_hash,
      key_material : TreeKemKeyMaterial {
        epoch_secret : secret,
        leaf_private_key : leaf_private,
        level0_private_key : level0,
        level1_private_key : level1,
        level2_private_key : level2,
        level3_private_key : level3,
        level4_private_key : level4,
        level5_private_key : level5,
        available_levels : value.available_levels
      },
      local_leaf : value.local_leaf,
      next_generation : value.next_generation,
      received_generations : value.received_generations,
      extensions : value.extensions,
      policy : value.policy,
      snapshot_version : value.snapshot_version
    })
  end
end

fn hpke_info() -> Bytes do
  Bytes.from_utf8("mesh-mls/v1/path-secret")
end

fn path_aad(context :: Bytes, level :: Int, recipient_node :: Int) -> Bytes ! GroupError do
  join([context, byte(level) ?, write_u16(recipient_node) ?], 0, Bytes.empty())
end

fn welcome_context(context :: Bytes, extensions :: List < Int >, policy :: GroupTransparencyPolicy) -> Bytes ! GroupError do
  join([Bytes.from_utf8("mesh-mls/v1/welcome"), context, extensions_bytes(extensions) ?, policy_bytes(policy) ?],
  0,
  Bytes.empty())
end

fn destroy_private(value :: consume X25519PrivateKey) do
  nil
end

fn fresh_x25519() -> X25519KeyPair ! GroupError do
  case Crypto.x25519_generate() do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end
end

fn base_key_material(epoch_secret :: SecretBytes, leaf_private_key :: consume X25519PrivateKey) -> TreeKemKeyMaterial ! GroupError do
  let level0 = fresh_x25519() ?
  let level1 = fresh_x25519() ?
  let level2 = fresh_x25519() ?
  let level3 = fresh_x25519() ?
  let level4 = fresh_x25519() ?
  let level5 = fresh_x25519() ?
  Ok(TreeKemKeyMaterial {
    epoch_secret : epoch_secret,
    leaf_private_key : leaf_private_key,
    level0_private_key : level0.private_key,
    level1_private_key : level1.private_key,
    level2_private_key : level2.private_key,
    level3_private_key : level3.private_key,
    level4_private_key : level4.private_key,
    level5_private_key : level5.private_key,
    available_levels : List.new()
  })
end

fn derive_path_secret(value :: borrow SecretBytes) -> SecretBytes ! GroupError do
  case Crypto.hkdf_sha256(value, Bytes.empty(), Bytes.from_utf8("mesh-mls/v1/path"), 32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( secret) -> Ok(secret)
  end
end

fn derive_node_key(value :: borrow SecretBytes, node_index :: Int) -> X25519KeyPair ! GroupError do
  let info = append(Bytes.from_utf8("mesh-mls/v1/node"), write_u16(node_index) ?) ?
  let material = case Crypto.hkdf_sha256(value, Bytes.empty(), info, 32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( secret) -> Ok(secret)
  end ?
  case Crypto.x25519_from_secret(material) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( pair) -> Ok(pair)
  end
end

# ponytail: six explicit fields match the protocol's fixed 64-leaf ceiling; use a resource-aware vector if that ceiling grows.

fn generate_treekem_path(committer_leaf :: Int) -> GeneratedTreeKemPath ! GroupError do
  let path = tree_path_error(direct_path(committer_leaf)) ?
  let leaf = fresh_x25519() ?
  let secret0 = case Secret.random(32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end ?
  let secret1 = derive_path_secret(secret0) ?
  let secret2 = derive_path_secret(secret1) ?
  let secret3 = derive_path_secret(secret2) ?
  let secret4 = derive_path_secret(secret3) ?
  let secret5 = derive_path_secret(secret4) ?
  let key0 = derive_node_key(secret0, List.get(path, 0)) ?
  let key1 = derive_node_key(secret1, List.get(path, 1)) ?
  let key2 = derive_node_key(secret2, List.get(path, 2)) ?
  let key3 = derive_node_key(secret3, List.get(path, 3)) ?
  let key4 = derive_node_key(secret4, List.get(path, 4)) ?
  let key5 = derive_node_key(secret5, List.get(path, 5)) ?
  let leaf_public_key = leaf.public_key
  let key0_public = key0.public_key
  let key1_public = key1.public_key
  let key2_public = key2.public_key
  let key3_public = key3.public_key
  let key4_public = key4.public_key
  let key5_public = key5.public_key
  let placeholder_epoch = case Secret.random(32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end ?
  Ok(GeneratedTreeKemPath {
    key_material : TreeKemKeyMaterial {
      epoch_secret : placeholder_epoch,
      leaf_private_key : leaf.private_key,
      level0_private_key : key0.private_key,
      level1_private_key : key1.private_key,
      level2_private_key : key2.private_key,
      level3_private_key : key3.private_key,
      level4_private_key : key4.private_key,
      level5_private_key : key5.private_key,
      available_levels : [0, 1, 2, 3, 4, 5]
    },
    secret0 : secret0,
    secret1 : secret1,
    secret2 : secret2,
    secret3 : secret3,
    secret4 : secret4,
    secret5 : secret5,
    leaf_public_key : leaf_public_key,
    parents : [TreeKemParentNode {
      node_index : List.get(path, 0),
      public_key : key0_public,
      unmerged_leaves : List.new()
    }, TreeKemParentNode {
      node_index : List.get(path, 1),
      public_key : key1_public,
      unmerged_leaves : List.new()
    }, TreeKemParentNode {
      node_index : List.get(path, 2),
      public_key : key2_public,
      unmerged_leaves : List.new()
    }, TreeKemParentNode {
      node_index : List.get(path, 3),
      public_key : key3_public,
      unmerged_leaves : List.new()
    }, TreeKemParentNode {
      node_index : List.get(path, 4),
      public_key : key4_public,
      unmerged_leaves : List.new()
    }, TreeKemParentNode {
      node_index : List.get(path, 5),
      public_key : key5_public,
      unmerged_leaves : List.new()
    }]
  })
end

fn seal_path_secret(secret :: borrow SecretBytes,
level :: Int,
recipient_public_key :: X25519PublicKey,
context :: Bytes,
recipient_node :: Int) -> Bytes ! GroupError do
  case Crypto.hpke_seal_secret(recipient_public_key,
  hpke_info(),
  path_aad(context, level, recipient_node) ?,
  secret) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( sealed) -> Ok(sealed)
  end
end

fn seal_generated_secret(value :: borrow GeneratedTreeKemPath,
level :: Int,
recipient_public_key :: X25519PublicKey,
context :: Bytes,
recipient_node :: Int) -> Bytes ! GroupError do
  if level == 0 do
    seal_path_secret(value.secret0, level, recipient_public_key, context, recipient_node)
  else if level == 1 do
    seal_path_secret(value.secret1, level, recipient_public_key, context, recipient_node)
  else if level == 2 do
    seal_path_secret(value.secret2, level, recipient_public_key, context, recipient_node)
  else if level == 3 do
    seal_path_secret(value.secret3, level, recipient_public_key, context, recipient_node)
  else if level == 4 do
    seal_path_secret(value.secret4, level, recipient_public_key, context, recipient_node)
  else if level == 5 do
    seal_path_secret(value.secret5, level, recipient_public_key, context, recipient_node)
  else
    Err(InvalidGroup)
  end
end

fn seal_resolution(values :: List < TreeKemResolutionNode >,
index :: Int,
excluded_leaf :: Int,
generated :: borrow GeneratedTreeKemPath,
level :: Int,
context :: Bytes,
output :: List < TreeKemCiphertext >) -> List < TreeKemCiphertext > ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    if value.node_index == 63 + excluded_leaf do
      seal_resolution(values, index + 1, excluded_leaf, generated, level, context, output)
    else
      let sealed = seal_generated_secret(generated,
      level,
      value.public_key,
      context,
      value.node_index) ?
      seal_resolution(values,
      index + 1,
      excluded_leaf,
      generated,
      level,
      context,
      List.append(output,
      TreeKemCiphertext {
        recipient_node : value.node_index,
        sealed : sealed
      }))
    end
  end
end

fn seal_update_nodes(tree :: borrow GroupTree,
committer_leaf :: Int,
generated :: borrow GeneratedTreeKemPath,
excluded_leaf :: Int,
context :: Bytes,
level :: Int,
output :: List < TreeKemUpdateNode >) -> List < TreeKemUpdateNode > ! GroupError do
  if level >= 6 do
    Ok(output)
  else
    let copath_nodes = tree_path_error(copath(committer_leaf)) ?
    let recipients = tree_resolution_error(resolution(tree, List.get(copath_nodes, level))) ?
    let ciphertexts = seal_resolution(recipients,
    0,
    excluded_leaf,
    generated,
    level,
    context,
    List.new()) ?
    seal_update_nodes(tree,
    committer_leaf,
    generated,
    excluded_leaf,
    context,
    level + 1,
    List.append(output,
    TreeKemUpdateNode {
      parent : List.get(generated.parents, level),
      ciphertexts : ciphertexts
    }))
  end
end

fn next_epoch_secret(root :: borrow SecretBytes, context :: Bytes) -> SecretBytes ! GroupError do
  case Crypto.hkdf_sha256(root, Crypto.sha256(context), Bytes.from_utf8("mesh-mls/v1/epoch"), 32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end
end

fn finish_generated(value :: consume GeneratedTreeKemPath, epoch_secret :: SecretBytes) -> TreeKemKeyMaterial do
  let key_material = value.key_material
  % { key_material | epoch_secret : epoch_secret }
end

fn validate_members(values :: List < IndexedGroupMember >,
extensions :: List < Int >,
policy :: GroupTransparencyPolicy,
index :: Int) -> Result <(), GroupError > do
  if index >= List.length(values) do
    Ok(nil)
  else
    validate_member_policy(List.get(values, index).member, extensions, policy) ?
    validate_members(values, extensions, policy, index + 1)
  end
end

fn apply_proposal(tree :: GroupTree, proposal :: GroupProposal) -> GroupTree ! GroupError do
  case proposal do
    AddMember( leaf_index, member) -> case insert_member(tree, member) do
      Err( error) -> Err(TreeFailure(error))
      Ok( value) -> do
        let ( next, actual_leaf) = value
        if actual_leaf == leaf_index do
          Ok(next)
        else
          Err(InvalidGroup)
        end
      end
    end
    RemoveMember( leaf_index) -> case remove_member(tree, leaf_index) do
      Err( error) -> Err(TreeFailure(error))
      Ok( next) -> Ok(next)
    end
  end
end

fn verify_commit(value :: GroupCommit, prior_tree :: GroupTree) -> Result <(), GroupError > do
  let committer = case member_at(prior_tree, value.committer_leaf) do
    Err( error) -> Err(TreeFailure(error))
    Ok( member) -> Ok(member)
  end ?
  let valid = case Crypto.verify(committer.signing_public_key,
  commit_unsigned(value) ?,
  value.signature) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( result) -> Ok(result)
  end ?
  if valid do
    Ok(nil)
  else
    Err(AuthenticationRejected)
  end
end

fn initial_transcript(group_id :: Bytes,
tree :: GroupTree,
extensions :: List < Int >,
policy :: GroupTransparencyPolicy) -> Bytes ! GroupError do
  Ok(Crypto.sha256(join([Bytes.from_utf8("mesh-mls/v1/group"), group_id, tree_hash(tree), extensions_bytes(extensions) ?, policy_bytes(policy) ?],
  0,
  Bytes.empty()) ?))
end

pub fn create_group(creator :: GroupMember,
leaf_private_key :: consume X25519PrivateKey,
extensions :: List < Int >,
policy :: GroupTransparencyPolicy) -> GroupState ! GroupError do
  if !valid_extensions(extensions, 0, 0) do
    destroy_private(leaf_private_key)
    Err(InvalidGroup)
  else
    case validate_member_policy(creator, extensions, policy) do
      Err( error) -> do
        destroy_private(leaf_private_key)
        Err(error)
      end
      Ok( _) -> case Crypto.x25519_public(leaf_private_key) do
        Err( error) -> do
          destroy_private(leaf_private_key)
          Err(CryptoFailure(error))
        end
        Ok( public_key) -> if !Bytes.secure_equals(public_key.bytes, creator.leaf_public_key.bytes) do
          destroy_private(leaf_private_key)
          Err(AuthenticationRejected)
        else
          let group_id = case Crypto.random_bytes(32) do
            Err( error) -> Err(CryptoFailure(error))
            Ok( value) -> Ok(value)
          end ?
          let secret = case Secret.random(32) do
            Err( error) -> Err(CryptoFailure(error))
            Ok( value) -> Ok(value)
          end ?
          let inserted = case insert_member(case empty_tree() do
            Err( error) -> Err(TreeFailure(error))
            Ok( value) -> Ok(value)
          end ?,
          creator) do
            Err( error) -> Err(TreeFailure(error))
            Ok( value) -> Ok(value)
          end ?
          let ( tree, creator_leaf) = inserted
          if creator_leaf != 0 do
            destroy_private(leaf_private_key)
            Secret.destroy(secret)
            Err(InvalidGroup)
          else
            Ok(GroupState {
              version : 1,
              suite : 3,
              group_id : group_id,
              epoch : zero() ?,
              tree : tree,
              tree_hash_cache : tree_hash(tree),
              transcript_hash : initial_transcript(group_id, tree, extensions, policy) ?,
              key_material : base_key_material(secret, leaf_private_key) ?,
              local_leaf : 0,
              next_generation : 0,
              received_generations : List.new(),
              extensions : extensions,
              policy : policy,
              snapshot_version : zero() ?
            })
          end
        end
      end
    end
  end
end

fn prepare_add(state :: borrow GroupState,
signing_key :: borrow SigningPrivateKey,
member :: GroupMember) -> PreparedGroupAdd ! GroupError do
  validate_member_policy(member, state.extensions, state.policy) ?
  let inserted = case insert_member(state.tree, member) do
    Err( error) -> Err(TreeFailure(error))
    Ok( value) -> Ok(value)
  end ?
  let ( proposal_tree, recipient_leaf) = inserted
  let epoch = next_epoch(state.epoch) ?
  let proposal = AddMember(recipient_leaf, member)
  let generated = generate_treekem_path(state.local_leaf) ?
  let public_path = TreeKemUpdatePath {
    leaf_public_key : generated.leaf_public_key,
    nodes : public_update_nodes(generated.parents, 0, List.new())
  }
  let leaf_tree = tree_error(update_leaf_public_key(proposal_tree,
  state.local_leaf,
  generated.leaf_public_key)) ?
  let next_tree = tree_error(apply_update_path(leaf_tree, state.local_leaf, generated.parents)) ?
  let context = update_path_context(1,
  3,
  state.group_id,
  state.epoch,
  epoch,
  state.local_leaf,
  state.transcript_hash,
  tree_hash(next_tree),
  proposal,
  public_path) ?
  let update_path = TreeKemUpdatePath {
    leaf_public_key : generated.leaf_public_key,
    nodes : seal_update_nodes(proposal_tree,
    state.local_leaf,
    generated,
    recipient_leaf,
    context,
    0,
    List.new()) ?
  }
  let secret = next_epoch_secret(generated.secret5, context) ?
  let unsigned = GroupCommit {
    version : 1,
    suite : 3,
    group_id : state.group_id,
    prior_epoch : state.epoch,
    epoch : epoch,
    committer_leaf : state.local_leaf,
    prior_transcript_hash : state.transcript_hash,
    tree_hash : tree_hash(next_tree),
    proposal : proposal,
    update_path : update_path,
    signature : Signature { bytes : Bytes.empty() }
  }
  let signature = case Crypto.sign(signing_key, commit_unsigned(unsigned) ?) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end ?
  let commit = % { unsigned | signature : signature }
  verify_commit(commit, state.tree) ?
  let transcript_hash = Crypto.sha256(signed_commit_bytes(commit) ?)
  let level = joiner_level(state.local_leaf, recipient_leaf, 0) ?
  let join_context = welcome_context(context, state.extensions, state.policy) ?
  let joiner_secret = seal_generated_secret(generated,
  level,
  member.init_public_key,
  join_context,
  63 + recipient_leaf) ?
  let welcome = GroupWelcome {
    commit : commit,
    members : indexed_members(next_tree),
    extensions : state.extensions,
    policy : state.policy,
    recipient_leaf : recipient_leaf,
    parent_nodes : public_parent_nodes(next_tree),
    joiner_path_level : level,
    joiner_path_secret : joiner_secret
  }
  Ok(PreparedGroupAdd {
    tree : next_tree,
    key_material : finish_generated(generated, secret),
    commit : commit,
    welcome : welcome,
    transcript_hash : transcript_hash
  })
end

pub fn commit_add(state :: consume GroupState,
signing_key :: borrow SigningPrivateKey,
member :: GroupMember) -> GroupAddOutcome do
  case prepare_add(state, signing_key, member) do
    Err( error) -> GroupAddRejected(state, error)
    Ok( prepared) -> do
      let tree = prepared.tree
      let commit = prepared.commit
      let welcome = prepared.welcome
      let transcript_hash = prepared.transcript_hash
      let next = % { state | epoch : commit.epoch, tree : tree, tree_hash_cache : tree_hash(tree), transcript_hash : transcript_hash, key_material : prepared.key_material, next_generation : 0, received_generations : List.new() }
      GroupMemberAdded(next, commit, welcome)
    end
  end
end

fn prepare_remove(state :: borrow GroupState,
signing_key :: borrow SigningPrivateKey,
leaf_index :: Int) -> PreparedGroupRemove ! GroupError do
  if leaf_index == state.local_leaf do
    Err(InvalidMember)
  else
    let proposal_tree = case remove_member(state.tree, leaf_index) do
      Err( error) -> Err(TreeFailure(error))
      Ok( value) -> Ok(value)
    end ?
    let epoch = next_epoch(state.epoch) ?
    let proposal = RemoveMember(leaf_index)
    let generated = generate_treekem_path(state.local_leaf) ?
    let public_path = TreeKemUpdatePath {
      leaf_public_key : generated.leaf_public_key,
      nodes : public_update_nodes(generated.parents, 0, List.new())
    }
    let leaf_tree = tree_error(update_leaf_public_key(proposal_tree,
    state.local_leaf,
    generated.leaf_public_key)) ?
    let next_tree = tree_error(apply_update_path(leaf_tree, state.local_leaf, generated.parents)) ?
    let context = update_path_context(1,
    3,
    state.group_id,
    state.epoch,
    epoch,
    state.local_leaf,
    state.transcript_hash,
    tree_hash(next_tree),
    proposal,
    public_path) ?
    let update_path = TreeKemUpdatePath {
      leaf_public_key : generated.leaf_public_key,
      nodes : seal_update_nodes(proposal_tree,
      state.local_leaf,
      generated,
      -1,
      context,
      0,
      List.new()) ?
    }
    let secret = next_epoch_secret(generated.secret5, context) ?
    let unsigned = GroupCommit {
      version : 1,
      suite : 3,
      group_id : state.group_id,
      prior_epoch : state.epoch,
      epoch : epoch,
      committer_leaf : state.local_leaf,
      prior_transcript_hash : state.transcript_hash,
      tree_hash : tree_hash(next_tree),
      proposal : proposal,
      update_path : update_path,
      signature : Signature { bytes : Bytes.empty() }
    }
    let signature = case Crypto.sign(signing_key, commit_unsigned(unsigned) ?) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end ?
    let commit = % { unsigned | signature : signature }
    verify_commit(commit, state.tree) ?
    let transcript_hash = Crypto.sha256(signed_commit_bytes(commit) ?)
    Ok(PreparedGroupRemove {
      tree : next_tree,
      key_material : finish_generated(generated, secret),
      commit : commit,
      transcript_hash : transcript_hash
    })
  end
end

pub fn commit_remove(state :: consume GroupState,
signing_key :: borrow SigningPrivateKey,
leaf_index :: Int) -> GroupRemoveOutcome do
  case prepare_remove(state, signing_key, leaf_index) do
    Err( error) -> GroupRemoveRejected(state, error)
    Ok( prepared) -> do
      let tree = prepared.tree
      let commit = prepared.commit
      let transcript_hash = prepared.transcript_hash
      let next = % { state | epoch : commit.epoch, tree : tree, tree_hash_cache : tree_hash(tree), transcript_hash : transcript_hash, key_material : prepared.key_material, next_generation : 0, received_generations : List.new() }
      GroupMemberRemoved(next, commit)
    end
  end
end

fn has_level(values :: List < Int >, level :: Int, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if List.get(values, index) == level do
    true
  else
    has_level(values, level, index + 1)
  end
end

fn private_level_for_node(path :: borrow TreeKemKeyMaterial,
local_leaf :: Int,
node_index :: Int,
index :: Int) -> Int ! GroupError do
  if node_index == 63 + local_leaf do
    Ok(-1)
  else
    let nodes = tree_path_error(direct_path(local_leaf)) ?
    if index >= List.length(nodes) do
      Ok(-2)
    else if List.get(nodes, index) == node_index && has_level(path.available_levels, index, 0) do
      Ok(index)
    else
      private_level_for_node(path, local_leaf, node_index, index + 1)
    end
  end
end

fn open_with_private(path :: borrow TreeKemKeyMaterial,
private_level :: Int,
update_level :: Int,
context :: Bytes,
recipient_node :: Int,
sealed :: Bytes) -> SecretBytes ! GroupError do
  if private_level == -1 do
    case Crypto.hpke_open_secret(path.leaf_private_key,
    hpke_info(),
    path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else if private_level == 0 do
    case Crypto.hpke_open_secret(path.level0_private_key,
    hpke_info(),
    path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else if private_level == 1 do
    case Crypto.hpke_open_secret(path.level1_private_key,
    hpke_info(),
    path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else if private_level == 2 do
    case Crypto.hpke_open_secret(path.level2_private_key,
    hpke_info(),
    path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else if private_level == 3 do
    case Crypto.hpke_open_secret(path.level3_private_key,
    hpke_info(),
    path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else if private_level == 4 do
    case Crypto.hpke_open_secret(path.level4_private_key,
    hpke_info(),
    path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else if private_level == 5 do
    case Crypto.hpke_open_secret(path.level5_private_key,
    hpke_info(),
    path_aad(context, update_level, recipient_node) ?,
    sealed) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end
  else
    Err(RemovedMember)
  end
end

fn open_level_ciphertexts(values :: List < TreeKemCiphertext >,
index :: Int,
path :: borrow TreeKemKeyMaterial,
local_leaf :: Int,
update_level :: Int,
context :: Bytes) -> OpenedPathSecret ! GroupError do
  if index >= List.length(values) do
    Err(RemovedMember)
  else
    let value = List.get(values, index)
    let private_level = private_level_for_node(path, local_leaf, value.recipient_node, 0) ?
    if private_level < -1 do
      open_level_ciphertexts(values, index + 1, path, local_leaf, update_level, context)
    else
      Ok(OpenedPathSecret {
        secret : open_with_private(path,
        private_level,
        update_level,
        context,
        value.recipient_node,
        value.sealed) ?,
        level : update_level
      })
    end
  end
end

fn open_update_path(values :: List < TreeKemUpdateNode >,
level :: Int,
path :: borrow TreeKemKeyMaterial,
local_leaf :: Int,
context :: Bytes) -> OpenedPathSecret ! GroupError do
  if level >= List.length(values) do
    Err(RemovedMember)
  else
    case open_level_ciphertexts(List.get(values, level).ciphertexts,
    0,
    path,
    local_leaf,
    level,
    context) do
      Err( RemovedMember) -> open_update_path(values, level + 1, path, local_leaf, context)
      Err( error) -> Err(error)
      Ok( opened) -> Ok(opened)
    end
  end
end

fn expected_recipient_nodes(values :: List < TreeKemResolutionNode >,
index :: Int,
excluded_leaf :: Int,
output :: List < Int >) -> List < Int > do
  if index >= List.length(values) do
    output
  else
    let value = List.get(values, index)
    if value.node_index == 63 + excluded_leaf do
      expected_recipient_nodes(values, index + 1, excluded_leaf, output)
    else
      expected_recipient_nodes(values,
      index + 1,
      excluded_leaf,
      List.append(output, value.node_index))
    end
  end
end

fn validate_ciphertext_recipients(values :: List < TreeKemCiphertext >,
expected :: List < Int >,
index :: Int) -> Result <(), GroupError > do
  if List.length(values) != List.length(expected) do
    Err(AuthenticationRejected)
  else if index >= List.length(values) do
    Ok(nil)
  else if List.get(values, index).recipient_node != List.get(expected, index) do
    Err(AuthenticationRejected)
  else
    validate_ciphertext_recipients(values, expected, index + 1)
  end
end

fn validate_update_recipients(tree :: borrow GroupTree,
committer_leaf :: Int,
update_path :: TreeKemUpdatePath,
excluded_leaf :: Int,
level :: Int) -> Result <(), GroupError > do
  if level >= 6 do
    Ok(nil)
  else
    let copath_nodes = tree_path_error(copath(committer_leaf)) ?
    let recipients = tree_resolution_error(resolution(tree, List.get(copath_nodes, level))) ?
    let expected = expected_recipient_nodes(recipients, 0, excluded_leaf, List.new())
    validate_ciphertext_recipients(List.get(update_path.nodes, level).ciphertexts, expected, 0) ?
    validate_update_recipients(tree, committer_leaf, update_path, excluded_leaf, level + 1)
  end
end

fn transition_tree(prior_tree :: GroupTree, commit :: GroupCommit) -> GroupTree ! GroupError do
  let proposal_tree = apply_proposal(prior_tree, commit.proposal) ?
  let excluded = case commit.proposal do
    AddMember( leaf, _) -> leaf
    RemoveMember( _) -> -1
  end
  validate_update_recipients(proposal_tree, commit.committer_leaf, commit.update_path, excluded, 0) ?
  let leaf_tree = tree_error(update_leaf_public_key(proposal_tree,
  commit.committer_leaf,
  commit.update_path.leaf_public_key)) ?
  let next_tree = tree_error(apply_update_path(leaf_tree,
  commit.committer_leaf,
  update_parents(commit.update_path.nodes, 0, List.new()))) ?
  if Bytes.secure_equals(tree_hash(next_tree), commit.tree_hash) do
    Ok(next_tree)
  else
    Err(AuthenticationRejected)
  end
end

fn dummy_private() -> X25519PrivateKey ! GroupError do
  Ok((fresh_x25519() ?).private_key)
end

fn build_patch0(secret0 :: SecretBytes, nodes :: List < TreeKemUpdateNode >, context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let secret1 = derive_path_secret(secret0) ?
  let secret2 = derive_path_secret(secret1) ?
  let secret3 = derive_path_secret(secret2) ?
  let secret4 = derive_path_secret(secret3) ?
  let secret5 = derive_path_secret(secret4) ?
  let key0 = derive_node_key(secret0, List.get(nodes, 0).parent.node_index) ?
  let key1 = derive_node_key(secret1, List.get(nodes, 1).parent.node_index) ?
  let key2 = derive_node_key(secret2, List.get(nodes, 2).parent.node_index) ?
  let key3 = derive_node_key(secret3, List.get(nodes, 3).parent.node_index) ?
  let key4 = derive_node_key(secret4, List.get(nodes, 4).parent.node_index) ?
  let key5 = derive_node_key(secret5, List.get(nodes, 5).parent.node_index) ?
  let epoch_secret = next_epoch_secret(secret5, context) ?
  Secret.destroy(secret0)
  Secret.destroy(secret1)
  Secret.destroy(secret2)
  Secret.destroy(secret3)
  Secret.destroy(secret4)
  Secret.destroy(secret5)
  if !Bytes.secure_equals(key0.public_key.bytes, List.get(nodes, 0).parent.public_key.bytes) || !Bytes.secure_equals(key1.public_key.bytes,
  List.get(nodes, 1).parent.public_key.bytes) || !Bytes.secure_equals(key2.public_key.bytes,
  List.get(nodes, 2).parent.public_key.bytes) || !Bytes.secure_equals(key3.public_key.bytes,
  List.get(nodes, 3).parent.public_key.bytes) || !Bytes.secure_equals(key4.public_key.bytes,
  List.get(nodes, 4).parent.public_key.bytes) || !Bytes.secure_equals(key5.public_key.bytes,
  List.get(nodes, 5).parent.public_key.bytes) do
    Err(AuthenticationRejected)
  else
    Ok(TreeKemPatch0(epoch_secret,
    key0.private_key,
    key1.private_key,
    key2.private_key,
    key3.private_key,
    key4.private_key,
    key5.private_key))
  end
end

fn build_patch1(secret1 :: SecretBytes, nodes :: List < TreeKemUpdateNode >, context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let secret2 = derive_path_secret(secret1) ?
  let secret3 = derive_path_secret(secret2) ?
  let secret4 = derive_path_secret(secret3) ?
  let secret5 = derive_path_secret(secret4) ?
  let key1 = derive_node_key(secret1, List.get(nodes, 1).parent.node_index) ?
  let key2 = derive_node_key(secret2, List.get(nodes, 2).parent.node_index) ?
  let key3 = derive_node_key(secret3, List.get(nodes, 3).parent.node_index) ?
  let key4 = derive_node_key(secret4, List.get(nodes, 4).parent.node_index) ?
  let key5 = derive_node_key(secret5, List.get(nodes, 5).parent.node_index) ?
  let epoch_secret = next_epoch_secret(secret5, context) ?
  Secret.destroy(secret1)
  Secret.destroy(secret2)
  Secret.destroy(secret3)
  Secret.destroy(secret4)
  Secret.destroy(secret5)
  if !Bytes.secure_equals(key1.public_key.bytes, List.get(nodes, 1).parent.public_key.bytes) || !Bytes.secure_equals(key2.public_key.bytes,
  List.get(nodes, 2).parent.public_key.bytes) || !Bytes.secure_equals(key3.public_key.bytes,
  List.get(nodes, 3).parent.public_key.bytes) || !Bytes.secure_equals(key4.public_key.bytes,
  List.get(nodes, 4).parent.public_key.bytes) || !Bytes.secure_equals(key5.public_key.bytes,
  List.get(nodes, 5).parent.public_key.bytes) do
    Err(AuthenticationRejected)
  else
    Ok(TreeKemPatch1(epoch_secret,
    key1.private_key,
    key2.private_key,
    key3.private_key,
    key4.private_key,
    key5.private_key))
  end
end

fn build_patch2(secret2 :: SecretBytes, nodes :: List < TreeKemUpdateNode >, context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let secret3 = derive_path_secret(secret2) ?
  let secret4 = derive_path_secret(secret3) ?
  let secret5 = derive_path_secret(secret4) ?
  let key2 = derive_node_key(secret2, List.get(nodes, 2).parent.node_index) ?
  let key3 = derive_node_key(secret3, List.get(nodes, 3).parent.node_index) ?
  let key4 = derive_node_key(secret4, List.get(nodes, 4).parent.node_index) ?
  let key5 = derive_node_key(secret5, List.get(nodes, 5).parent.node_index) ?
  let epoch_secret = next_epoch_secret(secret5, context) ?
  Secret.destroy(secret2)
  Secret.destroy(secret3)
  Secret.destroy(secret4)
  Secret.destroy(secret5)
  if !Bytes.secure_equals(key2.public_key.bytes, List.get(nodes, 2).parent.public_key.bytes) || !Bytes.secure_equals(key3.public_key.bytes,
  List.get(nodes, 3).parent.public_key.bytes) || !Bytes.secure_equals(key4.public_key.bytes,
  List.get(nodes, 4).parent.public_key.bytes) || !Bytes.secure_equals(key5.public_key.bytes,
  List.get(nodes, 5).parent.public_key.bytes) do
    Err(AuthenticationRejected)
  else
    Ok(TreeKemPatch2(epoch_secret,
    key2.private_key,
    key3.private_key,
    key4.private_key,
    key5.private_key))
  end
end

fn build_patch3(secret3 :: SecretBytes, nodes :: List < TreeKemUpdateNode >, context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let secret4 = derive_path_secret(secret3) ?
  let secret5 = derive_path_secret(secret4) ?
  let key3 = derive_node_key(secret3, List.get(nodes, 3).parent.node_index) ?
  let key4 = derive_node_key(secret4, List.get(nodes, 4).parent.node_index) ?
  let key5 = derive_node_key(secret5, List.get(nodes, 5).parent.node_index) ?
  let epoch_secret = next_epoch_secret(secret5, context) ?
  Secret.destroy(secret3)
  Secret.destroy(secret4)
  Secret.destroy(secret5)
  if !Bytes.secure_equals(key3.public_key.bytes, List.get(nodes, 3).parent.public_key.bytes) || !Bytes.secure_equals(key4.public_key.bytes,
  List.get(nodes, 4).parent.public_key.bytes) || !Bytes.secure_equals(key5.public_key.bytes,
  List.get(nodes, 5).parent.public_key.bytes) do
    Err(AuthenticationRejected)
  else
    Ok(TreeKemPatch3(epoch_secret, key3.private_key, key4.private_key, key5.private_key))
  end
end

fn build_patch4(secret4 :: SecretBytes, nodes :: List < TreeKemUpdateNode >, context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let secret5 = derive_path_secret(secret4) ?
  let key4 = derive_node_key(secret4, List.get(nodes, 4).parent.node_index) ?
  let key5 = derive_node_key(secret5, List.get(nodes, 5).parent.node_index) ?
  let epoch_secret = next_epoch_secret(secret5, context) ?
  Secret.destroy(secret4)
  Secret.destroy(secret5)
  if !Bytes.secure_equals(key4.public_key.bytes, List.get(nodes, 4).parent.public_key.bytes) || !Bytes.secure_equals(key5.public_key.bytes,
  List.get(nodes, 5).parent.public_key.bytes) do
    Err(AuthenticationRejected)
  else
    Ok(TreeKemPatch4(epoch_secret, key4.private_key, key5.private_key))
  end
end

fn build_patch5(secret5 :: SecretBytes, nodes :: List < TreeKemUpdateNode >, context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let key5 = derive_node_key(secret5, List.get(nodes, 5).parent.node_index) ?
  let epoch_secret = next_epoch_secret(secret5, context) ?
  Secret.destroy(secret5)
  if !Bytes.secure_equals(key5.public_key.bytes, List.get(nodes, 5).parent.public_key.bytes) do
    Err(AuthenticationRejected)
  else
    Ok(TreeKemPatch5(epoch_secret, key5.private_key))
  end
end

fn derive_verified_patch(secret :: SecretBytes,
start_level :: Int,
nodes :: List < TreeKemUpdateNode >,
context :: Bytes) -> TreeKemPathPatch ! GroupError do
  let patch = if start_level == 0 do
    build_patch0(secret, nodes, context) ?
  else if start_level == 1 do
    build_patch1(secret, nodes, context) ?
  else if start_level == 2 do
    build_patch2(secret, nodes, context) ?
  else if start_level == 3 do
    build_patch3(secret, nodes, context) ?
  else if start_level == 4 do
    build_patch4(secret, nodes, context) ?
  else if start_level == 5 do
    build_patch5(secret, nodes, context) ?
  else
    Err(InvalidGroup) ?
  end
  Ok(patch)
end

fn preserved_levels(values :: List < Int >,
start_level :: Int,
index :: Int,
output :: List < Int >) -> List < Int > do
  if index >= List.length(values) do
    output
  else
    let level = List.get(values, index)
    if level < start_level do
      preserved_levels(values, start_level, index + 1, List.append(output, level))
    else
      preserved_levels(values, start_level, index + 1, output)
    end
  end
end

fn append_levels(start_level :: Int, output :: List < Int >) -> List < Int > do
  if start_level >= 6 do
    output
  else
    append_levels(start_level + 1, List.append(output, start_level))
  end
end

fn merge_key_material(base :: consume TreeKemKeyMaterial, patch :: consume TreeKemPathPatch) -> TreeKemKeyMaterial do
  case patch do
    TreeKemPatch0( epoch_secret, level0, level1, level2, level3, level4, level5) -> % { base | epoch_secret : epoch_secret, level0_private_key : level0, level1_private_key : level1, level2_private_key : level2, level3_private_key : level3, level4_private_key : level4, level5_private_key : level5, available_levels : [0, 1, 2, 3, 4, 5] }
    TreeKemPatch1( epoch_secret, level1, level2, level3, level4, level5) -> do
      let levels = append_levels(1, preserved_levels(base.available_levels, 1, 0, List.new()))
      % { base | epoch_secret : epoch_secret, level1_private_key : level1, level2_private_key : level2, level3_private_key : level3, level4_private_key : level4, level5_private_key : level5, available_levels : levels }
    end
    TreeKemPatch2( epoch_secret, level2, level3, level4, level5) -> do
      let levels = append_levels(2, preserved_levels(base.available_levels, 2, 0, List.new()))
      % { base | epoch_secret : epoch_secret, level2_private_key : level2, level3_private_key : level3, level4_private_key : level4, level5_private_key : level5, available_levels : levels }
    end
    TreeKemPatch3( epoch_secret, level3, level4, level5) -> do
      let levels = append_levels(3, preserved_levels(base.available_levels, 3, 0, List.new()))
      % { base | epoch_secret : epoch_secret, level3_private_key : level3, level4_private_key : level4, level5_private_key : level5, available_levels : levels }
    end
    TreeKemPatch4( epoch_secret, level4, level5) -> do
      let levels = append_levels(4, preserved_levels(base.available_levels, 4, 0, List.new()))
      % { base | epoch_secret : epoch_secret, level4_private_key : level4, level5_private_key : level5, available_levels : levels }
    end
    TreeKemPatch5( epoch_secret, level5) -> do
      let levels = append_levels(5, preserved_levels(base.available_levels, 5, 0, List.new()))
      % { base | epoch_secret : epoch_secret, level5_private_key : level5, available_levels : levels }
    end
  end
end

fn prepare_join(welcome :: GroupWelcome,
init_private_key :: borrow X25519PrivateKey,
leaf_public_key :: X25519PublicKey) -> PreparedJoin ! GroupError do
  validate_welcome_shape(welcome) ?
  if welcome.commit.version != 1 || welcome.commit.suite != 3 || Bytes.length(welcome.commit.group_id) != 32 || !valid_extensions(welcome.extensions,
  0,
  0) do
    Err(InvalidGroup)
  else
    validate_policy(welcome.policy) ?
    validate_members(welcome.members, welcome.extensions, welcome.policy, 0) ?
    let tree = tree_error(tree_from_public(welcome.members, welcome.parent_nodes)) ?
    verify_commit(welcome.commit, tree) ?
    if !Bytes.secure_equals(tree_hash(tree), welcome.commit.tree_hash) do
      Err(AuthenticationRejected)
    else
      let init_public_key = case Crypto.x25519_public(init_private_key) do
        Err( error) -> Err(CryptoFailure(error))
        Ok( value) -> Ok(value)
      end ?
      let recipient = tree_member_error(member_at(tree, welcome.recipient_leaf)) ?
      if !Bytes.secure_equals(recipient.init_public_key.bytes, init_public_key.bytes) || !Bytes.secure_equals(recipient.leaf_public_key.bytes,
      leaf_public_key.bytes) do
        Err(AuthenticationRejected)
      else
        let context = update_path_context(welcome.commit.version,
        welcome.commit.suite,
        welcome.commit.group_id,
        welcome.commit.prior_epoch,
        welcome.commit.epoch,
        welcome.commit.committer_leaf,
        welcome.commit.prior_transcript_hash,
        welcome.commit.tree_hash,
        welcome.commit.proposal,
        welcome.commit.update_path) ?
        let path_secret = case Crypto.hpke_open_secret(init_private_key,
        hpke_info(),
        path_aad(welcome_context(context, welcome.extensions, welcome.policy) ?,
        welcome.joiner_path_level,
        63 + welcome.recipient_leaf) ?,
        welcome.joiner_path_secret) do
          Err( error) -> Err(CryptoFailure(error))
          Ok( value) -> Ok(value)
        end ?
        Ok(PreparedJoin {
          tree : tree,
          path_secret : path_secret,
          path_level : welcome.joiner_path_level,
          context : context
        })
      end
    end
  end
end

pub fn join_from_welcome(welcome :: GroupWelcome,
init_private_key :: borrow X25519PrivateKey,
leaf_private_key :: consume X25519PrivateKey) -> GroupState ! GroupError do
  case Crypto.x25519_public(leaf_private_key) do
    Err( error) -> do
      destroy_private(leaf_private_key)
      Err(CryptoFailure(error))
    end
    Ok( leaf_public_key) -> do
      case prepare_join(welcome, init_private_key, leaf_public_key) do
        Err( error) -> do
          destroy_private(leaf_private_key)
          Err(error)
        end
        Ok( prepared) -> do
          let tree = prepared.tree
          let path_level = prepared.path_level
          let context = prepared.context
          let placeholder_epoch = case Secret.random(32) do
            Err( error) -> Err(CryptoFailure(error))
            Ok( value) -> Ok(value)
          end ?
          let base = base_key_material(placeholder_epoch, leaf_private_key) ?
          let patch = derive_verified_patch(prepared.path_secret,
          path_level,
          welcome.commit.update_path.nodes,
          context) ?
          Ok(GroupState {
            version : 1,
            suite : 3,
            group_id : welcome.commit.group_id,
            epoch : welcome.commit.epoch,
            tree : tree,
            tree_hash_cache : welcome.commit.tree_hash,
            transcript_hash : Crypto.sha256(signed_commit_bytes(welcome.commit) ?),
            key_material : merge_key_material(base, patch),
            local_leaf : welcome.recipient_leaf,
            next_generation : 0,
            received_generations : List.new(),
            extensions : welcome.extensions,
            policy : welcome.policy,
            snapshot_version : zero() ?
          })
        end
      end
    end
  end
end

fn apply_verified_commit(state :: borrow GroupState, commit :: GroupCommit) -> PreparedAppliedCommit ! GroupError do
  validate_commit_shape(commit) ?
  if commit.version != 1 || commit.suite != state.suite || !Bytes.secure_equals(commit.group_id,
  state.group_id) do
    Err(AuthenticationRejected)
  else if U64.compare(commit.prior_epoch, state.epoch) < 0 do
    Err(StaleEpoch)
  else if U64.compare(commit.prior_epoch, state.epoch) > 0 do
    Err(FutureEpoch)
  else if U64.compare(commit.epoch, next_epoch(state.epoch) ?) != 0 do
    Err(FutureEpoch)
  else if !Bytes.secure_equals(commit.prior_transcript_hash, state.transcript_hash) do
    Err(AuthenticationRejected)
  else
    verify_commit(commit, state.tree) ?
    let next_tree = transition_tree(state.tree, commit) ?
    let next_members = indexed_members(next_tree)
    validate_members(next_members, state.extensions, state.policy, 0) ?
    case member_at(next_tree, state.local_leaf) do
      Err( _) -> Err(RemovedMember)
      Ok( _) -> do
        let context = update_path_context(commit.version,
        commit.suite,
        commit.group_id,
        commit.prior_epoch,
        commit.epoch,
        commit.committer_leaf,
        commit.prior_transcript_hash,
        commit.tree_hash,
        commit.proposal,
        commit.update_path) ?
        Ok(PreparedAppliedCommit {
          tree : next_tree,
          context : context
        })
      end
    end
  end
end

pub fn apply_commit(state :: consume GroupState, commit :: GroupCommit) -> CommitApplyOutcome do
  case apply_verified_commit(state, commit) do
    Err( error) -> CommitRejected(state, error)
    Ok( prepared) -> case signed_commit_bytes(commit) do
      Err( error) -> CommitRejected(state, error)
      Ok( signed) -> case open_update_path(commit.update_path.nodes,
      0,
      state.key_material,
      state.local_leaf,
      prepared.context) do
        Err( error) -> CommitRejected(state, error)
        Ok( opened) -> do
          let opened_level = opened.level
          case derive_verified_patch(opened.secret,
          opened_level,
          commit.update_path.nodes,
          prepared.context) do
            Err( error) -> CommitRejected(state, error)
            Ok( patch) -> do
              let version = state.version
              let suite = state.suite
              let group_id = state.group_id
              let local_leaf = state.local_leaf
              let extensions = state.extensions
              let policy = state.policy
              let snapshot_version = state.snapshot_version
              CommitApplied(GroupState {
                version : version,
                suite : suite,
                group_id : group_id,
                epoch : commit.epoch,
                tree : prepared.tree,
                tree_hash_cache : commit.tree_hash,
                transcript_hash : Crypto.sha256(signed),
                key_material : merge_key_material(state.key_material, patch),
                local_leaf : local_leaf,
                next_generation : 0,
                received_generations : List.new(),
                extensions : extensions,
                policy : policy,
                snapshot_version : snapshot_version
              })
            end
          end
        end
      end
    end
  end
end

fn message_context(suite :: Int,
group_id :: Bytes,
epoch :: U64,
current_tree_hash :: Bytes,
sender_leaf :: Int,
generation :: Int,
nonce :: Bytes,
caller_data :: Bytes) -> Bytes ! GroupError do
  join([Bytes.from_utf8("mesh-mls/v1/group-message"), byte(1) ?, write_u16(suite) ?, group_id, write_u64(epoch) ?, current_tree_hash, write_u16(sender_leaf) ?, write_u32(generation) ?, nonce, caller_data],
  0,
  Bytes.empty())
end

fn message_info(sender_leaf :: Int, generation :: Int) -> Bytes ! GroupError do
  join([Bytes.from_utf8("mesh-mls/v1/message-key"), write_u16(sender_leaf) ?, write_u32(generation) ?],
  0,
  Bytes.empty())
end

fn message_key(material :: SecretBytes) -> AeadKey ! GroupError do
  case Crypto.aead_key(material) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end
end

fn consume_message_key(key :: consume AeadKey) do
  nil
end

fn signed_message_bytes(message :: GroupMessage, context :: Bytes) -> Bytes ! GroupError do
  join([context, vector(message.ciphertext) ?], 0, Bytes.empty())
end

fn tree_message_context(tree :: borrow GroupTree, sender_leaf :: Int) -> TreeMessageContext ! GroupError do
  let sender = case member_at(tree, sender_leaf) do
    Err( error) -> Err(TreeFailure(error))
    Ok( value) -> Ok(value)
  end ?
  Ok(TreeMessageContext {
    hash : tree_hash(tree),
    sender : sender
  })
end

fn open_message_context(state :: borrow GroupState, message :: GroupMessage) -> OpenMessageContext ! GroupError do
  let suite = state.suite
  let group_id = state.group_id
  let epoch = state.epoch
  let last_generation = received_generation(state.received_generations, message.sender_leaf, 0)
  Ok(OpenMessageContext {
    suite : suite,
    group_id : group_id,
    epoch : epoch,
    last_generation : last_generation,
    tree : tree_message_context(state.tree, message.sender_leaf) ?
  })
end

fn seal_epoch_message(signing_key :: borrow SigningPrivateKey,
plaintext :: Bytes,
nonce :: Bytes,
info :: Bytes,
context :: Bytes,
metadata :: EncryptMessageContext,
secret :: borrow SecretBytes) -> GroupMessage ! GroupError do
  case Crypto.hkdf_sha256(secret, metadata.group_id, info, 32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( material) -> case message_key(material) do
      Err( error) -> Err(error)
      Ok( key) -> do
        let sealed = Crypto.aead_seal(key, nonce, context, plaintext)
        consume_message_key(key)
        case sealed do
          Err( error) -> Err(CryptoFailure(error))
          Ok( ciphertext) -> do
            let unsigned = GroupMessage {
              version : 1,
              suite : metadata.suite,
              group_id : metadata.group_id,
              epoch : metadata.epoch,
              tree_hash : metadata.tree_hash,
              sender_leaf : metadata.sender_leaf,
              generation : metadata.generation,
              nonce : nonce,
              ciphertext : ciphertext,
              signature : Signature { bytes : Bytes.empty() }
            }
            case signed_message_bytes(unsigned, context) do
              Err( error) -> Err(error)
              Ok( unsigned_bytes) -> case Crypto.sign(signing_key, unsigned_bytes) do
                Err( error) -> Err(CryptoFailure(error))
                Ok( signature) -> Ok(% { unsigned | signature : signature })
              end
            end
          end
        end
      end
    end
  end
end

fn prepare_group_message(state :: borrow GroupState,
signing_key :: borrow SigningPrivateKey,
plaintext :: Bytes,
caller_data :: Bytes) -> GroupMessage ! GroupError do
  if Bytes.length(plaintext) > 65520 || Bytes.length(caller_data) > 4096 || state.next_generation < 0 || state.next_generation >= 4294967295 do
    Err(InvalidGroup)
  else
    let nonce = case Crypto.random_bytes(12) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end ?
    let metadata = EncryptMessageContext {
      suite : state.suite,
      group_id : state.group_id,
      epoch : state.epoch,
      tree_hash : state.tree_hash_cache,
      sender_leaf : state.local_leaf,
      generation : state.next_generation
    }
    let info = message_info(metadata.sender_leaf, metadata.generation) ?
    let context = message_context(metadata.suite,
    metadata.group_id,
    metadata.epoch,
    metadata.tree_hash,
    metadata.sender_leaf,
    metadata.generation,
    nonce,
    caller_data) ?
    let message = seal_epoch_message(signing_key,
    plaintext,
    nonce,
    info,
    context,
    metadata,
    state.key_material.epoch_secret) ?
    let sender = case member_at(state.tree, state.local_leaf) do
      Err( error) -> Err(TreeFailure(error))
      Ok( value) -> Ok(value)
    end ?
    let signed = signed_message_bytes(message, context) ?
    case Crypto.verify(sender.signing_public_key, signed, message.signature) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( false) -> Err(AuthenticationRejected)
      Ok( true) -> Ok(message)
    end
  end
end

pub fn encrypt_group_message(state :: consume GroupState,
signing_key :: borrow SigningPrivateKey,
plaintext :: Bytes,
caller_data :: Bytes) -> GroupEncryptOutcome do
  case prepare_group_message(state, signing_key, plaintext, caller_data) do
    Err( error) -> GroupEncryptRejected(state, error)
    Ok( message) -> do
      let next_generation = state.next_generation + 1
      GroupMessageEncrypted(% { state | next_generation : next_generation }, message)
    end
  end
end

fn received_generation(values :: List < SenderGeneration >, leaf_index :: Int, index :: Int) -> Int do
  if index >= List.length(values) do
    -1
  else
    let value = List.get(values, index)
    if value.leaf_index == leaf_index do
      value.generation
    else
      received_generation(values, leaf_index, index + 1)
    end
  end
end

fn record_generation(values :: List < SenderGeneration >,
leaf_index :: Int,
generation :: Int,
index :: Int,
output :: List < SenderGeneration >) -> List < SenderGeneration > do
  if index >= List.length(values) do
    if received_generation(values, leaf_index, 0) < 0 do
      List.append(output,
      SenderGeneration {
        leaf_index : leaf_index,
        generation : generation
      })
    else
      output
    end
  else
    let value = List.get(values, index)
    let next = if value.leaf_index == leaf_index do
      SenderGeneration {
        leaf_index : leaf_index,
        generation : generation
      }
    else
      value
    end
    record_generation(values, leaf_index, generation, index + 1, List.append(output, next))
  end
end

pub fn decrypt_group_message(state :: consume GroupState,
message :: GroupMessage,
caller_data :: Bytes) -> GroupDecryptOutcome do
  case open_message_context(state, message) do
    Err( error) -> MessageRejected(state, error)
    Ok( public) -> do
      let wrong_header = message.version != 1 || message.suite != public.suite || !Bytes.secure_equals(message.group_id,
      public.group_id) || U64.compare(message.epoch, public.epoch) != 0 || !Bytes.secure_equals(message.tree_hash,
      public.tree.hash) || message.sender_leaf < 0 || message.sender_leaf >= 64 || message.generation < 0 || Bytes.length(message.nonce) != 12 || Bytes.length(message.ciphertext) < 16 || Bytes.length(message.ciphertext) > 65536 || Bytes.length(caller_data) > 4096
      if wrong_header do
        MessageRejected(state, InvalidGroup)
      else if message.generation <= public.last_generation do
        MessageRejected(state, Replay)
      else
        case message_context(public.suite,
        public.group_id,
        public.epoch,
        public.tree.hash,
        message.sender_leaf,
        message.generation,
        message.nonce,
        caller_data) do
          Err( error) -> MessageRejected(state, error)
          Ok( context) -> case signed_message_bytes(message, context) do
            Err( error) -> MessageRejected(state, error)
            Ok( signed) -> case Crypto.verify(public.tree.sender.signing_public_key,
            signed,
            message.signature) do
              Err( error) -> MessageRejected(state, CryptoFailure(error))
              Ok( false) -> MessageRejected(state, AuthenticationRejected)
              Ok( true) -> case message_info(message.sender_leaf, message.generation) do
                Err( error) -> MessageRejected(state, error)
                Ok( info) -> case Crypto.hkdf_sha256(state.key_material.epoch_secret,
                public.group_id,
                info,
                32) do
                  Err( error) -> MessageRejected(state, CryptoFailure(error))
                  Ok( material) -> case message_key(material) do
                    Err( error) -> MessageRejected(state, error)
                    Ok( key) -> do
                      let opened = Crypto.aead_open(key, message.nonce, context, message.ciphertext)
                      consume_message_key(key)
                      case opened do
                        Err( error) -> MessageRejected(state, CryptoFailure(error))
                        Ok( plaintext) -> do
                          let generations = record_generation(state.received_generations,
                          message.sender_leaf,
                          message.generation,
                          0,
                          List.new())
                          MessageOpened(% { state | received_generations : generations }, plaintext)
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end

# ponytail: sender replay tracking is a 64-entry scan; use an indexed persistent map if the fixed group cap grows.
