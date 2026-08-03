from Binary.Reader import BinaryReader, finish, read_fixed, read_u16_be, read_u8, read_vector, reader
from Groups.Tree import GroupMember, GroupTree, GroupTreeError, IndexedGroupMember, empty_tree, encode_member, indexed_members, insert_member, member_at, remove_member, tree_from_members, tree_hash, validate_member

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

pub struct WrappedEpochSecret do
  leaf_index :: Int
  sealed :: Bytes
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
  wrapped_secrets :: List < WrappedEpochSecret >
  signature :: Signature
end

pub struct GroupWelcome do
  commit :: GroupCommit
  members :: List < IndexedGroupMember >
  extensions :: List < Int >
  policy :: GroupTransparencyPolicy
  recipient_leaf :: Int
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

pub resource struct GroupState do
  version :: Int
  suite :: Int
  group_id :: Bytes
  epoch :: U64
  tree :: GroupTree
  tree_hash_cache :: Bytes
  transcript_hash :: Bytes
  epoch_secret :: SecretBytes
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

struct GroupReadWrapped do
  state :: BinaryReader
  value :: List < WrappedEpochSecret >
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
  received_generations :: List < SenderGeneration >
  extensions :: List < Int >
  policy :: GroupTransparencyPolicy
  sealed_epoch_secret :: Bytes
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
  secret :: SecretBytes
  commit :: GroupCommit
  welcome :: GroupWelcome
  transcript_hash :: Bytes
end

resource struct PreparedGroupRemove do
  tree :: GroupTree
  secret :: SecretBytes
  commit :: GroupCommit
  transcript_hash :: Bytes
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

fn wrapped_bytes(values :: List < WrappedEpochSecret >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    wrapped_bytes(values,
    index + 1,
    join([output, write_u16(value.leaf_index) ?, vector(value.sealed) ?], 0, Bytes.empty()) ?)
  end
end

fn commit_unsigned(value :: GroupCommit) -> Bytes ! GroupError do
  let context = commit_context(value.version,
  value.suite,
  value.group_id,
  value.prior_epoch,
  value.epoch,
  value.committer_leaf,
  value.prior_transcript_hash,
  value.tree_hash,
  value.proposal) ?
  wrapped_bytes(value.wrapped_secrets,
  0,
  append(context, write_u16(List.length(value.wrapped_secrets)) ?) ?)
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

fn read_wrapped(state :: BinaryReader,
count :: Int,
index :: Int,
previous :: Int,
output :: List < WrappedEpochSecret >) -> GroupReadWrapped ! GroupError do
  if count <= 0 || count > 64 do
    Err(InvalidGroup)
  else if index >= count do
    Ok(GroupReadWrapped {
      state : state,
      value : output
    })
  else
    let leaf = wire_u16(state) ?
    let sealed = wire_vector(leaf.state, 80) ?
    if leaf.value < 0 || leaf.value >= 64 || leaf.value <= previous || Bytes.length(sealed.value) != 80 do
      Err(InvalidGroup)
    else
      read_wrapped(sealed.state,
      count,
      index + 1,
      leaf.value,
      List.append(output,
      WrappedEpochSecret {
        leaf_index : leaf.value,
        sealed : sealed.value
      }))
    end
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

fn validate_wrapped_shape(values :: List < WrappedEpochSecret >, index :: Int, previous :: Int) -> Result <(), GroupError > do
  if List.length(values) <= 0 || List.length(values) > 64 do
    Err(InvalidGroup)
  else if index >= List.length(values) do
    Ok(nil)
  else
    let value = List.get(values, index)
    if value.leaf_index < 0 || value.leaf_index >= 64 || value.leaf_index <= previous || Bytes.length(value.sealed) != 80 do
      Err(InvalidGroup)
    else
      validate_wrapped_shape(values, index + 1, value.leaf_index)
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
    validate_wrapped_shape(value.wrapped_secrets, 0, -1)
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
  let wrapped_count = wire_u16(proposal.state) ?
  let wrapped = read_wrapped(wrapped_count.state, wrapped_count.value, 0, -1, List.new()) ?
  let signature = wire_fixed(wrapped.state, 64) ?
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
    wrapped_secrets : wrapped.value,
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

fn validate_wrapped_members(values :: List < WrappedEpochSecret >,
members :: List < IndexedGroupMember >,
index :: Int) -> Result <(), GroupError > do
  if List.length(values) != List.length(members) do
    Err(InvalidGroup)
  else if index >= List.length(members) do
    Ok(nil)
  else
    let wrapped = List.get(values, index)
    let member = List.get(members, index)
    if wrapped.leaf_index != member.leaf_index || Bytes.length(wrapped.sealed) != 80 do
      Err(InvalidGroup)
    else
      validate_wrapped_members(values, members, index + 1)
    end
  end
end

fn validate_welcome_shape(value :: GroupWelcome) -> Result <(), GroupError > do
  validate_commit_shape(value.commit) ?
  if !valid_extensions(value.extensions, 0, 0) || value.recipient_leaf < 0 || value.recipient_leaf >= 64 do
    Err(InvalidGroup)
  else
    validate_policy(value.policy) ?
    validate_members(value.members, value.extensions, value.policy, 0) ?
    let group_tree = tree_error(tree_from_members(value.members)) ?
    let expected_recipient = case value.commit.proposal do
      AddMember( leaf, _) -> leaf
      RemoveMember( _) -> -1
    end
    if expected_recipient != value.recipient_leaf || !Bytes.secure_equals(tree_hash(group_tree),
    value.commit.tree_hash) do
      Err(InvalidGroup)
    else
      let prior_tree = case remove_member(group_tree, value.recipient_leaf) do
        Err( error) -> Err(TreeFailure(error))
        Ok( tree) -> Ok(tree)
      end ?
      let rebuilt = apply_proposal(prior_tree, value.commit.proposal) ?
      if !Bytes.secure_equals(tree_hash(rebuilt), tree_hash(group_tree)) do
        Err(InvalidGroup)
      else
        validate_wrapped_members(value.commit.wrapped_secrets, value.members, 0)
      end
    end
  end
end

pub fn encode_group_welcome(value :: GroupWelcome) -> Bytes ! GroupError do
  validate_welcome_shape(value) ?
  let commit = encode_group_commit(value.commit) ?
  let body = join([vector(commit) ?, byte(List.length(value.members)) ?, encode_members(value.members,
  0,
  Bytes.empty()) ?, extensions_bytes(value.extensions) ?, policy_bytes(value.policy) ?, write_u16(value.recipient_leaf) ?],
  0,
  Bytes.empty()) ?
  if Bytes.length(body) > 26048 do
    Err(InvalidGroup)
  else
    join([byte(1) ?, Bytes.from_utf8("GWL"), body], 0, Bytes.empty())
  end
end

pub fn decode_group_welcome(input :: Bytes) -> GroupWelcome ! GroupError do
  let commit = wire_vector(wire_start(input, 26052, "GWL") ?, 8200) ?
  let member_count = wire_u8(commit.state) ?
  let members = read_members(member_count.state, member_count.value, 0, -1, List.new()) ?
  let extension_count = wire_u8(members.state) ?
  let extensions = read_extensions(extension_count.state, extension_count.value, 0, 0, List.new()) ?
  let minimum_sequence = wire_u64(extensions.state) ?
  let checkpoint = wire_fixed(minimum_sequence.state, 32) ?
  let witness = wire_u8(checkpoint.state) ?
  let recipient = wire_u16(witness.state) ?
  wire_end(recipient.state) ?
  let value = GroupWelcome {
    commit : decode_group_commit(commit.value) ?,
    members : members.value,
    extensions : extensions.value,
    policy : GroupTransparencyPolicy {
      minimum_directory_sequence : minimum_sequence.value,
      checkpoint_hash : checkpoint.value,
      witness_threshold : witness.value
    },
    recipient_leaf : recipient.value
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

fn validate_snapshot_state(state :: borrow GroupState,
account_id :: Bytes,
device_id :: Bytes,
snapshot_version :: U64) -> Result <(), GroupError > do
  let valid = state.version == 1 && state.suite == 3 && Bytes.length(state.group_id) == 32 && Bytes.length(state.tree_hash_cache) == 32 && Bytes.length(state.transcript_hash) == 32 && state.local_leaf >= 0 && state.local_leaf < 64 && state.next_generation >= 0 && Bytes.length(account_id) == 32 && Bytes.length(device_id) == 16 && U64.compare(snapshot_version,
  zero() ?) > 0 && Bytes.secure_equals(state.tree_hash_cache, tree_hash(state.tree))
  if !valid || !valid_extensions(state.extensions, 0, 0) || !local_identity_matches(state.tree,
  state.local_leaf,
  account_id,
  device_id) do
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
  join([byte(1) ?, Bytes.from_utf8("GST"), byte(state.version) ?, write_u16(state.suite) ?, state.group_id, write_u64(state.epoch) ?, write_u64(snapshot_version) ?, state.tree_hash_cache, state.transcript_hash, write_u16(state.local_leaf) ?, write_u32(state.next_generation) ?, byte(List.length(members)) ?, encode_members(members,
  0,
  Bytes.empty()) ?, byte(List.length(state.received_generations)) ?, encode_generations(state.received_generations,
  0,
  Bytes.empty()) ?, extensions_bytes(state.extensions) ?, policy_bytes(state.policy) ?],
  0,
  Bytes.empty())
end

fn group_storage_context(account_id :: Bytes,
device_id :: Bytes,
group_id :: Bytes,
header :: Bytes,
snapshot_version :: U64) -> Bytes ! GroupError do
  if Bytes.length(account_id) != 32 || Bytes.length(device_id) != 16 || Bytes.length(group_id) != 32 do
    Err(InvalidGroup)
  else
    let object = Crypto.sha256(join([Bytes.from_utf8("mesh-msg/v1/group-snapshot-object"), header, write_u16(16) ?],
    0,
    Bytes.empty()) ?)
    join([byte(1) ?, account_id, device_id, group_id, object, write_u16(16) ?, write_u64(snapshot_version) ?],
    0,
    Bytes.empty())
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
  snapshot_version) ?
  let sealed = case Secret.seal_for_storage(state.epoch_secret, wrapping_key, context) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end ?
  if Bytes.length(header) > 26048 || Bytes.length(sealed) != 99 do
    Err(InvalidGroup)
  else
    append(header, vector(sealed) ?)
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
  let state_version = wire_u8(wire_start(input, 26151, "GST") ?) ?
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
  let generation_count = wire_u8(members.state) ?
  let generations = read_generations(generation_count.state, generation_count.value, 0, List.new()) ?
  let extension_count = wire_u8(generations.state) ?
  let extensions = read_extensions(extension_count.state, extension_count.value, 0, 0, List.new()) ?
  let minimum_sequence = wire_u64(extensions.state) ?
  let checkpoint = wire_fixed(minimum_sequence.state, 32) ?
  let witness = wire_u8(checkpoint.state) ?
  let sealed = wire_vector(witness.state, 99) ?
  wire_end(sealed.state) ?
  if Bytes.length(sealed.value) != 99 do
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
      received_generations : generations.value,
      extensions : extensions.value,
      policy : GroupTransparencyPolicy {
        minimum_directory_sequence : minimum_sequence.value,
        checkpoint_hash : checkpoint.value,
        witness_threshold : witness.value
      },
      sealed_epoch_secret : sealed.value
    })
  end
end

fn parsed_group_header(value :: ParsedGroupSnapshot) -> Bytes ! GroupError do
  join([byte(1) ?, Bytes.from_utf8("GST"), byte(value.version) ?, write_u16(value.suite) ?, value.group_id, write_u64(value.epoch) ?, write_u64(value.snapshot_version) ?, value.tree_hash, value.transcript_hash, write_u16(value.local_leaf) ?, write_u32(value.next_generation) ?, byte(List.length(value.members)) ?, encode_members(value.members,
  0,
  Bytes.empty()) ?, byte(List.length(value.received_generations)) ?, encode_generations(value.received_generations,
  0,
  Bytes.empty()) ?, extensions_bytes(value.extensions) ?, policy_bytes(value.policy) ?],
  0,
  Bytes.empty())
end

fn validate_parsed_snapshot(value :: ParsedGroupSnapshot, account_id :: Bytes, device_id :: Bytes) -> GroupTree ! GroupError do
  let valid = value.version == 1 && value.suite == 3 && Bytes.length(value.group_id) == 32 && Bytes.length(value.tree_hash) == 32 && Bytes.length(value.transcript_hash) == 32 && value.local_leaf >= 0 && value.local_leaf < 64 && value.next_generation >= 0 && Bytes.length(account_id) == 32 && Bytes.length(device_id) == 16 && U64.compare(value.snapshot_version,
  zero() ?) > 0 && valid_extensions(value.extensions, 0, 0)
  if !valid do
    Err(InvalidGroup)
  else
    validate_policy(value.policy) ?
    validate_members(value.members, value.extensions, value.policy, 0) ?
    let group_tree = tree_error(tree_from_members(value.members)) ?
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
    value.snapshot_version) ?
    let secret = case Secret.unseal_from_storage(value.sealed_epoch_secret, wrapping_key, context) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( output) -> Ok(output)
    end ?
    Ok(GroupState {
      version : value.version,
      suite : value.suite,
      group_id : value.group_id,
      epoch : value.epoch,
      tree : group_tree,
      tree_hash_cache : value.tree_hash,
      transcript_hash : value.transcript_hash,
      epoch_secret : secret,
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
  Bytes.from_utf8("mesh-mls/v1/epoch-secret")
end

fn recipient_aad(context :: Bytes, leaf_index :: Int) -> Bytes ! GroupError do
  append(context, write_u16(leaf_index) ?)
end

fn wrap_epoch_secret(members :: List < IndexedGroupMember >,
index :: Int,
secret :: borrow SecretBytes,
context :: Bytes,
output :: List < WrappedEpochSecret >) -> List < WrappedEpochSecret > ! GroupError do
  if index >= List.length(members) do
    Ok(output)
  else
    let value = List.get(members, index)
    let leaf_index = value.leaf_index
    let sealed = case Crypto.hpke_seal_secret(value.member.init_public_key,
    hpke_info(),
    recipient_aad(context, leaf_index) ?,
    secret) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( blob) -> Ok(blob)
    end ?
    wrap_epoch_secret(members,
    index + 1,
    secret,
    context,
    List.append(output,
    WrappedEpochSecret {
      leaf_index : leaf_index,
      sealed : sealed
    }))
  end
end

fn wrapped_for(values :: List < WrappedEpochSecret >, leaf_index :: Int, index :: Int) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Err(RemovedMember)
  else
    let value = List.get(values, index)
    if value.leaf_index == leaf_index do
      Ok(value.sealed)
    else
      wrapped_for(values, leaf_index, index + 1)
    end
  end
end

fn leaf_for_init(values :: List < IndexedGroupMember >, public_key :: X25519PublicKey, index :: Int) -> Int do
  if index >= List.length(values) do
    -1
  else
    let value = List.get(values, index)
    if Bytes.secure_equals(value.member.init_public_key.bytes, public_key.bytes) do
      value.leaf_index
    else
      leaf_for_init(values, public_key, index + 1)
    end
  end
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
extensions :: List < Int >,
policy :: GroupTransparencyPolicy) -> GroupState ! GroupError do
  if !valid_extensions(extensions, 0, 0) do
    Err(InvalidGroup)
  else
    validate_member_policy(creator, extensions, policy) ?
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
        epoch_secret : secret,
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

fn prepare_add(state :: borrow GroupState,
signing_key :: borrow SigningPrivateKey,
member :: GroupMember) -> PreparedGroupAdd ! GroupError do
  validate_member_policy(member, state.extensions, state.policy) ?
  let inserted = case insert_member(state.tree, member) do
    Err( error) -> Err(TreeFailure(error))
    Ok( value) -> Ok(value)
  end ?
  let ( next_tree, recipient_leaf) = inserted
  let epoch = next_epoch(state.epoch) ?
  let proposal = AddMember(recipient_leaf, member)
  let context = commit_context(1,
  3,
  state.group_id,
  state.epoch,
  epoch,
  state.local_leaf,
  state.transcript_hash,
  tree_hash(next_tree),
  proposal) ?
  let secret = case Secret.random(32) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end ?
  let wrapped = wrap_epoch_secret(indexed_members(next_tree), 0, secret, context, List.new()) ?
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
    wrapped_secrets : wrapped,
    signature : Signature { bytes : Bytes.empty() }
  }
  let signature = case Crypto.sign(signing_key, commit_unsigned(unsigned) ?) do
    Err( error) -> Err(CryptoFailure(error))
    Ok( value) -> Ok(value)
  end ?
  let commit = % { unsigned | signature : signature }
  verify_commit(commit, state.tree) ?
  let transcript_hash = Crypto.sha256(signed_commit_bytes(commit) ?)
  let welcome = GroupWelcome {
    commit : commit,
    members : indexed_members(next_tree),
    extensions : state.extensions,
    policy : state.policy,
    recipient_leaf : recipient_leaf
  }
  Ok(PreparedGroupAdd {
    tree : next_tree,
    secret : secret,
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
      let next = % { state | epoch : commit.epoch, tree : tree, tree_hash_cache : tree_hash(tree), transcript_hash : transcript_hash, epoch_secret : prepared.secret, next_generation : 0, received_generations : List.new() }
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
    let next_tree = case remove_member(state.tree, leaf_index) do
      Err( error) -> Err(TreeFailure(error))
      Ok( value) -> Ok(value)
    end ?
    let epoch = next_epoch(state.epoch) ?
    let proposal = RemoveMember(leaf_index)
    let context = commit_context(1,
    3,
    state.group_id,
    state.epoch,
    epoch,
    state.local_leaf,
    state.transcript_hash,
    tree_hash(next_tree),
    proposal) ?
    let secret = case Secret.random(32) do
      Err( error) -> Err(CryptoFailure(error))
      Ok( value) -> Ok(value)
    end ?
    let wrapped = wrap_epoch_secret(indexed_members(next_tree), 0, secret, context, List.new()) ?
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
      wrapped_secrets : wrapped,
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
      secret : secret,
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
      let next = % { state | epoch : commit.epoch, tree : tree, tree_hash_cache : tree_hash(tree), transcript_hash : transcript_hash, epoch_secret : prepared.secret, next_generation : 0, received_generations : List.new() }
      GroupMemberRemoved(next, commit)
    end
  end
end

pub fn join_from_welcome(welcome :: GroupWelcome, init_private_key :: borrow X25519PrivateKey) -> GroupState ! GroupError do
  validate_welcome_shape(welcome) ?
  if welcome.commit.version != 1 || welcome.commit.suite != 3 || Bytes.length(welcome.commit.group_id) != 32 || !valid_extensions(welcome.extensions,
  0,
  0) do
    Err(InvalidGroup)
  else
    validate_policy(welcome.policy) ?
    validate_members(welcome.members, welcome.extensions, welcome.policy, 0) ?
    let tree = tree_error(tree_from_members(welcome.members)) ?
    let prior_tree = case welcome.commit.proposal do
      AddMember( leaf_index, _) -> if leaf_index != welcome.recipient_leaf do
        Err(InvalidGroup)
      else
        let without = case remove_member(tree, leaf_index) do
          Err( error) -> Err(TreeFailure(error))
          Ok( value) -> Ok(value)
        end ?
        Ok(without)
      end
      RemoveMember( _) -> Err(InvalidGroup)
    end ?
    verify_commit(welcome.commit, prior_tree) ?
    if !Bytes.secure_equals(tree_hash(tree), welcome.commit.tree_hash) do
      Err(AuthenticationRejected)
    else
      let public_key = case Crypto.x25519_public(init_private_key) do
        Err( error) -> Err(CryptoFailure(error))
        Ok( value) -> Ok(value)
      end ?
      let local_leaf = leaf_for_init(welcome.members, public_key, 0)
      if local_leaf != welcome.recipient_leaf do
        Err(AuthenticationRejected)
      else
        let sealed = wrapped_for(welcome.commit.wrapped_secrets, local_leaf, 0) ?
        let context = commit_context(welcome.commit.version,
        welcome.commit.suite,
        welcome.commit.group_id,
        welcome.commit.prior_epoch,
        welcome.commit.epoch,
        welcome.commit.committer_leaf,
        welcome.commit.prior_transcript_hash,
        welcome.commit.tree_hash,
        welcome.commit.proposal) ?
        let secret = case Crypto.hpke_open_secret(init_private_key,
        hpke_info(),
        recipient_aad(context, local_leaf) ?,
        sealed) do
          Err( error) -> Err(CryptoFailure(error))
          Ok( value) -> Ok(value)
        end ?
        Ok(GroupState {
          version : 1,
          suite : 3,
          group_id : welcome.commit.group_id,
          epoch : welcome.commit.epoch,
          tree : tree,
          tree_hash_cache : welcome.commit.tree_hash,
          transcript_hash : Crypto.sha256(signed_commit_bytes(welcome.commit) ?),
          epoch_secret : secret,
          local_leaf : local_leaf,
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

fn apply_verified_commit(state :: borrow GroupState,
init_private_key :: borrow X25519PrivateKey,
commit :: GroupCommit) -> SecretBytes ! GroupError do
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
    let next_tree = apply_proposal(state.tree, commit.proposal) ?
    let next_members = indexed_members(next_tree)
    validate_members(next_members, state.extensions, state.policy, 0) ?
    validate_wrapped_members(commit.wrapped_secrets, next_members, 0) ?
    if !Bytes.secure_equals(tree_hash(next_tree), commit.tree_hash) do
      Err(AuthenticationRejected)
    else
      let public_key = case Crypto.x25519_public(init_private_key) do
        Err( error) -> Err(CryptoFailure(error))
        Ok( value) -> Ok(value)
      end ?
      let local_leaf = leaf_for_init(indexed_members(next_tree), public_key, 0)
      if local_leaf != state.local_leaf do
        Err(RemovedMember)
      else
        let context = commit_context(commit.version,
        commit.suite,
        commit.group_id,
        commit.prior_epoch,
        commit.epoch,
        commit.committer_leaf,
        commit.prior_transcript_hash,
        commit.tree_hash,
        commit.proposal) ?
        case Crypto.hpke_open_secret(init_private_key,
        hpke_info(),
        recipient_aad(context, local_leaf) ?,
        wrapped_for(commit.wrapped_secrets, local_leaf, 0) ?) do
          Err( error) -> Err(CryptoFailure(error))
          Ok( value) -> Ok(value)
        end
      end
    end
  end
end

pub fn apply_commit(state :: consume GroupState,
init_private_key :: borrow X25519PrivateKey,
commit :: GroupCommit) -> CommitApplyOutcome do
  case apply_verified_commit(state, init_private_key, commit) do
    Err( error) -> CommitRejected(state, error)
    Ok( secret) -> case signed_commit_bytes(commit) do
      Err( error) -> do
        Secret.destroy(secret)
        CommitRejected(state, error)
      end
      Ok( signed) -> case apply_proposal(state.tree, commit.proposal) do
        Err( error) -> do
          Secret.destroy(secret)
          CommitRejected(state, error)
        end
        Ok( tree) -> CommitApplied(% { state | epoch : commit.epoch, tree : tree, tree_hash_cache : commit.tree_hash, transcript_hash : Crypto.sha256(signed), epoch_secret : secret, next_generation : 0, received_generations : List.new() })
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
    state.epoch_secret) ?
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
                Ok( info) -> case Crypto.hkdf_sha256(state.epoch_secret, public.group_id, info, 32) do
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
