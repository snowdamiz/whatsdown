##! Groups.CommitWire for the bounded messenger group protocol.

from Binary.Reader import BinaryReader
from Groups.GroupCodec import (
  group_append,
  group_byte,
  group_join,
  group_member_error,
  group_next_epoch,
  group_tree_path_error,
  group_valid_extensions,
  group_vector,
  group_wire_end,
  group_wire_fixed,
  group_wire_magic,
  group_wire_reader,
  group_wire_start,
  group_wire_u16,
  group_wire_u64,
  group_wire_u8,
  group_wire_vector,
  group_write_u16,
  group_write_u64
)
from Groups.Mls import (
  GroupCommit,
  GroupError,
  GroupProposal,
  GroupReadBytes,
  GroupReadCiphertexts,
  GroupReadInt,
  GroupReadInts,
  GroupReadParents,
  GroupReadProposal,
  GroupReadUpdateNodes,
  GroupReadWide,
  GroupTransparencyPolicy,
  TreeKemCiphertext,
  TreeKemUpdateNode,
  TreeKemUpdatePath
)
from Groups.Tree import (
  GroupMember,
  GroupTreeError,
  TreeKemParentNode,
  direct_path,
  encode_member,
  tree_hash,
  validate_member
)

fn encode_extensions(values :: List < Int >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_extensions(values,
    index + 1,
    group_append(output, group_write_u16(List.get(values, index)) ?) ?)
  end
end

pub fn group_extensions_bytes(values :: List < Int >) -> Bytes ! GroupError do
  if !group_valid_extensions(values, 0, 0) do
    Err(InvalidGroup)
  else
    encode_extensions(values, 0, group_byte(List.length(values)) ?)
  end
end

pub fn group_policy_bytes(value :: GroupTransparencyPolicy) -> Bytes ! GroupError do
  group_join([group_write_u64(value.minimum_directory_sequence) ?, value.checkpoint_hash, group_byte(value.witness_threshold) ?],
  0,
  Bytes.empty())
end

fn proposal_bytes(value :: GroupProposal) -> Bytes ! GroupError do
  case value do
    AddMember(leaf_index, member) -> group_join([group_byte(1) ?, group_write_u16(leaf_index) ?, group_vector(case encode_member(member) do
      Err(error) -> Err(TreeFailure(error))
      Ok(encoded) -> Ok(encoded)
    end ?) ?],
    0,
    Bytes.empty())
    UpdateKeys -> group_join([group_byte(3) ?, group_write_u16(0) ?], 0, Bytes.empty())
    RemoveMember(leaf_index) -> group_join([group_byte(2) ?, group_write_u16(leaf_index) ?],
    0,
    Bytes.empty())
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
  group_join([Bytes.from_utf8("mesh-mls/v1/commit"), group_byte(version) ?, group_write_u16(suite) ?, group_id, group_write_u64(prior_epoch) ?, group_write_u64(epoch) ?, group_write_u16(committer_leaf) ?, prior_transcript_hash, next_tree_hash, proposal_bytes(proposal) ?],
  0,
  Bytes.empty())
end

fn unmerged_bytes(values :: List < Int >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    unmerged_bytes(values,
    index + 1,
    group_append(output, group_write_u16(List.get(values, index)) ?) ?)
  end
end

pub fn group_parent_bytes(value :: TreeKemParentNode) -> Bytes ! GroupError do
  group_join([group_write_u16(value.node_index) ?, value.public_key.bytes, group_byte(List.length(value.unmerged_leaves)) ?, unmerged_bytes(value.unmerged_leaves,
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
    group_append(output, group_parent_bytes(List.get(values, index).parent) ?) ?)
  end
end

fn ciphertext_bytes(values :: List < TreeKemCiphertext >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    ciphertext_bytes(values,
    index + 1,
    group_join([output, group_write_u16(value.recipient_node) ?, value.sealed], 0, Bytes.empty()) ?)
  end
end

fn update_ciphertexts_bytes(values :: List < TreeKemUpdateNode >, index :: Int, output :: Bytes) -> Bytes ! GroupError do
  if index >= List.length(values) do
    Ok(output)
  else
    let value = List.get(values, index)
    update_ciphertexts_bytes(values,
    index + 1,
    group_join([output, group_byte(List.length(value.ciphertexts)) ?, ciphertext_bytes(value.ciphertexts,
    0,
    Bytes.empty()) ?],
    0,
    Bytes.empty()) ?)
  end
end

pub fn group_update_path_context(version :: Int,
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
  group_join([prefix, update_path.leaf_public_key.bytes, group_byte(List.length(update_path.nodes)) ?, update_public_bytes(update_path.nodes,
  0,
  Bytes.empty()) ?],
  0,
  Bytes.empty())
end

pub fn group_commit_unsigned(value :: GroupCommit) -> Bytes ! GroupError do
  let context = group_update_path_context(value.version,
  value.suite,
  value.group_id,
  value.prior_epoch,
  value.epoch,
  value.committer_leaf,
  value.prior_transcript_hash,
  value.tree_hash,
  value.proposal,
  value.update_path) ?
  let body = update_ciphertexts_bytes(value.update_path.nodes, 0, context) ?
  if value.version == 1 do
    Ok(body)
  else
    group_append(body, value.confirmation)
  end
end

pub fn group_signed_commit_bytes(value :: GroupCommit) -> Bytes ! GroupError do
  group_append(group_commit_unsigned(value) ?, value.signature.bytes)
end

pub fn group_read_extensions(state :: BinaryReader,
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
    let extension = group_wire_u16(state) ?
    if extension.value <= previous || extension.value <= 0 do
      Err(InvalidGroup)
    else
      group_read_extensions(extension.state,
      count,
      index + 1,
      extension.value,
      List.append(output, extension.value))
    end
  end
end

pub fn group_read_levels(state :: BinaryReader,
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
    let level = group_wire_u8(state) ?
    if level.value < 0 || level.value >= 6 || level.value <= previous do
      Err(InvalidGroup)
    else
      group_read_levels(level.state,
      count,
      index + 1,
      level.value,
      List.append(output, level.value))
    end
  end
end

pub fn group_decode_member_wire(input :: Bytes) -> GroupMember ! GroupError do
  let version = group_wire_u8(group_wire_reader(input, 251) ?) ?
  let account_id = group_wire_fixed(version.state, 32) ?
  let device_id = group_wire_fixed(account_id.state, 16) ?
  let signing_public_key = group_wire_fixed(device_id.state, 32) ?
  let init_public_key = group_wire_fixed(signing_public_key.state, 32) ?
  let leaf_public_key = group_wire_fixed(init_public_key.state, 32) ?
  let mailbox_token = group_wire_fixed(leaf_public_key.state, 32) ?
  let directory_sequence = group_wire_u64(mailbox_token.state) ?
  let checkpoint = group_wire_fixed(directory_sequence.state, 32) ?
  let witness_count = group_wire_u8(checkpoint.state) ?
  let extension_count = group_wire_u8(witness_count.state) ?
  let extensions = group_read_extensions(extension_count.state,
  extension_count.value,
  0,
  0,
  List.new()) ?
  group_wire_end(extensions.state) ?
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
  group_member_error(validate_member(value)) ?
  Ok(value)
end

fn read_proposal(state :: BinaryReader) -> GroupReadProposal ! GroupError do
  let kind = group_wire_u8(state) ?
  let leaf = group_wire_u16(kind.state) ?
  if leaf.value < 0 || leaf.value >= 64 do
    Err(InvalidGroup)
  else if kind.value == 1 do
    let member = group_wire_vector(leaf.state, 251) ?
    Ok(GroupReadProposal {
      state : member.state,
      value : AddMember(leaf.value, group_decode_member_wire(member.value) ?)
    })
  else if kind.value == 3 && leaf.value == 0 do
    Ok(GroupReadProposal {
      state : leaf.state,
      value : UpdateKeys
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

pub fn group_read_unmerged(state :: BinaryReader,
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
    let leaf = group_wire_u16(state) ?
    if leaf.value < 0 || leaf.value >= 64 || leaf.value <= previous do
      Err(InvalidGroup)
    else
      group_read_unmerged(leaf.state, count, index + 1, leaf.value, List.append(output, leaf.value))
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
    let recipient = group_wire_u16(state) ?
    let sealed = group_wire_fixed(recipient.state, 80) ?
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
    let node_index = group_wire_u16(state) ?
    let public_key = group_wire_fixed(node_index.state, 32) ?
    let unmerged_count = group_wire_u8(public_key.state) ?
    let unmerged = group_read_unmerged(unmerged_count.state,
    unmerged_count.value,
    0,
    -1,
    List.new()) ?
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
    let ciphertext_count = group_wire_u8(state) ?
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
    UpdateKeys -> Ok(nil)
    AddMember(leaf, member) -> if leaf < 0 || leaf >= 64 do
      Err(InvalidGroup)
    else
      group_member_error(validate_member(member))
    end
    RemoveMember(leaf) -> if leaf < 0 || leaf >= 64 do
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

pub fn group_validate_commit_shape(value :: GroupCommit) -> Result <(), GroupError > do
  let valid = (value.version == 1 || value.version == 2) && ((value.version == 1 && Bytes.length(value.confirmation) == 0) || (value.version == 2 && Bytes.length(value.confirmation) == 16)) && value.suite == 3 && Bytes.length(value.group_id) == 32 && value.committer_leaf >= 0 && value.committer_leaf < 64 && Bytes.length(value.prior_transcript_hash) == 32 && Bytes.length(value.tree_hash) == 32 && Bytes.length(value.signature.bytes) == 64
  let legacy_update = case value.proposal do
    UpdateKeys -> value.version == 1
    _ -> false
  end
  if !valid || legacy_update do
    Err(InvalidGroup)
  else if U64.compare(value.epoch, group_next_epoch(value.prior_epoch) ?) != 0 do
    Err(InvalidGroup)
  else
    validate_proposal_shape(value.proposal) ?
    if Bytes.length(value.update_path.leaf_public_key.bytes) != 32 do
      Err(InvalidGroup)
    else
      validate_update_nodes_shape(value.update_path.nodes,
      group_tree_path_error(direct_path(value.committer_leaf)) ?,
      0,
      0)
    end
  end
end

pub fn encode_group_commit(value :: GroupCommit) -> Bytes ! GroupError do
  group_validate_commit_shape(value) ?
  let body = group_signed_commit_bytes(value) ?
  if Bytes.length(body) > 8192 do
    Err(InvalidGroup)
  else
    group_join([group_byte(1) ?, Bytes.from_utf8("GCM"), group_vector(body) ?], 0, Bytes.empty())
  end
end

fn decode_commit_body(input :: Bytes) -> GroupCommit ! GroupError do
  let domain = group_wire_magic(group_wire_reader(input, 8192) ?, "mesh-mls/v1/commit") ?
  let version = group_wire_u8(domain) ?
  let suite = group_wire_u16(version.state) ?
  let group_id = group_wire_fixed(suite.state, 32) ?
  let prior_epoch = group_wire_u64(group_id.state) ?
  let epoch = group_wire_u64(prior_epoch.state) ?
  let committer = group_wire_u16(epoch.state) ?
  let prior_transcript = group_wire_fixed(committer.state, 32) ?
  let tree = group_wire_fixed(prior_transcript.state, 32) ?
  let proposal = read_proposal(tree.state) ?
  let leaf_public = group_wire_fixed(proposal.state, 32) ?
  let node_count = group_wire_u8(leaf_public.state) ?
  let parents = read_update_nodes(node_count.state, node_count.value, 0, List.new()) ?
  let nodes = read_update_ciphertexts(parents.state, parents.value, 0, List.new()) ?
  let confirmation = group_wire_fixed(nodes.state,
  if version.value == 2 do
    16
  else
    0
  end) ?
  let signature = group_wire_fixed(confirmation.state, 64) ?
  group_wire_end(signature.state) ?
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
    confirmation : confirmation.value,
    signature : Signature { bytes : signature.value }
  }
  group_validate_commit_shape(value) ?
  Ok(value)
end

pub fn decode_group_commit(input :: Bytes) -> GroupCommit ! GroupError do
  let body = group_wire_vector(group_wire_start(input, 8200, "GCM") ?, 8192) ?
  group_wire_end(body.state) ?
  decode_commit_body(body.value)
end
