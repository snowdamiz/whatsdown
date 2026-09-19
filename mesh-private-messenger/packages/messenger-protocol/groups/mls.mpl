##! Groups.Mls for the bounded messenger group protocol.

from Binary.Reader import BinaryReader
from Groups.Tree import (
  GroupMember,
  GroupTree,
  GroupTreeError,
  IndexedGroupMember,
  TreeKemParentNode,
  tree_hash
)

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

pub struct TreeMessageContext do
  hash :: Bytes
  sender :: GroupMember
end

pub struct OpenMessageContext do
  suite :: Int
  group_id :: Bytes
  epoch :: U64
  last_generation :: Int
  tree :: TreeMessageContext
end

pub struct EncryptMessageContext do
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

pub struct GroupReadInt do
  state :: BinaryReader
  value :: Int
end

pub struct GroupReadWide do
  state :: BinaryReader
  value :: U64
end

pub struct GroupReadBytes do
  state :: BinaryReader
  value :: Bytes
end

pub struct GroupReadInts do
  state :: BinaryReader
  value :: List < Int >
end

pub struct GroupReadProposal do
  state :: BinaryReader
  value :: GroupProposal
end

pub struct GroupReadCiphertexts do
  state :: BinaryReader
  value :: List < TreeKemCiphertext >
end

pub struct GroupReadUpdateNodes do
  state :: BinaryReader
  value :: List < TreeKemUpdateNode >
end

pub struct GroupReadParents do
  state :: BinaryReader
  value :: List < TreeKemParentNode >
end

pub struct GroupReadMembers do
  state :: BinaryReader
  value :: List < IndexedGroupMember >
end

pub struct GroupReadGenerations do
  state :: BinaryReader
  value :: List < SenderGeneration >
end

pub struct ParsedGroupSnapshot do
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

pub resource struct PreparedGroupAdd do
  tree :: GroupTree
  key_material :: TreeKemKeyMaterial
  commit :: GroupCommit
  welcome :: GroupWelcome
  transcript_hash :: Bytes
end

pub resource struct PreparedGroupRemove do
  tree :: GroupTree
  key_material :: TreeKemKeyMaterial
  commit :: GroupCommit
  transcript_hash :: Bytes
end

pub resource struct GeneratedTreeKemPath do
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

pub resource struct OpenedPathSecret do
  secret :: SecretBytes
  level :: Int
end

pub type TreeKemPathPatch do
  TreeKemPatch0( epoch_secret :: SecretBytes, level0 :: X25519PrivateKey, level1 :: X25519PrivateKey, level2 :: X25519PrivateKey, level3 :: X25519PrivateKey, level4 :: X25519PrivateKey, level5 :: X25519PrivateKey)

  TreeKemPatch1( epoch_secret :: SecretBytes, level1 :: X25519PrivateKey, level2 :: X25519PrivateKey, level3 :: X25519PrivateKey, level4 :: X25519PrivateKey, level5 :: X25519PrivateKey)

  TreeKemPatch2( epoch_secret :: SecretBytes, level2 :: X25519PrivateKey, level3 :: X25519PrivateKey, level4 :: X25519PrivateKey, level5 :: X25519PrivateKey)

  TreeKemPatch3( epoch_secret :: SecretBytes, level3 :: X25519PrivateKey, level4 :: X25519PrivateKey, level5 :: X25519PrivateKey)

  TreeKemPatch4( epoch_secret :: SecretBytes, level4 :: X25519PrivateKey, level5 :: X25519PrivateKey)

  TreeKemPatch5( epoch_secret :: SecretBytes, level5 :: X25519PrivateKey)
end

pub struct PreparedAppliedCommit do
  tree :: GroupTree
  context :: Bytes
end

pub resource struct PreparedJoin do
  tree :: GroupTree
  path_secret :: SecretBytes
  path_level :: Int
  context :: Bytes
end

# Keep construction with the defining type: GroupTreeError also has InvalidMember.

pub fn invalid_group_member_error() -> GroupError do
  InvalidMember
end
