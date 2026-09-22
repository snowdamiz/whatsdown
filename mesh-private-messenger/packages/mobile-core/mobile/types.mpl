from Binary.Reader import BinaryReader
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  DeviceSet,
  DirectoryEntry,
  InnerEnvelope,
  PrekeyBundle
)
from Session.Handshake import RatchetState
from Session.Snapshot import SnapshotOutcome, snapshot
from Transport.Packet import ClientProfile

##! Mobile.Types implementation.

pub struct MobileReadBytes do
  state :: BinaryReader
  value :: Bytes
end

pub struct MobileStoreRequest do
  database_path :: String
  record_key :: Bytes
  envelope :: Bytes
end

pub struct MobileAccountRequest do
  database_path :: Bytes
  username :: Bytes
end

pub struct MobilePrekeyRequest do
  database_path :: String
  count :: Int
end

pub struct MobilePrekeyReconcileRequest do
  database_path :: String
  response :: Bytes
end

pub struct MobileOneTimePrekey do
  id :: U64
  public_key :: Bytes
end

pub struct MobileStartRequest do
  database_path :: String
  peer_profile :: Bytes
  body :: Bytes
  attachment :: Bytes
end

pub struct MobileFanoutRequest do
  database_path :: String
  peer_device_set :: Bytes
  local_device_set :: Bytes
  body :: Bytes
  attachment :: Bytes
end

pub struct MobileAttachmentPrepareRequest do
  database_path :: String
  filename :: Bytes
  mime_type :: Bytes
  plaintext_size :: Int
  difficulty :: Int
end

pub struct MobileAttachmentChunkRequest do
  database_path :: String
  reference :: Bytes
  index :: Int
  payload :: Bytes
end

pub struct MobileAttachmentReference do
  object_id :: Bytes
  download_capability :: Bytes
  encrypted_manifest :: Bytes
  wrapped_key :: Bytes
end

pub struct MobileAttachmentRecipient do
  account_id :: Bytes
  device_id :: Bytes
  public_key :: Bytes
end

pub struct MobileFanoutTargetsRequest do
  database_path :: String
  peer_device_set :: Bytes
  local_device_set :: Bytes
end

pub struct MobileFanoutPrepareRequest do
  database_path :: String
  peer_device_set :: Bytes
  local_device_set :: Bytes
  directory_url :: String
end

pub struct MobileFanoutPrekeyReservationRequest do
  database_path :: String
  peer_device_set :: Bytes
  local_device_set :: Bytes
  claimed_prekey :: Bytes
end

pub struct MobileReceiveRequest do
  database_path :: String
  outer :: Bytes
end

pub struct MobileSessionRecord do
  snapshot :: Bytes
  local_account_id :: Bytes
  local_device_id :: Bytes
  peer_account_id :: Bytes
  peer_device_id :: Bytes
  peer_username :: String
  peer_mailbox :: Bytes
  conversation_id :: Bytes
  request_state :: Int
  blocked :: Bool
  verified :: Bool
  key_changed :: Bool
  disappearing_seconds :: Int
  strongest_suite :: Int
  safety_number :: Bytes
end

pub struct MobileLoadedSession do
  session_id :: Bytes
  label :: String
  record :: MobileSessionRecord
end

pub struct MobilePreparedSend do
  envelope :: Bytes
  session_id :: Bytes
  session_label :: String
  session_blob :: Bytes
  new_session :: Bool
end

pub struct MobileHistoryEntry do
  direction :: Int
  inner :: InnerEnvelope
end

pub struct MobileSyncPayload do
  peer_username :: String
  peer_account_id :: Bytes
  conversation_id :: Bytes
  client_message_id :: Bytes
  client_timestamp :: U64
  body :: Bytes
  disappearing_seconds :: Int
  safety_number :: Bytes
end

pub struct MobilePolicyRequest do
  database_path :: String
  peer_profile :: Bytes
  action :: Int
  value :: Int
end

pub struct MobilePeerRequest do
  database_path :: String
  peer_profile :: Bytes
end

pub struct ConversationSummary do
  conversation_id :: Bytes
  username :: String
  peer_account_id :: Bytes
  peer_device_id :: Bytes
  safety_number :: Bytes
  request_state :: Int
  blocked :: Bool
  verified :: Bool
  key_changed :: Bool
  disappearing_seconds :: Int
end

pub struct MobileBatchRequest do
  database_path :: String
  batch :: Bytes
end

pub struct MobilePayloadRequest do
  database_path :: String
  payload :: Bytes
end

pub struct MobileTriplePayloadRequest do
  database_path :: String
  first :: Bytes
  second :: Bytes
end

pub struct MobileTransparencyRequest do
  database_path :: String
  username :: String
  evidence :: Bytes
end

pub struct MobileSecurityConfig do
  transparency_service_public_key :: Bytes
  witness_a_public_key :: Bytes
  witness_b_public_key :: Bytes
  delivery_public_key :: Bytes
  abuse_difficulty :: Int
end

pub struct MobilePushState do
  revision :: U64
  mode :: Int
  wake_token_hash :: Bytes
  provider_token_hash :: Bytes
  pending_kind :: Int
  pending_wire :: Bytes
  action_epoch :: U64
  action_kind :: Int
  target_mode :: Int
  project_id :: Bytes
  broker_public_key :: Bytes
end

pub struct MobilePushIntentRequest do
  database_path :: String
  intent :: Int
end

pub struct MobilePushBuildConfig do
  project_id :: Bytes
  broker_public_key :: Bytes
end

pub struct MobilePushActionCompletion do
  database_path :: String
  action :: Bytes
  outcome :: Int
end

pub struct MobilePushActionFrame do
  kind :: Int
  epoch :: U64
  payload :: Bytes
end

pub struct MobileExpoRawToken do
  platform :: Int
  development :: Bool
  app_id :: String
  device_token :: String
end

pub struct MobileVerifiedDeviceSet do
  wire :: Bytes
  value :: DeviceSet
  account :: AccountIdentity
  profiles :: List < ClientProfile >
end

pub struct MobileClaimedPrekey do
  base_bundle :: Bytes
  profile :: ClientProfile
end

pub struct MobileVerifiedTransparencySet do
  checkpoint :: Bytes
  device_set :: Bytes
end

pub struct MobileTransparencyView do
  checkpoint :: Bytes
  consistency :: Bytes
  service_public_key :: Bytes
  witness_a_public_key :: Bytes
  witness_b_public_key :: Bytes
end

pub struct MobileTransparencyManifest do
  checkpoint :: Bytes
  consistency_length :: Int
  consistency_hash :: Bytes
  chunk_count :: Int
  service_public_key :: Bytes
  witness_a_public_key :: Bytes
  witness_b_public_key :: Bytes
end

pub struct MobileTransparencyStorage do
  labels :: List < String >
  blobs :: List < Bytes >
end

pub struct MobileGroupKeyPackage do
  account_id :: Bytes
  device_id :: Bytes
  init_public_key :: X25519PublicKey
  leaf_public_key :: X25519PublicKey
  checkpoint :: Bytes
  witness_count :: Int
  signature :: Signature
end

pub struct MobileGroupWelcomePacket do
  baseline_checkpoint :: Bytes
  welcome :: Bytes
end

pub struct MobileGroupAddRequest do
  database_path :: String
  group_id :: Bytes
  device_set :: Bytes
  key_package :: Bytes
end

pub struct MobileGroupRemoveRequest do
  database_path :: String
  group_id :: Bytes
  account_id :: Bytes
  device_id :: Bytes
end

pub struct MobileGroupSendRequest do
  database_path :: String
  group_id :: Bytes
  body :: Bytes
  attachment :: Bytes
end

pub struct MobileGroupPacket do
  kind :: Int
  payload :: Bytes
end

pub struct MobileGroupReferenceRequest do
  database_path :: String
  group_id :: Bytes
end

pub struct MobileGroupHistoryEntry do
  message_id :: Bytes
  direction :: Int
  epoch :: U64
  sender_account_id :: Bytes
  sender_device_id :: Bytes
  timestamp :: U64
  body :: Bytes
  attachment :: Bytes
end

pub type MobileGroupReceiveOutcome do
  GroupReceiveApplied(output :: Bytes)

  GroupReceiveRetry(error :: String)

  GroupReceiveRejected(error :: String)
end

pub type MobileDirectReceiveOutcome do
  DirectReceiveApplied(output :: Bytes)

  DirectReceiveRetry(error :: String)

  DirectReceiveRejected(error :: String)
end
