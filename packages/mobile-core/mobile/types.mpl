from Binary.Reader import BinaryReader
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  DeviceSet,
  DirectoryEntry,
  InnerEnvelope,
  PrekeyBundle
)
from Security.Config import SecurityConfig
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
  credits :: List<Bytes>
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

## `now` is this device's clock at receipt; tests set it to stand on either side
## of the legacy packet cutoff.

pub struct MobileReceiveRequest do
  database_path :: String
  outer :: Bytes
  now :: U64
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
  # Session healing (`Mobile.SessionReset`): 0, 1 once this device asked the
  # peer for a new session, 2 once a new session replaced this one (it stays
  # readable for what was already on its way, and is never sent on again).
  reset_state :: Int
  # When the conversation's secure session was last reset, 0 if never.
  reset_at :: U64
  # The peer device's X25519 identity key, which the recipient seal needs.
  # Empty in records from before session healing.
  peer_identity_key :: Bytes
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
  session_reset_at :: U64
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

# The whole security config (pinned witnesses with labels, k, set_id, chain
# anchor and RPC URLs, relays, issuer, C2SP origin, minimum suite) with the
# fields most callers need lifted out. profile: bootstrap | transitional | open.

pub struct MobileSecurityConfig do
  transparency_service_public_key :: Bytes
  delivery_public_key :: Bytes
  abuse_difficulty :: Int
  profile :: String
  config :: SecurityConfig
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

# profiles: the devices anyone may encrypt to. expired: devices still signed
# into the account whose credential or signed prekey has run out; no one
# encrypts to them until they are renewed, but they can be renewed and removed.

pub struct MobileVerifiedDeviceSet do
  wire :: Bytes
  value :: DeviceSet
  account :: AccountIdentity
  profiles :: List<ClientProfile>
  expired :: List<ClientProfile>
end

pub struct MobileClaimedPrekey do
  base_bundle :: Bytes
  profile :: ClientProfile
end

# A device set this device verified: the checkpoint it was in, and the pinned
# witness set that checkpoint was verified under.

pub struct MobileVerifiedTransparencySet do
  checkpoint :: Bytes
  device_set :: Bytes
  set_id :: Bytes
end

# What this device has verified of the log: the newest checkpoint, the service
# key and witness set it was verified under, and the hashes of older
# checkpoints known to be prefixes of it (ones this device verified, and
# anchors whose consistency proofs it verified).

pub struct MobileTransparencyView do
  checkpoint :: Bytes
  service_public_key :: Bytes
  set_id :: Bytes
  known :: List<Bytes>
end

pub struct MobileTransparencyStorage do
  labels :: List<String>
  blobs :: List<Bytes>
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
  # When a disappearing message goes (0: it stays), and what the entry is:
  # 0 a message, 1 a view-once message, 2 a notice that the group timer changed.
  expires_at :: U64
  kind :: Int
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
