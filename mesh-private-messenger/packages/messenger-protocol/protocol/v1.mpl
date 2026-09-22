##! Version-one protocol records and suite negotiation.

pub type ProtocolError do
  UnsupportedVersion

  UnsupportedSuite

  InvalidSuiteList

  DuplicateSuite

  InvalidSuiteHistory

  DowngradeDetected

  TooManyExtensions

  InvalidExtension

  UnknownMandatoryExtension

  NonCanonicalEncoding

  InvalidPolicy

  InvalidFieldLength

  InvalidPaddingBucket

  InvalidExpiration

  PostQuantumNotSupported

  OversizedInput

  MalformedEncoding
end deriving(Eq, Debug)

pub struct OuterEnvelope do
  version :: Int
  envelope_id :: Bytes
  mailbox_token :: Bytes
  suite :: Int
  expiration :: U64
  padding_bucket :: Int
  ciphertext :: Bytes
end

pub struct DeviceCredential do
  version :: Int
  suite :: Int
  account_id :: Bytes
  device_id :: Bytes
  signing_public_key :: Bytes
  dh_public_key :: Bytes
  post_quantum_public_key :: Bytes
  capabilities :: U64
  created_at :: U64
  expires_at :: U64
  directory_sequence :: U64
  signature :: Bytes
end

pub struct ProtocolExtension do
  id :: Int
  mandatory :: Bool
  value :: Bytes
end

pub struct AccountIdentity do
  version :: Int
  account_id :: Bytes
  authorization_public_key :: Bytes
  created_at :: U64
  directory_sequence :: U64
  extensions :: List < ProtocolExtension >
end

pub struct PrekeyBundle do
  version :: Int
  suite :: Int
  device_credential :: Bytes
  identity_dh_public_key :: Bytes
  signing_public_key :: Bytes
  signed_prekey_id :: U64
  signed_prekey :: Bytes
  signed_prekey_signature :: Bytes
  one_time_prekey_id :: U64
  one_time_prekey :: Bytes
  post_quantum_prekey :: Bytes
  supported_suites :: List < Int >
  expires_at :: U64
  extensions :: List < ProtocolExtension >
end

pub struct InnerEnvelope do
  version :: Int
  sender_account_id :: Bytes
  sender_device_id :: Bytes
  recipient_device_id :: Bytes
  conversation_id :: Bytes
  client_message_id :: Bytes
  client_timestamp :: U64
  message_type :: Int
  body :: Bytes
  reply_reference :: Bytes
  attachment_manifest :: Bytes
  receipt_policy :: Int
  disappearing_seconds :: Int
  extensions :: List < ProtocolExtension >
end

pub struct HandshakeTranscript do
  version :: Int
  suite :: Int
  initiator_credential_hash :: Bytes
  responder_prekey_bundle_hash :: Bytes
  initiator_ephemeral_public_key :: Bytes
  signed_prekey_id :: U64
  responder_signed_prekey :: Bytes
  one_time_prekey_id :: U64
  responder_one_time_prekey :: Bytes
  responder_post_quantum_prekey :: Bytes
  extensions :: List < ProtocolExtension >
end

pub struct InitialMessage do
  version :: Int
  suite :: Int
  signed_prekey_id :: U64
  one_time_prekey_id :: U64
  initiator_credential :: Bytes
  initiator_identity_public_key :: X25519PublicKey
  initiator_ephemeral_public_key :: X25519PublicKey
  post_quantum_ciphertext :: Bytes
  transcript_hash :: Bytes
  nonce :: Bytes
  ciphertext :: Bytes
end

pub struct DirectoryEntry do
  version :: Int
  username :: String
  account_identity :: Bytes
  prekey_bundle :: Bytes
  mailbox_token :: Bytes
end

pub struct DeviceLinkRequest do
  version :: Int
  suite :: Int
  nonce :: Bytes
  device_id :: Bytes
  signing_public_key :: Bytes
  dh_public_key :: Bytes
  post_quantum_public_key :: Bytes
  capabilities :: U64
  created_at :: U64
  expires_at :: U64
end

pub struct DeviceLinkAuthorization do
  version :: Int
  request_hash :: Bytes
  username :: String
  account_identity :: Bytes
  device_credential :: Bytes
  authorization_signature :: Bytes
end

pub struct DeviceSet do
  version :: Int
  username :: String
  account_identity :: Bytes
  sequence :: U64
  devices :: List < DirectoryEntry >
  revoked_device_ids :: List < Bytes >
end

pub struct DeviceRevocation do
  version :: Int
  account_id :: Bytes
  device_id :: Bytes
  sequence :: U64
  signature :: Bytes
end

pub struct AccountDeletion do
  version :: Int
  account_id :: Bytes
  issued_at :: U64
  signature :: Bytes
end

pub struct DeviceDeparture do
  version :: Int
  account_id :: Bytes
  device_id :: Bytes
  issued_at :: U64
  signature :: Bytes
end

pub struct MailboxFetch do
  version :: Int
  mailbox_token_hash :: Bytes
  after_sequence :: U64
  issued_at :: U64
  signature :: Bytes
end

pub struct DeliveredEnvelope do
  sequence :: U64
  envelope :: Bytes
end

pub struct MailboxAck do
  version :: Int
  mailbox_token_hash :: Bytes
  issued_at :: U64
  envelope_ids :: List < Bytes >
  signature :: Bytes
end

pub fn protocol_contains_suite(values :: List < Int >, target :: Int, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else
    List.get(values, index) == target || protocol_contains_suite(values, target, index + 1)
  end
end

pub fn protocol_supported_suite(value :: Int) -> Bool do
  value == 1 || value == 2
end

## The outer suite of a recipient-sealed packet. It names the transport only:
## the protocol suite and packet kind travel inside the seal.

pub fn protocol_sealed_outer_suite() -> Int do
  4
end

pub fn protocol_validate_suite_list(values :: List < Int >, index :: Int) -> Result <(), ProtocolError > do
  if List.length(values) == 0 || List.length(values) > 8 do
    Err(InvalidSuiteList)
  else
    if index >= List.length(values) do
      Ok(nil)
    else
      let suite = List.get(values, index)
      if protocol_contains_suite(values, suite, index + 1) do
        Err(DuplicateSuite)
      else
        if !protocol_supported_suite(suite) do
          Err(UnsupportedSuite)
        else
          protocol_validate_suite_list(values, index + 1)
        end
      end
    end
  end
end

pub fn negotiate_suites(local_suites :: List < Int >,
remote_suites :: List < Int >,
strongest_authenticated_suite :: Int) -> Int ! ProtocolError do
  protocol_validate_suite_list(local_suites, 0) ?
  protocol_validate_suite_list(remote_suites, 0) ?
  if strongest_authenticated_suite < 0 || strongest_authenticated_suite > 2 do
    Err(InvalidSuiteHistory)
  else
    let selected = if protocol_contains_suite(local_suites, 2, 0) && protocol_contains_suite(remote_suites,
    2,
    0) do
      2
    else if protocol_contains_suite(local_suites, 1, 0) && protocol_contains_suite(remote_suites,
    1,
    0) do
      1
    else
      0
    end
    if selected == 0 do
      Err(UnsupportedSuite)
    else if selected < strongest_authenticated_suite do
      Err(DowngradeDetected)
    else
      Ok(selected)
    end
  end
end

pub fn negotiate_profile_a(local_suites :: List < Int >,
remote_suites :: List < Int >,
strongest_authenticated_suite :: Int) -> Int ! ProtocolError do
  negotiate_suites(local_suites, remote_suites, strongest_authenticated_suite)
end
