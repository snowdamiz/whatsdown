##! Shared resource state; this module has no handshake or ratchet dependency.

pub type RatchetError do
  AuthenticationRejected
  CryptoFailure
  ExcessiveJump
  InvalidMessage
  Replay
end

pub resource struct RatchetState do
  version :: Int
  suite :: Int
  session_id :: Bytes
  root_key :: SecretBytes
  sending_chain_key :: SecretBytes
  receiving_chain_key :: SecretBytes
  local_ratchet_private :: X25519PrivateKey
  local_ratchet_public :: X25519PublicKey
  remote_ratchet_public :: X25519PublicKey
  previous_chain_length :: Int
  sent_count :: Int
  received_count :: Int
  skipped_keys :: SecretMap
  # The map cannot be listed, so this names what it holds, oldest first: 40
  # bytes a key, the chain's ratchet key, the message number, and
  # `receive_generation` as it was when the key was set aside.
  skipped_index :: Bytes
  receive_generation :: Int
  pending_send_ratchet :: Bool
  snapshot_version :: U64
  # Four current/next role slots plus bounded old receive-header keys.
  header_keys :: SecretMap
end

pub struct RatchetMessage do
  version :: Int
  suite :: Int
  session_id :: Bytes
  ratchet_public_key :: X25519PublicKey
  previous_chain_length :: Int
  message_number :: Int
  nonce :: Bytes
  ciphertext :: Bytes
  header_nonce :: Bytes
  encrypted_header :: Bytes
end

pub type DecryptOutcome do
  Opened(state :: RatchetState, plaintext :: Bytes)
  Rejected(state :: RatchetState, error :: RatchetError)
end
