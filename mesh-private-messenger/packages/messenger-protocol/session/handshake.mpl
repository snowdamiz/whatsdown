from Identity.Device import DeviceKeys, IdentityError, VerificationPolicy, is_retryable_identity_verification_error, verify_device_credential
from Prekeys.Bundle import OneTimePrekeySecrets, PostQuantumPrekeySecrets, PrekeyError, SignedPrekeySecrets, verify_prekey_bundle
from Protocol.HandshakeWire import decode_initial_message, hash_handshake_transcript
from Protocol.IdentityWire import decode_device_credential, encode_device_credential
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  HandshakeTranscript,
  InitialMessage,
  PrekeyBundle,
  ProtocolError,
  negotiate_suites
)

pub type SessionError do
  AuthenticationRejected
  CryptoFailure(error :: CryptoError)
  IdentityFailure(error :: IdentityError)
  PrekeyFailure(error :: PrekeyError)
  ProtocolFailure(error :: ProtocolError)
  InvalidHandshake
end

impl From<CryptoError> for SessionError do
  fn from(error :: CryptoError) -> SessionError do
    CryptoFailure(error)
  end
end

pub fn is_retryable_session_crypto_error(error :: CryptoError) -> Bool do
  case error do
    InvalidPublicKey -> false
    _ -> true
  end
end

pub fn is_retryable_session_error(error :: SessionError) -> Bool do
  case error do
    CryptoFailure(crypto_error) -> is_retryable_session_crypto_error(crypto_error)
    IdentityFailure(identity_error) -> is_retryable_identity_verification_error(identity_error)
    PrekeyFailure(_) -> true
    _ -> false
  end
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
end

fn initial_snapshot_version() -> U64!SessionError do
  case U64.parse("0") do
    Err(_) -> Err(InvalidHandshake)
    Ok(value)
  end
end

fn chain_key(root_key :: borrow SecretBytes, session_id :: Bytes, label :: String) -> SecretBytes!SessionError do
  let info = case Bytes.concat(Bytes.from_utf8("mesh-msg/v1/chain/"), Bytes.from_utf8(label)) do
    Err(_) -> Err(InvalidHandshake)
    Ok(value)
  end?
  Ok(Crypto.hkdf_sha256(root_key, session_id, info, 32)?)
end

fn skipped_key_store() -> SecretMap!SessionError do
  Ok(SecretMap.new(64)?)
end

fn concat(first :: SecretBytes, second :: SecretBytes) -> SecretBytes!SessionError do
  Ok(Secret.concat(first, second)?)
end

fn combine_dh(first :: SecretBytes,
  second :: SecretBytes,
  third :: SecretBytes,
  fourth :: SecretBytes) -> SecretBytes!SessionError do
  let combined = concat(first, second)?
  let combined = concat(combined, third)?
  concat(combined, fourth)
end

fn supported_suites(credential :: DeviceCredential) -> List<Int> do
  if credential.suite == 2 do
    [2, 1]
  else
    [1]
  end
end

fn selected_suite(credential :: DeviceCredential,
  bundle :: PrekeyBundle,
  strongest_authenticated_suite :: Int) -> Int!SessionError do
  case negotiate_suites(supported_suites(credential),
    bundle.supported_suites,
    strongest_authenticated_suite) do
    Err(error) -> Err(ProtocolFailure(error))
    Ok(value)
  end
end

fn initiator_ikm(suite :: Int, classical_ikm :: SecretBytes, bundle :: PrekeyBundle) -> Result<(Bytes, SecretBytes), SessionError> do
  if suite == 2 do
    let (ciphertext, shared_secret) = Crypto.mlkem_encapsulate(MlKemPublicKey { bytes: bundle.post_quantum_prekey })?
    Ok((ciphertext.bytes, concat(classical_ikm, shared_secret)?))
  else
    Ok((Bytes.empty(), classical_ikm))
  end
end

fn responder_ikm(suite :: Int,
  classical_ikm :: SecretBytes,
  post_quantum_prekey :: borrow PostQuantumPrekeySecrets,
  ciphertext :: Bytes) -> SecretBytes!SessionError do
  if suite == 2 do
    let shared_secret = Crypto.mlkem_decapsulate(post_quantum_prekey.private_key,
      MlKemCiphertext { bytes: ciphertext })?
    concat(classical_ikm, shared_secret)
  else
    Ok(classical_ikm)
  end
end

fn handshake_salt(transcript_hash :: Bytes) -> Bytes!SessionError do
  case Bytes.concat(Bytes.from_utf8("mesh-msg/v1/handshake"), transcript_hash) do
    Err(_) -> Err(InvalidHandshake)
    Ok(value) -> Ok(Crypto.sha256(value))
  end
end

fn encoded_credential(value :: DeviceCredential) -> Bytes!SessionError do
  case encode_device_credential(value) do
    Err(error) -> Err(ProtocolFailure(error))
    Ok(encoded)
  end
end

fn decoded_credential(value :: Bytes) -> DeviceCredential!SessionError do
  case decode_device_credential(value) do
    Err(error) -> Err(ProtocolFailure(error))
    Ok(decoded)
  end
end

fn transcript_for(initiator_credential :: DeviceCredential,
  responder_bundle :: PrekeyBundle,
  ephemeral_public_key :: X25519PublicKey,
  suite :: Int) -> HandshakeTranscript!SessionError do
  let credential_hash = Crypto.sha256(encoded_credential(initiator_credential)?)
  let bundle_hash = case encode_prekey_bundle(responder_bundle) do
    Err(error) -> Err(ProtocolFailure(error))
    Ok(encoded) -> Ok(Crypto.sha256(encoded))
  end?
  Ok(HandshakeTranscript {
    version: 1,
    suite: suite,
    initiator_credential_hash: credential_hash,
    responder_prekey_bundle_hash: bundle_hash,
    initiator_ephemeral_public_key: ephemeral_public_key.bytes,
    signed_prekey_id: responder_bundle.signed_prekey_id,
    responder_signed_prekey: responder_bundle.signed_prekey,
    one_time_prekey_id: responder_bundle.one_time_prekey_id,
    responder_one_time_prekey: responder_bundle.one_time_prekey,
    responder_post_quantum_prekey: if suite == 2 do
      responder_bundle.post_quantum_prekey
    else
      Bytes.empty()
    end,
    extensions: List.new()
  })
end

fn transcript_hash(value :: HandshakeTranscript) -> Bytes!SessionError do
  case hash_handshake_transcript(value) do
    Err(error) -> Err(ProtocolFailure(error))
    Ok(value)
  end
end

pub fn initiate(initiator :: borrow DeviceKeys,
  initiator_credential :: DeviceCredential,
  responder_account :: AccountIdentity,
  responder_bundle :: PrekeyBundle,
  responder_policy :: VerificationPolicy,
  strongest_authenticated_suite :: Int,
  plaintext :: Bytes) -> Result<(RatchetState, InitialMessage), SessionError> do
  let suite = selected_suite(initiator_credential, responder_bundle, strongest_authenticated_suite)?
  let credential_length = Bytes.length(encoded_credential(initiator_credential)?)
  let post_quantum_length = if suite == 2 do
    1088
  else
    0
  end
  let maximum_plaintext = 65382 - credential_length - post_quantum_length
  if Bytes.length(plaintext) > maximum_plaintext do
    Err(InvalidHandshake)
  else
    let bundle_valid = case verify_prekey_bundle(responder_account,
      responder_bundle,
      strongest_authenticated_suite,
      responder_policy.current_time,
      responder_policy.minimum_directory_sequence) do
      Err(_) -> false
      Ok(value) -> value
    end
    if !bundle_valid || Bytes.length(responder_bundle.one_time_prekey) != 32 do
      Err(InvalidHandshake)
    else
      let ephemeral = Crypto.x25519_generate()?
      let ephemeral_public = ephemeral.public_key
      let ephemeral_private = ephemeral.private_key
      let responder_identity = X25519PublicKey { bytes: responder_bundle.identity_dh_public_key }
      let responder_signed = X25519PublicKey { bytes: responder_bundle.signed_prekey }
      let responder_one_time = X25519PublicKey { bytes: responder_bundle.one_time_prekey }
      let dh1 = Crypto.x25519_shared(initiator.identity_private_key, responder_signed)?
      let dh2 = Crypto.x25519_shared(ephemeral_private, responder_identity)?
      let dh3 = Crypto.x25519_shared(ephemeral_private, responder_signed)?
      let dh4 = Crypto.x25519_shared(ephemeral_private, responder_one_time)?
      let classical_ikm = combine_dh(dh1, dh2, dh3, dh4)?
      let (post_quantum_ciphertext, ikm) = initiator_ikm(suite, classical_ikm, responder_bundle)?
      let transcript = transcript_for(initiator_credential,
        responder_bundle,
        ephemeral_public,
        suite)?
      let hash = transcript_hash(transcript)?
      let salt = handshake_salt(hash)?
      let root_key = Crypto.hkdf_sha256(ikm, salt, Bytes.from_utf8("mesh-msg/v1/root-key"), 32)?
      let sending_chain_key = chain_key(root_key, hash, "initiator")?
      let receiving_chain_key = chain_key(root_key, hash, "responder")?
      let skipped_keys = skipped_key_store()?
      let message_material = Crypto.hkdf_sha256(ikm,
        salt,
        Bytes.from_utf8("mesh-msg/v1/initial-message"),
        32)?
      Secret.destroy(ikm)
      let message_key = Crypto.aead_key(message_material)?
      let nonce = Crypto.random_bytes(12)?
      let ciphertext = Crypto.aead_seal(message_key, nonce, hash, plaintext)?
      let credential_bytes = encoded_credential(initiator_credential)?
      Ok((RatchetState {
          version: 1,
          suite: suite,
          session_id: hash,
          root_key: root_key,
          sending_chain_key: sending_chain_key,
          receiving_chain_key: receiving_chain_key,
          local_ratchet_private: ephemeral_private,
          local_ratchet_public: ephemeral_public,
          remote_ratchet_public: responder_one_time,
          previous_chain_length: 0,
          sent_count: 0,
          received_count: 0,
          skipped_keys: skipped_keys,
          skipped_index: Bytes.empty(),
          receive_generation: 0,
          pending_send_ratchet: true,
          snapshot_version: initial_snapshot_version()?
        },
        InitialMessage {
          version: 1,
          suite: suite,
          signed_prekey_id: responder_bundle.signed_prekey_id,
          one_time_prekey_id: responder_bundle.one_time_prekey_id,
          initiator_credential: credential_bytes,
          initiator_identity_public_key: initiator.identity_public_key,
          initiator_ephemeral_public_key: ephemeral_public,
          post_quantum_ciphertext: post_quantum_ciphertext,
          transcript_hash: hash,
          nonce: nonce,
          ciphertext: ciphertext
        }))
    end
  end
end

# ponytail: a receive attempt burns its claimed one-time prekey; add a durable
# reservation/commit wrapper when concurrent mailbox processing is introduced.

pub fn receive_initial(responder :: borrow DeviceKeys,
  responder_account :: AccountIdentity,
  responder_bundle :: PrekeyBundle,
  signed_prekey :: borrow SignedPrekeySecrets,
  one_time_prekey :: consume OneTimePrekeySecrets,
  post_quantum_prekey :: borrow PostQuantumPrekeySecrets,
  initiator_account :: AccountIdentity,
  responder_policy :: VerificationPolicy,
  initiator_policy :: VerificationPolicy,
  strongest_authenticated_suite :: Int,
  message_bytes :: Bytes) -> Result<(RatchetState, Bytes), SessionError> do
  let message = case decode_initial_message(message_bytes) do
    Err(_) -> Err(InvalidHandshake)
    Ok(value)
  end?
  let credential = decoded_credential(message.initiator_credential)?
  let suite = selected_suite(credential, responder_bundle, strongest_authenticated_suite)?
  let wrong_version = message.version != 1 || message.suite != suite
  let wrong_ids = U64.compare(message.signed_prekey_id, signed_prekey.id) != 0 || U64.compare(message.one_time_prekey_id,
    one_time_prekey.id) != 0
  let wrong_keys = !Bytes.secure_equals(responder_bundle.signed_prekey,
    signed_prekey.public_key.bytes) || !Bytes.secure_equals(responder_bundle.one_time_prekey,
    one_time_prekey.public_key.bytes)
  let wrong_post_quantum_key = suite == 2 && !Bytes.secure_equals(responder_bundle.post_quantum_prekey,
    post_quantum_prekey.public_key.bytes)
  if wrong_version || wrong_ids || wrong_keys || wrong_post_quantum_key do
    return Err(InvalidHandshake)
  end
  let bundle_valid = case verify_prekey_bundle(responder_account,
    responder_bundle,
    strongest_authenticated_suite,
    responder_policy.current_time,
    responder_policy.minimum_directory_sequence) do
    Err(error) -> Err(PrekeyFailure(error))
    Ok(false) -> Err(PrekeyFailure(InvalidBundle))
    Ok(true)
  end?
  let credential_valid = case verify_device_credential(initiator_account,
    credential,
    initiator_policy.current_time,
    initiator_policy.minimum_directory_sequence) do
    Err(error) -> if is_retryable_identity_verification_error(error) do
      Err(IdentityFailure(error))
    else
      Ok(false)
    end
    Ok(value)
  end?
  let identity_key_mismatch = !Bytes.secure_equals(credential.dh_public_key,
    message.initiator_identity_public_key.bytes)
  if !bundle_valid || !credential_valid || identity_key_mismatch do
    return Err(InvalidHandshake)
  end
  let transcript = transcript_for(credential,
    responder_bundle,
    message.initiator_ephemeral_public_key,
    suite)?
  let hash = transcript_hash(transcript)?
  if !Bytes.secure_equals(hash, message.transcript_hash) do
    return Err(InvalidHandshake)
  end
  let dh1 = Crypto.x25519_shared(signed_prekey.private_key, message.initiator_identity_public_key)?
  let dh2 = Crypto.x25519_shared(responder.identity_private_key,
    message.initiator_ephemeral_public_key)?
  let dh3 = Crypto.x25519_shared(signed_prekey.private_key, message.initiator_ephemeral_public_key)?
  let dh4 = Crypto.x25519_shared(one_time_prekey.private_key,
    message.initiator_ephemeral_public_key)?
  let classical_ikm = combine_dh(dh1, dh2, dh3, dh4)?
  let ikm = responder_ikm(suite,
    classical_ikm,
    post_quantum_prekey,
    message.post_quantum_ciphertext)?
  let salt = handshake_salt(hash)?
  let root_key = Crypto.hkdf_sha256(ikm, salt, Bytes.from_utf8("mesh-msg/v1/root-key"), 32)?
  let sending_chain_key = chain_key(root_key, hash, "responder")?
  let receiving_chain_key = chain_key(root_key, hash, "initiator")?
  let skipped_keys = skipped_key_store()?
  let message_material = Crypto.hkdf_sha256(ikm,
    salt,
    Bytes.from_utf8("mesh-msg/v1/initial-message"),
    32)?
  Secret.destroy(ikm)
  let message_key = Crypto.aead_key(message_material)?
  let plaintext = case Crypto.aead_open(message_key, message.nonce, hash, message.ciphertext) do
    Err(AuthenticationFailed) -> Err(AuthenticationRejected)
    Err(error) -> Err(CryptoFailure(error))
    Ok(value)
  end?
  let local_public = one_time_prekey.public_key
  let local_private = one_time_prekey.private_key
  Ok((RatchetState {
      version: 1,
      suite: suite,
      session_id: hash,
      root_key: root_key,
      sending_chain_key: sending_chain_key,
      receiving_chain_key: receiving_chain_key,
      local_ratchet_private: local_private,
      local_ratchet_public: local_public,
      remote_ratchet_public: message.initiator_ephemeral_public_key,
      previous_chain_length: 0,
      sent_count: 0,
      received_count: 0,
      skipped_keys: skipped_keys,
      skipped_index: Bytes.empty(),
      receive_generation: 0,
      pending_send_ratchet: false,
      snapshot_version: initial_snapshot_version()?
    },
    plaintext))
end
