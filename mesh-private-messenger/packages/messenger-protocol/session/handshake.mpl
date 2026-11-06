from Session.Spqr import SpqrState, initialize_spqr
from Session.SpqrKdf import SpqrError
from Session.BraidResponder import BraidScope, BraidAwaitHeader, BraidError, initialize_responder
from Session.BraidInitiator import BraidAliceIdle, initialize_initiator
from Session.State import RatchetState, RatchetError, DecryptOutcome
from Session.HeaderRatchet import (
  he_initialize_alice,
  he_initialize_bob,
  he_encrypt,
  he_decrypt,
  he_initial_aad
)
from Session.HeaderWire import he_encode_message, he_decode_message
from Protocol.Capabilities import supports_header_encryption
from Identity.Device import (
  DeviceKeys,
  IdentityError,
  VerificationPolicy,
  is_retryable_identity_verification_error,
  verify_device_credential
)
from Prekeys.Bundle import (
  OneTimePrekeySecrets,
  PostQuantumPrekeySecrets,
  PrekeyError,
  SignedPrekeySecrets,
  verify_prekey_bundle
)
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
  MinimumSessionSuiteRequired
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

fn header_error(error :: RatchetError) -> SessionError do
  case error do
    RatchetError.CryptoFailure -> CryptoFailure(InternalFailure)
    RatchetError.AuthenticationRejected -> AuthenticationRejected
    _ -> InvalidHandshake
  end
end

fn he_pair(credential :: DeviceCredential, bundle :: PrekeyBundle) -> Bool!SessionError do
  let responder = decoded_credential(bundle.device_credential)?
  Ok(supports_header_encryption(credential.capabilities)
    && supports_header_encryption(responder.capabilities))
end

fn initial_snapshot_version() -> U64!SessionError do
  case U64.parse("0") do
    Err(_) -> Err(InvalidHandshake)
    Ok(value)
  end
end

fn chain_key(root_key :: borrow SecretBytes,
  session_id :: Bytes,
  label :: String) -> SecretBytes!SessionError do
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

# The release floor is policy, not authenticated peer history. Keep both inputs
# separate and retain the old history-dependent bundle/transcript matching.
fn selected_suite_at_minimum(credential :: DeviceCredential,
  bundle :: PrekeyBundle,
  strongest_authenticated_suite :: Int,
  minimum_session_suite :: Int) -> Int!SessionError do
  if minimum_session_suite < 1 || minimum_session_suite > 2 do
    return Err(InvalidHandshake)
  end
  let selected = selected_suite(credential, bundle, strongest_authenticated_suite)?
  if selected < minimum_session_suite do
    Err(MinimumSessionSuiteRequired)
  else
    Ok(selected)
  end
end

fn initiator_ikm(suite :: Int,
  classical_ikm :: SecretBytes,
  bundle :: PrekeyBundle) -> Result<(Bytes, SecretBytes), SessionError> do
  if suite == 2 do
    let (ciphertext, shared_secret) = Crypto.mlkem_encapsulate(MlKemPublicKey {
      bytes: bundle.post_quantum_prekey
    })?
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
    version: if he_pair(initiator_credential, responder_bundle)? do
      2
    else
      1
    end,
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

# Manual protocol compatibility retains explicit classical negotiation. Release
# callers pass their separately captured minimum to the policy-taking API.
pub fn initiate(initiator :: borrow DeviceKeys,
  initiator_credential :: DeviceCredential,
  responder_account :: AccountIdentity,
  responder_bundle :: PrekeyBundle,
  responder_policy :: VerificationPolicy,
  strongest_authenticated_suite :: Int,
  plaintext :: Bytes) -> Result<(RatchetState, InitialMessage), SessionError> do
  initiate_at_minimum_suite(initiator,
    initiator_credential,
    responder_account,
    responder_bundle,
    responder_policy,
    strongest_authenticated_suite,
    1,
    plaintext)
end

pub fn initiate_at_minimum_suite(initiator :: borrow DeviceKeys,
  initiator_credential :: DeviceCredential,
  responder_account :: AccountIdentity,
  responder_bundle :: PrekeyBundle,
  responder_policy :: VerificationPolicy,
  strongest_authenticated_suite :: Int,
  minimum_session_suite :: Int,
  plaintext :: Bytes) -> Result<(RatchetState, InitialMessage), SessionError> do
  let (state, message, owners) = initiate_profile(initiator,
    initiator_credential,
    responder_account,
    responder_bundle,
    responder_policy,
    strongest_authenticated_suite,
    minimum_session_suite,
    plaintext,
    None)?
  case owners do
    None -> Ok((state, message))
    Some(_) -> Err(InvalidHandshake)
  end
end

fn initiate_profile(initiator :: borrow DeviceKeys,
  initiator_credential :: DeviceCredential,
  responder_account :: AccountIdentity,
  responder_bundle :: PrekeyBundle,
  responder_policy :: VerificationPolicy,
  strongest_authenticated_suite :: Int,
  minimum_session_suite :: Int,
  plaintext :: Bytes,
  configuration :: Option<Bytes>) -> (RatchetState, InitialMessage, Option<C1AliceOwners>)!SessionError do
  let suite = selected_suite_at_minimum(initiator_credential,
    responder_bundle,
    strongest_authenticated_suite,
    minimum_session_suite)?
  let credential_length = Bytes.length(encoded_credential(initiator_credential)?)
  let post_quantum_length = if suite == 2 do
    1088
  else
    0
  end
  let header_mode = he_pair(initiator_credential, responder_bundle)?
  c1_selected(configuration, suite, header_mode)?
  let maximum_plaintext = (if header_mode do
    48512
  else
    65382
  end) - credential_length - post_quantum_length
  let oversized = declassify(Bytes.length(plaintext) > maximum_plaintext,
    "initial handshake admission discloses only whether plaintext exceeds the public credential and suite dependent transport bound; plaintext content remains private")
  if oversized do
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
      let hash = c1_hash(configuration, transcript_hash(transcript)?)?
      let salt = handshake_salt(hash)?
      if header_mode do
        let root_key = Crypto.hkdf_sha256(ikm,
          salt,
          Bytes.from_utf8("mesh-msg/v2/he-bootstrap-root"),
          32)?
        let owners = case configuration do
          None
          Some(c) -> Some(c1_alice_owners(ikm,
            salt,
            c1_scope(c,
              hash,
              initiator_credential,
              decoded_credential(responder_bundle.device_credential)?)?)?)
        end
        Secret.destroy(ikm)
        let state = case he_initialize_alice(root_key,
          suite,
          hash,
          responder_one_time,
          initial_snapshot_version()?) do
          Err(error) -> Err(header_error(error))
          Ok(value)
        end?
        let initial_aad = case he_initial_aad(hash) do
          Err(error) -> Err(header_error(error))
          Ok(value)
        end?
        let (state, message) = case he_encrypt(state, plaintext, initial_aad) do
          Err(error) -> Err(header_error(error))
          Ok(value)
        end?
        let wire = case he_encode_message(message) do
          Err(error) -> Err(header_error(error))
          Ok(value)
        end?
        return Ok((state,
          InitialMessage {
            version: 2,
            suite: suite,
            signed_prekey_id: responder_bundle.signed_prekey_id,
            one_time_prekey_id: responder_bundle.one_time_prekey_id,
            initiator_credential: encoded_credential(initiator_credential)?,
            initiator_identity_public_key: initiator.identity_public_key,
            initiator_ephemeral_public_key: ephemeral_public,
            post_quantum_ciphertext: post_quantum_ciphertext,
            transcript_hash: hash,
            nonce: case Bytes.repeat(0, 12) do
              Err(_) -> Err(InvalidHandshake)
              Ok(value)
            end?,
            ciphertext: wire
          },
          owners))
      end
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
      let ciphertext = declassify_discriminant(Crypto.aead_seal(message_key,
          nonce,
          hash,
          plaintext),
        "initial handshake encryption exposes only success or failure; message bytes, error payloads, and unrelated private control remain private")?
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
          snapshot_version: initial_snapshot_version()?,
          header_keys: SecretMap.new(16)?
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
        },
        None))
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
  receive_initial_at_minimum_suite(responder,
    responder_account,
    responder_bundle,
    signed_prekey,
    one_time_prekey,
    post_quantum_prekey,
    initiator_account,
    responder_policy,
    initiator_policy,
    strongest_authenticated_suite,
    1,
    message_bytes)
end

pub fn receive_initial_at_minimum_suite(responder :: borrow DeviceKeys,
  responder_account :: AccountIdentity,
  responder_bundle :: PrekeyBundle,
  signed_prekey :: borrow SignedPrekeySecrets,
  one_time_prekey :: consume OneTimePrekeySecrets,
  post_quantum_prekey :: borrow PostQuantumPrekeySecrets,
  initiator_account :: AccountIdentity,
  responder_policy :: VerificationPolicy,
  initiator_policy :: VerificationPolicy,
  strongest_authenticated_suite :: Int,
  minimum_session_suite :: Int,
  message_bytes :: Bytes) -> Result<(RatchetState, Bytes), SessionError> do
  let (state, clear, owners) = receive_profile(responder,
    responder_account,
    responder_bundle,
    signed_prekey,
    one_time_prekey,
    post_quantum_prekey,
    initiator_account,
    responder_policy,
    initiator_policy,
    strongest_authenticated_suite,
    minimum_session_suite,
    message_bytes,
    None)?
  case owners do
    None -> Ok((state, clear))
    Some(_) -> Err(InvalidHandshake)
  end
end

fn receive_profile(responder :: borrow DeviceKeys,
  responder_account :: AccountIdentity,
  responder_bundle :: PrekeyBundle,
  signed_prekey :: borrow SignedPrekeySecrets,
  one_time_prekey :: consume OneTimePrekeySecrets,
  post_quantum_prekey :: borrow PostQuantumPrekeySecrets,
  initiator_account :: AccountIdentity,
  responder_policy :: VerificationPolicy,
  initiator_policy :: VerificationPolicy,
  strongest_authenticated_suite :: Int,
  minimum_session_suite :: Int,
  message_bytes :: Bytes,
  configuration :: Option<Bytes>) -> (RatchetState, Bytes, Option<C1BobOwners>)!SessionError do
  let message = case decode_initial_message(message_bytes) do
    Err(_) -> Err(InvalidHandshake)
    Ok(value)
  end?
  let credential = decoded_credential(message.initiator_credential)?
  let suite = selected_suite_at_minimum(credential,
    responder_bundle,
    strongest_authenticated_suite,
    minimum_session_suite)?
  let header_mode = he_pair(credential, responder_bundle)?
  c1_selected(configuration, suite, header_mode)?
  let expected_version = if header_mode do
    2
  else
    1
  end
  let wrong_version = message.version != expected_version || message.suite != suite
  let wrong_ids = U64.compare(message.signed_prekey_id, signed_prekey.id) != 0
    || U64.compare(message.one_time_prekey_id, one_time_prekey.id) != 0
  let wrong_keys = !Bytes.secure_equals(responder_bundle.signed_prekey,
    signed_prekey.public_key.bytes)
    || !Bytes.secure_equals(responder_bundle.one_time_prekey, one_time_prekey.public_key.bytes)
  let wrong_post_quantum_key = suite == 2
    && !Bytes.secure_equals(responder_bundle.post_quantum_prekey,
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
  let hash = c1_hash(configuration, transcript_hash(transcript)?)?
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
  if header_mode do
    let root_key = Crypto.hkdf_sha256(ikm,
      salt,
      Bytes.from_utf8("mesh-msg/v2/he-bootstrap-root"),
      32)?
    let owners = case configuration do
      None
      Some(c) -> Some(c1_bob_owners(ikm,
        salt,
        c1_scope(c, hash, decoded_credential(responder_bundle.device_credential)?, credential)?)?)
    end
    Secret.destroy(ikm)
    let one_time_prekey_public = one_time_prekey.public_key
    let one_time_prekey_private = one_time_prekey.private_key
    let state = case he_initialize_bob(root_key,
      suite,
      hash,
      one_time_prekey_private,
      one_time_prekey_public,
      initial_snapshot_version()?) do
      Err(error) -> Err(header_error(error))
      Ok(value)
    end?
    let message = case he_decode_message(message.ciphertext) do
      Err(error) -> Err(header_error(error))
      Ok(value)
    end?
    let aad = case he_initial_aad(hash) do
      Err(error) -> Err(header_error(error))
      Ok(value)
    end?
    return case he_decrypt(state, message, aad) do
      Rejected(rejected, error) -> Err(header_error(error))
      Opened(next, plaintext) -> Ok((next, plaintext, owners))
    end
  end
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
      snapshot_version: initial_snapshot_version()?,
      header_keys: SecretMap.new(16)?
    },
    plaintext,
    None))
end

## Whether a first message was sealed to exactly this responder bundle, with
## the one-time prekey it names filled in. A device that renews keeps earlier
## bundles for a while, and some share a signed prekey: only the transcript,
## which binds the bundle's hash, tells them apart.

pub fn initial_message_uses_bundle(responder_bundle :: PrekeyBundle,
  strongest_authenticated_suite :: Int,
  message_bytes :: Bytes) -> Bool do
  bundle_matches_message(responder_bundle, strongest_authenticated_suite, message_bytes)
    |> Option.unwrap_or(false)
end

## Whether the message was sealed to the bundle, or `None` when any step of
## reading it fails, which is a no.
fn bundle_matches_message(responder_bundle :: PrekeyBundle,
  strongest_authenticated_suite :: Int,
  message_bytes :: Bytes) -> Option<Bool> do
  let message = decode_initial_message(message_bytes)
    |> Result.ok()?
  let credential = decode_device_credential(message.initiator_credential)
    |> Result.ok()?
  let suite = selected_suite(credential, responder_bundle, strongest_authenticated_suite)
    |> Result.ok()?
  let transcript = transcript_for(credential,
    responder_bundle,
    message.initiator_ephemeral_public_key,
    suite)
    |> Result.ok()?
  let hash = transcript_hash(transcript)
    |> Result.ok()?
  Some(U64.compare(message.signed_prekey_id, responder_bundle.signed_prekey_id) == 0
    && Bytes.secure_equals(hash, message.transcript_hash))
end

## C1 remains an explicitly invoked separate profile; legacy wrappers pass None.
resource struct C1AliceOwners do
  spqr :: SpqrState
  braid :: BraidAliceIdle
end

resource struct C1BobOwners do
  spqr :: SpqrState
  braid :: BraidAwaitHeader
end

pub resource struct C1Initiated do
  he :: RatchetState
  spqr :: SpqrState
  braid :: BraidAliceIdle
  initial :: InitialMessage
end

pub resource struct C1Received do
  he :: RatchetState
  spqr :: SpqrState
  braid :: BraidAwaitHeader
  plaintext :: Bytes
end

fn c1_join(parts :: List<Bytes>) -> Bytes!SessionError do
  case Bytes.concat_many(parts, 256) do
    Ok(v)
    Err(_) -> Err(InvalidHandshake)
  end
end

fn c1_zero() -> Bytes!SessionError do
  case Bytes.from_list([0]) do
    Ok(v)
    Err(_) -> Err(InvalidHandshake)
  end
end

fn c1_selected(configuration :: Option<Bytes>,
  suite :: Int,
  headers :: Bool) -> Unit!SessionError do
  case configuration do
    None -> Ok(nil)
    Some(c) -> if Bytes.length(c) == 32 && suite == 2 && headers do
      Ok(nil)
    else
      Err(InvalidHandshake)
    end
  end
end

fn c1_hash(configuration :: Option<Bytes>, canonical :: Bytes) -> Bytes!SessionError do
  case configuration do
    None -> Ok(canonical)
    Some(c) -> Ok(Crypto.sha256(c1_join([
      Bytes.from_utf8("mesh-msg/c1/handshake/v1"),
      c1_zero()?,
      c,
      canonical
    ])?))
  end
end

fn c1_scope(c :: Bytes,
  hash :: Bytes,
  local :: DeviceCredential,
  peer :: DeviceCredential) -> BraidScope!SessionError do
  Ok(BraidScope {
    protocol_info: c1_join([Bytes.from_utf8("mesh-msg/braid/v1"), c1_zero()?, c, hash])?,
    configuration: c,
    session_id: hash,
    account_id: local.account_id,
    device_id: local.device_id,
    peer_account_id: peer.account_id,
    peer_device_id: peer.device_id
  })
end

fn c1_seed(ikm :: borrow SecretBytes,
  salt :: Bytes,
  scope :: BraidScope,
  label :: String) -> SecretBytes!SessionError do
  Ok(Crypto.hkdf_sha256(ikm,
    salt,
    c1_join([Bytes.from_utf8(label), c1_zero()?, scope.configuration, scope.session_id])?,
    32)?)
end

fn c1_braid_error(error :: BraidError) -> SessionError do
  case error do
    BraidCryptoFailure(e) -> CryptoFailure(e)
    _ -> InvalidHandshake
  end
end

fn c1_spqr_error(error :: SpqrError) -> SessionError do
  case error do
    SpqrCryptoFailure(e) -> CryptoFailure(e)
    _ -> InvalidHandshake
  end
end

fn c1_alice_owners(ikm :: borrow SecretBytes,
  salt :: Bytes,
  scope :: BraidScope) -> C1AliceOwners!SessionError do
  let seed = c1_seed(ikm, salt, scope, "mesh-msg/spqr/bootstrap/v1")?
  let q = initialize_spqr(scope, 0, seed)
  Secret.destroy(seed)
  let q = case q do
    Ok(v) -> v
    Err(e) -> return Err(c1_spqr_error(e))
  end
  let seed = c1_seed(ikm, salt, scope, "mesh-msg/braid/bootstrap/v1")?
  let b = initialize_initiator(scope, seed)
  Secret.destroy(seed)
  let b = case b do
    Ok(v) -> v
    Err(e) -> return Err(c1_braid_error(e))
  end
  Ok(C1AliceOwners { spqr: q, braid: b })
end

fn c1_bob_owners(ikm :: borrow SecretBytes,
  salt :: Bytes,
  scope :: BraidScope) -> C1BobOwners!SessionError do
  let seed = c1_seed(ikm, salt, scope, "mesh-msg/spqr/bootstrap/v1")?
  let q = initialize_spqr(scope, 1, seed)
  Secret.destroy(seed)
  let q = case q do
    Ok(v) -> v
    Err(e) -> return Err(c1_spqr_error(e))
  end
  let seed = c1_seed(ikm, salt, scope, "mesh-msg/braid/bootstrap/v1")?
  let b = initialize_responder(scope, seed)
  Secret.destroy(seed)
  let b = case b do
    Ok(v) -> v
    Err(e) -> return Err(c1_braid_error(e))
  end
  Ok(C1BobOwners { spqr: q, braid: b })
end

pub fn initiate_braid_spqr_at_minimum_suite(initiator :: borrow DeviceKeys,
  initiator_credential :: DeviceCredential,
  responder_account :: AccountIdentity,
  responder_bundle :: PrekeyBundle,
  responder_policy :: VerificationPolicy,
  strongest_authenticated_suite :: Int,
  minimum_session_suite :: Int,
  plaintext :: Bytes,
  configuration :: Bytes) -> C1Initiated!SessionError do
  if !Bytes.secure_equals(initiator.device_id, initiator_credential.device_id)
    || !Bytes.secure_equals(initiator.identity_public_key.bytes, initiator_credential.dh_public_key)
    || !Bytes.secure_equals(initiator.signing_public_key.bytes,
      initiator_credential.signing_public_key) do
    return Err(InvalidHandshake)
  end
  let (he, initial, owners) = initiate_profile(initiator,
    initiator_credential,
    responder_account,
    responder_bundle,
    responder_policy,
    strongest_authenticated_suite,
    minimum_session_suite,
    plaintext,
    Some(configuration))?
  case owners do
    Some(o) -> do
      let C1AliceOwners { spqr, braid } = o
      Ok(C1Initiated { he: he, spqr: spqr, braid: braid, initial: initial })
    end
    None -> Err(InvalidHandshake)
  end
end

pub fn receive_initial_braid_spqr_at_minimum_suite(responder :: borrow DeviceKeys,
  responder_account :: AccountIdentity,
  responder_bundle :: PrekeyBundle,
  signed_prekey :: borrow SignedPrekeySecrets,
  one_time_prekey :: consume OneTimePrekeySecrets,
  post_quantum_prekey :: borrow PostQuantumPrekeySecrets,
  initiator_account :: AccountIdentity,
  responder_policy :: VerificationPolicy,
  initiator_policy :: VerificationPolicy,
  strongest_authenticated_suite :: Int,
  minimum_session_suite :: Int,
  message_bytes :: Bytes,
  configuration :: Bytes) -> C1Received!SessionError do
  let local = decoded_credential(responder_bundle.device_credential)?
  if !Bytes.secure_equals(responder.device_id, local.device_id)
    || !Bytes.secure_equals(responder.identity_public_key.bytes, local.dh_public_key)
    || !Bytes.secure_equals(responder.signing_public_key.bytes, local.signing_public_key) do
    return Err(InvalidHandshake)
  end
  let (he, plaintext, owners) = receive_profile(responder,
    responder_account,
    responder_bundle,
    signed_prekey,
    one_time_prekey,
    post_quantum_prekey,
    initiator_account,
    responder_policy,
    initiator_policy,
    strongest_authenticated_suite,
    minimum_session_suite,
    message_bytes,
    Some(configuration))?
  case owners do
    Some(o) -> do
      let C1BobOwners { spqr, braid } = o
      Ok(C1Received { he: he, spqr: spqr, braid: braid, plaintext: plaintext })
    end
    None -> Err(InvalidHandshake)
  end
end
