from Identity.Device import AccountKeys, DeviceKeys, IdentityError, VerificationPolicy, generate_account, generate_device, issue_device_credential, issue_hybrid_device_credential
from Prekeys.Bundle import OneTimePrekeySecrets, PostQuantumPrekeySecrets, PrekeyError, SignedPrekeySecrets, build_hybrid_prekey_bundle, build_prekey_bundle, generate_one_time_prekey, generate_post_quantum_prekey, generate_signed_prekey, normalize_prekey_bundle, reauthorize_signed_prekey, verify_prekey_bundle
from Protocol.HandshakeWire import encode_initial_message
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  InitialMessage,
  PrekeyBundle,
  ProtocolError,
  ProtocolExtension,
  negotiate_suites
)
from Session.Handshake import RatchetState, SessionError, initiate, receive_initial
from Session.Ratchet import DecryptOutcome, decrypt, encrypt

fn wide(value :: String) -> U64!String do
  case U64.parse(value) do
    Err(_) -> Err("integer failed")
    Ok(parsed)
  end
end

fn account(now :: U64) -> Result<(AccountKeys, AccountIdentity), String> do
  case generate_account(now, wide("1")?) do
    Err(_) -> Err("account failed")
    Ok(value)
  end
end

fn device() -> DeviceKeys!String do
  case generate_device() do
    Err(_) -> Err("device failed")
    Ok(value)
  end
end

fn post_quantum_prekey() -> PostQuantumPrekeySecrets!String do
  case generate_post_quantum_prekey() do
    Err(_) -> Err("post-quantum prekey failed")
    Ok(value)
  end
end

fn hybrid_credential(account_keys :: borrow AccountKeys,
  device_keys :: borrow DeviceKeys,
  post_quantum :: borrow PostQuantumPrekeySecrets,
  now :: U64,
  expires :: U64) -> DeviceCredential!String do
  case issue_hybrid_device_credential(account_keys,
    device_keys,
    post_quantum.public_key,
    wide("3")?,
    now,
    expires,
    wide("1")?) do
    Err(_) -> Err("hybrid credential failed")
    Ok(value)
  end
end

fn classical_credential(account_keys :: borrow AccountKeys,
  device_keys :: borrow DeviceKeys,
  now :: U64,
  expires :: U64) -> DeviceCredential!String do
  case issue_device_credential(account_keys, device_keys, wide("1")?, now, expires, wide("1")?) do
    Err(_) -> Err("classical credential failed")
    Ok(value)
  end
end

fn signed_prekey(device_keys :: borrow DeviceKeys, credential :: DeviceCredential, expires :: U64) -> SignedPrekeySecrets!String do
  case generate_signed_prekey(device_keys, credential, wide("7")?, expires) do
    Err(_) -> Err("signed prekey failed")
    Ok(value)
  end
end

fn one_time_prekey() -> OneTimePrekeySecrets!String do
  case generate_one_time_prekey(wide("9")?) do
    Err(_) -> Err("one-time prekey failed")
    Ok(value)
  end
end

fn hybrid_bundle(credential :: DeviceCredential,
  signed :: borrow SignedPrekeySecrets,
  one_time :: borrow OneTimePrekeySecrets,
  post_quantum :: borrow PostQuantumPrekeySecrets) -> PrekeyBundle!String do
  case build_hybrid_prekey_bundle(credential, signed, one_time, post_quantum) do
    Err(_) -> Err("hybrid bundle failed")
    Ok(value)
  end
end

fn classical_bundle(credential :: DeviceCredential,
  signed :: borrow SignedPrekeySecrets,
  one_time :: borrow OneTimePrekeySecrets) -> PrekeyBundle!String do
  case build_prekey_bundle(credential, signed, one_time) do
    Err(_) -> Err("classical bundle failed")
    Ok(value)
  end
end

fn initial_bytes(value :: InitialMessage) -> Bytes!String do
  case encode_initial_message(value) do
    Err(_) -> Err("initial encoding failed")
    Ok(encoded)
  end
end

fn zeroes(length :: Int) -> Bytes!String do
  case Bytes.repeat(0, length) do
    Err(_) -> Err("zero bytes failed")
    Ok(value)
  end
end

fn maximal_extensions(index :: Int, output :: List<ProtocolExtension>) -> List<ProtocolExtension>!String do
  if index >= 16 do
    Ok(output)
  else
    maximal_extensions(index + 1,
      List.append(output,
        ProtocolExtension {
          id: index + 1,
          mandatory: false,
          value: zeroes(1024)?
        }))
  end
end

fn encoded_bundle(value :: PrekeyBundle) -> Bytes!String do
  case encode_prekey_bundle(value) do
    Err(_) -> Err("prekey bundle encoding failed")
    Ok(encoded)
  end
end

fn decoded_bundle(value :: Bytes) -> PrekeyBundle!String do
  case decode_prekey_bundle(value) do
    Err(_) -> Err("prekey bundle decoding failed")
    Ok(decoded)
  end
end

fn normalized_bundle(value :: PrekeyBundle) -> PrekeyBundle!String do
  case normalize_prekey_bundle(value) do
    Err(_) -> Err("prekey bundle normalization failed")
    Ok(normalized)
  end
end

fn maximal_bundle_proof() -> Bool!String do
  let now = wide("1700000000000")?
  let expires = wide("1700604800000")?
  let (account_keys, _) = account(now)?
  let device_keys = device()?
  let post_quantum = post_quantum_prekey()?
  let credential = hybrid_credential(account_keys, device_keys, post_quantum, now, expires)?
  let signed = signed_prekey(device_keys, credential, expires)?
  let one_time = one_time_prekey()?
  let bundle = hybrid_bundle(credential, signed, one_time, post_quantum)?
  let maximal = PrekeyBundle {
    version: bundle.version,
    suite: bundle.suite,
    device_credential: bundle.device_credential,
    identity_dh_public_key: bundle.identity_dh_public_key,
    signing_public_key: bundle.signing_public_key,
    signed_prekey_id: bundle.signed_prekey_id,
    signed_prekey: bundle.signed_prekey,
    signed_prekey_signature: bundle.signed_prekey_signature,
    one_time_prekey_id: bundle.one_time_prekey_id,
    one_time_prekey: bundle.one_time_prekey,
    post_quantum_prekey: bundle.post_quantum_prekey,
    supported_suites: bundle.supported_suites,
    expires_at: bundle.expires_at,
    extensions: maximal_extensions(0, List.new())?
  }
  let encoded = encoded_bundle(maximal)?
  assert(Bytes.length(encoded) == 19312)
  let decoded = decoded_bundle(encoded)?
  assert(List.length(decoded.extensions) == 16)
  assert(Bytes.secure_equals(encoded_bundle(decoded)?, encoded))
  let normalized = normalized_bundle(maximal)?
  assert(U64.compare(normalized.one_time_prekey_id, wide("0")?) == 0)
  assert(Bytes.length(normalized.one_time_prekey) == 0)
  assert(Bytes.secure_equals(encoded_bundle(normalized)?,
    encoded_bundle(%{maximal | one_time_prekey_id: wide("0")?, one_time_prekey: Bytes.empty()})?))
  Ok(true)
end

test("maximal hybrid prekey bundle round-trips at the canonical ceiling") do
  case maximal_bundle_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn signed_prekey_reauthorization_proof() -> Bool!String do
  let now = wide("1700000000000")?
  let expires = wide("1700604800000")?
  let (account_keys, account_identity) = account(now)?
  let device_keys = device()?
  let classical = classical_credential(account_keys, device_keys, now, expires)?
  let signed = signed_prekey(device_keys, classical, expires)?
  let original_id = signed.id
  let original_public_key = signed.public_key.bytes
  let post_quantum = post_quantum_prekey()?
  let hybrid = hybrid_credential(account_keys, device_keys, post_quantum, now, expires)?
  let signed = case reauthorize_signed_prekey(device_keys, hybrid, signed) do
    Err(_) -> Err("signed prekey reauthorization failed")
    Ok(value)
  end?
  let one_time = one_time_prekey()?
  let bundle = hybrid_bundle(hybrid, signed, one_time, post_quantum)?
  assert(U64.compare(signed.id, original_id) == 0)
  assert(Bytes.secure_equals(signed.public_key.bytes, original_public_key))
  assert(U64.compare(bundle.signed_prekey_id, original_id) == 0)
  assert(Bytes.secure_equals(bundle.signed_prekey, original_public_key))
  let valid = case verify_prekey_bundle(account_identity, bundle, 2, now, wide("1")?) do
    Err(_) -> Err("reauthorized hybrid bundle verification failed")
    Ok(value)
  end?
  assert(valid)
  Ok(true)
end

test("hybrid credential reauthorizes the existing signed prekey") do
  case signed_prekey_reauthorization_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn negotiated(value :: Result<Int, ProtocolError>) -> Int!String do
  case value do
    Err(_) -> Err("negotiation failed")
    Ok(selected)
  end
end

fn initiated(value :: Result<(RatchetState, InitialMessage), SessionError>) -> Result<(RatchetState, InitialMessage), String> do
  case value do
    Err(_) -> Err("initiation failed")
    Ok(started)
  end
end

fn received(value :: Result<(RatchetState, Bytes), SessionError>) -> Result<(RatchetState, Bytes), String> do
  case value do
    Err(_) -> Err("receive failed")
    Ok(opened)
  end
end

fn consume_sessions(first :: consume RatchetState, second :: consume RatchetState) do
  nil
end

fn consume_session(value :: consume RatchetState) do
  nil
end

fn consume_start(value :: consume (RatchetState, InitialMessage)) do
  nil
end

fn hybrid_ratchet(initiator :: consume RatchetState, responder :: consume RatchetState) -> Result<(RatchetState, RatchetState), String> do
  let plaintext = Bytes.from_utf8("hybrid ratchet")
  let associated_data = Bytes.from_utf8("conversation")
  case encrypt(initiator, plaintext, associated_data) do
    Err(_) -> do
      consume_session(responder)
      Err("ratchet encryption failed")
    end
    Ok(value) -> do
      let (next_initiator, message) = value
      case decrypt(responder, message, associated_data) do
        Rejected(next_responder, _) -> do
          consume_sessions(next_initiator, next_responder)
          Err("ratchet decryption failed")
        end
        Opened(next_responder, opened) -> do
          assert(Bytes.secure_equals(opened, plaintext))
          Ok((next_initiator, next_responder))
        end
      end
    end
  end
end

fn hybrid_proof() -> Bool!String do
  assert(negotiated(negotiate_suites([2, 1], [2, 1], 0))? == 2)
  assert(negotiated(negotiate_suites([2, 1], [1], 1))? == 1)
  case negotiate_suites([2, 1], [1], 2) do
    Err(DowngradeDetected) -> assert(true)
    _ -> assert(false)
  end
  let now = wide("1700000000000")?
  let expires = wide("1700604800000")?
  let verification_policy = VerificationPolicy {
    current_time: now,
    minimum_directory_sequence: wide("1")?
  }
  let (initiator_account_keys, initiator_account) = account(now)?
  let initiator_device = device()?
  let initiator_post_quantum = post_quantum_prekey()?
  let initiator_credential = hybrid_credential(initiator_account_keys,
    initiator_device,
    initiator_post_quantum,
    now,
    expires)?
  let (responder_account_keys, responder_account) = account(now)?
  let responder_device = device()?
  let responder_post_quantum = post_quantum_prekey()?
  let responder_credential = hybrid_credential(responder_account_keys,
    responder_device,
    responder_post_quantum,
    now,
    expires)?
  let responder_signed = signed_prekey(responder_device, responder_credential, expires)?
  let responder_one_time = one_time_prekey()?
  let responder_bundle = hybrid_bundle(responder_credential,
    responder_signed,
    responder_one_time,
    responder_post_quantum)?
  let plaintext = Bytes.from_utf8("hybrid hello")
  let (initiator_state, initial) = initiated(initiate(initiator_device,
    initiator_credential,
    responder_account,
    responder_bundle,
    verification_policy,
    0,
    plaintext))?
  let (responder_state, opened) = received(receive_initial(responder_device,
    responder_account,
    responder_bundle,
    responder_signed,
    responder_one_time,
    responder_post_quantum,
    initiator_account,
    verification_policy,
    verification_policy,
    0,
    initial_bytes(initial)?))?
  assert(initiator_state.suite == 2 && responder_state.suite == 2)
  assert(Bytes.secure_equals(initiator_state.session_id, responder_state.session_id))
  assert(Bytes.secure_equals(opened, plaintext))
  let (initiator_state, responder_state) = hybrid_ratchet(initiator_state, responder_state)?
  consume_sessions(initiator_state, responder_state)
  let tamper_signed = signed_prekey(responder_device, responder_credential, expires)?
  let tamper_one_time = one_time_prekey()?
  let tamper_bundle = hybrid_bundle(responder_credential,
    tamper_signed,
    tamper_one_time,
    responder_post_quantum)?
  let (tamper_state, tamper_initial) = initiated(initiate(initiator_device,
    initiator_credential,
    responder_account,
    tamper_bundle,
    verification_policy,
    0,
    Bytes.from_utf8("tamper proof")))?
  let tampered_initial = InitialMessage {
    version: tamper_initial.version,
    suite: tamper_initial.suite,
    signed_prekey_id: tamper_initial.signed_prekey_id,
    one_time_prekey_id: tamper_initial.one_time_prekey_id,
    initiator_credential: tamper_initial.initiator_credential,
    initiator_identity_public_key: tamper_initial.initiator_identity_public_key,
    initiator_ephemeral_public_key: tamper_initial.initiator_ephemeral_public_key,
    post_quantum_ciphertext: zeroes(1088)?,
    transcript_hash: tamper_initial.transcript_hash,
    nonce: tamper_initial.nonce,
    ciphertext: tamper_initial.ciphertext
  }
  let tamper_rejected = case receive_initial(responder_device,
    responder_account,
    tamper_bundle,
    tamper_signed,
    tamper_one_time,
    responder_post_quantum,
    initiator_account,
    verification_policy,
    verification_policy,
    0,
    initial_bytes(tampered_initial)?) do
    Err(AuthenticationRejected) -> true
    Err(_) -> false
    Ok(value) -> do
      let (unexpected_state, _) = value
      consume_session(unexpected_state)
      false
    end
  end
  consume_session(tamper_state)
  assert(tamper_rejected)
  let classical_credential_value = classical_credential(responder_account_keys,
    responder_device,
    now,
    expires)?
  let classical_signed = signed_prekey(responder_device, classical_credential_value, expires)?
  let classical_one_time = one_time_prekey()?
  let classical_bundle_value = classical_bundle(classical_credential_value,
    classical_signed,
    classical_one_time)?
  case initiate(initiator_device,
    initiator_credential,
    responder_account,
    classical_bundle_value,
    verification_policy,
    2,
    Bytes.from_utf8("downgrade")) do
    Err(ProtocolFailure(DowngradeDetected)) -> assert(true)
    Err(_) -> assert(false)
    Ok(value) -> do
      consume_start(value)
      assert(false)
    end
  end
  let (fallback_state, fallback_initial) = initiated(initiate(initiator_device,
    initiator_credential,
    responder_account,
    classical_bundle_value,
    verification_policy,
    1,
    Bytes.from_utf8("classical fallback")))?
  let (fallback_responder, fallback_opened) = received(receive_initial(responder_device,
    responder_account,
    classical_bundle_value,
    classical_signed,
    classical_one_time,
    responder_post_quantum,
    initiator_account,
    verification_policy,
    verification_policy,
    1,
    initial_bytes(fallback_initial)?))?
  assert(fallback_state.suite == 1 && fallback_responder.suite == 1)
  assert(Bytes.secure_equals(fallback_opened, Bytes.from_utf8("classical fallback")))
  consume_sessions(fallback_state, fallback_responder)
  Ok(true)
end

test("hybrid establishment, explicit classical fallback, and downgrade rejection") do
  case hybrid_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
