from Identity.Device import AccountKeys, DeviceKeys, VerificationPolicy, generate_account, generate_device, issue_device_credential, issue_hybrid_device_credential
from Prekeys.Bundle import OneTimePrekeySecrets, PostQuantumPrekeySecrets, PrekeyError, SignedPrekeySecrets, build_hybrid_prekey_bundle, build_prekey_bundle, generate_one_time_prekey, generate_post_quantum_prekey, generate_signed_prekey, normalize_prekey_bundle, reauthorize_signed_prekey, verify_prekey_bundle
from Prekeys.Renewal import (
  BundleTransition,
  RenewalRequest,
  bundle_renewal_request,
  bundle_with_renewal_request,
  classify_bundle_transition,
  decode_renewal_request,
  encode_renewal_request,
  generate_renewal_signed_prekey,
  issue_renewal_request,
  renewed_prekey_bundle,
  verify_renewal_request
)
from Protocol.HandshakeWire import encode_initial_message
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import AccountIdentity, DeviceCredential, InitialMessage, PrekeyBundle
from Session.Handshake import RatchetState, initial_message_uses_bundle, initiate, receive_initial

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
  expires :: U64,
  sequence :: U64) -> DeviceCredential!String do
  case issue_hybrid_device_credential(account_keys,
    device_keys,
    post_quantum.public_key,
    wide("1")?,
    now,
    expires,
    sequence) do
    Err(_) -> Err("hybrid credential failed")
    Ok(value)
  end
end

fn signed_prekey(device_keys :: borrow DeviceKeys,
  credential :: DeviceCredential,
  id :: U64,
  expires :: U64) -> SignedPrekeySecrets!String do
  case generate_signed_prekey(device_keys, credential, id, expires) do
    Err(_) -> Err("signed prekey failed")
    Ok(value)
  end
end

fn renewal_signed_prekey(device_keys :: borrow DeviceKeys,
  credential :: DeviceCredential,
  id :: U64,
  expires :: U64) -> SignedPrekeySecrets!String do
  case generate_renewal_signed_prekey(device_keys, credential, id, expires) do
    Err(_) -> Err("renewal signed prekey failed")
    Ok(value)
  end
end

fn one_time_prekey(id :: String) -> OneTimePrekeySecrets!String do
  case generate_one_time_prekey(wide(id)?) do
    Err(_) -> Err("one-time prekey failed")
    Ok(value)
  end
end

fn base_bundle(value :: Result<PrekeyBundle, PrekeyError>) -> PrekeyBundle!String do
  case value do
    Err(_) -> Err("bundle failed")
    Ok(bundle) -> case normalize_prekey_bundle(bundle) do
      Err(_) -> Err("bundle normalization failed")
      Ok(normalized)
    end
  end
end

fn request(device_keys :: borrow DeviceKeys,
  credential :: DeviceCredential,
  next_signed :: borrow SignedPrekeySecrets,
  next_post_quantum :: borrow PostQuantumPrekeySecrets) -> RenewalRequest!String do
  case issue_renewal_request(device_keys, credential, next_signed, next_post_quantum) do
    Err(_) -> Err("renewal request failed")
    Ok(value)
  end
end

fn requesting(bundle :: PrekeyBundle, value :: RenewalRequest) -> PrekeyBundle!String do
  case bundle_with_renewal_request(bundle, value) do
    Err(_) -> Err("request bundle failed")
    Ok(output)
  end
end

fn renewed(credential :: DeviceCredential, value :: RenewalRequest) -> PrekeyBundle!String do
  case renewed_prekey_bundle(credential, value) do
    Err(_) -> Err("renewed bundle failed")
    Ok(output)
  end
end

fn carried(bundle :: PrekeyBundle) -> Option<RenewalRequest>!String do
  case bundle_renewal_request(bundle) do
    Err(_) -> Err("carried request failed")
    Ok(value)
  end
end

fn encoded(bundle :: PrekeyBundle) -> Bytes!String do
  case encode_prekey_bundle(bundle) do
    Err(_) -> Err("bundle encoding failed")
    Ok(value)
  end
end

fn request_bytes(value :: RenewalRequest) -> Bytes!String do
  case encode_renewal_request(value) do
    Err(_) -> Err("request encoding failed")
    Ok(output)
  end
end

fn valid_bundle(account_identity :: AccountIdentity, bundle :: PrekeyBundle, now :: U64) -> Bool do
  case verify_prekey_bundle(account_identity, bundle, 2, now, account_identity.directory_sequence) do
    Err(_) -> false
    Ok(value) -> value
  end
end

fn accepted(value :: BundleTransition) -> Bool do
  case value do
    TransitionAccepted -> true
    _ -> false
  end
end

fn replayed(value :: BundleTransition) -> Bool do
  case value do
    TransitionReplayed -> true
    _ -> false
  end
end

fn refused(value :: BundleTransition) -> Bool do
  case value do
    TransitionRefused -> true
    _ -> false
  end
end

fn request_proof() -> Bool!String do
  let now = wide("1700000000000")?
  let expires = wide("1731536000000")?
  let later = wide("1739312000000")?
  let (account_keys, identity) = account(now)?
  let device_keys = device()?
  let stranger = device()?
  let first_post_quantum = post_quantum_prekey()?
  let credential = hybrid_credential(account_keys,
    device_keys,
    first_post_quantum,
    now,
    expires,
    wide("2")?)?
  let first_signed = signed_prekey(device_keys, credential, wide("1")?, expires)?
  let first_one_time = one_time_prekey("2")?
  let current = base_bundle(build_hybrid_prekey_bundle(credential,
    first_signed,
    first_one_time,
    first_post_quantum))?
  # A linked device cannot sign its own credential. It asks for the next one
  # with keys it made itself, signed with its own device key.
  let next_post_quantum = post_quantum_prekey()?
  let next_signed = renewal_signed_prekey(device_keys, credential, wide("2")?, later)?
  let asked = request(device_keys, credential, next_signed, next_post_quantum)?
  let wire = request_bytes(asked)?
  assert(Bytes.length(wire) == 1412)
  let decoded = case decode_renewal_request(wire) do
    Err(_) -> Err("request decoding failed")
    Ok(value)
  end?
  assert(Bytes.secure_equals(request_bytes(decoded)?, wire))
  assert(verify_renewal_request(credential, decoded))
  assert(U64.compare(decoded.signed_prekey_id, wide("2")?) == 0)
  assert(Bytes.secure_equals(decoded.post_quantum_prekey, next_post_quantum.public_key.bytes))
  # Another device's key, or any altered field, does not make a request.
  let forged = request(stranger, credential, next_signed, next_post_quantum)?
  assert(!verify_renewal_request(credential, forged))
  let other_post_quantum = post_quantum_prekey()?
  let swapped = %{asked | post_quantum_prekey: other_post_quantum.public_key.bytes}
  assert(!verify_renewal_request(credential, swapped))
  let stretched = %{asked | expires_at: U64.add(later, wide("1")?)?}
  assert(!verify_renewal_request(credential, stretched))
  # The request rides in the device's own logged bundle, in two extensions
  # because one extension holds at most 1,024 bytes. Peers ignore it.
  let published = requesting(current, asked)?
  assert(List.length(published.extensions) == 2)
  let reread = case decode_prekey_bundle(encoded(published)?) do
    Err(_) -> Err("published bundle decoding failed")
    Ok(value)
  end?
  case carried(reread)? do
    None -> assert(false)
    Some(value) -> assert(Bytes.secure_equals(request_bytes(value)?, wire))
  end
  case carried(current)? do
    None -> assert(true)
    Some(_) -> assert(false)
  end
  assert(valid_bundle(identity, published, now))
  # The account key answers with a credential for exactly those keys.
  let answer = hybrid_credential(account_keys, device_keys, next_post_quantum, now, later, wide("4")?)?
  let next = renewed(answer, asked)?
  assert(valid_bundle(identity, next, now))
  assert(U64.compare(next.signed_prekey_id, wide("2")?) == 0)
  assert(Bytes.secure_equals(next.signed_prekey, next_signed.public_key.bytes))
  assert(Bytes.secure_equals(next.post_quantum_prekey, next_post_quantum.public_key.bytes))
  assert(U64.compare(next.expires_at, later) == 0)
  assert(List.length(next.extensions) == 0)
  assert(Bytes.length(next.one_time_prekey) == 0)
  # A credential for other keys cannot carry the request.
  let wrong = hybrid_credential(account_keys, device_keys, first_post_quantum, now, later, wide("4")?)?
  case renewed_prekey_bundle(wrong, asked) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  # A classical device asks the same way and comes back hybrid: the request
  # signs its next prekey for the hybrid suite already.
  let classical = case issue_device_credential(account_keys, stranger, wide("1")?, now, expires, wide("3")?) do
    Err(_) -> Err("classical credential failed")
    Ok(value)
  end?
  let upgrade_post_quantum = post_quantum_prekey()?
  let upgrade_signed = renewal_signed_prekey(stranger, classical, wide("2")?, later)?
  let upgrade = request(stranger, classical, upgrade_signed, upgrade_post_quantum)?
  assert(verify_renewal_request(classical, upgrade))
  let upgraded = renewed(hybrid_credential(account_keys,
      stranger,
      upgrade_post_quantum,
      now,
      later,
      wide("5")?)?,
    upgrade)?
  assert(upgraded.suite == 2)
  assert(valid_bundle(identity, upgraded, now))
  Ok(true)
end

test("a linked device asks for renewal in its logged bundle and the account key answers") do
  case request_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn transition_proof() -> Bool!String do
  let now = wide("1700000000000")?
  let expires = wide("1731536000000")?
  let later = wide("1739312000000")?
  let (account_keys, _) = account(now)?
  let device_keys = device()?
  let stranger = device()?
  let first_post_quantum = post_quantum_prekey()?
  let credential = hybrid_credential(account_keys,
    device_keys,
    first_post_quantum,
    now,
    expires,
    wide("1")?)?
  let first_signed = signed_prekey(device_keys, credential, wide("1")?, expires)?
  let first_one_time = one_time_prekey("2")?
  let current = base_bundle(build_hybrid_prekey_bundle(credential,
    first_signed,
    first_one_time,
    first_post_quantum))?
  let next_post_quantum = post_quantum_prekey()?
  let next_signed = renewal_signed_prekey(device_keys, credential, wide("2")?, later)?
  let asked = request(device_keys, credential, next_signed, next_post_quantum)?
  let published = requesting(current, asked)?
  # Publishing a request is a transition of its own, under the same credential.
  assert(accepted(classify_bundle_transition(current, published, wide("2")?)))
  # Registering the bundle from before it is a replay: nothing changes.
  assert(replayed(classify_bundle_transition(published, current, wide("3")?)))
  assert(replayed(classify_bundle_transition(published, published, wide("3")?)))
  # The answer takes the next sequence, and only the next.
  let answer = hybrid_credential(account_keys, device_keys, next_post_quantum, now, later, wide("3")?)?
  let next = renewed(answer, asked)?
  assert(accepted(classify_bundle_transition(published, next, wide("3")?)))
  assert(refused(classify_bundle_transition(published, next, wide("4")?)))
  # Once renewed, anything under the older credential is a replay.
  assert(replayed(classify_bundle_transition(next, published, wide("4")?)))
  assert(replayed(classify_bundle_transition(next, current, wide("4")?)))
  # A new credential must bring a new signed prekey.
  let same_prekey = %{current | device_credential: next.device_credential, post_quantum_prekey: next.post_quantum_prekey}
  assert(refused(classify_bundle_transition(current, same_prekey, wide("3")?)))
  # Another device's keys never take this device's place.
  let intruder_post_quantum = post_quantum_prekey()?
  let intruder_credential = hybrid_credential(account_keys,
    stranger,
    intruder_post_quantum,
    now,
    later,
    wide("2")?)?
  let intruder_signed = signed_prekey(stranger, intruder_credential, wide("2")?, later)?
  let intruder_one_time = one_time_prekey("3")?
  let intruder = base_bundle(build_hybrid_prekey_bundle(intruder_credential,
    intruder_signed,
    intruder_one_time,
    intruder_post_quantum))?
  assert(refused(classify_bundle_transition(current, intruder, wide("2")?)))
  # A request the device did not sign, or for a prekey it already has, is refused.
  let forged = request(stranger, credential, next_signed, next_post_quantum)?
  assert(refused(classify_bundle_transition(current, requesting(current, forged)?, wide("2")?)))
  let stale_signed = renewal_signed_prekey(device_keys, credential, wide("1")?, later)?
  let stale = request(device_keys, credential, stale_signed, next_post_quantum)?
  assert(refused(classify_bundle_transition(current, requesting(current, stale)?, wide("2")?)))
  # A newer request replaces an older one; the older one then is a replay.
  let newer_signed = renewal_signed_prekey(device_keys, credential, wide("3")?, later)?
  let newer = requesting(current, request(device_keys, credential, newer_signed, next_post_quantum)?)?
  assert(accepted(classify_bundle_transition(published, newer, wide("3")?)))
  assert(replayed(classify_bundle_transition(newer, published, wide("4")?)))
  # No way back to the classical suite.
  let classical = case issue_device_credential(account_keys, device_keys, wide("1")?, now, later, wide("3")?) do
    Err(_) -> Err("classical credential failed")
    Ok(value)
  end?
  let classical_signed = signed_prekey(device_keys, classical, wide("4")?, later)?
  let classical_one_time = one_time_prekey("4")?
  let downgrade = base_bundle(build_prekey_bundle(classical, classical_signed, classical_one_time))?
  assert(refused(classify_bundle_transition(published, downgrade, wide("3")?)))
  # The original classical-to-hybrid step keeps its signed prekey.
  let old = case issue_device_credential(account_keys, stranger, wide("1")?, now, expires, wide("1")?) do
    Err(_) -> Err("classical credential failed")
    Ok(value)
  end?
  let old_signed = signed_prekey(stranger, old, wide("1")?, expires)?
  let old_one_time = one_time_prekey("5")?
  let old_bundle = base_bundle(build_prekey_bundle(old, old_signed, old_one_time))?
  let upgrade_post_quantum = post_quantum_prekey()?
  let upgrade = hybrid_credential(account_keys, stranger, upgrade_post_quantum, now, expires, wide("2")?)?
  let upgrade_signed = case reauthorize_signed_prekey(stranger, upgrade, old_signed) do
    Err(_) -> Err("reauthorization failed")
    Ok(value)
  end?
  let upgraded = base_bundle(build_hybrid_prekey_bundle(upgrade,
    upgrade_signed,
    old_one_time,
    upgrade_post_quantum))?
  assert(accepted(classify_bundle_transition(old_bundle, upgraded, wide("2")?)))
  Ok(true)
end

test("bundle transitions advance by renewal or request, replays change nothing, the rest is refused") do
  case transition_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn with_one_time(bundle :: PrekeyBundle, one_time :: borrow OneTimePrekeySecrets) -> PrekeyBundle do
  %{bundle | one_time_prekey_id: one_time.id, one_time_prekey: one_time.public_key.bytes}
end

fn consume_session(value :: consume RatchetState) do
  nil
end

fn initial_bytes(value :: InitialMessage) -> Bytes!String do
  case encode_initial_message(value) do
    Err(_) -> Err("initial encoding failed")
    Ok(encoded)
  end
end

fn transcript_proof() -> Bool!String do
  let now = wide("1700000000000")?
  let expires = wide("1731536000000")?
  let later = wide("1739312000000")?
  let policy = VerificationPolicy {
    current_time: now,
    minimum_directory_sequence: wide("1")?
  }
  let (sender_account_keys, sender_account) = account(now)?
  let sender = device()?
  let sender_post_quantum = post_quantum_prekey()?
  let sender_credential = hybrid_credential(sender_account_keys,
    sender,
    sender_post_quantum,
    now,
    expires,
    wide("1")?)?
  let (account_keys, identity) = account(now)?
  let device_keys = device()?
  let first_post_quantum = post_quantum_prekey()?
  let credential = hybrid_credential(account_keys,
    device_keys,
    first_post_quantum,
    now,
    expires,
    wide("1")?)?
  let first_signed = signed_prekey(device_keys, credential, wide("1")?, expires)?
  let registration = one_time_prekey("2")?
  let current = base_bundle(build_hybrid_prekey_bundle(credential,
    first_signed,
    registration,
    first_post_quantum))?
  let next_post_quantum = post_quantum_prekey()?
  let next_signed = renewal_signed_prekey(device_keys, credential, wide("2")?, later)?
  let published = requesting(current, request(device_keys, credential, next_signed, next_post_quantum)?)?
  # Two logged bundles share signed prekey 1: only the transcript tells which
  # one a first message was sealed to, and the responder needs that exact one.
  let one_time = one_time_prekey("7")?
  let (state, initial) = case initiate(sender,
    sender_credential,
    identity,
    with_one_time(published, one_time),
    policy,
    0,
    Bytes.from_utf8("sealed to the request bundle")) do
    Err(_) -> Err("initiation failed")
    Ok(value)
  end?
  consume_session(state)
  let wire = initial_bytes(initial)?
  assert(initial_message_uses_bundle(with_one_time(published, one_time), 0, wire))
  assert(!initial_message_uses_bundle(with_one_time(current, one_time), 0, wire))
  let sealed_to = with_one_time(published, one_time)
  let (responder, opened) = case receive_initial(device_keys,
    identity,
    sealed_to,
    first_signed,
    one_time,
    first_post_quantum,
    sender_account,
    policy,
    policy,
    0,
    wire) do
    Err(_) -> Err("receive failed")
    Ok(value)
  end?
  consume_session(responder)
  assert(Bytes.secure_equals(opened, Bytes.from_utf8("sealed to the request bundle")))
  Ok(true)
end

test("a first message names the exact logged bundle it was sealed to") do
  case transcript_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
