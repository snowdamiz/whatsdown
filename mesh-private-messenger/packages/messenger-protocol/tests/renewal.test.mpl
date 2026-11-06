from Session.State import RatchetState
from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  VerificationPolicy,
  generate_account,
  generate_device,
  issue_device_credential,
  issue_hybrid_device_credential
)
from Prekeys.Bundle import (
  OneTimePrekeySecrets,
  PostQuantumPrekeySecrets,
  PrekeyError,
  SignedPrekeySecrets,
  build_hybrid_prekey_bundle,
  build_prekey_bundle,
  generate_one_time_prekey,
  generate_post_quantum_prekey,
  generate_signed_prekey,
  normalize_prekey_bundle,
  reauthorize_signed_prekey,
  verify_prekey_bundle
)
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
  issue_ach3_renewal_request,
  issue_attachment_buckets_renewal_request,
  issue_header_encryption_renewal_request,
  issue_group_expiry_renewal_request,
  issue_current_readers_renewal_request,
  renewal_request_capabilities,
  renewed_prekey_bundle,
  verify_renewal_request
)
from Protocol.HandshakeWire import encode_initial_message
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import AccountIdentity, DeviceCredential, InitialMessage, PrekeyBundle
from Session.Handshake import initial_message_uses_bundle, initiate, receive_initial

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
  case verify_prekey_bundle(account_identity,
    bundle,
    2,
    now,
    account_identity.directory_sequence) do
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
  let answer = hybrid_credential(account_keys,
    device_keys,
    next_post_quantum,
    now,
    later,
    wide("4")?)?
  let next = renewed(answer, asked)?
  assert(valid_bundle(identity, next, now))
  assert(U64.compare(next.signed_prekey_id, wide("2")?) == 0)
  assert(Bytes.secure_equals(next.signed_prekey, next_signed.public_key.bytes))
  assert(Bytes.secure_equals(next.post_quantum_prekey, next_post_quantum.public_key.bytes))
  assert(U64.compare(next.expires_at, later) == 0)
  assert(List.length(next.extensions) == 0)
  assert(Bytes.length(next.one_time_prekey) == 0)
  # A credential for other keys cannot carry the request.
  let wrong = hybrid_credential(account_keys,
    device_keys,
    first_post_quantum,
    now,
    later,
    wide("4")?)?
  case renewed_prekey_bundle(wrong, asked) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  # A classical device asks the same way and comes back hybrid: the request
  # signs its next prekey for the hybrid suite already.
  let classical = case issue_device_credential(account_keys,
    stranger,
    wide("1")?,
    now,
    expires,
    wide("3")?) do
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
  let answer = hybrid_credential(account_keys,
    device_keys,
    next_post_quantum,
    now,
    later,
    wide("3")?)?
  let next = renewed(answer, asked)?
  assert(accepted(classify_bundle_transition(published, next, wide("3")?)))
  assert(refused(classify_bundle_transition(published, next, wide("4")?)))
  # Once renewed, anything under the older credential is a replay.
  assert(replayed(classify_bundle_transition(next, published, wide("4")?)))
  assert(replayed(classify_bundle_transition(next, current, wide("4")?)))
  # A new credential must bring a new signed prekey.
  let same_prekey = %{current |
    device_credential: next.device_credential,
    post_quantum_prekey: next.post_quantum_prekey
  }
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
  let newer = requesting(current,
    request(device_keys, credential, newer_signed, next_post_quantum)?)?
  assert(accepted(classify_bundle_transition(published, newer, wide("3")?)))
  assert(replayed(classify_bundle_transition(newer, published, wide("4")?)))
  # No way back to the classical suite.
  let classical = case issue_device_credential(account_keys,
    device_keys,
    wide("1")?,
    now,
    later,
    wide("3")?) do
    Err(_) -> Err("classical credential failed")
    Ok(value)
  end?
  let classical_signed = signed_prekey(device_keys, classical, wide("4")?, later)?
  let classical_one_time = one_time_prekey("4")?
  let downgrade = base_bundle(build_prekey_bundle(classical, classical_signed, classical_one_time))?
  assert(refused(classify_bundle_transition(published, downgrade, wide("3")?)))
  # The original classical-to-hybrid step keeps its signed prekey.
  let old = case issue_device_credential(account_keys,
    stranger,
    wide("1")?,
    now,
    expires,
    wide("1")?) do
    Err(_) -> Err("classical credential failed")
    Ok(value)
  end?
  let old_signed = signed_prekey(stranger, old, wide("1")?, expires)?
  let old_one_time = one_time_prekey("5")?
  let old_bundle = base_bundle(build_prekey_bundle(old, old_signed, old_one_time))?
  let upgrade_post_quantum = post_quantum_prekey()?
  let upgrade = hybrid_credential(account_keys,
    stranger,
    upgrade_post_quantum,
    now,
    expires,
    wide("2")?)?
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
  let policy = VerificationPolicy { current_time: now, minimum_directory_sequence: wide("1")? }
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
  let published = requesting(current,
    request(device_keys, credential, next_signed, next_post_quantum)?)?
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

fn capability_inference_proof() -> Bool!String do
  let now = wide("1700000000000")?
  let expires = wide("1731536000000")?
  let later = wide("1739312000000")?
  let (account_keys, _) = account(now)?
  let device_keys = device()?
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
  let answer = case issue_hybrid_device_credential(account_keys,
    device_keys,
    next_post_quantum.public_key,
    wide("3")?,
    now,
    later,
    wide("3")?) do
    Err(_) -> Err("capability credential failed")
    Ok(value)
  end?
  let proposed = renewed(answer, asked)?
  # An account signature alone must not claim that an existing device upgraded.
  assert(refused(classify_bundle_transition(current, proposed, wide("3")?)))
  # A valid legacy request asks only for keys, never a different capability mask.
  let published = requesting(current, asked)?
  assert(refused(classify_bundle_transition(published, proposed, wide("3")?)))
  Ok(true)
end

test("account renewal cannot infer ACH3 support without the device's signed capability request") do
  case capability_inference_proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn signed_capability_mask(device_keys :: borrow DeviceKeys,
  value :: RenewalRequest,
  mask :: U64) -> RenewalRequest!String do
  let zero = case Bytes.repeat(0, 64) do
    Err(_) -> return Err("signature allocation failed")
    Ok(value) -> value
  end
  let unsigned = %{value | requested_capabilities: Some(mask), signature: zero}
  let message = case Bytes.concat(Bytes.from_utf8("mesh-msg/v1/device-renewal-request"),
    request_bytes(unsigned)?) do
    Err(_) -> return Err("request framing failed")
    Ok(value) -> value
  end
  case Crypto.sign(device_keys.signing_private_key, message) do
    Err(_) -> Err("request signing failed")
    Ok(signature) -> Ok(%{unsigned | signature: signature.bytes})
  end
end

fn capability_request_proof(headers :: Bool) -> Bool!String do
  let expected_mask = if headers do
    wide("15")?
  else
    wide("3")?
  end
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
    wide("1")?)?
  let first_signed = signed_prekey(device_keys, credential, wide("1")?, expires)?
  let first_one_time = one_time_prekey("2")?
  let current = base_bundle(build_hybrid_prekey_bundle(credential,
    first_signed,
    first_one_time,
    first_post_quantum))?
  let next_post_quantum = post_quantum_prekey()?
  let next_signed = renewal_signed_prekey(device_keys, credential, wide("2")?, later)?
  let legacy = request(device_keys, credential, next_signed, next_post_quantum)?
  assert(legacy.version == 1 && Option.is_none(legacy.requested_capabilities))
  case renewal_request_capabilities(credential, legacy) do
    Err(_) -> assert(false)
    Ok(mask) -> assert(U64.compare(mask, credential.capabilities) == 0)
  end
  let asked = case if headers do
    issue_header_encryption_renewal_request(device_keys, credential, next_signed, next_post_quantum)
  else
    issue_ach3_renewal_request(device_keys, credential, next_signed, next_post_quantum)
  end do
    Err(_) -> return Err("capability request failed")
    Ok(value) -> value
  end
  let wire = request_bytes(asked)?
  assert(asked.version == 2 && Bytes.length(wire) == 1416)
  assert(verify_renewal_request(credential, asked))
  let decoded = case decode_renewal_request(wire) do
    Err(_) -> return Err("v2 decoding failed")
    Ok(value) -> value
  end
  assert(Bytes.secure_equals(request_bytes(decoded)?, wire))
  case renewal_request_capabilities(credential, decoded) do
    Err(_) -> assert(false)
    Ok(mask) -> assert(U64.compare(mask, expected_mask) == 0)
  end
  let clearing = signed_capability_mask(device_keys, asked, wide("2")?)?
  let unrelated = signed_capability_mask(device_keys, asked, wide("63")?)?
  let wrong_signer = signed_capability_mask(stranger, asked, expected_mask)?
  assert(!verify_renewal_request(credential, clearing))
  assert(!verify_renewal_request(credential, unrelated))
  assert(!verify_renewal_request(credential, wrong_signer))
  assert(!verify_renewal_request(credential, %{asked | requested_capabilities: Some(wide("1")?)}))
  case encode_renewal_request(%{asked | requested_capabilities: None}) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  case encode_renewal_request(%{legacy | requested_capabilities: Some(wide("3")?)}) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  let trailing = case Bytes.concat(wire, Bytes.from_utf8("x")) do
    Err(_) -> return Err("fixture append failed")
    Ok(value) -> value
  end
  case decode_renewal_request(trailing) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  let truncated = case Bytes.slice(wire, 0, Bytes.length(wire) - 1) do
    Err(_) -> return Err("fixture truncation failed")
    Ok(value) -> value
  end
  case decode_renewal_request(truncated) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  let published = requesting(current, asked)?
  assert(valid_bundle(identity, published, now))
  assert(accepted(classify_bundle_transition(current, published, wide("2")?)))
  let answer = case issue_hybrid_device_credential(account_keys,
    device_keys,
    next_post_quantum.public_key,
    expected_mask,
    now,
    later,
    wide("3")?) do
    Err(_) -> return Err("capability answer failed")
    Ok(value) -> value
  end
  let proposed = renewed(answer, asked)?
  assert(valid_bundle(identity, proposed, now))
  assert(refused(classify_bundle_transition(current, proposed, wide("3")?)))
  assert(accepted(classify_bundle_transition(published, proposed, wide("3")?)))
  assert(replayed(classify_bundle_transition(proposed, published, wide("4")?)))
  let unchanged = hybrid_credential(account_keys,
    device_keys,
    next_post_quantum,
    now,
    later,
    wide("3")?)?
  case renewed_prekey_bundle(unchanged, asked) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  let ignored = renewed(unchanged, legacy)?
  assert(refused(classify_bundle_transition(published, ignored, wide("3")?)))
  Ok(true)
end

test("RNWv2 binds the exact ACH3 upgrade and only its witnessed prior device request authorizes the answer") do
  case capability_request_proof(false) do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn padded_capability_request_proof() -> Bool!String do
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
    wide("1")?)?
  let next_post_quantum = post_quantum_prekey()?
  let next_signed = renewal_signed_prekey(device_keys, credential, wide("2")?, later)?
  let asked = case issue_ach3_renewal_request(device_keys,
    credential,
    next_signed,
    next_post_quantum) do
    Err(_) -> return Err("capability request failed")
    Ok(value) -> value
  end
  let padded = signed_capability_mask(device_keys, asked, wide("7")?)?
  let issued = case issue_attachment_buckets_renewal_request(device_keys,
    credential,
    next_signed,
    next_post_quantum) do
    Err(_) -> return Err("padded capability request failed")
    Ok(value) -> value
  end
  assert(Bytes.secure_equals(request_bytes(issued)?, request_bytes(padded)?))
  assert(verify_renewal_request(credential, padded))
  case renewal_request_capabilities(credential, padded) do
    Err(_) -> assert(false)
    Ok(mask) -> assert(U64.compare(mask, wide("7")?) == 0)
  end
  assert(!verify_renewal_request(credential,
    signed_capability_mask(device_keys, asked, wide("63")?)?))
  assert(!verify_renewal_request(credential,
    signed_capability_mask(device_keys, asked, wide("5")?)?))
  assert(!verify_renewal_request(credential, signed_capability_mask(stranger, asked, wide("7")?)?))
  Ok(true)
end

test("padded attachment support requires an exact authenticated monotone device-signed mask7 claim") do
  case padded_capability_request_proof() do
    Ok(value) -> assert(value)
    Err(_) -> assert(false)
  end
end

test("HE capability mask15 requires device signature, exact published prior request and monotone witnessed answer; unknown bits or unsigned downgrade fail") do
  case capability_request_proof(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn group_expiry_claim_proof() -> Bool!String do
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
    wide("1")?)?
  let first_signed = signed_prekey(device_keys, credential, wide("1")?, expires)?
  let current = base_bundle(build_hybrid_prekey_bundle(credential,
    first_signed,
    one_time_prekey("2")?,
    first_post_quantum))?
  let next_post_quantum = post_quantum_prekey()?
  let next_signed = renewal_signed_prekey(device_keys, credential, wide("2")?, later)?
  let asked = case issue_group_expiry_renewal_request(device_keys,
    credential,
    next_signed,
    next_post_quantum) do
    Err(_) -> return Err("group expiry claim failed")
    Ok(value) -> value
  end
  assert(asked.version == 2 && Bytes.length(request_bytes(asked)?) == 1416)
  assert(verify_renewal_request(credential, asked))
  case renewal_request_capabilities(credential, asked) do
    Err(_) -> assert(false)
    Ok(mask) -> assert(U64.compare(mask, wide("23")?) == 0)
  end
  assert(!verify_renewal_request(credential,
    signed_capability_mask(device_keys, asked, wide("16")?)?))
  assert(!verify_renewal_request(credential,
    signed_capability_mask(device_keys, asked, wide("63")?)?))
  assert(!verify_renewal_request(credential, signed_capability_mask(stranger, asked, wide("23")?)?))
  let upgraded = case issue_hybrid_device_credential(account_keys,
    device_keys,
    next_post_quantum.public_key,
    wide("23")?,
    now,
    later,
    wide("3")?) do
    Err(_) -> return Err("group expiry credential failed")
    Ok(value) -> value
  end
  # An extra one-time prekey is legal; this refusal must instead mismatch the
  # exact signed prekey authenticated by the device's durable prior request.
  let unrequested_signed = renewal_signed_prekey(device_keys, credential, wide("4")?, later)?
  let malformed_answer = base_bundle(build_hybrid_prekey_bundle(upgraded,
    unrequested_signed,
    one_time_prekey("3")?,
    next_post_quantum))?
  let answer = renewed(upgraded, asked)?
  assert(!accepted(classify_bundle_transition(current, answer, wide("3")?)))
  let pending = requesting(current, asked)?
  assert(valid_bundle(identity, pending, now))
  assert(accepted(classify_bundle_transition(current, pending, wide("2")?)))
  assert(!accepted(classify_bundle_transition(pending, malformed_answer, wide("3")?)))
  assert(accepted(classify_bundle_transition(pending, answer, wide("3")?)))
  Ok(true)
end

test("GMS6 capability requires exact device-signed monotone mask23 and a stored prior request") do
  case group_expiry_claim_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn current_reader_claim_proof(previous :: String, expected :: String) -> Bool!String do
  let now = wide("1700000000000")?
  let expires = wide("1731536000000")?
  let later = wide("1739312000000")?
  let (account_keys, identity) = account(now)?
  let device_keys = device()?
  let stranger = device()?
  let first_post_quantum = post_quantum_prekey()?
  let credential = case issue_hybrid_device_credential(account_keys,
    device_keys,
    first_post_quantum.public_key,
    wide(previous)?,
    now,
    expires,
    wide("1")?) do
    Err(_) -> return Err("prior reader credential failed")
    Ok(value) -> value
  end
  let first_signed = signed_prekey(device_keys, credential, wide("1")?, expires)?
  let current = base_bundle(build_hybrid_prekey_bundle(credential,
    first_signed,
    one_time_prekey("2")?,
    first_post_quantum))?
  let next_post_quantum = post_quantum_prekey()?
  let next_signed = renewal_signed_prekey(device_keys, credential, wide("2")?, later)?
  let asked = case issue_current_readers_renewal_request(device_keys,
    credential,
    next_signed,
    next_post_quantum) do
    Err(_) -> return Err("group expiry claim failed")
    Ok(value) -> value
  end
  assert(asked.version == 2 && Bytes.length(request_bytes(asked)?) == 1416)
  assert(verify_renewal_request(credential, asked))
  case renewal_request_capabilities(credential, asked) do
    Err(_) -> assert(false)
    Ok(mask) -> assert(U64.compare(mask, wide(expected)?) == 0)
  end
  assert(!verify_renewal_request(credential,
    signed_capability_mask(device_keys, asked, wide("16")?)?))
  assert(!verify_renewal_request(credential,
    signed_capability_mask(device_keys, asked, wide("63")?)?))
  assert(!verify_renewal_request(credential, signed_capability_mask(stranger, asked, wide(expected)?)?))
  let upgraded = case issue_hybrid_device_credential(account_keys,
    device_keys,
    next_post_quantum.public_key,
    wide(expected)?,
    now,
    later,
    wide("3")?) do
    Err(_) -> return Err("group expiry credential failed")
    Ok(value) -> value
  end
  # An extra one-time prekey is legal; this refusal must instead mismatch the
  # exact signed prekey authenticated by the device's durable prior request.
  let unrequested_signed = renewal_signed_prekey(device_keys, credential, wide("4")?, later)?
  let malformed_answer = base_bundle(build_hybrid_prekey_bundle(upgraded,
    unrequested_signed,
    one_time_prekey("3")?,
    next_post_quantum))?
  let answer = renewed(upgraded, asked)?
  assert(if previous == expected do
    accepted(classify_bundle_transition(current, answer, wide("3")?))
  else
    refused(classify_bundle_transition(current, answer, wide("3")?))
  end)
  let pending = requesting(current, asked)?
  assert(valid_bundle(identity, pending, now))
  assert(accepted(classify_bundle_transition(current, pending, wide("2")?)))
  assert(!accepted(classify_bundle_transition(pending, malformed_answer, wide("3")?)))
  assert(accepted(classify_bundle_transition(pending, answer, wide("3")?)))
  Ok(true)
end

test("combined readers renew from legacy, HE-only and group-only signed credentials without losing capability bits") do
  for previous in ["1", "7", "15", "23", "31"] do
    case current_reader_claim_proof(previous, "31") do
      Err(error) -> do
        println(previous)
        println(error)
        assert(false)
      end
      Ok(value) -> assert(value)
    end
  end
  # A previously signed future bit is preserved, never inferred or cleared.
  for previous in ["65", "95"] do
    case current_reader_claim_proof(previous, "95") do
      Err(error) -> do
        println(previous)
        println(error)
        assert(false)
      end
      Ok(value) -> assert(value)
    end
  end
end
