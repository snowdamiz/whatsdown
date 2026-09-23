from Identity.Device import IdentityError, authorize_device_link, generate_account, generate_device, issue_account_deletion, issue_device_departure, issue_device_revocation, verify_account_deletion, verify_device_departure, verify_device_link_authorization, verify_device_revocation
from Protocol.DirectoryWire import (
  decode_account_deletion,
  decode_device_departure,
  decode_device_link_authorization,
  decode_device_link_request,
  decode_device_revocation,
  decode_device_set,
  encode_account_deletion,
  encode_device_departure,
  encode_device_link_authorization,
  encode_device_link_request,
  encode_device_revocation,
  encode_device_set
)
from Protocol.IdentityWire import decode_device_credential
from Protocol.V1 import (
  DeviceLinkAuthorization,
  DeviceLinkRequest,
  DeviceRevocation,
  DeviceSet,
  DirectoryEntry,
  ProtocolError
)

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn wide(value :: Int) -> U64!ProtocolError do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err(MalformedEncoding)
    Ok(parsed)
  end
end

fn proof() -> Bool!ProtocolError do
  let link_request = DeviceLinkRequest {
    version: 1,
    suite: 1,
    nonce: repeated(1, 32),
    device_id: repeated(2, 16),
    signing_public_key: repeated(3, 32),
    dh_public_key: repeated(4, 32),
    post_quantum_public_key: Bytes.empty(),
    capabilities: wide(1)?,
    created_at: wide(1000)?,
    expires_at: wide(2000)?
  }
  let link_wire = encode_device_link_request(link_request)?
  let historical_link_wire = case Bytes.from_hex("014c4e4b01010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404000000000000000100000000000003e800000000000007d0") do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end?
  assert(Bytes.length(link_wire) == 140)
  assert(Bytes.secure_equals(link_wire, historical_link_wire))
  let decoded_link = decode_device_link_request(link_wire)?
  assert(Bytes.secure_equals(encode_device_link_request(decoded_link)?, link_wire))
  assert(decoded_link.suite == 1)
  assert(Bytes.length(decoded_link.post_quantum_public_key) == 0)
  assert(Bytes.secure_equals(decoded_link.device_id, link_request.device_id))
  assert(Bytes.secure_equals(decoded_link.nonce, link_request.nonce))
  let authorization = DeviceLinkAuthorization {
    version: 1,
    request_hash: Crypto.sha256(link_wire),
    username: "alice",
    account_identity: Bytes.from_utf8("account"),
    device_credential: Bytes.from_utf8("credential"),
    authorization_signature: repeated(11, 64)
  }
  let decoded_authorization = decode_device_link_authorization(encode_device_link_authorization(authorization)?)?
  assert(decoded_authorization.username == "alice")
  assert(Bytes.secure_equals(decoded_authorization.request_hash, authorization.request_hash))
  let first = DirectoryEntry {
    version: 1,
    username: "alice",
    account_identity: Bytes.from_utf8("account"),
    prekey_bundle: Bytes.from_utf8("prekey-a"),
    mailbox_token: repeated(5, 32)
  }
  let second = DirectoryEntry {
    version: 1,
    username: "alice",
    account_identity: Bytes.from_utf8("account"),
    prekey_bundle: Bytes.from_utf8("prekey-b"),
    mailbox_token: repeated(6, 32)
  }
  let device_set = DeviceSet {
    version: 1,
    username: "alice",
    account_identity: Bytes.from_utf8("account"),
    sequence: wide(3)?,
    devices: [first, second],
    revoked_device_ids: [repeated(7, 16)]
  }
  let decoded_set = decode_device_set(encode_device_set(device_set)?)?
  assert(U64.compare(decoded_set.sequence, wide(3)?) == 0)
  assert(List.length(decoded_set.devices) == 2)
  assert(List.length(decoded_set.revoked_device_ids) == 1)
  let revocation = DeviceRevocation {
    version: 1,
    account_id: repeated(8, 32),
    device_id: repeated(9, 16),
    sequence: wide(4)?,
    signature: repeated(10, 64)
  }
  let revocation_wire = encode_device_revocation(revocation)?
  let decoded_revocation = decode_device_revocation(revocation_wire)?
  assert(U64.compare(decoded_revocation.sequence, revocation.sequence) == 0)
  assert(Bytes.secure_equals(decoded_revocation.device_id, revocation.device_id))
  let trailing = case Bytes.concat(revocation_wire, Bytes.from_utf8("trailing")) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end?
  case decode_device_revocation(trailing) do
    Err(MalformedEncoding) -> assert(true)
    _ -> assert(false)
  end
  Ok(true)
end

test("device linking and device-set records have bounded canonical codecs") do
  case proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

fn hybrid_codec_proof() -> Bool!ProtocolError do
  let request = DeviceLinkRequest {
    version: 2,
    suite: 2,
    nonce: repeated(31, 32),
    device_id: repeated(32, 16),
    signing_public_key: repeated(33, 32),
    dh_public_key: repeated(34, 32),
    post_quantum_public_key: repeated(35, 1184),
    capabilities: wide(1)?,
    created_at: wide(1000)?,
    expires_at: wide(2000)?
  }
  let wire = encode_device_link_request(request)?
  assert(Bytes.length(wire) == 1326)
  let decoded = decode_device_link_request(wire)?
  assert(decoded.version == 2)
  assert(decoded.suite == 2)
  assert(Bytes.secure_equals(decoded.post_quantum_public_key, request.post_quantum_public_key))
  assert(Bytes.secure_equals(encode_device_link_request(decoded)?, wire))
  let mismatched_suite = DeviceLinkRequest {
    version: 2,
    suite: 1,
    nonce: request.nonce,
    device_id: request.device_id,
    signing_public_key: request.signing_public_key,
    dh_public_key: request.dh_public_key,
    post_quantum_public_key: request.post_quantum_public_key,
    capabilities: request.capabilities,
    created_at: request.created_at,
    expires_at: request.expires_at
  }
  case encode_device_link_request(mismatched_suite) do
    Err(UnsupportedSuite) -> assert(true)
    _ -> assert(false)
  end
  let short_key = DeviceLinkRequest {
    version: 2,
    suite: 2,
    nonce: request.nonce,
    device_id: request.device_id,
    signing_public_key: request.signing_public_key,
    dh_public_key: request.dh_public_key,
    post_quantum_public_key: repeated(35, 1183),
    capabilities: request.capabilities,
    created_at: request.created_at,
    expires_at: request.expires_at
  }
  case encode_device_link_request(short_key) do
    Err(InvalidFieldLength) -> assert(true)
    _ -> assert(false)
  end
  let trailing = case Bytes.concat(wire, Bytes.from_utf8("x")) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end?
  case decode_device_link_request(trailing) do
    Err(OversizedInput) -> assert(true)
    _ -> assert(false)
  end
  Ok(true)
end

test("hybrid device-link requests have a canonical v2 wire format") do
  case hybrid_codec_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

fn identity_wide(value :: Int) -> U64!IdentityError do
  case U64.parse(Int.to_string(value)) do
    Err(_) -> Err(InvalidCredential)
    Ok(parsed)
  end
end

fn identity_proof() -> Bool!IdentityError do
  let now = identity_wide(1000)?
  let (account, identity) = generate_account(now, identity_wide(1)?)?
  let request = DeviceLinkRequest {
    version: 1,
    suite: 1,
    nonce: repeated(21, 32),
    device_id: repeated(22, 16),
    signing_public_key: repeated(23, 32),
    dh_public_key: repeated(24, 32),
    post_quantum_public_key: Bytes.empty(),
    capabilities: identity_wide(1)?,
    created_at: now,
    expires_at: identity_wide(2000)?
  }
  let authorization = authorize_device_link(account,
    identity,
    request,
    "alice",
    identity_wide(31536001000)?,
    identity_wide(2)?)?
  assert(verify_device_link_authorization(request, authorization, now, identity_wide(1)?)?)
  let wrong_request = DeviceLinkRequest {
    version: request.version,
    suite: request.suite,
    nonce: repeated(25, 32),
    device_id: request.device_id,
    signing_public_key: request.signing_public_key,
    dh_public_key: request.dh_public_key,
    post_quantum_public_key: request.post_quantum_public_key,
    capabilities: request.capabilities,
    created_at: request.created_at,
    expires_at: request.expires_at
  }
  assert(!verify_device_link_authorization(wrong_request, authorization, now, identity_wide(1)?)?)
  let revocation = issue_device_revocation(account, repeated(26, 16), identity_wide(3)?)?
  assert(verify_device_revocation(identity, revocation)?)
  let changed_revocation = DeviceRevocation {
    version: revocation.version,
    account_id: revocation.account_id,
    device_id: repeated(27, 16),
    sequence: revocation.sequence,
    signature: revocation.signature
  }
  assert(!verify_device_revocation(identity, changed_revocation)?)
  Ok(true)
end

test("account authorization binds links and revocations to exact devices") do
  case identity_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

fn hybrid_identity_proof() -> Bool!IdentityError do
  let now = identity_wide(1000)?
  let (account, identity) = generate_account(now, identity_wide(1)?)?
  let request = DeviceLinkRequest {
    version: 2,
    suite: 2,
    nonce: repeated(41, 32),
    device_id: repeated(42, 16),
    signing_public_key: repeated(43, 32),
    dh_public_key: repeated(44, 32),
    post_quantum_public_key: repeated(45, 1184),
    capabilities: identity_wide(1)?,
    created_at: now,
    expires_at: identity_wide(2000)?
  }
  let authorization = authorize_device_link(account,
    identity,
    request,
    "alice",
    identity_wide(31536001000)?,
    identity_wide(2)?)?
  assert(authorization.version == 1)
  case encode_device_link_request(request) do
    Err(_) -> assert(false)
    Ok(wire) -> assert(Bytes.secure_equals(authorization.request_hash, Crypto.sha256(wire)))
  end
  case decode_device_credential(authorization.device_credential) do
    Err(_) -> assert(false)
    Ok(credential) -> do
      assert(credential.suite == 2)
      assert(Bytes.secure_equals(credential.post_quantum_public_key,
        request.post_quantum_public_key))
    end
  end
  assert(verify_device_link_authorization(request, authorization, now, identity_wide(1)?)?)
  let stripped = DeviceLinkRequest {
    version: 1,
    suite: 1,
    nonce: request.nonce,
    device_id: request.device_id,
    signing_public_key: request.signing_public_key,
    dh_public_key: request.dh_public_key,
    post_quantum_public_key: Bytes.empty(),
    capabilities: request.capabilities,
    created_at: request.created_at,
    expires_at: request.expires_at
  }
  assert(!verify_device_link_authorization(stripped, authorization, now, identity_wide(1)?)?)
  Ok(true)
end

test("account authorization preserves hybrid device-link credentials and rejects stripped downgrades") do
  case hybrid_identity_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

fn account_deletion_proof() -> Bool!IdentityError do
  let now = identity_wide(1000)?
  let (account, identity) = generate_account(now, identity_wide(1)?)?
  let (stranger, _) = generate_account(now, identity_wide(1)?)?
  let deletion = issue_account_deletion(account, now)?
  assert(Bytes.secure_equals(deletion.account_id, identity.account_id))
  assert(verify_account_deletion(identity, deletion)?)
  # The time is signed, so a verifier's freshness check cannot be walked around.
  assert(!verify_account_deletion(identity, % { deletion | issued_at: identity_wide(1001)? })?)
  let forged = issue_account_deletion(stranger, now)?
  assert(!verify_account_deletion(identity, % { forged | account_id: identity.account_id })?)
  let wire = case encode_account_deletion(deletion) do
    Err(_) -> Err(InvalidCredential)
    Ok(value)
  end?
  assert(Bytes.length(wire) == 108)
  let decoded = case decode_account_deletion(wire) do
    Err(_) -> Err(InvalidCredential)
    Ok(value)
  end?
  assert(verify_account_deletion(identity, decoded)?)
  let trailing = case Bytes.concat(wire, Bytes.from_utf8("x")) do
    Err(_) -> Err(InvalidCredential)
    Ok(value)
  end?
  case decode_account_deletion(trailing) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("only the account key deletes an account, at the time it signed") do
  case account_deletion_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end

fn device_departure_proof() -> Bool!IdentityError do
  let now = identity_wide(1000)?
  let device = generate_device()?
  let stranger = generate_device()?
  let account_id = repeated(51, 32)
  let departure = issue_device_departure(device, account_id, now)?
  assert(Bytes.secure_equals(departure.device_id, device.device_id))
  assert(verify_device_departure(device.signing_public_key.bytes, departure)?)
  # Only the departing device's own key, for its own account, at the signed time.
  assert(!verify_device_departure(stranger.signing_public_key.bytes, departure)?)
  assert(!verify_device_departure(device.signing_public_key.bytes,
    % { departure | account_id: repeated(52, 32) })?)
  assert(!verify_device_departure(device.signing_public_key.bytes,
    % { departure | issued_at: identity_wide(1001)? })?)
  let wire = case encode_device_departure(departure) do
    Err(_) -> Err(InvalidCredential)
    Ok(value)
  end?
  assert(Bytes.length(wire) == 124)
  let decoded = case decode_device_departure(wire) do
    Err(_) -> Err(InvalidCredential)
    Ok(value)
  end?
  assert(verify_device_departure(device.signing_public_key.bytes, decoded)?)
  let trailing = case Bytes.concat(wire, Bytes.from_utf8("x")) do
    Err(_) -> Err(InvalidCredential)
    Ok(value)
  end?
  case decode_device_departure(trailing) do
    Err(_) -> assert(true)
    Ok(_) -> assert(false)
  end
  Ok(true)
end

test("only a device's own key takes it out of its account, at the time it signed") do
  case device_departure_proof() do
    Err(_) -> assert(false)
    Ok(value) -> assert(value)
  end
end
