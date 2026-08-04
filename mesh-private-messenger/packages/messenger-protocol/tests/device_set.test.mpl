from Identity.Device import IdentityError, authorize_device_link, generate_account, issue_device_revocation, verify_device_link_authorization, verify_device_revocation
from Protocol.V1 import DeviceLinkAuthorization, DeviceLinkRequest, DeviceRevocation, DeviceSet, DirectoryEntry, ProtocolError, decode_device_link_authorization, decode_device_link_request, decode_device_revocation, decode_device_set, encode_device_link_authorization, encode_device_link_request, encode_device_revocation, encode_device_set

fn repeated(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err( _) -> Bytes.empty()
    Ok( output) -> output
  end
end

fn wide(value :: Int) -> U64 ! ProtocolError do
  case U64.parse(Int.to_string(value)) do
    Err( _) -> Err(MalformedEncoding)
    Ok( parsed) -> Ok(parsed)
  end
end

fn proof() -> Bool ! ProtocolError do
  let link_request = DeviceLinkRequest {
    version : 1,
    nonce : repeated(1, 32),
    device_id : repeated(2, 16),
    signing_public_key : repeated(3, 32),
    dh_public_key : repeated(4, 32),
    capabilities : wide(1) ?,
    created_at : wide(1000) ?,
    expires_at : wide(2000) ?
  }
  let link_wire = encode_device_link_request(link_request) ?
  let decoded_link = decode_device_link_request(link_wire) ?
  assert(Bytes.secure_equals(decoded_link.device_id, link_request.device_id))
  assert(Bytes.secure_equals(decoded_link.nonce, link_request.nonce))
  let authorization = DeviceLinkAuthorization {
    version : 1,
    request_hash : Crypto.sha256(link_wire),
    username : "alice",
    account_identity : Bytes.from_utf8("account"),
    device_credential : Bytes.from_utf8("credential"),
    authorization_signature : repeated(11, 64)
  }
  let decoded_authorization = decode_device_link_authorization(encode_device_link_authorization(authorization) ?) ?
  assert(decoded_authorization.username == "alice")
  assert(Bytes.secure_equals(decoded_authorization.request_hash, authorization.request_hash))
  let first = DirectoryEntry {
    version : 1,
    username : "alice",
    account_identity : Bytes.from_utf8("account"),
    prekey_bundle : Bytes.from_utf8("prekey-a"),
    mailbox_token : repeated(5, 32)
  }
  let second = DirectoryEntry {
    version : 1,
    username : "alice",
    account_identity : Bytes.from_utf8("account"),
    prekey_bundle : Bytes.from_utf8("prekey-b"),
    mailbox_token : repeated(6, 32)
  }
  let device_set = DeviceSet {
    version : 1,
    username : "alice",
    account_identity : Bytes.from_utf8("account"),
    sequence : wide(3) ?,
    devices : [first, second],
    revoked_device_ids : [repeated(7, 16)]
  }
  let decoded_set = decode_device_set(encode_device_set(device_set) ?) ?
  assert(U64.compare(decoded_set.sequence, wide(3) ?) == 0)
  assert(List.length(decoded_set.devices) == 2)
  assert(List.length(decoded_set.revoked_device_ids) == 1)
  let revocation = DeviceRevocation {
    version : 1,
    account_id : repeated(8, 32),
    device_id : repeated(9, 16),
    sequence : wide(4) ?,
    signature : repeated(10, 64)
  }
  let revocation_wire = encode_device_revocation(revocation) ?
  let decoded_revocation = decode_device_revocation(revocation_wire) ?
  assert(U64.compare(decoded_revocation.sequence, revocation.sequence) == 0)
  assert(Bytes.secure_equals(decoded_revocation.device_id, revocation.device_id))
  let trailing = case Bytes.concat(revocation_wire, Bytes.from_utf8("trailing")) do
    Err( _) -> Err(MalformedEncoding)
    Ok( value) -> Ok(value)
  end ?
  case decode_device_revocation(trailing) do
    Err( MalformedEncoding) -> assert(true)
    _ -> assert(false)
  end
  Ok(true)
end

test("device linking and device-set records have bounded canonical codecs") do
  case proof() do
    Err( _) -> assert(false)
    Ok( value) -> assert(value)
  end
end

fn identity_wide(value :: Int) -> U64 ! IdentityError do
  case U64.parse(Int.to_string(value)) do
    Err( _) -> Err(InvalidCredential)
    Ok( parsed) -> Ok(parsed)
  end
end

fn identity_proof() -> Bool ! IdentityError do
  let now = identity_wide(1000) ?
  let ( account, identity) = generate_account(now, identity_wide(1) ?) ?
  let request = DeviceLinkRequest {
    version : 1,
    nonce : repeated(21, 32),
    device_id : repeated(22, 16),
    signing_public_key : repeated(23, 32),
    dh_public_key : repeated(24, 32),
    capabilities : identity_wide(1) ?,
    created_at : now,
    expires_at : identity_wide(2000) ?
  }
  let authorization = authorize_device_link(account,
  identity,
  request,
  "alice",
  identity_wide(31536001000) ?,
  identity_wide(2) ?) ?
  assert(verify_device_link_authorization(request, authorization, now, identity_wide(1) ?) ?)
  let wrong_request = DeviceLinkRequest {
    version : request.version,
    nonce : repeated(25, 32),
    device_id : request.device_id,
    signing_public_key : request.signing_public_key,
    dh_public_key : request.dh_public_key,
    capabilities : request.capabilities,
    created_at : request.created_at,
    expires_at : request.expires_at
  }
  assert(!verify_device_link_authorization(wrong_request, authorization, now, identity_wide(1) ?) ?)
  let revocation = issue_device_revocation(account, repeated(26, 16), identity_wide(3) ?) ?
  assert(verify_device_revocation(identity, revocation) ?)
  let changed_revocation = DeviceRevocation {
    version : revocation.version,
    account_id : revocation.account_id,
    device_id : repeated(27, 16),
    sequence : revocation.sequence,
    signature : revocation.signature
  }
  assert(!verify_device_revocation(identity, changed_revocation) ?)
  Ok(true)
end

test("account authorization binds links and revocations to exact devices") do
  case identity_proof() do
    Err( _) -> assert(false)
    Ok( value) -> assert(value)
  end
end
