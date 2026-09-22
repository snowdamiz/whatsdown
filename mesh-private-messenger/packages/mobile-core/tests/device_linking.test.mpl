import File
from Identity.Device import verify_device_link_authorization, verify_device_revocation
from MobileCore import (
  authorize_device_link_for_set_export,
  complete_device_link_export,
  create_account_export,
  create_device_revocation_export,
  create_link_request_export,
  device_link_sas_export,
  directory_entry_export,
  forget_on_proof_export,
  inspect_device_set_export,
  install_group_transparency_for_test,
  load_profile_export,
  receive_initial_export,
  replenish_prekeys_export,
  test_inner_suite,
  start_conversation_export
)
from Prekeys.Pool import decode_prekey_publish
from Protocol.DirectoryWire import (
  decode_device_link_authorization,
  decode_device_link_request,
  decode_device_revocation,
  decode_directory_entry,
  encode_device_link_request,
  encode_device_set
)
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.IdentityWire import decode_account_identity, decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  DeviceLinkAuthorization,
  DeviceLinkRequest,
  DeviceRevocation,
  DeviceSet,
  DirectoryEntry,
  OuterEnvelope,
  PrekeyBundle
)
from Tests.GroupConsistencySupport import signed_transparency_view
from Tests.Support import append, database_path, vector, write_u32
from Transparency.Merkle import leaf_hash

fn encode_vectors(values :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_vectors(values, index + 1, append(output, vector(List.get(values, index)) ?) ?)
  end
end

fn request(values :: List < Bytes >) -> Bytes ! String do
  encode_vectors(values, 0, Bytes.empty())
end

fn wide(value :: String) -> U64 ! String do
  case U64.parse(value) do
    Err( _) -> Err("test integer conversion failed")
    Ok( parsed) -> Ok(parsed)
  end
end

fn byte(value :: Int) -> Bytes ! String do
  case Bytes.from_list([value]) do
    Err( _) -> Err("test byte encoding failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn write_u64(value :: U64) -> Bytes ! String do
  case Bytes.write_u64_be(value) do
    Err( _) -> Err("test integer encoding failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn first_six(value :: Bytes) -> Bytes ! String do
  case Bytes.slice(value, 0, 6) do
    Err( _) -> Err("test digest slicing failed")
    Ok( sliced) -> Ok(sliced)
  end
end

fn entry(input :: Bytes) -> DirectoryEntry ! String do
  case decode_directory_entry(input) do
    Err( _) -> Err("directory entry decode failed")
    Ok( value) -> Ok(value)
  end
end

fn account(input :: Bytes) -> AccountIdentity ! String do
  case decode_account_identity(input) do
    Err( _) -> Err("account identity decode failed")
    Ok( value) -> Ok(value)
  end
end

fn bundle(input :: Bytes) -> PrekeyBundle ! String do
  case decode_prekey_bundle(input) do
    Err( _) -> Err("prekey bundle decode failed")
    Ok( value) -> Ok(value)
  end
end

fn credential(input :: Bytes) -> DeviceCredential ! String do
  case decode_device_credential(input) do
    Err( _) -> Err("device credential decode failed")
    Ok( value) -> Ok(value)
  end
end

fn link_request(input :: Bytes) -> DeviceLinkRequest ! String do
  case decode_device_link_request(input) do
    Err( _) -> Err("link request decode failed")
    Ok( value) -> Ok(value)
  end
end

fn link_authorization(input :: Bytes) -> DeviceLinkAuthorization ! String do
  case decode_device_link_authorization(input) do
    Err( _) -> Err("link authorization decode failed")
    Ok( value) -> Ok(value)
  end
end

fn revocation(input :: Bytes) -> DeviceRevocation ! String do
  case decode_device_revocation(input) do
    Err( _) -> Err("device revocation decode failed")
    Ok( value) -> Ok(value)
  end
end

fn outer(input :: Bytes) -> OuterEnvelope ! String do
  case decode_outer_envelope(input) do
    Err( _) -> Err("outer envelope decode failed")
    Ok( value) -> Ok(value)
  end
end

fn link_wire(value :: DeviceLinkRequest) -> Bytes ! String do
  case encode_device_link_request(value) do
    Err( _) -> Err("link request encode failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn device_set_wire(value :: DeviceSet) -> Bytes ! String do
  case encode_device_set(value) do
    Err( _) -> Err("device set encode failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn inspect_row(device_id :: Bytes, active :: Int, current :: Int) -> Bytes ! String do
  request([device_id, byte(active) ?, byte(current) ?])
end

fn inspect_output(username :: String,
account_id :: Bytes,
sequence :: U64,
changed :: Int,
can_manage :: Int,
rows :: List < Bytes >) -> Bytes ! String do
  let encoded_rows = encode_vectors(rows, 0, vector(write_u32(List.length(rows)) ?) ?) ?
  request([Bytes.from_utf8(username), account_id, write_u64(sequence) ?, byte(changed) ?, byte(can_manage) ?, encoded_rows])
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let root_path = database_path("device-link-root") ?
  let linked_path = database_path("device-link-linked") ?
  let sender_path = database_path("device-link-sender") ?
  let root_profile = create_account_export(request([Bytes.from_utf8(root_path), Bytes.from_utf8("alice")]) ?) ?
  assert(Bytes.length(root_profile) > 0)
  let root_entry = entry(directory_entry_export(Bytes.from_utf8(root_path)) ?) ?
  let root_account = account(root_entry.account_identity) ?
  let root_credential = credential(bundle(root_entry.prekey_bundle) ?.device_credential) ?
  let request_wire = create_link_request_export(Bytes.from_utf8(linked_path)) ?
  let retried_request_wire = create_link_request_export(Bytes.from_utf8(linked_path)) ?
  let pending = link_request(request_wire) ?
  assert(Bytes.length(request_wire) == 1326)
  assert(Bytes.secure_equals(retried_request_wire, request_wire))
  assert(Bytes.secure_equals(request_wire, link_wire(pending) ?))
  assert(pending.version == 2)
  assert(pending.suite == 2)
  assert(Bytes.length(pending.nonce) == 32)
  assert(Bytes.length(pending.device_id) == 16)
  assert(Bytes.length(pending.signing_public_key) == 32)
  assert(Bytes.length(pending.dh_public_key) == 32)
  assert(Bytes.length(pending.post_quantum_public_key) == 1184)
  assert(U64.compare(pending.capabilities, wide("1") ?) == 0)
  assert(U64.compare(pending.expires_at, U64.add(pending.created_at, wide("600000") ?) ?) == 0)
  let expected_sas = Bytes.from_utf8(Bytes.to_hex(first_six(Crypto.sha256(request_wire)) ?))
  assert(Bytes.length(expected_sas) == 12)
  assert(Bytes.secure_equals(device_link_sas_export(request_wire) ?, expected_sas))
  let root_set = device_set_wire(DeviceSet {
    version : 1,
    username : root_entry.username,
    account_identity : root_entry.account_identity,
    sequence : wide("1") ?,
    devices : [root_entry],
    revoked_device_ids : List.new()
  }) ?
  case authorize_device_link_for_set_export(request([Bytes.from_utf8(root_path), root_set, request_wire]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "device_set_transparency_unverified")
  end
  let root_view = signed_transparency_view([leaf_hash(root_set) ?]) ?
  assert(install_group_transparency_for_test(root_path,
  root_view.checkpoint,
  root_view.consistency,
  root_view.service_public_key,
  root_view.witness_a_public_key,
  root_view.witness_b_public_key,
  root_set) ?)
  let authorization_wire = authorize_device_link_for_set_export(request([Bytes.from_utf8(root_path), root_set, request_wire]) ?) ?
  let authorization = link_authorization(authorization_wire) ?
  let linked_credential = credential(authorization.device_credential) ?
  assert(authorization.version == 1)
  assert(authorization.username == "alice")
  assert(Bytes.secure_equals(authorization.request_hash, Crypto.sha256(request_wire)))
  assert(Bytes.secure_equals(authorization.account_identity, root_entry.account_identity))
  assert(Bytes.secure_equals(linked_credential.account_id, root_account.account_id))
  assert(Bytes.secure_equals(linked_credential.device_id, pending.device_id))
  assert(Bytes.secure_equals(linked_credential.signing_public_key, pending.signing_public_key))
  assert(Bytes.secure_equals(linked_credential.dh_public_key, pending.dh_public_key))
  assert(linked_credential.suite == 2)
  assert(Bytes.secure_equals(linked_credential.post_quantum_public_key,
  pending.post_quantum_public_key))
  assert(U64.compare(linked_credential.directory_sequence, wide("2") ?) == 0)
  let authorization_valid = case verify_device_link_authorization(pending,
  authorization,
  pending.created_at,
  wide("1") ?) do
    Err( _) -> Err("link authorization verification failed")
    Ok( value) -> Ok(value)
  end ?
  assert(authorization_valid)
  let linked_profile = complete_device_link_export(request([Bytes.from_utf8(linked_path), authorization_wire]) ?) ?
  assert(Bytes.secure_equals(linked_profile, load_profile_export(Bytes.from_utf8(linked_path)) ?))
  let linked_entry = entry(directory_entry_export(Bytes.from_utf8(linked_path)) ?) ?
  let completed_bundle = bundle(linked_entry.prekey_bundle) ?
  let completed_credential = credential(completed_bundle.device_credential) ?
  assert(completed_bundle.suite == 2)
  assert(List.length(completed_bundle.supported_suites) == 2)
  if List.length(completed_bundle.supported_suites) == 2 do
    assert(List.get(completed_bundle.supported_suites, 0) == 2)
    assert(List.get(completed_bundle.supported_suites, 1) == 1)
  end
  assert(Bytes.secure_equals(completed_bundle.post_quantum_prekey, pending.post_quantum_public_key))
  assert(Bytes.secure_equals(linked_entry.account_identity, root_entry.account_identity))
  assert(Bytes.secure_equals(completed_credential.account_id, root_credential.account_id))
  assert(!Bytes.secure_equals(completed_credential.device_id, root_credential.device_id))
  assert(Bytes.secure_equals(completed_credential.device_id, pending.device_id))
  assert(U64.compare(completed_credential.directory_sequence, wide("2") ?) == 0)
  let sender_profile = create_account_export(request([Bytes.from_utf8(sender_path), Bytes.from_utf8("bob")]) ?) ?
  let linked_message = Bytes.from_utf8("hybrid linked device")
  let linked_initial = start_conversation_export(request([Bytes.from_utf8(sender_path), linked_profile, linked_message]) ?) ?
  assert(outer(linked_initial) ?.suite == 4)
  assert(test_inner_suite(linked_path, linked_initial) ? == 2)
  assert(Bytes.secure_equals(receive_initial_export(request([Bytes.from_utf8(linked_path), linked_initial]) ?) ?,
  linked_message))
  assert(Bytes.length(sender_profile) > 0)
  let publication = decode_prekey_publish(replenish_prekeys_export(request([Bytes.from_utf8(linked_path), write_u32(1) ?]) ?) ?) ?
  assert(Bytes.secure_equals(publication.account_id, root_account.account_id))
  assert(Bytes.secure_equals(publication.device_id, completed_credential.device_id))
  assert(List.length(publication.prekeys) == 1)
  assert(U64.compare(List.head(publication.prekeys).id, wide("3") ?) == 0)
  let linked_set = device_set_wire(DeviceSet {
    version : 1,
    username : root_entry.username,
    account_identity : root_entry.account_identity,
    sequence : wide("2") ?,
    devices : [root_entry, linked_entry],
    revoked_device_ids : List.new()
  }) ?
  let unverified_successor = device_set_wire(DeviceSet {
    version : 1,
    username : root_entry.username,
    account_identity : root_entry.account_identity,
    sequence : wide("3") ?,
    devices : [root_entry, linked_entry],
    revoked_device_ids : List.new()
  }) ?
  case inspect_device_set_export(request([Bytes.from_utf8(root_path), unverified_successor]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "device_set_transparency_unverified")
  end
  case create_device_revocation_export(request([Bytes.from_utf8(root_path), unverified_successor, completed_credential.device_id]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "device_set_transparency_unverified")
  end
  let expected_linked = inspect_output("alice",
  root_account.account_id,
  wide("2") ?,
  0,
  1,
  [inspect_row(root_credential.device_id, 1, 1) ?, inspect_row(completed_credential.device_id, 1, 0) ?]) ?
  let linked_view = signed_transparency_view([leaf_hash(linked_set) ?]) ?
  assert(install_group_transparency_for_test(root_path,
  linked_view.checkpoint,
  linked_view.consistency,
  linked_view.service_public_key,
  linked_view.witness_a_public_key,
  linked_view.witness_b_public_key,
  linked_set) ?)
  assert(Bytes.secure_equals(inspect_device_set_export(request([Bytes.from_utf8(root_path), linked_set]) ?) ?,
  expected_linked))
  let revocation_wire = create_device_revocation_export(request([Bytes.from_utf8(root_path), linked_set, completed_credential.device_id]) ?) ?
  let revoked = revocation(revocation_wire) ?
  assert(Bytes.secure_equals(revoked.account_id, root_account.account_id))
  assert(Bytes.secure_equals(revoked.device_id, completed_credential.device_id))
  assert(U64.compare(revoked.sequence, wide("3") ?) == 0)
  let revocation_valid = case verify_device_revocation(root_account, revoked) do
    Err( _) -> Err("device revocation verification failed")
    Ok( value) -> Ok(value)
  end ?
  assert(revocation_valid)
  let revoked_set = device_set_wire(DeviceSet {
    version : 1,
    username : root_entry.username,
    account_identity : root_entry.account_identity,
    sequence : wide("3") ?,
    devices : [root_entry],
    revoked_device_ids : [completed_credential.device_id]
  }) ?
  case inspect_device_set_export(request([Bytes.from_utf8(root_path), revoked_set]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "device_set_transparency_unverified")
  end
  let revoked_view = signed_transparency_view([leaf_hash(revoked_set) ?]) ?
  assert(install_group_transparency_for_test(root_path,
  revoked_view.checkpoint,
  revoked_view.consistency,
  revoked_view.service_public_key,
  revoked_view.witness_a_public_key,
  revoked_view.witness_b_public_key,
  revoked_set) ?)
  let expected_revoked = inspect_output("alice",
  root_account.account_id,
  wide("3") ?,
  1,
  1,
  [inspect_row(root_credential.device_id, 1, 1) ?, inspect_row(completed_credential.device_id, 0, 0) ?]) ?
  assert(Bytes.secure_equals(inspect_device_set_export(request([Bytes.from_utf8(root_path), revoked_set]) ?) ?,
  expected_revoked))
  # The removed device erases itself on the account's revocation of it. The
  # root keeps everything: the revocation names another device.
  case forget_on_proof_export(request([Bytes.from_utf8(root_path), revocation_wire]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "unproven_removal")
  end
  assert(Bytes.secure_equals(forget_on_proof_export(request([Bytes.from_utf8(linked_path), revocation_wire]) ?) ?,
  byte(2) ?))
  case load_profile_export(Bytes.from_utf8(linked_path)) do
    Ok( _) -> assert(false)
    Err( _) -> assert(true)
  end
  assert(Bytes.length(load_profile_export(Bytes.from_utf8(root_path)) ?) > 0)
  File.delete(root_path) ?
  File.delete(linked_path) ?
  File.delete(sender_path) ?
  Ok(true)
end

test("mobile device linking, inspection, and revocation are proved in Mesh") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
