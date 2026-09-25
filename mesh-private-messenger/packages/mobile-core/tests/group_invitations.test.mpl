import File
from Mobile.Codec import encode_output_list
from Mobile.Fanout import send_fanout_control
from Mobile.Types import MobileFanoutRequest
from Mobile.GroupInvitesState import GroupInvitation, load_invitations, accepted_invitation_scope
from Mobile.GroupState import decode_group_packet, decode_group_welcome_packet, canonical_group_welcome
from Mobile.Profile import load_profile, open_device
from Mobile.Types import MobileGroupPacket, MobileGroupWelcomePacket
from Groups.Mls import GroupWelcome, GroupCommit
from Groups.Tree import IndexedGroupMember, GroupMember
from Identity.Device import DeviceKeys
from Storage.Keys import platform_key
from MobileCore import (
  create_account_export,
  directory_entry_export,
  group_create_export,
  group_invite_export,
  group_invitation_accept_export,
  group_invitation_complete_export,
  group_invitations_export,
  group_invitation_decline_export,
  group_add_export,
  group_key_package_export,
  send_message_export,
  group_list_export,
  group_receive_export,
  receive_initial_export,
  receive_message_export,
  reserve_fanout_prekey_export,
  list_conversations_export
)
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.IdentityWire import decode_account_identity
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Prekeys.Bundle import normalize_prekey_bundle
from Protocol.V1 import DeviceSet, DirectoryEntry, AccountIdentity, PrekeyBundle, OuterEnvelope
from Tests.GroupLifecycleSupport import install_signed_transparency
from Tests.GroupLifecycleWire import group_vectors, output_list, acknowledge, outer
from Tests.GroupConsistencySupport import signed_transparency_view
from Tests.Support import database_path, repeated
from Transparency.Merkle import leaf_hash
from Transport.Recipient import open_recipient_packet
from Transport.Packet import decode_client_profile

fn device_set(path :: String, username :: String) -> Bytes!String do
  let entry = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(path))?) do
    Ok(value)
    Err(_) -> Err("invalid test directory entry")
  end?
  let account = case decode_account_identity(entry.account_identity) do
    Ok(value)
    Err(_) -> Err("invalid test account")
  end?
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Ok(value)
    Err(_) -> Err("invalid test bundle")
  end?
  let normalized = case normalize_prekey_bundle(bundle) do
    Ok(value)
    Err(_) -> Err("invalid test base bundle")
  end?
  let encoded_bundle = case encode_prekey_bundle(normalized) do
    Ok(value)
    Err(_) -> Err("invalid test bundle encoding")
  end?
  case encode_device_set(DeviceSet {
    version: 1,
    username: username,
    account_identity: entry.account_identity,
    sequence: account.directory_sequence,
    devices: [%{entry | prekey_bundle: encoded_bundle}],
    revoked_device_ids: []
  }) do
    Ok(value)
    Err(_) -> Err("invalid test device set")
  end
end

fn proof(malformed_first :: Bool) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let alice = database_path("invite-alice")?
  let bob = database_path("invite-bob")?
  let alice_path = Bytes.from_utf8(alice)
  let bob_path = Bytes.from_utf8(bob)
  let alice_profile = create_account_export(group_vectors([alice_path, Bytes.from_utf8("alice")])?)?
  let bob_profile = create_account_export(group_vectors([bob_path, Bytes.from_utf8("bob")])?)?
  let alice_set = device_set(alice, "alice")?
  let bob_set = device_set(bob, "bob")?
  let view = signed_transparency_view([leaf_hash(alice_set)?, leaf_hash(bob_set)?])?
  assert(install_signed_transparency(alice, view, alice_set)?)
  assert(install_signed_transparency(alice, view, bob_set)?)
  assert(install_signed_transparency(bob, view, alice_set)?)
  assert(install_signed_transparency(bob, view, bob_set)?)
  let claimed_bob = case decode_directory_entry(directory_entry_export(bob_path)?) do
    Ok(value)
    Err(_) -> Err("invalid test claim")
  end?
  reserve_fanout_prekey_export(group_vectors([
    alice_path,
    bob_set,
    alice_set,
    claimed_bob.prekey_bundle
  ])?)?
  if malformed_first do
    let malformed = output_list(send_fanout_control(MobileFanoutRequest {
        database_path: alice,
        peer_device_set: bob_set,
        local_device_set: alice_set,
        body: encode_output_list([
          repeated(7, 16)?,
          repeated(9, 32)?,
          Bytes.from_utf8("x"),
          repeated(5, 188)?
        ])?,
        attachment: Bytes.empty()
      },
      3,
      [],
      [])?)?
    receive_initial_export(group_vectors([bob_path, List.head(malformed)])?)?
    acknowledge(alice, malformed, 0)?
    assert(List.length(output_list(group_invitations_export(bob_path)?)?) == 0)
  end
  let group = group_create_export(alice_path)?
  let invite = output_list(group_invite_export(group_vectors([alice_path, bob_set, alice_set, group])?)?)?
  assert(List.length(invite) == 1)
  if malformed_first do
    receive_message_export(group_vectors([bob_path, List.head(invite)])?)
  else
    receive_initial_export(group_vectors([bob_path, List.head(invite)])?)
  end?
  acknowledge(alice, invite, 0)?
  assert(List.length(output_list(group_list_export(bob_path)?)?) == 0)
  let pending = output_list(group_invitations_export(bob_path)?)?
  assert(List.length(pending) == 1)
  assert(List.length(output_list(list_conversations_export(bob_path)?)?) == 0)
  let invitation = output_list(List.head(pending))?
  let reference = List.get(invitation, 0)
  assert(Bytes.secure_equals(List.get(invitation, 1), group))
  assert(Bytes.secure_equals(List.get(invitation, 2), Bytes.from_utf8("alice")))
  let acceptance = output_list(group_invitation_accept_export(group_vectors([
    bob_path,
    alice_set,
    bob_set,
    reference
  ])?)?)?
  assert(List.length(acceptance) == 1)
  receive_message_export(group_vectors([alice_path, List.head(acceptance)])?)?
  acknowledge(bob, acceptance, 0)?
  let ready = output_list(group_invitations_export(alice_path)?)?
  let ready_record = output_list(List.head(ready))?
  case group_invitation_complete_export(group_vectors([
    alice_path,
    alice_set,
    List.get(ready_record, 0)
  ])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "group_member_not_found")
  end
  # The inviter can see the public response, but cannot reuse it for another group.
  let accepted = List.head(load_invitations(alice, platform_key()?)?)
  group_key_package_export(bob_path)?
  let other_group = group_create_export(alice_path)?
  let wrong_welcome = output_list(group_add_export(group_vectors([
    alice_path,
    other_group,
    bob_set,
    accepted.key_package
  ])?)?)?
  case group_receive_export(group_vectors([bob_path, List.head(wrong_welcome)])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "group_welcome_rejected")
  end
  acknowledge(alice, wrong_welcome, 0)?
  assert(List.length(output_list(group_list_export(bob_path)?)?) == 0)
  let complete_request = group_vectors([alice_path, bob_set, List.get(ready_record, 0)])?
  let welcome = output_list(group_invitation_complete_export(complete_request)?)?
  assert(List.length(welcome) == 1)
  let accepted_local = List.head(load_invitations(bob, platform_key()?)?)
  assert(U64.compare(accepted_local.expires_at, outer(List.head(welcome))?.expiration) >= 0)
  # Welcomes travel sealed to Bob's device identity; open them the way delivery does.
  let bob_local = decode_client_profile(load_profile(bob)?)?
  let bob_device = open_device(bob_local, platform_key()?, bob)?
  let sealed_welcome = outer(List.head(welcome))?.ciphertext
  let packet = decode_group_packet(open_recipient_packet(sealed_welcome,
    bob_device.identity_private_key)?)?
  let encoded_welcome = decode_group_welcome_packet(packet.payload)?
  let original = canonical_group_welcome(encoded_welcome.welcome)?
  let fake_key = SigningPublicKey { bytes: repeated(9, 32)? }
  let substituted = List.map(original.members,
    fn (member) do
      if member.leaf_index == original.commit.committer_leaf do
        %{member | member: %{member.member | signing_public_key: fake_key}}
      else
        member
      end
    end)
  case accepted_invitation_scope(bob,
    platform_key()?,
    %{original | members: substituted},
    encoded_welcome.baseline_checkpoint) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "group_welcome_rejected")
  end
  assert(Bytes.secure_equals(group_receive_export(group_vectors([bob_path, List.head(welcome)])?)?,
    group))
  acknowledge(alice, welcome, 0)?
  assert(List.length(output_list(group_list_export(bob_path)?)?) == 1)
  assert(List.length(output_list(group_invitations_export(bob_path)?)?) == 0)
  assert(List.length(output_list(group_invitation_complete_export(complete_request)?)?) == 0)
  case send_message_export(group_vectors([bob_path, alice_profile, Bytes.from_utf8("unaccepted DM")])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "message_request_pending")
  end
  let declined_group = group_create_export(alice_path)?
  let next = output_list(group_invite_export(group_vectors([
    alice_path,
    bob_set,
    alice_set,
    declined_group
  ])?)?)?
  receive_message_export(group_vectors([bob_path, List.head(next)])?)?
  acknowledge(alice, next, 0)?
  let next_record = output_list(List.head(output_list(group_invitations_export(bob_path)?)?))?
  let next_reference = List.get(next_record, 0)
  group_invitation_decline_export(group_vectors([bob_path, next_reference])?)?
  assert(List.length(output_list(group_invitations_export(bob_path)?)?) == 0)
  case group_invitation_accept_export(group_vectors([bob_path, alice_set, bob_set, next_reference])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "invalid_group_invitation")
  end
  File.delete(alice)?
  File.delete(bob)?
  Ok(true)
end

test("username invitation joins only after acceptance and survives repeated completion") do
  case proof(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("malformed initial invitations do not block a later authenticated invitation") do
  case proof(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
