import File
from MobileCore import (
  credits_group_handover_export,
  credits_inbox_policy_export,
  group_receive_export,
  group_send_export,
  outbox_list_export,
  reconcile_prekeys_export,
  replenish_prekeys_export
)
from Mobile.GroupState import encode_group_packet
from Mobile.Profile import load_profile, open_device
from Mobile.Transport import sealed_outer_bytes
from Mobile.Codec import current_time
from Identity.Device import DeviceKeys
from Prekeys.Pool import (
  PrekeyPublishRequest,
  PrekeyPublishResponse,
  decode_prekey_publish,
  encode_prekey_publish_response
)
from Protocol.V1 import DeviceCredential, DirectoryEntry, OuterEnvelope
from Storage.Keys import platform_key
from Tests.GroupLifecycleCreate import create_group_with_bob
from Tests.GroupLifecycleSupport import GroupAccountFixture, group_account_fixture
from Tests.GroupLifecycleWire import envelope_for, group_vectors, outer, output_list
from Tests.Support import append, repeated, write_u32
from Transport.Packet import ClientProfile, decode_client_profile

fn run(name :: String, value :: Result<Bool, String>) -> Bool do
  case value do
    Err(error) -> do
      println(name <> ": " <> error)
      false
    end
    Ok(result) -> result
  end
end

fn publication(path :: String) -> PrekeyPublishRequest!String do
  decode_prekey_publish(replenish_prekeys_export(group_vectors([
    Bytes.from_utf8(path),
    write_u32(0)?
  ])?)?)
end

# The directory answered this device's publication, so the contact address it
# named is live and may be handed out.

fn published(path :: String) -> Bytes!String do
  let sent = publication(path)?
  let answer = encode_prekey_publish_response(PrekeyPublishResponse {
    account_id: sent.account_id,
    device_id: sent.device_id,
    active_ids: List.new()
  })?
  reconcile_prekeys_export(group_vectors([Bytes.from_utf8(path), answer])?)?
  case sent.contact_address_hash do
    None -> Err("publication names no contact address")
    Some(value) -> Ok(value)
  end
end

fn queued(path :: String) -> Int!String do
  let answer = credits_group_handover_export(group_vectors([Bytes.from_utf8(path)])?)?
  case Bytes.read_u32_be(answer, 0) do
    Err(_) -> Err("bad handover answer")
    Ok(value) -> case U64.to_int(value) do
      Err(_) -> Err("bad handover answer")
      Ok(count)
    end
  end
end

fn last_for(envelopes :: List<Bytes>, mailbox :: Bytes) -> Bytes!String do
  let matching = List.filter(envelopes,
    fn envelope -> case outer(envelope) do
      Ok(value) -> Bytes.secure_equals(value.mailbox_token, mailbox)
      Err(_) -> false
    end end)
  if List.length(matching) == 0 do
    Err("no envelope for that mailbox")
  else
    Ok(List.get(matching, List.length(matching) - 1))
  end
end

# A kind 4 packet claiming to come from Alice's device but signed by Bob's.

fn forged(accounts :: GroupAccountFixture, group_id :: Bytes) -> Bytes!String do
  let alice = decode_client_profile(load_profile(accounts.alice_path)?)?
  let bob = decode_client_profile(load_profile(accounts.bob_path)?)?
  let key = platform_key()?
  let device = open_device(bob, key, accounts.bob_path)?
  let body = append(append(append(append(append(append(repeated(1, 1)?, Bytes.from_utf8("GCH"))?,
            group_id)?,
          alice.account_id)?,
        alice.device_id)?,
      repeated(5, 32)?)?,
    repeated(0, 8)?)?
  let signature = case Crypto.sign(device.signing_private_key,
    append(Bytes.from_utf8("mesh-msg/v1/group-contact-address"), body)?) do
    Err(_) -> Err("test signing failed")
    Ok(value) -> Ok(value.bytes)
  end?
  sealed_outer_bytes(bob.entry.mailbox_token,
    encode_group_packet(4, append(body, signature)?)?,
    bob.credential.dh_public_key,
    current_time()?)
end

fn handover() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let accounts = group_account_fixture()?
  let group_id = create_group_with_bob(accounts)?
  let contact_hash = published(accounts.alice_path)?
  # Free inbox: nothing to hand over.
  assert(queued(accounts.alice_path)? == 0)
  credits_inbox_policy_export(group_vectors([
    Bytes.from_utf8(accounts.alice_path),
    repeated(5, 1)?
  ])?)?
  # Priced: Bob, a member but no contact, is handed Alice's contact address,
  # once.
  assert(queued(accounts.alice_path)? == 1)
  assert(queued(accounts.alice_path)? == 0)
  let envelopes = output_list(outbox_list_export(Bytes.from_utf8(accounts.alice_path))?)?
  let handed = last_for(envelopes, accounts.bob_entry.mailbox_token)?
  group_receive_export(group_vectors([Bytes.from_utf8(accounts.bob_path), handed])?)?
  # Bob's next group message reaches Alice at her contact address, which asks
  # no postage.
  let sent = output_list(group_send_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    group_id,
    Bytes.from_utf8("hello group")
  ])?)?)?
  let to_alice = List.filter(sent,
    fn envelope -> case outer(envelope) do
      Ok(value) -> Bytes.secure_equals(Crypto.sha256(value.mailbox_token), contact_hash)
      Err(_) -> false
    end end)
  assert(List.length(to_alice) == 1)
  # A handover signed by anyone but the named member is refused.
  assert(group_receive_export(group_vectors([
    Bytes.from_utf8(accounts.bob_path),
    forged(accounts, group_id)?
  ])?) == Err("invalid_group_packet"))
  File.delete(accounts.alice_path)?
  File.delete(accounts.linked_path)?
  File.delete(accounts.bob_path)?
  Ok(true)
end

test("a priced inbox hands its contact address to group members, who then use it") do
  assert(run("handover", handover()))
end
