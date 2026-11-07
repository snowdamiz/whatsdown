##! Public receive regression: synthetic accounts, real attacker signature and recipient crypto.
from Identity.Device import (
  AccountKeys,
  generate_account,
  generate_device,
  issue_hybrid_device_credential
)
from Mobile.Codec import current_time
from Mobile.Messages import receive_initial_message, receive_message
from Mobile.Profile import load_profile, policy, open_account, open_device
from Mobile.Sessions import (
  encode_sync_payload,
  self_sync_conversation_id,
  inner_bytes,
  initial_bytes,
  load_session_record,
  updated_session_record
)
from Mobile.Transport import sealed_outer_bytes
from Mobile.Types import MobileReceiveRequest
from Prekeys.Bundle import (
  generate_post_quantum_prekey,
  generate_signed_prekey,
  generate_one_time_prekey,
  build_hybrid_prekey_bundle
)
from Protocol.IdentityWire import encode_account_identity
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import DirectoryEntry, InnerEnvelope
from Session.Handshake import initiate_at_minimum_suite
from Session.State import RatchetState
from Storage.AccountGuard import load_account_basis, same_account_basis
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs, with_record_transaction, delete_blob
from Storage.Keys import one_time_prekey_label, platform_key, seal_local, local_context
from Protocol.DirectoryWire import encode_device_set
from Protocol.V1 import DeviceSet
from Transparency.Merkle import leaf_hash
from Tests.GroupLifecycleSupport import install_signed_transparency
from Tests.GroupConsistencySupport import signed_transparency_view, wide
from Tests.Support import repeated
from Tests.ViewOnceInitialSyncFixture import (
  initial_sync_fixture,
  clear_initial_sync_fixture,
  initial_carrier,
  sibling_carrier
)
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  decode_client_profile,
  encode_client_profile,
  encode_initial_plaintext,
  encode_packet,
  direct_conversation_id
)

fn check(value :: Plaintext<Bool>, failure :: String) -> Unit!String do
  if declassify(value, "test-only Boolean observation of synthetic sibling-authority regression") do
    Ok(nil)
  else
    Err(failure)
  end
end

fn sync_inner(sender :: ClientProfile,
  recipient :: ClientProfile,
  target :: ClientProfile,
  n :: Int) -> InnerEnvelope!String do
  let history = InnerEnvelope {
    version: 1,
    sender_account_id: sender.account_id,
    sender_device_id: sender.device_id,
    recipient_device_id: target.device_id,
    conversation_id: direct_conversation_id(sender.account_id, target.account_id)?,
    client_message_id: repeated(n, 16)?,
    client_timestamp: current_time()?,
    message_type: 1,
    body: Bytes.from_utf8("synthetic sibling message"),
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: []
  }
  Ok(%{history |
    recipient_device_id: recipient.device_id,
    conversation_id: self_sync_conversation_id(recipient.account_id)?,
    message_type: 2,
    body: encode_sync_payload(sender, target, history)?
  })
end

fn credential_carrier(sender_path :: String,
  recipient :: ClientProfile,
  target :: ClientProfile,
  replaced :: Bool) -> Result<(Bytes, Bytes), String> do
  let now = current_time()?
  let sender_wire = load_profile(sender_path)?
  let sender = decode_client_profile(sender_wire)?
  let key = platform_key()?
  let (device, credential) = if replaced do
    let original = case generate_device() do
      Err(_) -> return Err("fixture_device")
      Ok(value) -> value
    end
    let device = %{original | device_id: sender.device_id}
    let account = open_account(sender, key, sender_path)?
    let pq = case generate_post_quantum_prekey() do
      Err(_) -> return Err("fixture_pq")
      Ok(value) -> value
    end
    let credential = case issue_hybrid_device_credential(account,
      device,
      pq.public_key,
      U64.parse("31")?,
      now,
      U64.add(now, U64.parse("86400000")?)?,
      sender.credential.directory_sequence) do
      Err(_) -> return Err("fixture_credential")
      Ok(value) -> value
    end
    (device, credential)
  else
    (open_device(sender, key, sender_path)?, sender.credential)
  end
  let plaintext = encode_initial_plaintext(sender_wire,
    inner_bytes(sync_inner(sender, recipient, target, 101)?)?)?
  let (state, initial) = case initiate_at_minimum_suite(device,
    credential,
    recipient.account,
    recipient.bundle,
    policy(recipient, now),
    0,
    1,
    plaintext) do
    Err(_) -> return Err("fixture_handshake")
    Ok(value) -> value
  end
  let packet = encode_packet(InitialPacket(sender.entry.account_identity, initial_bytes(initial)?))?
  let wire = sealed_outer_bytes(recipient.entry.mailbox_token,
    packet,
    recipient.credential.dh_public_key,
    now)?
  Ok((state.session_id, wire))
end

fn credential_binding(replaced :: Bool) -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = initial_sync_fixture()?
  let recipient = decode_client_profile(load_profile(fixture.linked_path)?)?
  let target = decode_client_profile(load_profile(fixture.bob_path)?)?
  let (session_id, wire) = credential_carrier(fixture.alice_path, recipient, target, replaced)?
  let labels = [
    "sessions/v1",
    "one-time-prekeys/v1",
    "one-time-prekey-active/v1",
    one_time_prekey_label(recipient.bundle.one_time_prekey_id),
    "session/v1/#{Bytes.to_hex(session_id)}",
    "sibling-session/v1/#{Bytes.to_hex(session_id)}",
    "history/v1/#{Bytes.to_hex(direct_conversation_id(recipient.account_id, target.account_id)?)}"
  ]
  let before = load_account_basis(fixture.linked_path, labels)?
  let result = receive_initial_message(MobileReceiveRequest {
    database_path: fixture.linked_path,
    outer: wire
  })
  let observed = load_account_basis(fixture.linked_path, labels)?
  clear_initial_sync_fixture(fixture)?
  if replaced do
    let exact = case result do
      Err(error) -> error == "initial_identity_mismatch"
      Ok(_) -> false
    end
    check(exact, "actual handshake credential/profile key mismatch not refused exactly")?
    check(same_account_basis(before, observed), "credential mismatch changed durable state")
  else
    check(Result.is_ok(result), "matching credential/profile positive refused")?
    check(!same_account_basis(before, observed), "matching credential/profile did not commit")
  end
end

test("matching actual credential and decrypted profile admit sibling initial") do
  case credential_binding(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("valid same-root same-device credential with different actual keys refuses") do
  case credential_binding(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
