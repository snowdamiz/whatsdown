##! Public receive regression: synthetic accounts, real attacker signature and recipient crypto.
from Identity.Device import (
  AccountKeys,
  generate_account,
  generate_device,
  issue_hybrid_device_credential
)
from Mobile.Codec import current_time
from Mobile.Messages import receive_initial_message, receive_message
from Mobile.Profile import load_profile, policy
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

fn attacker_carrier(recipient :: ClientProfile,
  target :: ClientProfile) -> Result<(RatchetState, Bytes, ClientProfile), String> do
  let now = current_time()?
  let expiry = U64.add(now, U64.parse("86400000")?)?
  let (generated, identity) = case generate_account(now, U64.parse("1")?) do
    Err(_) -> return Err("fixture_account")
    Ok(value) -> value
  end
  # Account IDs are independent of authorization keys. The attacker owns this key.
  let public_key = generated.public_key
  let account = AccountKeys {
    account_id: recipient.account_id,
    private_key: generated.private_key,
    public_key: public_key
  }
  let identity = %{identity | account_id: recipient.account_id}
  let device = case generate_device() do
    Err(_) -> return Err("fixture_device")
    Ok(value) -> value
  end
  let pq = case generate_post_quantum_prekey() do
    Err(_) -> return Err("fixture_pq")
    Ok(value) -> value
  end
  let credential = case issue_hybrid_device_credential(account,
    device,
    pq.public_key,
    U64.parse("31")?,
    now,
    expiry,
    U64.parse("1")?) do
    Err(_) -> return Err("fixture_credential")
    Ok(value) -> value
  end
  let signed = case generate_signed_prekey(device, credential, U64.parse("1")?, expiry) do
    Err(_) -> return Err("fixture_signed")
    Ok(value) -> value
  end
  let once = case generate_one_time_prekey(U64.parse("2")?) do
    Err(_) -> return Err("fixture_once")
    Ok(value) -> value
  end
  let bundle = case build_hybrid_prekey_bundle(credential, signed, once, pq) do
    Err(_) -> return Err("fixture_bundle")
    Ok(value) -> value
  end
  let account_wire = case encode_account_identity(identity) do
    Err(_) -> return Err("fixture_identity_wire")
    Ok(value) -> value
  end
  let bundle_wire = case encode_prekey_bundle(bundle) do
    Err(_) -> return Err("fixture_bundle_wire")
    Ok(value) -> value
  end
  let sender_wire = encode_client_profile(DirectoryEntry {
      version: 1,
      username: recipient.username,
      account_identity: account_wire,
      prekey_bundle: bundle_wire,
      mailbox_token: repeated(67, 32)?
    },
    recipient.account_id,
    device.device_id)?
  let sender = decode_client_profile(sender_wire)?
  let plaintext = encode_initial_plaintext(sender_wire,
    inner_bytes(sync_inner(sender, recipient, target, 81)?)?)?
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
  let packet = encode_packet(InitialPacket(account_wire, initial_bytes(initial)?))?
  let wire = sealed_outer_bytes(recipient.entry.mailbox_token,
    packet,
    recipient.credential.dh_public_key,
    now)?
  Ok((state, wire, sender))
end

fn forged_initial_refuses() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = initial_sync_fixture()?
  let recipient = decode_client_profile(load_profile(fixture.linked_path)?)?
  let target = decode_client_profile(load_profile(fixture.bob_path)?)?
  let (state, wire, attacker) = attacker_carrier(recipient, target)?
  let session_id = state.session_id
  let labels = [
    "sessions/v1",
    "one-time-prekeys/v1",
    "one-time-prekey-active/v1",
    one_time_prekey_label(recipient.bundle.one_time_prekey_id),
    "session/v1/#{Bytes.to_hex(session_id)}",
    "history/v1/#{Bytes.to_hex(direct_conversation_id(recipient.account_id, target.account_id)?)}"
  ]
  let before = load_account_basis(fixture.linked_path, labels)?
  let initial = receive_initial_message(MobileReceiveRequest {
    database_path: fixture.linked_path,
    outer: wire
  })
  let observed = load_account_basis(fixture.linked_path, labels)?
  let (_next, follow_on) = sibling_carrier(state,
    recipient,
    sync_inner(attacker, recipient, target, 82)?)?
  let follow = receive_message(MobileReceiveRequest {
    database_path: fixture.linked_path,
    outer: follow_on
  })
  let final_basis = load_account_basis(fixture.linked_path, labels)?
  clear_initial_sync_fixture(fixture)?
  check(Result.is_err(initial), "forged same-account initial was admitted")?
  check(same_account_basis(before, observed),
    "forged initial changed durable session/prekey/history state")?
  check(Result.is_err(follow), "forged follow-on ratchet was admitted")?
  check(same_account_basis(before, final_basis), "forged follow-on changed durable state")
end

test("same account ID under attacker authority cannot admit sibling initial or follow-on") do
  case forged_initial_refuses() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn restored_sibling_refuses(mode :: Int) -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = initial_sync_fixture()?
  let sender = decode_client_profile(load_profile(fixture.alice_path)?)?
  let recipient = decode_client_profile(load_profile(fixture.linked_path)?)?
  let target = decode_client_profile(load_profile(fixture.bob_path)?)?
  let (state, initial) = initial_carrier(fixture.alice_path,
    fixture.linked_path,
    sync_inner(sender, recipient, target, 91)?)?
  let session_id = state.session_id
  let session = "session/v1/#{Bytes.to_hex(session_id)}"
  let marker = "sibling-session/v1/#{Bytes.to_hex(state.session_id)}"
  let _initial = receive_initial_message(MobileReceiveRequest {
    database_path: fixture.linked_path,
    outer: initial
  })?
  let original = load_blob(fixture.linked_path, session)?
  let (state, first) = sibling_carrier(state,
    recipient,
    sync_inner(sender, recipient, target, 92)?)?
  let _first = receive_message(MobileReceiveRequest {
    database_path: fixture.linked_path,
    outer: first
  })?
  let (state, second) = sibling_carrier(state,
    recipient,
    sync_inner(sender, recipient, target, 93)?)?
  let (_state, third) = sibling_carrier(state,
    recipient,
    sync_inner(sender, recipient, target, 94)?)?
  if mode == 4 do
    let key = platform_key()?
    let loaded = load_session_record(fixture.linked_path, key, session_id)?
    let before_marker = load_blob(fixture.linked_path, marker)?
    let changed = %{loaded.record | verified: true}
    store_updated_blobs(fixture.linked_path,
      [session],
      [
        seal_local(updated_session_record(changed.snapshot, changed)?,
          key,
          local_context(session)?)?
      ])?
    check(Bytes.secure_equals(before_marker, load_blob(fixture.linked_path, marker)?),
      "metadata update changed provenance")?
  end
  if mode == 0 || mode == 4 do
    let _second = receive_message(MobileReceiveRequest {
      database_path: fixture.linked_path,
      outer: second
    })?
    let _third = receive_message(MobileReceiveRequest {
      database_path: fixture.linked_path,
      outer: third
    })?
    clear_initial_sync_fixture(fixture)?
    return Ok(nil)
  end
  if mode == 1 do
    with_record_transaction(fixture.linked_path, fn(database) do delete_blob(database, marker) end)?
  else if mode == 3 do
    let devices = case encode_device_set(DeviceSet {
      version: 1,
      username: recipient.username,
      account_identity: recipient.entry.account_identity,
      sequence: wide(3)?,
      devices: [recipient.entry],
      revoked_device_ids: [sender.device_id]
    }) do
      Err(_) -> return Err("fixture_revocation_encoding")
      Ok(value) -> value
    end
    let signed = signed_transparency_view([leaf_hash(devices)?])?
    if !(install_signed_transparency(fixture.linked_path, signed, devices)?) do
      return Err("fixture_revocation_install")
    end
  else
    # Keep the current provenance row while restoring an older sealed snapshot.
    store_updated_blobs(fixture.linked_path, [session], [original])?
  end
  let labels = [
    session,
    marker,
    "sessions/v1",
    "history/v1/#{Bytes.to_hex(direct_conversation_id(recipient.account_id, target.account_id)?)}"
  ]
  let before = load_account_basis(fixture.linked_path, labels)?
  let result = receive_message(MobileReceiveRequest {
    database_path: fixture.linked_path,
    outer: if mode == 1 || mode == 3 do
      second
    else
      first
    end
  })
  let observed = load_account_basis(fixture.linked_path, labels)?
  clear_initial_sync_fixture(fixture)?
  let refused = case result do
    Err(error) -> error == if mode == 3 do
        "sibling_membership_invalid"
      else
        "sibling_session_unproven"
      end
    Ok(_) -> false
  end
  check(refused, "unproven or revoked sibling ratchet did not refuse exactly")?
  check(same_account_basis(before, observed), "refused sibling ratchet changed durable state")
end

test("genuine sibling initial and successive ratchets remain usable") do
  case restored_sibling_refuses(0) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("missing sibling provenance refuses before state mutation") do
  case restored_sibling_refuses(1) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("old sibling snapshot with current marker refuses before state mutation") do
  case restored_sibling_refuses(2) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("fresh witnessed revocation refuses an established sibling session") do
  case restored_sibling_refuses(3) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("metadata-only edits preserve sibling session provenance") do
  case restored_sibling_refuses(4) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
