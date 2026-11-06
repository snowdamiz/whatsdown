from Identity.Device import issue_device_credential
from Mobile.Profile import load_profile, open_account, open_device
from Mobile.Prekeys import load_prekey_pool
from Mobile.Renewal import open_bundle_prekeys, renew_devices_at
from Mobile.Sessions import load_session_ids, load_session_record, restore_session
from Mobile.FanoutPrekeys import fanout_prekey_claim_label, fanout_prekey_reservation_label
from MobileCore import (
  create_link_request_export,
  authorize_device_link_export,
  complete_device_link_export,
  directory_entry_export,
  start_conversation_export,
  send_message_export,
  send_fanout_export,
  receive_initial_export,
  receive_message_export,
  outbox_list_export,
  process_delivery_batch_export,
  replenish_prekeys_export,
  reserve_fanout_prekey_export
)
from Mobile.InboxState import load_delivery_attempts
from Prekeys.Pool import OneTimePrekeyPublic, decode_prekey_publish
from Tests.Support import write_u32, database_path
from Tests.GroupLifecycleWire import ack, delivery_batch
from Prekeys.Bundle import build_prekey_bundle, normalize_prekey_bundle, reauthorize_signed_prekey
from Protocol.DirectoryWire import decode_device_set, decode_directory_entry, encode_device_set
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import DirectoryEntry
from Storage.AccountGuard import load_account_basis, account_basis_current
from Storage.Keys import platform_key, local_context, seal_local, one_time_prekey_label
from Storage.Records import store_updated_session
from Tests.GroupLifecycleSupport import (
  GroupAccountFixture,
  group_account_fixture,
  install_signed_transparency
)
from Tests.GroupConsistencySupport import request, signed_transparency_view
from Tests.GroupLifecycleWire import output_list
from Transparency.Merkle import leaf_hash
from Transport.Packet import (
  ClientProfile,
  decode_client_profile,
  encode_client_profile,
  direct_conversation_id
)
from Session.State import RatchetState
import File

struct FloorFixture do
  alice_path :: String
  linked_path :: String
  bob_path :: String
  alice_profile :: Bytes
  linked_profile :: Bytes
  bob_profile :: Bytes
  alice_claimed :: DirectoryEntry
  linked_claimed :: DirectoryEntry
  bob_claimed :: DirectoryEntry
  own_set :: Bytes
  peer_set :: Bytes
  security_frame :: Bytes
end

fn assert_received_fixture(value :: Bool) do
  assert(declassify(value,
    "test-only Boolean assertion of controlled synthetic native session suite-floor delivery and exact receive errors; no application disclosure"))
end

fn discard(state :: consume RatchetState) do
  nil
end

# A real account-signed classical credential retains the current reader mask31,
# original device keys and encrypted OTP/signed-private keys. It cannot be
# refused merely by the unrelated HE capability check.
fn make_classical(primary_path :: String, target_path :: String) -> Unit!String do
  let key = platform_key()?
  let primary = decode_client_profile(load_profile(primary_path)?)?
  let target = decode_client_profile(load_profile(target_path)?)?
  let account = open_account(primary, key, primary_path)?
  let device = open_device(target, key, target_path)?
  let credential = case issue_device_credential(account,
    device,
    U64.parse("31")?,
    target.credential.created_at,
    target.credential.expires_at,
    target.credential.directory_sequence) do
    Err(_) -> return Err("classical_credential_fixture")
    Ok(value) -> value
  end
  let pool = load_prekey_pool(target, key, target_path)?
  let (signed, one_time, _) = open_bundle_prekeys(target,
    key,
    target_path,
    target.bundle,
    List.head(pool))?
  let signed = case reauthorize_signed_prekey(device, credential, signed) do
    Err(_) -> return Err("classical_signed_prekey_fixture")
    Ok(value) -> value
  end
  let bundle = case build_prekey_bundle(credential, signed, one_time) do
    Err(_) -> return Err("classical_bundle_fixture")
    Ok(value) -> value
  end
  # Local profile retains its actual advertised seed OTP, as account creation
  # does; only directory-set entries are normalized by base_entry below.
  let wire = case encode_prekey_bundle(bundle) do
    Err(_) -> return Err("classical_bundle_encoding_fixture")
    Ok(value) -> value
  end
  let profile = encode_client_profile(%{target.entry | prekey_bundle: wire},
    target.account_id,
    target.device_id)?
  store_updated_session(target_path,
    "profile/v1",
    seal_local(profile, key, local_context("profile/v1")?)?)
end

fn base_entry(entry :: DirectoryEntry) -> DirectoryEntry!String do
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> return Err("bundle_decode_fixture")
    Ok(value) -> value
  end
  let base = case normalize_prekey_bundle(bundle) do
    Err(_) -> return Err("bundle_normalize_fixture")
    Ok(value) -> value
  end
  let wire = case encode_prekey_bundle(base) do
    Err(_) -> return Err("bundle_encode_fixture")
    Ok(value) -> value
  end
  Ok(%{entry | prekey_bundle: wire})
end

fn claimed(path :: String) -> DirectoryEntry!String do
  case decode_directory_entry(directory_entry_export(Bytes.from_utf8(path))?) do
    Err(_) -> Err("entry_decode_fixture")
    Ok(value)
  end
end

fn fixture(classical_sender :: Bool,
  classical_peer :: Bool,
  classical_linked :: Bool) -> FloorFixture!String do
  let existing = group_account_fixture()?
  if classical_sender do
    make_classical(existing.alice_path, existing.alice_path)?
  end
  if classical_peer do
    make_classical(existing.bob_path, existing.bob_path)?
  end
  if classical_linked do
    make_classical(existing.alice_path, existing.linked_path)?
  end
  let alice = claimed(existing.alice_path)?
  let linked = claimed(existing.linked_path)?
  let bob = claimed(existing.bob_path)?
  let old_own = case decode_device_set(existing.alice_set) do
    Err(_) -> return Err("own_set_decode_fixture")
    Ok(value) -> value
  end
  let old_peer = case decode_device_set(existing.bob_set) do
    Err(_) -> return Err("peer_set_decode_fixture")
    Ok(value) -> value
  end
  let own = case encode_device_set(%{old_own |
    devices: [base_entry(alice)?, base_entry(linked)?]
  }) do
    Err(_) -> return Err("own_set_encode_fixture")
    Ok(value) -> value
  end
  let peers = case encode_device_set(%{old_peer | devices: [base_entry(bob)?]}) do
    Err(_) -> return Err("peer_set_encode_fixture")
    Ok(value) -> value
  end
  let view = signed_transparency_view([leaf_hash(own)?, leaf_hash(peers)?])?
  for path in [existing.alice_path, existing.bob_path, existing.linked_path] do
    assert(install_signed_transparency(path, view, own)?)
    assert(install_signed_transparency(path, view, peers)?)
  end
  let security = Host.push_get_token(Bytes.from_utf8("messenger/config/v1"))?
  Ok(FloorFixture {
    alice_path: existing.alice_path,
    linked_path: existing.linked_path,
    bob_path: existing.bob_path,
    alice_profile: load_profile(existing.alice_path)?,
    linked_profile: load_profile(existing.linked_path)?,
    bob_profile: load_profile(existing.bob_path)?,
    alice_claimed: alice,
    linked_claimed: linked,
    bob_claimed: bob,
    own_set: own,
    peer_set: peers,
    security_frame: security
  })
end

fn floor_two(value :: FloorFixture) -> Unit!String do
  let text = Bytes.to_utf8(value.security_frame)?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    Bytes.from_utf8("6\n2\n" <> text)))
  Ok(nil)
end

fn cleanup(value :: FloorFixture) -> Unit!String do
  File.delete(value.alice_path)?
  File.delete(value.linked_path)?
  File.delete(value.bob_path)
end

fn session_labels(path :: String, peer :: ClientProfile) -> List<String>!String do
  let ids = load_session_ids(path, platform_key()?)?
  Ok([
    "sessions/v1",
    "outbox/v1",
    "history/v1/#{Bytes.to_hex(direct_conversation_id(decode_client_profile(load_profile(path)?)?.account_id,
      peer.account_id)?)}"
  ]
    ++ for id in ids do
      "session/v1/#{Bytes.to_hex(id)}"
    end)
end

fn assert_classical(path :: String) -> Unit!String do
  let key = platform_key()?
  let ids = load_session_ids(path, key)?
  assert(List.length(ids) == 1)
  let loaded = load_session_record(path, key, List.head(ids))?
  let state = restore_session(loaded, key)?
  assert(state.suite == 1 && state.version == 2)
  discard(state)
  Ok(nil)
end

fn direct_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let value = fixture(false, true, false)?
  let hello = start_conversation_export(request([
    Bytes.from_utf8(value.alice_path),
    value.bob_profile,
    Bytes.from_utf8("valid old classical hello")
  ])?)?
  assert_received_fixture(Bytes.secure_equals(receive_initial_export(request([
      Bytes.from_utf8(value.bob_path),
      hello
    ])?)?,
    Bytes.from_utf8("valid old classical hello")))
  assert_classical(value.alice_path)?
  assert_classical(value.bob_path)?
  println("c3-native-classical-opened:passed")
  floor_two(value)?
  let peer = decode_client_profile(value.bob_profile)?
  let before = load_account_basis(value.alice_path, session_labels(value.alice_path, peer)?)?
  let pending = outbox_list_export(Bytes.from_utf8(value.alice_path))?
  assert(start_conversation_export(request([
    Bytes.from_utf8(value.alice_path),
    value.bob_profile,
    Bytes.from_utf8("new classical must refuse")
  ])?) == Err("session_suite_below_minimum"))
  assert(account_basis_current(value.alice_path, before))
  assert(Bytes.secure_equals(pending, outbox_list_export(Bytes.from_utf8(value.alice_path))?))
  let message = send_message_export(request([
    Bytes.from_utf8(value.alice_path),
    value.bob_profile,
    Bytes.from_utf8("existing classical still sends")
  ])?)?
  assert_received_fixture(Bytes.secure_equals(receive_message_export(request([
      Bytes.from_utf8(value.bob_path),
      message
    ])?)?,
    Bytes.from_utf8("existing classical still sends")))
  assert_classical(value.alice_path)?
  assert_classical(value.bob_path)?
  cleanup(value)?
  println("c3-native-direct-old-session:passed")
  Ok(true)
end

fn incoming_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let value = fixture(true, false, false)?
  let initial = start_conversation_export(request([
    Bytes.from_utf8(value.alice_path),
    value.bob_profile,
    Bytes.from_utf8("classical initial for hybrid reader")
  ])?)?
  println("c3-native-initial-created:passed")
  floor_two(value)?
  let peer = decode_client_profile(value.alice_profile)?
  let bundle = case decode_prekey_bundle(value.bob_claimed.prekey_bundle) do
    Err(_) -> return Err("incoming_bundle_fixture")
    Ok(value) -> value
  end
  let before = load_account_basis(value.bob_path,
    session_labels(value.bob_path, peer)?
      ++ [
        "one-time-prekeys/v1",
        "one-time-prekey-active/v1",
        one_time_prekey_label(bundle.one_time_prekey_id),
        "last-resort-replays/v1"
      ])?
  let result = receive_initial_export(request([Bytes.from_utf8(value.bob_path), initial])?)
  case result do
    Err(_) -> nil
    Ok(clear) -> do
      assert_received_fixture(Bytes.secure_equals(clear,
        Bytes.from_utf8("classical initial for hybrid reader")))
      println("c3-native-incoming-opened-baseline:passed")
    end
  end
  assert_received_fixture(result == Err("initial_receive_failed"))
  assert(account_basis_current(value.bob_path, before))
  cleanup(value)?
  println("c3-native-incoming-refusal:passed")
  Ok(true)
end

fn fanout_proof(classical_peer :: Bool, classical_linked :: Bool) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let value = fixture(false, classical_peer, classical_linked)?
  let bob = decode_client_profile(value.bob_profile)?
  let linked = decode_client_profile(value.linked_profile)?
  for bundle in [value.bob_claimed.prekey_bundle, value.linked_claimed.prekey_bundle] do
    assert(Bytes.length(reserve_fanout_prekey_export(request([
      Bytes.from_utf8(value.alice_path),
      value.peer_set,
      value.own_set,
      bundle
    ])?)?) == 0)
  end
  floor_two(value)?
  let before = load_account_basis(value.alice_path,
    session_labels(value.alice_path, bob)?
      ++ [
        fanout_prekey_claim_label(bob),
        fanout_prekey_reservation_label(bob),
        fanout_prekey_claim_label(linked),
        fanout_prekey_reservation_label(linked)
      ])?
  let result = send_fanout_export(request([
    Bytes.from_utf8(value.alice_path),
    value.peer_set,
    value.own_set,
    Bytes.from_utf8("floor-two fanout")
  ])?)
  if classical_peer || classical_linked do
    case result do
      Err(_) -> nil
      Ok(wire) -> do
        let packets = output_list(wire)?
        assert(List.length(packets) == 2)
        assert_received_fixture(Bytes.secure_equals(receive_initial_export(request([
            Bytes.from_utf8(value.bob_path),
            List.get(packets, 0)
          ])?)?,
          Bytes.from_utf8("floor-two fanout")))
        assert_received_fixture(Bytes.secure_equals(receive_initial_export(request([
            Bytes.from_utf8(value.linked_path),
            List.get(packets, 1)
          ])?)?,
          Bytes.from_utf8("floor-two fanout")))
        println("c3-native-mixed-opened-peer=#{classical_peer}-linked=#{classical_linked}:passed")
      end
    end
    assert(result == Err("session_suite_below_minimum"))
    assert(account_basis_current(value.alice_path, before))
  else
    let packets = case result do
      Err(error) -> return Err(error)
      Ok(value) -> output_list(value)?
    end
    assert(List.length(packets) == 2)
    assert_received_fixture(Bytes.secure_equals(receive_initial_export(request([
        Bytes.from_utf8(value.bob_path),
        List.get(packets, 0)
      ])?)?,
      Bytes.from_utf8("floor-two fanout")))
    assert_received_fixture(Bytes.secure_equals(receive_initial_export(request([
        Bytes.from_utf8(value.linked_path),
        List.get(packets, 1)
      ])?)?,
      Bytes.from_utf8("floor-two fanout")))
  end
  cleanup(value)?
  println("c3-native-fanout-peer=#{classical_peer}-linked=#{classical_linked}:passed")
  Ok(true)
end

test("native direct floor refuses a new classical session and preserves an installed classical HE snapshot") do
  assert_received_fixture(Result.unwrap_or(direct_proof(), false))
end

test("native incoming floor refuses a valid classical INITIAL without prekey/session mutation") do
  case incoming_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("fanout refuses an actual classical peer despite hybrid linked devices") do
  case fanout_proof(true, false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("fanout refuses a classical linked own device despite a hybrid peer") do
  case fanout_proof(false, true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("fanout accepts actual hybrid peer and linked INITIAL packets at floor two") do
  case fanout_proof(false, false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn set_with(entries :: List<DirectoryEntry>, previous :: Bytes, sequence :: U64) -> Bytes!String do
  let decoded = case decode_device_set(previous) do
    Err(_) -> return Err("renewal_set_decode_fixture")
    Ok(value) -> value
  end
  case encode_device_set(%{decoded | sequence: sequence, devices: entries}) do
    Err(_) -> Err("renewal_set_encode_fixture")
    Ok(value)
  end
end

fn install_sets(value :: FloorFixture, own :: Bytes, peers :: Bytes) -> Unit!String do
  let view = signed_transparency_view([leaf_hash(own)?, leaf_hash(peers)?])?
  for path in [value.alice_path, value.linked_path, value.bob_path] do
    assert(install_signed_transparency(path, view, own)?)
    assert(install_signed_transparency(path, view, peers)?)
  end
  Ok(nil)
end

fn entry_from(input :: Bytes) -> DirectoryEntry!String do
  case decode_directory_entry(input) do
    Err(_) -> Err("renewal_entry_decode_fixture")
    Ok(value)
  end
end

fn retained_proof(classical :: Bool) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let value = fixture(false, classical, false)?
  if !classical do
    floor_two(value)?
  end
  let text = Bytes.from_utf8("held exact old-generation initial")
  let held = start_conversation_export(request([
    Bytes.from_utf8(value.alice_path),
    value.bob_profile,
    text
  ])?)?
  let old = decode_client_profile(value.bob_profile)?
  # Existing fixture-only renewal age changes scheduling, never credential
  # timestamps or the release activation date. Production passes age zero.
  let due = renew_devices_at(value.bob_path, value.peer_set, U64.parse("7862400000")?)?
  assert(List.length(due) == 1)
  let next = entry_from(List.head(due))?
  let next_bundle = case decode_prekey_bundle(next.prekey_bundle) do
    Err(_) -> return Err("renewal_bundle_decode_fixture")
    Ok(value) -> value
  end
  assert(next_bundle.suite == 2)
  let previous_set = case decode_device_set(value.peer_set) do
    Err(_) -> return Err("renewal_set_decode_fixture")
    Ok(value) -> value
  end
  let next_set = set_with([base_entry(next)?],
    value.peer_set,
    U64.add(previous_set.sequence, U64.parse("1")?)?)?
  install_sets(value, value.own_set, next_set)?
  assert(List.length(renew_devices_at(value.bob_path, next_set, U64.parse("0")?)?) == 0)
  let current = decode_client_profile(load_profile(value.bob_path)?)?
  assert(current.credential.suite == 2)
  assert(U64.compare(current.bundle.signed_prekey_id, old.bundle.signed_prekey_id) > 0)
  assert(U64.compare(current.credential.capabilities, U64.parse("31")?) == 0)
  let current_frame = Host.push_get_token(Bytes.from_utf8("messenger/config/v1"))?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    Bytes.from_utf8("6\n2\n" <> Bytes.to_utf8(current_frame)?)))
  let before = load_account_basis(value.bob_path,
    [
      "sessions/v1",
      "prekey-bundles/v1",
      "one-time-prekeys/v1",
      "one-time-prekey-active/v1",
      "last-resort-replays/v1",
      one_time_prekey_label(old.bundle.one_time_prekey_id),
      "signed-prekey/v1",
      "signed-prekey/v1/#{U64.to_string(old.bundle.signed_prekey_id)}"
    ])?
  let result = receive_initial_export(request([Bytes.from_utf8(value.bob_path), held])?)
  if classical do
    case result do
      Err(_) -> nil
      Ok(opened) -> do
        assert_received_fixture(Bytes.secure_equals(opened, text))
        println("c3-native-retired-classical-opened-baseline:passed")
      end
    end
    assert_received_fixture(result == Err("initial_receive_failed"))
    assert(account_basis_current(value.bob_path, before))
    # The exact same packet must open at floor1: this proves it matched the
    # authenticated retained bundle and that floor2 did not consume its OTP.
    assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), current_frame))
    assert_received_fixture(Bytes.secure_equals(receive_initial_export(request([
        Bytes.from_utf8(value.bob_path),
        held
      ])?)?,
      text))
    assert_classical(value.bob_path)?
  else
    let opened = case result do
      Err(error) -> return Err(error)
      Ok(value) -> value
    end
    assert_received_fixture(Bytes.secure_equals(opened, text))
  end
  cleanup(value)?
  println("c3-native-retired-classical=#{classical}:passed")
  Ok(true)
end

fn linked_renewal_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let value = fixture(false, false, true)?
  let old = decode_client_profile(value.linked_profile)?
  assert(old.credential.suite == 1)
  let due = renew_devices_at(value.linked_path, value.own_set, U64.parse("7862400000")?)?
  assert(List.length(due) == 1)
  let asking = entry_from(List.head(due))?
  let previous_set = case decode_device_set(value.own_set) do
    Err(_) -> return Err("linked_set_decode_fixture")
    Ok(value) -> value
  end
  let asking_sequence = U64.add(previous_set.sequence, U64.parse("1")?)?
  let asking_set = set_with([base_entry(value.alice_claimed)?, base_entry(asking)?],
    value.own_set,
    asking_sequence)?
  install_sets(value, asking_set, value.peer_set)?
  let answers = renew_devices_at(value.alice_path, asking_set, U64.parse("0")?)?
  assert(List.length(answers) == 1)
  let answer = entry_from(List.head(answers))?
  let answer_bundle = case decode_prekey_bundle(answer.prekey_bundle) do
    Err(_) -> return Err("linked_answer_bundle_fixture")
    Ok(value) -> value
  end
  assert(answer_bundle.suite == 2)
  let final_set = set_with([base_entry(value.alice_claimed)?, base_entry(answer)?],
    value.own_set,
    U64.add(asking_sequence, U64.parse("1")?)?)?
  install_sets(value, final_set, value.peer_set)?
  assert(List.length(renew_devices_at(value.linked_path, final_set, U64.parse("0")?)?) == 0)
  let renewed = decode_client_profile(load_profile(value.linked_path)?)?
  assert(renewed.credential.suite == 2)
  assert(U64.compare(renewed.credential.capabilities, U64.parse("31")?) == 0)
  let frame = Host.push_get_token(Bytes.from_utf8("messenger/config/v1"))?
  assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"),
    Bytes.from_utf8("6\n2\n" <> Bytes.to_utf8(frame)?)))
  let packet = start_conversation_export(request([
    Bytes.from_utf8(value.linked_path),
    value.bob_profile,
    Bytes.from_utf8("linked renewed hybrid")
  ])?)?
  assert_received_fixture(Bytes.secure_equals(receive_initial_export(request([
      Bytes.from_utf8(value.bob_path),
      packet
    ])?)?,
    Bytes.from_utf8("linked renewed hybrid")))
  cleanup(value)?
  println("c3-native-linked-classical-renewal:passed")
  Ok(true)
end

test("floor two refuses a retained classical bundle but the identical packet survives for explicit floor one") do
  case retained_proof(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("a real retained hybrid bundle still opens an initial at floor two after renewal") do
  case retained_proof(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("a classical linked device completes its exact signed renewal and starts hybrid at floor two") do
  case linked_renewal_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn reusable_profile(path :: String, encoded :: Bytes) -> Bytes!String do
  let publication = decode_prekey_publish(replenish_prekeys_export(request([
    Bytes.from_utf8(path),
    write_u32(0)?
  ])?)?)?
  let reusable = case publication.last_resort do
    None -> return Err("last_resort_fixture_missing")
    Some(value) -> value
  end
  let profile = decode_client_profile(encoded)?
  let wire = case encode_prekey_bundle(%{profile.bundle |
    one_time_prekey_id: reusable.id,
    one_time_prekey: reusable.public_key
  }) do
    Err(_) -> return Err("last_resort_bundle_fixture")
    Ok(value) -> value
  end
  encode_client_profile(%{profile.entry | prekey_bundle: wire},
    profile.account_id,
    profile.device_id)
end

fn last_resort_floor_proof(classical :: Bool) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let value = fixture(false, classical, false)?
  let reusable = reusable_profile(value.bob_path, value.bob_profile)?
  let target = decode_client_profile(reusable)?
  let held = start_conversation_export(request([
    Bytes.from_utf8(value.alice_path),
    reusable,
    Bytes.from_utf8("valid reusable initial")
  ])?)?
  floor_two(value)?
  let before = load_account_basis(value.bob_path,
    [
      "sessions/v1",
      "last-resort-prekey/v1",
      "last-resort-retired/v1",
      "last-resort-replays/v1",
      one_time_prekey_label(target.bundle.one_time_prekey_id)
    ])?
  let result = receive_initial_export(request([Bytes.from_utf8(value.bob_path), held])?)
  if classical do
    assert_received_fixture(result == Err("initial_receive_failed"))
    assert(account_basis_current(value.bob_path, before))
    assert(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), value.security_frame))
    assert_received_fixture(Bytes.secure_equals(receive_initial_export(request([
        Bytes.from_utf8(value.bob_path),
        held
      ])?)?,
      Bytes.from_utf8("valid reusable initial")))
    assert_classical(value.bob_path)?
  else
    assert_received_fixture(result == Ok(Bytes.from_utf8("valid reusable initial")))
  end
  # Successful reuse records replay protection, while the durable reusable key
  # remains available. A second delivery never rolls back the installed session.
  assert_received_fixture(receive_initial_export(request([
    Bytes.from_utf8(value.bob_path),
    held
  ])?) == Err("replayed_initial_message"))
  cleanup(value)?
  println("c3-native-last-resort-classical=#{classical}:passed")
  Ok(true)
end

fn inbox_floor_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let value = fixture(true, false, false)?
  let held = start_conversation_export(request([
    Bytes.from_utf8(value.alice_path),
    value.bob_profile,
    Bytes.from_utf8("permanently refused classical initial")
  ])?)?
  let before = load_account_basis(value.bob_path,
    [
      "sessions/v1",
      "one-time-prekeys/v1",
      "one-time-prekey-active/v1",
      one_time_prekey_label(decode_client_profile(value.bob_profile)?.bundle.one_time_prekey_id),
      "last-resort-replays/v1"
    ])?
  floor_two(value)?
  let acknowledgement = ack(process_delivery_batch_export(request([
    Bytes.from_utf8(value.bob_path),
    delivery_batch(held)?
  ])?)?)?
  assert(List.length(acknowledgement.envelope_ids) == 1)
  assert(account_basis_current(value.bob_path, before))
  assert(Bytes.length(load_delivery_attempts(value.bob_path, platform_key()?)?) == 0)
  cleanup(value)?
  println("c3-native-inbox-permanent-refusal-ack:passed")
  Ok(true)
end

test("floor two refuses reusable classical initial without consuming durable key or replay state") do
  case last_resort_floor_proof(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("floor two admits a real hybrid reusable initial and retains replay protection") do
  case last_resort_floor_proof(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("inbox acknowledges a permanent floor refusal without installing session or consuming prekeys") do
  case inbox_floor_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn peer_sibling_proof(classical :: Bool) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let value = fixture(false, false, false)?
  let sibling_path = database_path("c3-peer-sibling")?
  let link_request = create_link_request_export(Bytes.from_utf8(sibling_path))?
  let authorization = authorize_device_link_export(request([
    Bytes.from_utf8(value.bob_path),
    link_request
  ])?)?
  complete_device_link_export(request([Bytes.from_utf8(sibling_path), authorization])?)?
  if classical do
    make_classical(value.bob_path, sibling_path)?
  end
  let bob = claimed(value.bob_path)?
  let sibling = claimed(sibling_path)?
  let previous = case decode_device_set(value.peer_set) do
    Err(_) -> return Err("sibling_set_fixture")
    Ok(value) -> value
  end
  let peers = set_with([base_entry(bob)?, base_entry(sibling)?],
    value.peer_set,
    U64.add(previous.sequence, U64.parse("1")?)?)?
  let view = signed_transparency_view([leaf_hash(value.own_set)?, leaf_hash(peers)?])?
  for path in [value.alice_path, value.linked_path, value.bob_path, sibling_path] do
    assert(install_signed_transparency(path, view, value.own_set)?)
    assert(install_signed_transparency(path, view, peers)?)
  end
  for bundle in [bob.prekey_bundle, sibling.prekey_bundle, value.linked_claimed.prekey_bundle] do
    reserve_fanout_prekey_export(request([
      Bytes.from_utf8(value.alice_path),
      peers,
      value.own_set,
      bundle
    ])?)?
  end
  floor_two(%{value |
    security_frame: Host.push_get_token(Bytes.from_utf8("messenger/config/v1"))?
  })?
  let peer = decode_client_profile(value.bob_profile)?
  let sibling_profile = decode_client_profile(load_profile(sibling_path)?)?
  let before = load_account_basis(value.alice_path,
    session_labels(value.alice_path, peer)?
      ++ [
        fanout_prekey_claim_label(peer),
        fanout_prekey_reservation_label(peer),
        fanout_prekey_claim_label(sibling_profile),
        fanout_prekey_reservation_label(sibling_profile)
      ])?
  let result = send_fanout_export(request([
    Bytes.from_utf8(value.alice_path),
    peers,
    value.own_set,
    Bytes.from_utf8("three actual targets")
  ])?)
  if classical do
    assert(result == Err("session_suite_below_minimum"))
    assert(account_basis_current(value.alice_path, before))
  else
    let packets = output_list(result?)?
    assert(List.length(packets) == 3)
    for index in 0..3 do
      let path = List.get([value.bob_path, sibling_path, value.linked_path], index)
      assert_received_fixture(Bytes.secure_equals(receive_initial_export(request([
          Bytes.from_utf8(path),
          List.get(packets, index)
        ])?)?,
        Bytes.from_utf8("three actual targets")))
    end
    let key = platform_key()?
    let ids = load_session_ids(value.alice_path, key)?
    assert(List.length(ids) == 3)
    for id in ids do
      let state = restore_session(load_session_record(value.alice_path, key, id)?, key)?
      assert(state.suite == 2)
      discard(state)
    end
    nil
  end
  File.delete(sibling_path)?
  cleanup(value)?
  println("c3-native-peer-sibling-classical=#{classical}:passed")
  Ok(true)
end

test("a hybrid representative cannot authorize an actual classical peer sibling in three-target fanout") do
  case peer_sibling_proof(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("three actual hybrid fanout targets install suite two snapshots at floor two") do
  case peer_sibling_proof(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn existing_classical_fanout_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let value = fixture(true, true, true)?
  for bundle in [value.bob_claimed.prekey_bundle, value.linked_claimed.prekey_bundle] do
    reserve_fanout_prekey_export(request([
      Bytes.from_utf8(value.alice_path),
      value.peer_set,
      value.own_set,
      bundle
    ])?)?
  end
  let packets = output_list(send_fanout_export(request([
    Bytes.from_utf8(value.alice_path),
    value.peer_set,
    value.own_set,
    Bytes.from_utf8("installed classical fanout")
  ])?)?)?
  for index in 0..2 do
    let path = List.get([value.bob_path, value.linked_path], index)
    assert_received_fixture(Bytes.secure_equals(receive_initial_export(request([
        Bytes.from_utf8(path),
        List.get(packets, index)
      ])?)?,
      Bytes.from_utf8("installed classical fanout")))
  end
  let pending = output_list(outbox_list_export(Bytes.from_utf8(value.alice_path))?)?
  assert(List.length(pending) == 2)
  floor_two(value)?
  let later = output_list(send_fanout_export(request([
    Bytes.from_utf8(value.alice_path),
    value.peer_set,
    value.own_set,
    Bytes.from_utf8("existing fanout after floor two")
  ])?)?)?
  for index in 0..2 do
    let path = List.get([value.bob_path, value.linked_path], index)
    assert_received_fixture(Bytes.secure_equals(receive_message_export(request([
        Bytes.from_utf8(path),
        List.get(later, index)
      ])?)?,
      Bytes.from_utf8("existing fanout after floor two")))
  end
  let queued = output_list(outbox_list_export(Bytes.from_utf8(value.alice_path))?)?
  assert(List.length(queued) == 4)
  for index in 0..2 do
    assert(Bytes.secure_equals(List.get(pending, index), List.get(queued, index)))
  end
  let key = platform_key()?
  let ids = load_session_ids(value.alice_path, key)?
  assert(List.length(ids) == 2)
  for id in ids do
    let state = restore_session(load_session_record(value.alice_path, key, id)?, key)?
    assert(state.suite == 1)
    discard(state)
  end
  cleanup(value)?
  println("c3-native-existing-classical-fanout-exact-retries:passed")
  Ok(true)
end

test("existing classical fanout snapshots and exact queued retry packets survive floor two") do
  case existing_classical_fanout_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
