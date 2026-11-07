from Tests.HeaderRoutingFixture import capacity_and_progress, expiry_and_churn, malformed
import File
from MobileCore import update_conversation_export
from Mobile.Messages import (
  start_conversation,
  send_message,
  receive_initial_message,
  receive_message
)
from Mobile.Inbox import process_delivery_batch
from Mobile.InboxState import load_delivery_attempts
from Mobile.HeaderRouting import (
  HeaderRoute,
  route_header,
  route_header_guarded,
  commit_header_receive
)
from Mobile.HeaderAdmission import capture_header_history
from Mobile.HeaderRoutingState import (
  HeaderCursor,
  HeaderRoutingState,
  encode_header_routing,
  decode_header_routing
)
from Mobile.Profile import load_profile, open_device
from Mobile.Sessions import (
  load_session_ids,
  load_session_record,
  seal_session_ids,
  updated_session_record,
  parse_ratchet_packet
)
from Mobile.Transport import open_outer_packet
from Mobile.Codec import canonical_outer
from Mobile.Types import MobileStartRequest, MobileReceiveRequest, MobileBatchRequest
from Storage.Keys import platform_key, seal_local, open_local, local_context
from Storage.Blobs import load_blob
from Storage.AccountGuard import load_account_basis
from Storage.Records import store_updated_blobs
from Tests.GroupLifecycleSupport import group_account_fixture, install_signed_transparency
from Tests.GroupConsistencySupport import signed_transparency_view, request
from Tests.GroupLifecycleWire import delivery_batch, ack
from Tests.Support import repeated, write_u32
from Transparency.Merkle import leaf_hash
from Transport.Packet import decode_client_profile
from Session.Ratchet import decode_ratchet_message
from Protocol.V1 import OuterEnvelope

fn assert_received_fixture(value :: Bool) do
  assert(declassify(value,
    "test-only Boolean assertion of controlled synthetic header-encrypted initial message delivery; no application disclosure"))
end

fn label(id :: Bytes) -> String do
  "session/v1/#{Bytes.to_hex(id)}"
end

fn cursor_label() -> String do
  "header-routing/v1"
end

fn add_aliases(path :: String, count :: Int) -> Result<(), String> do
  let key = platform_key()?
  let ids = load_session_ids(path, key)?
  let target = load_session_record(path, key, List.head(ids))?
  let added = for i in 0..count do
    Crypto.sha256(Bytes.from_utf8("fixture-alias/#{i}"))
  end
  let labels = for id in added do
    label(id)
  end
  # Each independent row is sealed against its actual label; no read/auth checker is bypassed.
  let blobs = for i in 0..count do
    seal_local(updated_session_record(Bytes.empty(),
        %{target.record | snapshot: Bytes.empty(), peer_account_id: repeated(99, 32)?})?,
      key,
      local_context(List.get(labels, i))?)?
  end
  store_updated_blobs(path,
    labels ++ ["sessions/v1"],
    blobs ++ [seal_session_ids(added ++ ids, key)?])
end

fn fake_id(index :: Int) -> Bytes!String do
  Bytes.slice(Crypto.sha256(Bytes.from_utf8("held/#{index}")), 0, 16)
end

fn held_cursors(path :: String, outer :: OuterEnvelope, packet :: Bytes) -> Result<(), String> do
  let key = platform_key()?
  let before = load_account_basis(path, ["sessions/v1", cursor_label()])?
  let one = U64.parse("1")?
  let rows = for i in 0..256 do
    HeaderCursor {
      envelope: if i == 0 do
        outer.envelope_id
      else
        fake_id(i)?
      end,
      packet: if i == 0 do
        Crypto.sha256(packet)
      else
        repeated(7, 32)?
      end,
      profile: Crypto.sha256(before.profile),
      sessions: Crypto.sha256(List.get(before.records, 0)),
      count: 17,
      offset: 0,
      first_tick: one,
      progress_tick: one
    }
  end
  let blob = seal_local(encode_header_routing(HeaderRoutingState { tick: one, cursors: rows })?,
    key,
    local_context(cursor_label())?)?
  store_updated_blobs(path, [cursor_label()], [blob])
end

fn packet_for(path :: String, outer :: OuterEnvelope) -> Bytes!String do
  let key = platform_key()?
  let profile = decode_client_profile(load_profile(path)?)?
  let device = open_device(profile, key, path)?
  let opened = open_outer_packet(outer, device.identity_private_key)?
  parse_ratchet_packet(opened.packet)
end

fn pending_and_cas() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = group_account_fixture()?
  let signed = signed_transparency_view([
    leaf_hash(fixture.alice_set)?,
    leaf_hash(fixture.bob_set)?
  ])?
  for path in [fixture.alice_path, fixture.bob_path] do
    assert(install_signed_transparency(path, signed, fixture.alice_set)?)
    assert(install_signed_transparency(path, signed, fixture.bob_set)?)
  end
  let alice_profile = load_profile(fixture.alice_path)?
  let bob_profile = load_profile(fixture.bob_path)?
  let hello = start_conversation(MobileStartRequest {
    database_path: fixture.alice_path,
    peer_profile: bob_profile,
    body: Bytes.from_utf8("first HE"),
    attachment: Bytes.empty()
  })?
  assert_received_fixture(Bytes.secure_equals(receive_initial_message(MobileReceiveRequest {
      database_path: fixture.bob_path,
      outer: hello
    })?,
    Bytes.from_utf8("first HE")))
  update_conversation_export(request([
    Bytes.from_utf8(fixture.bob_path),
    alice_profile,
    repeated(1, 1)?,
    write_u32(0)?
  ])?)?
  let message = send_message(MobileStartRequest {
    database_path: fixture.alice_path,
    peer_profile: bob_profile,
    body: Bytes.from_utf8("beyond-first-batch"),
    attachment: Bytes.empty()
  })?
  add_aliases(fixture.bob_path, 16)?
  let outer = canonical_outer(message)?
  let packet = packet_for(fixture.bob_path, outer)?
  let key = platform_key()?
  let decoded = case decode_ratchet_message(packet) do
    Err(_) -> Err("ratchet decode")
    Ok(value)
  end?
  # A real earlier profile from another owned account must fail before a
  # cursor is created, even though the incoming encrypted header is valid.
  assert(Result.is_err(load_blob(fixture.bob_path, cursor_label())))
  assert(case route_header_guarded(fixture.bob_path,
    key,
    outer.envelope_id,
    packet,
    decoded,
    alice_profile) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Result.is_err(load_blob(fixture.bob_path, cursor_label())))
  held_cursors(fixture.bob_path, outer, packet)?
  let attempts_before = load_delivery_attempts(fixture.bob_path, key)?
  let batch = MobileBatchRequest {
    database_path: fixture.bob_path,
    batch: delivery_batch(message)?
  }
  let first = process_delivery_batch(batch)?
  assert(Bytes.length(first) == 0)
  assert(Bytes.secure_equals(load_delivery_attempts(fixture.bob_path, key)?, attempts_before))
  let cursor = decode_header_routing(open_local(load_blob(fixture.bob_path, cursor_label())?,
    key,
    local_context(cursor_label())?)?)?
  assert(List.length(cursor.cursors) == 256)
  assert(List.any(cursor.cursors,
    fn(value) -> Bytes.secure_equals(value.envelope, outer.envelope_id) && value.offset == 16 end))
  # Read/probe succeeds, but changing the selected session before commit must win.
  let cursor_before_mismatch = load_blob(fixture.bob_path, cursor_label())?
  assert(case route_header_guarded(fixture.bob_path,
    key,
    outer.envelope_id,
    packet,
    decoded,
    alice_profile) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(fixture.bob_path, cursor_label())?, cursor_before_mismatch))
  let routed = route_header(fixture.bob_path, key, outer.envelope_id, packet, decoded)?
  let selected = routed.loaded
  let original = load_blob(fixture.bob_path, selected.label)?
  let changed = seal_local(updated_session_record(selected.record.snapshot,
      %{selected.record | blocked: true})?,
    key,
    local_context(selected.label)?)?
  store_updated_blobs(fixture.bob_path, [selected.label], [changed])?
  assert(case commit_header_receive(fixture.bob_path, routed, [selected.label], [original]) do
    Err(error) -> error == "account_state_changed"
    Ok(_) -> false
  end)
  assert(Bytes.secure_equals(load_blob(fixture.bob_path, selected.label)?, changed))
  store_updated_blobs(fixture.bob_path, [selected.label], [original])?
  for changed_label in ["profile/v1", "sessions/v1", cursor_label()] do
    let stale = route_header(fixture.bob_path, key, outer.envelope_id, packet, decoded)?
    let before_blob = load_blob(fixture.bob_path, changed_label)?
    let replacement = seal_local(open_local(before_blob, key, local_context(changed_label)?)?,
      key,
      local_context(changed_label)?)?
    store_updated_blobs(fixture.bob_path, [changed_label], [replacement])?
    assert(case commit_header_receive(fixture.bob_path, stale, [selected.label], [original]) do
      Err(error) -> error == "account_state_changed"
      Ok(_) -> false
    end)
    assert(Bytes.secure_equals(load_blob(fixture.bob_path, changed_label)?, replacement))
    store_updated_blobs(fixture.bob_path, [changed_label], [before_blob])?
  end
  # An independent authenticated history compaction can win after the history
  # source is captured. Neither the ratchet nor the older history may commit.
  let history_label = "history/v1/#{Bytes.to_hex(selected.record.conversation_id)}"
  let history_source = load_blob(fixture.bob_path, history_label)?
  let before_compaction = route_header(fixture.bob_path, key, outer.envelope_id, packet, decoded)?
  let history_basis = case capture_header_history(fixture.bob_path,
    Some(before_compaction.basis),
    selected.record.conversation_id)? do
    None -> return Err("fixture missing HE history basis")
    Some(value) -> value
  end
  let newer_history = seal_local(open_local(history_source, key, local_context(history_label)?)?,
    key,
    local_context(history_label)?)?
  store_updated_blobs(fixture.bob_path, [history_label], [newer_history])?
  assert(case commit_header_receive(fixture.bob_path,
    %{before_compaction | basis: history_basis},
    [selected.label, history_label],
    [original, history_source]) do
    Err(error) -> error == "account_state_changed"
    Ok(_) -> false
  end)
  assert(Bytes.secure_equals(load_blob(fixture.bob_path, history_label)?, newer_history))
  assert(Bytes.secure_equals(load_blob(fixture.bob_path, selected.label)?, original))
  store_updated_blobs(fixture.bob_path, [history_label], [history_source])?
  let result = ack(process_delivery_batch(batch)?)?
  assert(List.length(result.envelope_ids) == 1)
  assert(Bytes.secure_equals(List.head(result.envelope_ids), outer.envelope_id))
  let next = decode_header_routing(open_local(load_blob(fixture.bob_path, cursor_label())?,
    key,
    local_context(cursor_label())?)?)?
  assert(List.length(next.cursors) == 255)
  assert(Bytes.secure_equals(load_delivery_attempts(fixture.bob_path, key)?, attempts_before))
  # The exact same encrypted packet is a replay; never a second history/ratchet commit.
  assert(case receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: message
  }) do
    Err(_) -> true
    Ok(_) -> false
  end)
  File.delete(fixture.alice_path)?
  File.delete(fixture.linked_path)?
  File.delete(fixture.bob_path)?
  Ok(true)
end

test("actual HE receive progresses through full cursor queue without ACK/retry charge; selected-row CAS prevents stale commit") do
  assert_received_fixture(Result.unwrap_or(pending_and_cas(), false))
end

test("full unauthenticated cursor queue preserves admitted progress across cold reopen and does not impose4096 read ceiling") do
  assert(Result.unwrap_or(capacity_and_progress(), false))
end

test("deterministic idle and absolute cursor leases reclaim capacity; packet and profile/index churn cannot renew original lease") do
  assert(Result.unwrap_or(expiry_and_churn(), false))
end

test("strict cursor codec rejects duplicate IDs, trailing bytes, invalid offsets and future service ticks; writer admission never changes legacy readability") do
  assert(Result.unwrap_or(malformed(), false))
end

fn diagnostic_early(stop :: Int) -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = group_account_fixture()?
  if stop == 1 do
    return Ok(true)
  end
  let signed = signed_transparency_view([
    leaf_hash(fixture.alice_set)?,
    leaf_hash(fixture.bob_set)?
  ])?
  if stop == 2 do
    return Ok(true)
  end
  for path in [fixture.alice_path, fixture.bob_path] do
    assert(install_signed_transparency(path, signed, fixture.alice_set)?)
    assert(install_signed_transparency(path, signed, fixture.bob_set)?)
  end
  if stop == 3 do
    return Ok(true)
  end
  let alice_profile = load_profile(fixture.alice_path)?
  let bob_profile = load_profile(fixture.bob_path)?
  if stop == 4 do
    return Ok(true)
  end
  let hello = start_conversation(MobileStartRequest {
    database_path: fixture.alice_path,
    peer_profile: bob_profile,
    body: Bytes.from_utf8("first HE"),
    attachment: Bytes.empty()
  })?
  assert_received_fixture(Bytes.secure_equals(receive_initial_message(MobileReceiveRequest {
      database_path: fixture.bob_path,
      outer: hello
    })?,
    Bytes.from_utf8("first HE")))
  update_conversation_export(request([
    Bytes.from_utf8(fixture.bob_path),
    alice_profile,
    repeated(1, 1)?,
    write_u32(0)?
  ])?)?
  let message = send_message(MobileStartRequest {
    database_path: fixture.alice_path,
    peer_profile: bob_profile,
    body: Bytes.from_utf8("beyond-first-batch"),
    attachment: Bytes.empty()
  })?
  add_aliases(fixture.bob_path, 16)?
  let outer = canonical_outer(message)?
  let packet = packet_for(fixture.bob_path, outer)?
  let key = platform_key()?
  let decoded = case decode_ratchet_message(packet) do
    Err(_) -> Err("ratchet decode")
    Ok(value)
  end?
  # A real earlier profile from another owned account must fail before a
  # cursor is created, even though the incoming encrypted header is valid.
  assert(Result.is_err(load_blob(fixture.bob_path, cursor_label())))
  assert(case route_header_guarded(fixture.bob_path,
    key,
    outer.envelope_id,
    packet,
    decoded,
    alice_profile) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Result.is_err(load_blob(fixture.bob_path, cursor_label())))
  held_cursors(fixture.bob_path, outer, packet)?
  let attempts_before = load_delivery_attempts(fixture.bob_path, key)?
  let batch = MobileBatchRequest {
    database_path: fixture.bob_path,
    batch: delivery_batch(message)?
  }
  let first = process_delivery_batch(batch)?
  assert(Bytes.length(first) == 0)
  assert(Bytes.secure_equals(load_delivery_attempts(fixture.bob_path, key)?, attempts_before))
  let cursor = decode_header_routing(open_local(load_blob(fixture.bob_path, cursor_label())?,
    key,
    local_context(cursor_label())?)?)?
  assert(List.length(cursor.cursors) == 256)
  assert(List.any(cursor.cursors,
    fn(value) -> Bytes.secure_equals(value.envelope, outer.envelope_id) && value.offset == 16 end))
  # Read/probe succeeds, but changing the selected session before commit must win.
  let cursor_before_mismatch = load_blob(fixture.bob_path, cursor_label())?
  assert(case route_header_guarded(fixture.bob_path,
    key,
    outer.envelope_id,
    packet,
    decoded,
    alice_profile) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(fixture.bob_path, cursor_label())?, cursor_before_mismatch))
  let routed = route_header(fixture.bob_path, key, outer.envelope_id, packet, decoded)?
  let selected = routed.loaded
  let original = load_blob(fixture.bob_path, selected.label)?
  let changed = seal_local(updated_session_record(selected.record.snapshot,
      %{selected.record | blocked: true})?,
    key,
    local_context(selected.label)?)?
  store_updated_blobs(fixture.bob_path, [selected.label], [changed])?
  assert(case commit_header_receive(fixture.bob_path, routed, [selected.label], [original]) do
    Err(error) -> error == "account_state_changed"
    Ok(_) -> false
  end)
  assert(Bytes.secure_equals(load_blob(fixture.bob_path, selected.label)?, changed))
  store_updated_blobs(fixture.bob_path, [selected.label], [original])?
  for changed_label in ["profile/v1", "sessions/v1", cursor_label()] do
    let stale = route_header(fixture.bob_path, key, outer.envelope_id, packet, decoded)?
    let before_blob = load_blob(fixture.bob_path, changed_label)?
    let replacement = seal_local(open_local(before_blob, key, local_context(changed_label)?)?,
      key,
      local_context(changed_label)?)?
    store_updated_blobs(fixture.bob_path, [changed_label], [replacement])?
    assert(case commit_header_receive(fixture.bob_path, stale, [selected.label], [original]) do
      Err(error) -> error == "account_state_changed"
      Ok(_) -> false
    end)
    assert(Bytes.secure_equals(load_blob(fixture.bob_path, changed_label)?, replacement))
    store_updated_blobs(fixture.bob_path, [changed_label], [before_blob])?
  end
  # An independent authenticated history compaction can win after the history
  # source is captured. Neither the ratchet nor the older history may commit.
  let history_label = "history/v1/#{Bytes.to_hex(selected.record.conversation_id)}"
  let history_source = load_blob(fixture.bob_path, history_label)?
  let before_compaction = route_header(fixture.bob_path, key, outer.envelope_id, packet, decoded)?
  let history_basis = case capture_header_history(fixture.bob_path,
    Some(before_compaction.basis),
    selected.record.conversation_id)? do
    None -> return Err("fixture missing HE history basis")
    Some(value) -> value
  end
  let newer_history = seal_local(open_local(history_source, key, local_context(history_label)?)?,
    key,
    local_context(history_label)?)?
  store_updated_blobs(fixture.bob_path, [history_label], [newer_history])?
  assert(case commit_header_receive(fixture.bob_path,
    %{before_compaction | basis: history_basis},
    [selected.label, history_label],
    [original, history_source]) do
    Err(error) -> error == "account_state_changed"
    Ok(_) -> false
  end)
  assert(Bytes.secure_equals(load_blob(fixture.bob_path, history_label)?, newer_history))
  assert(Bytes.secure_equals(load_blob(fixture.bob_path, selected.label)?, original))
  store_updated_blobs(fixture.bob_path, [history_label], [history_source])?
  let result = ack(process_delivery_batch(batch)?)?
  assert(List.length(result.envelope_ids) == 1)
  assert(Bytes.secure_equals(List.head(result.envelope_ids), outer.envelope_id))
  let next = decode_header_routing(open_local(load_blob(fixture.bob_path, cursor_label())?,
    key,
    local_context(cursor_label())?)?)?
  assert(List.length(next.cursors) == 255)
  assert(Bytes.secure_equals(load_delivery_attempts(fixture.bob_path, key)?, attempts_before))
  # The exact same encrypted packet is a replay; never a second history/ratchet commit.
  assert(case receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: message
  }) do
    Err(_) -> true
    Ok(_) -> false
  end)
  File.delete(fixture.alice_path)?
  File.delete(fixture.linked_path)?
  File.delete(fixture.bob_path)?
  Ok(true)
end

test("diagnostic early 1") do
  assert_received_fixture(Result.unwrap_or(diagnostic_early(1), false))
end

test("diagnostic early 2") do
  assert_received_fixture(Result.unwrap_or(diagnostic_early(2), false))
end

test("diagnostic early 3") do
  assert_received_fixture(Result.unwrap_or(diagnostic_early(3), false))
end

test("diagnostic early 4") do
  assert_received_fixture(Result.unwrap_or(diagnostic_early(4), false))
end

test("diagnostic exact public fixture error") do
  assert(Test.install_in_memory_secure_store())
  case group_account_fixture() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end
