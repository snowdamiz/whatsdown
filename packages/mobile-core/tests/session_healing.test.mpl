import File
from Identity.Device import DeviceKeys
from Mobile.Codec import canonical_outer
from Mobile.History import decode_conversation_summary, history_newest_from, history_sent_after
from Mobile.Profile import load_profile, open_device
from Mobile.Sessions import find_peer_session, load_session_ids, restore_session
from Mobile.Transport import MobileOpenedPacket, open_outer_packet
from Mobile.Types import ConversationSummary, MobileLoadedSession
from MobileCore import (
  create_account_export,
  install_classical_session_for_test,
  list_conversations_export,
  load_history_export,
  outbox_ack_export,
  outbox_list_export,
  outbox_page_export,
  receive_initial_export,
  receive_message_export,
  send_message_export,
  start_conversation_export,
  update_conversation_export
)
from Security.Config import SecurityConfig, SecurityWitness, security_config_encode
from Session.Handshake import RatchetState
from Session.Ratchet import RatchetMessage, decode_ratchet_message
from Storage.Keys import platform_key
from Tests.GroupLifecycleWire import output_list
from Tests.Support import append, database_path, vector, write_u32
from Transport.Packet import TransportPacket, decode_client_profile, decode_packet

fn encode_vectors(values :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_vectors(values, index + 1, append(output, vector(List.get(values, index))?)?)
  end
end

fn request(values :: List<Bytes>) -> Bytes!String do
  encode_vectors(values, 0, Bytes.empty())
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("test byte allocation failed")
    Ok(output)
  end
end

fn path_bytes(path :: String) -> Bytes do
  Bytes.from_utf8(path)
end

fn acknowledge(path :: String, envelope :: Bytes) -> Bool!String do
  assert(Bytes.length(outbox_ack_export(request([path_bytes(path), envelope])?)?) == 0)
  Ok(true)
end

fn text(label :: String, index :: Int) -> Bytes do
  Bytes.from_utf8("#{label} #{index}: a message long enough to look like one people send")
end

fn sent(from_path :: String, peer_profile :: Bytes, body :: Bytes) -> Bytes!String do
  let envelope = send_message_export(request([path_bytes(from_path), peer_profile, body])?)?
  assert(acknowledge(from_path, envelope)?)
  Ok(envelope)
end

fn delivered(to_path :: String, envelope :: Bytes, body :: Bytes) -> Bool!String do
  assert(Bytes.secure_equals(receive_message_export(request([path_bytes(to_path), envelope])?)?,
    body))
  Ok(true)
end

## The version of the ratchet message inside a sealed envelope, as only its
## recipient can see.

fn inner_version(recipient_path :: String, envelope :: Bytes) -> Int!String do
  let profile = decode_client_profile(load_profile(recipient_path)?)?
  let device = open_device(profile, platform_key()?, recipient_path)?
  let opened = open_outer_packet(canonical_outer(envelope)?, device.identity_private_key)?
  case decode_packet(opened.packet)? do
    InitialPacket(_, _) -> Ok(0)
    RatchetPacket(message) -> case decode_ratchet_message(message) do
      Err(_) -> Err("invalid ratchet message")
      Ok(value) -> Ok(value.version)
    end
  end
end

fn drop_state(state :: consume RatchetState) do
  nil
end

struct SessionView do
  conversation_id :: Bytes
  header_encrypted :: Bool
  pq_epoch :: Int
  pq_phase :: Int
  reset_state :: Int
end

fn session_view(path :: String, peer_profile :: Bytes) -> SessionView!String do
  let wrapping_key = platform_key()?
  let peer = decode_client_profile(peer_profile)?
  let loaded = find_peer_session(path,
    wrapping_key,
    peer.account_id,
    load_session_ids(path, wrapping_key)?,
    0)?
  let state = restore_session(loaded, wrapping_key)?
  let view = SessionView {
    conversation_id: loaded.record.conversation_id,
    header_encrypted: state.header_encrypted,
    pq_epoch: state.pq_epoch,
    pq_phase: state.pq_phase,
    reset_state: loaded.record.reset_state
  }
  drop_state(state)
  Ok(view)
end

fn summary(path :: String) -> ConversationSummary!String do
  decode_conversation_summary(list_conversations_export(path_bytes(path))?)
end

struct Pair do
  alice_path :: String
  bob_path :: String
  alice_profile :: Bytes
  bob_profile :: Bytes
end

fn conversation(label :: String) -> Pair!String do
  let alice_path = database_path("#{label}-alice")?
  let bob_path = database_path("#{label}-bob")?
  let alice_profile = create_account_export(request([
    path_bytes(alice_path),
    Bytes.from_utf8("alice")
  ])?)?
  let bob_profile = create_account_export(request([path_bytes(bob_path), Bytes.from_utf8("bob")])?)?
  let greeting = Bytes.from_utf8("hello bob")
  let initial = start_conversation_export(request([
    path_bytes(alice_path),
    bob_profile,
    greeting
  ])?)?
  assert(acknowledge(alice_path, initial)?)
  assert(Bytes.secure_equals(receive_initial_export(request([path_bytes(bob_path), initial])?)?,
    greeting))
  assert(Bytes.secure_equals(update_conversation_export(request([
      path_bytes(bob_path),
      alice_profile,
      byte(1)?,
      write_u32(0)?
    ])?)?,
    Bytes.from_utf8("ok")))
  Ok(Pair {
    alice_path: alice_path,
    bob_path: bob_path,
    alice_profile: alice_profile,
    bob_profile: bob_profile
  })
end

fn exchange(pair :: Pair, round :: Int, rounds :: Int) -> Bool!String do
  exchange_sized(pair, round, rounds, 0)
end

## Longer messages leave more padding for the post-quantum ratchet's units.

fn sized(label :: String, index :: Int, length :: Int) -> Bytes do
  if length == 0 do
    text(label, index)
  else
    Bytes.from_utf8(String.slice("#{label} #{index}: " <> String.repeat("x", length), 0, length))
  end
end

fn exchange_sized(pair :: Pair, round :: Int, rounds :: Int, length :: Int) -> Bool!String do
  if round >= rounds do
    Ok(true)
  else
    let from_bob = sized("bob", round, length)
    let reply = sent(pair.bob_path, pair.alice_profile, from_bob)?
    assert(delivered(pair.alice_path, reply, from_bob)?)
    let from_alice = sized("alice", round, length)
    let message = sent(pair.alice_path, pair.bob_profile, from_alice)?
    assert(delivered(pair.bob_path, message, from_alice)?)
    exchange_sized(pair, round + 1, rounds, length)
  end
end

fn upgrade_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let pair = conversation("session-upgrade-v4")?
  # Bob answers on the handshake chain; each side has now heard the other.
  let reply = sent(pair.bob_path, pair.alice_profile, text("bob", 0))?
  assert(inner_version(pair.alice_path, reply)? == 3)
  assert(delivered(pair.alice_path, reply, text("bob", 0))?)
  # Alice's next sending root step upgrades the session.
  let upgraded = sent(pair.alice_path, pair.bob_profile, text("alice", 0))?
  assert(inner_version(pair.bob_path, upgraded)? == 4)
  assert(delivered(pair.bob_path, upgraded, text("alice", 0))?)
  assert(exchange_sized(pair, 1, 12, 700)?)
  let alice = session_view(pair.alice_path, pair.bob_profile)?
  let bob = session_view(pair.bob_path, pair.alice_profile)?
  assert(alice.header_encrypted && bob.header_encrypted)
  # Two hybrid accounts run the post-quantum ratchet; epochs completed, or the
  # later messages, under roots that mixed ML-KEM secrets, would not open.
  assert(alice.pq_epoch >= 2 && bob.pq_epoch >= 2)
  File.delete(pair.alice_path)?
  File.delete(pair.bob_path)?
  Ok(true)
end

test("mobile sessions upgrade to encrypted headers and the post-quantum ratchet") do
  case upgrade_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn lost(path :: String, peer_profile :: Bytes, index :: Int, count :: Int) -> Bool!String do
  if index >= count do
    Ok(true)
  else
    sent(path, peer_profile, text("lost", index))?
    lost(path, peer_profile, index + 1, count)
  end
end

## The answer's first envelope starts the new session; the rest are the
## messages sent again in it.

fn opened_all(path :: String, envelopes :: List<Bytes>, index :: Int) -> Int!String do
  if index >= List.length(envelopes) do
    Ok(index)
  else
    let envelope = request([path_bytes(path), List.get(envelopes, index)])?
    let opened = if index == 0 do
      receive_initial_export(envelope)?
    else
      receive_message_export(envelope)?
    end
    assert(index > 0 || Bytes.length(opened) == 0)
    opened_all(path, envelopes, index + 1)
  end
end

## The whole outbox, eight envelopes a page.

fn outbox_from(path :: String, offset :: Int, output :: List<Bytes>) -> List<Bytes>!String do
  let page = output_list(outbox_page_export(request([path_bytes(path), write_u32(offset)?])?)?)?
  if List.length(page) == 0 do
    Ok(output)
  else
    outbox_from(path, offset + List.length(page), List.concat(output, page))
  end
end

fn outbox(path :: String) -> List<Bytes>!String do
  outbox_from(path, 0, List.new())
end

## How many messages the conversation shows: the list's leading count.

fn history_count(path :: String, peer_profile :: Bytes) -> Int!String do
  let listed = load_history_export(request([path_bytes(path), peer_profile])?)?
  case Bytes.read_u32_be(listed, 4) do
    Err(_) -> Err("history count failed")
    Ok(value) -> case U64.to_int(value) do
      Err(_) -> Err("history count failed")
      Ok(count)
    end
  end
end

fn marker_proof(pair :: Pair) -> Bool!String do
  let key = platform_key()?
  let bob = decode_client_profile(pair.bob_profile)?
  let alice_side = session_view(pair.alice_path, pair.bob_profile)?
  let bob_side = session_view(pair.bob_path, pair.alice_profile)?
  let newest = history_newest_from(pair.alice_path,
    key,
    alice_side.conversation_id,
    bob.account_id,
    bob.device_id)?
  # What Bob sends again starts at a message he really sent; a time he never
  # sent at, 0 included, gets nothing, so no device can ask for older history.
  assert(List.length(history_sent_after(pair.bob_path,
    key,
    bob_side.conversation_id,
    newest,
    32)?) == 0)
  assert(List.length(history_sent_after(pair.bob_path,
    key,
    bob_side.conversation_id,
    U64.parse("1")?,
    32)?) == 0)
  assert(List.length(history_sent_after(pair.bob_path,
    key,
    bob_side.conversation_id,
    U64.parse("0")?,
    32)?) == 0)
  Ok(true)
end

fn healing_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let pair = conversation("session-healing")?
  assert(exchange(pair, 0, 2)?)
  assert(marker_proof(pair)?)
  Timer.sleep(5)
  # Seventy of Bob's messages never reach Alice: more than she can skip.
  assert(lost(pair.bob_path, pair.alice_profile, 0, 70)?)
  let too_far = sent(pair.bob_path, pair.alice_profile, text("too far", 0))?
  case receive_message_export(request([path_bytes(pair.alice_path), too_far])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "session_reset_requested")
  end
  # The request waits in Alice's outbox, sent in the direction that still works.
  let asked = outbox(pair.alice_path)?
  assert(List.length(asked) == 1)
  let reset_request = List.head(asked)
  assert(session_view(pair.alice_path, pair.bob_profile)?.reset_state == 1)
  assert(U64.compare(summary(pair.alice_path)?.session_reset_at, U64.parse("0")?) > 0)
  # One request a session: the next message too far ahead asks nothing more.
  let later = sent(pair.bob_path, pair.alice_profile, text("later", 0))?
  case receive_message_export(request([path_bytes(pair.alice_path), later])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "message_rejected")
  end
  assert(List.length(outbox(pair.alice_path)?) == 1)
  assert(acknowledge(pair.alice_path, reset_request)?)
  # Bob answers with a new session and sends again what Alice is missing: the
  # newest 32 of the 72 messages after the last one she has.
  assert(Bytes.length(receive_message_export(request([
    path_bytes(pair.bob_path),
    reset_request
  ])?)?) == 0)
  let answer = outbox(pair.bob_path)?
  assert(List.length(answer) == 33)
  assert(inner_version(pair.alice_path, List.head(answer))? == 0)
  assert(acknowledged_all(pair.bob_path, answer, 0)?)
  let before = history_count(pair.alice_path, pair.bob_profile)?
  assert(opened_all(pair.alice_path, answer, 0)? == 33)
  # Nothing of Alice's was lost, so she has nothing to send again.
  assert(List.length(outbox(pair.alice_path)?) == 0)
  assert(history_count(pair.alice_path, pair.bob_profile)? == before + 32)
  assert(session_view(pair.alice_path, pair.bob_profile)?.reset_state == 0)
  assert(U64.compare(summary(pair.bob_path)?.session_reset_at, U64.parse("0")?) > 0)
  assert(U64.compare(summary(pair.alice_path)?.session_reset_at, U64.parse("0")?) > 0)
  # Both sides go on in the new session.
  assert(exchange(pair, 10, 2)?)
  File.delete(pair.alice_path)?
  File.delete(pair.bob_path)?
  Ok(true)
end

test("a session that lost more than 64 messages is reset and what it lost is sent again") do
  case healing_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn delivered_all(path :: String, envelopes :: List<Bytes>, index :: Int) -> Int!String do
  if index >= List.length(envelopes) do
    Ok(index)
  else
    receive_message_export(request([path_bytes(path), List.get(envelopes, index)])?)?
    delivered_all(path, envelopes, index + 1)
  end
end

fn acknowledged_all(path :: String, envelopes :: List<Bytes>, index :: Int) -> Bool!String do
  if index >= List.length(envelopes) do
    Ok(true)
  else
    assert(acknowledge(path, List.get(envelopes, index))?)
    acknowledged_all(path, envelopes, index + 1)
  end
end

fn mutual_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let pair = conversation("session-healing-mutual")?
  assert(exchange(pair, 0, 2)?)
  Timer.sleep(5)
  # Each side loses 70 of the other's messages.
  assert(lost(pair.bob_path, pair.alice_profile, 0, 70)?)
  assert(lost(pair.alice_path, pair.bob_profile, 0, 70)?)
  let too_far = sent(pair.bob_path, pair.alice_profile, text("too far", 1))?
  case receive_message_export(request([path_bytes(pair.alice_path), too_far])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "session_reset_requested")
  end
  let reset_request = List.head(outbox(pair.alice_path)?)
  assert(acknowledge(pair.alice_path, reset_request)?)
  # Alice's request is itself 70 ahead for Bob. He reads it anyway, answers,
  # and asks for nothing himself.
  assert(Bytes.length(receive_message_export(request([
    path_bytes(pair.bob_path),
    reset_request
  ])?)?) == 0)
  let answer = outbox(pair.bob_path)?
  assert(List.length(answer) == 33)
  assert(acknowledged_all(pair.bob_path, answer, 0)?)
  let alice_before = history_count(pair.alice_path, pair.bob_profile)?
  let bob_before = history_count(pair.bob_path, pair.alice_profile)?
  # The answer tells Alice what Bob last has from her; she sends the rest again.
  assert(opened_all(pair.alice_path, answer, 0)? == 33)
  let again = outbox(pair.alice_path)?
  assert(List.length(again) == 32)
  assert(delivered_all(pair.bob_path, again, 0)? == 32)
  assert(acknowledged_all(pair.alice_path, again, 0)?)
  assert(history_count(pair.alice_path, pair.bob_profile)? == alice_before + 32)
  assert(history_count(pair.bob_path, pair.alice_profile)? == bob_before + 32)
  assert(exchange(pair, 20, 2)?)
  File.delete(pair.alice_path)?
  File.delete(pair.bob_path)?
  Ok(true)
end

test("when both sides lost more than 64 of each other's messages, both are healed") do
  case mutual_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn key(seed :: Int) -> Bytes!String do
  case Bytes.repeat(seed, 32) do
    Err(_) -> Err("key failed")
    Ok(value)
  end
end

fn floor_config() -> Bool!String do
  let delivery = case Crypto.x25519_generate() do
    Err(_) -> Err("delivery key failed")
    Ok(value) -> Ok(value.public_key.bytes)
  end?
  let frame = security_config_encode(SecurityConfig {
    version: 2,
    service_public_key: key(1)?,
    delivery_public_key: delivery,
    abuse_difficulty: 8,
    threshold: 1,
    witnesses: [SecurityWitness { witness_id: "witness-a", public_key: key(2)?, label: "Morse" }],
    judge_program_id: "",
    log_account: "",
    rpc_urls: List.new(),
    relays: List.new(),
    issuer_origin: "",
    c2sp_origin: "",
    minimum_suite: 2,
    ohttp_key_config: Bytes.empty(),
    ohttp_relay: "",
    set_id: Bytes.empty()
  })?
  Ok(Test.set_push_token(Bytes.from_utf8("messenger/config/v1"), frame))
end

fn floor_proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let alice_path = database_path("suite-floor-alice")?
  let bob_path = database_path("suite-floor-bob")?
  create_account_export(request([path_bytes(alice_path), Bytes.from_utf8("alice")])?)?
  create_account_export(request([path_bytes(bob_path), Bytes.from_utf8("bob")])?)?
  let fixture = output_list(install_classical_session_for_test(alice_path, bob_path)?)?
  let classical_bob = List.get(fixture, 2)
  assert(floor_config()?)
  # A new session to a device still on suite 1 is refused, with the error the
  # app turns into "This contact's app needs an update".
  case start_conversation_export(request([
    path_bytes(alice_path),
    classical_bob,
    Bytes.from_utf8("new")
  ])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "peer_suite_below_floor")
  end
  File.delete(alice_path)?
  File.delete(bob_path)?
  Ok(true)
end

test("with a suite floor of 2 a new classical session is refused") do
  case floor_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
