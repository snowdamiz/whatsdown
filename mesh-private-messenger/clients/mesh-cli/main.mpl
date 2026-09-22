from Identity.Device import AccountKeys, DeviceKeys, VerificationPolicy, generate_account, generate_device, issue_device_credential
from Prekeys.Bundle import OneTimePrekeySecrets, PostQuantumPrekeySecrets, SignedPrekeySecrets, build_prekey_bundle, generate_one_time_prekey, generate_post_quantum_prekey, generate_signed_prekey, normalize_prekey_bundle
from Prekeys.Pool import PrekeyClaimRequest, encode_prekey_claim
from Privacy.Edge import RequestStamp, encode_stamped_request, mint_request_stamp
from Protocol.DirectoryWire import decode_device_set, encode_directory_entry
from Protocol.EnvelopeWire import (
  decode_inner_envelope,
  decode_outer_envelope,
  encode_inner_envelope,
  encode_outer_envelope
)
from Protocol.HandshakeWire import encode_initial_message
from Protocol.IdentityWire import decode_account_identity, decode_device_credential, encode_account_identity
from Protocol.MailboxWire import decode_delivery_batch, sign_mailbox_ack, sign_mailbox_fetch
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import (
  AccountIdentity,
  DeliveredEnvelope,
  DeviceCredential,
  DeviceSet,
  DirectoryEntry,
  InnerEnvelope,
  OuterEnvelope,
  PrekeyBundle
)
from Session.Handshake import RatchetState, initiate, receive_initial
from Session.Ratchet import DecryptOutcome, RatchetError, RatchetMessage, decode_ratchet_message, decrypt, encode_ratchet_message, encrypt_sealed, ratchet_transport_matches
from Transparency.Client import checkpoint_fresh_at, verify_evidence
from Transparency.Merkle import TransparencyCheckpoint, WitnessKey
from Transparency.Wire import TransparencyEvidence, TransparencyLookup, decode_transparency_evidence, encode_transparency_lookup
from Transport.Packet import TransportPacket, decode_packet, encode_packet, session_aad
from Transport.Recipient import open_recipient_packet, seal_recipient_packet

fn wide(value :: String) -> U64 ! String do
  case U64.parse(value) do
    Err(_) -> Err("invalid wide integer")
    Ok(parsed) -> Ok(parsed)
  end
end

fn random(length :: Int) -> Bytes ! String do
  case Crypto.random_bytes(length) do
    Err(_) -> Err("random generation failed")
    Ok(value) -> Ok(value)
  end
end

fn account(created_at :: U64) -> Result <(AccountKeys, AccountIdentity), String > do
  case generate_account(created_at, wide("1") ?) do
    Err(_) -> Err("account generation failed")
    Ok(value) -> Ok(value)
  end
end

fn device() -> DeviceKeys ! String do
  case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(value) -> Ok(value)
  end
end

fn credential(account_keys :: borrow AccountKeys,
device_keys :: borrow DeviceKeys,
created_at :: U64,
expires_at :: U64) -> DeviceCredential ! String do
  case issue_device_credential(account_keys,
  device_keys,
  wide("1") ?,
  created_at,
  expires_at,
  wide("1") ?) do
    Err(_) -> Err("credential generation failed")
    Ok(value) -> Ok(value)
  end
end

fn signed_prekey(device_keys :: borrow DeviceKeys, value :: DeviceCredential, expires_at :: U64) -> SignedPrekeySecrets ! String do
  case generate_signed_prekey(device_keys, value, wide("1") ?, expires_at) do
    Err(_) -> Err("signed prekey generation failed")
    Ok(output) -> Ok(output)
  end
end

fn one_time_prekey() -> OneTimePrekeySecrets ! String do
  case generate_one_time_prekey(wide("2") ?) do
    Err(_) -> Err("one-time prekey generation failed")
    Ok(value) -> Ok(value)
  end
end

fn post_quantum_prekey() -> PostQuantumPrekeySecrets ! String do
  case generate_post_quantum_prekey() do
    Err(_) -> Err("post-quantum prekey generation failed")
    Ok(value) -> Ok(value)
  end
end

fn bundle(value :: DeviceCredential,
signed :: borrow SignedPrekeySecrets,
one_time :: borrow OneTimePrekeySecrets) -> PrekeyBundle ! String do
  case build_prekey_bundle(value, signed, one_time) do
    Err(_) -> Err("prekey bundle generation failed")
    Ok(output) -> Ok(output)
  end
end

fn account_wire(value :: AccountIdentity) -> Bytes ! String do
  case encode_account_identity(value) do
    Err(_) -> Err("account encoding failed")
    Ok(output) -> Ok(output)
  end
end

fn directory_wire(value :: DirectoryEntry) -> Bytes ! String do
  case encode_directory_entry(value) do
    Err(_) -> Err("directory encoding failed")
    Ok(output) -> Ok(output)
  end
end

fn inner_wire(value :: InnerEnvelope) -> Bytes ! String do
  case encode_inner_envelope(value) do
    Err(_) -> Err("inner envelope encoding failed")
    Ok(output) -> Ok(output)
  end
end

fn initial_wire(value :: InitialMessage) -> Bytes ! String do
  case encode_initial_message(value) do
    Err(_) -> Err("initial message encoding failed")
    Ok(output) -> Ok(output)
  end
end

fn ratchet_wire(value :: RatchetMessage) -> Bytes ! String do
  case encode_ratchet_message(value) do
    Err(_) -> Err("ratchet message encoding failed")
    Ok(output) -> Ok(output)
  end
end

fn outer_wire(value :: OuterEnvelope) -> Bytes ! String do
  case encode_outer_envelope(value) do
    Err(_) -> Err("outer envelope encoding failed")
    Ok(output) -> Ok(output)
  end
end

fn clock() -> U64 ! String do
  wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn pinned_key(name :: String) -> Bytes ! String do
  let value = Bytes.from_hex(Env.get(name, "")) ?
  if Bytes.length(value) == 32 do
    Ok(value)
  else
    Err("#{name} must be a pinned 32-byte public key")
  end
end

fn base_url() -> String do
  Env.get("MESSENGER_BASE_URL", "http://127.0.0.1:18086")
end

# Register, resolve and prekey claim are anonymous, so the directory wants proof
# of work minted for that endpoint. This client has no signed native
# configuration, so it reads the difficulty the deployment publishes.

fn stamped(label :: String, payload :: Bytes) -> Bytes ! String do
  let expires_at = U64.add(clock() ?, U64.parse("240000") ?) ?
  encode_stamped_request(mint_request_stamp(label,
  payload,
  expires_at,
  Env.get_int("MESSENGER_ABUSE_DIFFICULTY", 16)) ?,
  payload)
end

fn post(path :: String, body :: Bytes) -> HttpResponse ! String do
  Http.build(:post, base_url() <> path)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(600000)
    |> Http.send()
end

fn put(path :: String, body :: Bytes) -> HttpResponse ! String do
  Http.build(:put, base_url() <> path)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(600000)
    |> Http.send()
end

fn register_entry(entry :: DirectoryEntry) -> Int ! String do
  let response = put("/v1/devices/register",
  stamped("mesh-msg/v1/work/register", directory_wire(entry) ?) ?) ?
  if response.status == 201 do
    Ok(response.status)
  else
    Err("device registration returned #{response.status}")
  end
end

# The directory is untrusted: an entry is used only with a fresh checkpoint
# signed by the pinned service key, an inclusion proof, and both pinned witnesses.

fn evidence_verified(evidence :: TransparencyEvidence) -> Bool ! String do
  let witnesses = [WitnessKey {
    witness_id : "witness-a",
    public_key : pinned_key("MESSENGER_WITNESS_A_PUBLIC_KEY_HEX") ?
  }, WitnessKey {
    witness_id : "witness-b",
    public_key : pinned_key("MESSENGER_WITNESS_B_PUBLIC_KEY_HEX") ?
  }]
  let service_key_bytes = pinned_key("MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX") ?
  let service_key = SigningPublicKey { bytes : service_key_bytes }
  if !checkpoint_fresh_at(evidence.checkpoint.timestamp, clock() ?) do
    Ok(false)
  else
    verify_evidence(evidence, service_key, witnesses, 2, Bytes.empty())
  end
end

fn verified_entry(evidence :: TransparencyEvidence, username :: String) -> DirectoryEntry ! String do
  let device_set = case decode_device_set(evidence.entry_bytes) do
    Err(_) -> Err("invalid transparent device set")
    Ok(value) -> Ok(value)
  end ?
  if device_set.username != username || List.length(device_set.devices) != 1 do
    Err("unexpected transparent device set")
  else
    Ok(List.head(device_set.devices))
  end
end

fn retry_resolution(username :: String, attempt :: Int, reason :: String) -> DirectoryEntry ! String do
  if attempt < 240 do
    Timer.sleep(250)
    resolve_entry(username, attempt + 1)
  else
    Err(reason)
  end
end

fn resolve_entry(username :: String, attempt :: Int) -> DirectoryEntry ! String do
  let lookup = encode_transparency_lookup(TransparencyLookup {
    username : username,
    previous_tree_size : 0
  }) ?
  let response = post("/v1/devices/resolve", stamped("mesh-msg/v1/work/resolve", lookup) ?) ?
  if response.status == 404 do
    retry_resolution(username, attempt, "device resolution returned 404")
  else if response.status != 200 do
    Err("device resolution returned #{response.status}")
  else
    let evidence = decode_transparency_evidence(response.body_bytes) ?
    if evidence_verified(evidence) ? do
      verified_entry(evidence, username)
    else
      # Witnesses countersign asynchronously; unverified evidence is never used.
      retry_resolution(username, attempt, "transparency evidence was not verified")
    end
  end
end

# The transparent base bundle carries no one-time prekey. A claimed bundle is
# used only if clearing its one-time prekey reproduces the verified base exactly.

fn claim_prekey_bundle(base_bundle :: Bytes) -> PrekeyBundle ! String do
  let base = case decode_prekey_bundle(base_bundle) do
    Err(_) -> Err("invalid base prekey bundle")
    Ok(value) -> Ok(value)
  end ?
  let owner = case decode_device_credential(base.device_credential) do
    Err(_) -> Err("invalid base device credential")
    Ok(value) -> Ok(value)
  end ?
  let claim = encode_prekey_claim(PrekeyClaimRequest {
    account_id : owner.account_id,
    device_id : owner.device_id,
    base_bundle_hash : Crypto.sha256(base_bundle),
    reservation_id : random(16) ?
  }) ?
  let response = post("/v1/prekeys/bundle", stamped("mesh-msg/v1/work/prekey-claim", claim) ?) ?
  if response.status != 200 do
    Err("prekey claim returned #{response.status}")
  else
    let claimed = case decode_prekey_bundle(response.body_bytes) do
      Err(_) -> Err("invalid claimed prekey bundle")
      Ok(value) -> Ok(value)
    end ?
    let normalized = case normalize_prekey_bundle(claimed) do
      Err(_) -> Err("invalid claimed prekey bundle")
      Ok(value) -> Ok(value)
    end ?
    let normalized_bytes = case encode_prekey_bundle(normalized) do
      Err(_) -> Err("invalid claimed prekey bundle")
      Ok(value) -> Ok(value)
    end ?
    if Bytes.secure_equals(normalized_bytes, base_bundle) do
      Ok(claimed)
    else
      Err("claimed prekey bundle does not match the verified base")
    end
  end
end

fn submit_envelope(encoded :: Bytes, expected :: Int) -> Int ! String do
  let response = post("/v1/envelopes/batch", encoded) ?
  if response.status == expected do
    Ok(response.status)
  else
    Err("envelope submission returned #{response.status}, expected #{expected}")
  end
end

fn fetch_envelopes(device_keys :: borrow DeviceKeys, token :: Bytes, attempt :: Int) -> List < DeliveredEnvelope > ! String do
  let body = case sign_mailbox_fetch(device_keys.signing_private_key,
  Crypto.sha256(token),
  wide("0") ?,
  clock() ?) do
    Err(_) -> Err("mailbox fetch signing failed")
    Ok(value) -> Ok(value)
  end ?
  case post("/v1/mailbox/fetch", body) do
    Err(_) -> if attempt < 2 do
      Timer.sleep(250)
      fetch_envelopes(device_keys, token, attempt + 1)
    else
      Err("mailbox fetch failed")
    end
    Ok(response) -> if response.status != 200 do
      Err("mailbox fetch returned #{response.status}")
    else
      case decode_delivery_batch(response.body_bytes) do
        Err(_) -> Err("invalid mailbox response")
        Ok(deliveries) -> Ok(deliveries)
      end
    end
  end
end

fn acknowledge(device_keys :: borrow DeviceKeys, token :: Bytes, ids :: List < Bytes >) -> Int ! String do
  let body = case sign_mailbox_ack(device_keys.signing_private_key,
  Crypto.sha256(token),
  clock() ?,
  ids) do
    Err(_) -> Err("mailbox acknowledgement signing failed")
    Ok(value) -> Ok(value)
  end ?
  let response = post("/v1/mailbox/ack", body) ?
  if response.status == 200 do
    Ok(response.status)
  else
    Err("mailbox acknowledgement returned #{response.status}")
  end
end

fn policy(now :: U64) -> VerificationPolicy ! String do
  Ok(VerificationPolicy {
    current_time : now,
    minimum_directory_sequence : wide("1") ?
  })
end

fn inner(account_id :: Bytes,
sender_device_id :: Bytes,
recipient_device_id :: Bytes,
conversation_id :: Bytes,
message_id :: Bytes,
body :: String) -> InnerEnvelope ! String do
  Ok(InnerEnvelope {
    version : 1,
    sender_account_id : account_id,
    sender_device_id : sender_device_id,
    recipient_device_id : recipient_device_id,
    conversation_id : conversation_id,
    client_message_id : message_id,
    client_timestamp : wide("1800000000000") ?,
    message_type : 1,
    body : Bytes.from_utf8(body),
    reply_reference : Bytes.empty(),
    attachment_manifest : Bytes.empty(),
    receipt_policy : 0,
    disappearing_seconds : 0,
    extensions : List.new()
  })
end

fn encrypt_message(state :: consume RatchetState, value :: InnerEnvelope, aad :: Bytes) -> Result <(RatchetState, RatchetMessage), String > do
  case encrypt_sealed(state, inner_wire(value) ?, aad) do
    Err(_) -> Err("ratchet encryption failed")
    Ok(output) -> Ok(output)
  end
end

# Every packet is sealed to the recipient device: delivery sees outer suite 4,
# a size bucket, and opaque bytes, never the session or the packet kind.

fn outbound(token :: Bytes, packet :: Bytes, recipient_dh_public_key :: Bytes) -> Bytes ! String do
  let sealed = seal_recipient_packet(packet, X25519PublicKey { bytes : recipient_dh_public_key }) ?
  outer_wire(OuterEnvelope {
    version : 1,
    envelope_id : random(16) ?,
    mailbox_token : token,
    suite : 4,
    expiration : U64.add(clock() ?, wide("86400000") ?) ?,
    padding_bucket : Bytes.length(sealed),
    ciphertext : sealed
  })
end

fn run_device_a() -> Int ! String do
  let created_at = wide("1700000000000") ?
  let now = wide("1800000000000") ?
  let expires_at = wide("1900000000000") ?
  let directory = resolve_entry("device-b", 0) ?
  let bob_account = case decode_account_identity(directory.account_identity) do
    Err(_) -> Err("invalid responder account")
    Ok(value) -> Ok(value)
  end ?
  let bob_bundle = claim_prekey_bundle(directory.prekey_bundle) ?
  let bob_credential = case decode_device_credential(bob_bundle.device_credential) do
    Err(_) -> Err("invalid responder credential")
    Ok(value) -> Ok(value)
  end ?
  let (alice_account_keys, alice_account) = account(created_at) ?
  let alice = device() ?
  let alice_credential = credential(alice_account_keys, alice, created_at, expires_at) ?
  let conversation_id = random(16) ?
  let initial_inner = inner(alice_account.account_id,
  alice_credential.device_id,
  bob_credential.device_id,
  conversation_id,
  random(16) ?,
  "initial") ?
  let (alice_session, initial) = case initiate(alice,
  alice_credential,
  bob_account,
  bob_bundle,
  policy(now) ?,
  1,
  inner_wire(initial_inner) ?) do
    Err(_) -> Err("initial handshake failed")
    Ok(value) -> Ok(value)
  end ?
  let aad = session_aad(alice_session.session_id) ?
  let initial_outer = outbound(directory.mailbox_token,
  encode_packet(InitialPacket(account_wire(alice_account) ?, initial_wire(initial) ?)) ?,
  bob_credential.dh_public_key) ?
  let _ = submit_envelope(initial_outer, 202) ?
  let _ = submit_envelope(initial_outer, 200) ?
  let first_id = random(16) ?
  let second_id = random(16) ?
  let third_id = random(16) ?
  let (alice_session, first) = encrypt_message(alice_session,
  inner(alice_account.account_id,
  alice_credential.device_id,
  bob_credential.device_id,
  conversation_id,
  first_id,
  "first") ?,
  aad) ?
  let (alice_session, second) = encrypt_message(alice_session,
  inner(alice_account.account_id,
  alice_credential.device_id,
  bob_credential.device_id,
  conversation_id,
  second_id,
  "second") ?,
  aad) ?
  let (alice_session, third) = encrypt_message(alice_session,
  inner(alice_account.account_id,
  alice_credential.device_id,
  bob_credential.device_id,
  conversation_id,
  third_id,
  "third") ?,
  aad) ?
  let _alice_session = alice_session
  let third_outer = outbound(directory.mailbox_token,
  encode_packet(RatchetPacket(ratchet_wire(third) ?)) ?,
  bob_credential.dh_public_key) ?
  let first_outer = outbound(directory.mailbox_token,
  encode_packet(RatchetPacket(ratchet_wire(first) ?)) ?,
  bob_credential.dh_public_key) ?
  let duplicate_outer = outbound(directory.mailbox_token,
  encode_packet(RatchetPacket(ratchet_wire(second) ?)) ?,
  bob_credential.dh_public_key) ?
  let second_outer = outbound(directory.mailbox_token,
  encode_packet(RatchetPacket(ratchet_wire(second) ?)) ?,
  bob_credential.dh_public_key) ?
  let _ = submit_envelope(third_outer, 202) ?
  let _ = submit_envelope(first_outer, 202) ?
  let _ = submit_envelope(second_outer, 202) ?
  let _ = submit_envelope(duplicate_outer, 202) ?
  println("device-a:submitted")
  Ok(0)
end

fn display(value :: Bytes) do
  case decode_inner_envelope(value) do
    Err(_) -> println("device-b:invalid-inner")
    Ok(inner_value) -> case Bytes.to_utf8(inner_value.body) do
      Err(_) -> println("device-b:invalid-body")
      Ok(body) -> println("display:#{body}")
    end
  end
end

fn opened_packet(outer :: OuterEnvelope, recipient :: borrow DeviceKeys) -> TransportPacket ! String do
  decode_packet(open_recipient_packet(outer.ciphertext, recipient.identity_private_key) ?)
end

fn process_deliveries(state :: consume RatchetState,
recipient :: borrow DeviceKeys,
deliveries :: List < DeliveredEnvelope >,
index :: Int,
aad :: Bytes) -> RatchetState do
  if index >= List.length(deliveries) do
    state
  else
    let delivered = List.get(deliveries, index)
    case decode_outer_envelope(delivered.envelope) do
      Err(_) -> do
        println("device-b:invalid-outer")
        process_deliveries(state, recipient, deliveries, index + 1, aad)
      end
      Ok(outer) -> case opened_packet(outer, recipient) do
        Err(_) -> do
          println("device-b:invalid-packet")
          process_deliveries(state, recipient, deliveries, index + 1, aad)
        end
        Ok(InitialPacket(_, _)) -> do
          println("device-b:unexpected-initial")
          process_deliveries(state, recipient, deliveries, index + 1, aad)
        end
        Ok(RatchetPacket(message)) -> case decode_ratchet_message(message) do
          Err(_) -> do
            println("device-b:invalid-ratchet")
            process_deliveries(state, recipient, deliveries, index + 1, aad)
          end
          Ok(decoded) -> if !ratchet_transport_matches(decoded, true) do
            println("device-b:invalid-ratchet")
            process_deliveries(state, recipient, deliveries, index + 1, aad)
          else
            received_ratchet(state, recipient, deliveries, index, aad, decoded)
          end
        end
      end
    end
  end
end

fn received_ratchet(state :: consume RatchetState,
recipient :: borrow DeviceKeys,
deliveries :: List < DeliveredEnvelope >,
index :: Int,
aad :: Bytes,
decoded :: RatchetMessage) -> RatchetState do
  case decrypt(state, decoded, aad) do
    Rejected(next, Replay) -> do
      println("dedup:suppressed")
      process_deliveries(next, recipient, deliveries, index + 1, aad)
    end
    Rejected(next, _) -> do
      println("device-b:ratchet-rejected")
      process_deliveries(next, recipient, deliveries, index + 1, aad)
    end
    Opened(next, plaintext) -> do
      display(plaintext)
      process_deliveries(next, recipient, deliveries, index + 1, aad)
    end
  end
end

fn envelope_ids(deliveries :: List < DeliveredEnvelope >, index :: Int, ids :: List < Bytes >) -> List < Bytes > do
  if index >= List.length(deliveries) do
    ids
  else
    case decode_outer_envelope(List.get(deliveries, index).envelope) do
      Err(_) -> envelope_ids(deliveries, index + 1, ids)
      Ok(outer) -> envelope_ids(deliveries, index + 1, List.append(ids, outer.envelope_id))
    end
  end
end

fn run_device_b() -> Int ! String do
  let created_at = wide("1700000000000") ?
  let now = wide("1800000000000") ?
  let expires_at = wide("1900000000000") ?
  let (bob_account_keys, bob_account) = account(created_at) ?
  let bob = device() ?
  let bob_credential = credential(bob_account_keys, bob, created_at, expires_at) ?
  let signed = signed_prekey(bob, bob_credential, expires_at) ?
  let one_time = one_time_prekey() ?
  let post_quantum = post_quantum_prekey() ?
  let published = bundle(bob_credential, signed, one_time) ?
  let token = random(32) ?
  let _ = register_entry(DirectoryEntry {
    version : 1,
    username : "device-b",
    account_identity : account_wire(bob_account) ?,
    prekey_bundle : case encode_prekey_bundle(published) do
      Err(_) -> Err("prekey bundle encoding failed")
      Ok(value) -> Ok(value)
    end ?,
    mailbox_token : token
  }) ?
  println("device-b:registered")
  let delay = Env.get_int("MESSENGER_FETCH_DELAY_MS", 8000)
  if delay < 0 || delay > 60000 do
    Err("MESSENGER_FETCH_DELAY_MS must be between 0 and 60000")
  else
    Timer.sleep(delay)
    let deliveries = fetch_envelopes(bob, token, 0) ?
    if List.length(deliveries) == 0 do
      Err("mailbox was empty")
    else
      let first_delivery = List.head(deliveries)
      let first_outer = case decode_outer_envelope(first_delivery.envelope) do
        Err(_) -> Err("invalid initial outer envelope")
        Ok(value) -> Ok(value)
      end ?
      let (alice_account, initial) = case opened_packet(first_outer, bob) do
        Err(_) -> Err("invalid initial transport packet")
        Ok(RatchetPacket(_)) -> Err("expected initial transport packet")
        Ok(InitialPacket(account_bytes, initial_bytes)) -> case decode_account_identity(account_bytes) do
          Err(_) -> Err("invalid initiator account")
          Ok(account_value) -> Ok((account_value, initial_bytes))
        end
      end ?
      let (bob_session, initial_plaintext) = case receive_initial(bob,
      bob_account,
      published,
      signed,
      one_time,
      post_quantum,
      alice_account,
      policy(now) ?,
      policy(now) ?,
      1,
      initial) do
        Err(_) -> Err("initial receive failed")
        Ok(value) -> Ok(value)
      end ?
      display(initial_plaintext)
      let aad = session_aad(bob_session.session_id) ?
      let _bob_session = process_deliveries(bob_session, bob, deliveries, 1, aad)
      let ids = envelope_ids(deliveries, 0, List.new())
      let _ = acknowledge(bob, token, ids) ?
      println("device-b:acked=#{List.length(ids)}")
      Ok(0)
    end
  end
end

# Live-service tests in other languages need a registered device and a fetch
# frame signed by it; both come from the Mesh protocol code rather than a
# second implementation. The frame authorizes fetch and stream for five minutes.

fn run_stream_fixture() -> Int ! String do
  let created_at = wide("1700000000000") ?
  let expires_at = wide("1900000000000") ?
  let (account_keys, identity) = account(created_at) ?
  let keys = device() ?
  let issued = credential(account_keys, keys, created_at, expires_at) ?
  let published = bundle(issued, signed_prekey(keys, issued, expires_at) ?, one_time_prekey() ?) ?
  let token = random(32) ?
  let _ = register_entry(DirectoryEntry {
    version : 1,
    username : "stream_" <> Bytes.to_hex(random(8) ?),
    account_identity : account_wire(identity) ?,
    prekey_bundle : case encode_prekey_bundle(published) do
      Err(_) -> Err("prekey bundle encoding failed")
      Ok(value) -> Ok(value)
    end ?,
    mailbox_token : token
  }) ?
  let fetch = case sign_mailbox_fetch(keys.signing_private_key,
  Crypto.sha256(token),
  wide("0") ?,
  clock() ?) do
    Err(_) -> Err("mailbox fetch signing failed")
    Ok(value) -> Ok(value)
  end ?
  println("stream-fixture:token=" <> Bytes.to_hex(token))
  println("stream-fixture:fetch=" <> Bytes.to_hex(fetch))
  Ok(0)
end

fn report(role :: String, result :: Result < Int, String >) do
  case result do
    Err(error) -> println("#{role}:error:#{error}")
    Ok(_) -> println("#{role}:ok")
  end
end

fn main() do
  let role = Env.get("MESSENGER_ROLE", "")
  if role == "device-a" do
    report(role, run_device_a())
  else
    if role == "device-b" do
      report(role, run_device_b())
    else if role == "stream-fixture" do
      report(role, run_stream_fixture())
    else
      println("MESSENGER_ROLE must be device-a, device-b, or stream-fixture")
    end
  end
end
