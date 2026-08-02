from Identity.Device import AccountKeys, DeviceKeys, VerificationPolicy, generate_account, generate_device, issue_device_credential
from Prekeys.Bundle import OneTimePrekeySecrets, SignedPrekeySecrets, build_prekey_bundle, generate_one_time_prekey, generate_signed_prekey
from Protocol.V1 import AccountIdentity, DeliveredEnvelope, DeviceCredential, DirectoryEntry, InnerEnvelope, MailboxAck, MailboxFetch, OuterEnvelope, PrekeyBundle, decode_account_identity, decode_delivery_batch, decode_device_credential, decode_directory_entry, decode_inner_envelope, decode_outer_envelope, decode_prekey_bundle, encode_account_identity, encode_directory_entry, encode_directory_lookup, encode_initial_message, encode_inner_envelope, encode_mailbox_ack, encode_mailbox_fetch, encode_outer_envelope, encode_prekey_bundle
from Session.Handshake import RatchetState, initiate, receive_initial
from Session.Ratchet import DecryptOutcome, RatchetError, RatchetMessage, decode_ratchet_message, decrypt, encode_ratchet_message, encrypt
from Transport.Packet import TransportPacket, decode_packet, encode_packet

fn wide(value :: String) -> U64 ! String do
  case U64.parse(value) do
    Err( _) -> Err("invalid wide integer")
    Ok( parsed) -> Ok(parsed)
  end
end

fn random(length :: Int) -> Bytes ! String do
  case Crypto.random_bytes(length) do
    Err( _) -> Err("random generation failed")
    Ok( value) -> Ok(value)
  end
end

fn append(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err( _) -> Err("byte concatenation failed")
    Ok( value) -> Ok(value)
  end
end

fn account(created_at :: U64) -> Result <( AccountKeys, AccountIdentity), String > do
  case generate_account(created_at, wide("1") ?) do
    Err( _) -> Err("account generation failed")
    Ok( value) -> Ok(value)
  end
end

fn device() -> DeviceKeys ! String do
  case generate_device() do
    Err( _) -> Err("device generation failed")
    Ok( value) -> Ok(value)
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
    Err( _) -> Err("credential generation failed")
    Ok( value) -> Ok(value)
  end
end

fn signed_prekey(device_keys :: borrow DeviceKeys, value :: DeviceCredential, expires_at :: U64) -> SignedPrekeySecrets ! String do
  case generate_signed_prekey(device_keys, value, wide("1") ?, expires_at) do
    Err( _) -> Err("signed prekey generation failed")
    Ok( output) -> Ok(output)
  end
end

fn one_time_prekey() -> OneTimePrekeySecrets ! String do
  case generate_one_time_prekey(wide("2") ?) do
    Err( _) -> Err("one-time prekey generation failed")
    Ok( value) -> Ok(value)
  end
end

fn bundle(value :: DeviceCredential,
signed :: borrow SignedPrekeySecrets,
one_time :: borrow OneTimePrekeySecrets) -> PrekeyBundle ! String do
  case build_prekey_bundle(value, signed, one_time) do
    Err( _) -> Err("prekey bundle generation failed")
    Ok( output) -> Ok(output)
  end
end

fn account_wire(value :: AccountIdentity) -> Bytes ! String do
  case encode_account_identity(value) do
    Err( _) -> Err("account encoding failed")
    Ok( output) -> Ok(output)
  end
end

fn directory_wire(value :: DirectoryEntry) -> Bytes ! String do
  case encode_directory_entry(value) do
    Err( _) -> Err("directory encoding failed")
    Ok( output) -> Ok(output)
  end
end

fn inner_wire(value :: InnerEnvelope) -> Bytes ! String do
  case encode_inner_envelope(value) do
    Err( _) -> Err("inner envelope encoding failed")
    Ok( output) -> Ok(output)
  end
end

fn initial_wire(value :: InitialMessage) -> Bytes ! String do
  case encode_initial_message(value) do
    Err( _) -> Err("initial message encoding failed")
    Ok( output) -> Ok(output)
  end
end

fn ratchet_wire(value :: RatchetMessage) -> Bytes ! String do
  case encode_ratchet_message(value) do
    Err( _) -> Err("ratchet message encoding failed")
    Ok( output) -> Ok(output)
  end
end

fn outer_wire(value :: OuterEnvelope) -> Bytes ! String do
  case encode_outer_envelope(value) do
    Err( _) -> Err("outer envelope encoding failed")
    Ok( output) -> Ok(output)
  end
end

fn lookup_wire(username :: String) -> Bytes ! String do
  case encode_directory_lookup(username) do
    Err( _) -> Err("directory lookup encoding failed")
    Ok( output) -> Ok(output)
  end
end

fn fetch_wire(value :: MailboxFetch) -> Bytes ! String do
  case encode_mailbox_fetch(value) do
    Err( _) -> Err("mailbox fetch encoding failed")
    Ok( output) -> Ok(output)
  end
end

fn ack_wire(value :: MailboxAck) -> Bytes ! String do
  case encode_mailbox_ack(value) do
    Err( _) -> Err("mailbox ack encoding failed")
    Ok( output) -> Ok(output)
  end
end

fn base_url() -> String do
  Env.get("MESSENGER_BASE_URL", "http://127.0.0.1:18086")
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
  let response = put("/v1/directory/register", directory_wire(entry) ?) ?
  if response.status == 201 do
    Ok(response.status)
  else
    Err("directory registration returned #{response.status}")
  end
end

fn resolve_entry(attempt :: Int) -> DirectoryEntry ! String do
  let response = post("/v1/directory/resolve", lookup_wire("device-b") ?) ?
  if response.status == 200 do
    case decode_directory_entry(response.body_bytes) do
      Err( _) -> Err("invalid directory response")
      Ok( entry) -> Ok(entry)
    end
  else
    if response.status == 404 && attempt < 20 do
      Timer.sleep(250)
      resolve_entry(attempt + 1)
    else
      Err("directory resolution returned #{response.status}")
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

fn fetch_envelopes(token :: Bytes, attempt :: Int) -> List < DeliveredEnvelope > ! String do
  let body = fetch_wire(MailboxFetch {
    version : 1,
    mailbox_token : token,
    after_sequence : wide("0") ?
  }) ?
  case post("/v1/mailbox/fetch", body) do
    Err( _) -> if attempt < 2 do
      Timer.sleep(250)
      fetch_envelopes(token, attempt + 1)
    else
      Err("mailbox fetch failed")
    end
    Ok( response) -> if response.status != 200 do
      Err("mailbox fetch returned #{response.status}")
    else
      case decode_delivery_batch(response.body_bytes) do
        Err( _) -> Err("invalid mailbox response")
        Ok( deliveries) -> Ok(deliveries)
      end
    end
  end
end

fn acknowledge(token :: Bytes, ids :: List < Bytes >) -> Int ! String do
  let response = post("/v1/mailbox/ack",
  ack_wire(MailboxAck {
    version : 1,
    mailbox_token : token,
    envelope_ids : ids
  }) ?) ?
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

fn associated_data(token :: Bytes) -> Bytes ! String do
  Ok(Crypto.sha256(append(Bytes.from_utf8("mesh-msg/m8/mailbox-aad"), token) ?))
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

fn encrypt_message(state :: consume RatchetState, value :: InnerEnvelope, aad :: Bytes) -> Result <( RatchetState, RatchetMessage), String > do
  case encrypt(state, inner_wire(value) ?, aad) do
    Err( _) -> Err("ratchet encryption failed")
    Ok( output) -> Ok(output)
  end
end

fn packet_wire(value :: TransportPacket) -> Bytes ! String do
  encode_packet(value)
end

fn outbound(token :: Bytes, packet :: TransportPacket) -> Bytes ! String do
  let ciphertext = packet_wire(packet) ?
  outer_wire(OuterEnvelope {
    version : 1,
    envelope_id : random(16) ?,
    mailbox_token : token,
    suite : 1,
    expiration : wide("1900000000000") ?,
    padding_bucket : 4096,
    ciphertext : ciphertext
  })
end

fn run_device_a() -> Int ! String do
  let created_at = wide("1700000000000") ?
  let now = wide("1800000000000") ?
  let expires_at = wide("1900000000000") ?
  let directory = resolve_entry(0) ?
  let bob_account = case decode_account_identity(directory.account_identity) do
    Err( _) -> Err("invalid responder account")
    Ok( value) -> Ok(value)
  end ?
  let bob_bundle = case decode_prekey_bundle(directory.prekey_bundle) do
    Err( _) -> Err("invalid responder prekey bundle")
    Ok( value) -> Ok(value)
  end ?
  let bob_credential = case decode_device_credential(bob_bundle.device_credential) do
    Err( _) -> Err("invalid responder credential")
    Ok( value) -> Ok(value)
  end ?
  let ( alice_account_keys, alice_account) = account(created_at) ?
  let alice = device() ?
  let alice_credential = credential(alice_account_keys, alice, created_at, expires_at) ?
  let conversation_id = random(16) ?
  let initial_inner = inner(alice_account.account_id,
  alice_credential.device_id,
  bob_credential.device_id,
  conversation_id,
  random(16) ?,
  "initial") ?
  let aad = associated_data(directory.mailbox_token) ?
  let ( alice_session, initial) = case initiate(alice,
  alice_credential,
  bob_account,
  bob_bundle,
  policy(now) ?,
  1,
  inner_wire(initial_inner) ?) do
    Err( _) -> Err("initial handshake failed")
    Ok( value) -> Ok(value)
  end ?
  let initial_outer = outbound(directory.mailbox_token,
  InitialPacket(account_wire(alice_account) ?, initial_wire(initial) ?)) ?
  let _ = submit_envelope(initial_outer, 202) ?
  let _ = submit_envelope(initial_outer, 200) ?
  let first_id = random(16) ?
  let second_id = random(16) ?
  let third_id = random(16) ?
  let ( alice_session, first) = encrypt_message(alice_session,
  inner(alice_account.account_id,
  alice_credential.device_id,
  bob_credential.device_id,
  conversation_id,
  first_id,
  "first") ?,
  aad) ?
  let ( alice_session, second) = encrypt_message(alice_session,
  inner(alice_account.account_id,
  alice_credential.device_id,
  bob_credential.device_id,
  conversation_id,
  second_id,
  "second") ?,
  aad) ?
  let ( alice_session, third) = encrypt_message(alice_session,
  inner(alice_account.account_id,
  alice_credential.device_id,
  bob_credential.device_id,
  conversation_id,
  third_id,
  "third") ?,
  aad) ?
  let _alice_session = alice_session
  let third_outer = outbound(directory.mailbox_token, RatchetPacket(ratchet_wire(third) ?)) ?
  let first_outer = outbound(directory.mailbox_token, RatchetPacket(ratchet_wire(first) ?)) ?
  let duplicate_outer = outbound(directory.mailbox_token, RatchetPacket(ratchet_wire(second) ?)) ?
  let second_outer = outbound(directory.mailbox_token, RatchetPacket(ratchet_wire(second) ?)) ?
  let _ = submit_envelope(third_outer, 202) ?
  let _ = submit_envelope(first_outer, 202) ?
  let _ = submit_envelope(second_outer, 202) ?
  let _ = submit_envelope(duplicate_outer, 202) ?
  println("device-a:submitted")
  Ok(0)
end

fn display(value :: Bytes) do
  case decode_inner_envelope(value) do
    Err( _) -> println("device-b:invalid-inner")
    Ok( inner_value) -> case Bytes.to_utf8(inner_value.body) do
      Err( _) -> println("device-b:invalid-body")
      Ok( body) -> println("display:#{body}")
    end
  end
end

fn process_deliveries(state :: consume RatchetState,
deliveries :: List < DeliveredEnvelope >,
index :: Int,
aad :: Bytes) -> RatchetState do
  if index >= List.length(deliveries) do
    state
  else
    let delivered = List.get(deliveries, index)
    case decode_outer_envelope(delivered.envelope) do
      Err( _) -> do
        println("device-b:invalid-outer")
        process_deliveries(state, deliveries, index + 1, aad)
      end
      Ok( outer) -> case decode_packet(outer.ciphertext) do
        Err( _) -> do
          println("device-b:invalid-packet")
          process_deliveries(state, deliveries, index + 1, aad)
        end
        Ok( InitialPacket( _, _)) -> do
          println("device-b:unexpected-initial")
          process_deliveries(state, deliveries, index + 1, aad)
        end
        Ok( RatchetPacket( message)) -> case decode_ratchet_message(message) do
          Err( _) -> do
            println("device-b:invalid-ratchet")
            process_deliveries(state, deliveries, index + 1, aad)
          end
          Ok( decoded) -> case decrypt(state, decoded, aad) do
            Rejected( next, Replay) -> do
              println("dedup:suppressed")
              process_deliveries(next, deliveries, index + 1, aad)
            end
            Rejected( next, _) -> do
              println("device-b:ratchet-rejected")
              process_deliveries(next, deliveries, index + 1, aad)
            end
            Opened( next, plaintext) -> do
              display(plaintext)
              process_deliveries(next, deliveries, index + 1, aad)
            end
          end
        end
      end
    end
  end
end

fn envelope_ids(deliveries :: List < DeliveredEnvelope >, index :: Int, ids :: List < Bytes >) -> List < Bytes > do
  if index >= List.length(deliveries) do
    ids
  else
    case decode_outer_envelope(List.get(deliveries, index).envelope) do
      Err( _) -> envelope_ids(deliveries, index + 1, ids)
      Ok( outer) -> envelope_ids(deliveries, index + 1, List.append(ids, outer.envelope_id))
    end
  end
end

fn run_device_b() -> Int ! String do
  let created_at = wide("1700000000000") ?
  let now = wide("1800000000000") ?
  let expires_at = wide("1900000000000") ?
  let ( bob_account_keys, bob_account) = account(created_at) ?
  let bob = device() ?
  let bob_credential = credential(bob_account_keys, bob, created_at, expires_at) ?
  let signed = signed_prekey(bob, bob_credential, expires_at) ?
  let one_time = one_time_prekey() ?
  let published = bundle(bob_credential, signed, one_time) ?
  let token = random(32) ?
  let _ = register_entry(DirectoryEntry {
    version : 1,
    username : "device-b",
    account_identity : account_wire(bob_account) ?,
    prekey_bundle : case encode_prekey_bundle(published) do
      Err( _) -> Err("prekey bundle encoding failed")
      Ok( value) -> Ok(value)
    end ?,
    mailbox_token : token
  }) ?
  println("device-b:registered")
  let delay = Env.get_int("MESSENGER_FETCH_DELAY_MS", 8000)
  if delay < 0 || delay > 60000 do
    Err("MESSENGER_FETCH_DELAY_MS must be between 0 and 60000")
  else
    Timer.sleep(delay)
    let deliveries = fetch_envelopes(token, 0) ?
    if List.length(deliveries) == 0 do
      Err("mailbox was empty")
    else
      let first_delivery = List.head(deliveries)
      let first_outer = case decode_outer_envelope(first_delivery.envelope) do
        Err( _) -> Err("invalid initial outer envelope")
        Ok( value) -> Ok(value)
      end ?
      let ( alice_account, initial) = case decode_packet(first_outer.ciphertext) do
        Err( _) -> Err("invalid initial transport packet")
        Ok( RatchetPacket( _)) -> Err("expected initial transport packet")
        Ok( InitialPacket( account_bytes, initial_bytes)) -> case decode_account_identity(account_bytes) do
          Err( _) -> Err("invalid initiator account")
          Ok( account_value) -> Ok((account_value, initial_bytes))
        end
      end ?
      let ( bob_session, initial_plaintext) = case receive_initial(bob,
      bob_account,
      published,
      signed,
      one_time,
      alice_account,
      policy(now) ?,
      policy(now) ?,
      initial) do
        Err( _) -> Err("initial receive failed")
        Ok( value) -> Ok(value)
      end ?
      display(initial_plaintext)
      let _bob_session = process_deliveries(bob_session, deliveries, 1, associated_data(token) ?)
      let ids = envelope_ids(deliveries, 0, List.new())
      let _ = acknowledge(token, ids) ?
      println("device-b:acked=#{List.length(ids)}")
      Ok(0)
    end
  end
end

fn report(role :: String, result :: Result < Int, String >) do
  case result do
    Err( error) -> println("#{role}:error:#{error}")
    Ok( _) -> println("#{role}:ok")
  end
end

fn main() do
  let role = Env.get("MESSENGER_ROLE", "")
  if role == "device-a" do
    report(role, run_device_a())
  else
    if role == "device-b" do
      report(role, run_device_b())
    else
      println("MESSENGER_ROLE must be device-a or device-b")
    end
  end
end
