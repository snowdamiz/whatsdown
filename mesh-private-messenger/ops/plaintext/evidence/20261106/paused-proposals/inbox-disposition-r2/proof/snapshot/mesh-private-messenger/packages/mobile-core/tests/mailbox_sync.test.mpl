from Mobile.MailboxSync import synchronize_mailbox
from MobileCore import (
  create_account_export,
  directory_entry_export,
  erase_account_export,
  outbox_ack_export,
  send_message_export,
  start_conversation_export
)
from Protocol.DirectoryWire import decode_directory_entry
from Protocol.PrekeyWire import decode_prekey_bundle
from Protocol.IdentityWire import decode_device_credential
from Protocol.MailboxWire import (
  decode_mailbox_fetch,
  decode_mailbox_ack,
  encode_delivery_batch,
  mailbox_fetch_signing_bytes,
  mailbox_ack_signing_bytes
)
from Protocol.V1 import DeliveredEnvelope
from Tests.Support import database_path, append, vector

fn request(parts :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index == List.length(parts) do
    Ok(output)
  else
    request(parts, index + 1, append(output, vector(List.get(parts, index))?)?)
  end
end

fn pins(port :: Int) -> Bool do
  Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("1\n1\nhttp://127.0.0.1:"
      <> Int.to_string(port)
      <> "\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:18090/v1/mailbox/stream"))
end

fn fetch_response(input :: Request,
  path :: String,
  public_key :: Bytes,
  mailbox :: Bytes,
  batch :: Bytes,
  mode :: Int) -> Response do
  if Request.header(input, "cookie") != None || Request.header(input, "authorization") != None do
    return HTTP.response(400, "private headers")
  end
  let value = case decode_mailbox_fetch(Request.body_bytes(input)) do
    Err(_) -> return HTTP.response(400, "invalid fetch")
    Ok(value) -> value
  end
  if !Bytes.secure_equals(value.mailbox_token_hash, mailbox) do
    return HTTP.response(403, "wrong mailbox")
  end
  let signed = case mailbox_fetch_signing_bytes(value) do
    Err(_) -> return HTTP.response(400, "signing bytes")
    Ok(value) -> value
  end
  case Crypto.verify(SigningPublicKey { bytes: public_key },
    signed,
    Signature { bytes: value.signature }) do
    Ok(true) -> nil
    _ -> return HTTP.response(403, "signature")
  end
  if mode == 2 do
    return HTTP.response_bytes(200, Bytes.from_utf8("invalid batch"))
  end
  if mode == 3 do
    return HTTP.response_with_headers(307, "", Map.put(Map.new(), "Location", "/untrusted"))
  end
  if mode == 4 do
    case erase_account_export(Bytes.from_utf8(path)) do
      Err(_) -> return HTTP.response(500, "fixture erase")
      Ok(_) -> nil
    end
  end
  if (mode == 0 && U64.to_string(value.after_sequence) != "0")
    || ((mode == 1 || mode == 7) && File.exists(path <> ".acked")) do
    let empty = case Bytes.from_hex("0142415400") do
      Err(_) -> return HTTP.response(500, "fixture")
      Ok(value) -> value
    end
    HTTP.response_bytes(200, empty)
  else
    HTTP.response_bytes(200, batch)
  end
end

fn ack_response(input :: Request,
  path :: String,
  public_key :: Bytes,
  mailbox :: Bytes,
  mode :: Int) -> Response do
  let value = case decode_mailbox_ack(Request.body_bytes(input)) do
    Err(_) -> return HTTP.response(400, "invalid ack")
    Ok(value) -> value
  end
  if !Bytes.secure_equals(value.mailbox_token_hash, mailbox) do
    return HTTP.response(403, "wrong mailbox")
  end
  let signed = case mailbox_ack_signing_bytes(value) do
    Err(_) -> return HTTP.response(400, "signing bytes")
    Ok(value) -> value
  end
  case Crypto.verify(SigningPublicKey { bytes: public_key },
    signed,
    Signature { bytes: value.signature }) do
    Ok(true) -> nil
    _ -> return HTTP.response(403, "signature")
  end
  if mode == 7 && !File.exists(path <> ".ack-failed") do
    File.write(path <> ".ack-failed", "unknown response")
    return HTTP.response(503, "")
  end
  case File.write(path <> ".acked", "acknowledged") do
    Err(_) -> return HTTP.response(500, "fixture write")
    Ok(_) -> nil
  end
  HTTP.response(200, "")
end

actor peer(port :: Int,
  path :: String,
  public_key :: Bytes,
  mailbox :: Bytes,
  batch :: Bytes,
  mode :: Int) do
  HTTP.router()
    |> HTTP.on_post("/v1/mailbox/fetch",
      fn(input :: Request) do fetch_response(input, path, public_key, mailbox, batch, mode) end)
    |> HTTP.on_post("/v1/mailbox/ack",
      fn(input :: Request) do ack_response(input, path, public_key, mailbox, mode) end)
    |> HTTP.on_post("/untrusted",
      fn(_ :: Request) do
        File.write(path <> ".redirected", "bad")
        HTTP.response(200, "")
      end)
    |> HTTP.serve(port)
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let alice = database_path("mailbox-sync-alice")?
  let bob = database_path("mailbox-sync-bob")?
  let alice_profile = create_account_export(request([
      Bytes.from_utf8(alice),
      Bytes.from_utf8("alice")
    ],
    0,
    Bytes.empty())?)?
  create_account_export(request([Bytes.from_utf8(bob), Bytes.from_utf8("bob")], 0, Bytes.empty())?)?
  let entry = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(alice))?) do
    Err(_) -> return Err("fixture entry")
    Ok(value) -> value
  end
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> return Err("fixture bundle")
    Ok(value) -> value
  end
  let credential = case decode_device_credential(bundle.device_credential) do
    Err(_) -> return Err("fixture credential")
    Ok(value) -> value
  end
  let mailbox = Crypto.sha256(entry.mailbox_token)
  let hello = start_conversation_export(request([
      Bytes.from_utf8(bob),
      alice_profile,
      Bytes.from_utf8("hello")
    ],
    0,
    Bytes.empty())?)?
  outbox_ack_export(request([Bytes.from_utf8(bob), hello], 0, Bytes.empty())?)?
  let late = send_message_export(request([
      Bytes.from_utf8(bob),
      alice_profile,
      Bytes.from_utf8("second")
    ],
    0,
    Bytes.empty())?)?
  let late_batch = case encode_delivery_batch([
    DeliveredEnvelope { sequence: U64.parse("5")?, envelope: late }
  ]) do
    Err(_) -> return Err("fixture batch")
    Ok(value) -> value
  end
  let hello_batch = case encode_delivery_batch([
    DeliveredEnvelope { sequence: U64.parse("6")?, envelope: hello }
  ]) do
    Err(_) -> return Err("fixture batch")
    Ok(value) -> value
  end
  let _late = spawn(peer, 19981, alice, credential.signing_public_key, mailbox, late_batch, 0)
  let _hello = spawn(peer, 19982, alice, credential.signing_public_key, mailbox, hello_batch, 1)
  let _invalid = spawn(peer, 19983, alice, credential.signing_public_key, mailbox, hello_batch, 2)
  let _redirect = spawn(peer, 19984, alice, credential.signing_public_key, mailbox, hello_batch, 3)
  let _erase = spawn(peer, 19985, alice, credential.signing_public_key, mailbox, hello_batch, 4)
  let _endless = spawn(peer, 19986, alice, credential.signing_public_key, mailbox, hello_batch, 5)
  let _ack_failure = spawn(peer,
    19988,
    alice,
    credential.signing_public_key,
    mailbox,
    late_batch,
    7)
  Timer.sleep(100)
  assert(pins(19981))
  let delayed = synchronize_mailbox(alice)?
  assert(delayed.batches == 2
    && delayed.received == 1
    && delayed.acknowledged == 0
    && delayed.pending
    && !delayed.more)
  assert(!File.exists(alice <> ".acked"))
  assert(pins(19982))
  let first = synchronize_mailbox(alice)?
  assert(first.batches == 2
    && first.received == 1
    && first.acknowledged == 1
    && !first.pending
    && !first.more)
  File.delete(alice <> ".acked")?
  assert(pins(19988))
  assert(Result.is_err(synchronize_mailbox(alice)))
  assert(File.exists(alice <> ".ack-failed") && !File.exists(alice <> ".acked"))
  let recovered = synchronize_mailbox(alice)?
  assert(recovered.received == 1 && recovered.acknowledged == 1 && !recovered.pending)
  File.delete(alice <> ".acked")?
  File.delete(alice <> ".ack-failed")?
  assert(pins(19986))
  let bounded = synchronize_mailbox(alice)?
  assert(bounded.batches == 16
    && bounded.received == 16
    && bounded.acknowledged == 16
    && bounded.more
    && !bounded.pending)
  File.delete(alice <> ".acked")?
  assert(pins(19983))
  assert(Result.is_err(synchronize_mailbox(alice)))
  assert(!File.exists(alice <> ".acked"))
  assert(pins(19984))
  assert(Result.is_err(synchronize_mailbox(alice)))
  assert(!File.exists(alice <> ".redirected"))
  assert(pins(19985))
  assert(Result.is_err(synchronize_mailbox(alice)))
  assert(!File.exists(alice <> ".acked"))
  File.delete(alice)?
  File.delete(bob)?
  Ok(true)
end

test("mailbox HTTP signs inside Mesh, preserves delayed delivery, rejects malformed redirects and identity changes") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
