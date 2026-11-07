from Mobile.MailboxTransport import (
  connect_mailbox_stream,
  read_mailbox_stream,
  close_mailbox_stream
)
from MobileCore import (
  create_account_export,
  directory_entry_export,
  mailbox_stream_close_export,
  mailbox_stream_open_export,
  mailbox_stream_poll_export
)
from Protocol.DirectoryWire import decode_directory_entry
from Protocol.IdentityWire import decode_device_credential
from Protocol.MailboxWire import decode_mailbox_fetch, mailbox_fetch_signing_bytes
from Protocol.PrekeyWire import decode_prekey_bundle
from Tests.Support import append, database_path, vector, write_u32

fn session_request(path :: String, ticket :: Bytes) -> Bytes!String do
  append(append(write_u32(2)?, vector(Bytes.from_utf8(path))?)?, vector(ticket)?)
end

fn open_mailbox(path :: String) -> Bytes!String do
  mailbox_stream_open_export(Bytes.from_utf8(path))
end

fn poll_mailbox(path :: String, ticket :: Bytes) -> Bytes!String do
  mailbox_stream_poll_export(session_request(path, ticket)?)
end

fn close_mailbox(path :: String, ticket :: Bytes) -> Bytes!String do
  mailbox_stream_close_export(session_request(path, ticket)?)
end

fn authorized(path :: String,
  headers :: Map<String, String>,
  mailbox :: Bytes,
  public_key :: Bytes) -> Bool do
  if path != "/v1/mailbox/stream" || !Map.has_key(headers, "authorization") do
    return false
  end
  if Map.has_key(headers, "cookie") do
    return false
  end
  let header = Map.get(headers, "authorization")
  if String.length(header) != 244 || !String.starts_with(header, "MeshMailbox ") do
    return false
  end
  let wire = case Bytes.from_hex(String.slice(header, 12, 244)) do
    Err(_) -> return false
    Ok(value) -> value
  end
  let request = case decode_mailbox_fetch(wire) do
    Err(_) -> return false
    Ok(value) -> value
  end
  if !Bytes.secure_equals(request.mailbox_token_hash, Crypto.sha256(mailbox)) do
    return false
  end
  let signed = case mailbox_fetch_signing_bytes(request) do
    Err(_) -> return false
    Ok(value) -> value
  end
  case Crypto.verify(SigningPublicKey { bytes: public_key },
    signed,
    Signature { bytes: request.signature }) do
    Err(_) -> false
    Ok(value) -> value
  end
end

actor server(mailbox :: Bytes, public_key :: Bytes, port :: Int, early :: Bool) do
  Ws.serve(fn(conn :: Int, path :: String, headers :: Map<String, String>) do
      if !authorized(path, headers, mailbox, public_key) do
        0
      else
        let _ready = if early do
          0
        else
          Ws.send(conn, "ready")
        end
        Ws.send(conn, "encrypted-wakeup")
        Ws.send(conn, "not-a-mailbox-event")
        1
      end
    end,
    fn(_conn :: Int, _message :: String) do nil end,
    fn(_conn :: Int, _code :: Int, _reason :: String) do nil end,
    port)
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("1\n1\nhttp://127.0.0.1:18086\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:19972/v1/mailbox/stream")))
  let path = database_path("native-mailbox-transport")?
  create_account_export(append(vector(Bytes.from_utf8(path))?, vector(Bytes.from_utf8("alice"))?)?)?
  let entry = case decode_directory_entry(directory_entry_export(Bytes.from_utf8(path))?) do
    Err(_) -> return Err("fixture directory decode")
    Ok(value) -> value
  end
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> return Err("fixture prekey decode")
    Ok(value) -> value
  end
  let credential = case decode_device_credential(bundle.device_credential) do
    Err(_) -> return Err("fixture credential decode")
    Ok(value) -> value
  end
  let _server = spawn(server, entry.mailbox_token, credential.signing_public_key, 19972, false)
  Timer.sleep(100)
  let stream = connect_mailbox_stream(path)?
  let first = case read_mailbox_stream(stream, 2000) do
    Err(error) -> return Err("first:" <> error)
    Ok(value) -> value
  end
  assert(first == "ready")
  let second = case read_mailbox_stream(stream, 2000) do
    Err(error) -> return Err("second:" <> error)
    Ok(value) -> value
  end
  assert(second == "encrypted-wakeup")
  case read_mailbox_stream(stream, 2000) do
    Err(error) -> assert(error == "invalid_mailbox_stream_event")
    Ok(_) -> assert(false)
  end
  close_mailbox_stream(stream)
  let first_ticket = open_mailbox(path)?
  let second_ticket = open_mailbox(path)?
  assert(Bytes.length(second_ticket) == 32)
  assert(!Bytes.secure_equals(first_ticket, second_ticket))
  case mailbox_stream_poll_export(append(session_request(path, second_ticket)?, Bytes.from_utf8("extra"))?) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case poll_mailbox(path, Bytes.empty()) do
    Err(_) -> nil
    Ok(_) -> assert(false)
  end
  case poll_mailbox(path, first_ticket) do
    Err(error) -> assert(error == "mailbox_stream_expired")
    Ok(_) -> assert(false)
  end
  case poll_mailbox(path <> "-other", second_ticket) do
    Err(error) -> assert(error == "mailbox_stream_expired")
    Ok(_) -> assert(false)
  end
  assert(Bytes.to_utf8(poll_mailbox(path, second_ticket)?)? == "ready")
  assert(Bytes.to_utf8(poll_mailbox(path, second_ticket)?)? == "encrypted-wakeup")
  close_mailbox(path, second_ticket)?
  case poll_mailbox(path, second_ticket) do
    Err(error) -> assert(error == "mailbox_stream_expired")
    Ok(_) -> assert(false)
  end
  let _early = spawn(server, entry.mailbox_token, credential.signing_public_key, 19973, true)
  Timer.sleep(100)
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("1\n1\nhttp://127.0.0.1:18086\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:19973/v1/mailbox/stream")))
  let early_ticket = open_mailbox(path)?
  case poll_mailbox(path, early_ticket) do
    Err(error) -> assert(error == "invalid_mailbox_stream_order")
    Ok(_) -> assert(false)
  end
  assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
    Bytes.from_utf8("1\n1\nhttp://127.0.0.1:18086\nhttp://127.0.0.1:18087\nhttp://127.0.0.1:18089\nws://127.0.0.1:19972/v1/mailbox/stream")))
  let erased_ticket = open_mailbox(path)?
  File.delete(path)?
  case poll_mailbox(path, erased_ticket) do
    Err(error) -> assert(error == "mailbox_stream_identity_changed")
    Ok(_) -> assert(false)
  end
  if File.exists(path) do
    File.delete(path)?
  end
  Ok(true)
end

test("Mesh mailbox transport signs its own native-pinned upgrade and admits only wakeup events") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
