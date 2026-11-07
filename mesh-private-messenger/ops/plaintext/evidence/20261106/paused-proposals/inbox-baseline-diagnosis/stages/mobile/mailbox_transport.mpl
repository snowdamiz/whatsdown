from Mobile.Account import mailbox_fetch
from Mobile.NetworkPins import native_network_pins
from Mobile.Profile import load_profile

##! This internal transport never accepts a URL, authorization or payload from JS.
##! The embedding layer will expose only opaque mailbox lifecycle operations.

pub struct MobileMailboxStream do
  connection :: Int
  database_path :: String
  profile_hash :: Bytes
  stream_url :: String
end

pub fn close_mailbox_stream(stream :: MobileMailboxStream) do
  let _closed = WsClient.close(stream.connection, 1000, "mailbox closed")
  nil
end

fn current(stream :: MobileMailboxStream) -> Bool do
  let pins = case native_network_pins() do
    Err(_) -> return false
    Ok(value) -> value
  end
  let profile = case load_profile(stream.database_path) do
    Err(_) -> return false
    Ok(value) -> value
  end
  pins.stream_url == stream.stream_url
    && Bytes.secure_equals(Crypto.sha256(profile), stream.profile_hash)
end

pub fn connect_mailbox_stream(database_path :: String) -> MobileMailboxStream!String do
  let pins = native_network_pins()?
  let profile_hash = Crypto.sha256(load_profile(database_path)?)
  let authorization = "MeshMailbox " <> Bytes.to_hex(mailbox_fetch(database_path)?)
  let options = WsClient.options()
    |> WsClient.connect_timeout(5000)
    |> WsClient.heartbeat_timeout(30000)
    |> WsClient.max_message_bytes(32)
    |> WsClient.queue_capacity(8)
  let options = case WsClient.header(options, "Authorization", authorization) do
    Err(_) -> return Err("mailbox_stream_configuration_failed")
    Ok(value) -> value
  end
  let connection = case WsClient.connect(pins.stream_url, options) do
    Err(_) -> return Err("mailbox_stream_unavailable")
    Ok(value) -> value
  end
  let stream = MobileMailboxStream {
    connection: connection,
    database_path: database_path,
    profile_hash: profile_hash,
    stream_url: pins.stream_url
  }
  if !current(stream) do
    close_mailbox_stream(stream)
    Err("mailbox_stream_identity_changed")
  else
    Ok(stream)
  end
end

pub fn read_mailbox_stream(stream :: MobileMailboxStream, timeout_ms :: Int) -> String!String do
  if timeout_ms < 0 || timeout_ms > 5000 do
    return Err("invalid_mailbox_stream_timeout")
  end
  if !current(stream) do
    close_mailbox_stream(stream)
    return Err("mailbox_stream_identity_changed")
  end
  let message = case WsClient.recv(stream.connection, timeout_ms) do
    Err(error) -> if error == "TIMEOUT: WebSocket receive" do
      return Ok("")
    else
      close_mailbox_stream(stream)
      return Err("mailbox_stream_disconnected")
    end
    Ok(value) -> value
  end
  if !current(stream) do
    close_mailbox_stream(stream)
    return Err("mailbox_stream_identity_changed")
  end
  if message.kind == "text" do
    let text = case Bytes.to_utf8(message.data) do
      Err(_) -> ""
      Ok(value) -> value
    end
    if text == "ready" || text == "encrypted-wakeup" do
      return Ok(text)
    end
  end
  close_mailbox_stream(stream)
  Err("invalid_mailbox_stream_event")
end
