from Protocol.MailboxWire import decode_mailbox_fetch
from Protocol.V1 import MailboxFetch
from Runtime.Registry import get_pool
from Storage.MailboxAuth import authorize_mailbox_fetch
from Storage.RateLimit import allow_request

# The stream is authorized by a fresh device-signed fetch frame, hex-encoded:
# "MeshMailbox " (12) + 2 * 116 frame bytes. A mailbox address alone cannot
# subscribe, and only authorized connections spend the owner's rate budget.

pub fn mailbox_stream_room(pool :: PoolHandle, path :: String, headers :: Map<String, String>) -> String!String do
  let names = List.filter(Map.keys(headers),
    fn(name :: String) -> String.to_lower(name) == "authorization" end)
  if path != "/v1/mailbox/stream" || List.length(names) != 1 do
    Err("invalid stream request")
  else
    let authorization = Map.get(headers, List.head(names))
    if String.length(authorization) != 244 || !String.starts_with(authorization, "MeshMailbox ") do
      Err("invalid stream authorization")
    else
      let wire = Bytes.from_hex(String.slice(authorization, 12, 244))?
      let request = case decode_mailbox_fetch(wire) do
        Err(_) -> Err("invalid stream frame")
        Ok(value)
      end?
      case authorize_mailbox_fetch(pool, request)? do
        None -> Err("unauthorized stream")
        Some(_) -> do
          let room = "mailbox:" <> Bytes.to_hex(request.mailbox_token_hash)
          let bucket = Crypto.sha256(Bytes.from_utf8("stream:" <> room))
          if !allow_request(pool, bucket, 60, 60)? do
            Err("stream rate limited")
          else
            Ok(room)
          end
        end
      end
    end
  end
end

fn on_connect(conn :: Int, path :: String, headers :: Map<String, String>) -> Int do
  case mailbox_stream_room(get_pool(), path, headers) do
    Err(_) -> 0
    # Join before announcing readiness so catch-up cannot miss a delivery.
    Ok(room) -> if Ws.join(conn, room) != 0 do
      0
    else if Ws.send(conn, "ready") == 0 do
      1
    else
      0
    end
  end
end

fn on_message(_conn :: Int, _message :: String) do
  nil
end

fn on_close(_conn :: Int, _code :: Int, _reason :: String) do
  nil
end

pub fn start_mailbox_stream(port :: Int) do
  Ws.serve(on_connect, on_message, on_close, port)
end

pub fn wake_mailbox(token_hash :: Bytes) do
  # ponytail: rooms are local unless Mesh nodes are clustered; cluster before adding service replicas.
  let failures = Ws.broadcast("mailbox:" <> Bytes.to_hex(token_hash), "encrypted-wakeup")
  if failures > 0 do
    println("mailbox stream write failed; client must reconnect")
  else
    nil
  end
end
