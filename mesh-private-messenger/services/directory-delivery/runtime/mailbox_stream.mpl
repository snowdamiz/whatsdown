from Protocol.MailboxWire import decode_mailbox_fetch
from Protocol.V1 import MailboxFetch
from Runtime.Registry import get_pool
from Storage.Delivery import mailbox_is_active
from Storage.RateLimit import allow_request

pub fn mailbox_stream_room(pool :: PoolHandle, path :: String, headers :: Map < String, String >) -> String ! String do
  let names = List.filter(Map.keys(headers), fn (name :: String) -> String.to_lower(name) == "authorization" end)
  if path != "/v1/mailbox/stream" || List.length(names) != 1 do
    Err("invalid stream request")
  else
    let authorization = Map.get(headers, List.head(names))
    if String.length(authorization) != 100 || !String.starts_with(authorization, "MeshMailbox ") do
      Err("invalid stream authorization")
    else
      let wire = Bytes.from_hex(String.slice(authorization, 12, 100)) ?
      let request = case decode_mailbox_fetch(wire) do
        Err( _) -> Err("invalid stream frame")
        Ok( value) -> Ok(value)
      end ?
      let hash = Crypto.sha256(request.mailbox_token)
      if !mailbox_is_active(pool, hash) ? do
        Err("inactive mailbox")
      else
        let room = "mailbox:" <> Bytes.to_hex(hash)
        let bucket = Crypto.sha256(Bytes.from_utf8("stream:" <> room))
        if !allow_request(pool, bucket, 60, 60) ? do
          Err("stream rate limited")
        else
          Ok(room)
        end
      end
    end
  end
end

fn on_connect(conn :: Int, path :: String, headers :: Map < String, String >) -> Int do
  case mailbox_stream_room(get_pool(), path, headers) do
    Err( _) -> 0
    Ok( room) -> if Ws.join(conn, room) != 0 do
      0
    else
      # Join before announcing readiness so catch-up cannot miss a delivery.
      if Ws.send(conn, "ready") == 0 do 1 else 0 end
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
  if failures > 0 do println("mailbox stream write failed; client must reconnect") else nil end
end
