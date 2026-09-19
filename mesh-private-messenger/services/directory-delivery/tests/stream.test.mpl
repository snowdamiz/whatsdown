from Runtime.MailboxStream import mailbox_stream_room
from Protocol.MailboxWire import encode_mailbox_fetch
from Protocol.V1 import MailboxFetch

fn rejected(value :: String ! String) -> Bool do
  case value do
    Err( _) -> true
    Ok( _) -> false
  end
end

fn proof() -> Bool ! String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL", "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"), 1, 2, 5000) ?
  let token = case Crypto.random_bytes(32) do
    Err( _) -> Err("randomness failed")
    Ok( value) -> Ok(value)
  end ?
  let hash = Crypto.sha256(token)
  let _ = Pool.execute_values(pool, "INSERT INTO messenger_mailboxes (mailbox_token_hash) VALUES ($1)", [Binary(hash)]) ?
  let wire = case encode_mailbox_fetch(MailboxFetch { version : 1, mailbox_token : token, after_sequence : U64.parse("0") ? }) do
    Err( _) -> Err("encoding failed")
    Ok( value) -> Ok(value)
  end ?
  let headers = Map.put(Map.new(), "authorization", "MeshMailbox " <> Bytes.to_hex(wire))
  let room = mailbox_stream_room(pool, "/v1/mailbox/stream", headers) ?
  assert(room == "mailbox:" <> Bytes.to_hex(hash))
  assert(rejected(mailbox_stream_room(pool, "/wrong", headers)))
  assert(rejected(mailbox_stream_room(pool, "/v1/mailbox/stream", Map.new())))
  assert(rejected(mailbox_stream_room(pool, "/v1/mailbox/stream", Map.put(Map.new(), "authorization", "MeshMailbox ff"))))
  let _ = Pool.execute_values(pool, "UPDATE messenger_mailboxes SET active = false WHERE mailbox_token_hash = $1", [Binary(hash)]) ?
  assert(rejected(mailbox_stream_room(pool, "/v1/mailbox/stream", headers)))
  let _ = Pool.execute_values(pool, "DELETE FROM messenger_mailboxes WHERE mailbox_token_hash = $1", [Binary(hash)]) ?
  Pool.close(pool)
  Ok(true)
end

test("stream subscriptions validate the exact frame and active mailbox before joining") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
