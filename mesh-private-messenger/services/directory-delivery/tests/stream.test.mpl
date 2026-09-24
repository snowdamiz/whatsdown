from Runtime.MailboxStream import mailbox_stream_room
from Tests.MailboxSupport import mailbox_test_now, register_test_mailbox, signed_fetch, signed_fetch_at

fn rejected(value :: String!String) -> Bool do
  case value do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn authorization(wire :: Bytes) -> Map<String, String> do
  Map.put(Map.new(), "authorization", "MeshMailbox " <> Bytes.to_hex(wire))
end

fn legacy_frame(token :: Bytes) -> Bytes!String do
  let header = case Bytes.from_list([1, 70, 69, 84]) do
    Err(_) -> Err("test frame construction failed")
    Ok(value)
  end?
  let cursor = case Bytes.from_list([0, 0, 0, 0, 0, 0, 0, 0]) do
    Err(_) -> Err("test frame construction failed")
    Ok(value)
  end?
  Bytes.concat(Bytes.concat(header, token)?, cursor)
end

fn proof() -> Bool!String do
  let pool = Pool.open(Env.get("MESSENGER_TEST_DATABASE_URL",
      "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable"),
    1,
    2,
    5000)?
  Pool.execute(pool,
    "TRUNCATE messenger_mailbox_aliases, messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
    [])?
  let token = case Crypto.random_bytes(32) do
    Err(_) -> Err("randomness failed")
    Ok(value)
  end?
  let other_token = case Crypto.random_bytes(32) do
    Err(_) -> Err("randomness failed")
    Ok(value)
  end?
  let hash = Crypto.sha256(token)
  let owner = register_test_mailbox(pool, "stream-owner", token)?
  let stranger = register_test_mailbox(pool, "stream-stranger", other_token)?
  let headers = authorization(signed_fetch(owner, token)?)
  let room = mailbox_stream_room(pool, "/v1/mailbox/stream", headers)?
  assert(room == "mailbox:" <> Bytes.to_hex(hash))
  assert(rejected(mailbox_stream_room(pool, "/wrong", headers)))
  assert(rejected(mailbox_stream_room(pool, "/v1/mailbox/stream", Map.new())))
  assert(rejected(mailbox_stream_room(pool,
    "/v1/mailbox/stream",
    Map.put(Map.new(), "authorization", "MeshMailbox ff"))))
  # The public address alone, another device's key, and a stale frame all fail.
  assert(rejected(mailbox_stream_room(pool,
    "/v1/mailbox/stream",
    authorization(legacy_frame(token)?))))
  assert(rejected(mailbox_stream_room(pool,
    "/v1/mailbox/stream",
    authorization(signed_fetch(stranger, token)?))))
  let expired = U64.subtract(mailbox_test_now()?, U64.parse("301000")?)?
  assert(rejected(mailbox_stream_room(pool,
    "/v1/mailbox/stream",
    authorization(signed_fetch_at(owner, token, U64.parse("0")?, expired)?))))
  # Rejected attempts must not spend the owner's connection budget.
  let charged = Pool.query_values(pool,
    "SELECT count(*)::text AS value FROM messenger_rate_limits",
    [])?
  assert(List.length(charged) == 1)
  Pool.execute_values(pool,
    "UPDATE messenger_mailboxes SET active = false WHERE mailbox_token_hash = $1",
    [Binary(hash)])?
  assert(rejected(mailbox_stream_room(pool,
    "/v1/mailbox/stream",
    authorization(signed_fetch(owner, token)?))))
  Pool.close(pool)
  Ok(true)
end

test("stream subscriptions require a fresh frame signed by the mailbox's own device") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
