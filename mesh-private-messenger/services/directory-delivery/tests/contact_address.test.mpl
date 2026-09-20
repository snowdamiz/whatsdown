from Identity.Device import DeviceKeys
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.V1 import DeliveredEnvelope, OuterEnvelope
from Storage.ContactAddress import ContactAddressWrite, publish_contact_address
from Storage.Delivery import DeliveryInsert, enqueue_envelope, fetch_mailbox
from Storage.MailboxAuth import MailboxOwner
from Tests.MailboxSupport import register_test_mailbox

fn repeated(value :: Int, length :: Int) -> Bytes ! String do
  case Bytes.repeat(value, length) do
    Err( _) -> Err("test allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn envelope_id(number :: Int) -> Bytes ! String do
  case Bytes.slice(Crypto.sha256(Bytes.from_utf8(Int.to_string(number))), 0, 16) do
    Err( _) -> Err("test allocation failed")
    Ok( output) -> Ok(output)
  end
end

# 0 accepted, 1 refused for capacity, 2 anything else.

fn deposit_sized(pool :: PoolHandle, address :: Bytes, number :: Int, bucket :: Int) -> Int ! String do
  let now = U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()))) ?
  # Deposits are rate limited per mailbox; this test is about capacity.
  let _ = Pool.execute(pool, "DELETE FROM messenger_rate_limits", []) ?
  case enqueue_envelope(pool,
  OuterEnvelope {
    version : 1,
    envelope_id : envelope_id(number) ?,
    mailbox_token : address,
    suite : 4,
    expiration : U64.add(now, U64.parse("3600000") ?) ?,
    padding_bucket : bucket,
    ciphertext : Bytes.from_utf8("opaque")
  }) ? do
    Accepted -> Ok(0)
    MailboxFull -> Ok(1)
    _ -> Ok(2)
  end
end

# The largest envelope there is: sixty-four of them are a whole mailbox.

fn deposit(pool :: PoolHandle, address :: Bytes, number :: Int) -> Int ! String do
  deposit_sized(pool, address, number, 65536)
end

fn deposits(pool :: PoolHandle, address :: Bytes, number :: Int, remaining :: Int, expected :: Int) -> Bool ! String do
  if remaining <= 0 do
    Ok(true)
  else
    let outcome = deposit(pool, address, number) ?
    if outcome != expected do
      Ok(false)
    else
      deposits(pool, address, number + 1, remaining - 1, expected)
    end
  end
end

fn published(pool :: PoolHandle, mailbox :: Bytes, address :: Bytes) -> Int ! String do
  case publish_contact_address(pool, Crypto.sha256(mailbox), Crypto.sha256(address)) ? do
    ContactAddressPublished -> Ok(0)
    ContactAddressUnchanged -> Ok(1)
    ContactAddressConflict -> Ok(2)
    ContactAddressUnknownMailbox -> Ok(3)
  end
end

fn delivered_token(delivered :: DeliveredEnvelope) -> Bytes ! String do
  case decode_outer_envelope(delivered.envelope) do
    Err( _) -> Err("delivered envelope did not decode")
    Ok( outer) -> Ok(outer.mailbox_token)
  end
end

fn proof() -> Bool ! String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
  "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000) ?
  let _ = Pool.execute(pool,
  "TRUNCATE messenger_mailbox_aliases, messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
  []) ?
  let mailbox_address = repeated(11, 32) ?
  let contact_address = repeated(12, 32) ?
  let rotated_address = repeated(13, 32) ?
  let other_mailbox = repeated(21, 32) ?
  let owner_keys = register_test_mailbox(pool, "contact-owner", mailbox_address) ?
  let _other = register_test_mailbox(pool, "contact-other", other_mailbox) ?
  assert(published(pool, mailbox_address, contact_address) ? == 0)
  assert(published(pool, mailbox_address, contact_address) ? == 1)
  assert(published(pool, repeated(99, 32) ?, contact_address) ? == 3)
  # Nobody may claim an address that already routes somewhere: not another
  # mailbox's public address, and not another mailbox's contact address.
  assert(published(pool, other_mailbox, mailbox_address) ? == 2)
  assert(published(pool, other_mailbox, contact_address) ? == 2)
  # Whoever only knows the public address may hold three quarters of the
  # mailbox, 3 MiB, and not a byte more, however small the next envelope is.
  assert(deposits(pool, mailbox_address, 1, 48, 0) ?)
  assert(deposit_sized(pool, mailbox_address, 49, 256) ? == 1)
  # The contact address still reaches the same mailbox, up to its full size.
  assert(deposits(pool, contact_address, 100, 16, 0) ?)
  assert(deposit_sized(pool, contact_address, 116, 256) ? == 1)
  # What is delivered names the public address, however it was deposited, so
  # the device's own-mailbox check needs no knowledge of the scheme.
  let owner = MailboxOwner {
    mailbox_token : mailbox_address,
    signing_public_key : owner_keys.signing_public_key.bytes
  }
  let first_page = fetch_mailbox(pool, owner, U64.parse("0") ?) ?
  assert(List.length(first_page) == 8)
  assert(Bytes.secure_equals(delivered_token(List.head(first_page)) ?, mailbox_address))
  let contact_rows = Pool.query_values(pool,
  "SELECT sequence::text FROM messenger_envelopes WHERE contact ORDER BY sequence LIMIT 1",
  []) ?
  assert(List.length(contact_rows) == 1)
  # Rotation: the old address keeps routing, demoted to a stranger's share, so
  # nothing already addressed to it becomes undeliverable.
  let _ = Pool.execute(pool, "DELETE FROM messenger_envelopes", []) ?
  assert(published(pool, mailbox_address, rotated_address) ? == 0)
  # A device that lost its state republishes its old address in good faith:
  # that must not fail, and must not bring the old address back.
  assert(published(pool, mailbox_address, contact_address) ? == 1)
  assert(deposits(pool, mailbox_address, 200, 47, 0) ?)
  assert(deposit(pool, contact_address, 300) ? == 0)
  assert(deposit(pool, contact_address, 301) ? == 1)
  assert(deposit(pool, rotated_address, 302) ? == 0)
  # Someone who learns a contact address cannot take it over by registering a
  # device under it: the contact address is looked up first, so envelopes keep
  # reaching the mailbox that published it.
  let _thief = register_test_mailbox(pool, "contact-thief", rotated_address) ?
  assert(deposit(pool, rotated_address, 303) ? == 0)
  let kept = Pool.query_values(pool,
  "SELECT 1 AS found FROM messenger_envelopes WHERE mailbox_token_hash = $1 AND contact",
  [Binary(Crypto.sha256(mailbox_address))]) ?
  # Envelopes 302 and 303: the second arrived after the thief registered.
  assert(List.length(kept) == 2)
  Ok(true)
end

test("a contact address reaches the same mailbox and strangers cannot crowd contacts out") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end
