from Api.Binary import delete_account_request, leave_device_request, register_device_request, resolve_devices_request, submit_request
from Identity.Device import AccountKeys, DeviceKeys, generate_account, generate_device, issue_account_deletion, issue_device_credential, issue_device_departure
from Prekeys.Bundle import build_prekey_bundle, generate_one_time_prekey, generate_signed_prekey
from Protocol.DirectoryWire import encode_account_deletion, encode_device_departure, encode_directory_entry
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.IdentityWire import encode_account_identity
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import AccountDeletion, AccountIdentity, DeviceDeparture, DirectoryEntry, OuterEnvelope
from Transparency.Wire import TransparencyLookup, encode_transparency_lookup

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn now() -> U64!String do
  wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn filled(value :: Int, length :: Int) -> Bytes do
  case Bytes.repeat(value, length) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn account(created_at :: U64) -> Result<(AccountKeys, AccountIdentity), String> do
  case generate_account(created_at, wide("1")?) do
    Err(_) -> Err("account generation failed")
    Ok(value)
  end
end

fn fresh_device() -> DeviceKeys!String do
  case generate_device() do
    Err(_) -> Err("device generation failed")
    Ok(value)
  end
end

fn device_entry(username :: String,
  keys :: borrow AccountKeys,
  identity :: AccountIdentity,
  sequence :: String,
  mailbox_token :: Bytes) -> Bytes!String do
  let device = fresh_device()?
  device_entry_for(username, keys, identity, sequence, mailbox_token, device)
end

## `device` as one more device of `keys`, registered as the account's
## `sequence`th change.

fn device_entry_for(username :: String,
  keys :: borrow AccountKeys,
  identity :: AccountIdentity,
  sequence :: String,
  mailbox_token :: Bytes,
  device :: borrow DeviceKeys) -> Bytes!String do
  let created_at = now()?
  let expires_at = U64.add(created_at, wide("31536000000")?)?
  let credential = case issue_device_credential(keys,
    device,
    wide("1")?,
    created_at,
    expires_at,
    wide(sequence)?) do
    Err(_) -> Err("credential generation failed")
    Ok(value)
  end?
  let signed = case generate_signed_prekey(device, credential, wide("1")?, expires_at) do
    Err(_) -> Err("signed prekey generation failed")
    Ok(value)
  end?
  let one_time = case generate_one_time_prekey(wide("2")?) do
    Err(_) -> Err("one-time prekey generation failed")
    Ok(value)
  end?
  let bundle = case build_prekey_bundle(credential, signed, one_time) do
    Err(_) -> Err("bundle generation failed")
    Ok(value)
  end?
  let entry = DirectoryEntry {
    version: 1,
    username: username,
    account_identity: case encode_account_identity(identity) do
      Err(_) -> Err("account identity encoding failed")
      Ok(value)
    end?,
    prekey_bundle: case encode_prekey_bundle(bundle) do
      Err(_) -> Err("prekey bundle encoding failed")
      Ok(value)
    end?,
    mailbox_token: mailbox_token
  }
  case encode_directory_entry(entry) do
    Err(_) -> Err("directory entry encoding failed")
    Ok(value)
  end
end

fn deletion_wire(value :: AccountDeletion) -> Bytes!String do
  case encode_account_deletion(value) do
    Err(_) -> Err("deletion encoding failed")
    Ok(encoded)
  end
end

fn deletion(keys :: borrow AccountKeys, issued_at :: U64) -> AccountDeletion!String do
  case issue_account_deletion(keys, issued_at) do
    Err(_) -> Err("deletion signing failed")
    Ok(value)
  end
end

fn envelope(mailbox_token :: Bytes, id :: Int) -> Bytes!String do
  case encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: filled(id, 16),
    mailbox_token: mailbox_token,
    suite: 1,
    expiration: U64.add(now()?, wide("3600000")?)?,
    padding_bucket: 256,
    ciphertext: Bytes.from_utf8("opaque")
  }) do
    Err(_) -> Err("envelope encoding failed")
    Ok(value)
  end
end

fn lookup(username :: String) -> Bytes!String do
  case encode_transparency_lookup(TransparencyLookup {
    username: username,
    previous_tree_size: 0
  }) do
    Err(_) -> Err("lookup encoding failed")
    Ok(value)
  end
end

## What the directory keeps for an account, counted table by table:
## account, devices, prekeys, mailboxes, envelopes, outbox events, push
## bindings, contact addresses, readable log entries, and the tombstone.

fn kept(pool :: PoolHandle, account_id :: Bytes, mailboxes :: List<Bytes>) -> String!String do
  let hashes = List.map(mailboxes, fn (token) -> Bytes.to_hex(Crypto.sha256(token)) end)
  let rows = Pool.query_values(pool,
    "WITH mailbox AS (SELECT decode(value, 'hex') AS hash FROM unnest(string_to_array($2, ',')) AS value) SELECT concat((SELECT count(*) FROM messenger_accounts WHERE account_id = $1), ':', (SELECT count(*) FROM messenger_devices WHERE account_id = $1), ':', (SELECT count(*) FROM messenger_one_time_prekeys WHERE account_id = $1), ':', (SELECT count(*) FROM messenger_mailboxes WHERE mailbox_token_hash IN (SELECT hash FROM mailbox)), ':', (SELECT count(*) FROM messenger_envelopes WHERE mailbox_token_hash IN (SELECT hash FROM mailbox)), ':', (SELECT count(*) FROM messenger_outbox_events WHERE mailbox_token_hash IN (SELECT hash FROM mailbox)), ':', (SELECT count(*) FROM messenger_push_bindings WHERE mailbox_token_hash IN (SELECT hash FROM mailbox)), ':', (SELECT count(*) FROM messenger_mailbox_aliases WHERE mailbox_token_hash IN (SELECT hash FROM mailbox)), ':', (SELECT count(*) FROM transparency_entries WHERE entry_bytes IS NOT NULL AND account_commitment = sha256('mesh-msg/v1/transparency-account'::bytea || $1)), ':', (SELECT count(*) FROM messenger_deleted_accounts WHERE account_id = $1)) AS value",
    [Binary(account_id), Text(String.join(hashes, ","))])?
  case Map.get(List.head(rows), "value") do
    Text(value) -> Ok(value)
    _ -> Err("invalid test row")
  end
end

fn log_size(pool :: PoolHandle) -> String!String do
  let rows = Pool.query_values(pool, "SELECT count(*)::text AS value FROM transparency_entries", [])?
  case Map.get(List.head(rows), "value") do
    Text(value) -> Ok(value)
    _ -> Err("invalid test row")
  end
end

fn proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
    "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000)?
  Pool.execute(pool,
    "TRUNCATE messenger_deleted_accounts, messenger_mailbox_aliases, messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
    [])?
  let created_at = now()?
  let (alice, alice_identity) = account(created_at)?
  let (bob, bob_identity) = account(created_at)?
  let (stranger, stranger_identity) = account(created_at)?
  let phone = filled(41, 32)
  let laptop = filled(42, 32)
  let bobs_phone = filled(43, 32)
  assert(register_device_request(pool, device_entry("alice", alice, alice_identity, "1", phone)?).status == 201)
  assert(register_device_request(pool, device_entry("alice", alice, alice_identity, "2", laptop)?).status == 201)
  assert(register_device_request(pool, device_entry("bob", bob, bob_identity, "1", bobs_phone)?).status == 201)
  assert(submit_request(pool, envelope(laptop, 51)?).status == 202)
  assert(submit_request(pool, envelope(bobs_phone, 52)?).status == 202)
  Pool.execute_values(pool,
    "INSERT INTO messenger_push_bindings (mailbox_token_hash, wake_token_hash, revision, provider, provider_token_ciphertext) VALUES ($1, $2, 1, 1, $3)",
    [Binary(Crypto.sha256(phone)), Binary(filled(61, 32)), Binary(filled(62, 17))])?
  Pool.execute_values(pool,
    "INSERT INTO messenger_mailbox_aliases (alias_hash, mailbox_token_hash) VALUES ($1, $2)",
    [Binary(filled(63, 32)), Binary(Crypto.sha256(phone))])?
  let alices = [phone, laptop]
  assert(kept(pool, alice_identity.account_id, alices)? == "1:2:2:2:1:1:1:1:2:0")
  let bobs = kept(pool, bob_identity.account_id, [bobs_phone])?
  assert(bobs == "1:1:1:1:1:1:0:0:1:0")
  let leaves = log_size(pool)?
  # Refused without a change: a malformed frame, another key's signature, and a
  # stale statement.
  assert(delete_account_request(pool, Bytes.from_utf8("not a deletion")).status == 400)
  let forged = deletion(stranger, now()?)?
  assert(delete_account_request(pool,
    deletion_wire(% { forged | account_id: alice_identity.account_id })?).status == 403)
  let stale = wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()) - 360000))?
  assert(delete_account_request(pool, deletion_wire(deletion(alice, stale)?)?).status == 403)
  # An account the directory never had is as gone as a deleted one. Only a
  # directory without this route answers 404, and a client must not erase then.
  assert(delete_account_request(pool, deletion_wire(deletion(stranger, now()?)?)?).status == 204)
  assert(kept(pool, stranger_identity.account_id, [])? == "0:0:0:0:0:0:0:0:0:0")
  assert(kept(pool, alice_identity.account_id, alices)? == "1:2:2:2:1:1:1:1:2:0")
  let signed = deletion_wire(deletion(alice, now()?)?)?
  assert(delete_account_request(pool, signed).status == 204)
  # Nothing of the account is left but its tombstone. The log keeps its leaves,
  # which every proof needs, but no longer the entries naming the account.
  assert(kept(pool, alice_identity.account_id, alices)? == "0:0:0:0:0:0:0:0:0:1")
  assert(log_size(pool)? == leaves)
  assert(kept(pool, bob_identity.account_id, [bobs_phone])? == bobs)
  # A retry after a lost response succeeds.
  assert(delete_account_request(pool, signed).status == 204)
  assert(resolve_devices_request(pool, lookup("alice")?).status == 404)
  assert(submit_request(pool, envelope(phone, 53)?).status == 410)
  # A copy of the account left on a device cannot bring it back, and is told why
  # by the account's own key: the statement that deleted it...
  let resurrected = register_device_request(pool,
    device_entry("alice", alice, alice_identity, "1", filled(44, 32))?)
  assert(resurrected.status == 410 && Bytes.secure_equals(resurrected.body, signed))
  assert(kept(pool, alice_identity.account_id, alices)? == "0:0:0:0:0:0:0:0:0:1")
  # ...but the username is free for a new account, and then stays with it.
  let (newcomer, newcomer_identity) = account(created_at)?
  assert(register_device_request(pool,
    device_entry("alice", newcomer, newcomer_identity, "1", filled(45, 32))?).status == 201)
  assert(register_device_request(pool,
    device_entry("alice", alice, alice_identity, "1", filled(46, 32))?).status == 410)
  Pool.close(pool)
  Ok(true)
end

test("deleting an account removes all it left on the directory and frees its username") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn departure(device :: borrow DeviceKeys, account_id :: Bytes, issued_at :: U64) -> DeviceDeparture!String do
  case issue_device_departure(device, account_id, issued_at) do
    Err(_) -> Err("departure signing failed")
    Ok(value)
  end
end

fn departure_wire(value :: DeviceDeparture) -> Bytes!String do
  case encode_device_departure(value) do
    Err(_) -> Err("departure encoding failed")
    Ok(encoded)
  end
end

## Active devices, revoked devices, account sequence, log entries, and active
## mailboxes of one account.

fn device_state(pool :: PoolHandle, account_id :: Bytes) -> String!String do
  let rows = Pool.query_values(pool,
    "SELECT concat((SELECT count(*) FROM messenger_devices WHERE account_id = $1 AND revoked_at IS NULL), ':', (SELECT count(*) FROM messenger_revoked_devices WHERE account_id = $1), ':', (SELECT sequence FROM messenger_accounts WHERE account_id = $1), ':', (SELECT count(*) FROM transparency_entries WHERE account_commitment = sha256('mesh-msg/v1/transparency-account'::bytea || $1)), ':', (SELECT count(*) FROM messenger_mailboxes AS mailbox JOIN messenger_devices AS device USING (mailbox_token_hash) WHERE device.account_id = $1 AND mailbox.active)) AS value",
    [Binary(account_id)])?
  case Map.get(List.head(rows), "value") do
    Text(value) -> Ok(value)
    _ -> Err("invalid test row")
  end
end

fn departure_proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL",
    "postgres://messenger:messenger@127.0.0.1:55432/messenger?sslmode=disable")
  let pool = Pool.open(url, 1, 2, 5000)?
  Pool.execute(pool,
    "TRUNCATE messenger_deleted_accounts, messenger_mailbox_aliases, messenger_one_time_prekeys, messenger_push_bindings, witness_signatures, transparency_checkpoints, transparency_nodes, transparency_entries, messenger_outbox_events, messenger_rate_limits, messenger_envelopes, messenger_devices, messenger_revoked_devices, messenger_accounts, messenger_mailboxes RESTART IDENTITY",
    [])?
  let (alice, alice_identity) = account(now()?)?
  let alice_id = alice_identity.account_id
  let phone = fresh_device()?
  let laptop = fresh_device()?
  assert(register_device_request(pool,
    device_entry_for("alice", alice, alice_identity, "1", filled(71, 32), phone)?).status == 201)
  assert(register_device_request(pool,
    device_entry_for("alice", alice, alice_identity, "2", filled(72, 32), laptop)?).status == 201)
  assert(device_state(pool, alice_id)? == "2:0:2:2:2")
  # Refused without a change: a malformed frame, another device's signature, and
  # a stale statement.
  assert(leave_device_request(pool, Bytes.from_utf8("garbage")).status == 400)
  let forged = departure(phone, alice_id, now()?)?
  assert(leave_device_request(pool, departure_wire(% { forged | device_id: laptop.device_id })?).status == 403)
  let stale = wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()) - 360000))?
  assert(leave_device_request(pool, departure_wire(departure(laptop, alice_id, stale)?)?).status == 403)
  assert(device_state(pool, alice_id)? == "2:0:2:2:2")
  # The laptop leaves like a removed device: revoked in a logged device set, its
  # mailbox closed. A retry after a lost answer changes nothing more.
  let left = departure_wire(departure(laptop, alice_id, now()?)?)?
  assert(leave_device_request(pool, left).status == 204)
  assert(device_state(pool, alice_id)? == "1:1:3:3:1")
  assert(leave_device_request(pool, left).status == 204)
  assert(device_state(pool, alice_id)? == "1:1:3:3:1")
  # If its erase never ran, it is told so with its own departure.
  let returning = device_entry_for("alice", alice, alice_identity, "2", filled(72, 32), laptop)?
  let refused = register_device_request(pool, returning)
  assert(refused.status == 410 && Bytes.secure_equals(refused.body, left))
  # A device removed before removals kept their statement has none to show.
  Pool.execute(pool, "UPDATE messenger_revoked_devices SET statement = NULL", [])?
  assert(register_device_request(pool, returning).status == 409)
  # The last device cannot leave an account behind with no device; it deletes
  # the account instead, and then there is nothing left to leave.
  assert(leave_device_request(pool, departure_wire(departure(phone, alice_id, now()?)?)?).status == 409)
  assert(device_state(pool, alice_id)? == "1:1:3:3:1")
  assert(delete_account_request(pool, deletion_wire(deletion(alice, now()?)?)?).status == 204)
  assert(leave_device_request(pool, departure_wire(departure(phone, alice_id, now()?)?)?).status == 204)
  Pool.close(pool)
  Ok(true)
end

test("a linked device leaves its account without leaving anything to send to") do
  case departure_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end
