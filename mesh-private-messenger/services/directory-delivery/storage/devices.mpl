from Identity.Device import verify_account_deletion, verify_device_departure, verify_device_revocation
from Prekeys.Pool import OneTimePrekeyPublic
from Prekeys.Bundle import normalize_prekey_bundle, verify_prekey_bundle
from Protocol.DirectoryWire import encode_account_deletion, encode_device_departure, encode_device_revocation, encode_device_set, encode_directory_entry
from Protocol.IdentityWire import decode_account_identity, decode_device_credential
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.MailboxWire import mailbox_request_is_fresh
from Protocol.V1 import (
  AccountDeletion,
  AccountIdentity,
  DeviceCredential,
  DeviceDeparture,
  DeviceRevocation,
  DeviceSet,
  DirectoryEntry,
  PrekeyBundle
)
from Storage.MailboxAuth import bundle_signing_public_key
from Storage.Prekeys import seed_registration_prekey_on_connection
from Storage.Transparency import append_entry_on_connection, forget_account_entries_on_connection

# DeviceRemoved: the account was deleted, or this device removed from it, for
# good. It carries the signed statement that did it, which the device checks
# before it erases its own copy. DeviceRetired: a device was just taken out of
# its account; it names the mailbox to wake so the device hears it at once.

pub type DeviceWrite do
  DeviceAccepted
  DeviceUnchanged
  DeviceConflict
  DeviceInvalid
  DeviceLogFull
  DeviceRemoved(statement :: Bytes)
  DeviceRetired(mailbox :: Bytes)
end deriving(Eq, Debug)

# AccountRemoved is also the answer for an account that is already gone, or
# was never registered: either way nothing of it is left, and a retry after a
# lost answer succeeds. It lists the mailboxes to wake, so that devices still
# listening learn at once.

pub type AccountRemoval do
  AccountRemoved(mailboxes :: List<Bytes>)
  AccountRemovalRefused
end deriving(Eq, Debug)

struct VerifiedRegistration do
  entry :: DirectoryEntry
  account :: AccountIdentity
  credential :: DeviceCredential
  initial_prekey :: Option<OneTimePrekeyPublic>
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(bytes) -> Ok(bytes)
    _ -> Err("invalid device row")
  end
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid device row")
  end
end

fn wide(value :: DbValue) -> U64!String do
  U64.parse(text(value)?)
end

fn integer(value :: DbValue) -> Int!String do
  case String.to_int(text(value)?) do
    None -> Err("invalid device integer")
    Some(output) -> Ok(output)
  end
end

fn current_time() -> U64!String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn normalized_bundle(bundle :: PrekeyBundle) -> PrekeyBundle!String do
  case normalize_prekey_bundle(bundle) do
    Err(_) -> Err("invalid normalized prekey bundle")
    Ok(normalized)
  end
end

fn verified_registration(entry :: DirectoryEntry) -> VerifiedRegistration!String do
  case encode_directory_entry(entry) do
    Err(_) -> Err("invalid device registration")
    Ok(value)
  end?
  let account = case decode_account_identity(entry.account_identity) do
    Err(_) -> Err("invalid device registration")
    Ok(value)
  end?
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> Err("invalid device registration")
    Ok(value)
  end?
  let credential = case decode_device_credential(bundle.device_credential) do
    Err(_) -> Err("invalid device registration")
    Ok(value)
  end?
  case verify_prekey_bundle(account, bundle, 1, current_time()?, account.directory_sequence) do
    Err(_) -> Err("invalid device registration")
    Ok(false) -> Err("invalid device registration")
    Ok(true) -> do
      let initial_prekey = if Bytes.length(bundle.one_time_prekey) == 32 do
        Some(OneTimePrekeyPublic {
          id: bundle.one_time_prekey_id,
          public_key: bundle.one_time_prekey
        })
      else
        None
      end
      let base = normalized_bundle(bundle)?
      let encoded_base = case encode_prekey_bundle(base) do
        Err(_) -> Err("invalid normalized prekey bundle")
        Ok(output)
      end?
      Ok(VerifiedRegistration {
        entry: %{entry | prekey_bundle: encoded_base},
        account: account,
        credential: credential,
        initial_prekey: initial_prekey
      })
    end
  end
end

fn entries(rows :: List<Map<String, DbValue>>, username :: String, account_identity :: Bytes) -> List<DirectoryEntry>!String do
  let values = for row in rows do
    DirectoryEntry {
      version: 1,
      username: username,
      account_identity: account_identity,
      prekey_bundle: binary(Map.get(row, "prekey_bundle"))?,
      mailbox_token: binary(Map.get(row, "mailbox_token"))?
    }
  end
  Ok(values)
end

fn ids(rows :: List<Map<String, DbValue>>) -> List<Bytes>!String do
  let values = for row in rows do
    binary(Map.get(row, "device_id"))?
  end
  Ok(values)
end

fn mailbox_hashes(rows :: List<Map<String, DbValue>>) -> List<Bytes>!String do
  let values = for row in rows do
    binary(Map.get(row, "mailbox_token_hash"))?
  end
  Ok(values)
end

fn removal_statement(pool :: PoolHandle, account_id :: Bytes, device_id :: Bytes) -> Bytes!String do
  let rows = Pool.query_values(pool,
    "SELECT statement FROM messenger_revoked_devices WHERE account_id = $1 AND device_id = $2 AND statement IS NOT NULL",
    [Binary(account_id), Binary(device_id)])?
  if List.length(rows) != 1 do
    Err("removed device missing")
  else
    binary(Map.get(List.head(rows), "statement"))
  end
end

## A kept statement says how a device was removed, and the device is shown it.
## One removed before statements were kept is only refused.

fn revoked_error(row :: Map<String, DbValue>) -> String do
  case Map.get(row, "statement") do
    Binary(_) -> "messenger_device_revoked"
    _ -> "messenger_devices_conflict"
  end
end

fn deletion_statement(pool :: PoolHandle, account_id :: Bytes) -> Bytes!String do
  let rows = Pool.query_values(pool,
    "SELECT statement FROM messenger_deleted_accounts WHERE account_id = $1",
    [Binary(account_id)])?
  if List.length(rows) != 1 do
    Err("deleted account missing")
  else
    binary(Map.get(List.head(rows), "statement"))
  end
end

fn resolve_on_connection(conn :: borrow PgConn, username :: String) -> Option<DeviceSet>!String do
  let accounts = Pg.query_values(conn,
    "SELECT account_id, account_identity, sequence::text FROM messenger_accounts WHERE username = $1 FOR SHARE",
    [Text(username)])?
  if List.length(accounts) == 0 do
    Ok(None)
  else
    let account = List.head(accounts)
    let account_id = binary(Map.get(account, "account_id"))?
    let account_identity = binary(Map.get(account, "account_identity"))?
    let device_rows = Pg.query_values(conn,
      "SELECT prekey_bundle, mailbox_token FROM messenger_devices WHERE account_id = $1 AND revoked_at IS NULL ORDER BY device_id",
      [Binary(account_id)])?
    let revoked_rows = Pg.query_values(conn,
      "SELECT device_id FROM messenger_revoked_devices WHERE account_id = $1 ORDER BY device_id",
      [Binary(account_id)])?
    let value = DeviceSet {
      version: 1,
      username: username,
      account_identity: account_identity,
      sequence: wide(Map.get(account, "sequence"))?,
      devices: entries(device_rows, username, account_identity)?,
      revoked_device_ids: ids(revoked_rows)?
    }
    case encode_device_set(value) do
      Err(_) -> Err("invalid stored device set")
      Ok(encoded)
    end?
    Ok(Some(value))
  end
end

fn record_device_set(conn :: borrow PgConn,
  account_id :: Bytes,
  username :: String,
  new_account :: Bool) -> DeviceWrite!String do
  let device_set = case resolve_on_connection(conn, username)? do
    None -> Err("device set disappeared")
    Some(value) -> Ok(value)
  end?
  let encoded = case encode_device_set(device_set) do
    Err(_) -> Err("invalid stored device set")
    Ok(value)
  end?
  append_entry_on_connection(conn, account_id, encoded, new_account)?
  Ok(DeviceAccepted)
end

fn rotate_on_connection(conn :: borrow PgConn,
  entry :: DirectoryEntry,
  account :: AccountIdentity,
  credential :: DeviceCredential,
  row :: Map<String, DbValue>,
  device_row :: Map<String, DbValue>,
  token_hash :: Bytes) -> DeviceWrite!String do
  let mailbox_matches = text(Map.get(device_row, "mailbox_active"))? == "true" && Bytes.secure_equals(binary(Map.get(device_row,
      "mailbox_token"))?,
    entry.mailbox_token) && Bytes.secure_equals(binary(Map.get(device_row, "mailbox_token_hash"))?,
    token_hash)
  if Bytes.secure_equals(binary(Map.get(device_row, "prekey_bundle"))?, entry.prekey_bundle) && mailbox_matches do
    return Ok(DeviceUnchanged)
  end
  let stored_bundle = case decode_prekey_bundle(binary(Map.get(device_row, "prekey_bundle"))?) do
    Err(_) -> Err("invalid stored prekey bundle")
    Ok(value)
  end?
  let stored_credential = case decode_device_credential(stored_bundle.device_credential) do
    Err(_) -> Err("invalid stored device credential")
    Ok(value)
  end?
  let proposed_bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> Err("invalid proposed prekey bundle")
    Ok(value)
  end?
  let sequence = wide(Map.get(row, "sequence"))?
  let next_sequence = U64.add(sequence, U64.parse("1")?)?
  let same_keys = Bytes.secure_equals(stored_credential.signing_public_key,
    credential.signing_public_key) && Bytes.secure_equals(stored_credential.dh_public_key,
    credential.dh_public_key)
  let same_signed_prekey = U64.compare(stored_bundle.signed_prekey_id,
    proposed_bundle.signed_prekey_id) == 0 && Bytes.secure_equals(stored_bundle.signed_prekey,
    proposed_bundle.signed_prekey) && U64.compare(stored_bundle.expires_at,
    proposed_bundle.expires_at) == 0
  let rotates_to_hybrid = stored_credential.suite == 1 && credential.suite == 2 && Bytes.length(credential.post_quantum_public_key) == 1184
  if !mailbox_matches || !same_keys || !same_signed_prekey || !rotates_to_hybrid || U64.compare(credential.directory_sequence,
    next_sequence) != 0 do
    return Err("messenger_devices_conflict")
  end
  let changed = Pg.execute_values(conn,
    "UPDATE messenger_devices SET prekey_bundle = $3 WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL",
    [Binary(account.account_id), Binary(credential.device_id), Binary(entry.prekey_bundle)])?
  let sequence_changed = Pg.execute_values(conn,
    "UPDATE messenger_accounts SET sequence = $2::bigint, updated_at = now() WHERE account_id = $1 AND sequence = $3::bigint",
    [Binary(account.account_id), Text(U64.to_string(next_sequence)), Text(U64.to_string(sequence))])?
  if changed != 1 || sequence_changed != 1 do
    return Err("device rotation changed concurrently")
  end
  record_device_set(conn, account.account_id, entry.username, false)
end

fn register_on_connection(conn :: borrow PgConn,
  entry :: DirectoryEntry,
  account :: AccountIdentity,
  credential :: DeviceCredential,
  initial_prekey :: Option<OneTimePrekeyPublic>) -> DeviceWrite!String do
  Pg.execute_values(conn,
    "INSERT INTO messenger_accounts (username, account_id, account_identity) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    [Text(entry.username), Binary(account.account_id), Binary(entry.account_identity)])?
  # After the insert, which waits out a deletion of this account in progress.
  let deleted = Pg.query_values(conn,
    "SELECT account_id FROM messenger_deleted_accounts WHERE account_id = $1",
    [Binary(account.account_id)])?
  if List.length(deleted) > 0 do
    return Err("messenger_account_deleted")
  end
  let accounts = Pg.query_values(conn,
    "SELECT username, account_id, account_identity, sequence::text, (SELECT count(*)::text FROM messenger_devices WHERE account_id = messenger_accounts.account_id AND revoked_at IS NULL) AS active_count FROM messenger_accounts WHERE username = $1 OR account_id = $2 FOR UPDATE",
    [Text(entry.username), Binary(account.account_id)])?
  if List.length(accounts) != 1 do
    return Err("messenger_devices_conflict")
  end
  let row = List.head(accounts)
  let account_matches = text(Map.get(row, "username"))? == entry.username && Bytes.secure_equals(binary(Map.get(row,
      "account_id"))?,
    account.account_id) && Bytes.secure_equals(binary(Map.get(row, "account_identity"))?,
    entry.account_identity)
  if !account_matches do
    return Err("messenger_devices_conflict")
  end
  let revoked = Pg.query_values(conn,
    "SELECT statement FROM messenger_revoked_devices WHERE account_id = $1 AND device_id = $2",
    [Binary(account.account_id), Binary(credential.device_id)])?
  if List.length(revoked) > 0 do
    return Err(revoked_error(List.head(revoked)))
  end
  let existing = Pg.query_values(conn,
    "SELECT device.prekey_bundle, device.mailbox_token, device.mailbox_token_hash, mailbox.active::text AS mailbox_active FROM messenger_devices AS device JOIN messenger_mailboxes AS mailbox ON mailbox.mailbox_token_hash = device.mailbox_token_hash WHERE device.account_id = $1 AND device.device_id = $2 AND device.revoked_at IS NULL FOR UPDATE OF device, mailbox",
    [Binary(account.account_id), Binary(credential.device_id)])?
  let token_hash = Crypto.sha256(entry.mailbox_token)
  if List.length(existing) > 0 do
    return rotate_on_connection(conn,
      entry,
      account,
      credential,
      row,
      List.head(existing),
      token_hash)
  end
  let sequence = wide(Map.get(row, "sequence"))?
  let next_sequence = U64.add(sequence, U64.parse("1")?)?
  if U64.compare(credential.directory_sequence, next_sequence) != 0 || integer(Map.get(row,
    "active_count"))? >= 8 do
    return Err("messenger_devices_conflict")
  end
  Pg.execute_values(conn,
    "INSERT INTO messenger_mailboxes (mailbox_token_hash) VALUES ($1) ON CONFLICT DO NOTHING",
    [Binary(token_hash)])?
  let mailboxes = Pg.query_values(conn,
    "SELECT active::text FROM messenger_mailboxes WHERE mailbox_token_hash = $1 FOR UPDATE",
    [Binary(token_hash)])?
  if List.length(mailboxes) != 1 || text(Map.get(List.head(mailboxes), "active"))? != "true" do
    return Err("messenger_devices_conflict")
  end
  Pg.execute_values(conn,
    "INSERT INTO messenger_devices (account_id, device_id, prekey_bundle, mailbox_token, mailbox_token_hash) VALUES ($1, $2, $3, $4, $5)",
    [
      Binary(account.account_id),
      Binary(credential.device_id),
      Binary(entry.prekey_bundle),
      Binary(entry.mailbox_token),
      Binary(token_hash)
    ])?
  seed_registration_prekey_on_connection(conn,
    account.account_id,
    credential.device_id,
    initial_prekey)?
  let changed = Pg.execute_values(conn,
    "UPDATE messenger_accounts SET sequence = $2::bigint, updated_at = now() WHERE account_id = $1 AND sequence = $3::bigint",
    [Binary(account.account_id), Text(U64.to_string(next_sequence)), Text(U64.to_string(sequence))])?
  if changed != 1 do
    return Err("device sequence changed")
  end
  record_device_set(conn,
    account.account_id,
    entry.username,
    U64.compare(sequence, U64.parse("0")?) == 0)
end

pub fn register_device(pool :: PoolHandle, entry :: DirectoryEntry) -> DeviceWrite!String do
  case verified_registration(entry) do
    Err(_) -> Ok(DeviceInvalid)
    Ok(verified) -> do
      case Repo.transaction(pool,
        fn(conn :: borrow PgConn) -> register_on_connection(conn,
          verified.entry,
          verified.account,
          verified.credential,
          verified.initial_prekey) end) do
        Err(error) -> if String.contains(error, "transparency_log_full") do
          Ok(DeviceLogFull)
        else if String.contains(error, "messenger_account_deleted") do
          Ok(DeviceRemoved(deletion_statement(pool, verified.account.account_id)?))
        else if String.contains(error, "messenger_device_revoked") do
          Ok(DeviceRemoved(removal_statement(pool,
            verified.account.account_id,
            verified.credential.device_id)?))
        else if String.contains(error, "messenger_devices_") || String.contains(error,
          "duplicate key") do
          Ok(DeviceConflict)
        else
          Err(error)
        end
        Ok(result)
      end
    end
  end
end

pub fn resolve_devices(pool :: PoolHandle, username :: String) -> Option<DeviceSet>!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> resolve_on_connection(conn, username) end)
end

fn revoke_on_connection(conn :: borrow PgConn, value :: DeviceRevocation) -> DeviceWrite!String do
  let accounts = Pg.query_values(conn,
    "SELECT username, account_identity, sequence::text FROM messenger_accounts WHERE account_id = $1 FOR UPDATE",
    [Binary(value.account_id)])?
  if List.length(accounts) != 1 do
    return Err("messenger_revoked_devices_conflict")
  end
  let row = List.head(accounts)
  let account = case decode_account_identity(binary(Map.get(row, "account_identity"))?) do
    Err(_) -> Err("invalid stored account identity")
    Ok(decoded)
  end?
  let valid = case verify_device_revocation(account, value) do
    Err(_) -> false
    Ok(result) -> result
  end
  if !valid do
    return Ok(DeviceInvalid)
  end
  let sequence = wide(Map.get(row, "sequence"))?
  let next_sequence = U64.add(sequence, U64.parse("1")?)?
  if U64.compare(value.sequence, next_sequence) != 0 do
    return Err("messenger_revoked_devices_conflict")
  end
  let devices = Pg.query_values(conn,
    "SELECT mailbox_token_hash, (SELECT count(*)::text FROM messenger_devices WHERE account_id = $1 AND revoked_at IS NULL) AS active_count FROM messenger_devices WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL",
    [Binary(value.account_id), Binary(value.device_id)])?
  if List.length(devices) != 1 do
    return Err("messenger_revoked_devices_conflict")
  end
  let device = List.head(devices)
  if integer(Map.get(device, "active_count"))? <= 1 do
    return Err("messenger_revoked_devices_conflict")
  end
  let statement = case encode_device_revocation(value) do
    Err(_) -> Err("invalid device revocation")
    Ok(encoded)
  end?
  retire_on_connection(conn,
    value.account_id,
    value.device_id,
    binary(Map.get(device, "mailbox_token_hash"))?,
    text(Map.get(row, "username"))?,
    sequence,
    value.sequence,
    statement)
end

## Takes one device out of its account's logged device set: its ID is revoked
## for good, its mailbox stops taking envelopes, and its prekeys go. The signed
## statement that removed it is kept to show the device.

fn retire_on_connection(conn :: borrow PgConn,
  account_id :: Bytes,
  device_id :: Bytes,
  mailbox_token_hash :: Bytes,
  username :: String,
  sequence :: U64,
  next_sequence :: U64,
  statement :: Bytes) -> DeviceWrite!String do
  Pg.execute_values(conn,
    "INSERT INTO messenger_revoked_devices (account_id, device_id, sequence, statement) VALUES ($1, $2, $3::bigint, $4)",
    [Binary(account_id), Binary(device_id), Text(U64.to_string(next_sequence)), Binary(statement)])?
  let changed = Pg.execute_values(conn,
    "UPDATE messenger_devices SET revoked_at = now() WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL",
    [Binary(account_id), Binary(device_id)])?
  let mailbox_changed = Pg.execute_values(conn,
    "UPDATE messenger_mailboxes SET active = false WHERE mailbox_token_hash = $1 AND active",
    [Binary(mailbox_token_hash)])?
  let sequence_changed = Pg.execute_values(conn,
    "UPDATE messenger_accounts SET sequence = $2::bigint, updated_at = now() WHERE account_id = $1 AND sequence = $3::bigint",
    [Binary(account_id), Text(U64.to_string(next_sequence)), Text(U64.to_string(sequence))])?
  if changed != 1 || mailbox_changed != 1 || sequence_changed != 1 do
    return Err("device revocation changed concurrently")
  end
  record_device_set(conn, account_id, username, false)?
  Ok(DeviceRetired(mailbox_token_hash))
end

pub fn revoke_device(pool :: PoolHandle, value :: DeviceRevocation) -> DeviceWrite!String do
  case encode_device_revocation(value) do
    Err(_) -> Ok(DeviceInvalid)
    Ok(_) -> case Repo.transaction(pool,
      fn(conn :: borrow PgConn) -> revoke_on_connection(conn, value) end) do
      Err(error) -> if String.contains(error, "transparency_log_full") do
        Ok(DeviceLogFull)
      else if String.contains(error, "messenger_revoked_devices_") || String.contains(error,
        "duplicate key") do
        Ok(DeviceConflict)
      else
        Err(error)
      end
      Ok(result)
    end
  end
end

fn delete_on_connection(conn :: borrow PgConn, value :: AccountDeletion) -> AccountRemoval!String do
  let accounts = Pg.query_values(conn,
    "SELECT account_identity FROM messenger_accounts WHERE account_id = $1 FOR UPDATE",
    [Binary(value.account_id)])?
  if List.length(accounts) != 1 do
    return Ok(AccountRemoved([]))
  end
  let account = case decode_account_identity(binary(Map.get(List.head(accounts), "account_identity"))?) do
    Err(_) -> Err("invalid stored account identity")
    Ok(decoded)
  end?
  let signed = case verify_account_deletion(account, value) do
    Err(_) -> false
    Ok(result) -> result
  end
  if !signed do
    return Ok(AccountRemovalRefused)
  end
  let statement = case encode_account_deletion(value) do
    Err(_) -> Err("invalid account deletion")
    Ok(encoded)
  end?
  let listening = mailbox_hashes(Pg.query_values(conn,
    "SELECT mailbox_token_hash FROM messenger_devices WHERE account_id = $1 AND revoked_at IS NULL",
    [Binary(value.account_id)])?)?
  # Envelopes before the mailboxes they are queued in. Prekeys go with their
  # devices, and push bindings and contact addresses with their mailboxes.
  Pg.execute_values(conn,
    "DELETE FROM messenger_envelopes WHERE mailbox_token_hash IN (SELECT mailbox_token_hash FROM messenger_devices WHERE account_id = $1)",
    [Binary(value.account_id)])?
  Pg.execute_values(conn,
    "WITH devices AS (DELETE FROM messenger_devices WHERE account_id = $1 RETURNING mailbox_token_hash) DELETE FROM messenger_mailboxes WHERE mailbox_token_hash IN (SELECT mailbox_token_hash FROM devices)",
    [Binary(value.account_id)])?
  Pg.execute_values(conn,
    "DELETE FROM messenger_revoked_devices WHERE account_id = $1",
    [Binary(value.account_id)])?
  Pg.execute_values(conn,
    "DELETE FROM messenger_accounts WHERE account_id = $1",
    [Binary(value.account_id)])?
  Pg.execute_values(conn,
    "INSERT INTO messenger_deleted_accounts (account_id, statement) VALUES ($1, $2)",
    [Binary(value.account_id), Binary(statement)])?
  forget_account_entries_on_connection(conn, value.account_id)?
  Ok(AccountRemoved(listening))
end

## Deletes an account on a fresh statement signed by its own key. Freshness is
## checked first, so a stale or replayed statement costs no query.

pub fn delete_account(pool :: PoolHandle, value :: AccountDeletion) -> AccountRemoval!String do
  if !mailbox_request_is_fresh(value.issued_at, current_time()?) do
    Ok(AccountRemovalRefused)
  else
    Repo.transaction(pool, fn(conn :: borrow PgConn) -> delete_on_connection(conn, value) end)
  end
end

fn leave_on_connection(conn :: borrow PgConn, value :: DeviceDeparture) -> DeviceWrite!String do
  let accounts = Pg.query_values(conn,
    "SELECT username, sequence::text FROM messenger_accounts WHERE account_id = $1 FOR UPDATE",
    [Binary(value.account_id)])?
  if List.length(accounts) != 1 do
    return Ok(DeviceUnchanged)
  end
  let row = List.head(accounts)
  let devices = Pg.query_values(conn,
    "SELECT prekey_bundle, mailbox_token_hash, (SELECT count(*)::text FROM messenger_devices WHERE account_id = $1 AND revoked_at IS NULL) AS active_count FROM messenger_devices WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL",
    [Binary(value.account_id), Binary(value.device_id)])?
  if List.length(devices) != 1 do
    return Ok(DeviceUnchanged)
  end
  let device = List.head(devices)
  let signed = case verify_device_departure(bundle_signing_public_key(binary(Map.get(device,
      "prekey_bundle"))?)?,
    value) do
    Err(_) -> false
    Ok(result) -> result
  end
  if !signed do
    return Ok(DeviceInvalid)
  end
  # The last device deletes the account instead of leaving one with no device.
  if integer(Map.get(device, "active_count"))? <= 1 do
    return Err("messenger_revoked_devices_conflict")
  end
  let sequence = wide(Map.get(row, "sequence"))?
  let statement = case encode_device_departure(value) do
    Err(_) -> Err("invalid device departure")
    Ok(encoded)
  end?
  retire_on_connection(conn,
    value.account_id,
    value.device_id,
    binary(Map.get(device, "mailbox_token_hash"))?,
    text(Map.get(row, "username"))?,
    sequence,
    U64.add(sequence, U64.parse("1")?)?,
    statement)
end

## A device leaves its account on a fresh statement signed by its own key, and
## is revoked like a removed one. An account or device already gone answers as
## if it had just left, so a retry succeeds.

pub fn leave_device(pool :: PoolHandle, value :: DeviceDeparture) -> DeviceWrite!String do
  if !mailbox_request_is_fresh(value.issued_at, current_time()?) do
    Ok(DeviceInvalid)
  else
    case Repo.transaction(pool, fn(conn :: borrow PgConn) -> leave_on_connection(conn, value) end) do
      Err(error) -> if String.contains(error, "transparency_log_full") do
        Ok(DeviceLogFull)
      else if String.contains(error, "messenger_revoked_devices_") || String.contains(error,
        "duplicate key") do
        Ok(DeviceConflict)
      else
        Err(error)
      end
      Ok(result)
    end
  end
end
