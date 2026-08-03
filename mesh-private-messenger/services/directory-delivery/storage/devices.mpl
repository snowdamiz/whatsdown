from Identity.Device import verify_device_revocation
from Prekeys.Bundle import verify_prekey_bundle
from Protocol.V1 import AccountIdentity, DeviceCredential, DeviceRevocation, DeviceSet, DirectoryEntry, decode_account_identity, decode_device_credential, decode_prekey_bundle, encode_device_revocation, encode_device_set, encode_directory_entry

pub type DeviceWrite do
  DeviceAccepted

  DeviceConflict

  DeviceInvalid
end deriving(Eq, Debug)

fn binary(value :: DbValue) -> Bytes ! String do
  case value do
    Binary( bytes) -> Ok(bytes)
    _ -> Err("invalid device row")
  end
end

fn text(value :: DbValue) -> String ! String do
  case value do
    Text( output) -> Ok(output)
    _ -> Err("invalid device row")
  end
end

fn wide(value :: DbValue) -> U64 ! String do
  U64.parse(text(value) ?)
end

fn integer(value :: DbValue) -> Int ! String do
  case String.to_int(text(value) ?) do
    None -> Err("invalid device integer")
    Some( output) -> Ok(output)
  end
end

fn current_time() -> U64 ! String do
  U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn verified_registration(entry :: DirectoryEntry) -> Result <( AccountIdentity, DeviceCredential), String > do
  let _ = case encode_directory_entry(entry) do
    Err( _) -> Err("invalid device registration")
    Ok( value) -> Ok(value)
  end ?
  let account = case decode_account_identity(entry.account_identity) do
    Err( _) -> Err("invalid device registration")
    Ok( value) -> Ok(value)
  end ?
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err( _) -> Err("invalid device registration")
    Ok( value) -> Ok(value)
  end ?
  let credential = case decode_device_credential(bundle.device_credential) do
    Err( _) -> Err("invalid device registration")
    Ok( value) -> Ok(value)
  end ?
  case verify_prekey_bundle(account, bundle, 1, current_time() ?, account.directory_sequence) do
    Err( _) -> Err("invalid device registration")
    Ok( false) -> Err("invalid device registration")
    Ok( true) -> Ok((account, credential))
  end
end

fn register_on_connection(conn :: borrow PgConn,
entry :: DirectoryEntry,
account :: AccountIdentity,
credential :: DeviceCredential) -> DeviceWrite ! String do
  let _ = Pg.execute_values(conn,
  "INSERT INTO messenger_accounts (username, account_id, account_identity) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
  [Text(entry.username), Binary(account.account_id), Binary(entry.account_identity)]) ?
  let accounts = Pg.query_values(conn,
  "SELECT username, account_id, account_identity, sequence::text, (SELECT count(*)::text FROM messenger_devices WHERE account_id = messenger_accounts.account_id AND revoked_at IS NULL) AS active_count FROM messenger_accounts WHERE username = $1 OR account_id = $2 FOR UPDATE",
  [Text(entry.username), Binary(account.account_id)]) ?
  if List.length(accounts) != 1 do
    Err("messenger_devices_conflict")
  else
    let row = List.head(accounts)
    let account_matches = text(Map.get(row, "username")) ? == entry.username && Bytes.secure_equals(binary(Map.get(row,
    "account_id")) ?,
    account.account_id) && Bytes.secure_equals(binary(Map.get(row, "account_identity")) ?,
    entry.account_identity)
    if !account_matches do
      Err("messenger_devices_conflict")
    else
      let revoked = Pg.query_values(conn,
      "SELECT sequence::text FROM messenger_revoked_devices WHERE account_id = $1 AND device_id = $2",
      [Binary(account.account_id), Binary(credential.device_id)]) ?
      if List.length(revoked) > 0 do
        Err("messenger_devices_conflict")
      else
        let existing = Pg.query_values(conn,
        "SELECT prekey_bundle, mailbox_token_hash FROM messenger_devices WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL",
        [Binary(account.account_id), Binary(credential.device_id)]) ?
        let token_hash = Crypto.sha256(entry.mailbox_token)
        if List.length(existing) > 0 do
          let device_row = List.head(existing)
          if Bytes.secure_equals(binary(Map.get(device_row, "prekey_bundle")) ?,
          entry.prekey_bundle) && Bytes.secure_equals(binary(Map.get(device_row,
          "mailbox_token_hash")) ?,
          token_hash) do
            Ok(DeviceAccepted)
          else
            Err("messenger_devices_conflict")
          end
        else
          let sequence = wide(Map.get(row, "sequence")) ?
          let next_sequence = U64.add(sequence, U64.parse("1") ?) ?
          if U64.compare(credential.directory_sequence, next_sequence) != 0 || integer(Map.get(row,
          "active_count")) ? >= 8 do
            Err("messenger_devices_conflict")
          else
            let _ = Pg.execute_values(conn,
            "INSERT INTO messenger_mailboxes (mailbox_token_hash) VALUES ($1) ON CONFLICT DO NOTHING",
            [Binary(token_hash)]) ?
            let mailboxes = Pg.query_values(conn,
            "SELECT active::text FROM messenger_mailboxes WHERE mailbox_token_hash = $1 FOR UPDATE",
            [Binary(token_hash)]) ?
            if List.length(mailboxes) != 1 || text(Map.get(List.head(mailboxes), "active")) ? != "true" do
              Err("messenger_devices_conflict")
            else
              let _ = Pg.execute_values(conn,
              "INSERT INTO messenger_devices (account_id, device_id, prekey_bundle, mailbox_token, mailbox_token_hash) VALUES ($1, $2, $3, $4, $5)",
              [Binary(account.account_id), Binary(credential.device_id), Binary(entry.prekey_bundle), Binary(entry.mailbox_token), Binary(token_hash)]) ?
              let changed = Pg.execute_values(conn,
              "UPDATE messenger_accounts SET sequence = $2::bigint, updated_at = now() WHERE account_id = $1 AND sequence = $3::bigint",
              [Binary(account.account_id), Text(U64.to_string(next_sequence)), Text(U64.to_string(sequence))]) ?
              if changed == 1 do
                Ok(DeviceAccepted)
              else
                Err("device sequence changed")
              end
            end
          end
        end
      end
    end
  end
end

pub fn register_device(pool :: PoolHandle, entry :: DirectoryEntry) -> DeviceWrite ! String do
  case verified_registration(entry) do
    Err( _) -> Ok(DeviceInvalid)
    Ok( verified) -> do
      let ( account, credential) = verified
      case Repo.transaction(pool,
      fn (conn :: borrow PgConn) -> register_on_connection(conn, entry, account, credential) end) do
        Err( error) -> if String.contains(error, "messenger_devices_") || String.contains(error,
        "duplicate key") do
          Ok(DeviceConflict)
        else
          Err(error)
        end
        Ok( result) -> Ok(result)
      end
    end
  end
end

fn entries(rows :: List < Map < String, DbValue > >,
username :: String,
account_identity :: Bytes,
index :: Int,
output :: List < DirectoryEntry >) -> List < DirectoryEntry > ! String do
  if index >= List.length(rows) do
    Ok(output)
  else
    let row = List.get(rows, index)
    entries(rows,
    username,
    account_identity,
    index + 1,
    List.append(output,
    DirectoryEntry {
      version : 1,
      username : username,
      account_identity : account_identity,
      prekey_bundle : binary(Map.get(row, "prekey_bundle")) ?,
      mailbox_token : binary(Map.get(row, "mailbox_token")) ?
    }))
  end
end

fn ids(rows :: List < Map < String, DbValue > >, index :: Int, output :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(rows) do
    Ok(output)
  else
    ids(rows, index + 1, List.append(output, binary(Map.get(List.get(rows, index), "device_id")) ?))
  end
end

fn resolve_on_connection(conn :: borrow PgConn, username :: String) -> Option < DeviceSet > ! String do
  let accounts = Pg.query_values(conn,
  "SELECT account_id, account_identity, sequence::text FROM messenger_accounts WHERE username = $1 FOR SHARE",
  [Text(username)]) ?
  if List.length(accounts) == 0 do
    Ok(None)
  else
    let account = List.head(accounts)
    let account_id = binary(Map.get(account, "account_id")) ?
    let account_identity = binary(Map.get(account, "account_identity")) ?
    let device_rows = Pg.query_values(conn,
    "SELECT prekey_bundle, mailbox_token FROM messenger_devices WHERE account_id = $1 AND revoked_at IS NULL ORDER BY device_id",
    [Binary(account_id)]) ?
    let revoked_rows = Pg.query_values(conn,
    "SELECT device_id FROM messenger_revoked_devices WHERE account_id = $1 ORDER BY device_id",
    [Binary(account_id)]) ?
    let value = DeviceSet {
      version : 1,
      username : username,
      account_identity : account_identity,
      sequence : wide(Map.get(account, "sequence")) ?,
      devices : entries(device_rows, username, account_identity, 0, List.new()) ?,
      revoked_device_ids : ids(revoked_rows, 0, List.new()) ?
    }
    let _ = case encode_device_set(value) do
      Err( _) -> Err("invalid stored device set")
      Ok( encoded) -> Ok(encoded)
    end ?
    Ok(Some(value))
  end
end

pub fn resolve_devices(pool :: PoolHandle, username :: String) -> Option < DeviceSet > ! String do
  Repo.transaction(pool, fn (conn :: borrow PgConn) -> resolve_on_connection(conn, username) end)
end

fn revoke_on_connection(conn :: borrow PgConn, value :: DeviceRevocation) -> DeviceWrite ! String do
  let accounts = Pg.query_values(conn,
  "SELECT account_identity, sequence::text FROM messenger_accounts WHERE account_id = $1 FOR UPDATE",
  [Binary(value.account_id)]) ?
  if List.length(accounts) != 1 do
    Err("messenger_revoked_devices_conflict")
  else
    let row = List.head(accounts)
    let account = case decode_account_identity(binary(Map.get(row, "account_identity")) ?) do
      Err( _) -> Err("invalid stored account identity")
      Ok( decoded) -> Ok(decoded)
    end ?
    let valid = case verify_device_revocation(account, value) do
      Err( _) -> false
      Ok( result) -> result
    end
    if !valid do
      Ok(DeviceInvalid)
    else
      let sequence = wide(Map.get(row, "sequence")) ?
      let next_sequence = U64.add(sequence, U64.parse("1") ?) ?
      if U64.compare(value.sequence, next_sequence) != 0 do
        Err("messenger_revoked_devices_conflict")
      else
        let devices = Pg.query_values(conn,
        "SELECT mailbox_token_hash, (SELECT count(*)::text FROM messenger_devices WHERE account_id = $1 AND revoked_at IS NULL) AS active_count FROM messenger_devices WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL",
        [Binary(value.account_id), Binary(value.device_id)]) ?
        if List.length(devices) != 1 do
          Err("messenger_revoked_devices_conflict")
        else
          let device = List.head(devices)
          let count = integer(Map.get(device, "active_count")) ?
          if count <= 1 do
            Err("messenger_revoked_devices_conflict")
          else
            let _ = Pg.execute_values(conn,
            "INSERT INTO messenger_revoked_devices (account_id, device_id, sequence) VALUES ($1, $2, $3::bigint)",
            [Binary(value.account_id), Binary(value.device_id), Text(U64.to_string(value.sequence))]) ?
            let changed = Pg.execute_values(conn,
            "UPDATE messenger_devices SET revoked_at = now() WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL",
            [Binary(value.account_id), Binary(value.device_id)]) ?
            let mailbox_changed = Pg.execute_values(conn,
            "UPDATE messenger_mailboxes SET active = false WHERE mailbox_token_hash = $1 AND active",
            [Binary(binary(Map.get(device, "mailbox_token_hash")) ?)]) ?
            let sequence_changed = Pg.execute_values(conn,
            "UPDATE messenger_accounts SET sequence = $2::bigint, updated_at = now() WHERE account_id = $1 AND sequence = $3::bigint",
            [Binary(value.account_id), Text(U64.to_string(value.sequence)), Text(U64.to_string(sequence))]) ?
            if changed == 1 && mailbox_changed == 1 && sequence_changed == 1 do
              Ok(DeviceAccepted)
            else
              Err("device revocation changed concurrently")
            end
          end
        end
      end
    end
  end
end

pub fn revoke_device(pool :: PoolHandle, value :: DeviceRevocation) -> DeviceWrite ! String do
  case encode_device_revocation(value) do
    Err( _) -> Ok(DeviceInvalid)
    Ok( _) -> case Repo.transaction(pool,
    fn (conn :: borrow PgConn) -> revoke_on_connection(conn, value) end) do
      Err( error) -> if String.contains(error, "messenger_revoked_devices_") || String.contains(error,
      "duplicate key") do
        Ok(DeviceConflict)
      else
        Err(error)
      end
      Ok( result) -> Ok(result)
    end
  end
end
