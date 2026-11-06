from Credits.PostagePolicy import (
  PostagePolicy,
  decode_postage_policy,
  verify_postage_policy,
  strip_postage_policy_extension,
  bundle_with_postage_policy
)
from Protocol.IdentityWire import decode_account_identity
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import DirectoryEntry

fn policy_binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(value) -> Ok(value)
    _ -> Err("invalid_stored_postage_policy")
  end
end

# Taking the account lock first gives publication, registration and paid enqueue
# one consistent lock order. The policy statement is verified against the
# immutable registered account, never a caller-supplied key.
pub fn latest_postage_policy_on_connection(conn :: borrow PgConn,
  account_id :: Bytes) -> Option<PostagePolicy>!String do
  let accounts = Pg.query_values(conn,
    "SELECT account_identity FROM messenger_accounts WHERE account_id = $1 FOR SHARE",
    [Binary(account_id)])?
  if List.length(accounts) != 1 do
    return Err("unknown_credit_account")
  end
  let rows = Pg.query_values(conn,
    "SELECT statement FROM credit_postage_policies WHERE account_id = $1 ORDER BY revision DESC LIMIT 1",
    [Binary(account_id)])?
  if List.length(rows) == 0 do
    return Ok(None)
  end
  let policy = decode_postage_policy(policy_binary(Map.get(List.head(rows), "statement"))?)?
  let identity = case decode_account_identity(policy_binary(Map.get(List.head(accounts),
    "account_identity"))?) do
    Err(_) -> return Err("invalid_stored_postage_policy")
    Ok(value) -> value
  end
  if !verify_postage_policy(policy, identity)? do
    return Err("invalid_stored_postage_policy")
  end
  Ok(Some(policy))
end

pub fn postage_price_on_connection(conn :: borrow PgConn, account_id :: Bytes) -> Int!String do
  case latest_postage_policy_on_connection(conn, account_id)? do
    None -> Ok(0)
    Some(policy) -> Ok(policy.credits)
  end
end

pub fn canonical_postage_entry_on_connection(conn :: borrow PgConn,
  account_id :: Bytes,
  entry :: DirectoryEntry) -> DirectoryEntry!String do
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err(_) -> return Err("invalid_postage_policy_bundle")
    Ok(value) -> value
  end
  let clean = strip_postage_policy_extension(bundle)
  let canonical = case latest_postage_policy_on_connection(conn, account_id)? do
    None -> clean
    Some(policy) -> bundle_with_postage_policy(clean, policy)?
  end
  let encoded = case encode_prekey_bundle(canonical) do
    Err(_) -> return Err("invalid_postage_policy_bundle")
    Ok(value) -> value
  end
  Ok(%{entry | prekey_bundle: encoded})
end

pub fn initialize_postage_mailbox_on_connection(conn :: borrow PgConn,
  account_id :: Bytes,
  mailbox_hash :: Bytes) -> Result<(), String> do
  let price = postage_price_on_connection(conn, account_id)?
  Pg.execute_values(conn,
    "UPDATE messenger_mailboxes SET postage_credits = $2::smallint WHERE mailbox_token_hash = $1",
    [Binary(mailbox_hash), Text(Int.to_string(price))])?
  Ok(nil)
end

pub fn mirror_postage_policy_on_connection(conn :: borrow PgConn,
  account_id :: Bytes,
  policy :: PostagePolicy) -> Result<(), String> do
  let rows = Pg.query_values(conn,
    "SELECT device_id, prekey_bundle FROM messenger_devices WHERE account_id = $1 AND revoked_at IS NULL ORDER BY device_id FOR UPDATE",
    [Binary(account_id)])?
  if List.length(rows) < 1 || List.length(rows) > 8 do
    return Err("invalid_postage_device_set")
  end
  for row in rows do
    let bundle = case decode_prekey_bundle(policy_binary(Map.get(row, "prekey_bundle"))?) do
      Err(_) -> return Err("invalid_stored_postage_policy")
      Ok(value) -> value
    end
    let updated = bundle_with_postage_policy(bundle, policy)?
    let encoded = case encode_prekey_bundle(updated) do
      Err(_) -> return Err("invalid_stored_postage_policy")
      Ok(value) -> value
    end
    Pg.execute_values(conn,
      "UPDATE messenger_devices SET prekey_bundle = $3 WHERE account_id = $1 AND device_id = $2",
      [Binary(account_id), Binary(policy_binary(Map.get(row, "device_id"))?), Binary(encoded)])?
  end
  Pg.execute_values(conn,
    "UPDATE messenger_mailboxes SET postage_credits = $2::smallint WHERE mailbox_token_hash IN (SELECT mailbox_token_hash FROM messenger_devices WHERE account_id = $1 AND revoked_at IS NULL)",
    [Binary(account_id), Text(Int.to_string(policy.credits))])?
  Ok(nil)
end
