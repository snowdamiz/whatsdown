from Protocol.DirectoryWire import encode_directory_entry, encode_directory_lookup
from Protocol.V1 import DirectoryEntry

fn protocol_ok(value :: Result < Bytes, ProtocolError >) -> Result <(), String > do
  case value do
    Err( _) -> Err("invalid directory record")
    Ok( _) -> Ok(nil)
  end
end

fn binary(value :: DbValue) -> Bytes ! String do
  case value do
    Binary( bytes) -> Ok(bytes)
    _ -> Err("invalid directory row")
  end
end

pub fn register_directory(pool :: PoolHandle, entry :: DirectoryEntry) -> Int ! String do
  protocol_ok(encode_directory_entry(entry)) ?
  Pool.execute_values(pool,
  "WITH mailbox AS (INSERT INTO messenger_mailboxes (mailbox_token_hash) VALUES ($5) ON CONFLICT DO NOTHING) INSERT INTO messenger_directory (username, account_identity, prekey_bundle, mailbox_token, mailbox_token_hash) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (username) DO UPDATE SET account_identity = EXCLUDED.account_identity, prekey_bundle = EXCLUDED.prekey_bundle, mailbox_token = EXCLUDED.mailbox_token, mailbox_token_hash = EXCLUDED.mailbox_token_hash, updated_at = now()",
  [Text(entry.username), Binary(entry.account_identity), Binary(entry.prekey_bundle), Binary(entry.mailbox_token), Binary(Crypto.sha256(entry.mailbox_token))])
end

pub fn resolve_directory(pool :: PoolHandle, username :: String) -> Option < DirectoryEntry > ! String do
  protocol_ok(encode_directory_lookup(username)) ?
  let rows = Pool.query_values(pool,
  "SELECT account_identity, prekey_bundle, mailbox_token FROM messenger_directory WHERE username = $1",
  [Text(username)]) ?
  if List.length(rows) == 0 do
    Ok(None)
  else
    let row = List.head(rows)
    Ok(Some(DirectoryEntry {
      version : 1,
      username : username,
      account_identity : binary(Map.get(row, "account_identity")) ?,
      prekey_bundle : binary(Map.get(row, "prekey_bundle")) ?,
      mailbox_token : binary(Map.get(row, "mailbox_token")) ?
    }))
  end
end
