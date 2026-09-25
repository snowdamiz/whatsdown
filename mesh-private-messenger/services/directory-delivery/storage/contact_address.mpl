##! A device's secret second deposit address, shared only with contacts.

pub type ContactAddressWrite do
  ContactAddressPublished
  ContactAddressUnchanged
  ContactAddressConflict
  ContactAddressUnknownMailbox
end

fn exists(conn :: borrow PgConn, statement :: String, values :: List<DbValue>) -> Bool!String do
  let rows = Pg.query_values(conn, statement, values)?
  Ok(List.length(rows) > 0)
end

# An address that already routes somewhere can never be claimed again: not a
# mailbox's public address and not any contact address, current or retired.
# Otherwise a device could publish a victim's address as its own and have the
# victim's envelopes delivered to itself.
# The device's own address counts as unchanged whether it is current or retired,
# and a retired one stays retired. A device that lost its state republishes an
# old address in good faith: refusing would fail its every publication, and
# reinstating would hand the contact share back to whoever the rotation was
# meant to shut out.

pub fn publish_contact_address_on_connection(conn :: borrow PgConn,
  mailbox_hash :: Bytes,
  alias_hash :: Bytes) -> ContactAddressWrite!String do
  if !(exists(conn,
    "SELECT 1 AS found FROM messenger_mailboxes WHERE mailbox_token_hash = $1 AND active FOR UPDATE",
    [Binary(mailbox_hash)])?) do
    Ok(ContactAddressUnknownMailbox)
  else if exists(conn,
    "SELECT 1 AS found FROM messenger_mailbox_aliases WHERE alias_hash = $1 AND mailbox_token_hash = $2",
    [Binary(alias_hash), Binary(mailbox_hash)])? do
    Ok(ContactAddressUnchanged)
  else if exists(conn,
    "SELECT 1 AS found FROM messenger_mailboxes WHERE mailbox_token_hash = $1 UNION ALL SELECT 1 FROM messenger_mailbox_aliases WHERE alias_hash = $1",
    [Binary(alias_hash)])? do
    Ok(ContactAddressConflict)
  else
    Pg.execute_values(conn,
      "UPDATE messenger_mailbox_aliases SET retired_at = clock_timestamp() WHERE mailbox_token_hash = $1 AND retired_at IS NULL",
      [Binary(mailbox_hash)])?
    Pg.execute_values(conn,
      "INSERT INTO messenger_mailbox_aliases (alias_hash, mailbox_token_hash) VALUES ($1, $2)",
      [Binary(alias_hash), Binary(mailbox_hash)])?
    Ok(ContactAddressPublished)
  end
end

pub fn publish_contact_address(pool :: PoolHandle, mailbox_hash :: Bytes, alias_hash :: Bytes) -> ContactAddressWrite!String do
  if Bytes.length(mailbox_hash) != 32 || Bytes.length(alias_hash) != 32 do
    Err("invalid contact address")
  else
    Repo.transaction(pool,
      fn(conn :: borrow PgConn) -> publish_contact_address_on_connection(conn,
        mailbox_hash,
        alias_hash) end)
  end
end

# Where an envelope's address leads: the mailbox it belongs to, and whether it
# was that mailbox's current contact address. Anything else, a retired contact
# address included, is a stranger's.
#
# Contact addresses are looked up before public ones. A device registered under
# someone's contact address therefore cannot intercept it; it only makes its
# own public address unreachable.

pub fn resolve_deposit_address(conn :: borrow PgConn, address_hash :: Bytes) -> Result<(Bytes, Bool), String> do
  let rows = Pg.query_values(conn,
    "SELECT mailbox_token_hash, (retired_at IS NULL)::text AS current FROM messenger_mailbox_aliases WHERE alias_hash = $1",
    [Binary(address_hash)])?
  if List.length(rows) == 0 do
    Ok((address_hash, false))
  else
    let row = List.head(rows)
    case Map.get(row, "mailbox_token_hash") do
      Binary(mailbox_hash) -> case Map.get(row, "current") do
        Text(current) -> Ok((mailbox_hash, current == "true"))
        _ -> Err("invalid contact address row")
      end
      _ -> Err("invalid contact address row")
    end
  end
end
