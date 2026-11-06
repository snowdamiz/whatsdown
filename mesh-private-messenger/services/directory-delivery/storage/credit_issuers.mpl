from Credits.Issuer import (
  CreditIssuerKey,
  decode_issuer_key,
  encode_issuer_key,
  issuer_key_id,
  verify_issuer_key
)
from Credits.Policy import issuer_epoch_accepted
from Storage.Transparency import append_entry_on_connection, create_checkpoint_for_on_connection
from Storage.TransparencyLog import writable_log_version
from Storage.TransparencyRecords import entry_bytes_on_connection
from Transparency.Merkle import TransparencyCheckpoint, WitnessKey
from Transparency.Wire import TransparencyEvidence, encode_checkpoint

pub struct CreditIssuerAnnouncement do
  created :: Bool
  entry_sequence :: Int
  checkpoint :: TransparencyCheckpoint
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_credit_issuer_row")
  end
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid_credit_issuer_row")
  end
end

pub fn credit_now(conn :: borrow PgConn) -> U64!String do
  let rows = Pg.query_values(conn,
    "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint::text AS now",
    [])?
  U64.parse(text(Map.get(List.head(rows), "now"))?)
end

pub fn configured_credit_purpose() -> Int!String do
  case Env.get("MESSENGER_CREDITS_PURPOSE", "live") do
    "live" -> Ok(0)
    "test" -> Ok(1)
    _ -> Err("invalid_credit_purpose_configuration")
  end
end

fn core_signer() -> SigningKeyPair!String do
  let material = case Env.get_secret_hex("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX") do
    Err(_) -> return Err("invalid_credit_service_key")
    Ok(value) -> value
  end
  case Crypto.signing_from_secret(material) do
    Err(_) -> Err("invalid_credit_service_key")
    Ok(value)
  end
end

pub fn core_credit_service_key() -> SigningPublicKey!String do
  let signer = core_signer()?
  Ok(signer.public_key)
end

fn announcement(conn :: borrow PgConn, leaf :: Bytes) -> CreditIssuerAnnouncement!String do
  let key = decode_issuer_key(leaf)?
  let now = credit_now(conn)?
  if !issuer_epoch_accepted(key.epoch, now)? do
    return Err("inactive_credit_issuer")
  end
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365487)", [])?
  if writable_log_version(conn)? != 2 do
    return Err("credits_require_rfc6962_log")
  end
  let existing = Pg.query_values(conn,
    "SELECT spki, entry_sequence::text FROM credit_issuer_announcements WHERE epoch = $1::bigint AND purpose = $2::smallint FOR UPDATE",
    [Text(U64.to_string(key.epoch)), Text(Int.to_string(key.purpose))])?
  let id = issuer_key_id(key)?
  let created = List.length(existing) == 0
  let sequence = if !created do
    let row = List.head(existing)
    let sequence = case String.to_int(text(Map.get(row, "entry_sequence"))?) do
      None -> return Err("invalid_credit_issuer_row")
      Some(value) -> value
    end
    if !Bytes.secure_equals(binary(Map.get(row, "spki"))?, key.spki)
      || !Bytes.secure_equals(entry_bytes_on_connection(conn, sequence)?, leaf) do
      return Err("credit_issuer_changed")
    end
    sequence
  else
    if List.length(Pg.query_values(conn,
      "SELECT key_id FROM credit_issuer_announcements WHERE key_id = $1",
      [Binary(id)])?) > 0 do
      return Err("credit_issuer_key_reused")
    end
    let scoped_id = Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-credit-issuer-entry-v1"),
      leaf)?)
    let added = append_entry_on_connection(conn, scoped_id, leaf, false)?
    Pg.execute_values(conn,
      "INSERT INTO credit_issuer_announcements (epoch, purpose, key_id, spki, entry_sequence) VALUES ($1::bigint, $2::smallint, $3, $4, $5::bigint)",
      [
        Text(U64.to_string(key.epoch)),
        Text(Int.to_string(key.purpose)),
        Binary(id),
        Binary(key.spki),
        Text(Int.to_string(added))
      ])?
    added
  end
  let signer = core_signer()?
  let checkpoint = create_checkpoint_for_on_connection(conn,
    2,
    signer.private_key,
    signer.public_key.bytes)?
  Ok(CreditIssuerAnnouncement {
    created: created,
    entry_sequence: sequence,
    checkpoint: checkpoint
  })
end

# Publication is issuer-admin authorized at the HTTP boundary. Witnesses attest
# append-only log consistency, not permission to mint credits. This step alone
# never admits a key for redemption.
pub fn announce_credit_issuer(pool :: PoolHandle,
  leaf :: Bytes) -> CreditIssuerAnnouncement!String do
  decode_issuer_key(leaf)?
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> announcement(conn, leaf) end)
end

pub fn credit_witnesses_on_connection(conn :: borrow PgConn) -> List<WitnessKey>!String do
  let rows = Pg.query_values(conn,
    "SELECT witness_id, public_key FROM transparency_witness_registry WHERE status = 'pinned' ORDER BY witness_id LIMIT 17 FOR SHARE",
    [])?
  if List.length(rows) < 1 || List.length(rows) > 16 do
    return Err("invalid_credit_witness_configuration")
  end
  let pins = for row in rows do
    WitnessKey {
      witness_id: text(Map.get(row, "witness_id"))?,
      public_key: binary(Map.get(row, "public_key"))?
    }
  end
  Ok(pins)
end

fn admit(conn :: borrow PgConn, evidence :: TransparencyEvidence) -> Bool!String do
  let proposed = decode_issuer_key(evidence.entry_bytes)?
  let now = credit_now(conn)?
  if !issuer_epoch_accepted(proposed.epoch, now)? do
    return Err("inactive_credit_issuer")
  end
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365487)", [])?
  let rows = Pg.query_values(conn,
    "SELECT a.spki, a.entry_sequence::text, a.admitted_checkpoint, e.leaf_index::text, e.log_version::text FROM credit_issuer_announcements a JOIN transparency_entries e ON e.sequence = a.entry_sequence WHERE a.epoch = $1::bigint AND a.purpose = $2::smallint FOR UPDATE OF a",
    [Text(U64.to_string(proposed.epoch)), Text(Int.to_string(proposed.purpose))])?
  if List.length(rows) != 1 do
    return Err("unannounced_credit_issuer")
  end
  let row = List.head(rows)
  let sequence = case String.to_int(text(Map.get(row, "entry_sequence"))?) do
    None -> return Err("invalid_credit_issuer_row")
    Some(value) -> value
  end
  if !Bytes.secure_equals(binary(Map.get(row, "spki"))?, proposed.spki)
    || !Bytes.secure_equals(entry_bytes_on_connection(conn, sequence)?, evidence.entry_bytes)
    || text(Map.get(row, "log_version"))? != "2"
    || text(Map.get(row, "leaf_index"))? != Int.to_string(evidence.inclusion.leaf_index) do
    return Err("unannounced_credit_issuer")
  end
  case Map.get(row, "admitted_checkpoint") do
    Binary(_) -> return Ok(false)
    _ -> nil
  end
  let cursor = Pg.query_values(conn,
    "SELECT checkpoint FROM credit_issuer_cursor WHERE singleton FOR UPDATE",
    [])?
  let previous = binary(Map.get(List.head(cursor), "checkpoint"))?
  let pins = credit_witnesses_on_connection(conn)?
  let key = verify_issuer_key(evidence,
    core_credit_service_key()?,
    pins,
    List.length(pins) / 2 + 1,
    previous,
    now,
    proposed.purpose)?
  let checkpoint = encode_checkpoint(evidence.checkpoint)?
  Pg.execute_values(conn,
    "UPDATE credit_issuer_announcements SET admitted_checkpoint = $3, admitted_at = clock_timestamp() WHERE epoch = $1::bigint AND purpose = $2::smallint",
    [Text(U64.to_string(key.epoch)), Text(Int.to_string(key.purpose)), Binary(checkpoint)])?
  Pg.execute_values(conn,
    "UPDATE credit_issuer_cursor SET checkpoint = $1 WHERE singleton",
    [Binary(checkpoint)])?
  Ok(true)
end

pub fn admit_credit_issuer(pool :: PoolHandle, evidence :: TransparencyEvidence) -> Bool!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> admit(conn, evidence) end)
end

# Only durable, witnessed admissions from this core's issuer-admin path qualify.
# Caller-supplied key lists never reach the redemption verifier.
pub fn admitted_credit_keys_on_connection(conn :: borrow PgConn,
  now :: U64,
  purpose :: Int) -> List<CreditIssuerKey>!String do
  let rows = Pg.query_values(conn,
    "SELECT epoch::text, purpose::text, spki, entry_sequence::text FROM credit_issuer_announcements WHERE admitted_at IS NOT NULL AND purpose = $1::smallint AND epoch BETWEEN GREATEST(0, $2::bigint / 2592000 - 1) AND $2::bigint / 2592000 ORDER BY epoch DESC LIMIT 3 FOR SHARE",
    [Text(Int.to_string(purpose)), Text(U64.to_string(now))])?
  if List.length(rows) < 1 || List.length(rows) > 2 do
    return Err("unknown_credit_issuer")
  end
  let keys = for row in rows do
    let sequence = case String.to_int(text(Map.get(row, "entry_sequence"))?) do
      None -> return Err("invalid_credit_issuer_row")
      Some(value) -> value
    end
    let key = decode_issuer_key(entry_bytes_on_connection(conn, sequence)?)?
    if key.epoch != U64.parse(text(Map.get(row, "epoch"))?)?
      || key.purpose != purpose
      || !Bytes.secure_equals(key.spki, binary(Map.get(row, "spki"))?) do
      return Err("invalid_credit_issuer_row")
    end
    key
  end
  Ok(keys)
end
