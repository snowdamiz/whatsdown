##! Explicit, resumable legacy -> RFC 6962 cutover. Each public operation runs
##! in the caller's PostgreSQL transaction; the shared append lock serializes
##! registrations, retention, account deletion and every migration batch.
from Storage.Transparency import create_checkpoint_for_on_connection
from Storage.TransparencyLog import cutover_phase, legacy_seal
from Storage.TransparencyRecords import entry_bytes_on_connection, store_entry_records
from Storage.TransparencyTree import (
  append_tree_leaf_for,
  tree_size_for,
  tree_consistency_for,
  tree_inclusion_for
)
from Transparency.Merkle import (
  TransparencyCheckpoint,
  WitnessAttestation,
  WitnessKey,
  leaf_hash_for,
  verify_witnesses
)
from Transparency.Migration import LegacyBridge, legacy_bridge_leaf
from Transparency.Wire import encode_checkpoint, encode_witnesses, decode_witnesses

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(bytes) -> Ok(bytes)
    _ -> Err("invalid cutover row")
  end
end

fn integer(value :: DbValue) -> Int!String do
  case value do
    Text(value) -> case String.to_int(value) do
      Some(number) -> Ok(number)
      None -> Err("invalid cutover integer")
    end
    _ -> Err("invalid cutover integer")
  end
end

fn lock(conn :: borrow PgConn) -> Result<(), String> do
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  Ok(nil)
end

fn required_seal(conn :: borrow PgConn) -> TransparencyCheckpoint!String do
  case legacy_seal(conn)? do
    None -> Err("transparency_cutover_not_started")
    Some(value) -> Ok(value)
  end
end

pub fn begin_cutover_on_connection(conn :: borrow PgConn,
  signing_key :: borrow SigningPrivateKey,
  signing_public_key :: Bytes) -> TransparencyCheckpoint!String do
  lock(conn)?
  case legacy_seal(conn)? do
    Some(value) -> if Bytes.secure_equals(value.service_public_key, signing_public_key) do
      return Ok(value)
    else
      return Err("transparency cutover signer mismatch")
    end
    None -> nil
  end
  if tree_size_for(conn, 2)? != 0 do
    return Err("transparency v2 tree already exists")
  end
  let seal = create_checkpoint_for_on_connection(conn, 1, signing_key, signing_public_key)?
  if !Bytes.secure_equals(seal.service_public_key, signing_public_key) do
    return Err("transparency cutover signer mismatch")
  end
  Pg.execute_values(conn,
    "INSERT INTO transparency_log_cutover (phase, legacy_checkpoint) VALUES ('sealing', $1)",
    [Binary(encode_checkpoint(seal)?)])?
  Ok(seal)
end

fn valid_policy(keys :: List<WitnessKey>, threshold :: Int) -> Bool do
  let count = List.length(keys)
  if count < 1 || count > 16 || threshold <= count / 2 || threshold > count do
    return false
  end
  for index in 0..count do
    let key = List.get(keys, index)
    let length = Bytes.length(Bytes.from_utf8(key.witness_id))
    if length < 1 || length > 64 || Bytes.length(key.public_key) != 32 do
      return false
    end
    for previous in 0..index do
      let other = List.get(keys, previous)
      if other.witness_id == key.witness_id
        || Bytes.secure_equals(other.public_key, key.public_key) do
        return false
      end
    end
  end
  true
end

# Pins come from the operator's trusted legacy release policy. HTTP responses
# never supply a trust policy. Once copied, later registry edits cannot change
# or remove the authenticated legacy seal carried to upgrading clients.
pub fn accept_legacy_seal_on_connection(conn :: borrow PgConn,
  attestations :: List<WitnessAttestation>,
  legacy_pins :: List<WitnessKey>,
  legacy_threshold :: Int) -> Result<(), String> do
  lock(conn)?
  let seal = required_seal(conn)?
  if !valid_policy(legacy_pins, legacy_threshold)
    || List.any(attestations, fn(value) -> Bytes.length(value.signature) != 64 end)
    || !verify_witnesses(seal, attestations, legacy_pins, legacy_threshold)? do
    return Err("legacy_seal_quorum_missing")
  end
  if cutover_phase(conn)? != "sealing" do
    return Ok(nil)
  end
  if tree_size_for(conn, 2)? != 0 do
    return Err("transparency v2 tree already exists")
  end
  let witnesses = encode_witnesses(attestations)?
  append_tree_leaf_for(conn, 2, 0, leaf_hash_for(2, legacy_bridge_leaf(seal)?)?)?
  Pg.execute_values(conn,
    "UPDATE transparency_log_cutover SET phase = 'copying', legacy_witnesses = $1 WHERE singleton",
    [Binary(witnesses)])?
  Ok(nil)
end

pub fn copy_cutover_batch_on_connection(conn :: borrow PgConn,
  limit :: Int,
  signing_key :: borrow SigningPrivateKey,
  signing_public_key :: Bytes) -> Bool!String do
  if limit < 1 || limit > 100 do
    return Err("invalid cutover batch limit")
  end
  lock(conn)?
  let phase = cutover_phase(conn)?
  if phase == "active" do
    return Ok(true)
  end
  if phase != "copying" do
    return Err("legacy_seal_quorum_missing")
  end
  let seal = required_seal(conn)?
  if !Bytes.secure_equals(seal.service_public_key, signing_public_key)
    || U64.compare(U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?,
      seal.timestamp) < 0 do
    return Err("transparency cutover signer or clock mismatch")
  end
  # Do not fall back to an earlier entry when the latest was deleted. Account
  # deletion erases both profiles under this lock, including a copied snapshot.
  let rows = Pg.query_values(conn,
    "SELECT e.sequence::text, e.account_commitment FROM transparency_entries e WHERE e.log_version = 1 AND e.sequence > (SELECT copied_through FROM transparency_log_cutover) AND (e.entry_bytes IS NOT NULL OR e.entry_header IS NOT NULL) AND NOT EXISTS (SELECT 1 FROM transparency_entries newer WHERE newer.log_version = 1 AND newer.account_commitment = e.account_commitment AND newer.sequence > e.sequence) ORDER BY e.sequence LIMIT $1::integer",
    [Text(Int.to_string(limit))])?
  for row in rows do
    let sequence = integer(Map.get(row, "sequence"))?
    let bytes = entry_bytes_on_connection(conn, sequence)?
    let hash = leaf_hash_for(2, bytes)?
    let index = tree_size_for(conn, 2)?
    let inserted = Pg.query_values(conn,
      "INSERT INTO transparency_entries (log_version, account_commitment, entry_bytes, leaf_hash, leaf_index) VALUES (2, $1, $2, $3, $4::bigint) RETURNING sequence::text",
      [
        Binary(binary(Map.get(row, "account_commitment"))?),
        Binary(bytes),
        Binary(hash),
        Text(Int.to_string(index))
      ])?
    store_entry_records(conn, integer(Map.get(List.head(inserted), "sequence"))?, bytes, hash)?
    append_tree_leaf_for(conn, 2, index, hash)?
    Pg.execute(conn,
      "UPDATE transparency_log_cutover SET copied_through = $1::bigint WHERE singleton",
      [Int.to_string(sequence)])?
  end
  if List.length(rows) == limit do
    return Ok(false)
  end
  # Activation and the first RFC checkpoint are one durable transaction. A
  # signing/storage failure rolls back the phase, so no reader sees a half log.
  Pg.execute(conn,
    "UPDATE transparency_log_cutover SET phase = 'active', activated_at = now() WHERE singleton",
    [])?
  create_checkpoint_for_on_connection(conn, 2, signing_key, signing_public_key)?
  Ok(true)
end

pub fn legacy_bridge_on_connection(conn :: borrow PgConn,
  previous_legacy_size :: Int,
  current_rfc_size :: Int) -> LegacyBridge!String do
  if cutover_phase(conn)? != "active" do
    return Err("transparency_v2_not_active")
  end
  let seal = required_seal(conn)?
  let rows = Pg.query_values(conn, "SELECT legacy_witnesses FROM transparency_log_cutover", [])?
  Ok(LegacyBridge {
    checkpoint: seal,
    witnesses: decode_witnesses(binary(Map.get(List.head(rows), "legacy_witnesses"))?)?,
    consistency: tree_consistency_for(conn, 1, previous_legacy_size, U64.to_int(seal.tree_size)?)?,
    inclusion: tree_inclusion_for(conn, 2, 0, current_rfc_size)?
  })
end
