from Credits.Discovery import CreditIssuerQuery
from Credits.Issuer import decode_issuer_key, encode_issuer_key
from Credits.Policy import issuer_epoch
from Storage.CreditIssuers import (
  credit_now,
  core_credit_service_key,
  credit_witnesses_on_connection
)
from Storage.Transparency import historical_checkpoint_on_connection
from Storage.TransparencyLog import cutover_phase
from Storage.TransparencyRecords import entry_bytes_on_connection
from Storage.TransparencyTree import tree_inclusion_for, tree_consistency_for, tree_root_for
from Storage.WitnessRegistry import signature_policy_sql
from Transparency.Client import checkpoint_fresh_at
from Transparency.Merkle import (
  WitnessAttestation,
  verify_checkpoint,
  verify_witnesses_at,
  leaf_hash_for,
  verify_inclusion,
  verify_consistency
)
from Transparency.Wire import TransparencyEvidence

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("credit_issuer_not_ready")
  end
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("credit_issuer_not_ready")
  end
end

fn integer(value :: DbValue) -> Int!String do
  case String.to_int(text(value)?) do
    Some(output) -> Ok(output)
    None -> Err("credit_issuer_not_ready")
  end
end

fn evidence(conn :: borrow PgConn,
  query :: CreditIssuerQuery,
  require_admitted :: Bool) -> TransparencyEvidence!String do
  if cutover_phase(conn)? != "active" do
    return Err("credit_issuer_not_ready")
  end
  let now = credit_now(conn)?
  let epoch = issuer_epoch(now)?
  let rows = Pg.query_values(conn,
    "SELECT a.spki, a.entry_sequence::text, e.leaf_index::text FROM credit_issuer_announcements a JOIN transparency_entries e ON e.sequence = a.entry_sequence WHERE a.epoch = $1::bigint AND a.purpose = $2::smallint AND (NOT $3::boolean OR a.admitted_at IS NOT NULL) AND e.log_version = 2 FOR SHARE OF a, e",
    [
      Text(U64.to_string(epoch)),
      Text(Int.to_string(query.purpose)),
      Text(if require_admitted do
        "true"
      else
        "false"
      end)
    ])?
  if List.length(rows) != 1 do
    return Err("credit_issuer_not_ready")
  end
  let row = List.head(rows)
  let index = integer(Map.get(row, "leaf_index"))?
  let entry = entry_bytes_on_connection(conn, integer(Map.get(row, "entry_sequence"))?)?
  let key = decode_issuer_key(entry)?
  if key.epoch != epoch
    || key.purpose != query.purpose
    || !Bytes.secure_equals(key.spki, binary(Map.get(row, "spki"))?)
    || !Bytes.secure_equals(entry, encode_issuer_key(key)?) do
    return Err("credit_issuer_not_ready")
  end
  let pins = credit_witnesses_on_connection(conn)?
  let threshold = List.length(pins) / 2 + 1
  let now_ms = U64.multiply(now, U64.parse("1000")?)?
  let policy = signature_policy_sql(2)?
  # Pick the latest ready stored checkpoint, rather than minting one or hiding
  # a still-fresh quorum behind a newer checkpoint awaiting its witnesses.
  let ready = Pg.query_values(conn,
    "SELECT c.sequence::text FROM transparency_v2_checkpoints c WHERE c.tree_size > $1::bigint AND c.timestamp_ms BETWEEN $2::bigint - 300000 AND $2::bigint + 60000 AND (SELECT count(*) FROM witness_v2_signatures s JOIN transparency_witness_registry r ON r.witness_id = s.witness_id AND r.public_key = s.witness_public_key WHERE s.checkpoint_sequence = c.sequence AND r.status = 'pinned' AND "
      <> policy
      <> ") >= $3::integer ORDER BY c.sequence DESC LIMIT 1 FOR SHARE OF c",
    [Text(Int.to_string(index)), Text(U64.to_string(now_ms)), Text(Int.to_string(threshold))])?
  if List.length(ready) != 1 do
    return Err("credit_issuer_not_ready")
  end
  let sequence = U64.parse(text(Map.get(List.head(ready), "sequence"))?)?
  let checkpoint = case historical_checkpoint_on_connection(conn, 2, sequence)? do
    None -> return Err("credit_issuer_not_ready")
    Some(value) -> value
  end
  if U64.compare(query.previous_size, checkpoint.tree_size) > 0 do
    return Err("credit_issuer_previous_ahead")
  end
  let signatures = Pg.query_values(conn,
    "SELECT s.witness_id, s.checkpoint_hash, s.signature FROM witness_v2_signatures s JOIN transparency_witness_registry r ON r.witness_id = s.witness_id AND r.public_key = s.witness_public_key WHERE s.checkpoint_sequence = $1::bigint AND r.status = 'pinned' AND "
      <> policy
      <> " ORDER BY s.witness_id LIMIT 16",
    [Text(U64.to_string(sequence))])?
  let witnesses = for signature in signatures do
    WitnessAttestation {
      witness_id: text(Map.get(signature, "witness_id"))?,
      checkpoint_hash: binary(Map.get(signature, "checkpoint_hash"))?,
      signature: binary(Map.get(signature, "signature"))?
    }
  end
  if !checkpoint_fresh_at(checkpoint.timestamp, now_ms)
    || !verify_checkpoint(checkpoint, core_credit_service_key()?)?
    || !verify_witnesses_at(checkpoint, witnesses, pins, threshold, now_ms)? do
    return Err("credit_issuer_not_ready")
  end
  let count = U64.to_int(checkpoint.tree_size)?
  let previous = U64.to_int(query.previous_size)?
  let inclusion = tree_inclusion_for(conn, 2, index, count)?
  let consistency = tree_consistency_for(conn, 2, previous, count)?
  if !verify_inclusion(leaf_hash_for(2, entry)?, inclusion, checkpoint.tree_root)?
    || !verify_consistency(tree_root_for(conn, 2, previous)?, checkpoint.tree_root, consistency)? do
    return Err("credit_issuer_not_ready")
  end
  Ok(TransparencyEvidence {
    entry_bytes: entry,
    inclusion: inclusion,
    consistency: consistency,
    checkpoint: checkpoint,
    witnesses: witnesses
  })
end

pub fn current_credit_issuer_evidence(pool :: PoolHandle,
  query :: CreditIssuerQuery) -> TransparencyEvidence!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> evidence(conn, query, true) end)
end

# Issuer-admin only. This publishes proof of a candidate; it never admits it.
pub fn announced_credit_issuer_evidence(pool :: PoolHandle,
  query :: CreditIssuerQuery) -> TransparencyEvidence!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> evidence(conn, query, false) end)
end

pub fn credit_issuer_cursor(pool :: PoolHandle) -> Bytes!String do
  let rows = Pool.query_values(pool,
    "SELECT checkpoint FROM credit_issuer_cursor WHERE singleton",
    [])?
  if List.length(rows) != 1 do
    return Err("credit_issuer_not_ready")
  end
  binary(Map.get(List.head(rows), "checkpoint"))
end
